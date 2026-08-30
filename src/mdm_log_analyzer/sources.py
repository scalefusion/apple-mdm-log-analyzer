"""Log source abstraction (spec section 5).

Every source returns raw `log show --style ndjson` text for a given predicate +
time window. Four implementations:

- LiveLogSource     — shells `log show` on the current Mac (macOS only).
- ArchiveLogSource  — shells `log show --archive <.logarchive>` (macOS only).
- BundleLogSource   — reads a `tools/collect-mdm-logs.sh` bundle (dir or auto-
                      extracted from its .tar.gz). Portable, no `log` binary.
- FixtureLogSource  — replays a single captured NDJSON file. Off-Mac.

The engine never cares which one it is talking to.
"""
from __future__ import annotations

import atexit
import gzip
import json
import re
import shutil
import os
import platform
import subprocess
import tarfile
import tempfile
import zipfile
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath

from .parser import epoch_ms, to_iso_utc

_INSTALL_LOG = "/var/log/install.log"
_WINDOW_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
# macOS 26 writes ISO-colon offsets (+05:30); older builds wrote +0530.
_RE_INSTALL_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}(?::?\d{2})?)")


def _window_seconds(last: str) -> int | None:
    """Parse '30m' / '2h' / '1d' to seconds; None if unrecognized (= no filter)."""
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", last or "")
    return int(m.group(1)) * _WINDOW_UNITS[m.group(2)] if m else None


def _within(root: PurePath, target: PurePath) -> bool:
    """True if `target` is inside `root`.

    Uses PurePath semantics rather than string prefixes: the previous
    `str(target).startswith(str(root) + "/")` hardcoded the POSIX separator, so
    on Windows every legitimate archive member failed the check and extraction
    was impossible. Takes PurePath so it is testable against both flavours.
    """
    try:
        return target == root or target.is_relative_to(root)
    except (ValueError, AttributeError):  # pragma: no cover - defensive
        return False


def _span_from_timestamps(times: list[str]) -> dict | None:
    """Earliest/latest of raw log timestamps, as ISO-8601 UTC.

    Compared as instants, not strings. `min()`/`max()` over the raw text was
    wrong whenever a capture mixed UTC offsets — and real ones do: an apsd
    export carried 1,858 events stamped +0000 alongside 30,116 at +0530, so
    lexicographic ordering put a later instant first and the reported span was
    both wrong and rendered in two different zones. Normalized to UTC for the
    same reason Event.timestamp is: one zone, no ambiguity.
    """
    stamps = []
    for t in times:
        iso = to_iso_utc(t)
        ms = epoch_ms(iso) if iso else None
        if ms is not None:
            stamps.append((ms, iso))
    if not stamps:
        return None
    return {"start": min(stamps)[1], "end": max(stamps)[1]}


def _filter_ndjson_window(text: str, last: str) -> str:
    """Keep only NDJSON lines within `last` of the NEWEST event in the text.

    Anchored on the newest event in the data, not wall-clock now. A collected
    archive is analyzed hours or days after capture, so a wall-clock window
    would return nothing at all — "the last hour" of a capture means the last
    hour it covers. Lines whose timestamp cannot be parsed are kept rather than
    silently dropped.

    Previously this filtering did not exist: FixtureLogSource and
    BundleLogSource ignored `last` entirely, so a caller asking for 1h silently
    received the whole capture.
    """
    secs = _window_seconds(last)
    if secs is None:
        return text
    parsed: list[tuple[str, int | None]] = []
    stamps: list[int] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            ts = json.loads(line).get("timestamp")
        except json.JSONDecodeError:
            continue
        ms = epoch_ms(to_iso_utc(ts)) if ts else None
        parsed.append((line, ms))
        if ms is not None:
            stamps.append(ms)
    if not stamps:
        return "\n".join(line for line, _ in parsed)
    cutoff = max(stamps) - secs * 1000
    return "\n".join(line for line, ms in parsed if ms is None or ms >= cutoff)


def _filter_ndjson_text(text: str, predicate: str) -> str:
    """Apply the coarse predicate filter (process/subsystem CONTAINS terms) used
    by FixtureLogSource + BundleLogSource. Keeps parity with `log show`'s
    NSPredicate matching without needing an NSPredicate engine.
    """
    terms = re.findall(r'"([^"]+)"', predicate)
    if not terms:
        return text
    kept = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        haystack = " ".join(
            str(obj.get(k, "")) for k in ("process", "processImagePath", "subsystem")
        )
        if any(t in haystack for t in terms):
            kept.append(line)
    return "\n".join(kept)


# Detect os_major from a captured `sw_vers`-shaped os.txt: the line reading
# "ProductVersion:    26.5.1" → 26. Falls back to None if unparsable.
_RE_PRODUCT_VER = re.compile(r"ProductVersion:\s*(\d+)")
# The full dotted version ("26.5.1"), for labelling — see LogSource.os_version.
_RE_PRODUCT_VER_FULL = re.compile(r"ProductVersion:\s*([0-9][0-9.]*)")


def _read_os_major(os_txt: Path) -> int | None:
    if not os_txt.exists():
        return None
    m = _RE_PRODUCT_VER.search(os_txt.read_text(errors="replace"))
    return int(m.group(1)) if m else None


def _read_os_version(os_txt: Path) -> str | None:
    if not os_txt.exists():
        return None
    m = _RE_PRODUCT_VER_FULL.search(os_txt.read_text(errors="replace"))
    return m.group(1) if m else None


def _install_line_time(line: str) -> datetime | None:
    """Parse the leading timestamp of an install.log line, or None."""
    m = _RE_INSTALL_TS.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S%z")
    except ValueError:
        # %z rejects a bare two-digit offset ("-04"), which real install.log
        # lines do use; fromisoformat accepts all three shapes.
        try:
            return datetime.fromisoformat(m.group(1))
        except ValueError:
            return None


def _filter_install_window(text: str, last: str) -> str:
    """Keep install.log lines newer than `now - last`. No-op if `last` unparsed.

    Wall-clock anchored — correct for the LIVE log, where "now" is the incident.
    For a collected capture use `_filter_install_window_anchored` instead.
    """
    secs = _window_seconds(last)
    if secs is None:
        return text
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=secs)
    kept = []
    for line in text.splitlines():
        ts = _install_line_time(line)
        if ts is None:
            continue
        if ts.astimezone(timezone.utc) >= cutoff:
            kept.append(line)
    return "\n".join(kept)


def _filter_install_window_anchored(text: str, last: str) -> str:
    """Keep install.log lines within `last` of the NEWEST line in the text.

    The capture counterpart of `_filter_install_window`, mirroring
    `_filter_ndjson_window`: a bundle is analyzed hours or days after capture, so
    a wall-clock window would return nothing at all.

    This exists because bundles previously ignored `last` outright, on the
    assumption that `collect-mdm-logs.sh` had already windowed install.log. It
    had not — the script `cp`s the whole file, so a 10-minute request returned
    9 days of history: 33,917 lines parsed into 31,760 phase records (8.7 MB),
    which both blew the MCP 1 MB response limit and reported installs from days
    outside the window as if they were inside it.
    """
    secs = _window_seconds(last)
    if secs is None:
        return text
    stamped: list[tuple[str, datetime | None]] = []
    newest: datetime | None = None
    for line in text.splitlines():
        ts = _install_line_time(line)
        if ts is None:
            # Continuation lines (plist/JSON bodies) carry no timestamp of their
            # own; keep them attached to the record above rather than dropping.
            stamped.append((line, None))
            continue
        ts = ts.astimezone(timezone.utc)
        stamped.append((line, ts))
        if newest is None or ts > newest:
            newest = ts
    if newest is None:
        return text
    cutoff = newest - timedelta(seconds=secs)
    kept: list[str] = []
    keeping = False
    for line, ts in stamped:
        if ts is None:
            if keeping:
                kept.append(line)
            continue
        keeping = ts >= cutoff
        if keeping:
            kept.append(line)
    return "\n".join(kept)


class LogSource(ABC):
    os_major: int
    # Full dotted OS version ("26.5.1") when the source knows it. Used only for
    # labelling: a bare `os_major` invites small models to "translate" 26 into a
    # marketing name and get it wrong. None where unknown.
    os_version: str | None = None

    @abstractmethod
    def fetch(self, predicate: str, last: str, level: str) -> str:
        """Return raw NDJSON text for the predicate over the time window."""

    def read_install_log(self, last: str) -> str:
        """Return raw /var/log/install.log text over the time window.

        install.log is a separate plain-text file, not unified-log NDJSON, so it
        has its own read path rather than a predicate query. Optional: a source
        that cannot supply it raises NotImplementedError.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not provide install.log"
        )

    def probe(self) -> dict:
        """Return {os_build, time_span} for open_archive. Best-effort; a source
        that can't determine them returns None values."""
        return {"os_build": None, "time_span": None}

    def capture_inventory(self) -> Optional[dict]:
        """What this source actually contains, for sources that know.

        Exists to settle a question the tools could not previously answer: when a
        category returns 0 events, was nothing logged, or was that process never
        captured? A reader faced with `asset_download: 0` reasoned it out from
        side evidence and got it backwards — the file was present and empty.
        A live source returns None: there is no capture to inventory.
        """
        return None


def _build_argv(predicate: str, last: str, level: str, archive: str | None) -> list[str]:
    argv = ["log", "show", "--style", "ndjson", "--last", last, "--predicate", predicate]
    if level == "info":
        argv.append("--info")
    elif level == "debug":
        argv += ["--info", "--debug"]
    if archive:
        argv += ["--archive", archive]
    return argv


class LiveLogSource(LogSource):
    """Reads the live unified log on the current Mac. Requires root for full access."""

    def __init__(self, os_major: int):
        self.os_major = os_major
        self.os_version = platform.mac_ver()[0] or None

    def fetch(self, predicate: str, last: str, level: str) -> str:
        argv = _build_argv(predicate, last, level, archive=None)
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"log show failed: {proc.stderr.strip()}")
        return proc.stdout

    def read_install_log(self, last: str) -> str:
        """Read /var/log/install.log plus rotated .gz files within the window.

        Rotated logs are install.log.0.gz, install.log.1.gz, ... (oldest highest).
        We concatenate oldest→newest then time-filter so the result is ordered.
        """
        base = Path(_INSTALL_LOG)
        # Only numerically-suffixed rotations; sort oldest (highest index) first.
        indexed = []
        for p in base.parent.glob("install.log.*.gz"):
            m = re.search(r"\.(\d+)\.gz$", p.name)
            if m:
                indexed.append((int(m.group(1)), p))
        rotated = [p for _, p in sorted(indexed, reverse=True)]
        texts: list[str] = []
        for path in [*rotated, base]:
            if not path.exists():
                continue
            if path.suffix == ".gz":
                with gzip.open(path, "rt", errors="replace") as fh:
                    texts.append(fh.read())
            else:
                texts.append(path.read_text(errors="replace"))
        return _filter_install_window("\n".join(texts), last)


class ArchiveLogSource(LogSource):
    """Reads a collected .logarchive / sysdiagnose bundle via `log show --archive`."""

    def __init__(self, archive_path: str, os_major: int):
        self.archive_path = archive_path
        self.os_major = os_major

    def fetch(self, predicate: str, last: str, level: str) -> str:
        argv = _build_argv(predicate, last, level, archive=self.archive_path)
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"log show --archive failed: {proc.stderr.strip()}")
        return proc.stdout

    def probe(self) -> dict:
        """Read {os_build} from the archive's Info.plist. time_span left None —
        deriving it cheaply requires either an undocumented `log stats` shape
        or reading TraceV3 headers (macOS-internal, fragile)."""
        import plistlib

        info_path = Path(self.archive_path) / "Info.plist"
        os_build = None
        if info_path.exists():
            try:
                plist = plistlib.loads(info_path.read_bytes())
                # Typical keys on a .logarchive: OSVersion, OSBuild, HostArchitecture.
                os_build = (
                    plist.get("OSVersion")
                    or plist.get("OSBuild")
                    or plist.get("BuildID")
                    or plist.get("SystemVersion", {}).get("BuildID")
                )
            except Exception:  # noqa: BLE001 — plist parse is best-effort
                pass
        return {"os_build": os_build, "time_span": None}


class FixtureLogSource(LogSource):
    """Reads NDJSON from a file. For development/tests off-Mac.

    Applies a coarse predicate filter (process / subsystem CONTAINS terms) so
    fixtures behave roughly like the real thing without an NSPredicate engine.
    """

    def __init__(
        self,
        fixture_path: str | Path,
        os_major: int = 15,
        install_log_path: str | Path | None = None,
    ):
        self.fixture_path = Path(fixture_path)
        self.os_major = os_major
        self.install_log_path = Path(install_log_path) if install_log_path else None

    def read_install_log(self, last: str) -> str:
        # Anchored on the newest line in the fixture, matching BundleLogSource —
        # a fixture is a capture, so a wall-clock window would match nothing.
        if self.install_log_path is None:
            raise NotImplementedError(
                "FixtureLogSource has no install_log_path configured"
            )
        return _filter_install_window_anchored(
            self.install_log_path.read_text(), last
        )

    def probe(self) -> dict:
        times = []
        for line in self.fixture_path.read_text().splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                ts = json.loads(line).get("timestamp")
            except json.JSONDecodeError:
                continue
            if ts:
                times.append(ts)
        return {
            "os_build": f"fixture-os{self.os_major}",
            "time_span": _span_from_timestamps(times),
        }

    def fetch(self, predicate: str, last: str, level: str) -> str:
        text = _filter_ndjson_window(self.fixture_path.read_text(), last)
        return _filter_ndjson_text(text, predicate)


# Default OS major for a .logarchive when not otherwise known. Detecting the
# archive's real OS build is a Mac/format follow-up (see open_archive_source);
# the predicate loader falls back gracefully, so this only sets which predicate
# file is tried first.
_DEFAULT_ARCHIVE_OS = 26


class BundleLogSource(LogSource):
    """Reads a bundle directory produced by `tools/collect-mdm-logs.sh`:

        mdm-logs-<host>/
          os.txt               # sw_vers — used to detect os_major
          manifest.txt         # informational
          mdmclient.ndjson     # one file per predicate category
          push.ndjson  …       # (each already pre-filtered by log show)
          install.log          # optional — for get_install_log

    `fetch()` concatenates every `*.ndjson` file in the bundle and applies the
    same coarse predicate filter as FixtureLogSource. Overlapping content across
    files (e.g. mdmclient + ddm categories share some mdmclient lines) is fine
    — the engine dedupes by raw_ref downstream.
    """

    def __init__(self, bundle_dir: str | Path, os_major: int | None = None):
        self.bundle_dir = Path(bundle_dir)
        detected = _read_os_major(self.bundle_dir / "os.txt")
        self.os_major = os_major or detected or _DEFAULT_ARCHIVE_OS
        self.os_version = _read_os_version(self.bundle_dir / "os.txt")
        self._install_log = self.bundle_dir / "install.log"
        # Windowed text memo, keyed by `last`. Reading and window-filtering the
        # bundle costs a json.loads per line, and one request fetches the same
        # bundle once per predicate category (7+ times for an incident bundle):
        # on a real 205 MB / 224k-line capture that was the whole runtime. The
        # memo lives on the source object, which the server builds per request —
        # it is not a cache of the corpus across requests (spec §4.4).
        self._windowed: dict[str, str] = {}

    def _windowed_text(self, last: str) -> str:
        if last not in self._windowed:
            parts = []
            for p in sorted(self.bundle_dir.glob("*.ndjson")):
                try:
                    parts.append(p.read_text(errors="replace"))
                except OSError:
                    continue
            self._windowed[last] = _filter_ndjson_window("\n".join(parts), last)
        return self._windowed[last]

    def fetch(self, predicate: str, last: str, level: str) -> str:
        # Combine every .ndjson file in the bundle, then apply `last` relative to
        # the newest event present (the bundle was already windowed at capture,
        # so this narrows further rather than reaching back in time).
        return _filter_ndjson_text(self._windowed_text(last), predicate)

    def read_install_log(self, last: str) -> str:
        # `last` is NOT informational: collect-mdm-logs.sh copies install.log
        # wholesale, so the file spans days regardless of the capture window.
        # Anchor on the newest line, as fetch() does for the ndjson.
        if not self._install_log.exists():
            raise NotImplementedError(
                f"bundle {self.bundle_dir.name} has no install.log"
            )
        return _filter_install_window_anchored(
            self._install_log.read_text(errors="replace"), last
        )

    def capture_inventory(self) -> Optional[dict]:
        """Per-file record counts for the bundle, plus whether install.log is in it.

        A file listed with 0 records was captured and the predicate matched
        nothing. A file absent from `files` was never captured. `log show
        --style ndjson` ends every export with a `{"count":N,"finished":1}`
        trailer even when it matched nothing, so that line is not counted.
        """
        files: dict[str, int] = {}
        for path in sorted(self.bundle_dir.glob("*.ndjson")):
            records = 0
            try:
                with path.open("r", errors="replace") as fh:
                    for line in fh:
                        line = line.strip().rstrip(",")
                        if not line or line in ("[", "]"):
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(obj, dict) and set(obj) == {"count", "finished"}:
                            continue  # log show's end-of-export trailer
                        records += 1
            except OSError:
                continue
            files[path.name] = records
        return {"files": files, "install_log": self._install_log.exists()}

    def probe(self) -> dict:
        os_txt = self.bundle_dir / "os.txt"
        os_build = os_txt.read_text(errors="replace").strip() if os_txt.exists() else None
        # time_span from the union of ndjson timestamps.
        times = []
        for p in self.bundle_dir.glob("*.ndjson"):
            for line in p.read_text(errors="replace").splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    ts = json.loads(line).get("timestamp")
                except json.JSONDecodeError:
                    continue
                if ts:
                    times.append(ts)
        return {"os_build": os_build, "time_span": _span_from_timestamps(times)}


# Bundle detection: a directory (or the top-level dir inside a tarball) is our
# bundle if it has an os.txt AND at least one *.ndjson.
def _looks_like_bundle(d: Path) -> bool:
    return (d / "os.txt").exists() and any(d.glob("*.ndjson"))


# Extraction cleanup — per-process temp dirs, removed at exit so we stay stateless.
_EXTRACTED_TEMP_DIRS: list[str] = []


def _cleanup_extracted_dirs():
    for d in _EXTRACTED_TEMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup_extracted_dirs)


def _safe_extract_tarball(tar_path: Path) -> Path:
    """Extract a bundle tarball into a per-process temp dir with path-traversal
    guards, and return the extracted top-level bundle directory."""
    tmp = tempfile.mkdtemp(prefix="mdm-log-analyzer-bundle-")
    _EXTRACTED_TEMP_DIRS.append(tmp)
    tmp_root = Path(tmp).resolve()
    try:
        tf_ctx = tarfile.open(tar_path, "r:*")
    except tarfile.TarError as e:
        raise ValueError(f"not a readable tarball: {tar_path.name} ({e})") from e
    with tf_ctx as tf:
        for member in tf.getmembers():
            # Guard against '../' and absolute paths — never let a tarball
            # write outside the extraction root.
            target = (tmp_root / member.name).resolve()
            if not _within(tmp_root, target):
                raise ValueError(f"unsafe tarball member: {member.name}")
            # member.name is only half the story: a symlink/hardlink escapes via
            # its TARGET, which the check above never sees. Bundles arrive from
            # other people's machines, so this is reachable input.
            if member.issym() or member.islnk():
                link = Path(member.linkname)
                resolved = (
                    link if link.is_absolute() else (tmp_root / member.name).parent / link
                )
                try:
                    resolved = resolved.resolve()
                except OSError as e:  # pragma: no cover - platform dependent
                    raise ValueError(f"unsafe tarball link: {member.name}") from e
                if not _within(tmp_root, resolved) or resolved == tmp_root:
                    raise ValueError(
                        f"unsafe tarball link: {member.name} -> {member.linkname}"
                    )
        # Belt and braces: tarfile's own 'data' filter rejects absolute links,
        # device nodes and setuid bits too. It arrived in 3.12 and was backported
        # to 3.11.4 (PEP 706), so feature-detect rather than assume — the
        # declared floor is 3.11, where 3.11.0-3.11.3 lack the keyword. On 3.14+
        # 'data' is already the default; passing it explicitly pins the behaviour
        # across every version in range.
        if hasattr(tarfile, "data_filter"):
            tf.extractall(tmp, filter="data")
        else:  # pragma: no cover - only on 3.11.0-3.11.3
            tf.extractall(tmp)
    # Find the bundle root — usually the single top-level directory produced
    # by collect-mdm-logs.sh (mdm-logs-<host>/).
    return _find_bundle_root(Path(tmp), tar_path.name)


def _safe_extract_zip(zip_path: Path) -> Path:
    """Extract a bundle .zip with the same traversal guards as the tarball path.

    macOS Finder's "Compress" produces .zip, so this is what an admin actually
    receives when someone sends them a bundle folder — even though
    collect-mdm-logs.sh emits .tar.gz. Without this, open_archive rejected the
    file and users fell back to attaching it to the chat, which skips redaction
    entirely (see README "Attach vs open_archive").
    """
    tmp = tempfile.mkdtemp(prefix="mdm-log-analyzer-bundle-")
    _EXTRACTED_TEMP_DIRS.append(tmp)
    tmp_root = Path(tmp).resolve()
    try:
        zf_ctx = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise ValueError(f"not a readable zip: {zip_path.name} ({e})") from e
    with zf_ctx as zf:
        members = [
            n for n in zf.namelist()
            # Finder stores resource forks in __MACOSX/; they are not bundle content.
            if not n.startswith("__MACOSX/") and not Path(n).name.startswith("._")
        ]
        for name in members:
            target = (tmp_root / name).resolve()
            if not _within(tmp_root, target):
                raise ValueError(f"unsafe zip member: {name}")
        zf.extractall(tmp, members=members)
    return _find_bundle_root(Path(tmp), zip_path.name)


def _find_bundle_root(tmp: Path, label: str) -> Path:
    """Locate the bundle directory inside an extraction root.

    Finder zips the folder itself, our tarball nests one directory, and a user
    may have zipped the contents directly — accept all three.
    """
    candidates = [p for p in tmp.iterdir() if p.is_dir() and _looks_like_bundle(p)]
    if candidates:
        return candidates[0]
    if _looks_like_bundle(tmp):
        return tmp
    raise ValueError(
        f"{label} does not look like a collect-mdm-logs.sh bundle "
        "(missing os.txt + *.ndjson). Sysdiagnose tarballs aren't yet supported; "
        "extract the .logarchive from the sysdiagnose and open that instead."
    )


def open_archive_source(path: str | Path, os_major: int | None = None) -> LogSource:
    """Build a LogSource for a collected archive path (spec §7.6 open_archive).

    Recognised inputs:
    - `*.logarchive` (dir/bundle) → ArchiveLogSource (`log show --archive`, Mac-only).
    - `*.tar.gz` / `*.tgz` produced by `tools/collect-mdm-logs.sh`, or a `*.zip`
      of the same bundle (what Finder's "Compress" makes) → auto-extract into a
      per-process temp dir (cleaned up at exit) and open as BundleLogSource.
    - A directory containing `os.txt` + `*.ndjson` (an extracted bundle) →
      BundleLogSource directly.
    - `*.ndjson` / `*.json` → FixtureLogSource (replay a captured export off-Mac).

    Sysdiagnose tarballs aren't wired yet — extract the `.logarchive` from the
    sysdiagnose and open that. Raises FileNotFoundError / ValueError /
    NotImplementedError on bad input.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"archive path not found: {path}")
    name = p.name.lower()
    # Extracted bundle directory (before the .logarchive check, which also matches dirs)
    if p.is_dir() and _looks_like_bundle(p):
        return BundleLogSource(p, os_major=os_major)
    if name.endswith((".ndjson", ".json")):
        return FixtureLogSource(p, os_major=os_major or 15)
    if name.endswith(".logarchive"):
        return ArchiveLogSource(str(p), os_major=os_major or _DEFAULT_ARCHIVE_OS)
    if name.endswith((".tar.gz", ".tgz")):
        # Our collect-mdm-logs.sh bundle → auto-extract. A sysdiagnose tarball
        # will fail the bundle check inside _safe_extract_tarball with a clear error.
        bundle_dir = _safe_extract_tarball(p)
        return BundleLogSource(bundle_dir, os_major=os_major)
    if name.endswith(".zip"):
        # What macOS Finder's "Compress" produces — the common real-world case.
        return BundleLogSource(_safe_extract_zip(p), os_major=os_major)
    raise ValueError(f"unrecognized archive type: {path}")


# --- environment-driven source selection (shared by the MCP server and the CLI) ---

# Predicate set assumed when the host OS tells us nothing (i.e. off-Mac).
DEFAULT_OS_MAJOR = 15


def is_macos() -> bool:
    return platform.system() == "Darwin"


def detect_os_major() -> int:
    """The host's macOS major, for predicate selection.

    Off-Mac (a Windows or Linux admin analyzing a collected bundle) mac_ver()
    returns empty strings and there is nothing to detect. Bundles carry the
    source Mac's version in os.txt and BundleLogSource reads it, so this
    fallback only applies to a bare .ndjson — where the caller should pass
    os_major explicitly rather than inherit a guess.
    """
    try:
        ver = platform.mac_ver()[0]
        if ver:
            return int(ver.split(".")[0])
    except (ValueError, IndexError):
        pass
    return DEFAULT_OS_MAJOR


def env_os_major() -> int:
    """MDM_LOG_OS_MAJOR override, falling back to the detected OS.

    A malformed value is ignored rather than raised: it used to surface as an
    uncaught ValueError on every tool call.
    """
    raw = os.environ.get("MDM_LOG_OS_MAJOR")
    if raw is None:
        return detect_os_major()
    try:
        return int(raw.strip())
    except (ValueError, AttributeError):
        return detect_os_major()


def from_env(os_major: int | None = None) -> LogSource:
    """Build a source from the environment: archive > fixture > live."""
    major = os_major or env_os_major()
    archive = os.environ.get("MDM_LOG_ARCHIVE")
    fixture = os.environ.get("MDM_LOG_FIXTURE")
    if archive:
        return ArchiveLogSource(archive, os_major=major)
    if fixture:
        return FixtureLogSource(
            fixture,
            os_major=major,
            install_log_path=os.environ.get("MDM_INSTALL_LOG_FIXTURE"),
        )
    if not is_macos():
        # The live source shells Apple's `log`, which exists only on macOS.
        raise ValueError(
            f"live log capture needs macOS (this host is {platform.system()}). "
            "Analyze a collected bundle instead: pass --source with a "
            "collect-mdm-logs.sh .tar.gz/.zip or a captured .ndjson, or set "
            "MDM_LOG_ARCHIVE / MDM_LOG_FIXTURE."
        )
    return LiveLogSource(os_major=major)
