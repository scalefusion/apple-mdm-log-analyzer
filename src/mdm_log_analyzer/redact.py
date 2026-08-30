"""Redaction / minimization layer (spec section 4.3).

Identifiers are replaced with a stable per-session salted hash so the model can
still correlate "same device / same command" across events without ever seeing
the real value. Nothing here is reversible without the session salt, which is
generated fresh per process run and never persisted.

Two hash spellings, deliberately:

- `h:<12hex>` for structured Event FIELDS (spec §6 shows `command_uuid: "h:3f9c…"`).
- `h-<12hex>` for identifiers rewritten INSIDE free-text messages. A colon would
  terminate the identifier token for every downstream consumer that re-parses a
  scrubbed message — `ddm_status._extract_decl_id` reads declaration ids back out
  of `Event.message`, and `com.acme.declaration.h:9f2c` truncates to
  `com.acme.declaration`, collapsing every declaration onto one ref. The hyphen
  form keeps the token intact, so distinct declarations stay distinct.

Both forms are salted with the same per-session secret, so a value hashed in a
field and in a message body still correlate to each other by suffix.
"""
from __future__ import annotations

import hashlib
import os
import re

_SALT = os.urandom(16)  # per-process; never persisted


def _digest(value: str) -> str:
    return hashlib.sha256(_SALT + value.encode("utf-8", "replace")).hexdigest()[:12]


def _hash(value: str) -> str:
    return "h:" + _digest(value)


def hash_id(value: str | None) -> str | None:
    if not value:
        return None
    return _hash(value)


def _inline_hash(value: str) -> str:
    """Token-safe hash for identifiers rewritten inside message text."""
    return "h-" + _digest(value)


# Standard macOS directories under /Users that are not a person's account.
_NON_USER_HOME_DIRS = frozenset({"Shared", "Guest", "Deleted Users", ".localized"})

# Secret-bearing keys. `<private>` is deliberately exempt: it is macOS's own
# masking marker, and triage.py keys the `private_data_masked` finding off it —
# scrubbing it would hide the very signal that says detail is missing.
# The optional scheme word matters: without it `Authorization: Bearer <token>`
# consumes "Bearer" as the value and leaves the token in the clear.
_RE_SECRET_KV = re.compile(
    r"(?i)\b(token|bearer|authorization|challenge|password|passwd|passphrase"
    r"|secret|api[_-]?key|private[_-]?key)\b\s*[=:]\s*"
    r"(?:(?:Bearer|Basic|Token|Digest)\s+)?(?!<private>)\S+"
)

# MAC addresses, colon or hyphen separated. Must run BEFORE the IPv6 rule, which
# would otherwise claim a MAC's six hex groups.
_RE_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# IPv6. Deliberately conservative: a rule permitting three colon-separated hex
# groups eats unified-log timestamps ("14:03:12" is three valid hex groups), so
# a match requires either a `::` compression or at least four groups.
_RE_IPV6 = re.compile(
    r"(?<![\w:.-])"
    r"(?=[0-9A-Fa-f:]*::|(?:[0-9A-Fa-f]{1,4}:){3,}[0-9A-Fa-f]{1,4}(?![\w:.-]))"
    r"[0-9A-Fa-f:]{3,}"
    r"(?![\w:.-])"
)

# Hardware UUIDs / UDIDs / declaration instance ids (8-4-4-4-12). Hashed rather
# than blanked so the model can still tell two declarations apart. Must run
# BEFORE the serial rule, which would otherwise consume only the 12-hex tail and
# leave a UUID that merely *looks* redacted.
_RE_UUID = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
)

# Home-directory paths leak the account short name.
_RE_USER_HOME = re.compile(r"(/Users/)([^/\s\"',;:)\]]+)")

# Numeric user/group ids.
_RE_UID = re.compile(r"(?i)\b(uid|gid)(\s*[=:]\s*)(\d+)")

# Account names carried as plist/JSON keys. The home-directory rule only catches
# a name inside a /Users/ path, so a command-response payload spelling it out
# ("UserLongName = jappleseed;") walked straight through — a real capture leaked
# the account name in an InstallProfile error response. Spec §4.3 requires
# usernames masked, so these are hashed rather than blanked, keeping the model
# able to tell two accounts apart.
_RE_USER_NAME_KV = re.compile(
    r'(?i)\b(UserLongName|UserShortName|UserName|AccountName|ManagedAppleID'
    r'|FullName|RealName|EmailAddress)\b(\s*[=:]\s*)"?([^"\n;,}\]]+?)"?(?=\s*[;,}\]\n]|$)'
)

# The `<User: 506>` spelling of a user id, which mdmclient uses to mark
# user-channel commands. `_RE_UID` only matches the `uid=`/`uid:` spellings.
# Hashed, not dropped: which channel a command rode on is diagnostic, and a
# stable hash still separates the device channel from a user's.
_RE_USER_ANGLE = re.compile(r"(?i)\b(User)(:\s*)(\d+)\b")


def _sub_uuid(m: re.Match) -> str:
    return _inline_hash(m.group(0))


def _sub_user_home(m: re.Match) -> str:
    name = m.group(2)
    if name in _NON_USER_HOME_DIRS:
        return m.group(0)
    return m.group(1) + _inline_hash(name)


def _sub_uid(m: re.Match) -> str:
    return m.group(1) + m.group(2) + _inline_hash(m.group(3))


def _sub_user_name(m: re.Match) -> str:
    return m.group(1) + m.group(2) + _inline_hash(m.group(3))


# Patterns for secrets/PII that must never leave toward a model. These scrub
# free-text message bodies; structured fields are hashed separately. ORDER IS
# LOAD-BEARING — see the notes on the MAC/IPv6 and UUID/serial pairs above.
_SCRUBBERS = (
    # key=value secrets (auth tokens, SCEP challenges, payload passwords)
    (_RE_SECRET_KV, r"\1=<redacted>"),
    # hardware UUIDs / UDIDs / declaration instance ids -> stable inline hash
    (_RE_UUID, _sub_uuid),
    # MAC addresses (before IPv6)
    (_RE_MAC, "<redacted-mac>"),
    # IPv6
    (_RE_IPV6, "<redacted-ip>"),
    # push tokens / long hex blobs (>= 32 hex chars)
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<redacted-hex>"),
    # email-ish usernames
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b"), "<redacted-email>"),
    # IPv4
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted-ip>"),
    # account short names in home-directory paths -> stable inline hash
    (_RE_USER_HOME, _sub_user_home),
    # numeric user/group ids -> stable inline hash
    (_RE_UID, _sub_uid),
    # account names spelled out as plist/JSON keys -> stable inline hash
    (_RE_USER_NAME_KV, _sub_user_name),
    # the "<User: 506>" spelling of a user id -> stable inline hash
    (_RE_USER_ANGLE, _sub_user_name),
    # Apple serial numbers (10-12 alnum, uppercase) — heuristic. Require BOTH a
    # letter and a digit so all-caps diagnostic words (e.g. "DEVICELOCKED",
    # "NOTNOWREASON") survive; real serials always mix the two.
    (
        re.compile(r"\b(?=[A-Z0-9]*[0-9])(?=[A-Z0-9]*[A-Z])[A-Z0-9]{10,12}\b"),
        "<redacted-serial>",
    ),
    # Long all-digit runs (>= 10 digits): IMEIs and numeric device IDs. Kept as a
    # separate rule so the alphanumeric serial rule above can require a letter
    # without letting pure-numeric identifiers leak. Error codes / adamIds are
    # shorter and unaffected.
    (re.compile(r"\b\d{10,}\b"), "<redacted-id>"),
)


def scrub_message(message: str) -> str:
    out = message or ""
    for pattern, repl in _SCRUBBERS:
        out = pattern.sub(repl, out)
    return out
