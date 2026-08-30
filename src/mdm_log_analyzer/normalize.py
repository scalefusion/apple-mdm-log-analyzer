"""Normalize a raw `log show` dict into the Event schema (spec section 6).

The MDM field extraction (command type / uuid / status / error) is heuristic and
version-sensitive: unified-log message text is not a stable API. Patterns live
here so they can be tuned per macOS build alongside the predicate table.
"""
from __future__ import annotations

import re
from typing import Optional

from .parser import to_iso_utc
from .redact import hash_id, scrub_message
from .schema import Event

_RE_UUID = re.compile(r"CommandUUID[=:]\s*([0-9A-Za-z\-]+)")
_RE_REQTYPE = re.compile(r"RequestType[=:]\s*([0-9A-Za-z]+)")
_RE_STATUS = re.compile(r"Status[=:]\s*([A-Za-z]+)")
_RE_ERRCODE = re.compile(r"ErrorCode[=:]\s*(\d+)")
_RE_SERIAL = re.compile(r"(?:SerialNumber|Serial)[=:]\s*([A-Z0-9]+)")
# DDM declaration identifier, heuristic.
_RE_DECL = re.compile(r"[Dd]eclaration[=:]\s*([0-9A-Za-z._\-]+)")

# Modern mdmclient format — validated against real logs on macOS 11.7.10
# (20G1427), 14.0 (23A344), 15.6.1 (24G90) and 26.5.1 (25F80); the shape is
# identical across all four (the bracket goes back at least to Big Sur).
# The command status + type ride in a check-in bracket, e.g.
# "[Acknowledged(InstallProfile):0]", "[Error(InstallProfile):0]", or bare
# "[Idle]" when no command is pending. On receipt the line reads
# "Processing server request: <Type> for: <Device>". The old
# CommandUUID=/RequestType=/Status= phrasing is essentially absent on these
# builds. There is NO protocol-level CommandUUID, BUT two correlation keys exist:
#   1. A per-check-in SEQUENCE number shared by the receipt line
#      "Processing server request: <Type> for: <Device> (12804726)" and the
#      result bracket "[Acknowledged(<Type>):12804726]" — this ties receipt→result.
#   2. For InstallApplication, an operation UUID logged as "UUID:"/"ID:" (e.g.
#      "StartInstall using UUID: 47F5…", "InstallApplication (UUID:47F5…)",
#      "submitManifestRequest … ID: 47F5…") that threads the app-install sub-steps.
# normalize.py extracts both so correlate_command can stitch deterministically
# instead of guessing by time window. (Verified on real macOS logs.)
_RE_BRACKET_STATUS = re.compile(
    r"\[(?P<status>Acknowledged|Error|NotNow|Idle|CommandFormatError)"
    r"(?:\((?P<ctype>[A-Za-z]+)\))?(?::\d+)?\]"
)
_RE_SERVER_REQUEST = re.compile(r"Processing server request:\s*([A-Za-z]+)")
# Operation UUID logged as "UUID:" / "ID:" followed by a standard 8-4-4-4-12.
_RE_OP_UUID = re.compile(
    r"(?:UUID|ID):\s*([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})"
)
# Per-check-in sequence number: the result bracket "[Status(Type):n]" and the
# receipt "Processing server request: <Type> for: <…> (n)".
_RE_SEQ_BRACKET = re.compile(
    r"\[(?:Acknowledged|Error|NotNow|Idle|CommandFormatError)"
    r"(?:\([A-Za-z]+\))?:(\d+)\]"
)
_RE_SEQ_RECEIPT = re.compile(r"Processing server request:.*?for:\s*<[^>]*>\s*\((\d+)\)")

# WHY a command was deferred. The `[NotNow(Type):n]` bracket says only that it
# was; the reason rides on a separate line with no bracket and no sequence
# number, and is not masked:
#   Responding 'NotNow' to server request: ProfileList for: <Device>
#           reason: Not supported during DarkWake
# Validated on a real macOS 27.0 (26A5416b) capture. Without this the tool could
# report "NotNow x2" and not one reason, which is the count, not the diagnosis.
_RE_RESPONDING = re.compile(
    r"Responding\s+'(?P<status>Acknowledged|Error|NotNow|Idle|CommandFormatError)'"
    r"\s+to server request:\s*(?P<ctype>[A-Za-z]+)"
    r"(?:.*?\breason:\s*(?P<reason>[^\n]+))?"
)

# --- managed-app install phases (mdmclient `ManagedApps` subsystem) ----------
#
# An InstallApplication that the device accepts can still fail later, inside
# PackageKit, and that failure is logged ONLY here — never in install.log,
# because installd never opens a session when the package is rejected up front.
# Validated against a real macOS 26.6.1 (25G76) capture:
#
#   [ERROR] […ManagedApps…] Aborting app install: Package signature cannot be
#           verified <PKInstallErrorDomain:100>
#   Install phase 97 (<uuid>) completed. Result: <Abort> ==> Package signature
#           cannot be verified <PKInstallErrorDomain:100>
#   Install '<uuid>' finished.  Sucess: no  Error: { code = 100; domain =
#           PKInstallErrorDomain; userInfo = { NSLocalizedDescription = "…" } }
#   Processing install phase 99 for <uuid> ==> { "__Error__" = { code = 100; … };
#           "__Success__" = 0; }
#   <ASDApp…>: {bundleID = com.example.app; installed = 0; installError = Error
#           Domain=PKInstallErrorDomain Code=100 "Authorisation is required…"}
#
# Note the log's own misspelling "Sucess:" — matched literally below, since
# matching the corrected spelling would silently miss every real line.
_RE_PK_INLINE = re.compile(r"<([A-Za-z]*ErrorDomain):(-?\d+)>")
# Any domain, not only names ending in "ErrorDomain". Real ones include
# MDMResponseStatus, CPProfile, MDMClientError and MCMDMErrorDomain — the old
# `[A-Za-z.]*ErrorDomain` shape missed the 401 that fails a manual enrollment.
_RE_PK_DOMAIN = re.compile(
    r"Error Domain=([A-Za-z][A-Za-z0-9._]*)\s+Code=(-?\d+)"
)
_RE_PK_DICT = re.compile(r"code\s*=\s*(-?\d+);\s*\n?\s*domain\s*=\s*([A-Za-z.]*ErrorDomain)")
_RE_NSDESC = re.compile(r'NSLocalizedDescription\s*=\s*"?([^";\n]+?)"?\s*[;\n}]')
_RE_ABORT = re.compile(r"Aborting app install:\s*(.+?)\s*<[A-Za-z]*ErrorDomain:-?\d+>")
_RE_ABORT_RESULT = re.compile(
    r"Result:\s*<Abort>\s*==>\s*(.+?)\s*<[A-Za-z]*ErrorDomain:-?\d+>"
)
_RE_INSTALL_FINISHED = re.compile(
    r"Install\s+'([0-9A-Fa-f-]{36})'\s+finished\.\s+Suc+ess:\s*(yes|no)", re.I
)
_RE_INSTALL_PHASE = re.compile(
    r"[Ii]nstall phase\s+\d+\s+(?:for\s+|\()([0-9A-Fa-f-]{36})\)?"
)
# The line that OPENS a managed-app install operation. It carries the operation
# uuid but no phase number, so it was read only as a generic "UUID:" match: it
# got a command_uuid, no install id and no command type, which made it its own
# group and produced a second timeline for the same round-trip.
_RE_INSTALL_START = re.compile(
    r"(?:StartInstall\s+using\s+UUID|InstallApplication\s*\(UUID)\s*:\s*"
    r"([0-9A-Fa-f-]{36})"
)
_RE_SUCCESS_FLAG = re.compile(r'"__Success__"\s*=\s*(\d+)')
_RE_APP_BUNDLE_ID = re.compile(r"bundleID\s*=\s*([A-Za-z0-9][A-Za-z0-9._\-]*)")

# mdmclient's own check-in transport, e.g.
#   <<<<< Received HTTP response (401) [MDM_Authenticate] <<<<<
# The bracket here is the REQUEST TYPE, not a command status, so nothing read
# it. A non-2xx on MDM_Authenticate is exactly how a manual enrollment fails.
_RE_CHECKIN_RESPONSE = re.compile(
    r"Received HTTP response\s*\((?P<code>\d{3})\)\s*\[(?P<ctype>MDM_[A-Za-z]+)\]"
)
# The ASD notification is the only line that names the failing app, so it has to
# count as a failure in its own right — otherwise the bundle id never reaches
# notable_errors and the report says an install failed without saying which.
_RE_ASD_NOT_INSTALLED = re.compile(r"installed\s*=\s*0\b")

# --- ErrorChain: the reason a command failed ---------------------------------
#
# The `[Status(Type):n]` bracket says a command failed; the ErrorChain says why,
# and on a real macOS 26.6.1 capture it is NOT masked even without the
# private-data profile. Two shapes, both validated against that capture:
#
#   [ERROR] […MDMAgent…] [ErrorChain.0] (InstallProfile) [CPProfile:-102] The
#           profile is either missing some required information or contains
#           information in an invalid format.>
#   [ERROR] […MDMAgent…] Error in pending response: {
#       CommandUUID = 13273055;
#       ErrorChain = ( { ErrorCode = "-102"; ErrorDomain = CPProfile;
#                        LocalizedDescription = "…"; } );
#       RequestType = InstallProfile; Status = Error; … }
#
# The response-payload spelling uses `Key = Value` with spaces, which the older
# `Key[=:]` patterns above do not match — hence separate, space-tolerant ones.
# Note `CommandUUID` here is the numeric check-in sequence, not a UUID.
_RE_CHAIN_INLINE = re.compile(
    r"\[ErrorChain\.\d+\]\s*\((?P<ctype>[A-Za-z]+)\)\s*"
    r"\[(?P<domain>[A-Za-z]+):(?P<code>-?\d+)\]\s*(?P<desc>[^\n]*?)\s*>?\s*$"
)
_RE_RESP_REQTYPE = re.compile(r"RequestType\s*=\s*([A-Za-z]+)\s*;")
_RE_RESP_STATUS = re.compile(r"Status\s*=\s*([A-Za-z]+)\s*;")
_RE_RESP_ERRCODE = re.compile(r'ErrorCode\s*=\s*"?(-?\d+)"?\s*;')
_RE_RESP_DESC = re.compile(r'LocalizedDescription\s*=\s*"([^"]+)"')
_RE_RESP_CMDID = re.compile(r'CommandUUID\s*=\s*"?([0-9A-Za-z\-]+)"?\s*;')
# The quoted description that trails `Error Domain=… Code=N`.
_RE_PK_DOMAIN_DESC = re.compile(
    r'Error Domain=[A-Za-z][A-Za-z0-9._]*\s+Code=-?\d+\s+\\?"([^"\\]+)'
)
_RE_ASD_INSTALL_ERROR = re.compile(r"installError\s*=\s*Error")


def _process_name(raw: dict) -> str:
    if raw.get("process"):
        return raw["process"]
    path = raw.get("processImagePath", "")
    return path.rsplit("/", 1)[-1] if path else "unknown"


def _raw_ref(raw: dict, index: int) -> str:
    """A pointer back into the source that is unique PER LINE.

    `traceID` alone is not: it identifies the emitting code site (the format
    string), so thousands of distinct events share one value — 452 distinct
    traceIDs across 17,019 real mdmclient lines. Deduping by it collapsed
    genuinely different errors into one and dropped real events from timelines.
    `machTimestamp` is a per-event monotonic counter, so the pair is unique
    (verified: 17,019 unique pairs over those same lines) while staying
    intrinsic to the line — and therefore stable when the same line is fetched
    again under a different predicate category, which is what cross-category
    de-duplication relies on. Never carries raw log text (spec §6).
    """
    trace = raw.get("traceID")
    mach = raw.get("machTimestamp")
    if trace is not None and mach is not None:
        return f"{trace}:{mach}"
    if trace is not None:
        # No machTimestamp: fall back to the timestamp, which is still
        # intrinsic, before resorting to a fetch-relative index.
        ts = raw.get("timestamp")
        return f"{trace}:{ts}" if ts else f"{trace}#{index}"
    return f"{_process_name(raw)}#{index}"


def _message_type(raw: dict) -> str:
    mt = (raw.get("messageType") or raw.get("eventType") or "default").lower()
    if mt == "logevent":
        mt = "default"
    return mt


def normalize(raw: dict, category: str, index: int = 0) -> Event:
    message = raw.get("eventMessage", "") or ""

    uuid_m = _RE_UUID.search(message)
    op_uuid_m = _RE_OP_UUID.search(message)
    reqtype_m = _RE_REQTYPE.search(message)
    status_m = _RE_STATUS.search(message)
    errcode_m = _RE_ERRCODE.search(message)
    serial_m = _RE_SERIAL.search(message)
    decl_m = _RE_DECL.search(message)
    bracket_m = _RE_BRACKET_STATUS.search(message)
    server_req_m = _RE_SERVER_REQUEST.search(message)
    seq_m = _RE_SEQ_BRACKET.search(message) or _RE_SEQ_RECEIPT.search(message)

    # command_type: prefer old RequestType=, then macOS 26 "Processing server
    # request: <Type>" and the "[Status(Type):n]" bracket, then DDM declaration.
    command_type = reqtype_m.group(1) if reqtype_m else None
    if command_type is None and server_req_m:
        command_type = server_req_m.group(1)
    if command_type is None and bracket_m and bracket_m.group("ctype"):
        command_type = bracket_m.group("ctype")
    if command_type is None and decl_m:
        command_type = "Declaration:" + decl_m.group(1)

    # status: old Status= first, else the macOS 26 check-in bracket.
    status = status_m.group(1) if status_m else (
        bracket_m.group("status") if bracket_m else None
    )
    error_code = int(errcode_m.group(1)) if errcode_m else None

    reason = None
    if status == "Error":
        if error_code is not None:
            reason = f"Error {error_code}"
        elif command_type:
            reason = f"Error ({command_type})"

    # --- managed-app install failure (ManagedApps / PKInstallErrorDomain) ----
    # These lines carry no check-in bracket, so without this block they
    # normalize to a plain message with no status — invisible to the outcome
    # tally, to notable_errors, and to triage. An aborted managed-app install is
    # exactly the failure an "app installation errors" query must surface.
    app_id = None
    install_uuid = None
    abort_reason = None
    pk_code = None

    phase_m = _RE_INSTALL_PHASE.search(message)
    finished_m = _RE_INSTALL_FINISHED.search(message)
    start_m = _RE_INSTALL_START.search(message)
    if phase_m or finished_m or start_m:
        install_uuid = (
            phase_m.group(1)
            if phase_m
            else (finished_m.group(1) if finished_m else start_m.group(1))
        )

    inline_m = _RE_PK_INLINE.search(message)
    domain_m = _RE_PK_DOMAIN.search(message)
    dict_m = _RE_PK_DICT.search(message)
    if inline_m:
        pk_code = int(inline_m.group(2))
    elif domain_m:
        pk_code = int(domain_m.group(2))
    elif dict_m:
        pk_code = int(dict_m.group(1))

    abort_m = _RE_ABORT.search(message) or _RE_ABORT_RESULT.search(message)
    if abort_m:
        abort_reason = abort_m.group(1).strip()
    elif pk_code is not None:
        desc_m = _RE_NSDESC.search(message) or _RE_PK_DOMAIN_DESC.search(message)
        if desc_m:
            abort_reason = desc_m.group(1).strip()

    success_m = _RE_SUCCESS_FLAG.search(message)
    app_failed = bool(
        abort_m
        or (finished_m and finished_m.group(2).lower() == "no")
        or (success_m and success_m.group(1) == "0")
        or (_RE_ASD_NOT_INSTALLED.search(message)
            and _RE_ASD_INSTALL_ERROR.search(message))
    )
    # The success side, symmetric with app_failed above. Without it a managed
    # app install that WORKED produced phase lines carrying an operation uuid
    # and no status at all, so the correlated timeline found no terminal event,
    # reported `outcome: Idle`, and raised `no_terminal` — "received but reached
    # no terminal status" for an install that had plainly finished.
    app_succeeded = not app_failed and bool(
        (finished_m and finished_m.group(2).lower() == "yes")
        or (success_m and success_m.group(1) == "1")
    )
    app_id_m = _RE_APP_BUNDLE_ID.search(message)
    if app_id_m:
        app_id = app_id_m.group(1)

    if pk_code is not None and error_code is None:
        error_code = pk_code
    if install_uuid and uuid_m is None and op_uuid_m is None:
        uuid_val_override = install_uuid
    else:
        uuid_val_override = None
    # Any managed-app install line belongs to an InstallApplication operation,
    # whatever its outcome — labelling only the failures left successful
    # timelines with `command_type: null`. The App Store notification carries no
    # phase marker of its own, so app_failed/app_succeeded count too.
    if command_type is None and (
        phase_m or finished_m or start_m or success_m or app_failed or app_succeeded
    ):
        command_type = "InstallApplication"
    if app_failed:
        # The install *operation* failed. The InstallApplication command itself
        # may well have been Acknowledged earlier — that is the point: the
        # command succeeded and the install did not.
        if status is None:
            status = "Error"
        if abort_reason:
            reason = abort_reason
        elif reason is None and error_code is not None:
            reason = f"Error {error_code}"
    elif app_succeeded and status is None:
        status = "Acknowledged"

    # --- check-in transport result (enrollment lives here) -------------------
    checkin_m = _RE_CHECKIN_RESPONSE.search(message)
    if checkin_m:
        http_code = int(checkin_m.group("code"))
        if command_type is None:
            command_type = checkin_m.group("ctype")
        if http_code >= 400:
            # A refused check-in IS the failure — there is no other line that
            # states it as one. 2xx is left unmarked so ordinary check-in
            # chatter does not inflate the command tally.
            if status is None:
                status = "Error"
            if error_code is None:
                error_code = http_code
            if reason is None:
                reason = f"HTTP {http_code} on {checkin_m.group('ctype')}"

    # --- deferral reason ("Responding 'NotNow' … reason: …") ------------------
    responding_m = _RE_RESPONDING.search(message)
    if responding_m:
        if command_type is None:
            command_type = responding_m.group("ctype")
        why = responding_m.group("reason")
        if why:
            reason = f"{responding_m.group('status')}: {why.strip()}"
        # Status deliberately NOT set: this line carries no sequence number, and
        # the command it explains is already counted via its status bracket.
        # Setting one here tallied a third NotNow for two deferred commands.

    # --- ErrorChain / command response payload ------------------------------
    chain_m = _RE_CHAIN_INLINE.search(message)
    if chain_m:
        # Detail about a command already counted via its status bracket, so the
        # status is deliberately NOT set here: these lines carry no sequence
        # number, and marking them Error would tally each one as its own failed
        # command. They surface through notable_errors on error_code + reason.
        if command_type is None:
            command_type = chain_m.group("ctype")
        if error_code is None:
            error_code = int(chain_m.group("code"))
        desc = chain_m.group("desc").strip()
        if desc:
            reason = f"[{chain_m.group('domain')}:{chain_m.group('code')}] " + desc

    resp_status_m = _RE_RESP_STATUS.search(message)
    resp_type_m = _RE_RESP_REQTYPE.search(message)
    if resp_status_m and resp_type_m:
        # The full command response payload. Unlike the inline chain this DOES
        # carry the command's identity, so it can be attributed and counted.
        if command_type is None:
            command_type = resp_type_m.group(1)
        if status is None:
            status = resp_status_m.group(1)
        resp_code_m = _RE_RESP_ERRCODE.search(message)
        if resp_code_m and error_code is None:
            error_code = int(resp_code_m.group(1))
        resp_desc_m = _RE_RESP_DESC.search(message)
        if resp_desc_m:
            reason = resp_desc_m.group(1).strip()
        resp_id_m = _RE_RESP_CMDID.search(message)
        if resp_id_m:
            ident = resp_id_m.group(1)
            if ident.isdigit():
                seq_m = seq_m or re.match(r"(\d+)", ident)
            elif uuid_m is None and op_uuid_m is None:
                uuid_val_override = ident

    raw_ref = _raw_ref(raw, index)

    # command_uuid: legacy CommandUUID= first, else the modern operation UUID
    # (UUID:/ID:). Hashed like any identifier.
    uuid_val = uuid_m.group(1) if uuid_m else (op_uuid_m.group(1) if op_uuid_m else None)
    if uuid_val is None:
        uuid_val = uuid_val_override

    return Event(
        timestamp=to_iso_utc(raw.get("timestamp", "")),
        process=_process_name(raw),
        subsystem=raw.get("subsystem"),
        category=category,
        message_type=_message_type(raw),
        message=scrub_message(message),
        command_type=command_type,
        command_uuid=hash_id(uuid_val) if uuid_val else None,
        command_seq=seq_m.group(1) if seq_m else None,
        status=status,
        error_code=error_code,
        # Scrubbed like any message text: an ErrorChain description quotes the
        # profile identifier that failed ("Profile with identifier '<uuid>-user'
        # not found"), which the redaction allowlist must still cover.
        reason=scrub_message(reason) if reason else None,
        device_ref=hash_id(serial_m.group(1)) if serial_m else None,
        app_id=app_id,
        install_uuid=hash_id(install_uuid) if install_uuid else None,
        raw_ref=str(raw_ref),
    )
