#!/bin/bash
#
# redaction-audit.sh — prove that a rendered report leaks no plaintext identifier.
#
# Usage:  ./redaction-audit.sh <report.json> [extra-secret ...]
#
# Checks the report for this Mac's real identifiers (serial, hardware UUID, MAC
# and IPv4 addresses, account short/long name, hostname), plus any extra values
# you pass — a Managed Apple ID, a SCEP challenge, an enrollment token — which
# cannot be discovered automatically.
#
# WHY THIS EXISTS: the obvious one-liner is a trap.
#
#     for V in "$SERIAL" "$MAC"; do grep -c -- "$V" report.json; done
#
# If a variable is unset, `grep -c -- ""` matches EVERY line, so the audit
# reports a large number for every value and looks like a catastrophic leak —
# or, worse, someone reads the same number for all of them, assumes it is noise,
# and concludes the report is clean. Either way nothing was tested. This script
# refuses to check an empty value and says so.
#
# Run it ON THE MAC THE CAPTURE CAME FROM. Auto-discovery finds the identifiers
# of the machine it runs on; against a capture from a different Mac every check
# passes trivially and proves nothing.
#
# Values are never printed — only a masked form — so the output is safe to paste.
#
set -uo pipefail

REPORT="${1:-}"
if [ -z "$REPORT" ]; then
  echo "usage: $0 <report.json> [extra-secret ...]" >&2
  echo "  Generate the report on THIS Mac first, e.g." >&2
  echo "    mcp-mdm-log-analyzer --report --format json --symptom activity \\" >&2
  echo "      --last 20m --source <bundle.tar.gz> > /tmp/report.json" >&2
  exit 2
fi
# Distinguish the two failures: a report generated on another machine (or under
# another account) is the common case, and "usage:" did not say so.
if [ ! -e "$REPORT" ]; then
  echo "error: $REPORT does not exist on this Mac." >&2
  echo "  The report has to be generated here, or copied here — a path that" >&2
  echo "  existed on the machine you rendered it on means nothing to this one." >&2
  exit 2
fi
if [ ! -r "$REPORT" ]; then
  echo "error: $REPORT exists but is not readable by $(id -un)." >&2
  echo "  Check ownership; do not re-run under sudo (see below)." >&2
  exit 2
fi
shift || true

# sudo is NOT needed: this script only reads a file and runs ifconfig /
# system_profiler. Worse, under sudo `id -un` is root, so the account name it
# would check is root's and the real account is never tested. Recover the
# invoking user from SUDO_USER when present.
ACCOUNT="${SUDO_USER:-$(id -un)}"
if [ -n "${SUDO_USER:-}" ]; then
  echo "note: running under sudo — auditing account '$SUDO_USER', not root."
  echo "      sudo is not required for this script."
  echo
fi

mask() {  # show enough to identify which value failed, never the value
  local v="$1"
  if [ "${#v}" -le 4 ]; then printf '****'; else printf '%s***%s' "${v:0:2}" "${v: -2}"; fi
}

FAIL=0
CHECKED=0
SKIPPED=0

check() {  # check <label> <value>
  local label="$1" value="$2"
  if [ -z "$value" ]; then
    printf '  SKIP  %-18s (not discoverable here — pass it as an argument)\n' "$label"
    SKIPPED=$((SKIPPED + 1))
    return
  fi
  local n
  n=$(grep -ioF -- "$value" "$REPORT" 2>/dev/null | wc -l | tr -d ' ')
  CHECKED=$((CHECKED + 1))
  if [ "$n" -eq 0 ]; then
    printf '  PASS  %-18s %s\n' "$label" "$(mask "$value")"
  else
    printf '  FAIL  %-18s %s appears %s time(s)\n' "$label" "$(mask "$value")" "$n"
    FAIL=$((FAIL + 1))
  fi
}

echo "Redaction audit of $REPORT"
echo "(run this on the Mac the capture came from, or the checks pass trivially)"
echo

check "serial"        "$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number/{print $2; exit}')"
check "hardware UUID" "$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Hardware UUID/{print $2; exit}')"
check "account short" "$ACCOUNT"
check "account long"  "$(id -F "$ACCOUNT" 2>/dev/null)"
check "hostname"      "$(hostname -s 2>/dev/null)"

# Every MAC and IPv4 the machine currently has.
i=0
while read -r m; do
  [ -n "$m" ] || continue
  i=$((i + 1)); check "MAC #$i" "$m"
done < <(ifconfig 2>/dev/null | awk '/ether /{print $2}' | sort -u)

i=0
while read -r a; do
  [ -n "$a" ] || continue
  case "$a" in 127.*) continue ;; esac
  i=$((i + 1)); check "IPv4 #$i" "$a"
done < <(ifconfig 2>/dev/null | awk '/inet /{print $2}' | sort -u)

# Anything that cannot be discovered: Managed Apple ID, SCEP challenge, token.
i=0
for extra in "$@"; do
  i=$((i + 1)); check "supplied #$i" "$extra"
done
[ "$#" -eq 0 ] && echo "  NOTE  no extra secrets supplied — a Managed Apple ID, SCEP" \
  && echo "        challenge or enrollment token must be passed as an argument."

echo
echo "checked=$CHECKED  skipped=$SKIPPED  leaked=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL — the report contains plaintext identifiers (spec §4.3)." >&2
  exit 1
fi
if [ "$CHECKED" -eq 0 ]; then
  echo "RESULT: INCONCLUSIVE — nothing could be checked." >&2
  exit 2
fi
echo "RESULT: PASS — no checked identifier appears in the report."
