#!/bin/bash
#
# collect-mdm-logs.sh — capture macOS MDM/DDM/installer logs as NDJSON fixtures
# for the mdm-log-analyzer. Run on the SOURCE Mac (the one with MDM activity).
#
# Usage:   ./collect-mdm-logs.sh [time_window] [symptom]
# Example: ./collect-mdm-logs.sh 3h                    # everything, 3h (default)
#          ./collect-mdm-logs.sh 1h install_failure    # only what that needs
#
# The symptom mirrors build_incident_bundle's routing (engine.py _SYMPTOM_PLANS),
# so a targeted capture collects exactly the categories the analyzer will read
# for that symptom — smaller bundles, faster transfer. Valid symptoms:
#   command_failure  install_failure  profile_failure  ddm_failure
#   enrollment_failure  all (default)
#
# Note: the analyzer also accepts activity-flavoured symptoms (app_activity,
# profile_activity, ddm_activity, activity). They read the same categories as
# their failure counterparts, so capture with the matching symptom below — or
# with `all`, which stays re-queryable for any question.
#
# sudo is needed for full --info --debug detail across processes.
#
# PRIVACY: these raw exports contain identifiers (device serial/UDID, usernames,
# MDM server URL, APNs/push tokens, cert material). The analyzer redacts them on
# ingest, but THIS TARBALL IS NOT REDACTED. Transfer it over a trusted channel
# and delete it after sharing. Command detail is masked as <private> unless the
# private-data logging profile (tools/private-data-logging.mobileconfig) is
# installed first — see that file's header. This is ESPECIALLY required for DDM:
# with the profile off, remotemanagementd does not log the declaration failure
# (sync error / activation error) and it is only visible server-side.
#
set -euo pipefail

WINDOW="${1:-3h}"
SYMPTOM="${2:-all}"

# Which capture steps each symptom needs. Keep in sync with _SYMPTOM_PLANS in
# src/mdm_log_analyzer/engine.py — same routing, applied at capture time.
case "$SYMPTOM" in
  all)                WANT="mdmclient enrollment push dasd storedownloadd installd ddm install" ;;
  command_failure)    WANT="mdmclient push dasd" ;;
  # `installd` feeds the analyzer's pkg_install category, which install_failure
  # and app_activity both query — without it those plans always saw 0 events.
  # `push` is here because correlate_command pulls the push category for EVERY
  # symptom, so a bundle without apsd made it report "no APNs push correlated"
  # when the truth was that no apsd was captured.
  install_failure)    WANT="mdmclient push storedownloadd installd install" ;;
  profile_failure)    WANT="mdmclient" ;;
  ddm_failure)        WANT="mdmclient ddm" ;;
  enrollment_failure) WANT="mdmclient enrollment push" ;;
  *)
    echo "Unknown symptom '$SYMPTOM'. Valid: all command_failure install_failure \
profile_failure ddm_failure enrollment_failure" >&2
    exit 2 ;;
esac

# want <step> -> 0 if that capture step is in scope for this symptom.
want() { case " $WANT " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Timestamped so repeat captures from one Mac never collide. Without this every
# run produced "mdm-logs-<host>.tar.gz" and a second capture either overwrote
# the first or had to be told apart by which folder it was filed in — which is
# exactly how two different captures end up compared as if they were one.
# Local time, matching install.log and `log show`; the manifest records the
# offset so a bundle is unambiguous once it leaves this machine.
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="mdm-logs-$(hostname -s)-$STAMP"
mkdir -p "$OUT"
echo "Capturing the last $WINDOW ($SYMPTOM) into $OUT/ (sudo prompts are for log --debug access)…"

# OS / build — drives predicate-file selection (data/predicates/<major>.json).
sw_vers > "$OUT/os.txt"

# 1) MDM client + ManagedClient — the core: mdm_command / ddm / profile_payload.
if want mdmclient; then
  sudo log show --last "$WINDOW" --style ndjson --info --debug \
    --predicate 'processImagePath CONTAINS "mdmclient" OR subsystem CONTAINS "com.apple.ManagedClient"' \
    > "$OUT/mdmclient.ndjson" || true
fi

# 2) Enrollment — DEP/ADE (cloudconfigurationd) AND the manual profile path.
# cloudconfigurationd is DEP-only: a manual enrollment never touches it, so a
# real failed manual enrollment produced an empty enrollment.ndjson while the
# failure (HTTP 401 on MDM_Authenticate, after SCEP succeeded) sat unread in
# mdmclient's check-in lines. Mirrors data/predicates/<os>.json enrollment.
if want enrollment; then
  sudo log show --last "$WINDOW" --style ndjson --info --debug \
    --predicate 'subsystem CONTAINS "com.apple.ManagedClient.cloudconfigurationd" OR process == "cloudconfigurationd" OR (processImagePath CONTAINS "mdmclient" AND (eventMessage CONTAINS "MDM_Authenticate" OR eventMessage CONTAINS "MDM_TokenUpdate" OR eventMessage CONTAINS "MDM_CheckOut" OR eventMessage CONTAINS "MDM_SCEP_Enroll" OR eventMessage CONTAINS "Enrolling MDM" OR eventMessage CONTAINS "Unenrolling" OR eventMessage CONTAINS "DeviceEnrollment"))' \
    > "$OUT/enrollment.ndjson" || true
fi

# 3) APNs push wake/delivery.
if want push; then
  sudo log show --last "$WINDOW" --style ndjson --info \
    --predicate 'process == "apsd"' > "$OUT/push.ndjson" || true
fi

# 4) Activity scheduling/throttling (delays commands).
if want dasd; then
  sudo log show --last "$WINDOW" --style ndjson --info --debug \
    --predicate 'process == "dasd"' > "$OUT/dasd.ndjson" || true
fi

# 5) App/asset download for InstallApplication — feeds asset_download.
# storedownloadd alone is NOT enough: a device-assigned VPP install on macOS
# 26/27 is carried by appstored (subsystem com.apple.appstored), and a real 27.0
# managed-install capture logged 0 storedownloadd events while appstored did all
# the work — so the bundle showed "requested" and "installed" with no download
# telemetry in between. Keep both; storedownloadd still covers the older and
# manifest-URL paths. Mirrors data/predicates/<os>.json asset_download.
if want storedownloadd; then
  sudo log show --last "$WINDOW" --style ndjson --info --debug \
    --predicate 'process == "storedownloadd" OR process == "appstored" OR subsystem == "com.apple.appstored" OR subsystem == "com.apple.AppStoreDaemon"' \
    > "$OUT/storedownloadd.ndjson" || true
fi

# 5b) PackageKit / installer daemons — feeds the pkg_install category. Pairs
# with install.log below: install.log is the human-readable narrative, these are
# the structured events. Predicate mirrors data/predicates/<os>.json pkg_install
# — keep the two in sync.
if want installd; then
  sudo log show --last "$WINDOW" --style ndjson --info --debug \
    --predicate 'process == "installd" OR process == "installer" OR process == "system_installd" OR subsystem == "com.apple.install"' \
    > "$OUT/installd.ndjson" || true
fi

# 6) DDM declarative subsystems — feeds get_ddm_status. Centred on
# remotemanagementd (the status/activation engine) plus the pinned declarative
# subsystems, NOT just lines containing "declaration": the failure signals
# ("Failed to sync with conduit: Error Domain=…", "Error while fetching …
# ActivationPayload") come from remotemanagementd and do NOT mention
# "declaration", so the old eventMessage-only filter missed them. Needs the
# private-data logging profile ON to capture DDM failure detail (see header).
if want ddm; then
  sudo log show --last "$WINDOW" --style ndjson --info --debug \
    --predicate 'process == "remotemanagementd" OR subsystem CONTAINS "remotemanagementd" OR subsystem CONTAINS "com.apple.dmd" OR subsystem CONTAINS "SoftwareUpdateMacController" OR subsystem CONTAINS "ManagedAppDistribution" OR eventMessage CONTAINS[c] "declaration"' \
    > "$OUT/ddm.ndjson" || true
fi

# 7) Installer log (+ rotations) — feeds get_install_log.
#
# Windowed to $WINDOW, unlike the rest of install.log's history. A plain `cp`
# here shipped the whole file — 9 days and 34k lines for a 10-minute capture on
# a real Mac — which made the bundle large and, worse, let get_install_log
# report installs from days outside the window as if they were inside it.
# Rotations are still copied whole: they only matter for windows long enough to
# reach back into them, and the analyzer windows what it reads either way.
if want install; then
  if [ -r /var/log/install.log ] || sudo test -r /var/log/install.log; then
    # Cutoff in LOCAL time: install.log stamps are local ("… 10:09:43+05:30"),
    # so a UTC cutoff would be off by the machine's offset. The analyzer
    # re-windows what it reads with real timezone handling; this only keeps the
    # bundle from carrying weeks of unrelated history.
    #
    # `date -v` wants uppercase unit letters for time (S/M/H) while `log show
    # --last` wants lowercase (s/m/h) — days are `d` in both. Passing "1h"
    # straight through makes `date` fail, which yielded an empty cutoff and
    # silently kept the entire file: the no-op this whole change exists to fix.
    case "$WINDOW" in
      *s) DATE_ADJ="${WINDOW%s}S" ;;
      *m) DATE_ADJ="${WINDOW%m}M" ;;
      *h) DATE_ADJ="${WINDOW%h}H" ;;
      *d) DATE_ADJ="${WINDOW}" ;;
      *)  DATE_ADJ="" ;;
    esac
    CUTOFF=""
    if [ -n "$DATE_ADJ" ]; then
      CUTOFF="$(date -v-"$DATE_ADJ" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "")"
    fi
    if [ -z "$CUTOFF" ]; then
      echo "  warning: could not derive an install.log cutoff from '$WINDOW';" \
           "copying the whole file (the analyzer still windows what it reads)." >&2
    fi
    sudo awk -v cutoff="$CUTOFF" '
      # install.log lines start "YYYY-MM-DD HH:MM:SS±ZZ:ZZ"; lines without a
      # timestamp are continuations, kept with whatever record precedes them.
      {
        if (match($0, /^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/)) {
          stamp = substr($0, 1, 10) "T" substr($0, 12, 8)
          keep = (cutoff == "" || stamp >= cutoff)
        }
        if (keep) print
      }
    ' /var/log/install.log > "$OUT/install.log" 2>/dev/null \
      || sudo cp /var/log/install.log "$OUT/install.log" 2>/dev/null || true
  fi
  sudo cp /var/log/install.log.*.gz "$OUT/" 2>/dev/null || true
  sudo chown "$(id -un)" "$OUT"/* 2>/dev/null || true
fi

# Manifest so we can see what landed without opening the files.
{
  echo "window=$WINDOW"
  echo "symptom=$SYMPTOM"
  echo "captured=$(date +%Y-%m-%dT%H:%M:%S%z)"
  echo "host=$(hostname -s)"
  cat "$OUT/os.txt"
  for f in "$OUT"/*.ndjson; do
    [ -e "$f" ] && printf "%s\t%s lines\n" "$(basename "$f")" "$(wc -l < "$f" | tr -d ' ')"
  done
} > "$OUT/manifest.txt"

tar czf "$OUT.tar.gz" "$OUT"
rm -rf "$OUT"
echo "Done → $OUT.tar.gz ($(du -h "$OUT.tar.gz" | cut -f1)). Share this file."
