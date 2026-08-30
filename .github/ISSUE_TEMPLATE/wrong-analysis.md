---
name: Wrong analysis
about: The tool reported something false — a clean window that was not clean, a wrong package, a missing failure. The most valuable kind of report.
labels: bug, wrong-analysis
title: 'Wrong analysis: '
---

<!-- For when the tool reports something false: a clean window that was not
     clean, a wrong package, a wrong outcome, a missing failure. This is the
     most valuable kind of report. -->

### What the tool said

<!-- Paste the finding / tally / timeline, not a screenshot. -->

### What the log actually contained

<!-- The log line(s) that contradict it. Redact by hand if needed. -->

### How you know

<!-- e.g. "grepped the bundle for the status bracket and counted 9" -->

### Environment

- macOS version and build of the **captured** machine:
- Analyzer version (`pip show mdm-log-analyzer`):
- Source type: live / .logarchive / collect-mdm-logs.sh bundle / .ndjson
- Symptom and window used:

### Checklist

- [ ] No raw capture attached (see CONTRIBUTING.md — captures contain serials,
      UUIDs, usernames, tokens and certificate material)
- [ ] Any pasted report was checked with `tools/redaction-audit.sh`
