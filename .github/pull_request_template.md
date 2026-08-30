### What this changes

### Why

<!-- If a real capture exposed this, say what the tool claimed and what the log
     actually said. That framing is how the rest of this codebase is documented. -->

### Verification

```
$ python3 tests/test_engine.py
<paste the result>
```

<!-- If you could not verify part of it (no Mac, no DDM-active device, no
     reproduction), say which part rather than leaving it implied. -->

### Checklist

- [ ] Engine suite green
- [ ] Regression test added, written from the real log shape
- [ ] Works across Live / Archive / Bundle / Fixture with no source-specific branch
- [ ] No new dependency (the engine is stdlib-only; `mcp` is the sole runtime dep)
- [ ] If `redact.py` changed: `tools/redaction-audit.sh` run on a real capture
- [ ] If a tool's return shape changed: called out above
