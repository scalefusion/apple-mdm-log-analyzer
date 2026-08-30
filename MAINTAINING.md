# Maintainer guide

For the person cutting releases of `mdm-log-analyzer`. Testers don't need this
file — they follow [SETUP.md](./SETUP.md); contributors follow
[CONTRIBUTING.md](./CONTRIBUTING.md).

- [Cut a release](#cut-a-release)
- [What CI does](#what-ci-does)
- [Publishing to PyPI (not yet wired)](#publishing-to-pypi-not-yet-wired)
- [How testers install](#how-testers-install)
- [Release checklist](#release-checklist)

---

## Cut a release

A release is a semver tag. CI builds the wheel and sdist and attaches them to a
GitHub Release; nothing else is required, and there are no credentials to hold.

```bash
# 1. Bump the version. This is the single source of truth.
#    Read README § Stability first: a change to what an existing field MEANS
#    is a MAJOR bump, not a patch.
$EDITOR pyproject.toml

# 2. Add a CHANGELOG entry. Anything that changed the meaning of an existing
#    response field belongs under a major version, called out explicitly.
$EDITOR CHANGELOG.md

# 3. Verify locally before tagging — CI runs the same two suites.
python3 tests/test_engine.py
pip install -e . && python3 tests/test_server_smoke.py

# 4. Commit, tag, push. The tag is what triggers the release job.
git add pyproject.toml CHANGELOG.md
git commit -m "release 1.0.1"
git tag v1.0.1
git push && git push --tags
```

The `release` job fires only on tags matching `v*`, so a stray tag like `wip`
cannot cut a release.

### Building by hand

If you need a wheel without tagging — to hand a tester a file directly:

```bash
rm -rf dist build
python -m build          # needs: pip install build
ls dist/                 # mdm_log_analyzer-<version>-py3-none-any.whl + .tar.gz
```

### Two traps worth knowing

**The version in `pyproject.toml` is what the server reports over MCP.**
`server.py` reads it with `importlib.metadata.version()`, so a client sees the
*installed* version. With an editable install that value only updates on
reinstall — the code can be newer than the number it reports. Re-run
`pip install -e .` after a bump if you are testing locally.

**A tag on the wrong commit is worse than no tag.** The wheel is built from the
tagged tree, so verify `git log --oneline -1` before tagging.

## What CI does

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml), on every push to `main`
and every pull request:

| Job | What it does |
|---|---|
| `test` | Both suites on Python 3.11 and 3.13 |
| `build` | Builds wheel + sdist, uploads as a run artifact (30 days) |
| `release` | Tags only — attaches the artifacts to a GitHub Release |

The server smoke test matters more than it looks: the engine suite is
stdlib-only and never imports `server.py`, so without the smoke test an `mcp`
SDK breaking change reaches a user before it reaches CI. That has happened once
already.

No runner setup is needed — GitHub-hosted runners are used.

## Publishing to PyPI (not yet wired)

Deliberately not enabled. Installing from a tag works today and needs no
account, no token and no index URL, so PyPI buys convenience rather than
capability.

When you do want it:

1. Check the name `mdm-log-analyzer` is free on pypi.org. If it is taken, rename
   the package in `pyproject.toml` — much cheaper before the first upload than
   after.
2. Set up **Trusted Publishing** (OIDC) on pypi.org rather than storing a token:
   Publisher → this repository, workflow `ci.yml`, environment `pypi`.
3. Uncomment the `pypi` job sketched at the bottom of `ci.yml`.

Trusted Publishing stores no long-lived credential, which is the whole reason to
prefer it over a `PYPI_API_TOKEN` secret.

## How testers install

Three paths, in the order most people should use them. All three produce the
`mcp-mdm-log-analyzer` command inside a venv. Full detail in
[SETUP.md § 3](./SETUP.md).

| Path | When |
|---|---|
| A `.whl` you hand them | Simplest; nothing to clone, no network access to the repo needed |
| `pip install "git+https://github.com/scalefusion/apple-mdm-log-analyzer.git@v1.0.0"` | Self-service upgrades; needs `git` |
| `pip install -e .` from a clone | Contributors |

## Release checklist

- [ ] `pyproject.toml` version bumped, and the bump matches README § Stability
      (a changed field *meaning* is a major)
- [ ] `CHANGELOG.md` entry added, breaking changes called out
- [ ] Both suites green locally
- [ ] `git log --oneline -1` is the commit you mean to tag
- [ ] Tag pushed; the `release` run went green and the Release has both files
- [ ] If `redact.py` changed: `tools/redaction-audit.sh` run on a real capture
      from the Mac that produced it, and the result noted
- [ ] Docs still true — `SETUP.md` install commands, README status and limits
