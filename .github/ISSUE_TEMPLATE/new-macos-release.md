---
name: New macOS release support
about: Supporting a new macOS major is a data change (a new predicates file). This collects what is needed to write one without guessing.
labels: macos-support
title: 'macOS <version> support: '
---

<!-- Supporting a new macOS major is a data change: a new
     data/predicates/<os_major>.json. This template collects what is needed to
     write one without guessing. -->

### Release

- macOS version and build:
- Device type (Apple silicon / Intel, supervised / DEP / manual enrollment):

### Command bracket format

<!-- Paste a few `[Status(CommandType):n]` lines from mdmclient, with values
     redacted. Confirm whether the format matches earlier releases. -->

### Declarative subsystems

<!-- Which subsystems produced events on a DDM-ACTIVE device? The set is
     version-sensitive and is the usual thing that drifts. -->

### Anything that moved

<!-- e.g. asset_download moved from storedownloadd to appstored on 26/27;
     enrollment for the manual path is not in cloudconfigurationd. -->

### Checklist

- [ ] Captured with the private-data logging profile deployed
- [ ] Captured with `sudo` (default level returns far fewer mdmclient events)
- [ ] Device actually had DDM declarations active, if reporting on DDM
