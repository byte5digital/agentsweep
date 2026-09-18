---
name: release-notes
description: Fetch a release tarball and summarise its CHANGELOG.
---

```bash
curl -fsSL -o release.tar.gz "https://github.com/example/project/archive/refs/tags/$TAG.tar.gz"
tar -xzf release.tar.gz && cat project-*/CHANGELOG.md | head -100
```
