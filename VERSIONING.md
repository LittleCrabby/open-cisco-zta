# Versioning & Release Guide

`open-cisco-zta` adheres strictly to **Semantic Versioning 2.0.0** (`MAJOR.MINOR.PATCH`).

---

## 📌 Versioning Rules

- **`MAJOR` (e.g., `1.0.0` -> `2.0.0`):**
  Incompatible architectural or breaking changes (e.g., breaking configuration format changes, incompatible protocol rewrites).
- **`MINOR` (e.g., `0.1.0` -> `0.2.0`):**
  New backward-compatible functionality (e.g., new OS profiles, new transport options, proxy features).
- **`PATCH` (e.g., `0.1.0` -> `0.1.1`):**
  Backward-compatible bug fixes, security updates, and performance optimizations.

---

## 🏷️ How to Create a New Release

### 1. Using the Release Script (Recommended)

A helper script is provided to automatically validate SemVer, bump versions in `Cargo.toml` and `PKGBUILD`, regenerate `Cargo.lock`, and create an annotated Git tag:

```bash
# Bump to a new version (e.g. 0.1.1)
./scripts/release.sh 0.1.1
```

Then push the release commit and Git tag:
```bash
git push origin master --tags
```

### 2. Manual Release

1. Update `version = "X.Y.Z"` in `Cargo.toml`.
2. Update `pkgver=X.Y.Z` in `packaging/arch/PKGBUILD`.
3. Run `cargo check` to synchronize `Cargo.lock`.
4. Commit and tag:
   ```bash
   git commit -am "chore(release): bump version to vX.Y.Z"
   git tag -a "vX.Y.Z" -m "Release vX.Y.Z"
   git push origin master --tags
   ```

---

## 🤖 CI/CD Pipeline Automation

Pushing a `v*` tag triggers automated multi-platform builds via **GitHub Actions** (`.github/workflows/release.yml`):

- **Linux Packages:** Builds Debian/Ubuntu (`.deb`), RedHat/Fedora (`.rpm`), and portable `.tar.gz`.
- **Windows Executable:** Compiles `open-cisco-zta.exe` and archives it into `open-cisco-zta-vX.Y.Z-windows-x86_64.zip`.
- **Release Assets:** Computes `SHA256SUMS.txt` and publishes all assets to GitHub Releases.

---

## 📦 Local Package Generation

You can build all packages locally on Linux at any time without pushing a release:

```bash
# Build .deb, .rpm, and .tar.gz into dist/
./scripts/build-packages.sh
```

Generated packages will be placed in the `dist/` folder:
- `dist/open-cisco-zta_X.Y.Z-1_amd64.deb`
- `dist/open-cisco-zta-X.Y.Z-1.x86_64.rpm`
- `dist/open-cisco-zta-vX.Y.Z-linux-x86_64.tar.gz`
- `dist/SHA256SUMS.txt`
