#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version> (e.g. 0.1.1)"
    exit 1
fi

NEW_VERSION="${1#v}" # Strip leading 'v' if provided

# Validate SemVer pattern
if [[ ! "${NEW_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Error: '${NEW_VERSION}' is not a valid Semantic Version (e.g. 0.1.1 or 1.0.0-rc.1)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

CURRENT_VERSION="$(cargo metadata --format-version 1 --no-deps | grep -oP '"version":"\K[^"]+' | head -n1)"
echo "Current version: ${CURRENT_VERSION}"
echo "Bumping to     : ${NEW_VERSION}"

# Check git status
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Warning: Working directory has uncommitted changes."
    read -p "Do you want to continue? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update Cargo.toml
sed -i "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/" Cargo.toml

# Update PKGBUILD
if [[ -f packaging/arch/PKGBUILD ]]; then
    sed -i "s/^pkgver=.*/pkgver=${NEW_VERSION}/" packaging/arch/PKGBUILD
    sed -i "s/^pkgrel=.*/pkgrel=1/" packaging/arch/PKGBUILD
fi

# Update Cargo.lock
cargo check

echo "Creating release commit and tag..."
git commit -am "chore(release): bump version to v${NEW_VERSION}" || true
git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"

echo "================================================================================"
echo "Successfully created tag v${NEW_VERSION}!"
echo "To publish the release and trigger CI/CD pipelines, run:"
echo "  git push origin main --tags"
echo "================================================================================"
