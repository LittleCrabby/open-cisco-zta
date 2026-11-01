#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

VERSION="$(cargo metadata --format-version 1 --no-deps | grep -oP '"version":"\K[^"]+' | head -n1)"
DIST_DIR="${ROOT_DIR}/dist"
mkdir -p "${DIST_DIR}"

echo "================================================================================"
echo "          Building Packages for open-cisco-zta v${VERSION}                     "
echo "================================================================================"

BUILD_ARGS=()
if [[ "${1:-}" == "--vendored" ]]; then
    echo "[1/4] Compiling release binary with vendored OpenSSL..."
    BUILD_ARGS+=(--features vendored-openssl)
else
    echo "[1/4] Compiling release binary (system OpenSSL)..."
fi
cargo build --release "${BUILD_ARGS[@]}"

BIN_SRC="${ROOT_DIR}/target/release/open-cisco-zta"
if [[ ! -f "${BIN_SRC}" ]]; then
    echo "Error: Binary not found at ${BIN_SRC}"
    exit 1
fi

echo "[2/4] Generating standalone portable tarball..."
TAR_DIR="${DIST_DIR}/open-cisco-zta-v${VERSION}-linux-x86_64"
rm -rf "${TAR_DIR}"
mkdir -p "${TAR_DIR}"
cp "${BIN_SRC}" "${TAR_DIR}/"
cp "${ROOT_DIR}/systemd/open-cisco-zta.service" "${TAR_DIR}/"
mkdir -p "${TAR_DIR}/packaging"
cp "${ROOT_DIR}/packaging/io.github.littlecrabby.open_cisco_zta.metainfo.xml" "${TAR_DIR}/packaging/"
cp "${ROOT_DIR}/README.md" "${TAR_DIR}/"
cp "${ROOT_DIR}/LICENSE" "${TAR_DIR}/"
tar -czf "${DIST_DIR}/open-cisco-zta-v${VERSION}-linux-x86_64.tar.gz" -C "${DIST_DIR}" "open-cisco-zta-v${VERSION}-linux-x86_64"
rm -rf "${TAR_DIR}"
echo "  -> Created: ${DIST_DIR}/open-cisco-zta-v${VERSION}-linux-x86_64.tar.gz"

echo "[3/4] Building .deb package..."
if command -v cargo-deb &>/dev/null; then
    cargo deb --no-build
    cp "${ROOT_DIR}/target/debian/"*.deb "${DIST_DIR}/"
    echo "  -> Created: $(ls "${DIST_DIR}/"*.deb 2>/dev/null | tail -n1)"
else
    echo "  [SKIP] cargo-deb not found. Install with: cargo install cargo-deb"
fi

echo "[4/4] Building .rpm package..."
if command -v cargo-generate-rpm &>/dev/null; then
    cargo generate-rpm
    cp "${ROOT_DIR}/target/generate-rpm/"*.rpm "${DIST_DIR}/"
    echo "  -> Created: $(ls "${DIST_DIR}/"*.rpm 2>/dev/null | tail -n1)"
else
    echo "  [SKIP] cargo-generate-rpm not found. Install with: cargo install cargo-generate-rpm"
fi

echo ""
echo "Calculating SHA256 checksums..."
cd "${DIST_DIR}"
sha256sum *.tar.gz *.deb *.rpm 2>/dev/null > SHA256SUMS.txt || true

echo "================================================================================"
echo "Artifacts ready in: ${DIST_DIR}"
ls -lh "${DIST_DIR}"
echo "================================================================================"
