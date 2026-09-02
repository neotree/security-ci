#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="8.30.1"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    ASSET="gitleaks_${VERSION}_linux_x64.tar.gz"
    SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    ;;
  aarch64|arm64)
    ASSET="gitleaks_${VERSION}_linux_arm64.tar.gz"
    SHA256="e4a487f82e1e4881fe79c9f9ef15a703c008d271a0b143bc8e4e6d55e5259ad1"
    ;;
  *)
    echo "Unsupported runner architecture for pinned Gitleaks binary: $ARCH" >&2
    exit 2
    ;;
esac

DEST="${RUNNER_TEMP:-/tmp}/gitleaks-${VERSION}"
mkdir -p "$DEST"
TARBALL="$DEST/$ASSET"
URL="https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${ASSET}"

curl --proto '=https' --tlsv1.2 --fail --location --retry 3 --silent --show-error "$URL" --output "$TARBALL"
printf '%s  %s\n' "$SHA256" "$TARBALL" | sha256sum --check --status || {
  echo "Gitleaks checksum verification failed" >&2
  exit 3
}
tar -xzf "$TARBALL" -C "$DEST" gitleaks
chmod 0755 "$DEST/gitleaks"
printf '%s\n' "$DEST/gitleaks"
