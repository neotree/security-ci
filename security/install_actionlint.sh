#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.7.12"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    ASSET="actionlint_${VERSION}_linux_amd64.tar.gz"
    SHA256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
    ;;
  aarch64|arm64)
    ASSET="actionlint_${VERSION}_linux_arm64.tar.gz"
    SHA256="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"
    ;;
  *)
    echo "Unsupported runner architecture for pinned actionlint binary: $ARCH" >&2
    exit 2
    ;;
esac

DEST="${RUNNER_TEMP:-/tmp}/actionlint-${VERSION}"
mkdir -p "$DEST"
TARBALL="$DEST/$ASSET"
URL="https://github.com/rhysd/actionlint/releases/download/v${VERSION}/${ASSET}"

curl --proto '=https' --tlsv1.2 --fail --location --retry 3 --silent --show-error "$URL" --output "$TARBALL"
printf '%s  %s\n' "$SHA256" "$TARBALL" | sha256sum --check --status || {
  echo "actionlint checksum verification failed" >&2
  exit 3
}
tar -xzf "$TARBALL" -C "$DEST" actionlint
chmod 0755 "$DEST/actionlint"
printf '%s\n' "$DEST/actionlint"
