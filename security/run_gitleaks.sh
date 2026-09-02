#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-.}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GITLEAKS_BIN="$("$SCRIPT_DIR/install_gitleaks.sh")"
exec "$GITLEAKS_BIN" git \
  --config "$SCRIPT_DIR/gitleaks.toml" \
  --redact \
  --no-banner \
  --ignore-gitleaks-allow \
  --gitleaks-ignore-path "$SCRIPT_DIR/gitleaks-ignore.txt" \
  --max-decode-depth 3 \
  --max-archive-depth 2 \
  "$ROOT"
