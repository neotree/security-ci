#!/usr/bin/env bash
# Secret scan with a scope appropriate to the event.
#
# A pull-request gate exists to stop a NEW secret being introduced. Re-scanning the whole
# history on every pull request is redundant - history does not change between them - and
# on this codebase it costs about nine minutes a run versus well under a second for the
# commits the change actually adds. Full history still runs on the schedule, where it
# belongs, and that is what catches a secret that predates the pipeline.
#
# Falls back to a full scan whenever the range cannot be established, so a shallow clone,
# a force-push or a first push is never silently scanned as "nothing to see".
set -Eeuo pipefail

SCANNER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:?usage: run_secret_scan.sh <repo-path> [base-sha]}"
BASE="${2:-}"

IGNORE="${SCANNER_DIR}/empty-gitleaks-ignore.txt"
if [ -n "${GITLEAKS_IGNORE_PATH:-}" ] && [ -f "${GITLEAKS_IGNORE_PATH}" ]; then
  IGNORE="${GITLEAKS_IGNORE_PATH}"
fi

BIN="$("${SCANNER_DIR}/install_gitleaks.sh")"

args=(git
  --config "${SCANNER_DIR}/gitleaks.toml"
  --redact --no-banner --ignore-gitleaks-allow
  --gitleaks-ignore-path "${IGNORE}"
  --max-decode-depth 3 --max-archive-depth 2)

scope="full history"
if [ -n "${BASE}" ] && [ "${BASE}" != "0000000000000000000000000000000000000000" ]; then
  if git -C "${REPO}" cat-file -e "${BASE}^{commit}" 2>/dev/null \
     && git -C "${REPO}" rev-list --quiet "${BASE}..HEAD" 2>/dev/null; then
    count="$(git -C "${REPO}" rev-list --count "${BASE}..HEAD")"
    args+=(--log-opts="${BASE}..HEAD")
    scope="${count} commit(s) introduced by this change"
  else
    echo "::warning::Base commit ${BASE} is unusable here (shallow clone or force-push);" \
         "falling back to a full-history scan."
  fi
fi

echo "Secret scan scope: ${scope}"
exec "${BIN}" "${args[@]}" "${REPO}"
