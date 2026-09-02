#!/usr/bin/env bash
# Scan every remote branch, not just the default one.
#
# The reported PolinRider "commit twin" technique force-pushes infected versions of
# existing commits across many branches. A payload parked on a stale feature branch is
# never seen by a pull-request gate, and is one `git checkout` away from a developer.
#
# The scanner is always the copy from the checked-out (trusted) default branch; each
# branch is extracted as inert data with `git archive` and never executed.
set -Eeuo pipefail

SCANNER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="${SCANNER_ROOT}/security/scan_repo.py"
# TARGET_REPO lets the shared pipeline scan a repository checked out beside the scanner.
REPO_ROOT="$(cd -- "${TARGET_REPO:-${SCANNER_ROOT}}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

MAX_BRANCHES="${MAX_BRANCHES:-200}"

mapfile -t BRANCHES < <(
  git -C "${REPO_ROOT}" for-each-ref --format='%(refname:short)' refs/remotes/origin \
    | grep -v '^origin/HEAD$' \
    | head -n "${MAX_BRANCHES}"
)

if [ "${#BRANCHES[@]}" -eq 0 ]; then
  echo "No remote branches found to scan." >&2
  exit 1
fi

echo "Scanning ${#BRANCHES[@]} branch(es)."
failed=()
for branch in "${BRANCHES[@]}"; do
  tree="${WORK}/tree"
  rm -rf "${tree}"
  mkdir -p "${tree}"
  if ! git -C "${REPO_ROOT}" archive --format=tar "${branch}" | tar -x -C "${tree}" 2>/dev/null; then
    echo "::warning::Could not extract ${branch}; skipping."
    continue
  fi
  echo "::group::${branch}"
  args=(--root "${tree}" --policy "${SCANNER_ROOT}/security/policy.defaults.json"
        --iocs "${SCANNER_ROOT}/security/polinrider_iocs.json")
  if [ -n "${POLICY_OVERLAY:-}" ] && [ -f "${REPO_ROOT}/${POLICY_OVERLAY}" ]; then
    args+=(--policy-overlay "${REPO_ROOT}/${POLICY_OVERLAY}")
  fi
  if python3 "${SCANNER}" "${args[@]}"; then
    echo "OK ${branch}"
  else
    failed+=("${branch}")
    echo "::error::Policy violation on branch ${branch}"
  fi
  echo "::endgroup::"
done

if [ "${#failed[@]}" -gt 0 ]; then
  echo
  echo "Branches with blocking findings: ${failed[*]}"
  exit 1
fi
echo
echo "All ${#BRANCHES[@]} branch(es) passed."
