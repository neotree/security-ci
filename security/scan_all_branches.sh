#!/usr/bin/env bash
# Scan every remote branch, not just the default one.
#
# The reported PolinRider "commit twin" technique force-pushes infected versions of
# existing commits across many branches. A payload parked on a stale feature branch is
# never seen by a pull-request gate, and is one `git checkout` away from a developer.
#
# The scanner is always the copy from the checked-out (trusted) default branch; each
# branch is extracted as inert data by extract_tree.py and never executed. Not with
# `git archive`: that honours the branch's own .gitattributes, so `export-ignore` could
# drop a committed payload from the scan.
set -Eeuo pipefail

SCANNER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="${SCANNER_ROOT}/security/scan_repo.py"
# TARGET_REPO lets the shared pipeline scan a repository checked out beside the scanner.
REPO_ROOT="$(cd -- "${TARGET_REPO:-${SCANNER_ROOT}}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# 0 means no limit. A limit is a cost control, never a silent coverage cut: exceeding it
# fails the job, because an unscanned branch is exactly where a parked payload would sit.
MAX_BRANCHES="${MAX_BRANCHES:-0}"

mapfile -t BRANCHES < <(
  git -C "${REPO_ROOT}" for-each-ref --format='%(refname:lstrip=2)' refs/remotes/origin \
    | grep -v '^origin/HEAD$'
)

if [ "${#BRANCHES[@]}" -eq 0 ]; then
  echo "No remote branches found to scan." >&2
  exit 1
fi
if [ "${MAX_BRANCHES}" -gt 0 ] && [ "${#BRANCHES[@]}" -gt "${MAX_BRANCHES}" ]; then
  echo "::error::${#BRANCHES[@]} branches exceed MAX_BRANCHES=${MAX_BRANCHES}; refusing to scan only some of them."
  exit 1
fi

echo "Scanning ${#BRANCHES[@]} branch(es)."
failed=()
for branch in "${BRANCHES[@]}"; do
  tree="${WORK}/tree"
  rm -rf "${tree}"
  mkdir -p "${tree}"
  gitlinks="${WORK}/gitlinks.txt"
  rm -f "${gitlinks}"
  if ! python3 "${SCANNER_ROOT}/security/extract_tree.py" "${REPO_ROOT}" "refs/remotes/${branch}" "${tree}" \
        --gitlinks-out "${gitlinks}"; then
    # Fail, never skip: a branch that cannot be read has not been shown to be clean.
    failed+=("${branch}")
    echo "::error::Could not extract ${branch}; it was NOT scanned."
    continue
  fi
  # Submodules are forbidden (GIT_SUBMODULE). The extracted tree has no index for the
  # scanner to find them in, so the extractor's own list decides.
  if [ -s "${gitlinks}" ]; then
    failed+=("${branch}")
    echo "::error::Branch ${branch} contains submodule/gitlink entries: $(tr '\n' ' ' < "${gitlinks}")"
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
