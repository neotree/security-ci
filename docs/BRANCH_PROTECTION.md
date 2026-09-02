# Required GitHub repository protection

The files in this starter provide CI checks. **A CI check cannot block a merge until GitHub branch protection/rulesets require it.**

Configure the default branch (`master`) with:

1. Require a pull request before merging.
2. Require at least one approval; use two for high-risk/production repositories.
3. Require review from Code Owners. `.github/CODEOWNERS` is wired to the real org teams:
   `@neotree/core-devs` (3 members) owns the code and the security controls,
   `@neotree/maintainers` owns organisation-level governance, and both are listed on every
   protected path so review never depends on one person being available.

   **Confirm both teams have at least Write access to this repository** under
   *Settings -> Collaborators and teams*. GitHub silently ignores a CODEOWNERS entry whose
   team has no access — the control fails open with no error shown anywhere. The scanner
   checks for placeholder owners and for missing coverage of `/security/` and
   `/.github/workflows/`, but it cannot see team permissions from inside CI.
4. Dismiss stale approvals when new commits are pushed.
5. Require approval of the most recent reviewable push.
6. Require conversation resolution.
7. Require these status checks (see the merge-queue note below):
   - **PR Malware Gate**
   - **Merge Gate**
8. Block force pushes and branch deletion.
9. Do not allow bypass of the ruleset except a tightly controlled break-glass role.
10. Enable the dependency graph, Dependabot alerts/security updates, secret scanning and push protection where your GitHub plan supports them.
11. Keep GitHub Actions workflow permissions at **Read repository contents** by default and disable "Allow GitHub Actions to create and approve pull requests" unless explicitly needed.

## Current state of this repository (checked 2026-09-02)

Three rulesets are already active, and several of the recommendations above are met:

| Already in place | Where |
| --- | --- |
| Force-push blocked (`non_fast_forward`) | master, prod, demo-prod, main, build, dev, stage, auto-deploy, all tags |
| Branch/tag deletion blocked | same |
| Pull request required, 1 approving review | `master` ruleset |
| Stale approvals dismissed on push | `master` ruleset |
| Extra approval for unattributed changes | `master` ruleset |
| No bypass actors on any ruleset | all three |

Force-push protection matters more than it looks: the reported "commit twin" technique
force-pushes infected versions of existing commits, and that is already blocked here on
every deployment branch.

**Four settings still need changing**, all on the `master` ruleset:

| Setting | Now | Needs to be | Why |
| --- | --- | --- | --- |
| `require_code_owner_review` | `false` | **`true`** | Until this is on, `.github/CODEOWNERS` has no effect at all and security-control changes need no security review |
| *required status checks* | *rule absent* | **add `PR Malware Gate` + `Merge Gate`** | Without it every job reports but nothing blocks; the pipeline is advisory only |
| `require_last_push_approval` | `false` | `true` | Stops a final push landing after approval |
| `required_review_thread_resolution` | `false` | `true` | Unresolved review comments cannot be merged past |

### Sequencing

A status check cannot be marked required until GitHub has seen it report at least once. So:

1. Merge this pipeline to `master`. The trusted gate cannot protect its own introduction —
   `pull_request_target` runs the workflow from the *base* branch, which does not have it yet.
2. Open one throwaway pull request and let the workflows run end to end.
3. Then add the required status checks and flip the three review settings above.

Until step 3, everything here reports and nothing blocks.

## Merge queue

`PR Malware Gate` runs on `pull_request_target`, which has **no merge-queue equivalent**: it can never report a result for a `merge_group` event.

If you enable GitHub Merge Queue, requiring `PR Malware Gate` as a merge-queue status check will leave queued pull requests waiting for a check that never arrives, until they time out.

So:

- **Require `PR Malware Gate` for pull requests.** It is a pre-queue gate: a PR cannot be approved or queued without it.
- **Require only `Merge Gate` inside the merge queue.** `Security CI` handles `merge_group` and re-runs the full scanner, secret scan, SAST, dependency and build checks against the merged result.

If you do not use a merge queue, require both checks and additionally require branches to be up to date before merging.

## Security-control changes

The trusted `pull_request_target` gate blocks changes to the following:

- `.github/workflows/**` and `.github/actions/**`
- `security/**`
- `.github/CODEOWNERS`, `.github/dependabot.yml`
- `.npmrc`, `.yarnrc*`, `.pnpmfile*`, `pnpm-workspace.yaml`, `.semgrepignore`, `.gitleaksignore`, `.osv-scanner.toml`
- `packageManager`, lifecycle scripts and `ci:prepare` in any `package.json`

### Granting a review for a control change

A plain `security-reviewed` label would survive later pushes to the same pull request, so a reviewed control change could be swapped for an unreviewed one. The grant is therefore **bound to a commit**:

1. Review the control change in full.
2. Add the label `security-reviewed:<first 7 characters of the head SHA>`, e.g. `security-reviewed:a1b2c3d`.
3. Any subsequent push changes the head SHA, the grant no longer matches, and the block applies again.

The label is **not** a substitute for Code Owner approval. It records that a security maintainer looked at this exact commit.

## Optional repository variables

- `ENABLE_CODEQL=false` — only if CodeQL/code scanning is unavailable. Secure default is enabled.
- `ENABLE_DEPENDENCY_REVIEW=false` — only if GitHub Dependency Review is unavailable. OSV and package-manager audits still run.
- `ENABLE_SCORECARD=false` — disables the scheduled OpenSSF Scorecard job (it needs a public repository).
- `ENABLE_ALL_BRANCH_SCAN=false` — disables the scheduled all-branch malware scan. Leave it on: it is the only control that sees branches no pull request has touched.

## Bootstrap

The trusted PR workflow must already exist on the default branch to protect later pull requests. For the first installation, have an administrator/security maintainer merge this baseline through an already-trusted process, then immediately enable the ruleset above.
