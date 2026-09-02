# Adopting the shared pipeline in a repository

Four files to add, one SHA to set, then branch protection. Budget an hour for the first
repository and about fifteen minutes for each one after.

## 1. Pick the SHA

Everything is pinned to a commit of `neotree/security-ci`. Get the current one:

```bash
git ls-remote https://github.com/neotree/security-ci refs/heads/main
```

That 40-character SHA goes in **two places per workflow**: the `uses:` line and the
`security-ci-ref` input. They must match. The gate refuses to run if the ref is not a full
SHA, because a branch or tag can be moved and the whole trust model rests on that pin.

## 2. Copy the files

| From `templates/` | To, in the target repository |
| --- | --- |
| `workflows/security-ci.yml` | `.github/workflows/security-ci.yml` |
| `workflows/pr-malware-gate.yml` | `.github/workflows/pr-malware-gate.yml` |
| `workflows/scheduled-security.yml` | `.github/workflows/scheduled-security.yml` |
| `policy.json` | `security/policy.json` |
| `gitleaks-ignore.txt` | `security/gitleaks-ignore.txt` |
| `github/CODEOWNERS` | `.github/CODEOWNERS` |
| `dependabot.yml` | `.github/dependabot.yml` |

Replace every `0000000000000000000000000000000000000000` with the SHA from step 1.

## 3. Make the repository satisfiable

The project runner requires a `lint` script, and a `typecheck` script when TypeScript is
present. It runs `test` and `build` only if those scripts exist, so a repository without
them is fine.

```json
{ "scripts": { "lint": "eslint .", "typecheck": "tsc --noEmit" } }
```

**Native modules need a `ci:prepare` script.** Dependencies install with lifecycle scripts
disabled, so anything whose binary is produced by its own `install` hook will be missing.
This bit `neotree-editor`: `bcrypt` failed at build time until `ci:prepare` was added.

```json
{ "scripts": { "ci:prepare": "prisma generate && npm rebuild bcrypt" } }
```

## 4. Run it before requiring it

Open a throwaway pull request and let everything run. Expect findings on a repository that
has never been scanned — that is the point. Triage them:

- **A real problem** → fix it.
- **A rule that misfires** → fix the rule *here*, with a regression test, so nobody else
  hits it. Do not work around it locally.
- **Accepted risk** → add an entry to that repository's `security/policy.json`:

  ```json
  { "rule": "DYNAMIC_CODE_EXECUTION", "paths": ["app/x/_eval.ts"],
    "reason": "Why this is acceptable and what would remove the need for it.",
    "expires": "2027-03-01" }
  ```

  `reason` and `expires` are mandatory. An exception downgrades a finding to INFO and
  annotates it; it never hides it, and it stops working on its expiry date so the risk is
  re-reviewed rather than inherited.

- **Historical secrets** → rotate first, then record the fingerprint in
  `security/gitleaks-ignore.txt` with a note saying what was rotated and when. Never add a
  fingerprint for a live credential.

## 5. Branch protection

Nothing blocks until the checks are required. A status check cannot be marked required
until GitHub has seen it report at least once, which is why step 4 comes first.

On the default-branch ruleset:

- require a pull request, at least one approving review
- **`require_code_owner_review: true`** — without this, CODEOWNERS does nothing at all
- required status checks: **`PR Malware Gate`** and **`Merge Gate`**
- dismiss stale approvals on push, require last-push approval, require thread resolution
- block force-pushes and deletion — this is the control that stops the "commit twin"
  technique, and it matters as much as any scanner

Confirm `@neotree/core-devs` and `@neotree/maintainers` both have Write access. GitHub
silently ignores a CODEOWNERS entry whose team lacks access; the control fails open with
no error shown anywhere.

Full detail in [`BRANCH_PROTECTION.md`](BRANCH_PROTECTION.md).

## Per-repository notes

**Private repositories on the Free plan** have no code scanning, so disable the pieces that
need it:

```yaml
with:
  security-ci-ref: <sha>
  enable-codeql: false
  upload-sarif: false
```

**React Native / library repositories** need nothing special — `build` and `test` run only
when those scripts exist.

**Repositories that commit build output** (as `neotree-editor` does for deployment) should
keep `scan_build_artifacts` on. Committed bundles are code that reaches production, built
on a developer workstation, so they are scanned under a reduced profile that tolerates
minification. The mutation guard excludes them, because a rebuild legitimately changes
every content hash.

**Non-JavaScript repositories** (the R and Python ones) can still use the malware scan and
secret scan; set `enable-quality: false` to skip the Node-specific jobs.

## Suggested order

`node-api` first — it is the smallest, and it is one of the four confirmed-infected
repositories. Then `dhis-integration`, `neotree-impilo-shr-adapter`,
`neotree-react-native-app`, `neotree-editor`, and `metabase-admin` last with the
private-repository profile.
