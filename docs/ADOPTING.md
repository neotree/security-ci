# Adopting the shared pipeline in a repository

Four files to add, one SHA to set, then branch protection. Budget an hour for the first
repository and about fifteen minutes for each one after.

## 1. Pick the SHA

Everything is pinned to a commit of `neotree/security-ci`. Get the current one:

```bash
git ls-remote https://github.com/neotree/security-ci refs/heads/main
```

That 40-character SHA goes in **two places per workflow**: the `uses:` line and the
`security-ci-ref` input. They must match, and the pipeline enforces it — `uses:` decides
which workflow runs, `security-ci-ref` decides which scanner is checked out, and Dependabot
updates only the first. A bump that touches one and not the other would otherwise run a new
workflow against an old scanner with nothing anywhere saying so. `check_caller_pin.py`
fails the build on that mismatch, and the trusted gate checks the **base** commit's copy so
a pull request cannot relax its own pin.

The gate also refuses to run if the ref is not a full SHA, because a branch or tag can be
moved and the whole trust model rests on that pin.

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

  An exception covers **one site per file** unless it says otherwise with `"sites": N`
  (1–50). A site is a call, not a line: `eval(a); eval(b);` is two. Adding a second call
  to an excepted file makes every finding of that rule in the file block again; an
  accepted call is never cover for a new one.

  The same file holds Semgrep's accepted risk, with the rule written `semgrep:<rule-id>`:

  ```json
  { "rule": "semgrep:js-ts-dynamic-eval", "paths": ["app/x/_eval.ts"],
    "reason": "...", "expires": "2027-03-01" }
  ```

  Nothing repository-specific belongs in the shared Semgrep rules; they have no expiry.

- **Historical secrets** → rotate first, then record the fingerprint in
  `security/gitleaks-ignore.txt` with a note saying what was rotated and when. Never add a
  fingerprint for a live credential.

## 4b. Dependency thresholds are a starting point, not a target

Two knobs decide how much of an existing dependency backlog blocks a merge. Both default
to the loosest useful setting, because a gate nobody can satisfy is a gate everybody routes
around.

| Knob | Default | Meaning |
| --- | --- | --- |
| `audit_severity` (policy) | `critical` | `npm`/`yarn`/`pnpm` audit floor |
| `osv-cvss-threshold` (workflow input) | `9.0` | OSV blocks at or above this CVSS score |

Measured on `neotree-editor`: 243 advisories (15 low, 87 moderate, 130 high, 11 critical),
and 186 OSV findings of which 4 are CVSS >= 9.0 and 102 are >= 7.0. A `high` floor is
simply unreachable there today.

What keeps this honest is that **Dependency Review blocks newly introduced high-severity
dependencies on every pull request, unconditionally**. So the full-tree thresholds govern
the *existing backlog*, while "don't make it worse" is enforced regardless.

Ratchet down as the backlog clears: `9.0` -> `7.0` -> `4.0`, and `critical` -> `high` ->
`moderate`. A repository may tighten either via its overlay; an attempt to loosen them is
rejected and reported as `POLICY_OVERLAY_WEAKENED`.

## 4c. What blocks, and how accepted risk is recorded

Beyond the malware and policy rules, the gate blocks on:

| Check | Blocks on |
| --- | --- |
| `POSSIBLE_SQL_INJECTION` | every SQL string built by interpolation or concatenation, each site reported separately |
| `SECRET_IN_LOG` | an API key, token, password, `Authorization` header or cookie passed to a log call |
| `INLINE_SCANNER_SUPPRESSION` | an inline Gitleaks allow-comment (a Semgrep one is reported, and has no effect) |
| Semgrep | every `ERROR` rule, plus the reviewed `WARNING` rules in `security/semgrep-blocking-rules.txt` |
| `js-ts-request-data-in-sql` | `req.query` / `params` / `body` / `headers` flowing into a SQL string, through variables |

Every high-severity rule reports **every** site in a file, not only the first. A reviewed
exception for one call never covers a second call added beside it.

**Inline suppressions do nothing here.** Semgrep runs with `--disable-nosem`, and a Gitleaks
allow-comment is itself a blocking finding. Both would let an ordinary code change silence a
scanner with no reviewer, reason or expiry. Accepted risk goes in `security/policy.json`
(reason and expiry mandatory) or `security/gitleaks-ignore.txt`; both are Code-Owner files.

**The OSV threshold can only be tightened.** `osv-cvss-threshold` above `9.0` is refused by
the gate, so a caller cannot switch dependency blocking off by raising it.

**Tests must be wired in.** A project that contains tests (`tests/`, `__tests__/`,
`*.test.*`, `*.spec.*`) but no `test` script fails, because the runner would otherwise skip
the suite without a word.

**Policy switches only tighten.** An overlay cannot turn off `run_tests_if_present`,
`require_npm_lock_integrity`, `verify_npm_registry_signatures` or the other checks, cannot
raise a detection limit such as `max_line_length`, and may only *remove* entries from
`artifact_globs`. Beyond those ratchets it may set only `exceptions`, the console-hygiene
keys and `allowed_npm_registries`; any other key is ignored. Each attempt is reported as
`POLICY_OVERLAY_WEAKENED` and the central value is enforced.

**Project scripts cannot rewrite tracked files.** Before any project code runs, the
runner records the commit's file list; afterwards it re-hashes every tracked file from
disk itself. Git is not asked, because `assume-unchanged`, `skip-worktree` and clean
filters in `.git/config` are all under the control of the code being checked.

**OSV uses only the trusted configuration.** Both OSV jobs pass security-ci's own
`osv-scanner.toml` with `--config`, so an `osv-scanner.toml` added by a pull request
cannot ignore a package. Both spellings of that file are Code-Owner protected regardless.

**All three connectors are required.** The pin check runs with `--require-all`: a pull
request that deletes the malware gate or the scheduled scan fails, rather than leaving the
repository with less protection and nothing saying so.

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

**CodeQL** is enabled for every Neotree repository by the organisation-level code scanning
configuration, so this pipeline does not run it (`enable-codeql` defaults to `false`). A
second, advanced configuration is rejected by GitHub when it uploads, so turning it on here
fails the build without adding coverage. Leave it to the organisation configuration.

**Private repositories on the Free plan** have no code scanning, so disable SARIF upload:

```yaml
with:
  security-ci-ref: <sha>
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
