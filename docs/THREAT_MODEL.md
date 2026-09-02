# Threat model and design rationale

This baseline assumes a pull request may be intentionally hostile, including a PR from a compromised developer account, a poisoned take-home/interview repository, or a supply-chain compromise in an npm dependency.

## PolinRider behaviors represented in the controls

Public reporting and community investigation of the PolinRider campaign has included multiple generations of identifiers and several execution/propagation mechanisms. The pipeline therefore does **not** depend on a single signature.

The custom scanner combines the IOC set in `security/polinrider_iocs.json` with behavior checks for:

- hidden payloads after unusually large whitespace runs;
- obfuscated/encoded data and decode-then-execute chains;
- JavaScript hidden in files whose extension suggests a font/binary asset;
- VS Code automatic tasks that execute on folder open;
- application/config entry-point process execution;
- network-download + process-execution chains;
- malicious or suspicious package-manager lifecycle behavior;
- package/lockfile artifact substitution and alternate registries;
- force-push/history-rewrite helper artifacts reported in campaign investigations.

Known campaign infrastructure strings are treated as context signals rather than automatic proof of compromise when they can plausibly have legitimate use. Exact campaign markers and known malicious package names are hard blockers.

## CI-specific attacker model

A malicious PR may also try to attack the CI pipeline itself rather than the application. Controls therefore include:

- a trusted `pull_request_target` scanner sourced only from the base commit;
- review grants bound to a specific head commit, so a later push to the same pull
  request cannot inherit an earlier approval of a security-control change;
- symlink-safe traversal in the privileged gate, so a hostile symlink cycle cannot
  stall or mislead the scanner before it reports;
- manual PR fetching as inert data instead of executing a PR checkout in the privileged job;
- SHA verification of the fetched PR commit;
- no submodule updates and explicit gitlink rejection;
- symlink rejection before file reads to prevent scanner path-escape attacks;
- full-SHA GitHub Action pinning;
- digest pinning for the Semgrep container;
- checksum validation for the downloaded Gitleaks binary;
- explicit trusted OSV/Gitleaks/Semgrep configuration instead of PR-controlled suppression files;
- dependency lifecycle scripts disabled during installation;
- read-only/minimal GitHub token permissions and no persisted Git credentials;
- outbound network allowlists on jobs that handle untrusted repository content;
- post-build scanning and tracked-file mutation detection.

## Precision is a security property

An unattainable gate is a disabled gate. Every rule that fires on ordinary, correct code
spends reviewer attention and pushes the team toward bypassing the pipeline, so precision
is treated here as part of the control, not as polish:

- Behavioural rules require evidence of a real capability, not a bare identifier.
  `child_process` execution is inferred from an actual import/require binding or from
  call names that do not collide with common APIs. Bare `exec(` is deliberately excluded,
  because `someRegExp.exec(str)` is ordinary JavaScript; treating it as process execution
  produced critical findings on clean code.
- "Network access" means a real fetch/HTTP/socket capability, not the presence of a URL
  string literal.
- Indicators that are specific enough to be proof (`POLINRIDER_IOC`) block outright.
  Generic strings that merely co-occur with the campaign are `context_markers`, reported
  at MEDIUM to corroborate other signals rather than to block on their own.
- Code hygiene (console output, `dangerouslySetInnerHTML`) is reported but does not block.
  Mixing style enforcement into a malware gate trains people to ignore the gate.
- Findings are reported once per host/file where repetition adds nothing: a single
  misconfigured registry should produce one finding, not one per locked package.

The regression suite in `security/tests/` therefore asserts both directions — that malicious
fixtures block, and that clean fixtures do not.

## Accepted risk is tracked, not hidden

The scanner has no silent ignore mechanism. Risk that is knowingly accepted is declared in
`security/policy.json` with a mandatory reason and expiry, downgraded to INFO rather than
deleted, and re-surfaced automatically when the expiry passes. Compromise indicators and the
controls protecting the gate itself cannot be excepted at all. Because exceptions live under
`security/`, adding one is a security-control change requiring Code Owner review.

## What the Neotree incident changed

The internal incident report (classification CRITICAL, 2026-09-02) shifted three
assumptions this pipeline was built on:

**Entry points, not just build configs.** Payloads were appended directly to
`node-api/index.js`, `dhis-integration/app.js` and `impilo-shr-adapter/fhir-adapter/index.ts`.
Execution therefore happens when the **service starts**, not only when someone runs a build.
`ENTRYPOINT_LINE_ANOMALY` gives entry points their own tight line budget (1,500 characters
against a measured real-world maximum of 1,004 across 3,975 files on all 85 branches).

**Force-push was the delivery mechanism.** Ten force-pushes in 2 minutes 44 seconds across
three repositories - machine-paced, not manual. Branch rulesets now block `non_fast_forward`
on every deployment branch, which is the actual control here; the scheduled all-branch scan
covers refs no pull request touches.

**Account identity is deliberately not an indicator.** The malware runs on a compromised
developer machine and pushes using whatever cached Git credentials it finds, so the account
on a malicious commit belongs to a victim, not an attacker. Denylisting that account would
name the victim publicly while catching only the one account already known to be burned -
the next compromise is a different account, and the pipeline would be blind to it. What is
checked instead is `COMMIT_AUTHOR_ANOMALY`: invisible or bidirectional characters in author
and committer metadata, the spoofing technique this campaign is reported to use. That is
behavioural, applies to everyone equally, and accuses nobody.

**Blockchain RPC is C2, not a coincidence.** The loader fetches and executes remote
JavaScript addressed through TRON/BSC/Ethereum RPC endpoints. This application has no
legitimate blockchain use, so `infrastructure_severity` is set to `high` here and those
hosts block rather than merely annotate. A project that genuinely uses web3 should lower it.

**History was rewritten during remediation**, so the current repository is not authoritative
for reconstructing the original sequence of events. Forensic mirrors, bundles and preserved
refs are. That also means commit-scoped artefacts derived from history - such as the
Gitleaks fingerprints in `security/gitleaks-ignore.txt` - are valid only against the current
history and must be regenerated if it is ever rewritten again.


## Independent layers

The gate intentionally uses overlapping scanners because each has different blind spots:

- custom repository policy/malware scanner: campaign IOCs + repository/CI-specific behavior;
- Semgrep: deterministic local AST patterns for dangerous JS/TS constructs;
- CodeQL: deeper data-flow/static analysis for JS/TS and GitHub Actions;
- Gitleaks: secret detection across Git history, archives and encoded content;
- npm/pnpm/Yarn audit + OSV + GitHub Dependency Review: independent dependency intelligence sources;
- lint/typecheck/tests/build: correctness and project-specific validation.

A finding in one layer cannot be ignored merely because another layer passes.

## Public references used when designing the baseline

- GitHub Community discussion supplied with the original request: https://github.com/orgs/community/discussions/188732
- Independent PolinRider investigation repository: https://github.com/sam1am/polinrider
- OpenSourceMalware developer guidance: https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
- GitHub secure-use guidance for Actions: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- GitHub CodeQL documentation: https://docs.github.com/en/code-security/code-scanning
- OSV Scanner documentation: https://google.github.io/osv-scanner/
- Gitleaks project: https://github.com/gitleaks/gitleaks
- Semgrep CI documentation: https://semgrep.dev/docs/semgrep-ci/sample-ci-configs

Threat intelligence changes. Update `security/polinrider_iocs.json` through a security-reviewed, CODEOWNER-approved PR rather than dynamically trusting an external IOC feed at CI runtime.
