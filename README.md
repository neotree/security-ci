# neotree/security-ci

Shared, fail-closed CI security pipeline for Neotree's JavaScript and TypeScript
repositories. One place to maintain detection logic; each repository keeps only its own
accepted risk.

Built after the April–August 2026 repository compromise. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what it defends against and why.

## How it is used

Each repository adds three thin workflows that call this one, pinned by commit SHA:

```yaml
jobs:
  security:
    uses: neotree/security-ci/.github/workflows/security-ci.yml@<sha>
    with:
      security-ci-ref: <same sha>
```

Everything else — the scanner, the rules, the installers, the indicators — lives here.

## What is shared, and what is not

| Lives here | Lives in each repository |
| --- | --- |
| `scan_repo.py`, `run_project_checks.py`, `gate_sarif.py` | `security/policy.json` — its exceptions and thresholds |
| Semgrep rules (6 local + 87 vendored community) | `security/gitleaks-ignore.txt` — its acknowledged leaks |
| Gitleaks / OSV configuration, pinned installers | `.github/CODEOWNERS` |
| Campaign indicators (`polinrider_iocs.json`) | Three ~15-line caller workflows |
| The reusable workflows | |

The seam is **detection logic versus accepted risk**. Exceptions and secret fingerprints
are inherently local; scanners and indicators are not. This session alone the indicator
file changed three times — doing that by hand in six repositories is where drift starts.

## Why this is more secure than copying the files

In a single-repository installation the trusted gate checks out the scanner from the base
commit *of the repository being scanned*. Here the scanner comes from a **different
repository pinned by SHA**, so a pull request has no path to influence it at all.

The trusted gate also reads each repository's policy overlay from its **base commit**, not
from the pull request — so a pull request cannot introduce or relax its own policy in the
very run that judges it. And `merge_policy` refuses any overlay that removes a blocking
severity, reporting `POLICY_OVERLAY_WEAKENED`: a repository may tighten this gate, never
loosen it.

## Keeping six repositories in sync

Pin by **SHA, never a tag** — a tag can be moved. Dependabot's `github-actions` ecosystem
updates reusable-workflow `uses:` refs, so a change here arrives as an automated pull
request in each consuming repository, gated by that repository's own pipeline.

The trade-off is honest: updates are not instant. For a security control that is the right
side to err on.

Dependabot updates the `uses:` line but not the `security-ci-ref` input, which would leave a
new workflow running an old scanner. `security/check_caller_pin.py` fails the build when
those two disagree, so the drift is loud rather than silent.

**Secret-scan cost.** Pull requests scan only the commits the change introduces; full
history runs on the schedule. On `neotree-editor` that is ~0.4s versus 9 minutes, and it
finds the same things — history does not change between pull requests. The script falls
back to a full scan whenever the range cannot be established (shallow clone, force-push,
first push), so a narrowed scope is never silently mistaken for a clean one.

## A note on severity gates

Two scanners, two conventions, both of which silently defeat a naive gate:

* **Semgrep** emits no per-result `level` — the severity is on the rule descriptor. Reading
  `result.level` sees `None` for every finding and passes everything.
* **OSV-Scanner** marks *every* result `warning` regardless of how serious the advisory is;
  the real severity is a CVSS score in the rule's `security-severity` property. Its own
  `--fail-on-vuln` flag is all-or-nothing.

`security/gate_sarif.py` handles both, and is tested against real output from each.

## Adopting it

See [`docs/ADOPTING.md`](docs/ADOPTING.md). Roughly: copy four files from
[`templates/`](templates/), set the pinned SHA, then configure branch protection —
nothing blocks until the checks are marked required.

## Working on this repository

```bash
python3 -m unittest discover -s security/tests -t . -v   # 130 regression tests
python3 security/scan_repo.py --root .                   # scan this repo with itself
shellcheck --severity=warning security/*.sh
$(./security/install_actionlint.sh) .github/workflows/*.yml templates/workflows/*.yml
```

**Install shellcheck before linting workflows.** actionlint runs it over every `run:`
block, but only when it is on `PATH` — otherwise it skips that analysis and reports
success. A clean actionlint run without shellcheck installed means considerably less than
it appears to.

The `Self Test` workflow runs all of that plus `shellcheck` and an Action-pinning check on
every pull request. A change that breaks detection fails here rather than silently
stopping detection in six downstream repositories.

## What it does not do

It is a detector, not a proof. It does not replace code review, it cannot see a payload
that never reaches the repository, and it does nothing until branch protection requires
its checks. A red gate is a finding, not an obstacle — see
[`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).
