# Security Policy

## Reporting

**Do not open a public issue.** This repository is the security pipeline for several
Neotree services, so a weakness here affects all of them.

The reporting process is the organisation-wide one in
[neotree/.github](https://github.com/neotree/.github/blob/main/SECURITY.md), reachable from
this repository's [Security tab](https://github.com/neotree/security-ci/security/policy).
Use private vulnerability reporting, or the address given there.

This file adds only what is specific to this repository.

## Especially valuable reports

- A way to get a payload past the gate — a variant of the campaign this was built for, or
  any other malicious change, that the scanners do not flag.
- A way for a consuming repository's policy overlay to **weaken** the shared defaults.
  Overlays are supposed to tighten only; `merge_policy` rejects attempts to remove a
  blocking severity or raise the audit floor.
- A way for a pull request in a consuming repository to **influence the scanner**. The
  trusted gate runs the scanner from this repository at a pinned SHA and reads the policy
  overlay from the caller's base commit precisely to prevent that.
- A way to make a scanner report success when it did not run, or when it skipped analysis.
  Two real instances of this class have already been fixed: a merge gate that exited 0
  regardless of job results, and actionlint silently skipping shellcheck when it was absent.

## Out of scope

Findings that require an already-compromised maintainer account, and false positives —
those are welcome as normal issues, they just are not vulnerabilities.

## What this repository deliberately does not contain

No credentials, and no incident-specific detail. Commit author identity is **not** used as
an indicator: this malware runs on a compromised developer machine and pushes with cached
Git credentials, so the account on a malicious commit belongs to a victim. Author metadata
is checked for spoofing instead, which applies to everyone equally and accuses nobody.
