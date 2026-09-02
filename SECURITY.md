# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** This repository is the security pipeline for several
Neotree services, so a weakness here affects all of them.

Report privately through
[private vulnerability reporting](https://github.com/neotree/security-ci/security/advisories/new),
or email **security@neotree.org**.

Especially valuable: a way to get a payload past the gate, a way for a repository's policy
overlay to weaken the shared defaults, or a way to influence the scanner from a pull
request in a consuming repository.

## Scope

In scope: everything in `security/` and `.github/workflows/`.

Out of scope: findings that require an already-compromised maintainer account, and
false-positive reports (open a normal issue for those — they are welcome, just not
vulnerabilities).

## What this repository deliberately does not contain

No credentials, and no incident-specific detail. Commit author identity is **not** used as
an indicator: this malware runs on a compromised developer machine and pushes with cached
Git credentials, so the account on a malicious commit belongs to a victim. Author metadata
is checked for spoofing instead, which applies to everyone equally and accuses nobody.
