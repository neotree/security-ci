#!/usr/bin/env python3
"""Verify a calling repository pins the scanner and the workflow to the SAME commit.

Each caller names the security-ci commit twice: once in `uses:` (which decides WHICH
reusable workflow runs) and once in `security-ci-ref` (which decides WHICH scanner is
checked out). Dependabot updates the first and not the second, so a routine dependency
bump would silently run a new workflow against an old scanner - stale detection, with
nothing anywhere saying so.

They live in the same file, and that file is checked out, so the mismatch is detectable.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

USES = re.compile(r"^\s*uses:\s*([^\s@]+/security-ci)/\.github/workflows/(\S+?)@([0-9a-fA-F]{40})\s*$", re.M)
REF = re.compile(r"^\s*security-ci-ref:\s*[\"']?([0-9a-fA-F]{40})[\"']?\s*$", re.M)


def check_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    uses = USES.findall(text)
    refs = REF.findall(text)
    if not uses:
        return []
    problems: list[str] = []
    used = {sha.lower() for _, _, sha in uses}
    pinned = {sha.lower() for sha in refs}
    if not pinned:
        problems.append(f"{path}: calls security-ci but sets no security-ci-ref input.")
        return problems
    for sha in sorted(used - pinned):
        problems.append(
            f"{path}: `uses:` is pinned to {sha[:12]} but security-ci-ref is "
            f"{', '.join(sorted(s[:12] for s in pinned))}. The workflow and the scanner "
            "would come from different commits; update both together."
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, help="Checkout of the calling repository.")
    args = ap.parse_args(argv)

    workflows = sorted((args.root / ".github" / "workflows").glob("*.yml"))
    problems: list[str] = []
    checked = 0
    for wf in workflows:
        found = check_file(wf)
        if USES.search(wf.read_text(encoding="utf-8", errors="replace")):
            checked += 1
        problems.extend(found)

    for p in problems:
        print(f"::error::{p}")
    print(f"Caller pin check: {checked} workflow(s) call security-ci, {len(problems)} mismatch(es).")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
