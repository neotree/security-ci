#!/usr/bin/env python3
"""Verify a calling repository pins the scanner and the workflow to the SAME commit.

Each caller names the security-ci commit twice: once in `uses:` (which decides WHICH
reusable workflow runs) and once in `security-ci-ref` (which decides WHICH scanner is
checked out). Dependabot updates the first and not the second, so a routine dependency
bump would silently run a new workflow against an old scanner - stale detection, with
nothing anywhere saying so.

They live in the same file, and that file is checked out, so the mismatch is detectable.

Three further ways a caller can drift are also refused:
  * a `uses:` ref that is not a full commit SHA (a branch or tag can be moved, and such a
    line previously did not match at all, so the file was silently skipped);
  * callers in `.yaml` files, which GitHub runs but a `*.yml` glob never sees;
  * callers in one repository pinned to different commits, e.g. a half-applied bump
    leaving the malware gate on an older scanner than Security CI.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# One parser for every form YAML allows on a line: bare, 'single' or "double" quoted, and
# an optional trailing comment. Two patterns that disagreed on quoting used to let a
# quoted SHA through the comparison while the stricter one silently matched nothing.
_VALUE = r"""(?:"([^"\n]*)"|'([^'\n]*)'|([^\s#"']+))\s*(?:#.*)?$"""
ANY_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*" + _VALUE, re.M)
ANY_REF = re.compile(r"^\s*security-ci-ref:\s*" + _VALUE, re.M)
TARGET = re.compile(r"^([^\s@]+/security-ci/\.github/workflows/[^\s@]+)@(.*)$")
# Anything that names a security-ci workflow at all. A reference the parser above cannot
# read (folded scalars, flow mappings, odd spacing) is refused rather than skipped.
MENTION = re.compile(r"security-ci/\.github/workflows/")
SHA = re.compile(r"[0-9a-fA-F]{40}")


def _value(groups: tuple[str, str, str]) -> str:
    return next((g for g in groups if g), "")


def security_ci_uses(text: str) -> list[tuple[str, str]]:
    """(workflow path, ref) for every `uses:` that names a security-ci workflow."""
    out = []
    for m in ANY_USES.finditer(text):
        target = TARGET.match(_value(m.groups()))
        if target:
            out.append((target.group(1), target.group(2)))
    return out


def scanner_refs(text: str) -> list[str]:
    return [_value(m.groups()) for m in ANY_REF.finditer(text)]
# The three connectors every repository must keep. Losing one is not a smaller pipeline:
# without pr-malware-gate.yml nothing scans pull requests from a trusted context, and
# without scheduled-security.yml stale branches and new advisories go unseen.
REQUIRED_CALLERS = ("security-ci.yml", "pr-malware-gate.yml", "scheduled-security.yml")


def check_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    problems: list[str] = []
    uses = security_ci_uses(text)
    refs = scanner_refs(text)
    parsed_mentions = sum(1 for line in text.splitlines()
                          if MENTION.search(line) and ANY_USES.match(line) and TARGET.match(_value(ANY_USES.match(line).groups())))
    all_mentions = sum(1 for line in text.splitlines()
                       if MENTION.search(line) and not line.lstrip().startswith("#"))
    if all_mentions > parsed_mentions:
        problems.append(
            f"{path}: references security-ci in a form this check cannot parse. Write it as "
            "one `uses: <owner>/security-ci/.github/workflows/<file>@<40-char SHA>` line."
        )
    for target, ref in uses:
        if not SHA.fullmatch(ref):
            problems.append(
                f"{path}: `uses: {target}@{ref}` is not pinned to a full 40-character commit "
                "SHA. A branch or tag can be moved; pin the commit."
            )
    for ref in refs:
        if not SHA.fullmatch(ref):
            problems.append(f"{path}: security-ci-ref '{ref}' is not a full 40-character commit SHA.")
    # Compared job by job. A file-wide comparison let a matching ref in one job mask a
    # mismatched ref in another: each `uses:` must agree with its OWN job's input.
    for job, block in job_blocks(text):
        job_uses = security_ci_uses(block)
        if not job_uses:
            continue
        job_refs = scanner_refs(block)
        if not job_refs:
            problems.append(f"{path}: job `{job}` calls security-ci but sets no security-ci-ref input.")
            continue
        for target, ref in job_uses:
            for scanner in job_refs:
                if SHA.fullmatch(ref) and SHA.fullmatch(scanner) and ref.lower() != scanner.lower():
                    problems.append(
                        f"{path}: job `{job}` runs {target.rsplit('/', 1)[-1]} at {ref[:12]} but "
                        f"checks out the scanner at {scanner[:12]}. The workflow and the scanner "
                        "would come from different commits; update both together."
                    )
    return problems


JOBS = re.compile(r"^jobs:\s*(?:#.*)?$", re.M)


def job_blocks(text: str) -> list[tuple[str, str]]:
    """(job id, job text) for each job under the top-level `jobs:` mapping.

    Without a `jobs:` key the whole file is treated as one job, so nothing is skipped.
    """
    m = JOBS.search(text)
    if not m:
        return [("<file>", text)]
    lines = text[m.end():].splitlines(keepends=True)
    indent: int | None = None
    blocks: list[tuple[str, list[str]]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if blocks:
                blocks[-1][1].append(line)
            continue
        width = len(line) - len(line.lstrip(" "))
        if width == 0:
            break  # next top-level key
        if indent is None:
            indent = width
        if width == indent and re.match(r"^[\w.-]+\s*:", stripped):
            blocks.append((stripped.split(":", 1)[0].strip(), [line]))
        elif blocks:
            blocks[-1][1].append(line)
    return [(name, "".join(body)) for name, body in blocks] or [("<file>", text)]


def workflow_files(root: Path) -> list[Path]:
    wf = root / ".github" / "workflows"
    return sorted([*wf.glob("*.yml"), *wf.glob("*.yaml")])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, help="Checkout of the calling repository.")
    ap.add_argument("--require-all", action="store_true",
                    help="Fail unless the repository calls every reusable security-ci workflow.")
    args = ap.parse_args(argv)

    problems: list[str] = []
    checked = 0
    shas: dict[str, list[str]] = {}
    called: set[str] = set()
    for wf in workflow_files(args.root):
        problems.extend(check_file(wf))
        text = wf.read_text(encoding="utf-8", errors="replace")
        uses = security_ci_uses(text)
        if uses:
            checked += 1
        for target, ref in uses:
            called.add(target.rsplit("/", 1)[-1])
            if SHA.fullmatch(ref):
                shas.setdefault(ref.lower(), []).append(wf.name)

    if args.require_all:
        for name in REQUIRED_CALLERS:
            if name not in called:
                problems.append(
                    f"No workflow calls security-ci's {name}. Every repository keeps all three "
                    f"connectors ({', '.join(REQUIRED_CALLERS)}); restore it from templates/workflows/."
                )

    if len(shas) > 1:
        detail = "; ".join(f"{sha[:12]} in {', '.join(sorted(set(files)))}" for sha, files in sorted(shas.items()))
        problems.append(
            f"security-ci callers are pinned to {len(shas)} different commits ({detail}). "
            "Every caller in a repository must run the same scanner; bump them together."
        )

    for p in problems:
        print(f"::error::{p}")
    print(f"Caller pin check: {checked} workflow(s) call security-ci, {len(problems)} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
