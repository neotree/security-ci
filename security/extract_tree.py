#!/usr/bin/env python3
"""Write every blob of a commit to a directory, byte for byte, as inert data.

`git archive` was used for this and is the wrong tool: it honours the commit's own
`.gitattributes`, so a branch can mark its payload `export-ignore` and the file never
reaches the scanner. It also runs `export-subst` and filters. This reads objects straight
from the object database with `ls-tree` and `cat-file --batch`, which apply no attributes,
filters, hooks or smudge, so what is scanned is exactly what is committed.

Symlinks are recreated as symlinks (never followed) so the scanner's SYMLINK rule still
sees them. Submodule (gitlink) entries have no content to write, and the extracted tree
has no Git index for the scanner's GIT_SUBMODULE check to read, so they are reported
separately via --gitlinks-out rather than silently dropped.
Exits non-zero on any inconsistency: a partial tree must never read as a clean branch.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def entries(repo: Path, ref: str) -> list[tuple[str, str, str]]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", ref],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    result = []
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        mode, kind, sha = meta.decode().split()
        result.append((mode, kind, sha, os.fsdecode(path)))  # type: ignore[arg-type]
    return result  # type: ignore[return-value]


def safe_target(root: Path, rel: str) -> Path:
    parts = Path(rel).parts
    if not parts or Path(rel).is_absolute() or any(p in ("", ".", "..", ".git") for p in parts):
        raise ValueError(f"refusing unsafe tree path {rel!r}")
    target = root.joinpath(*parts)
    # No parent may be a symlink: writing through one would escape the extraction root.
    for parent in list(target.parents)[: len(parts) - 1]:
        if parent.is_symlink():
            raise ValueError(f"refusing path {rel!r} beneath a symlink")
    return target


def extract(repo: Path, ref: str, root: Path) -> tuple[int, list[str]]:
    items = entries(repo, ref)
    blobs = [e for e in items if e[1] == "blob"]
    gitlinks = [e[3] for e in items if e[1] == "commit"]
    unknown = [e for e in items if e[1] not in ("blob", "commit")]
    if unknown:
        raise RuntimeError(f"unexpected tree entry type {unknown[0][1]!r} at {unknown[0][3]}")
    batch = subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    assert batch.stdin and batch.stdout
    written = 0
    try:
        for mode, _, sha, rel in blobs:
            batch.stdin.write(sha.encode() + b"\n")
            batch.stdin.flush()
            header = batch.stdout.readline().split()
            if len(header) != 3 or header[0].decode() != sha or header[1] != b"blob":
                raise RuntimeError(f"object database returned {header!r} for {rel}")
            size = int(header[2])
            data = batch.stdout.read(size)
            batch.stdout.read(1)  # trailing newline
            if len(data) != size:
                raise RuntimeError(f"short read for {rel}")
            target = safe_target(root, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            if mode == "120000":
                os.symlink(os.fsdecode(data), target)
            else:
                target.write_bytes(data)
                if mode == "100755":
                    target.chmod(0o755)
            written += 1
    finally:
        batch.stdin.close()
        batch.wait()
    if batch.returncode != 0:
        raise RuntimeError(f"git cat-file exited {batch.returncode}")
    return written, gitlinks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", type=Path)
    ap.add_argument("ref")
    ap.add_argument("dest", type=Path)
    ap.add_argument("--gitlinks-out", type=Path, metavar="FILE",
                    help="Write the path of every submodule entry here, one per line. Keep it "
                         "OUTSIDE dest so the branch cannot pre-create or overwrite it.")
    args = ap.parse_args(argv)
    args.dest.mkdir(parents=True, exist_ok=True)
    try:
        n, gitlinks = extract(args.repo, args.ref, args.dest.resolve())
    except (subprocess.CalledProcessError, RuntimeError, ValueError, OSError) as e:
        print(f"::error::Could not extract {args.ref}: {e}", file=sys.stderr)
        return 1
    if args.gitlinks_out is not None:
        args.gitlinks_out.write_text("".join(f"{g}\n" for g in gitlinks), encoding="utf-8")
    for g in gitlinks:
        print(f"::error::{args.ref}: submodule/gitlink at {g} (GIT_SUBMODULE).", file=sys.stderr)
    print(f"Extracted {n} file(s) and found {len(gitlinks)} gitlink(s) in {args.ref}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
