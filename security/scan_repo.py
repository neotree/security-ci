#!/usr/bin/env python3
"""Fail-closed repository policy and malware scanner for JavaScript/TypeScript CI.

Designed to be safe when invoked from a trusted base branch against an untrusted
PR checkout. It never imports or executes project code.

Key invariants:
  * The scanner only ever reads bytes. It never imports, evaluates or runs
    anything from the tree under inspection.
  * Directory traversal never follows symlinks, and every symlink encountered in
    a scanned tree is itself reported.
  * Policy exceptions are declarative, auditable and expiring, and a curated set
    of rules can never be excepted at all (see NON_EXEMPT_RULES).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import date
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
DEFAULT_POLICY = HERE / "policy.defaults.json"
DEFAULT_IOCS = HERE / "polinrider_iocs.json"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CODE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"}
# Build-config and entry-point identification.
#
# An explicit filename list is as brittle as an explicit version string: the reported
# target set already includes postcss.config.mjs, tailwind.config.mjs, vite.config.mjs,
# vue.config.js, astro.config.mjs, jest.config.js and App.js, and new tools appear
# constantly. Matching `<known-tool>.config.<js|mjs|cjs|ts|...>` case-insensitively covers
# the whole family, including extensions that do not exist yet.
CONFIG_STEMS = {
    "next", "tailwind", "postcss", "vite", "webpack", "babel", "metro", "eslint", "app",
    "jest", "vue", "astro", "nuxt", "rollup", "svelte", "remix", "drizzle", "playwright",
    "vitest", "cypress", "karma", "gatsby", "craco", "esbuild", "tsup", "rspack", "parcel",
    "prettier", "stylelint", "commitlint", "lint-staged", "capacitor", "expo", "sentry",
}
CONFIG_EXTS = {".js", ".cjs", ".mjs", ".ts", ".mts", ".cts", ".json"}
# Dotfile configs that do not follow the `<stem>.config.<ext>` shape.
EXTRA_CONFIG_NAMES = {
    ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".babelrc", ".babelrc.js",
    ".babelrc.json", ".prettierrc", ".prettierrc.js", ".prettierrc.json", ".swcrc",
}
ENTRYPOINT_STEMS = {
    "index", "app", "server", "main", "bootstrap", "middleware", "entry", "instrumentation",
}
ENTRYPOINT_EXTS = {".js", ".ts", ".mjs", ".cjs", ".mts", ".cts"}


def is_config_file(path: Path) -> bool:
    name = path.name.lower()
    if name in EXTRA_CONFIG_NAMES:
        return True
    parts = name.split(".")
    if len(parts) >= 3 and parts[-2] == "config" and f".{parts[-1]}" in CONFIG_EXTS:
        return ".".join(parts[:-2]) in CONFIG_STEMS
    return False


def is_entrypoint_file(path: Path) -> bool:
    return path.suffix.lower() in ENTRYPOINT_EXTS and path.stem.lower() in ENTRYPOINT_STEMS


SKIP_DIR_NAMES = {
    ".git", "node_modules", ".next", "dist", "build", "coverage", "out", ".turbo", ".cache",
    ".expo", ".gradle", "Pods", "vendor", ".pnpm-store", ".yarn",
}
# Multi-segment paths that are skipped wherever they appear, not only at the root.
SKIP_DIR_SEQUENCES = (
    (".yarn", "cache"),
    (".yarn", "unplugged"),
    (".yarn", "install-state.gz"),
)
TRUSTED_SELF_EXCLUDES = {
    "security/polinrider_iocs.json",
    "security/tests",
}
FONT_EXTS = {".woff", ".woff2", ".ttf", ".otf", ".ttc"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp"}
ASSET_EXTS = FONT_EXTS | IMAGE_EXTS
# Text formats that are not "code" but can still carry executable content. SVG in
# particular supports <script>, and the campaign is reported to stage payloads in assets.
MARKUP_EXTS = {".svg", ".html", ".htm", ".xml", ".xhtml"}
# Shell/batch scripts. PolinRider persists through Git hooks and dropped batch droppers,
# none of which are JavaScript. The dropper filenames themselves live in the IOC file.
SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".psm1"}
HOOK_DIR_PARTS = {".husky", ".githooks", "githooks"}
GIT_HOOK_NAMES = {
    "pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge", "post-update",
    "pre-rebase", "post-rewrite", "prepare-commit-msg", "commit-msg", "post-applypatch",
    "applypatch-msg", "pre-applypatch", "pre-auto-gc", "push-to-checkout",
}
LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}
REVIEWED_EXEC_SCRIPTS = LIFECYCLE_SCRIPTS | {"ci:prepare"}
SENSITIVE_PREFIXES = (
    ".github/workflows/", ".github/actions/", "security/", ".github/CODEOWNERS", ".github/dependabot.yml",
)
SENSITIVE_CONFIG_NAMES = {
    ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", ".pnpmfile.js", "pnpm-workspace.yaml",
    ".semgrepignore", ".gitleaksignore", ".osv-scanner.toml",
}
ACTION_MANIFEST_NAMES = {"action.yml", "action.yaml"}

# Rules a repository-local exception can never silence. These are either direct
# evidence of compromise, or the controls that keep the gate itself honest.
NON_EXEMPT_RULES = {
    "SECURITY_CONTROL_CHANGE",
    "POLINRIDER_IOC",
    "KNOWN_MALICIOUS_PACKAGE",
    "DANGEROUS_LIFECYCLE_SCRIPT",
    "EXCEPTION_EXPIRED",
    "EXCEPTION_INVALID",
    "SYMLINK",
    "GIT_SUBMODULE",
    "SPECIAL_FILE",
    "FS_UNREADABLE",
    "UNPINNED_ACTION",
    "UNPINNED_DOCKER_ACTION",
    "PR_TARGET_UNTRUSTED_CHECKOUT",
    "VSCODE_AUTORUN",
    "VSCODE_AUTOTASKS_ALLOWED",
    "VSCODE_EXECUTION_TASK",
    "LOCKFILE_REMOTE_ARTIFACT",
    "DOWNLOAD_EXECUTE",
    "DECODE_AND_EXECUTE",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    message: str
    line: int | None = None
    exempted: bool = False


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_skipped(rel: str, unskip: frozenset[str] = frozenset()) -> bool:
    parts = tuple(rel.split("/"))
    if any(p in SKIP_DIR_NAMES and p not in unskip for p in parts):
        return True
    for seq in SKIP_DIR_SEQUENCES:
        n = len(seq)
        if any(parts[i:i + n] == seq for i in range(len(parts) - n + 1)):
            return True
    return False


def is_trusted_self_excluded(rel: str) -> bool:
    return any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in TRUSTED_SELF_EXCLUDES)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to a regex. `**` crosses separators, `*` does not."""
    out = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def path_matches_any(rel: str, patterns: Iterable[str]) -> bool:
    return any(glob_to_regex(p).match(rel) for p in patterns)


def github_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit_annotation(f: Finding) -> None:
    if os.getenv("GITHUB_ACTIONS") != "true":
        return
    rank = SEVERITY_RANK[f.severity]
    level = "error" if rank >= SEVERITY_RANK["high"] else ("notice" if rank <= SEVERITY_RANK["info"] else "warning")
    attrs = f"file={github_escape(f.path)}"
    if f.line:
        attrs += f",line={f.line}"
    msg = github_escape(f"[{f.rule}] {f.message}")
    print(f"::{level} {attrs}::{msg}")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def safe_walk(root: Path, findings: list[Finding], unskip: frozenset[str] = frozenset()) -> Iterator[Path]:
    """Walk without following symlinks and reject symlinked dirs/files."""
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cur = Path(current)
        kept_dirs: list[str] = []
        for d in dirs:
            p = cur / d
            rel = relpath(p, root)
            if is_skipped(rel, unskip):
                continue
            try:
                mode = p.lstat().st_mode
            except OSError as e:
                findings.append(Finding("critical", "FS_UNREADABLE", rel, f"Cannot stat directory: {e}"))
                continue
            if stat.S_ISLNK(mode):
                findings.append(Finding("critical", "SYMLINK", rel, "Symlinked directories are forbidden in CI-scanned source."))
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for name in files:
            p = cur / name
            rel = relpath(p, root)
            if is_skipped(rel, unskip):
                continue
            try:
                mode = p.lstat().st_mode
            except OSError as e:
                findings.append(Finding("critical", "FS_UNREADABLE", rel, f"Cannot stat file: {e}"))
                continue
            if stat.S_ISLNK(mode):
                findings.append(Finding("critical", "SYMLINK", rel, "Symlinked files are forbidden in CI-scanned source."))
                continue
            if not stat.S_ISREG(mode):
                findings.append(Finding("high", "SPECIAL_FILE", rel, "Non-regular filesystem object is not allowed."))
                continue
            yield p


def safe_relative_files(root: Path) -> set[str]:
    """Every regular non-skipped file under root, never following symlinks.

    Used by the privileged trusted gate instead of Path.rglob, which follows
    directory symlinks on Python <= 3.12 and can be driven into a cycle by a
    hostile pull request.
    """
    out: set[str] = set()
    if not root.is_dir():
        return out
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cur = Path(current)
        kept: list[str] = []
        for d in dirs:
            p = cur / d
            rel = relpath(p, root)
            if is_skipped(rel):
                continue
            try:
                if stat.S_ISLNK(p.lstat().st_mode):
                    continue
            except OSError:
                continue
            kept.append(d)
        dirs[:] = kept
        for name in files:
            p = cur / name
            rel = relpath(p, root)
            if is_skipped(rel):
                continue
            try:
                if not stat.S_ISREG(p.lstat().st_mode):
                    continue
            except OSError:
                continue
            out.add(rel)
    return out


def is_hook_script(path: Path, rel: str) -> bool:
    parts = rel.split("/")
    if any(part in HOOK_DIR_PARTS for part in parts[:-1]):
        return True
    return path.name in GIT_HOOK_NAMES


def is_shell_like(path: Path, rel: str) -> bool:
    return path.suffix.lower() in SCRIPT_EXTS or is_hook_script(path, rel)


def scan_path_iocs(rel: str, iocs: dict, findings: list[Finding]) -> None:
    """Some campaign artifacts are identified by their filename alone."""
    name = rel.rsplit("/", 1)[-1]
    for marker in iocs.get("markers", []):
        if len(marker) >= 6 and "/" not in marker and marker.lower() == name.lower():
            findings.append(Finding(
                "critical", "DROPPER_ARTIFACT", rel,
                "Filename matches a known PolinRider dropper artifact.",
            ))
            return


def scan_gitlinks(root: Path, findings: list[Finding]) -> None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-s", "-z"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    except OSError:
        return
    if proc.returncode != 0:
        return
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        # format: mode SP object SP stage TAB path
        try:
            meta, name = raw.split(b"\t", 1)
            mode = meta.split(b" ", 1)[0]
        except ValueError:
            continue
        if mode == b"160000":
            path = name.decode("utf-8", "replace")
            findings.append(Finding("critical", "GIT_SUBMODULE", path, "Git submodules/gitlinks are forbidden by this baseline policy."))


# Paths whose Code Owner coverage the gate depends on. Losing an entry here would leave a
# security control reviewable by anyone, so absence is itself a finding.
CODEOWNERS_REQUIRED_PATHS = ("/security/", "/.github/workflows/")
PLACEHOLDER_OWNER = re.compile(r"@(?:YOUR|ORG|TEAM|OWNER|TODO|CHANGEME|EXAMPLE)[A-Z_]*\b", re.IGNORECASE)


def scan_codeowners(root: Path, findings: list[Finding]) -> None:
    """Verify the CODEOWNERS file actually protects the paths the gate blocks on.

    An entry naming a team that does not exist, or a leftover placeholder, makes GitHub
    ignore the rule silently - the control fails open with no error anywhere.
    """
    # Governance applies to a real project repository, not to an arbitrary subtree. A
    # fixture directory or an extracted artifact tree has no CODEOWNERS to speak of, and
    # reporting one there would be noise. Both markers together mean "project root".
    # Only a tree that actually runs these workflows needs Code Owners for them. Historical
    # branches predating the pipeline have no CODEOWNERS and that is not a finding.
    if not ((root / ".github" / "workflows").is_dir() and (root / "package.json").is_file()):
        return

    rel = ".github/CODEOWNERS"
    path = root / rel
    if not path.is_file():
        findings.append(Finding(
            "medium", "CODEOWNERS_MISSING", rel,
            "No CODEOWNERS file: security-control changes cannot require Code Owner review.",
        ))
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    active: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            active.append((parts[0], parts[1:]))

    for pattern, owners in active:
        for owner in owners:
            if PLACEHOLDER_OWNER.match(owner):
                findings.append(Finding(
                    "critical", "CODEOWNERS_PLACEHOLDER", rel,
                    f"Placeholder owner {owner!r} for {pattern!r}. GitHub ignores entries naming "
                    "a non-existent user or team, so this control silently does nothing.",
                ))

    for required in CODEOWNERS_REQUIRED_PATHS:
        # Only require ownership of a path that exists in this tree.
        if not (root / required.strip("/")).exists():
            continue
        covered = any(pattern.rstrip("/") == required.rstrip("/") for pattern, _ in active)
        if not covered:
            findings.append(Finding(
                "high", "CODEOWNERS_COVERAGE", rel,
                f"{required} has no explicit CODEOWNERS entry. The trusted gate blocks changes "
                "to it, but nothing would require a Code Owner to review them.",
            ))


def scan_commit_authors(root: Path, iocs: dict, findings: list[Finding]) -> None:
    """Detect spoofed commit-author metadata.

    Author identity is deliberately not treated as an indicator: this malware runs on a
    compromised developer machine and pushes with whatever cached Git credentials it finds,
    so the account on a malicious commit is a victim's. Denylisting it would name that
    victim and would only ever catch the one account already known to be burned.

    What IS an indicator is metadata that renders as one thing and contains another.
    Reporting on this campaign notes author display names carrying invisible directional
    marks, which makes a commit appear to come from someone it did not.
    """
    hidden = {ord(c) for c in BIDI_CONTROLS} | {ord(c) for c, _, _ in INVISIBLE_CHARS}
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce", "-n", "5000"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
    except OSError:
        return
    if proc.returncode != 0:
        return
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\x1f")
        if len(parts) != 5:
            continue
        sha, author, author_email, committer, committer_email = parts
        for label, value in (("author name", author), ("author email", author_email),
                             ("committer name", committer), ("committer email", committer_email)):
            found = next((c for c in value if ord(c) in hidden), None)
            if found is not None:
                findings.append(Finding(
                    "high", "COMMIT_AUTHOR_ANOMALY", ".",
                    f"Commit {sha[:12]} has an invisible character (U+{ord(found):04X}) in its "
                    f"{label}. Author metadata that renders differently from its actual bytes "
                    "misattributes the commit.",
                ))
                return


def read_bytes(path: Path, max_bytes: int) -> bytes | None:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        return path.read_bytes()
    except OSError:
        return None


def decode_text(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", "replace")
        except Exception:
            return None


BIDI_CONTROLS = ("\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069")
# Zero-width and invisible characters. ZWJ/ZWNJ are advisory because they are legitimate
# inside emoji sequences; the rest have no honest use in source. Measured across this
# repository's 784 source files: zero occurrences of any of them.
INVISIBLE_CHARS = (
    ("\u200b", "ZERO WIDTH SPACE", "high"),
    ("\u2060", "WORD JOINER", "high"),
    ("\ufeff", "ZERO WIDTH NO-BREAK SPACE", "high"),
    ("\u180e", "MONGOLIAN VOWEL SEPARATOR", "high"),
    ("\u2061", "FUNCTION APPLICATION", "high"),
    ("\u2062", "INVISIBLE TIMES", "high"),
    ("\u2063", "INVISIBLE SEPARATOR", "high"),
    ("\u2064", "INVISIBLE PLUS", "high"),
    ("\u200c", "ZERO WIDTH NON-JOINER", "medium"),
    ("\u200d", "ZERO WIDTH JOINER", "medium"),
)
# A word containing both Latin and Cyrillic/Greek letters - the homoglyph shape.
MIXED_SCRIPT_WORD = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*[\u0370-\u03ff\u0400-\u04ff]"
    r"|[\u0370-\u03ff\u0400-\u04ff][A-Za-z0-9_$]*[A-Za-z]"
)

SCRIPTISH = re.compile(
    rb"\b(?:require|import|eval|Function|process|global|fetch|Buffer|child_process|atob)\b"
    rb"|=>|\bconst\b|\blet\b|<script",
    re.IGNORECASE,
)

STRONG_SCRIPT = re.compile(
    rb"require\s*\(|createRequire|eval\s*\(|new\s+Function|child_process|<script"
    rb"|atob\s*\(|Buffer\s*\.\s*from|process\s*\.\s*env|globalThis|XMLHttpRequest",
    re.IGNORECASE,
)

ASSET_MAGIC = {
    ".woff": (b"wOFF",), ".woff2": (b"wOF2",), ".otf": (b"OTTO",), ".ttc": (b"ttcf",),
    ".ttf": (b"\x00\x01\x00\x00", b"true", b"OTTO"),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".bmp": (b"BM",),
    ".webp": (b"RIFF",),
    ".ico": (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"),
}


def asset_logical_length(ext: str, data: bytes) -> int | None:
    """Byte length of the well-formed asset, so appended payloads become visible.

    Returns None when the format's real length cannot be determined cheaply; the
    caller then simply skips the trailing-data check rather than guessing.
    """
    try:
        if ext == ".png":
            offset = 8
            while offset + 8 <= len(data):
                length = int.from_bytes(data[offset:offset + 4], "big")
                ctype = data[offset + 4:offset + 8]
                offset += 12 + length  # length + type + payload + CRC
                if ctype == b"IEND":
                    return offset
            return None
        if ext in {".woff", ".woff2"}:
            return int.from_bytes(data[8:12], "big") if len(data) >= 12 else None
        if ext in {".jpg", ".jpeg"}:
            idx = data.rfind(b"\xff\xd9")
            return idx + 2 if idx >= 0 else None
        if ext == ".gif":
            idx = data.rfind(b"\x3b")
            return idx + 1 if idx >= 0 else None
        if ext in {".ttf", ".otf"}:
            num_tables = int.from_bytes(data[4:6], "big")
            if not num_tables or 12 + num_tables * 16 > len(data):
                return None
            end = 12 + num_tables * 16
            for i in range(num_tables):
                rec = 12 + i * 16
                offset = int.from_bytes(data[rec + 8:rec + 12], "big")
                length = int.from_bytes(data[rec + 12:rec + 16], "big")
                end = max(end, offset + length)
            return min(end + (-end % 4), len(data)) if end <= len(data) else None
    except (ValueError, IndexError):
        return None
    return None


def scan_asset(path: Path, rel: str, data: bytes, iocs: dict, findings: list[Finding]) -> None:
    """Validate binary assets: correct magic bytes, and nothing appended after the end.

    Fonts and images are a reported PolinRider staging location. A file can carry a
    payload either by not being the format its extension claims, or by being a valid
    asset with data glued on after its logical end.
    """
    ext = path.suffix.lower()
    magics = ASSET_MAGIC.get(ext)
    if magics and not data.startswith(magics):
        printable = sum(1 for b in data[:32768] if b in b"\t\r\n" or 32 <= b < 127)
        ratio = printable / max(1, min(len(data), 32768))
        scriptish = bool(SCRIPTISH.search(data[:32768]))
        rule = "FAKE_FONT" if ext in FONT_EXTS else "FAKE_IMAGE"
        sev = "critical" if ratio > 0.75 and scriptish else "high"
        findings.append(Finding(
            sev, rule, rel,
            f"{ext} file has invalid magic bytes; script content masquerading as a binary "
            "asset is a known PolinRider technique.",
        ))
        return

    # Structure-independent check first. The declared length in a font/image header is
    # attacker-controlled, so a payload can hide behind a bogus length. Executable-looking
    # sequences have no business anywhere inside a compressed binary asset.
    m = STRONG_SCRIPT.search(data)
    if m:
        findings.append(Finding(
            "critical", "ASSET_EMBEDDED_SCRIPT", rel,
            f"Script content found inside a binary {ext} asset at byte offset {m.start()}; "
            "fonts and images are a reported PolinRider payload-staging location.",
        ))
        return

    logical = asset_logical_length(ext, data)
    if logical is None or logical <= 0 or logical > len(data):
        return
    trailing = data[logical:]
    # A few padding bytes are normal; a payload is not.
    if len(trailing.strip(b"\x00\r\n\t ")) < 16:
        return
    marker_hit = any(m.encode("utf-8", "ignore") in trailing for m in iocs.get("markers", []))
    scriptish = bool(SCRIPTISH.search(trailing))
    sev = "critical" if marker_hit else ("high" if scriptish else "medium")
    findings.append(Finding(
        sev, "ASSET_TRAILING_DATA", rel,
        f"{len(trailing)} bytes are appended after the end of this {ext} asset"
        + (" and contain a known campaign marker." if marker_hit
           else " and look like script content." if scriptish
           else "; binary assets should not carry extra payload."),
    ))


def scan_binary_iocs(rel: str, data: bytes, iocs: dict, findings: list[Finding]) -> None:
    """IOC search across raw bytes, so a payload inside a binary file is still seen."""
    blob = data.decode("latin-1", "ignore")
    for marker in iocs.get("markers", []):
        if marker in blob:
            findings.append(Finding(
                "critical", "POLINRIDER_IOC", rel,
                "Known PolinRider campaign marker detected inside a binary/undecodable file.",
            ))
            return


def scan_iocs(text: str, rel: str, iocs: dict, findings: list[Finding]) -> set[str]:
    hits: set[str] = set()
    for marker in iocs.get("markers", []):
        idx = text.find(marker)
        if idx >= 0:
            findings.append(Finding("critical", "POLINRIDER_IOC", rel, "Known PolinRider campaign marker detected.", line_of(text, idx)))
            hits.add("marker")
    for marker in iocs.get("context_markers", []):
        idx = text.find(marker)
        if idx >= 0:
            # Generic enough to occur in benign tooling; corroborates other signals rather than blocking alone.
            findings.append(Finding("medium", "POLINRIDER_CONTEXT", rel, "String associated with PolinRider tooling detected; review context.", line_of(text, idx)))
            hits.add("context")
    for domain in iocs.get("domains", []):
        idx = text.find(domain)
        if idx >= 0:
            # Some campaign infrastructure can also be used legitimately; escalate when paired with other behavior.
            sev = str(iocs.get("infrastructure_severity", "medium")).lower()
            findings.append(Finding(
                sev if sev in SEVERITY_RANK else "medium", "POLINRIDER_INFRA", rel,
                "Known campaign C2/infrastructure host detected.", line_of(text, idx)))
            hits.add("infra")
    return hits


# --- Behavioural detectors -------------------------------------------------
# These deliberately require evidence of a real capability rather than a bare
# identifier. `RegExp.prototype.exec` and a URL string constant are ordinary
# JavaScript and must never be mistaken for a download-and-execute chain.

CHILD_PROCESS_BINDING = re.compile(
    r"""require\s*\(\s*['"](?:node:)?child_process['"]\s*\)"""
    r"""|from\s+['"](?:node:)?child_process['"]"""
    r"""|import\s+['"](?:node:)?child_process['"]"""
    r"""|import\s*\(\s*['"](?:node:)?child_process['"]\s*\)"""
)
# Names that do not collide with common non-Node APIs. Bare `exec(` is excluded
# on purpose: `someRegExp.exec(str)` is extremely common and entirely benign.
PROCESS_LAUNCH_CALL = re.compile(r"\b(?:execSync|execFile|execFileSync|spawnSync|forkSync)\s*\(|\bchild_process\s*\.\s*\w+\s*\(")
NETWORK_CALL = re.compile(
    r"""\bfetch\s*\(|\baxios\s*[.(]|\bgot\s*[.(]|\bsuperagent\b|\bundici\b|\bXMLHttpRequest\b|\bWebSocket\s*\("""
    r"""|\bhttps?\s*\.\s*(?:get|request)\s*\("""
    r"""|require\s*\(\s*['"](?:node:)?(?:http|https|net|dgram|dns)['"]\s*\)"""
    r"""|from\s+['"](?:node:)?(?:http|https|net|dgram|dns)['"]""",
    re.IGNORECASE,
)
SHELL_DOWNLOAD = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b", re.IGNORECASE)
SHELL_PIPE_EXEC = re.compile(
    r"(?:curl|wget)[^\n]{0,300}\|\s*(?:sh|bash|zsh)|powershell[^\n]{0,200}(?:iex|invoke-expression)",
    re.IGNORECASE,
)
# Deliberately excludes decodeURIComponent: it is ordinary URL handling and its presence
# used to escalate legitimate download code to CRITICAL. Base64/char-code decoding next to
# dynamic execution is the signal that actually distinguishes a packer.
DECODER_CALL = re.compile(
    # `[^;\n]` rather than `[^)]`: the argument list frequently contains a nested call,
    # e.g. Buffer.from(await res.text(), 'base64'), which an inner-paren-free class misses.
    r"""\batob\s*\(|Buffer\s*\.\s*from\s*\([^;\n]{0,120}['"]base64['"]"""
    r"""|String\s*\.\s*fromCharCode|\bunescape\s*\("""
)
EVAL_CALL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
# Campaign tag. Every reported generation writes a short literal to a short-named
# property of the global object, but the property name (`!`, `_V`, `i`, `e`, `o`, ...)
# and the value (`4-1928`, `9-0191-4`, `A10-*19290`, `NPM`, ...) both change per build.
# Matching either literal is therefore worthless; this matches the SHAPE:
#   global | globalThis   .<1-2 char prop> | ['<1-3 char prop>']   =   '<short literal>'
# Measured against 36,259 real .js/.mjs/.cjs/.ts files in node_modules: 0 matches.
POLINRIDER_GLOBAL_TAG = re.compile(
    r"""\bglobal(?:This)?\s*"""
    r"""(?:\[\s*(['"])[^'"]{1,3}\1\s*\]|\.\s*[A-Za-z_$][A-Za-z0-9_$]?)"""
    r"""\s*=\s*(['"`])[^'"`\n]{0,40}\2"""
)

# Obfuscator-generated identifier family. The published name is one instance of a
# per-build pattern, so that literal is as fragile as the version tag; the family is
# matched instead. Same corpus: 0 matches in 36,259 files, so a single occurrence is
# enough to report. (Indicator literals deliberately live in the IOC file, not here:
# naming one in this source would make the scanner flag itself.)
OBFUSCATED_IDENTIFIER = re.compile(r"_\$_[0-9a-fA-F]{2,8}\b")


def scan_code_behavior(path: Path, rel: str, text: str, policy: dict, findings: list[Finding], ioc_hits: set[str]) -> None:
    ext = path.suffix.lower()
    is_code = ext in CODE_EXTS or is_config_file(path) or is_entrypoint_file(path)
    is_markup = ext in MARKUP_EXTS
    is_shell = is_shell_like(path, rel)
    if not (is_code or is_markup or is_shell):
        return

    # An image is not a document: SVG carrying script is a payload vector, whereas an
    # HTML file with <script src> is simply an HTML file. Only image-like markup is flagged.
    if ext in {".svg", ".xml"}:
        m = re.search(r"<script\b|\bon(?:load|error|click|mouseover)\s*=|javascript:", text, re.IGNORECASE)
        if m:
            findings.append(Finding(
                "high", "MARKUP_EMBEDDED_SCRIPT", rel,
                "Executable script content inside an image/markup asset; SVG payloads are a known malware vector.",
                line_of(text, m.start()),
            ))

    scan_campaign_signatures(rel, text, findings)

    # Hidden payload / formatting anomalies.
    m = re.search(rf"[ \t]{{{int(policy['hidden_whitespace_run'])},}}\S", text)
    if m:
        findings.append(Finding("high", "HIDDEN_WHITESPACE", rel, "Very long whitespace run immediately before content may conceal a payload.", line_of(text, m.start())))
    m = re.search(rf"\t{{{int(policy['max_tab_run'])},}}", text)
    if m:
        findings.append(Finding("high", "ABNORMAL_TABS", rel, "Abnormally long tab run detected.", line_of(text, m.start())))
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > int(policy["max_line_length"]):
            findings.append(Finding("high", "EXTREME_LINE_LENGTH", rel, "Extremely long source line may contain generated or obfuscated payload.", n))
            break

    # Console use. Hygiene rather than compromise, so severity is policy-driven and
    # test/tooling directories can be exempted wholesale.
    methods = "|".join(re.escape(x) for x in policy.get("block_console_methods", []))
    if is_code and methods and not path_matches_any(rel, policy.get("console_exempt_globs", [])):
        m = re.search(rf"\bconsole\s*\.\s*(?:{methods})\s*\(", text)
        if m:
            sev = str(policy.get("console_severity", "medium")).lower()
            if sev not in SEVERITY_RANK:
                sev = "medium"
            findings.append(Finding(sev, "CONSOLE_CALL", rel, "Blocked console method found; use the project logger or remove debug output.", line_of(text, m.start())))

    # SQL injection / unsafe raw SQL patterns.
    sql_patterns = [
        r"\b(?:query|execute|raw|queryRawUnsafe|executeRawUnsafe)\s*\(\s*`[^`]*\$\{",
        r"\b(?:query|execute|raw|queryRawUnsafe|executeRawUnsafe)\s*\([^\n]{0,300}(?:\+\s*[A-Za-z_$]|[A-Za-z_$][\w$]*\s*\+)",
        r"\$queryRawUnsafe\s*\(",
        r"\$executeRawUnsafe\s*\(",
        r"sequelize\s*\.\s*query\s*\(\s*`[^`]*\$\{",
    ]
    for pat in sql_patterns:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m:
            findings.append(Finding("high", "POSSIBLE_SQL_INJECTION", rel, "Dynamic/raw SQL construction detected; parameterize the query.", line_of(text, m.start())))
            break

    # Generic obfuscation and code-execution behaviour.
    has_eval = bool(EVAL_CALL.search(text))
    has_decoder = bool(DECODER_CALL.search(text))
    has_child_process = bool(CHILD_PROCESS_BINDING.search(text))
    has_exec = has_child_process or bool(PROCESS_LAUNCH_CALL.search(text))
    has_shell_download = bool(SHELL_DOWNLOAD.search(text))
    has_network = has_shell_download or bool(NETWORK_CALL.search(text))
    has_shell_pipe = bool(SHELL_PIPE_EXEC.search(text))

    if is_shell:
        m = re.search(
            r"(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|certutil)[^\n]{0,200}"
            r"(?:https?://(?:\d{1,3}\.){3}\d{1,3}"
            r"|-o\s|--output|-OutFile"
            r"|>\s*\S+\.(?:exe|bat|cmd|ps1|sh|scr|dll))",
            text, re.IGNORECASE,
        )
        if m:
            # A download whose result is checked against a pinned digest is a different
            # thing from a dropper: the fetched bytes cannot be substituted. Report it,
            # but do not block on it.
            verified = re.search(
                r"sha256sum[^\n]{0,80}(?:--check|-c)\b|shasum\s+-a\s+256[^\n]{0,40}-c"
                r"|Get-FileHash|openssl\s+dgst\s+-sha256",
                text, re.IGNORECASE,
            )
            findings.append(Finding(
                "medium" if verified else "high", "SHELL_REMOTE_FETCH", rel,
                "Shell/batch script downloads a remote file to disk"
                + (", but verifies it against a pinned checksum."
                   if verified else
                   "; this is the reported PolinRider dropper pattern."),
                line_of(text, m.start()),
            ))

    if has_shell_pipe:
        m = SHELL_PIPE_EXEC.search(text)
        findings.append(Finding("critical", "DOWNLOAD_EXECUTE", rel, "Download-and-execute shell behavior detected.", line_of(text, m.start()) if m else None))
    if has_eval and has_decoder:
        m = EVAL_CALL.search(text)
        findings.append(Finding("critical", "DECODE_AND_EXECUTE", rel, "Encoded/decoded content is dynamically executed.", line_of(text, m.start()) if m else None))
    elif has_eval:
        m = EVAL_CALL.search(text)
        findings.append(Finding("high", "DYNAMIC_CODE_EXECUTION", rel, "Dynamic code execution (eval/new Function) is blocked.", line_of(text, m.start()) if m else None))
    if has_exec and has_network:
        m = CHILD_PROCESS_BINDING.search(text) or PROCESS_LAUNCH_CALL.search(text)
        corroborated = has_decoder or bool(ioc_hits) or has_shell_download
        findings.append(Finding(
            "critical" if corroborated else "high",
            "NETWORK_PROCESS_CHAIN", rel,
            "Process execution combined with network/download behavior is highly suspicious.",
            line_of(text, m.start()) if m else None,
        ))
    elif has_exec and (is_config_file(path) or is_entrypoint_file(path)):
        m = CHILD_PROCESS_BINDING.search(text) or PROCESS_LAUNCH_CALL.search(text)
        findings.append(Finding("high", "CONFIG_PROCESS_EXEC", rel, "Process execution from an application entry point/config file requires removal or explicit redesign.", line_of(text, m.start()) if m else None))

    if is_config_file(path):
        limit = int(policy.get("max_config_file_bytes", 16384))
        if len(text) > limit:
            findings.append(Finding(
                "high", "OVERSIZED_CONFIG", rel,
                f"Build config file is {len(text)} bytes (limit {limit}). Reported PolinRider "
                "infections inflate 80-200 byte configs to tens of kilobytes.",
            ))

    # Length anomaly, independent of how the payload was concealed.
    #
    # HIDDEN_WHITESPACE only fires above a fixed padding run, so a variant that pads with
    # 50 spaces instead of 300 would slip past it. Line length does not care: the payload
    # still has to live somewhere. Measured across all 85 branches of this repository, the
    # longest line in any build config is 103 characters, so the config limit has a wide
    # margin while still catching an append of any size.
    longest, longest_no = 0, 1
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > longest:
            longest, longest_no = len(line), n
    if is_config_file(path):
        cfg_limit = int(policy.get("max_config_line_length", 400))
        if longest > cfg_limit:
            findings.append(Finding(
                "high", "CONFIG_LINE_ANOMALY", rel,
                f"Build config contains a {longest}-character line (limit {cfg_limit}). "
                "Appending a payload to the end of a config line is the reported PolinRider "
                "injection shape, and needs no whitespace padding to hide.",
                longest_no,
            ))
    elif is_entrypoint_file(path):
        # Application entry points are a confirmed target of this campaign, and a payload
        # appended here executes when the SERVICE STARTS, not only at build time. Measured
        # across 3,975 entry-point files on all 85 branches, the longest real line is 1,004
        # characters, so this limit keeps a wide margin.
        ep_limit = int(policy.get("max_entrypoint_line_length", 1500))
        if longest > ep_limit:
            findings.append(Finding(
                "high", "ENTRYPOINT_LINE_ANOMALY", rel,
                f"Application entry point contains a {longest}-character line (limit {ep_limit}). "
                "Payloads appended to entry points execute at service startup, not just during a build.",
                longest_no,
            ))
    elif is_code:
        soft = int(policy.get("anomalous_line_length", 2500))
        if longest > soft:
            findings.append(Finding(
                "high" if (has_decoder or has_eval) else "medium", "ANOMALOUS_LINE_LENGTH", rel,
                f"Source line of {longest} characters is far outside this project's norm"
                + (" and the file also decodes or dynamically executes content." if (has_decoder or has_eval)
                   else "; review it for generated or appended content."),
                longest_no,
            ))

    encoded_pat = re.compile(rf"[A-Za-z0-9+/=_-]{{{int(policy['high_entropy_min_length'])},}}")
    for m in encoded_pat.finditer(text):
        token = m.group(0)
        if entropy(token) >= float(policy["high_entropy_threshold"]):
            sev = "high" if (has_decoder or has_eval or has_exec or ioc_hits) else "medium"
            findings.append(Finding(sev, "HIGH_ENTROPY_PAYLOAD", rel, "Long high-entropy token may be an encoded/obfuscated payload.", line_of(text, m.start())))
            break

    # Trojan Source: characters that make the rendered source differ from what runs.
    for ch in BIDI_CONTROLS:
        idx = text.find(ch)
        if idx >= 0:
            findings.append(Finding("high", "BIDI_CONTROL", rel, "Unicode bidirectional control character detected in source.", line_of(text, idx)))
            break

    for ch, name, sev in INVISIBLE_CHARS:
        idx = text.find(ch)
        # A byte-order mark at position 0 is legitimate; anywhere else it is not.
        if idx == 0 and ch == "\ufeff":
            idx = text.find(ch, 1)
        if idx >= 0:
            findings.append(Finding(
                sev, "INVISIBLE_CHARACTER", rel,
                f"Invisible character {name} (U+{ord(ch):04X}) in source; it renders as nothing "
                "but is part of the code.",
                line_of(text, idx),
            ))
            break

    m = MIXED_SCRIPT_WORD.search(text)
    if m:
        findings.append(Finding(
            "medium", "MIXED_SCRIPT_IDENTIFIER", rel,
            "Word mixes Latin with Cyrillic/Greek characters. Homoglyphs let a reviewer read "
            "one identifier while the runtime sees another.",
            line_of(text, m.start()),
        ))


def scan_campaign_signatures(rel: str, text: str, findings: list[Finding]) -> None:
    """Campaign signatures that stay valid on minified/bundled code.

    These are the only behavioural checks safe to run against build artifacts: both were
    measured at zero matches across 36,259 real node_modules JS/TS files, which include
    plenty of minified bundles. The generic rules (line length, entropy, eval, download)
    all fire on ordinary bundler output and are excluded from the artifact profile.
    """
    m = POLINRIDER_GLOBAL_TAG.search(text)
    if m:
        findings.append(Finding(
            "critical", "POLINRIDER_GLOBAL_TAG", rel,
            f"Short literal assigned to a short-named global ({m.group(0)[:48]!r}) matches the "
            "PolinRider runtime tag shape used across every reported variant.",
            line_of(text, m.start()),
        ))
    m = OBFUSCATED_IDENTIFIER.search(text)
    if m:
        findings.append(Finding(
            "critical", "OBFUSCATED_IDENTIFIER", rel,
            f"Obfuscator-generated identifier {m.group(0)!r} of the family used by the "
            "PolinRider packer.",
            line_of(text, m.start()),
        ))


PERMISSIVE_CORS = re.compile(
    r"""['"]?Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]"""
    r"""|['"]?Access-Control-Allow-Origin['"]?\s*,?\s*\n?\s*value\s*:\s*['"]\*['"]"""
)
CORS_CREDENTIALLED = re.compile(
    r"""Access-Control-Allow-(?:Headers|Credentials)['"]?\s*[,:]""", re.IGNORECASE
)


def scan_http_headers(path: Path, rel: str, text: str, findings: list[Finding]) -> None:
    """HTTP response-header misconfiguration in application/config code.

    Restricted to JS/TS sources: the scanner is itself scanned, and this project's own
    test fixtures contain the very header strings being matched.
    """
    if path.suffix.lower() not in CODE_EXTS and not is_config_file(path):
        return
    m = PERMISSIVE_CORS.search(text)
    if not m:
        return
    credentialled = bool(CORS_CREDENTIALLED.search(text))
    findings.append(Finding(
        "high" if credentialled else "medium", "PERMISSIVE_CORS", rel,
        "Access-Control-Allow-Origin is '*'"
        + (", and the same block allows Authorization/credential headers, so any origin can "
           "call these routes with a bearer token." if credentialled
           else "; any origin can read these responses."),
        line_of(text, m.start()),
    ))


def scan_vscode(path: Path, rel: str, text: str, findings: list[Finding]) -> None:
    if rel == ".vscode/tasks.json":
        if re.search(r"[\"']?runOn[\"']?\s*:\s*[\"']folderOpen[\"']", text, re.IGNORECASE):
            findings.append(Finding("critical", "VSCODE_AUTORUN", rel, "VS Code task auto-runs on folder open, a known malware execution vector."))
        if re.search(r"(?:curl|wget|powershell|Invoke-WebRequest|child_process|node\s+-e)", text, re.IGNORECASE):
            findings.append(Finding("critical", "VSCODE_EXECUTION_TASK", rel, "VS Code task contains network/shell execution behavior."))
    if rel == ".vscode/settings.json" and re.search(r"task\.allowAutomaticTasks[\"']?\s*:\s*true", text, re.IGNORECASE):
        findings.append(Finding("critical", "VSCODE_AUTOTASKS_ALLOWED", rel, "Automatic VS Code tasks are explicitly enabled."))


def scan_package_manager_config(path: Path, rel: str, text: str, policy: dict, findings: list[Finding]) -> None:
    name = path.name
    allowed = set(policy.get("allowed_npm_registries", []))
    if name in {".pnpmfile.cjs", ".pnpmfile.js"}:
        findings.append(Finding("high", "PNPM_HOOK_FILE", rel, "pnpm hook file executes JavaScript during dependency resolution/install and is blocked by default."))
    if name == ".npmrc":
        if re.search(r"(?im)^\s*(?:script-shell|node-options)\s*=", text):
            findings.append(Finding("high", "NPM_EXEC_CONFIG", rel, "npm execution-affecting configuration is blocked."))
        if re.search(r"(?im)^\s*ignore-scripts\s*=\s*(?:false|0|no)\s*$", text):
            findings.append(Finding("high", "NPM_SCRIPTS_ENABLED", rel, "Repository attempts to enable npm lifecycle scripts."))
        for m in re.finditer(r"(?im)^\s*(?:registry|@[^:]+:registry)\s*=\s*(\S+)", text):
            host = urlparse(m.group(1)).hostname
            if host and host not in allowed:
                findings.append(Finding("high", "CUSTOM_NPM_REGISTRY", rel, f"Unapproved npm registry host: {host}", line_of(text, m.start())))
    if name in {".yarnrc", ".yarnrc.yml"}:
        if re.search(r"(?im)^\s*yarnPath\s*:", text) or re.search(r"(?im)^\s*plugins\s*:", text):
            findings.append(Finding("high", "YARN_EXEC_PLUGIN", rel, "Yarn path/plugins can execute repository-controlled code during install and are blocked."))
        if re.search(r"(?im)^\s*enableScripts\s*:\s*true\s*$", text):
            findings.append(Finding("high", "YARN_SCRIPTS_ENABLED", rel, "Repository attempts to enable dependency build/lifecycle scripts."))
        for m in re.finditer(r"(?im)^\s*npmRegistryServer\s*:\s*[\"']?(https?://[^\s\"']+)", text):
            host = urlparse(m.group(1)).hostname
            if host and host not in allowed:
                findings.append(Finding("high", "CUSTOM_YARN_REGISTRY", rel, f"Unapproved Yarn registry host: {host}", line_of(text, m.start())))


def dependency_name_bad(name: str, iocs: dict) -> bool:
    return name in set(iocs.get("known_malicious_packages", []))


def scan_package_json(path: Path, rel: str, text: str, policy: dict, iocs: dict, findings: list[Finding]) -> None:
    if path.name != "package.json":
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        findings.append(Finding("high", "INVALID_PACKAGE_JSON", rel, f"package.json is invalid JSON: {e.msg}", e.lineno))
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = obj.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if dependency_name_bad(str(name), iocs):
                findings.append(Finding("critical", "KNOWN_MALICIOUS_PACKAGE", rel, f"Known/reported malicious package dependency: {name}"))
            s = str(spec).strip()
            if not policy.get("allow_git_dependencies", False) and re.match(r"^(?:git\+|git://|github:|gitlab:|bitbucket:|https?://)", s, re.IGNORECASE):
                findings.append(Finding("high", "REMOTE_DEPENDENCY_SPEC", rel, f"Remote/git dependency spec is blocked by baseline policy: {name}"))
    scripts = obj.get("scripts") or {}
    if isinstance(scripts, dict):
        for key in sorted(REVIEWED_EXEC_SCRIPTS):
            cmd = scripts.get(key)
            if not isinstance(cmd, str):
                continue
            if re.search(r"(?:curl|wget|powershell|Invoke-WebRequest|\bnode\s+-e\b|\beval\b|https?://)", cmd, re.IGNORECASE):
                findings.append(Finding("critical", "DANGEROUS_LIFECYCLE_SCRIPT", rel, f"Suspicious {key} execution script contains network/dynamic execution behavior."))


def approved_registry_url(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in allowed_hosts


def scan_package_lock(path: Path, rel: str, text: str, policy: dict, iocs: dict, findings: list[Finding]) -> None:
    allowed = set(policy.get("allowed_npm_registries", []))
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            findings.append(Finding("high", "INVALID_LOCKFILE", rel, f"Invalid npm lockfile JSON: {e.msg}", e.lineno))
            return
        packages = obj.get("packages") or {}
        if isinstance(packages, dict):
            for pkg_path, meta in packages.items():
                if not isinstance(meta, dict) or pkg_path == "":
                    continue
                name = meta.get("name")
                if not name and pkg_path.startswith("node_modules/"):
                    name = pkg_path.rsplit("node_modules/", 1)[-1]
                if name and dependency_name_bad(str(name), iocs):
                    findings.append(Finding("critical", "KNOWN_MALICIOUS_PACKAGE", rel, f"Known/reported malicious package in lockfile: {name}"))
                resolved = meta.get("resolved")
                if isinstance(resolved, str) and resolved and not resolved.startswith(("file:", "workspace:")):
                    if not approved_registry_url(resolved, allowed):
                        findings.append(Finding("critical", "LOCKFILE_REMOTE_ARTIFACT", rel, f"Lockfile resolves package from unapproved/non-HTTPS location: {urlparse(resolved).hostname or resolved[:40]}"))
                    if policy.get("require_npm_lock_integrity", True) and not meta.get("integrity"):
                        findings.append(Finding("high", "LOCKFILE_MISSING_INTEGRITY", rel, "Remote npm lockfile artifact is missing integrity metadata."))

        # v1 lockfiles may use a dependencies tree rather than `packages`.
        def visit_dep_tree(tree: object) -> None:
            if not isinstance(tree, dict):
                return
            for name, meta in tree.items():
                if dependency_name_bad(str(name), iocs):
                    findings.append(Finding("critical", "KNOWN_MALICIOUS_PACKAGE", rel, f"Known/reported malicious package in lockfile: {name}"))
                if isinstance(meta, dict):
                    resolved = meta.get("resolved")
                    if isinstance(resolved, str) and resolved and not resolved.startswith(("file:", "workspace:")) and not approved_registry_url(resolved, allowed):
                        findings.append(Finding("critical", "LOCKFILE_REMOTE_ARTIFACT", rel, f"Lockfile resolves package from unapproved/non-HTTPS location: {urlparse(resolved).hostname or resolved[:40]}"))
                    visit_dep_tree(meta.get("dependencies"))

        visit_dep_tree(obj.get("dependencies"))
        return

    if path.name in {"yarn.lock", "pnpm-lock.yaml"}:
        for bad in iocs.get("known_malicious_packages", []):
            if re.search(rf"(?m)(?:^|[/@\s\"']){re.escape(bad)}(?:@|/|\s|\"|'|:)", text):
                findings.append(Finding("critical", "KNOWN_MALICIOUS_PACKAGE", rel, f"Known/reported malicious package in lockfile: {bad}"))
        # Report each unapproved host once rather than once per resolved artifact:
        # a single wrong registry would otherwise emit thousands of identical findings.
        bad_hosts: dict[str, int] = {}
        for m in re.finditer(r"https?://[^\s\"']+", text):
            url = m.group(0).rstrip(",)}]")
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                continue
            if host not in allowed or parsed.scheme != "https":
                bad_hosts.setdefault(host, line_of(text, m.start()))
        for host, line in sorted(bad_hosts.items()):
            findings.append(Finding("critical", "LOCKFILE_REMOTE_ARTIFACT", rel, f"Lockfile references unapproved registry/artifact host: {host}", line))
        if re.search(r"(?im)(?:git\+ssh|git\+https|git://|github\.com/.+\.git)", text) and not policy.get("allow_git_dependencies", False):
            findings.append(Finding("high", "LOCKFILE_GIT_DEPENDENCY", rel, "Git dependency detected in lockfile and is blocked by baseline policy."))


def scan_actions(path: Path, rel: str, text: str, findings: list[Finding]) -> None:
    is_workflow = rel.startswith(".github/workflows/") and path.suffix.lower() in {".yml", ".yaml"}
    is_action_manifest = path.name in ACTION_MANIFEST_NAMES
    if not (is_workflow or is_action_manifest):
        return
    for m in re.finditer(r"(?m)^\s*(?:-\s*)?uses\s*:\s*[\"']?([^\s\"']+)", text):
        value = m.group(1)
        if value.startswith("./"):
            continue
        if value.startswith("docker://"):
            if "@sha256:" not in value:
                findings.append(Finding("critical", "UNPINNED_DOCKER_ACTION", rel, f"Docker action must be digest-pinned: {value}", line_of(text, m.start())))
            continue
        if "@" not in value:
            findings.append(Finding("critical", "UNPINNED_ACTION", rel, f"GitHub Action has no immutable ref: {value}", line_of(text, m.start())))
            continue
        _, ref = value.rsplit("@", 1)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            findings.append(Finding("critical", "UNPINNED_ACTION", rel, f"GitHub Action must be pinned to a full 40-character commit SHA: {value}", line_of(text, m.start())))

    if not is_workflow:
        return

    # Common dangerous pull_request_target anti-pattern: checkout of attacker head in privileged context.
    if re.search(r"(?m)^\s*pull_request_target\s*:", text) and re.search(
        r"ref\s*:\s*.*github\.event\.pull_request\.(?:head\.sha|head\.ref)", text
    ):
        findings.append(Finding("critical", "PR_TARGET_UNTRUSTED_CHECKOUT", rel, "pull_request_target workflow appears to checkout PR head with privileged context."))


# Reported PolinRider behaviour: the dropper adds its own artifacts to .gitignore so
# they stay invisible to `git status`, and removes `.env` so secrets become committable.
DROPPER_IGNORE = re.compile(r"(?im)^\s*!?\s*(?:.*/)?(?:config|temp_auto_push|temp_interactive_push)\.bat\s*$")


def scan_gitignore(path: Path, rel: str, text: str, findings: list[Finding]) -> None:
    if path.name != ".gitignore":
        return
    m = DROPPER_IGNORE.search(text)
    if m:
        findings.append(Finding(
            "critical", "DROPPER_IGNORE_ENTRY", rel,
            "`.gitignore` hides a batch artifact associated with the PolinRider dropper.",
            line_of(text, m.start()),
        ))
    # `!.env-example` / `!.env.sample` are legitimate; a real env file is not.
    for m in re.finditer(r"(?im)^\s*!\s*(?:.*/)?\.env(?![-.](?:example|sample|template|dist))[^\s]*\s*$", text):
        findings.append(Finding(
            "high", "GITIGNORE_ENV_UNIGNORED", rel,
            "`.gitignore` explicitly re-includes an .env file, which makes secrets committable.",
            line_of(text, m.start()),
        ))


def file_bytes_equal(a: Path, b: Path) -> bool:
    a_exists, b_exists = a.exists(), b.exists()
    if not a_exists and not b_exists:
        return True
    if a_exists != b_exists:
        return False
    try:
        if a.is_dir() or b.is_dir():
            return a.is_dir() and b.is_dir()
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def collect_relative_files(root: Path, prefix: str, index: set[str] | None = None) -> set[str]:
    """Files at `prefix` (a file path or directory prefix) within root.

    `index` is a precomputed symlink-safe file listing; it is used instead of
    walking the tree again for every prefix.
    """
    if index is None:
        index = safe_relative_files(root)
    if prefix in index:
        return {prefix}
    dir_prefix = prefix.rstrip("/") + "/"
    return {rel for rel in index if rel.startswith(dir_prefix)}


def package_sensitive_projection(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"exists": True, "invalid": True}
    scripts = obj.get("scripts") if isinstance(obj.get("scripts"), dict) else {}
    lifecycle = {k: scripts.get(k) for k in sorted(REVIEWED_EXEC_SCRIPTS) if k in scripts}
    return {"exists": True, "packageManager": obj.get("packageManager"), "reviewedExecutionScripts": lifecycle}


def sensitive_changes(candidate: Path, base: Path) -> list[str]:
    changed: set[str] = set()
    candidate_index = safe_relative_files(candidate)
    base_index = safe_relative_files(base)

    # Protected pipeline/control files.
    for prefix in SENSITIVE_PREFIXES:
        rels = collect_relative_files(candidate, prefix, candidate_index) | collect_relative_files(base, prefix, base_index)
        if not rels and prefix.endswith(("CODEOWNERS", "dependabot.yml")):
            rels = {prefix}
        for rel in rels:
            if not file_bytes_equal(candidate / rel, base / rel):
                changed.add(rel)

    # Package-manager execution configuration anywhere in the repository.
    names = {rel for rel in (candidate_index | base_index) if rel.rsplit("/", 1)[-1] in SENSITIVE_CONFIG_NAMES}
    for rel in names:
        if not file_bytes_equal(candidate / rel, base / rel):
            changed.add(rel)

    # Only package.json fields that alter package-manager executable/version or lifecycle execution.
    package_paths = {rel for rel in (candidate_index | base_index) if rel.rsplit("/", 1)[-1] == "package.json"}
    for rel in package_paths:
        if package_sensitive_projection(candidate / rel) != package_sensitive_projection(base / rel):
            changed.add(rel + " [packageManager/lifecycle/ci:prepare]")
    return sorted(changed)


# --- Exceptions ------------------------------------------------------------

def validate_exceptions(policy: dict, findings: list[Finding], today: date) -> list[dict]:
    """Return usable exceptions, reporting invalid and expired entries."""
    usable: list[dict] = []
    raw = policy.get("exceptions") or []
    if not isinstance(raw, list):
        findings.append(Finding("critical", "EXCEPTION_INVALID", "security/policy.json", "`exceptions` must be a list."))
        return usable
    for i, item in enumerate(raw):
        where = f"security/policy.json#exceptions[{i}]"
        if not isinstance(item, dict):
            findings.append(Finding("critical", "EXCEPTION_INVALID", where, "Exception entry must be an object."))
            continue
        rule = item.get("rule")
        paths = item.get("paths")
        reason = item.get("reason")
        expires = item.get("expires")
        problems: list[str] = []
        if not isinstance(rule, str) or not rule:
            problems.append("`rule` is required")
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
            problems.append("`paths` must be a non-empty list of globs")
        if not isinstance(reason, str) or len(reason.strip()) < 12:
            problems.append("`reason` must be a meaningful explanation")
        if not isinstance(expires, str) or not expires:
            problems.append("`expires` (YYYY-MM-DD) is required so exceptions are re-reviewed")
        parsed_expiry: date | None = None
        if isinstance(expires, str) and expires:
            try:
                parsed_expiry = date.fromisoformat(expires)
            except ValueError:
                problems.append("`expires` must be an ISO date (YYYY-MM-DD)")
        if isinstance(rule, str) and rule in NON_EXEMPT_RULES:
            problems.append(f"rule {rule} can never be excepted")
        if problems:
            findings.append(Finding("critical", "EXCEPTION_INVALID", where, "Invalid policy exception: " + "; ".join(problems)))
            continue
        assert parsed_expiry is not None
        if parsed_expiry < today:
            findings.append(Finding(
                "high", "EXCEPTION_EXPIRED", where,
                f"Policy exception for {rule} expired on {parsed_expiry.isoformat()}; re-review it or remove the underlying risk.",
            ))
            continue
        usable.append({"rule": rule, "paths": paths, "reason": reason.strip(), "expires": parsed_expiry.isoformat()})
    return usable


def apply_exceptions(findings: list[Finding], exceptions: list[dict]) -> list[Finding]:
    if not exceptions:
        return findings
    out: list[Finding] = []
    for f in findings:
        if f.rule in NON_EXEMPT_RULES:
            out.append(f)
            continue
        match = next((e for e in exceptions if e["rule"] == f.rule and path_matches_any(f.path, e["paths"])), None)
        if match is None:
            out.append(f)
            continue
        # Downgraded, never deleted: the finding stays visible in logs and reports.
        out.append(replace(
            f,
            severity="info",
            exempted=True,
            message=f"{f.message} [accepted exception until {match['expires']}: {match['reason']}]",
        ))
    return out


def merge_policy(defaults: dict, overlay: dict) -> tuple[dict, list[Finding]]:
    """Merge a repository's policy overlay onto the central defaults.

    A repository legitimately needs its own exceptions, thresholds and registry
    allowances. It must not be able to switch the gate off: `block_severities` may be
    widened but never narrowed, so an overlay can tighten the gate and never loosen it.
    The trusted pull-request gate additionally reads the overlay from the BASE commit, so
    a pull request cannot introduce one at all without a reviewed control change.
    """
    findings: list[Finding] = []
    if not isinstance(overlay, dict):
        findings.append(Finding("critical", "POLICY_OVERLAY_INVALID", "security/policy.json",
                                "Policy overlay is not a JSON object; central defaults enforced."))
        return dict(defaults), findings

    merged = {**defaults, **overlay}

    # The dependency-audit floor may only move downward (stricter). "critical" is the
    # loosest setting, so an overlay must not raise the floor above the central default.
    audit_order = ["info", "low", "moderate", "high", "critical"]
    d_audit = defaults.get("audit_severity", "high")
    m_audit = merged.get("audit_severity", d_audit)
    if d_audit in audit_order and m_audit in audit_order and audit_order.index(m_audit) > audit_order.index(d_audit):
        merged["audit_severity"] = d_audit
        findings.append(Finding(
            "critical", "POLICY_OVERLAY_WEAKENED", "security/policy.json",
            f"Repository policy raised audit_severity from {d_audit!r} to {m_audit!r}, which "
            "audits less. Central defaults are enforced instead.",
        ))

    default_block = set(defaults.get("block_severities", ["critical", "high"]))
    merged_block = set(merged.get("block_severities", []) or [])
    removed = default_block - merged_block
    if removed:
        merged["block_severities"] = sorted(default_block | merged_block,
                                            key=lambda x: SEVERITY_RANK.get(x, 0))
        findings.append(Finding(
            "critical", "POLICY_OVERLAY_WEAKENED", "security/policy.json",
            f"Repository policy removed blocking severities {sorted(removed)}. Central "
            "defaults are enforced instead: a repository may tighten this gate, never loosen it.",
        ))
    return merged, findings


def scan_repository(
    root: Path,
    policy: dict,
    iocs: dict,
    base_root: Path | None = None,
    security_reviewed: bool = False,
    today: date | None = None,
) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    exceptions = validate_exceptions(policy, findings, today or date.today())

    if base_root is not None:
        base_root = base_root.resolve()
        changes = sensitive_changes(root, base_root)
        if changes and not security_reviewed:
            for rel in changes[:30]:
                findings.append(Finding("critical", "SECURITY_CONTROL_CHANGE", rel, "Security-sensitive CI/package-manager control changed without the required security-reviewed label and CODEOWNER review."))
            if len(changes) > 30:
                findings.append(Finding("critical", "SECURITY_CONTROL_CHANGE", ".", f"{len(changes) - 30} additional security-sensitive files changed."))

    scan_gitlinks(root, findings)
    scan_codeowners(root, findings)
    scan_commit_authors(root, iocs, findings)

    # Committed build output is code that reaches production, and it is produced on a
    # developer workstation - precisely the machine this campaign compromises. It is
    # normally skipped for performance, so scanning it must be opted into explicitly, and
    # it gets the reduced artifact profile because minified bundles trip every generic rule.
    artifact_globs = list(policy.get("artifact_globs", [])) if policy.get("scan_build_artifacts") else []
    unskip = frozenset(
        g.split("/", 1)[0] for g in artifact_globs
        if g.split("/", 1)[0] and "*" not in g.split("/", 1)[0]
    )

    max_bytes = int(policy.get("max_text_file_bytes", 50 * 1024 * 1024))
    for path in safe_walk(root, findings, unskip):
        rel = relpath(path, root)
        is_artifact = bool(artifact_globs) and path_matches_any(rel, artifact_globs)
        data = read_bytes(path, max_bytes)
        if data is None:
            # Large source/config/manifest files are suspicious and bypass normal scanners.
            if path.suffix.lower() in CODE_EXTS or is_config_file(path) or path.name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
                findings.append(Finding("high", "OVERSIZED_SECURITY_INPUT", rel, "Security-relevant file exceeds scanner size limit."))
            continue

        if path.suffix.lower() in ASSET_EXTS:
            scan_asset(path, rel, data, iocs, findings)

        text = decode_text(data)
        if text is None:
            # Undecodable (binary) content is still searched for campaign markers, so a
            # payload hidden inside an image, font or other binary is not simply skipped.
            if not is_trusted_self_excluded(rel):
                scan_binary_iocs(rel, data, iocs, findings)
            continue
        if not is_trusted_self_excluded(rel):
            ioc_hits = scan_iocs(text, rel, iocs, findings)
            scan_path_iocs(rel, iocs, findings)
        else:
            ioc_hits = set()

        if is_artifact:
            # Reduced profile: campaign signatures and asset integrity only.
            scan_campaign_signatures(rel, text, findings)
            if path.suffix.lower() in {".svg", ".xml"}:
                m = re.search(r"<script\b|\bon(?:load|error|click|mouseover)\s*=|javascript:", text, re.IGNORECASE)
                if m:
                    findings.append(Finding(
                        "high", "MARKUP_EMBEDDED_SCRIPT", rel,
                        "Executable script content inside an image/markup asset.",
                        line_of(text, m.start()),
                    ))
            continue

        scan_code_behavior(path, rel, text, policy, findings, ioc_hits)
        scan_vscode(path, rel, text, findings)
        scan_http_headers(path, rel, text, findings)
        scan_package_manager_config(path, rel, text, policy, findings)
        scan_package_json(path, rel, text, policy, iocs, findings)
        scan_package_lock(path, rel, text, policy, iocs, findings)
        scan_actions(path, rel, text, findings)
        scan_gitignore(path, rel, text, findings)

    return apply_exceptions(findings, exceptions)


# --- Reporting -------------------------------------------------------------

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "warning", "info": "note"}


def build_sarif(findings: list[Finding], policy: dict) -> dict:
    rule_ids = sorted({f.rule for f in findings})
    rules = [{
        "id": rid,
        "name": rid,
        "shortDescription": {"text": rid.replace("_", " ").title()},
        "defaultConfiguration": {"level": "error"},
    } for rid in rule_ids]
    results = []
    for f in findings:
        region = {"startLine": f.line} if f.line else {"startLine": 1}
        results.append({
            "ruleId": f.rule,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": region,
                }
            }],
            "properties": {"severity": f.severity, "exempted": f.exempted},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "neotree-repo-scanner",
                "informationUri": "https://github.com/neotree/neotree-editor/blob/master/security/scan_repo.py",
                "semanticVersion": str(policy.get("version", "1")),
                "rules": rules,
            }},
            "results": results,
        }],
    }


def write_step_summary(findings: list[Finding], blocked: list[Finding], policy: dict) -> None:
    """Render a short Markdown table into the GitHub Actions job summary.

    A reviewer should be able to see what a red gate found without opening the log.
    """
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    counts = Counter(f.severity for f in findings)
    lines = ["## Repository policy scan", ""]
    lines.append("**BLOCKED**" if blocked else "**PASS**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"| {sev.upper()} | {counts[sev]} |")
    exempted = [f for f in findings if f.exempted]
    if blocked:
        lines += ["", "### Blocking findings", "", "| Rule | Location | Message |", "| --- | --- | --- |"]
        for f in blocked[:40]:
            loc = f"`{f.path}:{f.line}`" if f.line else f"`{f.path}`"
            lines.append(f"| `{f.rule}` | {loc} | {f.message[:160]} |")
        if len(blocked) > 40:
            lines.append(f"| … | | {len(blocked) - 40} more |")
        lines += ["", "See `docs/INCIDENT_RESPONSE.md`. Do not disable a scanner to go green."]
    if exempted:
        lines += ["", f"### Accepted exceptions ({len(exempted)})", ""]
        for f in exempted[:10]:
            lines.append(f"- `{f.rule}` — `{f.path}`")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail-closed repository malware and policy scanner.")
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--base-root", type=Path)
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY,
                    help="Central policy defaults.")
    ap.add_argument("--policy-overlay", type=Path,
                    help="Repository-specific policy merged onto the defaults. It may "
                         "tighten the gate but never loosen it.")
    ap.add_argument("--iocs", type=Path, default=DEFAULT_IOCS)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--security-reviewed", action="store_true")
    args = ap.parse_args()

    policy = load_json(args.policy)
    policy_findings: list[Finding] = []
    if args.policy_overlay and args.policy_overlay.is_file():
        policy, policy_findings = merge_policy(policy, load_json(args.policy_overlay))
    iocs = load_json(args.iocs)
    findings = policy_findings + scan_repository(
        args.root, policy, iocs, args.base_root, args.security_reviewed)

    blockers = set(policy.get("block_severities", ["critical", "high"]))
    blocked = [f for f in findings if f.severity in blockers]
    findings_sorted = sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line or 0, f.rule))

    for f in findings_sorted:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"{f.severity.upper():8} {f.rule:28} {loc} — {f.message}")
        emit_annotation(f)

    report_obj = {
        "scanner": "world-class-js-ts-ci",
        "policyVersion": policy.get("version"),
        "blocked": bool(blocked),
        "summary": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_RANK},
        "exempted": sum(1 for f in findings if f.exempted),
        "findings": [asdict(f) for f in findings_sorted],
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report_obj, indent=2) + "\n", encoding="utf-8")
    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(json.dumps(build_sarif(findings_sorted, policy), indent=2) + "\n", encoding="utf-8")

    write_step_summary(findings_sorted, blocked, policy)

    exempted = report_obj["exempted"]
    suffix = f", {exempted} accepted exception(s)" if exempted else ""
    print("\nSecurity policy:", "BLOCK" if blocked else "PASS", f"({len(findings)} findings, {len(blocked)} blocking{suffix})")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
