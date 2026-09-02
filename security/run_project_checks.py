#!/usr/bin/env python3
"""Run dependency, quality, test and build checks without dependency lifecycle scripts.

This script is intentionally executed only in an unprivileged `pull_request` job,
after the trusted malware gate has inspected the PR as data.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_policy() -> dict:
    """Central defaults merged with an optional repository overlay.

    Paths come from the environment so the reusable workflow can point at a checkout of
    the repository under test without this module needing to know where that is.
    """
    defaults_path = Path(os.environ.get("SECURITY_POLICY_DEFAULTS", HERE / "policy.defaults.json"))
    if not defaults_path.is_file():
        defaults_path = HERE / "policy.json"
    policy = json.loads(defaults_path.read_text(encoding="utf-8"))
    overlay_path = os.environ.get("SECURITY_POLICY_OVERLAY")
    if overlay_path and Path(overlay_path).is_file():
        overlay = json.loads(Path(overlay_path).read_text(encoding="utf-8"))
        if isinstance(overlay, dict):
            policy = {**policy, **overlay}
    return policy


POLICY = _load_policy()
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "coverage", "out", ".turbo", ".cache", ".expo", "Pods", "vendor"}
LOCKS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}
COREPACK_FALLBACK = "0.35.0"
DEFAULT_PNPM = "11.25.0"
DEFAULT_YARN_BERRY = "4.18.0"
DEFAULT_YARN_CLASSIC = "1.22.22"

SEVERITY_ORDER = ["info", "low", "moderate", "high", "critical"]
# Yarn Classic reports audit results as a bitmask rather than a plain exit code.
YARN_CLASSIC_AUDIT_BITS = {"info": 1, "low": 2, "moderate": 4, "high": 8, "critical": 16}


@dataclass(frozen=True)
class Project:
    root: Path
    manager: str
    lockfile: Path
    package: dict


def audit_severity() -> str:
    value = str(POLICY.get("audit_severity", "high")).lower()
    return value if value in SEVERITY_ORDER else "high"


def clean_env() -> dict[str, str]:
    env = dict(os.environ)
    secretish = re.compile(r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|CLIENT_SECRET|AUTH)(?:$|_)", re.I)
    explicit = {
        "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN", "DATABASE_URL", "DATABASE_URI",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS", "SSH_AUTH_SOCK",
    }
    for key in list(env):
        if key in explicit or secretish.search(key):
            env.pop(key, None)
    env.update({
        "CI": "true",
        "NODE_ENV": "test",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "YARN_ENABLE_SCRIPTS": "false",
        "PNPM_ENABLE_PRE_POST_SCRIPTS": "false",
        "HUSKY": "0",
    })
    return env


def group(title: str) -> None:
    if os.getenv("GITHUB_ACTIONS") == "true":
        print(f"::group::{title}", flush=True)
    else:
        print(f"\n==> {title}", flush=True)


def endgroup() -> None:
    if os.getenv("GITHUB_ACTIONS") == "true":
        print("::endgroup::", flush=True)


def run(cmd: list[str], cwd: Path, env: dict[str, str], label: str) -> None:
    group(label)
    print(f"$ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=cwd, env=env, check=False)
    endgroup()
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {proc.returncode}")


def run_status(cmd: list[str], cwd: Path, env: dict[str, str], label: str) -> int:
    group(label)
    print(f"$ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=cwd, env=env, check=False)
    endgroup()
    return proc.returncode


def capture(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def ignored(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def discover_projects(repo: Path) -> list[Project]:
    package_files = [p for p in repo.rglob("package.json") if not ignored(p.relative_to(repo))]
    projects: list[Project] = []
    for pkg_file in sorted(package_files):
        root = pkg_file.parent
        present = [(name, manager) for name, manager in LOCKS.items() if (root / name).exists()]
        # npm-shrinkwrap and package-lock are alternatives; having both is ambiguous.
        if len(present) > 1:
            names = ", ".join(name for name, _ in present)
            raise RuntimeError(f"{root.relative_to(repo) or Path('.')}: multiple lockfiles found ({names}); keep exactly one package-manager lockfile")
        if not present:
            # Workspace child package; root lockfile/project handles it.
            continue
        try:
            obj = json.loads(pkg_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid {pkg_file}: {e}") from e
        name, manager = present[0]
        projects.append(Project(root=root, manager=manager, lockfile=root / name, package=obj))
    if not projects:
        raise RuntimeError("No independently locked JavaScript/TypeScript project found. Commit package.json and exactly one lockfile.")
    return projects


def ts_present(project: Project) -> bool:
    root = project.root
    if any(root.glob("tsconfig*.json")):
        return True
    # Traverse workspace children, but do not let a separately locked nested project
    # force its parent to expose a typecheck script.
    for current, dirs, files in os.walk(root, topdown=True):
        cur = Path(current)
        kept = []
        for d in dirs:
            child = cur / d
            if d in SKIP_DIRS:
                continue
            if child != root and any((child / lock).exists() for lock in LOCKS):
                continue
            kept.append(d)
        dirs[:] = kept
        for name in files:
            if name.startswith("tsconfig") and name.endswith(".json"):
                return True
            if Path(name).suffix.lower() in {".ts", ".tsx", ".mts", ".cts"} and not name.endswith(".d.ts"):
                return True
    return False


def package_manager_spec(project: Project) -> str | None:
    value = project.package.get("packageManager")
    if not value:
        return None
    value = str(value).strip()
    m = re.fullmatch(r"(npm|pnpm|yarn)@([0-9][0-9A-Za-z.+_-]*)", value)
    if not m:
        raise RuntimeError(f"Unsupported/invalid packageManager field in {project.root / 'package.json'}: {value!r}")
    if m.group(1) != project.manager:
        raise RuntimeError(f"packageManager={value!r} conflicts with {project.lockfile.name}")
    return value


def ensure_corepack(cwd: Path, env: dict[str, str]) -> None:
    if shutil.which("corepack"):
        return
    run(["npm", "install", "--global", f"corepack@{COREPACK_FALLBACK}", "--ignore-scripts", "--no-audit", "--no-fund"], cwd, env, "Install pinned Corepack fallback")


def ensure_manager(project: Project, env: dict[str, str]) -> str | None:
    if project.manager == "npm":
        return None
    ensure_corepack(project.root, env)
    run(["corepack", "enable"], project.root, env, "Enable Corepack shims")
    spec = package_manager_spec(project)
    if spec is None:
        if project.manager == "pnpm":
            spec = f"pnpm@{DEFAULT_PNPM}"
        else:
            head = project.lockfile.read_text(encoding="utf-8", errors="ignore")[:256]
            spec = f"yarn@{DEFAULT_YARN_CLASSIC}" if "yarn lockfile v1" in head else f"yarn@{DEFAULT_YARN_BERRY}"
    run(["corepack", "prepare", spec, "--activate"], project.root, env, f"Activate reviewed {spec}")
    return spec


def manager_version(project: Project, env: dict[str, str]) -> str:
    return capture([project.manager, "--version"], project.root, env)


def manager_major(project: Project, env: dict[str, str]) -> int:
    version = manager_version(project, env)
    return int(version.split(".", 1)[0]) if version and version[0].isdigit() else 0


def install_dependencies(project: Project, env: dict[str, str]) -> None:
    if project.manager == "npm":
        run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], project.root, env, "Install npm dependencies (scripts disabled)")
    elif project.manager == "pnpm":
        run(["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"], project.root, env, "Install pnpm dependencies (scripts disabled)")
    elif manager_major(project, env) <= 1:
        run(["yarn", "install", "--frozen-lockfile", "--ignore-scripts", "--non-interactive"], project.root, env, "Install Yarn Classic dependencies (scripts disabled)")
    else:
        run(["yarn", "install", "--immutable", "--mode=skip-build"], project.root, env, "Install Yarn dependencies (build scripts skipped)")


def audit_yarn_classic(project: Project, env: dict[str, str], floor: str) -> None:
    """Yarn Classic returns a severity bitmask, so `--level` alone cannot gate the build."""
    label = f"Yarn Classic vulnerability audit ({floor.upper()}+ blocks)"
    code = run_status(["yarn", "audit", "--level", floor, "--non-interactive"], project.root, env, label)
    if code < 0:
        raise RuntimeError(f"{label} terminated by signal {-code}")
    blocking_mask = 0
    for name in SEVERITY_ORDER[SEVERITY_ORDER.index(floor):]:
        blocking_mask |= YARN_CLASSIC_AUDIT_BITS[name]
    unknown = code & ~sum(YARN_CLASSIC_AUDIT_BITS.values())
    if unknown:
        raise RuntimeError(f"{label} failed to run correctly (exit code {code})")
    if code & blocking_mask:
        present = [n for n, bit in YARN_CLASSIC_AUDIT_BITS.items() if code & bit]
        raise RuntimeError(f"{label} found advisories at or above '{floor}': {', '.join(present)}")
    if code:
        below = [n for n, bit in YARN_CLASSIC_AUDIT_BITS.items() if code & bit]
        print(f"Advisories below the '{floor}' blocking threshold were reported: {', '.join(below)}", flush=True)


def audit_dependencies(project: Project, env: dict[str, str]) -> None:
    floor = audit_severity()
    if project.manager == "npm":
        run(["npm", "audit", f"--audit-level={floor}"], project.root, env, f"npm vulnerability audit ({floor.upper()}+ blocks)")
        if POLICY.get("verify_npm_registry_signatures", True):
            run(["npm", "audit", "signatures"], project.root, env, "Verify npm registry package signatures/provenance")
    elif project.manager == "pnpm":
        run(["pnpm", "audit", "--audit-level", floor], project.root, env, f"pnpm vulnerability audit ({floor.upper()}+ blocks)")
    elif manager_major(project, env) <= 1:
        audit_yarn_classic(project, env, floor)
    else:
        run(["yarn", "npm", "audit", "--all", "--severity", floor], project.root, env, f"Yarn npm vulnerability audit ({floor.upper()}+ blocks)")


def script_command(project: Project, script: str) -> list[str]:
    return [project.manager, "run", script]


def artifact_pathspecs() -> list[str]:
    """Git pathspecs excluding committed build output from the mutation guard.

    This repository commits `build/` on its deployment branches. Re-running the build
    legitimately rewrites those files - Next.js emits fresh content hashes and a new build
    ID every time - so committed artifacts cannot participate in a "nothing changed" check.
    They are still scanned, under the reduced artifact profile in scan_repo.py.
    """
    globs = POLICY.get("artifact_globs", []) if POLICY.get("scan_build_artifacts") else []
    tops = {g.split("/", 1)[0] for g in globs}
    return sorted(f":!{t}" for t in tops if t and "*" not in t)


def tracked_clean(repo: Path, env: dict[str, str], phase: str) -> None:
    cmd = ["git", "diff", "--exit-code", "--stat", "--", ".", *artifact_pathspecs()]
    proc = subprocess.run(cmd, cwd=repo, env=env, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Tracked repository files changed during {phase}. CI project scripts must not "
            "rewrite committed source/configuration."
        )


def run_project(project: Project, repo: Path, env: dict[str, str]) -> None:
    display = str(project.root.relative_to(repo)) or "."
    print(f"\n{'=' * 72}\nProject: {display} | manager: {project.manager} | lock: {project.lockfile.name}\n{'=' * 72}")
    ensure_manager(project, env)
    print(f"Package manager version: {manager_version(project, env) or 'unknown'}")

    scripts = project.package.get("scripts") if isinstance(project.package.get("scripts"), dict) else {}
    if POLICY.get("require_lint_script", True) and "lint" not in scripts:
        raise RuntimeError(f"{display}: required package.json script 'lint' is missing")
    if POLICY.get("require_typecheck_for_typescript", True) and ts_present(project) and "typecheck" not in scripts:
        raise RuntimeError(f"{display}: TypeScript detected but required package.json script 'typecheck' is missing")

    install_dependencies(project, env)
    tracked_clean(repo, env, "dependency installation")
    audit_dependencies(project, env)

    # Optional reviewed escape hatch for deterministic setup such as patch-package,
    # `prisma generate`, or an explicit rebuild of a dependency that genuinely
    # requires an install step. Changes to this script are security-sensitive in
    # the trusted PR gate.
    if "ci:prepare" in scripts:
        run(script_command(project, "ci:prepare"), project.root, env, f"Reviewed CI prepare {display}")
        tracked_clean(repo, env, "ci:prepare")

    run(script_command(project, "lint"), project.root, env, f"Lint {display}")
    if "typecheck" in scripts:
        run(script_command(project, "typecheck"), project.root, env, f"Typecheck {display}")
    if POLICY.get("run_tests_if_present", True) and "test" in scripts:
        run(script_command(project, "test"), project.root, env, f"Test {display}")
    if POLICY.get("run_build_if_present", True) and "build" in scripts:
        run(script_command(project, "build"), project.root, env, f"Build {display}")
    tracked_clean(repo, env, "lint/typecheck/test/build")


def main() -> int:
    ap = argparse.ArgumentParser(description="Install, audit, lint, typecheck, test and build every locked project.")
    ap.add_argument("--repo", type=Path, default=Path("."))
    args = ap.parse_args()
    repo = args.repo.resolve()
    env = clean_env()
    try:
        projects = discover_projects(repo)
        for project in projects:
            run_project(project, repo, env)
    except RuntimeError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1
    print(f"\nAll project checks passed for {len(projects)} independently locked project(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
