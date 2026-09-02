#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("run_project_checks", SECURITY / "run_project_checks.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader
spec.loader.exec_module(mod)


def write(root: Path, rel: str, text: str = "") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class ProjectRunnerTests(unittest.TestCase):
    def test_discovers_locked_root_and_ignores_workspace_child_without_lock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "package.json", json.dumps({"scripts": {"lint": "eslint ."}}))
            write(root, "package-lock.json", "{}")
            write(root, "packages/a/package.json", json.dumps({"name": "a"}))
            projects = mod.discover_projects(root)
            self.assertEqual(1, len(projects))
            self.assertEqual("npm", projects[0].manager)

    def test_rejects_multiple_lockfiles_same_project(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "package.json", "{}")
            write(root, "package-lock.json", "{}")
            write(root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
            with self.assertRaises(RuntimeError):
                mod.discover_projects(root)

    def test_nested_independent_ts_project_does_not_force_parent_ts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "package.json", json.dumps({"scripts": {"lint": "eslint ."}}))
            write(root, "package-lock.json", "{}")
            write(root, "tools/typed/package.json", json.dumps({"scripts": {"lint": "eslint .", "typecheck": "tsc --noEmit"}}))
            write(root, "tools/typed/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
            write(root, "tools/typed/src/index.ts", "export const x:number=1;\n")
            projects = mod.discover_projects(root)
            parent = next(p for p in projects if p.root == root)
            child = next(p for p in projects if p.root != root)
            self.assertFalse(mod.ts_present(parent))
            self.assertTrue(mod.ts_present(child))

    def test_package_manager_field_must_match_lockfile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = {"packageManager": "yarn@4.18.0", "scripts": {"lint": "eslint ."}}
            write(root, "package.json", json.dumps(pkg))
            write(root, "package-lock.json", "{}")
            project = mod.discover_projects(root)[0]
            with self.assertRaises(RuntimeError):
                mod.package_manager_spec(project)

    def test_discovery_failure_reports_cleanly_instead_of_raising(self):
        """A misconfigured repo must produce an actionable error, not a traceback."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "package.json", "{}")
            write(root, "package-lock.json", "{}")
            write(root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
            err, out = io.StringIO(), io.StringIO()
            argv = sys.argv
            sys.argv = ["run_project_checks.py", "--repo", str(root)]
            try:
                with redirect_stderr(err), redirect_stdout(out):
                    code = mod.main()
            finally:
                sys.argv = argv
            self.assertEqual(1, code)
            self.assertIn("multiple lockfiles", err.getvalue())


class AuditSeverityTests(unittest.TestCase):
    def test_severity_floor_comes_from_policy(self):
        floor = mod.audit_severity()
        self.assertIn(floor, mod.SEVERITY_ORDER)
        self.assertEqual(mod.POLICY.get("audit_severity", "high"), floor)

    def test_invalid_policy_value_falls_back_to_high(self):
        original = mod.POLICY.get("audit_severity")
        try:
            mod.POLICY["audit_severity"] = "not-a-severity"
            self.assertEqual("high", mod.audit_severity())
        finally:
            if original is None:
                mod.POLICY.pop("audit_severity", None)
            else:
                mod.POLICY["audit_severity"] = original


class YarnClassicAuditTests(unittest.TestCase):
    """Yarn Classic returns a severity bitmask, so a plain exit code check is wrong."""

    def audit(self, exit_code: int, floor: str = "high"):
        project = mod.Project(root=Path("."), manager="yarn", lockfile=Path("yarn.lock"), package={})
        original = mod.run_status
        try:
            mod.run_status = lambda *a, **k: exit_code
            buf = io.StringIO()
            with redirect_stdout(buf):
                mod.audit_yarn_classic(project, {}, floor)
            return buf.getvalue()
        finally:
            mod.run_status = original

    def test_clean_audit_passes(self):
        self.audit(0)

    def test_low_and_moderate_below_high_floor_do_not_block(self):
        output = self.audit(2 | 4)  # LOW + MODERATE
        self.assertIn("below the 'high' blocking threshold", output)

    def test_high_blocks(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.audit(8)
        self.assertIn("high", str(ctx.exception))

    def test_critical_blocks(self):
        with self.assertRaises(RuntimeError):
            self.audit(16)

    def test_low_floor_blocks_on_low(self):
        with self.assertRaises(RuntimeError):
            self.audit(2, floor="low")

    def test_info_never_blocks_at_high_floor(self):
        self.audit(1)

    def test_unexpected_exit_code_fails_closed(self):
        """An exit code outside the bitmask means yarn itself failed to run."""
        with self.assertRaises(RuntimeError) as ctx:
            self.audit(127)
        self.assertIn("failed to run correctly", str(ctx.exception))


class ArtifactMutationGuardTests(unittest.TestCase):
    def test_committed_build_output_is_excluded_from_the_mutation_guard(self):
        """Deployment branches commit build/. A rebuild emits new content hashes, so the
        artifacts cannot take part in a "nothing changed" check without failing always."""
        specs = mod.artifact_pathspecs()
        self.assertIn(":!build", specs)
        self.assertTrue(all(x.startswith(":!") for x in specs))

    def test_guard_is_unrestricted_when_artifact_scanning_is_off(self):
        original = mod.POLICY.get("scan_build_artifacts")
        try:
            mod.POLICY["scan_build_artifacts"] = False
            self.assertEqual([], mod.artifact_pathspecs())
        finally:
            mod.POLICY["scan_build_artifacts"] = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
