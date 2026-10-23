#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_caller_pin", SECURITY / "check_caller_pin.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader
spec.loader.exec_module(mod)

A = "a" * 40
B = "b" * 40


def caller(uses_sha: str, ref_sha: str | None) -> str:
    ref = f"      security-ci-ref: {ref_sha}\n" if ref_sha else ""
    return (
        "jobs:\n"
        "  security:\n"
        f"    uses: neotree/security-ci/.github/workflows/security-ci.yml@{uses_sha}\n"
        "    with:\n" + ref
    )


class CallerPinTests(unittest.TestCase):
    """`uses:` decides which workflow runs; `security-ci-ref` decides which scanner is
    checked out. Dependabot updates only the first, so drift is the expected failure."""

    def write(self, td: str, content: str) -> Path:
        root = Path(td)
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "security-ci.yml").write_text(content, encoding="utf-8")
        return root

    def test_matching_pins_pass(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(0, mod.main([str(self.write(td, caller(A, A)))]))

    def test_dependabot_style_drift_is_caught(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(1, mod.main([str(self.write(td, caller(B, A)))]))

    def test_missing_ref_input_is_caught(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(1, mod.main([str(self.write(td, caller(A, None)))]))

    def test_repository_that_does_not_use_security_ci_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.write(td, "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + A + "\n")
            self.assertEqual(0, mod.main([str(root)]))

    def test_case_insensitive_sha_comparison(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(0, mod.main([str(self.write(td, caller(A.upper(), A)))]))

    def test_quoted_ref_value_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            content = caller(A, None) + f'      security-ci-ref: "{A}"\n'
            self.assertEqual(0, mod.main([str(self.write(td, content))]))

    def test_branch_or_tag_pin_is_caught(self):
        # Regression: a non-SHA ref did not match the SHA-only pattern at all, so the
        # file was skipped and the check passed.
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(1, mod.main([str(self.write(td, caller("main", "main")))]))
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(1, mod.main([str(self.write(td, caller("v1.2.0", A)))]))

    def test_short_sha_ref_is_caught(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(1, mod.main([str(self.write(td, caller(A, A[:7])))]))

    def test_yaml_extension_is_checked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "security.yaml").write_text(caller(B, A), encoding="utf-8")
            self.assertEqual(1, mod.main([str(root)]))

    def test_callers_pinned_to_different_commits_are_caught(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.write(td, caller(A, A))
            (root / ".github" / "workflows" / "pr-malware-gate.yml").write_text(caller(B, B), encoding="utf-8")
            self.assertEqual(1, mod.main([str(root)]))

    def test_callers_pinned_to_the_same_commit_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.write(td, caller(A, A))
            (root / ".github" / "workflows" / "pr-malware-gate.yml").write_text(caller(A, A), encoding="utf-8")
            self.assertEqual(0, mod.main([str(root)]))

    def test_require_all_fails_when_a_connector_is_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.write(td, caller(A, A))
            self.assertEqual(0, mod.main([str(root)]))
            self.assertEqual(1, mod.main(["--require-all", str(root)]))

    def test_require_all_passes_with_all_three_connectors(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.write(td, caller(A, A))
            wf = root / ".github" / "workflows"
            for name in ("pr-malware-gate.yml", "scheduled-security.yml"):
                (wf / name).write_text(caller(A, A).replace("security-ci.yml@", name + "@"), encoding="utf-8")
            self.assertEqual(0, mod.main(["--require-all", str(root)]))

    def test_no_workflows_directory_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(0, mod.main([td]))


class ParsingBypassTests(unittest.TestCase):
    """Valid YAML spellings that used to slip past the comparison."""

    def check(self, content: str) -> int:
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "security-ci.yml").write_text(content, encoding="utf-8")
            return mod.main([td])

    def body(self, uses: str, ref: str) -> str:
        return f"jobs:\n  s:\n    uses: {uses}\n    with:\n      security-ci-ref: {ref}\n"

    def test_quoted_uses_with_different_ref_is_caught(self):
        wf = "neotree/security-ci/.github/workflows/security-ci.yml@"
        self.assertEqual(1, self.check(self.body(f'"{wf}{B}"', A)))
        self.assertEqual(1, self.check(self.body(f"'{wf}{B}'", f"'{A}'")))

    def test_trailing_comments_do_not_hide_a_mismatch(self):
        wf = "neotree/security-ci/.github/workflows/security-ci.yml@"
        self.assertEqual(1, self.check(self.body(f"{wf}{B} # v2", f"{A}  # pinned")))
        self.assertEqual(0, self.check(self.body(f"{wf}{A} # v2", f'"{A}"  # pinned')))

    def test_unparseable_reference_is_refused(self):
        content = ("jobs:\n  s:\n    uses: >-\n      neotree/security-ci/.github/workflows/security-ci.yml@"
                   + B + f"\n    with:\n      security-ci-ref: {A}\n")
        self.assertEqual(1, self.check(content))


class PerJobTests(unittest.TestCase):
    def check(self, content: str) -> int:
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "security-ci.yml").write_text(content, encoding="utf-8")
            return mod.main([td])

    def job(self, name: str, wf: str, uses: str, ref: str) -> str:
        return (f"  {name}:\n    uses: neotree/security-ci/.github/workflows/{wf}@{uses}\n"
                f"    with:\n      security-ci-ref: {ref}\n")

    def test_matching_job_does_not_mask_a_mismatched_job(self):
        content = "jobs:\n" + self.job("one", "security-ci.yml", A, A) + self.job("two", "pr-malware-gate.yml", A, B)
        self.assertEqual(1, self.check(content))

    def test_each_job_matching_its_own_ref_passes(self):
        content = "jobs:\n" + self.job("one", "security-ci.yml", A, A) + self.job("two", "pr-malware-gate.yml", A, A)
        self.assertEqual(0, self.check(content))

    def test_job_without_its_own_ref_is_caught(self):
        content = ("jobs:\n" + self.job("one", "security-ci.yml", A, A)
                   + "  two:\n    uses: neotree/security-ci/.github/workflows/pr-malware-gate.yml@" + A + "\n")
        self.assertEqual(1, self.check(content))


if __name__ == "__main__":
    unittest.main(verbosity=2)
