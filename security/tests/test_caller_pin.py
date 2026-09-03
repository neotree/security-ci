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

    def test_no_workflows_directory_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(0, mod.main([td]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
