#!/usr/bin/env python3
"""Runs the Merge Gate's real shell step from security-ci.yml under each scenario.

The gate is the only required check that sees every scan, so its pass/fail rules are tested
against the script that actually ships, extracted from the workflow, not a copy of it.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "security-ci.yml"
STEP_NAME = "- name: Require every enabled security job to pass"


def gate_script() -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == STEP_NAME)
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip()) + 2
    body = []
    for line in lines[run + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


# A normal, fully enabled pull request in which every job ran and passed.
PASSING_PR = {
    "STATIC_POLICY": "success", "QUALITY": "success", "POST_BUILD": "success",
    "GITLEAKS": "success", "SEMGREP": "success", "DEP_REVIEW": "success",
    "OSV": "success", "CODEQL": "skipped",
    "EVENT_NAME": "pull_request", "IS_DRAFT": "false",
    "ENABLE_QUALITY": "true", "ENABLE_DEPENDENCY_REVIEW": "true", "ENABLE_CODEQL": "false",
}


class MergeGateTests(unittest.TestCase):
    script: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = gate_script()

    def run_gate(self, **overrides: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GITHUB_STEP_SUMMARY": str(summary)}
            env.update(PASSING_PR)
            env.update(overrides)
            proc = subprocess.run(["bash", "-c", self.script], env=env, capture_output=True, text=True)
            return proc.returncode, proc.stdout + proc.stderr

    def test_extracted_the_real_step(self) -> None:
        self.assertIn("skip_expected", self.script)
        self.assertIn("IS_DRAFT", self.script)

    def test_all_jobs_passing_opens_the_gate(self) -> None:
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)

    def test_draft_fails_even_with_every_job_skipped(self) -> None:
        # The bypass: a green draft-time gate is what GitHub shows while a later run is re-run.
        skipped = {k: "skipped" for k in ("STATIC_POLICY", "QUALITY", "POST_BUILD", "GITLEAKS",
                                          "SEMGREP", "DEP_REVIEW", "OSV", "CODEQL")}
        code, out = self.run_gate(IS_DRAFT="true", **skipped)
        self.assertEqual(code, 1, out)
        self.assertIn("Draft pull request", out)

    def test_draft_fails_even_if_jobs_somehow_passed(self) -> None:
        code, _ = self.run_gate(IS_DRAFT="true")
        self.assertEqual(code, 1)

    def test_any_failure_closes_the_gate(self) -> None:
        for var in ("STATIC_POLICY", "QUALITY", "POST_BUILD", "GITLEAKS", "SEMGREP", "DEP_REVIEW", "OSV"):
            for result in ("failure", "cancelled"):
                with self.subTest(var=var, result=result):
                    code, out = self.run_gate(**{var: result})
                    self.assertEqual(code, 1, out)

    def test_core_scans_may_never_be_skipped(self) -> None:
        for var in ("STATIC_POLICY", "GITLEAKS", "SEMGREP", "OSV"):
            with self.subTest(var=var):
                code, out = self.run_gate(**{var: "skipped"})
                self.assertEqual(code, 1, out)
                self.assertIn("skipped unexpectedly", out)

    def test_quality_skip_needs_quality_disabled(self) -> None:
        code, _ = self.run_gate(QUALITY="skipped", POST_BUILD="skipped")
        self.assertEqual(code, 1, "quality was enabled but did not run")
        code, out = self.run_gate(QUALITY="skipped", POST_BUILD="skipped", ENABLE_QUALITY="false")
        self.assertEqual(code, 0, out)

    def test_post_build_must_run_once_quality_passed(self) -> None:
        code, _ = self.run_gate(POST_BUILD="skipped")
        self.assertEqual(code, 1)

    def test_failed_quality_with_skipped_post_build_still_fails(self) -> None:
        code, _ = self.run_gate(QUALITY="failure", POST_BUILD="skipped")
        self.assertEqual(code, 1)

    def test_dependency_review_skip_only_outside_pull_requests_or_when_disabled(self) -> None:
        code, _ = self.run_gate(DEP_REVIEW="skipped")
        self.assertEqual(code, 1, "enabled dependency review skipped on a pull request")
        for event in ("push", "merge_group"):
            with self.subTest(event=event):
                code, out = self.run_gate(DEP_REVIEW="skipped", EVENT_NAME=event)
                self.assertEqual(code, 0, out)
        code, out = self.run_gate(DEP_REVIEW="skipped", ENABLE_DEPENDENCY_REVIEW="false")
        self.assertEqual(code, 0, out)

    def test_codeql_skip_only_when_disabled(self) -> None:
        code, out = self.run_gate(CODEQL="skipped", ENABLE_CODEQL="false")
        self.assertEqual(code, 0, out)
        code, _ = self.run_gate(CODEQL="skipped", ENABLE_CODEQL="true")
        self.assertEqual(code, 1)
        code, out = self.run_gate(CODEQL="success", ENABLE_CODEQL="true")
        self.assertEqual(code, 0, out)

    def test_push_with_everything_enabled_and_passing(self) -> None:
        code, out = self.run_gate(EVENT_NAME="push", DEP_REVIEW="skipped", IS_DRAFT="false")
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
