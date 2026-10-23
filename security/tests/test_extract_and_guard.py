#!/usr/bin/env python3
"""Regression tests that need a real Git repository.

* extract_tree.py must write exactly what is committed. `git archive` honoured each
  branch's `.gitattributes`, so `export-ignore` removed a committed payload from the scan.
* The project-check mutation guard must compare against the commit under test. Comparing
  to the index let a script hide a rewrite with `git add`.
* A repository with tests and no `test` script must fail instead of skipping them.
"""
from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SECURITY / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


extract_tree = load("extract_tree")
checks = load("run_project_checks")

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_NOSYSTEM": "1"}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, env=GIT_ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout


def make_repo(root: Path, files: dict[str, str]) -> Path:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    return repo


class ExtractTreeTests(unittest.TestCase):
    def test_export_ignore_cannot_hide_a_committed_file(self):
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(Path(td), {
                ".gitattributes": "payload.js export-ignore\n",
                "payload.js": "eval(x);\n",
                "ok.js": "module.exports = 1;\n",
            })
            archived = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "HEAD"],
                                      check=True, stdout=subprocess.PIPE).stdout
            names = tarfile.open(fileobj=io.BytesIO(archived)).getnames()
            self.assertNotIn("payload.js", names, "precondition: git archive drops it")
            out = Path(td) / "out"
            self.assertEqual(0, extract_tree.main([str(repo), "HEAD", str(out)]))
            self.assertEqual("eval(x);\n", (out / "payload.js").read_text())

    def test_filters_and_substitution_are_not_applied(self):
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(Path(td), {
                ".gitattributes": "*.js export-subst\n",
                "a.js": "// $Format:%H$\n",
            })
            out = Path(td) / "out"
            self.assertEqual(0, extract_tree.main([str(repo), "HEAD", str(out)]))
            self.assertEqual("// $Format:%H$\n", (out / "a.js").read_text())

    def test_symlinks_are_recreated_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(Path(td), {"a.js": "1;\n"})
            os.symlink("/etc/passwd", repo / "link")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "link")
            out = Path(td) / "out"
            self.assertEqual(0, extract_tree.main([str(repo), "HEAD", str(out)]))
            self.assertTrue((out / "link").is_symlink())
            self.assertEqual("/etc/passwd", os.readlink(out / "link"))

    def test_submodules_are_reported_not_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(Path(td), {"a.js": "1;\n"})
            git(repo, "update-index", "--add", "--cacheinfo",
                "160000,0123456789abcdef0123456789abcdef01234567,vendor/evil")
            git(repo, "commit", "-qm", "submodule")
            links = Path(td) / "gitlinks.txt"
            self.assertEqual(0, extract_tree.main([str(repo), "HEAD", str(Path(td) / "out"),
                                                   "--gitlinks-out", str(links)]))
            self.assertEqual("vendor/evil\n", links.read_text())

    def test_unknown_ref_fails(self):
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(Path(td), {"a.js": "1;\n"})
            self.assertEqual(1, extract_tree.main([str(repo), "refs/heads/nope", str(Path(td) / "out")]))

    def test_unsafe_paths_are_refused(self):
        for bad in ("../x", ".git/hooks/pre-commit", "/abs"):
            with self.assertRaises(ValueError, msg=bad):
                extract_tree.safe_target(Path("/tmp/root"), bad)


class MutationGuardTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.td.name), {"src/a.js": "module.exports = 1;\n"})
        checks.record_baseline(self.repo, GIT_ENV)

    def tearDown(self):
        checks.BASELINE = None
        self.td.cleanup()

    def test_clean_tree_passes(self):
        checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_staged_rewrite_is_caught(self):
        (self.repo / "src/a.js").write_text("module.exports = evil;\n")
        git(self.repo, "add", "-A")
        with self.assertRaises(RuntimeError):
            checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_committed_rewrite_is_caught(self):
        (self.repo / "src/a.js").write_text("module.exports = evil;\n")
        git(self.repo, "commit", "-qam", "sneaky")
        with self.assertRaises(RuntimeError) as ctx:
            checks.tracked_clean(self.repo, GIT_ENV, "test")
        self.assertIn("HEAD moved", str(ctx.exception))

    def test_assume_unchanged_rewrite_is_caught(self):
        git(self.repo, "update-index", "--assume-unchanged", "src/a.js")
        (self.repo / "src/a.js").write_text("module.exports = evil;\n")
        self.assertEqual("", git(self.repo, "diff", "--name-only"), "precondition: git diff is blind")
        with self.assertRaises(RuntimeError):
            checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_skip_worktree_rewrite_is_caught(self):
        git(self.repo, "update-index", "--skip-worktree", "src/a.js")
        (self.repo / "src/a.js").write_text("module.exports = evil;\n")
        with self.assertRaises(RuntimeError):
            checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_clean_filter_cannot_launder_a_rewrite(self):
        git(self.repo, "config", "filter.launder.clean", "printf 'module.exports = 1;\\n'")
        (self.repo / ".git" / "info").mkdir(exist_ok=True)
        (self.repo / ".git" / "info" / "attributes").write_text("*.js filter=launder\n")
        (self.repo / "src/a.js").write_text("module.exports = evil;\n")
        with self.assertRaises(RuntimeError):
            checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_deleted_file_is_caught(self):
        (self.repo / "src/a.js").unlink()
        with self.assertRaises(RuntimeError):
            checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_crlf_checkout_of_an_lf_blob_is_not_a_change(self):
        (self.repo / "src/a.js").write_bytes(b"module.exports = 1;\r\n")
        checks.tracked_clean(self.repo, GIT_ENV, "test")

    def test_guard_refuses_to_run_without_a_baseline(self):
        checks.BASELINE = None
        with self.assertRaises(RuntimeError):
            checks.tracked_clean(self.repo, GIT_ENV, "test")


class TestScriptRequiredTests(unittest.TestCase):
    def project(self, root: Path, files: dict[str, str]):
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return checks.Project(root=root, manager="npm", lockfile=root / "package-lock.json",
                              package={"scripts": {"lint": "x"}})

    def test_test_directory_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.project(Path(td), {"tests/a.test.ts": "", "package-lock.json": "{}"})
            self.assertTrue(checks.tests_present(p))

    def test_dependency_tests_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.project(Path(td), {"node_modules/x/test/a.test.js": "", "src/a.js": ""})
            self.assertEqual([], checks.tests_present(p))

    def test_missing_test_script_fails_before_any_install(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.project(Path(td), {"tests/a.test.js": ""})
            originals = (checks.ensure_manager, checks.manager_version)
            checks.ensure_manager = lambda *a, **k: None
            checks.manager_version = lambda *a, **k: "test"
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    checks.run_project(p, Path(td), {})
            finally:
                checks.ensure_manager, checks.manager_version = originals
            self.assertIn("no 'test' script", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
