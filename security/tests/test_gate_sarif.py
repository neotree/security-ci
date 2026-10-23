#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gate_sarif", SECURITY / "gate_sarif.py")
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
assert spec.loader
spec.loader.exec_module(gate)


def sarif(results, rules=None):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": rules or []}},
            "results": results,
        }],
    }


def result(rule_id, level=None):
    r = {
        "ruleId": rule_id,
        "message": {"text": "finding"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.ts"},
            "region": {"startLine": 7},
        }}],
    }
    if level:
        r["level"] = level
    return r


def rule(rule_id, level):
    return {"id": rule_id, "defaultConfiguration": {"level": level}}


class GateSarifTests(unittest.TestCase):
    def run_gate(self, doc, *extra):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text(json.dumps(doc), encoding="utf-8")
            return gate.main([str(p), *extra])

    def test_level_is_resolved_from_the_rule_descriptor(self):
        """Semgrep omits `level` on results; reading it alone would pass everything."""
        doc = sarif([result("r-error")], [rule("r-error", "error")])
        self.assertNotIn("level", doc["runs"][0]["results"][0])
        self.assertEqual([("r-error", "error")], [(r["ruleId"], r["level"]) for r in gate.collect(doc)])
        self.assertEqual(1, self.run_gate(doc))

    def test_warning_rule_does_not_block(self):
        doc = sarif([result("r-warn")], [rule("r-warn", "warning")])
        self.assertEqual(0, self.run_gate(doc))

    def test_mixed_severities_block_only_on_error(self):
        doc = sarif(
            [result("r-warn"), result("r-error"), result("r-warn")],
            [rule("r-warn", "warning"), rule("r-error", "error")],
        )
        levels = sorted(r["level"] for r in gate.collect(doc))
        self.assertEqual(["error", "warning", "warning"], levels)
        self.assertEqual(1, self.run_gate(doc))

    def test_explicit_result_level_wins_over_rule_default(self):
        doc = sarif([result("r", level="error")], [rule("r", "warning")])
        self.assertEqual("error", gate.collect(doc)[0]["level"])
        self.assertEqual(1, self.run_gate(doc))

    def test_unknown_rule_falls_back_to_warning(self):
        doc = sarif([result("not-declared")], [])
        self.assertEqual("warning", gate.collect(doc)[0]["level"])
        self.assertEqual(0, self.run_gate(doc))

    def test_fail_on_threshold_is_configurable(self):
        doc = sarif([result("r-warn")], [rule("r-warn", "warning")])
        self.assertEqual(0, self.run_gate(doc))
        self.assertEqual(1, self.run_gate(doc, "--fail-on", "warning"))

    def test_no_results_passes(self):
        self.assertEqual(0, self.run_gate(sarif([])))

    def test_missing_report_fails_closed(self):
        """A scanner that never ran must not look like a clean scan."""
        self.assertEqual(1, gate.main(["/nonexistent/does-not-exist.sarif"]))

    def test_corrupt_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text("{not json", encoding="utf-8")
            self.assertEqual(1, gate.main([str(p)]))

    def test_location_is_extracted_for_annotations(self):
        entry = gate.collect(sarif([result("r")], [rule("r", "error")]))[0]
        self.assertEqual("src/a.ts", entry["uri"])
        self.assertEqual(7, entry["line"])

    def test_result_without_location_does_not_crash(self):
        doc = sarif([{"ruleId": "r", "message": {"text": "x"}}], [rule("r", "error")])
        self.assertEqual("unknown", gate.collect(doc)[0]["uri"])
        self.assertEqual(1, self.run_gate(doc))


class CvssGateTests(unittest.TestCase):
    """OSV-Scanner marks EVERY result "warning" regardless of severity, and puts the real
    severity in the rule's `security-severity` property as a CVSS score. Gating on the
    SARIF level alone therefore blocks on everything or on nothing."""

    def doc(self, scored):
        """scored: list of (ruleId, cvss-or-None) -> a SARIF doc shaped like OSV's."""
        rules, results = [], []
        for rid, score in scored:
            rule = {"id": rid}
            if score is not None:
                rule["properties"] = {"security-severity": str(score)}
            rules.append(rule)
            results.append({
                "ruleId": rid, "level": "warning",
                "message": {"text": rid},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "yarn.lock"}, "region": {"startLine": 1}}}],
            })
        return {"version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "osv-scanner", "rules": rules}},
                          "results": results}]}

    def run_gate(self, doc, *extra):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text(json.dumps(doc), encoding="utf-8")
            return gate.main([str(p), *extra])

    def test_cvss_is_read_from_the_rule_property(self):
        entries = gate.collect(self.doc([("CVE-1", 9.3), ("CVE-2", 5.3)]))
        self.assertEqual([9.3, 5.3], [e["cvss"] for e in entries])
        self.assertEqual(["critical", "medium"], [e["band"] for e in entries])

    def test_sarif_level_alone_would_miss_a_critical(self):
        """Every OSV result is "warning", so the default level gate passes a CVSS 9.3."""
        doc = self.doc([("CVE-1", 9.3)])
        self.assertEqual(0, self.run_gate(doc))
        self.assertEqual(1, self.run_gate(doc, "--fail-on-cvss", "9.0"))

    def test_threshold_selects_the_right_findings(self):
        doc = self.doc([("crit", 9.3), ("high", 7.4), ("med", 5.3), ("low", 2.1)])
        self.assertEqual(1, self.run_gate(doc, "--fail-on-cvss", "9.0"))
        self.assertEqual(1, self.run_gate(doc, "--fail-on-cvss", "7.0"))
        self.assertEqual(0, self.run_gate(doc, "--fail-on-cvss", "9.9"))

    def test_missing_cvss_blocks_rather_than_reading_as_safe(self):
        """An advisory with no score is still an advisory; absence is not evidence."""
        self.assertEqual(1, self.run_gate(self.doc([("no-score", None)]), "--fail-on-cvss", "9.0"))

    def test_clean_report_passes(self):
        self.assertEqual(0, self.run_gate(self.doc([]), "--fail-on-cvss", "9.0"))

    def test_band_boundaries(self):
        self.assertEqual("critical", gate.cvss_band(9.0))
        self.assertEqual("high", gate.cvss_band(8.9))
        self.assertEqual("high", gate.cvss_band(7.0))
        self.assertEqual("medium", gate.cvss_band(6.9))
        self.assertEqual("low", gate.cvss_band(0.1))
        self.assertEqual("none", gate.cvss_band(0.0))
        self.assertEqual("unknown", gate.cvss_band(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestSuiteIntegrityTests(unittest.TestCase):
    """A duplicated class name silently shadows the earlier definition, so its tests stop
    running while the suite still reports success. That happened here: three classes were
    defined twice after the split into a shared repository, and the assertions that mattered
    for the shared defaults never executed."""

    def test_no_test_class_is_defined_twice(self):
        import collections, re
        for path in sorted(SECURITY.glob("tests/test_*.py")):
            names = re.findall(r"^class (\w+)\(", path.read_text(encoding="utf-8"), re.M)
            dupes = [n for n, c in collections.Counter(names).items() if c > 1]
            self.assertEqual([], dupes, f"{path.name} defines {dupes} more than once")

    def test_no_test_method_is_defined_twice_in_a_class(self):
        import ast, collections
        for path in sorted(SECURITY.glob("tests/test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                names = [n.name for n in node.body
                         if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
                dupes = [n for n, c in collections.Counter(names).items() if c > 1]
                self.assertEqual([], dupes, f"{path.name}:{node.name} defines {dupes} twice")


class BlockRulesTests(unittest.TestCase):
    """Reviewed WARNING rules promoted into the gate via --block-rules."""

    BLOCK_FILE = SECURITY / "semgrep-blocking-rules.txt"
    VENDORED_ID = "javascript.aws-lambda.security.pg-sqli.pg-sqli"

    def run_gate(self, doc, *extra):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text(json.dumps(doc), encoding="utf-8")
            return gate.main([str(p), *extra])

    def test_promoted_warning_rule_blocks_with_semgrep_path_prefix(self):
        rid = "rules.semgrep." + self.VENDORED_ID
        doc = sarif([result(rid)], [rule(rid, "warning")])
        self.assertEqual(0, self.run_gate(doc, "--fail-on", "error"))
        self.assertEqual(1, self.run_gate(doc, "--fail-on", "error", "--block-rules", str(self.BLOCK_FILE)))

    def test_unlisted_warning_rule_stays_advisory(self):
        rid = "rules.react-dangerously-set-inner-html"
        doc = sarif([result(rid)], [rule(rid, "warning")])
        self.assertEqual(0, self.run_gate(doc, "--fail-on", "error", "--block-rules", str(self.BLOCK_FILE)))

    def test_suffix_match_requires_a_dot_boundary(self):
        rid = "rules.semgrep.x" + self.VENDORED_ID
        self.assertFalse(gate.rule_matches(rid, [self.VENDORED_ID]))

    def test_missing_block_rules_file_fails_closed(self):
        doc = sarif([], [])
        self.assertEqual(1, self.run_gate(doc, "--block-rules", "/nonexistent/block.txt"))

    def test_every_listed_rule_exists_in_the_shipped_rules(self):
        # A typo would match nothing, silently leaving that rule advisory.
        shipped = "\n".join(
            p.read_text(encoding="utf-8")
            for p in [SECURITY / "semgrep-rules.yml", *sorted((SECURITY / "semgrep").glob("*.yml"))]
        )
        missing = [e for e in gate.load_block_rules(self.BLOCK_FILE)
                   if not re.search(rf"^\s*-?\s*id:\s*{re.escape(e)}\s*$", shipped, re.M)]
        self.assertEqual([], missing)


class CvssCeilingTests(unittest.TestCase):
    def run_gate(self, *extra):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text(json.dumps(sarif([], [])), encoding="utf-8")
            return gate.main([str(p), *extra])

    def test_threshold_above_ceiling_is_refused(self):
        self.assertEqual(1, self.run_gate("--fail-on-cvss", "10.0", "--cvss-ceiling", "9.0"))

    def test_tighter_threshold_is_accepted(self):
        self.assertEqual(0, self.run_gate("--fail-on-cvss", "7.0", "--cvss-ceiling", "9.0"))
        self.assertEqual(0, self.run_gate("--fail-on-cvss", "9.0", "--cvss-ceiling", "9.0"))


class FailClosedTests(unittest.TestCase):
    """Reports that are not evidence of a completed scan must never pass."""

    def run_gate(self, doc, *extra):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text(json.dumps(doc), encoding="utf-8")
            return gate.main([str(p), *extra])

    def test_empty_document_fails(self):
        self.assertEqual(1, self.run_gate({}))
        self.assertEqual(1, self.run_gate({"runs": []}))
        self.assertEqual(1, self.run_gate([]))

    def test_run_without_a_tool_name_fails(self):
        self.assertEqual(1, self.run_gate({"runs": [{"results": []}]}))

    def test_self_reported_execution_failure_fails(self):
        doc = sarif([], [])
        doc["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        self.assertEqual(1, self.run_gate(doc))
        doc["runs"][0]["invocations"] = [{"executionSuccessful": True}]
        self.assertEqual(0, self.run_gate(doc))

    def test_nan_threshold_is_refused(self):
        self.assertEqual(1, self.run_gate(sarif([], []), "--fail-on-cvss", "nan", "--cvss-ceiling", "9.0"))
        self.assertEqual(1, self.run_gate(sarif([], []), "--fail-on-cvss", "inf"))
        self.assertEqual(1, self.run_gate(sarif([], []), "--fail-on-cvss", "-1"))

    def test_nan_score_blocks_instead_of_passing(self):
        rule_desc = {"id": "osv-1", "properties": {"security-severity": "NaN"}}
        doc = sarif([result("osv-1", "warning")], [rule_desc])
        self.assertEqual(1, self.run_gate(doc, "--fail-on-cvss", "9.0"))


class SemgrepExceptionTests(unittest.TestCase):
    """`semgrep:<rule>` exceptions in the policy overlay, same rules as the scanner's."""

    RID = "rules.js-ts-dynamic-eval"

    def run_gate(self, results, exceptions):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.sarif"
            p.write_text(json.dumps(sarif(results, [rule(self.RID, "error")])), encoding="utf-8")
            o = Path(td) / "policy.json"
            o.write_text(json.dumps({"exceptions": exceptions}), encoding="utf-8")
            return gate.main([str(p), "--fail-on", "error",
                              "--policy", str(SECURITY / "policy.defaults.json"), "--policy-overlay", str(o)])

    def exc(self, **extra):
        return {"rule": "semgrep:js-ts-dynamic-eval", "paths": ["src/a.ts"],
                "reason": "Reviewed sandboxed evaluator.", "expires": "2099-01-01", **extra}

    def test_valid_exception_clears_the_finding(self):
        self.assertEqual(0, self.run_gate([result(self.RID)], [self.exc()]))

    def test_exception_covers_only_its_site_count(self):
        self.assertEqual(1, self.run_gate([result(self.RID), result(self.RID)], [self.exc()]))
        self.assertEqual(0, self.run_gate([result(self.RID), result(self.RID)], [self.exc(sites=2)]))

    def test_expired_or_invalid_exception_is_not_applied(self):
        self.assertEqual(1, self.run_gate([result(self.RID)], [self.exc(expires="2020-01-01")]))
        self.assertEqual(1, self.run_gate([result(self.RID)], [self.exc(reason="short")]))

    def test_exception_for_another_path_does_not_apply(self):
        self.assertEqual(1, self.run_gate([result(self.RID)], [self.exc(paths=["src/other.ts"])]))

    def test_scanner_rule_names_do_not_clear_semgrep(self):
        self.assertEqual(1, self.run_gate([result(self.RID)], [self.exc(rule="DYNAMIC_CODE_EXECUTION")]))
