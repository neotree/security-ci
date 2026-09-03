#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
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
