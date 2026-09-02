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


if __name__ == "__main__":
    unittest.main(verbosity=2)
