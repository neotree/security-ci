#!/usr/bin/env python3
"""Fail a CI job when a SARIF report contains results at or above a severity level.

Written for Semgrep, whose SARIF results carry no per-result `level` field: the
severity lives on the rule descriptor in `tool.driver.rules[].defaultConfiguration`.
Reading `result.level` alone therefore sees `None` for every finding and silently
passes the build, so the rule descriptor is always consulted as a fallback.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path

# SARIF levels, least to most severe. "none" is informational only.
LEVELS = ["none", "note", "warning", "error"]
DEFAULT_LEVEL = "warning"


def rule_levels(run: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    driver = run.get("tool", {}).get("driver", {})
    for extension in [driver, *run.get("tool", {}).get("extensions", [])]:
        for rule in extension.get("rules", []) or []:
            rid = rule.get("id")
            level = (rule.get("defaultConfiguration") or {}).get("level")
            if rid and level:
                out[rid] = level
    return out


def collect(sarif: dict) -> list[dict]:
    results = []
    for run in sarif.get("runs", []) or []:
        levels = rule_levels(run)
        for result in run.get("results", []) or []:
            level = result.get("level") or levels.get(result.get("ruleId", ""), DEFAULT_LEVEL)
            location = {"uri": "unknown", "line": 1}
            for loc in result.get("locations", []) or []:
                physical = loc.get("physicalLocation", {})
                location = {
                    "uri": physical.get("artifactLocation", {}).get("uri", "unknown"),
                    "line": (physical.get("region") or {}).get("startLine", 1),
                }
                break
            results.append({
                "ruleId": result.get("ruleId", "unknown"),
                "level": level,
                "message": (result.get("message") or {}).get("text", ""),
                **location,
            })
    return results


def annotate(entry: dict) -> None:
    if os.getenv("GITHUB_ACTIONS") != "true":
        return
    level = "error" if entry["level"] == "error" else "warning"
    text = f"[{entry['ruleId']}] {entry['message']}".replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} file={entry['uri']},line={entry['line']}::{text}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sarif", type=Path)
    ap.add_argument("--fail-on", default="error", choices=LEVELS,
                    help="Lowest SARIF level that blocks the build (default: error).")
    ap.add_argument("--label", default="SARIF")
    args = ap.parse_args(argv)

    try:
        sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        # Fail closed: an unreadable report is indistinguishable from a scanner that
        # never ran, and must never be treated as a clean result.
        print(f"::error::{args.label}: cannot read SARIF report {args.sarif}: {e}")
        return 1

    results = collect(sarif)
    threshold = LEVELS.index(args.fail_on)
    counts = collections.Counter(r["level"] for r in results)
    for level in LEVELS:
        if counts.get(level):
            print(f"{level:8} {counts[level]}")

    blocking = [r for r in results if LEVELS.index(r["level"]) >= threshold] if results else []
    for entry in results:
        annotate(entry)
    for entry in blocking:
        print(f"BLOCKING {entry['level']:8} {entry['ruleId']:45} {entry['uri']}:{entry['line']}")

    advisory = len(results) - len(blocking)
    print(f"\n{args.label}: {len(blocking)} blocking (>= {args.fail_on}), {advisory} advisory.")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
