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
import math
import os
import sys
from datetime import date
from pathlib import Path

# SARIF levels, least to most severe. "none" is informational only.
LEVELS = ["none", "note", "warning", "error"]
DEFAULT_LEVEL = "warning"
# CVSS v3 qualitative bands, as used by NVD and GitHub advisories.
CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def cvss_band(score: float | None) -> str:
    if score is None:
        return "unknown"
    for floor, name in CVSS_BANDS:
        if score >= floor:
            return name
    return "none"


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


def rule_cvss(run: dict) -> dict[str, float]:
    """CVSS scores keyed by rule id, from the `security-severity` rule property."""
    out: dict[str, float] = {}
    driver = run.get("tool", {}).get("driver", {})
    for extension in [driver, *run.get("tool", {}).get("extensions", [])]:
        for rule in extension.get("rules", []) or []:
            rid = rule.get("id")
            raw = (rule.get("properties") or {}).get("security-severity")
            if not rid or raw is None:
                continue
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue
            # NaN/inf compare false against any threshold, so they would read as "below".
            # Leaving the score out makes the finding block as "no CVSS" instead.
            if math.isfinite(score):
                out[rid] = score
    return out


def collect(sarif: dict) -> list[dict]:
    results = []
    for run in sarif.get("runs", []) or []:
        levels = rule_levels(run)
        scores = rule_cvss(run)
        for result in run.get("results", []) or []:
            level = result.get("level") or levels.get(result.get("ruleId", ""), DEFAULT_LEVEL)
            cvss = scores.get(result.get("ruleId", ""))
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
                "cvss": cvss,
                "band": cvss_band(cvss),
                "message": (result.get("message") or {}).get("text", ""),
                **location,
            })
    return results


def structural_problems(sarif: object) -> list[str]:
    """Reasons a document cannot be trusted as a complete scan.

    `{}` or a run that reports its own failure is indistinguishable from a scanner that
    never ran; both used to exit 0 as "no findings".
    """
    if not isinstance(sarif, dict):
        return ["top level is not an object"]
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        return ["no `runs` - the scanner produced no run at all"]
    problems = []
    for i, run in enumerate(runs):
        if not isinstance(run, dict):
            problems.append(f"runs[{i}] is not an object")
            continue
        driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        if not isinstance(driver, dict) or not driver.get("name"):
            problems.append(f"runs[{i}] has no tool.driver.name")
        if not isinstance(run.get("results", []), list):
            problems.append(f"runs[{i}].results is not a list")
        for inv in run.get("invocations") or []:
            if isinstance(inv, dict) and inv.get("executionSuccessful") is False:
                problems.append(f"runs[{i}] reports executionSuccessful: false")
    return problems


def load_exceptions(defaults: Path | None, overlay: Path | None, today: date) -> list[dict]:
    """Valid, unexpired `semgrep:<rule-id>` exceptions from the policy files.

    The same files, fields and validation as the custom scanner, so one reviewed, dated
    exception covers a behaviour in both engines. Invalid or expired entries are simply
    not applied (the custom scanner reports them as blocking findings), so a bad entry
    can only ever leave a finding blocking.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scan_repo  # noqa: E402 - sibling module, imported lazily

    policy: dict = {}
    if defaults is not None:
        policy = json.loads(defaults.read_text(encoding="utf-8"))
    if overlay is not None and overlay.is_file():
        policy, _ = scan_repo.merge_policy(policy, json.loads(overlay.read_text(encoding="utf-8")))
    usable = scan_repo.validate_exceptions(policy, [], today)
    return [e for e in usable if e["rule"].startswith("semgrep:")]


def apply_exceptions(results: list[dict], exceptions: list[dict]) -> None:
    """Mark results covered by an exception, at most `sites` per file (default 1)."""
    # Same glob semantics as the custom scanner, so one `paths` entry means one thing.
    from scan_repo import path_matches_any  # noqa: E402 - loaded by load_exceptions
    hits: dict[tuple[int, str], list[dict]] = {}
    for r in results:
        for n, e in enumerate(exceptions):
            if rule_matches(r["ruleId"], [e["rule"][len("semgrep:"):]]) and path_matches_any(r["uri"], e["paths"]):
                hits.setdefault((n, r["uri"]), []).append(r)
                break
    for (n, uri), covered in hits.items():
        e = exceptions[n]
        if len(covered) > e.get("sites", 1):
            print(f"::warning::{uri}: exception {e['rule']} covers {e.get('sites', 1)} site(s), "
                  f"found {len(covered)}; none are excepted until it is re-reviewed.")
            continue
        for r in covered:
            r["excepted"] = f"{e['reason']} (until {e['expires']})"


def load_block_rules(path: Path) -> list[str]:
    """Rule ids that block regardless of SARIF level, one per line, `#` comments allowed."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def rule_matches(rule_id: str, entries: list[str]) -> bool:
    # Semgrep prefixes rule ids with the path of the config they came from
    # (`rules.semgrep.<id>` for the vendored set), so an entry matches a dotted suffix.
    return any(rule_id == e or rule_id.endswith("." + e) for e in entries)


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
    ap.add_argument("--fail-on-cvss", type=float, metavar="SCORE",
                    help="Block on findings whose CVSS score is at or above SCORE. Use for "
                         "producers like OSV-Scanner that put severity in the rule's "
                         "`security-severity` property rather than the SARIF level. When "
                         "set, the level threshold is not applied; a finding carrying no "
                         "CVSS score blocks, so a missing score never reads as safe.")
    ap.add_argument("--cvss-ceiling", type=float, metavar="SCORE",
                    help="Refuse a --fail-on-cvss above SCORE. The threshold is a caller input, "
                         "so without a ceiling a caller could set it beyond any real score and "
                         "turn the gate off while appearing to run it.")
    ap.add_argument("--block-rules", type=Path, metavar="FILE",
                    help="File of rule ids that block at ANY level. Used to promote reviewed, "
                         "high-confidence WARNING rules (injection, hardcoded secrets) into the "
                         "gate without blocking every advisory rule. Missing file fails closed.")
    ap.add_argument("--policy", type=Path, metavar="FILE",
                    help="Central policy defaults; with --policy-overlay, `semgrep:<rule-id>` "
                         "exceptions are honoured exactly as the custom scanner honours its own.")
    ap.add_argument("--policy-overlay", type=Path, metavar="FILE")
    ap.add_argument("--label", default="SARIF")
    args = ap.parse_args(argv)

    for name, value in (("--fail-on-cvss", args.fail_on_cvss), ("--cvss-ceiling", args.cvss_ceiling)):
        # NaN compares false against every score, so `--fail-on-cvss nan` blocked nothing.
        if value is not None and not (math.isfinite(value) and 0.0 <= value <= 10.0):
            print(f"::error::{args.label}: {name} must be a CVSS score from 0 to 10, got {value}.")
            return 1
    if args.fail_on_cvss is not None and args.cvss_ceiling is not None and args.fail_on_cvss > args.cvss_ceiling:
        print(f"::error::{args.label}: CVSS threshold {args.fail_on_cvss} is above the allowed "
              f"maximum {args.cvss_ceiling}. A repository may tighten this gate, never loosen it.")
        return 1

    try:
        sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        # Fail closed: an unreadable report is indistinguishable from a scanner that
        # never ran, and must never be treated as a clean result.
        print(f"::error::{args.label}: cannot read SARIF report {args.sarif}: {e}")
        return 1

    problems = structural_problems(sarif)
    if problems:
        for problem in problems:
            print(f"::error::{args.label}: report is not a complete scan: {problem}")
        return 1

    results = collect(sarif)
    if args.policy is not None or args.policy_overlay is not None:
        try:
            exceptions = load_exceptions(args.policy, args.policy_overlay, date.today())
        except (OSError, json.JSONDecodeError) as e:
            print(f"::error::{args.label}: cannot read policy: {e}")
            return 1
        apply_exceptions(results, exceptions)

    block_rules: list[str] = []
    if args.block_rules is not None:
        try:
            block_rules = load_block_rules(args.block_rules)
        except OSError as e:
            # Fail closed: a missing list would silently demote every promoted rule.
            print(f"::error::{args.label}: cannot read block-rules file {args.block_rules}: {e}")
            return 1

    if args.fail_on_cvss is not None:
        counts = collections.Counter(r["band"] for r in results)
        for band in ("critical", "high", "medium", "low", "none", "unknown"):
            if counts.get(band):
                print(f"{band:8} {counts[band]}")
        # A finding with no CVSS score blocks: absence of a score is not evidence of safety.
        blocking = [r for r in results if r["cvss"] is None or r["cvss"] >= args.fail_on_cvss]
        criterion = f">= CVSS {args.fail_on_cvss}"
    else:
        threshold = LEVELS.index(args.fail_on)
        counts = collections.Counter(r["level"] for r in results)
        for level in LEVELS:
            if counts.get(level):
                print(f"{level:8} {counts[level]}")
        blocking = [r for r in results if LEVELS.index(r["level"]) >= threshold] if results else []
        criterion = f">= {args.fail_on}"
    if block_rules:
        promoted = [r for r in results if r not in blocking and rule_matches(r["ruleId"], block_rules)]
        blocking = blocking + promoted
        criterion += f" or one of {len(block_rules)} promoted rules"
    excepted = [r for r in blocking if r.get("excepted")]
    blocking = [r for r in blocking if not r.get("excepted")]
    for entry in excepted:
        print(f"EXCEPTED {entry['ruleId']} {entry['uri']}:{entry['line']} - {entry['excepted']}")

    for entry in results:
        annotate(entry)
    for entry in sorted(blocking, key=lambda r: -(r["cvss"] or 0))[:50]:
        score = f"CVSS {entry['cvss']}" if entry["cvss"] is not None else "no CVSS"
        print(f"BLOCKING {score:11} {entry['ruleId']:32} {entry['uri']}:{entry['line']}")
    if len(blocking) > 50:
        print(f"... and {len(blocking) - 50} more")

    advisory = len(results) - len(blocking)
    print(f"\n{args.label}: {len(blocking)} blocking ({criterion}), {advisory} advisory.")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
