"""Output formats for a Gardu scan report: text, json, sarif (GitHub code scanning) and markdown."""

from __future__ import annotations

import json

from .scanner import RULES, SEVERITY_ORDER

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0", "info": "0.0"}
VERDICT_LINE = {
    "PASS": "PASS - nothing risky found",
    "REVIEW": "REVIEW - read the findings before you load this",
    "FAIL": "FAIL - do not load this until the findings are fixed",
}


def filter_report(report: dict, min_severity: str) -> dict:
    floor = SEVERITY_ORDER[min_severity]
    kept = [f for f in report["findings"] if SEVERITY_ORDER[f["severity"]] >= floor]
    return {**report, "findings": kept}


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def to_text(report: dict) -> str:
    lines = [f"Gardu {report['version']}: {VERDICT_LINE[report['verdict']]}",
             f"{report['files_scanned']} files scanned; "
             + ", ".join(f"{count} {name}" for name, count in report["counts"].items() if count) or "no findings"]
    for finding in report["findings"]:
        lines.append("")
        lines.append(f"[{finding['severity'].upper()}] {finding['rule']} {finding['title']}")
        lines.append(f"  at {finding['file']}:{finding['line']}")
        lines.append(f"  {finding['evidence']}")
        if finding.get("hidden_text"):
            lines.append(f"  hidden text: {finding['hidden_text']}")
        lines.append(f"  why: {finding['why']}")
        lines.append(f"  fix: {finding['fix']}")
    for skipped in report.get("skipped", []):
        lines.append("")
        lines.append(f"[NOT SCANNED] {skipped['path']}: {skipped['reason']}")
    return "\n".join(lines) + "\n"


def to_markdown(report: dict) -> str:
    lines = [f"### Gardu: {VERDICT_LINE[report['verdict']]}", "",
             f"{report['files_scanned']} files scanned. "
             + (", ".join(f"**{count} {name}**" for name, count in report["counts"].items() if count) or "No findings."),
             ""]
    if report["findings"]:
        lines += ["| Severity | Rule | Where | What |", "|---|---|---|---|"]
        for finding in report["findings"]:
            evidence = finding["evidence"].replace("|", "\\|").replace("`", "'")[:120]
            lines.append(f"| {finding['severity']} | {finding['rule']} {finding['title']} | "
                         f"`{finding['file']}:{finding['line']}` | {evidence} |")
    for skipped in report.get("skipped", []):
        lines.append(f"\nNot scanned: `{skipped['path']}` ({skipped['reason']})")
    return "\n".join(lines) + "\n"


def to_sarif(report: dict) -> str:
    used = sorted({f["rule"] for f in report["findings"]})
    rules = []
    for rule_id in used:
        rule = RULES["by_id"][rule_id]
        rules.append({
            "id": rule_id,
            "name": rule["title"].replace(" ", ""),
            "shortDescription": {"text": rule["title"]},
            "fullDescription": {"text": rule["why"]},
            "help": {"text": rule["fix"], "markdown": rule["fix"]},
            "helpUri": (rule.get("refs") or ["https://github.com/juw12/gardu"])[0],
            "properties": {"security-severity": SECURITY_SCORE[rule["severity"]], "tags": ["security", rule["category"]]},
        })
    results = []
    for finding in report["findings"]:
        message = f"{finding['title']}: {finding['evidence']}"
        if finding.get("hidden_text"):
            message += f" (hidden text: {finding['hidden_text']})"
        results.append({
            "ruleId": finding["rule"],
            "level": SARIF_LEVEL[finding["severity"]],
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding["file"]},
                "region": {"startLine": max(1, finding["line"])},
            }}],
            "properties": {"security-severity": SECURITY_SCORE[finding["severity"]]},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Gardu", "version": report["version"],
                                "informationUri": "https://github.com/juw12/gardu", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif, "md": to_markdown, "markdown": to_markdown}
