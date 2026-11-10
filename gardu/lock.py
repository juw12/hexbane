"""Rug-pull protection: pin the exact skill files and tool descriptions you approved, then flag any change.

`gardu lock PATH` writes gardu.lock.json. `gardu scan PATH --lock gardu.lock.json` reports GD801 for files or
tools that changed since then and GD802 for new ones.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .scanner import RULES, Finding, classify, collect_files, find_tools

LOCK_VERSION = 1


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_fingerprints(path: str, text: str) -> dict:
    kind, parsed = classify(path, text)
    if kind != "tool":
        return {}
    prints = {}
    for tool in find_tools(parsed):
        schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters") or {}
        canonical = json.dumps({"description": tool.get("description", ""), "schema": schema}, sort_keys=True)
        prints[f"{path}::{tool['name']}"] = digest(canonical)
    return prints


def build_lock(root: Path) -> dict:
    files = collect_files(root)
    lock = {"gardu_lock": LOCK_VERSION, "files": {}, "tools": {}}
    for path, text in files:
        lock["files"][path] = digest(text)
        lock["tools"].update(tool_fingerprints(path, text))
    return lock


def compare(lock: dict, files: list[tuple[str, str]]) -> list[Finding]:
    findings = []
    changed_rule = RULES["by_id"]["GD801"]
    new_rule = RULES["by_id"]["GD802"]

    def add(rule, path, evidence):
        findings.append(Finding(rule=rule["id"], severity=rule["severity"], title=rule["title"], file=path, line=1,
                                evidence=evidence, why=rule["why"], fix=rule["fix"], refs=list(rule.get("refs", []))))

    for path, text in files:
        tools_now = tool_fingerprints(path, text)
        pinned_file = lock["files"].get(path)
        if pinned_file is None:
            add(new_rule, path, "file was not in the lock")
        elif pinned_file != digest(text):
            changed_tools = [key.split("::", 1)[1] for key, value in tools_now.items()
                             if key in lock["tools"] and lock["tools"][key] != value]
            new_tools = [key.split("::", 1)[1] for key in tools_now if key not in lock["tools"]]
            detail = "file content changed"
            if changed_tools:
                detail = "tool description changed: " + ", ".join(changed_tools)
            add(changed_rule, path, detail)
            if new_tools:
                add(new_rule, path, "new tools: " + ", ".join(new_tools))
    return findings


def load_lock(path: Path) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("gardu_lock") != LOCK_VERSION:
        raise ValueError(f"{path} is not a Gardu lock file (version {LOCK_VERSION})")
    return lock
