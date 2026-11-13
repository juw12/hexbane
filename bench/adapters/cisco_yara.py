"""hexbench adapter for Cisco's mcp-scanner (pip: cisco-ai-mcp-scanner), offline YARA analyzer only.

    python bench/adapters/cisco_yara.py <case folder>

mcp-scanner's static mode reads an MCP tools/list JSON ({"tools": [...]}). This adapter runs it on every JSON
file in the case folder that has a "tools" array and exits 1 if any tool is reported unsafe, else 0.
Cases with no tools list (MCP configs, skills, plain text) cannot be read by this mode; the adapter prints
"no tool list" and exits 0, so they count as not flagged. The README reports both the full-set score and the
score on the cases it can read.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def tool_lists(folder: Path) -> list[Path]:
    found = []
    for path in sorted(folder.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("tools"), list):
            found.append(path)
    return found


def unsafe(node) -> bool:
    if isinstance(node, dict):
        if node.get("is_safe") is False:
            return True
        return any(unsafe(value) for value in node.values())
    if isinstance(node, list):
        return any(unsafe(item) for item in node)
    return False


def main() -> int:
    folder = Path(sys.argv[1])
    files = tool_lists(folder)
    if not files:
        print("no tool list")
        return 0
    flagged = False
    for path in files:
        result = subprocess.run(
            ["mcp-scanner", "--analyzers", "yara", "--format", "raw", "static", "--tools", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        start = result.stdout.find("{")
        try:
            report = json.loads(result.stdout[start:]) if start >= 0 else {}
        except ValueError:
            print(f"{path.name}: unparsable output, exit {result.returncode}")
            continue
        verdict = unsafe(report)
        flagged = flagged or verdict
        print(f"{path.name}: {'UNSAFE' if verdict else 'safe'}")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
