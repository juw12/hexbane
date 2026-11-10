"""Gate G2: the browser scanner (web/scan.js) and the Python scanner (hexbane/scanner.py) must give identical
findings - same rule, file, line and severity - on every corpus. Runs scan.js in headless Microsoft Edge.

    python ui-tests/parity.py [extra folders to include...]

Exit 0 when every corpus matches, 1 otherwise. Needs Playwright (pip install playwright) and Edge.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hexbane.scanner import collect_files, scan_files  # noqa: E402



def launch_options() -> dict:
    """Edge locally (Windows); plain Playwright Chromium in CI (HEXBANE_BROWSER=chromium)."""
    if os.environ.get("HEXBANE_BROWSER", "msedge") == "chromium":
        return {"headless": True}
    return {"channel": "msedge", "headless": True}

def corpus_sets(extra: list[str]) -> dict:
    sets = {}
    for name in ("tuning", "heldout", "obfuscated"):
        data = json.loads((ROOT / "corpus" / f"{name}.json").read_text(encoding="utf-8"))
        files = []
        for sample in data["samples"]:
            for path, b64 in sample["files"].items():
                files.append((f"{sample['id']}/{path}", base64.b64decode(b64).decode("utf-8")))
        sets[name] = files
    for folder in extra:
        sets[Path(folder).name] = collect_files(Path(folder))
    return sets


def key(finding: dict) -> tuple:
    return (finding["file"], finding["line"], finding["rule"], finding["severity"])


def main() -> int:
    from playwright.sync_api import sync_playwright

    sets = corpus_sets(sys.argv[1:])
    rules = json.loads((ROOT / "hexbane" / "rules.json").read_text(encoding="utf-8"))
    web_rules = json.loads((ROOT / "web" / "rules.json").read_text(encoding="utf-8"))
    failures = 0
    if rules != web_rules:
        print("FAIL web/rules.json differs from hexbane/rules.json (run: python tests/sync_rules.py)")
        failures += 1
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(**launch_options())
        scan_js = (ROOT / "web" / "scan.js").read_text(encoding="utf-8")
        for name, files in sets.items():
            # A fresh page per corpus keeps the large external folders from exhausting one renderer.
            page = browser.new_page()
            page.set_content("<!doctype html><html><body></body></html>")
            page.add_script_tag(content=scan_js)
            page.evaluate("rules => { HexbaneScan.loadRules(rules); }", rules)
            python_report = scan_files(files)
            js_report = page.evaluate("files => HexbaneScan.scanFiles(files)", [list(f) for f in files])
            py_keys = sorted(map(key, python_report["findings"]))
            js_keys = sorted(map(key, js_report["findings"]))
            same = py_keys == js_keys and python_report["verdict"] == js_report["verdict"]
            print(f"{'ok  ' if same else 'FAIL'} {name}: {len(files)} files, {len(py_keys)} findings, verdict {python_report['verdict']}")
            if not same:
                failures += 1
                only_py = sorted(set(py_keys) - set(js_keys))[:10]
                only_js = sorted(set(js_keys) - set(py_keys))[:10]
                print("   only in Python:", only_py)
                print("   only in browser:", only_js)
            page.close()
        browser.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
