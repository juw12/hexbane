"""Gate G1: run every hermetic suite (no browser, no network).  python tests/run_all.py"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITES = [
    ("scanner, lock, call gate, CLI", [sys.executable, "tests/test_scanner.py"], ROOT),
    ("web app hermetic checks", [sys.executable, "tests/test_web.py"], ROOT),
    ("WCAG AA contrast (severity + decoded callout)", [sys.executable, "tests/test_contrast.py"], ROOT),
    ("hexbench harness", [sys.executable, "tests/test_bench.py"], ROOT),
    ("server (chat, load and call gates)", [sys.executable, "tests.py"], ROOT / "server"),
]

env = dict(os.environ, NO_PROXY="*", PYTHONIOENCODING="utf-8")
failed = []
for name, command, cwd in SUITES:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8")
    ok = result.returncode == 0
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        failed.append(name)
        print((result.stdout + result.stderr)[-3000:])
print(f"\n{len(SUITES) - len(failed)}/{len(SUITES)} suites passed")
sys.exit(1 if failed else 0)
