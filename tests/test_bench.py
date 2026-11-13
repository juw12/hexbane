"""bench/run.py: case loading, in-process scoring, command adapter, regression check.

Only harmless synthetic files are written to disk here, so the suite does not trip endpoint protection.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))

import run as bench  # noqa: E402


def synthetic_cases():
    clean = {"set": "heldout", "id": "s-clean", "label": "benign", "expected": "PASS", "trick": None,
             "files": {"tools.json": b'{"tools": [{"name": "add", "description": "Adds two numbers."}]}'}}
    marked = {"set": "heldout", "id": "s-marked", "label": "malicious", "expected": "FAIL", "trick": None,
              "files": {"notes/readme.md": b"BENCH-MARKER"}}
    return [clean, marked]


class BenchTest(unittest.TestCase):
    def test_corpus_loads(self):
        cases = bench.load_cases()
        self.assertEqual(len(cases), 112)
        self.assertEqual({c["set"] for c in cases}, set(bench.SETS))
        self.assertEqual(sum(c["label"] == "benign" for c in cases), 12)

    def test_hexbane_in_process_matches_evaluation(self):
        result = bench.score(bench.hexbane_flags, bench.load_cases(), on_disk=False)
        heldout = result["sets"]["heldout"]
        self.assertEqual((heldout["caught"], heldout["malicious"]), (11, 11))
        self.assertEqual((heldout["false_alarms"], heldout["benign"]), (0, 5))
        self.assertEqual(result["sets"]["obfuscated"]["caught"], 65)

    def test_command_adapter_exit_and_regex(self):
        script = (
            "import pathlib, sys; "
            "hit = any('BENCH-MARKER' in p.read_text() for p in pathlib.Path(sys.argv[1]).rglob('*') if p.is_file()); "
            "print('FLAG' if hit else 'ok'); sys.exit(1 if hit else 0)"
        )
        with tempfile.TemporaryDirectory() as temp:
            script_path = Path(temp) / "marker.py"
            script_path.write_text(script, encoding="utf-8")
            command = f'"{sys.executable}" "{script_path}" {{path}}'
            for flag in ("exit", "regex:FLAG"):
                result = bench.score(bench.command_flags(command, flag, 30), synthetic_cases())
                row = result["sets"]["heldout"]
                self.assertEqual((row["caught"], row["false_alarms"], row["blocked"]), (1, 0, []), flag)

    def test_unreadable_case_is_not_scored(self):
        original = bench.readable
        bench.readable = lambda case_dir, case: case["id"] != "s-marked"
        try:
            result = bench.score(lambda case, case_dir: (True, ""), synthetic_cases())
        finally:
            bench.readable = original
        row = result["sets"]["heldout"]
        self.assertEqual(row["blocked"], ["s-marked"])
        self.assertEqual(row["malicious"], 0)

    def test_check_flags_regression(self):
        committed = json.loads((ROOT / "bench" / "results" / "hexbane.json").read_text(encoding="utf-8"))
        worse = json.loads(json.dumps(committed))
        worse["sets"]["heldout"]["caught"] -= 1
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "committed.json"
            path.write_text(json.dumps(committed), encoding="utf-8")
            self.assertEqual(bench.check(committed, path), [])
            self.assertTrue(bench.check(worse, path))

    def test_export_rejects_path_escape(self):
        evil = dict(synthetic_cases()[0], files={"../escape.txt": b"x"})
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                bench.write_case(evil, Path(temp))


if __name__ == "__main__":
    unittest.main(verbosity=2)
