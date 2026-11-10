"""Reproduce the numbers in docs/EVALUATION.md.

    python tests/evaluate.py                       # labelled corpora only (tuning + held-out)
    python tests/evaluate.py path/to/skills ...    # also scan public folders and list every non-PASS file

Labelled corpora: each sample has an expected verdict (PASS / REVIEW / FAIL). A sample is "caught" when a
malicious sample gets REVIEW or FAIL, and a "false alarm" when a benign sample gets anything but PASS.
Public folders have no labels: every REVIEW/FAIL file is printed so a human can judge it.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gardu.scanner import collect_files, scan_files  # noqa: E402


def decode(files: dict) -> list[tuple[str, str]]:
    return [(name, base64.b64decode(data).decode("utf-8")) for name, data in files.items()]


def labelled(name: str) -> list[str]:
    data = json.loads((ROOT / "corpus" / f"{name}.json").read_text(encoding="utf-8"))
    lines = [f"### {name} ({len(data['samples'])} samples)", "", "| sample | set | expected | got | rules |", "|---|---|---|---|---|"]
    exact = caught = malicious = alarms = benign = 0
    for sample in data["samples"]:
        report = scan_files(decode(sample["files"]))
        got = report["verdict"]
        rules = sorted({finding["rule"] for finding in report["findings"]})
        exact += got == sample["expected"]
        if sample["set"] == "benign":
            benign += 1
            alarms += got != "PASS"
        else:
            malicious += 1
            caught += got != "PASS"
        mark = "" if got == sample["expected"] else " **(differs)**"
        lines.append(f"| {sample['id']} | {sample['set']} | {sample['expected']} | {got}{mark} | {', '.join(rules) or '-'} |")
    lines += ["", f"Exact verdict: {exact}/{len(data['samples'])} - malicious caught: {caught}/{malicious} - "
                  f"benign false alarms: {alarms}/{benign}", ""]
    return lines


def public(folder: Path) -> list[str]:
    skipped: list = []
    started = time.perf_counter()
    files = collect_files(folder, skipped)
    report = scan_files(files, skipped)
    seconds = time.perf_counter() - started
    size = sum(len(text.encode("utf-8")) for _, text in files)
    per_file = Counter(entry["verdict"] for entry in report["files"])
    lines = [f"### {folder.name} ({len(files)} files, {size / 1e6:.1f} MB, {seconds:.1f} s)", "",
             f"Files: {per_file.get('PASS', 0)} PASS, {per_file.get('REVIEW', 0)} REVIEW, {per_file.get('FAIL', 0)} FAIL. "
             f"Skipped: {len(skipped)}.", ""]
    flagged = [entry for entry in report["files"] if entry["verdict"] != "PASS"]
    if flagged:
        lines += ["| file | verdict | rules |", "|---|---|---|"]
        for entry in flagged:
            rules = sorted({f["rule"] for f in report["findings"] if f["file"] == entry["path"]})
            lines.append(f"| {entry['path']} | {entry['verdict']} | {', '.join(rules)} |")
        lines.append("")
    return lines


def main() -> int:
    out = ["## Labelled corpora", ""]
    out += labelled("tuning")
    out += labelled("heldout")
    if len(sys.argv) > 1:
        out += ["## Public folders (unlabelled)", ""]
        for arg in sys.argv[1:]:
            out += public(Path(arg))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
