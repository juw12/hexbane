"""hexbench: score any scanner on hexbane's labelled corpora.

    python bench/run.py                                    # hexbane, in-process
    python bench/run.py --name mytool --command "mytool scan {path}"
    python bench/run.py --name mytool --command "mytool scan {path}" --flag "regex:(?i)high|critical"
    python bench/run.py --export cases/                    # the cases as plain folders + labels.json
    python bench/run.py --check bench/results/hexbane.json # fail if hexbane scores worse than the committed result

Each case is one folder with the files an agent would load (an MCP config, a tool list, a skill). A scanner
"flags" a case when it says the case is not clean. With --command, {path} is replaced by the case folder and
the case counts as flagged when:
    --flag exit          (default) the command exits non-zero
    --flag regex:PATTERN  the pattern matches stdout + stderr
A malicious case that is flagged is "caught"; a benign case that is flagged is a "false alarm".

Sets (scored separately, never summed into one number):
    heldout     16 cases written after hexbane's rules were frozen and run once. The fair set.
    obfuscated  65 malicious cases: the tuning attacks rewritten with one evasion trick each.
    tuning      31 cases hexbane's rules were written against. Not a fair set for hexbane; listed for others.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETS = ("heldout", "obfuscated", "tuning")
FAIR_NOTE = {
    "heldout": "written after the rules were frozen",
    "obfuscated": "derived from tuning attacks; hexbane's unfolding pass was built for these tricks",
    "tuning": "hexbane was tuned on this set - not a fair score for hexbane",
}


def load_cases() -> list[dict]:
    cases = []
    for set_name in SETS:
        data = json.loads((ROOT / "corpus" / f"{set_name}.json").read_text(encoding="utf-8"))
        for sample in data["samples"]:
            cases.append({
                "set": set_name,
                "id": sample["id"],
                "label": sample["set"],
                "expected": sample["expected"],
                "trick": sample.get("trick"),
                "files": {name: base64.b64decode(blob) for name, blob in sample["files"].items()},
            })
    return cases


def write_case(case: dict, folder: Path) -> Path:
    case_dir = folder / case["set"] / case["id"]
    for name, content in case["files"].items():
        target = (case_dir / name).resolve()
        if case_dir.resolve() not in target.parents:
            raise ValueError(f"unsafe file name in corpus: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return case_dir


def export(folder: Path) -> Path:
    cases = load_cases()
    labels = []
    for case in cases:
        write_case(case, folder)
        labels.append({key: case[key] for key in ("set", "id", "label", "expected", "trick")})
    (folder / "labels.json").write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
    return folder


def readable(case_dir: Path, case: dict) -> bool:
    """False when files written for a case cannot be read back (for example, quarantined by antivirus)."""
    try:
        return all((case_dir / name).read_bytes() == content for name, content in case["files"].items())
    except OSError:
        return False


def hexbane_flags(case: dict, case_dir: Path | None) -> tuple[bool, str]:
    sys.path.insert(0, str(ROOT))
    from hexbane.scanner import scan_files

    files = [(name, content.decode("utf-8")) for name, content in case["files"].items()]
    verdict = scan_files(files)["verdict"]
    return verdict != "PASS", verdict


def command_flags(command: str, flag: str, timeout: float):
    def run(case: dict, case_dir: Path) -> tuple[bool, str]:
        tokens = shlex.split(command, posix=(sys.platform != "win32"))
        if sys.platform == "win32":
            tokens = [token[1:-1] if len(token) > 1 and token[0] == token[-1] == '"' else token for token in tokens]
        parts = [token.replace("{path}", str(case_dir)) for token in tokens]
        try:
            result = subprocess.run(parts, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "timeout"
        if flag == "exit":
            return result.returncode != 0, f"exit {result.returncode}"
        pattern = re.compile(flag.removeprefix("regex:"))
        matched = bool(pattern.search(result.stdout + result.stderr))
        return matched, "match" if matched else "no match"
    return run


def score(scanner, cases: list[dict], on_disk: bool = True) -> dict:
    """on_disk=False runs the scanner on the in-memory files only (nothing is written)."""
    per_set = {name: {"malicious": 0, "caught": 0, "benign": 0, "false_alarms": 0, "misses": [], "alarms": [], "blocked": []}
               for name in SETS}
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="hexbench-") as temp:
        for case in cases:
            row = per_set[case["set"]]
            case_dir = None
            if on_disk:
                case_dir = write_case(case, Path(temp))
                if not readable(case_dir, case):
                    row["blocked"].append(case["id"])
                    continue
            flagged, detail = scanner(case, case_dir)
            if case["label"] == "benign":
                row["benign"] += 1
                if flagged:
                    row["false_alarms"] += 1
                    row["alarms"].append(case["id"])
            else:
                row["malicious"] += 1
                if flagged:
                    row["caught"] += 1
                else:
                    row["misses"].append(case["id"] + (f" ({case['trick']})" if case["trick"] else ""))
    return {"seconds": round(time.perf_counter() - started, 1), "sets": per_set}


def markdown(name: str, result: dict) -> str:
    lines = [f"## {name}", "", "| set | malicious caught | benign false alarms | note |", "|---|---|---|---|"]
    for set_name, row in result["sets"].items():
        benign = f"{row['false_alarms']}/{row['benign']}" if row["benign"] else "-"
        lines.append(f"| {set_name} | {row['caught']}/{row['malicious']} | {benign} | {FAIR_NOTE[set_name]} |")
    lines.append("")
    for set_name, row in result["sets"].items():
        if row["misses"]:
            lines.append(f"Missed in {set_name}: {', '.join(row['misses'])}")
        if row["alarms"]:
            lines.append(f"False alarms in {set_name}: {', '.join(row['alarms'])}")
        if row["blocked"]:
            lines.append(f"Not scored in {set_name} (case files unreadable after writing, e.g. quarantined by antivirus): "
                         f"{', '.join(row['blocked'])}")
    lines.append(f"\n{result['seconds']} s for {sum(r['malicious'] + r['benign'] for r in result['sets'].values())} cases.")
    return "\n".join(lines) + "\n"


def check(result: dict, committed_path: Path) -> list[str]:
    committed = json.loads(committed_path.read_text(encoding="utf-8"))["sets"]
    problems = []
    for set_name, row in result["sets"].items():
        old = committed[set_name]
        if row["caught"] < old["caught"]:
            problems.append(f"{set_name}: caught {row['caught']} < committed {old['caught']}")
        if row["false_alarms"] > old["false_alarms"]:
            problems.append(f"{set_name}: false alarms {row['false_alarms']} > committed {old['false_alarms']}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--name", default="hexbane")
    parser.add_argument("--command", help="scanner command; {path} is the case folder")
    parser.add_argument("--flag", default="exit", help="'exit' or 'regex:PATTERN'")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--json", help="write the result as JSON here")
    parser.add_argument("--export", help="write the cases as plain folders here and stop")
    parser.add_argument("--check", help="committed result JSON; exit 1 if this run is worse")
    args = parser.parse_args(argv)

    if args.export:
        folder = export(Path(args.export))
        print(f"wrote {len(load_cases())} cases and labels.json to {folder}")
        return 0
    if args.flag != "exit" and not args.flag.startswith("regex:"):
        parser.error("--flag must be 'exit' or 'regex:PATTERN'")

    scanner = command_flags(args.command, args.flag, args.timeout) if args.command else hexbane_flags
    result = score(scanner, load_cases(), on_disk=bool(args.command))
    result["scanner"] = args.name
    result["command"] = args.command or "in-process hexbane.scanner.scan_files (verdict != PASS)"
    print(markdown(args.name, result))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.check:
        problems = check(result, Path(args.check))
        for problem in problems:
            print("REGRESSION:", problem)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
