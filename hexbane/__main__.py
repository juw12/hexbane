"""Hexbane command line.

  python -m hexbane scan PATH [PATH...] [--format text|json|sarif|md] [--out FILE]
                                       [--fail-on high] [--min-severity low] [--lock hexbane.lock.json]
  python -m hexbane lock PATH [--out hexbane.lock.json]
  python -m hexbane check-call TOOL ARGS_JSON [--policy policy.json]
  python -m hexbane check-output FILE [--policy policy.json]
  python -m hexbane rules
  python -m hexbane serve [server options]      (chat gate + scan/call gate HTTP API, see server/README.md)

Exit codes: 0 = below --fail-on, 1 = findings at or above --fail-on (or deny/quarantine), 2 = usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report as report_formats
from .fixes import fix_path
from .lock import build_lock, compare, load_lock
from .scanner import RULES, SEVERITY_ORDER, Finding, build_report, collect_files, scan_paths
from .toolgate import check_call, check_output, load_policy


def cmd_scan(args) -> int:
    for path in args.paths:
        if not Path(path).exists():
            print(f"hexbane: no such file or folder: {path}", file=sys.stderr)
            return 2
    result = scan_paths(args.paths)
    if args.lock:
        pin_findings = compare(load_lock(Path(args.lock)), collect_files(Path(args.paths[0])))
        findings = [Finding(**f) for f in result["findings"]] + pin_findings
        result = build_report(findings, result["files"], result.get("skipped", []))
    result = report_formats.filter_report(result, args.min_severity)
    output = report_formats.FORMATS[args.format](result)
    if args.out:
        Path(args.out).write_bytes(output.encode("utf-8"))
        print(f"hexbane: {result['verdict']} - report written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(output)
    if args.fail_on == "never":
        return 0
    floor = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f["severity"]] >= floor for f in result["findings"]) else 0


def cmd_lock(args) -> int:
    lock = build_lock(Path(args.path))
    Path(args.out).write_bytes((json.dumps(lock, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(f"hexbane: pinned {len(lock['files'])} files and {len(lock['tools'])} tools in {args.out}")
    return 0


def cmd_check_call(args) -> int:
    try:
        arguments = json.loads(args.arguments)
    except ValueError as error:
        print(f"hexbane: ARGS_JSON is not valid JSON: {error}", file=sys.stderr)
        return 2
    result = check_call(load_policy(args.policy), args.tool, arguments)
    print(json.dumps(result, indent=2))
    return 1 if result["decision"] == "deny" else 0


def cmd_check_output(args) -> int:
    if args.file == "-":
        text = sys.stdin.read()
        source = "stdin"
    else:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        source = Path(args.file).name
    result = check_output(load_policy(args.policy), text, source=source)
    result.pop("sanitized")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result["decision"] == "quarantine" else 0


def cmd_fix(args) -> int:
    if not Path(args.path).exists():
        print(f"hexbane: no such file or folder: {args.path}", file=sys.stderr)
        return 2
    results = fix_path(args.path, write=args.write)
    if not results:
        print("hexbane: no invisible, bidi or tag characters found; nothing to fix")
        return 0
    for row in results:
        print(f"{'fixed' if row['written'] else 'would fix'} {row['file']}: {row['removed']} hidden characters")
    if not args.write:
        print("hexbane: dry run - add --write to change the files")
    return 0


def cmd_rules(_args) -> int:
    for rule in RULES["rules"]:
        print(f"{rule['id']}  {rule['severity']:8}  {rule['title']}")
    return 0


def cmd_serve(rest: list[str]) -> int:
    server_dir = Path(__file__).resolve().parent.parent / "server"
    sys.path.insert(0, str(server_dir))
    import server  # noqa: E402  (the chat-gate server lives next to the package)
    sys.argv = ["hexbane serve", *rest]
    server.main()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["serve"]:
        return cmd_serve(argv[1:])
    parser = argparse.ArgumentParser(prog="hexbane", description="Check AI agent skills, MCP servers and tools before you load them.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan skills, MCP configs, tool manifests and scripts")
    scan.add_argument("paths", nargs="+")
    scan.add_argument("--format", choices=sorted(report_formats.FORMATS), default="text")
    scan.add_argument("--out")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="high")
    scan.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low")
    scan.add_argument("--lock", help="compare against a hexbane.lock.json made by 'hexbane lock'")
    scan.set_defaults(func=cmd_scan)

    lock = sub.add_parser("lock", help="pin the current files and tool descriptions")
    lock.add_argument("path")
    lock.add_argument("--out", default="hexbane.lock.json")
    lock.set_defaults(func=cmd_lock)

    call = sub.add_parser("check-call", help="decide allow/ask/deny for one tool call")
    call.add_argument("tool")
    call.add_argument("arguments", help="tool arguments as JSON")
    call.add_argument("--policy")
    call.set_defaults(func=cmd_check_call)

    output = sub.add_parser("check-output", help="check a tool result for injected instructions")
    output.add_argument("file", help="tool result file, or - for stdin")
    output.add_argument("--policy")
    output.set_defaults(func=cmd_check_output)

    fix = sub.add_parser("fix", help="delete invisible, bidi and tag characters (the only safe automatic fix)")
    fix.add_argument("path")
    fix.add_argument("--write", action="store_true", help="change the files (default: dry run)")
    fix.set_defaults(func=cmd_fix)

    rules = sub.add_parser("rules", help="list every rule")
    rules.set_defaults(func=cmd_rules)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
