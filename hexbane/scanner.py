"""Hexbane scanner: checks AI agent skills, MCP configs, tool manifests and their scripts before you load them.

Standard library only. The browser app (web/scan.js) implements the same logic from the same rules.json,
and the UI test suite checks that both give identical findings on the whole corpus.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import os
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

RULES_PATH = Path(__file__).with_name("rules.json")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_FILE_BYTES = 2_000_000
MAX_PER_RULE = 25
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".tox"}
INSTRUCTION_EXTS = {".md", ".mdc", ".markdown", ".txt", ".rst"}
INSTRUCTION_NAMES = {".cursorrules", ".windsurfrules", ".clinerules", ".goosehints", ".rules"}
CODE_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
             ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".go", ".rs", ".java", ".kt", ".php", ".lua"}
OTHER_TEXT_EXTS = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml", ".html",
                   ".htm", ".csv", ".sql", ".lock"}


def load_rules(path: Path = RULES_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    flags = re.I | re.A
    for rule in data["rules"]:
        rule["compiled"] = [re.compile(p, flags) for p in rule.get("patterns", [])]
    for capability in data["capabilities"].values():
        capability["compiled"] = [re.compile(p, flags) for p in capability["patterns"]]
    data["by_id"] = {rule["id"]: rule for rule in data["rules"]}
    data["side_channel_re"] = re.compile(data["side_channel_words"], flags)
    data["comment_ai_re"] = re.compile(data["comment_ai_words"], flags)
    data["comment_order_re"] = re.compile(data["comment_order_words"], flags)
    data["negation_re"] = re.compile(data["negation_words"], flags)
    return data


RULES = load_rules()
INVISIBLE = set(RULES["invisible"])
BIDI = set(RULES["bidi"])
CONFUSABLE_TABLE = str.maketrans(RULES["confusables"])
FOLD_RULES = set(RULES["fold_rules"])


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    why: str
    fix: str
    hidden_text: Optional[str] = None
    refs: list = field(default_factory=list)


# ---------------------------------------------------------------- text helpers

def is_tag_char(code: int) -> bool:
    return 0xE0000 <= code <= 0xE007F


def is_emoji_neighbour(code: int) -> bool:
    return code >= 0x1F000 or 0x2600 <= code <= 0x27BF or code == 0xFE0F or 0x1F3FB <= code <= 0x1F3FF


def is_joining_script(code: int) -> bool:
    return 0x0600 <= code <= 0x06FF or 0x0900 <= code <= 0x0DFF or 0x0750 <= code <= 0x077F


def legit_joiner(text: str, index: int) -> bool:
    """Zero-width joiners inside emoji sequences and joining scripts are normal text, not hiding."""
    code = ord(text[index])
    if code not in (0x200C, 0x200D):
        return False
    before = ord(text[index - 1]) if index > 0 else 0
    after = ord(text[index + 1]) if index + 1 < len(text) else 0
    if code == 0x200D and (is_emoji_neighbour(before) or is_emoji_neighbour(after)):
        return True
    return is_joining_script(before) or is_joining_script(after)


def strip_hidden(text: str) -> str:
    """Remove characters used to hide or split words, keeping every newline (line numbers stay valid)."""
    out = []
    for index, char in enumerate(text):
        code = ord(char)
        if is_tag_char(code) or code in BIDI:
            continue
        if code in INVISIBLE and not legit_joiner(text, index):
            continue
        out.append(char)
    return unicodedata.normalize("NFKC", "".join(out))


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def visible_line(text: str, line: int) -> str:
    lines = text.split("\n")
    raw = lines[line - 1] if 0 < line <= len(lines) else ""
    shown = []
    hidden_run = 0
    for char in raw:
        code = ord(char)
        if is_tag_char(code):
            hidden_run += 1
            continue
        if hidden_run:
            shown.append(f"[{hidden_run} hidden tag chars]")
            hidden_run = 0
        if code in INVISIBLE or code in BIDI:
            shown.append(f"[U+{code:04X}]")
        elif char == "\r":
            continue
        else:
            shown.append(char)
    if hidden_run:
        shown.append(f"[{hidden_run} hidden tag chars]")
    snippet = "".join(shown).strip()
    return snippet if len(snippet) <= 200 else snippet[:197] + "..."


def mask_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}****({len(value)} chars)"


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in RULES["placeholder_words"])


def decode_tags(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


# ---------------------------------------------------------------- classification

def classify(path: str, text: str) -> tuple[str, Optional[object]]:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext in (".json", ".jsonc") or name.endswith(".json"):
        try:
            parsed = json.loads(text)
        except ValueError:
            return "other", None
        if find_servers(parsed) is not None:
            return "config", parsed
        if find_tools(parsed):
            return "tool", parsed
        return "other", parsed
    if ext in CODE_EXTS:
        return "code", None
    if ext in INSTRUCTION_EXTS or name in INSTRUCTION_NAMES:
        return "instructions", None
    return "other", None


def find_servers(parsed) -> Optional[dict]:
    if not isinstance(parsed, dict):
        return None
    for key in ("mcpServers", "servers", "context_servers"):
        value = parsed.get(key)
        if isinstance(value, dict) and value and all(isinstance(v, dict) for v in value.values()):
            if any(("command" in v or "url" in v or "serverUrl" in v) for v in value.values()):
                return value
    mcp = parsed.get("mcp")
    if isinstance(mcp, dict):
        return find_servers(mcp)
    return None


def find_tools(parsed) -> list:
    candidates = []
    if isinstance(parsed, dict) and isinstance(parsed.get("tools"), list):
        candidates = parsed["tools"]
    elif isinstance(parsed, dict) and isinstance(parsed.get("result"), dict) and isinstance(parsed["result"].get("tools"), list):
        candidates = parsed["result"]["tools"]
    elif isinstance(parsed, list):
        candidates = parsed
    elif isinstance(parsed, dict) and "name" in parsed and "description" in parsed and (
            "inputSchema" in parsed or "input_schema" in parsed or "parameters" in parsed):
        candidates = [parsed]
    return [t for t in candidates if isinstance(t, dict) and isinstance(t.get("name"), str)
            and isinstance(t.get("description", ""), str)]


# ---------------------------------------------------------------- core text scan

class FileScan:
    def __init__(self, path: str, text: str, kind: str):
        self.path = path
        self.text = text
        self.kind = kind
        self.findings: list[Finding] = []
        self.seen: set = set()
        self.per_rule: dict = {}
        self.lines = text.split("\n")

    def add(self, rule_id: str, line: int, evidence: Optional[str] = None, hidden: Optional[str] = None,
            severity: Optional[str] = None, extra_key: str = "") -> None:
        key = (rule_id, line, extra_key)
        if key in self.seen:
            return
        if self.per_rule.get(rule_id, 0) >= MAX_PER_RULE:
            return
        if self.suppressed(rule_id, line):
            return
        rule = RULES["by_id"][rule_id]
        self.seen.add(key)
        self.per_rule[rule_id] = self.per_rule.get(rule_id, 0) + 1
        self.findings.append(Finding(
            rule=rule_id,
            severity=severity or rule["severity"],
            title=rule["title"],
            file=self.path,
            line=line,
            evidence=evidence if evidence is not None else visible_line(self.text, line),
            why=rule["why"],
            fix=rule["fix"],
            hidden_text=hidden,
            refs=list(rule.get("refs", [])),
        ))

    def suppressed(self, rule_id: str, line: int) -> bool:
        for number in (line, line - 1):
            if 0 < number <= len(self.lines):
                content = self.lines[number - 1]
                marker = content.find("hexbane-ignore")
                if marker == -1:
                    continue
                if number == line - 1 and "hexbane-ignore-next-line" not in content:
                    continue
                rest = content[marker:]
                ids = re.findall(r"HB\d{3}", rest)
                if not ids or rule_id in ids:
                    return True
        return False


SEVERITY_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}


def severity_for(rule: dict, kind: str) -> str:
    return rule.get("severity_by_kind", {}).get(kind, rule["severity"])


def context_severity(rule: dict, kind: str, text: str, start: int) -> str:
    """Lower severity one level when the match sits in a code comment, or in a warning such as
    'never run curl | sh'. The finding is still reported, so nothing is hidden from the user."""  # hexbane-ignore: HB401 (example text)
    severity = severity_for(rule, kind)
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    if kind == "code" and prefix.lstrip().startswith(tuple(RULES["comment_prefixes"])):
        severity = SEVERITY_DOWN[severity]
    if (rule["category"] in RULES["downgrade_categories"] or rule["id"] in RULES["downgrade_rules"]) \
            and RULES["negation_re"].search(prefix):
        severity = SEVERITY_DOWN[severity]
    return severity


def applies(rule: dict, kind: str) -> bool:
    targets = rule.get("applies")
    return not targets or kind in targets


def scan_patterns(scan: FileScan, text: str, line_offset: Optional[int] = None, hidden_source: Optional[str] = None) -> None:
    """Run every regex rule over text. line_offset pins all findings to one line (used for decoded text)."""
    for rule in RULES["rules"]:
        if not rule.get("compiled") or not applies(rule, scan.kind):
            continue
        for pattern in rule["compiled"]:
            for match in pattern.finditer(text):
                line = line_offset if line_offset is not None else line_of(text, match.start())
                evidence = None
                if rule.get("mask"):
                    if rule["id"] == "HB311":
                        raw_value = re.split(r"[:=]", match.group(0), maxsplit=1)[-1].strip()
                        quoted = raw_value[:1] in ("\"", "'")
                        value = raw_value.strip("\"'")
                        if is_placeholder(value) or not (quoted or re.search(r"\d", value)):
                            continue
                        evidence = f"{match.group(0).split(value)[0].strip()} {mask_secret(value)}"
                    else:
                        evidence = f"secret {mask_secret(match.group(0))}"
                severity = (severity_for(rule, scan.kind) if line_offset is not None
                            else context_severity(rule, scan.kind, text, match.start()))
                scan.add(rule["id"], line, evidence=evidence, hidden=hidden_source, severity=severity)


# ---------------------------------------------------------------- disguised text (fold pass)

FOLD_ENTITY = re.compile(r"&#(\d{2,5});|&#[xX]([0-9a-fA-F]{2,5});")
FOLD_STEPS = [
    # (pattern, replacement); replacement None means "decode the entity"
    (re.compile(r"(?<=[A-Za-z])(\*{1,2}|~~|`)(?=[A-Za-z])"), ""),          # ig**no**re
    (re.compile(r"(?<=[A-Za-z])(''|\"\")(?=[A-Za-z])"), ""),                # cu''rl
    # i g n o r e : a run of single letters. It may follow a normal word ("json a n d"), but not a letter glued to
    # other characters ("-F f i l e" must not become "-Ffile"), and never starts in the middle of another run.
    (re.compile(r"(?<!\s[A-Za-z] )(?<!^[A-Za-z] )(?<![\w-])[A-Za-z](?: [A-Za-z])+(?![A-Za-z])(?! [A-Za-z](?![A-Za-z]))"), "SPACED"),
]
FOLD_NEWLINE = re.compile(r"(?<=[^\n])\n(?=[^\n])")
FOLD_GAPS = re.compile(r"(?<=\S)[ \t]{2,}(?=\S)")


def fold_sub(text: str, source: list, disguised: list, pattern, replace, mark: bool = True) -> tuple[str, list, list]:
    """Apply one substitution while keeping, for every output character, the index of the input character it
    came from (so findings keep their original line numbers) and whether it was produced by undoing a disguise."""
    out, out_source, out_disguised = [], [], []
    cursor = 0
    for match in pattern.finditer(text):
        out.append(text[cursor:match.start()])
        out_source.extend(source[cursor:match.start()])
        out_disguised.extend(disguised[cursor:match.start()])
        replacement = replace(match)
        anchor = source[match.start()]
        out.append(replacement)
        out_source.extend([anchor] * len(replacement))
        out_disguised.extend([mark] * len(replacement))
        if mark and not replacement and match.end() < len(text):
            disguised = disguised[:match.end()] + [True] + disguised[match.end() + 1:]
        cursor = match.end()
    out.append(text[cursor:])
    out_source.extend(source[cursor:])
    out_disguised.extend(disguised[cursor:])
    return "".join(out), out_source, out_disguised


def entity_char(match) -> str:
    code = int(match.group(1)) if match.group(1) else int(match.group(2), 16)
    return chr(code) if 32 <= code < 0x110000 else match.group(0)


def fold(clean: str) -> Optional[tuple[str, list, list]]:
    """Undo common disguises: look-alike letters, HTML entities, markdown markers or empty quotes inside words,
    letters separated by spaces, and lines wrapped mid-sentence. Returns None when nothing changes."""
    text = clean.translate(CONFUSABLE_TABLE)
    disguised = [a != b for a, b in zip(text, clean)]
    source = list(range(len(text)))
    text, source, disguised = fold_sub(text, source, disguised, FOLD_ENTITY, entity_char)
    for pattern, replacement in FOLD_STEPS:
        if replacement == "SPACED":
            text, source, disguised = fold_sub(text, source, disguised, pattern, lambda m: m.group(0).replace(" ", ""))
        else:
            text, source, disguised = fold_sub(text, source, disguised, pattern, lambda m, r=replacement: r)
    text, source, disguised = fold_sub(text, source, disguised, FOLD_GAPS, lambda m: " ", mark=False)
    joined = FOLD_NEWLINE.sub(" ", text)
    if joined == clean:
        return None
    return joined, source, disguised


def fold_window(text: str, source: list, clean: str, start: int, end: int) -> str:
    """Decoded text for a folded match, limited to the original line(s) the match came from."""
    origin = source[start]
    first_line_start = clean.rfind("\n", 0, origin) + 1
    line_end = clean.find("\n", source[end - 1])
    if line_end == -1:
        line_end = len(clean)
    left = start
    while left > 0 and start - left < 80 and source[left - 1] >= first_line_start:
        left -= 1
    right = end
    while right < len(text) and right - end < 80 and source[right] < line_end:
        right += 1
    return " ".join(text[left:right].split())[:300]


def scan_folded(scan: FileScan, clean: str) -> None:
    """Rescan the folded text and report what only the folded text reveals."""
    folded = fold(clean)
    if folded is None:
        return
    text, source, disguised = folded
    if scan.kind == "code" and not any(disguised):
        return  # only wrapping or spacing changed; that matters for prompt text, not for source code
    for rule in RULES["rules"]:
        if rule["id"] not in FOLD_RULES or not rule.get("compiled") or not applies(rule, scan.kind):
            continue
        for pattern in rule["compiled"]:
            for match in pattern.finditer(text):
                origin = source[match.start()]
                line = line_of(clean, origin)
                if (rule["id"], line, "") in scan.seen:
                    continue
                snippet = fold_window(text, source, clean, match.start(), match.end())
                severity = context_severity(rule, scan.kind, clean, origin)
                scan.add(rule["id"], line, hidden=snippet, severity=severity)
                if any(disguised[match.start():match.end()]):
                    scan.add("HB106", line, hidden=snippet)


def invisible_severity(kind: str, text: str, index: int) -> str:
    """In code, an invisible character that does not sit inside a word (e.g. a BOM test fixture) cannot
    split a trigger word, so it is reported as medium. Inside a word, or in any prompt-facing file, it is high."""
    if kind != "code":
        return "high"
    before = text[index - 1] if index > 0 else " "
    after = text[index + 1] if index + 1 < len(text) else " "
    return "high" if before.isalnum() and after.isalnum() else "medium"


def scan_hidden_chars(scan: FileScan) -> None:
    text = scan.text
    start = 1 if text.startswith("\ufeff") else 0
    index = start
    while index < len(text):
        code = ord(text[index])
        if is_tag_char(code):
            end = index
            while end < len(text) and is_tag_char(ord(text[end])):
                end += 1
            hidden = decode_tags(text[index:end])
            line = line_of(text, index)
            scan.add("HB103", line, hidden=hidden[:300] or None)
            if hidden:
                scan_patterns(scan, hidden, line_offset=line, hidden_source=hidden[:300])
            index = end
            continue
        if code in BIDI:
            scan.add("HB102", line_of(text, index))
        elif code in INVISIBLE and not legit_joiner(text, index):
            scan.add("HB101", line_of(text, index), severity=invisible_severity(scan.kind, text, index))
        index += 1


HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


# ---------------------------------------------------------------- letter-spaced text (squeeze pass)

SQUEEZE_RUN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z](?:[ \t]{1,3}[A-Za-z]){7,}(?![A-Za-z0-9])")


def squeeze_patterns(rule: dict) -> list:
    """Space-tolerant versions of a rule's patterns: word gaps become optional and word boundaries are dropped."""
    if "squeezed" not in rule:
        rule["squeezed"] = [
            re.compile(pattern.pattern.replace(r"\b", "").replace(r"\s+", r"\s*"), pattern.flags)
            for pattern in rule["compiled"]
        ]
    return rule["squeezed"]


def scan_squeezed(scan: FileScan, clean: str) -> None:
    """Letters typed one space apart ("i g n o r e a l l p r e v i o u s") lose their word gaps once joined, so the
    fold pass cannot read them. For each line holding a run of 8+ spaced letters, remove every space and match
    space-tolerant versions of the fold rules. A match only counts if it covers part of the spaced run, so normal
    text on the same line cannot trigger it."""
    translated = clean.translate(CONFUSABLE_TABLE)
    for line_number, line in enumerate(translated.split("\n"), start=1):
        runs = [(match.start(), match.end()) for match in SQUEEZE_RUN.finditer(line)]
        if not runs:
            continue
        squeezed_chars, in_run = [], []
        for index, char in enumerate(line):
            if char.isspace():
                continue
            squeezed_chars.append(char)
            in_run.append(any(start <= index < end for start, end in runs))
        squeezed = "".join(squeezed_chars)
        readable = line
        for start, end in reversed(runs):
            readable = readable[:start] + re.sub(r"\s+", "", readable[start:end]) + readable[end:]
        readable = " ".join(readable.split())[:300]
        for rule in RULES["rules"]:
            if rule["id"] not in FOLD_RULES or not rule.get("compiled") or not applies(rule, scan.kind):
                continue
            if (rule["id"], line_number, "") in scan.seen:
                continue
            for pattern in squeeze_patterns(rule):
                match = next((m for m in pattern.finditer(squeezed) if any(in_run[m.start():m.end()])), None)
                if match is None:
                    continue
                scan.add(rule["id"], line_number, hidden=readable, severity=severity_for(rule, scan.kind))
                scan.add("HB106", line_number, hidden=readable)
                break


def scan_comments(scan: FileScan, clean: str) -> None:
    if scan.kind != "instructions":
        return
    for match in HTML_COMMENT.finditer(clean):
        body = match.group(1)
        if len(body.strip()) < 20:
            continue
        if RULES["comment_ai_re"].search(body) and RULES["comment_order_re"].search(body):
            scan.add("HB104", line_of(clean, match.start()), hidden=" ".join(body.split())[:300])


def scan_base64(scan: FileScan, clean: str) -> None:
    for match in BASE64_BLOB.finditer(clean):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        if not decoded:
            continue
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(decoded) < 0.9:
            continue
        text = decoded.decode("latin-1")
        line = line_of(clean, match.start())
        before = len(scan.findings)
        scan_patterns(scan, text, line_offset=line, hidden_source=" ".join(text.split())[:300])
        severity = "high" if len(scan.findings) > before else None
        scan.add("HB105", line, hidden=" ".join(text.split())[:300], severity=severity)


def tool_line(text: str, name: str) -> int:
    index = text.find(f'"{name}"')
    return line_of(text, index) if index >= 0 else 1


def scan_tools(scan: FileScan, parsed) -> None:
    tools = find_tools(parsed)
    names = [t["name"] for t in tools]
    for tool in tools:
        name = tool["name"]
        line = tool_line(scan.text, name)
        description = tool.get("description") or ""
        schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters") or {}
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        param_text = "\n".join(
            f"{key}: {value.get('description', '')}" for key, value in properties.items() if isinstance(value, dict))
        combined = f"{name}\n{description}\n{param_text}"
        decoded_scan = FileScan(scan.path, combined, scan.kind)
        scan_hidden_chars(decoded_scan)
        scan_patterns(decoded_scan, strip_hidden(combined))
        for finding in decoded_scan.findings:
            scan.add(finding.rule, line, evidence=f"tool '{name}': {finding.evidence}", hidden=finding.hidden_text,
                     severity=finding.severity)
        if len(description) > 1200:
            scan.add("HB601", line, evidence=f"tool '{name}': description is {len(description)} characters")
        for key, value in properties.items():
            if key.lower() in RULES["side_channel_params"]:
                param_description = value.get("description", "") if isinstance(value, dict) else ""
                if RULES["side_channel_re"].search(description + " " + param_description):
                    scan.add("HB602", line, evidence=f"tool '{name}': parameter '{key}'", extra_key=key)
        for other in names:
            if other != name and len(other) >= 4 and re.search(r"(?<![\w-])" + re.escape(other) + r"(?![\w-])", description):
                scan.add("HB603", line, evidence=f"tool '{name}' mentions tool '{other}'", extra_key=other)


PACKAGE_RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpm", "yarn", "npm"}
SHELLS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
BROAD_ROOTS = {"c:", "~", "$home", "${home}", "%userprofile%", "/users", "/home", "c:\\users", "c:/users",
               "${userprofile}", "$env:userprofile"}


def is_broad_root(arg: str) -> bool:
    normal = arg.strip().lower()
    if normal in ("/", "c:\\", "c:/"):
        return True
    trimmed = re.sub(r"[\\/]+$", "", normal)
    return bool(trimmed) and trimmed in BROAD_ROOTS
SECRET_KEY = re.compile(r"(key|token|secret|password|passwd|pass|auth|credential|cookie)", re.I)
ENV_REFERENCE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_]+%|\{env:[^}]+\}|\$\{\{[^}]+\}\})\s*$")


def package_spec(command: str, args: list) -> Optional[str]:
    base = os.path.basename(command).lower().replace(".cmd", "").replace(".exe", "")
    if base not in PACKAGE_RUNNERS:
        return None
    rest = list(args)
    if base in ("pnpm", "yarn") and rest and rest[0] == "dlx":
        rest = rest[1:]
    elif base == "npm" and rest and rest[0] in ("exec", "x"):
        rest = rest[1:]
    elif base == "pipx" and rest and rest[0] == "run":
        rest = rest[1:]
    elif base in ("pnpm", "yarn", "npm"):
        return None
    skip_next = False
    for arg in rest:
        if skip_next:
            skip_next = False
            continue
        if arg in ("--package", "-p", "--from", "--with", "--python"):
            skip_next = True
            continue
        if arg.startswith("-") or arg == "--":
            continue
        return arg
    return None


def is_pinned(spec: str, runner: str) -> bool:
    if runner in ("uvx", "pipx"):
        return "==" in spec or spec.endswith((".whl", ".tar.gz")) or spec.startswith(("git+", "/", "."))
    if spec.startswith((".", "/", "file:", "git+", "http")):
        return True
    at = spec.rfind("@")
    if at <= 0:
        return False
    version = spec[at + 1:]
    return bool(version) and version not in ("latest", "next", "*") and not version.startswith("^") and not version.startswith("~")


def scan_config(scan: FileScan, parsed) -> None:
    servers = find_servers(parsed) or {}
    for name, server in servers.items():
        line = tool_line(scan.text, name)
        command = str(server.get("command", ""))
        args = [str(a) for a in server.get("args", []) if isinstance(a, (str, int, float))]
        base = os.path.basename(command).lower()
        runner = base.replace(".cmd", "").replace(".exe", "")
        spec = package_spec(command, args)
        if spec is not None and not is_pinned(spec, runner):
            scan.add("HB501", line, evidence=f"server '{name}': {runner} {spec}", extra_key=name)
        filesystem_like = "filesystem" in name.lower() or any("filesystem" in a.lower() for a in args)
        for arg in args:
            if is_broad_root(arg):
                severity = "high" if filesystem_like else None
                scan.add("HB502", line, evidence=f"server '{name}': gets '{arg}'", severity=severity, extra_key=name)
                break
        url = str(server.get("url") or server.get("serverUrl") or "")
        if url.lower().startswith("http://"):
            host = re.sub(r"^http://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
            if host not in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0") and not host.endswith(".localhost"):
                scan.add("HB503", line, evidence=f"server '{name}': {url}", extra_key=name)
        for block_name in ("env", "headers"):
            block = server.get(block_name)
            if not isinstance(block, dict):
                continue
            for key, value in block.items():
                value = str(value)
                if not SECRET_KEY.search(key) or not value.strip():
                    continue
                if ENV_REFERENCE.match(value) or is_placeholder(value) or len(value.strip()) < 8:
                    continue
                if value.lower().startswith("bearer ") and ENV_REFERENCE.match(value[7:]):
                    continue
                scan.add("HB504", line, evidence=f"server '{name}': {block_name}.{key} = {mask_secret(value)}",
                         extra_key=f"{name}.{key}")
        if base in SHELLS and any(a.lower() in ("-c", "/c", "-command", "/k", "-encodedcommand", "-e") for a in args):
            scan.add("HB505", line, evidence=f"server '{name}': {command} {' '.join(args)[:120]}", extra_key=name)
        if runner == "docker":
            joined = " ".join(args)
            if re.search(r"--privileged|docker\.sock|(-v|--volume)[ =]/:|--pid[ =]host|--network[ =]host", joined):
                scan.add("HB506", line, evidence=f"server '{name}': docker {joined[:120]}", extra_key=name)


def scan_code_tools(scan: FileScan, clean: str) -> None:
    """MCP servers written in code: a tool function with a 'sidenote'-style parameter."""
    if scan.kind != "code":
        return
    if not re.search(r"@\w+\.tool\b|\.tool\(|server\.setRequestHandler|registerTool\(|ListToolsRequestSchema", clean):
        return
    for match in re.finditer(r"\b(def|function|async\s+def)\s+\w+\s*\(([^)]*)\)", clean):
        params = re.findall(r"\b(sidenote|side_note)\b", match.group(2), re.I)
        if params:
            scan.add("HB602", line_of(clean, match.start()), extra_key=params[0])


def scan_text(path: str, text: str) -> tuple[str, list[Finding]]:
    """Scan one file's text. Returns (kind, findings)."""
    if text.startswith("\ufeff"):
        text = text[1:]
    kind, parsed = classify(path, text)
    scan = FileScan(path, text, kind)
    scan_hidden_chars(scan)
    clean = strip_hidden(text)
    scan_patterns(scan, clean)
    scan_folded(scan, clean)
    scan_squeezed(scan, clean)
    scan_comments(scan, clean)
    scan_base64(scan, clean)
    scan_code_tools(scan, clean)
    if kind == "tool":
        scan_tools(scan, parsed)
    elif kind == "config":
        scan_config(scan, parsed)
    return kind, scan.findings


# ---------------------------------------------------------------- skills (scope check)

FRONTMATTER = re.compile(r"\A---\s*\n([\s\S]*?)\n---\s*(\n|\Z)")


def declared_text(skill_md: str) -> str:
    match = FRONTMATTER.match(skill_md.replace("\r\n", "\n"))
    block = match.group(1) if match else skill_md[:600]
    return block.lower()


def capability_hits(text: str) -> dict:
    clean = strip_hidden(text)
    hits = {}
    for key, capability in RULES["capabilities"].items():
        for pattern in capability["compiled"]:
            match = pattern.search(clean)
            if match:
                hits[key] = line_of(clean, match.start())
                break
    return hits


def scope_findings(skill_path: str, skill_md: str, members: list[tuple[str, str]]) -> list[Finding]:
    """members: (path, text) of every file in the skill folder, including SKILL.md."""
    declared = declared_text(skill_md)
    undeclared = []
    for path, text in members:
        kind, _ = classify(path, text)
        if kind not in RULES["capability_kinds"] and path != skill_path:
            continue
        for key, line in capability_hits(text).items():
            if any(entry[0] == key for entry in undeclared):
                continue
            words = RULES["capabilities"][key]["declare"]
            if not any(word in declared for word in words):
                undeclared.append((key, path, line))
    if not undeclared:
        return []
    rule = RULES["by_id"]["HB701"]
    severity = "high" if any(key in ("credentials", "persistence") for key, _, _ in undeclared) else rule["severity"]
    parts = [f"{RULES['capabilities'][key]['label']} ({os.path.basename(path)}:{line})" for key, path, line in undeclared]
    return [Finding(
        rule="HB701", severity=severity, title=rule["title"], file=skill_path, line=1,
        evidence="description never mentions: " + "; ".join(parts),
        why=rule["why"], fix=rule["fix"], refs=list(rule.get("refs", [])),
    )]


# ---------------------------------------------------------------- walking + report

class Unreadable(Exception):
    pass


def read_text(path: Path) -> Optional[str]:
    """Returns text, None for binary files, or raises Unreadable (too big, locked, quarantined)."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise Unreadable(f"larger than {MAX_FILE_BYTES // 1_000_000} MB")
        data = path.read_bytes()
    except OSError as error:
        raise Unreadable(error.strerror or type(error).__name__) from error
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n")


def is_text_candidate(path: Path) -> bool:
    name = path.name.lower()
    ext = path.suffix.lower()
    return (ext in CODE_EXTS or ext in INSTRUCTION_EXTS or ext in OTHER_TEXT_EXTS or name in INSTRUCTION_NAMES
            or name in ("dockerfile", "makefile") or ext == "")


MINIFIED_SUFFIXES = (".min.js", ".min.mjs", ".min.css", ".js.map", ".css.map", ".bundle.js")


def is_minified_name(name: str) -> bool:
    return name.lower().endswith(MINIFIED_SUFFIXES)


def load_ignore(root: Path) -> list[str]:
    ignore_file = root / ".hexbaneignore"
    if not ignore_file.is_file():
        return []
    patterns = []
    for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def ignored(rel: str, patterns: list[str]) -> bool:
    rel = rel.replace("\\", "/")
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def collect_files(root: Path, skipped: Optional[list] = None) -> list[tuple[str, str]]:
    """Returns (relative path with / separators, text) for every scannable file under root.
    Files that exist but cannot be read are appended to skipped as {"path", "reason"}."""
    skipped = skipped if skipped is not None else []
    if root.is_file():
        candidates = [(root, root.name)]
        patterns = []
    else:
        patterns = load_ignore(root)
        candidates = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                candidates.append((path, path.relative_to(root).as_posix()))
    files = []
    for path, rel in candidates:
        if path.name == ".hexbaneignore" or ignored(rel, patterns) or not is_text_candidate(path):
            continue
        if is_minified_name(path.name):
            skipped.append({"path": rel, "reason": "minified bundle (not scanned)"})
            continue
        try:
            text = read_text(path)
        except Unreadable as reason:
            skipped.append({"path": rel, "reason": str(reason)})
            continue
        if text is not None:
            files.append((rel, text))
    return files


def scan_files(files: list[tuple[str, str]], skipped: Optional[list] = None) -> dict:
    """Scan (path, text) pairs. Same entry point as the browser's scanFiles()."""
    findings: list[Finding] = []
    file_rows = []
    for path, text in files:
        kind, file_findings = scan_text(path, text)
        findings.extend(file_findings)
        file_rows.append({"path": path, "kind": kind, "findings": len(file_findings)})
    skill_roots = sorted({p.rsplit("/", 1)[0] if "/" in p else "" for p, _ in files
                          if p.rsplit("/", 1)[-1].lower() == "skill.md"})
    for root in skill_roots:
        prefix = root + "/" if root else ""
        skill_md_path = prefix + next(p.rsplit("/", 1)[-1] for p, _ in files
                                      if p.lower() == (prefix + "skill.md").lower())
        skill_md = next(t for p, t in files if p == skill_md_path)
        nested = [r for r in skill_roots if r != root and r.startswith(prefix)]
        members = [(p, t) for p, t in files if p.startswith(prefix)
                   and not any(p.startswith(n + "/") for n in nested)]
        findings.extend(scope_findings(skill_md_path, skill_md, members))
    return build_report(findings, file_rows, skipped or [])


def build_report(findings: list[Finding], file_rows: list[dict], skipped: Optional[list] = None) -> dict:
    findings.sort(key=lambda f: (f.file, f.line, f.rule))
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    per_file = {}
    for finding in findings:
        current = per_file.get(finding.file, "info")
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[current]:
            per_file[finding.file] = finding.severity
    for row in file_rows:
        row["verdict"] = verdict_for(per_file.get(row["path"], "info"))
    worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=0)
    worst_name = next(k for k, v in SEVERITY_ORDER.items() if v == worst)
    return {
        "tool": "hexbane",
        "version": RULES["version"],
        "verdict": verdict_for(worst_name),
        "counts": counts,
        "files_scanned": len(file_rows),
        "files": file_rows,
        "skipped": skipped or [],
        "findings": [asdict(f) for f in findings],
    }


def verdict_for(severity: str) -> str:
    level = SEVERITY_ORDER.get(severity, 0)
    if level >= SEVERITY_ORDER["high"]:
        return "FAIL"
    if level >= SEVERITY_ORDER["medium"]:
        return "REVIEW"
    return "PASS"


def scan_path(path: str | Path) -> dict:
    return scan_paths([path])


def scan_paths(paths: Iterable[str | Path]) -> dict:
    roots = [Path(p) for p in paths]
    files = []
    skipped = []
    for root in roots:
        prefix = "" if len(roots) == 1 else root.name + "/"
        found_skipped = []
        files.extend((prefix + rel, text) for rel, text in collect_files(root, found_skipped))
        skipped.extend({"path": prefix + s["path"], "reason": s["reason"]} for s in found_skipped)
    return scan_files(files, skipped)
