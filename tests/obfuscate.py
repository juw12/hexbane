"""Build corpus/obfuscated.json: the malicious tuning samples rewritten with common evasion tricks.

    python tests/obfuscate.py          # regenerate corpus/obfuscated.json (deterministic)

Each trick is applied only to word tokens inside text that a Hexbane rule matched in the original sample
(URLs, paths and file names are left alone), so the attack still reads the same to a language model but no
longer matches a plain regex. The set measures how well Hexbane survives these specific tricks. It was
written by the same people who wrote the normaliser, so it is not a test against unknown evasions.

Tricks:
  homoglyph   Latin letters swapped for look-alike Cyrillic letters (a -> U+0430, e -> U+0435, ...)
  fullwidth   ASCII letters swapped for fullwidth forms (U+FF21...)
  spaced      letters one space apart, words further apart: "i g n o r e   a l l"
  spaced-uniform  every gap one space: "i g n o r e a l l" (word boundaries lost; known gap)
  markdown    emphasis markers inside words: "ig**no**re"
  entities    HTML numeric entities: "&#105;&#103;..."
  linebreak   words split across lines with mixed case
  shellquote  empty quotes inside shell command words: cu''rl ... | ba''sh
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TARGET_RULES = {"HB201", "HB202", "HB203", "HB204", "HB205", "HB206", "HB301", "HB401", "HB403", "HB404", "HB405"}
CODE_SUFFIXES = (".sh", ".ps1", ".py", ".js", ".ts", ".bash")
SHELL_SUFFIXES = (".sh", ".bash")

HOMOGLYPHS = {
    "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440", "c": "\u0441", "x": "\u0445", "i": "\u0456",
    "y": "\u0443", "A": "\u0410", "E": "\u0415", "O": "\u041e", "P": "\u0420", "C": "\u0421", "X": "\u0425",
    "I": "\u0406", "T": "\u0422", "H": "\u041d", "K": "\u041a", "M": "\u041c", "B": "\u0412",
}
WORD = re.compile(r"[A-Za-z]{2,}")


def homoglyph(word: str, _index: int) -> str:
    return "".join(HOMOGLYPHS.get(char, char) for char in word)


def fullwidth(word: str, _index: int) -> str:
    return "".join(chr(ord(char) + 0xFEE0) for char in word)


def spaced(word: str, _index: int) -> str:
    """Readable form: letters one space apart, words three spaces apart (see WIDE_GAP)."""
    return " ".join(word)


def spaced_uniform(word: str, _index: int) -> str:
    """Every gap is one space, so word boundaries are lost (a known gap, reported separately)."""
    return " ".join(word)


def markdown(word: str, _index: int) -> str:
    if len(word) < 4:
        return word
    middle = len(word) // 2
    return word[:2] + "**" + word[2:middle + 1] + "**" + word[middle + 1:]


def entities(word: str, _index: int) -> str:
    return "".join(f"&#{ord(char)};" for char in word)


def linebreak(word: str, index: int) -> str:
    mixed = "".join(char.upper() if position % 2 else char.lower() for position, char in enumerate(word))
    return ("\n" if index % 2 else "") + mixed


def shellquote(word: str, _index: int) -> str:
    if len(word) < 2:
        return word
    return word[:1] + "''" + word[1:]


TRICKS = {
    "homoglyph": (homoglyph, lambda name: True),
    "fullwidth": (fullwidth, lambda name: True),
    "spaced": (spaced, lambda name: not name.endswith(CODE_SUFFIXES)),
    "spaced-uniform": (spaced_uniform, lambda name: not name.endswith(CODE_SUFFIXES)),
    "markdown": (markdown, lambda name: not name.endswith(CODE_SUFFIXES)),
    "entities": (entities, lambda name: not name.endswith(CODE_SUFFIXES)),
    "linebreak": (linebreak, lambda name: not name.endswith(CODE_SUFFIXES)),
    "shellquote": (shellquote, lambda name: name.endswith(SHELL_SUFFIXES)),
}


WIDE_GAP = {spaced}


def target_spans(text: str, rules: list[dict]) -> list[tuple[int, int]]:
    spans = []
    for rule in rules:
        if rule["id"] not in TARGET_RULES:
            continue
        for pattern in rule.get("patterns", []):
            for match in re.finditer(pattern, text, re.IGNORECASE):
                spans.append((match.start(), match.end()))
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def is_locator(text: str, start: int, end: int) -> bool:
    """True for tokens that are part of a URL, path, flag or file name, which an attacker cannot disguise."""
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return before in "/.:-_~$\\@=" or after in "/.:_\\@"


def rewrite(text: str, spans: list[tuple[int, int]], trick) -> str:
    pieces = []
    cursor = 0
    counter = 0
    for span_start, span_end in spans:
        pieces.append(text[cursor:span_start])
        segment = text[span_start:span_end]
        out = []
        last = 0
        for match in WORD.finditer(segment):
            absolute_start = span_start + match.start()
            absolute_end = span_start + match.end()
            separator = segment[last:match.start()]
            if trick in WIDE_GAP and separator == " " and out:
                separator = "   "
            out.append(separator)
            if is_locator(text, absolute_start, absolute_end):
                out.append(match.group())
            else:
                out.append(trick(match.group(), counter))
                counter += 1
            last = match.end()
        out.append(segment[last:])
        pieces.append("".join(out))
        cursor = span_end
    pieces.append(text[cursor:])
    return "".join(pieces)


def build() -> dict:
    rules = json.loads((ROOT / "hexbane" / "rules.json").read_text(encoding="utf-8"))["rules"]
    tuning = json.loads((ROOT / "corpus" / "tuning.json").read_text(encoding="utf-8"))
    samples = []
    for sample in tuning["samples"]:
        if sample["set"] != "malicious":
            continue
        files = {name: base64.b64decode(data).decode("utf-8") for name, data in sample["files"].items()}
        spans = {name: target_spans(text, rules) for name, text in files.items()}
        if not any(spans.values()):
            continue
        for trick_name, (trick, applies) in TRICKS.items():
            touched = [name for name in files if spans[name] and applies(name)]
            if not touched:
                continue
            new_files = {}
            for name, text in files.items():
                new_text = rewrite(text, spans[name], trick) if name in touched else text
                new_files[name] = base64.b64encode(new_text.encode("utf-8")).decode("ascii")
            samples.append({
                "id": f"{sample['id']}~{trick_name}",
                "set": "malicious",
                "expected": sample["expected"],
                "trick": trick_name,
                "source": sample["id"],
                "files": new_files,
            })
    return {
        "description": "Malicious tuning samples rewritten with seven evasion tricks by tests/obfuscate.py. "
                       "Generated, deterministic; written by the Hexbane authors.",
        "samples": samples,
    }


def main() -> int:
    data = build()
    target = ROOT / "corpus" / "obfuscated.json"
    target.write_text(json.dumps(data, indent=1, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    tricks = {}
    for sample in data["samples"]:
        tricks[sample["trick"]] = tricks.get(sample["trick"], 0) + 1
    print(f"wrote {target.relative_to(ROOT)}: {len(data['samples'])} samples {tricks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
