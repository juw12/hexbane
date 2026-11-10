"""Safe automatic fixes and copy-paste helpers.

Only one fix is applied automatically: deleting characters a human cannot see (zero-width characters, bidi
controls and Unicode tag characters). Removing them never changes what a reader sees, so it cannot break a
skill. Everything else is printed as a suggestion for a human to apply.
"""

from __future__ import annotations

from pathlib import Path

from .scanner import BIDI, INVISIBLE, RULES, collect_files, is_tag_char, legit_joiner

HASH_COMMENT = (".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".rb", ".pl", ".yaml", ".yml", ".toml", ".ini",
                ".cfg", ".conf", ".env", ".cursorrules", ".windsurfrules", ".clinerules", ".rules")
SLASH_COMMENT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
                 ".php", ".jsonc")
HTML_COMMENT = (".md", ".mdc", ".markdown", ".html", ".htm", ".xml", ".txt", ".rst")


def strip_invisible(text: str) -> tuple[str, int]:
    """Remove zero-width, bidi and tag characters. Keeps a leading BOM and joiners inside emoji or joining
    scripts. Returns the new text and how many characters were removed."""
    out = []
    removed = 0
    for index, char in enumerate(text):
        code = ord(char)
        if index == 0 and code == 0xFEFF:
            out.append(char)
            continue
        if is_tag_char(code) or code in BIDI or (code in INVISIBLE and not legit_joiner(text, index)):
            removed += 1
            continue
        out.append(char)
    return "".join(out), removed


def fix_path(path: str | Path, write: bool = False) -> list[dict]:
    """Strip invisible characters from every text file under path. Dry run unless write is True."""
    root = Path(path)
    results = []
    for rel, text in collect_files(root):
        fixed, removed = strip_invisible(text)
        if not removed:
            continue
        target = root / rel if root.is_dir() else root
        if write:
            target.write_bytes(fixed.encode("utf-8"))
        results.append({"file": rel, "removed": removed, "written": write})
    return results


def snippet_for(finding: dict) -> str | None:
    """A copy-paste fix for a finding, or None when the fix is 'read it and delete it'."""
    template = RULES["by_id"].get(finding["rule"], {}).get("snippet")
    if not template:
        return None
    return template.replace("{file}", finding["file"]).replace("{line}", str(finding["line"]))


def suppression_for(finding: dict) -> str:
    """The comment that marks one finding as a reviewed false alarm, in the file's own comment syntax.
    Files without comments (JSON) go in .hexbaneignore instead."""
    name = finding["file"].lower()
    marker = f"hexbane-ignore-next-line: {finding['rule']} (reviewed: why this is safe)"
    if name.endswith(HTML_COMMENT):
        return f"<!-- {marker} -->"
    if name.endswith(SLASH_COMMENT):
        return f"// {marker}"
    if name.endswith(HASH_COMMENT):
        return f"# {marker}"
    return f"# add to .hexbaneignore (this file type has no comments):\n{finding['file']}"
