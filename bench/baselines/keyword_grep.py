"""Naive baseline: flag a folder if any file contains one of a few well-known injection phrases.

    python bench/baselines/keyword_grep.py <folder>     # exit 1 = flagged, 0 = clean

It exists to show how an external scanner plugs into bench/run.py and to give a floor: a scanner that does
not beat plain keyword search on these cases is not adding much.
"""

import re
import sys
from pathlib import Path

PHRASES = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"do not (tell|inform|mention)[^.]{0,40}user",
    r"<important>",
    r"~/\.ssh|id_rsa",
    r"system prompt",
]
PATTERN = re.compile("|".join(PHRASES), re.IGNORECASE)


def main(folder: str) -> int:
    for path in Path(folder).rglob("*"):
        if path.is_file() and PATTERN.search(path.read_text(encoding="utf-8", errors="replace")):
            print(f"flagged: {path}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
