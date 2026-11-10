"""Copy gardu/rules.json to web/rules.json (the browser app is deployed on its own, so it needs its own copy).
The parity test fails if the two ever differ."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
source = (ROOT / "gardu" / "rules.json").read_bytes()
(ROOT / "web" / "rules.json").write_bytes(source)
print(f"web/rules.json updated ({len(source)} bytes)")
