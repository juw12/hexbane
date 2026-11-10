"""Hermetic checks for the Hexbane web app (stdlib only, no browser) - run by tests/run_all.py.

Checks what breaks a Pages deploy or the product promise:
  * every asset referenced by index.html exists and is relative (Pages serves /hexbane/)
  * scripts load in dependency order, the service worker only caches files that exist
  * the manifest is valid and its icons exist
  * user text is never inserted as HTML (XSS guard)
  * every policy template loads in the Python engine and behaves on its own samples
  * the web CAD policy matches the server policy the accuracy numbers were measured with
  * the browser rule file is identical to the Python rule file (one source of truth)
  * the old product names are gone from what users see

The browser suites (JS/Python scanner parity, UI flows, screenshots) live in ui-tests/.
"""

import json
import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
WEB = APP / "web"
SERVER = APP / "server"
sys.path.insert(0, str(SERVER))

from engine import Engine  # noqa: E402  (server engine, standard library only)

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


index_html = (WEB / "index.html").read_text(encoding="utf-8")

for ref in re.findall(r'(?:src|href)="([^"#]+)"', index_html):
    if ref.startswith(("http://", "https://")):
        continue
    check(not ref.startswith("/"), f"absolute path in index.html: {ref}")
    check((WEB / ref).is_file(), f"index.html references missing file: {ref}")

script_order = re.findall(r'<script src="([^"]+)"', index_html)
check(script_order == ["engine.js", "scan.js", "scanview.js", "store.js", "app.js"], f"unexpected script order: {script_order}")

manifest = json.loads((WEB / "manifest.webmanifest").read_text(encoding="utf-8"))
check(manifest.get("start_url") == "./", "manifest start_url must be relative ./")
for icon in manifest.get("icons", []):
    check((WEB / icon["src"]).is_file(), f"manifest icon missing: {icon['src']}")

sw_source = (WEB / "sw.js").read_text(encoding="utf-8")
shell_block = re.search(r"SHELL_FILES = \[(.*?)\];", sw_source, re.S)
check(shell_block is not None, "sw.js has no SHELL_FILES list")
if shell_block:
    for entry in re.findall(r'"([^"]+)"', shell_block.group(1)):
        if entry != "./":
            check((WEB / entry).is_file(), f"sw.js caches a missing file: {entry}")

for script in ("app.js", "engine.js", "store.js", "scan.js", "scanview.js"):
    code = re.sub(r"//.*", "", (WEB / script).read_text(encoding="utf-8"))
    dangerous = re.findall(r"\.(?:inner|outer)HTML\s*=|insertAdjacentHTML|document\.write|\beval\(", code)
    check(not dangerous, f"{script} inserts HTML or evals code: {dangerous}")

# No third-party requests: the app must work offline and send nothing anywhere.
# (Lines that build the Integrate page's code samples are display text, not requests.)
for script in ("app.js", "engine.js", "store.js", "scan.js", "scanview.js", "index.html"):
    for line in (WEB / script).read_text(encoding="utf-8").splitlines():
        if "code(`" in line:
            continue
        for url in re.findall(r"fetch\(\s*[\"'`](https?://[^\"'`]+)", line):
            check(False, f"{script} fetches a third-party URL: {url}")

templates = {}
for path in sorted((WEB / "policies").glob("*.json")):
    if path.name.endswith(".eval.json"):
        continue
    policy = json.loads(path.read_text(encoding="utf-8"))
    templates[policy["id"]] = policy
    check(path.stem == policy["id"], f"{path.name}: id {policy['id']!r} does not match file name")
    try:
        engine = Engine(policy)
    except Exception as error:  # a broken template would break the app's start-up
        check(False, f"{path.name} does not load in the engine: {error}")
        continue
    for sample in policy.get("samples", []):
        check(bool(engine.check("sample", sample).action), f"{path.name}: sample produced no action: {sample}")
    for user, messages in policy.get("demo", {}).items():
        actions = [engine.check(user, message).action for message in messages]
        # Demo personas: jailbreakers are blocked, free-ChatGPT users are stopped, genuine users are
        # served. Mixed personas (topic creep, student) are intentionally a bit of both - not asserted.
        if "jailbreak" in user:
            check(all(action == "BLOCK" for action in actions), f"{path.name}: jailbreak demo not blocked: {actions}")
        elif "free-ChatGPT" in user:
            check(all(action in ("REDIRECT", "THROTTLE") for action in actions), f"{path.name}: off-topic demo served: {actions}")
        elif any(tag in user for tag in ("real user", "customer", "shopper")):
            check(all(action in ("ALLOW", "ADJACENT") for action in actions),
                  f"{path.name}: genuine user {user!r} was stopped: {actions}")

check(set(templates) == {"cad-copilot", "bank-support", "store-support"}, f"unexpected templates: {sorted(templates)}")

server_policy = json.loads((SERVER / "policy_cad_assistant.json").read_text(encoding="utf-8"))
web_policy = templates.get("cad-copilot", {})
for key in ("mission", "examples", "core_keywords", "adjacent_keywords", "out_of_scope_keywords", "thresholds"):
    check(web_policy.get(key) == server_policy.get(key), f"cad-copilot.json differs from the server policy in {key!r}")

eval_bundle = json.loads((WEB / "policies" / "cad-copilot.eval.json").read_text(encoding="utf-8"))
for eval_set in eval_bundle["sets"]:
    on_disk = json.loads((SERVER / f"{eval_set['id']}.json").read_text(encoding="utf-8"))["cases"]
    check(eval_set["cases"] == on_disk, f"web eval set {eval_set['id']} differs from server/{eval_set['id']}.json")

sw_cached = re.findall(r'"([^"]+)"', shell_block.group(1)) if shell_block else []
for needed in ("scan.js", "scanview.js", "rules.json"):
    check(needed in sw_cached, f"sw.js does not cache {needed} (the Scan page would break offline)")

python_rules = json.loads((APP / "hexbane" / "rules.json").read_text(encoding="utf-8"))
web_rules = json.loads((WEB / "rules.json").read_text(encoding="utf-8"))
check(python_rules == web_rules, "web/rules.json differs from hexbane/rules.json - run tests/sync_rules.py")
rule_ids = [rule["id"] for rule in python_rules["rules"]]
check(len(rule_ids) == len(set(rule_ids)), "duplicate rule ids in rules.json")
# Every finding must offer a copyable fix command (the web "Copy fix command" button and the
# CLI "How to fix" section are both driven by this field); a rule without one would leave a
# finding with no concrete way to fix it.
for rule in python_rules["rules"]:
    snippet = rule.get("snippet")
    check(isinstance(snippet, str) and snippet.strip(), f"rule {rule['id']} has no fix command (snippet) - every finding must offer one")

visible_html = re.sub(r"<script.*?</script>", "", index_html, flags=re.S)
for old_name in ("Steward", "ScopeGuard"):
    check(old_name not in visible_html, f"index.html still shows the old name {old_name!r}")
check("<title>Hexbane" in index_html, "index.html title is not Hexbane")

if failures:
    print("FAILED")
    for failure in failures:
        print(" -", failure)
    sys.exit(1)

print(f"OK - web app checks passed ({len(rule_ids)} rules, {len(templates)} chat-gate templates)")