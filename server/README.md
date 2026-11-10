# Hexbane server - load gate, call gate and chat gate

A drop-in guard between your app and any LLM. It allows on-mission requests, briefly answers
related ones and steers them back, redirects or throttles off-topic use, and blocks jailbreaks.
It also shows the business what users actually want.
Pure Python standard library (3.10+). No installs, no model downloads.

Run it from the repository root with `python -m hexbane serve`, or from this folder with `python server.py`.

## Load gate and call gate
```
POST /v1/scan          {"files": [{"path": "SKILL.md", "content": "..."}]}      -> {"verdict": "PASS|REVIEW|FAIL", "findings": [...]}
POST /v1/tool-call     {"tool": "shell", "arguments": {"command": "..."}}        -> {"decision": "allow|ask|deny", "reasons": [...]}
POST /v1/tool-output   {"source": "web_fetch", "content": "..."}                 -> {"decision": "pass|quarantine", "findings": [...]}
```
The call-gate policy is `hexbane/policy_default.json` (change it with `--tool-policy`). In proxy mode, tool calls the
policy denies are removed from the model's reply and tool results with injected instructions are replaced by a
quarantine notice before they reach the model.

## Chat gate: quick start
```
python demo.py        # sends sample traffic, then serves the dashboard at http://127.0.0.1:8787/
python server.py      # real server (policy_cad_assistant.json, hexbane.db)
python tests.py       # 25 tests (chat, load and call gates) + accuracy report
```

## Integrate (pick one)
**1. Check endpoint:** call it before your own LLM call.
```
POST /v1/check   {"user": "alice", "message": "add a fillet"}
-> {"action": "ALLOW|ADJACENT|REDIRECT|THROTTLE|BLOCK", "allowed": true, "reply": "...", ...}
```
If `allowed` is false, show `reply` to the user. For ADJACENT, add `reply` as a system hint.

**2. OpenAI-compatible proxy:** change only the base URL in your existing client.
```
POST /v1/chat/completions   (non-streaming)
```
Allowed requests are forwarded to `HEXBANE_UPSTREAM`. ADJACENT requests get a steering system message.
Off-mission requests get the redirect text as a normal assistant reply, and the LLM is never called.
The header `X-Hexbane-Action` reports the decision.

## Configuration (environment variables; the old `SCOPEGUARD_*` names still work)
| Variable | Purpose |
|---|---|
| `HEXBANE_API_KEY` | bearer key your app must send to `/v1/*` |
| `HEXBANE_ADMIN_KEY` | bearer key for the dashboard/admin API; open the dashboard as `/#key=...` |
| `HEXBANE_UPSTREAM` | OpenAI-compatible base URL (e.g. `https://api.openai.com/v1`, or a local `http://127.0.0.1:11434/v1`) |
| `HEXBANE_UPSTREAM_KEY` | upstream LLM key |
| `HEXBANE_JUDGE_MODEL` | enables an LLM judge for low-confidence messages (recommended) |

## Adapting to your business
Copy `policy_cad_assistant.json` and edit the following:
- the mission
- about 20â€“30 example messages for each class (in-scope / adjacent / off-topic)
- the keywords
- the redirect text
- the budgets and the price per 1k tokens

Corrections made in the dashboard's review queue become training examples immediately.

## Measured accuracy (CAD policy, local classifier only, no LLM judge)
| Set | Purpose | Served vs stopped | Real users wrongly redirected | Off-topic let through* |
|---|---|---|---|---|
| eval_set.json | used for tuning (optimistic) | 100% | 0/23 | 0/15 |
| eval_set_blind.json | written after tuning v1 | 89% | 0/16 | 3/12 |
| eval_set_final.json | never tuned against | 85% | 1/11 | 2/9 |

\*Let-through items still get a "steer back" hint and are flagged in the review queue.

## Known limits (v0.2)
- Keyword/TF-IDF matching doesn't understand meaning. The LLM judge, or a future embedding backend, is the fix.
- Streaming (`stream: true`) is not supported yet.
- SQLite with a single lock is fine for a prototype, not for high traffic.
- Sessions live in memory, so off-topic allowances reset on restart.
- Cost saved is an estimate (\(\text{tokens} \approx \text{chars}/4\) plus an assumed average reply length).
- The answer side is not checked yet. Only incoming messages are guarded.
