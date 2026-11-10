"""
Hexbane server - one drop-in guard for an AI assistant and its tools. Standard library only.

    python server.py --policy policy_cad_assistant.json --port 8787      (or: python -m hexbane serve)

Three gates in one process:
    chat gate   POST /v1/check, /v1/chat/completions  keeps users on the assistant's mission (ex-ScopeGuard)
    load gate   POST /v1/scan                         scans skills / MCP configs / tool manifests before use
    call gate   POST /v1/tool-call, /v1/tool-output   checks each tool call and tool result at run time;
                the chat proxy applies it automatically to tool calls and tool results it relays

Environment (all optional; the old SCOPEGUARD_* names still work):
    HEXBANE_API_KEY       bearer key required on /v1/*  (your app -> Hexbane)
    HEXBANE_ADMIN_KEY     bearer key required on /api/* (dashboard; open it as /#key=...)
    HEXBANE_UPSTREAM      OpenAI-compatible base URL, e.g. https://api.openai.com/v1
    HEXBANE_UPSTREAM_KEY  key for the upstream LLM
    HEXBANE_JUDGE_MODEL   model name -> enables the LLM judge for low-confidence messages
"""

import argparse
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from engine import LABELS, Engine, load_policy, make_openai_judge, open_url
from store import Store

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from hexbane.scanner import scan_files  # noqa: E402  (package lives next to server/)
from hexbane.toolgate import check_call, check_output, load_policy as load_tool_policy, quarantine_notice  # noqa: E402

MAX_BODY_BYTES = 64 * 1024
MAX_SCAN_BYTES = 4 * 1024 * 1024


def env_value(env: dict, name: str) -> str:
    """HEXBANE_<name>, falling back to the old SCOPEGUARD_<name> so existing setups keep working."""
    return env.get("HEXBANE_" + name) or env.get("SCOPEGUARD_" + name, "")


class HexbaneApp:
    def __init__(self, policy_path: Path, db_path: Path, env: dict | None = None, tool_policy_path: Path | None = None):
        env = dict(os.environ if env is None else env)
        self.api_key = env_value(env, "API_KEY")
        self.admin_key = env_value(env, "ADMIN_KEY")
        self.upstream = env_value(env, "UPSTREAM").rstrip("/")
        self.upstream_key = env_value(env, "UPSTREAM_KEY")
        judge = None
        judge_model = env_value(env, "JUDGE_MODEL")
        if self.upstream and judge_model:
            judge = make_openai_judge(self.upstream, self.upstream_key, judge_model)
        self.tool_policy = load_tool_policy(tool_policy_path)
        self.store = Store(db_path)
        self.engine = Engine(load_policy(policy_path), self.store.learned_examples(), llm_judge=judge)
        self.dashboard_html = (HERE / "dashboard.html").read_bytes()

    def guard(self, user: str, message: str) -> tuple[int, object]:
        decision = self.engine.check(user, message)
        event_id = self.store.log(user, message, decision)
        return event_id, decision

    def feedback(self, event_id: int, label: str) -> None:
        self.store.add_feedback(event_id, label)
        self.engine.rebuild(self.store.learned_examples())

    def gate_tool_results(self, messages: list) -> list[dict]:
        """Call gate, inbound: replace tool results that carry injected instructions before the model reads them."""
        actions = []
        for message in messages:
            if not isinstance(message, dict) or message.get("role") != "tool":
                continue
            content = message.get("content", "")
            text = content if isinstance(content, str) else json.dumps(content)
            result = check_output(self.tool_policy, text)
            if result["decision"] == "quarantine":
                message["content"] = quarantine_notice(result)
                actions.append({"tool_call_id": message.get("tool_call_id"), "decision": "quarantine",
                                "rules": sorted({f["rule"] for f in result["findings"]})})
        return actions

    def gate_tool_calls(self, payload: dict) -> list[dict]:
        """Call gate, outbound: check tool calls the model asks for; drop denied ones before the app runs them."""
        decisions = []
        for choice in payload.get("choices", []) if isinstance(payload, dict) else []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict) or not isinstance(message.get("tool_calls"), list):
                continue
            kept = []
            for call in message["tool_calls"]:
                function = call.get("function", {}) if isinstance(call, dict) else {}
                raw_args = function.get("arguments", "{}")
                try:
                    arguments = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except ValueError:
                    arguments = raw_args
                result = check_call(self.tool_policy, str(function.get("name", "")), arguments)
                result["id"] = call.get("id") if isinstance(call, dict) else None
                decisions.append(result)
                if result["decision"] != "deny":
                    kept.append(call)
            if len(kept) != len(message["tool_calls"]):
                message["tool_calls"] = kept or None
                if not kept:
                    message.pop("tool_calls")
                    choice["finish_reason"] = "stop"
                    blocked = [d for d in decisions if d["decision"] == "deny"]
                    message["content"] = (message.get("content") or "") + (
                        "\n[Hexbane blocked a tool call: " + "; ".join(r["detail"] for d in blocked for r in d["reasons"][:1]) + "]")
        return decisions


ScopeGuardApp = HexbaneApp  # old name, kept for existing integrations


def decision_payload(event_id: int, decision) -> dict:
    return {
        "event_id": event_id,
        "action": decision.action,
        "allowed": decision.action in ("ALLOW", "ADJACENT"),
        "label": decision.label,
        "uncertain": decision.uncertain,
        "reason": decision.reason,
        "scores": decision.scores,
        "reply": decision.reply,
    }


def last_user_text(messages: list) -> str:
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content", "")
            if isinstance(content, list):
                return " ".join(part.get("text", "") for part in content if isinstance(part, dict))
            return str(content)
    return ""


def completion_response(model: str, text: str, guard_info: dict) -> dict:
    return {
        "id": "chatcmpl-sg-" + uuid.uuid4().hex[:12],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "hexbane": guard_info,
        "scopeguard": guard_info,
    }


def make_handler(app: HexbaneApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Hexbane/0.1"

        def log_message(self, format, *args):
            pass

        # ---------- helpers ----------

        def send_json(self, status: int, payload: dict, headers: dict | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def read_json(self, limit: int = MAX_BODY_BYTES) -> dict | None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > limit:
                self.send_json(413, {"error": "request body too large"})
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self.send_json(400, {"error": "invalid JSON"})
                return None
            if not isinstance(data, dict):
                self.send_json(400, {"error": "JSON object expected"})
                return None
            return data

        def authorized(self, required_key: str) -> bool:
            if not required_key:
                return True
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if hmac.compare_digest(supplied.encode(), required_key.encode()):
                return True
            self.send_json(401, {"error": "missing or invalid bearer key"})
            return False

        # ---------- routes ----------

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/dashboard"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
                self.send_header("Content-Length", str(len(app.dashboard_html)))
                self.end_headers()
                self.wfile.write(app.dashboard_html)
            elif path == "/health":
                self.send_json(200, {"ok": True, "examples": app.engine.example_count})
            elif path == "/api/stats":
                if self.authorized(app.admin_key):
                    self.send_json(200, app.store.stats(app.engine))
            elif path == "/api/policy":
                if self.authorized(app.admin_key):
                    self.send_json(200, app.engine.policy)
            else:
                self.send_json(404, {"error": "not found"})

        def do_POST(self):
            path = self.path.split("?")[0]
            if path == "/v1/check":
                self.handle_check()
            elif path == "/v1/chat/completions":
                self.handle_chat()
            elif path == "/v1/scan":
                self.handle_scan()
            elif path == "/v1/tool-call":
                self.handle_tool_call()
            elif path == "/v1/tool-output":
                self.handle_tool_output()
            elif path == "/api/classify":
                self.handle_classify()
            elif path == "/api/feedback":
                self.handle_feedback()
            else:
                self.send_json(404, {"error": "not found"})

        def handle_check(self):
            if not self.authorized(app.api_key):
                return
            data = self.read_json()
            if data is None:
                return
            message = data.get("message")
            if not isinstance(message, str) or not message.strip():
                self.send_json(400, {"error": "'message' (non-empty string) is required"})
                return
            user = str(data.get("user") or "anonymous")[:200]
            event_id, decision = app.guard(user, message)
            self.send_json(200, decision_payload(event_id, decision))

        def handle_chat(self):
            if not self.authorized(app.api_key):
                return
            data = self.read_json()
            if data is None:
                return
            if data.get("stream"):
                self.send_json(400, {"error": "streaming is not supported by Hexbane yet; send stream=false"})
                return
            messages = data.get("messages")
            if not isinstance(messages, list) or not messages:
                self.send_json(400, {"error": "'messages' list is required"})
                return
            user = str(data.get("user") or self.headers.get("X-User-Id") or "anonymous")[:200]
            event_id, decision = app.guard(user, last_user_text(messages))
            info = decision_payload(event_id, decision)
            info["tool_results"] = app.gate_tool_results(messages)
            headers = {"X-Hexbane-Action": decision.action, "X-ScopeGuard-Action": decision.action}
            model = str(data.get("model", "hexbane"))

            if not info["allowed"]:
                self.send_json(200, completion_response(model, decision.reply, info), headers)
                return

            if decision.action == "ADJACENT":
                data["messages"] = [{"role": "system", "content": decision.reply}] + messages

            if not app.upstream:
                mock = f"[mock LLM - set HEXBANE_UPSTREAM to forward] Would answer: {last_user_text(messages)[:200]}"
                self.send_json(200, completion_response(model, mock, info), headers)
                return

            request = urllib.request.Request(
                app.upstream + "/chat/completions",
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {app.upstream_key}"},
            )
            try:
                with open_url(request, 120) as response:
                    upstream_payload = json.loads(response.read())
            except urllib.error.HTTPError as error:
                self.send_json(502, {"error": f"upstream HTTP {error.code}", "hexbane": info}, headers)
                return
            except Exception as error:
                self.send_json(502, {"error": f"upstream unreachable: {error}", "hexbane": info}, headers)
                return
            info["tool_calls"] = app.gate_tool_calls(upstream_payload)
            upstream_payload["hexbane"] = info
            upstream_payload["scopeguard"] = info
            self.send_json(200, upstream_payload, headers)

        def handle_scan(self):
            """Load gate: scan files (skills, MCP configs, tool manifests, scripts) sent as {files: [{path, content}]}."""
            if not self.authorized(app.api_key):
                return
            data = self.read_json(MAX_SCAN_BYTES)
            if data is None:
                return
            files = data.get("files")
            if not isinstance(files, list) or not files:
                self.send_json(400, {"error": "'files' list of {path, content} is required"})
                return
            pairs = []
            for item in files:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
                    self.send_json(400, {"error": "each file needs string 'path' and 'content'"})
                    return
                pairs.append((item["path"].replace("\\", "/"), item["content"].replace("\r\n", "\n")))
            self.send_json(200, scan_files(pairs))

        def handle_tool_call(self):
            """Call gate: decide allow / ask / deny for one tool call."""
            if not self.authorized(app.api_key):
                return
            data = self.read_json()
            if data is None:
                return
            tool = data.get("tool")
            if not isinstance(tool, str) or not tool:
                self.send_json(400, {"error": "'tool' (string) is required"})
                return
            self.send_json(200, check_call(app.tool_policy, tool, data.get("arguments", {})))

        def handle_tool_output(self):
            """Call gate: check a tool result for injected instructions before the model reads it."""
            if not self.authorized(app.api_key):
                return
            data = self.read_json(MAX_SCAN_BYTES)
            if data is None:
                return
            content = data.get("content")
            if not isinstance(content, str):
                self.send_json(400, {"error": "'content' (string) is required"})
                return
            result = check_output(app.tool_policy, content, source=str(data.get("source") or "tool-output.md"))
            if result["decision"] == "quarantine":
                result["notice"] = quarantine_notice(result)
            self.send_json(200, result)

        def handle_classify(self):
            """Playground: classify without logging or touching user sessions."""
            if not self.authorized(app.admin_key):
                return
            data = self.read_json()
            if data is None:
                return
            message = str(data.get("message", ""))
            if app.engine.is_abuse(message):
                self.send_json(200, {"label": "abuse", "action": "BLOCK", "scores": {}, "uncertain": False,
                                     "reason": "jailbreak / prompt-injection pattern"})
                return
            result = app.engine.classify(message)
            action = {"in_scope": "ALLOW", "adjacent": "ADJACENT", "out_of_scope": "REDIRECT"}[result.label]
            self.send_json(200, {"label": result.label, "action": action, "scores": result.scores,
                                 "uncertain": result.uncertain, "reason": result.reason,
                                 "nearest_example": result.nearest_example})

        def handle_feedback(self):
            if not self.authorized(app.admin_key):
                return
            data = self.read_json()
            if data is None:
                return
            label = data.get("label")
            if label not in LABELS:
                self.send_json(400, {"error": f"'label' must be one of {list(LABELS)}"})
                return
            try:
                app.feedback(int(data.get("event_id")), label)
            except (KeyError, TypeError, ValueError):
                self.send_json(404, {"error": "unknown event_id"})
                return
            self.send_json(200, {"ok": True, "learned_examples": len(app.store.learned_examples())})

    return Handler


def create_server(app: HexbaneApp, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(app))


def main():
    parser = argparse.ArgumentParser(description="Hexbane - guard an AI assistant and its tools")
    parser.add_argument("--policy", default=str(HERE / "policy_cad_assistant.json"), help="chat-gate mission policy")
    parser.add_argument("--tool-policy", default=None, help="call-gate policy (default: hexbane/policy_default.json)")
    parser.add_argument("--db", default=str(HERE / "hexbane.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    app = HexbaneApp(Path(args.policy), Path(args.db), tool_policy_path=Path(args.tool_policy) if args.tool_policy else None)
    server = create_server(app, args.host, args.port)
    print(f"Hexbane running: http://{args.host}:{args.port}/  (mission policy: {app.engine.policy['name']})")
    print("  chat gate: POST /v1/check, /v1/chat/completions | load gate: POST /v1/scan | "
          "call gate: POST /v1/tool-call, /v1/tool-output | dashboard at /")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.store.close()


if __name__ == "__main__":
    main()
