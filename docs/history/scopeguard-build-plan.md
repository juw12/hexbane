> Historical: planning notes from ScopeGuard, the project that became Gardu's chat gate.

# ScopeGuard v0.2 — Build plan

## Goal for this round
1. A smarter relevance engine that fixes the "steel stocks" false pass.
2. A drop-in server any app can connect to.
3. A web dashboard for analytics, a review queue and a playground.
4. A feedback loop: admin labels from the dashboard teach the classifier.

## Constraints
- Must run anywhere with **only the Python standard library** (3.10+): no pip install and no model downloads.
- Optional plug-ins, if the business has them: an external embedding API and an LLM judge (via environment variables).
- Bind to localhost by default; an API key is optional.

## Architecture
```
app / chatbot ──► ScopeGuard server ──► (optional) upstream LLM (OpenAI-compatible)
                    │  engine.py   classify + decide
                    │  store.py    SQLite log, feedback, learned examples
                    └─ dashboard.html (served at /)
```

### engine.py — relevance classifier (local, dependency-free)
- Policy JSON holds the mission, **labelled example sentences** for each class
  (in_scope / adjacent / out_of_scope), keywords, budgets and prices.
- Features: TF-IDF over word unigrams + bigrams + character 4-grams
  (handles plurals and typos, e.g. "stocks" vs "stock").
- Score for each class = mean of the top-3 cosine similarities to that class's examples (kNN).
- A small keyword boost for core terms, capped so a single word like "steel" cannot win alone.
- Uncertainty: if the best score is below `min_confidence`, call the LLM judge (if configured).
  Otherwise treat the message as off-mission but mark it as `uncertain`, so it shows up in the review queue.
- Abuse/jailbreak regex layer stays first. Session drift and off-topic allowance stay as before.
- Learned examples (from admin labels) are merged in and the vectorizer is refitted, with no restart needed.

### store.py — SQLite
- `events`: id, ts, user, message, action, label, scores, reason, uncertain, est_tokens, est_cost_saved.
- `feedback`: event_id, correct_label → also becomes a learned example.
- Thread-safe (one lock, `check_same_thread=False`).

### server.py — stdlib ThreadingHTTPServer
| Method | Path | Purpose |
|---|---|---|
| POST | /v1/check | `{user, message}` → decision JSON |
| POST | /v1/chat/completions | OpenAI-compatible proxy: guard the last user msg; forward if allowed (adjacent → inject steering system msg); otherwise return the redirect as a normal assistant message |
| POST | /api/feedback | `{event_id, label}`: admin correction |
| GET | /api/stats | KPIs, action counts, demand clusters, flagged users, review queue, recent events |
| GET | /api/policy | current policy (read-only) |
| GET | / | dashboard |
- Mock upstream when `SCOPEGUARD_UPSTREAM` is not set, so the demo works offline.
- Body size limit (64 KB), JSON validation, optional `SCOPEGUARD_API_KEY` bearer check on /v1/*.

### dashboard.html — single file, no CDN
- KPI cards: total messages, % off-mission, estimated $ saved, flagged users.
- Action breakdown bars, unmet-demand clusters, flagged users.
- Review queue for uncertain/redirected items, with buttons: In scope / Adjacent / Off-topic.
- Recent events table and a playground box to test a message live. Auto-refresh every 5 s.
- **All user text inserted via `textContent`**, never innerHTML (logged messages are untrusted → XSS).

### Demand clustering
- Greedy clustering of off-mission messages by TF-IDF cosine (threshold ~0.25).
- Each cluster is labelled with its top terms and a sample message.

## Verification plan
1. **Accuracy test** on a held-out labelled set (messages NOT in the policy examples), covering
   in-scope, adjacent, off-topic and tricky cases ("steel stocks", "print my essay", "bolt for a door"?).
   Report the confusion matrix. Target ≥ 85 %, with "steel stocks" → off-mission.
2. Unit checks: jailbreak → BLOCK, allowance → THROTTLE after N, drift → REDIRECT.
3. Server integration test: start on a free port, call every endpoint, run the proxy in mock mode,
   check that feedback changes a later classification, and check that the API key is enforced when set.
4. XSS check: log `<img src=x onerror=alert(1)>`, then confirm the dashboard renders it as text.
5. Headless Edge screenshot of the dashboard to inspect it visually.
6. Clean up: stop the server and delete test databases.

## Self-review of this plan (double-check)
- ❗ Risk: testing on the same sentences used as examples inflates accuracy → use a separate held-out set. ✔ planned.
- ❗ Risk: "uncertain → off-mission" may annoy real users with unusual phrasing → mitigated by the
  keyword boost, a soft redirect that still counts against the allowance, and the review queue for fixing it. Tradeoff to state in the summary.
- ❗ Risk: the proxy breaks streaming clients → v0.2 supports non-streaming only; returns 400 with a clear message if `stream:true`. State it.
- ❗ Risk: SQLite under concurrent requests → single lock. Fine for a prototype, not for high scale.
- ❗ Cost estimate is approximate: \(\text{tokens} \approx \text{chars}/4\), using a configurable $/1k tokens and an assumed average reply length. Label it as an estimate.
- ❗ Output-side checking (was the LLM *answer* on-mission?) is out of scope this round → list as next.
- ✔ Old `scopeguard.py`/`demo.py` kept working? → replace with new modules; update demo.py to use the engine.

## Outcome vs plan (after build)
- Done: engine, store, server, dashboard, feedback loop, 18 tests. The suite runs in about 1 s.
- Accuracy target (85% held-out): met on the final untouched set (85% served-vs-stopped), 89% on the blind set.
  The tuned set's 100% is optimistic and not claimed.
- Changes found during verification:
  - Added a benefit-of-the-doubt rule, after the blind set showed real users being redirected.
  - Fixed a system-proxy bug: loopback LLMs were being routed through the corporate proxy.
  - Made the XSS test precise. The browser-rendered DOM confirmed injected HTML shows as text.
  - Switched demand clustering to word features, after the dashboard showed every theme as 1x.
  - Fixed the stemmer ("calculus" had become "calculu").
- Deferred: the external embedding backend, output-side checking, streaming, and persistent sessions.
