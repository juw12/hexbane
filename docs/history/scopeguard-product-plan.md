> Historical: planning notes from ScopeGuard, the project that became Gardu's chat gate.

# ScopeGuard — Keep business AI on-mission

## The problem
Companies put AI assistants into their products (support bots, CAD copilots, banking apps, HR portals)
to do one job. Users treat them as a free general-purpose ChatGPT: essays, homework, code, jailbreaks.
- The company pays for the extra tokens and compute.
- Brand risk: the bot says off-brand or unsafe things under the company's logo.
- Legal and compliance risk: a bank bot giving medical advice, for example.
- Capacity is wasted that real customers need.
- Blunt blocking frustrates real users, because many "off-topic" questions are actually adjacent.

## The product
A drop-in "AI firewall for purpose". It sits between any app and any LLM, enforces the business mission,
and turns misuse into insight.

### 1. Mission Policy Studio (no-code)
- The business describes its assistant in plain language ("We help users model CAD parts").
- The studio auto-generates the scope: core topics, adjacent topics, forbidden topics, and tone.
- Test it in a playground against an attack library (essay requests, jailbreaks, topic creep).
- Policies are versioned, with A/B testing of strictness.

### 2. Runtime Gateway (the engine; prototype in `scopeguard.py`)
- OpenAI/Anthropic-compatible proxy: change one URL and you're protected. SDKs for JS, Python, and mobile.
- Layered checks, cheapest first:
  1. Abuse/jailbreak/prompt-injection patterns
  2. Embedding similarity to the mission (~5 ms)
  3. Small fast LLM judge only for grey-zone messages
  4. Conversation-level drift detection (slow topic creep)
  5. Output check: was the *answer* on-mission? (catches what got past the input filter)
- Graduated actions: ALLOW → ADJACENT (answer briefly, steer back) → REDIRECT (polite, suggest real
  features) → THROTTLE → BLOCK. Never a dead-end "I can't help".
- Per-user and per-tier budgets: off-mission allowance, token caps, rate limits.
- Tool/agent guard: an agent may only call tools that match the mission
  (e.g. no shell access for a CAD copilot unless the task needs it).

### 3. Insight Dashboard
- Cost leakage: "$4,210 this month went to off-mission requests".
- Unmet demand: clusters of what users keep asking for → new features, upsells, or partner referrals.
- Abuse leaderboard: accounts, IPs, and API keys that repeatedly misuse the assistant.
- Quality: false-block rate from user "this was relevant" feedback, used to tune automatically.

### 4. Monetize instead of block (optional)
- "Unlock general assistant mode" as a paid add-on.
- Route off-mission requests to a cheaper model instead of the expensive one.
- Affiliate redirect: "For essays, try X".

### 5. Compliance pack
- Audit logs, PII redaction, and data residency.
- Mapping to the EU AI Act, SOC 2, and industry rules (finance, health).

## Who uses it
SaaS companies with AI features, customer-support bots, e-commerce assistants, banks, insurers,
telecoms, edtech (anti-cheating mode), internal enterprise copilots, game NPCs, and government services.

## Business model
| Tier       | Price            | For |
|------------|------------------|-----|
| Free       | 10k checks/mo    | indie devs |
| Pro        | ~$49/mo + usage  | startups |
| Business   | ~$499/mo         | dashboard, SSO, custom policies |
| Enterprise | custom           | on-prem / VPC, compliance pack |
Selling point: it pays for itself, because blocked off-mission tokens usually cost more than the subscription.

## Roadmap
1. **Weeks 0–4:** open-source SDK plus a hosted gateway (embeddings + LLM judge) and a basic dashboard.
2. **Months 2–3:** Policy Studio, attack-test library, Slack/Discord/Intercom/Zendesk plugins.
3. **Months 4–6:** output checks, agent tool guard, monetization routing, and auto-tuning from feedback.
4. **Months 6+:** compliance pack, on-prem deployment, and a marketplace of industry policy templates.

## Moat
- A cross-customer attack and jailbreak dataset that improves detection for everyone.
- Unmet-demand analytics, which is a product-strategy tool and not just a filter.
- Model-agnostic, so it works with any LLM provider.

## Risks
- False positives annoying real users → mitigated by the ADJACENT tier, soft redirects, and feedback loops.
- Latency → cheap layers first; the LLM judge runs only on roughly 10–20% of traffic.
- Big LLM providers adding basic guardrails → stay differentiated through business analytics and monetization.
