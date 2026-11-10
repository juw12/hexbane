# /hone run log - Gardu (ScopeGuard + agent skill/MCP scanner)

## Run queue

- [x] Q1 Pick a free name (ScopeGuard is taken) and set up repo `juw12/gardu`
- [x] Q2 Freeze rubric (docs/hone/rubric.md) and score baseline v0 (ScopeGuard playground as-is)
- [x] Q3 Scanner core (Python, stdlib): rules.json, skills / MCP config / tool manifest / script parsing, verdicts, masking
- [x] Q4 Rug-pull pinning (`gardu lock` / `--lock`), suppressions, SARIF + JSON + Markdown output, CLI
- [x] Q5 Runtime tool gate (tool-call + tool-output checks) and server endpoints next to the ScopeGuard chat guard
- [x] Q6 Browser scanner (same rules.json) + Scan page, rebrand web app to Gardu
- [x] Q7 Corpus: tuning malicious/benign, held-out set, public Invariant PoCs, anthropics/skills, MCP reference servers
- [x] Q8 Tests: scanner unit tests, web hermetic checks, server suite, JS/Python parity in headless Edge
- [x] Q9 Evaluation report (docs/EVALUATION.md) with honest numbers
- [x] Q10 README, GitHub Action (action.yml), CI + Pages workflows
- [x] Q11 Hone loop: council score + blind pair per round, keep best
- [x] Q12 Publish: repo, Pages, live check (G8)
- [x] Q13 Sync: profile README, portfolio card, landing page, Obsidian notes; old ScopeGuard notes point to Gardu
- [x] Q14 Lessons + precedent log + cairn end

## Assumptions

- Assumed: name **Gardu** (Indonesian for a neighbourhood guard post, "gardu ronda"). Checked 2026-11-10: no AI-security product, PyPI or npm package, or juw12 repo with that name; github.com/gardu is an unrelated personal account.
- Assumed: Gardu is a new standalone repo `juw12/gardu` built from the newest ScopeGuard code (`juw12/steward/apps/playground`, commit b152792). Steward stays untouched; ScopeGuard keeps its history there.
- Assumed: the ScopeGuard engine keeps working unchanged (same decisions, same accuracy numbers) and is presented as Gardu's "chat gate"; env vars get `GARDU_*` names with the old `SCOPEGUARD_*` names still accepted.
- Assumed: no money is spent (free tools only); patent filing is out of scope for this run (needs Juwen + an attorney).

## Rounds

| round | change | gates | judge score | pairwise win | kept? | note |
|---|---|---|---|---|---|---|
| 2026-11-10 08:45 | v0 baseline: ScopeGuard playground as-is | n/a | 4.67 (Pega-Vision 6.6, Pega-Thinking 2.75; GLM failed) | not run | baseline | split on C1-C5 |
| 2026-11-10 10:05 | v1 Gardu: scanner + rug-pull pin + tool gate + browser scan + Action + evaluation + Pages | G1-G8 pass (3/3 suites, parity 5/5, UI 11/11, held-out 15/16, self-scan PASS, live G8) | 9.5 (Pega-Vision 9.3, Pega-Thinking 9.7; GLM failed) | not run | kept | docs/hone/v1.json; fix ideas: decoded GD105 view, copyable fixes, mobile statement |
