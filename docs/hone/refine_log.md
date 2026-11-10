# /hone run log - Gardu (ScopeGuard + agent skill/MCP scanner)

## Run queue

- [ ] Q1 Pick a free name (ScopeGuard is taken) and set up repo `juw12/gardu`
- [ ] Q2 Freeze rubric (docs/hone/rubric.md) and score baseline v0 (ScopeGuard playground as-is)
- [ ] Q3 Scanner core (Python, stdlib): rules.json, skills / MCP config / tool manifest / script parsing, verdicts, masking
- [ ] Q4 Rug-pull pinning (`gardu lock` / `--lock`), suppressions, SARIF + JSON + Markdown output, CLI
- [ ] Q5 Runtime tool gate (tool-call + tool-output checks) and server endpoints next to the ScopeGuard chat guard
- [ ] Q6 Browser scanner (same rules.json) + Scan page, rebrand web app to Gardu
- [ ] Q7 Corpus: tuning malicious/benign, held-out set, public Invariant PoCs, anthropics/skills, MCP reference servers
- [ ] Q8 Tests: scanner unit tests, web hermetic checks, server suite, JS/Python parity in headless Edge
- [ ] Q9 Evaluation report (docs/EVALUATION.md) with honest numbers
- [ ] Q10 README, GitHub Action (action.yml), CI + Pages workflows
- [ ] Q11 Hone loop: council score + blind pair per round, keep best
- [ ] Q12 Publish: repo, Pages, live check (G8)
- [ ] Q13 Sync: profile README, portfolio card, landing page, Obsidian notes; old ScopeGuard notes point to Gardu
- [ ] Q14 Lessons + precedent log + cairn end

## Assumptions

- Assumed: name **Gardu** (Indonesian for a neighbourhood guard post, "gardu ronda"). Checked 2026-11-10: no AI-security product, PyPI or npm package, or juw12 repo with that name; github.com/gardu is an unrelated personal account.
- Assumed: Gardu is a new standalone repo `juw12/gardu` built from the newest ScopeGuard code (`juw12/steward/apps/playground`, commit b152792). Steward stays untouched; ScopeGuard keeps its history there.
- Assumed: the ScopeGuard engine keeps working unchanged (same decisions, same accuracy numbers) and is presented as Gardu's "chat gate"; env vars get `GARDU_*` names with the old `SCOPEGUARD_*` names still accepted.
- Assumed: no money is spent (free tools only); patent filing is out of scope for this run (needs Juwen + an attorney).

## Rounds

| round | change | gates | judge score | pairwise win | kept? | note |
|---|---|---|---|---|---|---|
| 2026-11-10 08:45 | council score | 4.67 | split: C1,C2,C3,C4,C5 | Pega-Vision=6.6, Pega-Thinking=2.75, GLM-5.3-Flash=x |
