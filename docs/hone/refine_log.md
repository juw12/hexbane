# /hone run log - Hexbane (ScopeGuard + agent skill/MCP scanner)

## Run queue

- [x] Q1 Pick a free name (ScopeGuard is taken) and set up repo `juw12/hexbane`
- [x] Q2 Freeze rubric (docs/hone/rubric.md) and score baseline v0 (ScopeGuard playground as-is)
- [x] Q3 Scanner core (Python, stdlib): rules.json, skills / MCP config / tool manifest / script parsing, verdicts, masking
- [x] Q4 Rug-pull pinning (`hexbane lock` / `--lock`), suppressions, SARIF + JSON + Markdown output, CLI
- [x] Q5 Runtime tool gate (tool-call + tool-output checks) and server endpoints next to the ScopeGuard chat guard
- [x] Q6 Browser scanner (same rules.json) + Scan page, rebrand web app to Hexbane
- [x] Q7 Corpus: tuning malicious/benign, held-out set, public Invariant PoCs, anthropics/skills, MCP reference servers
- [x] Q8 Tests: scanner unit tests, web hermetic checks, server suite, JS/Python parity in headless Edge
- [x] Q9 Evaluation report (docs/EVALUATION.md) with honest numbers
- [x] Q10 README, GitHub Action (action.yml), CI + Pages workflows
- [x] Q11 Hone loop: council score + blind pair per round, keep best
- [x] Q12 Publish: repo, Pages, live check (G8)
- [x] Q13 Sync: profile README, portfolio card, landing page, Obsidian notes; old ScopeGuard notes point to Hexbane
- [x] Q14 Lessons + precedent log + cairn end

## Assumptions

- Name: **Hexbane** ("breaks the hex": it breaks the curse hidden in a skill or tool before the agent falls for it).
- Assumed: Hexbane is a new standalone repo `juw12/hexbane` built from the newest ScopeGuard code (`juw12/steward/apps/playground`, commit b152792). Steward stays untouched; ScopeGuard keeps its history there.
- Assumed: the ScopeGuard engine keeps working unchanged (same decisions, same accuracy numbers) and is presented as Hexbane's "chat gate"; env vars get `HEXBANE_*` names with the old `SCOPEGUARD_*` names still accepted.
- Assumed: no money is spent (free tools only); patent filing is out of scope for this run (needs Juwen + an attorney).

## Rounds

| round | change | gates | judge score | pairwise win | kept? | note |
|---|---|---|---|---|---|---|
| 2026-11-10 08:45 | v0 baseline: ScopeGuard playground as-is | n/a | 4.67 (Pega-Vision 6.6, Pega-Thinking 2.75; GLM failed) | not run | baseline | split on C1-C5 |
| 2026-11-10 10:05 | v1 Hexbane: scanner + rug-pull pin + tool gate + browser scan + Action + evaluation + Pages | G1-G8 pass (3/3 suites, parity 5/5, UI 11/11, held-out 15/16, self-scan PASS, live G8) | 9.5 (Pega-Vision 9.3, Pega-Thinking 9.7; GLM failed) | not run | kept | docs/hone/v1.json; fix ideas: decoded HB105 view, copyable fixes, mobile statement |
| 2026-11-10 13:10 | v2 Hexbane: rename + hex logo, disguised-text unfolding (HB106) with decoded text, copy-paste fixes and suppressions, `hexbane fix`, 65-sample disguised corpus (53 -> 63 flagged), README as one story | G1 3/3, G2 6/6 corpora, G3-G7 pass | 9.25 (3 judges: Vision 9.55, Thinking 9.25, GLM 9.25) | not run | kept (v1 9.5 had only 2 judges) | C5 median 8: phone tabs cut off, only dark screenshots |
| 2026-11-10 13:30 | v3: phone nav as 3x2 grid (all six sections visible), light-theme and phone screenshots linked and judged | G1 3/3, G2 6/6, G8 live 200 | **9.85** (3 judges: C1-C4 median 10, C5 9) | v3 beats v1 (blind, order-swapped) | **kept, best** | docs/hone/v3.json, v3-pair.json |

## Round 2 (2026-11-10): user asked for a cooler, non-Indonesian name, a 10/10 attempt, and the weaknesses fixed

- Assumed: new name **Hexbane** ("breaks the hex": injected spells and hex/base64-hidden payloads). Checked: free on PyPI; on GitHub only tiny unrelated repos; on the web an indie horror game and a tiny dev module, no AI or security product. Rejected: IronMoat (ClawMoat/OpenMoat exist), Ironward (an AI security scanner with MCP already uses it), Antivenom (AI prompt WAF).
- Assumed: the repo was renamed in place to juw12/hexbane, so stars, issues and links carry over.
- Weaknesses targeted (from the v1 judges and the v1 README limits): disguised text slipped past plain patterns; fixes were prose, not copyable; no mobile evidence; README read as two merged tools.
- Rubric unchanged (frozen); only the product name in its title changed.

### Round 2 result

Best: v3, 9.85 (all 3 judges answered, unlike v1). Not 10: C5 visual 9 from every judge. Open items the judges named: third-party malicious corpora (all labelled sets are author-written), uniform-spacing gap (8/14 rules), spaced command flags (m22), chat-gate numbers only in the app (about 1 in 5 clever off-topic requests get through), quoted-attack docs still flagged (5/273), WCAG AA audit of small dark-theme text, SRI for browser scripts.

Note: the archived judge outputs (docs/hone/v0.json to v3.json) have the product name normalized to Hexbane; scores and all other wording are verbatim.

## Round 3 (v0.2.1)

- Fixed: a spaced run could start right after a flag (`-F f i l e=@`), gluing it into `-Ffile` and hiding the upload.
- New squeeze pass for letters spaced with the same gap as words (`i g n o r e a l l`): on lines with 8+ spaced
  letters, spaces are removed and space-tolerant fold rules must match across the spaced run.
- Disguised set: files flagged 63/65 -> 65/65; rules kept 109/123 -> 116/123. Tuning 31/31, held-out 15/16,
  public folders unchanged (5/273, 2/388), browser = Python on all 6 corpora, 38 unit tests pass.
