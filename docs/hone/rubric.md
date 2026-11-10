# Hexbane rubric v1 (frozen 2026-11-10, before any code was written; product renamed Gardu -> Hexbane in round 2, criteria unchanged)

Goal beyond the goal: Juwen gets a security tool people can trust and cite - one install-free check that
tells a developer whether an AI agent skill, MCP server or tool is safe to load, plus the runtime guard
(from ScopeGuard) that keeps the agent on its mission once it runs. Name-building comes from honest,
reproducible numbers on public samples, not from claims.

## Hard gates (checked by code, never by the judge)

- G1 Every test suite passes: `python tests/run_all.py` (scanner unit tests, web hermetic checks, server suite).
- G2 Python and browser scanners give identical findings (rule id, file, line) on the whole corpus
  (`ui-tests/run_ui_tests.py` parity check in headless Edge).
- G3 Recall on the tuning malicious corpus >= 90 % (verdict REVIEW or FAIL) and 100 % on the public
  Invariant Labs PoCs (3 files).
- G4 False alarms: FAIL verdicts on the public benign corpus (anthropics/skills skill folders) <= 10 %, and
  every remaining FAIL is listed with its reason in `docs/EVALUATION.md`.
- G5 Secrets found by the scanner are masked in every output format (text, JSON, SARIF, browser).
- G6 Untrusted scanned text is rendered as text, never HTML (XSS test).
- G7 Repo hygiene: LF line endings, MIT licence, README states measured numbers and limits; no private data
  (no personal paths, hosts or credentials) in the repo.
- G8 After publishing: the live Pages URL returns 200 and the Scan page renders (headless screenshot).

## Soft criteria (council-scored)

- C1 Security depth (w=0.30): 4 = keyword grep for "ignore previous instructions"; 7 = covers the main published attack classes for agent skills and MCP (tool poisoning, hidden Unicode, cross-tool shadowing, exfiltration, remote-code pipes, risky MCP config) with an explanation and fix per finding; 10 = also a runtime tool-call gate, rug-pull detection by pinning, decoded hidden payloads shown to the user, and measured results on real public samples.
- C2 Usability and developer experience (w=0.25): 4 = CLI with raw output only; 7 = one-command scan with clear PASS/REVIEW/FAIL verdicts and a browser demo; 10 = zero-install browser scan with folder drop and samples, CI-ready SARIF and a GitHub Action, copy-paste fixes and suppressions.
- C3 Product coherence (w=0.15): 4 = two tools bolted together; 7 = one brand, shared navigation and a single story; 10 = one model where each part reinforces the other (the "stay in scope" idea applied to both chat messages and skills/tools).
- C4 Evidence and honesty (w=0.15): 4 = claims without numbers; 7 = measured numbers with sample sizes; 10 = tuning vs held-out vs public sets separated, false alarms explained, limits stated plainly, sources linked.
- C5 Visual and UI quality (w=0.15): 4 = generic template look; 7 = clean, consistent, readable in both themes; 10 = distinctive, calm security-tool look with clear hierarchy, severity colours that pass contrast, works on a phone.
