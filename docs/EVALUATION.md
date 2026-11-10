# Gardu evaluation

Every number here comes from `python tests/evaluate.py` (labelled corpora) and
`python tests/evaluate.py <folder> ...` (public folders). Measured on 2026-11-10 with rules version in `gardu/rules.json`.

## Method

- **Tuning set** (`corpus/tuning.json`, 31 samples): written first; the rules were adjusted until it matched. Its score says the
  rules do what they were built for, nothing more.
- **Held-out set** (`corpus/heldout.json`, 16 samples): written after the rules were frozen, run once, and **not tuned on**.
  The one miss is reported as it came out.
- **Invariant Labs PoCs** (`invariantlabs-ai/mcp-injection-experiments` @ 7382a5e): the three published MCP tool-poisoning
  attacks. The rules were written from public write-ups before these files were opened.
- **Public folders** (`anthropics/skills` @ 2c5958e, `modelcontextprotocol/servers` @ 3638028): real, presumably benign
  repositories. They have no labels, so they measure **false alarms**, not detection. Every non-PASS file is listed below
  with a verdict on whether the alarm is fair.
- Samples are stored base64-encoded because Windows Defender quarantined a plain-text PowerShell attack sample.
- The browser scanner (`web/scan.js`) was checked against the Python scanner on all five corpora: identical rule, file,
  line and severity for every finding (`ui-tests/parity.py`).

Two tuning samples are labelled with a deliberately "wrong" class:
`b04-security-docs` is benign documentation that quotes `curl | sh`; Gardu fails it on purpose (quoted attacks are
indistinguishable from real ones to a pattern scanner - suppress with `gardu-ignore` after review).
`m23-long-description` is a suspicious but harmless long tool description; it only earns a low finding, so it passes.

## Summary

| Corpus | Malicious flagged | Benign false alarms | Exact verdict |
|---|---|---|---|
| Tuning | 23/24 (m23 is low-only by design) | 1/7 (b04 by design) | 31/31 |
| **Held-out** | **11/11** | **0/5** | 15/16 |
| Invariant PoCs | 3/3 FAIL | - | - |
| anthropics/skills | - | 5 of 273 files (1 FAIL, 4 REVIEW) | - |
| MCP servers | - | 2 of 388 files (0 FAIL, 2 REVIEW) | - |

Held-out miss: `h07-zed-config` (an MCP config in Zed's format with an unpinned package and an inline secret) got REVIEW
instead of FAIL - both findings fired, but at medium severity because inline secrets are often placeholders in example
configs. Not tuned after the fact.

Speed: about 0.2 MB/s in pure Python on a laptop (3.5 MB of skills in 18 s); the browser is similar.

## Review of the public-folder alarms

| File | Verdict | Fair? |
|---|---|---|
| skills/claude-api/shared/managed-agents-onboarding-from-url.md | FAIL (GD401) | False alarm: it tells the agent *never* to run a page's setup scripts and quotes `curl ... \| sh` as the bad example. |
| skills/claude-api/shared/model-migration.md | REVIEW (GD201) | False alarm: it advises *avoiding* override wording and quotes "ignore what the user said" as the example. |
| skills/claude-api/shared/evals/report/build-report-lite.mjs, runner-scaffold.mjs | REVIEW (GD301) | False alarm: a code comment uses `~/.ssh/id_rsa` as an example of a path an attacker might target. |
| skills/pdf/reference.md | REVIEW (GD311) | False alarm: `password="secret"` in a PDF-encryption example. |
| servers: scripts/lib/skill-manifest.test.mjs, src/fetch/tests/test_non_cp1252_pages.py | REVIEW (GD101) | Fair: test fixtures that really contain invisible/BOM characters. |

So on these two benign repositories, 2 of the 7 alarms are fair and 5 are documentation or comments that *quote* an
attack in order to warn about it. Quoted attacks are the main false-alarm source; negation words already downgrade
some of them (that is why most are REVIEW, not FAIL), but not all. Per file, the false-alarm rate on
anthropics/skills is \(5/273 \approx 1.8\%\) and on the MCP servers repository \(0/388\) (the 2 alarms there are fair).

## Limits

- Pattern and structure rules, no model. Paraphrased or novel attacks pass.
- 47 labelled samples written by one person are not a benchmark; treat these as smoke tests with honest bookkeeping.
- No execution, no network, no package download, no binary inspection.

## Raw output

## Labelled corpora

### tuning (31 samples)

| sample | set | expected | got | rules |
|---|---|---|---|---|
| b01-pinned-config | benign | PASS | PASS | - |
| b02-honest-skill | benign | PASS | PASS | - |
| b03-emoji | benign | PASS | PASS | - |
| b04-security-docs | benign | FAIL | FAIL | GD401 |
| b05-tools-clean | benign | PASS | PASS | - |
| b06-build-script | benign | PASS | PASS | - |
| b07-env-config | benign | PASS | PASS | - |
| m01-poisoned-calculator | malicious | FAIL | FAIL | GD202, GD203, GD206, GD602 |
| m02-shadow-email | malicious | FAIL | FAIL | GD204, GD603 |
| m03-hidden-tags-skill | malicious | FAIL | FAIL | GD103, GD401 |
| m04-zero-width-split | malicious | FAIL | FAIL | GD101, GD201 |
| m05-html-comment | malicious | FAIL | FAIL | GD104 |
| m06-curl-pipe-script | malicious | FAIL | FAIL | GD401, GD701 |
| m07-powershell-iex | malicious | FAIL | FAIL | GD401 |
| m08-exfil-webhook | malicious | FAIL | FAIL | GD301, GD402 |
| m09-unpinned-mcp | malicious | FAIL | FAIL | GD501, GD502 |
| m10-secret-in-config | malicious | FAIL | FAIL | GD310, GD504 |
| m11-http-remote | malicious | FAIL | FAIL | GD503 |
| m12-docker-privileged | malicious | FAIL | FAIL | GD506 |
| m13-shell-wrapper | malicious | FAIL | FAIL | GD401, GD505 |
| m14-scope-creep | malicious | FAIL | FAIL | GD301, GD701 |
| m15-persistence | malicious | FAIL | FAIL | GD405, GD701 |
| m16-bidi | malicious | FAIL | FAIL | GD102 |
| m17-base64-payload | malicious | FAIL | FAIL | GD105, GD201, GD202, GD402 |
| m18-override | malicious | FAIL | FAIL | GD201, GD402 |
| m19-destructive | malicious | FAIL | FAIL | GD404 |
| m20-secret-harvest | malicious | FAIL | FAIL | GD206, GD602 |
| m21-auto-approve | malicious | REVIEW | REVIEW | GD205 |
| m22-file-upload | malicious | REVIEW | REVIEW | GD403 |
| m23-long-description | malicious | PASS | PASS | GD601 |
| m24-eval-atob | malicious | FAIL | FAIL | GD401 |

Exact verdict: 31/31 - malicious caught: 23/24 - benign false alarms: 1/7

### heldout (16 samples)

| sample | set | expected | got | rules |
|---|---|---|---|---|
| h01-poison-summarizer | malicious | FAIL | FAIL | GD202, GD203, GD206, GD301 |
| h02-redirect-payments | malicious | FAIL | FAIL | GD204, GD603 |
| h03-tag-smuggle-agents | malicious | FAIL | FAIL | GD103 |
| h04-wget-python | malicious | FAIL | FAIL | GD401, GD701 |
| h05-encoded-ps | malicious | FAIL | FAIL | GD401 |
| h06-telegram-exfil | malicious | FAIL | FAIL | GD301, GD402 |
| h07-zed-config | malicious | FAIL | REVIEW **(differs)** | GD501, GD504 |
| h08-hidden-comment-rules | malicious | FAIL | FAIL | GD104 |
| h09-undeclared-network | malicious | REVIEW | REVIEW | GD701 |
| h10-rm-root | malicious | FAIL | FAIL | GD404 |
| h11-cron-persist | malicious | FAIL | FAIL | GD401, GD405, GD701 |
| h12-clean-skill | benign | PASS | PASS | - |
| h13-clean-mcp-config | benign | PASS | PASS | - |
| h14-clean-tools | benign | PASS | PASS | - |
| h15-clean-script | benign | PASS | PASS | - |
| h16-persian-text | benign | PASS | PASS | - |

Exact verdict: 15/16 - malicious caught: 11/11 - benign false alarms: 0/5

## Public folders (unlabelled)

### mcp-injection-experiments (4 files, 0.0 MB, 0.0 s)

Files: 1 PASS, 0 REVIEW, 3 FAIL. Skipped: 0.

| file | verdict | rules |
|---|---|---|
| direct-poisoning.py | FAIL | GD203, GD206, GD301, GD602 |
| shadowing.py | FAIL | GD202, GD203, GD204 |
| whatsapp-takeover.py | FAIL | GD202, GD203, GD204 |

### skills (273 files, 3.5 MB, 18.2 s)

Files: 268 PASS, 4 REVIEW, 1 FAIL. Skipped: 0.

| file | verdict | rules |
|---|---|---|
| skills/claude-api/shared/managed-agents-onboarding-from-url.md | FAIL | GD401 |
| skills/claude-api/shared/model-migration.md | REVIEW | GD201 |
| skills/claude-api/shared/evals/report/build-report-lite.mjs | REVIEW | GD301 |
| skills/claude-api/shared/evals/report/runner-scaffold.mjs | REVIEW | GD301 |
| skills/pdf/reference.md | REVIEW | GD311 |

### servers (388 files, 4.8 MB, 18.1 s)

Files: 386 PASS, 2 REVIEW, 0 FAIL. Skipped: 0.

| file | verdict | rules |
|---|---|---|
| scripts/lib/skill-manifest.test.mjs | REVIEW | GD101 |
| src/fetch/tests/test_non_cp1252_pages.py | REVIEW | GD101 |


