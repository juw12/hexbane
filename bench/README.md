# hexbench - run any scanner on the same labelled cases

A trust score is only as good as the test behind it, so the test is public. `bench/run.py` turns hexbane's
labelled corpora into 112 plain folders (an MCP config, a tool list or a skill per case) and scores any
scanner on them: how many attacks it catches and how many clean cases it raises an alarm on.

```bash
python bench/run.py                                             # hexbane, in-process, nothing written to disk
python bench/run.py --name mytool --command "mytool scan {path}"                  # flagged = non-zero exit
python bench/run.py --name mytool --command "mytool scan {path}" --flag "regex:HIGH|CRITICAL"
python bench/run.py --export cases/                             # just the folders + labels.json
```

Python 3.10+, standard library only. `{path}` is replaced by one case folder per run.

## Results (13 Nov 2026)

| scanner | held-out caught | held-out false alarms | obfuscated caught | tuning caught | tuning false alarms |
|---|---|---|---|---|---|
| hexbane 0.2.4 | 11/11 | 0/5 | 65/65 | 23/24 | 1/7 |
| keyword baseline (`bench/baselines/keyword_grep.py`) | 0/11 | 0/5 | 3/65 | 4/24 | 0/7 |

Raw results: `bench/results/*.json`. CI re-runs hexbane on every push and fails if it catches fewer cases or
raises more false alarms than the committed result.

## Read this before quoting a number

- **Sets are scored separately on purpose.** `tuning` is the set hexbane's rules were written against, so
  hexbane's tuning score says little. `obfuscated` is the tuning attacks rewritten with one evasion trick each,
  and hexbane's unfolding pass was built for those tricks. `heldout` was written after the rules were frozen
  and run once; it is the fairest set here, and it is small (11 attacks, 5 clean cases).
- **12 clean cases in total is too few** to say much about false alarms. On public repositories hexbane flags
  \(5/273 \approx 1.8\%\) of anthropics/skills files (see `docs/EVALUATION.md`).
- **The cases are text-only.** A scanner that runs a server, watches network traffic or reads package metadata
  can catch things these cases cannot show, and will get no credit for it here.
- **"Flagged" is binary.** Each scanner's own threshold decides; say which flag you used when you report.
- **Antivirus may quarantine cases.** Some cases are realistic attack files (for example a PowerShell
  download-and-run). On a machine with endpoint protection, `--command` mode can find a case file unreadable
  after writing it; such cases are listed as "not scored", never as misses. Run external scanners in CI or a
  container if that happens.

## Add your scanner

Open a PR that adds `bench/results/<scanner>.json` (from `--json`) and a row above, with the exact command and
version. Results that hexbane's author cannot reproduce from the command will not be merged. New attack or
clean cases are welcome too - they go into a new held-out set, so nobody (hexbane included) has tuned on them.
