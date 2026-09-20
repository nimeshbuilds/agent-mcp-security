# Invarune 0.14 selected-skill reports

These are actual installed-CLI executions against the public, inert [skill and tool fixture](../../skills/README.md), selecting `AI043,AI044,AI045,AI046`. The target contains two files, four deliberately risky instruction patterns, and no executable attack. The selected rules map to six controls and twelve acceptance checks. This small demonstration is separate from the [81-case accuracy evaluation](../../../benchmarks/comparison-v014/README.md) and the eight public-project comparison.

| Actual run | Static findings | AI check answers | Result |
|---|---:|---:|---|
| [Deterministic](skills-static/report.html) · [PDF](skills-static/report.pdf) · [JSON](skills-static/report.json) | 4 | Disabled | Exit 1: severity gate triggered |
| [Codex, completed retry](skills-codex/report.html) · [PDF](skills-codex/report.pdf) · [JSON](skills-codex/report.json) | 4, unchanged | 12/12: 2 potential gaps, 10 insufficient evidence | Exit 1: same deterministic gate |
| [Claude, actual sign-in failure](skills-claude/report.html) · [PDF](skills-claude/report.pdf) · [JSON](skills-claude/report.json) | 4, unchanged | 0/12 | Exit 2: requested review could not start |
| [Codex, first timed-out attempt](skills-codex-attempt/report.html) · [JSON](skills-codex-attempt/report.json) | 4, unchanged | 0/12; four finding reviews completed | Exit 2: control batch exceeded 120 seconds |

Each directory also contains `report.md` and `report.sarif`. The successful Codex run used the installed Codex CLI 0.154.0, its existing subscription authentication, automatic model `gpt-6-astra`, and real Headroom 0.37.0. It made one finding-review call and three control-review calls. Headroom reports evidence-payload byte reduction; this is **not a measured token-cost saving**. Model outputs are advisory interpretations, not independent truth labels or proof that a deployed agent is vulnerable.

The first Codex attempt and the Claude failure are retained so unsuccessful requested work is visible. No successful Claude inference is claimed. An interactive user can authenticate within the scanner with `invscan --login claude`; ordinary interactive scans also support automatic login. These publication runs deliberately used `--judge-login never` to avoid an unattended authentication prompt.

## Reproduce the runs

Install the release with its `ai` and `pdf` extras using the [quickstart](../../../docs/QUICKSTART.md). Commands below use repository-relative paths for readability. The recorded executions ran from outside the checkout using absolute paths and the installed `invscan` command.

```sh
invscan examples/skills/risky --scans AI043,AI044,AI045,AI046 \
  --output examples/reports/v014/skills-static --summary-json

invscan examples/skills/risky --scans AI043,AI044,AI045,AI046 \
  --output examples/reports/v014/skills-codex \
  --judge-cli codex --judge-login never --judge-timeout 300 \
  --analyst-max-calls 3 --analyst-batch-size 2 --analyst-time-budget 900 \
  --summary-json

invscan examples/skills/risky --scans AI043,AI044,AI045,AI046 \
  --output examples/reports/v014/skills-claude \
  --judge-cli claude --judge-login never --judge-timeout 120 \
  --analyst-max-calls 2 --analyst-time-budget 240 --summary-json
```

The first Codex attempt used the Claude command's 120-second timeout, two-call control budget and 240-second total control-review budget, with provider `codex` and the default batch size of six. The retry explicitly reduced the control batch size to two and increased its deadlines. A budget setting is not a guarantee of provider response time. Model results may differ on another run.

The three PDFs were exported **after** the original scans from their recorded JSON using Invarune's report/PDF renderer; no additional model calls were made to generate them. The export added `pdf` to each report's recorded output formats. To create PDF directly during a future scan, add `--pdf` to the corresponding command.

## Reading and editing the result

Begin with the summary, immediate concerns and recommended actions. Each finding includes its exact location, deterministic evidence, AI/MCP relevance, fixes and additional safeguards. The coverage section lists what remains unresolved. In the completed Codex report, **100% AI answer coverage means twelve answers were received**; ten answers explicitly say the evidence is insufficient. Deterministic mapping reach is also 100% within this narrow selection, meaning all six selected controls have at least one mapped pattern. Neither number is a security/compliance score or a control pass.

Use the editable review workspace to record an owner's justification, disposition and supporting evidence. Then rerun with `--review-report PATH` and the same target/selection. All five report formats support that workflow; the PDF contains editable fields, the HTML has an editor, and Markdown/JSON/SARIF carry the bound review data. A user justification is labeled **justified**, excluded from active denominators without pass credit, and rejected as stale when its binding no longer matches. See the [review-format guide](../../../docs/PDF_REVIEW.md) for editing details and supported PDF viewers.

[Run and artifact receipt](receipt.json) · [PDF visual/form validation](../../../benchmarks/validation-v014/skill-pdfs-receipt.json) · [Coverage and score formulas](../../../docs/SCAN_COVERAGE.md).
