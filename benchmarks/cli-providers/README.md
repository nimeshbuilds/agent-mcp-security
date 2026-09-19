# Actual CLI-provider validation receipts

**Invarune by NimeshBuild — 2026-09-19.** These are observed integration results from the development of version 0.8.0. They test the optional CLI transports and deterministic response validators with fixed synthetic evidence. They are not a security-judge accuracy benchmark or scans of a deployed application.

| Provider / installed version | Requested model | Actual stage | Outcome | Elapsed seconds | Receipt |
|---|---|---|---|---:|---|
| Codex 0.154.0 | `gpt-6-astra` | Finding triage | Completed; supplied finding ID validated; advisory verdict `needs_review` | 8.836 | [Codex receipt](codex_cli.json) |
| Codex 0.154.0 | `gpt-6-astra` | Control review | Completed; supplied control/check IDs and exact source quote validated; advisory status `potential_gap` | 10.837 | [Codex receipt](codex_cli.json) |
| Claude Code 2.1.214 | `opus` | Finding triage | Missing/expired sign-in; no successful model response | 0.624 | [Claude receipt](claude_cli.json) |
| Claude Code 2.1.214 | `opus` | Control review | Missing/expired sign-in; no successful model response | 0.424 | [Claude receipt](claude_cli.json) |
| Grok Build 0.2.60 | `grok-build` | Finding-stage preflight | Rejected active extensions before inference | 0.235 | [Grok receipt](grok_cli.json) |

An additional real `invarune --login claude` invocation opened the official browser authorization flow. The account authorization was not completed within its **300-second** timeout; the command returned **exit 2**. This is evidence of login-flow invocation and timeout handling, not successful Claude authentication. [Sanitized login observation](claude_login.json).

A separate actual end-to-end invocation used Invarune's public scan CLI on its vulnerable fixture and wrote all four report formats: [HTML](../../examples/reports/cli-codex/report.html), [Markdown](../../examples/reports/cli-codex/report.md), [JSON](../../examples/reports/cli-codex/report.json), [SARIF](../../examples/reports/cli-codex/report.sarif).

```bash
python3 -m ai_security_scan examples/vulnerable \
  --judge-cli codex --judge-timeout 120 --judge-login never \
  --judge-mode findings --judge-max-findings 2 \
  --output examples/reports/cli-codex
```

That scan retained **11 deterministic findings**, reported **zero coverage gaps**, and completed Codex review of the selected **two findings**, both with advisory `needs_review` verdicts. The other **nine open findings were explicitly omitted** from model review. Exit **1** was the expected deterministic findings gate. SARIF validation succeeded. This was bounded finding triage; it was **not** a full 132-check model review. The single-control adapter experiment in the table is a separate validation result.

All displayed durations include local adapter overhead and, where reached, inference. Failure timings are not successful-inference latency measurements. Two successful Codex responses do not establish model accuracy, repeatability, entitlement for other accounts, or live support for Claude/Grok accounts that did not complete these runs.

## Exact test inputs and route

The original local harness was `tmp/cli-live/run.py`. Each receipt includes the SHA-256 of that harness and of the original local receipt. The harness called `ai_security_scan.judge.review` for finding triage and `review_controls` for the control stage, with a 120-second per-stage timeout and no explicit model override. Invarune selected the provider defaults listed above. It did not run the synthetic code or provide a repository directory to the model.

The finding payload supplied one finding, `LIVE-F1`, identified as `AI002`, with the evidence string `os.system(user_input)`, the relative path `synthetic.py`, and an explicit statement that this was a single-line synthetic fixture. Its line value was 2. That is fixture metadata, not a claimed finding obtained by scanning a real project.

The control payload supplied `LIVE-C1`, one acceptance check, and evidence `LIVE-E1` containing exactly:

```python
import os
def run(user_input):
    os.system(user_input)
```

The evidence used lines 1–3 and SHA-256 `b96e16ae2f8b203a976093800f387abb83aa4f98a3e03d1765cdb035a5f55f5a`. The Codex control answer cited an exact substring; the deterministic validator derived citation location lines 2–3 from that source. The same judge instructions, response normalization, allowed verdicts and grounded-citation checks used by the scanner were applied. Raw vendor protocol streams were not published.

The Codex receipt records the exact capability restrictions, CLI version, prompt/response hashes, byte counts and the recognized startup warning for deliberately disabled Code Mode. Its full source/metadata is synthetic. The Claude and Grok failures came from the actual installed programs; they are not mocked successes.

## Reproduce explicitly

The maintained harness [validate_cli_providers.py](../../scripts/validate_cli_providers.py) preserves those payloads and defaults. It requires explicit permission for live requests, accepts one provider at a time, writes local JSON receipts, and never opens a login flow or uploads reports.

```bash
python3 scripts/validate_cli_providers.py --help

# At most two fixed synthetic advisory requests; uses account allowance.
python3 scripts/validate_cli_providers.py --provider codex --allow-live-requests
python3 scripts/validate_cli_providers.py --provider claude --allow-live-requests

# The recorded Grok attempt covered only the finding-stage preflight.
python3 scripts/validate_cli_providers.py --provider grok --stage findings --allow-live-requests
```

If needed, authenticate in an interactive terminal with `invarune --login codex`, `invarune --login claude`, or `invarune --login grok`. A Grok profile must also pass the extension preflight. `--cli-home` can select an existing clean Grok profile; credentials are not copied. A dedicated profile may still inherit home or managed configuration.

The new harness was checked with `--help`, no-opt-in rejection and mocked receipt-writing smoke checks after extraction from the actual local runner; it was not used to make additional model calls when these receipts were published. Its future runs record their own scanner version, harness digest and UTC timestamp. It returns exit 0 only if every requested stage completes; otherwise it returns exit 2. New runs can differ because model responses, subscriptions, account state and provider software change.

## Interpretation and privacy

- Optional model advice cannot turn a deterministic finding into a pass or lower its severity gate. A provider failure leaves deterministic scan evidence intact.
- No successful live Claude or Grok inference is claimed by these receipts. Mocked adapter coverage is recorded separately in the test suite.
- Installed executables, vendor authentication stores and administrator policy remain trusted. CLI capability restrictions are not OS containment.
- Receipts omit OAuth URLs, device codes, tokens, account identities, raw stderr and machine-specific paths. The separate login record is a sanitized execution observation rather than a transcript.
- The original harness did not capture a full scanner-source digest or source commit for each run. The receipts identify the development cycle and adapter version; they must not be described as a rerun of every final release byte.
- This is an adapter smoke test. Real-project scan reports and competing-scanner measurements are separate: [real projects](../real-world/README.md), [external tools](../external-tools/README.md).

For version requirements, primary sources, default-model rationale, auth behavior and detailed restrictions, see [CLI provider research](../../docs/CLI_PROVIDER_RESEARCH.md).
