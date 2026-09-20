# Invarune quick start

**NimeshBuild · Evidence for agent security**

Get your first report, explore its security controls, then add image scanning, optional AI review or accepted exceptions. These checkout examples target **Invarune 0.12.0**. The primary command is **`invscan`**. Deterministic scans and catalog exploration need **Python 3.9+**, with no runtime dependencies, API keys or model subscription. PDF export/import uses optional Python packages.

## 1. Install the CLI and get your first report

Want the CLI without a source checkout? The [v0.12.0 release](https://github.com/nimeshbuilds/agent-mcp-security/releases/tag/v0.12.0) provides a downloadable wheel, checksums and installation commands, including the offline explorer. Its downloaded wheel was installed and verified in a fresh environment. The checkout route below also includes the example source and image fixtures used throughout this guide.

Clone this repository using Git credentials that have access:

```sh
git clone https://github.com/nimeshbuilds/agent-mcp-security.git
cd agent-mcp-security
```

Already have the checkout? Change to its directory. Create a **new** virtual environment; if `.venv` already belongs to this project, reuse it and skip the creation command. Otherwise choose an unused environment name. Installation can download Python build tooling.

macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
. .venv/bin/activate
invscan --version
```

Windows PowerShell, without changing script execution policy:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
$env:Path = "$((Resolve-Path .venv\Scripts).Path);$env:Path"
invscan --version
```

The PATH change applies to this terminal. Expect version **0.12.0** from the current checkout. All `invscan` commands below work in either shell after this setup. In a new terminal, reactivate this environment or use the installed executable's absolute path. The existing `invarune` and `ai-security-scan` commands are compatible aliases.

Run your first offline scan:

```sh
invscan examples/safer --output ./scan-report/quickstart-safer
```

Expect **2 scanned files, 0 findings, 0 coverage gaps and exit 0**. Open `scan-report/quickstart-safer/report.html` using your file manager, or read `report.md`. No model was called and no target code was executed.

To see findings and remediation guidance:

```sh
invscan examples/vulnerable --output ./scan-report/quickstart-vulnerable
```

Expect **11 open findings and exit 1**. This is the intended findings gate, not a scanner crash. The deliberately unsafe fixture is inspected as text, never run. [Preview its published report](../examples/reports/v011/source/report.md).

### Explore what the checks mean

These commands inspect the bundled reference without scanning files, loading provider configuration, logging in or calling a model:

```sh
invscan --list-topics
invscan --ask 'What do you check for prompt injection?'
invscan --ask 'How is MCP authentication covered?'
invscan --ask 'What NSA and CISA guidance do you use?'
invscan --explain-control AUTH-01
invscan --explain-check AUTH-01:1
invscan --list-sources
invscan --explain-source JOINT-AGENTIC
```

`--ask` performs deterministic literal lookup, not generative chat. New commands default to readable text; add `--catalog-format json` for structured output. Use `--help-topic security` for the focused guide. Answers distinguish static rule mappings from required runtime/human validation and primary citations from thematic alignments. No lookup result establishes a security pass. [Worked examples, query limits and complete explorer guide](SECURITY_EXPLORER.md).

## 2. Scan your code or built image

Replace the placeholder with your agent or MCP server's local directory. Keep reports outside the assessed directory when possible:

```sh
invscan "/absolute/path/to/agent-or-mcp-repo" --output ./scan-report/my-agent
```

For a built **Linux container image**, choose one route; no separate source checkout is needed:

```sh
# Docker-save or OCI tar archive: no container runtime needed to scan it.
invscan --image-archive ./agent-image.tar --output ./scan-report/my-image

# Existing local Docker image: Docker and its daemon must be available.
invscan --image my-agent:latest --output ./scan-report/my-image
```

Try the included archive without installing Docker or Podman:

```sh
invscan --image-archive examples/images/demo-agent.tar --output ./scan-report/quickstart-image
```

Expect **3 findings, 0 coverage gaps and exit 1**. Image scans never start a container. Use `--image-runtime podman` for a Podman image; registry pulls require explicit `--pull`. Supply a Docker **image save** archive, not `docker export`. Compiled-only images receive metadata assessment; binary logic and dependency CVEs remain unassessed. [Image formats and scope](IMAGE_SCANNING.md).

## 3. Read the result

| Report | Use it for |
|---|---|
| `report.html` | Executive summary, immediate concerns, evidence and proposed mitigation layers. Open locally; no web server needed. |
| `report.md` | Portable text to review or share. |
| `report.json` | Structured findings, controls, coverage and audit details. |
| `report.sarif` | Deterministic findings for compatible code-review and CI systems. |
| `report.pdf` (with `--pdf`) | Charts, clickable contents and fillable review fields. Install the PDF extra first. |

Review immediate concerns first, then **coverage gaps**, file/line evidence and controls needing human or runtime verification. Proposed defenses are not assumed to be deployed. Use separate output directories to retain earlier runs: each run replaces its report files.

| Exit | Meaning |
|---|---|
| `0` | Selected scope completed; no open finding reached the threshold. This is not a security certification. |
| `1` | Findings reached the threshold: **high or critical by default**. |
| `2` | Invalid input, operational failure, incomplete scan, report export failure, stale/pending imported review, or failed/incomplete requested AI review. Inspect diagnostics and any report produced. |

For CI, gate medium and higher findings and emit a JSON summary while saving all reports:

```sh
invscan "/absolute/path/to/agent-or-mcp-repo" --fail-on medium --summary-json --output ./scan-report/ci
```

`--fail-on none` removes only the findings gate; failures and incomplete scans still return 2. [Full report interpretation](REPORTS.md).

## 4. Add AI review, optionally

Without `--judge-cli` or `--judge-config`, both model-review stages stay **off**. The deterministic scan and all four reports still work. Installing optional packages alone never enables a model.

For the recommended optional AI/PDF setup, upgrade the same environment from this checkout:

```sh
python -m pip install '.[ai,pdf]'
```

The `ai` extra installs **Headroom 0.37.0** on Python 3.10+. Enabled AI review uses guarded, lossless JSON compaction by default; it preserves source/evidence and never enables retrieval tools or another model. If Headroom is missing, unsupported or fails, built-in compaction is used and recorded. Python 3.9 uses that fallback. `--token-optimizer compact` selects it explicitly; `--token-optimizer off` preserves spaced JSON. These options require enabled AI review. Token savings depend on the actual payload/tokenizer and are not guaranteed.

For an already installed official **Codex, Claude Code or Grok Build** CLI, use its CLI-managed login instead of configuring a separate API key in Invarune:

```sh
invscan "/absolute/path/to/agent-or-mcp-repo" --judge-cli codex --judge-timeout 120 --analyst-time-budget 600 --output ./scan-report/ai-review
```

Replace `codex` with `claude` or `grok` to choose that provider. Invarune selects its review model automatically; `--judge-model MODEL` overrides it. Interactive scans launch the official login when needed and resume after successful sign-in. You complete any browser/device authorization. To sign in without scanning:

```sh
invscan --login claude
```

Unattended, quiet and JSON-summary runs never prompt. Add `--judge-login never` to make that explicit. The official CLI must already be installed; account access and usage limits apply. Grok profiles must pass extension inspection. [Requirements, defaults and actual provider validation](CLI_PROVIDER_RESEARCH.md).

**Enabled review defaults to full mode:** finding triage plus every active control/check, including controls with no findings. It sends bounded, redacted source excerpts to the selected service. A normal full catalog needs 11 control requests plus finding triage. Budgets or missing answers can leave an explicit incomplete result. Redaction is best-effort; enable review only for evidence you may send to that service.

For a smaller, findings-only review:

```sh
invscan "/absolute/path/to/agent-or-mcp-repo" --judge-cli codex --judge-mode findings --output ./scan-report/findings-review
```

Advice remains separate: it cannot change deterministic severity, waive findings or turn controls into passes. Runtime questions and evidence gaps remain visible.

**API/custom gateway:** save this as trusted `judge.json`, replacing the model and exact endpoint:

```json
{
  "provider": "openai_chat",
  "model": "YOUR_GATEWAY_MODEL_ID",
  "endpoint": "https://gateway.example.com/v1/chat/completions",
  "api_key_env": "SECURITY_JUDGE_API_KEY",
  "timeout_seconds": 60,
  "max_output_tokens": 4096
}
```

Set `SECURITY_JUDGE_API_KEY` through your shell or secret manager; keep its value out of JSON. Then run:

```sh
invscan "/absolute/path/to/agent-or-mcp-repo" --judge-config ./judge.json --analyst-time-budget 600 --output ./scan-report/gateway-review
```

This example requires a Chat Completions-compatible endpoint. Other native protocols and custom JSON gateways use different configurations: [adapter guide](JUDGE.md), [example files](../examples/judges/).

## 5. Record accepted exceptions

Create a trusted review JSON file with your own evidence and reasons, then select it with `--review-config`. To try the shipped example on the demo:

```sh
invscan examples/vulnerable --review-config examples/review-config.json --output ./scan-report/quickstart-reviewed
```

Expect **9 open, 1 justified and 1 disabled finding**, with exit 1 because other high findings remain. The example reasons are illustrative; replace them with actual reviewed decisions before using a policy on your system.

**Justified** and **disabled** items remain visible and contribute neither a pass nor a failure to active counts. Checklist exceptions do not automatically waive mapped rule findings. Policies never load automatically from target code, and exceptions cannot hide scan errors. [Schema and precedence](REVIEW_CONFIGURATION.md).

## 6. Review a report, then scan again

Operational reports within the documented review-size limits carry the same review fields. If a complete review workspace cannot be exported, static reports remain available with an explicit error and exit 2. In HTML, enter a decision, reason and reviewer, then click **Download reviewed HTML**. JSON, Markdown and SARIF expose the same fields in their review capsule. Use `needs_runtime_validation` when deployment testing is still required; use `justified` only to record your accepted exception.

```sh
invscan examples/vulnerable --review-report ./reviewed-report.html --output ./scan-report/final
```

For a fillable PDF, upgrade this project's existing environment if PDF support is not installed yet. Run from the checkout; use `python` from the environment configured in step 1:

```sh
python -m pip install '.[pdf]'
invscan examples/vulnerable --pdf --output ./scan-report/pdf-review
```

The vulnerable fixture intentionally returns exit 1. Fill `scan-report/pdf-review/report.pdf` in an AcroForm-compatible editor and save a separate copy as `reviewed-report.pdf` in the checkout. Preserve its fields and attachments; do not print or flatten it. Then rescan:

```sh
invscan examples/vulnerable --review-report ./reviewed-report.pdf --pdf --output ./scan-report/final-pdf
```

Always select the fresh source/image target explicitly and use a new output directory. Matching decisions are applied individually; changed evidence leaves decisions unapplied. A justification is recorded as **justified**, never as a verified pass. Explicit pending runtime/human decisions return exit 2. Model review stays off unless you enable it again. [Field definitions, format limits and complete workflow](REVIEW_WORKFLOW.md).

## 7. Use a reviewed baseline, if needed

A baseline accepts individual finding IDs. First create a candidate, then review its entries and retain only the exceptions you authorize:

```sh
invscan examples/vulnerable --write-baseline ./candidate-baseline.json --baseline-reason 'Candidate for owner review' --output ./scan-report/baseline-candidate
```

This still reports **11 open findings and exit 1**. Writing a candidate does not accept it. After review, save your chosen entries as `reviewed-baseline.json` and load them explicitly:

```sh
invscan examples/vulnerable --baseline ./reviewed-baseline.json --output ./scan-report/baseline-reviewed
```

Matched entries become **suppressed**, not fixed or passed. Unmatched IDs stay visible in the audit. If you accept all 11 inert demo findings, the demo has 0 open and 11 suppressed findings with exit 0. Do not copy these demo decisions into a production baseline. [Baseline format and precedence](CLI.md#finding-baselines).

## Compatibility invocations

Installed `invarune` and `ai-security-scan` accept the same flags and produce the same static reports as `invscan`. From a checkout, the original `python3 scan.py` and `python3 -m ai_security_scan` routes remain available. On Windows use `py -3` for those compatibility routes. The installed CLI works from any directory; target/config/report paths remain relative to the current directory.

## Reproduce the quickstart validation

The [executed 53-step quickstart receipt](../benchmarks/quickstart-v012/README.md) records command exits, fixture counts, package versions, and exact source-file hashes, including the new explorer commands. The validator creates a fresh local Git clone with explicitly selected current-checkout files overlaid, installs them in a new temporary environment, and runs the installed commands from outside the checkout. It verifies all three installed aliases, focused help, example output, catalog commands, baseline acceptance and actual PDF form editing and fresh import for both source and image scans, plus all six HTTP adapters through local fixture endpoints.

```sh
python3 scripts/validate_quickstart.py --output test-output/quickstart
```

On Windows use `py -3` in place of `python3`. Git and Python 3.9+ must be available; installation can download build, optional AI and PDF packages. The script deletes its temporary clone and environment after the run, and retains the receipt at the selected output directory. Use `--skip-pdf` or `--skip-gateway` to record explicitly narrower coverage. Each invocation replaces only `receipt.json` and `README.md` in that output directory.

Fixture success validates these workflows. It does not measure production detection accuracy, perform a real provider login, test a live model, or establish behavior on a platform absent from the receipt. See [detector accuracy and known mismatches](RULE_ACCURACY.md) and [actual CLI provider validation](CLI_PROVIDER_RESEARCH.md) for those separate results.

## Help and next steps

```sh
invscan --help
invscan --help-topic images
invscan --help-topic gateways
invscan --help-topic security
invscan --examples
invscan --explain-rule AI002
invscan --list-controls
```

| Symptom | Next step |
|---|---|
| Cannot clone | Check Git credentials and access to the private repository. |
| `invscan` not found | Activate the step-1 environment or use its installed executable: `.venv/bin/invscan` or `.\.venv\Scripts\invscan.exe`. |
| Exit 1 | Read the findings; the selected threshold was reached. |
| Exit 2 | Read stderr and coverage/review gaps; correct the input, limit or provider problem. |
| Local image missing | Check the Docker/Podman image store, supply an archive, or explicitly use `--pull`. |
| Optional CLI unavailable/signed out | Install a supported official CLI, then use Invarune's interactive login. See provider requirements above. |

Continue with the [complete CLI reference](CLI.md), [source-linked control checklist](SECURITY_CHECKLIST.md), or [real-project reports and competitor comparison](BENCHMARK_RESULTS.md).
