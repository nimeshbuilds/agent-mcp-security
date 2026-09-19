# Invarune quick start

**NimeshBuild · Evidence for agent security**

Get your first report, then add image scanning, optional AI review or accepted exceptions. These examples target **Invarune 0.10.0**. Deterministic scans need **Python 3.9+**, with no Python packages, API keys or model subscription. PDF export/import uses optional Python packages.

## 1. Get your first report

Clone this private repository using Git credentials that have access:

```sh
git clone https://github.com/nimeshbuilds/agent-mcp-security.git
cd agent-mcp-security
python3 scan.py examples/safer --output ./scan-report/quickstart-safer
```

Already have the checkout? Run the last command from its directory. On Windows, replace `python3` with `py -3`; check that it selects Python 3.9 or newer with `py -3 --version`. The single-line scan commands also work in PowerShell.

Expect **2 scanned files, 0 findings, 0 coverage gaps and exit 0**. Open `scan-report/quickstart-safer/report.html` using your file manager, or read `report.md`. No model was called and no target code was executed.

To see findings and remediation guidance:

```sh
python3 scan.py examples/vulnerable --output ./scan-report/quickstart-vulnerable
```

Expect **11 open findings and exit 1**. This is the intended findings gate, not a scanner crash. The deliberately unsafe fixture is inspected as text, never run. [Preview its published report](../examples/reports/vulnerable/report.md).

## 2. Scan your code or built image

Replace the placeholder with your agent or MCP server's local directory. Keep reports outside the assessed directory when possible:

```sh
python3 scan.py "/absolute/path/to/agent-or-mcp-repo" --output ./scan-report/my-agent
```

For a built **Linux container image**, choose one route; no separate source checkout is needed:

```sh
# Docker-save or OCI tar archive: no container runtime needed to scan it.
python3 scan.py --image-archive ./agent-image.tar --output ./scan-report/my-image

# Existing local Docker image: Docker and its daemon must be available.
python3 scan.py --image my-agent:latest --output ./scan-report/my-image
```

Try the included archive without installing Docker or Podman:

```sh
python3 scan.py --image-archive examples/images/demo-agent.tar --output ./scan-report/quickstart-image
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
python3 scan.py "/absolute/path/to/agent-or-mcp-repo" --fail-on medium --summary-json --output ./scan-report/ci
```

`--fail-on none` removes only the findings gate; failures and incomplete scans still return 2. [Full report interpretation](REPORTS.md).

## 4. Add AI review, optionally

Without `--judge-cli` or `--judge-config`, both model-review stages stay **off**. The deterministic scan and all four reports still work.

For an already installed official **Codex, Claude Code or Grok Build** CLI, use its CLI-managed login instead of configuring a separate API key in Invarune:

```sh
python3 scan.py "/absolute/path/to/agent-or-mcp-repo" --judge-cli codex --judge-timeout 120 --analyst-time-budget 600 --output ./scan-report/ai-review
```

Replace `codex` with `claude` or `grok` to choose that provider. Invarune selects its review model automatically; `--judge-model MODEL` overrides it. Interactive scans launch the official login when needed and resume after successful sign-in. You complete any browser/device authorization. To sign in without scanning:

```sh
python3 scan.py --login claude
```

Unattended, quiet and JSON-summary runs never prompt. Add `--judge-login never` to make that explicit. The official CLI must already be installed; account access and usage limits apply. Grok profiles must pass extension inspection. [Requirements, defaults and actual provider validation](CLI_PROVIDER_RESEARCH.md).

**Enabled review defaults to full mode:** finding triage plus every active control/check, including controls with no findings. It sends bounded, redacted source excerpts to the selected service. A normal full catalog needs 11 control requests plus finding triage. Budgets or missing answers can leave an explicit incomplete result. Redaction is best-effort; enable review only for evidence you may send to that service.

For a smaller, findings-only review:

```sh
python3 scan.py "/absolute/path/to/agent-or-mcp-repo" --judge-cli codex --judge-mode findings --output ./scan-report/findings-review
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
python3 scan.py "/absolute/path/to/agent-or-mcp-repo" --judge-config ./judge.json --analyst-time-budget 600 --output ./scan-report/gateway-review
```

This example requires a Chat Completions-compatible endpoint. Other native protocols and custom JSON gateways use different configurations: [adapter guide](JUDGE.md), [example files](../examples/judges/).

## 5. Record accepted exceptions

Create a trusted review JSON file with your own evidence and reasons, then select it with `--review-config`. To try the shipped example on the demo:

```sh
python3 scan.py examples/vulnerable --review-config examples/review-config.json --output ./scan-report/quickstart-reviewed
```

Expect **9 open, 1 justified and 1 disabled finding**, with exit 1 because other high findings remain. The example reasons are illustrative; replace them with actual reviewed decisions before using a policy on your system.

**Justified** and **disabled** items remain visible and contribute neither a pass nor a failure to active counts. Checklist exceptions do not automatically waive mapped rule findings. Policies never load automatically from target code, and exceptions cannot hide scan errors. [Schema and precedence](REVIEW_CONFIGURATION.md).

## 6. Review a report, then scan again

Every new operational report carries the same review fields. In HTML, enter a decision, reason and reviewer, then click **Download reviewed HTML**. JSON, Markdown and SARIF expose the same fields in their review capsule. Use `needs_runtime_validation` when deployment testing is still required; use `justified` only to record your accepted exception.

```sh
python3 scan.py examples/vulnerable --review-report ./reviewed-report.html --output ./scan-report/final
```

For a fillable PDF, install the extra in a virtual environment and generate it. Run from the checkout. Create `.venv` only if you have not already created it for this project; choose another environment name if that path belongs to something else.

macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[pdf]'
.venv/bin/python scan.py examples/vulnerable --pdf --output ./scan-report/pdf-review
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install '.[pdf]'
.\.venv\Scripts\python.exe scan.py examples/vulnerable --pdf --output ./scan-report/pdf-review
```

The vulnerable fixture intentionally returns exit 1. Fill `scan-report/pdf-review/report.pdf` in an AcroForm-compatible editor and save a separate copy as `reviewed-report.pdf` in the checkout. Preserve its fields and attachments; do not print or flatten it. Then run the command for your platform:

```sh
.venv/bin/python scan.py examples/vulnerable --review-report ./reviewed-report.pdf --pdf --output ./scan-report/final-pdf
```

```powershell
.\.venv\Scripts\python.exe scan.py examples/vulnerable --review-report ./reviewed-report.pdf --pdf --output ./scan-report/final-pdf
```

Always select the fresh source/image target explicitly and use a new output directory. Matching decisions are applied individually; changed evidence leaves decisions unapplied. A justification is recorded as **justified**, never as a verified pass. Explicit pending runtime/human decisions return exit 2. Model review stays off unless you enable it again. [Field definitions, format limits and complete workflow](REVIEW_WORKFLOW.md).

## 7. Install the shorter command, optionally

Direct script usage needs no installation. To use `invarune` from another directory, install this checkout in a virtual environment. If you installed the PDF extra above, the command is already installed: skip environment creation and installation here. Otherwise, create a new environment or reuse this project's existing `.venv`.

macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
. .venv/bin/activate
invarune --help
```

Windows PowerShell, without requiring environment activation:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\invarune.exe --help
```

Installation may download build tooling. With the environment active, replace `python3 scan.py` above with `invarune`. Otherwise, use the installed executable's absolute path, or give Python the absolute path to this checkout's `scan.py`.

## Reproduce the quickstart validation

The [executed quickstart receipt](../benchmarks/quickstart-v010/README.md) records command exits, fixture counts, package versions, and exact source-file hashes. The validator creates a fresh local Git clone with explicitly selected current-checkout files overlaid, installs them in a new temporary environment, and runs the installed commands from outside the checkout. It checks actual PDF form editing and fresh import for both source and image scans, plus all six HTTP adapters through local fixture endpoints.

```sh
python3 scripts/validate_quickstart.py --output test-output/quickstart
```

On Windows use `py -3` in place of `python3`. Git and Python 3.9+ must be available; installation can download build/PDF packages. The script deletes its temporary clone and environment after the run, and retains the receipt at the selected output directory. Use `--skip-pdf` or `--skip-gateway` to record explicitly narrower coverage. Each invocation replaces only `receipt.json` and `README.md` in that output directory.

Fixture success validates these workflows. It does not measure production detection accuracy, perform a real provider login, test a live model, or establish behavior on a platform absent from the receipt. See [detector accuracy and known mismatches](RULE_ACCURACY.md) and [actual CLI provider validation](CLI_PROVIDER_RESEARCH.md) for those separate results.

## Help and next steps

```sh
python3 scan.py --help
python3 scan.py --explain-rule AI002
python3 scan.py --list-controls
```

| Symptom | Next step |
|---|---|
| Cannot clone | Check Git credentials and access to the private repository. |
| `scan.py` not found | Run from this checkout or use the absolute script path. |
| Exit 1 | Read the findings; the selected threshold was reached. |
| Exit 2 | Read stderr and coverage/review gaps; correct the input, limit or provider problem. |
| Local image missing | Check the Docker/Podman image store, supply an archive, or explicitly use `--pull`. |
| Optional CLI unavailable/signed out | Install a supported official CLI, then use Invarune's interactive login. See provider requirements above. |

Continue with the [complete CLI reference](CLI.md), [source-linked control checklist](SECURITY_CHECKLIST.md), or [real-project reports and competitor comparison](BENCHMARK_RESULTS.md).
