# Actual Codex review of the MCP reference filesystem server

Invarune 0.15.0 reviewed nine pinned public implementation files for **EXEC-04** using the optional Codex investigator. The result contains **one model-reported potential gap and one insufficient-evidence answer**. The deterministic result remains **0 findings, 1 analysis coverage gap, exit 2**. These are advisory observations, not independently verified vulnerabilities, exploit proof, or measured true positives.

Read the [25-page fillable PDF](report.pdf), [HTML report](report.html), or [Markdown report](report.md). [JSON](report.json) and [SARIF](report.sarif) support tooling. The [execution receipt](execution-receipt.json) records source hashes, the installed package, invocation, actual requests, budgets, invariants, and artifact hashes. The [PDF validation receipt](pdf-validation.json) records rendering, navigation, forms, embedded data, and visual inspection.

## Scope and source attribution

The source is [`modelcontextprotocol/servers`, `src/filesystem`](https://github.com/modelcontextprotocol/servers/tree/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/filesystem), pinned to commit `d73f99efbfd40c3aa1b61e88728b3d49fb52608f`. All nine offered files were checked against the [published snapshot manifest](../../../../benchmarks/real-world/snapshots/mcp-reference.json) before and after scanning. The [export policy](../../../../benchmarks/real-world/manifest.json) excludes tests and documentation; missing test excerpts do **not** establish that upstream has no tests.

Retain the [copied upstream license notice](../../../../benchmarks/real-world/licenses/mcp-reference.txt) when using these source-derived excerpts. The [pinned upstream license](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/LICENSE) describes the project's licensing transition and applicable original licenses. The [corpus notes](../../../../benchmarks/real-world/README.md) explain attribution and selection. Upstream describes these servers as educational reference implementations, not production-ready solutions.

Only one control with two acceptance checks was selected. Target code was never imported or executed, dependencies were not installed, and the MCP server was not started. This is a real public-source advisory review, separate from the [labeled detection benchmark](../../../../benchmarks/comparison-v015/README.md).

## What actually happened

| Observation | Recorded result |
|---|---|
| Installed scanner | 0.15.0; final implementation `02c1a309226db622fe6ab86ae72b3c652e370d2faae3876b7ec64049d8f5e1c5` |
| Provider | Codex CLI 0.154.0, model `gpt-6-astra` |
| Actual calls | 1 finding-triage call and 3 control-review calls |
| Three control responses | Evidence requests, evidence requests, final conclusions |
| Bounded investigation | 2 rounds; 15 requested ranges served; 0 denied |
| Source excerpts | 34,317 additional characters; 36,310 total characters |
| Acceptance checks | 2/2 answered, with structured reasoning; 1 potential gap, 1 insufficient evidence |
| Deterministic outcome | 0 findings; 1 unsupported-callback coverage gap; exit 2 |
| Headroom 0.37.0 | Evidence payload bytes 104,391 → 102,466; 1,925 bytes saved |

Headroom byte savings exclude system instructions, response schemas, and provider envelopes. Token consumption, billed cost, and accuracy improvements were not measured. The seed-selection candidate cap was reached and is retained in the report; the subsequent bounded requests added context without claiming complete source coverage.

The model identified possible access-time path races, a check-then-rename overwrite concern, and temporary-file exclusivity or permission concerns. It considered lexical and real-path validation, schema checks, randomized temporary names, atomic rename, and exclusive creation as counterevidence. These interpretations require authorized runtime tests and deployment context before deciding whether they are exploitable. The report includes proposed fixes and validation steps, explicitly labeled as unverified model advice.

The deterministic analyzer reported that a `registerTool` callback uses complex, default, or rest parameters, leaving entrypoint analysis incomplete. AI completion did not repair this gap. Static scan identifiers, findings, controls, summary, assessment, and coverage were compared with a fresh deterministic-only run and matched exactly; SARIF was byte-identical. Five accepted citations were independently rechecked against their submitted evidence and hashes.

## Reproduce

Install the [quickstart](../../../../docs/QUICKSTART.md) environment with AI and PDF extras. Prepare the unchanged public source export using the [pinned corpus instructions](../../../../benchmarks/real-world/README.md#reproduce-the-scans), then run:

```sh
invscan tmp/real-world-src/mcp-reference/src/filesystem \
  --scans EXEC-04 \
  --judge-cli codex --judge-login never --judge-timeout 300 \
  --analyst-investigation-rounds 2 --analyst-batch-size 1 \
  --analyst-max-calls 3 --analyst-time-budget 900 \
  --report ./reference-filesystem-codex --pdf --summary-json
```

The recorded run used the installed wheel from outside the checkout and an already authenticated Codex session. For interactive login, omit `--judge-login never`. Without the `--judge-cli` option, the deterministic scanner runs on its own. Source sent to the selected provider is bounded and redacted; exact model ranges, conclusions, timing, and output hashes can vary between runs.

The [earlier execution](../earlier/reference-filesystem-codex-525747fc/execution-receipt.json) and its five reports remain unchanged. A fresh model run produced this final report after the opening summary was improved. The earlier run served 16 ranges; this run served 15. Neither execution is an independent detection-accuracy trial.

## Review and justify

The PDF has 13 bookmarks, 32 internal links, and 15 editable fields covering three review items. Its embedded report and review workspace match the JSON exactly. All 25 pages were rendered and inspected, with full-size checks of the summary, evidence, conclusions, configuration, and forms.

Use the report's review workspace to record deployment evidence, runtime validation, or a justified disposition, then follow the [report review workflow](../../../../docs/REVIEW_WORKFLOW.md) to rescan. A recorded justification is labeled as justified; it receives no pass credit and does not turn an advisory model conclusion into a proven finding.
