# Actual v0.15 bounded investigation reports

These reports come from the installed `invscan` 0.15.0 wheel, executed outside the checkout. The final implementation is `02c1a309226db622fe6ab86ae72b3c652e370d2faae3876b7ec64049d8f5e1c5`; [package, tests and workflow receipts](../../../benchmarks/validation-v015/README.md) bind the release inputs. Source and targets were never imported or executed. The model remained advisory.

## Start with the result

| Run | Selected source / control | Actual result |
|---|---|---|
| [Deterministic context example](context-static/report.html) | Two authored fixture files; EXEC-05 | 0 static matches, 0 analysis errors, model disabled, exit 0. Cross-file context remains outside complete static propagation; no match is not a safety pass. |
| [Live Codex context investigation](context-codex/report.html) | The same files and control | 1 evidence round, 1 requested range served, 2/2 structured check answers: 1 potential gap and 1 insufficient-evidence answer. Static results unchanged; exit 0. |
| [Live Codex public MCP filesystem investigation](reference-filesystem-codex/README.md) | Nine pinned reference-server files; EXEC-04 | 2 evidence rounds, 15 ranges served, 2/2 structured answers: 1 potential gap and 1 insufficient-evidence answer. Original 0 findings and 1 unsupported-callback coverage gap remain; exit 2. See the full source/receipt explanation. |

Each run includes JSON, HTML, Markdown, SARIF and a fillable PDF. Model concerns and missing runtime evidence are separate from static findings. Answer coverage of 100% means two requested checks received answers; neither control was certified. The source fixture was authored to demonstrate missing cross-file context and is not independent accuracy ground truth. The public-source model's interpretation is not a verified vulnerability disclosure or production true-positive measurement.

## Inspect every format

| Run | Reports and actual invocation |
|---|---|
| Deterministic fixture | [PDF, 15 pages](context-static/report.pdf) · [HTML](context-static/report.html) · [Markdown](context-static/report.md) · [JSON](context-static/report.json) · [SARIF](context-static/report.sarif) · [run receipt](context-static/run-receipt.json) |
| Codex fixture | [PDF, 22 pages](context-codex/report.pdf) · [HTML](context-codex/report.html) · [Markdown](context-codex/report.md) · [JSON](context-codex/report.json) · [SARIF](context-codex/report.sarif) · [run receipt](context-codex/run-receipt.json) |
| Codex public source | [PDF](reference-filesystem-codex/report.pdf) · [HTML](reference-filesystem-codex/report.html) · [Markdown](reference-filesystem-codex/report.md) · [JSON](reference-filesystem-codex/report.json) · [SARIF](reference-filesystem-codex/report.sarif) · [execution details](reference-filesystem-codex/README.md) |

The context PDFs have two bound review items and ten editable fields each. Their embedded reports, canonical field trees, widgets, appearances, navigation, five-format review workspaces and all rendered pages were checked. [Context PDF receipt](../../../benchmarks/validation-v015/context-pdfs-receipt.json). A recorded justification remains a user disposition and receives no pass credit; [review workflow](../../../docs/REVIEW_WORKFLOW.md).

## What the context investigator actually did

The deterministic seeds showed a caller-selected address passed into `dispatch` and a request using that address, but omitted the predicate body. Codex requested `delivery.py` lines 13–41 through its captured file ID. The request explicitly sought destination constraints, URL parsing, IP/DNS validation and counterevidence for lane 1. The controller served 324 characters, from the unchanged snapshot only. One final conclusion call followed.

The model cited `_admit`: lane 1 accepts the supplied destination, while lane 0 uses a fixed address. It also considered disabled redirects as a protective feature, without treating that as an original-destination restriction. It proposed destination-policy enforcement and authorized isolated tests. Whether the fixture represents an exposed tool, and whether deployed network defenses constrain it, remain unverified. Check 2 remained insufficient evidence because no runtime attack tests were supplied.

The fixture review made three actual calls: one finding-triage request and two control-stage calls. All three used actual Headroom; evidence payloads totaled **13,488 → 13,060 bytes**, saving 428 bytes. This excludes system instructions, schemas and provider envelopes. Model tokens, billed costs and accuracy gains were not measured.

## Reproduce with the CLI

Install the [quickstart](../../../docs/QUICKSTART.md) environment with `.[ai,pdf]`, and use the already installed official Codex CLI. Interactive runs can launch its official login; these recorded noninteractive runs used `--judge-login never` and an existing authenticated session.

```sh
invscan examples/investigation/context-tools --scans EXEC-05 \
  --report ./context-static --pdf

invscan examples/investigation/context-tools --scans EXEC-05 \
  --judge-cli codex --judge-login never --judge-timeout 300 \
  --analyst-batch-size 1 --analyst-max-calls 3 \
  --analyst-time-budget 900 --analyst-investigation-rounds 2 \
  --report ./context-codex --pdf
```

No model is required for the first command. The second sends bounded, redacted source to the selected provider. Model outputs, ranges, timing and receipt hashes may differ between executions. For the public code, first reproduce the pinned source export in the [benchmark instructions](../../../benchmarks/comparison-v015/README.md), then follow its report-specific command.

## Earlier executions are retained

The earlier implementation `525747fc...` had identical detector/evidence algorithms but did not expose advisory outcome counts in the opening PDF/HTML summary. After fixing those two renderers, the CLI was rebuilt and both live investigations were run again. Earlier artifacts remain unchanged: [context static JSON](earlier/context-static-525747fc/report.json), [context Codex JSON](earlier/context-codex-525747fc/report.json), and [public filesystem Codex JSON](earlier/reference-filesystem-codex-525747fc/report.json). Each directory retains its five report formats and execution receipt. The earlier context request served 92 characters; the final request served 324. This variation is a real example of nondeterminism, not an additional detection-accuracy trial.

Claude was not used for these completed runs. The [historical Claude authentication failure](../v014/skills-claude/report.json) is retained and is not represented as a successful Claude assessment.
