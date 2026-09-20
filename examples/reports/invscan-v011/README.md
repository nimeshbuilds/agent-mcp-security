# Invarune 0.11: installed invscan, actual Codex and Headroom

This is a **new actual scan** of the deliberately vulnerable fixture through the installed `invscan` wheel, run outside the checkout. It includes the revised PDF/HTML layout, exact fixes, AI/MCP relevance and editable review fields.

- **11 deterministic findings** remain open (8 high, 2 medium, 1 low); exit **1** is the finding gate.
- Actual Codex 0.154.0, requested `gpt-6-astra` with high effort, reviewed **2 selected findings** and returned **3 additional concerns**. All five received structured proposed actions. These are unverified model judgments.
- **9 findings were outside the cap.** Control review was not requested (`findings` mode); this is not a full AI assessment or a Claude review.
- Actual default **Headroom 0.37.0** preserved every evidence value: **3,558 → 3,430 bytes**, 128 fewer evidence-JSON bytes. Token counts and billed savings were not measured.
- All deterministic findings, controls, files, coverage, remediation, tool metadata and scan ID match the [AI-disabled scan](../v011/source/report.json). SARIF matches byte for byte.

[Fillable PDF](report.pdf) · [HTML](report.html) · [Markdown](report.md) · [JSON](report.json) · [SARIF](report.sarif).

The PDF opens with a linked priority table, puts findings before the detailed methods and rule inventory, links each finding to mitigating layers and review fields, and presents configuration, model coverage, optimization receipts and user-decision audit in readable sections. Editable fields stay distinct from verified passes. Save a reviewed copy and select a fresh target explicitly when importing it.

Reproduce after installing the CLI and `.[ai,pdf]`, with an authenticated official Codex CLI:

```sh
invscan examples/vulnerable --judge-cli codex --judge-login never --judge-mode findings --judge-max-findings 2 --judge-timeout 180 --judge-include-source --pdf --output ./scan-report/live-codex
```

Expected exit is 1 if the static fixture remains unchanged; model output can differ. Use `--judge-mode full --analyst-time-budget 600` to request active control review as well; budgets and missing answers remain explicit. Claude still requires official account authorization in this environment.

[Executed provider receipt](../../../benchmarks/validation-v011/live-provider-receipt.json) · [New validation evidence](../../../benchmarks/validation-v011/README.md).
