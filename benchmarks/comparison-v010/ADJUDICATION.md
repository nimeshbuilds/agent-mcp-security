# Blinded advisory review and measured uncertainty

The [actual Claude attempt](adjudication-live/model-adjudication.json) produced **no model judgments**. The installed official Claude CLI version 2.1.214 was invoked once on 19 September 2026 with the requested `opus` model and high effort. It returned an authentication error in 0.892 seconds. No sign-in was launched and the remaining 19 batches were not invoked. All 153 selected observations remain unknown. A real-project likely-TP percentage is **unavailable**, not 0%. The 0..100% bounds in the receipt describe unresolved uncertainty, not measured precision.

The [preparation receipt](adjudication-prepared/preparation.json) successfully accounts for 153 source observations in 20 bounded batches. The failed first batch contains 8 observations; 145 observations were never submitted after the authentication failure. These results must not be described as 153 failed model judgments, successful expert analysis, or confirmed vulnerabilities. The CLI rejected authentication before any valid analyst response existed. Its 785-byte response remains private; the public call audit records its SHA-256.

## What was selected and blinded

The [frozen selection](adjudication-selection.json) predates any model outcomes and includes 120 exact source spans, representing 153 observations: 28 Invarune, 27 Semgrep, 95 Bandit and 3 Gitleaks. It covers all 101 observed tool/project/family strata. It is a purposive diagnostic sample; no population precision or recall is inferred from it.

The selection is bound by canonical SHA-256 to [its original ledger](observations-selection-v1.json). The current [review ledger](observations.json) contains Invarune 0.10.0. Preparation checks every selected project's commit, source manifest, path, line span, rule, tool and family against the frozen original. A scanner version may change only while those selected observation identities remain unchanged. Both the original selection and final review ledger digests are retained in receipts. Historical 0.9.0 results remain available separately.

Each request contains an opaque case ID, a benchmark-authored security predicate, the candidate span and redacted source evidence. Tool names, tool severities, native rule IDs, scanner agreement, original messages, repository names and file paths are withheld. Source text can inherently identify a framework; this is not a claim of perfect anonymity. Tool metadata is attached to the normalized audit only after validating model output. The benchmark-authored predicates retain applicability caveats: an import, assertion, serialization operation, non-security hash/randomness use or intentional dangerous capability does not by itself establish exploitable impact.

## Evidence handling and execution restrictions

The harness reads pinned regular files through the scanner's confined read helper. It rejects traversal, visible symbolic links, changed file bytes/hashes, oversized files and invalid spans. On platforms without directory-descriptor confinement, the helper has a documented concurrent-filesystem limitation. SHA-256 checks still verify the offered bytes against the pinned source manifest.

Defaults allow at most 20 MB per selected source file, 100 complete offered lines and 12,000 characters per case, with 12 lines of context and 8 cases per 150 KB batch. No partial source line is offered. Truncation and incomplete candidate spans are explicit. Credential/key redaction preserves source line numbering. Redaction is best effort; it can remove context, and the analyst must retain uncertainty when that happens. No target code, dependency hook, MCP server or exploit is executed.

The trusted installed official Claude CLI runs in an empty temporary working directory with tools disabled, an empty strict MCP configuration, `dontAsk` permissions, safe mode, disabled session persistence, no Chrome, no slash commands and empty setting sources. The adapter uses bounded I/O and deadlines, validates the official result envelope and rejects tool activity. Authentication stays with the official CLI; the harness never launches login. These restrictions are not an OS sandbox and do not protect against a malicious installed CLI or administrator policy.

By default, private case maps, bounded evidence payloads and raw model responses live under ignored `tmp/comparison-v010/`, with directory 0700/file 0600 permissions where supported. Existing private files are tightened to 0600 and symbolic-link file/directory targets are rejected. Keep any custom private-output directory outside published artifacts. Published artifacts contain hashes, bounded redacted diagnostics and validated likelihood judgments rather than raw responses, full source, credentials or host paths.

## Judgment contract and metrics

Only four verdicts are accepted:

- `likely_true_positive`: the offered evidence supports the stated security concern and applicability; this is an advisory model label.
- `likely_false_positive`: the offered context contradicts the concern or establishes a non-security/placeholder use.
- `needs_runtime_validation`: reachability, deployment, authorization, trust boundaries or runtime safeguards remain decisive.
- `insufficient_evidence`: bounded or redacted source cannot resolve the predicate.

Every answer must match an offered opaque case ID and the strict JSON fields. A likely-positive or likely-negative verdict requires at least one citation with the exact evidence ID, offered source line bounds and an exact quote present within those redacted lines. Missing, duplicated, unsupported or invalid answers remain unknown; they are never silently promoted to positive or negative labels. Authentication failure stops all remaining model calls. Other execution/response errors are recorded per batch.

For a successful future review, the receipt separately reports:

- Likely TP divided by likely TP plus likely FP, with the exact adjudicable denominator.
- Likely TP divided by all valid model answers, alongside runtime-validation and insufficient-evidence counts.
- Every error/unattempted observation, total selected coverage and conservative bounds assigning unresolved observations either negative or positive.

Point estimates are null when no TP/FP assessment was made. Dry-run fixture mode exposes no model precision summary at all. These likelihoods cannot be called independently evidence-reviewed true positives, confirmed exploitation or a population estimate. Tool agreement alone is never a TP label.

## Reproduction

Preparation is deterministic and makes no model call:

```bash
python3 scripts/adjudicate_scanner_findings.py --prepare-only
python3 scripts/adjudicate_scanner_findings.py --help
python3 -m unittest discover -s tests -p test_benchmark_adjudication.py
```

The fixture mode validates the pipeline without invoking a model. Choose separate output directories so synthetic results cannot be confused with actual model output:

```bash
python3 scripts/adjudicate_scanner_findings.py --dry-run \
  --output tmp/comparison-v010/adjudication-dry-run-audit \
  --private-output tmp/comparison-v010/adjudication-dry-run-private
```

A future explicitly authorized live run requires an already authenticated official Claude CLI. Use a fresh private directory to preserve any previous raw response, and a new published output directory to retain historical attempts:

```bash
python3 scripts/adjudicate_scanner_findings.py --judge-cli claude --loginnever \
  --model opus --timeout 180 \
  --output benchmarks/comparison-v010/adjudication-new-attempt \
  --private-output tmp/comparison-v010/adjudication-new-attempt
```

The published attempt used the same command with the `adjudication-live` directories and a 60-second timeout. It did not trigger or complete an interactive login. A later harness hardening retained the official adapter's default nonzero-exit authentication checks so stderr-only authentication errors also stop safely; no second live request was made after the failed attempt.

Post-attempt validation also corrected physical source-line handling and process exit status. CRLF and CR normalize to LF; Unicode separators inside source strings or comments do not create invented source-line numbers. The CLI returns exit 2 for incomplete preparation, synthetic validation, or requested live review, including authentication and missing/invalid-answer errors. Complete preparation and fully answered review return exit 0; a valid runtime-validation or insufficient-evidence answer is a completed answer, not an operational failure. Expected input errors produce a sanitized diagnostic without a traceback. All **18 harness tests** pass, including source-line coordinates, confined reads, citation rejection, private output handling and failure-stop behavior. These later fixture checks are not additional live model attempts and do not create model judgments for the preserved attempt.

The separate [shared API-pattern fixtures](external-results/shared-pattern-fixtures.json) are the only cross-tool labeled TP/TN measurements in this benchmark. Each of Invarune, Semgrep and Bandit matched five positive and five negative development fixtures. Those labels establish ten API-pattern assertions, not real-project vulnerability truth. No fresh real-project scan in this experiment has a confirmed-TP percentage.
