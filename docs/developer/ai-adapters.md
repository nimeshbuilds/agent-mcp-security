# Optional AI adapters and evidence handling

AI review adds advisory interpretation to a completed deterministic scan. The surrounding selection, budgets, parsing and citation checks are deterministic; the model judgment is not. Temperature zero, a seed or a fixed prompt does not make the service reproducible or establish the truth of an assessment.

Use the [judge configuration guide](../JUDGE.md) for endpoint examples and the [analyst guide](../ANALYST.md) for the full output protocol. This page explains where to extend the implementation safely.

## Trace a request

```text
fresh static report + explicit user dispositions
  |
  +-- cli.judge_payload --> judge.review --> finding assessments
  |
  +-- evidence.build_evidence --> analyst.run_analyst
                                  |
                                  +-- judge.review_controls
                                        |
                                        +-- validated snapshot range request
                                        |       --> EvidenceInvestigation.retrieve
                                        |       --> next bounded review call
                                        |
                                        +-- check assessments + exact citations
```

`--judge-config` or `--judge-cli` explicitly enables review. Full mode performs finding triage and then reviews every active selected acceptance check, including a zero-finding scan. Findings-only mode performs the triage stage. Static findings, severity, user exceptions and finding gates remain unchanged; failed or incomplete optional review has a separate exit-2 path.

Finding triage normally sends selected open findings with redacted evidence and minimized metadata. `--judge-include-source` adds neighboring source for that stage. Full control review independently collects bounded source excerpts, so the absence of that flag does not mean full mode sends no source. User rationales are local audit data and must not become model instructions or evidence.

## Supported transport boundaries

[`judge.py`](../../ai_security_scan/judge.py) contains `_validate_config()`, `_build_request()`, `_post_json()`, `_extract()`, `review()` and `review_controls()`. Its HTTP protocols are `openai_chat`, `openai_responses`, `anthropic`, `gemini`, `ollama` and `custom`. [`cli_judge.py`](../../ai_security_scan/cli_judge.py) implements `codex_cli`, `claude_cli` and `grok_cli` through `validate_cli_config()`, `probe_auth()`, `login_cli()` and `run_cli()`.

HTTP adapters use the exact configured endpoint; they do not append a guessed path. Custom requests are synchronous JSON-over-HTTP POST, with a JSON request template and a dotted response path. Template placeholders are expanded once. Repository text containing `${ENV:NAME}` remains literal rather than triggering a second environment lookup.

The transport disables redirects, automatic HTTP retries, implicit proxies, cookies and compressed response bodies. Remote plaintext HTTP needs explicit opt-in; loopback HTTP supports local test servers. Only explicitly named environment variables supply credentials. Preserve request/response byte bounds, HTTPS validation and sanitized `JudgeError`/`JudgeAuthenticationError` failures. Do not put raw provider bodies or exception strings into diagnostics.

These adapters do not cover every API shape. Signing, OAuth acquisition/refresh, mTLS, streaming-only protocols, multipart/binary requests and asynchronous polling need a compatible gateway or an additional adapter. A custom gateway can also run hidden server-side tools: client-side no-tools validation cannot establish what its operator executes.

## Extend a protocol in reviewable steps

1. Define strict accepted configuration keys, endpoint/authentication semantics and bounded defaults. Extend the relevant validator before adding request construction. Do not accept arbitrary executable arguments or an opaque unvalidated transport object.
2. Map finding triage, one-shot control review and bounded investigation to the protocol's text/schema envelope. Preserve instructions, evidence and output schema. Reject configured tools and provider tool-call objects. The investigation loop accepts only the explicit evidence-request JSON contract, not arbitrary actions.
3. Extract only the expected assistant text or structured assessment. Handle incomplete, refused, malformed, duplicated and oversized output explicitly. Provider reasoning or tool-call objects are not assessment text.
4. Feed the result through the existing stage normalizer. Do not return provider JSON directly as report findings or check statuses.
5. Add synthetic request/response tests and a real loopback or controlled subprocess exchange. Verify exact evidence, credential routing, time/byte failures and unchanged static gates. A mocked constructor alone does not validate transport behavior.
6. Update configuration examples, help, protocol documentation and provenance versions with the release owner. A live account check is separate, explicit validation, not a prerequisite for routine unit tests.

Start with [`examples/judges`](../../examples/judges/) and [`test_judge_integration.py`](../../tests/test_judge_integration.py). The generic adapter may already support the API without adding a new provider branch.

## Evidence selection and the bounded investigation loop

[`evidence.build_evidence()`](../../ai_security_scan/evidence.py) reads only valid scanner-manifest entries through confined reads and verifies their recorded hashes. Sensitive paths, exclusions, changed bytes, invalid paths, substituted symlinks and unavailable text produce explicit omissions. It never follows a model-supplied path or fetches an `evidence_ref` URL.

Seed retrieval is a deterministic keyword/finding heuristic over bounded local context. It can miss callers or deployment configuration; a selected excerpt is not the entire repository. Seed caps are 240 excerpts, 12 lines and 2,000 characters each, and four per control. When investigation is enabled, seed selection receives half the overall excerpt-character budget, leaving capacity for requested context.

`build_evidence(..., snapshot_store=...)` captures verified, redacted lines in memory. `EvidenceInvestigation` offers opaque file IDs derived from each original path and source hash. Its inventory contains paths, line counts and lexical definition hints, with fixed bounds of 200 files, 32,000 serialized characters and 12 hints per file. It is not a symbol resolver or call graph. Files omitted during collection or inventory construction cannot later be requested by the model.

`judge.review_controls()` selects protocol version `1.2.0` investigation instructions when the payload contains `investigation`. `_investigation_inventory()` validates offered identities; `_normalize_investigation()` accepts either final assessments or up to eight evidence requests. Each request names a current control/check, listed file ID and a range of at most 80 lines, plus `purpose`, `reason` and mandatory `counterevidence` to seek. The controller returns at most 4,000 excerpt characters per request and allows 128 requests across the run. It cannot open a path, fetch a URL, import code or execute a tool in response to the model.

`EvidenceInvestigation.retrieve()` serves the captured snapshot only. It does not reread changed disk contents. Unknown IDs, invalid ranges and unsupported output fields fail protocol validation; duplicates across rounds and exhausted source-character budgets produce explicit denial receipts. Seed and requested excerpts share the overall character budget. Shared identical excerpt IDs consume it once; overlapping but distinct excerpts consume their retained characters separately.

The controller appends accepted excerpts only to the requesting control's evidence allowlist, preserving exact-citation checks. It resubmits the batch with updated evidence and prior request receipts. Prompts require a concrete risk hypothesis, trust boundary, counterevidence and explicit unresolved limits. This helps investigate zero-hit controls and parser gaps without resolving the original static coverage error or converting model interpretations into confirmed findings.

`analyst.validate_limits()` and `run_analyst()` enforce these default control-stage budgets:

| Budget | Default | Meaning |
|---|---:|---|
| Control requests | 36 | Includes evidence requests, final answers and authentication retries; finding triage is additional. |
| Controls per batch | 6 | Stable batching of active checks; original check indices are retained. |
| Investigation rounds | 2 | Range-request rounds per batch, configurable 0–3; zero retains one-shot control review. |
| File attempts | 200 | Candidate evidence reads, not a guarantee of 200 usable files. |
| Source I/O bytes | 2,000,000 | Charged reads include failed attempts and growth-detection reservations. |
| Retained excerpt characters | 120,000 | Combined seed and requested source excerpts, excluding inventory metadata. |
| Scheduling time | 600 seconds | Bounds scheduling/per-request time; not a hard process deadline. |

`bytes_read` and `bytes_charged` are different metrics. A failed read conservatively charges its attempted size plus a sentinel; do not change reporting to make failed I/O appear free. Zero source budgets leave evidence unavailable; they do not produce a source-supported pass.

The first failed control batch stops subsequent requests, preserves previous advice and leaves unanswered checks visible. Explicit authentication recovery can retry within the request budget, with login time handled separately. DNS/socket blocking can overrun the scheduling deadline. Describe these limits accurately rather than promising a wall-clock or billing cap.

Before authorizing an evidence expansion, `run_analyst()` reserves a conclusion call for the current batch and each remaining batch. Reevaluate authorization after a counted authentication retry, retaining the retry payload digest. This prevents an early batch from consuming the call budget intended for later controls. It cannot guarantee completion against time exhaustion or provider failure. Immediate answers for 66 controls use 11 control calls; two evidence expansions per batch use 33. The maximum budget is not the actual usage count.

## Normalize judgments without converting them to proof

Finding triage accepts only known, unique finding IDs and permitted verdicts. Omitted assessments receive `needs_review` placeholders. Control review checks exact fields, known control IDs, original check indices, allowed statuses and citations; omitted checks remain `insufficient_evidence`.

Grounded check statuses require an exact substring quote from an excerpt assigned to that control. Deterministic code supplies paths and line coordinates. This prevents fabricated quote/location pairs, but does not prove the model interpreted a real quote correctly. A `supported_by_code` response for a dynamic control is downgraded to `needs_runtime_validation`; a manual control becomes `needs_human_review`.

Prompts request recommended actions, but response validators permit their omission. `advice_coverage` distinguishes actual assessments/actions from omitted placeholders. Preserve those denominators when changing reports. No model status creates a validated control pass, removes a static finding or authorizes remediation execution.

The optional check-level `analysis` object has exactly four nonempty fields: `risk_hypothesis`, `boundary`, `counterevidence` and `conclusion_limits`, each at most 1,200 characters. CLI investigation response schemas require it and both root arrays (`control_assessments`, `evidence_requests`). HTTP/custom normalization accepts legacy final responses without the extra array or analysis, but counts only actually supplied structure in `investigation.structured_analysis_checks`. Missing structure is not an omitted check; malformed supplied structure fails validation. Keep the older `controls` CLI stage for `--analyst-investigation-rounds 0` and use `investigation` for the new schema.

`analyst.investigation` and per-request receipts retain offered/omitted inventory counts, rounds, calls, requested file/range/check identities, reason/counterevidence, served/denied status, character charges and range completeness. Receipts map compact response check indexes back to original `CONTROL:INDEX` identities. Human reports present this separately from static findings. Global and per-control provenance distinguish `model_selected_evidence_allowed` from actual served `model_selected_evidence`; do not report capability as evidence that a follow-up happened. Both remain false for a pure deterministic scan, which makes no model call.

## Official CLI isolation and its limits

Native adapters run a trusted installed executable from a private temporary working directory with a filtered environment, bounded input/output, version/capability probes and provider-specific tool/customization restrictions. Bare executable lookup excludes current-directory and relative PATH entries. Arbitrary extra arguments, relative executable paths and shell command files are rejected.

Grok additionally inspects active extensions/instructions and fails closed when they cannot be excluded. The executable, authentication store and administrator configuration remain trusted. These restrictions are not an OS sandbox. POSIX inference cleanup targets a process group; Windows cleanup currently targets the direct child. Vendor CLI token/cost caps cannot be enforced uniformly.

Keep login separate from inference. Automated/noninteractive runs must not silently open authentication flows. Use synthetic credential files and executables in adapter tests, not a contributor's real login state. [Provider research and live-validation limits](../CLI_PROVIDER_RESEARCH.md).

## Preserve lossless Headroom invariants

[`token_optimizer.optimize_payload()`](../../ai_security_scan/token_optimizer.py) returns serialized evidence JSON and a receipt. Modes are `headroom`, `compact` and `off`; enabled AI defaults to Headroom. The optional `ai` extra pins `headroom-ai==0.37.0` on Python 3.10+. Missing or incompatible Headroom, including the base Python 3.9 installation, uses an explicit built-in compaction fallback.

Only the pinned lossless JSON-minification helper is invoked. Independent validation requires the same parsed values and types, key content, array order and source/citation strings. Any lossy, invalid or larger candidate is rejected in favor of safe compaction. General summarization, evidence removal, model loading, retrieval tools and proxy interception are outside this integration.

The original request bound applies before optimization. `token_optimization` records requested/actual engine, fallback reason, byte counts and original/sent hashes. These are evidence-JSON bytes, excluding instructions, schemas and provider wrappers; they are not measured token savings or a cost promise. Never relax a budget because a request happened to compress well.

## Validate without a real model

```sh
python -m unittest tests.test_judge tests.test_judge_integration tests.test_analyst_protocol -v
python -m unittest tests.test_analyst_controller tests.test_analyst_review_policy tests.test_evidence -v
python -m unittest tests.test_analyst_investigation tests.test_cli_login -v
python -m unittest tests.test_cli_judge tests.test_cli_judge_integration tests.test_token_optimizer -v
```

[`test_full_gateway_e2e.py`](../../tests/test_full_gateway_e2e.py) exercises both stages across six HTTP protocols using a local fixture server. The [fresh quickstart validator](testing-and-releasing.md#installed-workflows) also checks installed Headroom receipts against actual captured JSON and source evidence. Neither is a measurement of model security accuracy. Preserve [adversarial protocol tests](../../tests/test_protocol_adversarial.py) when modifying no-tools, output validation or citation behavior.

[`test_analyst_investigation.py`](../../tests/test_analyst_investigation.py) covers cross-file requested citations, all HTTP/CLI adapters, malicious or stale IDs, traversal/URL requests, exact source coordinates, snapshot mutation, sensitive-file exclusions, redaction, budget denials, duplicate requests, zero sharing, conclusion reservation, authentication retries, provider failures and unchanged static results. The [inert context fixture](../../examples/investigation/README.md) supports a separately recorded live run. Authored fixture responses prove controller behavior; only the actual live receipt can show what a real model requested or concluded.
