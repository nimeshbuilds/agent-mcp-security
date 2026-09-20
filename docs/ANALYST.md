# Invarune controlled security analyst

When optional LLM review is enabled, the scanner queues every active selected control for a security analyst review, including controls with no deterministic findings. A deterministic controller selects evidence, schedules bounded requests, checks the response schema, and verifies citations. The analyst's interpretation remains nondeterministic and advisory.

The packaged catalog currently contains **66 controls and 132 acceptance checks**. Without `--scans`, all active controls are queued because a static pattern scan cannot establish that a control is implemented correctly or effective in production. The analyst can identify code evidence, propose potential gaps, and specify the next verification steps. It cannot turn incomplete evidence into a security pass or perform runtime validation.

See the [control checklist](SECURITY_CHECKLIST.md) and [research and source mappings](RESEARCH.md) for the underlying control requirements. These are project-defined checks mapped to published guidance, not an official benchmark score or certification.

Explicit user exceptions in `--review-config` retain `justified` or `disabled` checklist entries with their reason, but remove them from model requests, active totals and omitted-answer counts. They are not passes or model verdicts. Fully exempt controls require no evidence collection or control request. A partial control sends only active check text; request receipts map compact response indexes back to the original `CONTROL:INDEX` identities. User reasons are not added to analyst prompts. Source excerpts may still discuss related topics needed for active checks. See [review configuration](REVIEW_CONFIGURATION.md).

Both review stages use the default guarded Headroom evidence-JSON optimizer when the AI extra is installed; `--token-optimizer compact` uses built-in compaction and `--token-optimizer off` retains legacy JSON formatting. The optimizer cannot omit controls, source strings or evidence fields, and cannot enable retrieval tools. Exact citations are checked against the same original evidence. Each completed control-request receipt records the actual engine, fallback and before/after payload bytes; these are not measured token or billing savings. [Configuration and limits](JUDGE.md#default-evidence-json-optimization), [upstream research](HEADROOM_RESEARCH.md).

## Run the review

Create a trusted configuration using the protocol and exact endpoint your model service supports. [JUDGE.md](JUDGE.md) documents the supported native protocols, custom JSON gateway templates, credentials, request limits, and provider-specific options. The same configuration serves finding triage and control review.

With a valid configuration and its credential environment variables already set, run from the project directory:

```bash
invscan /path/to/agent-or-mcp-repository \
  --judge-config /path/to/trusted-judge.json \
  --output ./security-report
```

`--judge-config` defaults to `--judge-mode full`. This performs one finding-triage request, followed by the bounded control analyst stage. The analyst examines all active selected checks that fit its budgets, including when the static scan reports zero findings. A request can fail, be omitted by the model, or be skipped when a budget is exhausted; every unanswered check stays visible in the report.

To retain the earlier finding-triage behavior:

```bash
invscan /path/to/agent-or-mcp-repository \
  --judge-config /path/to/trusted-judge.json \
  --judge-mode findings \
  --output ./finding-review
```

To run entirely offline, omit `--judge-config`:

```bash
invscan /path/to/agent-or-mcp-repository --output ./static-report
```

**Source transmission changes in full mode.** Full review sends bounded, redacted source excerpts selected for the controls, even without `--judge-include-source` and even when there are no findings. `--judge-include-source` controls additional neighboring source in the separate finding-triage request; it does not switch control-analyst evidence on or off. Choose an endpoint authorized to receive the repository's content.

## What the controller does

1. Run the existing deterministic scan and preserve its findings, severities, baseline suppressions, control statuses, and SARIF output.
2. Build an evidence pool from supported files already present in the scanner's manifest. Read files through confined filesystem operations, reject changed content against the manifest's SHA-256 hashes, and redact selected source.
3. Rank excerpts using packaged control terms, control titles and acceptance checks, file paths, and finding locations. Selection is deterministic for the same inputs and limits. The model does not choose files, follow links, or request additional retrieval.
4. Submit controls in stable batches. Each payload contains the acceptance checks, validation mode, source-reference URLs, static status, related rule/finding IDs, and only the excerpts selected for those controls.
5. Validate every returned control/check identity, status, explanation, verification step, citation and any proposed action guidance. Derive citation paths and line numbers locally from the submitted evidence; reject model-supplied paths or line claims.
6. Preserve accepted advice separately from the deterministic report. Fill omissions with explicit `insufficient_evidence` entries and leave runtime or human verification open.

Files with deterministic analysis errors are prioritized after files with findings. For an eligible, manifest-hash-verified file with such an error, its first bounded excerpt receives a candidate boost for each selected control, even if it contains no keyword match. This gives the analyst an opportunity to review syntax or analysis uncertainty; it does not guarantee the excerpt fits the final evidence budget. Missing, unreadable, changed or excluded files cannot supply source evidence. Original deterministic gaps remain visible and continue to make the scan incomplete even if the model offers an explanation.

Evidence selection is a bounded keyword-retrieval method. It is not whole-program analysis and can miss relevant implementations or select irrelevant context. A model can also misunderstand authentic evidence. **An exact quote establishes that text was present in a submitted excerpt; it does not establish that the interpretation is true.**

Temperature zero, fixed seeds, strict JSON, and exact citations do not make the analyst deterministic. They also do not prove resistance to prompt injection. The enforceable limits are the controller's input selection, protocol checks, tool restrictions, budgets, and separation from deterministic findings. Model advice never authorizes execution or modifies an access-control decision.

## Interpret each outcome

| Check status | Meaning | Work that remains |
| --- | --- | --- |
| `supported_by_code` | The analyst identified code that appears to support the narrow acceptance check. At least one exact citation is required. | Confirm the interpretation, applicability, surrounding call paths, deployment settings, and any runtime conditions. This is not a pass. |
| `potential_gap` | The analyst proposes a possible weakness supported by a submitted excerpt. At least one exact citation is required. | Investigate other implementation paths and verify the concern before treating it as a finding. |
| `needs_runtime_validation` | Static evidence cannot establish the required behavior. | Perform authorized runtime, adversarial, integration, or deployment testing and record the results. |
| `needs_human_review` | An accountable person or external evidence is needed. | Confirm policy, ownership, operational practice, approvals, or other evidence with the responsible owner. |
| `insufficient_evidence` | Submitted material cannot support an assessment, or the model never assessed the check. | Collect missing evidence and investigate collection limits, retrieval misses, or omitted responses. |
| `not_applicable_proposed` | The analyst proposes that the check does not apply, with at least one exact citation. | Have the owner confirm scope and record the justification. The check is not automatically waived. |

For a catalog control marked `dynamic`, a model response of `supported_by_code` is deterministically changed to `needs_runtime_validation`. For `manual`, it becomes `needs_human_review`. The report records the original and adjusted status and the adjustment reason. Code support for `static` or `hybrid` controls remains advisory; it never establishes full control completion.

Control-level `review_status` means `reviewed` when the model supplied every active check, `partial` when it supplied some, or `not_reviewed` when it supplied none. A reviewed control may contain only `insufficient_evidence` answers. Overall analyst status `completed` means every active check received an accepted answer; it does not mean the controls passed. `validation_established` remains false, and `coverage.validated_controls` remains zero.

## Budgets and incomplete work

The CLI exposes these control-analyst limits:

| Flag | Default | Allowed range | What it bounds |
| --- | ---: | --- | --- |
| `--analyst-max-calls` | 12 | 0–100 | Control-review request attempts; finding triage uses one additional request. |
| `--analyst-batch-size` | 6 | 1–20 | Controls submitted per control-review request. |
| `--analyst-max-files` | 200 | 0–20,000 | Eligible manifest file read attempts for evidence collection. |
| `--analyst-max-bytes` | 2,000,000 | 0–50,000,000 | Conservative source I/O charge, including failed-read reservations and bytes later rejected because their hash changed. |
| `--analyst-max-chars` | 120,000 | 0–1,000,000 | Unique retained redacted excerpt characters, excluding metadata. |
| `--analyst-time-budget` | 180 seconds | Greater than 0, at most 3,600 | Scheduling budget for evidence collection and the control-review stage. |

With 66 controls and a batch size of 6, a complete run normally uses **11 control requests plus 1 finding-triage request**. The default call budget permits up to 12 control attempts, but does not create a retry: there are no automatic retries. A failed request attempt counts toward the budget, including attempts rejected locally before an HTTP request is sent.

`--analyst-max-calls 0` stops control requests only. The CLI still sends the finding-triage request when `--judge-config` or `--judge-cli` is present, and it can still collect and retain local analyst evidence. It returns an incomplete control review when active checks remain. Omit both `--judge-config` and `--judge-cli` when no LLM request is intended.

Setting `--analyst-max-files 0`, `--analyst-max-bytes 0`, or `--analyst-max-chars 0` leaves the analyst with no source excerpts; it can still receive control metadata and must acknowledge missing evidence. A zero character limit does not prevent local source reads. These limits do not change the separate deterministic scanner or finding-triage payload.

The time budget is **best effort**, not a hard process deadline. It starts after finding triage and includes evidence collection. Before each control request, the controller checks remaining time and lowers that request's configured timeout accordingly. DNS resolution or a blocking network operation can exceed the elapsed-time target. The finding-triage request has its own configured timeout. Use an external process supervisor if a hard wall-clock cutoff is required.

Additional evidence caps are fixed in the implementation: at most 240 unique excerpts globally, four excerpts per control, 12 lines and 2,000 characters per excerpt, and 64 ranked excerpt candidates per control. Individual evidence files are limited to the smaller of the scanner's file-size limit and 1,000,000 bytes. A single overlong line can be truncated; metadata records an incomplete final line and the number of retained characters in its redacted form.

Each source read must fit its manifest size plus one reserved sentinel byte used to detect file growth. Successful reads charge the returned byte count. Failed reads charge their maximum possible size, including the sentinel, even when failure occurred before reading content. Evidence coverage reports `bytes_charged`, `bytes_read`, and `failed_read_bytes_charged` separately so conservative budgeting is visible.

Character limits describe the evidence pool, not cumulative network traffic or model tokens. A shared excerpt can be included in several batches, and every request also contains instructions and control metadata. Provider `max_request_bytes`, `max_response_bytes`, `max_output_tokens`, context limits, and timeouts still apply. For custom request templates, supply the gateway's own output-token setting. Oversized or truncated responses fail explicitly; reducing batch size may help but requires enough control calls to cover the catalog.

At the first provider or protocol-validation error, the controller stops further control requests, retains earlier accepted advice, and marks remaining checks unreviewed. Exhausting call or time budgets produces `incomplete`. An error produces `error`. Neither state silently removes controls from the review queue.

## Evidence and privacy boundaries

Only files within the completed scanner manifest are eligible. Existing scanner exclusions, unsupported file formats, limits, and `--exclude` patterns therefore constrain analyst coverage. Default excluded directories include dependency trees, virtual environments, VCS data, caches, and build outputs. The scanner excludes its configured report output, judge configuration, and baseline paths. Review the report's exclusion and skipped-file records instead of assuming the entire repository was examined.

The analyst additionally excludes environment files, common credential files, and private-key containers. Examples include `.env` variants, `.npmrc`, `.netrc`, `.pypirc`, `credentials.*`, `secrets.*`, `id_rsa` and related key names, `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, and descendants of `.ssh`, `.aws`, `.gnupg`, and `.kube`. This list is a protective heuristic; a secret with another name or format can still be present.

Confined reads reject unsafe paths and symlinks and pin the root's filesystem identity. Source whose bytes differ from the scanner's manifest hash is skipped. Binary and non-UTF-8 content is skipped. Private-key blocks and known credential patterns are redacted, and source lines associated with credential-detection rules are replaced with a redaction notice. Original line numbering is retained.

Redaction is best effort. Proprietary algorithms, sensitive descriptions, personal information, unusual credentials, and revealing filenames can remain in source or metadata. The JSON report retains the selected redacted evidence pool, including excerpts that a later budget or error may prevent from being sent. Treat the reports as sensitive repository artifacts. Provider and gateway retention policies are outside the scanner's control.

The judge configuration is trusted operator input. Keep it outside the repository under assessment. A configuration can choose the recipient and explicitly resolve environment variables. Credentials are supplied through the documented environment-backed configuration fields; the adapter does not implicitly forward unrelated provider keys. API secrets used by the adapter are scrubbed if echoed in generated output. If a credential overlaps a structural control or evidence ID, control review fails safely before sending that batch instead of producing corrupt provenance.

## Protocol and deterministic checks

The model receives an explicit security-analyst role. Repository content, comments, filenames, evidence, and embedded instructions are untrusted data. Source URLs are provenance references, not instructions to browse. The model must assess each acceptance check, explain uncertainty, and propose verification steps without executing them.

The control response schema is separate from the finding-triage schema in [JUDGE.md](JUDGE.md). A minimal control response looks like this:

```json
{
  "control_assessments": [
    {
      "control_id": "EXACT_SUBMITTED_CONTROL_ID",
      "check_assessments": [
        {
          "check_index": 1,
          "status": "insufficient_evidence",
          "reason": "The supplied excerpts do not show how the deployed service enforces this check.",
          "citations": [],
          "verification_steps": [
            "Obtain deployment configuration and authorized test evidence for this acceptance check."
          ],
          "recommended_actions": {
            "agent_mcp_relevance": "A protected MCP tool needs authorization for the caller, tenant and target resource.",
            "applicability": "The supplied excerpts do not establish the effective deployment or every request path.",
            "steps": [
              "Obtain the deployed authorization policy and trace where the tool handler enforces resource ownership before proposing a code change."
            ],
            "verification": [
              "Use authorized runtime tests to check a valid caller with an insufficient scope and a different tenant resource."
            ]
          }
        }
      ]
    }
  ]
}
```

The example shows one check for readability; a complete response must include every submitted check of every submitted control. `check_index` is the one-based index in the input control's `checks` array. A grounded citation has only these model-supplied fields:

```json
{
  "evidence_id": "EXACT_SUBMITTED_EVIDENCE_ID",
  "quote": "Exact nonempty substring from that evidence's text"
}
```

The deterministic protocol validator enforces:

- A strict JSON object with only the documented fields. Markdown fences, duplicate JSON keys, non-finite numbers, malformed structures, and unexpected fields are rejected.
- Known, unique control IDs and check indexes. Citation IDs must exist and be included in that control's allowed evidence list.
- The six status values documented above. `pass`, `secure`, and compliance verdicts are not accepted.
- A nonempty reason of at most 2,000 characters and one to five nonempty verification steps of at most 500 characters each.
- When present, `recommended_actions` has exactly `agent_mcp_relevance`, `applicability`, `steps` and `verification`. The first two are nonempty strings of at most 1,200 characters; each array contains one to five nonempty strings of at most 1,000 characters. The same credential sanitization applies to these fields. Unexpected keys, empty or oversized values and invalid types fail the batch.
- At most three citations per check. Quotes must be nonempty exact substrings of submitted evidence, no longer than 500 characters; duplicate citations are rejected. Quotes that would need credential or control-character sanitization also fail instead of being changed after validation.
- At least one grounded citation for `supported_by_code`, `potential_gap`, and `not_applicable_proposed`.
- Locally derived paths, line ranges, and source-file hashes. Model-supplied location or hash fields are rejected. The original-file hash identifies the scanned bytes; it is not the hash of the redacted excerpt.
- Explicit `insufficient_evidence` replacements for missing controls or checks, with omission counts. `model_supplied` is added locally as true or false; the model cannot supply that field.

The normalized result also records configured provider/model, an optional provider-reported model identifier, adapter/protocol versions, and any deterministic status adjustment. This is provenance for review, not independent attestation of which model a remote gateway actually ran.

Current prompts and official CLI response schemas request action guidance for every answered check. A recommendation should identify the relevant agent/MCP trust boundary, explain when a change applies, name specific APIs/settings when supported, and describe verification that remains to be performed. A supported control may need no code change: the recommendation can instead identify the evidence and regression checks to retain. Missing evidence should lead to a request for that evidence, not an invented implementation defect.

Older responses without `recommended_actions` remain accepted for compatibility. They retain their original check assessment and verification steps, and `advice_coverage` shows that no model fix plan was supplied. A missing action object alone does not make the control review incomplete; an omitted acceptance-check assessment still does. A provided but malformed action object fails validation. Neither detailed action advice nor its absence changes the citation requirement, the deterministic adjustment of manual/dynamic outcomes, or the finding gate.

## Execution and gateway restrictions

The scanner does not install dependencies, import or execute target code, start an agent, invoke an MCP tool, contact the target service, run a suggested verification step, or allow the model to select follow-up actions. Only the configured LLM endpoint is contacted for the optional review. References and model-provided URLs are not retrieved.

Both finding triage and the control analyst reject recognized tool/function configuration in request templates and provider options, and reject recognized tool-call attempts in provider responses. They do not dispatch tool calls. Custom templates expand placeholders once; repository text containing `${ENV:NAME}` remains literal data and cannot read the scanner's environment. Configuration nesting is limited to 64 levels; invalid or excessive configuration fails without discarding static results.

**Operators must also disable tools and execution inside their model gateway.** The client can reject tool configuration or tool-call responses it sees, but it cannot inspect or prevent a gateway from running hidden server-side workflows. Choose a plain inference endpoint and review its data and execution policies. Prompt wording alone does not constrain a remote service.

Native adapters support the documented OpenAI-compatible Chat Completions, Responses, Anthropic, Gemini, and Ollama protocol shapes; the custom adapter supports configured synchronous JSON-over-HTTP APIs. Other authentication, streaming, signing, or proprietary protocols can require a gateway or another adapter. There is no claim that every vendor API works unchanged.

## Read and use the report

`report.md` presents analyst coverage, status counts, per-check explanations, verified quotes, and remaining verification steps next to each control. It also includes the evidence-collection ledger and request receipts. Model text is escaped as untrusted report content.

`report.json` preserves the complete structured record:

| Field | Contents |
| --- | --- |
| `findings`, `controls`, `summary` | Existing deterministic findings and control coverage. |
| `judge` | Separate finding-triage results, selected/omitted finding counts, and mode. |
| `remediation` | Deterministic catalog fix plans keyed by finding ID, including conditional agent/MCP relevance, applicability, concrete changes, verification scenarios and primary references. Available without a model. |
| `advice_coverage` | Separate counts of static plans and model-provided plans for finding assessments, answered checks and additional concerns; missing model guidance is not filled in. |
| `analyst.control_assessments` | Every control and acceptance check, its advisory status, model-supplied marker, explanations, citations, proposed verification steps and optional `recommended_actions`. |
| `analyst.coverage` | Attempted/reviewed controls, unanswered checks, budgets, evidence limits, skipped files, and stop reason when applicable. |
| `analyst.evidence` | Selected redacted excerpt pool with IDs, source paths, source-file hashes, line ranges, and any truncation metadata. |
| `analyst.requests` | Batch control/evidence IDs, canonical payload hash, request status, model identifiers, protocol versions, and returned omission counts. |
| `analyst.provenance` | Explicit facts that no target execution, model tools, model-selected evidence, or modification of deterministic findings occurred; citation and assurance limits. |
| `execution` | Severity threshold, deterministic finding-gate decision, and process exit code. |

The payload hash identifies the controller's canonical control/evidence JSON payload. It does not hash authentication headers, the complete provider request envelope, or a model's internal state. An evidence item present in the local pool is not necessarily transmitted; consult request receipts for the evidence IDs included in each attempted batch. A request marked completed can still have model omissions, which are counted separately.

`report.sarif` continues to contain deterministic findings only, with catalog remediation in result messages and `properties.agentMcpRemediation`. Model interpretations and model-proposed actions are excluded. Analyst advice cannot delete a finding, lower its severity, waive a control, or become a confirmed SARIF finding. HTML, Markdown, JSON and the optional PDF present model proposals separately from the deterministic plan; all verification instructions remain unexecuted text.

Exit codes remain operational:

- `0`: the selected static scan and requested review stages completed, and no open deterministic finding met the configured failure threshold. This is not a security pass.
- `1`: an open deterministic finding met the configured severity threshold.
- `2`: scanning was incomplete, a requested judge stage failed, or the control analyst remained incomplete. Operational incompleteness takes precedence over the severity gate, including with `--fail-on none`.

Use the report to assign ownership and gather the missing runtime, configuration, policy, or human evidence. Acceptance of a control still needs the responsible reviewer to validate its scope and outcome. The analyst narrows and documents the work; it does not close the assurance gap by itself.
