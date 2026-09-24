# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `89791e8051d89f532704d66d4d26a1d4df049468a99252699448d9f86779e000`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Incomplete scan \- close the coverage gaps

The selected static scope was not fully inspected\. There are 0 open findings, including 0 critical/high findings\. Resolve reported gaps and review existing evidence before relying on this result\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 | 1 |

**1 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 0/0 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 2/2 answered checks. These are proposed changes requiring verification.

**Execution:** exit 2; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** completed. Model advice is separate from the deterministic assessment and cannot lower these priorities.

Control-review status: **completed**; 1/1 controls answered, 0 unanswered checks. An answered check is not a passed check.

**Requested work is incomplete.** Inspect scan gaps and optional-review errors below; retain the static findings even when a model request failed.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

**Close scan coverage gaps:** resolve the listed errors or scope limits and rerun on a stable input. Existing findings still need review.

- parse\_error: MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete: 1 entries. Examples: index\.ts

There are no open pattern findings to prioritize. This does not close the coverage, runtime, or accepted-risk follow-up work.

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

No finding-specific mitigation was selected because no configured pattern was detected. Use the full control checklist to validate identity and authorization, tool execution boundaries, isolation, secrets, monitoring, and incident response.

### What remains unknown

- Actual reachability, deployment configuration, upstream validation, data sensitivity, and exploitability require verification\.
- Authentication, authorization, tenant isolation, tool approvals, prompt\-injection resistance, and recovery need runtime or human evidence\.
- Suggested defense layers have not been verified as deployed\. There is no calculated residual\-risk score or automatic severity reduction\.
- No dependency CVE feed or live adversarial agent/MCP benchmark was run\. Excluded and unsupported files remain outside the selected scope\.

Guidance catalog version: 1\.0\.0; SHA-256: `1bd48fd16d4fe76ae3ccd1cacddce9bea2dedd0000856d61b21ffb8ba8c5dd7b`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 0 | Observed patterns requiring review; 0 critical/high. No severity weights or estimated compromise probability are assigned. |
| Partial deterministic mapping reach | 100.00% (1/1) | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |
| Optional AI answer coverage | 100.00% (2/2) | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |

**Selected scope:** 4 rules (4 active), 1 controls (1 active), 2 active acceptance checks. The selected static scope is incomplete. Recorded coverage gaps: 1.

**Mapping formula:** 100 × active selected controls with at least one active selected mapped rule / active selected controls\. This describes partial rule availability, not completed tests, passes, or control effectiveness\.

**AI answer formula:** 100 × unique active selected acceptance checks with a received, valid model answer / active selected acceptance checks\. An answer can be a concern or an explicit unknown\. Disabled AI has zero answered checks; an empty denominator is not applicable \(null\), never 100%\.

**Optional AI:** enabled; finding stage completed; control stage completed.

| Advisory check outcome | Count |
|---|---:|
| supported\_by\_code | 0 |
| potential\_gap | 1 |
| needs\_runtime\_validation | 0 |
| needs\_human\_review | 0 |
| insufficient\_evidence | 1 |
| not\_applicable\_proposed | 0 |
| not\_reviewed | 0 |

Supported by code and proposed non\-applicability are advisory interpretations\. Runtime/human validation and missing evidence remain unresolved\. AI cannot erase findings, lower their severity, change the severity gate, or turn checks into passes\.

Justified and disabled rules/checks are excluded from active metric denominators without pass credit\. Findings with user decisions or baseline suppressions remain visible outside open\-finding counts\. Selection narrows the requested scope; it does not establish the excluded system is safe\.

The existing CLI gate uses open deterministic findings at or above the configured severity\. Scan/review/export errors can make requested work incomplete\. Coverage percentages and model opinions never dismiss the gate\.

## Methods, configuration and blind spots

Find repeatable security patterns and organize the remaining assurance work for agents, MCP servers, skills and built images\.

| Selected scope measure | Count |
|---|---:|
| Selected deterministic rules | 4 |
| Selected controls with partial static mapping | 1 |
| Selected controls without static mapping | 0 |
| Selected acceptance checks | 2 |
| Rules available in the full catalog | 47 |
| Controls available in the full catalog | 66 |

Mapping counts describe available checks, not percent secure, detection accuracy or validated control effectiveness\.

### How the layers operate

1. Choose an explicit code/image target and scan configuration; no target code or container is started\.
2. Collect bounded deterministic evidence, record hashes, rule matches, exclusions and coverage gaps\.
3. When explicitly enabled, select bounded evidence for finding triage and every active control check; findings\-only mode narrows this step\.
4. Run advisory requests under fixed limits\. The default full analyst may request only validated file\-ID/line ranges from an already captured, hash\-verified snapshot; no arbitrary file reads or target tools execute\. Validate response schemas, known identifiers and exact quotes\.
5. Retain unsupported claims and runtime/human requirements; record user review decisions separately from model advice\.
6. Import an explicitly selected reviewed report with a fresh target scan; revalidate evidence bindings, retain stale decisions for audit and recompute the result\.

### What each layer can and cannot establish

#### Execution and data flow

**Deterministic:** Python AST checks propagate selected registered\-tool inputs and same\-file arguments/returns, retain aliases and exact literal constraints, and check selected execution/file/network sinks\. JavaScript tokens support narrow registerTool callbacks and direct\-return named/arrow wrappers\. Explicit world\-writable chmod modes are checked\.

**Optional model review:** A model can form a trust\-boundary hypothesis, request bounded captured source ranges to inspect callers or guards, seek counterevidence and explain what the supplied code still cannot establish\.

**Can miss or misclassify:** Cross\-file flows, unknown decorators/methods, complex JavaScript wrappers, dynamic imports, reflection, generated code and runtime values can hide a risk\. Recognized resource/binding failures remain gaps\. A dangerous API can be intentional and correctly constrained\.

**Runtime/human evidence:** Exercise actual entry points with authorized negative tests; verify input provenance, execution privileges and sandbox boundaries\.

#### MCP identity, authorization and tools

**Deterministic:** Selected configuration/code signals flag insecure transport, explicit authentication bypass, token passthrough, broad tool grants and unpinned server launch packages\.

**Optional model review:** A model can review supplied authorization logic, tool descriptions and trust\-boundary evidence for missing assumptions or inconsistent checks\.

**Can miss or misclassify:** Configuration may differ from deployment\. External gateways, identity providers, token audience checks and tenant boundaries may be absent from retrieved evidence\.

**Runtime/human evidence:** Test expired/wrong\-audience tokens, cross\-tenant access, per\-tool authorization, consent binding and the deployed MCP transport\.

#### Prompt injection, retrieval and memory

**Deterministic:** Selected patterns identify external content placed in privileged model messages and explicit approval/sandbox bypass\. This is not an attack simulation\.

**Optional model review:** A model can reason about untrusted\-content handling, persistent memory, tool\-output influence and missing approval boundaries in the supplied excerpts\.

**Can miss or misclassify:** Adaptive attacks, multi\-turn interactions and tool chains depend on runtime behavior\. Retrieval can omit the relevant code; a model can overlook an attack or be influenced by hostile evidence\.

**Runtime/human evidence:** Run isolated adversarial agent/MCP evaluations with attack\-success and legitimate\-task measurements, plus human review of consequential actions\.

#### Secrets and data handling

**Deterministic:** Selected literal credentials, plausible private\-key material, credential\-bearing URLs, logging patterns and browser credential exposure are flagged and redacted best\-effort\.

**Optional model review:** A model can identify sensitive data flows and retention concerns when the supplied evidence explains their context\.

**Can miss or misclassify:** Encoded, split or runtime\-fetched credentials can be missed; labels/test values can resemble secrets\. Neither layer establishes whether a credential is live or redaction is complete\.

**Runtime/human evidence:** Verify secret stores, credential rotation, logging/retention policy, egress destinations and actual data\-access permissions\.

#### Skills and malicious\-tool indicators

**Deterministic:** Bounded skill/tool/schema descriptions are checked for instruction hijacking, sensitive\-data transfer, covert or approval\-bypassing actions\. Selected Spanish/French/German overrides and paired authority claims supplement English predicates\. Python read\-only tool annotations are compared with recognized direct write witnesses\.

**Optional model review:** A model can review intent, indirect social engineering, skill reference context and tool behavior visible in retrieved evidence, including cases where syntax or supported patterns are inconclusive\.

**Can miss or misclassify:** A pattern is risk evidence, not proof of malicious authorship\. Obfuscation, remote references, external packages, omitted context and runtime behavior can evade either layer\.

**Runtime/human evidence:** Inspect publisher provenance and the exact installed skill/tool; test consequential actions in an authorized isolated environment and verify effective permissions\.

#### Built images and supply chain

**Deterministic:** Image archives are reconstructed without starting containers; supported packaged source, metadata, retained credentials, stored permissions and package inventories are inspected\.

**Optional model review:** A model can interpret supplied image/source evidence, flag missing deployment context and propose verification work\.

**Can miss or misclassify:** Compiled logic, live deployment overrides, signature trust and dependency CVEs are not assessed\. Package inventory and archive consistency do not establish safety or publisher identity\.

**Runtime/human evidence:** Use vulnerability/advisory analysis, provenance/signature verification and deployment testing alongside the static image assessment\.

#### Operations and control effectiveness

**Deterministic:** The catalog retains governance, monitoring, recovery, approval and isolation checks even where no deterministic rule maps to them\.

**Optional model review:** Full review queues every active acceptance check and can identify evidence gaps or propose runtime/human validation; it can cite exact submitted source text\.

**Can miss or misclassify:** A valid citation proves that a quote exists, not that the model's interpretation is correct\. Policies, external services, incident procedures and production outcomes may be unavailable\.

**Runtime/human evidence:** Record owner\-reviewed evidence, operational exercises and runtime results\. A written justification remains an accepted exception, never an automatically validated pass\.

### Recorded scan configuration

These are settings and limits, not proof of completed coverage. Current CLI flags select a fresh scan; imported reports do not execute commands, select targets, restore credentials or enable model review.

```text
{
  "image_limits": {},
  "invocation": {
    "optional_review": {
      "analyst_limits": {
        "batch_size": 1,
        "investigation_rounds": 2,
        "max_bytes": 2000000,
        "max_calls": 3,
        "max_chars": 120000,
        "max_files": 200,
        "max_seconds": 900.0
      },
      "cli_login": "never",
      "cli_timeout_seconds": 300.0,
      "effective_transport": {
        "max_request_bytes": 524288,
        "max_response_bytes": 1048576,
        "model": "gpt-6-astra",
        "provider": "codex_cli",
        "timeout_seconds": 300.0,
        "token_optimizer": "headroom"
      },
      "enabled": true,
      "findings_limit": 100,
      "include_finding_source": false,
      "mode": "full",
      "provider": "codex_cli",
      "transport_replay": "Endpoints, credentials, headers, executable paths and identity stores are not embedded for automatic replay."
    },
    "reporting": {
      "failure_threshold": "high",
      "formats": [
        "html",
        "markdown",
        "json",
        "sarif",
        "pdf"
      ]
    },
    "review_inputs": {
      "baseline": false,
      "review_config": false,
      "review_report": false
    },
    "schema_version": "1.0"
  },
  "source_and_packaged_file_scope": {
    "default_excluded_directories": [
      ".cache",
      ".git",
      ".hg",
      ".mypy_cache",
      ".next",
      ".pytest_cache",
      ".svn",
      ".tox",
      ".venv",
      "__pycache__",
      "build",
      "coverage",
      "dist",
      "node_modules",
      "vendor",
      "venv"
    ],
    "exclude": [],
    "explicit_exclusion_identity_scope": "Existing selected files and directories, including case aliases and file hardlinks; inputs must remain stable during the scan. Device/inode identities are not persisted in reports.",
    "explicit_exclusion_matching": "resolved_paths_and_snapshot_filesystem_identities",
    "generated_outputs_and_judge_config_excluded": true,
    "max_entries": 100000,
    "max_file_bytes": 1000000,
    "max_files": 20000,
    "max_total_bytes": 50000000,
    "requested_scan_ids": [
      "EXEC-04"
    ],
    "selected_control_ids": [
      "EXEC-04"
    ],
    "selected_rule_ids": [
      "AI015",
      "AI016",
      "AI037",
      "AI047"
    ]
  }
}
```

## Scan details

Scanned **9 files**; **0 open findings**, **0 suppressed findings**, and **1 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 | 0 |

Source I/O: **58024 bytes read**, **58024 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 1 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| javascript\_lexical | 6 | Bounded JavaScript/TypeScript tokens, calls, configuration and direct\-return function\-wrapper summaries; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 2 | Parsed JSON/JSONC fields, selected configuration rules and recognized tool/input\-schema descriptions; runtime values and referenced files are not resolved\. |

Severity failure threshold: **high** · Process exit code: **2**.

### Advisory security analyst

Review status: **completed** · Controls reviewed: **1/1** · Unanswered checks: **0** · Control requests: **3/3**.

Every active control is routed for review because static patterns cannot establish completion. Review completion means an answer was received for every active check; it does not mean the checks passed. User-justified and disabled checks are excluded from review counts. The model is nondeterministic. Evidence selection, schema checks, and exact-quote validation are deterministic. Runtime execution and model tools are disabled.

| Advisory check status | Count |
|---|---:|
| insufficient\_evidence | 1 |
| potential\_gap | 1 |

### Bounded evidence investigation

The model may request exact ranges from verified, redacted snapshots; the controller enforces file IDs, scope, shared budgets and quote validation. No target tools or code execute. Requests do not resolve runtime uncertainty.

Follow-up rounds: **2**; requests served / denied: **15 / 0**; captured files offered: **9**.

```text
{
  "conclusion_calls": 1,
  "enabled": true,
  "excerpt_character_budget": 120000,
  "excerpt_characters_used": 36310,
  "inventory_characters": 2615,
  "limits": {
    "max_chars_per_request": 4000,
    "max_inventory_chars": 32000,
    "max_inventory_files": 200,
    "max_lines_per_request": 80,
    "max_requests_per_round": 8,
    "max_requests_total": 128,
    "max_symbols_per_file": 12
  },
  "max_rounds_per_batch": 2,
  "protocol": "manifest_snapshot_ranges_v1",
  "receipts": [
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for canonical target and parent checks, safe file handles, exclusive creation, and validation immediately associated with access.",
      "end_line": 219,
      "evidence_id": "src-d28872b02bc6a10fe16c62ab",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 3595,
      "original_check_index": 1,
      "purpose": "risk_hypothesis",
      "range_complete": true,
      "reason": "Trace path validation into filesystem access, including nonexistent targets, to assess whether attacker-controlled paths can escape between validation and use.",
      "retained_characters": 3595,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 140,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for overwrite prevention, constrained temporary files, atomic operations, and protections against symlink substitution.",
      "end_line": 299,
      "evidence_id": "src-d0295ca728dc16eb8dc246c4",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2670,
      "original_check_index": 1,
      "purpose": "risk_hypothesis",
      "range_complete": true,
      "reason": "Inspect write and move operations for destination replacement, temporary-file handling, permissions, and separate validation of source and destination.",
      "retained_characters": 2670,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 220,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for component-aware containment and fail-closed handling of malformed or ambiguous paths.",
      "end_line": 86,
      "evidence_id": "src-456285d9deaeffe2ed92aa98",
      "file_id": "file-987db9b947eadc16acc4f7f9",
      "new_characters_charged": 2551,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Determine how the containment predicate handles absolute paths, traversal, sibling prefixes, and platform separators.",
      "retained_characters": 2551,
      "source_sha256": "20833254c044c3d4d0672616ad546d50f09dae8b704c8a3619b86310f2cec3ba",
      "start_line": 7,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for schema restrictions, mandatory validation, safe access APIs, or evidence that the apparent operation is data-only.",
      "end_line": 274,
      "evidence_id": "src-79719540d5b09ece1df87e38",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2749,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect MCP registration and caller-side constraints connecting tool arguments to file access; the reported callback parsing gap remains unresolved.",
      "retained_characters": 2749,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 195,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for caller-side validation, restricted destinations, and wrappers that enforce containment independently of callback parsing.",
      "end_line": 429,
      "evidence_id": "src-9b0f9e4289167321e1be0a92",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2950,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect additional tool callbacks for direct filesystem operations and whether attacker-supplied paths consistently reach validation before access.",
      "retained_characters": 2950,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 350,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for server-owned limits, authenticated root authority, and fail-closed handling of missing or invalid roots.",
      "end_line": 786,
      "evidence_id": "src-00a7481a5f1d3f2b7fdb5396",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2865,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Determine whether client-provided roots replace or intersect the server's allowed directories and how updates affect the authorization boundary.",
      "retained_characters": 2865,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 725,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Look for file-scheme restrictions, canonicalization, directory checks, and rejection of roots outside an independently established policy.",
      "end_line": 77,
      "evidence_id": "src-798ccbc00c025c20d75d0d6e",
      "file_id": "file-2f90dc06de04ee6c31f5153c",
      "new_characters_charged": 2811,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Inspect root URI parsing and directory validation used to construct the filesystem access policy.",
      "retained_characters": 2811,
      "source_sha256": "bce7c15a73dc592c23339edcd68603d08fed8d7f3d0f371db29042703f93240d",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:2",
      "check_index": 2,
      "control_id": "EXEC-04",
      "counterevidence": "Look for explicit security-test coverage or test references while distinguishing test scripts from evidence that adversarial cases were exercised.",
      "end_line": 43,
      "evidence_id": "src-c7e718e049f51ab7a5cfbc94",
      "file_id": "file-9b73cee629c530fd3bf63a92",
      "new_characters_charged": 1186,
      "original_check_index": 2,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Identify declared test infrastructure and any supplied references to filesystem security tests; no test cases or execution results are currently provided.",
      "retained_characters": 1186,
      "source_sha256": "d91000e9d2cb2373b4dcd73027bdeb42e60790c8d7469618bad256770109bbed",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek canonical parent containment checks, rejection of ambiguous targets, and protections against following an existing symlink through the fallback.",
      "end_line": 139,
      "evidence_id": "src-27b002fa4ff3b6ae471400e7",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2633,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Inspect relative-path resolution and the Unicode fallback used when a requested target does not exist, particularly whether the returned target remains inside canonical allowed directories.",
      "retained_characters": 2633,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 77,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek mandatory validation of the caller-controlled path and any file-handle-based access barrier. Reading this callback does not resolve the reported parser coverage gap.",
      "end_line": 194,
      "evidence_id": "src-c67692042563669a512075ef",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 879,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Complete the visible text-read handler's argument-to-validation flow before its filesystem read; the supplied excerpt starts after validPath is established.",
      "retained_characters": 879,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 170,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek per-target canonical validation, safe stream creation, and caller-side restrictions that could constrain the apparent read flow.",
      "end_line": 349,
      "evidence_id": "src-84abde46d0ddd31836690720",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2858,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Trace media and multiple-file read callbacks to determine whether each supplied path is constrained before contents are returned to the MCP client.",
      "retained_characters": 2858,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 275,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek validation of both operands, restrictions on overwrites, and additional enforcement between validation and filesystem access.",
      "end_line": 704,
      "evidence_id": "src-c1b896fc23175f99b9adf439",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 3008,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect remaining tool registrations for the caller of moveFile and related access operations, including whether both source and destination receive validation before mutation.",
      "retained_characters": 3008,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 625,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek reuse of guarded write operations, dry-run enforcement, exclusive temporary-file creation, or descriptor-based operations that limit symlink substitution.",
      "end_line": 399,
      "evidence_id": "src-3af1c30514bd02009e75c3c0",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2689,
      "original_check_index": 1,
      "purpose": "risk_hypothesis",
      "range_complete": true,
      "reason": "Follow the supplied editing function toward its eventual write and inspect adjacent read helpers for direct access after path validation.",
      "retained_characters": 2689,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 320,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek an explicit unprivileged identity, restricted filesystem exposure, or other concrete isolation settings; deployment declarations alone cannot establish runtime enforcement.",
      "end_line": 25,
      "evidence_id": "src-b8010ae783d56bfc38f97a55",
      "file_id": "file-9e181b70de0137f101e66dc0",
      "new_characters_charged": 567,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Inspect supplied deployment configuration for confinement that could limit the impact of client-selected roots or concurrent filesystem changes.",
      "retained_characters": 567,
      "source_sha256": "fc27009ddfd1d72773ddb89b0d169e449e940daa5cd1d56fe56bcc08b6e85598",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:2",
      "check_index": 2,
      "control_id": "EXEC-04",
      "counterevidence": "Seek explicit security-test inclusion or references to relevant fixtures, while retaining the absence of supplied test bodies and execution results as an evidence limitation.",
      "end_line": 14,
      "evidence_id": "src-c39da0c47ebf2e1715125cde",
      "file_id": "file-1e37847deefaaf829c40c17d",
      "new_characters_charged": 306,
      "original_check_index": 2,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Determine whether the supplied test configuration identifies relevant filesystem security tests or exclusions. The declared test script alone does not establish adversarial coverage.",
      "retained_characters": 306,
      "source_sha256": "a28c7034f39f5910667f49e4eee542fef853227432c2596eee2676bd5e6f96be",
      "start_line": 1,
      "status": "served"
    }
  ],
  "requests_attempted": 15,
  "requests_denied": 0,
  "requests_served": 15,
  "rounds_completed": 2,
  "snapshot_files_offered": 9,
  "snapshot_files_omitted": 0,
  "snapshot_semantics": "Evidence is the captured manifest snapshot, not a live filesystem reread; deployment behavior remains unverified.",
  "structured_analysis_checks": 2
}
```


A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

No configured risk patterns were detected in the selected files.
## Control checklist and coverage

These are project-defined checks mapped to published guidance. They are not official benchmark scores. `no_pattern_detected` means only that the mapped detector did not fire. `findings_detected` requires investigation, not an automatic compliance failure.

### EXEC\-04: Constrain file and archive access

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions\.
- [ ] Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret\-directory reads\.

Partial static rules: AI015, AI016, AI037, AI047

**Advisory analyst:** reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: potential\_gap**

Visible MCP handlers validate caller\-supplied paths before filesystem operations, and validatePath checks both lexical containment and resolved symlink targets\. However, validation returns a pathname that subsequent operations resolve again\. Concurrent replacement of a path component could therefore undermine access\-time containment\. The move helper separately checks destination existence with lstat before rename, leaving an apparent overwrite race\. Write and edit helpers use randomly named temporary files and atomic replacement, but temporary creation does not explicitly request exclusive creation or restrictive permissions; permission restoration occurs afterward and errors are ignored\. These are unverified concerns whose impact depends on filesystem mutation rights, umask, and deployment isolation\. Upload, download, and archive\-specific behavior is not established by the excerpts\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Agent\-controlled MCP path arguments cross into the server's filesystem authority\. Concurrent filesystem writers introduce a second boundary: a pathname validated earlier may identify a different object when accessed\. Client\-provided roots also require an explicit ownership and authorization policy\.

**When this applies:** Race\-related changes are relevant where another process or principal can mutate accessible directory entries during an operation\. Permission changes depend on the intended confidentiality policy and deployed umask\. Archive\-specific changes require evidence that extraction is supported\.

1. Retain lexical and canonical containment checks\. Where concurrent mutation is possible, use platform\-supported descriptor\-relative access with enforced beneath\-root resolution, or deployment confinement that prevents access outside approved roots\. A final\-component no\-follow flag alone does not protect ancestor components\.
2. Replace the lstat\-then\-rename no\-overwrite sequence with a platform\-supported atomic no\-replace operation or an equivalent filesystem\-specific design whose guarantees cover every supported object type\.
3. Create temporary files with fs\.open using exclusive creation and mode 0o600, write through the returned FileHandle, and apply intended permissions through that handle before publication\. Define explicit handling for permission failures and separately protect parent\-directory resolution\.
4. Document who may change MCP roots and whether they must remain within an operator\-defined ceiling; obtain complete handler and deployment evidence before proposing archive or transfer changes\.

**How to verify:**

- Retain regression results showing that final\-component and ancestor substitution cannot redirect access beyond approved roots\.
- Verify that concurrent destination creation never causes an unintended move overwrite\.
- Verify temporary\-file confidentiality, intended final permissions, and defined failure behavior on every supported deployment platform\.

**Risk hypothesis:** An attacker able to influence MCP path arguments and concurrently mutate directory entries could redirect a later pathname\-based access after validation\. Concurrent destination creation could defeat the move helper's intended no\-overwrite behavior\. Temporary replacement files may expose content more broadly than intended before permission restoration\.

**Trust boundary:** MCP tool arguments enter validatePath and then reach filesystem reads or mutations under the server identity\. The relevant enforcement boundary is the actual filesystem operation, including ancestor resolution, destination replacement, and temporary\-file publication\.

**Counterevidence considered:** Considered visible handler\-side validation, separator\-aware containment, realpath checks, Unicode ambiguity rejection and component checks, initial write creation with 'wx', random temporary names, atomic replacement, and destination lstat\. These constrain static traversal and some symlink cases\. Atomic replacement does not itself bind ancestor resolution or make the separate destination check atomic\. Deployment isolation and attacker mutation rights remain unresolved\.

**Conclusion limits:** No exploit or runtime behavior was verified\. The callback parser coverage gap remains unresolved, and omitted handlers or caller constraints may change reachability\. Effective identity, mounts, umask, root policy, and transfer or extraction support are not established\. The assessment is advisory and subject to human review\.

Evidence src\-d28872b02bc6a10fe16c62ab: lib\.ts:163–168 (exact quote verified).

```text
    const realPath = await fs.realpath(absolute);
    const normalizedReal = normalizePath(realPath);
    if (!isPathWithinAllowedDirectories(normalizedReal, allowedDirectories)) {
      throw new Error(`Access denied - symlink target outside allowed directories: ${realPath} not in ${allowedDirectories.join(', ')}`);
    }
    return realPath;
```

Evidence src\-d0295ca728dc16eb8dc246c4: lib\.ts:247–251 (exact quote verified).

```text
    await fs.lstat(destinationPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      await fs.rename(sourcePath, destinationPath);
      return;
```

Evidence src\-3af1c30514bd02009e75c3c0: lib\.ts:341–344 (exact quote verified).

```text
    const tempPath = `${filePath}.${randomBytes(16).toString('hex')}.tmp`;
    try {
      await fs.writeFile(tempPath, modifiedContent, 'utf-8');
      await fs.rename(tempPath, filePath);
```

Verification still required:
- In an authorized isolated environment, test replacement of final and ancestor path components between validation and reads, writes, edits, and moves; verify that outside\-root sentinel files remain unread and unchanged\.
- Test concurrent creation of a move destination after its existence check and establish whether the operation preserves the newly created destination\.
- Inspect temporary and replacement file permissions throughout writes and edits under deployed umask settings, including permission\-restoration failures\.
- Review deployment mutation rights, filesystem mounts, root\-update authorization and revocation behavior, and the complete operation inventory to establish upload, download, and extraction applicability\.

**Check 2: insufficient\_evidence**

The supplied configuration establishes Vitest test discovery and coverage settings, but no test bodies, fixtures, or execution results establish testing of symlink races, archive traversal, absolute paths, overwrite attempts, or secret\-directory reads\. Visible implementation guards are not evidence that these scenarios were tested\. Missing test evidence does not establish that tests are absent; authorized runtime validation is required\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Tests must exercise the MCP argument\-to\-filesystem boundary as well as helper functions, because agent\-supplied paths, dynamic roots, and concurrent filesystem changes affect enforcement\.

**When this applies:** First obtain existing security tests and execution evidence\. Add coverage only where review identifies missing scenarios\. Archive testing depends on confirmed extraction functionality\.

1. Create a coverage matrix linking each requested scenario to existing test cases, expected outcomes, and recorded results\.
2. Where coverage is missing, add isolated MCP integration tests with controlled synchronization for symlink substitution and destination\-creation races\.
3. Use synthetic restricted\-directory fixtures to verify that rejected requests disclose no sentinel content and cause no outside\-root changes\.
4. Record the supported platform matrix and have an owner confirm archive applicability rather than inferring it from missing excerpts\.

**How to verify:**

- Have an owner review test assertions for unauthorized reads, writes, and overwrites, rather than relying only on returned errors\.
- Retain authorized runtime results with platform, filesystem, permissions, and umask context\.
- Confirm that each acceptance\-check scenario has execution evidence or an explicitly reviewed applicability decision\.

**Risk hypothesis:** Filesystem guards may behave differently under concurrent changes, platform\-specific path semantics, or extraction behavior; ordinary functional tests may not exercise these conditions\.

**Trust boundary:** The verification boundary runs from attacker\-influenced MCP requests through filesystem operations to observable disclosure or mutation of synthetic protected fixtures\.

**Counterevidence considered:** A Vitest test script and Node test configuration are supplied, so test infrastructure exists\. Existing adversarial tests elsewhere are a plausible alternative, but no supplied test bodies or results establish their coverage\. Production guards do not substitute for testing evidence\.

**Conclusion limits:** Test completeness, execution outcomes, and archive applicability remain unknown\. The static parser diagnostic also limits entrypoint coverage\. This advisory assessment does not infer that tests are missing and requires human review and authorized runtime evidence\.

Evidence src\-c39da0c47ebf2e1715125cde: vitest\.config\.ts:5–6 (exact quote verified).

```text
    globals: true,
    environment: 'node',
```

Evidence src\-c7e718e049f51ab7a5cfbc94: package\.json:25–25 (exact quote verified).

```text
    "test": "vitest run --coverage"
```

Verification still required:
- Obtain relevant test bodies and recent results mapped to all five requested scenario categories, including supported platforms and filesystem assumptions\.
- Request deterministic race tests that coordinate mutation between validation and access, covering ancestor replacement and concurrent move\-destination creation\.
- Review traversal and absolute\-path cases, plus secret\-directory read tests using synthetic sentinel content outside approved roots and through symlink aliases\.
- Establish whether archive extraction exists; if applicable, review tests for parent traversal, absolute entry names, link entries, and overwrite behavior\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

## Coverage and limitations

- Static pattern and local syntax analysis do not prove exploitability, authentication, isolation, or absence of vulnerabilities\.
- Python receives AST\-based call checks; other source languages receive selected textual/configuration checks, not whole\-program dataflow\.
- No dependencies are installed, target code executed, services contacted, or CVE feed queried\.
- Default excluded directories and unsupported files remain outside the selected scan scope\.
- Prompt injection resistance, authorization, tenant separation, runtime egress, and human approval need adversarial/runtime validation\.
- Evidence redaction is best\-effort; reports and optional judge payloads can still contain sensitive code or data\.

### Inventory

Dependency manifests: 1; agent/MCP signal files: 3.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

- index\.ts: MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|

## Optional LLM judge

### Evidence-JSON optimization

All evidence values and exact source/citation strings are preserved. These byte counts exclude instructions, response schemas and provider wrappers; tokenizer savings and billing reductions were not measured.

| Request | Requested | Actual engine | Status / fallback | Before bytes | After bytes | Bytes saved |
|---|---|---|---|---:|---:|---:|
| Finding triage | headroom | headroom | optimized | 1229 | 1185 | 44 |
| Control request 1 | headroom | headroom | optimized | 9025 | 8689 | 336 |
| Control request 2 | headroom | headroom | optimized | 39542 | 38813 | 729 |
| Control request 3 | headroom | headroom | optimized | 54595 | 53779 | 816 |

Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.

```text
{
  "adapter_version": "1.3.0",
  "additional_concern_actions": [
    {
      "concern_index": 1,
      "recommended_actions": {
        "agent_mcp_relevance": "It is unknown whether the coverage gap affects agent tool execution, MCP authorization, or another trust boundary.",
        "applicability": "Further review is warranted if the uncovered material implements or configures security-relevant behavior.",
        "steps": [
          "Obtain the coverage gap details and scanned/excluded file inventory. Identify any omitted MCP handlers, authorization checks, and tool execution paths; arrange appropriate review for those files. No code or configuration change is supported by the supplied evidence alone."
        ],
        "verification": [
          "Check that each reported coverage gap has an explained disposition and that relevant agent/MCP entry points are included in the review scope. Treat any subsequent static scan as limited evidence, not runtime validation."
        ]
      }
    }
  ],
  "additional_concerns": [
    "Review coverage is incomplete: scan_complete_within_selected_scope is false, coverage_gaps is 1, and source context is unavailable. No findings were supplied; this does not establish security. The gap details and scanned/excluded file inventory are needed to assess what remains unreviewed."
  ],
  "advisory_only": true,
  "assessments": [],
  "cli": {
    "arguments": [
      "-a",
      "never",
      "exec",
      "--ignore-user-config",
      "--ignore-rules",
      "--ephemeral",
      "--skip-git-repo-check",
      "--sandbox",
      "read-only",
      "--json",
      "--color",
      "never",
      "--disable",
      "shell_tool",
      "--disable",
      "unified_exec",
      "--disable",
      "code_mode",
      "--disable",
      "code_mode_host",
      "--disable",
      "computer_use",
      "--disable",
      "browser_use",
      "--disable",
      "browser_use_external",
      "--disable",
      "browser_use_full_cdp_access",
      "--disable",
      "in_app_browser",
      "--disable",
      "image_generation",
      "--disable",
      "view_image",
      "--disable",
      "artifact",
      "--disable",
      "apps",
      "--disable",
      "plugins",
      "--disable",
      "plugin_sharing",
      "--disable",
      "hooks",
      "--disable",
      "multi_agent",
      "--disable",
      "multi_agent_v2",
      "--disable",
      "skill_search",
      "--disable",
      "workspace_dependencies",
      "--disable",
      "shell_snapshot",
      "--disable",
      "memories",
      "--disable",
      "sleep_tool",
      "--disable",
      "goals",
      "--disable",
      "remote_plugin",
      "--disable",
      "tool_suggest",
      "-c",
      "web_search=\"disabled\"",
      "-c",
      "mcp_servers={}",
      "-c",
      "project_doc_max_bytes=0",
      "-c",
      "skills.include_instructions=false",
      "-c",
      "model_reasoning_effort=\"high\"",
      "--output-schema",
      "<private temporary directory>/response-schema.json",
      "--model",
      "gpt-6-astra",
      "-"
    ],
    "auth_mode": "cli_managed",
    "cli_version": "0.154.0",
    "descendant_termination": "process_group",
    "executable": "codex",
    "isolation": "CLI capability restrictions; installed executable and administrator policy remain trusted",
    "provider": "codex_cli",
    "repository_working_directory": false,
    "request_bytes": 3399,
    "request_sha256": "2bbb2d87b5d67911fd0c5453b7d806010b68391badd4d17d569e4d6da3d2df6e",
    "requested_model": "gpt-6-astra",
    "response_bytes": 1802,
    "response_sha256": "ebd52f9b0ba8b39db0344c526e4f59ab7a7606259c04c7fbc7064f91eabf07b6",
    "stage": "findings",
    "startup_warnings": [
      "codex_code_mode_intentionally_disabled"
    ],
    "structured_output_requested": true,
    "token_budget_enforced": false,
    "token_optimization": {
      "bytes_saved": 44,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "1b6e028b2d3bc22a4e9e0b8516fcd2b09f7f2bce5af979b1bf8a318a754c944c",
      "payload_bytes_after": 1185,
      "payload_bytes_before": 1229,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "8b04a9e5367f23d7de64889eb95859f2184ba39de6a019a724fa8eeb2018f3d5",
      "status": "optimized",
      "token_savings_measured": false
    },
    "tools_policy": "disabled_for_advisory_review",
    "transport": "official_cli"
  },
  "data_policy": "Caller-supplied minimized payload; source excerpts require separate CLI opt-in.",
  "enabled": true,
  "findings_submitted": 0,
  "mode": "full",
  "model": "gpt-6-astra",
  "nondeterministic": true,
  "omitted_assessments": 0,
  "omitted_open_findings": 0,
  "provider": "codex_cli",
  "selected_findings": 0,
  "source_context_requested": false,
  "source_context_sent_count": 0,
  "source_context_skipped": [],
  "status": "completed",
  "token_optimization": {
    "bytes_saved": 44,
    "engine": "headroom",
    "evidence_preserved": true,
    "fallback_reason": null,
    "headroom_version": "0.37.0",
    "original_payload_sha256": "1b6e028b2d3bc22a4e9e0b8516fcd2b09f7f2bce5af979b1bf8a318a754c944c",
    "payload_bytes_after": 1185,
    "payload_bytes_before": 1229,
    "requested": "headroom",
    "schema_version": "1.0",
    "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
    "sent_payload_sha256": "8b04a9e5367f23d7de64889eb95859f2184ba39de6a019a724fa8eeb2018f3d5",
    "status": "optimized",
    "token_savings_measured": false
  }
}
```
### Additional model concern 1 (unverified)

Review coverage is incomplete: scan\_complete\_within\_selected\_scope is false, coverage\_gaps is 1, and source context is unavailable\. No findings were supplied; this does not establish security\. The gap details and scanned/excluded file inventory are needed to assess what remains unreviewed\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** It is unknown whether the coverage gap affects agent tool execution, MCP authorization, or another trust boundary\.

**When this applies:** Further review is warranted if the uncovered material implements or configures security\-relevant behavior\.

1. Obtain the coverage gap details and scanned/excluded file inventory\. Identify any omitted MCP handlers, authorization checks, and tool execution paths; arrange appropriate review for those files\. No code or configuration change is supported by the supplied evidence alone\.

**How to verify:**

- Check that each reported coverage gap has an explained disposition and that relevant agent/MCP entry points are included in the review scope\. Treat any subsequent static scan as limited evidence, not runtime validation\.


## Analyst evidence and request audit

Only bounded excerpts were submitted. Missing evidence may reflect collection limits, exclusions, or retrieval misses. A verified quote establishes its presence in an excerpt, not the truth of the model's interpretation. Verification steps are proposals and have not been executed.

Evidence selection and review coverage:

```text
{
  "attempted_controls": 1,
  "batch_size": 1,
  "call_budget": 3,
  "calls_made": 3,
  "catalog_checks": 2,
  "catalog_controls": 1,
  "disabled_checks": 0,
  "disabled_controls": 0,
  "evidence": {
    "budget_exhausted": [
      "max_candidates_per_control"
    ],
    "bytes_charged": 58024,
    "bytes_read": 58024,
    "candidate_rankings_dropped": 59,
    "candidate_snippets": 123,
    "characters_selected": 1993,
    "controls_total": 1,
    "controls_with_evidence": 1,
    "controls_without_evidence": [],
    "evidence_files": 3,
    "failed_read_bytes_charged": 0,
    "file_read_attempts": 9,
    "files_read": 9,
    "files_verified": 9,
    "full_repository_review": false,
    "limitations": [
      "Keyword-selected excerpts are partial context and do not prove implementation, absence, effectiveness, or compliance.",
      "Only unchanged manifest files are eligible; scanner exclusions and unsupported files remain outside this review.",
      "Credentials and environment files are excluded; other redaction is best-effort and source can contain sensitive data.",
      "Read budgets reserve one sentinel byte and conservatively charge failed read attempts, even if failure happened before any source bytes were read.",
      "No target code is executed, imported, installed, or contacted; repository instructions cannot change retrieval.",
      "Runtime behavior and missing evidence require additional validation; an empty control mapping is not a pass."
    ],
    "limits": {
      "max_bytes": 2000000,
      "max_candidates_per_control": 64,
      "max_chars": 60000,
      "max_chars_per_excerpt": 2000,
      "max_excerpts_per_control": 4,
      "max_file_bytes": 1000000,
      "max_files": 200,
      "max_lines_per_excerpt": 12,
      "max_snippets": 240
    },
    "manifest_files": 9,
    "requested_characters_selected": 34317,
    "scope": "bounded_excerpts_from_unchanged_scanner_manifest_files",
    "selection_method": "deterministic_control_keywords_and_findings",
    "skipped_counts": {},
    "skipped_files": [],
    "snippets_selected": 4
  },
  "excluded_checks": 0,
  "excluded_controls": 0,
  "justified_checks": 0,
  "justified_controls": 0,
  "omitted_checks": 0,
  "reviewed_controls": 1,
  "time_budget_seconds": 900.0,
  "total_checks": 2,
  "total_controls": 1,
  "unreviewed_control_ids": [],
  "validated_controls": 0
}
```


Request receipts (payload hashes and model identifiers):

```text
[
  {
    "adapter_version": "1.3.0",
    "batch": 1,
    "check_index_map": {
      "EXEC-04": [
        1,
        2
      ]
    },
    "checks_submitted": 2,
    "cli": {
      "arguments": [
        "-a",
        "never",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--json",
        "--color",
        "never",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "code_mode",
        "--disable",
        "code_mode_host",
        "--disable",
        "computer_use",
        "--disable",
        "browser_use",
        "--disable",
        "browser_use_external",
        "--disable",
        "browser_use_full_cdp_access",
        "--disable",
        "in_app_browser",
        "--disable",
        "image_generation",
        "--disable",
        "view_image",
        "--disable",
        "artifact",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "plugin_sharing",
        "--disable",
        "hooks",
        "--disable",
        "multi_agent",
        "--disable",
        "multi_agent_v2",
        "--disable",
        "skill_search",
        "--disable",
        "workspace_dependencies",
        "--disable",
        "shell_snapshot",
        "--disable",
        "memories",
        "--disable",
        "sleep_tool",
        "--disable",
        "goals",
        "--disable",
        "remote_plugin",
        "--disable",
        "tool_suggest",
        "-c",
        "web_search=\"disabled\"",
        "-c",
        "mcp_servers={}",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        "skills.include_instructions=false",
        "-c",
        "model_reasoning_effort=\"high\"",
        "--output-schema",
        "<private temporary directory>/response-schema.json",
        "--model",
        "gpt-6-astra",
        "-"
      ],
      "auth_mode": "cli_managed",
      "cli_version": "0.154.0",
      "descendant_termination": "process_group",
      "executable": "codex",
      "isolation": "CLI capability restrictions; installed executable and administrator policy remain trusted",
      "provider": "codex_cli",
      "repository_working_directory": false,
      "request_bytes": 15221,
      "request_sha256": "2b69840070560ff95062e95a5404c3a0888825a79070edfff015d4aebb373ac4",
      "requested_model": "gpt-6-astra",
      "response_bytes": 4359,
      "response_sha256": "8399c7db806de95e3ba30ae91642896de806a97ba3022c0ed0ce1f5ddc9b797f",
      "stage": "investigation",
      "startup_warnings": [
        "codex_code_mode_intentionally_disabled"
      ],
      "structured_output_requested": true,
      "token_budget_enforced": false,
      "token_optimization": {
        "bytes_saved": 336,
        "engine": "headroom",
        "evidence_preserved": true,
        "fallback_reason": null,
        "headroom_version": "0.37.0",
        "original_payload_sha256": "f8982ae145b5698986e3330d224b63ef555455d20d87863ff1ed91547a948cc6",
        "payload_bytes_after": 8689,
        "payload_bytes_before": 9025,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "c0d6fdecf7bb012e4f0b2020d5e0dc01813ce5003e975cdf1f55f9e8994e74f8",
        "status": "optimized",
        "token_savings_measured": false
      },
      "tools_policy": "disabled_for_advisory_review",
      "transport": "official_cli"
    },
    "control_ids": [
      "EXEC-04"
    ],
    "controls_submitted": 1,
    "evidence_ids": [
      "src-7d7e02c858a447037de50438",
      "src-17399bf8d41781072687de0c",
      "src-4f9d0004e5a942800853224f",
      "src-c01e656cad72d145f2421bf1"
    ],
    "evidence_request_receipts": [
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for canonical target and parent checks, safe file handles, exclusive creation, and validation immediately associated with access.",
        "end_line": 219,
        "evidence_id": "src-d28872b02bc6a10fe16c62ab",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 3595,
        "original_check_index": 1,
        "purpose": "risk_hypothesis",
        "range_complete": true,
        "reason": "Trace path validation into filesystem access, including nonexistent targets, to assess whether attacker-controlled paths can escape between validation and use.",
        "retained_characters": 3595,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 140,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for overwrite prevention, constrained temporary files, atomic operations, and protections against symlink substitution.",
        "end_line": 299,
        "evidence_id": "src-d0295ca728dc16eb8dc246c4",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2670,
        "original_check_index": 1,
        "purpose": "risk_hypothesis",
        "range_complete": true,
        "reason": "Inspect write and move operations for destination replacement, temporary-file handling, permissions, and separate validation of source and destination.",
        "retained_characters": 2670,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 220,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for component-aware containment and fail-closed handling of malformed or ambiguous paths.",
        "end_line": 86,
        "evidence_id": "src-456285d9deaeffe2ed92aa98",
        "file_id": "file-987db9b947eadc16acc4f7f9",
        "new_characters_charged": 2551,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Determine how the containment predicate handles absolute paths, traversal, sibling prefixes, and platform separators.",
        "retained_characters": 2551,
        "source_sha256": "20833254c044c3d4d0672616ad546d50f09dae8b704c8a3619b86310f2cec3ba",
        "start_line": 7,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for schema restrictions, mandatory validation, safe access APIs, or evidence that the apparent operation is data-only.",
        "end_line": 274,
        "evidence_id": "src-79719540d5b09ece1df87e38",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2749,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect MCP registration and caller-side constraints connecting tool arguments to file access; the reported callback parsing gap remains unresolved.",
        "retained_characters": 2749,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 195,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for caller-side validation, restricted destinations, and wrappers that enforce containment independently of callback parsing.",
        "end_line": 429,
        "evidence_id": "src-9b0f9e4289167321e1be0a92",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2950,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect additional tool callbacks for direct filesystem operations and whether attacker-supplied paths consistently reach validation before access.",
        "retained_characters": 2950,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 350,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for server-owned limits, authenticated root authority, and fail-closed handling of missing or invalid roots.",
        "end_line": 786,
        "evidence_id": "src-00a7481a5f1d3f2b7fdb5396",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2865,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Determine whether client-provided roots replace or intersect the server's allowed directories and how updates affect the authorization boundary.",
        "retained_characters": 2865,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 725,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Look for file-scheme restrictions, canonicalization, directory checks, and rejection of roots outside an independently established policy.",
        "end_line": 77,
        "evidence_id": "src-798ccbc00c025c20d75d0d6e",
        "file_id": "file-2f90dc06de04ee6c31f5153c",
        "new_characters_charged": 2811,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Inspect root URI parsing and directory validation used to construct the filesystem access policy.",
        "retained_characters": 2811,
        "source_sha256": "bce7c15a73dc592c23339edcd68603d08fed8d7f3d0f371db29042703f93240d",
        "start_line": 1,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:2",
        "check_index": 2,
        "control_id": "EXEC-04",
        "counterevidence": "Look for explicit security-test coverage or test references while distinguishing test scripts from evidence that adversarial cases were exercised.",
        "end_line": 43,
        "evidence_id": "src-c7e718e049f51ab7a5cfbc94",
        "file_id": "file-9b73cee629c530fd3bf63a92",
        "new_characters_charged": 1186,
        "original_check_index": 2,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Identify declared test infrastructure and any supplied references to filesystem security tests; no test cases or execution results are currently provided.",
        "retained_characters": 1186,
        "source_sha256": "d91000e9d2cb2373b4dcd73027bdeb42e60790c8d7469618bad256770109bbed",
        "start_line": 1,
        "status": "served"
      }
    ],
    "investigation_response": "evidence_requests",
    "investigation_round": 0,
    "model": "gpt-6-astra",
    "payload_sha256": "c0d6fdecf7bb012e4f0b2020d5e0dc01813ce5003e975cdf1f55f9e8994e74f8",
    "protocol_version": "1.2.0",
    "provider": "codex_cli",
    "status": "completed",
    "structured_analysis_checks": 0,
    "token_optimization": {
      "bytes_saved": 336,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "f8982ae145b5698986e3330d224b63ef555455d20d87863ff1ed91547a948cc6",
      "payload_bytes_after": 8689,
      "payload_bytes_before": 9025,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "c0d6fdecf7bb012e4f0b2020d5e0dc01813ce5003e975cdf1f55f9e8994e74f8",
      "status": "optimized",
      "token_savings_measured": false
    }
  },
  {
    "adapter_version": "1.3.0",
    "batch": 1,
    "check_index_map": {
      "EXEC-04": [
        1,
        2
      ]
    },
    "checks_submitted": 2,
    "cli": {
      "arguments": [
        "-a",
        "never",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--json",
        "--color",
        "never",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "code_mode",
        "--disable",
        "code_mode_host",
        "--disable",
        "computer_use",
        "--disable",
        "browser_use",
        "--disable",
        "browser_use_external",
        "--disable",
        "browser_use_full_cdp_access",
        "--disable",
        "in_app_browser",
        "--disable",
        "image_generation",
        "--disable",
        "view_image",
        "--disable",
        "artifact",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "plugin_sharing",
        "--disable",
        "hooks",
        "--disable",
        "multi_agent",
        "--disable",
        "multi_agent_v2",
        "--disable",
        "skill_search",
        "--disable",
        "workspace_dependencies",
        "--disable",
        "shell_snapshot",
        "--disable",
        "memories",
        "--disable",
        "sleep_tool",
        "--disable",
        "goals",
        "--disable",
        "remote_plugin",
        "--disable",
        "tool_suggest",
        "-c",
        "web_search=\"disabled\"",
        "-c",
        "mcp_servers={}",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        "skills.include_instructions=false",
        "-c",
        "model_reasoning_effort=\"high\"",
        "--output-schema",
        "<private temporary directory>/response-schema.json",
        "--model",
        "gpt-6-astra",
        "-"
      ],
      "auth_mode": "cli_managed",
      "cli_version": "0.154.0",
      "descendant_termination": "process_group",
      "executable": "codex",
      "isolation": "CLI capability restrictions; installed executable and administrator policy remain trusted",
      "provider": "codex_cli",
      "repository_working_directory": false,
      "request_bytes": 45345,
      "request_sha256": "1fcb5581623270361da68d8d8c62c1f4179fe4d88fe3b3b3c8adc6194a1d504f",
      "requested_model": "gpt-6-astra",
      "response_bytes": 4263,
      "response_sha256": "1ca1e82f153654c19440d7033bf203f1d0845c421af11dee624db375697f3781",
      "stage": "investigation",
      "startup_warnings": [
        "codex_code_mode_intentionally_disabled"
      ],
      "structured_output_requested": true,
      "token_budget_enforced": false,
      "token_optimization": {
        "bytes_saved": 729,
        "engine": "headroom",
        "evidence_preserved": true,
        "fallback_reason": null,
        "headroom_version": "0.37.0",
        "original_payload_sha256": "10d47fd8adac84233f609d22bbb7ecbcef65a034d533477e429d8efab7f96fbd",
        "payload_bytes_after": 38813,
        "payload_bytes_before": 39542,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "15b826a0af20afe6a9b8262343301f040fd669fa61a7e48cf798ed39ed4986c9",
        "status": "optimized",
        "token_savings_measured": false
      },
      "tools_policy": "disabled_for_advisory_review",
      "transport": "official_cli"
    },
    "control_ids": [
      "EXEC-04"
    ],
    "controls_submitted": 1,
    "evidence_ids": [
      "src-7d7e02c858a447037de50438",
      "src-17399bf8d41781072687de0c",
      "src-4f9d0004e5a942800853224f",
      "src-c01e656cad72d145f2421bf1",
      "src-d28872b02bc6a10fe16c62ab",
      "src-d0295ca728dc16eb8dc246c4",
      "src-456285d9deaeffe2ed92aa98",
      "src-79719540d5b09ece1df87e38",
      "src-9b0f9e4289167321e1be0a92",
      "src-00a7481a5f1d3f2b7fdb5396",
      "src-798ccbc00c025c20d75d0d6e",
      "src-c7e718e049f51ab7a5cfbc94"
    ],
    "evidence_request_receipts": [
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek canonical parent containment checks, rejection of ambiguous targets, and protections against following an existing symlink through the fallback.",
        "end_line": 139,
        "evidence_id": "src-27b002fa4ff3b6ae471400e7",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2633,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Inspect relative-path resolution and the Unicode fallback used when a requested target does not exist, particularly whether the returned target remains inside canonical allowed directories.",
        "retained_characters": 2633,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 77,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek mandatory validation of the caller-controlled path and any file-handle-based access barrier. Reading this callback does not resolve the reported parser coverage gap.",
        "end_line": 194,
        "evidence_id": "src-c67692042563669a512075ef",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 879,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Complete the visible text-read handler's argument-to-validation flow before its filesystem read; the supplied excerpt starts after validPath is established.",
        "retained_characters": 879,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 170,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek per-target canonical validation, safe stream creation, and caller-side restrictions that could constrain the apparent read flow.",
        "end_line": 349,
        "evidence_id": "src-84abde46d0ddd31836690720",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2858,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Trace media and multiple-file read callbacks to determine whether each supplied path is constrained before contents are returned to the MCP client.",
        "retained_characters": 2858,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 275,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek validation of both operands, restrictions on overwrites, and additional enforcement between validation and filesystem access.",
        "end_line": 704,
        "evidence_id": "src-c1b896fc23175f99b9adf439",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 3008,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect remaining tool registrations for the caller of moveFile and related access operations, including whether both source and destination receive validation before mutation.",
        "retained_characters": 3008,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 625,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek reuse of guarded write operations, dry-run enforcement, exclusive temporary-file creation, or descriptor-based operations that limit symlink substitution.",
        "end_line": 399,
        "evidence_id": "src-3af1c30514bd02009e75c3c0",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2689,
        "original_check_index": 1,
        "purpose": "risk_hypothesis",
        "range_complete": true,
        "reason": "Follow the supplied editing function toward its eventual write and inspect adjacent read helpers for direct access after path validation.",
        "retained_characters": 2689,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 320,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek an explicit unprivileged identity, restricted filesystem exposure, or other concrete isolation settings; deployment declarations alone cannot establish runtime enforcement.",
        "end_line": 25,
        "evidence_id": "src-b8010ae783d56bfc38f97a55",
        "file_id": "file-9e181b70de0137f101e66dc0",
        "new_characters_charged": 567,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Inspect supplied deployment configuration for confinement that could limit the impact of client-selected roots or concurrent filesystem changes.",
        "retained_characters": 567,
        "source_sha256": "fc27009ddfd1d72773ddb89b0d169e449e940daa5cd1d56fe56bcc08b6e85598",
        "start_line": 1,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:2",
        "check_index": 2,
        "control_id": "EXEC-04",
        "counterevidence": "Seek explicit security-test inclusion or references to relevant fixtures, while retaining the absence of supplied test bodies and execution results as an evidence limitation.",
        "end_line": 14,
        "evidence_id": "src-c39da0c47ebf2e1715125cde",
        "file_id": "file-1e37847deefaaf829c40c17d",
        "new_characters_charged": 306,
        "original_check_index": 2,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Determine whether the supplied test configuration identifies relevant filesystem security tests or exclusions. The declared test script alone does not establish adversarial coverage.",
        "retained_characters": 306,
        "source_sha256": "a28c7034f39f5910667f49e4eee542fef853227432c2596eee2676bd5e6f96be",
        "start_line": 1,
        "status": "served"
      }
    ],
    "investigation_response": "evidence_requests",
    "investigation_round": 1,
    "model": "gpt-6-astra",
    "payload_sha256": "15b826a0af20afe6a9b8262343301f040fd669fa61a7e48cf798ed39ed4986c9",
    "protocol_version": "1.2.0",
    "provider": "codex_cli",
    "status": "completed",
    "structured_analysis_checks": 0,
    "token_optimization": {
      "bytes_saved": 729,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "10d47fd8adac84233f609d22bbb7ecbcef65a034d533477e429d8efab7f96fbd",
      "payload_bytes_after": 38813,
      "payload_bytes_before": 39542,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "15b826a0af20afe6a9b8262343301f040fd669fa61a7e48cf798ed39ed4986c9",
      "status": "optimized",
      "token_savings_measured": false
    }
  },
  {
    "adapter_version": "1.3.0",
    "batch": 1,
    "check_index_map": {
      "EXEC-04": [
        1,
        2
      ]
    },
    "checks_submitted": 2,
    "cli": {
      "arguments": [
        "-a",
        "never",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--json",
        "--color",
        "never",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "code_mode",
        "--disable",
        "code_mode_host",
        "--disable",
        "computer_use",
        "--disable",
        "browser_use",
        "--disable",
        "browser_use_external",
        "--disable",
        "browser_use_full_cdp_access",
        "--disable",
        "in_app_browser",
        "--disable",
        "image_generation",
        "--disable",
        "view_image",
        "--disable",
        "artifact",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "plugin_sharing",
        "--disable",
        "hooks",
        "--disable",
        "multi_agent",
        "--disable",
        "multi_agent_v2",
        "--disable",
        "skill_search",
        "--disable",
        "workspace_dependencies",
        "--disable",
        "shell_snapshot",
        "--disable",
        "memories",
        "--disable",
        "sleep_tool",
        "--disable",
        "goals",
        "--disable",
        "remote_plugin",
        "--disable",
        "tool_suggest",
        "-c",
        "web_search=\"disabled\"",
        "-c",
        "mcp_servers={}",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        "skills.include_instructions=false",
        "-c",
        "model_reasoning_effort=\"high\"",
        "--output-schema",
        "<private temporary directory>/response-schema.json",
        "--model",
        "gpt-6-astra",
        "-"
      ],
      "auth_mode": "cli_managed",
      "cli_version": "0.154.0",
      "descendant_termination": "process_group",
      "executable": "codex",
      "isolation": "CLI capability restrictions; installed executable and administrator policy remain trusted",
      "provider": "codex_cli",
      "repository_working_directory": false,
      "request_bytes": 60311,
      "request_sha256": "2a6d2ecb27863caf25afc59b2a3b63c2857dfe151ae0786b328a1826d4d52303",
      "requested_model": "gpt-6-astra",
      "response_bytes": 12120,
      "response_sha256": "f09f963eb1e88992375534e78fa1ccd9e045cf63643297c9c2183c011b00c6a5",
      "stage": "investigation",
      "startup_warnings": [
        "codex_code_mode_intentionally_disabled"
      ],
      "structured_output_requested": true,
      "token_budget_enforced": false,
      "token_optimization": {
        "bytes_saved": 816,
        "engine": "headroom",
        "evidence_preserved": true,
        "fallback_reason": null,
        "headroom_version": "0.37.0",
        "original_payload_sha256": "d7574b2fe5ce0d5ec5d7219e74f3e93937c71de3de082cf9be2a2e0fdb0f7999",
        "payload_bytes_after": 53779,
        "payload_bytes_before": 54595,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "05263add45da398deeee84a9d7316c080041496abef3780f6ba602d1136924dc",
        "status": "optimized",
        "token_savings_measured": false
      },
      "tools_policy": "disabled_for_advisory_review",
      "transport": "official_cli"
    },
    "control_ids": [
      "EXEC-04"
    ],
    "controls_submitted": 1,
    "evidence_ids": [
      "src-7d7e02c858a447037de50438",
      "src-17399bf8d41781072687de0c",
      "src-4f9d0004e5a942800853224f",
      "src-c01e656cad72d145f2421bf1",
      "src-d28872b02bc6a10fe16c62ab",
      "src-d0295ca728dc16eb8dc246c4",
      "src-456285d9deaeffe2ed92aa98",
      "src-79719540d5b09ece1df87e38",
      "src-9b0f9e4289167321e1be0a92",
      "src-00a7481a5f1d3f2b7fdb5396",
      "src-798ccbc00c025c20d75d0d6e",
      "src-c7e718e049f51ab7a5cfbc94",
      "src-27b002fa4ff3b6ae471400e7",
      "src-c67692042563669a512075ef",
      "src-84abde46d0ddd31836690720",
      "src-c1b896fc23175f99b9adf439",
      "src-3af1c30514bd02009e75c3c0",
      "src-b8010ae783d56bfc38f97a55",
      "src-c39da0c47ebf2e1715125cde"
    ],
    "investigation_response": "conclusions",
    "investigation_round": 2,
    "model": "gpt-6-astra",
    "omitted_checks": 0,
    "omitted_controls": 0,
    "payload_sha256": "3129edc89085202509ba59b57b4081fe8bf1bfd8ef71b3270fb1b56fe3ba7bac",
    "protocol_version": "1.2.0",
    "provider": "codex_cli",
    "status": "completed",
    "structured_analysis_checks": 2,
    "token_optimization": {
      "bytes_saved": 816,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "d7574b2fe5ce0d5ec5d7219e74f3e93937c71de3de082cf9be2a2e0fdb0f7999",
      "payload_bytes_after": 53779,
      "payload_bytes_before": 54595,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "05263add45da398deeee84a9d7316c080041496abef3780f6ba602d1136924dc",
      "status": "optimized",
      "token_savings_measured": false
    }
  }
]
```

The JSON report includes redacted evidence excerpts, original file hashes, complete per-check assessments, and deterministic provenance.
## Editable review and fresh scan

Edit only decision, reason, reviewer, reviewed_at and evidence_ref in the JSON block below. Keep IDs, bindings, subjects and origin unchanged. Save this Markdown file and pass it to a fresh scan with --review-report. JSON and SARIF expose the same editable fields; HTML provides a Download reviewed HTML button and optional PDF provides fillable fields.

Allowed decisions: empty (no decision), justified, disabled, note, needs_runtime_validation, needs_human_review. Nonempty decisions need a reason; justified/disabled decisions also need a reviewer. Evidence references are plain text, never fetched or executed. Gap records cannot waive scan failures.

Justifications are user exceptions, not validated passes. They are excluded from active counts without positive or negative credit. Evidence changes leave decisions unapplied and visible for re-review. Explicit pending runtime/human validation remains incomplete. A finding not detected on a fresh complete scan is not proof that a vulnerability was fixed.

Example: invscan /explicit/path/to/repository --review-report ./reviewed-report.md --output ./new-report

### Review fields

<!-- INVARUNE_REVIEW_BEGIN -->
```json
{
  "items": [
    {
      "binding_sha256": "0d48c32c4e3def92cc1083260ab889cb8b6f2513b008d1524023a02b0b293ef7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-04:1 Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions."
    },
    {
      "binding_sha256": "7d1f37123b0099018b87b13f7fe63762aef0f623c0c3ad41cbe2b89add1d7b35",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-04:2 Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret-directory reads."
    },
    {
      "binding_sha256": "7f1a8b8a00e928a207693ea26c4301f71e84d78787ba757dede7befc5013f574",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:b84cd8393cf85f96da36a7be6f7113729ed0c55edaef25e137aa0d33551290a1",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "index.ts: MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete"
    }
  ],
  "kind": "invarune_review",
  "origin": {
    "catalog_sha256": "468d22dfd1b6de6081998eaf5a73e05d6bba97aefcd186fce5633392535fbb9f",
    "configuration": {
      "default_excluded_directories": [
        ".cache",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "vendor",
        "venv"
      ],
      "exclude": [],
      "generated_outputs_and_judge_config_excluded": true,
      "max_entries": 100000,
      "max_file_bytes": 1000000,
      "max_files": 20000,
      "max_total_bytes": 50000000,
      "requested_scan_ids": [
        "EXEC-04"
      ],
      "selected_control_ids": [
        "EXEC-04"
      ],
      "selected_rule_ids": [
        "AI015",
        "AI016",
        "AI037",
        "AI047"
      ]
    },
    "evidence_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "image_limits": {},
    "manifest_sha256": "2540817b960ce1acb8bf6fda65ceb115b2aaf85da222a85c3ab731453584ceb3",
    "scan_id": "89791e8051d89f532704d66d4d26a1d4df049468a99252699448d9f86779e000",
    "scope_sha256": "d7f18a4233bada5bf178dfca44848920b002e71f8cff5bce6516c1c2b5388d66",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "02c1a309226db622fe6ab86ae72b3c652e370d2faae3876b7ec64049d8f5e1c5",
      "name": "agent-mcp-security-scan",
      "version": "0.15.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

