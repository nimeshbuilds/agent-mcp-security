# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `2f01d3255747009bedad350dc442b07f55b99bf94f644dab0b00f536f50d76a4`

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

Follow-up rounds: **2**; requests served / denied: **16 / 0**; captured files offered: **9**.

```text
{
  "conclusion_calls": 1,
  "enabled": true,
  "excerpt_character_budget": 120000,
  "excerpt_characters_used": 40716,
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
      "counterevidence": "Seek access-time enforcement, safe handling of nonexistent targets, and filesystem operations bound to validated objects.",
      "end_line": 219,
      "evidence_id": "src-d28872b02bc6a10fe16c62ab",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 3595,
      "original_check_index": 1,
      "purpose": "risk_hypothesis",
      "range_complete": true,
      "reason": "Trace path validation into filesystem access, including missing-path handling and writes, to assess whether attacker-controlled paths can change between validation and use.",
      "retained_characters": 3595,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 140,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek exclusive creation, no-follow handling, destination revalidation, restrictive permissions, and cleanup on failure.",
      "end_line": 299,
      "evidence_id": "src-d0295ca728dc16eb8dc246c4",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2670,
      "original_check_index": 1,
      "purpose": "risk_hypothesis",
      "range_complete": true,
      "reason": "Inspect the remainder of writing and the move operation for temporary-file placement, destination validation, overwrite behavior, and permissions.",
      "retained_characters": 2670,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 220,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek separator-aware containment, rejection of traversal and incompatible roots, and handling of absolute paths and platform differences.",
      "end_line": 86,
      "evidence_id": "src-456285d9deaeffe2ed92aa98",
      "file_id": "file-987db9b947eadc16acc4f7f9",
      "new_characters_charged": 2551,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Inspect the complete containment decision underlying the supplied realpath check; normalization alone does not establish directory containment.",
      "retained_characters": 2551,
      "source_sha256": "20833254c044c3d4d0672616ad546d50f09dae8b704c8a3619b86310f2cec3ba",
      "start_line": 7,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek mandatory validation before stream creation, constraints on tool arguments, and additional access-time guards.",
      "end_line": 234,
      "evidence_id": "src-33f17b55f6692b87f491f810",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2393,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect the streaming helper and surrounding tool registration to connect client-supplied paths to actual reads despite incomplete static callback coverage.",
      "retained_characters": 2393,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 155,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek validation on every supplied path, restrictions on batch access, and guards that prevent direct use of unvalidated arguments.",
      "end_line": 314,
      "evidence_id": "src-e5152c42b870fc2737585e01",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 3027,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Continue inspecting tool entrypoints for caller-side constraints and whether validated paths are consistently used by read operations.",
      "retained_characters": 3027,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 235,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek explicit policy intersection, rejection of invalid roots, and fail-closed behavior before initialization or after root-update failures.",
      "end_line": 786,
      "evidence_id": "src-00a7481a5f1d3f2b7fdb5396",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2865,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect how MCP roots become allowed directories and how initialization or root changes affect the filesystem authorization boundary.",
      "retained_characters": 2865,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 725,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek immutable or normalized policy state, rejection of empty or overbroad policies, and caller constraints on policy updates.",
      "end_line": 80,
      "evidence_id": "src-9c9ff329e64dbb73fd24b503",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2378,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect storage and initialization of allowed directories and the beginning of relative-path resolution used by validation.",
      "retained_characters": 2378,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:2",
      "check_index": 2,
      "control_id": "EXEC-04",
      "counterevidence": "Seek explicit filesystem security test configuration; script declarations alone cannot establish test coverage or successful execution.",
      "end_line": 43,
      "evidence_id": "src-c7e718e049f51ab7a5cfbc94",
      "file_id": "file-9b73cee629c530fd3bf63a92",
      "new_characters_charged": 1186,
      "original_check_index": 2,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Identify declared test tooling and validation scripts to determine what test evidence is available for the required adversarial filesystem cases.",
      "retained_characters": 1186,
      "source_sha256": "d91000e9d2cb2373b4dcd73027bdeb42e60790c8d7469618bad256770109bbed",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek canonical parent containment, rejection of existing symlink targets, and checks on the actual returned target rather than only the original spelling.",
      "end_line": 139,
      "evidence_id": "src-7026e2929ce6738678e5ced6",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2385,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Inspect relative-path resolution and the Unicode-equivalent fallback used for nonexistent targets, where containment of the final target remains unresolved.",
      "retained_characters": 2385,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 81,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek canonicalization, URI restrictions, directory validation, and intersection with an independently authorized server policy.",
      "end_line": 77,
      "evidence_id": "src-798ccbc00c025c20d75d0d6e",
      "file_id": "file-2f90dc06de04ee6c31f5153c",
      "new_characters_charged": 2811,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Determine what validation occurs before client-supplied MCP roots replace the allowed-directory policy.",
      "retained_characters": 2811,
      "source_sha256": "bce7c15a73dc592c23339edcd68603d08fed8d7f3d0f371db29042703f93240d",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek mandatory validation for every argument and access-time barriers or caller restrictions before filesystem operations.",
      "end_line": 394,
      "evidence_id": "src-ac462823e545f33c8551058e",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 2789,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Continue the visible tool registrations to trace client-controlled arguments into batch reads and write operations despite incomplete callback parsing.",
      "retained_characters": 2789,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 315,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek validation of all source and destination arguments, authorization constraints, exclusive creation, or restrictions on concurrent filesystem changes.",
      "end_line": 474,
      "evidence_id": "src-2af269eaaa0ccbd5f6c165d7",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 3184,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect subsequent mutation entrypoints to determine whether the write and editing helpers receive validated targets and additional restrictions.",
      "retained_characters": 3184,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 395,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek source and destination validation, no-replace semantics, serialization, or caller-side constraints that reduce overwrite and path-substitution concerns.",
      "end_line": 714,
      "evidence_id": "src-82829517a214ad7f9148b803",
      "file_id": "file-5ae3d39aff74aeb01e9363af",
      "new_characters_charged": 3066,
      "original_check_index": 1,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Inspect later tool registrations for callers of moveFile and other filesystem helpers; the visible destination existence check and rename are separate operations.",
      "retained_characters": 3066,
      "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
      "start_line": 635,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek reuse of guarded writing, dry-run restrictions, canonical containment checks, and filesystem access bound to validated objects.",
      "end_line": 379,
      "evidence_id": "src-8231e4d7134a6b2856684c44",
      "file_id": "file-efb8eb6d32ff5732dfea3c05",
      "new_characters_charged": 2950,
      "original_check_index": 1,
      "purpose": "risk_hypothesis",
      "range_complete": true,
      "reason": "Follow applyFileEdits through its eventual write and inspect adjacent operations for enforcement omitted from the current excerpts.",
      "retained_characters": 2950,
      "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
      "start_line": 300,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:1",
      "check_index": 1,
      "control_id": "EXEC-04",
      "counterevidence": "Seek an unprivileged runtime identity, restricted filesystem exposure, and permission constraints; distinguish image configuration from actual deployment guarantees.",
      "end_line": 25,
      "evidence_id": "src-b8010ae783d56bfc38f97a55",
      "file_id": "file-9e181b70de0137f101e66dc0",
      "new_characters_charged": 567,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "Inspect the supplied deployment definition for containment or permission barriers relevant to filesystem races and secret-directory access.",
      "retained_characters": 567,
      "source_sha256": "fc27009ddfd1d72773ddb89b0d169e449e940daa5cd1d56fe56bcc08b6e85598",
      "start_line": 1,
      "status": "served"
    },
    {
      "check_id": "EXEC-04:2",
      "check_index": 2,
      "control_id": "EXEC-04",
      "counterevidence": "Seek explicit security-test inclusion or exclusions; configuration alone cannot establish that the required cases exist or were executed.",
      "end_line": 14,
      "evidence_id": "src-c39da0c47ebf2e1715125cde",
      "file_id": "file-1e37847deefaaf829c40c17d",
      "new_characters_charged": 306,
      "original_check_index": 2,
      "purpose": "boundary_context",
      "range_complete": true,
      "reason": "Determine whether the declared test configuration supplies any concrete coverage context for adversarial filesystem tests.",
      "retained_characters": 306,
      "source_sha256": "a28c7034f39f5910667f49e4eee542fef853227432c2596eee2676bd5e6f96be",
      "start_line": 1,
      "status": "served"
    }
  ],
  "requests_attempted": 16,
  "requests_denied": 0,
  "requests_served": 16,
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

Visible MCP handlers validate caller\-supplied paths before filesystem operations, and validatePath checks both requested\-path containment and resolved symlink targets\. However, validation returns a pathname that subsequent operations resolve again\. If an attacker can replace filesystem components between validation and access, these checks may not constrain the actual object accessed\. Atomic replacement and exclusive initial creation provide useful protection, but do not establish protection against parent\-directory substitution\. Editing also writes a temporary file without explicit exclusive creation or restrictive permissions\. These are unverified concerns whose impact depends on concurrent filesystem access, deployment permissions, and umask\. Upload, download, and extraction coverage cannot be established from the excerpts\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** MCP tool arguments cross from the client or agent into server\-side filesystem access\. Canonical pathname checks are useful barriers, but their effectiveness at access time depends on namespace stability and deployment isolation\.

**When this applies:** Prioritize changes where another principal can mutate accessible filesystem components or observe temporary files\. Establish the intended roots authority and runtime permission policy before changing those behaviors\.

1. Retain requested\-path and resolved\-target containment checks\. Where concurrent namespace mutation is possible, use filesystem operations anchored to trusted directory handles with platform\-enforced containment, or isolate the server so unauthorized principals cannot replace ancestors\.
2. Create temporary files exclusively with restrictive initial permissions, such as fs\.open with 'wx' and mode 0o600, then write and apply the intended permissions through the same FileHandle before publication\. Ancestor containment still requires a separate barrier\.
3. Review moveFile's separate existence check and rename against its no\-overwrite contract; use an appropriate atomic no\-replace operation or an explicitly enforced concurrency restriction where necessary\.
4. Document the authority of client\-provided roots\. If clients must not expand server authorization, intersect requested roots with an independently configured server policy\.

**How to verify:**

- Retain regression evidence showing permitted operations work and unauthorized objects remain inaccessible during controlled filesystem substitutions\.
- Confirm temporary files never expose content more broadly than the approved permission policy, including failure cases\.
- Record deployment constraints and roots authorization decisions alongside adversarial test results\.

**Risk hypothesis:** An attacker able to mutate filesystem components could redirect a pathname after validation but before access\. A principal with directory access could also potentially observe replacement content under default temporary\-file permissions\.

**Trust boundary:** Client\-controlled tool paths enter validatePath, which returns canonical strings consumed by filesystem helpers\. The unresolved boundary is between checking a pathname and accessing the filesystem object currently named by it\.

**Counterevidence considered:** The supplied code checks lexical containment and resolved symlink targets, validates visible tool arguments, checks resolved Unicode components, uses 'wx' for initial creation, and uses randomized temporary names and atomic rename for replacement\. These reduce static traversal and leaf\-target risks\. A deployment preventing hostile namespace mutation could further limit exposure, but actual deployment constraints are unprovided\.

**Conclusion limits:** No race or disclosure was executed or demonstrated\. Filesystem permissions, umask, caller restrictions, and omitted helpers may change the assessment\. The callback parse diagnostic remains unresolved; manually following supplied handlers does not establish complete entrypoint coverage\. Archive and transfer applicability remains unknown\.

Evidence src\-ac462823e545f33c8551058e: index\.ts:374–375 (exact quote verified).

```text
const validPath = await validatePath(args.path);
    await writeFileContent(validPath, args.content);
```

Evidence src\-d28872b02bc6a10fe16c62ab: lib\.ts:163–168 (exact quote verified).

```text
const realPath = await fs.realpath(absolute);
    const normalizedReal = normalizePath(realPath);
    if (!isPathWithinAllowedDirectories(normalizedReal, allowedDirectories)) {
      throw new Error(`Access denied - symlink target outside allowed directories: ${realPath} not in ${allowedDirectories.join(', ')}`);
    }
    return realPath;
```

Evidence src\-8231e4d7134a6b2856684c44: lib\.ts:341–344 (exact quote verified).

```text
const tempPath = `${filePath}.${randomBytes(16).toString('hex')}.tmp`;
    try {
      await fs.writeFile(tempPath, modifiedContent, 'utf-8');
      await fs.rename(tempPath, filePath);
```

Verification still required:
- In an authorized isolated environment, exercise leaf and ancestor replacement between validation and reads, writes, edits, directory creation, and moves; check the actual objects accessed\.
- Inspect temporary\-file permissions throughout replacement, including restrictive original permissions and permission\-restoration failures\.
- Review deployment identity, directory ownership, mounts, and whether another principal can modify allowed\-directory ancestors\.
- Confirm who may authorize MCP roots, whether empty root updates revoke access, and whether secrets can fall within an authorized root\.
- Obtain the remaining tool implementations and any upload, download, or extraction handlers; resolve entrypoint coverage separately from this review\.

**Check 2: insufficient\_evidence**

The supplied configuration establishes a Vitest test environment and coverage provider, but includes no test bodies or execution results demonstrating symlink races, archive traversal, absolute\-path handling, overwrite attempts, or secret\-directory reads\. Existing path guards identify useful test targets but do not demonstrate testing\. Missing test evidence does not establish that these tests are absent\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Tests must exercise the MCP argument\-to\-filesystem boundary and any roots\-policy changes, since helper tests alone may miss entrypoint\-specific behavior\.

**When this applies:** First obtain existing tests and results\. Add missing cases only after comparing their coverage with the acceptance check; archive testing depends on whether extraction is exposed directly or indirectly\.

1. Map existing tests to symlink races, traversal, absolute paths, overwrite attempts, and secret\-directory reads, including end\-to\-end MCP calls\.
2. Where missing, add coordinated leaf and ancestor substitution tests covering reads, edits, writes, directory creation, and moves\.
3. Distinguish authorized write\_file replacement from forbidden move\_file destination replacement, including concurrent destination creation\.
4. Use synthetic secret fixtures outside authorized roots and verify that no contents are returned or modified; include roots expansion and revocation scenarios\.
5. For any extraction surface, cover traversal entries, absolute entries, link entries, destination overwrites, and temporary\-file permissions\.

**How to verify:**

- Have the owner review test assertions and retain execution results tied to the reviewed revision and deployment platform\.
- Confirm tests inspect resulting objects, contents, and permissions rather than relying only on error messages or coverage percentages\.
- Record unresolved platform behavior and any human\-confirmed archive applicability decision\.

**Risk hypothesis:** Filesystem boundary regressions could remain undetected if tests cover only normalization or static symlinks and omit concurrent replacement, forbidden overwrites, or unauthorized content reads\.

**Trust boundary:** The required evidence concerns adversarial validation of MCP filesystem access and any archive processing, from supplied arguments through observable filesystem effects\.

**Counterevidence considered:** Vitest configuration and coverage instrumentation show a testing mechanism is configured\. Existing security tests elsewhere are a plausible alternative, but no test bodies or results were supplied\. Visible implementation guards do not establish test coverage\.

**Conclusion limits:** Test existence, completeness, and outcomes cannot be determined\. No runtime validation occurred\. Archive functionality is unresolved, and incomplete callback parsing further limits confidence in the tested\-surface inventory\.

Evidence src\-c39da0c47ebf2e1715125cde: vitest\.config\.ts:5–6 (exact quote verified).

```text
globals: true,
    environment: 'node',
```

Evidence src\-c39da0c47ebf2e1715125cde: vitest\.config\.ts:9–9 (exact quote verified).

```text
provider: 'v8',
```

Verification still required:
- Obtain security test bodies and recent authorized execution results mapped to every requested scenario and supported platform\.
- Verify that race tests coordinate changes between validation and access, rather than testing only pre\-existing symlinks\.
- Review absolute\-path, traversal, overwrite, and secret\-read assertions for checks on actual filesystem effects and returned content\.
- Identify any archive extraction surface and its tests, or obtain an owner\-confirmed applicability assessment supported by complete surface coverage\.

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
| Control request 2 | headroom | headroom | optimized | 38903 | 38174 | 729 |
| Control request 3 | headroom | headroom | optimized | 59989 | 59124 | 865 |

Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.

```text
{
  "adapter_version": "1.3.0",
  "additional_concern_actions": [
    {
      "concern_index": 1,
      "recommended_actions": {
        "agent_mcp_relevance": "Applicability is unestablished because no agent or MCP implementation evidence is supplied; uncovered files could contain relevant trust boundaries.",
        "applicability": "Further review applies if the coverage gap affects files or configuration within the intended assessment scope.",
        "steps": [
          "Obtain the scanner's coverage-gap details, intended file inventory, and exclusion configuration before proposing code changes; no specific vulnerable API or incorrect setting is established.",
          "Resolve applicable read or scope issues and repeat static analysis; arrange source review for relevant files unsupported by the scanner."
        ],
        "verification": [
          "Compare the assessed file inventory against the intended scope and document every remaining exclusion or unsupported file.",
          "Confirm whether relevant agent/MCP entry points were covered; assess runtime authorization and isolation separately if those components exist."
        ]
      }
    }
  ],
  "additional_concerns": [
    "Review coverage is incomplete: the payload reports one coverage gap and scan_complete_within_selected_scope=false, with no source context. Zero reported findings does not establish security. The gap details and intended file inventory are needed to determine what remains unassessed."
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
    "request_sha256": "1cbfb6fb95ad2a2c18d67e524b2eb46ca2f811b54bd97f39a0d5b210b9386f28",
    "requested_model": "gpt-6-astra",
    "response_bytes": 1942,
    "response_sha256": "b3c712bdfbae0184ebd289861f2c6decef2240688790843d0f99d465b9bbb50e",
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
      "original_payload_sha256": "adcdb02f28a0cd3b6a65004baeda9aa3717c8a3193f0aff9de94684df692a9fb",
      "payload_bytes_after": 1185,
      "payload_bytes_before": 1229,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "e098314e436eef915ee8b3fbd72426d928cb19c372e24aad98cccc84b3dbcbe0",
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
    "original_payload_sha256": "adcdb02f28a0cd3b6a65004baeda9aa3717c8a3193f0aff9de94684df692a9fb",
    "payload_bytes_after": 1185,
    "payload_bytes_before": 1229,
    "requested": "headroom",
    "schema_version": "1.0",
    "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
    "sent_payload_sha256": "e098314e436eef915ee8b3fbd72426d928cb19c372e24aad98cccc84b3dbcbe0",
    "status": "optimized",
    "token_savings_measured": false
  }
}
```
### Additional model concern 1 (unverified)

Review coverage is incomplete: the payload reports one coverage gap and scan\_complete\_within\_selected\_scope=false, with no source context\. Zero reported findings does not establish security\. The gap details and intended file inventory are needed to determine what remains unassessed\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Applicability is unestablished because no agent or MCP implementation evidence is supplied; uncovered files could contain relevant trust boundaries\.

**When this applies:** Further review applies if the coverage gap affects files or configuration within the intended assessment scope\.

1. Obtain the scanner's coverage\-gap details, intended file inventory, and exclusion configuration before proposing code changes; no specific vulnerable API or incorrect setting is established\.
2. Resolve applicable read or scope issues and repeat static analysis; arrange source review for relevant files unsupported by the scanner\.

**How to verify:**

- Compare the assessed file inventory against the intended scope and document every remaining exclusion or unsupported file\.
- Confirm whether relevant agent/MCP entry points were covered; assess runtime authorization and isolation separately if those components exist\.


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
    "requested_characters_selected": 38723,
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
      "request_sha256": "e119da22e34a6843f3fd8e9c12d17e73505f83bb29be6197559f666367181735",
      "requested_model": "gpt-6-astra",
      "response_bytes": 4416,
      "response_sha256": "e43a5c5e88603c3345fc7b7e984821fb742ba7c32c56403264dc1e0a1fd76145",
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
        "original_payload_sha256": "817d4c8c4036abe68682116b4592a845c92ed15c30c3ec04ce430853a34f76bc",
        "payload_bytes_after": 8689,
        "payload_bytes_before": 9025,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "bd3857692aa0fd1060d4b215fbe7e7da0643963bf7c14df4782522cbd014aa39",
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
        "counterevidence": "Seek access-time enforcement, safe handling of nonexistent targets, and filesystem operations bound to validated objects.",
        "end_line": 219,
        "evidence_id": "src-d28872b02bc6a10fe16c62ab",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 3595,
        "original_check_index": 1,
        "purpose": "risk_hypothesis",
        "range_complete": true,
        "reason": "Trace path validation into filesystem access, including missing-path handling and writes, to assess whether attacker-controlled paths can change between validation and use.",
        "retained_characters": 3595,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 140,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek exclusive creation, no-follow handling, destination revalidation, restrictive permissions, and cleanup on failure.",
        "end_line": 299,
        "evidence_id": "src-d0295ca728dc16eb8dc246c4",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2670,
        "original_check_index": 1,
        "purpose": "risk_hypothesis",
        "range_complete": true,
        "reason": "Inspect the remainder of writing and the move operation for temporary-file placement, destination validation, overwrite behavior, and permissions.",
        "retained_characters": 2670,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 220,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek separator-aware containment, rejection of traversal and incompatible roots, and handling of absolute paths and platform differences.",
        "end_line": 86,
        "evidence_id": "src-456285d9deaeffe2ed92aa98",
        "file_id": "file-987db9b947eadc16acc4f7f9",
        "new_characters_charged": 2551,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Inspect the complete containment decision underlying the supplied realpath check; normalization alone does not establish directory containment.",
        "retained_characters": 2551,
        "source_sha256": "20833254c044c3d4d0672616ad546d50f09dae8b704c8a3619b86310f2cec3ba",
        "start_line": 7,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek mandatory validation before stream creation, constraints on tool arguments, and additional access-time guards.",
        "end_line": 234,
        "evidence_id": "src-33f17b55f6692b87f491f810",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2393,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect the streaming helper and surrounding tool registration to connect client-supplied paths to actual reads despite incomplete static callback coverage.",
        "retained_characters": 2393,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 155,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek validation on every supplied path, restrictions on batch access, and guards that prevent direct use of unvalidated arguments.",
        "end_line": 314,
        "evidence_id": "src-e5152c42b870fc2737585e01",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 3027,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Continue inspecting tool entrypoints for caller-side constraints and whether validated paths are consistently used by read operations.",
        "retained_characters": 3027,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 235,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek explicit policy intersection, rejection of invalid roots, and fail-closed behavior before initialization or after root-update failures.",
        "end_line": 786,
        "evidence_id": "src-00a7481a5f1d3f2b7fdb5396",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2865,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect how MCP roots become allowed directories and how initialization or root changes affect the filesystem authorization boundary.",
        "retained_characters": 2865,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 725,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek immutable or normalized policy state, rejection of empty or overbroad policies, and caller constraints on policy updates.",
        "end_line": 80,
        "evidence_id": "src-9c9ff329e64dbb73fd24b503",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2378,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect storage and initialization of allowed directories and the beginning of relative-path resolution used by validation.",
        "retained_characters": 2378,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 1,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:2",
        "check_index": 2,
        "control_id": "EXEC-04",
        "counterevidence": "Seek explicit filesystem security test configuration; script declarations alone cannot establish test coverage or successful execution.",
        "end_line": 43,
        "evidence_id": "src-c7e718e049f51ab7a5cfbc94",
        "file_id": "file-9b73cee629c530fd3bf63a92",
        "new_characters_charged": 1186,
        "original_check_index": 2,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Identify declared test tooling and validation scripts to determine what test evidence is available for the required adversarial filesystem cases.",
        "retained_characters": 1186,
        "source_sha256": "d91000e9d2cb2373b4dcd73027bdeb42e60790c8d7469618bad256770109bbed",
        "start_line": 1,
        "status": "served"
      }
    ],
    "investigation_response": "evidence_requests",
    "investigation_round": 0,
    "model": "gpt-6-astra",
    "payload_sha256": "bd3857692aa0fd1060d4b215fbe7e7da0643963bf7c14df4782522cbd014aa39",
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
      "original_payload_sha256": "817d4c8c4036abe68682116b4592a845c92ed15c30c3ec04ce430853a34f76bc",
      "payload_bytes_after": 8689,
      "payload_bytes_before": 9025,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "bd3857692aa0fd1060d4b215fbe7e7da0643963bf7c14df4782522cbd014aa39",
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
      "request_bytes": 44706,
      "request_sha256": "5e6bcd8e732b86bf00d345873d1e38a3375ce8ec7262440a29079db996dd9af7",
      "requested_model": "gpt-6-astra",
      "response_bytes": 4496,
      "response_sha256": "ffa4021ab42cba004a6fff9eacfda9e61560fbb2361260e8e51d6a6e5a16ff2a",
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
        "original_payload_sha256": "d14662a71c20630dcd2ec8f12849c08b39d863033c378d6c86082c97210f9ff9",
        "payload_bytes_after": 38174,
        "payload_bytes_before": 38903,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "b78702cf07a5c69181d2be060cabfc1cda762ed9be758b780963082e8b71d19c",
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
      "src-33f17b55f6692b87f491f810",
      "src-e5152c42b870fc2737585e01",
      "src-00a7481a5f1d3f2b7fdb5396",
      "src-9c9ff329e64dbb73fd24b503",
      "src-c7e718e049f51ab7a5cfbc94"
    ],
    "evidence_request_receipts": [
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek canonical parent containment, rejection of existing symlink targets, and checks on the actual returned target rather than only the original spelling.",
        "end_line": 139,
        "evidence_id": "src-7026e2929ce6738678e5ced6",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2385,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Inspect relative-path resolution and the Unicode-equivalent fallback used for nonexistent targets, where containment of the final target remains unresolved.",
        "retained_characters": 2385,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 81,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek canonicalization, URI restrictions, directory validation, and intersection with an independently authorized server policy.",
        "end_line": 77,
        "evidence_id": "src-798ccbc00c025c20d75d0d6e",
        "file_id": "file-2f90dc06de04ee6c31f5153c",
        "new_characters_charged": 2811,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Determine what validation occurs before client-supplied MCP roots replace the allowed-directory policy.",
        "retained_characters": 2811,
        "source_sha256": "bce7c15a73dc592c23339edcd68603d08fed8d7f3d0f371db29042703f93240d",
        "start_line": 1,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek mandatory validation for every argument and access-time barriers or caller restrictions before filesystem operations.",
        "end_line": 394,
        "evidence_id": "src-ac462823e545f33c8551058e",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 2789,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Continue the visible tool registrations to trace client-controlled arguments into batch reads and write operations despite incomplete callback parsing.",
        "retained_characters": 2789,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 315,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek validation of all source and destination arguments, authorization constraints, exclusive creation, or restrictions on concurrent filesystem changes.",
        "end_line": 474,
        "evidence_id": "src-2af269eaaa0ccbd5f6c165d7",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 3184,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect subsequent mutation entrypoints to determine whether the write and editing helpers receive validated targets and additional restrictions.",
        "retained_characters": 3184,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 395,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek source and destination validation, no-replace semantics, serialization, or caller-side constraints that reduce overwrite and path-substitution concerns.",
        "end_line": 714,
        "evidence_id": "src-82829517a214ad7f9148b803",
        "file_id": "file-5ae3d39aff74aeb01e9363af",
        "new_characters_charged": 3066,
        "original_check_index": 1,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Inspect later tool registrations for callers of moveFile and other filesystem helpers; the visible destination existence check and rename are separate operations.",
        "retained_characters": 3066,
        "source_sha256": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        "start_line": 635,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek reuse of guarded writing, dry-run restrictions, canonical containment checks, and filesystem access bound to validated objects.",
        "end_line": 379,
        "evidence_id": "src-8231e4d7134a6b2856684c44",
        "file_id": "file-efb8eb6d32ff5732dfea3c05",
        "new_characters_charged": 2950,
        "original_check_index": 1,
        "purpose": "risk_hypothesis",
        "range_complete": true,
        "reason": "Follow applyFileEdits through its eventual write and inspect adjacent operations for enforcement omitted from the current excerpts.",
        "retained_characters": 2950,
        "source_sha256": "d67db7074d9823a306e83326a4362e477e0ff7492fb484e015a15abad761b495",
        "start_line": 300,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:1",
        "check_index": 1,
        "control_id": "EXEC-04",
        "counterevidence": "Seek an unprivileged runtime identity, restricted filesystem exposure, and permission constraints; distinguish image configuration from actual deployment guarantees.",
        "end_line": 25,
        "evidence_id": "src-b8010ae783d56bfc38f97a55",
        "file_id": "file-9e181b70de0137f101e66dc0",
        "new_characters_charged": 567,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "Inspect the supplied deployment definition for containment or permission barriers relevant to filesystem races and secret-directory access.",
        "retained_characters": 567,
        "source_sha256": "fc27009ddfd1d72773ddb89b0d169e449e940daa5cd1d56fe56bcc08b6e85598",
        "start_line": 1,
        "status": "served"
      },
      {
        "check_id": "EXEC-04:2",
        "check_index": 2,
        "control_id": "EXEC-04",
        "counterevidence": "Seek explicit security-test inclusion or exclusions; configuration alone cannot establish that the required cases exist or were executed.",
        "end_line": 14,
        "evidence_id": "src-c39da0c47ebf2e1715125cde",
        "file_id": "file-1e37847deefaaf829c40c17d",
        "new_characters_charged": 306,
        "original_check_index": 2,
        "purpose": "boundary_context",
        "range_complete": true,
        "reason": "Determine whether the declared test configuration supplies any concrete coverage context for adversarial filesystem tests.",
        "retained_characters": 306,
        "source_sha256": "a28c7034f39f5910667f49e4eee542fef853227432c2596eee2676bd5e6f96be",
        "start_line": 1,
        "status": "served"
      }
    ],
    "investigation_response": "evidence_requests",
    "investigation_round": 1,
    "model": "gpt-6-astra",
    "payload_sha256": "79e4801a7db2b3d21e9e9c4bf72b91d6f33554a0fba5f1ada587d10443ed83f7",
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
      "original_payload_sha256": "d14662a71c20630dcd2ec8f12849c08b39d863033c378d6c86082c97210f9ff9",
      "payload_bytes_after": 38174,
      "payload_bytes_before": 38903,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "b78702cf07a5c69181d2be060cabfc1cda762ed9be758b780963082e8b71d19c",
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
      "request_bytes": 65656,
      "request_sha256": "b8d8a94cff3f9f4fd3da79d3b08fdde1f672fbc926212f904f73224643d6291d",
      "requested_model": "gpt-6-astra",
      "response_bytes": 11561,
      "response_sha256": "aa99dcf10c237a8db49ff0ab81b9e1f768a45a93cad09a86557b488c56da1cad",
      "stage": "investigation",
      "startup_warnings": [
        "codex_code_mode_intentionally_disabled"
      ],
      "structured_output_requested": true,
      "token_budget_enforced": false,
      "token_optimization": {
        "bytes_saved": 865,
        "engine": "headroom",
        "evidence_preserved": true,
        "fallback_reason": null,
        "headroom_version": "0.37.0",
        "original_payload_sha256": "01e55d9d0bbdd85d1e60210955713a4c81248c8faa508b0e98775355626a2dc4",
        "payload_bytes_after": 59124,
        "payload_bytes_before": 59989,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "9045c32f3cab420e94554c3a2647c04ed0da8acaa518e4e388c0a2d7fefefef6",
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
      "src-33f17b55f6692b87f491f810",
      "src-e5152c42b870fc2737585e01",
      "src-00a7481a5f1d3f2b7fdb5396",
      "src-9c9ff329e64dbb73fd24b503",
      "src-c7e718e049f51ab7a5cfbc94",
      "src-7026e2929ce6738678e5ced6",
      "src-798ccbc00c025c20d75d0d6e",
      "src-ac462823e545f33c8551058e",
      "src-2af269eaaa0ccbd5f6c165d7",
      "src-82829517a214ad7f9148b803",
      "src-8231e4d7134a6b2856684c44",
      "src-b8010ae783d56bfc38f97a55",
      "src-c39da0c47ebf2e1715125cde"
    ],
    "investigation_response": "conclusions",
    "investigation_round": 2,
    "model": "gpt-6-astra",
    "omitted_checks": 0,
    "omitted_controls": 0,
    "payload_sha256": "c221ee71d20417bd79d4935ca816613c1acd0642f48b39da88d9b0406a7277e1",
    "protocol_version": "1.2.0",
    "provider": "codex_cli",
    "status": "completed",
    "structured_analysis_checks": 2,
    "token_optimization": {
      "bytes_saved": 865,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "01e55d9d0bbdd85d1e60210955713a4c81248c8faa508b0e98775355626a2dc4",
      "payload_bytes_after": 59124,
      "payload_bytes_before": 59989,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "9045c32f3cab420e94554c3a2647c04ed0da8acaa518e4e388c0a2d7fefefef6",
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
      "binding_sha256": "991cdd9638c7520e68e6515db8b9f559ef0da6cc8be650ce4ecd0ab0b1e5f890",
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
      "binding_sha256": "8345dc45e9b1f075a7c19bb286c4cafc06589fc8a32123064a9baac2275ed136",
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
      "binding_sha256": "e0ae5be75e42f42bb54d5a88dd207659071285681196200431ee47a98a59acf7",
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
    "scan_id": "2f01d3255747009bedad350dc442b07f55b99bf94f644dab0b00f536f50d76a4",
    "scope_sha256": "d7f18a4233bada5bf178dfca44848920b002e71f8cff5bce6516c1c2b5388d66",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "525747fc453830a4bc93b887c21161ff44c21212af1a525bbd5a9d615086954b",
      "name": "agent-mcp-security-scan",
      "version": "0.15.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

