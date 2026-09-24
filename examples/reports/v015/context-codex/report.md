# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `d4246648ec0e739efdbd0fc8a03c8670f095828210e5768af2e3e1c7a8cad202`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### No configured risk patterns detected

The selected static scope completed without a detector match\. This is not a security pass\. Review the unassessed boundaries and validate the controls below\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 | 0 |

**1 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 0/0 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 2/2 answered checks. These are proposed changes requiring verification.

**Execution:** exit 0; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** completed. Model advice is separate from the deterministic assessment and cannot lower these priorities.

Control-review status: **completed**; 1/1 controls answered, 0 unanswered checks. An answered check is not a passed check.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

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

**Selected scope:** 1 rules (1 active), 1 controls (1 active), 2 active acceptance checks. The selected static scope completed. Recorded coverage gaps: 0.

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
| Selected deterministic rules | 1 |
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
      "EXEC-05"
    ],
    "selected_control_ids": [
      "EXEC-05"
    ],
    "selected_rule_ids": [
      "AI014"
    ]
  }
}
```

## Scan details

Scanned **2 files**; **0 open findings**, **0 suppressed findings**, and **0 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 | 0 |

Source I/O: **1243 bytes read**, **1243 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| python\_ast | 2 | Python AST, bounded aliases/values, selected same\-file argument/return flow, exact literal guards and read\-only tool write witnesses; no whole\-program or runtime proof\. |

Severity failure threshold: **high** · Process exit code: **0**.

### Advisory security analyst

Review status: **completed** · Controls reviewed: **1/1** · Unanswered checks: **0** · Control requests: **2/3**.

Every active control is routed for review because static patterns cannot establish completion. Review completion means an answer was received for every active check; it does not mean the checks passed. User-justified and disabled checks are excluded from review counts. The model is nondeterministic. Evidence selection, schema checks, and exact-quote validation are deterministic. Runtime execution and model tools are disabled.

| Advisory check status | Count |
|---|---:|
| insufficient\_evidence | 1 |
| potential\_gap | 1 |

### Bounded evidence investigation

The model may request exact ranges from verified, redacted snapshots; the controller enforces file IDs, scope, shared budgets and quote validation. No target tools or code execute. Requests do not resolve runtime uncertainty.

Follow-up rounds: **1**; requests served / denied: **1 / 0**; captured files offered: **2**.

```text
{
  "conclusion_calls": 1,
  "enabled": true,
  "excerpt_character_budget": 120000,
  "excerpt_characters_used": 1471,
  "inventory_characters": 491,
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
      "check_id": "EXEC-05:1",
      "check_index": 1,
      "control_id": "EXEC-05",
      "counterevidence": "Seek lane-specific rejection, destination allowlists, URL parsing, IP/DNS validation, or other constraints protecting lane 1. Redirect following is already explicitly disabled at the visible request call.",
      "end_line": 41,
      "evidence_id": "src-e5731df412d29009bbf4b319",
      "file_id": "file-01133ae2e5e076d2cc2525ac",
      "new_characters_charged": 324,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "tool_forward passes caller-controlled user_url to dispatch with lane 1. Inspect _admit to determine what destination and scheme constraints apply before requests.post, and whether the constant-destination lane has different enforcement.",
      "retained_characters": 324,
      "source_sha256": "b7995f3334ed328ff74ebdf4834b75fe7b4a84cb608c6e8408490f89b1cd8c9c",
      "start_line": 13,
      "status": "served"
    }
  ],
  "requests_attempted": 1,
  "requests_denied": 0,
  "requests_served": 1,
  "rounds_completed": 1,
  "snapshot_files_offered": 2,
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

### EXEC\-05: Prevent SSRF and unsafe network destinations

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect\.
- [ ] Test loopback, private/link\-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect\-to\-private cases\.

Partial static rules: AI014

**Advisory analyst:** reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: potential\_gap**

The visible tool\_forward entry point passes caller\-selected user\_url to dispatch with lane 1\. The predicate accepts lane 1 regardless of destination, so its constant\-destination comparison does not constrain this entry point before requests\.post\. Disabling redirects provides a concrete barrier against redirect\-based destination changes\. Application\-level scheme restrictions and connection\-time IP/DNS enforcement are not established by the supplied flow\. This is an explicitly labeled inert fixture; deployment, external egress restrictions, and exploitability remain unverified\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** The relevant boundary is caller\-controlled tool input becoming an outbound HTTP request\. If this entry point is exposed through an agent or MCP tool, lane 1 currently bypasses the visible destination comparison\.

**When this applies:** Apply changes if this fixture reflects production behavior and callers can influence destinations\. First establish the intended destination policy and any independently enforced egress restrictions\.

1. Replace unconditional lane\-1 admission in \_admit with destination\-policy enforcement for every caller\-controlled request, using explicit permitted schemes, hosts, and ports\.
2. Use a transport or enforcing egress proxy that validates resolved IPv4 and IPv6 destinations and binds the actual connection to an approved address, preventing DNS changes from bypassing validation\.
3. Retain allow\_redirects=False\. If redirects become necessary, enforce the same destination and connection policy independently on every hop\.

**How to verify:**

- Review that no caller\-controlled lane can bypass the destination policy\.
- Retain isolated integration evidence showing prohibited addresses are blocked at connection time, including DNS changes and redirect responses\.

**Risk hypothesis:** A caller could supply an internal or metadata destination through user\_url; lane 1 satisfies \_admit without checking that URL, allowing it to reach requests\.post if downstream network controls permit\.

**Trust boundary:** tool\_forward receives caller\-selected URL and content, dispatch applies \_admit, and requests\.post performs the outbound operation\. The visible predicate does not enforce a destination restriction for lane 1\.

**Counterevidence considered:** The rejection branch was inspected, but its predicate admits lane 1 unconditionally\. The sibling fixed\_forward uses a constant destination and lane 0, which does not constrain tool\_forward\. allow\_redirects=False blocks automatic redirect following\. Fixture labeling provides an alternative explanation for the intentionally permissive code\.

**Conclusion limits:** The static flow supports an advisory concern, not a confirmed vulnerability\. Actual tool registration, upstream validation, transport behavior, DNS resolution, deployment reachability, and external egress barriers are unresolved\.

Evidence src\-ea8f5ad7a1e9b55c0a223d85: agent\.py:5–7 (exact quote verified).

```text
def tool_forward(user_url, user_content):
    """Forward a caller-selected record through the delivery boundary."""
    return dispatch(1, user_url, user_content)
```

Evidence src\-e5731df412d29009bbf4b319: delivery\.py:17–18 (exact quote verified).

```text
def _admit(a, b):
    return a == 1 or b == "https://approved.invalid"
```

Evidence src\-6a02164f7498f198ded37c26: delivery\.py:37–41 (exact quote verified).

```text
def dispatch(lane, addr, record):
    if not _admit(lane, addr):
        raise ValueError("Unsupported destination")
    return requests.post(addr, json={"record": record}, timeout=5,
                         allow_redirects=False)
```

Verification still required:
- Confirm whether this fixture represents a deployed agent tool and identify caller authorization, URL constraints, and outbound proxy or firewall enforcement\.
- In an authorized isolated environment, verify that rejected destinations produce no connection and that DNS changes cannot move an admitted request to a prohibited address\.
- Verify that redirects remain disabled throughout the delivery chain, including any caller retries or response handling\.

**Check 2: insufficient\_evidence**

No test definitions, coverage records, or execution results are supplied for the required destination classes and encoding cases\. The visible caller\-controlled flow identifies what needs testing, and allow\_redirects=False provides a behavior to validate, but neither establishes that adversarial tests exist or succeed\. The fixture label also limits inference about a deployed service\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Tests should exercise the caller\-controlled tool\_forward boundary because a fixed\-destination sibling does not demonstrate protection for agent\-selected URLs\.

**When this applies:** First identify the actual production implementation and existing test suite\. Missing submitted tests do not establish that tests are absent; do not execute the supplied inert fixture\.

1. If coverage is missing, add a destination\-policy matrix covering both address families, metadata destinations, alternate numeric encodings, IPv4\-mapped IPv6, and public\-to\-private redirects\.
2. Include controlled DNS changes between validation and connection, and assert that prohibited destinations receive no connection\.
3. Exercise the caller\-selected entry point and confirm redirect responses do not trigger follow\-up requests while allow\_redirects=False is retained\.

**How to verify:**

- Review test inputs, expected policy decisions, and connection observations for every required case\.
- Retain authorized integration results tied to the production transport and egress configuration; mocked policy tests alone do not establish connection\-time enforcement\.

**Risk hypothesis:** Destination restrictions could appear effective for ordinary URLs while failing for alternate encodings, IPv6, DNS changes, or redirect handling unless those cases are tested\.

**Trust boundary:** The relevant test boundary spans caller\-selected tool input, admission logic, HTTP transport, DNS, and effective outbound network controls\.

**Counterevidence considered:** Redirect following is explicitly disabled, reducing one attack route\. The source labels itself an inert fixture, so production tests may exist elsewhere\. No supplied test evidence establishes either coverage or its absence\.

**Conclusion limits:** Test completeness and runtime outcomes cannot be assessed from these excerpts\. Additional test artifacts and authorized runtime validation are required\.

Evidence src\-1c85609fb313cbfd95eb25cd: delivery\.py:1–1 (exact quote verified).

```text
"""Inert review fixture: network calls below must never be executed."""
```

Evidence src\-ea8f5ad7a1e9b55c0a223d85: agent\.py:7–7 (exact quote verified).

```text
return dispatch(1, user_url, user_content)
```

Evidence src\-6a02164f7498f198ded37c26: delivery\.py:40–41 (exact quote verified).

```text
return requests.post(addr, json={"record": record}, timeout=5,
                         allow_redirects=False)
```

Verification still required:
- Obtain existing test definitions and results covering loopback, private and link\-local IPv4 and IPv6, cloud metadata, alternate address encodings, and redirect\-to\-private destinations\.
- Have an authorized owner validate the actual deployment boundary in an isolated test environment with controlled DNS and destination simulators, recording attempted connections as well as returned errors\.

- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

## Coverage and limitations

- Static pattern and local syntax analysis do not prove exploitability, authentication, isolation, or absence of vulnerabilities\.
- Python receives AST\-based call checks; other source languages receive selected textual/configuration checks, not whole\-program dataflow\.
- No dependencies are installed, target code executed, services contacted, or CVE feed queried\.
- Default excluded directories and unsupported files remain outside the selected scan scope\.
- Prompt injection resistance, authorization, tenant separation, runtime egress, and human approval need adversarial/runtime validation\.
- Evidence redaction is best\-effort; reports and optional judge payloads can still contain sensitive code or data\.

### Inventory

Dependency manifests: 0; agent/MCP signal files: 0.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

None.

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|

## Optional LLM judge

### Evidence-JSON optimization

All evidence values and exact source/citation strings are preserved. These byte counts exclude instructions, response schemas and provider wrappers; tokenizer savings and billing reductions were not measured.

| Request | Requested | Actual engine | Status / fallback | Before bytes | After bytes | Bytes saved |
|---|---|---|---|---:|---:|---:|
| Finding triage | headroom | headroom | optimized | 1226 | 1182 | 44 |
| Control request 1 | headroom | headroom | optimized | 5331 | 5164 | 167 |
| Control request 2 | headroom | headroom | optimized | 6931 | 6714 | 217 |

Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.

```text
{
  "adapter_version": "1.3.0",
  "additional_concern_actions": [],
  "additional_concerns": [],
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
    "request_bytes": 3396,
    "request_sha256": "34133c91d94b969dcd38adb13f8731df659d71525791d5f0e5f127442ff961c0",
    "requested_model": "gpt-6-astra",
    "response_bytes": 655,
    "response_sha256": "6d353fc1bace1429869b402b98a9f73b882e1ce19e367a651058ed41e3c3f739",
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
      "original_payload_sha256": "1b9076ad8b293db6c5d471143639635a64846fb04dfdbaebd328007cd38ebfde",
      "payload_bytes_after": 1182,
      "payload_bytes_before": 1226,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "5e5f8bc5a3190e60ae553e35efb64adbace6a99571a99b837de40160f3f57bed",
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
    "original_payload_sha256": "1b9076ad8b293db6c5d471143639635a64846fb04dfdbaebd328007cd38ebfde",
    "payload_bytes_after": 1182,
    "payload_bytes_before": 1226,
    "requested": "headroom",
    "schema_version": "1.0",
    "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
    "sent_payload_sha256": "5e5f8bc5a3190e60ae553e35efb64adbace6a99571a99b837de40160f3f57bed",
    "status": "optimized",
    "token_savings_measured": false
  }
}
```

## Analyst evidence and request audit

Only bounded excerpts were submitted. Missing evidence may reflect collection limits, exclusions, or retrieval misses. A verified quote establishes its presence in an excerpt, not the truth of the model's interpretation. Verification steps are proposals and have not been executed.

Evidence selection and review coverage:

```text
{
  "attempted_controls": 1,
  "batch_size": 1,
  "call_budget": 3,
  "calls_made": 2,
  "catalog_checks": 2,
  "catalog_controls": 1,
  "disabled_checks": 0,
  "disabled_controls": 0,
  "evidence": {
    "budget_exhausted": [],
    "bytes_charged": 1243,
    "bytes_read": 1243,
    "candidate_rankings_dropped": 0,
    "candidate_snippets": 3,
    "characters_selected": 1147,
    "controls_total": 1,
    "controls_with_evidence": 1,
    "controls_without_evidence": [],
    "evidence_files": 2,
    "failed_read_bytes_charged": 0,
    "file_read_attempts": 2,
    "files_read": 2,
    "files_verified": 2,
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
    "manifest_files": 2,
    "requested_characters_selected": 324,
    "scope": "bounded_excerpts_from_unchanged_scanner_manifest_files",
    "selection_method": "deterministic_control_keywords_and_findings",
    "skipped_counts": {},
    "skipped_files": [],
    "snippets_selected": 3
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
      "EXEC-05": [
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
      "request_bytes": 11696,
      "request_sha256": "1d032fc521d81072236eb8ad6136939c41509613e94b5587d4ec8bde30e98943",
      "requested_model": "gpt-6-astra",
      "response_bytes": 1268,
      "response_sha256": "1f6f668c9200e3673a92798c8d81902f9067185334e81de0e40b01ea98bd47f6",
      "stage": "investigation",
      "startup_warnings": [
        "codex_code_mode_intentionally_disabled"
      ],
      "structured_output_requested": true,
      "token_budget_enforced": false,
      "token_optimization": {
        "bytes_saved": 167,
        "engine": "headroom",
        "evidence_preserved": true,
        "fallback_reason": null,
        "headroom_version": "0.37.0",
        "original_payload_sha256": "c010c2054c3da806ff97f2e6b492192b51a1bf106c802ca18a864ebbc6c02e20",
        "payload_bytes_after": 5164,
        "payload_bytes_before": 5331,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "78e3c2f25bbae23de3b65027614c309cae347b79911bc577e8dfbd86a7b0ef18",
        "status": "optimized",
        "token_savings_measured": false
      },
      "tools_policy": "disabled_for_advisory_review",
      "transport": "official_cli"
    },
    "control_ids": [
      "EXEC-05"
    ],
    "controls_submitted": 1,
    "evidence_ids": [
      "src-1c85609fb313cbfd95eb25cd",
      "src-ea8f5ad7a1e9b55c0a223d85",
      "src-6a02164f7498f198ded37c26"
    ],
    "evidence_request_receipts": [
      {
        "check_id": "EXEC-05:1",
        "check_index": 1,
        "control_id": "EXEC-05",
        "counterevidence": "Seek lane-specific rejection, destination allowlists, URL parsing, IP/DNS validation, or other constraints protecting lane 1. Redirect following is already explicitly disabled at the visible request call.",
        "end_line": 41,
        "evidence_id": "src-e5731df412d29009bbf4b319",
        "file_id": "file-01133ae2e5e076d2cc2525ac",
        "new_characters_charged": 324,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "tool_forward passes caller-controlled user_url to dispatch with lane 1. Inspect _admit to determine what destination and scheme constraints apply before requests.post, and whether the constant-destination lane has different enforcement.",
        "retained_characters": 324,
        "source_sha256": "b7995f3334ed328ff74ebdf4834b75fe7b4a84cb608c6e8408490f89b1cd8c9c",
        "start_line": 13,
        "status": "served"
      }
    ],
    "investigation_response": "evidence_requests",
    "investigation_round": 0,
    "model": "gpt-6-astra",
    "payload_sha256": "78e3c2f25bbae23de3b65027614c309cae347b79911bc577e8dfbd86a7b0ef18",
    "protocol_version": "1.2.0",
    "provider": "codex_cli",
    "status": "completed",
    "structured_analysis_checks": 0,
    "token_optimization": {
      "bytes_saved": 167,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "c010c2054c3da806ff97f2e6b492192b51a1bf106c802ca18a864ebbc6c02e20",
      "payload_bytes_after": 5164,
      "payload_bytes_before": 5331,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "78e3c2f25bbae23de3b65027614c309cae347b79911bc577e8dfbd86a7b0ef18",
      "status": "optimized",
      "token_savings_measured": false
    }
  },
  {
    "adapter_version": "1.3.0",
    "batch": 1,
    "check_index_map": {
      "EXEC-05": [
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
      "request_bytes": 13246,
      "request_sha256": "778653255806d113cdda070052bdba1ff0df574f6d61300f8318ede9a6fe7fd1",
      "requested_model": "gpt-6-astra",
      "response_bytes": 9518,
      "response_sha256": "1bf182e4091aa0f0fb81bde00200b7985e58dd72eceeed927ebd94643a7a1b4b",
      "stage": "investigation",
      "startup_warnings": [
        "codex_code_mode_intentionally_disabled"
      ],
      "structured_output_requested": true,
      "token_budget_enforced": false,
      "token_optimization": {
        "bytes_saved": 217,
        "engine": "headroom",
        "evidence_preserved": true,
        "fallback_reason": null,
        "headroom_version": "0.37.0",
        "original_payload_sha256": "d8d4407a94eb3257956471bb400d11b4a5e08210ee0d1e2f7a5cb0c7be862e50",
        "payload_bytes_after": 6714,
        "payload_bytes_before": 6931,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "bf80077f0dc8c3b87f8c7caefe488c9a8a5f5f9aa1d85ae6311465e2918421f0",
        "status": "optimized",
        "token_savings_measured": false
      },
      "tools_policy": "disabled_for_advisory_review",
      "transport": "official_cli"
    },
    "control_ids": [
      "EXEC-05"
    ],
    "controls_submitted": 1,
    "evidence_ids": [
      "src-1c85609fb313cbfd95eb25cd",
      "src-ea8f5ad7a1e9b55c0a223d85",
      "src-6a02164f7498f198ded37c26",
      "src-e5731df412d29009bbf4b319"
    ],
    "investigation_response": "conclusions",
    "investigation_round": 1,
    "model": "gpt-6-astra",
    "omitted_checks": 0,
    "omitted_controls": 0,
    "payload_sha256": "bf80077f0dc8c3b87f8c7caefe488c9a8a5f5f9aa1d85ae6311465e2918421f0",
    "protocol_version": "1.2.0",
    "provider": "codex_cli",
    "status": "completed",
    "structured_analysis_checks": 2,
    "token_optimization": {
      "bytes_saved": 217,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "d8d4407a94eb3257956471bb400d11b4a5e08210ee0d1e2f7a5cb0c7be862e50",
      "payload_bytes_after": 6714,
      "payload_bytes_before": 6931,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "bf80077f0dc8c3b87f8c7caefe488c9a8a5f5f9aa1d85ae6311465e2918421f0",
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
      "binding_sha256": "3007e9fdbf0be8edf287b4f811e86ad4d50ba21a2ae976acdfcc534f4e915ba1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-05:1 Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect."
    },
    {
      "binding_sha256": "666459be29ce37a1299ad84dfe6c2a673af2ea842c4a2d3180f014885e0fcc9d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-05:2 Test loopback, private/link-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect-to-private cases."
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
        "EXEC-05"
      ],
      "selected_control_ids": [
        "EXEC-05"
      ],
      "selected_rule_ids": [
        "AI014"
      ]
    },
    "evidence_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "image_limits": {},
    "manifest_sha256": "998febdd04741eaa52250542d70cbb578ba602982cd9faedea4a151be69c7005",
    "scan_id": "d4246648ec0e739efdbd0fc8a03c8670f095828210e5768af2e3e1c7a8cad202",
    "scope_sha256": "41c6e1347c906671678303fd38e8ead3f6e3bb61445397b9274b2aed9f4a235e",
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

