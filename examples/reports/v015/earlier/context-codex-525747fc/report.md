# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `da4d62e183b5547b3271a025705316305a4112899c8b700c67c7ba3805b003dd`

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
  "excerpt_characters_used": 1239,
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
      "counterevidence": "Seek effective lane-specific allowlists, URL parsing, address restrictions, and DNS enforcement. Determine whether the constant destination used by lane 0 constrains lane 1 as well; redirects are already explicitly disabled at the visible request.",
      "end_line": 36,
      "evidence_id": "src-c76b9846c312b1d8e2392d1c",
      "file_id": "file-01133ae2e5e076d2cc2525ac",
      "new_characters_charged": 92,
      "original_check_index": 1,
      "purpose": "counterevidence",
      "range_complete": true,
      "reason": "The caller-selected URL reaches requests.post through dispatch with lane 1. Inspect _admit and its surrounding definitions to determine whether that lane enforces destination and scheme restrictions before the network operation.",
      "retained_characters": 92,
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

The visible caller\-selected URL enters dispatch with lane 1\. The admission predicate accepts that lane independently of the destination, allowing the URL to reach requests\.post without a visible destination or scheme restriction in this flow\. Redirects are explicitly disabled, which limits redirect\-based exposure\. The constant destination used by the sibling lane does not constrain lane 1\. Connection\-time address restrictions and DNS enforcement are not established by the supplied evidence\. This is an unverified concern in a declared inert fixture, not evidence of deployed exploitability\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** If exposed as an agent or MCP tool, caller\-controlled user\_url crosses into server\-side outbound HTTP, potentially using network access unavailable to the caller\.

**When this applies:** Apply changes to any operational implementation represented by this fixture\. Deployment reachability and existing transport or egress controls require owner confirmation\.

1. Replace the unconditional lane\-1 admission with a destination policy applied to every caller\-controlled URL; explicitly allow required schemes and approved destinations\.
2. Enforce resolved\-address restrictions at connection time through a controlled transport or egress proxy, covering loopback, private, link\-local, metadata, and IPv6 destinations without a validation\-to\-connection DNS race\.
3. Retain allow\_redirects=False\. If redirects become necessary, validate every target and its connection destination before following it\.

**How to verify:**

- Review that every relevant lane invokes the same destination policy and cannot bypass it through lane selection\.
- Use isolated transport observations to verify blocked addresses receive no connections, including after DNS changes\.
- Retain regression coverage showing redirect responses are not followed\.

**Risk hypothesis:** A caller could select an internal or metadata destination and reach requests\.post because lane 1 makes \_admit true regardless of the URL\.

**Trust boundary:** The visible boundary is caller\-controlled user\_url entering tool\_forward, crossing the admission predicate, and becoming the destination of a server\-side HTTP POST\. Actual agent or MCP registration is not supplied\.

**Counterevidence considered:** The rejection branch is present, but its predicate does not restrict lane 1\. The sibling caller uses a constant destination on lane 0, and redirects are disabled\. The excerpts describe an inert fixture\. These alternatives limit the claim but do not establish destination restrictions for lane 1\.

**Conclusion limits:** Only the local flow is established\. No code was executed, and deployed reachability, library behavior, DNS handling, network isolation, and external egress policy remain unresolved\.

Evidence src\-ea8f5ad7a1e9b55c0a223d85: agent\.py:7–7 (exact quote verified).

```text
return dispatch(1, user_url, user_content)
```

Evidence src\-c76b9846c312b1d8e2392d1c: delivery\.py:17–18 (exact quote verified).

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
- Have the owner establish whether this fixture represents a reachable agent or MCP tool and identify caller authorization and external egress restrictions\.
- Review the deployed transport and destination policy for allowed schemes, resolved IPv4 and IPv6 addresses, and enforcement against the actual connection destination\.
- In an authorized isolated environment, verify that disallowed destinations cannot receive a connection and that redirect responses are never followed\.

**Check 2: insufficient\_evidence**

The supplied excerpts contain no test cases or results covering loopback, private/link\-local IPv4 and IPv6, cloud metadata, alternate encodings, or redirects to private destinations\. Disabling redirects is relevant implementation evidence but does not establish that these cases were tested\. The declared fixture context further limits conclusions about operational coverage; omitted tests may exist\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Destination tests should exercise the caller\-controlled tool boundary through to the outbound transport, since predicate\-only tests cannot establish which destination actually receives a connection\.

**When this applies:** First identify the operational implementation and existing tests\. Do not execute the submitted inert fixture or contact real metadata or internal services\.

1. Obtain existing test artifacts before concluding that coverage is missing\.
2. Where coverage is missing, add isolated cases for loopback, private and link\-local IPv4 and IPv6, metadata destinations, alternate address encodings, and redirects to prohibited destinations\.
3. Include controlled DNS changes and assert the observed connection destination; cover lane 1 and the fixed\-destination sibling to detect lane\-dependent bypasses\.

**How to verify:**

- Have an owner review the case matrix against every address category in this acceptance check\.
- Retain isolated test results demonstrating rejection before prohibited connections and no follow\-up connection after a redirect response\.

**Risk hypothesis:** Incomplete destination testing could leave lane\-dependent admission bypasses or address\-interpretation differences undetected\.

**Trust boundary:** Required coverage spans caller\-provided URLs, admission decisions, DNS resolution, actual outbound connections, and redirect handling\.

**Counterevidence considered:** The visible request disables redirects, reducing one relevant exposure\. The fixture declaration was considered as a possible nonoperational context\. Neither establishes test coverage; tests outside the submitted excerpts remain possible\.

**Conclusion limits:** No test suite, case matrix, or runtime results were supplied\. Test absence and operational applicability cannot be inferred, and runtime validation remains outstanding\.

Evidence src\-1c85609fb313cbfd95eb25cd: delivery\.py:1–1 (exact quote verified).

```text
"""Inert review fixture: network calls below must never be executed."""
```

Evidence src\-6a02164f7498f198ded37c26: delivery\.py:40–41 (exact quote verified).

```text
return requests.post(addr, json={"record": record}, timeout=5,
                         allow_redirects=False)
```

Verification still required:
- Request the relevant test inventory and results covering every required address class, alternate encodings, and redirects to private destinations\.
- Have the owner validate the operational implementation in an authorized isolated harness with controlled DNS and connection observations, including both visible caller lanes\.

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
| Control request 2 | headroom | headroom | optimized | 6723 | 6506 | 217 |

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
    "request_sha256": "07f23c33ca00a89807c04ab5954dc222c8bbb9bf6c5c2c9986ef4d33529385c9",
    "requested_model": "gpt-6-astra",
    "response_bytes": 655,
    "response_sha256": "f779930b876f5b78e85dbaf568422318f563240f5b7a780babc1231b018af62b",
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
      "original_payload_sha256": "3376aade7785df1a0afe1423b2b04e48415eb95524e93f74a941e22858041be6",
      "payload_bytes_after": 1182,
      "payload_bytes_before": 1226,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "efd0f5b1025ed343d0da64453c6b1074f5b4c8ab412c57f5bdbd0d9bbab2eb9b",
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
    "original_payload_sha256": "3376aade7785df1a0afe1423b2b04e48415eb95524e93f74a941e22858041be6",
    "payload_bytes_after": 1182,
    "payload_bytes_before": 1226,
    "requested": "headroom",
    "schema_version": "1.0",
    "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
    "sent_payload_sha256": "efd0f5b1025ed343d0da64453c6b1074f5b4c8ab412c57f5bdbd0d9bbab2eb9b",
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
    "requested_characters_selected": 92,
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
      "request_sha256": "5ac3875de224f1d3c4211be4f86be5a59b2fbd77b03e6b8507459af587636d7f",
      "requested_model": "gpt-6-astra",
      "response_bytes": 1303,
      "response_sha256": "c948542ec337b341d74b5954af1eceaabba01b45d723b09b103cadf480c869eb",
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
        "original_payload_sha256": "8d79167e8f99bcb1dc8331865fedd4af2a5954ffaa1252ce13333b2a0f2049c4",
        "payload_bytes_after": 5164,
        "payload_bytes_before": 5331,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "cf64ebaafba13742f4e8efe78baf28184bf51dc61aba39dd043fbc0b6f9a8ef7",
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
        "counterevidence": "Seek effective lane-specific allowlists, URL parsing, address restrictions, and DNS enforcement. Determine whether the constant destination used by lane 0 constrains lane 1 as well; redirects are already explicitly disabled at the visible request.",
        "end_line": 36,
        "evidence_id": "src-c76b9846c312b1d8e2392d1c",
        "file_id": "file-01133ae2e5e076d2cc2525ac",
        "new_characters_charged": 92,
        "original_check_index": 1,
        "purpose": "counterevidence",
        "range_complete": true,
        "reason": "The caller-selected URL reaches requests.post through dispatch with lane 1. Inspect _admit and its surrounding definitions to determine whether that lane enforces destination and scheme restrictions before the network operation.",
        "retained_characters": 92,
        "source_sha256": "b7995f3334ed328ff74ebdf4834b75fe7b4a84cb608c6e8408490f89b1cd8c9c",
        "start_line": 13,
        "status": "served"
      }
    ],
    "investigation_response": "evidence_requests",
    "investigation_round": 0,
    "model": "gpt-6-astra",
    "payload_sha256": "cf64ebaafba13742f4e8efe78baf28184bf51dc61aba39dd043fbc0b6f9a8ef7",
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
      "original_payload_sha256": "8d79167e8f99bcb1dc8331865fedd4af2a5954ffaa1252ce13333b2a0f2049c4",
      "payload_bytes_after": 5164,
      "payload_bytes_before": 5331,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "cf64ebaafba13742f4e8efe78baf28184bf51dc61aba39dd043fbc0b6f9a8ef7",
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
      "request_bytes": 13038,
      "request_sha256": "25858b8f53c0154fa6623d078ec0664e3af0b39f848be384f8afd22d02171ae3",
      "requested_model": "gpt-6-astra",
      "response_bytes": 8992,
      "response_sha256": "6f3fc8cab4b98491cdf5595e5ad8a54712631bbd2e30a90755706e63a03cb66d",
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
        "original_payload_sha256": "fef90c36b03e704010dd2d0f22ed8210253f81ad2ccbf1c667644336f0aef700",
        "payload_bytes_after": 6506,
        "payload_bytes_before": 6723,
        "requested": "headroom",
        "schema_version": "1.0",
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
        "sent_payload_sha256": "f3f8e27151b16bad0c28413ea724b542adea75b68a6089ec49969fba31af4456",
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
      "src-c76b9846c312b1d8e2392d1c"
    ],
    "investigation_response": "conclusions",
    "investigation_round": 1,
    "model": "gpt-6-astra",
    "omitted_checks": 0,
    "omitted_controls": 0,
    "payload_sha256": "f3f8e27151b16bad0c28413ea724b542adea75b68a6089ec49969fba31af4456",
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
      "original_payload_sha256": "fef90c36b03e704010dd2d0f22ed8210253f81ad2ccbf1c667644336f0aef700",
      "payload_bytes_after": 6506,
      "payload_bytes_before": 6723,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "f3f8e27151b16bad0c28413ea724b542adea75b68a6089ec49969fba31af4456",
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
      "binding_sha256": "fd831b2d29a514ba09a917ddc9ad117f06287052030abc3272a928e2e58aff0d",
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
      "binding_sha256": "a733931c250c834626baefc91c10f32a139dd325c5fd295fe6713285d66cc4b3",
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
    "scan_id": "da4d62e183b5547b3271a025705316305a4112899c8b700c67c7ba3805b003dd",
    "scope_sha256": "41c6e1347c906671678303fd38e8ead3f6e3bb61445397b9274b2aed9f4a235e",
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

