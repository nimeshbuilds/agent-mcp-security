# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `25b371cf9c33a9d2685e47fc685213c6fcbeef2befbe1cb04338ca5533e50bc7`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Incomplete scan \- close the coverage gaps

The selected static scope was not fully inspected\. There are 23 open findings, including 23 critical/high findings\. Resolve reported gaps and review existing evidence before relying on this result\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 23 | 23 | 13 | 0 | 1 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 23/23 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Tool execution: 20; Secrets: 2; Deserialization: 1. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 2; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

**Close scan coverage gaps:** resolve the listed errors or scope limits and rerun on a stable input. Existing findings still need review.

- analysis\_error: ValueError while reading or analyzing file: 1 entries. Examples: libs/langgraph/langgraph/pregel/main\.py

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P1 | [AI005: Executable deserialization requires trusted inputs](#group-9ee5075ce1a1) (source) | 1 | Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\. | Application/model pipeline owner |
| P1 | [AI010: Credential\-like literal in source or configuration](#group-57a1992f928c) (source) | 2 | Determine whether the value is real without reproducing it; revoke or rotate a real exposed credential and remove retained copies through the incident process\. | Credential/service owner |
| P1 | [AI036: SQL query constructed with interpolation](#group-beaa8fb2b87e) (source) | 20 | Bind values as parameters and allowlist any dynamic identifiers or operation choices; trace generated and tool\-supplied query fragments\. | Database/tool developer |

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

<a id="group-9ee5075ce1a1"></a>

### AI005: Executable deserialization requires trusted inputs

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [libs/checkpoint/langgraph/checkpoint/serde/jsonplus\.py:288](#finding-feddf7ea214b0362)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If an attacker can supply or replace the serialized input, loading it may execute code even before the application examines the returned object\.

**Address the cause:** Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Verify artifact identity before use | Require reviewed artifact provenance plus a digest or signature checked against an independently trusted identity or manifest\. | Substitute bytes, producer identity, or verification metadata in a controlled test and confirm the consumer rejects the artifact\. | Authenticity establishes the producer and bytes; an approved producer can still ship vulnerable or malicious content\. |
| Separate artifact conversion from production | Perform necessary conversion of legacy serialized artifacts in a disposable environment without production data or credentials\. | Demonstrate that a conversion job cannot reach production services and only approved output formats are promoted\. | Conversion output still needs integrity, format, and downstream behavior review; isolation is not proof of benign content\. |

Related controls: EXEC\-06

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OPENSSF\-MODEL\-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/); [SLSA\-12](https://slsa.dev/spec/v1.2/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html); [TECH\-PYTORCH\-SERIAL](https://pytorch.org/docs/stable/notes/serialization.html)

<a id="group-57a1992f928c"></a>

### AI010: Credential\-like literal in source or configuration

**HIGH** · open · 2 occurrences · source

**Observed evidence:** [libs/cli/langgraph\_cli/constants\.py:5](#finding-99ad34ebf195412f), [libs/cli/langgraph\_cli/docker\.py:239](#finding-095971f35bac1437)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If the detected literal is a live credential, anyone with access to the source, image layers, or copied artifacts may use its granted permissions\.

**Address the cause:** Determine whether the value is real without reproducing it; revoke or rotate a real exposed credential and remove retained copies through the incident process\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Investigate and contain confirmed secret exposure | For a real exposed credential, identify reachable systems, revoke or rotate it, and review access records for misuse\. | Confirm the old credential no longer works and record the exposure window, affected copies, and follow\-up owner\. | Successful rotation stops future use of that credential but cannot reverse access or data loss that already occurred\. |
| Use managed credential injection and revocation | Load secrets at runtime through an approved store or workload identity; keep them out of source, artifacts, and model context\. | Test rotation and revocation without disclosing values; inspect build layers and launch metadata for retained copies\. | Deleting a file or hiding a later image layer does not revoke a credential or erase copies already distributed\. |
| Limit credentials available to the workload | Give this component a distinct identity and only the downstream scopes and lifetime needed for its approved operations\. | Use its runtime identity to attempt forbidden service operations, then revoke it and confirm subsequent access fails\. | A compromised component can still use its allowed permissions until credentials expire or revocation takes effect\. |

Related controls: AUTH\-05, DATA\-01

Guidance sources (engineering synthesis): [CISA\-JCDC](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP\-AUTH\-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)

<a id="group-beaa8fb2b87e"></a>

### AI036: SQL query constructed with interpolation

**HIGH** · open · 20 occurrences · source

**Observed evidence:** [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/\_\_init\_\_\.py:160](#finding-3158d76958abb993), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/\_\_init\_\_\.py:238](#finding-1e634d153cc78fc5), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/aio\.py:149](#finding-c2dc64de8900c054), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/aio\.py:206](#finding-c08cbef90b43077b), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:280](#finding-7fe7cd667c0d2523), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:344](#finding-48573e8c4a0a0676), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:646](#finding-09eb9aa9524ca70f), [libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:691](#finding-b4361b0dae68accb), [libs/checkpoint\-postgres/langgraph/store/postgres/aio\.py:236](#finding-15bed6f005838488), [libs/checkpoint\-postgres/langgraph/store/postgres/aio\.py:243](#finding-42b9581bcad6a7cb), [libs/checkpoint\-postgres/langgraph/store/postgres/aio\.py:290](#finding-232248ee256e3a3c), [libs/checkpoint\-postgres/langgraph/store/postgres/base\.py:1124](#finding-e6738e8f6d53149b), [libs/checkpoint\-postgres/langgraph/store/postgres/base\.py:1131](#finding-18007110461981da), [libs/checkpoint\-postgres/langgraph/store/postgres/base\.py:1186](#finding-3553ec640bfe3d19), [libs/checkpoint\-sqlite/langgraph/cache/sqlite/\_\_init\_\_\.py:56](#finding-8f8f038cf2283168), [libs/checkpoint\-sqlite/langgraph/cache/sqlite/\_\_init\_\_\.py:106](#finding-cea8682d474adbb9), [libs/checkpoint\-sqlite/langgraph/checkpoint/sqlite/\_\_init\_\_\.py:343](#finding-fc2cf6c6464e27c8), [libs/checkpoint\-sqlite/langgraph/checkpoint/sqlite/aio\.py:463](#finding-7b7c651eee3260c7), [libs/checkpoint\-sqlite/langgraph/store/sqlite/aio\.py:571](#finding-95f9bbbc1db92606), [libs/checkpoint\-sqlite/langgraph/store/sqlite/base\.py:1422](#finding-8ade01242f57fc25)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If untrusted values are inserted as SQL syntax, they may alter a query to read or change unintended records within the database identity authority\.

**Address the cause:** Bind values as parameters and allowlist any dynamic identifiers or operation choices; trace generated and tool\-supplied query fragments\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Constrain the database identity and operation set | Use dedicated database credentials with only the required tables, rows, and operations; separate administrative access from agent tools\. | Using the agent identity, attempt schema changes, other\-tenant records, unrestricted exports, and unauthorized writes\. | Database permissions bound damage but cannot make a permitted query correct; query parameters do not safely bind identifiers\. |
| Authorize downstream effects separately | For each effect, check caller identity, tenant, operation, and target at the executing service using bounded downstream credentials\. | Try read\-only users against writes, other\-tenant identifiers, and direct tool calls without an agent session\. | Correct token verification alone cannot prevent an authorized but overly broad or harmful business operation\. |

Related controls: EXEC\-03

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [CSA\-AGENT\-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### What remains unknown

- Actual reachability, deployment configuration, upstream validation, data sensitivity, and exploitability require verification\.
- Authentication, authorization, tenant isolation, tool approvals, prompt\-injection resistance, and recovery need runtime or human evidence\.
- Suggested defense layers have not been verified as deployed\. There is no calculated residual\-risk score or automatic severity reduction\.
- No dependency CVE feed or live adversarial agent/MCP benchmark was run\. Excluded and unsupported files remain outside the selected scope\.

Guidance catalog version: 1\.0\.0; SHA-256: `c04353ab7c9999ea513de31a48130971509f8a52666745b24d1b726f96a4f374`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 23 | Observed patterns requiring review; 23 critical/high. No severity weights or estimated compromise probability are assigned. |
| Partial deterministic mapping reach | 45.45% (30/66) | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |
| Optional AI answer coverage | 0.00% (0/132) | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |

**Selected scope:** 46 rules (46 active), 66 controls (66 active), 132 active acceptance checks. The selected static scope is incomplete. Recorded coverage gaps: 1.

**Mapping formula:** 100 × active selected controls with at least one active selected mapped rule / active selected controls\. This describes partial rule availability, not completed tests, passes, or control effectiveness\.

**AI answer formula:** 100 × unique active selected acceptance checks with a received, valid model answer / active selected acceptance checks\. An answer can be a concern or an explicit unknown\. Disabled AI has zero answered checks; an empty denominator is not applicable \(null\), never 100%\.

**Optional AI:** disabled; finding stage disabled; control stage disabled.

| Advisory check outcome | Count |
|---|---:|
| supported\_by\_code | 0 |
| potential\_gap | 0 |
| needs\_runtime\_validation | 0 |
| needs\_human\_review | 0 |
| insufficient\_evidence | 0 |
| not\_applicable\_proposed | 0 |
| not\_reviewed | 132 |

Supported by code and proposed non\-applicability are advisory interpretations\. Runtime/human validation and missing evidence remain unresolved\. AI cannot erase findings, lower their severity, change the severity gate, or turn checks into passes\.

Justified and disabled rules/checks are excluded from active metric denominators without pass credit\. Findings with user decisions or baseline suppressions remain visible outside open\-finding counts\. Selection narrows the requested scope; it does not establish the excluded system is safe\.

The existing CLI gate uses open deterministic findings at or above the configured severity\. Scan/review/export errors can make requested work incomplete\. Coverage percentages and model opinions never dismiss the gate\.

## Methods, configuration and blind spots

Find repeatable security patterns and organize the remaining assurance work for agents, MCP servers, skills and built images\.

| Selected scope measure | Count |
|---|---:|
| Selected deterministic rules | 46 |
| Selected controls with partial static mapping | 30 |
| Selected controls without static mapping | 36 |
| Selected acceptance checks | 132 |
| Rules available in the full catalog | 46 |
| Controls available in the full catalog | 66 |

Mapping counts describe available checks, not percent secure, detection accuracy or validated control effectiveness\.

### How the layers operate

1. Choose an explicit code/image target and scan configuration; no target code or container is started\.
2. Collect bounded deterministic evidence, record hashes, rule matches, exclusions and coverage gaps\.
3. When explicitly enabled, select bounded evidence for finding triage and every active control check; findings\-only mode narrows this step\.
4. Run advisory model requests under fixed limits; validate response schemas, known identifiers and exact evidence quotes\. The model cannot select files or execute tools through the review controller\.
5. Retain unsupported claims and runtime/human requirements; record user review decisions separately from model advice\.
6. Import an explicitly selected reviewed report with a fresh target scan; revalidate evidence bindings, retain stale decisions for audit and recompute the result\.

### What each layer can and cannot establish

#### Execution and data flow

**Deterministic:** Python AST checks with bounded local aliases/values; JavaScript/TypeScript tokens and balanced calls identify selected eval, shell, deserialization, SQL and template patterns\.

**Optional model review:** A model can explain a retrieved call path, question whether input is trusted and identify contextual concerns the pattern rules do not encode\.

**Can miss or misclassify:** Cross\-file flows, dynamic imports, wrappers, reflection, generated code, unsupported languages and runtime values can hide a risk\. A dangerous API can also be intentional and correctly constrained\.

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

**Deterministic:** Bounded skill instructions and tool metadata are inspected for explicit instruction hijacking, sensitive\-data transfer, covert or approval\-bypassing actions, and contradictory read\-only declarations\.

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
        "batch_size": 6,
        "max_bytes": 2000000,
        "max_calls": 12,
        "max_chars": 120000,
        "max_files": 200,
        "max_seconds": 180
      },
      "cli_login": "auto",
      "cli_timeout_seconds": null,
      "effective_transport": {},
      "enabled": false,
      "findings_limit": 100,
      "include_finding_source": false,
      "mode": "full",
      "provider": null,
      "transport_replay": "Endpoints, credentials, headers, executable paths and identity stores are not embedded for automatic replay."
    },
    "reporting": {
      "failure_threshold": "high",
      "formats": [
        "html",
        "markdown",
        "json",
        "sarif"
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
    "max_file_bytes": 20000000,
    "max_files": 20000,
    "max_total_bytes": 300000000,
    "requested_scan_ids": [],
    "selected_control_ids": [
      "AGT-01",
      "AGT-02",
      "AGT-03",
      "AGT-04",
      "AGT-05",
      "AGT-06",
      "AGT-07",
      "AUTH-01",
      "AUTH-02",
      "AUTH-03",
      "AUTH-04",
      "AUTH-05",
      "AUTH-06",
      "AUTH-07",
      "AUTH-08",
      "AUTH-09",
      "DATA-01",
      "DATA-02",
      "DATA-03",
      "DATA-04",
      "DATA-05",
      "DATA-06",
      "EXEC-01",
      "EXEC-02",
      "EXEC-03",
      "EXEC-04",
      "EXEC-05",
      "EXEC-06",
      "EXEC-07",
      "GOV-01",
      "GOV-02",
      "GOV-03",
      "GOV-04",
      "GOV-05",
      "GOV-06",
      "MCP-01",
      "MCP-02",
      "MCP-03",
      "MCP-04",
      "MCP-05",
      "MCP-06",
      "MCP-07",
      "MCP-08",
      "MCP-09",
      "MCP-10",
      "OPS-01",
      "OPS-02",
      "OPS-03",
      "OPS-04",
      "OPS-05",
      "OPS-06",
      "SUP-01",
      "SUP-02",
      "SUP-03",
      "SUP-04",
      "SUP-05",
      "SUP-06",
      "TEST-01",
      "TEST-02",
      "TEST-03",
      "TEST-04",
      "TEST-05",
      "TEST-06",
      "TEST-07",
      "TEST-08",
      "TEST-09"
    ],
    "selected_rule_ids": [
      "AI001",
      "AI002",
      "AI003",
      "AI004",
      "AI005",
      "AI006",
      "AI007",
      "AI008",
      "AI009",
      "AI010",
      "AI011",
      "AI012",
      "AI013",
      "AI014",
      "AI015",
      "AI016",
      "AI017",
      "AI018",
      "AI019",
      "AI020",
      "AI021",
      "AI022",
      "AI023",
      "AI024",
      "AI025",
      "AI026",
      "AI027",
      "AI028",
      "AI029",
      "AI030",
      "AI031",
      "AI032",
      "AI033",
      "AI034",
      "AI035",
      "AI036",
      "AI037",
      "AI038",
      "AI039",
      "AI040",
      "AI041",
      "AI042",
      "AI043",
      "AI044",
      "AI045",
      "AI046"
    ]
  }
}
```

## Scan details

Scanned **211 files**; **23 open findings**, **0 suppressed findings**, and **1 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 23 | 0 | 0 | 0 |

Source I/O: **6378697 bytes read**, **6378697 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 15 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| generic\_text | 10 | Generic secret/URL signals and bounded recognized skill/instruction directives; language\-specific execution and dataflow are not analyzed\. |
| json\_structured | 3 | Parsed JSON/JSONC fields and selected configuration rules; runtime values and referenced files are not resolved\. |
| python\_ast | 183 | Python syntax, bounded local aliases/value tracking and selected security sinks; no whole\-program or interprocedural proof\. |

Severity failure threshold: **high** · Process exit code: **2**.

A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

<a id="finding-3158d76958abb993"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/\_\_init\_\_\.py:160–160 · Finding ID: `b2c38b5835f1f8a2839ec011`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(query, params)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-1e634d153cc78fc5"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/\_\_init\_\_\.py:238–241 · Finding ID: `451c0b7574ca3c42e003e843`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(
                self.SELECT_SQL + where,
                args,
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-c2dc64de8900c054"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/aio\.py:149–149 · Finding ID: `318b54ec7ce9e0a952e50928`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            await cur.execute(query, params, binary=True)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-c08cbef90b43077b"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/aio\.py:206–210 · Finding ID: `6daba84ba6680768f8b7c81f`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            await cur.execute(
                self.SELECT_SQL + where,
                args,
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-7fe7cd667c0d2523"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:280–280 · Finding ID: `f02711b198ef60d0f15ba549`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(query, params, binary=True)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-48573e8c4a0a0676"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:344–348 · Finding ID: `2d6bc11b77ad73d68b1ef44e`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(
                self.SELECT_SQL + where,
                args,
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-09eb9aa9524ca70f"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:646–646 · Finding ID: `f27074c799df548b0c528627`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            await cur.execute(query, params, binary=True)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-b4361b0dae68accb"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/checkpoint/postgres/shallow\.py:691–695 · Finding ID: `c0fd27b46f5af81b21de1440`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            await cur.execute(
                self.SELECT_SQL + where,
                args,
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-15bed6f005838488"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/store/postgres/aio\.py:236–242 · Finding ID: `549f2a26378737bba7d09085`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            await cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {table} (
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-42b9581bcad6a7cb"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/store/postgres/aio\.py:243–243 · Finding ID: `45c1a462742498388c9630ed`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            await cur.execute(f"SELECT v FROM {table} ORDER BY v DESC LIMIT 1")
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-232248ee256e3a3c"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/store/postgres/aio\.py:290–290 · Finding ID: `3d51002a6ec0ed7f474ad9b4`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                    await cur.execute(sql)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-e6738e8f6d53149b"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/store/postgres/base\.py:1124–1130 · Finding ID: `202c42d80f9d2ac762b159c5`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {table} (
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-18007110461981da"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/store/postgres/base\.py:1131–1131 · Finding ID: `80688422952496533add7769`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(f"SELECT v FROM {table} ORDER BY v DESC LIMIT 1")
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-3553ec640bfe3d19"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-postgres/langgraph/store/postgres/base\.py:1186–1186 · Finding ID: `5837e9a9fb7de782c35a88ae`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                    cur.execute(sql)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-8f8f038cf2283168"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-sqlite/langgraph/cache/sqlite/\_\_init\_\_\.py:56–59 · Finding ID: `ba7cbfc2ff94881cb0fcb12e`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cursor = self._conn.execute(
                f"SELECT ns, key, expiry, encoding, val FROM cache WHERE (ns, key) IN ({placeholders})",
                tuple(params),
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-cea8682d474adbb9"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-sqlite/langgraph/cache/sqlite/\_\_init\_\_\.py:106–109 · Finding ID: `d7ee82541f3155d5a94ec1f3`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                self._conn.execute(
                    f"DELETE FROM cache WHERE (ns) IN ({placeholders})",
                    tuple(",".join(key) for key in namespaces),
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-fc2cf6c6464e27c8"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-sqlite/langgraph/checkpoint/sqlite/\_\_init\_\_\.py:343–343 · Finding ID: `e0812a065f4ce2cd75c343a0`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            cur.execute(query, param_values)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-7b7c651eee3260c7"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-sqlite/langgraph/checkpoint/sqlite/aio\.py:463–463 · Finding ID: `3e79513adb35c12b28efc46e`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
            self.conn.execute(query, params) as cur,
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-95f9bbbc1db92606"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-sqlite/langgraph/store/sqlite/aio\.py:571–571 · Finding ID: `12483c89b7acfe261dc33455`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                            await cur.execute(update_query, update_params)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-8ade01242f57fc25"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint\-sqlite/langgraph/store/sqlite/base\.py:1422–1422 · Finding ID: `14729ddbec188892d98fac3d`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                            cur.execute(update_query, update_params)
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-feddf7ea214b0362"></a>

### AI005 — Executable deserialization requires trusted inputs

**HIGH** · Confidence: medium · Status: open

Location: libs/checkpoint/langgraph/checkpoint/serde/jsonplus\.py:288–288 · Finding ID: `2c25446598d6ff7b33cf8888`

Pickle\-compatible deserialization can execute code\. This finding identifies a dangerous trust boundary, not proof that the serialized input is attacker controlled\.

```text
            return pickle.loads(data_)
```

**Remediation:** Use a nonexecutable serialization format with schema validation\. If compatibility requires pickle, accept only authenticated artifacts from a strictly controlled producer\.

#### Fix plan and agent/MCP relevance

Replace executable object deserialization or tightly authenticate its producer\.

**Why this matters for agents/MCP:** A cached agent state, plugin artifact or MCP\-uploaded file may reach pickle\-compatible loading\. Deserialization can execute producer\-selected code before downstream data validation\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Identify the producer and every write path to the artifact, including shared caches, object stores and task workspaces\.
- The finding identifies a dangerous loader; it does not show that its input is attacker controlled\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Migrate to data\-only serialization | Replace pickle, dill, joblib or equivalent object loading with JSON or another nonexecutable format plus a versioned schema\. Reconstruct only explicitly supported application types\. | Roundtrip required benign state and reject unexpected type markers, fields and oversized collections without importing producer\-selected code\. |
| 2\. Control unavoidable legacy artifacts | If compatibility requires executable deserialization, authenticate the exact bytes against a producer/key or registry digest established independently of the artifact location\. Restrict cache and artifact writers\. | Alter one byte and change the producer identity in test artifacts; verify rejection before the deserializer is called\. |
| 3\. Quarantine conversion | Convert legacy artifacts in a disposable credential\-free worker with resource and network limits, then export validated data to the main service\. | Verify conversion cannot read main\-service secrets or contact forbidden destinations and that failed conversions publish no partial trusted state\. |

**Remaining validation:**

- A valid signature identifies a producer; it does not make a compromised or malicious producer safe\.
- Schema validation after pickle loading is too late to prevent execution during loading\.

Related controls: EXEC\-06

Fix guidance sources: [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-502

- [Reference](https://docs.python.org/3/library/security_warnings.html)

<a id="finding-99ad34ebf195412f"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: libs/cli/langgraph\_cli/constants\.py:5–5 · Finding ID: `af4482a6a8e9174f701bf192`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-095971f35bac1437"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: libs/cli/langgraph\_cli/docker\.py:239–239 · Finding ID: `98a2493baaed725cdbbd3a57`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

## Control checklist and coverage

These are project-defined checks mapped to published guidance. They are not official benchmark scores. `no_pattern_detected` means only that the mapped detector did not fire. `findings_detected` requires investigation, not an automatic compliance failure.

### GOV\-01: Inventory every agent, MCP server, tool, and model

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Record owner, deployment, model/version, MCP transport/version, exposed tools, data classes, and external endpoints\.
- [ ] Reconcile approved inventory with deployed configurations; investigate unregistered agents and servers\.
- [Source](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)

### GOV\-02: Model trust boundaries and attack paths

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials\.
- [ ] Identify who controls each input and the highest\-impact action reachable if that input is malicious\.
- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)

### GOV\-03: Define authorized use and accountable owners

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes\.
- [ ] Record impact, reversibility, approval requirements, and accepted residual risk before production use\.
- [Source](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)

### GOV\-04: Maintain evidence and risk exceptions

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Give each control an owner, evidence link, validation date, result, and next review date\.
- [ ] Time\-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### GOV\-05: Reassess changes in autonomy and integrations

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Review security impact when adding a model, tool, server, data source, skill, or broader permission\.
- [ ] Require deployment evidence for the complete configured system; a model\-only score is insufficient\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### GOV\-06: Assign shared security responsibilities across AI providers

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on\.
- [ ] Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review\.
- [Source](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)
- [Source](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1)

### AUTH\-01: Authenticate protected operations on every request

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries\.
- [ ] Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation\.

Partial static rules: AI026, AI041
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### AUTH\-02: Authorize the exact action and target

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution\.
- [ ] Deny by default; test read\-only callers against write tools and object identifiers owned by another user\.

Partial static rules: AI027
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

### AUTH\-03: Validate access\-token cryptography and claims

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes\.
- [ ] Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation\.

Partial static rules: AI017
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)

### AUTH\-04: Prevent token passthrough and confused deputy use

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use audience\-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens\.
- [ ] Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize\.

Partial static rules: AI028
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### AUTH\-05: Constrain credential lifetime and exposure

Category: Identity and authorization · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use short\-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation\.
- [ ] Avoid tokens in query strings, model context, source, child\-process arguments, and diagnostic output\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: af4482a6a8e9174f701bf192, 98a2493baaed725cdbbd3a57
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### AUTH\-06: Bind OAuth flows and validate redirects

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Test PKCE support and S256, exact registered redirects, transaction binding, and authorization\-response issuer validation\.
- [ ] Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions\.

Partial static rules: AI038
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### AUTH\-07: Secure OAuth discovery and registration

Category: Identity and authorization · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes\.
- [ ] Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services\.
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### AUTH\-08: Bind delegation to identity, scope, and expiry

Category: Identity and authorization · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Carry authenticated initiator and delegation identity through multi\-agent calls instead of trusting identity fields in text\.
- [ ] Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences\.
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AUTH\-09: Manage agent identity enrollment and retirement

Category: Identity and authorization · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access\.
- [ ] Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access\.
- [Source](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)
- [Source](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)

### MCP\-01: Validate transport exposure and origin

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces\.
- [ ] Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment\.

Partial static rules: AI006, AI007, AI008, AI029
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

### MCP\-02: Validate tool arguments and results

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate\.
- [ ] Bound sizes and nesting; validate declared structured output and render errors without leaking secrets\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

### MCP\-03: Treat descriptions and annotations as untrusted

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries\.
- [ ] Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy\.

Partial static rules: AI043, AI044, AI046
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-04: Detect tool substitution and metadata changes

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Bind tool approval to verified server identity and the reviewed tool definition or version\.
- [ ] Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names\.

Partial static rules: AI046
- [Source](https://owasp.org/projects/mcp-top-10)

### MCP\-05: Protect state handles and legacy sessions

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries\.
- [ ] For older sessionful protocol versions, test session hijacking and cross\-user resumption; a session ID is not authentication\.

Partial static rules: AI038
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### MCP\-06: Constrain sampling and returned model context

Category: MCP protocol and tools · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access\.
- [ ] Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling)

### MCP\-07: Secure elicitation and URL interactions

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Keep sensitive credential collection out of form\-mode elicitation; validate and visibly identify URL destinations\.
- [ ] Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)

### MCP\-08: Enforce filesystem isolation independently of roots

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Treat declared roots as scoped information, not an operating\-system sandbox or complete authorization mechanism\.
- [ ] Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace\.

Partial static rules: AI015
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)

### MCP\-09: Constrain local server launch and inherited environment

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment\.
- [ ] Restrict proxy process\-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs\.

Partial static rules: AI018, AI031
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-10: Apply version\-aware metadata, caching, and cancellation

Category: MCP protocol and tools · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules\.
- [ ] Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

### AGT\-01: Enforce action policy outside the model

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities\.
- [ ] Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval\.

Partial static rules: AI027, AI031
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### AGT\-02: Bind approval to the action executed

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Present actual recipient, target, arguments, data disclosure, and consequences for high\-impact approval\.
- [ ] Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse\.

Partial static rules: AI031, AI045
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AGT\-03: Separate untrusted content from authoritative instructions

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions\.
- [ ] Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls\.

Partial static rules: AI032, AI043
- [Source](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

### AGT\-04: Protect retrieval and persistent memory

Category: Agent behavior and context · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters\.
- [ ] Test poisoned memory persistence, cross\-tenant retrieval, provenance loss, deletion, and stale privileged context\.
- [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

### AGT\-05: Keep objectives and authority bounded across agents

Category: Agent behavior and context · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions\.
- [ ] Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs\.
- [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

### AGT\-06: Protect agent configuration and skills

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs\.
- [ ] Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy\.

Partial static rules: AI043, AI044, AI045
- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)
- [Source](https://agentskills.io/specification)

### AGT\-07: Prevent sensitive context leaving through legitimate tools

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents\.
- [ ] Use canary data to test encoded leakage and combinations of otherwise permitted tools\.

Partial static rules: AI044
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### EXEC\-01: Prevent shell and command injection

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values\.
- [ ] Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames\.

Partial static rules: AI002, AI003, AI012
- [Source](https://owasp.org/projects/mcp-top-10)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-02: Constrain generated\-code execution

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content\.
- [ ] Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits\.

Partial static rules: AI001, AI013
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### EXEC\-03: Parameterize database and query operations

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search\-language construction\.
- [ ] Separate read/write database identities and test whether generated queries can escape permitted objects or operations\.

Partial static rules: AI036

Open finding IDs: b2c38b5835f1f8a2839ec011, 451c0b7574ca3c42e003e843, 318b54ec7ce9e0a952e50928, 6daba84ba6680768f8b7c81f, f02711b198ef60d0f15ba549, 2d6bc11b77ad73d68b1ef44e, f27074c799df548b0c528627, c0fd27b46f5af81b21de1440, 549f2a26378737bba7d09085, 45c1a462742498388c9630ed, 3d51002a6ec0ed7f474ad9b4, 202c42d80f9d2ac762b159c5, 80688422952496533add7769, 5837e9a9fb7de782c35a88ae, ba7cbfc2ff94881cb0fcb12e, d7ee82541f3155d5a94ec1f3, e0812a065f4ce2cd75c343a0, 3e79513adb35c12b28efc46e, 12483c89b7acfe261dc33455, 14729ddbec188892d98fac3d
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-04: Constrain file and archive access

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions\.
- [ ] Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret\-directory reads\.

Partial static rules: AI015, AI016, AI037
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### EXEC\-05: Prevent SSRF and unsafe network destinations

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect\.
- [ ] Test loopback, private/link\-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect\-to\-private cases\.

Partial static rules: AI014
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### EXEC\-06: Reject unsafe parsing and deserialization

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers\.
- [ ] Use data\-only formats with byte, nesting, and type limits; test malformed input and expansion attacks\.

Partial static rules: AI004, AI005, AI035

Open finding IDs: 2c25446598d6ff7b33cf8888
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### EXEC\-07: Render model and tool output safely

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use context\-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media\.
- [ ] Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports\.

Partial static rules: AI039, AI040
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### DATA\-01: Detect and remove embedded credentials

Category: Data and privacy · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret\-like values\.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: af4482a6a8e9174f701bf192, 98a2493baaed725cdbbd3a57
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### DATA\-02: Minimize data sent to models and gateways

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway\.
- [ ] Document allowed data classes, processing location, retention, and training use; redact before transmission where required\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-03: Protect logs, traces, and error responses

Category: Data and privacy · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them\.
- [ ] Test the failure paths and provider errors as well as success paths; restrict access and export destinations\.

Partial static rules: AI009, AI033
- [Source](https://owasp.org/projects/mcp-top-10)

### DATA\-04: Track provenance and integrity of AI data

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds\.
- [ ] Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced\.
- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)

### DATA\-05: Enforce retention and deletion across copies

Category: Data and privacy · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider\-held data\.
- [ ] Verify deleting a source record removes or invalidates dependent retrieval content and access grants\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-06: Protect stored data and keys

Category: Data and privacy · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Check transport verification, storage access controls, encryption settings, key separation, and backup permissions\.
- [ ] Validate key rotation and denied access using a principal outside the authorized tenant or operational role\.
- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### SUP\-01: Pin and inventory executable dependencies

Category: Supply chain · Status: no\_pattern\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins\.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries\.

Partial static rules: AI018, AI024, AI025
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-02: Check vulnerability and maintenance exposure

Category: Supply chain · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version\.
- [ ] Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### SUP\-03: Verify artifact identity and provenance

Category: Supply chain · Status: no\_pattern\_detected · Validation: manual

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts\.
- [ ] Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe\.

Partial static rules: AI019, AI024, AI035
- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-04: Protect build, release, and configuration changes

Category: Supply chain · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance\.
- [ ] Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies\.

Partial static rules: AI020
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-05: Harden runtime isolation and deployment defaults

Category: Supply chain · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints\.
- [ ] Separate agent execution from control\-plane credentials and audit storage; test isolation in the deployed environment\.

Partial static rules: AI021, AI022, AI023, AI031, AI042
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### SUP\-06: Separate and protect model development environments

Category: Supply chain · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] When training or fine\-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions\.
- [ ] Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact\.
- [Source](https://csrc.nist.gov/pubs/sp/800/218/a/final)

### OPS\-01: Produce attributable audit events

Category: Operations and resilience · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers\.
- [ ] Protect log integrity and clock consistency; ensure agents cannot erase their own action history\.
- [Source](https://owasp.org/projects/mcp-top-10)

### OPS\-02: Bound work, spending, and concurrency

Category: Operations and resilience · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Set server\-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time\.
- [ ] Exercise stuck loops and amplification paths; verify limits apply across retries and child agents\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### OPS\-03: Make cancellation and shutdown effective

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks\.
- [ ] Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)

### OPS\-04: Fail safely and prevent duplicate side effects

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege\.
- [ ] Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### OPS\-05: Monitor behavior and support rollback

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes\.
- [ ] Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### OPS\-06: Practice incident response and disclosure

Category: Operations and resilience · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state\.
- [ ] Exercise an AI\-specific incident and define approved vulnerability/intelligence\-sharing channels without exposing sensitive evidence\.
- [Source](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet)

### TEST\-01: Measure prompt\-injection security and useful task completion

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Run paired benign and adversarial workflows with representative tools and attacker\-controlled external content\.
- [ ] Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect\.
- [Source](https://github.com/ethz-spylab/agentdojo)
- [Source](https://github.com/uiuc-kang-lab/InjecAgent)

### TEST\-02: Test adaptively and repeat scenarios

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses\.
- [ ] Report per\-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average\.
- [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)

### TEST\-03: Exercise MCP authentication and protocol abuse

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing\.
- [ ] Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed\.
- [Source](https://github.com/AIS2Lab/MCPSecBench)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### TEST\-04: Verify cross\-tenant and cross\-agent isolation

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Create two principals and attempt cross\-access to objects, memory, caches, handles, subscriptions, and execution results\.
- [ ] Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation\.
- [Source](https://github.com/agiresearch/ASB)

### TEST\-05: Test approval, policy, and sandbox bypass

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Use explicit forbidden\-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution\.
- [ ] Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary\.
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### TEST\-06: Verify conventional application security

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Run language\-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services\.
- [ ] Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access\-control risks with safe fixtures\.
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### TEST\-07: Validate resource exhaustion and observability

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies\.
- [ ] Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### TEST\-08: Evaluate the optional security judge itself

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts\.
- [ ] Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation\.
- [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### TEST\-09: Evaluate model\-layer attacks for hosted or customized models

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget\.
- [ ] Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk\.
- [Source](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/a/final)

## Coverage and limitations

- Static pattern and local syntax analysis do not prove exploitability, authentication, isolation, or absence of vulnerabilities\.
- Python receives AST\-based call checks; other source languages receive selected textual/configuration checks, not whole\-program dataflow\.
- No dependencies are installed, target code executed, services contacted, or CVE feed queried\.
- Default excluded directories and unsupported files remain outside the selected scan scope\.
- Prompt injection resistance, authorization, tenant separation, runtime egress, and human approval need adversarial/runtime validation\.
- Evidence redaction is best\-effort; reports and optional judge payloads can still contain sensitive code or data\.

### Inventory

Dependency manifests: 25; agent/MCP signal files: 185.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

- libs/langgraph/langgraph/pregel/main\.py: ValueError while reading or analyzing file

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|

## Optional LLM judge

Disabled. No LLM request was made.
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
      "binding_sha256": "8b53931373a6e858b0b49c794fc4a31c3d9c7801eb7078cf8b02a74ae803af48",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:b2c38b5835f1f8a2839ec011",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/__init__.py:160"
    },
    {
      "binding_sha256": "c494ca30752058c621c6fe2855b3ba0a2c3f3ac29117fbf7d6870d9fd966848b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:451c0b7574ca3c42e003e843",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/__init__.py:238"
    },
    {
      "binding_sha256": "c2ff1263612fa9a7ba459b07523807130bbd7d50007b23a1bdee76a3f221605a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:318b54ec7ce9e0a952e50928",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/aio.py:149"
    },
    {
      "binding_sha256": "9b9f4fb9ea7d5111a12a2d6c877d58529aeee33932f376aa015bd14e4a53abd5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:6daba84ba6680768f8b7c81f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/aio.py:206"
    },
    {
      "binding_sha256": "c4046f74decc04a3562a227393cf7b821073181b40f73e9be77b6973bf496542",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:f02711b198ef60d0f15ba549",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/shallow.py:280"
    },
    {
      "binding_sha256": "27ea90585a2ffe3297abd8bebf289d11b4fff48f0cac222b99109d7bc4dc7dcb",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2d6bc11b77ad73d68b1ef44e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/shallow.py:344"
    },
    {
      "binding_sha256": "38fc525ef4c4caec270192063384a77284f2cc9df5d12ffcf5f63bf06b9f0561",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:f27074c799df548b0c528627",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/shallow.py:646"
    },
    {
      "binding_sha256": "1d4574a552454658db7a49c87b4f96c092170c914d7ac57069595ae111e92096",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c0fd27b46f5af81b21de1440",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/checkpoint/postgres/shallow.py:691"
    },
    {
      "binding_sha256": "5e6022fcaf63fa747a0d8c09d8c5092cead74cd399e0fe1bcd643f273389094a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:549f2a26378737bba7d09085",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/store/postgres/aio.py:236"
    },
    {
      "binding_sha256": "4a7c4c6e48f5ccbaa60d20964adc4caf84091c0db2fc85c839281e21adce4341",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:45c1a462742498388c9630ed",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/store/postgres/aio.py:243"
    },
    {
      "binding_sha256": "d24e180d5a30e02d50c9d1ee1df2e60fc7bad74accb4830848917728d6e15a70",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:3d51002a6ec0ed7f474ad9b4",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/store/postgres/aio.py:290"
    },
    {
      "binding_sha256": "8879dc1cb6614fb1a458a414f9706667d30f2281394080a05267f2b75d46d268",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:202c42d80f9d2ac762b159c5",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/store/postgres/base.py:1124"
    },
    {
      "binding_sha256": "ca0c187f04f29190221dcea3b4480c123e5daae947de4c4d482cce0476cb0298",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:80688422952496533add7769",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/store/postgres/base.py:1131"
    },
    {
      "binding_sha256": "27e1576d9b08e7cd6b5ae56dea08d03aa51b3a57cd51210d42e8f4a7e4cd7aca",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:5837e9a9fb7de782c35a88ae",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-postgres/langgraph/store/postgres/base.py:1186"
    },
    {
      "binding_sha256": "da4645fa02ad116abcff6947455e692dd6600d6d5042f76819273c64c60cde0f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:ba7cbfc2ff94881cb0fcb12e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-sqlite/langgraph/cache/sqlite/__init__.py:56"
    },
    {
      "binding_sha256": "52fc31e5d0d9f2cb2f5aa4cd829b73a34c46f190adfc9530d9d447fcdc34f7bf",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:d7ee82541f3155d5a94ec1f3",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-sqlite/langgraph/cache/sqlite/__init__.py:106"
    },
    {
      "binding_sha256": "05b48ed08ea5ab0e66da4ac1428609aa843e6fd91833e343c15382df8830e2ae",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e0812a065f4ce2cd75c343a0",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-sqlite/langgraph/checkpoint/sqlite/__init__.py:343"
    },
    {
      "binding_sha256": "7c2e0f78ee0ff406cf57f8fdf617f1dc7d17b55893a707a28a21002d5e6fd47b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:3e79513adb35c12b28efc46e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-sqlite/langgraph/checkpoint/sqlite/aio.py:463"
    },
    {
      "binding_sha256": "04d516341f781a7757b938dc74a6101edc240ab9f255a125ccd50cf43ff41fe8",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:12483c89b7acfe261dc33455",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-sqlite/langgraph/store/sqlite/aio.py:571"
    },
    {
      "binding_sha256": "dbaac0cb9dd0ed6fa7f7a2369f9fe4680923cab1b4365812aaa5645897453c99",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:14729ddbec188892d98fac3d",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 libs/checkpoint-sqlite/langgraph/store/sqlite/base.py:1422"
    },
    {
      "binding_sha256": "4ad39b992f2f78f7041d393dac81c5f361946d39c80c389f5908b86b2228e91a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2c25446598d6ff7b33cf8888",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI005 Executable deserialization requires trusted inputs \u2014 libs/checkpoint/langgraph/checkpoint/serde/jsonplus.py:288"
    },
    {
      "binding_sha256": "853a8fa76ad71528d96857032d4952bb5abc9478c9f8ada337c9bdbd1c451935",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:af4482a6a8e9174f701bf192",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 libs/cli/langgraph_cli/constants.py:5"
    },
    {
      "binding_sha256": "3aef2a84ef38a300429145e868e0a9fdf71663fb12ed293486815609d38159d7",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:98a2493baaed725cdbbd3a57",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 libs/cli/langgraph_cli/docker.py:239"
    },
    {
      "binding_sha256": "01383cceb30f9a58cfd4365fb064ef59e0d40027eb204e66fbc6d39dc706e990",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-01:1 Record owner, deployment, model/version, MCP transport/version, exposed tools, data classes, and external endpoints."
    },
    {
      "binding_sha256": "5093595a820e4e4d28e9f403a6ce3e33d382af1e982702f5964dc426c7bf6dcc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-01:2 Reconcile approved inventory with deployed configurations; investigate unregistered agents and servers."
    },
    {
      "binding_sha256": "3f85acb9a3f0d7e4f21a6c091925c6673c2dd8deca63de72981d3c4e329b4a1e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-02:1 Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials."
    },
    {
      "binding_sha256": "ce12043c1f99a2b9e32f7a9927b29a240cee94886fd8d93fc322daf62ea7cfcb",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-02:2 Identify who controls each input and the highest-impact action reachable if that input is malicious."
    },
    {
      "binding_sha256": "d6f82995d88af44397f29fec074150e96b516b0bcd3007d5f9b862b8cd5958d7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-03:1 Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes."
    },
    {
      "binding_sha256": "8bc9ffdf09f7c193e3e1cb12437d1a96eea5fa14138c54b6d7c2e4c867757896",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-03:2 Record impact, reversibility, approval requirements, and accepted residual risk before production use."
    },
    {
      "binding_sha256": "f729d0c6aa257a560c057fc19921240da3e2a10fd67d5309b412f74494893888",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-04:1 Give each control an owner, evidence link, validation date, result, and next review date."
    },
    {
      "binding_sha256": "f5330be62d466173debcda8a4ef123fc75149cc5f04dd7c873abba4f53d8d6f7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-04:2 Time-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure."
    },
    {
      "binding_sha256": "fb98c4554da9c1d846888df298bea59fe7a53247ce8e4e6c1c3c41ae95eabafb",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-05:1 Review security impact when adding a model, tool, server, data source, skill, or broader permission."
    },
    {
      "binding_sha256": "c4644b968c18aad436641e13a9a1e43c53cd2ff624032720af226b27e409ff34",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-05:2 Require deployment evidence for the complete configured system; a model-only score is insufficient."
    },
    {
      "binding_sha256": "63fdc70a4b7b9befa7222d7f0d40cc1b2a96e4714895fcdc87abeb7931980947",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-06:1 For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on."
    },
    {
      "binding_sha256": "88cadcadbbd84d4170e57dc8441886d62fe2ca87deddf0bc654cf98936e95daa",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-06:2 Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review."
    },
    {
      "binding_sha256": "e60b5d1887d59889f1e6e071f51da988d6f9503dd864de6ad29f518210313848",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-01:1 Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries."
    },
    {
      "binding_sha256": "6f983a627168873dbb3733fc80cb459a371d129ce494c7fa120e6ed98014eaff",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-01:2 Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation."
    },
    {
      "binding_sha256": "887416b64b961a3effa9b9073e1c796b49bc55bccd6a73f05dde412d6a391fb8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-02:1 Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution."
    },
    {
      "binding_sha256": "3affec263338e44d1b5f952da1a8ffef2c5b642de16a8b9ea94717052b74268f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-02:2 Deny by default; test read-only callers against write tools and object identifiers owned by another user."
    },
    {
      "binding_sha256": "a7136ac0f09a5ac5389320c42da4f3353269234d3e01acd9a62ce01fdb817f20",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-03:1 Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes."
    },
    {
      "binding_sha256": "8cf0be7fc349b656b11cc75fdf15ba708c13610347e6360f62d7a18807ef0076",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-03:2 Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation."
    },
    {
      "binding_sha256": "81099a2bab3ac1d9f0aa4ef53ad2868f7260aaabefe172083fbf774f435bf40a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-04:1 Use audience-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens."
    },
    {
      "binding_sha256": "8d7f6f71770ddfc637414da2d42f0a18bee46640fb57280b6f147e208cff7fc4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-04:2 Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize."
    },
    {
      "binding_sha256": "5341d52ccee45be8febd87b570fca808892b5640baeecba67761969307db0662",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-05:1 Use short-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation."
    },
    {
      "binding_sha256": "39e561eb49234fa0d36e01e2804dfb4a043c56bb8b6be15abece0aa7f230a930",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-05:2 Avoid tokens in query strings, model context, source, child-process arguments, and diagnostic output."
    },
    {
      "binding_sha256": "287e1c9ab7de590b025b90ea0a8cdd2e413e382e4ab92b7c3f53ebe2ce020eb9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-06:1 Test PKCE support and S256, exact registered redirects, transaction binding, and authorization-response issuer validation."
    },
    {
      "binding_sha256": "93204501b21463ad0fb02e9b842863cdce592a57658196f4de211921948ed6c9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-06:2 Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions."
    },
    {
      "binding_sha256": "6bcf5df2c6e992b8f261e6e06709906db49b5fa8c8e4e286534ae71f1c4f0e7f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-07:1 Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes."
    },
    {
      "binding_sha256": "760288221980d07c6f9bd7b624b9f8e4455c64f4090c6dbab909d093b3feb63e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-07:2 Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services."
    },
    {
      "binding_sha256": "3554492e6041877fb41a233e3b6d5355733804fc7c267c060f23f6a0a8ccab28",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-08:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-08:1 Carry authenticated initiator and delegation identity through multi-agent calls instead of trusting identity fields in text."
    },
    {
      "binding_sha256": "930c7d031367fb8df40f3b452bcd25067b16b42d087d55f22f9061980287d069",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-08:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-08:2 Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences."
    },
    {
      "binding_sha256": "6bfa00cf9cbda63b16142844de74841bdc4b58c4f4050d5c223ea21e7444cbff",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-09:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-09:1 Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access."
    },
    {
      "binding_sha256": "5dd9bf595ae2645ec613db2bc0e0582c832664e286f480ff79002500db33a762",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-09:2 Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access."
    },
    {
      "binding_sha256": "cdd2798b50f0098f698d50ee2426d7334d16161e48af0fda4e646c65f662a745",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-01:1 For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces."
    },
    {
      "binding_sha256": "96f9340cc8806fdfd261d9c261b1fec74e93a3ec5baa2f928928b27ecd7a4032",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-01:2 Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment."
    },
    {
      "binding_sha256": "d395744b66f5d07691d7342be4d15e7823841f42f191b874615dec93ba26d4cb",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-02:1 Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate."
    },
    {
      "binding_sha256": "8ffcaf0990834379cc03cadedfad0af684cb2e5f9e0e557d55b811a2d3b8610d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-02:2 Bound sizes and nesting; validate declared structured output and render errors without leaking secrets."
    },
    {
      "binding_sha256": "9a9419e1ad67c1e90af02935782ac4093e5b149f4ab48f80e58364420a6fbae3",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-03:1 Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries."
    },
    {
      "binding_sha256": "2e3ea2e09c4b02413b6d5b1a4128af69a4f6cde503da4efa446f0f2a7b15541b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-03:2 Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy."
    },
    {
      "binding_sha256": "c4e97cfa80450b8de4a12f130d4e6ce504ee76bdb9af2db012c4328f03bf3a40",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-04:1 Bind tool approval to verified server identity and the reviewed tool definition or version."
    },
    {
      "binding_sha256": "e729795e96c5892df0c9a796722388e3231da6f1f9e6db9aebc029af3516a292",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-04:2 Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names."
    },
    {
      "binding_sha256": "c04a1959059324248e9c15fd0843bd8509cb3588cd42cab8485e649d13c79d5d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-05:1 Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries."
    },
    {
      "binding_sha256": "7727c6180a5f849036693a22aedee7b53dc6664f919b8a37333117f71d1ee87a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-05:2 For older sessionful protocol versions, test session hijacking and cross-user resumption; a session ID is not authentication."
    },
    {
      "binding_sha256": "17f55a16ff0da385160afc3ae70a17f2cb9e0ba54c63b332aa47988c55c71e3d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-06:1 Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access."
    },
    {
      "binding_sha256": "99ad66ffd54d49252358e5c15e4b68574d75e1270fafb664a871defa75590f6e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-06:2 Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget."
    },
    {
      "binding_sha256": "67be1016b327c573933c47153793f80988ee57a7fc4eb4690e65086081aac1f6",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-07:1 Keep sensitive credential collection out of form-mode elicitation; validate and visibly identify URL destinations."
    },
    {
      "binding_sha256": "12a155c72147947580ff18489d3c1d32c57f3c3663bc223c11aa949c67983f2d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-07:2 Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version."
    },
    {
      "binding_sha256": "129f9145e197194787d4193f05ad591b88c46d11b5616366c8db6dfa805b602a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-08:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-08:1 Treat declared roots as scoped information, not an operating-system sandbox or complete authorization mechanism."
    },
    {
      "binding_sha256": "2234dcfce3a3c1c0594373fa261fc6ba11dbb94828cf8a838cd5456ae014dae4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-08:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-08:2 Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace."
    },
    {
      "binding_sha256": "5119d7bee854c5888b401b7ec21154198465488392a25d7515d7567092ab5978",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-09:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-09:1 Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment."
    },
    {
      "binding_sha256": "427a0116e8e840778dc78b90df56e66c8c1725deeaec165b279ee400abbb0ab1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-09:2 Restrict proxy process-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs."
    },
    {
      "binding_sha256": "2575d5d3060166d034343ce2715b351433f0017f265fc7cda6640152563fbc2d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-10:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-10:1 Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules."
    },
    {
      "binding_sha256": "0cc98ec9fc5b1d8424a55dda74d94b385125e7f4c119298b7e666342797fd594",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-10:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-10:2 Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally."
    },
    {
      "binding_sha256": "baad8e89820cb18a67c756722d4b305e5cb1d758da9f6bc57e76e3a0a7c3e24d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-01:1 Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities."
    },
    {
      "binding_sha256": "6f73a1af3405d7673363e1ac6a8324d5dc7ef985dd33db9f436fb5b3465793a8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-01:2 Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval."
    },
    {
      "binding_sha256": "59c24334704dbeded18dd46a6bb0a594b52f713acfcdad7758d7af53b97026f6",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-02:1 Present actual recipient, target, arguments, data disclosure, and consequences for high-impact approval."
    },
    {
      "binding_sha256": "7486517a0e59efc567443ef339708b4f9c591ff847c756de830027b5fdae206e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-02:2 Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse."
    },
    {
      "binding_sha256": "af06a9b351cdb8b9d160a9645acada2582ce9f289d0cd81c28f8e16a2bc34b8f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-03:1 Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions."
    },
    {
      "binding_sha256": "1be36e9a439bb7e9fa303d7099a12e0cf95197680109f125444d2b24e8afdf73",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-03:2 Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls."
    },
    {
      "binding_sha256": "4963270bbb7ec069828af2bf0ce6d5ad6e033e697a381a5e6fd0da049c8b60b9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-04:1 Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters."
    },
    {
      "binding_sha256": "f3f1b4f23860637e13c9552a03fd6b5a252459a07bfade38b122b95acc237dae",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-04:2 Test poisoned memory persistence, cross-tenant retrieval, provenance loss, deletion, and stale privileged context."
    },
    {
      "binding_sha256": "c18f43539966fd54d80ccd3eb7ea2a79fa9357615074a517e539e5020a05fa16",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-05:1 Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions."
    },
    {
      "binding_sha256": "e82e283dd0c92c0f53409c580bf60dfb946d45825dc37cbea68a942032696365",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-05:2 Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs."
    },
    {
      "binding_sha256": "0cc89e742ca137b24c93c962a3ccff69936719a7bfadf8ddefc89123b44f7ac4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-06:1 Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs."
    },
    {
      "binding_sha256": "692169d9818ebf2244bb631a7c40db6b4b65157a9b839ddd5037d7145a1e98b3",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-06:2 Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy."
    },
    {
      "binding_sha256": "70c278be67422a2c0966a936f9860da19908f4493c8535da23f41dbdc03024dd",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-07:1 Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents."
    },
    {
      "binding_sha256": "4535334de37853cbc73c346fa60160d55a2647077d0b4dad34df4257113a191e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-07:2 Use canary data to test encoded leakage and combinations of otherwise permitted tools."
    },
    {
      "binding_sha256": "7423c8286fae9d6e15e1443dbebb83b71cac31f9bf89de0715ea3081bef3e51f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-01:1 Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values."
    },
    {
      "binding_sha256": "8a92dad6c8abb6040d03c60b4e6869a316a649c284765d9fb354004698080164",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-01:2 Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames."
    },
    {
      "binding_sha256": "8603d4cde5c4cf3e44e65625cdb1179a4d5678882b455bb2db1b50d6dae7d9dd",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-02:1 Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content."
    },
    {
      "binding_sha256": "5be4cd62b89311e670d3e9278fc426d923d1a85a2a0de574634e559f9e8669b1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-02:2 Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits."
    },
    {
      "binding_sha256": "3d0b0779698b01e53290dfa10fd30b7198a52466957fe4ebcd1e4cee05756835",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-03:1 Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search-language construction."
    },
    {
      "binding_sha256": "70326ed2aef09c0cb7dcf9ef4bcdb048f4d02651e533a824e1128b8eac15af8a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-03:2 Separate read/write database identities and test whether generated queries can escape permitted objects or operations."
    },
    {
      "binding_sha256": "8c481cb4c62c4eefcd06a74272388c08509e417353965fc2c05d04564e6377a8",
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
      "binding_sha256": "33e19e6eeabbc73fd39d21799e498e326915a9584ea89110dabd3e7c285fde65",
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
      "binding_sha256": "6cc7edc3fd02e88d5f3a343d77004fb3024f0aecb15151a1a474d5c606bad62e",
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
      "binding_sha256": "87b25f5e0a76b247c3cf1161d28ac8d04bc441d5e55b34c0e7fa604c05e1aa7c",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-05:2 Test loopback, private/link-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect-to-private cases."
    },
    {
      "binding_sha256": "edec22bc6b0f76a2d2bf2d9db25435d661da4eea4e9a8eb6a9961d20971aa69a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-06:1 Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers."
    },
    {
      "binding_sha256": "820fcf83427d41705c200a08d7321e7fc5b2109fa2d8a227370f6846bfb134dc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-06:2 Use data-only formats with byte, nesting, and type limits; test malformed input and expansion attacks."
    },
    {
      "binding_sha256": "a31c816b8bd63c9519bc728113dfad7d4e8c2ca3e3a6b4e74b2a8f7042b82565",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-07:1 Use context-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media."
    },
    {
      "binding_sha256": "7f8387f291546a3543d8ab2b8ae2fbf94e948c7a6d705c909a501cb0d223b468",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-07:2 Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports."
    },
    {
      "binding_sha256": "4575cd5128d21c7a613dc82f2dbb1bc35ca0e863e2981562e12432292682ef1b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-01:1 Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret-like values."
    },
    {
      "binding_sha256": "01b693830f085c7afdc3ff48f03fd09f8f8a87351a60d5d3d0aac9cca8993dbb",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-01:2 Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts."
    },
    {
      "binding_sha256": "9488a38a334d108ee7dd5f255d3acf920e5bd0fd494d41561268edbca7d8a3de",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-02:1 Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway."
    },
    {
      "binding_sha256": "904efe128800dea9a82038edff9caaf118be230d9a97c9d10a4eca9b4e046b9c",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-02:2 Document allowed data classes, processing location, retention, and training use; redact before transmission where required."
    },
    {
      "binding_sha256": "4fe8b36e8bbfc9881a696d34b6756c370563ebae1e7c59e1397632c4b0d5ea4c",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-03:1 Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them."
    },
    {
      "binding_sha256": "1bf1bb02b805ac2b301801a7cc2c4fe96ceeabadf420c24d031e1ebbd45199a2",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-03:2 Test the failure paths and provider errors as well as success paths; restrict access and export destinations."
    },
    {
      "binding_sha256": "c9c54ae10d42a591fee44f21d5a78df1b7f2339eb8e416366ebb850e47dd2160",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-04:1 Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds."
    },
    {
      "binding_sha256": "7c953f4fcd19e8ae26c50658b9168167ebffab5fd06060f16a20a9be14b55834",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-04:2 Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced."
    },
    {
      "binding_sha256": "ee4a96f3ddc49eeea2df3db17818b17e1794a66e3f676e0c063334e74a34174b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-05:1 Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider-held data."
    },
    {
      "binding_sha256": "2d897957486ece2342b3623e93d5ebbe1ca5a7a5f463b941f34847f58c80d898",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-05:2 Verify deleting a source record removes or invalidates dependent retrieval content and access grants."
    },
    {
      "binding_sha256": "9078dafa78d83874b83d091959628cf595b77db9f8f88af4fcd9751a25b27998",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-06:1 Check transport verification, storage access controls, encryption settings, key separation, and backup permissions."
    },
    {
      "binding_sha256": "75e833bbdfbac02a01307de7114ab54f16f1f0f5679fc4dee0bb9c5452bdb111",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-06:2 Validate key rotation and denied access using a principal outside the authorized tenant or operational role."
    },
    {
      "binding_sha256": "4a84699a062361c925030df86090475c34f89004e9f1d1f1413b5155fd5caba2",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-01:1 Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins."
    },
    {
      "binding_sha256": "b5a2a2a4a3ddcee472537efc27982d8ee553d31c6b61b657089026912d3eb4d0",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-01:2 Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries."
    },
    {
      "binding_sha256": "9cdf0f1bc315a85420c3388dcc9eca88de1a7f842e7c9df486027a4e991c5832",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-02:1 Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version."
    },
    {
      "binding_sha256": "2af860554f1ccf82368a231c4b1aac8101d65300d4de8a6bec242e2f28c84220",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-02:2 Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage."
    },
    {
      "binding_sha256": "555b1a39184c968c0cabbd6cec28bbaa79ca353543f976875865e2a959f959ea",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-03:1 Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts."
    },
    {
      "binding_sha256": "8ee40aebd1b4bc6b2bbb7f1281871912366442b4dd0e98a9c0dd47029255385d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-03:2 Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe."
    },
    {
      "binding_sha256": "7915d5f749400c7b378560c09778497d3cfe3fa472e48eba2a0211ba927f083c",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-04:1 Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance."
    },
    {
      "binding_sha256": "7f9942ff0eddf7724f6f6bc38eb6a326dd39816ee8be4ddb07e83cc896f893da",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-04:2 Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies."
    },
    {
      "binding_sha256": "b18a4079a18b6f10924aef2b609771b2a6c9fe87eac2c5041193a6c8c967fb3b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-05:1 Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints."
    },
    {
      "binding_sha256": "fba8ec8c0cfe0081a0c957d5ebbfc9b5c2054fa63332353ef1d39fff8ec3caa2",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-05:2 Separate agent execution from control-plane credentials and audit storage; test isolation in the deployed environment."
    },
    {
      "binding_sha256": "29b6566456127a31454e9b8553d8f7bcdaf5a59cf408c32cfb9b8fbc2970d424",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-06:1 When training or fine-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions."
    },
    {
      "binding_sha256": "ff76c23c8a2121019149b5eaf6cb8f24d6b8e2d42fb2c04af22a86c710127693",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-06:2 Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact."
    },
    {
      "binding_sha256": "7995076560e2bf661cf1727277d6173a81f5883b65e62ceb950777456eae76e4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-01:1 Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers."
    },
    {
      "binding_sha256": "c5f4301d72a356f88a9f2943dc056905729af5db8ca86daf21487e65c46504cf",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-01:2 Protect log integrity and clock consistency; ensure agents cannot erase their own action history."
    },
    {
      "binding_sha256": "8cb659f5d29752a44414dfd41068a89e1fc97080a35202fe727560c125806f7e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-02:1 Set server-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time."
    },
    {
      "binding_sha256": "8787cacee7e3eb99b11494af8fcf0cf2ab6c00098eaea04c928a5b5be9570a8f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-02:2 Exercise stuck loops and amplification paths; verify limits apply across retries and child agents."
    },
    {
      "binding_sha256": "f3f979d97a447dd4e9747cf7db5001ff71b3f9d9911e82c5bac4f2721e2365c2",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-03:1 Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks."
    },
    {
      "binding_sha256": "969b4304e81f0a82dac99ad77f909cf2db1f999aaf6ce35a110b386decc1aefb",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-03:2 Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects."
    },
    {
      "binding_sha256": "7716923864b6a7b3b74eb5a743ac213e9dc92c5eeff31339035f9cffd3d23ec7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-04:1 Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege."
    },
    {
      "binding_sha256": "af0238f141db6ebf29f2aa7713510fc6e5b415108eca63c6017c55634b35e096",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-04:2 Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects."
    },
    {
      "binding_sha256": "f05a608b305909c96dbb7602ec752898d47da9683064cb7c557cf597808fdadb",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-05:1 Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes."
    },
    {
      "binding_sha256": "84afca93f9242a1a138e26d727d450014e572f568ff5034337da2ec9c91bb718",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-05:2 Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory."
    },
    {
      "binding_sha256": "513b12b9228a3b82c61fdfd1d91c01028748a20b4ab71b1515c09f8bb10427fc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-06:1 Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state."
    },
    {
      "binding_sha256": "8e19aa502894552a379050556be9db1b769b7520314d6985dcd4c9dadb9ce213",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-06:2 Exercise an AI-specific incident and define approved vulnerability/intelligence-sharing channels without exposing sensitive evidence."
    },
    {
      "binding_sha256": "20210e5d73316f2a04d79272f5707f37562544073256707619ebc3e47108c58d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-01:1 Run paired benign and adversarial workflows with representative tools and attacker-controlled external content."
    },
    {
      "binding_sha256": "55d54630820f9f0bafd1e1dd88c5b513f51f83fb66b3c5b1e400e5961ea21efa",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-01:2 Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect."
    },
    {
      "binding_sha256": "94e9cfe9fab4a0e988adf90b457564c95ba46ce937c1d3c9091bc176283998e9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-02:1 Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses."
    },
    {
      "binding_sha256": "f94e15b169550162d8e9f08a03e12cf31b479378c2f79a9ece1d9ce56ac240a1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-02:2 Report per-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average."
    },
    {
      "binding_sha256": "2f7961494f5c0f7de531001613f3200f780f82e46074f84d19d9a99f48a2ee81",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-03:1 In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing."
    },
    {
      "binding_sha256": "91f5e6e93e064786326cd8acf483e3da16cee6a643f87814bc1e00d73bc372e2",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-03:2 Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed."
    },
    {
      "binding_sha256": "f39370b691dbbf1c3c78318c7069a3a2bf2ca80aac8769ec20cf2c5972c5d4c1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-04:1 Create two principals and attempt cross-access to objects, memory, caches, handles, subscriptions, and execution results."
    },
    {
      "binding_sha256": "b9fa66a2d208391dc04b327aca6b5828817f2f378cb39537ac7dd01d87a58750",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-04:2 Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation."
    },
    {
      "binding_sha256": "f500ed5fd7e70d877c5dfce32814c60c0710b25c052172b3c05be7a126b0f83e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-05:1 Use explicit forbidden-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution."
    },
    {
      "binding_sha256": "228d6d840ad035b7d0a6406be1f3a2de3950f8878eb88d227503134137fceb8e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-05:2 Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary."
    },
    {
      "binding_sha256": "ef4d041da6fcd6bd4bd134ca665997f17b3a7572e78da1daffa5e1e3fcb00bb8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-06:1 Run language-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services."
    },
    {
      "binding_sha256": "d4b1779406f433c6dd6aad922ad2d7ad5f1760312b65b64c410d583ca997a8c9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-06:2 Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access-control risks with safe fixtures."
    },
    {
      "binding_sha256": "e3225ef5cb1839f9892703ca7f1c97bda77045279f9c09ff5332b641b0613411",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-07:1 Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies."
    },
    {
      "binding_sha256": "fe8f205dbb78d6e77b1b0d04dd73b66ad64f416b9dfc989082dd4f686ed74749",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-07:2 Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution."
    },
    {
      "binding_sha256": "3a224e53c64861ea98da2f55e90a70fdf2c321993a3de6bb17d6537ce381d866",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-08:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-08:1 Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts."
    },
    {
      "binding_sha256": "cbb06f841d6f126594693f57c8fd4ad30b1c5e82d174cc456f8b7b12e4fa7194",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-08:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-08:2 Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation."
    },
    {
      "binding_sha256": "0f5ed6c344105c6e18cabd1ff434338f78bebde1bb89d9489f0c1f87e647b49f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-09:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-09:1 Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget."
    },
    {
      "binding_sha256": "b8f007291e059bb0d1a077d5bbb47f235b9a0d0bfb1752e140c8f6c055e50acf",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-09:2 Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk."
    },
    {
      "binding_sha256": "f8321b6f407dab90915ab8f044ea119f266db5e08facb5e1dbef862d53e8e5b8",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:90aac303c7b0f01f57a0e55682b18e36341bbc22b0954a65e4e10bc8197c7301",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "libs/langgraph/langgraph/pregel/main.py: ValueError while reading or analyzing file"
    }
  ],
  "kind": "invarune_review",
  "origin": {
    "catalog_sha256": "6cf14d276defd895985dc521fc4538e717c5cd7d576123e5c600da047aacab8f",
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
      "max_file_bytes": 20000000,
      "max_files": 20000,
      "max_total_bytes": 300000000,
      "requested_scan_ids": [],
      "selected_control_ids": [
        "AGT-01",
        "AGT-02",
        "AGT-03",
        "AGT-04",
        "AGT-05",
        "AGT-06",
        "AGT-07",
        "AUTH-01",
        "AUTH-02",
        "AUTH-03",
        "AUTH-04",
        "AUTH-05",
        "AUTH-06",
        "AUTH-07",
        "AUTH-08",
        "AUTH-09",
        "DATA-01",
        "DATA-02",
        "DATA-03",
        "DATA-04",
        "DATA-05",
        "DATA-06",
        "EXEC-01",
        "EXEC-02",
        "EXEC-03",
        "EXEC-04",
        "EXEC-05",
        "EXEC-06",
        "EXEC-07",
        "GOV-01",
        "GOV-02",
        "GOV-03",
        "GOV-04",
        "GOV-05",
        "GOV-06",
        "MCP-01",
        "MCP-02",
        "MCP-03",
        "MCP-04",
        "MCP-05",
        "MCP-06",
        "MCP-07",
        "MCP-08",
        "MCP-09",
        "MCP-10",
        "OPS-01",
        "OPS-02",
        "OPS-03",
        "OPS-04",
        "OPS-05",
        "OPS-06",
        "SUP-01",
        "SUP-02",
        "SUP-03",
        "SUP-04",
        "SUP-05",
        "SUP-06",
        "TEST-01",
        "TEST-02",
        "TEST-03",
        "TEST-04",
        "TEST-05",
        "TEST-06",
        "TEST-07",
        "TEST-08",
        "TEST-09"
      ],
      "selected_rule_ids": [
        "AI001",
        "AI002",
        "AI003",
        "AI004",
        "AI005",
        "AI006",
        "AI007",
        "AI008",
        "AI009",
        "AI010",
        "AI011",
        "AI012",
        "AI013",
        "AI014",
        "AI015",
        "AI016",
        "AI017",
        "AI018",
        "AI019",
        "AI020",
        "AI021",
        "AI022",
        "AI023",
        "AI024",
        "AI025",
        "AI026",
        "AI027",
        "AI028",
        "AI029",
        "AI030",
        "AI031",
        "AI032",
        "AI033",
        "AI034",
        "AI035",
        "AI036",
        "AI037",
        "AI038",
        "AI039",
        "AI040",
        "AI041",
        "AI042",
        "AI043",
        "AI044",
        "AI045",
        "AI046"
      ]
    },
    "evidence_sha256": "f8cd6e23cc8128bbad0f643d213813c600e391b33648526b9e77d54c16857efb",
    "image_limits": {},
    "manifest_sha256": "7d1243fcfd19995ece7712f0bf69223e3cc8c66ffefa36cadf52b8787bfd469d",
    "scan_id": "25b371cf9c33a9d2685e47fc685213c6fcbeef2befbe1cb04338ca5533e50bc7",
    "scope_sha256": "efcfb2ab970ccb377a9f43575e8ceba85dead1517d2ffa271f89c511785704f6",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "a10cff2be83ee83ef7f016e0d9644b42b2cc9869528a91763840970dc87765f1",
      "name": "agent-mcp-security-scan",
      "version": "0.14.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

