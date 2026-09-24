# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `4ed2966b3eeb541cdcade0473065a36d243c06d23ab358f1aff84f4345a53bd2`

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

Guidance catalog version: 1\.0\.0; SHA-256: `1bd48fd16d4fe76ae3ccd1cacddce9bea2dedd0000856d61b21ffb8ba8c5dd7b`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 23 | Observed patterns requiring review; 23 critical/high. No severity weights or estimated compromise probability are assigned. |
| Partial deterministic mapping reach | 45.45% (30/66) | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |
| Optional AI answer coverage | 0.00% (0/132) | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |

**Selected scope:** 47 rules (47 active), 66 controls (66 active), 132 active acceptance checks. The selected static scope is incomplete. Recorded coverage gaps: 1.

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
| Selected deterministic rules | 47 |
| Selected controls with partial static mapping | 30 |
| Selected controls without static mapping | 36 |
| Selected acceptance checks | 132 |
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
        "batch_size": 6,
        "investigation_rounds": 2,
        "max_bytes": 2000000,
        "max_calls": 36,
        "max_chars": 120000,
        "max_files": 200,
        "max_seconds": 600
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
      "AI046",
      "AI047"
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
| generic\_text | 10 | Generic secret/URL signals, bounded English skill/instruction directives and selected Spanish/French/German override forms; no general translation\. Language\-specific execution/dataflow is not analyzed\. |
| json\_structured | 3 | Parsed JSON/JSONC fields, selected configuration rules and recognized tool/input\-schema descriptions; runtime values and referenced files are not resolved\. |
| python\_ast | 183 | Python AST, bounded aliases/values, selected same\-file argument/return flow, exact literal guards and read\-only tool write witnesses; no whole\-program or runtime proof\. |

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

Partial static rules: AI015, AI016, AI037, AI047
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
      "binding_sha256": "b16a317ca6734f1257f35a46d3e8292161b75e9193502906437a8e78bc18b908",
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
      "binding_sha256": "c60f92409d4f2ff77bac20c0d58198f8cc04600d960c049a717e5c81b76fa987",
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
      "binding_sha256": "903b51361d4d5c6257ad911c1dfd581ee4c8054277915f334a4412d56e423060",
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
      "binding_sha256": "d9e07b6ebeec5b72b37c5792fe5ab1320e7e1f5470bb5d1e695b2a9ba2c3ae42",
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
      "binding_sha256": "17750e7646da1e29668a6c8f9090617db0f18e6902c7fa2fd963989944305371",
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
      "binding_sha256": "8f39a75ae3b6863bf0cd5ef31a94df3667fd445784a4812227b8c970fe26b1d4",
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
      "binding_sha256": "f53a24d513eeba1d9840c237f6a2c1d21b76db51c2b320bc2049f3c0db0bafea",
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
      "binding_sha256": "6de6da4fa1d4d29f614f8c2b6ea3bcc5f9f04a8897cc0da0342a693c2e2965ed",
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
      "binding_sha256": "c48b285d59ef6f76e9bb5cd411a850a72d8af9a64e980003aa9c94b5397e3d4b",
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
      "binding_sha256": "2ccb2152bc4757e6ab6437f15201d94648525255e7e982e3356073a6b42ccdb5",
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
      "binding_sha256": "83cb190989b4dc5639dd8b5f458fbb871acbbdba454dbd364e1c299dab73cde5",
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
      "binding_sha256": "132221c83dcfd7d7fa00dbeba05cda780a097a8b63aed0e9ead59361570f2245",
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
      "binding_sha256": "1d76c6e80cfa1f4f855d51d699a1bae07ff29ceb7bf121524b3802459d8f2a60",
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
      "binding_sha256": "46601ce409c25954525edabd26f8035a78acd0f455dc4c677637a687b528236c",
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
      "binding_sha256": "eaeb05d23a140f3eaa5662f0a5111820509dea72c695f23054ef0752e09a0cc8",
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
      "binding_sha256": "2c462ca7c52e07cfb83b53f579e55d137a4a9dcd67ac48f61d16f732917dad3e",
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
      "binding_sha256": "e7320a25d34fc1033967067f9ceb01acdc08cbe9797e38c16978e4cfefe6e136",
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
      "binding_sha256": "2e3bc1922fa7dfd8dcdb42ead7376a963b0dc8cba968160b876b2d6d621daa11",
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
      "binding_sha256": "59bd28a0eb2fe3eb9d8e6975d4eaf6008a42d211015b6e160552e08f2111f077",
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
      "binding_sha256": "2b13945867b397a2490000d27974775d42d71e5baecd3056dee5c2f9f0d4d03a",
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
      "binding_sha256": "31b534f48e4219e105b5d1cb3de5e2732fc9bc66c2c0ae746f79e126c34bf609",
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
      "binding_sha256": "b862d6a8c699e0fcb3b16c7be0b8a31219f23018654f2dc05256e97f757119ae",
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
      "binding_sha256": "3df773c8586db97a3dde94358dcd830a0affa1c24c2a49d63b41fd242b39bd09",
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
      "binding_sha256": "c1bd26a115f502ddc5248396b598a5533063520ace8f04dbfa301e4fcc629691",
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
      "binding_sha256": "5f2bf3dfc0e424e1f1315f88f84a4d327dc0ca38273f02f423dba995c29da61b",
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
      "binding_sha256": "43eb42ccefaf7aaf1942f01b7456042e1dfec0cde053dcdea200e109ca5a7476",
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
      "binding_sha256": "dea085995afb8401f880ec7f7bbc5aa9c5dc9884a0e695199ad3aa0738d247fb",
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
      "binding_sha256": "a88a08e61cb507cc674de8204a3bc156f79e64a194afb770c8a39e07e0039a87",
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
      "binding_sha256": "1107cd12186b7cb9976fb7b0df47407d423cb5574c1e04aa1dcf05c4a6a76f52",
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
      "binding_sha256": "7cd2057af89b37eb57ca4f45b96a7e03949467015fc2576e36c25705851ad10d",
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
      "binding_sha256": "dd7b6397ed9a0aee9db178fc4ce6b8ec9180a4dedede16341abfa57ec7493cb1",
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
      "binding_sha256": "55ef12d6a86641457dc70d715d1fb6528db1d533d87f2da7b4b70362f923d3c9",
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
      "binding_sha256": "365a56e4d684565c9a86562459e92a130e17887b07b6fc753e11b5c89b07f9c7",
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
      "binding_sha256": "8ebdea6385233157cecd1d60393edbc177180b5a9b31c43826b3b62ecfce9484",
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
      "binding_sha256": "486b611b439ba4289801524b61782f426605e74d6f534e90594fd08961c29c92",
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
      "binding_sha256": "c804971f7b89b9192153214508e8b8de86c2c77c07d1a0048460ff70fe710ffc",
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
      "binding_sha256": "1556c5c77dbec236619682034e47cf4e2a34635dfb259d3cb09cb93abe9a019d",
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
      "binding_sha256": "aa8709121fff7827c93cdc57a04105ceb0941ac539f0deecaaf41988e7a4aba0",
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
      "binding_sha256": "4767eb8e5ffe238f1683a97734f82ba0329da6c29d184af73383b735442f7398",
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
      "binding_sha256": "e6349bec4b46c014825039df5ed94af62c43a805a6e0625678644c0042bf47e7",
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
      "binding_sha256": "f8431564fa1c2088ba8a36bc1eb5fce9be9804c82bb6d2fec229be9a4babb945",
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
      "binding_sha256": "59bec947df4ff89e9cbb8c617022ecb9272efb7e81a596afaf3cd7a738295d0d",
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
      "binding_sha256": "fe79593208ec0f39c9d349e5db53bf6ba36922c39169e78924820f4d95b50c1e",
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
      "binding_sha256": "da59e160b6cd98e1fc310703a4228269d6672c23004f73b4af297532d714f7e7",
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
      "binding_sha256": "b7ac9cae2005f26e946d374808d74639c796d1684fc17ca1645423b746758f94",
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
      "binding_sha256": "39ceffb7b3427de7ea78b2bfa7fb63c0d3f564934e6b508bcdbc4c8d02f3feb1",
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
      "binding_sha256": "d214b35533c404c01047836654097e3ffcca89786a242febe220ca0db2c346f9",
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
      "binding_sha256": "73611a6cd0832c1fa491caaa216b9ab7cd0cc04f020ab4a60332d992a2ac62c6",
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
      "binding_sha256": "fb81a8e006c7889b5735f7cacfee3a80b0855a703a7c0143db0783237586ca80",
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
      "binding_sha256": "d71d8f9b53d846a4683fba38e3193fdfb4db4d3cca6dedb32e33e0b363ac9a58",
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
      "binding_sha256": "f9742cd68112dda4934f08bf9328bcaab9b35dc8fc3c16697727766be40cfbd2",
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
      "binding_sha256": "2c1d92ebc57f3500c1a064fd4eadccc61b9514d392382131a8089731f5d8d53b",
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
      "binding_sha256": "75e3c28568a1305e406aa88c0461dc5d1dd2ba0d49cbbbbaa050586b2bf7aa78",
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
      "binding_sha256": "782a6c6440722564435b7a3c258afdbc23250851a78ec996aeaf6c2ba576f1b0",
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
      "binding_sha256": "1d2b6c22be7d285468fee1dc7ac5186925140bb40b9cfcf704214a83d3dd0025",
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
      "binding_sha256": "38733065cf0f104c34c75fcb7af823d27bb061abb050c17665519406b7cc8000",
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
      "binding_sha256": "6f9434b67cd366bb940029405b2f7e39e6e0252496e9d842729f33936ee697d9",
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
      "binding_sha256": "8293760ee20541b77db20fa5f0f396aa7825f2ab1a64300ea11efaaed1cb2287",
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
      "binding_sha256": "b03bda6e17122cb44f567227d961d4da84b66a85031b0263308a2e2f11387806",
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
      "binding_sha256": "2ab39465999a79d20ed2d981dd8e901579841c88eafe6b4865c064d24fb7f6dd",
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
      "binding_sha256": "094cd5d9084f310c22061dccad39cccf4106abcba8c8937c05fba575f6c38cdb",
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
      "binding_sha256": "bbd4fee345291189bd7b05641d92f67b1a342f50028086feb0174e71cef5a6e8",
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
      "binding_sha256": "95bf3bd578ada6f58f0e93fdbf6b6caf5ca8430fb19960aa0c8a74bcd9b4b901",
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
      "binding_sha256": "acc94a8a758ebf2908e876e608c44459c1afed7bc7809053d05519a93048e894",
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
      "binding_sha256": "6cc32bf64fb66f7d57a7fc5667aed95a1e0fe128fe67f94fa71e450202d9de3b",
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
      "binding_sha256": "35fd0dc8da6bb62ab6f18f4fc21a800953fde5ceefa1deb187a8aa5f60983746",
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
      "binding_sha256": "53cfe65962e7b8fb8045865e3d65ab8544e9863b16ef031545f90d629cb57f51",
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
      "binding_sha256": "539ada6a1a154933e5cb42e48a1752ab2b9ca005a1a7bf90efe4423c27dfa236",
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
      "binding_sha256": "09b2a81f5051482769f5eeee4337258cefd8bd77bd59477a0c19c8a357f8c2d9",
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
      "binding_sha256": "1bbf3c916f58091ea1ef34ce66ed0440f784e666f660389ba987a583a6021e62",
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
      "binding_sha256": "8496ccff6ae76c5f41a11f1ce7e6f56622608a3e4c66b6ff093ba23fe1fb6493",
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
      "binding_sha256": "2e8fd44242cd0bc255ce611a31d9a58427304e90749b372195f8726ed9d7a94a",
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
      "binding_sha256": "b5c2fd4839d8d1b32d4b56389de6579be86201c10f6be400ff0d4772e5574fd2",
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
      "binding_sha256": "fa1f5103b591d700e126b8d1b6d205bfc1854c4bd3273dafa9dc774fd93d5a2a",
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
      "binding_sha256": "e1deb1ce9f3db3b3908bfe37b764b3450b5cf7f5821393fb34c5642c14ec468f",
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
      "binding_sha256": "0b3d9a5807dfc79a4b4055bf940aa89a4794bf58b58f8682ef4aeda86bf66866",
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
      "binding_sha256": "8d1430e20b70a6751bbdd34426dc0f83f528fb8c933a524abf03fec329bfcf50",
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
      "binding_sha256": "a183d2c38147323cf438648c60c5de68748f13331477d57d56ab8bf05376582e",
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
      "binding_sha256": "e5e3862979f27e760a1921128674ea880f55091bf561f9ad8bb2886dbb56bc8d",
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
      "binding_sha256": "b0bbd214fb27c18e2aee5d8db45068f8103be25e39f11ef4f39e80561042ff36",
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
      "binding_sha256": "01052acf835dbcfe97005d9b0bf3bdb19fdc86ea77e0efd47f7c08d84437c468",
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
      "binding_sha256": "1856cdef5a1c98604660dffc6d9af6b681d5d3696c994dee4d32edded7286bb7",
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
      "binding_sha256": "7dd21cf849c332bdba5da60c8ae46a1c4833ef571cfd2bd208be0b6c888da990",
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
      "binding_sha256": "21ab6e501ff2f6141fe6b6d1d0487c57c0905f8b3125ef9dbe3339a370b1ca14",
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
      "binding_sha256": "174bb835e6a78a298bf471a544c07b7e13621a9d4b090cacebecc99add884180",
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
      "binding_sha256": "e256289e1095cc9ad2e77490edd33984b486592e09ee7a23be1551a6718d305c",
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
      "binding_sha256": "ca8816684a422b866632427cad924e170ae223cf9ab741daf3d1778d971a46d3",
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
      "binding_sha256": "30f4670e7dcf5e7e8ce4d9bfa25e079aec3c9b02c3e03acf9815b63a2f502119",
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
      "binding_sha256": "7cc5a6a9a705a0021a24e78e4d5ad077629f427b33439bb6d6e016c91ede32cc",
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
      "binding_sha256": "fc7b4edb929f31f35cd2fb0b14bb216c4ac08b7eb1f697749d8be0cc861cb8cd",
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
      "binding_sha256": "13faec2e507675fe4c6fbbd18e62b7d8ee7ea6f8a86f92049fb1b6049a92c818",
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
      "binding_sha256": "964792e37fe77a78557a540aa943d89c20bdcb863b3696b10c735afc2d1a525f",
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
      "binding_sha256": "aaca049d1078e92af28ae1d38ef0ce5123b79852cf5a7d56dd63ef95370dd9df",
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
      "binding_sha256": "4edc2df06e234bf0c5bcc574ad4fee2a764ad9e01dbe91783998ba0e83961e5c",
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
      "binding_sha256": "970dfc0ec03cffdea03169d7bfe211715f054481e3872ed0f55299ebae019b96",
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
      "binding_sha256": "cb4cd6373289b8b4973d626556035edba972ba199ef32e9fa6236b4befafa1ad",
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
      "binding_sha256": "eea286bee631b91d9ecfaed49998555c9e5057e5b33bbc38c792895165fe19a2",
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
      "binding_sha256": "8d6269bfe47ef7fab65f4d3e683af203cbe98ce8c52fbbc2a4cd4994f94577aa",
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
      "binding_sha256": "1e898760bda89e1fe29035e4d4fab0a45c58cea1fecc04128754169dc8f77ce2",
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
      "binding_sha256": "987eecc6d0647d7ce69cc2b5cdcf82df437b3c8f31cdb27311dcdca74875914c",
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
      "binding_sha256": "32461bc9695413790dcd8b2f8fc68f9ad9036044a881963bd13b90dd47bfc328",
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
      "binding_sha256": "d51345f467fd13d93049983e1b6aa81f6fc6943cf49f2b1345bbe3e8b88c3728",
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
      "binding_sha256": "ceefca742a2dcb574f7bbca715fed6c9c5e637c44d02766d3e6ddd8cc0d2a0bd",
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
      "binding_sha256": "80a886348847724be3231e4ad326350eda918799671b1a4ffa699a3b8287cf3c",
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
      "binding_sha256": "6a17d14e1feb23d7e9913d75b5f607f35c28bb20cb47f9bb8271b249b227bb3e",
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
      "binding_sha256": "9ee99b935184f1da23608eeb9092cae7fe17f12b0646e08fa3665cf422eedb5b",
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
      "binding_sha256": "5a97be21887235410475530ce755df1f344c6afa71f3e3bdb78e99e1edc9ea11",
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
      "binding_sha256": "a43e62977fafdade2b6123e7e3dfb728312e79323326464826e412a343e2dda8",
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
      "binding_sha256": "6899a1ddb62303a47fbaec46abcd9766eddc3e41c8874fd6a832e8b452f51c46",
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
      "binding_sha256": "45eadfd63477ba8efdf69574a5b7699d2f3f46ca3de202984f89a4d0b385a102",
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
      "binding_sha256": "e2fd2bd984e96b2a47be0ac66f0a2f3921557d521d31cd9340a62d98006bee12",
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
      "binding_sha256": "b7020f15660cd62a778fbf1817a1c192043dc5b205ace72e7d1bea35c9c4a458",
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
      "binding_sha256": "b67037af368ddeb96181102ac7d88eb8ca175add25cdd4493bad46648c24c4ed",
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
      "binding_sha256": "9f99dc1cdce8965a641f337e5e4042b10c5453ac7572fe9b6dc4ee671c0a70ee",
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
      "binding_sha256": "ac41c58c0a687ee2f0c9241b2eb00a799e88ab3700a1c15db14f4861b7ed3afa",
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
      "binding_sha256": "d6359ee630468ea4ae99aa254246a7a921e4b03f99391857f9be9ab74ce70827",
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
      "binding_sha256": "373ea53e28b4b9b1001bc53273a6a337f5a9c159882bbda632f3703705af6780",
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
      "binding_sha256": "da90e79f6006ef676125f642e7ff72ee451c6bb569853d4d29e58bce16133039",
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
      "binding_sha256": "fd687954c0333d8e48183e532bef26c820dfa747be599cefb662b8df6254faa0",
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
      "binding_sha256": "81daec88a3596e07458b752c705a494f9c780df50879ebe050d7957c3e4775bd",
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
      "binding_sha256": "10dcce574dbb7ccfc309b469d9604baa9b20f3b83f45ec5d3562a4b0dc55f7f5",
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
      "binding_sha256": "e68b0b4feff276f2faafb212977cea8f4bcd1d7f212f687ebb56815beb82b339",
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
      "binding_sha256": "95c8e0452f095b023e729972b143d4dd769cdbfecc41b117d8d4876ed35bd5ab",
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
      "binding_sha256": "f2bb45b9285ffa7b5a751f3c3bb897d9e4fc81389108d4ba79eddc482a4db748",
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
      "binding_sha256": "3fa20595e9175be772d53418647df4f9fb402161a7a5f7480af3566e6e29a098",
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
      "binding_sha256": "eca30c54110c8156fa5c3f256bf51b6985fa674f36ef92d239d5ab7ae74c27ee",
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
      "binding_sha256": "18f518850815fa66dac22af0b28b4ccbb27aa2af94082483b43dbdaf98b7aa98",
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
      "binding_sha256": "3c48d81dfac814c5495594a276f3d380b053ac13f881a3f1ea5f77effec5d6b4",
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
      "binding_sha256": "8abc64e050602f23ade13587ea2156b1bbd48741f0e8bb5bd2b975ed4e5cee9c",
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
      "binding_sha256": "99ba7ccaad60f840f9f5f5477ca61e2c9194292791d4f3c10289bad79d0e7560",
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
      "binding_sha256": "c3b3e8c2ed9227ca1b823859972e961086c50a205eb9724675f5a1dfc7e5b6f2",
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
      "binding_sha256": "72a1f59d3b4e3c67271c9f9fc7522bd94d4d3ea6b0266ab57d3342bded65d98a",
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
      "binding_sha256": "b3074348abcae82ffeeaa9976b20c30d6a81acc08cb3ba830271b711cb593e8b",
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
      "binding_sha256": "ba57ff9a59807e3125303069219e985d918368d6e5605a543829eec0ad79d52a",
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
      "binding_sha256": "4a394ebaf8b5939911fc65ee4acde441176c4f50b313aa901023e0e0e13afcee",
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
      "binding_sha256": "26d2665125821f256e1306c2ad35cb4f8679d3cfd8634e4439a1e2d8ee0ab04e",
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
      "binding_sha256": "4c2d74fb6e87ccc80374e3c144e3fdaa3d3f006341203c7ca85347f673fab86f",
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
      "binding_sha256": "fd879a9a89e5c40aaf752bd6c809d6a2042b8547cf1a5ca3a1bfad2377d4b00c",
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
      "binding_sha256": "b3e97feaa218f37f35244267fba1f9909d350585d5adec95b76ae2f7184dbfef",
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
      "binding_sha256": "12f41ddb07c8e8033c8c6e11c8c747a2d9907a9a0169f762b5ea6c947968e529",
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
      "binding_sha256": "c298c281060f5f10b0fb3c7c9722ec1262b07b06ae4a6c0247f9432afed8a9ac",
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
      "binding_sha256": "579c66da1d16a9f663e52ff392d65feb278f1c92e30674c50b3a74259c668acf",
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
      "binding_sha256": "310e7ae0265894fd25d2ff5558049117f81fe5ce9adf41ca3465850dd6ebf8ef",
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
      "binding_sha256": "f4064aa3ae79cb11620947f9fad833332b653fb32e436b26946161390e96a4a9",
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
      "binding_sha256": "8d777f5c5f93bb637d051dfe1f0f3d9418c0e1b0c34b230162b5dd7d6f57a746",
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
      "binding_sha256": "511a9d5c7fc4291e0fc1fcaade3f477f65edc7240bfb47d4cc9baccd15fcd4cb",
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
      "binding_sha256": "7b04186c9c46d3bf83b5bee89e43c350a0176410217296bb5b3ac964e0ed6927",
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
      "binding_sha256": "dca0c9cb297d49d242ac6774b28872dcd04c7f14a78b76df88488bbfc9cba6b3",
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
      "binding_sha256": "f4c8e1ba54f416f54212005c0a4bf20490ac735496122401180b75badbed1c82",
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
      "binding_sha256": "afc5ef78eb655d200cc95cbb8fe19e773d51df75af1c557aefd81a4f91983cad",
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
      "binding_sha256": "c9729eb605f6b6d4eea00e59c0ab43d3143d56c63c487e1c4770b00d108c0777",
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
      "binding_sha256": "218b6a96e4ae072015dfee22bf66ea58c55707be6f418c00aa360ba31eb4521a",
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
      "binding_sha256": "ef784863a14eefe4f6ca4416e3885eda579c7ba2df641fc43593a357c78bbd49",
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
      "binding_sha256": "8c0f3b0d84e0a99492dd94a73dd204cbda5cd5c8cc725da5f6aa7fb223eeabb1",
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
      "binding_sha256": "e1df9a9b853de4ec4da6484a0eb303a0b4b103c29624e9b595edadab3495eb09",
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
      "binding_sha256": "03f9c12b0e074fc7ae6ed685a44afc5fa185b1d7923af323eef5770dd70d66f7",
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
        "AI046",
        "AI047"
      ]
    },
    "evidence_sha256": "f8cd6e23cc8128bbad0f643d213813c600e391b33648526b9e77d54c16857efb",
    "image_limits": {},
    "manifest_sha256": "7d1243fcfd19995ece7712f0bf69223e3cc8c66ffefa36cadf52b8787bfd469d",
    "scan_id": "4ed2966b3eeb541cdcade0473065a36d243c06d23ab358f1aff84f4345a53bd2",
    "scope_sha256": "e475ea84d6b455001672c9f73d82a5157303bec031ba2ad997411599b09c702a",
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

