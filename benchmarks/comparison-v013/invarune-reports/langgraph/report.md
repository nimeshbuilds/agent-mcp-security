# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `5216f6ea18dd4bc4e82fefc2ca03fbb5315fcd445f2db00428ff6a87bf834961`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
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

Guidance catalog version: 1\.0\.0; SHA-256: `dadde42b9b4e7f65d34d897f716649ed0b49b1fc561e5e45a9eadbac43c5eed1`. The catalog is bundled and does not contact external sources during a scan.

## Methods, configuration and blind spots

Find repeatable security patterns and organize the remaining assurance work for agents, MCP servers and built images\.

| Catalog measure | Count |
|---|---:|
| Deterministic rules | 42 |
| Controls with partial static mapping | 26 |
| Controls without static mapping | 40 |
| Catalog acceptance checks | 132 |

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
    "max_total_bytes": 300000000
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
| generic\_text | 10 | Generic secret, URL and applicable text signals only; language\-specific execution and dataflow are not analyzed\. |
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

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries\.
- [ ] Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-04: Detect tool substitution and metadata changes

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Bind tool approval to verified server identity and the reviewed tool definition or version\.
- [ ] Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names\.
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

Partial static rules: AI031
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AGT\-03: Separate untrusted content from authoritative instructions

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions\.
- [ ] Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls\.

Partial static rules: AI032
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

Category: Agent behavior and context · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs\.
- [ ] Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy\.
- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### AGT\-07: Prevent sensitive context leaving through legitimate tools

Category: Agent behavior and context · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents\.
- [ ] Use canary data to test encoded leakage and combinations of otherwise permitted tools\.
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
      "binding_sha256": "70b8b142bc084b8af11e9698c190b39752e7b3f6bf6f5b81588867e7c3da31e8",
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
      "binding_sha256": "c1f77cf06d775e25a3f24e341962230675587a9984e84ca2d670148da9204772",
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
      "binding_sha256": "505807ed8e3acd646fd707de280fab06d92b86d3a7b9250f34974da731ce260b",
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
      "binding_sha256": "f30210879bbbf844e0ab2089da0241dc9e415acd946c6db981f58ef0c2fda71c",
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
      "binding_sha256": "63f0aa00f5d7212a7a37c7daf69d05989ff9c82434ccf3a29023b130fb3a8755",
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
      "binding_sha256": "34d5de2c8adad77c1ba50ee07e06352414419b83841a9457de2c4558885fc5b4",
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
      "binding_sha256": "abe69e2bcebf3df5f5f9308c70e1a698411b686e20681067a79b6d0b1db23b4c",
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
      "binding_sha256": "fb3258f4ee17b3f70909974aa57e740ba94037ad76fb80a096bb82bc89a3b64a",
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
      "binding_sha256": "11e844343e07bb6681ac52fa6334f054553d139652f07b790f40c2a606f09447",
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
      "binding_sha256": "ddf1631203ba7b3f2fd48fa5f40b7c7f9015054f09b4f9cd7d500e12db4d92bf",
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
      "binding_sha256": "b42d85c9d2cb070169c947dbdba31ea12292b60012394140d218ff9cb8cf2742",
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
      "binding_sha256": "d28845d59ff692df9505c68609b76bfcf60755330f2cfc9923fb3f168a78e757",
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
      "binding_sha256": "81629f18a4c9ae70cb285f8efd3cb44cfad6ba58a5ca96f78fefbf484bb7eb5b",
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
      "binding_sha256": "8bfd37d06054401acf9e69771657b569bf3c33c6011e8a52544435a8539e255a",
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
      "binding_sha256": "2c8c23376ffc0d0dfb109e411c59343dd0dbb6b06c49136f641777d26bdf108f",
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
      "binding_sha256": "9890c49aae7946ea7d2ebf7cf709fbfcae71e780e3091d64181f3fbcf9d925a1",
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
      "binding_sha256": "fd7a9d1d70dd1ea52b2c647014e7243286709d6f3eb16af86a4b6be8b0d1b296",
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
      "binding_sha256": "344228ecabb00279fa79d06b6d3d293c8a07eaae6f1f5495c93acca809532fbf",
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
      "binding_sha256": "c0ffdc89b83feadf8a71359299367cf6325594d05f252d1492a5ce73a75c35bf",
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
      "binding_sha256": "aa1a000a562f695189a541d380c82087e35a9a26924bdbc90db3cb8c81b363c9",
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
      "binding_sha256": "5d6ac8689cd840a9b46af746b4673d0afa02c14464b31b75e34a81f258fabca7",
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
      "binding_sha256": "69a7613c8f7ec4db658dd334b3b51bcae4c11f9d8800f486ec06c19c9ec6496e",
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
      "binding_sha256": "baedbc8a4988176e2efb64bbab5c0d6b86f918ff0e3b91928f9f008af21bfc95",
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
      "binding_sha256": "0136d736d63a65a00cae2d4e7dd007876a6138f566a16f50a0c08cc00df9d747",
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
      "binding_sha256": "39ffa8d2b21a91ecc50f5b264c93f8d392b235af5699d0881cfd44469085f73d",
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
      "binding_sha256": "a5593022741d75935e8abb783cb96fef41c55dc937821d19d2b9b2b1054f9a04",
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
      "binding_sha256": "7bf63fd4ff4daf043f8e3045fae2aaee58d209c5fc3f96843d097b4953cf0c10",
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
      "binding_sha256": "2935617a2979c81edf45f72911f1514a7b100659a39bb6a80dc8709a9557ab8e",
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
      "binding_sha256": "e4af7a943c8e5622fde08403eabb74766482fa3bb216925667675d89de4a6435",
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
      "binding_sha256": "077f3f6cb64ae0649fc4b28f8394dfd1f34ba10579090586b80a5c7d08b1169d",
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
      "binding_sha256": "ee80bb3e07189a6c37821c52b3cb54182e9a28de9a676ed343d36192412b6a19",
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
      "binding_sha256": "f2db588d3d141c93ef52c18fad964af3b132a3b6d1bad903aed2c3f99ebc14bc",
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
      "binding_sha256": "cadae303850f94472e31cbf0592f89a5ef941f4f4f16a97db1272914153995ae",
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
      "binding_sha256": "e8c6d2a95cbc69535e176a951977c4439450057696d06480ded1c64b3827f99e",
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
      "binding_sha256": "4eb2b933a05a296e5c1506c80e476cce6f6110fc20feea83f9959ab8c59cad92",
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
      "binding_sha256": "255f901a37ecc9dae3b6c831a885b684781c126f2f99756cc773ad3728c1fcba",
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
      "binding_sha256": "bc78840bbd7ab3d668e05828d8c4a85fe26e99f02dff0f6cc5517db55b728b28",
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
      "binding_sha256": "2a3f3a7a4b8c12c6d75c7e4b636301082a46c477c1e35ab839e51524fb9049f0",
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
      "binding_sha256": "2f57ff039185116d1a760477f19bbeab7129f4c6ee60aa705df5da3375d5159e",
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
      "binding_sha256": "b9d12218a879ad7193bc9ee6606ddc5e33023e6741a36b35d86e96523c51793b",
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
      "binding_sha256": "e43d4a20aa51b208086eed850122c4e47b02912c77c4636383adf61dfeebe463",
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
      "binding_sha256": "9f20cc2f92caf1315515d2b0ffc3152f0d6eb885c77e78acd71720324c3721b5",
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
      "binding_sha256": "c69210fb3f5c9b74889b3167f2ed00ad7c27e50dca5de5f4ab34c0bf3b2445fe",
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
      "binding_sha256": "188f4631fa5d5247e3d8b958de93521cc31ec95f12806df469033ef378b6192a",
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
      "binding_sha256": "e2144729f689e202fc8d39f23ee5d4502b7d6af8cf8c78a812bf6057aa2327a0",
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
      "binding_sha256": "a7b7b6da762606adf538591296a8f43c619012a7ab90b4e2ebcb6a1341916e50",
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
      "binding_sha256": "c92f2f95dd9e07b28f8f833bc0d56cc7e58b824883d7f71aa1e0ef2909d8f118",
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
      "binding_sha256": "67a8dd1f5486ab22eaf39f074c3f51f358baeb74195c3a9330e387aab54e578a",
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
      "binding_sha256": "f7e48852fd9047340996d4268f8c7d52af96d8e89e5d80f49bff3e646e7e2030",
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
      "binding_sha256": "029f37df0969c24b69b0f981caebd1a4154b8dc9b89b492deab140e1faee3d45",
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
      "binding_sha256": "e61bb73df24e68d33b7973fe71ffd62a17c932163be718de1f318a678c3bee31",
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
      "binding_sha256": "8c5502c34e06ed68360825a8e2a4ee4802980d6af00c3bc56e744af66c5d41ab",
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
      "binding_sha256": "726906891119374ba7ab993d38e8de4e0f4156bcb9bd7c86aeceafaa427abfed",
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
      "binding_sha256": "eb8db9def84affd4d643fb10d3b9d378d16c6cf23bca8c8125e4c475ca1c12dc",
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
      "binding_sha256": "3fb4d90922ab50d8330cbd05d72b84046976be2eb9f85f3c23f5390dea317229",
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
      "binding_sha256": "40d65726cac886fd1448bfa3f902fe0ccadb3a985c8351661a3b405aacdb40be",
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
      "binding_sha256": "31e8c7b4ae39d0a27e503c002693ae0ac65ed911bd4e5ac8ccc7a60298e181f3",
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
      "binding_sha256": "5e97d8aa4defd4987ff114533645d3bea3a8fd554a1e7b8cbb0756e32cc7a187",
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
      "binding_sha256": "7367682f93afe4d92868d8ca36bc8d229c01de576bb7ad662539eebe08aff811",
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
      "binding_sha256": "d93d67e82d2be85019b4517aae0399105211d9b826585199c41c2a13306655cc",
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
      "binding_sha256": "4b4f3f1da5894a4f81c310d1971a5cf84cc7db1a13d535f9bd46f5c14b9669c6",
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
      "binding_sha256": "4ad86d82c22feceb45c985451fae76722d33cdcca18afa13c6653ced6adb8cb3",
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
      "binding_sha256": "e05b9605bf3a3e1166d9c916b3264f4a80fb4ac7261cd9c66f54e8091d5966c5",
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
      "binding_sha256": "81b12abdffea182190b98997468934392295d51466d46dde39341f702e6ef606",
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
      "binding_sha256": "baad4deea67fcfc66b221d7904991193ad169a39a91a2b00151ead0cce635220",
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
      "binding_sha256": "56d27528ded80a781b45f74b4286045e73e0dabb144ef8f96dc05b874e2c1b00",
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
      "binding_sha256": "733de90d4e9bfac2d2e5b7932cf235afdec4e5e42a968dc20a7b76e67b7ba359",
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
      "binding_sha256": "14f5b472078c0459d07bccfa96d54928efee1865a9e533b63972823e9a4db006",
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
      "binding_sha256": "df7f30677853a174422edc18b74f34ab2990d618974892b82fc3c896ef2dd398",
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
      "binding_sha256": "0d3dd21d830847112ecb82722d614b054cfd417707a8c666568d8fe58446ccc4",
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
      "binding_sha256": "a56478b4a7bb8807a1b4aa708bf6fc0f1eb7f1249b065bbd7f0e6b298ae57e77",
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
      "binding_sha256": "a047aab9650f572c478208cb957e3d02cd14e80e90fa96312e7a53b54ea079d3",
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
      "binding_sha256": "fe2b8380cb21e0ee17d02fe8a1a8c0bdd562abc5783b68d52fb89324d2098d64",
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
      "binding_sha256": "a90f8fc45b97763ac928bf8630dbe414fd5b37e5aa96d708eadec8d78df7ba9e",
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
      "binding_sha256": "5cb7d0b6b22f782bf275adde0b3c038fc89ee3a06dba6c1c402c028107df9ac0",
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
      "binding_sha256": "bb91511b32c864f68a00c8f40640c7da984069aaa919ed9db0ed49ba413e36df",
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
      "binding_sha256": "90289cb213913e50f9a4ef693ea122c98cb10781f96ee94359f3e49c2b3e3e9d",
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
      "binding_sha256": "6c385ebca4948d69e09e0d38da3be22fe60342759f80a68d82071352cdf7b8b3",
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
      "binding_sha256": "c4705d8dcf5536922c125fa4607c7bca118ec36cf9f0ad1aca3ceac95ebfcd3f",
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
      "binding_sha256": "682498b28691bc7b5eefcd5735d068c53d98a6a47d6811f34f6c720f62922829",
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
      "binding_sha256": "46c5656a9325d2596c8d2653279fef72fbbab2e4af137d089be1b65caa06d724",
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
      "binding_sha256": "e8db009d2bc1702c8b0b11fa226c41d75a8d86edd048c8ad797632e867ddeba4",
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
      "binding_sha256": "4f9e45f23d4ee7b9124a321fd353e39c544cd540420b8e54f292431bc53823f6",
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
      "binding_sha256": "2435f188585d8e06367771c1effa99e6b0a95b8a7722bc9a7a12ad30ad53ea1c",
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
      "binding_sha256": "576f7e441c9f74e015fbe85d5fbaf5ee3ab3830d301470ff4e8e2345ad13ea8a",
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
      "binding_sha256": "27d0cc54c774eb32a6fa766ef19f531ee058014b791bd516a36be1318e712f22",
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
      "binding_sha256": "79a55a90161d837167691717d1e0c7bde9841e1d32cd3033b559510f62eba27f",
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
      "binding_sha256": "08d788070d49383c6faa3705fbfda9cd51b54985d41917ca4fa341bda42b000a",
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
      "binding_sha256": "102edaeabb4f7813abc618e0afd3e5fd241f3fad4227d6a726c739d9458227c1",
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
      "binding_sha256": "378ca5faa148e3f9fdf8ecd3ab1cc5378af206b113ffab6edcf772a4e386b01a",
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
      "binding_sha256": "659e1a30305ab24532a1b0878eb63134f5282243e436adb1d481b8ced48d710a",
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
      "binding_sha256": "cb91807d037aa709019699c8053c3c38ac59384d1826713c90f9b2c102ba48e2",
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
      "binding_sha256": "c040466e340a1d938486d6f83897ca767740692dbae227b878449994aa8a8497",
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
      "binding_sha256": "59467670dd627469e88d40c21c67034832b983fe07faa1119a314ee344c2efba",
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
      "binding_sha256": "c51d67cf4ca9dbba8666a3ba0f834881092d10f9a4fda3f05c5b95837e22203a",
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
      "binding_sha256": "1ee9c16a6e2a19579bddac11eb68adefdbf4d2894405a8a22942de12527e2723",
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
      "binding_sha256": "5169e5ff716c01dc9357879799c91a32f23846811db97c3f13fd052f0bdf169c",
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
      "binding_sha256": "1ffed774e2b0bef15a7d2fad96865fe158341334943bcd144f9de81cf63ff1e1",
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
      "binding_sha256": "84b6b5cfe593a8ac1822c059e0a17c7ce86ffe8d804c3afa3da64cbd62eafd03",
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
      "binding_sha256": "d90b67fffcf690e74fc420df30e0060c80fa5c32361073ef2baa171ca8bee37a",
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
      "binding_sha256": "92c87c8c175c8c3b5e71ee388e5a71ec8fa4f6b0a13e6ceb0ce8a45ce899fad3",
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
      "binding_sha256": "3126f12dc15b25a763750fae56aa2c2557a45d1834ed84ccc64366f54a75761e",
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
      "binding_sha256": "befb74ac30fc2a393ac40a827e695eb7106f01bf465adbe6eac3c2b275334d0e",
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
      "binding_sha256": "469fe41f40599987e149568ddfe6b92b521a0e7d68f083f4935e42980f668ceb",
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
      "binding_sha256": "98074bcece8cb1d848f5f7e07e1d1c7f2f9c8922197efc9e4fb4438f0ceb36e6",
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
      "binding_sha256": "732049beafcc9b05bdf55b9815458c1e55c19fc529fdaa2de2ab0de22ac2164c",
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
      "binding_sha256": "50e4e52ea0ac4c44e6452c3c22c40f8a237214ec6acd133172d80d00212dc09c",
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
      "binding_sha256": "d5104d10fe71dba9c502801f51e3f2407dd112209680d30551f1e07404a304ba",
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
      "binding_sha256": "48d5cec7f5eec48150b88e0ca1ba452cb97d4c5d521fdb135f5e9ee6ddac7be4",
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
      "binding_sha256": "bc579cba33f9e8ff99f85625b6c834ab8271d655abf1012654d023245e763a9e",
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
      "binding_sha256": "f90dfcb48846b6cf0fbb44a1abbc4b43aee3e8d2e316d45c1d9a2562c1ecdf03",
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
      "binding_sha256": "43929dc1a118bcb36e39a6fef9a09608a08507c1e64156ba101d9a57ee9f7607",
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
      "binding_sha256": "4e3d88b475b06d108a1b80e1b49c28903b372217c5304a8a8bcfa12485ffc258",
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
      "binding_sha256": "7fc567d70a2b14ac8c52fd003c9567c389877b8664c0c0691dcbdd351e88932c",
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
      "binding_sha256": "3f062573b354a81a87a20781067d8bd8fe69d865e3b47966e77cd8a9ca1d4547",
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
      "binding_sha256": "bd7a8c67a28603adb917ecdf1965122a47d3f458f0c9181954a6992e9524ca24",
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
      "binding_sha256": "2c433b8242b1f5a739896d5726c28a03437f3b14e44beba26711ab5f5d464a4f",
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
      "binding_sha256": "7f62fc32848eb3822fe4e8bc2eb17f141b5b6ca6af2a7b568d4279e8e5f673af",
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
      "binding_sha256": "38591337ef1f145ffc0edc909f8b65660ab98b8482ba0720c7f08576dac8b18c",
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
      "binding_sha256": "4d2aee42452453b989fff15ce991b5eb54bd37b213f671d3916f8c95da0d0cde",
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
      "binding_sha256": "bb9f769b0f53563cbc14b7797fbc60f4a697eb618e67579c1e874b16b6108948",
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
      "binding_sha256": "3c0d730a690a262584d140c62b23ee9a6defa9ea1c710f28897ba27e4708f733",
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
      "binding_sha256": "43855acea115fe70e07d7c82d0802823f60540725ef68619e678ecfbf59d21d0",
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
      "binding_sha256": "2e98eb46d9de9d1013138ebf346e63f20697e8268255509a63c62a2756d444b1",
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
      "binding_sha256": "f5fd7700d840888d408457cdb6fb8b07b0529d8726d72f33a8643902d813211a",
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
      "binding_sha256": "69715786f8e1eaded8b4c21bb1b0df25393ecf3581c4fc738be1265a4874ec0b",
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
      "binding_sha256": "7c965b71eebd794de8cc9c79b8e113ab8cc85e3e36e4d50cb0ae0d7645ab9023",
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
      "binding_sha256": "ae14d4ce21ea5e114c89df1322f1d1b4f1896c00817854c9e313bc04ecd50682",
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
      "binding_sha256": "1284cfe648efee0fb968deb4a2e073d03bd46b32f957f377bf7d77aa1f63376f",
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
      "binding_sha256": "4fa27b9ef59877abc45b3c6b264b9ab4af38a4e3ca0d698987b3bb014fea58f8",
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
      "binding_sha256": "1670d80ba21912c92c128d51bba1bb49f79fc14b8cb87cd856ede2931f27ba73",
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
      "binding_sha256": "201c460a004386ef06d98085774648a1709d2b00bf76ddcdc42fa4e398df14b2",
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
      "binding_sha256": "c7bdb5476a946515bb8aa1327f7c0b9de9d611414dde50221c31bf8cc34ec881",
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
      "binding_sha256": "224ff477dc22525c1646acd107dd96f4d38bae2917e5e3e24916941b9ce17fc1",
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
      "binding_sha256": "6890cdba8a3b1002fed7f26ff5bfa3f071030272b50875b2cb59cefdbdb0cda7",
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
      "binding_sha256": "b166f50e706f8377dd1d927e75d8ace0fccfbc0cc907af2c884794909ff6a6fc",
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
      "binding_sha256": "5861ce4569a9c14f852865837dd695c187e4454df65627c8f2ac73c4a9804b2e",
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
      "binding_sha256": "9dfd6d301ae8f8f98861ed25ed115176b99eb32c141e9fa325d7c48c6419e7ba",
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
      "binding_sha256": "ef92a1203224390d605d83b8f621228dc13a09b3861ee1f7e464c4f02b59f90c",
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
      "binding_sha256": "773c942e893fd4ad00ec49f511cf5874bf158d458f3956ab3b221a7e1ce211b0",
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
      "binding_sha256": "5503493c884b2a14fc8197ba59c2d1c4cb8fee3862ab92ee49f077f04216d352",
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
      "binding_sha256": "3dd8e3f1218b7d170175b3d014bfe14c91ca5c3bc10bc878f5da1519b006fa88",
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
      "binding_sha256": "69db20bb802813172dfa406b677dfa85f3c6b500a5220ad6f59efb2c088d6672",
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
      "binding_sha256": "fd28b3b66b53a8eca1b7413c4c67957613bdd7689a6794f49c62116568ce69fd",
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
      "binding_sha256": "12c7f827f4d5b6cc7cdcf1ca31f94eca9ff83b655aa18c7b10a7dee802e239dc",
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
      "binding_sha256": "d498370a3d10657a1243e6781ef0482f2c03b3bafd21a2c8f1b38843742cee10",
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
      "binding_sha256": "32383bc8695a34ead50c8a5adc17d7f53ad3835b02ccd4fab8f582d3bc7928c4",
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
      "binding_sha256": "e41a9f232931875621c5dd749c63d2cf871bdebf35f990afdbed0800407202c7",
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
      "binding_sha256": "8126393edf26b9d178851fca4818069cceb88b4355461add3283c71a34b01502",
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
      "binding_sha256": "33200a8d819934d16aa7de52593d86e35e875b56b0ccc34de7a778af14c56b9d",
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
      "binding_sha256": "13baef5dc512b63ea0c6f5e4e9e1b8d5cac2034cf2e9af5da5269716a9a94ae7",
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
      "binding_sha256": "27d49115e05d5b4a50b2712b6cb2a2715e49272c6ded1655096a7472107bff0e",
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
      "binding_sha256": "6e4efe9e2f4b39abf0b5c556d189165222f0aef0460c3f11385b2738efbadf82",
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
      "binding_sha256": "34e142d619f27ba651b6259f290355461a9d1a15019f19b2c7da49f165897d0d",
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
      "binding_sha256": "c567b178afc8eb64b68c3ea112c62cf66ddcce32f6d6b973df5e553e2416d5d5",
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
      "binding_sha256": "4f218fa6f95ae9642306815be3e5712ca9f76f345b86c5b48553c11bea644946",
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
    "catalog_sha256": "1ce59f52efcdab26074adc7164eb269aeb7235012835ad40fc64a94cfae03d7d",
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
      "max_total_bytes": 300000000
    },
    "evidence_sha256": "f8cd6e23cc8128bbad0f643d213813c600e391b33648526b9e77d54c16857efb",
    "image_limits": {},
    "manifest_sha256": "7d1243fcfd19995ece7712f0bf69223e3cc8c66ffefa36cadf52b8787bfd469d",
    "scan_id": "5216f6ea18dd4bc4e82fefc2ca03fbb5315fcd445f2db00428ff6a87bf834961",
    "scope_sha256": "1ac0e3943777ebb10c33d20ef4246e6527b1a0664e1b3cffac249558e9730f36",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "8d56fcf24bb47474196842268b3512ce8df00a81a3371f7fce63757fa1a8f309",
      "name": "agent-mcp-security-scan",
      "version": "0.13.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

