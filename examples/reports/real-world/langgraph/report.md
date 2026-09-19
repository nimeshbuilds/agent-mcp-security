# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `83a872fbef16c92d1ee559ef3d63dbeb5ff109d49c0ded9a67302a206718179c`

This is static security triage, not certification or proof that a system is secure.

## Executive assessment

### Incomplete scan \- close the coverage gaps

The selected static scope was not fully inspected\. There are 23 open findings, including 23 critical/high findings\. Resolve reported gaps and review existing evidence before relying on this result\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 23 | 23 | 13 | 0 | 1 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

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
