# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `1432f74546db9475daca2ca6fdda9c324d0c430fbedadb14346be564c00a4d63`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Open findings need investigation

The scanner found 61 open patterns, with no open critical/high detections\. Review applicability, address the causes, and validate the proposed defenses\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 61 | 0 | 14 | 0 | 0 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 61/61 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Supply chain: 59; Network exposure: 2. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 0; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P2 | [AI007: Wildcard cross\-origin access](#group-817457e7c4ab) (source) | 2 | Identify intended browser clients, restrict allowed origins, and verify MCP Origin checks on each reachable HTTP endpoint\. | MCP/API service owner |
| P3 | [AI024: Container image is not digest pinned](#group-0cc3d39352a0) (source) | 14 | Identify the approved image digest and enforce it in the effective build or deployment while preserving a reviewed update process\. | Container/release owner |
| P3 | [AI025: Direct dependency is not exactly pinned](#group-35a2b5731941) (source) | 45 | Check the effective install command and lockfile; enforce a verified resolution and document intentionally flexible development declarations\. | Dependency/build owner |

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

<a id="group-817457e7c4ab"></a>

### AI007: Wildcard cross\-origin access

**MEDIUM** · open · 2 occurrences · source

**Observed evidence:** [src/everything/transports/sse\.ts:12](#finding-aee5e0176e37e7f4), [src/everything/transports/streamableHttp\.ts:45](#finding-00588940eac896d4)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If a browser can reach this service, permissive origin handling may allow an unintended site to interact with or read responses; actual impact depends on authentication and browser behavior\.

**Address the cause:** Identify intended browser clients, restrict allowed origins, and verify MCP Origin checks on each reachable HTTP endpoint\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Validate browser origin at the MCP listener | Reject disallowed Origin values at the HTTP MCP endpoint and keep the allowed list limited to intended browser clients\. | Send requests with permitted and unapproved origins through each ingress path, including the direct backend path\. | Origin checks and CORS behavior do not authenticate non\-browser clients; missing\-Origin handling needs its own policy\. |
| Authenticate and authorize protected requests | Authenticate each protected request and enforce tool, tenant, and target permissions at the service handling the operation\. | Test missing, expired, wrong\-audience, and revoked credentials, plus a valid caller requesting a forbidden target\. | Authentication identifies a caller; it does not make their supplied data safe or grant every authenticated caller equal authority\. |

Related controls: MCP\-01

Guidance sources (engineering synthesis): [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP\-AUTH\-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP\-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="group-0cc3d39352a0"></a>

### AI024: Container image is not digest pinned

**LOW** · open · 14 occurrences · source

**Observed evidence:** [src/everything/Dockerfile:1](#finding-fbae64d60617614a), [src/everything/Dockerfile:9](#finding-6abf57af3c15e017), [src/fetch/Dockerfile:2](#finding-3928ea427baf4ce4), [src/fetch/Dockerfile:23](#finding-81a28be6289ed9ab), [src/filesystem/Dockerfile:1](#finding-d98ef3fa4ab36d84), [src/filesystem/Dockerfile:11](#finding-bde90920fb171ace), [src/git/Dockerfile:2](#finding-53cc6a1e83cfe5d7), [src/git/Dockerfile:23](#finding-7a340c02be7ff06a), [src/memory/Dockerfile:1](#finding-f3ad75ff0384001a), [src/memory/Dockerfile:11](#finding-a4cc6415279bab1e), [src/sequentialthinking/Dockerfile:1](#finding-4e1087130a652c9d), [src/sequentialthinking/Dockerfile:11](#finding-e5f2993ec01d89b0), [src/time/Dockerfile:2](#finding-be52a2c54197a70e), [src/time/Dockerfile:23](#finding-3dc649c420efca0f)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If a mutable image tag changes, a rebuild or deployment may consume unreviewed bytes; the scan does not establish that the current image is vulnerable\.

**Address the cause:** Identify the approved image digest and enforce it in the effective build or deployment while preserving a reviewed update process\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Verify artifact identity before use | Require reviewed artifact provenance plus a digest or signature checked against an independently trusted identity or manifest\. | Substitute bytes, producer identity, or verification metadata in a controlled test and confirm the consumer rejects the artifact\. | Authenticity establishes the producer and bytes; an approved producer can still ship vulnerable or malicious content\. |
| Keep pinned artifacts maintained | Review known\-vulnerability and maintenance evidence for the actual resolved artifacts and apply updates through a repeatable release process\. | Demonstrate a dependency update, relevant regression checks, and deployment or rollback of the resulting approved artifact\. | This source/image scan does not provide a current CVE verdict, and a vulnerability database cannot identify every unknown flaw\. |

Related controls: SUP\-01, SUP\-03

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [NSA\-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/); [OPENSSF\-MODEL\-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/); [OPENSSF\-SCORECARD](https://securityscorecards.dev/); [SLSA\-12](https://slsa.dev/spec/v1.2/)

<a id="group-35a2b5731941"></a>

### AI025: Direct dependency is not exactly pinned

**LOW** · open · 45 occurrences · source

**Observed evidence:** [package\.json:22](#finding-751141a58e4e31dd), [package\.json:23](#finding-2868f68b63152d11), [package\.json:24](#finding-e9573402441f736d), [package\.json:25](#finding-5597f1a3cf1142da), [src/everything/package\.json:33](#finding-b3c00222e1c0129e), [src/everything/package\.json:34](#finding-3b7a9ae22717a505), [src/everything/package\.json:35](#finding-ff04753a5acf31f8), [src/everything/package\.json:36](#finding-845f7ea09f443fe4), [src/everything/package\.json:37](#finding-bcfd8d65dfe12337), [src/everything/package\.json:40](#finding-b3cc2f6fe13598c9), [src/everything/package\.json:41](#finding-0a0805bd2124e102), [src/everything/package\.json:42](#finding-2b06a31c453863a2), [src/everything/package\.json:43](#finding-4006631be70e79ec), [src/everything/package\.json:44](#finding-40d4355e9b0c7c6e), [src/everything/package\.json:45](#finding-0a4017b36cf72179), [src/everything/package\.json:46](#finding-b9cd31a241a027db), [src/filesystem/package\.json:28](#finding-cbbd35b2e8e0798e), [src/filesystem/package\.json:29](#finding-fe5893faed33bb1a), [src/filesystem/package\.json:30](#finding-0ff9de605914adb7), [src/filesystem/package\.json:31](#finding-2040a59b8c53a0ec), [src/filesystem/package\.json:32](#finding-61f5dab35b9e5abc), [src/filesystem/package\.json:35](#finding-9fb9472b76c60a67), [src/filesystem/package\.json:36](#finding-dc098e372271a0ca), [src/filesystem/package\.json:37](#finding-7b78e7b9808a3c23), [src/filesystem/package\.json:38](#finding-e54fa441bc81b97e), [src/filesystem/package\.json:39](#finding-9b001603a74e3902), [src/filesystem/package\.json:40](#finding-d7118b8630a54523), [src/filesystem/package\.json:41](#finding-324ddaca8a8eb16c), [src/memory/package\.json:28](#finding-b92ddc4a6ddd4243), [src/memory/package\.json:29](#finding-ba418e84b39dc005), [src/memory/package\.json:32](#finding-05e296ec27d85c29), [src/memory/package\.json:33](#finding-bbeb1345128a77ec), [src/memory/package\.json:34](#finding-252caa79dec45acf), [src/memory/package\.json:35](#finding-5fa3dfb3903ae709), [src/memory/package\.json:36](#finding-09592c8e91968321), [src/sequentialthinking/package\.json:28](#finding-6dcfaaabcb5551bf), [src/sequentialthinking/package\.json:29](#finding-c2ac55d4aeacafc1), [src/sequentialthinking/package\.json:30](#finding-700b364d14a6fd50), [src/sequentialthinking/package\.json:31](#finding-5e57db80c6f18912), [src/sequentialthinking/package\.json:34](#finding-12d9243266ef6b30), [src/sequentialthinking/package\.json:35](#finding-8de81ebb7907d49b), [src/sequentialthinking/package\.json:36](#finding-4e40cd8fed1a2b41), [src/sequentialthinking/package\.json:37](#finding-3aa1a1bf9e7168ed), [src/sequentialthinking/package\.json:38](#finding-222a8cb1858870a2), [src/sequentialthinking/package\.json:39](#finding-e699ae12ecee137a)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If the actual install is not constrained by an enforced lockfile or hash, dependency versions may change without a corresponding reviewed source change\.

**Address the cause:** Check the effective install command and lockfile; enforce a verified resolution and document intentionally flexible development declarations\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Resolve and install reviewed dependency bytes | Use a committed lock or approved artifact manifest, enforce it during installation, and retain the resolved dependency inventory\. | Build in a clean environment and compare resolved bytes; modify a lock or artifact and verify the release gate rejects it\. | An exact version or digest can still identify a vulnerable artifact; mutable transitive dependencies must also be constrained\. |
| Keep pinned artifacts maintained | Review known\-vulnerability and maintenance evidence for the actual resolved artifacts and apply updates through a repeatable release process\. | Demonstrate a dependency update, relevant regression checks, and deployment or rollback of the resulting approved artifact\. | This source/image scan does not provide a current CVE verdict, and a vulnerability database cannot identify every unknown flaw\. |

Related controls: SUP\-01

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OPENSSF\-BASELINE\-202608](https://baseline.openssf.org/versions/2026-08-28); [OPENSSF\-SCORECARD](https://securityscorecards.dev/)

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

Scanned **86 files**; **61 open findings**, **0 suppressed findings**, and **0 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 0 | 2 | 59 | 0 |

Source I/O: **1003862 bytes read**, **1003862 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 10 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| generic\_text | 4 | Generic secret, URL and applicable text signals only; language\-specific execution and dataflow are not analyzed\. |
| javascript\_lexical | 51 | Bounded JavaScript/TypeScript tokens, calls and configuration signals; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 12 | Parsed JSON/JSONC fields and selected configuration rules; runtime values and referenced files are not resolved\. |
| python\_ast | 9 | Python syntax, bounded local aliases/value tracking and selected security sinks; no whole\-program or interprocedural proof\. |

Severity failure threshold: **high** · Process exit code: **0**.

A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

<a id="finding-aee5e0176e37e7f4"></a>

### AI007 — Wildcard cross\-origin access

**MEDIUM** · Confidence: high · Status: open

Location: src/everything/transports/sse\.ts:12–12 · Finding ID: `1dfd877e293f6304ea57ccd1`

Cross\-origin access explicitly permits every origin\. For credential\-bearing or local MCP services this can expose a browser\-accessible trust boundary; reachability and framework behavior require review\.

```text
    origin: "*", // use "*" with caution in production
```

**Remediation:** Allow only required origins, validate Origin on HTTP MCP endpoints, and combine origin checks with authentication\. Do not combine wildcard origins with credentials\.

#### Fix plan and agent/MCP relevance

Replace wildcard browser origins and enforce MCP Origin checks at the server\.

**Why this matters for agents/MCP:** A browser can reach some local or remote MCP HTTP services\. A broad cross\-origin policy may expose tool responses or weaken the browser\-facing boundary around operations running with the user credentials\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- CORS primarily controls browser response access; it is not authentication and does not prevent every state\-changing request\.
- Check the effective framework behavior, credentials mode and transport\. A public credential\-free resource may intentionally allow broad reads\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Specify exact allowed origins | Replace wildcard or reflected\-origin rules with an explicit scheme/host/port allowlist for the legitimate UI\. Avoid broad subdomain matches and do not combine wildcard origins with credentialed access\. | Send trusted and untrusted Origin headers and inspect both preflight and actual responses; verify a disallowed origin does not receive credentialed response access\. |
| 2\. Validate MCP transport origins | For an HTTP MCP endpoint, validate an Origin header when present and reject invalid origins before processing tool requests\. Treat absent Origin according to client/transport requirements rather than assuming it authenticates the caller\. | Send a direct POST with an untrusted Origin and verify denial before a harmless tool side effect; separately test supported nonbrowser clients\. |
| 3\. Enforce independent access control | Require the appropriate authentication and per\-tool/resource authorization and constrain local listeners or ingress\. Do not rely on CORS to protect anonymous mutations\. | Attempt the same unauthorized operation through a nonbrowser HTTP client with no Origin; confirm authentication and authorization still deny it\. |

**Remaining validation:**

- Allowed origins can be compromised; tenant isolation, CSRF protections where applicable and tool authorization remain separate checks\.

Related controls: MCP\-01

Fix guidance sources: [MCP\-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-942

- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-00588940eac896d4"></a>

### AI007 — Wildcard cross\-origin access

**MEDIUM** · Confidence: high · Status: open

Location: src/everything/transports/streamableHttp\.ts:45–45 · Finding ID: `17d0b8fb13e9a07921683c62`

Cross\-origin access explicitly permits every origin\. For credential\-bearing or local MCP services this can expose a browser\-accessible trust boundary; reachability and framework behavior require review\.

```text
    origin: "*", // use "*" with caution in production
```

**Remediation:** Allow only required origins, validate Origin on HTTP MCP endpoints, and combine origin checks with authentication\. Do not combine wildcard origins with credentials\.

#### Fix plan and agent/MCP relevance

Replace wildcard browser origins and enforce MCP Origin checks at the server\.

**Why this matters for agents/MCP:** A browser can reach some local or remote MCP HTTP services\. A broad cross\-origin policy may expose tool responses or weaken the browser\-facing boundary around operations running with the user credentials\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- CORS primarily controls browser response access; it is not authentication and does not prevent every state\-changing request\.
- Check the effective framework behavior, credentials mode and transport\. A public credential\-free resource may intentionally allow broad reads\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Specify exact allowed origins | Replace wildcard or reflected\-origin rules with an explicit scheme/host/port allowlist for the legitimate UI\. Avoid broad subdomain matches and do not combine wildcard origins with credentialed access\. | Send trusted and untrusted Origin headers and inspect both preflight and actual responses; verify a disallowed origin does not receive credentialed response access\. |
| 2\. Validate MCP transport origins | For an HTTP MCP endpoint, validate an Origin header when present and reject invalid origins before processing tool requests\. Treat absent Origin according to client/transport requirements rather than assuming it authenticates the caller\. | Send a direct POST with an untrusted Origin and verify denial before a harmless tool side effect; separately test supported nonbrowser clients\. |
| 3\. Enforce independent access control | Require the appropriate authentication and per\-tool/resource authorization and constrain local listeners or ingress\. Do not rely on CORS to protect anonymous mutations\. | Attempt the same unauthorized operation through a nonbrowser HTTP client with no Origin; confirm authentication and authorization still deny it\. |

**Remaining validation:**

- Allowed origins can be compromised; tenant isolation, CSRF protections where applicable and tool authorization remain separate checks\.

Related controls: MCP\-01

Fix guidance sources: [MCP\-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-942

- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-751141a58e4e31dd"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: package\.json:22–22 · Finding ID: `1b7d19a705e34835beb1b70b`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/server\-everything\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/server-everything": "*",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-2868f68b63152d11"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: package\.json:23–23 · Finding ID: `df2d619cd8cf7123d9926255`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/server\-memory\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/server-memory": "*",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-e9573402441f736d"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: package\.json:24–24 · Finding ID: `5412b16ecee0c9e95b14403f`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/server\-filesystem\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/server-filesystem": "*",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-5597f1a3cf1142da"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: package\.json:25–25 · Finding ID: `51bd6ebea666f10e3091cf79`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/server\-sequential\-thinking\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/server-sequential-thinking": "*"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-fbae64d60617614a"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/Dockerfile:1–1 · Finding ID: `568034dfa4bd4e782cfb45a9`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM node:22.12-alpine AS builder
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-6abf57af3c15e017"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/Dockerfile:9–10 · Finding ID: `5ebf8aa9117cad31c49e539e`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text

FROM node:22-alpine AS release
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-b3c00222e1c0129e"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:33–33 · Finding ID: `80e495d5906784ccec828089`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/sdk\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/sdk": "^1.30.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-3b7a9ae22717a505"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:34–34 · Finding ID: `b0b0af6784c0810cceccd901`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: cors\. A lockfile may pin its resolved version\.

```text
    "cors": "^2.8.5",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-ff04753a5acf31f8"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:35–35 · Finding ID: `51c7448bed77678f553657e1`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: express\. A lockfile may pin its resolved version\.

```text
    "express": "^5.2.1",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-845f7ea09f443fe4"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:36–36 · Finding ID: `7c35d7d9235aca32b02975a2`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: jszip\. A lockfile may pin its resolved version\.

```text
    "jszip": "^3.10.1",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-bcfd8d65dfe12337"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:37–37 · Finding ID: `495aba3ebb1266c8222904d6`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: zod\. A lockfile may pin its resolved version\.

```text
    "zod": "^4.0.0"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-b3cc2f6fe13598c9"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:40–40 · Finding ID: `a68c71cb0d21f8f0b81b0a0f`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/cors\. A lockfile may pin its resolved version\.

```text
    "@types/cors": "^2.8.19",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-0a0805bd2124e102"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:41–41 · Finding ID: `5fb6c130e93c99353a2975cd`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/express\. A lockfile may pin its resolved version\.

```text
    "@types/express": "^5.0.6",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-2b06a31c453863a2"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:42–42 · Finding ID: `43ba5f64a38737b21965fa99`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @vitest/coverage\-v8\. A lockfile may pin its resolved version\.

```text
    "@vitest/coverage-v8": "^4.1.8",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-4006631be70e79ec"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:43–43 · Finding ID: `79693ad1bd194fbcae2abe28`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: prettier\. A lockfile may pin its resolved version\.

```text
    "prettier": "^2.8.8",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-40d4355e9b0c7c6e"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:44–44 · Finding ID: `206cae20be3b2ca993ce64d5`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: shx\. A lockfile may pin its resolved version\.

```text
    "shx": "^0.4.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-0a4017b36cf72179"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:45–45 · Finding ID: `b396687b0d535c6c40bc29dd`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: typescript\. A lockfile may pin its resolved version\.

```text
    "typescript": "^5.6.2",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-b9cd31a241a027db"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/everything/package\.json:46–46 · Finding ID: `1c601effbd99af125045ce7a`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: vitest\. A lockfile may pin its resolved version\.

```text
    "vitest": "^4.1.8"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-3928ea427baf4ce4"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/fetch/Dockerfile:2–2 · Finding ID: `a144ed0f0cb0957fc8e13e62`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS uv
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-81a28be6289ed9ab"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/fetch/Dockerfile:23–24 · Finding ID: `972173cdcc98cb74e0d0eabd`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text

FROM python:3.12-slim-bookworm
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-d98ef3fa4ab36d84"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/Dockerfile:1–1 · Finding ID: `88497812f52f68362ad113dc`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM node:22.12-alpine AS builder
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-bde90920fb171ace"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/Dockerfile:11–13 · Finding ID: `e813c32cc917461467c87e6f`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text


FROM node:22-alpine AS release
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-cbbd35b2e8e0798e"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:28–28 · Finding ID: `3388f58baa8bb1aacf7639dd`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/sdk\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/sdk": "^1.30.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-fe5893faed33bb1a"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:29–29 · Finding ID: `e22b5ee57881446e725436a2`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: diff\. A lockfile may pin its resolved version\.

```text
    "diff": "^8.0.3",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-0ff9de605914adb7"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:30–30 · Finding ID: `0065a8cd9b4f647455f13543`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: glob\. A lockfile may pin its resolved version\.

```text
    "glob": "^13.0.6",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-2040a59b8c53a0ec"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:31–31 · Finding ID: `5c191e703dec08cedc106757`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: minimatch\. A lockfile may pin its resolved version\.

```text
    "minimatch": "^10.0.1",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-61f5dab35b9e5abc"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:32–32 · Finding ID: `e36175bfef75a258ba8cbfe4`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: zod\. A lockfile may pin its resolved version\.

```text
    "zod": "^4.0.0"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-9fb9472b76c60a67"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:35–35 · Finding ID: `60d1554dc2d3c2a449ddc2fb`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/diff\. A lockfile may pin its resolved version\.

```text
    "@types/diff": "^5.0.9",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-dc098e372271a0ca"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:36–36 · Finding ID: `2d3a35438bdde5b6f4106074`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/minimatch\. A lockfile may pin its resolved version\.

```text
    "@types/minimatch": "^5.1.2",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-7b78e7b9808a3c23"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:37–37 · Finding ID: `e1775c49a1a0db20f2b22f7d`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/node\. A lockfile may pin its resolved version\.

```text
    "@types/node": "^22",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-e54fa441bc81b97e"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:38–38 · Finding ID: `c115b0aae0d8e200a012bf26`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @vitest/coverage\-v8\. A lockfile may pin its resolved version\.

```text
    "@vitest/coverage-v8": "^4.1.8",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-9b001603a74e3902"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:39–39 · Finding ID: `444b210313144756cc0a122c`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: shx\. A lockfile may pin its resolved version\.

```text
    "shx": "^0.4.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-d7118b8630a54523"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:40–40 · Finding ID: `f32f795eeef054562dda5996`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: typescript\. A lockfile may pin its resolved version\.

```text
    "typescript": "^5.8.2",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-324ddaca8a8eb16c"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/filesystem/package\.json:41–41 · Finding ID: `9af6297524eb8cf283c4aef2`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: vitest\. A lockfile may pin its resolved version\.

```text
    "vitest": "^4.1.8"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-53cc6a1e83cfe5d7"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/git/Dockerfile:2–2 · Finding ID: `1f96b910676f792ffbfd2f3a`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS uv
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-7a340c02be7ff06a"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/git/Dockerfile:23–24 · Finding ID: `a883e95131d46202282862de`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text

FROM python:3.12-slim-bookworm
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-f3ad75ff0384001a"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/Dockerfile:1–1 · Finding ID: `2bcaf1deb38935aabec7d085`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM node:22.12-alpine AS builder
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-a4cc6415279bab1e"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/Dockerfile:11–12 · Finding ID: `2dde4cc86e243dc95eae315c`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text

FROM node:22-alpine AS release
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-b92ddc4a6ddd4243"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:28–28 · Finding ID: `6814a42323c6b6b11c88eb80`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/sdk\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/sdk": "^1.30.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-ba418e84b39dc005"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:29–29 · Finding ID: `6bbd76e0849a12cd13f3ade2`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: zod\. A lockfile may pin its resolved version\.

```text
    "zod": "^4.0.0"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-05e296ec27d85c29"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:32–32 · Finding ID: `9d9308d6851e44c36eaa62a6`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/node\. A lockfile may pin its resolved version\.

```text
    "@types/node": "^22",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-bbeb1345128a77ec"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:33–33 · Finding ID: `95baf2ef9a1e1bf1b853a6c2`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @vitest/coverage\-v8\. A lockfile may pin its resolved version\.

```text
    "@vitest/coverage-v8": "^4.1.8",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-252caa79dec45acf"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:34–34 · Finding ID: `c848a4339842b02444596e00`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: shx\. A lockfile may pin its resolved version\.

```text
    "shx": "^0.4.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-5fa3dfb3903ae709"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:35–35 · Finding ID: `95a67136405ede793c1f8fc4`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: typescript\. A lockfile may pin its resolved version\.

```text
    "typescript": "^5.6.2",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-09592c8e91968321"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/memory/package\.json:36–36 · Finding ID: `26404436b05c98d521bcf7f4`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: vitest\. A lockfile may pin its resolved version\.

```text
    "vitest": "^4.1.8"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-4e1087130a652c9d"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/Dockerfile:1–1 · Finding ID: `7a477495caa8301889e292d2`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM node:22.12-alpine AS builder
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-e5f2993ec01d89b0"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/Dockerfile:11–12 · Finding ID: `8305fb9cc560266dd8c4a2e9`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text

FROM node:22-alpine AS release
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-6dcfaaabcb5551bf"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:28–28 · Finding ID: `34d0cfa1757dfd255008ada6`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/sdk\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/sdk": "^1.30.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-c2ac55d4aeacafc1"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:29–29 · Finding ID: `45718a5482c11281d1c43253`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: chalk\. A lockfile may pin its resolved version\.

```text
    "chalk": "^5.3.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-700b364d14a6fd50"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:30–30 · Finding ID: `526a41abfaea3399aa2fdae8`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: yargs\. A lockfile may pin its resolved version\.

```text
    "yargs": "^17.7.2",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-5e57db80c6f18912"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:31–31 · Finding ID: `3357cbea8a47bb58934795ac`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: zod\. A lockfile may pin its resolved version\.

```text
    "zod": "^4.0.0"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-12d9243266ef6b30"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:34–34 · Finding ID: `7d13fe3d8103aa4742658311`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/node\. A lockfile may pin its resolved version\.

```text
    "@types/node": "^22",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-8de81ebb7907d49b"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:35–35 · Finding ID: `a2045fe8cc24486d2708c7e4`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/yargs\. A lockfile may pin its resolved version\.

```text
    "@types/yargs": "^17.0.32",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-4e40cd8fed1a2b41"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:36–36 · Finding ID: `8924a7ff2090b763f795030f`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @vitest/coverage\-v8\. A lockfile may pin its resolved version\.

```text
    "@vitest/coverage-v8": "^4.1.8",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-3aa1a1bf9e7168ed"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:37–37 · Finding ID: `ba5980af7001c9ed0c3019fc`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: shx\. A lockfile may pin its resolved version\.

```text
    "shx": "^0.4.0",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-222a8cb1858870a2"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:38–38 · Finding ID: `c40027fb334dbae147d1983d`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: typescript\. A lockfile may pin its resolved version\.

```text
    "typescript": "^5.3.3",
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-e699ae12ecee137a"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: src/sequentialthinking/package\.json:39–39 · Finding ID: `054ddfbf95d4af75f63eb7b5`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: vitest\. A lockfile may pin its resolved version\.

```text
    "vitest": "^4.1.8"
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

#### Fix plan and agent/MCP relevance

Make the effective dependency installation reproducible and reviewed\.

**Why this matters for agents/MCP:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary\. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A version range in a package manifest may be intentionally constrained by a committed lockfile used in the actual build\.
- Exact direct pins alone do not freeze transitive dependencies, build tooling or package artifacts\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Identify the real resolver input | Inspect the installation command, supported lockfile and package indexes\. Use the ecosystem frozen/locked installation mode; for Python pip, exact requirements with verified hashes can constrain the complete set\. | Install from an empty controlled cache using the production build command and verify it does not rewrite the lockfile or resolve unexpected versions\. |
| 2\. Verify artifact integrity and origin | Record integrity information for transitive packages as supported by the toolchain and restrict package sources\. Review build hooks and package\-name confusion risks\. | Change an expected artifact/hash in a test mirror and verify installation fails before package code is used\. |
| 3\. Review updates and known vulnerabilities | Automate proposed dependency updates and run separate dependency\-vulnerability and agent/MCP integration tests against the resulting lock\. | Verify an update changes only the reviewed dependency set and retain results for the exact installed versions\. |

**Remaining validation:**

- A locked malicious package remains malicious, and a reproducible install is not evidence of absence of known vulnerabilities\.

Related controls: SUP\-01

Fix guidance sources: [REM\-PIP\-INTEGRITY](https://pip.pypa.io/en/stable/topics/secure-installs/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-1104

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-be52a2c54197a70e"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/time/Dockerfile:2–2 · Finding ID: `58bd25b805f69d45cb9e307a`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS uv
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-3dc649c420efca0f"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: src/time/Dockerfile:23–24 · Finding ID: `e320d41acc7f1d0aa016ee89`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text

FROM python:3.12-slim-bookworm
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

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

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use short\-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation\.
- [ ] Avoid tokens in query strings, model context, source, child\-process arguments, and diagnostic output\.

Partial static rules: AI010, AI011, AI030, AI034
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

Category: MCP protocol and tools · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces\.
- [ ] Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment\.

Partial static rules: AI006, AI007, AI008, AI029

Open finding IDs: 1dfd877e293f6304ea57ccd1, 17d0b8fb13e9a07921683c62
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

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search\-language construction\.
- [ ] Separate read/write database identities and test whether generated queries can escape permitted objects or operations\.

Partial static rules: AI036
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

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers\.
- [ ] Use data\-only formats with byte, nesting, and type limits; test malformed input and expansion attacks\.

Partial static rules: AI004, AI005, AI035
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### EXEC\-07: Render model and tool output safely

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use context\-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media\.
- [ ] Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports\.

Partial static rules: AI039, AI040
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### DATA\-01: Detect and remove embedded credentials

Category: Data and privacy · Status: no\_pattern\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret\-like values\.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts\.

Partial static rules: AI010, AI011, AI030, AI034
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

Category: Supply chain · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins\.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries\.

Partial static rules: AI018, AI024, AI025

Open finding IDs: 1b7d19a705e34835beb1b70b, df2d619cd8cf7123d9926255, 5412b16ecee0c9e95b14403f, 51bd6ebea666f10e3091cf79, 568034dfa4bd4e782cfb45a9, 5ebf8aa9117cad31c49e539e, 80e495d5906784ccec828089, b0b0af6784c0810cceccd901, 51c7448bed77678f553657e1, 7c35d7d9235aca32b02975a2, 495aba3ebb1266c8222904d6, a68c71cb0d21f8f0b81b0a0f, 5fb6c130e93c99353a2975cd, 43ba5f64a38737b21965fa99, 79693ad1bd194fbcae2abe28, 206cae20be3b2ca993ce64d5, b396687b0d535c6c40bc29dd, 1c601effbd99af125045ce7a, a144ed0f0cb0957fc8e13e62, 972173cdcc98cb74e0d0eabd, 88497812f52f68362ad113dc, e813c32cc917461467c87e6f, 3388f58baa8bb1aacf7639dd, e22b5ee57881446e725436a2, 0065a8cd9b4f647455f13543, 5c191e703dec08cedc106757, e36175bfef75a258ba8cbfe4, 60d1554dc2d3c2a449ddc2fb, 2d3a35438bdde5b6f4106074, e1775c49a1a0db20f2b22f7d, c115b0aae0d8e200a012bf26, 444b210313144756cc0a122c, f32f795eeef054562dda5996, 9af6297524eb8cf283c4aef2, 1f96b910676f792ffbfd2f3a, a883e95131d46202282862de, 2bcaf1deb38935aabec7d085, 2dde4cc86e243dc95eae315c, 6814a42323c6b6b11c88eb80, 6bbd76e0849a12cd13f3ade2, 9d9308d6851e44c36eaa62a6, 95baf2ef9a1e1bf1b853a6c2, c848a4339842b02444596e00, 95a67136405ede793c1f8fc4, 26404436b05c98d521bcf7f4, 7a477495caa8301889e292d2, 8305fb9cc560266dd8c4a2e9, 34d0cfa1757dfd255008ada6, 45718a5482c11281d1c43253, 526a41abfaea3399aa2fdae8, 3357cbea8a47bb58934795ac, 7d13fe3d8103aa4742658311, a2045fe8cc24486d2708c7e4, 8924a7ff2090b763f795030f, ba5980af7001c9ed0c3019fc, c40027fb334dbae147d1983d, 054ddfbf95d4af75f63eb7b5, 58bd25b805f69d45cb9e307a, e320d41acc7f1d0aa016ee89
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-02: Check vulnerability and maintenance exposure

Category: Supply chain · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version\.
- [ ] Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### SUP\-03: Verify artifact identity and provenance

Category: Supply chain · Status: findings\_detected · Validation: manual

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts\.
- [ ] Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe\.

Partial static rules: AI019, AI024, AI035

Open finding IDs: 568034dfa4bd4e782cfb45a9, 5ebf8aa9117cad31c49e539e, a144ed0f0cb0957fc8e13e62, 972173cdcc98cb74e0d0eabd, 88497812f52f68362ad113dc, e813c32cc917461467c87e6f, 1f96b910676f792ffbfd2f3a, a883e95131d46202282862de, 2bcaf1deb38935aabec7d085, 2dde4cc86e243dc95eae315c, 7a477495caa8301889e292d2, 8305fb9cc560266dd8c4a2e9, 58bd25b805f69d45cb9e307a, e320d41acc7f1d0aa016ee89
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

Dependency manifests: 12; agent/MCP signal files: 52.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

None.

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
      "binding_sha256": "b85ca78782d04f6cf8d104176e285b5ba5e2d729a96b42a925ae2684b48c05a5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1dfd877e293f6304ea57ccd1",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI007 Wildcard cross-origin access \u2014 src/everything/transports/sse.ts:12"
    },
    {
      "binding_sha256": "d78d031d9b4dfa8d7c23cd513858e65ef62348f5b9fa7ac67c5805dd1fbd58af",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:17d0b8fb13e9a07921683c62",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI007 Wildcard cross-origin access \u2014 src/everything/transports/streamableHttp.ts:45"
    },
    {
      "binding_sha256": "8174c71d4437e7b39d3032d4ae31a6a2a3cae653128bc2d9e761e115c53b9032",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1b7d19a705e34835beb1b70b",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 package.json:22"
    },
    {
      "binding_sha256": "5ceb61808c4a4a712914b212d512182c893e9a7682cc6b46b22d7d03a2b42276",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:df2d619cd8cf7123d9926255",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 package.json:23"
    },
    {
      "binding_sha256": "18f11b9092f795a6773ff33276fda4050f634feb6a774faad9d53c129d1affd1",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:5412b16ecee0c9e95b14403f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 package.json:24"
    },
    {
      "binding_sha256": "9ddd398def6eef0f04d1b42d3c29f83d636995c4fae978799f0bb4eba9c00f76",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:51bd6ebea666f10e3091cf79",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 package.json:25"
    },
    {
      "binding_sha256": "58dd11cfb860a55247621f37eeab15c4718df9e4521c42c6233f5a77ab800804",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:568034dfa4bd4e782cfb45a9",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/everything/Dockerfile:1"
    },
    {
      "binding_sha256": "b49918416f998739e6e0a959398979937ef584b4f004b3da0d20c9834c29f044",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:5ebf8aa9117cad31c49e539e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/everything/Dockerfile:9"
    },
    {
      "binding_sha256": "ec48c3667bb16292cef5c413ef43b427e9ea6447ff9044dc1713f961282288d3",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:80e495d5906784ccec828089",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:33"
    },
    {
      "binding_sha256": "c7232bbd91aa298516b886e1676e6515709c5b4356ba546d63d52367df6fc0af",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:b0b0af6784c0810cceccd901",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:34"
    },
    {
      "binding_sha256": "dc40f625166147896e4f599f9a3de106a7d030f41ba03ab5738be99efe545194",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:51c7448bed77678f553657e1",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:35"
    },
    {
      "binding_sha256": "fe1f8b89d8bc97e3ee3b993f91344ace305a56013b4c3a7ea231d7bf698a0ec4",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:7c35d7d9235aca32b02975a2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:36"
    },
    {
      "binding_sha256": "57deff8c2ea4037412a85e7f584d879109f851914540dc43029fdcfd74a8f09d",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:495aba3ebb1266c8222904d6",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:37"
    },
    {
      "binding_sha256": "c0a6b5c6cc1dec79f0b9fbde3ad8966053291393d1c1e41424b599fff3ce2842",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:a68c71cb0d21f8f0b81b0a0f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:40"
    },
    {
      "binding_sha256": "1c4248c334bb832e3ecda1766d4b96166f515f8ac00ca537aceae033089ac4e3",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:5fb6c130e93c99353a2975cd",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:41"
    },
    {
      "binding_sha256": "964b01970658dc7fe6729b984f4743ea770669c4d60ce0f9c8699e085c7ab883",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:43ba5f64a38737b21965fa99",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:42"
    },
    {
      "binding_sha256": "236b3ded0524c73b0ef599ef73588778591619a110aed047d4711c25bfe25ce1",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:79693ad1bd194fbcae2abe28",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:43"
    },
    {
      "binding_sha256": "3e975d47dfe83311068aeba5342add46e0827e8f5f626d03dbe9275476aac8ed",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:206cae20be3b2ca993ce64d5",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:44"
    },
    {
      "binding_sha256": "e81f75652d579c4f6bf31aa194e87c4d9ed82dcc73f9fd34f5f10d1020395a2b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:b396687b0d535c6c40bc29dd",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:45"
    },
    {
      "binding_sha256": "960c427a5b386ee35b7e158e70f127e9ddf635432cfaf24b1a2b9bdef733eca8",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1c601effbd99af125045ce7a",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/everything/package.json:46"
    },
    {
      "binding_sha256": "ffc12b34c3a2722daacf327cc5349598fe6a36d3a3ca69d78e7bc16c7366c758",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:a144ed0f0cb0957fc8e13e62",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/fetch/Dockerfile:2"
    },
    {
      "binding_sha256": "7b78fabbe1448a3b971b54a19008184ae63492d9a38dd2d6a7437cb31a9676f5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:972173cdcc98cb74e0d0eabd",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/fetch/Dockerfile:23"
    },
    {
      "binding_sha256": "2508194ba050c67b2ab76e9ce637f72b5d8b6200beba266098b1108efc8141d1",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:88497812f52f68362ad113dc",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/filesystem/Dockerfile:1"
    },
    {
      "binding_sha256": "6e918086e24e0fea6394f9d58bb6d2fe95bab6cd8cf5c0021108beafa99b9cb6",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e813c32cc917461467c87e6f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/filesystem/Dockerfile:11"
    },
    {
      "binding_sha256": "206ebede764a81172587a6903e794861ca0fefc8c1066e057ef68c1f4414a5de",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:3388f58baa8bb1aacf7639dd",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:28"
    },
    {
      "binding_sha256": "ab4d16b83361beec79e3bc28ee0e55feca561ae56d1e6b676bff1018fb89660d",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e22b5ee57881446e725436a2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:29"
    },
    {
      "binding_sha256": "c49c80a891ad8dd01d694ae3f52318afc6ecbf3eede7507f9acee338a124c0c7",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:0065a8cd9b4f647455f13543",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:30"
    },
    {
      "binding_sha256": "cbf1275f920f06db588575d90f351d1db77a49a944bafbb98be77f9993fd00e0",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:5c191e703dec08cedc106757",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:31"
    },
    {
      "binding_sha256": "8b6c4ae466a89c7e3b5a079bded6535cdd9ea984777b6d9ef1e67a5aca33967d",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e36175bfef75a258ba8cbfe4",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:32"
    },
    {
      "binding_sha256": "640783453d0c63e18c01b1f251481a6d5fee6b9a0e2a0d745673d998881e464e",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:60d1554dc2d3c2a449ddc2fb",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:35"
    },
    {
      "binding_sha256": "2a6f4b88b887603e9009cb0334e87ed5e0f804ef9a856c9de048b9dc740c3c7f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2d3a35438bdde5b6f4106074",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:36"
    },
    {
      "binding_sha256": "8bffc2ca1652569c277a01fd5bf19198c5a8d43c1f91990c62ee741176ea1a92",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e1775c49a1a0db20f2b22f7d",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:37"
    },
    {
      "binding_sha256": "60e11b4f2a719aac9e7249af30ba30abd0cdcf514ff24716fe1cc7ce5a3fe90b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c115b0aae0d8e200a012bf26",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:38"
    },
    {
      "binding_sha256": "d66116832d1a869773faa195953a3154e76d2dff300dfce57469af013bcd0660",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:444b210313144756cc0a122c",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:39"
    },
    {
      "binding_sha256": "0f603690e55ed35fe09bd5a194c909830968d56dcdf9b3d18da7812a67b3c2e2",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:f32f795eeef054562dda5996",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:40"
    },
    {
      "binding_sha256": "343fc86ffb8a14ab5150fe23cd646e1ee44af7e03c7bb5efcaf1a8fbd9ae86dd",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:9af6297524eb8cf283c4aef2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/filesystem/package.json:41"
    },
    {
      "binding_sha256": "5311cb5cffa8c88442ab33e96145f30b105365d3e62ba3b989309bb30d3080e2",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1f96b910676f792ffbfd2f3a",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/git/Dockerfile:2"
    },
    {
      "binding_sha256": "e076f557d96e0a50d73768946cefa5eaf11b90d061091b08b0c1eb9f8a5a250a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:a883e95131d46202282862de",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/git/Dockerfile:23"
    },
    {
      "binding_sha256": "53b278bbb913715917d3cbd5973b7897ce18cd76b5017b28ef0b417e1ab84c61",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2bcaf1deb38935aabec7d085",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/memory/Dockerfile:1"
    },
    {
      "binding_sha256": "d56e64c58e874cf2748ee8b59c9776d4d80afdc3300a1c574fc8b56ffa2ee221",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2dde4cc86e243dc95eae315c",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/memory/Dockerfile:11"
    },
    {
      "binding_sha256": "0dafe5ebe795b8d2c779c2f945ac2c72177b2b40e3b6c6468cc93b9e3b8b4cf3",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:6814a42323c6b6b11c88eb80",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:28"
    },
    {
      "binding_sha256": "b599d93d7c61535cc44c3b0dd4d616d3ec1cbe060d6a19c1fcdc7c63cf2cf0af",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:6bbd76e0849a12cd13f3ade2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:29"
    },
    {
      "binding_sha256": "fcbdc8c29f3edfecf9367ece71734387c15bdc70d9d2f1eddf60c2d04954f178",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:9d9308d6851e44c36eaa62a6",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:32"
    },
    {
      "binding_sha256": "b1269070b991ceebd24019f46d7604888a73c42eb011a8a678eb2bf122ebf60a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:95baf2ef9a1e1bf1b853a6c2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:33"
    },
    {
      "binding_sha256": "6ecb2255141dd8456cde234acc3fd3e6270c4a1936de7de9c4c9955fba63b5cc",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c848a4339842b02444596e00",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:34"
    },
    {
      "binding_sha256": "7273816c93ac91366386d907d3f9ca642f951c2eb8ed3903b9a24e12b79c39f2",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:95a67136405ede793c1f8fc4",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:35"
    },
    {
      "binding_sha256": "b4cdf7d70a47cf08203f72e2d905eedb645f7d718eb54df76b31230f9aee96af",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:26404436b05c98d521bcf7f4",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/memory/package.json:36"
    },
    {
      "binding_sha256": "a3e9ffa4102c16d6da56937994920cacafdbd6eeb9f16799ebe86f94fea8d7e5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:7a477495caa8301889e292d2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/sequentialthinking/Dockerfile:1"
    },
    {
      "binding_sha256": "bad6c62dbcbd0a9872d4d15e72d39f09aca55d8e10578e5d5dd88b87add3c572",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:8305fb9cc560266dd8c4a2e9",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/sequentialthinking/Dockerfile:11"
    },
    {
      "binding_sha256": "ccc53d1de51e25e3d4217d50dd8146c609fe5d34581aa718aeb6eb20fc559732",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:34d0cfa1757dfd255008ada6",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:28"
    },
    {
      "binding_sha256": "5a17686edb08375dcb3a6a6a6422efc55f516bec8b169e11ef9c543a8538e27a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:45718a5482c11281d1c43253",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:29"
    },
    {
      "binding_sha256": "1f554bf741981db2fd362b2d1eabfc606ad977aa488fdceab085e55967aff644",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:526a41abfaea3399aa2fdae8",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:30"
    },
    {
      "binding_sha256": "50861c399610dd3c97f33627ec4ad167443590bf0b73ea2ff4e37912b223c96c",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:3357cbea8a47bb58934795ac",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:31"
    },
    {
      "binding_sha256": "55f073aa42600093933e37da504368bb318c3f85722ef952b9cfa7b579bf3171",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:7d13fe3d8103aa4742658311",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:34"
    },
    {
      "binding_sha256": "e9aa15cd24c765f9012255237333b23a679ab0803c68f64e50da78b41dda2916",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:a2045fe8cc24486d2708c7e4",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:35"
    },
    {
      "binding_sha256": "e763d2b253b0872f9dd982c287e108d3303c7ef9e381f69944bdb88881d49f13",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:8924a7ff2090b763f795030f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:36"
    },
    {
      "binding_sha256": "f269b72f9f48d9b22c8476ec11a8914b77edefb7192a3bf25b62179e10cb6bcb",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:ba5980af7001c9ed0c3019fc",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:37"
    },
    {
      "binding_sha256": "e5c3cba71d6cc4c590c34d24597c59c1b2aba679b3018b5820a5d644516d2786",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c40027fb334dbae147d1983d",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:38"
    },
    {
      "binding_sha256": "80c5a983b047f9bd3eeeac43356ce01d7e5ccbf69a840887bd4c7e22587ebe84",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:054ddfbf95d4af75f63eb7b5",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 src/sequentialthinking/package.json:39"
    },
    {
      "binding_sha256": "e32cbd8fb6c9166bca1f147d6647d3bef0d1eb949648c55b46495de27d5f93f1",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:58bd25b805f69d45cb9e307a",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/time/Dockerfile:2"
    },
    {
      "binding_sha256": "03f34f0454783c746d9c36e893e6eef38b4e7541b75606752d3fde71bc9b1c6f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e320d41acc7f1d0aa016ee89",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 src/time/Dockerfile:23"
    },
    {
      "binding_sha256": "82287362adfcc28ec71b143b7c223994bf887fb3a9239525499cc2a2cca759ff",
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
      "binding_sha256": "8979690a24a8299b47c70bfc1c844817345aa60f4d259ef75e42f0c8b985f9da",
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
      "binding_sha256": "ba165e1bf06c80f5159288fede7e905e427af9679215d68f79ba3a7f7ab0a1ab",
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
      "binding_sha256": "92f88bc18dbfd0092a606a30a14f9250c67dd7d645e7f365bc2716abcaa5e8e0",
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
      "binding_sha256": "6c0e72cc910dd8e8efe846ce4f5da8b2e41d66662fa238e9bc2c3c235b028240",
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
      "binding_sha256": "ff0c9846548f43443d35430699fa943e7313670f978e7dd120974b682b52d094",
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
      "binding_sha256": "e11babaad05aeb2ccc4ddc4b5996b673aacf107573d6f4a8f242f083628bf671",
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
      "binding_sha256": "938f35365f340c0e0dde685584f979df570c7f9e39a8e1b1566fadf47165549f",
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
      "binding_sha256": "f3cb197eb68d143a422b766316c151a4c6d55a59d9fc6f803cb57bda69225499",
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
      "binding_sha256": "035d177dbb09c501d5a9e23e6ad505388f35c3083d639416eb93f57413d5fe98",
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
      "binding_sha256": "bf76952e0028e54d1f45cf570b19bde0ce06337382402d4dd59705f9da48a3d6",
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
      "binding_sha256": "c47f38a628592e32dfdfab9607be39276425c5e10d03a11ff34800fbdefaa23e",
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
      "binding_sha256": "748423998bc4231eb14880603f55475d019111adb6b78b3ea852f1370e8546df",
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
      "binding_sha256": "4a681476a2b530de60abd0ff746de38afc90a23ab1f1f4836dfc3bfab285168a",
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
      "binding_sha256": "7b3dc980e3e2d6fd97acc96cf8c4eb9c4b6b374389345a623e89fae2b17d5f8f",
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
      "binding_sha256": "a73b32ccb7170c654b81f9750e63edd061875dea98f947f03fc823bd190efb75",
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
      "binding_sha256": "43b1036c22959092dbda4e64f4b620cdc4f114de96a769aeb5e52d4b606f3d07",
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
      "binding_sha256": "82e6b5b9248f574822a2ac64f7b1ffa887c7c118be0b34f1159166f276847a09",
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
      "binding_sha256": "aee8c5b88e2126fcaf4f99c0ad06b8699282862b4569d0cd65756e8672ba83ed",
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
      "binding_sha256": "e4287254fe581522626bcad97d2b958d394c0681928b337372188ae76763fa50",
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
      "binding_sha256": "b1cbc97e1c11569eaf3e48e2c69124f1748fc1bc382fff1aafb446bb036cdf56",
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
      "binding_sha256": "88204cd3ea853153aa377b9895c757c454bbecd14db37896852be081af97751f",
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
      "binding_sha256": "9c4f251874c54e6396fe37f228f022f3ab5441128ae0bb579cb1c404d9b40f0e",
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
      "binding_sha256": "ee1891daa75681bf33f3f08d88c1f4a9cf8af51256b07d4a7f18b8fa6935904a",
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
      "binding_sha256": "2348ce0074ddd21ddc3affbce81e4a43ed1a0477f5781ea53f709b14586aaac6",
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
      "binding_sha256": "1c367a7b869d214b9154fc83b45f2d34431459520bb4d8155051f3c77dc075eb",
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
      "binding_sha256": "ca9fc6f1bab3a05a3194b008a97a876308ba7f1a118838aae63fc4bb66da86da",
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
      "binding_sha256": "933ca6bd8c79963de348771e5bd00dd19d2f270bc39a4d1c67ceb6cfdb016102",
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
      "binding_sha256": "8f35ae74014d1fd869f771b8787cc72c7bd10b7afc23d23e9a5ed09647913724",
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
      "binding_sha256": "b085aac2ed387b10cba17ec6d886632c0e3ea270fac8cc806ac298ccf21f6442",
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
      "binding_sha256": "53f224dce60101f7115f366c0a77ec8e3744909e0a166ded0cdd355388fd9350",
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
      "binding_sha256": "d0ab98f0b011fb839889b43258a44956eb513470012523aec178e948348a040d",
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
      "binding_sha256": "055493e679c7e785e9f44df81d50fc78013a119a6fed5f67b237deab558ccec3",
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
      "binding_sha256": "8389303c77580063da8ef19a23078fa39e8799e0206935175975e1535a2b9255",
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
      "binding_sha256": "0d2c96696be87af15b549cf1ba7c79c79579571b2c913802a1c6a2a68e8ee87a",
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
      "binding_sha256": "a74b44bdd964217e98b21f528a71d26b47eccccaa5a1c5555f515f374df5451c",
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
      "binding_sha256": "6f97be98a3a1321190474fa4a4f9e681166eedaad26a5b2302af213294dd4150",
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
      "binding_sha256": "f9c81476ca1c8b5066e0ceffd2d8470064863a65bf2347197c0ab23eed80ee20",
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
      "binding_sha256": "13df804e8cbf0917d27f577cd94d4a9e4a30229c0dea9deb6ad2bf10699e1b79",
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
      "binding_sha256": "1bbc09991478baf3584690e9089b09252ba27f315d448c54e9b2945f34aecd5c",
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
      "binding_sha256": "32223eb84c14a42dc36c0bf3b6d03ff42a65aef84805ea2a1b6ff936cf220bab",
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
      "binding_sha256": "dc6922f65eee9ab68c6059bfe3e6db1220c570997202fe101fffc6edeb40b125",
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
      "binding_sha256": "05878b4ac29c8c7c594ad8e8ddba92c576ea0d018686c91b5089f605b2598ce0",
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
      "binding_sha256": "87dfe4d511e6acf284a9b0aa410d87b586bb0a52f790639df1583431d23b0aa0",
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
      "binding_sha256": "1ebe45719f393ebd723bac22c663211481d5659cf360a0445d9db156442f7f0d",
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
      "binding_sha256": "ecbd77b9374b9f3c7145d1071574222e99278f55f04cb1b351b4a4e2ee3f39b9",
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
      "binding_sha256": "dbe79dadc636c61916a1eee8efaecf88e7462418c03a9b97d1f4840032d3b537",
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
      "binding_sha256": "e9e73505eebb8fbd73218de55a9debc2a84c39a2da2647fd4d09c1c5118f57b0",
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
      "binding_sha256": "e2bbefa3ec88c95da0170450be27203927ce19e258cf5ca1dc6f11015092478d",
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
      "binding_sha256": "a1b406cad57c055b5b54c6634ee6c0efd82801043d79e232c9db878df4f4334c",
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
      "binding_sha256": "3f28023c93a26d0c8df3990aa349dff40b7ff04876994337b8ed1489be5aed8b",
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
      "binding_sha256": "75dcac19e69c4ad5bb801395e6762a36eb141535ac86ae7267fbe2e915922121",
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
      "binding_sha256": "f356f8f03ce9653d66d1eb6827d44f1da8931fd3742030e3a2a76084f5a9f009",
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
      "binding_sha256": "bfe07d9ab18bc96ad8beda8a0a04a92c9128fae3fcd5edf111e8d00a6a85cbb3",
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
      "binding_sha256": "01b5cba9dc3799654b20af7175ee56339d5ddea568d0136d6a3af7d0265fb56c",
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
      "binding_sha256": "a0b9d90b9ba22fb1bb68e94b1add7c103be4caa2365c9c98b7fa788d0f8e8ec2",
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
      "binding_sha256": "8c5b8d2e78723e319e18ae99a8b17d198e593639580d1aee965dde8e874cb39a",
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
      "binding_sha256": "5ee5306d7911d8c2ad1f168166e657b6af46f877e49258cae3111ba45d397832",
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
      "binding_sha256": "e7ac09f2b6ec0298a35d623c069cab77722a1545a34028724c0482f33da973d2",
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
      "binding_sha256": "342cce46804f419f8778274ce731647663625ed7b1635a26a46b9ddfcefa3826",
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
      "binding_sha256": "99fec12578036a391350bd622322b80737cd06724dab57216c1bbed319c2dc58",
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
      "binding_sha256": "cbc9eedba3d349a3b718f713ab35851bc3d8f851eb9caefa411c264f737b65d7",
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
      "binding_sha256": "85c1836469321c3d9872ac2b8fb212fb24549b9afde90cba6a8592f003a9997f",
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
      "binding_sha256": "4b63b34ec1584083a23f93cf2b31574bdb55874f34f1ff99bb0909c04c989d93",
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
      "binding_sha256": "21e046cded8ea4b67c6b0c3ec82cd8b1614553f01d29ad2b474b47f049425e3e",
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
      "binding_sha256": "13d6451acd3b9f9e6579469c1a679de899ee0ed29c16f28b44ef5e09aab844e7",
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
      "binding_sha256": "f2c3694e83480a166d382670dfa01b8d13ca815dd8072f8901b18f9e1ecdd628",
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
      "binding_sha256": "7917e2819ff97888b76d81babfe70ff3814a4015ec7175ad749d6020e1d050f4",
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
      "binding_sha256": "a225e30c7d0ed8f2cc01a2b7c96b825b05b273955c02d5899b8d421aa286093f",
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
      "binding_sha256": "db0fdb59cae9e2834cf1d34cf166fde448fed57795f0ec3f5b571e11033cc144",
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
      "binding_sha256": "75742c9ebb6f869f07761fcad35232f05470d8aedf15df62fe0d30d3214224fd",
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
      "binding_sha256": "6fffa5aba94f2c9d109a2ce8018d06bb681607d38676506a757371becda8f335",
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
      "binding_sha256": "546a930b48ebb5935c99812da6384cb4bfc37a25b8c8cec8081bf3364c4aca7c",
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
      "binding_sha256": "4507d86f26c394672174b74a1ff1afa85e4aa2b8b2a3ce960cca7f0dd1e271c1",
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
      "binding_sha256": "87e13c82f1f95969a7aa50d93570c9fca206415e34ddf899f3ddb98d8b5e22bb",
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
      "binding_sha256": "e163578a9f40a8806a861f525e50b8e1d1b61f17dbcb5338fb0eed60afe37c69",
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
      "binding_sha256": "d6f59b62d5de6d08c8a6fd3f8927968d276ad5b7a02c594490a6a560bfd435a9",
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
      "binding_sha256": "c49bb43d7e306aaa04081d33d661c08e66cd2b60129815c0ca77520663df9829",
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
      "binding_sha256": "9636a5cb4cfbcb86aa349eb82445ac611c49f219fbe23e7e93f308fe16599253",
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
      "binding_sha256": "1f6a75aedc342933d104f0dcdecae77ac3629057cfe28b0c0cb7f54499beae5c",
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
      "binding_sha256": "e73a0ddb6128e6547a5bb22116b001e9365b3ed735e5e646729d61df9acc0cdc",
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
      "binding_sha256": "aa74db34d4e29ddc91a44ad7fa75b1c72803f0bf44a86b0d4e3cc50560ea94a5",
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
      "binding_sha256": "d6f73b6dfb094564fe06adf3760beaeb6932f5fe5446e9c494b17ed40b45b9db",
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
      "binding_sha256": "4f4c396bacccd34468f105216928e64c6aa4bfea7867a20d5926e170349e3771",
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
      "binding_sha256": "b6d3deb759310beb17f52fd924ecdd199f6ef3770025886a9a4e16a7cb70584e",
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
      "binding_sha256": "3a4ed6b9ef788534ee7d227f18fc372a0ea359d3654c3939fd8fd60fc5c77e99",
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
      "binding_sha256": "ca6cf57e32bf884edbfaf208897930dd504cb000f67f6ca9ed565af50e759f2e",
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
      "binding_sha256": "06f9c348cd56798fb5fda4e732dc91d6feed2c2d1a3f90f4a94e129324df7f8f",
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
      "binding_sha256": "8c5cbe2fb06ad2e852a4b3a4cff994e04e2339bea96436097357349f2639326e",
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
      "binding_sha256": "6fc408b498faaa90efb636d974a7b2da400089de4f69fd383caf63be89270f96",
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
      "binding_sha256": "864ca7aeae0164d52dbba42ac76062e353dd547dd0ce3fc48056f2b841217ed4",
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
      "binding_sha256": "8888b5d78372aed52a89628f14564ddf1e83e9d6230d2957d15343f3da58ec3b",
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
      "binding_sha256": "11aa05ff617aee5c4f18ff65bf3237ed6d1d5e3598bfdaa44a0a8a925d95e7be",
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
      "binding_sha256": "0e68ec8fef543eb47a90075a89b19c06f513f1a78af390aa0c06a782deec2836",
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
      "binding_sha256": "ac4b7c452954f37b2ab6457206ecc320206647f0415ba25b6c2d95dc3498b528",
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
      "binding_sha256": "66d9e580d11de4109c650887d0a54e49d444f310daad637104da2852c27cb922",
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
      "binding_sha256": "522f4824c2256fd52bbc7362c6f7c39d05a4369b0df49c9c564bf42570bee017",
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
      "binding_sha256": "0440e914038f09756b30dcbec8407fe8858546ba8bed14ff2632b1c1e30291eb",
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
      "binding_sha256": "d343ee0a77ed094ed02cd453ff09e4b34c5f833dd310cd15dcf04379b0926832",
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
      "binding_sha256": "837f0e3141dddcbc0c74008bf1fc63af7b140978b81063ae5421765aa47e56dd",
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
      "binding_sha256": "4a131d2bfc55a7e55dcc30a05e3f5cc9b937d3e7da999cc7e0e6e940c1795b4f",
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
      "binding_sha256": "bad2799113e9d74d0951945261d03743c5986cfc2795fe70c4d7eaaa8c737357",
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
      "binding_sha256": "d46d385f565391525df025bd11dabfae6daa6ccfb5284a2326415196783dd46c",
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
      "binding_sha256": "ed28000d4fb2ae85497bc8dbe06dfbbe193c00a73d65198d9e6cf9a8a78668c7",
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
      "binding_sha256": "4269829b57291017a5d12c09360ae971c1b0f0911a736d74e8002b5be4d0808a",
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
      "binding_sha256": "b16966d53620ad06be8b0d9ffa75a9c80cc71d4b475146a24c86cb54c6205815",
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
      "binding_sha256": "ead64a51d551ecafeab2d540bac059efcb253eebbf5324715b41316fd443d0f4",
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
      "binding_sha256": "951df741ecfeca9ea0fd21a596f8d2a31d319f834e1f10e5ae689b588c7a0b26",
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
      "binding_sha256": "50a1b91ba07d8d2579d9c33356fb55e3d1a1f1f32b52e087499748146f09c5d5",
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
      "binding_sha256": "64dbce6a30061a92aec4e718d2f7814f7405b5d4cea8d65fc2f3bbe43418b369",
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
      "binding_sha256": "4c0c501d3170b83616a905eb293ba12e6356a1b6437d517db776fa3ca3ac9878",
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
      "binding_sha256": "57ea9640d2cbab0b12221e4f6d9a3a97ecf583ff99db8b0f56654eb43b1cb542",
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
      "binding_sha256": "360ecbec2fef79f4ec51e499ebb156fc9ff18c566c43e1ebc683cc3fe2d97f16",
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
      "binding_sha256": "5e6077a58eda86d58ba8988f1254cd751d9d34b5b23f5d875928e5b48aebf13c",
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
      "binding_sha256": "32485c38e0fc673e5741cfc879ea5765ce4f3884827029aba2682d8cbd4385c0",
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
      "binding_sha256": "88414deb4bc6d218abed393cc86bd3033b07c0f93fc6d130e896fa66b71c2d41",
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
      "binding_sha256": "b588f57acfce5187a075bd121651d1f9ebd38e2a2eadb8a0af1d072a4abf213c",
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
      "binding_sha256": "c1b014e83410155b294302410b3dd0cc8ac873b83460ac276aee09fee64b7929",
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
      "binding_sha256": "2eef1f8af711c6417475d8dc08b1ec30281e8ce9dd68b8760049b2938feb1504",
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
      "binding_sha256": "5d67cc026df9d82d03eb14da364fcffb5d2a996224906ad2b6ec256ba6f1fc39",
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
      "binding_sha256": "e7ef42f34d163dc07697a9150f76afe2eda14b09ce7c2dce7f2f16deaed0838e",
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
      "binding_sha256": "9bbf1266b77a76073eff6b6836ce4eae1a8de3a21537c164c2a8841dfe15c934",
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
      "binding_sha256": "1d42fe5d93904441d92661f5488ba35fa6844a4e3a64fc09ff094fc6c876b5e3",
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
      "binding_sha256": "c5d6a266d325990033381b976ec48878cdf4d5688a2c964920ed62986993ef05",
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
      "binding_sha256": "dbf86e41b5c931cd267d8fe8df6a07bec6e97a220b17fa0daa633a8187cff3fd",
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
      "binding_sha256": "d893e55667ea55ebaa66dd60106e8036ef5345e308f19c45d4407118bae5c52b",
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
      "binding_sha256": "f24823976b225eb2cb1c620005082f00d302bd04657f4da5a7e95a2d5f4c36c2",
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
      "binding_sha256": "988978fc4e8cabe24b8eeb1a3a480490314e12fe2d27696c97367b4b4f8f6f35",
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
      "binding_sha256": "fb98cfad2b3f2567f95f1f8636e66c13f1c9528c7a4d1047947ef57761bc3ece",
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
      "binding_sha256": "ce2830a186d287679a4f5f8aebb4946b26c30f7411f5177070719ff30410a8c7",
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
      "binding_sha256": "c98e80cfef7afb6d2b6c1fa9da72b6aed5e7a021f29dcd4068101bbafb58b3a9",
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
      "binding_sha256": "a94e850723c564e5d232dc0207a062253b80f0d4378c9e330c88622505cdb34c",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-09:2 Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk."
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
    "evidence_sha256": "36a7f1c53ead0736fbc726a7231d4c7b1cac6f0bc4a540b067070c0aef713992",
    "image_limits": {},
    "manifest_sha256": "94a847a7c8e4928607dc944ccd091431bcb04f86c2cba8472949a447056c32f5",
    "scan_id": "1432f74546db9475daca2ca6fdda9c324d0c430fbedadb14346be564c00a4d63",
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

