# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `b556c65e26af4b3305e6f11d2f2663ba691c1faa9c5fde2ec55017fd3ba294ba`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
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

Guidance catalog version: 1\.0\.0; SHA-256: `c04353ab7c9999ea513de31a48130971509f8a52666745b24d1b726f96a4f374`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 61 | Observed patterns requiring review; 0 critical/high. No severity weights or estimated compromise probability are assigned. |
| Partial deterministic mapping reach | 45.45% (30/66) | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |
| Optional AI answer coverage | 0.00% (0/132) | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |

**Selected scope:** 46 rules (46 active), 66 controls (66 active), 132 active acceptance checks. The selected static scope completed. Recorded coverage gaps: 0.

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
| generic\_text | 4 | Generic secret/URL signals and bounded recognized skill/instruction directives; language\-specific execution and dataflow are not analyzed\. |
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
      "binding_sha256": "1634775899cbdcb6df85d87f7352a1c319dd50caa4d71eeaf0e8897f910ed5ec",
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
      "binding_sha256": "fc607c0410c5e7405fcf119128d711c8618e5392623c86f5de8aa07a0c0bad1d",
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
      "binding_sha256": "735eb54163f97643457cfa2cdd4dd0d5e87e5590c2dea7ba64c8889398c52d29",
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
      "binding_sha256": "5337b548be12f3f8932d10941214543b55b238425c94bb99ef60a2d30365c78d",
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
      "binding_sha256": "36b316b7ec2ddcd2cc62c6aad93efc7c6f89228c71d111a48db996abcaaa909e",
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
      "binding_sha256": "666bb8b884d1472f20262e8e446637a6cb3c5619199d66feb6ea26ec5f2bd658",
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
      "binding_sha256": "43f81bb12b63c68f7e1c2ddf98b50fad1bb52fb254d33754f6c61f19e01d4aa2",
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
      "binding_sha256": "3531ee1633714a773f374ee5fc6af6810b6eb40f4b171c2924541102f14f2016",
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
      "binding_sha256": "6d75e87c5438b76b4d872fbd96927dc53b83ab7f1b33a896e62367f9499c5bc5",
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
      "binding_sha256": "dd4790e422951f2f6415d3957c76840513f86006635c18abbba8b7fa2cc3c53b",
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
      "binding_sha256": "efe7c19968e897227ef2eec0b411ebe916dc479b1914dd00487338231af377dd",
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
      "binding_sha256": "b8cc281b988a35f0a8cf096942333dbd7b259cfb394f1eefb3de5321622c928b",
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
      "binding_sha256": "456968bf1527bb07a19420c629f64cc15aedbf00bd9bed5a27eb05a77f7defd3",
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
      "binding_sha256": "0913229225ca854b0983e23e47e807057a85cd72398c1f73492b0669b8689de6",
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
      "binding_sha256": "7391f4c8cea3e48d5f43fd2a7648dd9c4f887145764725e8c1e95d4ee020eb04",
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
      "binding_sha256": "553ec47dc207d3246535618d91ce012b38be1f450f5e5defa56b03111cd447fa",
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
      "binding_sha256": "9aebca8d65086684e867f1969a60d912007b9c4ffd8fe9ef967592c2c557d71b",
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
      "binding_sha256": "22976fb5c899f0b955c6e4bcadd6f7dd3fbbe3de4a0ecda9ebf585daf76ac482",
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
      "binding_sha256": "e8f59f7cf885a878b3a5108e65677a01db53d95b005e0bbfba80f141437a1bce",
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
      "binding_sha256": "42c13054652a8569c74e6e2e69d2c90f43ed1f84fae3d8c339f25ead4fac312f",
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
      "binding_sha256": "8133a0cd71bfb92e40c800324281a9c7c586020bf827a675fba54c2761babc84",
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
      "binding_sha256": "50c4612b48afed12a029967253861f4964b1124e9e10364acef1ac2f63f8d427",
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
      "binding_sha256": "6c5e87d8cfd68708061810f639d5d842c2641e958a49e73fb41510b59c8362b5",
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
      "binding_sha256": "b0cc8d5de45a1d8bccce979811480cfb5a4a0b32f800d3c264438f5afdf3f21a",
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
      "binding_sha256": "189f6f7c4eb7ec1c737ebf7af0ad7cca9762dfd124906821ec60bd04c8f5ce62",
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
      "binding_sha256": "e4a5ceafbc1d85bb7a3d4933daa01c6675d20e8e2e28b0bf9fe10c80886e7f57",
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
      "binding_sha256": "ad30b1a7c02119febe45511f11793f666099e6021e565ce39cba6a6b13b015c4",
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
      "binding_sha256": "c9ac4f3f25debb4cac20f5d0deb632dbf97ed63caa9ae41a443d4fedae264887",
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
      "binding_sha256": "523d1a0ddae3cf5f5db13f41ac1f97b431a2deee136b5ab967285def0ad4b34a",
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
      "binding_sha256": "f9fa0c167d39af44166fc5ea06a6a3932c101a6d57c66ed780553ea08b674b6a",
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
      "binding_sha256": "bed9bf127921c241a4669eda8e40ccbf4ebe0cd30b2fb683236a70ab39b5fb0c",
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
      "binding_sha256": "83b5ec80ab8e09a7e6a4dbb2dde087e9c28fb7876e8d038595d7e46b2f903ba3",
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
      "binding_sha256": "ef846ba738eb3a021a01388d8793a2649b4a54146fbb1a2be67eb50768270904",
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
      "binding_sha256": "b402511a7a54e67317d2407887b6f0b69cff57124cc2d2b89073e5811c12d7f0",
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
      "binding_sha256": "f496a3e41eca9bfd79c04e867671d51b1c605d11be808103c080595dc65b5393",
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
      "binding_sha256": "6f3cbc92e2e14938ff1b3bfda1fccf7184389b4734dc0c3b61dbdc002cf97c98",
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
      "binding_sha256": "a1f430a44a15767a9ba6385210e073392a4f2b138a0447d9991d60c11a6c5661",
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
      "binding_sha256": "ec4f7abbe8faa53738715cbfca218322f720e40dd5ae2ab79fb34fc7cc3ac145",
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
      "binding_sha256": "cb8ed8bc601f04d38724aa0871b58c77ef39e58915fabafd321934128d844ea6",
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
      "binding_sha256": "bab2eec1e4e632b58e481bef24307b6afef58021e882c8e6b5d5005ced1703f1",
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
      "binding_sha256": "3e5231551e593c1f23fdfce962610adcd9ae757c264713e6bffb43c041952e7f",
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
      "binding_sha256": "e189a318df848b5611fd5e5c9cd16bd5cc061e4b08e9f6915ba8664202533dff",
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
      "binding_sha256": "44fa5e24bb301157fe7a7db8f2477b4fbd8c6f6291d452d9b862628846de058f",
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
      "binding_sha256": "32ff62cce352c7ff10e6e2b6488a0144c33e632881a9cea6063e40ee37546e12",
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
      "binding_sha256": "183c242ed08decf55e8b9f479d78988b4624729b8a2b14430e906315bf2730f2",
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
      "binding_sha256": "579aa693fc3a0f2efb8c285d33ed8f11d9f352d1e671fb3e84f28f93f32391cf",
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
      "binding_sha256": "294399daf314f154db29055524c11566517b22c6a98ea4d4dfea7c084085167c",
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
      "binding_sha256": "72b88981c641ba84b333e94c8ea24bcd5caf8794fc2c6da932b5f3d15fe83d80",
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
      "binding_sha256": "005a0daab1eda03dfd3e10fc2029b7fbc79518500b8819feaa55cf405733a44f",
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
      "binding_sha256": "692a7d74eeb100b279087ac19f970c7df9500eecf4ba5b5b62a100aadb723ab8",
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
      "binding_sha256": "8321ab89a632660baf7bf9133878f4cd7d3cf2cba8f2e87853e8e18a5455f902",
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
      "binding_sha256": "1757352c162f13310cac0b6ecdbda36afa6cda5dd3b8a532cdfb532b6eabd41a",
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
      "binding_sha256": "b5c93a8e6be20ddc62353c659769d8aa68b3ff1fc695abd3c72aab675c412a47",
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
      "binding_sha256": "122ec8fc4260d57a3e817f379b20dd0f2ca46458b03564a23d3cf6ba76ef10b5",
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
      "binding_sha256": "411afe14eb343d7c9e430d1fb30b6a13b8f280d311441e2fd63c4d4677cdd65e",
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
      "binding_sha256": "daeb0e0eedd38654383fa2388aff3763ed0a1351d3869567643d638934492894",
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
      "binding_sha256": "27b98da56a54ece97f6a7ba163cf4dcb28d3f1580087464e2d171b709ae654cc",
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
      "binding_sha256": "710ab726cce28b843ec143a48c4036e6b50e665de466541954b9339e70a8b5ba",
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
      "binding_sha256": "544bb695c17aff27fea9bff5aaca773efadc686046ffd80fc82fc64083cf28ad",
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
      "binding_sha256": "239d40ad2c798362f807d5784a038b38daef93adba6b5ae6a8e50c2aef0718ac",
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
      "binding_sha256": "bc3f544fedc2841696c68154247a8388a4bd168c0e43001c0131741592844ab2",
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
      "binding_sha256": "6efb66b82f54f8a06689cb28bc2a4b66dfb95a5865c6b4b894890f7809caa263",
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
      "binding_sha256": "aa4a4fe12ce891392519c319d09ec1d7a15b7c773848ec8577e9ff78a2dc42d0",
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
      "binding_sha256": "0580d88c374005d7df178637aa931e3aabf58fd94a0ae09bdc6ee1361a083dbb",
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
      "binding_sha256": "29a80ef221a9456e5e3c40131ed9cf0a80df550d3d497d142f99f17dcfb37159",
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
      "binding_sha256": "a878a5023ce59551561674a35a02e1fcd7ae70748ca1f9ecc5f0dccd22f28344",
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
      "binding_sha256": "e127711585b52cc16c7b710af4be265fcf2cd58789af4632bf33edb321b2f79e",
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
      "binding_sha256": "4944e4f6917ce6f501e8c59c0aca8839db529a260b1796c8db80efad6403d358",
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
      "binding_sha256": "04410671700b16e913d524ffef9bc9a1761c975d0085489d01bce9e681d2f7f3",
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
      "binding_sha256": "c59db455f93daf9e05f9c74bf78fa0c2ba03072b61fcb28649d21322a504dd89",
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
      "binding_sha256": "6d1a43868f3579202c49a9ed3edf96836b0735362643e0788ab513aff64a0914",
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
      "binding_sha256": "cf48368caa114071abba1fa5b2b5096b8121e9dd103bf8e3199c265ed4843841",
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
      "binding_sha256": "66ede95b8af48aff0a164cab9a166b13907dc5f0ca0d1bcf24e25735da1d443c",
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
      "binding_sha256": "54703d4e8c98ee5e1bd06599d533a5a159c6a1090059e4b6ab552a430d21c27c",
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
      "binding_sha256": "47b7a002498626a8812905a744a94526a9865709cc069544d048e1f4f5203ef2",
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
      "binding_sha256": "5f71e54c3da721f20f129a051c8a3570feddbab508455af8199dbab46fec6b79",
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
      "binding_sha256": "3aa1b4c734123cdb4358b862fccbf6813122c983a3a520218fc95b3fb3d4d1c9",
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
      "binding_sha256": "d4eada4c1a5630021fa01e38617ad555cba98c91c87f811f3730bcfb98dab3d0",
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
      "binding_sha256": "b9b622c10b8856544e0b59f1ddc492490d93ddce4ef3072677c050d339d427d5",
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
      "binding_sha256": "08eb60136e621203a0ccfa53234ad626a76c0ae587ab47e15a40ae65f3c9dbb1",
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
      "binding_sha256": "d12933fe0587e3fba52442b2af232e1fcb8c5a3cbfff9891d9127bc7d3407afc",
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
      "binding_sha256": "ee917e505343293f854c999348b66cfd391d85e92d8755fd31422feb5a262a23",
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
      "binding_sha256": "74d9dbdb893a5543d5bef828a0c8d064da0382da16ffe9c62163499d1043f7a6",
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
      "binding_sha256": "e9f80353c22b148ab9a4d7e0ebd61d19f515c8fbdaf9eb6b1cbdd4317a5be768",
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
      "binding_sha256": "607428b5034b5ca80dfc391826de79c9b59282f331192c706d4b2325c346836e",
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
      "binding_sha256": "43ddfd566ad3376b1546bb3f4c9e44a3e3e57f57afae01d2d3e40b63f4110bf6",
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
      "binding_sha256": "0017265fd02691ee1dbf10542e72199ad41ca63f0b39f821efdd6d43074604ce",
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
      "binding_sha256": "c88d27a7486b626e5d8b166fe8ab7cb0bb2272bbb60bb5c0056351671bc1da15",
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
      "binding_sha256": "4090a08acc51d4095622b61411fb4cf1dbf32c360986a82af9976077793b1070",
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
      "binding_sha256": "03ac4f06c5fdab2dbf5fa75080f934e9f4e96e6f72949b3a01c0e2e1d7aa8c2c",
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
      "binding_sha256": "ae1c912b11cc41dfd77164b6e0c39e424c8654650cf898cd1e0ecaa21ea65bbf",
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
      "binding_sha256": "1618a676206777c73b5cd04b67f786b9344dbdaa130d0d51f9befbf09ec11a6e",
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
      "binding_sha256": "f954fc3e0e9e4877bb58d623d1172950246d453657d53c39b0fa3f56cd9e4836",
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
      "binding_sha256": "8ae313b81897a6058bcd1493c37af2b118a63ac525ef80e958734650c13a01e3",
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
      "binding_sha256": "9aecdc883c4d82db3ad640f6670f1d16c180921a755c09d0bf8421ecce125ea1",
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
      "binding_sha256": "f53e1938b66bb7050d7348c3b29f5b6213f9119b5b4469a1223efae9efaf544d",
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
      "binding_sha256": "19fc1e0641d56c46bee8cab9e2e08157a737dbcb32f484afe9c1801d45be04a6",
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
      "binding_sha256": "76ebebcded6b53495911cb787bdda4e424861828f43e79adaeb91a89a193be4f",
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
      "binding_sha256": "1908a7dfac52d2381b6e2224d595a7b8245b6cff041c0b11f6b0d426ba83ce43",
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
      "binding_sha256": "f78b72f240cb79b2232556496c0839c2732a30a1344df3a5b02932065b3076f8",
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
      "binding_sha256": "2123072946653dd330ec846c84608c1be3f49882d652cab8fad80d18d630f387",
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
      "binding_sha256": "df019e48257c1c4708c61d75f8a6a69bc22e819ffd0d1e08c79b817c72b79421",
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
      "binding_sha256": "3ef87811abca33155412c78f4b39cac72b7bd7bb171d74dcf06c15d576391cc4",
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
      "binding_sha256": "9ec8a0fd84056a54e809659d28af793c9e820bbd013c96241f1336c0dd9c244b",
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
      "binding_sha256": "6321cab79c4a79f7f10eed187333602d55f90913e8964fcb28ce5aaa4e51e05a",
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
      "binding_sha256": "e40c0736f29b6fec92ec11e0a21de47f67bc4284f30b361d7584ea6c6a2c25bf",
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
      "binding_sha256": "8aa9f54e528221848dcd39db387e1656a300538ca81f66524928f1b3ee467e26",
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
      "binding_sha256": "7418d1d83157f75c0d34292d9aa8a8499f1dea6339f311f36fac4cebd7259512",
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
      "binding_sha256": "4a8b7fa9c921f46a46c31f0e17aba01437bd9b8936ae18827aa633c938fbe430",
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
      "binding_sha256": "7c41ca1587b97fb6b8f84ef822938f9594180ccd0256a783e3f8a64be1b48759",
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
      "binding_sha256": "984339ea72fb920cbe8965484ac2e3c03bf1c5e6b9d7f4e5da411c70dcb60fc4",
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
      "binding_sha256": "7027de331d490a60cd8db9007c6cd468ba9119944aa731e771610527447ba699",
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
      "binding_sha256": "23ee1332fdd34c3b5614a092a47c7693bfe512ca30f9563b9adf8cc90c43b5b6",
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
      "binding_sha256": "cc58b0a5ff6f624a075fce0839c305a41631e20e96ef96e52b67ba3e03dfc16f",
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
      "binding_sha256": "e2638b79171ca6baabd18ec583402ac12ef724d94b8dc60ae15806f36cf285c8",
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
      "binding_sha256": "13beecd517bddbf26f4cf133752ba826449d91af0985505e7c43a8bd16a47c22",
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
      "binding_sha256": "2c6e97b3a0a5c4324adb0072c6a8bf497518a0f69056aca28883cb26f8c4f442",
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
      "binding_sha256": "f31719ce223df40f0f05b325cc39c60ae8f221634847965d03ddfe90bbf9bda0",
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
      "binding_sha256": "5eb7b7d3558b16d22151057f1f986ae3a854ae7ad5fd733ba45f935cd370b9fa",
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
      "binding_sha256": "c35cc614e7309428476d691ee812d71d98192f68da3cc9ea9f0f58af28379dd1",
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
      "binding_sha256": "f90090e1c7715334356fd040d75a8c3866a4181dcc63e9337b4985ffdfbb6ae6",
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
      "binding_sha256": "203425626ac79c2026a09b909ea8c7bde144be3ac19af69343101e93b7dfe433",
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
      "binding_sha256": "09d9e97faf1027192215740b8ecaeb5fb27b4d1e083027f1b4031dc93a172550",
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
      "binding_sha256": "3b93e128af9d863fe9ed987664c7b7a95945f01069f019a3237794517940eeda",
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
      "binding_sha256": "9bd0959712d6ea30c823ec92abb1ea14138d2772b52ecc58b1ac42414383660c",
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
      "binding_sha256": "ba4286f460beea5973e3c0a1c5f7b0a470c7f050b8d7d8ca3ddec82fc6f3a9e5",
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
      "binding_sha256": "a6ade2086db9b18b10a85c54ddddc7bb8f525e2397a80204d4b4198a5bafa5a4",
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
      "binding_sha256": "d8c344a24db2afa2152d6bb18fd1700b26bc459dc3d11103f05be81cffa302fe",
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
      "binding_sha256": "cdff5ab87e61b395da7e5502d11136d6678397057850f6b4cc9d1855318bcab9",
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
      "binding_sha256": "dddfd1c2e2df18678f1a4d24cf03f560fcc7e1c2a570e1f487e362fd85161599",
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
      "binding_sha256": "c98ce7a6aed864973247117fb44a87694d26fe9e6eb9b6008fdde511323040d0",
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
      "binding_sha256": "8f7cda13e0d6eaebcf94b8cb4b277e3228b32987cfd7a4c74c2b96351794483c",
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
      "binding_sha256": "faae3d6b6bceabf159b35199eb47994f66eb54d4d8fdd95c5feda20222c9d11d",
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
      "binding_sha256": "e3b5439e183bcef0d561ac2d3743189f9414a79d81d3eae450b39ffa7abdcafe",
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
      "binding_sha256": "7c8bc9aae5483391e6b8df88b38ba4ad087ae68c02862d6c440b1900082ff39e",
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
      "binding_sha256": "18f3f584aa6f6c39a03354cd75154580d18c3cd7990e9c1cfa45cb11ab987c4b",
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
      "binding_sha256": "408c2cfecb07b927dfcbe32e4fd456c170e0968fec9e754a73f882731d3406ef",
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
      "binding_sha256": "36d2ac65a62022a06d8c01be8dd85ca1db1decb68fa608ab3f456c6e849ee47f",
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
      "binding_sha256": "be97f30b7787fb1c097bdb8d540f2f78b0c0b66b4c9079d247c3f5ca5c8d0023",
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
      "binding_sha256": "4d83aa45032f68e9febdefff7d629220e64f0a37fc36acd2362402b8390c5921",
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
      "binding_sha256": "a621f71eeb6a3a25b021a68b53238b39d0321c1722c846897d1d9d683eea8cc8",
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
      "binding_sha256": "78015eca53c0ddede3bdfa77cee1f917adca2786370f6f3f1f2cbfff371d8129",
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
      "binding_sha256": "2348d083c330dd7e34b37c77ab9c601b48d0dcddaceecd478dab975591ce8fc0",
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
      "binding_sha256": "64c2c2c1f8379d8eadab20e8fc0220340c7d47fc84c0ecc8d7e4239ab079aad5",
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
      "binding_sha256": "868303903232ce1edb46ed3cb0752fb49fa0cc8f5e247662761a8c3aa443a376",
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
      "binding_sha256": "269e5fd0fec3211cf073ee3df426059f0d2cb0435ba7aaf8a63a25363c1996dd",
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
      "binding_sha256": "6dbea3381c0c5f66560ccddd93827b5049ede32702a6c26170affecf9d9231e3",
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
      "binding_sha256": "52ae8fdfc5d9783db78a401d1c741497a7b2d6f7e6f1a05ec7b8fa22c252368a",
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
      "binding_sha256": "b155a5c0061529de9492c63ab6a8881fe6486b053bf9103b41bd92abdbcd9a7a",
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
      "binding_sha256": "9d15e873dad9809abe0b97169e8d754f4291c67767a05f1a30601d73e1ec2955",
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
      "binding_sha256": "9bbe677dd0aa6ea94336a953856a89b8ecc9694553b7a48b4bc0e74cb50683f8",
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
      "binding_sha256": "27b7e2c638931dced49e89d11625ded443a6c45bde4d50811b80d720bb5ddcb2",
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
      "binding_sha256": "ef805519be6465c03f53bd22e59a6516075fdb25eb14b835d1337a77361b125f",
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
      "binding_sha256": "097cdca7224f3e99da6182cce742b3eeb8e96f5f1190b37611097e7276863559",
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
      "binding_sha256": "9c0deca0676786ece8f7025ca0f8d45fb62a789ebd7466d5edc5c7fb933f1b37",
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
      "binding_sha256": "e5ac1eee3787508d39646bb3ebfbb20045ec0900c7debea4de0378462c4a147c",
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
      "binding_sha256": "84c79f5205544a5038692b35077d3f6a9ff7d4efb2899482bf4676b596c9d36e",
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
      "binding_sha256": "fdb0e5517f9007207d64d69cdaac9ff60863453741f8b496e564b88eb08385fd",
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
      "binding_sha256": "99a790ae9728fcc8482b94ffa33580104eae67bf48775d2cb2330bd6d9a3440a",
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
      "binding_sha256": "6e0e4572d5fa8d0264fd19c9f1bdb46b4b5c25d7a5ba9c06d9bf1d017e8ee5c0",
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
      "binding_sha256": "9b4c6e8929ccfa8a0bc4d70c59f6b9f43129eefaa70547bfe7c84dc717769509",
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
      "binding_sha256": "5eaba298a5a2e60784131e908ce001533b9958e7fe0f73480093ac2c5864f57d",
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
      "binding_sha256": "055b609c0aa0464f89d8efa02091647d87800e96ade7b2b319225cef8a12b9bb",
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
      "binding_sha256": "bf2fccac3eddff63a0f5a6422df539f98fbf814572ad479c6d167250b40d6f25",
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
      "binding_sha256": "6a6254608434262a2e78681d73d3dc9f7dae550477e99189b4afedc46dd598bd",
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
      "binding_sha256": "4a042ea187f8fc15bc52fa390f3e6f17f5f4ac53eee6db2bac7f71404b73d9a8",
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
      "binding_sha256": "0aef9daf072ac7a4e0c3a650721c3b49e7c50f593cdacd65d30f530d0165e5a3",
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
      "binding_sha256": "4c116d243270c2588a2d01b19da3527c6e94fe92cacc81e86363eeebd192132e",
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
      "binding_sha256": "30f3ef281ffd3091ba82dd2573e769cea7acc1e64ef1bedd74b916e4ddf6dfa8",
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
      "binding_sha256": "da08f64c2684bcd8c8f636d50e9e60bb3b6f59d4d458776dcaadb20e4a11df39",
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
      "binding_sha256": "1302b2adfa90889cfa747103a83e491c92d88c57f653611d383b2748cc055451",
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
      "binding_sha256": "d591322d7f282ace95ed49fdfd00ae31a685b02d50441d7326c8ca34ae4ffafd",
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
      "binding_sha256": "28b7469c4346ab1788f7880245b97b8c0cf2ceb0ed178f19e27b7a8acf483a22",
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
      "binding_sha256": "90da2f7afc95b7dd38c4abc5d8a8f178870ad76b9392945d2d503fd095ba2b0a",
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
      "binding_sha256": "b5f4c5fc1754798efb0767f07f346de46703e75803c17459ad88d6a9f38db92e",
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
      "binding_sha256": "5542ee73a441c80cc1902871eaab9252be60436c1e5ca18beab23c6104808725",
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
      "binding_sha256": "89277bbfe57f4827ca5c4e9b4751ca8aa4725ebedbce86a22adb315dcc25cb8f",
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
      "binding_sha256": "45efd554f995b5078e28abf5f2b313b973f54082f321dd561087afb0c932e48e",
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
      "binding_sha256": "c077d7b665096edb5c1f2f33238c14ac47a5dd9a6f6c10b835767aca945ea776",
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
      "binding_sha256": "d5936af1541559a2300ee01c6159a71ab133599812d524316688d3c51ae18cc8",
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
      "binding_sha256": "cdad8ad18d1d6536b76cff70a10b8e4ab11fafcbaddc0e9e7d41cb67b8c62d3d",
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
      "binding_sha256": "92c4764a7f6784d855df450354266fb1780f2fb809215fb6000713c382eadfa6",
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
      "binding_sha256": "9bf451e33fc12b4bfc26a85259ddd9681e5988b1c5922914534067e7fd3e1f4c",
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
      "binding_sha256": "ef70074a1678bb040e86c9a12c0d6162834b95f359e993077450d48322b93131",
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
      "binding_sha256": "a4807c3524cea230d823886030bf06812db4dd91bc413ae0b7423ec1d8a9b4ed",
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
      "binding_sha256": "dd64ba11b3a20e5939fa4ed5b491021ff7be3a678468d0d33c2ee72dfe4765b3",
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
      "binding_sha256": "9d22ff6d22faf2ba16eac20029d155bdc41d47bb71fb01ea7b58b5e21d849b8d",
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
      "binding_sha256": "641488ac0e0ccf6a6c74056f5ee90772a2db3f4e091fe5bee44e6392299d124c",
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
      "binding_sha256": "8245392c7303d063ce16fd6c53d12d899676681767efdc79cb832dfc06cc1e6a",
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
      "binding_sha256": "159b2e82949e14c3e824b63e3095c7bd79a32d4d766e174243592f4ef077785e",
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
      "binding_sha256": "5d789c2a64eed4831ac07276f5827a25831f22e19cd07c480dd8220dc4460cc4",
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
      "binding_sha256": "41ce64746351bc47061a88b98312048eb4ea37456a17f1925830b6cde6af0e0e",
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
      "binding_sha256": "5d669d641fbf2f5a62f78e58ed8e151b288b41003902ac2d1daa42f10fe9512c",
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
    "evidence_sha256": "36a7f1c53ead0736fbc726a7231d4c7b1cac6f0bc4a540b067070c0aef713992",
    "image_limits": {},
    "manifest_sha256": "94a847a7c8e4928607dc944ccd091431bcb04f86c2cba8472949a447056c32f5",
    "scan_id": "b556c65e26af4b3305e6f11d2f2663ba691c1faa9c5fde2ec55017fd3ba294ba",
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

