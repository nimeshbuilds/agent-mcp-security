# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `ac0543d58433de601aafb67d7a6184a1fddc7095628a3912c50b3f00860a8ef8`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Incomplete scan \- close the coverage gaps

The selected static scope was not fully inspected\. There are 61 open findings, including 0 critical/high findings\. Resolve reported gaps and review existing evidence before relying on this result\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 61 | 0 | 14 | 0 | 1 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 61/61 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Supply chain: 59; Network exposure: 2. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 2; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

**Close scan coverage gaps:** resolve the listed errors or scope limits and rerun on a stable input. Existing findings still need review.

- parse\_error: MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete: 1 entries. Examples: src/filesystem/index\.ts

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

Guidance catalog version: 1\.0\.0; SHA-256: `1bd48fd16d4fe76ae3ccd1cacddce9bea2dedd0000856d61b21ffb8ba8c5dd7b`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 61 | Observed patterns requiring review; 0 critical/high. No severity weights or estimated compromise probability are assigned. |
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

Scanned **86 files**; **61 open findings**, **0 suppressed findings**, and **1 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 0 | 2 | 59 | 0 |

Source I/O: **1003862 bytes read**, **1003862 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 10 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| generic\_text | 4 | Generic secret/URL signals, bounded English skill/instruction directives and selected Spanish/French/German override forms; no general translation\. Language\-specific execution/dataflow is not analyzed\. |
| javascript\_lexical | 51 | Bounded JavaScript/TypeScript tokens, calls, configuration and direct\-return function\-wrapper summaries; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 12 | Parsed JSON/JSONC fields, selected configuration rules and recognized tool/input\-schema descriptions; runtime values and referenced files are not resolved\. |
| python\_ast | 9 | Python AST, bounded aliases/values, selected same\-file argument/return flow, exact literal guards and read\-only tool write witnesses; no whole\-program or runtime proof\. |

Severity failure threshold: **high** · Process exit code: **2**.

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

- src/filesystem/index\.ts: MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete

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
      "binding_sha256": "7ccf4d8e5df96d59cb15b153ac09433a33319cf703c284089835d1eb64a00024",
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
      "binding_sha256": "e4ea273ab56ca399ff711ba085d9d11ba2ffdebe59d28fd14bc7aaf9bb0837c7",
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
      "binding_sha256": "d795660b8cc807aaf536a9599048cc3359e83e5e5281ba85c26fba2b38da76a5",
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
      "binding_sha256": "de94b2f901d23c4e955f4d3f01bfb51ab46adb847ffd0eae06897e7ceb18c5e9",
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
      "binding_sha256": "4b1b98b29158452562564c7a8e1e73cee23242c53a1529678a210938d4ab3bc8",
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
      "binding_sha256": "ba245f1e5da48c056b1c905295bba87cf604d35bdf207502ddae889f42f5c2ff",
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
      "binding_sha256": "aea04405aeb2ad796699ff256da78ea2e35e5c5eb9b90c93ae5480369ee4b29b",
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
      "binding_sha256": "b820254179f661b4da7c74bb1b247f8074c6f04794aed03c85224712c9a2b9f2",
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
      "binding_sha256": "09b7e9973b9a4dcb0cf764e000acb24b215941fcc763ef816941f0a939967249",
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
      "binding_sha256": "6e4fee97bc5aafc073b0fcc8fb71d8bcf1c91473af18161c67f8720d646b8351",
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
      "binding_sha256": "01fb5754db2f1eb415936b9ee1422d29dca681afa4d32e4270efdc200b307b33",
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
      "binding_sha256": "07b38f039f158656b967acabc34b38afc800fe50748418dde5bd3fa9ff1210a5",
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
      "binding_sha256": "5666773368355f7a8d531866da4c50478bdff9676a32ef955576266292ba9109",
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
      "binding_sha256": "c01f902c3981ae6caab68d6c2cbd4bebbf8c9587a8e58917e090e0a09e75bdd2",
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
      "binding_sha256": "85c79eadab91d4af39b13c5bb3ded7f7690acfce7e7390416b581c83d045764f",
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
      "binding_sha256": "87d6c14b0f89a06a4f5162d1d535661f3763a524d10884d682fc20f249310c6a",
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
      "binding_sha256": "610b6279ca4f21ae9b78db87cd5b51ca94a3447f87a8f37b5963c39fef9afcab",
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
      "binding_sha256": "64d5240cab96d0905624a0ea7d31f7091e9e5575d8ad4188ec30a3529adf383e",
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
      "binding_sha256": "105418840412ffbc70b88a46b9aadf147846d19494c71b9c52562d60fe28322d",
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
      "binding_sha256": "0fc2a3e9da75349212111ca88bb1a026629a6a7d6d8d2a75b5c6d975d7841ef3",
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
      "binding_sha256": "fd81a1ec896e1ed79dbd3cc9b8746c89d6e52ebe3a0cc63e4a009278e6bccbe4",
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
      "binding_sha256": "fdd61e867780a39fb262feecec769de4927fc6db2cab58b64dfa1d08c05d4bbf",
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
      "binding_sha256": "9ade69c4464309c6b5744fa3ea11ec74c879fcfd9799da8c8a19690327d4d1ca",
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
      "binding_sha256": "6c75c1c95a88aac6763b668dee78034d216793560197c79cc3a21c8328fc5d49",
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
      "binding_sha256": "47d5f953945173d89b92fe71b75c1f0e802eba2c3806bb234db431f620f57c38",
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
      "binding_sha256": "bc488c151ea377969478fb835f5cefca437734c1ba56374961b280c187c63c45",
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
      "binding_sha256": "bddee37b232309dbf41e5ffd5d9db1dfc942f4fb0d1f58c73cfb6be332fa7e47",
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
      "binding_sha256": "b276893573f4f629bc15df82dc72d1f5135318734495d69c25c8edb39093eff7",
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
      "binding_sha256": "4a91168c97358924c0e1dd787ea08b798462c6f8520610a3dd7298d081383dac",
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
      "binding_sha256": "6647f589437bffb4a4c2bd0eb3bb27e35f17e6f65550abf767dd5f2993f0cf91",
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
      "binding_sha256": "1c6b2642f49f3375b02d2231730601f6da3a18f20f01c037494381cad025ae38",
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
      "binding_sha256": "89ab92bb333177a5688b9995eac327746997f9f404cda87b2229a063e7bf608c",
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
      "binding_sha256": "29b714ed125ffc4d20cca199ced3452ce4130901fa622aac30a6bf9cbdc19347",
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
      "binding_sha256": "58b6a03a21045770cdd53928b9ceeb09d319a7addd4a46cc69c42dc6440794ba",
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
      "binding_sha256": "74b1b16b92406b4d9435e8bdc112b15fda5549485a1da22d434498955c5bf5c3",
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
      "binding_sha256": "4708f7ba3b840d93c3ec43b6ec9a8f9c387108c20a544a982e2c56693e2ff0e5",
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
      "binding_sha256": "11d85d84acb8e66068d31e3c91bf949749904ecf4ab70d61016880d010131b77",
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
      "binding_sha256": "a6ae162fa05f81f4335b66f57f107e8f05ac6c1319028cce2d56449df1756746",
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
      "binding_sha256": "695edcaae60ef1cc59902e22dd88c243ee5e9fd6b06a5025776192b1e9775828",
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
      "binding_sha256": "15d176b2a654188c165cafa46f77ecfb80cbb3d3a2cf3c21b5b7fe95395a28e6",
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
      "binding_sha256": "4d491162a465cc3fdb621480dbc8b43673ee2a24f97a70ea214fd4f17760e70f",
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
      "binding_sha256": "84dd60d44046f586d2c16e9303152b29d63c7c58b48706b2193c64a21021e4cc",
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
      "binding_sha256": "83770e219239e1bee8f15b8ab61744d340ad3bf2eba27ac2d8b823bd3c8958ef",
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
      "binding_sha256": "71d1bb8e8bf94f038e1c212c709225d63319f61e23f41ea92839cb076541323e",
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
      "binding_sha256": "574f1c229834fefa66ecd3ec26371c408e63afafcdc6f4d816e9daeddecc71c0",
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
      "binding_sha256": "1d05feb6f7c3ca2c8284a6da71fed5c93c5317367da0c37ac0072559a5c3f705",
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
      "binding_sha256": "33122c9e7d2b4bf80a5d7d4aaefdbd03c0efa7a444e7f7e9aade744d7036a5c5",
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
      "binding_sha256": "7b744893182f468309299f75e3ec6b7bf24c0e0ad933b0e0b0439990cb3d6190",
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
      "binding_sha256": "d96cba969d61019dadde0098e9be171b7eed0a27e9dd284d7fa912b93c335ae1",
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
      "binding_sha256": "62fea94686d0391dd0ffe17873f67480a022391a5d2582bd691c207ab76494f1",
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
      "binding_sha256": "5f77d8196d0d1e1dd526488dbf863e5ad5a01ef7e9fa46096dbe0423d9c3b439",
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
      "binding_sha256": "578cb71adba146944e387d6093a1c16919cd2e7d1ecb70e6ebd8a2ea28aa3b09",
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
      "binding_sha256": "91bd575d4658b644604cee794cb1b10c45beb1344225c3234a90d01576285c21",
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
      "binding_sha256": "015173c03431d256a95120ff6c2f3eb7acb76b172d544216c8a6c119fdc92605",
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
      "binding_sha256": "80b97d4717f9d5a240f4eb9b8d399e4f6fc43c88b0cf83f901ef9bc576f21142",
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
      "binding_sha256": "70821da5c74c9fe37e7d97c48c675fe687d49242f4e0c143357b2619541ca0d5",
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
      "binding_sha256": "9f252498b0877894a56ba50545e81f404f18f6cd6b99d1e885952f9b55a1654b",
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
      "binding_sha256": "7e9f825dcf534edb261141d767a3028058e975c9d81825f23468105a9b9611d2",
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
      "binding_sha256": "4afeecff409749e1c781f230b34d43abcfdaf5faee4218ab050de7386d55a09b",
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
      "binding_sha256": "427e6299f8e2fb53c74fb39de67c1028d752c92fc4d66f973229c49f615e1f43",
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
      "binding_sha256": "d33237aaff419bd82fe542271ba8a737462e5cd1969f2d8eb1f58c6876f98460",
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
      "binding_sha256": "89237828d2a7492f05b70c76a9cfab407cdad3405e2317e6a2f74c0118c0074f",
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
      "binding_sha256": "f50aa19b1d4c441248a568abda74ace08add8608572e06fbe99152a6dc79c205",
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
      "binding_sha256": "6d5bf3fa21d3d86d306e065f414cb641a9046d043be15ab3e9e2b7ba9b3d709d",
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
      "binding_sha256": "517b7acb8145425218bcb38bdfea6f591d8d97672577a7a3a3a3c9d9ce817c79",
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
      "binding_sha256": "9efbc90b0e6044d803326dfd89ba71248fd6a85e6f37b12accb950b6a9fcd0da",
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
      "binding_sha256": "bc955ddd6073fe5ce9dc755193b29c7038d2a873fd95599e28063c7f1ec31474",
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
      "binding_sha256": "5621e653f2c5c5c70c9230f5ce574b00a89552d7f8a28d777cff5b7061948f6f",
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
      "binding_sha256": "43c841efab68ff8daa8de076ff28642d5e93cca089b8a37aa160f23391835b0f",
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
      "binding_sha256": "0a5378d4138f1c476d9ffc0a061e7ecbea8bf45f786bfe6d47daad153a473451",
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
      "binding_sha256": "930b705fc90204eb168fc4de21577dafc3a754a5ab19747649afd8a69a75fba1",
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
      "binding_sha256": "0840b32fce6d3b902cb79b48772a4e2db07f34145ad3bb59a2f43fbf9625568d",
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
      "binding_sha256": "330f41397debb07b79dd207939ac9dae3b0e3cce66da81e864e50d020c641189",
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
      "binding_sha256": "826b9df0660ca052fc46ed751bd3415c831774c0eb6d4e04ba6c9eb66a183a70",
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
      "binding_sha256": "60b3a8f0c83cad856b3d34906f4178169b975637dd66fbbea142eb9c48f1369d",
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
      "binding_sha256": "a9a14115e20e12af918e635b7b64716067367439684072fb40d51a45eeeb44b7",
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
      "binding_sha256": "380f9bb78f37b8846499b358e2ce6c8c2017c0c184d079b8175b51d53bde5b55",
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
      "binding_sha256": "9346cd7b10c4019bd70c1fdf0089b37abd48e9da6f88b2f755b53af7ce8d12c6",
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
      "binding_sha256": "a41032e759a7069487cbefb18e394a7054dd819551d3e02039fed1f212a107a8",
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
      "binding_sha256": "74b1cf01004fe795218510c13d5505e8cb72e93cf8c13a4a6f5cc4ac45a92368",
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
      "binding_sha256": "4ebbaac4c8b2befd480684b5ea54fe50a9339dfcddee6a52f7b6fb166de0ac44",
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
      "binding_sha256": "27daab56b20a97d118c57d31f5fca15534322a8221d14961c7c55d5ad108e4fb",
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
      "binding_sha256": "c5f6a5ef21f3ec09294ff46471b2859febe103747c209baac67d1affc555a3d5",
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
      "binding_sha256": "570595f5760a1bd7d13c9f4eb675a0ef102de1989c8cb77c4a3aa7de33dcbde9",
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
      "binding_sha256": "b08bd63766580845850852178975dfec5b62033a7b1c02995693c0a41daf07b4",
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
      "binding_sha256": "8abe5b4173557ecd77d47e77c26a300bcfd03b4752091b1c3c82a1093e5b66d0",
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
      "binding_sha256": "8f0ddfc589bbe613555aefaa65b5dc26934534371b2d077b2dd46a820c79a2ee",
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
      "binding_sha256": "93eeb3375a892018f58856bb3b7629e3c06271370a179782334eef9c3786cff5",
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
      "binding_sha256": "4e511f5c1f807ddb247d05c6fac9cb836d19d86965e5352b05c283d21dfdcc57",
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
      "binding_sha256": "28819a81cc2a4a2a625d67e46a7b888729c5b520dec5fd036e0f4e01d17528d1",
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
      "binding_sha256": "33cedd4309e3d77e176b7a087d7b8e22d767ec16a089069d01951a8fa93f4314",
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
      "binding_sha256": "a2f855f61e3ef4426130f582f70dd4b91edef9ae5d58e0947cbaa386d948658a",
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
      "binding_sha256": "cd765f7f998a16a21fc5a7ef78482e976183eec71629a831d4f9e7ff57575124",
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
      "binding_sha256": "04fc2070779958c5b5dd8fc579c27de979c95506d40aedff89e28a59273ea83a",
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
      "binding_sha256": "a24c2e82579d4b322b5b0d21794ad30994e9475ff9d0683c680e421a0ecfd78f",
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
      "binding_sha256": "7627a2082c23d5bcd89b82c1315de0f2bf6f45764bbae1b83c805c6d4987b0b1",
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
      "binding_sha256": "b008c29a94a502f6047067fc8cbbc638473b50267dc2d826406ebbea4bd7f492",
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
      "binding_sha256": "b23c5519c456437746277de76e7223dc61e674eec0860198e4f07514aafbc5cd",
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
      "binding_sha256": "d69ed68079b1869f06c872fe26f498caf3fa29866bdf184905b05edb540d6509",
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
      "binding_sha256": "2f7aa062956ebd01dbcdde89afdc5415949fc72c7c420a7d3b1bacb52131b7d8",
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
      "binding_sha256": "f0d3254620c71c7bea3c2ed5ccc227a25d232a36e24868a028472568107b9428",
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
      "binding_sha256": "022ed9c20ee91460ae377be26a10c72903ac650c0d6a31c0981e21599a8cb9a2",
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
      "binding_sha256": "30680fe72cec7b557ad1434f34fb2bd651d1a4cd5aafb541a70b4268225a0be0",
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
      "binding_sha256": "fa2546391ffeafff9e57312bc2fcd43d4b5cf2f6f519d06ac8f7c6a251ac52d4",
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
      "binding_sha256": "a182a2aa79c8c5e9b8571d614303ab79775bdab6347c312fc5b70f558ff18062",
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
      "binding_sha256": "49a56f0547aa42b5d105efcafe9dab822159561ce600f72756cc47d4989e36e3",
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
      "binding_sha256": "2eff7d0b12ea88751f46d3be4406b6f454f965700a2f5093570a4c26c2f6393c",
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
      "binding_sha256": "1d3a9c0b3de641a34aef748e07fe96e60160f92a65f00c082f21681e8124649e",
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
      "binding_sha256": "f1c43a8c10179376a0f14adba329e5ac967d4b9ecc32adf0d40872661071422d",
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
      "binding_sha256": "3bb9ce64f2c6301dfe14f3de460ffe42199f8bb5b837a2189b475e60067fc36d",
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
      "binding_sha256": "b33f84fe01128f4506a334d587e8f10301721c771f505dd4c6b58e15f0d11e0e",
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
      "binding_sha256": "67e1bf6a736b0c31d73fe5e7786e9afce7267a1703fe598fb684c359163d8fd5",
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
      "binding_sha256": "a6ed3f9cfe25dd5c791457614a2161725d89701511d7f6bd54b46bc4b76aae78",
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
      "binding_sha256": "4d99f063f082dbdf9bbfb19b9eb9e29c9d753c30246ddb690f0879ac22926496",
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
      "binding_sha256": "fdf31c9848ecc66a264823ecf1ab8b3d0eb7101cade562efc694a26ed6d14b1c",
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
      "binding_sha256": "3306ac5bb31c9d3ad453e7237f8936a20f375e2e9dd7e8135cd8019b75d7b750",
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
      "binding_sha256": "65c461759f9efb2353ff5ceaaa78c6c2dc4dd440e879f158ecaf6fdc62c3044e",
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
      "binding_sha256": "6df853c22510e09f8635efe822900b57d4106d76315f9b661b9192e4c53e4afc",
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
      "binding_sha256": "63f109f0421771d06822fe1079e14c902430e1e18522a3d7d1809d0edfbff5aa",
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
      "binding_sha256": "a8f6764ed9ffecd79e18537ea1ce7b2900e64ca736bf004d9b27461ae83e31dc",
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
      "binding_sha256": "28adc99439a3d09340081c7e85220ec062623f20bb37d2dd8521fe68b4b15b84",
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
      "binding_sha256": "689618dfff298e54edbb224a3c37f1949f4d173b648122626627380f23da761e",
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
      "binding_sha256": "05f0774078b1d8f9672713c7c1548f21eb82b5ba74a46e1d048e3f2492226517",
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
      "binding_sha256": "b04470c5b19bacb1d4ede3bc2c43faf14460806237ec6c63f2060f2d1f45885a",
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
      "binding_sha256": "75d2d7795b858a37223e99dfaf4fe0a0223a4bfadd7c62c547a398cbd1fff69d",
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
      "binding_sha256": "43e33e34cfd366634eec5ba1c02d76098aebd84465176712fd9717cc68f29e8c",
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
      "binding_sha256": "0542c25f1cb511ec0446d6a60f74a5b71373894628100c1da5162812c7f32051",
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
      "binding_sha256": "f7a641e2adb3c48265ec2c3bc1be88a253763df198f108e44bcf99d3f11555f1",
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
      "binding_sha256": "878b357c47afa30fd0106e61e0d051d6a60568e479a52dc6a9dcb887a2d4354a",
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
      "binding_sha256": "8488f182bea0ba054feb2372336041a5cbc722cf281d22509aa34bd5f8c168fe",
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
      "binding_sha256": "dd29eb21d31655bc4f5481491ef7789aa6d6a7a53016333e47f153f9906d38e5",
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
      "binding_sha256": "78fbcd7740dbccb0b38172f19bd68300e59f61a46db292e9a070d88aeb22bd5f",
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
      "binding_sha256": "844eaaca85e8339785dbe03b3c633ea4ee8118410af7ad5748ce362784abef6f",
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
      "binding_sha256": "fbaf7160c8d269efa8eb56fec90383b9c5884e49b143bb249637596b26e9def3",
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
      "binding_sha256": "15ecd5a5e0ef70858b88550c5a7de8acde5b24467efccc5966912d2280c8f5a9",
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
      "binding_sha256": "c467cb379df6275eb3fa8393bfb1a3f3086b845209e7b6fa03265cda59e17b82",
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
      "binding_sha256": "649e1c94346934bb73b7207e4c5c203afccaccdabd92196e8300d1590f17a552",
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
      "binding_sha256": "1e545072537b21bb9acafdbc45f9d8fe6a1463e59daeb162d7cf206039b3c386",
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
      "binding_sha256": "d086c23ed502e5fb146e185375320c32da2d566b9911e8b2f4225ccef4c09c72",
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
      "binding_sha256": "9809beceb8c0fd6da47e78eeb544bc53481c27322956dc05f9ad86a469344243",
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
      "binding_sha256": "dfca4c3ab594f2f1bcad299973c5ccb2e221f8c46226765de86a8cb9a5ee9fcb",
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
      "binding_sha256": "71307d4abf742ec9eab18e397d89b46c3e5d7df2d183cc852c8731cab8faae03",
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
      "binding_sha256": "1927af8614cd3ad65f14b646f3221b92ae0b4a2e7e147d17771192fcc4da023e",
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
      "binding_sha256": "1dafa54c35c0b2c0967cd95ecb61269fb9b2e126001ee6f5afdc68727ac85854",
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
      "binding_sha256": "c6acceeb2f4b79c84c587baa2941b42ccba2822edf2b698dfedb8e9c9b140ad1",
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
      "binding_sha256": "a8ef36e5763d7d7fe7fab3f2a5f03c34da0cc0a13ae86d94537c0985c5f1af30",
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
      "binding_sha256": "b5fbb9e3d02f577b476550d096e8f6e4a0bbc2460212ffcd90e5fa4acf405d3f",
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
      "binding_sha256": "f2d1b769014d549772432f5781ca5b9203c115d4d36a622783fd3caff045c11c",
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
      "binding_sha256": "b759e1c30906bfdbbdba07d61536231d1c5040b05323ccd2a643827d3b3b8f39",
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
      "binding_sha256": "e74e5bdfb1b50aa4de7544bfd54815a3c4e6a2fa6861f089b7d67ef228e1785e",
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
      "binding_sha256": "68732485f7a319d4c0b6c9d691b3f858835d10db231ca72b223afbff9fd895b9",
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
      "binding_sha256": "faac73aa0c383f093d94398c7be90d3e2ecc36c200dc64dddcfa08b6a45f193f",
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
      "binding_sha256": "52aa3048ab8bd3edfb3d667591213981ba1e3993c4e3d7aec1f9b300f6b7ccef",
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
      "binding_sha256": "6420e6624da7ba748287c73ab53f2eb939c86bd097a3ac5ea57aa0fb77819071",
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
      "binding_sha256": "df9e0e741ad5104c0f22f5b5daa6c41b4d6cb97f449e518c10de1c2e6474ec78",
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
      "binding_sha256": "ad5d6fafb1e1e5ee44efc270a37fdb3e442f130c58f8b791d36f40107333af93",
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
      "binding_sha256": "9209afa4f1b6c7b93def29403a93effa433e3c9690cc34ebead6c04815ab9f49",
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
      "binding_sha256": "59580f52dcb6ae3015d76c373dd350c3374dadb47cea5ecd04f7f94d471a430b",
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
      "binding_sha256": "83b7640df0d9619d621369a083c321477758e43051d3c61ee22714d79e9e1f37",
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
      "binding_sha256": "3c0278e9efbc2570b532b121a36a967478d111bede1b462cb07f757c3490788e",
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
      "binding_sha256": "672633d0fc7e8c7a66f722a26ff9f6c07afdeef5e59c5cdd06bfa24c187c04aa",
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
      "binding_sha256": "7eb421946640a859eced59918b3bbbd630d4567388782a331f603d8ef2d8163f",
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
      "binding_sha256": "72da55175d86fa65fdc280175ec08e7572f7998cc02be84de78bfd42ec0c10f0",
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
      "binding_sha256": "8f7dae5d23041147d0978e0ffc2ac5a35a421fb500c876356d06a39a98fa8d6f",
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
      "binding_sha256": "55bee27275251c989d1e1143510d062d9f0cce5e50e35de748388257b2f682fe",
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
      "binding_sha256": "7ec4716c7c188d0c750ede0de353c92ee7827af1d73a6cba801960b82f705dee",
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
      "binding_sha256": "31113f47007d14c527fc4f7e20378604ddbaf820d424b0638cd0c48179656ba7",
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
      "binding_sha256": "bfc1ff9f754233fcae2d5b5ab359081187fa6a8350cd72b7079cbfb6bcc591ec",
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
      "binding_sha256": "ee834650302be5970552568c4eb49608262d25e90c57f9e57afb13d02fa531e9",
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
      "binding_sha256": "f0b63c6ad37a955741caa59678b1d7224bddf069ff4e0810f7725a41fb29e1e1",
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
      "binding_sha256": "5e7e92270816a25d2876908f8613ea94fd101b303f5a96eb5364b31798605fc9",
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
      "binding_sha256": "fce78262f6ddd48c15010b253f1340faf1eeed6a709583d7553a4276f84323a2",
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
      "binding_sha256": "f8fa0d239ac15fb1e3aefe88d95479ec98042762c41c0512cd7c48e934d8a1d5",
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
      "binding_sha256": "b4ef04ea7fdaeefc777cc13fef7c25234e3ff0b099e57f3c9548707574abce11",
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
      "binding_sha256": "ef9bd17c6200bbfaf517cd60d32cb80fea33d08ac921e79cad1e15cbcb1e6a9c",
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
      "binding_sha256": "ae7b3d35b51af3e5b2c79d5072b48b78acb12455bc520a8b9b7a571224201cb3",
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
      "binding_sha256": "725e27e5b907236f0bca6996d39562088975a756fd5d3686e58a1fa38e2159e7",
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
      "binding_sha256": "8c60b479a4f7c4fa2d5176de94d0099195033e158b8ab09298c33d8b05da08f8",
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
      "binding_sha256": "57be48a3c1a32a2c215721c1feb8eee270271298c063c7d75b1582488e44397d",
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
      "binding_sha256": "9299ad3d43a637b643f75904558ff69021123f00e24f9714331fee63a0922bfd",
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
      "binding_sha256": "cff543e150748ae4d7fe62cf5de4b8361b0223f3e2a9a9336384ba30621ef4d9",
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
      "binding_sha256": "fa92674fde9e39ceecf9f59cdd5182e2ad84919c712de024b1bf2b8bd2763754",
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
      "binding_sha256": "21caa8944962805dfbe84799ccd025187f92bb760959b9b87ec480e6bbc0ca89",
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
      "binding_sha256": "efe1b7cc3b6fcf1ec23385248461af20884b467fc5bf10a97dd4e40194fd391c",
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
      "binding_sha256": "729df943f531cbb681f28db9f8dd42fbe2a71e2760d3f7e2ec0ee3c9d5ad4543",
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
      "binding_sha256": "4ca16c10ba9a6c443f221256dd718bcbcf73de25fc8a84ed4862d30b96d63501",
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
      "binding_sha256": "7f57f4110c8b7d90681456b52282f352c49d14e4373e3373697dcb9a255d34d6",
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
      "binding_sha256": "c2a2ca652fc3c3270daf0c1d61e9fded7c9cdd2ed04f92ad14029ad984ce447b",
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
      "binding_sha256": "45c8b679751fd261813cc5de8fa06935070c82805d327f2495c7fd6f97564629",
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
      "binding_sha256": "dfcee48d6f349b7e85e82409105ff43ff20249f99f235c43d487f30d8552de9f",
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
      "binding_sha256": "018aba90eb8226c2a8b3575f3b61d8c06e185d38de3728d99c67d85f3fc77ff7",
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
      "binding_sha256": "75431df9d62f88afcedc682fbbfd7c64b4af8af312f94f3a73e338326d02a68e",
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
      "binding_sha256": "57174cb2f825d1f6e4a8d62e45e17b25dbfae622b9def53018d57093f28cf733",
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
      "binding_sha256": "ad0ec17c530f63decf2b400bcd1b81d9d2ea0b752e29b6559aef50ca2347ecf6",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:730e7c9cc110e14d185ecf65e66abb9e95627899f3c9129cc69a7d1e5ec867d8",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "src/filesystem/index.ts: MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete"
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
    "evidence_sha256": "36a7f1c53ead0736fbc726a7231d4c7b1cac6f0bc4a540b067070c0aef713992",
    "image_limits": {},
    "manifest_sha256": "94a847a7c8e4928607dc944ccd091431bcb04f86c2cba8472949a447056c32f5",
    "scan_id": "ac0543d58433de601aafb67d7a6184a1fddc7095628a3912c50b3f00860a8ef8",
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

