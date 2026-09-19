# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `7d6921664d19717efdeb6ebcc294497b29d015e6c99d019619019959ede0f635`

This is static security triage, not certification or proof that a system is secure.

## Executive assessment

### Open findings need investigation

The scanner found 61 open patterns, with no open critical/high detections\. Review applicability, address the causes, and validate the proposed defenses\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 61 | 0 | 14 | 0 | 0 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

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
