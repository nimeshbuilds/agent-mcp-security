# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `a821a7998899281364430f5dddcd4f13e6c71cb1a1e7411536de5289f8e83d58`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Open findings need investigation

The scanner found 15 open patterns, with no open critical/high detections\. Review applicability, address the causes, and validate the proposed defenses\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 15 | 0 | 1 | 0 | 0 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 15/15 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Supply chain: 15. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 0; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P3 | [AI025: Direct dependency is not exactly pinned](#group-35a2b5731941) (source) | 15 | Check the effective install command and lockfile; enforce a verified resolution and document intentionally flexible development declarations\. | Dependency/build owner |

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

<a id="group-35a2b5731941"></a>

### AI025: Direct dependency is not exactly pinned

**LOW** · open · 15 occurrences · source

**Observed evidence:** [ui/package\.json:17](#finding-885fd1ff8c680557), [ui/package\.json:18](#finding-e2aa2242d12f944e), [ui/package\.json:19](#finding-0eeb21b69e1f8516), [ui/package\.json:20](#finding-5b02dd257b15d5ed), [ui/package\.json:21](#finding-eab38ca94c25e0b1), [ui/package\.json:22](#finding-016b4e22b5b27798), [ui/package\.json:23](#finding-10892c7058ebee51), [ui/package\.json:24](#finding-b70e2107b958086e), [ui/package\.json:27](#finding-471abcedf1bf7a9c), [ui/package\.json:28](#finding-6d032baac500bca9), [ui/package\.json:29](#finding-8043529f7815dfb7), [ui/package\.json:30](#finding-17950c92824cb6b1), [ui/package\.json:31](#finding-3f4472e98ae31597), [ui/package\.json:32](#finding-5814efbb2feef3f1), [ui/package\.json:33](#finding-e62299abdd2414e5)

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
| Open deterministic findings | 15 | Observed patterns requiring review; 0 critical/high. No severity weights or estimated compromise probability are assigned. |
| Partial deterministic mapping reach | 45.45% (30/66) | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |
| Optional AI answer coverage | 0.00% (0/132) | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |

**Selected scope:** 47 rules (47 active), 66 controls (66 active), 132 active acceptance checks. The selected static scope completed. Recorded coverage gaps: 0.

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

Scanned **156 files**; **15 open findings**, **0 suppressed findings**, and **0 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 15 | 0 |

Source I/O: **2086786 bytes read**, **2086786 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 1 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| generic\_text | 136 | Generic secret/URL signals, bounded English skill/instruction directives and selected Spanish/French/German override forms; no general translation\. Language\-specific execution/dataflow is not analyzed\. |
| javascript\_lexical | 12 | Bounded JavaScript/TypeScript tokens, calls, configuration and direct\-return function\-wrapper summaries; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 7 | Parsed JSON/JSONC fields, selected configuration rules and recognized tool/input\-schema descriptions; runtime values and referenced files are not resolved\. |

Severity failure threshold: **high** · Process exit code: **0**.

A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

<a id="finding-885fd1ff8c680557"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:17–17 · Finding ID: `7b0fae91f2cabbd6a542b53c`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @github/markdown\-toolbar\-element\. A lockfile may pin its resolved version\.

```text
    "@github/markdown-toolbar-element": "^2.2.3",
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

<a id="finding-e2aa2242d12f944e"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:18–18 · Finding ID: `fc99c43368b10dce0d91882c`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @modelcontextprotocol/ext\-apps\. A lockfile may pin its resolved version\.

```text
    "@modelcontextprotocol/ext-apps": "^1.7.2",
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

<a id="finding-0eeb21b69e1f8516"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:19–19 · Finding ID: `ee4c762926aea9ae5fb706ab`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @primer/octicons\-react\. A lockfile may pin its resolved version\.

```text
    "@primer/octicons-react": "^19.0.0",
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

<a id="finding-5b02dd257b15d5ed"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:20–20 · Finding ID: `2191362e772c695d302d6156`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @primer/react\. A lockfile may pin its resolved version\.

```text
    "@primer/react": "^36.0.0",
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

<a id="finding-eab38ca94c25e0b1"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:21–21 · Finding ID: `ab9645a9bbd122fb1bb9ae31`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: react\. A lockfile may pin its resolved version\.

```text
    "react": "^18.0.0",
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

<a id="finding-016b4e22b5b27798"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:22–22 · Finding ID: `a0dcbaea3b4035b68a8e7614`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: react\-dom\. A lockfile may pin its resolved version\.

```text
    "react-dom": "^18.0.0",
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

<a id="finding-10892c7058ebee51"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:23–23 · Finding ID: `24d211a4b8c1639e01ae5601`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: react\-markdown\. A lockfile may pin its resolved version\.

```text
    "react-markdown": "^10.1.0",
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

<a id="finding-b70e2107b958086e"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:24–24 · Finding ID: `f1877494f91dc313d8307dc0`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: remark\-gfm\. A lockfile may pin its resolved version\.

```text
    "remark-gfm": "^4.0.1"
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

<a id="finding-471abcedf1bf7a9c"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:27–27 · Finding ID: `32960660d02c89436915407f`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/node\. A lockfile may pin its resolved version\.

```text
    "@types/node": "^25.2.0",
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

<a id="finding-6d032baac500bca9"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:28–28 · Finding ID: `719e873f7809682295fc4b6d`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/react\. A lockfile may pin its resolved version\.

```text
    "@types/react": "^18.0.0",
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

<a id="finding-8043529f7815dfb7"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:29–29 · Finding ID: `382befcbc606c75fe87ef11e`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @types/react\-dom\. A lockfile may pin its resolved version\.

```text
    "@types/react-dom": "^18.0.0",
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

<a id="finding-17950c92824cb6b1"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:30–30 · Finding ID: `9eccc82fb8f49a2154fb4cb6`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: @vitejs/plugin\-react\. A lockfile may pin its resolved version\.

```text
    "@vitejs/plugin-react": "^6.0.2",
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

<a id="finding-3f4472e98ae31597"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:31–31 · Finding ID: `1d948705e50af0cc089ac09a`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: typescript\. A lockfile may pin its resolved version\.

```text
    "typescript": "^5.7.0",
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

<a id="finding-5814efbb2feef3f1"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:32–32 · Finding ID: `c9f1720f37736ca8a9099d87`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: vite\. A lockfile may pin its resolved version\.

```text
    "vite": "^8.0.16",
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

<a id="finding-e62299abdd2414e5"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: ui/package\.json:33–33 · Finding ID: `71a47f1998d31d071cb167f0`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\. Dependency: vite\-plugin\-singlefile\. A lockfile may pin its resolved version\.

```text
    "vite-plugin-singlefile": "^2.3.3"
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

Open finding IDs: 7b0fae91f2cabbd6a542b53c, fc99c43368b10dce0d91882c, ee4c762926aea9ae5fb706ab, 2191362e772c695d302d6156, ab9645a9bbd122fb1bb9ae31, a0dcbaea3b4035b68a8e7614, 24d211a4b8c1639e01ae5601, f1877494f91dc313d8307dc0, 32960660d02c89436915407f, 719e873f7809682295fc4b6d, 382befcbc606c75fe87ef11e, 9eccc82fb8f49a2154fb4cb6, 1d948705e50af0cc089ac09a, c9f1720f37736ca8a9099d87, 71a47f1998d31d071cb167f0
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

Dependency manifests: 4; agent/MCP signal files: 67.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

None.

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|
| internal/oauth/templates/error\.html | unsupported\_extension | outside scope |
| internal/oauth/templates/success\.html | unsupported\_extension | outside scope |
| pkg/github/ui\_dist/\.placeholder\.html | unsupported\_extension | outside scope |
| ui/src/apps/get\-me/index\.html | unsupported\_extension | outside scope |
| ui/src/apps/issue\-write/index\.html | unsupported\_extension | outside scope |
| ui/src/apps/pr\-edit/index\.html | unsupported\_extension | outside scope |
| ui/src/apps/pr\-write/index\.html | unsupported\_extension | outside scope |

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
      "binding_sha256": "d41000477fa25158e38dd0902a81da42010d7b6504d6ddf613c7d90e922559e1",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:7b0fae91f2cabbd6a542b53c",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:17"
    },
    {
      "binding_sha256": "096713561353446621c98e647fde4b5c49543b786f79e00829edffad444d1d99",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:fc99c43368b10dce0d91882c",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:18"
    },
    {
      "binding_sha256": "91ec477b1da82e4d9d910cb1aa164e830d6498c86ae6a2bdcbce01e03448f6dc",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:ee4c762926aea9ae5fb706ab",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:19"
    },
    {
      "binding_sha256": "955977f0d9470d54e37577d693968b35b529c62944682937a46c3f5d957cf4d7",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2191362e772c695d302d6156",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:20"
    },
    {
      "binding_sha256": "9dc71512216d1a93215c523161932adcc8ea0ff0e43274c4511f3d5481ae38a0",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:ab9645a9bbd122fb1bb9ae31",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:21"
    },
    {
      "binding_sha256": "5c7e6091b1d4ae73410483279c20eb822d19465270ebec25cdfc5871223e08d4",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:a0dcbaea3b4035b68a8e7614",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:22"
    },
    {
      "binding_sha256": "1aeb06ab676584923e0261e97c86e3b50ae546015a3b7855d5fd52a3728474bb",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:24d211a4b8c1639e01ae5601",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:23"
    },
    {
      "binding_sha256": "6c65411e0dbb82563cd639766a3a4a127316a120998f9cd11fab20638416dee5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:f1877494f91dc313d8307dc0",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:24"
    },
    {
      "binding_sha256": "3d6f26953533fea89af671bec5e5998ed113cd1df37c7833bcf83cf2b5f4f1d5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:32960660d02c89436915407f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:27"
    },
    {
      "binding_sha256": "3249f8b1420aba1e9bf341133524b0dc507ec18f9246828128baf9f0d39513ee",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:719e873f7809682295fc4b6d",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:28"
    },
    {
      "binding_sha256": "977ba1303987477add79e85ab81f3290188c16c7aff29f60299c63605ba06eb0",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:382befcbc606c75fe87ef11e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:29"
    },
    {
      "binding_sha256": "9413d34f8f69c5b979e7046626550b1d6027c70fc940d6eb5fc65f5b22e6c54f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:9eccc82fb8f49a2154fb4cb6",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:30"
    },
    {
      "binding_sha256": "42354ff13627de3c33f279e89028ad7f3aafb37225794883d5eb883666c33da2",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1d948705e50af0cc089ac09a",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:31"
    },
    {
      "binding_sha256": "c7c65f0aa13bb97aee9bfa65d16ae7d430faadf3cbf22ca416659ce7d19431db",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c9f1720f37736ca8a9099d87",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:32"
    },
    {
      "binding_sha256": "b34dc07b3c211e698e5f51750221338732f7eaf47d19a50e2888eae2a46a0b75",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:71a47f1998d31d071cb167f0",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI025 Direct dependency is not exactly pinned \u2014 ui/package.json:33"
    },
    {
      "binding_sha256": "ef9334639b842911dfcae5db68d1b5ebbc5641b3f1307f4ef07dd8a13e0b9589",
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
      "binding_sha256": "405dc3f3b4acc577e8656608070832d322381d71a72f74d7e033ef753cc94ee9",
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
      "binding_sha256": "603cd06266ec59892184730e5463e11d1a6907e44e3d58685ec3292f7cdf921a",
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
      "binding_sha256": "67ac4267091f32d202f4da028e23fd231a519b6d3dad6b2f78c47b878b628252",
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
      "binding_sha256": "12273070637be63b34cd73a9dba558d05d0ecabd02290c8617c1c7eb7520099a",
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
      "binding_sha256": "6bfef20caec53b5e2793b1533c252d1e4a860323b99a6199a6efccc21c241389",
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
      "binding_sha256": "32ffeb3da5d19642f2a89838c68006e4cf289719cd41af0da0f2539a46410551",
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
      "binding_sha256": "c9517c937a1b3e81cefce40de7c9cfe13770fe7dc93a367c6f56539c08ca27af",
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
      "binding_sha256": "8acfe220a4364159cef9b160ba9542aeb4cd372788eb6683387abeb0720d00fd",
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
      "binding_sha256": "68c1bf06d0529f694d034a8e882f67278b708cf610eb745196771d1671d80147",
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
      "binding_sha256": "bab679a2f64f21429a2b3c8107b963c6c5170484363be9f9b2bd0d9fcb8b5890",
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
      "binding_sha256": "b0806c297bda23dd6e68fa90a07b9edcd4736c183cb8c9fe03af5ec297efc578",
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
      "binding_sha256": "7f5cb79dc30f06de701f8caaf7b063b0cfe043e56a95a8ee8960649ae212e29f",
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
      "binding_sha256": "8c98113bc930ae8c71da22689709c4751fe9dab61d67c4eb39e994cd2a3fb4ea",
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
      "binding_sha256": "9a21bfafc4e2db2033392c771d89513f98515e5bdf5486275b9d6ddd99fbc87a",
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
      "binding_sha256": "c821445c087bb20ecf9cbe4a01172ac1c3956afe0fcc600d6a5cc08b39c30fb2",
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
      "binding_sha256": "adb2ebf2b922a343b4c49ffe6671752d0d73fce6dc9cc9682063a036544bd4a9",
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
      "binding_sha256": "da77079d35bb45dda73cba389e67d156f138175b7ff7b03e7d5975a2aeb66cb9",
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
      "binding_sha256": "4d94048d1d6c540dcea3891d621776681b9989faefd79dff616edca91e7b2def",
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
      "binding_sha256": "b7798d8630b05f595c7bd6570fc8a185197da2aed519ed63c55379e7e5251006",
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
      "binding_sha256": "4acc13135a24d366fbf8b6bf768d9a0f21cc25c4cafef12e074a31c43718c503",
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
      "binding_sha256": "7253459f497375892ebc631e9e9c89d8ce08db549ce681d71133d1627b0f1ecd",
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
      "binding_sha256": "741ed6afbc730835a971d690dd059c32f466ff61743e93355f5b8b5f58d09dd1",
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
      "binding_sha256": "d9f5efc106ab9b950145e788be5049658d469e315f75a542a85896a8c25a1ced",
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
      "binding_sha256": "7bcd69d474f0a8e76f639006f078b48e92af609f0705fd6948d70edfdca02f39",
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
      "binding_sha256": "2d886d3a8a5813cf090c33d60bb3bf61e8623444ff8069b9747f6880feee8455",
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
      "binding_sha256": "8b174276a785a551f1153fc1b4e9867f6682979e79060e8751d240e47371f41b",
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
      "binding_sha256": "35fc9fb2c6248370ee85103abee19c233ce66474b25b1ac012ac6bca7c3cbbfe",
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
      "binding_sha256": "4780744ee36a2ecbed8982838e26747e484e78aba19be876a4cc3435df5d1d82",
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
      "binding_sha256": "3488397017b83254361ecea5b87cd3b9d422480bcb0480d36f8fa8db081c14a1",
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
      "binding_sha256": "215789c08ccd473000167541e528a5b7b9bb3aa54a45ec8eca2e8b0493268195",
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
      "binding_sha256": "deafeb9a81c7df5bd1c431772ff1d8485e0fdd0588effebf4650314a8269df72",
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
      "binding_sha256": "e2fd5b26873397726bf5032e2e5b3d525e36c0c94f77291d64e70d95324c0c81",
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
      "binding_sha256": "7c89129c03e79015c918820d46fb5601236e8ac48afdafc1778fd3f0fc81844e",
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
      "binding_sha256": "301febe3edd5b88c1ff821dd510704461d360c012bcd367470ede8372c8abf28",
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
      "binding_sha256": "06d2534e140f2839b8c109fda8f0e25d484adafdcd402444bea84388f6ceeee0",
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
      "binding_sha256": "6bc60df63cbcf884adc1f21c3a4afa1beb5817e9efd637915a94784c1e808e1e",
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
      "binding_sha256": "79c71055f0a58f90a45e3addfc1a08dfbf00e9ccb498b13ffbc152d0dbd323b5",
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
      "binding_sha256": "2ba0e1b511918bfa85c197cd946530ec3e267e25f832adea3eeded7dbff7edd6",
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
      "binding_sha256": "76c9f5dda6cb070f72a98e3e2425997f0e1ca4703c97a30503843ef0b0c267ff",
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
      "binding_sha256": "e58f3707be32509b8fc5fb81cca778cd845704878893cecec2256cae795e29f6",
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
      "binding_sha256": "acde58b31a7b63921f3f77f072f625ddf2902b066105ae7877ebf04f09764158",
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
      "binding_sha256": "7166f9e439074a28fc4afd962f60fe4b3434528e6d3508d96be92f2772cea28f",
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
      "binding_sha256": "580ae097e6729cb3f63da6c26883e0ca869fa1292412f6bb4f1427b554a22f3a",
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
      "binding_sha256": "d1a276fd8a2cd9bc91b46be659942e44f5117f3721572f1a8feac62ade6dbbba",
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
      "binding_sha256": "817f954e98d8ff196d6d30892fb15fff08d61fea0733f04b9626da61597e6dca",
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
      "binding_sha256": "decdae8b721bc1417fe0b0daf19fbd4e99a79173f84ca6fcc47009aa4f3d9527",
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
      "binding_sha256": "e1dc31170a00d823cd5cf983a4007debeafbabe27d36f178b2969346848d37d7",
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
      "binding_sha256": "895cfd338497c64b10fd3aabd1547e272b28126fdaab3d6dc47379b7d4157e1f",
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
      "binding_sha256": "4c476ebdaccf29f6c7b0eaeabf09b662ae153338279fa6f731af0c8d22eb4a85",
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
      "binding_sha256": "65971e35317e49ae8c31408d1813c0ae513649ca39a5e474e3feac7002fa8a76",
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
      "binding_sha256": "438c64777eb985d26332128d3d35f874db6e34d77b71ed7ebebbcf103e329485",
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
      "binding_sha256": "ad65ae57d80595466f11ed0f4308d8cbca43a37cf44b3416fea218b71a25cbe8",
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
      "binding_sha256": "b6b1b56a3b27a903763ee01a9d6121ae4f3da78816a80b82913ee8a214a9b8a2",
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
      "binding_sha256": "d39169aae7497e634d78e7f796f30bfba45e49aa90fce59d62aacaa6eea310d4",
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
      "binding_sha256": "c7c0cb59ddfdcb0c4a062fc82732114d5b8c52f5baa3fb1827f8ddbec1714f57",
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
      "binding_sha256": "2e9e7f33d759e13960ab6f84eb57c396787ed0711c0aa95dd169267714083581",
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
      "binding_sha256": "d2b93c705b1a5fb6dacb521054b867b9d98bf9de3f0359ee54d55c65ab610485",
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
      "binding_sha256": "5a8098398b303f288069303330b5e098f33c0b1481bcca0e1877c87533fc2024",
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
      "binding_sha256": "90ce43e0a0a256d56bb62849bc54cf01611c8cb183f22724d5f0db776ae3fff7",
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
      "binding_sha256": "f02662dedd1285775d2325a5fd2bc3857b132233952291f175c661474e76f3d9",
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
      "binding_sha256": "5c8abbd1bf1f3b72ce582ec4305e4a36e6ab461232d24c0cbda548d7b2134802",
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
      "binding_sha256": "97f49b18dcfb30fd0f4aa1839cd49c55364010708aba8446e028a72d7ca0b780",
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
      "binding_sha256": "34ceeb6f216913e001c831638cde1d7631537824248d25d1138c31819ccffa2e",
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
      "binding_sha256": "2f0705cb933360e67850a11f4ac1b3e322b36907d78c3ffb948e989dbc5adadc",
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
      "binding_sha256": "e7334961712553dbd275e886db7c0e9da137bfdf59035f7f782c063ab11274d8",
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
      "binding_sha256": "348d139da83fdb6f58bf04315e031bf13b15ac3979a04c77a4c6d363bd123429",
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
      "binding_sha256": "28d951a2510c4d87b9c2da8dd84935516ea8b8d8b2dde9ee58c04afd4faefae1",
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
      "binding_sha256": "cefef80d0966d802de54ff56a25f842587cf89d99774b7d063e9222ed0a30f0f",
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
      "binding_sha256": "07d9be7e074989ab316dba51d093b84b60d3eacb6bcd14f67880869b8ddc78fa",
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
      "binding_sha256": "bab9d291770fcc7d1fdb30a36baecdeb1cf7461f7035479560c90f4599ecd067",
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
      "binding_sha256": "043c1142b23274676a6c6bde9e2471acdf35ba915dc8111fdd02d70c1e6a94ec",
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
      "binding_sha256": "b065abf600b0706a7090412f31f3ae987ddb679ed3e9dc8e0be19f7862038408",
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
      "binding_sha256": "4f48afadfc18286a93b9897e3e4d509ddca1e9d59859ebb9f1b65c7991ec22d0",
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
      "binding_sha256": "cd4bb0ec2607115fa4cf41b87903cebec964c858d22f22e98a83ef0077251682",
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
      "binding_sha256": "e03432a812ad273bc313cacf70f136d84cc977c7d5a1b62e170037d675819b3f",
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
      "binding_sha256": "30bae8f66937d89b1c4a72aac9939c1d656e016870dc942caa720ced4919ba38",
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
      "binding_sha256": "25a5b73e5907456278430da8f1ead4a5ee946a3c4bbdbbae06be7bf20d8aa100",
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
      "binding_sha256": "1181a845879285ae70d38abf59e747e419f6d111e31d664ad053a656fb421aa3",
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
      "binding_sha256": "66d1466af06a9fa424c9cd9855ab8cdd7156bc908a958d66007aafdb83034354",
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
      "binding_sha256": "d73bd3b73b6d8d4de4af558b5583cad046ff7c9e7297001c1d67d6383d3a54a0",
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
      "binding_sha256": "63f3915570ec6b5f21e6716d22df8b55fcf1e001cd0fb9c8a1c7cb6af57c950d",
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
      "binding_sha256": "741c099594638ba121dbe4cc611e27ba2abe67fe4653aeedc2050684e00ec680",
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
      "binding_sha256": "7899602f703d0389a400293747d4db936341c05f4b767f4b6406823c821396d0",
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
      "binding_sha256": "884a538919bb1bb620463be6d0647c9d372c0ff0345a1f0db016773a85b952ec",
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
      "binding_sha256": "97845cb5fa8740061bd0ec80775e54fd3b4ed87aadf4db59029e23e6cfabfad4",
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
      "binding_sha256": "b1a8cf5018e7201a19fa6f013514f43fe4f991f25cae4a77ef1f96c54a76b52e",
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
      "binding_sha256": "f94d816b9292d9d31ce319a2b7f6bc356d729683300d504bab48e8a6a20e16ec",
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
      "binding_sha256": "60eb658ca869f1e0b59b2b64a1ca01e00414c079bb7a9e82223bcd3bab15086f",
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
      "binding_sha256": "bd4f3cba05d20635bc5a81bc1faf6657b515ea9c341c3f3655804d6b1dbc3472",
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
      "binding_sha256": "7e67977b1fa5418a3b721579d3c995abfd71d46bc9acd3f23d36a728b2ba7bde",
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
      "binding_sha256": "a7ffd205595d3755e356e092c8ffb617aaa502f6a82e00960f9e385504323568",
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
      "binding_sha256": "08a45bc5b112465f280d1ec91722e21bad67773ab79a93c7d9ca1ddb0c48b3ac",
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
      "binding_sha256": "ffe902db9051d8243b91b020d5036fef79d5a856646c4f73bf05bc32a1f954c6",
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
      "binding_sha256": "7c02844faac93a53c91701cf71c9a650478b14406b93f5f4340a31567ecabc1a",
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
      "binding_sha256": "77df7d80250546ec3778a3477a0d11512f6a7e2aa01e80a582885dad64805a43",
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
      "binding_sha256": "98a25de07b445f733534b562d84d8b9546c200b9bd0377a5bb56059adafd9502",
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
      "binding_sha256": "9d7b6778e7690df0deae3cd11dc881b8e85aaeccf852bceab478090d778b9f7d",
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
      "binding_sha256": "43fd4a0859a8724b5282476d61df058edd937d644a5ce943cb53213de56a1f0f",
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
      "binding_sha256": "a058245641638ab4ac309c34aab8f311b84d141c93951dd2ee72cb9f991b9dc9",
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
      "binding_sha256": "b37fb0c0f2b30bc007881f1142470333d96d951e9a18fb42a3496cf57cc41059",
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
      "binding_sha256": "09e5d59e65232714f0ca60d344339ba598f825d50d8c9bbaf38cfec7e1e718fb",
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
      "binding_sha256": "508fedcd0f6c079a00c0d3ccdbcb9857a57cfe3fc6d0331a5b26a03398299180",
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
      "binding_sha256": "add632c10cb5434a03a4a6bcf146a0b220b397fa1e5be1f00284590477f39abd",
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
      "binding_sha256": "532acf8ab9eea74f53283b4d1a76912c04875312c11eb34e8254ff2d71c1de1c",
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
      "binding_sha256": "e391cf74eda78d7029a3ab11e76aba08c0eb048357f6e5f888f88c54d5a96103",
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
      "binding_sha256": "1be03aea271265780dae831e7c11a7d4ad12e29355935d74740907d9a83b4b83",
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
      "binding_sha256": "1dde65f9c8b6a027a28ec1090d3e56589887c5fc05864f94ce9564948f75cecd",
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
      "binding_sha256": "5fb58ab09cd964e25d76e20b011f914ab009111eb982050f7afafe0cd6df5287",
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
      "binding_sha256": "7ad54208cc2973043d1bd426538a0d7bea7abfa7109905002eae7952d28761b9",
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
      "binding_sha256": "4877645a23a6a7f00720cfc1aa0b1c45b720d9fd601063e207f926cc72ede48f",
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
      "binding_sha256": "6d1480f1a7add8dcf2a86d8c00e7f7cc7f5424ed19eebb81ec7f1d1f1044339a",
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
      "binding_sha256": "3501d99a9479eb45e6c1a78dfd7b95b689bda48ff34d6508936c0b8c51a46d0c",
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
      "binding_sha256": "3e217855ef4bb4a9e2f16a85e622fb28516ceb08d012655853aa367417c23c96",
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
      "binding_sha256": "0961823a606b848f0cd73b7ddd05f91ca80430b833cbafc44a47ccc7bf8bbca8",
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
      "binding_sha256": "9bb76a1f1c95fa7d88418987fbdaff073f09f76f82c3f2c7aa39af846b8b435c",
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
      "binding_sha256": "b31b0cda431337fb106850bd3c811fcdad8b4ac3077c121147658d50ab62dc35",
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
      "binding_sha256": "b09a100c46b28c9385791efc8b6bd039b68b57274561467813fc7c2faf179d25",
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
      "binding_sha256": "0b33ead046e9cde380b2832be4d4c2ace42e3d5dc33f5fb8fbd6183171563dd8",
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
      "binding_sha256": "1545529fc67744594252f44cb66dffaf63fc3a788291fcf5a2390c78423bbca9",
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
      "binding_sha256": "1d861011c6f3292d1ec72ff4b11c6cfd609c0dc8fc35ec74798024a2edf23ffe",
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
      "binding_sha256": "c228213fd979fdd926a324d0e3b022757d493ce547376d2af185e899b903a158",
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
      "binding_sha256": "dd818f77015054e7ac8d144dc5422fb3025907d3f5024cdedb27d86ab900ace1",
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
      "binding_sha256": "903979e8227202a4352846414e20ce8b3576e89356ad9877ec14892ca8f77ebd",
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
      "binding_sha256": "190b9d2d82d10830f5cee326b018250d5b4e96f95610d2945cf2f355fd3e8b53",
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
      "binding_sha256": "94f4b82e78fa7a661e45496dfb0fd66bda4d0b1c6e698b18edb499904e8c4d6b",
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
      "binding_sha256": "236dff1e9102b0940d9e2508fa9ffd260295668d5c30d6a335c3a9481682a68d",
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
      "binding_sha256": "5936c2ff7ffa98943607739f4fc500756541db452b6f1c720f5b6abe85adafe8",
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
      "binding_sha256": "7e0baffa4ebe887a62b6896b9c0a9ac6f7b5b3e4b86bf5f5df9b8b0243a5820e",
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
      "binding_sha256": "b7a199469dd0a056fcfeeb96e108428b86d4058b9c33da03ce2a6611a1f1de46",
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
      "binding_sha256": "38660b65458ee98cf263a062f06d3d335b0725b4369a811f200fcfc5cda45dec",
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
      "binding_sha256": "92c34eb15bc2f505d0d205d9c44b6ffa174d17bff4c284de0879aa6e48a213c4",
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
    "evidence_sha256": "380c8d530b80dba5419dccbd0aa4075032c02add7167b3f58d38f97c497e45b0",
    "image_limits": {},
    "manifest_sha256": "958d2709e6b6a7c55d805c2db1b6fbe24cb73f04e603a9dfd9758c7d4fd0cbf3",
    "scan_id": "a821a7998899281364430f5dddcd4f13e6c71cb1a1e7411536de5289f8e83d58",
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

