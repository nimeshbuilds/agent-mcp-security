# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `d0330b4f58a2407a8528bc485c77906acf70f9f0b56bd88a83bd8774211fc05e`

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

Guidance catalog version: 1\.0\.0; SHA-256: `c04353ab7c9999ea513de31a48130971509f8a52666745b24d1b726f96a4f374`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 15 | Observed patterns requiring review; 0 critical/high. No severity weights or estimated compromise probability are assigned. |
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
| generic\_text | 136 | Generic secret/URL signals and bounded recognized skill/instruction directives; language\-specific execution and dataflow are not analyzed\. |
| javascript\_lexical | 12 | Bounded JavaScript/TypeScript tokens, calls and configuration signals; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 7 | Parsed JSON/JSONC fields and selected configuration rules; runtime values and referenced files are not resolved\. |

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
      "binding_sha256": "badeee9428451ca9f313b8bc5e711c0679c9d2b9cd80b124f160f772778e59a7",
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
      "binding_sha256": "fcfd1eea844e0e27722907ef56bc4e357a88fa8c2ceed38cddc9aa6bf39d05ea",
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
      "binding_sha256": "1ffb872d365f600294975e26a952d896259dca00c34f1095b2f1ca3c55297908",
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
      "binding_sha256": "e833fc41c674e6d6fa0f03d8a2bbad49f83c31795ab16e6b3d6dd6a123d2c981",
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
      "binding_sha256": "f6e5d4268274228f11e47cf191a3ea8c6a09ea6db3db325444bfd32c6f3e23cb",
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
      "binding_sha256": "14c69b3619e3ec5cbdce207c7834b8350cc53841c9a9be3f430ecd2bf9e9bb83",
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
      "binding_sha256": "f77eead71bb3c108607919b41292c61b216f5f231cae7cc106439ecd2d4a32fb",
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
      "binding_sha256": "c1435948f63e882a1d7de78dea525d42818e98a0be443412665a34eb9c3bfdb8",
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
      "binding_sha256": "d8cfa74c5e7bb2472ea7d7878d7ff9f600d70eef124a00a7e63a7c2e220d5ce1",
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
      "binding_sha256": "db62f15256d1bbdc0d87f508e627238946bd6c6094a31c989c092f7d64caf242",
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
      "binding_sha256": "e6ea27a5cda2e0d58aab74d6c894081c8d66341be7bddfb0765d000c19cc1225",
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
      "binding_sha256": "1311d428006a9acac0679332114ff4385f65a4b9031025b2ba2f8ee1f7ff055d",
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
      "binding_sha256": "eb9c70b75f52366e7fabfdadcc86691f03d8fc7dca274ec1f8173f00d139bdde",
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
      "binding_sha256": "71a128be958802e181153fc02fa5712abef8893e7b0ef05ccbdff435847d9b5f",
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
      "binding_sha256": "72592bed0db11fdc36af9924491f5016873fb939b4defa70165a5b3e78e4ddde",
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
      "binding_sha256": "7d000accf14be99e5531755db782a8d6337617761997897877cb0949a75ab447",
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
      "binding_sha256": "95603fe32e9c588f0790075e30195dc13fc5216e1f9e53a45bb3f8005733256f",
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
      "binding_sha256": "47182f75125c31e2e3fd5e9da211bd2d2c859549edc344facb5279b8186d6c09",
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
      "binding_sha256": "24631d8ad2c7e242aff21074f79827739ae7cc41df268d235888f875e6bf739f",
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
      "binding_sha256": "a4fab00ebd11df5ca5efef3306583debfe0606816389babca935c83db8cd9aef",
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
      "binding_sha256": "c76f003738b0383d59bd8b2ef88ef3d78b21daf460e9adb0fb2334f238c810f5",
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
      "binding_sha256": "b659164720895e810f671da65b0e113fe31600bef5b1d50f4b465291ca6b3677",
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
      "binding_sha256": "f17b01e97aa965afeabcc869188ac3b9b9736572df83e7e2614bbcfbb87a0f09",
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
      "binding_sha256": "ae788f452d7a04559aa1f5c1cad4e0e83d77e36d77ea200248f1ef64e67631a4",
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
      "binding_sha256": "cb1751ecc761848ea17ceb0c9838100353378435e252de411b9030a0ed12811d",
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
      "binding_sha256": "2cb57833110f2bfb608c0c9f2ef8237abe02d2c1818ab3c18350e0d1a7a79395",
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
      "binding_sha256": "03a4cd0bb425a452fb730a0a115aec1465292a2267aa36037ad502574a84b261",
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
      "binding_sha256": "2a43c5dcce694ed747102f023f73d4258a923f1c32b182558423b9dbb3488af0",
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
      "binding_sha256": "afc15c13f68b1f331b33a32b48cb8ae86ec10dcbf87a1ae5cc3f7c2c2852b9dc",
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
      "binding_sha256": "665263a4c9f26156b98ef79c316d649f3e4af26efabe267d6f30ce0b6909ccb8",
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
      "binding_sha256": "b83a4c20c962b7751bf734072f30523afd9215af6c3f531f2b183e2cb8143de7",
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
      "binding_sha256": "b20e599dbb2cddf4d303c83de97ca41d807e68335eaf96a93d96b92cdc0a003e",
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
      "binding_sha256": "e69d1f28a540869b55a68f3d41a04e870f38697043db3fe7052faebbb80df426",
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
      "binding_sha256": "b2e6b653d55c72a38ac36113787eb4e14cfe4dc544ba76591d04172129406968",
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
      "binding_sha256": "5c90c7481446a8ef43b946e01fa1e64f2713ea2e70a48707d05138c4c0e3bf0d",
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
      "binding_sha256": "5b486524729140202ff7fb79ba99ce5f7af19cc4b06ddcc8a723cb4bc65b165a",
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
      "binding_sha256": "36a0764f09303c532e6291f1ea7b077123ea2265a03e7a8ea214ece1de17cd2e",
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
      "binding_sha256": "f2c8b965291012e12ee936376a3cb119338ae73232b13345a5c1dc9322dad6ef",
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
      "binding_sha256": "abe8f86fce8f3fa26006f7af80f7d93860cbe4543904d0fe746ffbed5ee50a84",
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
      "binding_sha256": "f31be85d6909b650bcb5ef23d67f79deffe851b6b6af4b8b804ef151e2298fab",
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
      "binding_sha256": "afcd7975d5332a62f8e0fb6c6a6a36dea5b21647455f6662981ea7b80a08abe5",
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
      "binding_sha256": "9887f268f22b70fa4c639620c22e454cbba95b53d6cfb12402b6f309f9fe49db",
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
      "binding_sha256": "4ee78a68a1f0f1dcffacaed8a6568dce1a28c1db31dcf217ff0bc37d069afa2a",
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
      "binding_sha256": "a460ee45f7d956669ad06bb93c28cedf4dc16513ff30b986ff754471fa03fdb3",
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
      "binding_sha256": "541ef31787614886b5a9af0dc4fc54f3de2139340a4f3e73a837e37e70c8f5c4",
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
      "binding_sha256": "5091731f7358f9ffa50736aebbb05d66165b31ec62ef8aead1dfd969f6c24088",
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
      "binding_sha256": "f1c9357469fcd41fae35a1536d13499ba9695322e18290bdb48d826b36fc4410",
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
      "binding_sha256": "fbad2c6dea7a82fe0ec3ae437cae244be4ea6880bd6be61f3f2571854184e1c0",
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
      "binding_sha256": "bae5221f91f1ee4f9cff0ecacb6000ac5f6fdfa3cdf6c76d5464a377ef028c02",
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
      "binding_sha256": "c4156919c824b41721bddb5f4a952e3b8b48b51811549bb0c086a29324ff0004",
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
      "binding_sha256": "6b1c33c99567590973e62beb18644906f1d015dec102aeefacea03d2c7d436af",
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
      "binding_sha256": "1d4bdfa3189921cdc63ef8460c25d295e500896fedc9bba9a54f60e3886a251a",
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
      "binding_sha256": "754682f4900300bd3402060329cf5ec2844ec5acd900907f3949e445981c6c6c",
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
      "binding_sha256": "07cd9d078ef5caf6081e9337c889c07e37fb54941b66232846ede937f6911119",
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
      "binding_sha256": "5ca342d69fa143060bc891b0453658bac5687f6efeb38a3d0bf0a216ede4fd51",
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
      "binding_sha256": "405832e1c3dac75a8d4696aab2d16cfbcfa4e38386c9c39237540e45dacad926",
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
      "binding_sha256": "a00f2fdaba7907015c44170bff7eea8ace1ea4e73ae4e525c97736e000956384",
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
      "binding_sha256": "49746bbaf6df6da06507608fee58f714d46bd4b945998431e8bfe193173cb5c1",
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
      "binding_sha256": "d785315367825cda3fc9d84ae750be2d2971306796eb11aea81a33a8e006c53f",
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
      "binding_sha256": "fe9cd6ad7230385c4845e7a440e09beb0986dd28b83f40170b89fd4eaf403b14",
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
      "binding_sha256": "f7e912f3590d2c808a124667244288fd984210360a704c2280b2c8c2eb6f2f2a",
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
      "binding_sha256": "2bbb52616f0f5890fd56e2abd5b2533aecbbeadb762d96bf364267057b8eef40",
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
      "binding_sha256": "4df9ec97cedb80121b4275d04b9f5834d62bd6a8c943fad6d21cbf668c6a7613",
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
      "binding_sha256": "fb5c7dfed28f380c93f7df0524405ca743edf2e6beda4a5e0c9031833b12ee48",
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
      "binding_sha256": "d215bb5232ed79636eacf63afcf3262e57a763be55a7e4b17f9b56082a9ab068",
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
      "binding_sha256": "d63567928f66659f9a6784e6cea084b65895ecdef3183cc00e613fd1dd7402a6",
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
      "binding_sha256": "22fcb0b5441d3c0e3b8e46cbfcee132948f3c84dd0284d2690383470bbb55b56",
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
      "binding_sha256": "d6fe67d2b73b916b57584180c5eb3341e8ecf75ec435cec74ab463ef912ac995",
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
      "binding_sha256": "879d44a9204ccdbd3055170b0b78c7c0ad85058288e5c6f84a5ef9261e6da4b2",
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
      "binding_sha256": "3c2bf3d8c956889b90a1de6211e912b7bc3b82fb28264a47b97de3f9bc4c9a3e",
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
      "binding_sha256": "3beeb0db02e9b52ec4aed1fdb785a78affa672c725a2d3e5d073b08f5a834c1a",
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
      "binding_sha256": "50bf7b865e7514a395258c7c0e906ef97c8ca2831ef4c36a5c2a62844c830832",
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
      "binding_sha256": "0ab22d98a3ac597687ce0ae77ac2a5b8483b837a6c7a296701d9637d84c8d4ff",
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
      "binding_sha256": "99447de1c71cf0bd821f457ac077789b073de37e1924d083c7761f3e8929a323",
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
      "binding_sha256": "245480ccc0fb03e58758204accd9c170b7f5f1a60c4c689eb8a8592819579bab",
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
      "binding_sha256": "61e133320399548108aed8ba197aad9c37a663610ad772067a9586f786f3394e",
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
      "binding_sha256": "709226014eddc1c032d92ea9a5e91d34610b621820919d42901d220dc928aa11",
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
      "binding_sha256": "24cc1d1f1806d8efd7ba70308df82808f64df0a4b460293d66fa28b73a07b894",
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
      "binding_sha256": "3ceb5fd17bbfdeb807eb0aa26e6a172796ca5f06708cc5c3aade88ff26a28005",
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
      "binding_sha256": "d5a0349d2ada49e24088943415215647b35fb863dc7fb3c3b502c45d417a7430",
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
      "binding_sha256": "2065f5401cc7c82bcfc60396fe2a2aa60aeb9f0ef0ddfb7cb7e02795ad8d4110",
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
      "binding_sha256": "4dcfcc9eca79f20a05b43f9f0f01cb46fb9e658e86fbb0b25399363151ff3c62",
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
      "binding_sha256": "55f3dc471d9a26505f08d7586128f308e88f22cf07c9f4b12d2f4158a38376dd",
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
      "binding_sha256": "8410a0a8f43bdb7ad4babd247e0e87a9e2153fef3880f7edadde6c10244fe2a4",
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
      "binding_sha256": "448f5128ab1ed82464b33157b8cbb443b376e6e726aa46596e1e1529ab9346ca",
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
      "binding_sha256": "590ba9a2e3f68373cd69966071d42c69b81d7f768325750e43642f86063310a1",
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
      "binding_sha256": "f3e52d638dc51bc3978430cb6187200b5fa4437b43a2703864ecb9b02d90fbb4",
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
      "binding_sha256": "d7f8af65dbea2095dfee2ede21adf822805b76b27f99f4ff44b8d51f52e2e7eb",
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
      "binding_sha256": "6ddf5fc539fda0aee23e7f3d2562829186d6d3f36fd1f3d17e36e7c257dc4f5b",
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
      "binding_sha256": "6cf14f3cd5453326581210a104d580f6de57e415e06c60edd639e9a9952bc162",
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
      "binding_sha256": "825e3e7743e04112580fa90a5e82cf47526528605e41d95dfa66d429564acd6c",
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
      "binding_sha256": "76ccbfd696dbd2d22ba03ddd8f8ce5865744a1aec9d154d9fc9ddaa9ca78a33f",
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
      "binding_sha256": "8831800f11919de050c05cb1678ecb3685c6b9998375607eb948f34010ea3645",
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
      "binding_sha256": "263f386d37190ee80b0401210663d175cf552ba6b044aa735bab494a6f48fca1",
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
      "binding_sha256": "14343cf8e016216edf563bf4bf9d72f842d11bcdd4690228b2dd7c92b9b972fa",
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
      "binding_sha256": "1147c6ec81d6c561c269d7a629a90c06a75a700a9c9c13b1db0c24fdff208529",
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
      "binding_sha256": "3983a94465cb0605f5eff46478482cd5fe2b9f29abf85c250f03af6f9f186702",
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
      "binding_sha256": "f541a0cc8b5e9475901b9d3fde7d20e82e7e50a6aeb407ae6fb6bbd1deff4f30",
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
      "binding_sha256": "22c92cb4837a98c021ae9457dc249d20ba41e0a7ff2e8fe952998391d6b83c53",
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
      "binding_sha256": "b0404dc054521b10919f328fde03d5a9f62e02b59f45a13e94969416325edc92",
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
      "binding_sha256": "242494aaf74970f087116d5877fe9f4021bd8dfa5116a1b2240a93f24096cd09",
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
      "binding_sha256": "47fb7efa28a59e130c759416d6982adaf913c489d8fc9a19680840800c042dd4",
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
      "binding_sha256": "f4eccb656aeb197d328fccea58e29f200df1c39e07d776ca34e51b0fa1e94d64",
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
      "binding_sha256": "63954bea010f19f2f878d790e1a47e4a9137bdc0ce9763e8aa45ba9082b9d3e2",
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
      "binding_sha256": "aacf0cf889ea77302de318a0f78f1afaa95564650362b252fb179cfdd05874ed",
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
      "binding_sha256": "72ff5c278c64df3470a910ee9c3d88a8207e77b3c6f8d713485978a50289da7c",
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
      "binding_sha256": "5e4a95b3f55f7f11ef8c4a5ad18042a32180fcc98190ea910a9558308ed6229e",
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
      "binding_sha256": "a65014ed70db2cdb082c59f90abd5434048cc75ca2e77ce35cbfa41c1ec3289c",
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
      "binding_sha256": "908dd5210f63bb69bf24eeb1d00876590b4cadd474cab6d663a06a1c10a76214",
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
      "binding_sha256": "cabf29935148dc4aaf25f943e430556e47b5519b5d814e37ac6d9da535f700ad",
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
      "binding_sha256": "6fa5e853d18ea509d3d49e99cc6153cf025f34d43da8949ad09d344e8cbeb7b8",
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
      "binding_sha256": "142f52f0f1b66fffda4cebb45d6db9eb949834d41a333885ae9ce5bdde68b78a",
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
      "binding_sha256": "5d4ab0f19e7637b9d384d5a013d3fd20529c0407ec74e766e75212f91816c4b8",
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
      "binding_sha256": "452e6c52f87b6ea4ac3d6675a4e16f0113db17eaaa3b186412f9a275cdc736e2",
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
      "binding_sha256": "c6705b6427e6863fab8ab11ebbe0ce8766a0a7f2f21c267728358cb2028ac070",
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
      "binding_sha256": "e1e684d45f63e8274bfa3a8cba6aca8b0b6bac3abcd01c7f0e828d0fc41c8ec7",
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
      "binding_sha256": "2eea6e0362dd3f46562920eef3980096103f1efa189c289b23dbd1416fd760ca",
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
      "binding_sha256": "bb01fe98f8834470a13bade80be48ed26a9c3b5f96745a61f0c1843393dd8c22",
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
      "binding_sha256": "a0459e4ba1b107f6bcc4574c6404e9969396dfcdc426bcdb3642618394bca0e9",
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
      "binding_sha256": "7ced5453c1eacfd32b84c7f79dc34761a8e1d2c57677a9fb09077005cb33630e",
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
      "binding_sha256": "4db4ec446f52d2e6b2b186fb04b69b766399816ba756c977ae6c95f3c83b3f90",
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
      "binding_sha256": "950659b392e5be94f2a0932ff0ba03a17b9d834c6324d1184998ebb35e920fdd",
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
      "binding_sha256": "d703e3210f3bfd49d64b20256c94d85fe421cef94afadeb2feaf44a9c71757b9",
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
      "binding_sha256": "c9268e3e65e12ed4f32f9eb62e52a1e4aa97bba77dea2df04ac68b0ee6bd4ed2",
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
      "binding_sha256": "eb6e2d77149f6e2a136876265f68b27cf07e1288b3eb70fe7ef914014415aa6d",
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
      "binding_sha256": "d9dcb389d60b2a1cd3b748d94b44a7af74933ca9312f852c1ae10467c4aebd35",
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
      "binding_sha256": "a1e44c2557d90845f43976941db80f4cc71635f6137eda41265ba4482b1fcf8d",
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
      "binding_sha256": "fd0471c74fcb9543bd4a95b03ca53c6a406d40897da73372f4353020aabd0e1a",
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
      "binding_sha256": "909c98c6308c8a786ea1444d60b4c5b97fcc7c0572e6dca67bed57320839ceeb",
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
      "binding_sha256": "283957869ac1ec1f141dcceabc686247a7bd26fc9b663b0e0db985a3f6ad4ec0",
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
      "binding_sha256": "3cfe5dc3f5194b366fd0a643a7dd7810815cdb83006ee249538aa9279d777b51",
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
      "binding_sha256": "d051d943cb2e0a1475f9a970e17dcf10766704a27260f46e700f5be67faceb01",
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
      "binding_sha256": "e71e5f56497dd35f2f4a22eb0ed87d8a4474b6229896d033801f41eff09c288b",
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
      "binding_sha256": "a88466d72e2741f1265678947ce71f00c20d9ffe2b1bbaf656f07adad0489eb8",
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
      "binding_sha256": "eab190ab50d9caa9316d548af747ba5da8e397711f368dd4acce0883e41c5d53",
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
      "binding_sha256": "f86f8fba92afcfb3716ea3fcbb1cf97f6c43ae59f5cde198fee51aacc9166199",
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
      "binding_sha256": "c4f3c15c49cff55b8c355b023748e4af5a4b896c6821c760252263eb98b64373",
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
      "binding_sha256": "adbbe6d4cd548915ffde2b10360369d16b056065b46184b02653bdb49d5a99fd",
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
      "binding_sha256": "9866717e95fa5c96bf0993e23ac22157047dbe1dcfbef90f9847d0309edb2064",
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
      "binding_sha256": "08946ba62c92301a877da3f343bf5b58d58e7719343731460cfa64a70286f7f0",
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
      "binding_sha256": "38ae9f4aed52053df8f68fe48c8c4e76f43ecca3fba03383a0b5b746948a6127",
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
      "binding_sha256": "8c1408b456f8a7d85f182f6f4d7b457c7e3bd7be05f13069934be30ef37a593f",
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
      "binding_sha256": "26e8cbc3be39ebc290dda4085f4b4a4ee3c658bb7d63d2990695ddc6675b54b1",
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
      "binding_sha256": "585bc7118c2e93e474e7dd60e9b6138906d7b03de7018815a6521fe00f6671d9",
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
      "binding_sha256": "e16be6d5c2f0705f8a395c1356c0bd383b12c7b34099aeb3ab394f9057565f13",
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
      "binding_sha256": "ba47c63e474c6d0b5ccf3b494ea990ffebd6b319a8c9a05485ba766b3982473b",
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
      "binding_sha256": "90f1a5f64b04605b1a40746a08ca8ff706344be8af77bdd2a9495e53fc7c1947",
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
    "evidence_sha256": "380c8d530b80dba5419dccbd0aa4075032c02add7167b3f58d38f97c497e45b0",
    "image_limits": {},
    "manifest_sha256": "958d2709e6b6a7c55d805c2db1b6fbe24cb73f04e603a9dfd9758c7d4fd0cbf3",
    "scan_id": "d0330b4f58a2407a8528bc485c77906acf70f9f0b56bd88a83bd8774211fc05e",
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

