# What Invarune scans

**Invarune by NimeshBuild** inspects AI agents, MCP servers, skills and built Linux images without executing their code or invoking their tools. This is the complete current inventory: **{{RULE_COUNT}} deterministic rules**, **{{CONTROL_COUNT}} controls** and **{{CHECK_COUNT}} acceptance checks**. Ruleset **{{RULESET_VERSION}}**. The inventory is generated from the catalogs used by <code>invscan --list-scans</code>.

The default scan is deterministic and needs no model, API key, login or network. Optional AI review adds bounded evidence interpretation for selected controls, including questions that deterministic patterns cannot settle. It can propose additional gaps; its conclusions remain advisory. Neither layer promises that a clean result proves security or that a suspicious tool is malicious.

## Choose the scope from your terminal

~~~sh
# Every implemented deterministic rule; findings in the terminal
invscan ./my-agent

# MCP implementation and skill instructions with packaged scripts
invscan ./my-mcp-server
invscan ./my-skill

# Exact predicates, algorithms, limits, fixes and source organizations
invscan --list-scans
invscan --explain-scan AI043
invscan --explain-scan AUTH-01
invscan --list-scans --catalog-format json

# One rule, several rules, or a control's mapped rules and review plan
invscan ./my-agent --scans AI002
invscan ./my-agent --scans AI002,AI032 --scans AI043
invscan ./my-mcp-server --scan AUTH-01,MCP-01

# Selected patterns and their corresponding optional control review
invscan ./my-agent --scans AI032,AI043 --judge-cli claude

# Explicit report files; --report alone uses ./scan-report
invscan ./my-agent --report
invscan ./my-agent --output ./security-report
invscan ./my-skill --report ./skill-report --pdf

# Built image, without starting it or needing a checkout
invscan --image-archive ./agent-image.tar --scans AI010,AI021,AI043
invscan --image my-mcp-server:latest --output ./image-report
~~~

<code>--scans</code> (alias <code>--scan</code>) accepts rule IDs and control IDs, separated by commas or repeated. IDs are case-insensitive and deduplicated. A rule ID selects that rule and its mapped control review. A control ID selects that control and its mapped deterministic rules; mixed selections use their union. A control without mapped rules retains a review requirement and runs zero associated deterministic detectors. It never silently falls back to all rules. Parsing, resource budgets, source integrity and coverage checks remain active. Unselected findings are outside the requested result scope, not implicitly passed or justified.

Without <code>--report</code>, <code>--output</code> or <code>--pdf</code>, the result stays in the terminal and no report directory is created. <code>--summary-json</code> selects machine-readable stdout; <code>--quiet</code> suppresses normal output. <code>--output DIR</code> or <code>--report [DIR]</code> writes HTML, JSON, Markdown and SARIF. <code>--pdf</code> also requests a fillable PDF and implies report output. See the [CLI reference](CLI.md), [quickstart](QUICKSTART.md) and <code>invscan --help-topic scans</code>.

## Which layer does what?

| Layer | What runs | Output | What remains uncertain |
| --- | --- | --- | --- |
| Deterministic (always) | Applicable selected code/configuration/instruction predicates, bounded source and image processing, redaction, control mapping and integrity checks. | Stable finding IDs, locations, severity, evidence, remediation, explicit coverage errors and control review requirements. | Unrecognized syntax, complete data flow, real reachability, intent and deployed protections. |
| Optional finding triage | One bounded model review of detected findings; additional source context is controlled by its flags. | Advisory applicability, explanation and recommended follow-up. | Does not search the full repository or establish new deterministic findings. |
| Optional full control analyst | Deterministically selected excerpts for every active selected acceptance check, including controls without detector matches. Default when AI is enabled. | Cited code support, potential gaps, runtime/human review needs, proposed applicability and missing-evidence outcomes. | Retrieval can miss relevant code and the model can misinterpret evidence. No target execution, autonomous retrieval or runtime tests. |
| Operator/runtime validation | Separate authorized deployment, adversarial, identity and operational checks. | Evidence and accountable decisions, optionally recorded in editable report fields. | These activities are not performed automatically by either scanner layer. |

Enable AI explicitly with <code>--judge-cli codex</code>, <code>--judge-cli claude</code>, <code>--judge-cli grok</code> or a trusted <code>--judge-config</code> for a supported API/gateway. The default <code>--judge-mode full</code> retains deterministic findings, adds finding triage, then reviews active selected controls. <code>--judge-mode findings</code> restricts AI to finding triage. Missing credentials, rejected responses, omitted answers and exhausted budgets remain visible. They do not become successful checks. Guarded Headroom optimization is the default when AI support is installed; <code>compact</code> and <code>off</code> are available. Exact evidence strings must survive optimization. [Review workflow and supported statuses](ANALYST.md); [providers, custom URLs and privacy](JUDGE.md).

When a supported deterministic scan is inconclusive, the full analyst can inspect the supplied relevant excerpts and propose a supported interpretation or the next validation step. Files with deterministic analysis errors receive evidence-selection priority after finding-bearing files. Their first bounded, manifest-verified excerpt is offered as a candidate to selected controls even without a keyword match; final selection still obeys evidence budgets. It cannot repair missing, unreadable or unselected source, prove a parse failure harmless, or turn an analysis gap into a pass. A quoted source fragment proves that text was submitted, not that the model's explanation is correct.

## Agents, MCP servers, skills and images

| Target | Relevant checks | Input and boundary |
| --- | --- | --- |
| AI agent | Tool execution, permissions/approval bypass, privileged prompt composition, credentials/data leaks, dependencies, model loaders and isolation; applicable instruction checks. | Select the agent repository or directory. Framework signals do not switch off generic rules or prove a running agent was exercised. |
| MCP server/client | Tool implementation and literal metadata, authentication settings, token forwarding, origins, transport, package launchers, permissions and sandbox controls. | Select implementation/configuration. No deployed MCP connection, tools/list call, tool invocation or OAuth probe occurs. |
| Skill package | Recognized skill/agent instruction documents, bounded suspicious-instruction patterns, supported literal tool descriptors, and ordinary rules for packaged scripts. | Select the skill directory. Instructions remain untrusted data; the skill is never loaded or installed. |
| Built Linux image | Applicable packaged-file rules plus user/environment/labels/commands, retained secret revisions and build-history signals. | Use Docker-save or OCI-layout archives, or trusted local Docker/Podman export. No container starts; binary-only logic is unassessed. |

Every rule can be relevant to code packaged in any target type; a surface label does not mean the rule applies to every file. A Python-only API check does not analyze the equivalent Go call. A skill's helper script can trigger shell/credential rules even if SKILL.md has no suspicious instruction. [Built-image scope and budgets](IMAGE_SCANNING.md).

### Suspicious tool and skill instructions

AI043–AI046 recognize specific instruction and metadata inconsistencies: overriding trusted instructions, explicit sensitive-data transfer, concealment/approval bypass, and destructive descriptions advertised as read-only. Supported instruction filenames are SKILL.md, AGENTS.md, CLAUDE.md, GEMINI.md and copilot-instructions.md (case-insensitive), plus .instructions.md and .mdc files. Markdown under skills/ or .skills/ directories is also recognized. The scanner follows literal local Markdown links (including spaced angle destinations, escaped punctuation, balanced parentheses and full/collapsed/shortcut reference definitions) from SKILL.md recursively within that skill directory, using only already scanned files and a shared 2,048-reference budget. Missing/outside-scope local references leave coverage gaps. It never fetches remote reference content. Supported literal descriptors include JSON tool objects with a name and input schema/parameters, Python tool decorator docstrings or description keywords, and recognized JavaScript registration calls. Dynamic description values in recognized registration forms remain coverage gaps. Indirect registrations outside those forms may not be discovered.

The detector uses bounded English instruction predicates, Unicode normalization and a single bounded layer of explicitly labelled base64 decoding. It does not recursively unpack arbitrary encodings or execute decoded text. Quoted, negated and explanatory security examples are excluded only where the bounded predicates recognize them. Shell examples in recognized instruction documents also receive applicable direct-download execution checks; explicit unrestricted skill tool grants receive the wildcard-authorization check.

Fixed instruction-detector bounds are 262,144 Markdown characters or 1,000,000 metadata-source characters, 2,048 actual tool/instruction segments, 8,192 characters per segment and 32 labelled base64 values of at most 8,192 decoded bytes each. Exceeding a bound leaves a coverage gap; it does not silently validate the remainder.

These are suspicious-pattern findings, not malware attribution or proof of intent. Legitimate examples, paraphrases, hidden staged behavior, implicit transfer destinations, dynamic descriptions, external documents and runtime outputs remain difficult cases. The [separate skill/tool corpus](../benchmarks/skills_tools_accuracy.json) retains unsupported challenges for non-English override instructions, indirect authority replacement and vault/attachment disclosure semantics. Use the optional analyst for evidence-backed context, then verify actual handler behavior, authority, destinations and approval enforcement in a controlled environment.

## Read the result

| Result | Meaning | Next action |
| --- | --- | --- |
| Open finding / findings_detected | A selected predicate matched source or image evidence. | Confirm relevance, prioritize critical/high findings and use the fix and verification steps. |
| no_pattern_detected | No mapped selected rule matched scanned evidence. | Check limitations and remaining acceptance criteria. It is not a pass. |
| No mapped deterministic rule / manual or runtime requirement | The selected control needs evidence beyond implemented patterns. | Use full optional review for source context where useful; collect accountable or runtime evidence. |
| justified | The operator accepted a documented exception. | Preserve reviewer, scope and evidence. It earns no pass/fail credit. |
| disabled | The operator excluded an item from active assessment. | Keep its rationale and excluded count visible. It earns no pass/fail credit. |
| suppressed | A finding matches an explicitly reviewed baseline. | Preserve it as an accepted exception, not removed evidence or a fixed issue. |
| Coverage gap / incomplete | Selected source or requested review could not be fully processed. | Resolve read/parse/budget/provider issues or collect missing evidence; exit status is 2. |

Optional analyst checks use <code>supported_by_code</code>, <code>potential_gap</code>, <code>needs_runtime_validation</code>, <code>needs_human_review</code>, <code>insufficient_evidence</code> and <code>not_applicable_proposed</code>. Missing accepted answers remain <code>not_reviewed</code> in answer coverage. Proposed non-applicability is not an operator exception. For dynamic/manual controls, apparent code support is deterministically adjusted to runtime/human review. No model status establishes a validated pass.

Exit **0** means selected work completed below the open-finding threshold; **1** means active deterministic findings meet <code>--fail-on</code>; **2** means invalid input or incomplete requested work. Incompleteness wins over the findings gate. <code>--fail-on none</code> disables only severity gating. Reports start with scope, immediate concerns and coverage, then show grouped findings, actionable fixes, proposed defense layers and outstanding checks. [Report guide](REPORTS.md); [editable decisions](REVIEW_WORKFLOW.md).

## Scores and denominators

Invarune does **not** invent a universal security score from pattern counts. <code>overall_security_score</code> is <code>null</code>: exploitability, business impact and compensating controls cannot honestly be reduced to a percentage from these scans. Reports expose reproducible evidence measures:

| Measure | Calculation | Interpretation |
| --- | --- | --- |
| Active deterministic findings | Count selected open findings separately for critical/high/medium/low/info. Urgent = critical + high. | Detected review work; baseline, justified and disabled records remain outside active counts. |
| Deterministic mapping reach | 100 × active selected controls with at least one active selected mapped rule ÷ active selected controls, rounded to two decimals. | Available partial rule coverage, not test completion, pass rate or assurance. No active denominator produces null. |
| Optional AI answer coverage | 100 × unique active selected checks with a valid received model answer ÷ active selected checks, rounded to two decimals. | Answer completeness, including concerns and unknowns. Omitted/synthesized answers do not count. No active denominator produces null. |
| AI check outcomes | Separate counts for code support, potential gap, runtime/human review, insufficient evidence, proposed non-applicability and not reviewed. | An answered unknown is still unknown. |
| Validated controls | Zero based on scanner/model interpretation alone. | External validation remains necessary; neither layer certifies controls. |

Enabling AI changes its answer-coverage and outcome records, **not** deterministic finding severities, open counts or severity gating. Disabled AI has zero accepted answers. A control with no detector can have 0% deterministic mapping reach and a fully answered AI review while still requiring runtime/human evidence. Justified and disabled controls/checks leave the relevant active denominators; they add neither pass points nor penalties.

Selecting fewer rules changes scope, so percentages from different selections are not directly comparable. Fixture benchmark precision/recall are measured against labeled cases; they never become the application's security score.
