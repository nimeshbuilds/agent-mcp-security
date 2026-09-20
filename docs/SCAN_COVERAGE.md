# What Invarune scans

**Invarune by NimeshBuild** inspects AI agents, MCP servers, skills and built Linux images without executing their code or invoking their tools. This is the complete current inventory: **46 deterministic rules**, **66 controls** and **132 acceptance checks**. Ruleset **1.5.0**. The inventory is generated from the catalogs used by <code>invscan --list-scans</code>.

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

## Supported analysis algorithms and their limits

| Profile | Deterministic boundary |
| --- | --- |
| `python_ast` | Bounded local aliases, constants and selected external-input propagation; no complete interprocedural or whole-program proof. |
| `javascript_lexical` | Balanced tokens and selected import/call/configuration patterns; not a complete JS/TS parser, type checker or flow graph. |
| `json_structured` | Parsed JSON/JSONC with selected typed-field predicates; dynamic values and referenced configuration are not resolved. |
| `configuration_lexical` | Selected literal configuration and shell patterns; limited YAML scalar/alias support, not full template or YAML semantics. |
| `generic_text` | Applicable generic patterns only; supported file selection is not full language-specific analysis. |
| `instruction_text` | Supplementary detector path for recognized agent/skill documents; bounded English instruction patterns, not model execution. The file manifest retains its ordinary source profile. |
| `tool_metadata` | Supplementary detector path for supported literal descriptors; dynamic descriptions/runtime tool output need separate evidence. The file manifest retains its ordinary source profile. |

Selected files must be supported UTF-8 text (BOM accepted). Source scans skip configured exclusions and dependency/build/cache directories by default; image scans intentionally include packaged dependency/build content. Unreadable files, invalid supported syntax and exhausted budgets remain coverage gaps. Unknown file types are outside selected source coverage. No dependency installation, target imports, build commands, target network probes, CVE-feed calls, decompilation, publisher-signature verification or runtime execution is implied. Run `invscan --help-topic source` for the live file-extension inventory and `invscan --help-topic limits` for every budget.

## All deterministic scans

Each entry gives its supported predicate, algorithm, blind spots, mapped controls and technical/provenance references. References do not mean Invarune executes every external benchmark or has an official certification.

| ID | Scan | Severity | Profiles | Mapped controls |
| --- | --- | --- | --- | --- |
| [AI001](#ai001) | Dynamic Python code execution | high | `python_ast` | EXEC-02 |
| [AI002](#ai002) | Dynamic command executed through a shell | high | `python_ast` | EXEC-01 |
| [AI003](#ai003) | Dynamic os shell command | high | `python_ast` | EXEC-01 |
| [AI004](#ai004) | Unsafe YAML object construction | high | `python_ast` | EXEC-06 |
| [AI005](#ai005) | Executable deserialization requires trusted inputs | high | `python_ast` | EXEC-06 |
| [AI006](#ai006) | TLS certificate verification disabled | high | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical` | MCP-01 |
| [AI007](#ai007) | Wildcard cross-origin access | medium | `python_ast`, `javascript_lexical`, `json_structured` | MCP-01 |
| [AI008](#ai008) | Service binds to all network interfaces | low | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical` | MCP-01 |
| [AI009](#ai009) | Application debug mode enabled | medium | `python_ast`, `json_structured`, `configuration_lexical` | DATA-03 |
| [AI010](#ai010) | Credential-like literal in source or configuration | high | `python_ast`, `json_structured`, `generic_text` | AUTH-05, DATA-01 |
| [AI011](#ai011) | Private key material in repository | critical | `generic_text` | AUTH-05, DATA-01 |
| [AI012](#ai012) | Dynamic JavaScript shell execution | high | `javascript_lexical` | EXEC-01 |
| [AI013](#ai013) | Dynamic JavaScript code execution | high | `javascript_lexical` | EXEC-02 |
| [AI014](#ai014) | Externally influenced outbound request | medium | `python_ast`, `javascript_lexical` | EXEC-05 |
| [AI015](#ai015) | Externally influenced filesystem path | medium | `python_ast`, `javascript_lexical` | MCP-08, EXEC-04 |
| [AI016](#ai016) | Race-prone temporary filename creation | medium | `python_ast` | EXEC-04 |
| [AI017](#ai017) | JWT verification explicitly bypassed | high | `python_ast`, `javascript_lexical` | AUTH-03 |
| [AI018](#ai018) | MCP package runner resolves an unpinned artifact | medium | `json_structured` | MCP-09, SUP-01 |
| [AI019](#ai019) | Remote download executed directly by a shell | high | `configuration_lexical`, `generic_text` | SUP-03 |
| [AI020](#ai020) | GitHub Action reference is not pinned to a commit | medium | `configuration_lexical` | SUP-04 |
| [AI021](#ai021) | Container explicitly runs as root | medium | `configuration_lexical` | SUP-05 |
| [AI022](#ai022) | Privileged container or privilege escalation enabled | high | `json_structured`, `configuration_lexical` | SUP-05 |
| [AI023](#ai023) | Container runtime socket exposed | high | `json_structured`, `configuration_lexical` | SUP-05 |
| [AI024](#ai024) | Container image is not digest pinned | low | `json_structured`, `configuration_lexical` | SUP-01, SUP-03 |
| [AI025](#ai025) | Direct dependency is not exactly pinned | low | `json_structured`, `configuration_lexical` | SUP-01 |
| [AI026](#ai026) | Authentication explicitly disabled | high | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical` | AUTH-01 |
| [AI027](#ai027) | Wildcard tool or permission authorization | high | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical` | AUTH-02, AGT-01 |
| [AI028](#ai028) | MCP token passthrough enabled | high | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical` | AUTH-04 |
| [AI029](#ai029) | Remote MCP URL uses plaintext HTTP | high | `json_structured` | MCP-01 |
| [AI030](#ai030) | Browser-side API credential access explicitly enabled | medium | `javascript_lexical`, `json_structured` | AUTH-05, DATA-01 |
| [AI031](#ai031) | Agent approval or sandbox safeguard explicitly bypassed | high | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`, `generic_text` | MCP-09, AGT-01, AGT-02, SUP-05 |
| [AI032](#ai032) | External data inserted into privileged LLM instructions | medium | `python_ast`, `javascript_lexical` | AGT-03 |
| [AI033](#ai033) | Potential secret included in logging call | medium | `python_ast`, `javascript_lexical` | DATA-03 |
| [AI034](#ai034) | Credential-like value embedded in URL query | high | `generic_text` | AUTH-05, DATA-01 |
| [AI035](#ai035) | Unsafe model checkpoint deserialization | high | `python_ast` | EXEC-06, SUP-03 |
| [AI036](#ai036) | SQL query constructed with interpolation | high | `python_ast`, `javascript_lexical` | EXEC-03 |
| [AI037](#ai037) | Archive extraction without an explicit safe filter | medium | `python_ast` | EXEC-04 |
| [AI038](#ai038) | Cryptographically weak randomness used for a security value | medium | `python_ast` | AUTH-06, MCP-05 |
| [AI039](#ai039) | Server-Side Template rendered from a dynamic template | high | `python_ast` | EXEC-07 |
| [AI040](#ai040) | Unsafe HTML rendering boundary | medium | `javascript_lexical` | EXEC-07 |
| [AI041](#ai041) | MCP inspector authorization explicitly disabled | high | `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical` | AUTH-01 |
| [AI042](#ai042) | Container uses host namespaces | high | `json_structured`, `configuration_lexical` | SUP-05 |
| [AI043](#ai043) | Instruction-hierarchy override in agent-facing text | high | `instruction_text`, `tool_metadata` | MCP-03, AGT-03, AGT-06 |
| [AI044](#ai044) | Sensitive-data transfer instruction | high | `instruction_text`, `tool_metadata` | MCP-03, AGT-06, AGT-07 |
| [AI045](#ai045) | Covert action or approval-bypass instruction | high | `instruction_text`, `tool_metadata` | AGT-02, AGT-06 |
| [AI046](#ai046) | Read-only tool annotation contradicts a destructive description | medium | `tool_metadata` | MCP-03, MCP-04 |

### AI001

**Dynamic Python code execution** · high · `tool_execution`

**Looks for:** Nonliteral eval/exec calls, including recognized builtins aliases and constant getattr names.

**Why it matters for agents/MCP/skills:** An agent can convert a prompt or MCP tool result into an eval/exec argument. If that value reaches this call, model influence becomes Python execution with the tool process identity.

**Deterministic algorithm:** AST call resolution and bounded local constant/alias tracking. Profiles: `python_ast`.

**Can miss or require context:** Dynamic imports, computed attributes and cross-function input flow are not completely resolved; a dynamic argument alone does not prove attacker control.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Replace dynamic execution with an allowlisted operation dispatcher; use ast.literal_eval only for bounded literal parsing. Isolate unavoidable execution with no ambient credentials and strict resource limits.

**Partial control mapping:** [EXEC-02](#exec-02).

**Source organizations and relationships:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html) (Python Software Foundation; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI001
invscan TARGET --scans AI001
```

### AI002

**Dynamic command executed through a shell** · high · `tool_execution`

**Looks for:** Dynamic subprocess shell=True, asyncio.create_subprocess_shell, or an explicit recognized shell executable with its command option.

**Why it matters for agents/MCP/skills:** An agent or MCP tool often translates model-selected operations into subprocess commands. Untrusted arguments embedded in a shell string can turn one permitted tool action into additional commands.

**Deterministic algorithm:** AST call/argument matching and bounded local tracking. Profiles: `python_ast`.

**Can miss or require context:** Does not establish command reachability, input sanitization across functions, executable trust, or sandbox effectiveness.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Pass an argument list with shell=False, allowlist executable names and options, and enforce working-directory and resource restrictions.

**Partial control mapping:** [EXEC-01](#exec-01).

**Source organizations and relationships:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html) (Python Software Foundation; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI002
invscan TARGET --scans AI002
```

### AI003

**Dynamic os shell command** · high · `tool_execution`

**Looks for:** Dynamic os.system/os.popen arguments through recognized imports and aliases.

**Why it matters for agents/MCP/skills:** An MCP command tool may interpolate planner output into os.system or os.popen. Those APIs introduce a shell boundary that can expand attacker-controlled syntax into the server account privileges.

**Deterministic algorithm:** AST resolved-API matching and constant exclusion. Profiles: `python_ast`.

**Can miss or require context:** A dangerous shell boundary is identified, not complete upstream taint or production exploitability.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use subprocess with a fixed executable and argument list, shell=False, and explicit allowed options.

**Partial control mapping:** [EXEC-01](#exec-01).

**Source organizations and relationships:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html) (Python Software Foundation; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI003
invscan TARGET --scans AI003
```

### AI004

**Unsafe YAML object construction** · high · `deserialization`

**Looks for:** Recognized YAML load/load_all/unsafe_load calls without an explicitly recognized SafeLoader, CSafeLoader, BaseLoader or CBaseLoader.

**Why it matters for agents/MCP/skills:** Agents and MCP servers often read tool manifests, workflows or uploaded configuration as YAML. An executable loader can convert attacker-influenced configuration into Python objects before tool authorization runs.

**Deterministic algorithm:** AST loader allowlist. Profiles: `python_ast`.

**Can miss or require context:** User-defined wrapper safety and every third-party YAML API are outside the allowlist; the actual input's trust is not established.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use yaml.safe_load or SafeLoader/CSafeLoader and validate the parsed schema and size.

**Partial control mapping:** [EXEC-06](#exec-06).

**Source organizations and relationships:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [TECH-PYYAML](https://pyyaml.org/wiki/PyYAMLDocumentation) (PyYAML maintainers; rule technical reference).

```sh
invscan --explain-scan AI004
invscan TARGET --scans AI004
```

### AI005

**Executable deserialization requires trusted inputs** · high · `deserialization`

**Looks for:** pickle/dill/cloudpickle load/loads and joblib.load calls.

**Why it matters for agents/MCP/skills:** A cached agent state, plugin artifact or MCP-uploaded file may reach pickle-compatible loading. Deserialization can execute producer-selected code before downstream data validation.

**Deterministic algorithm:** AST executable-deserializer API matching. Profiles: `python_ast`.

**Can miss or require context:** Authenticated trusted artifacts may be intentional; this does not inspect serialized objects or prove attacker control.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use a nonexecutable serialization format with schema validation. If compatibility requires pickle, accept only authenticated artifacts from a strictly controlled producer.

**Partial control mapping:** [EXEC-06](#exec-06).

**Source organizations and relationships:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html) (Python Software Foundation; rule technical reference).

```sh
invscan --explain-scan AI005
invscan TARGET --scans AI005
```

### AI006

**TLS certificate verification disabled** · high · `transport_security`

**Looks for:** Explicit TLS verification bypass in supported Python HTTP clients/SSL, JavaScript rejectUnauthorized, NODE_TLS_REJECT_UNAUTHORIZED and supported configuration fields.

**Why it matters for agents/MCP/skills:** The affected connection can carry model credentials, prompts, MCP tool requests or retrieved evidence. Disabling TLS verification lets a reachable intermediary impersonate that peer and influence both data and agent decisions.

**Deterministic algorithm:** Typed literal and recognized network/configuration API checks. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** Does not establish effective CA trust, hostname validation, gateway behavior or an override supplied at deployment.

**Image context:** `final_filesystem`, `runtime_configuration`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Enable certificate verification and install the correct CA bundle; use a trusted private CA for custom gateways.

**Partial control mapping:** [MCP-01](#mcp-01).

**Source organizations and relationships:** [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) (Model Context Protocol maintainers; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI006
invscan TARGET --scans AI006
```

### AI007

**Wildcard cross-origin access** · medium · `network_exposure`

**Looks for:** Wildcard origins in supported Python CORS calls, JavaScript fields and structured configuration.

**Why it matters for agents/MCP/skills:** A browser can reach some local or remote MCP HTTP services. A broad cross-origin policy may expose tool responses or weaken the browser-facing boundary around operations running with the user credentials.

**Deterministic algorithm:** Literal origin-list matching. Profiles: `python_ast`, `javascript_lexical`, `json_structured`.

**Can miss or require context:** Does not infer authentication, browser reachability, credential mode or framework-specific CORS response behavior.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Allow only required origins, validate Origin on HTTP MCP endpoints, and combine origin checks with authentication. Do not combine wildcard origins with credentials.

**Partial control mapping:** [MCP-01](#mcp-01).

**Source organizations and relationships:** [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) (Model Context Protocol maintainers; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI007
invscan TARGET --scans AI007
```

### AI008

**Service binds to all network interfaces** · low · `network_exposure`

**Looks for:** Wildcard host bindings such as 0.0.0.0 or :: in supported calls and configuration keys.

**Why it matters for agents/MCP/skills:** A broadly bound agent dashboard or MCP HTTP server may expose its tool authority to additional networks. The bind literal does not establish whether firewalls, published ports or authentication actually permit access.

**Deterministic algorithm:** Literal listener/bind matching. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** Binding is an exposure review signal; ingress restrictions, authentication and actual remote reachability require deployment evidence.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Bind local-only tools to loopback. For intentional remote services, verify ingress policy, TLS, authentication, and origin validation.

**Partial control mapping:** [MCP-01](#mcp-01).

**Source organizations and relationships:** [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) (Model Context Protocol maintainers; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI008
invscan TARGET --scans AI008
```

### AI009

**Application debug mode enabled** · medium · `configuration`

**Looks for:** Recognized debug=True calls/assignments and supported debug/FLASK_DEBUG configuration values.

**Why it matters for agents/MCP/skills:** An agent API or MCP server may handle secrets, prompts and privileged tools. A reachable development debugger or verbose exception page can reveal that state and, in some frameworks, permit code execution.

**Deterministic algorithm:** Explicit debug-setting matching. Profiles: `python_ast`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** A setting may be development-only; environment, framework defaults and production overrides are not proven.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Disable debug mode in deployed services and return sanitized errors while retaining protected server-side diagnostics.

**Partial control mapping:** [DATA-03](#data-03).

**Source organizations and relationships:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI009
invscan TARGET --scans AI009
```

### AI010

**Credential-like literal in source or configuration** · high · `secrets`

**Looks for:** Nonplaceholder credential-named literals, supported token formats and literal bearer credentials; explicit environment-variable-name fields are excluded.

**Why it matters for agents/MCP/skills:** A hardcoded model, gateway or downstream-tool key can grant access outside the intended agent session and tenant. Repository or image readers may obtain the credential independently of the agent approval path.

**Deterministic algorithm:** Credential-name/value heuristics and bounded token patterns. Profiles: `python_ast`, `json_structured`, `generic_text`.

**Can miss or require context:** May miss unusual secret formats and may flag realistic test data; never validates credentials remotely or proves they are live.

**Image context:** `final_filesystem`, `runtime_configuration`, `retained_layer`, `build_history`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege.

**Partial control mapping:** [AUTH-05](#auth-05), [DATA-01](#data-01).

**Source organizations and relationships:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI010
invscan TARGET --scans AI010
```

### AI011

**Private key material in repository** · critical · `secrets`

**Looks for:** Private-key PEM headers accompanied by plausible encoded key data.

**Why it matters for agents/MCP/skills:** A signing or TLS key used by an agent gateway or MCP identity can let another party impersonate a service or forge trusted artifacts. A repository/image copy can outlive the file currently deployed.

**Deterministic algorithm:** PEM marker plus plausible encoded-material check. Profiles: `generic_text`.

**Can miss or require context:** Does not establish cryptographic validity, key use or test-versus-production ownership.

**Image context:** `final_filesystem`, `runtime_configuration`, `retained_layer`, `build_history`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Determine whether the key was used, revoke or rotate it if necessary, remove it from version history, and use a managed key store.

**Partial control mapping:** [AUTH-05](#auth-05), [DATA-01](#data-01).

**Source organizations and relationships:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI011
invscan TARGET --scans AI011
```

### AI012

**Dynamic JavaScript shell execution** · high · `tool_execution`

**Looks for:** Dynamic Node child-process shell execution APIs in supported import and call forms.

**Why it matters for agents/MCP/skills:** An agent or MCP tool can pass model-selected text to child_process.exec or a shell-enabled spawn. Shell parsing can grant extra command execution under the server account.

**Deterministic algorithm:** Tokenized child-process imports/calls with bounded alias handling. Profiles: `javascript_lexical`.

**Can miss or require context:** Not a full JavaScript/TypeScript parser or interprocedural taint engine; computed wrappers and dynamic imports may be missed.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use execFile or spawn with a fixed executable, validated argument array, and shell disabled; constrain tools by policy before execution.

**Partial control mapping:** [EXEC-01](#exec-01).

**Source organizations and relationships:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [TECH-NODE-PROCESS](https://nodejs.org/api/child_process.html) (Node.js contributors; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI012
invscan TARGET --scans AI012
```

### AI013

**Dynamic JavaScript code execution** · high · `tool_execution`

**Looks for:** Dynamic JavaScript eval or Function constructor arguments.

**Why it matters for agents/MCP/skills:** If planner output or tool results reach eval or a Function constructor, agent-controlled text can execute with the host application privileges rather than merely describe an operation.

**Deterministic algorithm:** Balanced token call matching and literal exclusion. Profiles: `javascript_lexical`.

**Can miss or require context:** Wrapper calls, runtime bindings, reachability and input provenance may remain unknown.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use validated structured data and allowlisted operations instead of evaluating generated code.

**Partial control mapping:** [EXEC-02](#exec-02).

**Source organizations and relationships:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI013
invscan TARGET --scans AI013
```

### AI014

**Externally influenced outbound request** · medium · `ssrf`

**Looks for:** Supported Python requests/httpx/urllib/aiohttp and JavaScript fetch/axios URL expressions with obvious external influence.

**Why it matters for agents/MCP/skills:** A fetch/search/browser MCP tool can turn a model-selected URL into a request from a privileged network location. An attacker may use retrieved instructions or tool arguments to target internal services or metadata.

**Deterministic algorithm:** Recognized HTTP sinks and bounded external-input propagation. Profiles: `python_ast`, `javascript_lexical`.

**Can miss or require context:** Cross-function flow, JavaScript wrappers, DNS/redirect behavior and guards can remain unresolved; a visible input signal is not proof of SSRF.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Allowlist destinations and schemes, resolve and validate addresses on each connection and redirect, block metadata/private destinations unless explicitly needed, and enforce egress policy.

**Partial control mapping:** [EXEC-05](#exec-05).

**Source organizations and relationships:** [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI014
invscan TARGET --scans AI014
```

### AI015

**Externally influenced filesystem path** · medium · `filesystem`

**Looks for:** Supported open/remove/copy/path operations and JavaScript fs read/write/delete operations using obvious external-input expressions.

**Why it matters for agents/MCP/skills:** Agent and MCP file tools can translate model-selected names into reads, writes or deletions. Without confinement, a prompt or tool result may reach server credentials, another tenant workspace or executable files.

**Deterministic algorithm:** Recognized filesystem sinks and bounded external-input propagation. Profiles: `python_ast`, `javascript_lexical`.

**Can miss or require context:** Canonicalization, symlink races, cross-function validation and effective filesystem confinement need further review.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Resolve paths under a fixed workspace root, reject paths outside it after canonicalization, handle symlinks safely, and give the process only required filesystem permissions.

**Partial control mapping:** [MCP-08](#mcp-08), [EXEC-04](#exec-04).

**Source organizations and relationships:** [MCP-ROOTS](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI015
invscan TARGET --scans AI015
```

### AI016

**Race-prone temporary filename creation** · medium · `filesystem`

**Looks for:** tempfile.mktemp usage, which returns a name without atomically creating the file.

**Why it matters for agents/MCP/skills:** An agent or MCP worker may stage sensitive tool inputs or outputs in temporary files. A name-only reservation lets another local process substitute a file or symlink before the worker opens it.

**Deterministic algorithm:** Resolved AST API matching. Profiles: `python_ast`.

**Can miss or require context:** Does not prove a concurrent attacker, downstream file permissions or whether the path is subsequently used.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use TemporaryFile, NamedTemporaryFile, TemporaryDirectory, or mkstemp with restrictive permissions and reliable cleanup.

**Partial control mapping:** [EXEC-04](#exec-04).

**Source organizations and relationships:** [MCP-ROOTS](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html) (Python Software Foundation; rule technical reference).

```sh
invscan --explain-scan AI016
invscan TARGET --scans AI016
```

### AI017

**JWT verification explicitly bypassed** · high · `authentication`

**Looks for:** Recognized Python JWT decode verification bypasses and JavaScript algorithms containing none.

**Why it matters for agents/MCP/skills:** MCP or agent gateways may use token claims to select tools, users and tenants. An unverified token can let caller-controlled claims impersonate authority across those boundaries.

**Deterministic algorithm:** JWT decode and literal algorithm/verification checks. Profiles: `python_ast`, `javascript_lexical`.

**Can miss or require context:** Does not establish a complete issuer/audience/scope policy or that unverified claims reach authorization.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Verify signature, algorithm allowlist, issuer, audience, expiry, and scopes before using claims for authorization.

**Partial control mapping:** [AUTH-03](#auth-03).

**Source organizations and relationships:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI017
invscan TARGET --scans AI017
```

### AI018

**MCP package runner resolves an unpinned artifact** · medium · `supply_chain`

**Looks for:** MCP launch configurations using supported ephemeral package runners without an exact package version.

**Why it matters for agents/MCP/skills:** An MCP client often launches a package with its local user permissions and injected credentials. Unpinned npx/uvx resolution can replace the tool implementation between launches without a reviewed configuration change.

**Deterministic algorithm:** Structured MCP command/argument package-version check. Profiles: `json_structured`.

**Can miss or require context:** Does not resolve the registry, verify provenance or inspect transitive dependencies; non-JSON launch formats may not receive this predicate.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Pin an exact audited package version and lock or verify transitive artifacts. Prefer preinstalled verified tools in a controlled environment.

**Partial control mapping:** [MCP-09](#mcp-09), [SUP-01](#sup-01).

**Source organizations and relationships:** [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI018
invscan TARGET --scans AI018
```

### AI019

**Remote download executed directly by a shell** · high · `supply_chain`

**Looks for:** curl/wget output directly piped to a shell or used as shell -c command text in supported shell/configuration contexts.

**Why it matters for agents/MCP/skills:** A tool bootstrap or agent image build that pipes downloaded text into a shell or uses it directly as shell command text lets the remote response choose commands under the build/runtime identity, potentially reaching deployment credentials.

**Deterministic algorithm:** Bounded shell token/command-substitution and pipeline patterns. Profiles: `configuration_lexical`, `generic_text`.

**Can miss or require context:** Not a complete shell interpreter; complex expansion, wrappers, runtime fetch destinations and remote artifact contents are not resolved.

**Image context:** `final_filesystem`, `build_history`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Fetch a versioned artifact, verify an independently trusted digest or signature, review it, and execute it under least privilege.

**Partial control mapping:** [SUP-03](#sup-03).

**Source organizations and relationships:** [NSA-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) (NSA, CISA, FBI and international partners; primary control source); [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [SLSA-12](https://slsa.dev/spec/v1.2/) (SLSA / OpenSSF; thematic alignment); [OPENSSF-MODEL-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/) (OpenSSF; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI019
invscan TARGET --scans AI019
```

### AI020

**GitHub Action reference is not pinned to a commit** · medium · `supply_chain`

**Looks for:** Remote action uses references lacking a reviewed full commit SHA in recognized workflow files.

**Why it matters for agents/MCP/skills:** Agent/MCP build and release workflows may possess signing, registry or deployment credentials. A mutable Action reference allows workflow code to change without a repository workflow edit.

**Deterministic algorithm:** GitHub workflow uses-reference pattern and full-SHA check. Profiles: `configuration_lexical`.

**Can miss or require context:** Pinning alone does not establish the action is safe, signed, reviewed or minimally privileged.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Pin remote actions to a reviewed full commit SHA and use dependency automation to propose updates.

**Partial control mapping:** [SUP-04](#sup-04).

**Source organizations and relationships:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OPENSSF-BASELINE-202608](https://baseline.openssf.org/versions/2026-08-28) (OpenSSF; thematic alignment); [SLSA-12](https://slsa.dev/spec/v1.2/) (SLSA / OpenSSF; thematic alignment); [TECH-GITHUB-ACTIONS](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) (GitHub; rule technical reference).

```sh
invscan --explain-scan AI020
invscan TARGET --scans AI020
```

### AI021

**Container explicitly runs as root** · medium · `sandboxing`

**Looks for:** Explicit/inherited literal root USER in the default final Dockerfile stage; built-image configured user/default UID 0 is separately checked.

**Why it matters for agents/MCP/skills:** An injected or overbroad agent/MCP tool action inherits the container process identity. Root can increase access to mounted data and the impact of an isolation failure, although container root is not automatically host root.

**Deterministic algorithm:** Dockerfile final-stage user tracking plus built-image user inspection. Profiles: `configuration_lexical`.

**Can miss or require context:** External Dockerfile base defaults, variables and selected build targets may be unresolved; deployed user overrides require runtime configuration.

**Image context:** `final_filesystem`, `runtime_configuration`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use a dedicated nonroot runtime user and minimal capabilities; verify the final build stage and deployment security context.

**Partial control mapping:** [SUP-05](#sup-05).

**Source organizations and relationships:** [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI021
invscan TARGET --scans AI021
```

### AI022

**Privileged container or privilege escalation enabled** · high · `sandboxing`

**Looks for:** Explicit privileged or allowPrivilegeEscalation settings in supported configuration.

**Why it matters for agents/MCP/skills:** Agent-selected tool actions in a privileged container can reach host-facing capabilities beyond the intended task. This can turn a tool compromise into a wider infrastructure incident.

**Deterministic algorithm:** Exact privilege-setting predicates. Profiles: `json_structured`, `configuration_lexical`.

**Can miss or require context:** Not a complete container capability or admission-policy audit; missing settings are not treated as proof of isolation.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Disable privileged mode and privilege escalation, drop capabilities, and expose only narrowly required devices or operations.

**Partial control mapping:** [SUP-05](#sup-05).

**Source organizations and relationships:** [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI022
invscan TARGET --scans AI022
```

### AI023

**Container runtime socket exposed** · high · `sandboxing`

**Looks for:** Recognized Docker/containerd runtime socket paths in supported configuration.

**Why it matters for agents/MCP/skills:** A model-influenced tool with Docker/containerd API access can control workloads and potentially host-mounted files. A socket mount bypasses many restrictions otherwise applied to the agent container.

**Deterministic algorithm:** Known runtime-socket path matching. Profiles: `json_structured`, `configuration_lexical`.

**Can miss or require context:** Presence does not prove the mount is active or writable; read-only filesystem mounts do not necessarily restrict socket API operations.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Remove runtime socket access or use a tightly scoped broker outside the agent sandbox. Read-only mounts do not necessarily make socket APIs read-only.

**Partial control mapping:** [SUP-05](#sup-05).

**Source organizations and relationships:** [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI023
invscan TARGET --scans AI023
```

### AI024

**Container image is not digest pinned** · low · `supply_chain`

**Looks for:** Mutable Dockerfile FROM or supported deployment image references rather than content digests.

**Why it matters for agents/MCP/skills:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves. That changes the code holding credentials and enforcing tool policy without a matching application source change.

**Deterministic algorithm:** Container reference parsing and digest-presence check. Profiles: `json_structured`, `configuration_lexical`.

**Can miss or require context:** No registry lookup, signature verification, CVE database or guarantee of safe pinned content.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability-remediation workflows.

**Partial control mapping:** [SUP-01](#sup-01), [SUP-03](#sup-03).

**Source organizations and relationships:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [NSA-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) (NSA, CISA, FBI and international partners; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [SLSA-12](https://slsa.dev/spec/v1.2/) (SLSA / OpenSSF; thematic alignment); [OPENSSF-MODEL-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/) (OpenSSF; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI024
invscan TARGET --scans AI024
```

### AI025

**Direct dependency is not exactly pinned** · low · `supply_chain`

**Looks for:** Recognized package.json dependency declarations and requirements-style entries permitting version movement; a local '.' self-install is excluded.

**Why it matters for agents/MCP/skills:** Agent SDKs, MCP libraries and tool dependencies execute inside the application trust boundary. Uncontrolled dependency changes can alter prompt handling, authentication or tool behavior with the same source revision.

**Deterministic algorithm:** Direct manifest dependency version-shape checks. Profiles: `json_structured`, `configuration_lexical`.

**Can miss or require context:** Lockfile inventory does not resolve the effective build or transitive graph; this is not a CVE, dependency-confusion or integrity assessment.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates.

**Partial control mapping:** [SUP-01](#sup-01).

**Source organizations and relationships:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI025
invscan TARGET --scans AI025
```

### AI026

**Authentication explicitly disabled** · high · `authentication`

**Looks for:** Supported authentication fields with the actual false value in code/configuration, including bounded supported YAML aliases.

**Why it matters for agents/MCP/skills:** A reachable MCP or agent service with disabled authentication can expose its tool authority to callers outside the intended user session. Direct local stdio instead relies on a process/OS boundary that must be assessed separately.

**Deterministic algorithm:** Explicit authentication-disable field matching. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** Local stdio may rely on the OS boundary; absent authentication code or custom middleware is not automatically classified.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** For remote protected resources, require authenticated clients and scoped per-tool authorization. Document local-only trust boundaries and protect launch configuration.

**Partial control mapping:** [AUTH-01](#auth-01).

**Source organizations and relationships:** [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI026
invscan TARGET --scans AI026
```

### AI027

**Wildcard tool or permission authorization** · high · `authorization`

**Looks for:** Supported tool, permission and resource allowlists granting '*', including bounded supported YAML aliases.

**Why it matters for agents/MCP/skills:** An agent with all-tools or wildcard permissions can turn a misinterpreted task or injected instruction into unrelated actions. Model-side tool selection does not limit a direct client calling the same server.

**Deterministic algorithm:** Literal tool/resource wildcard matching. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** Does not enumerate effective IAM permissions or validate argument/resource policy and approval at runtime.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Replace wildcard grants with named tools and constrained resources; enforce authorization server-side for each call and require approval for sensitive effects.

**Partial control mapping:** [AUTH-02](#auth-02), [AGT-01](#agt-01).

**Source organizations and relationships:** [JOINT-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services) (ASD ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK; primary control source); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [ASD-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses) (ASD ACSC; primary control source); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI027
invscan TARGET --scans AI027
```

### AI028

**MCP token passthrough enabled** · high · `authentication`

**Looks for:** Supported token-passthrough/forwarding settings explicitly enabled.

**Why it matters for agents/MCP/skills:** A server that forwards a caller token to another service can act as a confused intermediary, bypassing audience, consent and scope boundaries between the MCP resource and downstream tools.

**Deterministic algorithm:** Explicit token-forwarding field matching. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** Does not trace actual downstream token audiences, exchange flows or proxy behavior.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Validate tokens for this MCP resource and obtain separate audience-bound downstream credentials through an appropriate authorization flow.

**Partial control mapping:** [AUTH-04](#auth-04).

**Source organizations and relationships:** [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI028
invscan TARGET --scans AI028
```

### AI029

**Remote MCP URL uses plaintext HTTP** · high · `transport_security`

**Looks for:** Nonloopback plaintext HTTP endpoints in recognized MCP configuration.

**Why it matters for agents/MCP/skills:** Remote MCP requests can contain access tokens, task context and tool output. Plain HTTP exposes those bytes and allows modification by parties able to observe or influence the network path.

**Deterministic algorithm:** Structured MCP URL scheme and loopback classification. Profiles: `json_structured`.

**Can miss or require context:** Transport encryption outside the application, DNS trust and deployment-specific tunnels are unverified; other endpoint formats may be missed.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use HTTPS with certificate verification for remote MCP endpoints. Reserve plaintext HTTP for explicitly controlled local development or a documented protected transport.

**Partial control mapping:** [MCP-01](#mcp-01).

**Source organizations and relationships:** [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) (Model Context Protocol maintainers; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI029
invscan TARGET --scans AI029
```

### AI030

**Browser-side API credential access explicitly enabled** · medium · `secrets`

**Looks for:** dangerouslyAllowBrowser enabled in supported JavaScript/JSON fields.

**Why it matters for agents/MCP/skills:** A browser-facing agent may expose model or tool credentials through a bundled SDK configuration. Any page user or compromised script could then call the API outside the intended agent task and server authorization.

**Deterministic algorithm:** Explicit browser-SDK opt-in field matching. Profiles: `javascript_lexical`, `json_structured`.

**Can miss or require context:** Does not establish that a privileged long-lived credential actually reaches a browser bundle.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Keep durable API credentials on a trusted server, or use narrowly scoped short-lived client tokens designed for the browser.

**Partial control mapping:** [AUTH-05](#auth-05), [DATA-01](#data-01).

**Source organizations and relationships:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI030
invscan TARGET --scans AI030
```

### AI031

**Agent approval or sandbox safeguard explicitly bypassed** · high · `agent_permissions`

**Looks for:** Supported unrestricted agent approval/sandbox configuration and recognized dangerous CLI flags in applicable contexts.

**Why it matters for agents/MCP/skills:** Disabling agent approval or sandbox safeguards lets model-driven actions inherit the full process authority. Prompt injection or a mistaken plan can then modify files, send data or invoke credentials without the intended review boundary.

**Deterministic algorithm:** Known bypass flags and typed unrestricted-approval settings. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`, `generic_text`.

**Can miss or require context:** Cannot determine effective process permissions, external approval enforcement or whether the command actually runs.

**Image context:** `final_filesystem`, `runtime_configuration`, `build_history`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use bounded tool permissions and an isolated runtime; require deliberate approval for destructive, external, financial, or credential-bearing actions.

**Partial control mapping:** [MCP-09](#mcp-09), [AGT-01](#agt-01), [AGT-02](#agt-02), [SUP-05](#sup-05).

**Source organizations and relationships:** [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [ASD-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses) (ASD ACSC; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI031
invscan TARGET --scans AI031
```

### AI032

**External data inserted into privileged LLM instructions** · medium · `prompt_injection`

**Looks for:** Supported system/developer message objects with obviously external content.

**Why it matters for agents/MCP/skills:** External text inserted into a system/developer message is promoted into the same channel as trusted agent policy. A retrieved document or tool response may then steer planning and sensitive tool arguments.

**Deterministic algorithm:** Privileged message-role plus local external-input matching. Profiles: `python_ast`, `javascript_lexical`.

**Can miss or require context:** Does not detect every prompt injection, prove a model follows it or trace a prompt assembled across functions/services.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Keep trusted instructions separate from untrusted content, label provenance, enforce tool policy outside the model, and test indirect prompt injection and sensitive-action approval.

**Partial control mapping:** [AGT-03](#agt-03).

**Source organizations and relationships:** [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; primary control source); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI032
invscan TARGET --scans AI032
```

### AI033

**Potential secret included in logging call** · medium · `data_protection`

**Looks for:** Supported logging calls directly referencing credential-named variables, attributes or fields.

**Why it matters for agents/MCP/skills:** Agent traces and MCP logs commonly cross observability vendors, support systems and retention tiers. Logging a credential widens who can use the underlying model or tool authority beyond its intended worker.

**Deterministic algorithm:** Logging sink and credential-name matching. Profiles: `python_ast`, `javascript_lexical`.

**Can miss or require context:** Variable names can be misleading; sanitizers, custom loggers, downstream formatters and unusual secret names may be missed.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Log nonsecret identifiers and outcomes; redact credentials before formatting and restrict log access and retention.

**Partial control mapping:** [DATA-03](#data-03).

**Source organizations and relationships:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI033
invscan TARGET --scans AI033
```

### AI034

**Credential-like value embedded in URL query** · high · `data_protection`

**Looks for:** URLs embedding a nonplaceholder credential-like query value.

**Why it matters for agents/MCP/skills:** Agent and MCP connectors often record request URLs in traces, tool results or browser history. A credential in the query string can be copied to systems that were never authorized to use the downstream service.

**Deterministic algorithm:** URL query credential-name/value patterns. Profiles: `generic_text`.

**Can miss or require context:** Cannot establish live credential validity, deployed URL use or all custom query parameter names.

**Image context:** `final_filesystem`, `runtime_configuration`, `retained_layer`, `build_history`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use an appropriate authorization header or short-lived scoped credential; redact existing logs and rotate real exposed credentials.

**Partial control mapping:** [AUTH-05](#auth-05), [DATA-01](#data-01).

**Source organizations and relationships:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI034
invscan TARGET --scans AI034
```

### AI035

**Unsafe model checkpoint deserialization** · high · `model_supply_chain`

**Looks for:** torch.load(weights_only=False) and recognized load_model(..., safe_mode=False).

**Why it matters for agents/MCP/skills:** Model loaders may run in agent infrastructure with access to prompts, datasets and deployment credentials. A malicious executable checkpoint can run producer-controlled code when loaded, before inference or tool policy applies.

**Deterministic algorithm:** Explicit model-loader safety opt-out checks. Profiles: `python_ast`.

**Can miss or require context:** Does not inspect model bytes, evaluate architecture behavior or infer unsafe defaults across every framework/version.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use safe tensor formats or restricted weights-only loading, verify model provenance and integrity, and isolate model conversion workflows.

**Partial control mapping:** [EXEC-06](#exec-06), [SUP-03](#sup-03).

**Source organizations and relationships:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NSA-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) (NSA, CISA, FBI and international partners; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [SLSA-12](https://slsa.dev/spec/v1.2/) (SLSA / OpenSSF; thematic alignment); [OPENSSF-MODEL-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/) (OpenSSF; thematic alignment); [TECH-PYTORCH-SERIAL](https://pytorch.org/docs/stable/notes/serialization.html) (PyTorch contributors; rule technical reference); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI035
invscan TARGET --scans AI035
```

### AI036

**SQL query constructed with interpolation** · high · `tool_execution`

**Looks for:** Supported database execution calls with interpolated or concatenated query text.

**Why it matters for agents/MCP/skills:** A database MCP tool may interpolate model-selected filters or generated SQL. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant.

**Deterministic algorithm:** SQL execution sink plus interpolation/concatenation tracking. Profiles: `python_ast`, `javascript_lexical`.

**Can miss or require context:** Dynamic SQL identifiers may be intentionally allowlisted; cross-function parameterization and database-specific wrappers need review.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations.

**Partial control mapping:** [EXEC-03](#exec-03).

**Source organizations and relationships:** [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI036
invscan TARGET --scans AI036
```

### AI037

**Archive extraction without an explicit safe filter** · medium · `filesystem`

**Looks for:** Recognized tar extract/extractall calls without filter='data' or selecting a fully trusted filter.

**Why it matters for agents/MCP/skills:** Agents may unpack repository snapshots, uploaded datasets or MCP tool artifacts. Archive member paths and links can otherwise overwrite files used by the agent or expose material outside its workspace.

**Deterministic algorithm:** Tar object/API tracking and explicit extraction-filter check. Profiles: `python_ast`.

**Can miss or require context:** Runtime-version defaults, custom safe filters and member-validation wrappers may need review; this does not audit every archive format.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use filter='data' on supported runtimes, validate members and resource limits, and extract into an isolated directory with no sensitive files.

**Partial control mapping:** [EXEC-04](#exec-04).

**Source organizations and relationships:** [MCP-ROOTS](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [TECH-PYTHON-TAR](https://docs.python.org/3/library/tarfile.html#extraction-filters) (Python Software Foundation; rule technical reference).

```sh
invscan --explain-scan AI037
invscan TARGET --scans AI037
```

### AI038

**Cryptographically weak randomness used for a security value** · medium · `authentication`

**Looks for:** Credential-, nonce-, token- or secret-named assignments using the general-purpose random module.

**Why it matters for agents/MCP/skills:** Predictable agent session IDs, MCP access tokens or approval nonces may let another caller guess authority or replay an action. A general-purpose random generator does not provide that security guarantee.

**Deterministic algorithm:** Security-named assignment plus random API matching. Profiles: `python_ast`.

**Can miss or require context:** Name heuristics do not prove security use or entropy requirements; custom weak generators and JS randomness are not comprehensively analyzed.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use the secrets module or a cryptographically secure runtime API with sufficient entropy for security values.

**Partial control mapping:** [AUTH-06](#auth-06), [MCP-05](#mcp-05).

**Source organizations and relationships:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html) (Python Software Foundation; rule technical reference).

```sh
invscan --explain-scan AI038
invscan TARGET --scans AI038
```

### AI039

**Server-Side Template rendered from a dynamic template** · high · `tool_execution`

**Looks for:** Dynamic Flask render_template_string or Jinja2 Template source.

**Why it matters for agents/MCP/skills:** An agent or MCP tool may render generated reports, emails or pages. If model/user content becomes server-side template source, template expressions can access server objects or operations under the tool identity.

**Deterministic algorithm:** Recognized template-source sink and constant exclusion. Profiles: `python_ast`.

**Can miss or require context:** Template contents, sandbox configuration, wrapper calls and actual attacker control require context.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use a fixed trusted template and pass untrusted content only as escaped data; sandbox and limit any intentional template authoring.

**Partial control mapping:** [EXEC-07](#exec-07).

**Source organizations and relationships:** [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI039
invscan TARGET --scans AI039
```

### AI040

**Unsafe HTML rendering boundary** · medium · `output_handling`

**Looks for:** Supported innerHTML, insertAdjacentHTML and dangerouslySetInnerHTML dynamic assignments.

**Why it matters for agents/MCP/skills:** Agent messages and MCP results may contain attacker-origin content. Passing that output to innerHTML, dangerouslySetInnerHTML or a similar raw sink can execute browser markup with access to the application session.

**Deterministic algorithm:** Raw-HTML sink and dynamic-value matching. Profiles: `javascript_lexical`.

**Can miss or require context:** Does not validate a sanitizer, framework escaping, browser CSP or DOM behavior at runtime.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Render untrusted output as text or sanitize with a maintained HTML policy before using a raw-HTML sink; apply a restrictive content security policy.

**Partial control mapping:** [EXEC-07](#exec-07).

**Source organizations and relationships:** [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI040
invscan TARGET --scans AI040
```

### AI041

**MCP inspector authorization explicitly disabled** · high · `authentication`

**Looks for:** Recognized DANGEROUSLY_OMIT_AUTH assignments with a nonempty value; strings 'false' and '0' still disable the safeguard.

**Why it matters for agents/MCP/skills:** MCP Inspector can reach connected servers and their tool permissions. A reachable unauthenticated inspector can expose that authority outside the intended developer session.

**Deterministic algorithm:** Inspector environment/configuration nonempty-value semantics. Profiles: `python_ast`, `javascript_lexical`, `json_structured`, `configuration_lexical`.

**Can miss or require context:** Does not determine Inspector reachability or runtime environment overrides; an empty string alone is not treated as enabled.

**Image context:** `final_filesystem`, `runtime_configuration`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Retain inspector authentication and restrict its listeners and origins to a controlled development environment.

**Partial control mapping:** [AUTH-01](#auth-01).

**Source organizations and relationships:** [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI041
invscan TARGET --scans AI041
```

### AI042

**Container uses host namespaces** · high · `sandboxing`

**Looks for:** hostPID/hostNetwork enabled or supported pid/network_mode values set to host.

**Why it matters for agents/MCP/skills:** Host PID or network namespace sharing lets an agent or MCP tool observe or interact with host-level processes or services beyond its isolated workload. Model-influenced actions may then reach assets outside the intended task sandbox.

**Deterministic algorithm:** Explicit host namespace setting checks. Profiles: `json_structured`, `configuration_lexical`.

**Can miss or require context:** Does not inventory all namespace, seccomp, capability or kernel-isolation behavior in a running deployment.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Use isolated namespaces and explicit network rules; document and minimize any unavoidable host-level access.

**Partial control mapping:** [SUP-05](#sup-05).

**Source organizations and relationships:** [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [CISA-SECURE-BY-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design) (CISA and U.S./international partners; rule technical reference).

```sh
invscan --explain-scan AI042
invscan TARGET --scans AI042
```

### AI043

**Instruction-hierarchy override in agent-facing text** · high · `prompt_injection`

**Looks for:** Recognized agent/skill instructions or literal tool descriptions directing an override of higher-priority instructions or policy.

**Why it matters for agents/MCP/skills:** A tool description or skill instruction can be inserted into model context before invocation; an override directive attempts to cross the boundary from external data into agent authority.

**Deterministic algorithm:** Bounded instruction extraction, normalization and action/object predicates. Profiles: `instruction_text`, `tool_metadata`.

**Can miss or require context:** Pattern evidence does not establish intent or successful prompt injection; non-English instructions, indirect authority replacement, paraphrases, unsupported encodings and dynamic descriptions may evade detection.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Remove the override directive, keep tool metadata scoped to its function, and enforce instruction/data separation and sensitive-action policy outside the model. Test the exact text against the deployed agent with harmless canary actions.

**Partial control mapping:** [MCP-03](#mcp-03), [AGT-03](#agt-03), [AGT-06](#agt-06).

**Source organizations and relationships:** [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; primary control source); [MITRE-ATLAS](https://github.com/mitre-atlas/atlas-data) (MITRE; primary control source); [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; primary control source); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; rule technical reference); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; rule technical reference); [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; rule technical reference).

```sh
invscan --explain-scan AI043
invscan TARGET --scans AI043
```

### AI044

**Sensitive-data transfer instruction** · high · `data_protection`

**Looks for:** Recognized English instructions transferring a directly named sensitive credential/file, or previously read sensitive data via a pronoun, to an explicit URL/email destination following the transfer.

**Why it matters for agents/MCP/skills:** An instruction that directs an agent to gather a credential or sensitive file and send it to a URL/email can turn an otherwise legitimate tool into a disclosure path.

**Deterministic algorithm:** Sensitive-object, transfer-action and explicit-destination predicates. Profiles: `instruction_text`, `tool_metadata`.

**Can miss or require context:** Does not establish actual access, an executed network request or an attacker's ownership of the destination; implicit destinations and staged transfers may be missed.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Remove credential collection from tool descriptions and skill instructions. Use a scoped credential broker, allowlist outbound destinations, redact tool inputs and require approval displaying the actual recipient and data before any sensitive disclosure.

**Partial control mapping:** [MCP-03](#mcp-03), [AGT-06](#agt-06), [AGT-07](#agt-07).

**Source organizations and relationships:** [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [MITRE-ATLAS](https://github.com/mitre-atlas/atlas-data) (MITRE; primary control source); [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; primary control source); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; rule technical reference); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; rule technical reference); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI044
invscan TARGET --scans AI044
```

### AI045

**Covert action or approval-bypass instruction** · high · `agent_permissions`

**Looks for:** Recognized instructions pairing an action with concealment from the user, or directing approval/sandbox bypass.

**Why it matters for agents/MCP/skills:** Concealment or approval-bypass text in skills/tool descriptions can induce the planner to exceed user-authorized actions under the agent or MCP process identity.

**Deterministic algorithm:** Action/concealment and approval-bypass instruction predicates. Profiles: `instruction_text`, `tool_metadata`.

**Can miss or require context:** Cannot establish deceptive intent from all natural-language variations; legitimate quoted security examples are excluded only where the bounded parser recognizes them.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Delete the concealment or bypass directive. Bind approvals to the exact operation and arguments, enforce policy in the tool server, retain auditable execution records and isolate the process with minimum privileges.

**Partial control mapping:** [AGT-02](#agt-02), [AGT-06](#agt-06).

**Source organizations and relationships:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [MITRE-ATLAS](https://github.com/mitre-atlas/atlas-data) (MITRE; primary control source); [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; primary control source); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; rule technical reference); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; rule technical reference); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI045
invscan TARGET --scans AI045
```

### AI046

**Read-only tool annotation contradicts a destructive description** · medium · `tool_integrity`

**Looks for:** Literal readOnlyHint=true paired with a recognized destructive write/delete/modify instruction in the same tool description.

**Why it matters for agents/MCP/skills:** An MCP client may prioritize tools or reduce consent using annotations; an explicit destructive description paired with readOnlyHint=true exposes conflicting metadata at that trust boundary.

**Deterministic algorithm:** Same-descriptor readOnlyHint/operation consistency check. Profiles: `tool_metadata`.

**Can miss or require context:** A description/annotation contradiction is a review signal, not proof of handler behavior; a truthful-looking description can hide malicious implementation.

**Image context:** `final_filesystem`. Packaged-file analysis still needs the supported source/descriptor form.

**Optional AI adds:** Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding. Full mode reviews the selected active controls even with zero rule matches. It can propose evidence-backed gaps missed by local patterns; it does not execute tools or validate runtime behavior.

**Fix direction:** Inspect the implementation and correct its description and annotations together. Treat the tool as potentially mutating until verified, reapprove changed metadata and enforce write authorization independently of model decisions or annotation hints.

**Partial control mapping:** [MCP-03](#mcp-03), [MCP-04](#mcp-04).

**Source organizations and relationships:** [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; rule technical reference); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; rule technical reference).

```sh
invscan --explain-scan AI046
invscan TARGET --scans AI046
```

## All control review plans

These 66 controls and 132 acceptance checks are the broader scope reviewed in full optional mode, subject to selection, explicit exceptions and budgets. 30 controls have at least one mapped deterministic pattern. Each rule is partial control-level coverage; it does not prove either acceptance check is automated. Controls with no mapped rules remain visible. Exact primary and thematic source roles are preserved below.

### GOV-01

**Inventory every agent, MCP server, tool, and model** · Governance · validation: `manual`

Maintain a reconciled inventory of the components that can read data, make decisions or execute actions.

**Why it matters:** An unregistered tool or endpoint can inherit access without a responsible owner or security review.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **GOV-01:1:** Record owner, deployment, model/version, MCP transport/version, exposed tools, data classes, and external endpoints.
- **GOV-01:2:** Reconcile approved inventory with deployed configurations; investigate unregistered agents and servers.

**Sources:** [NIST-RMF](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10) (NIST; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-AISMM](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment).

```sh
invscan --explain-scan GOV-01
invscan TARGET --scans GOV-01 --judge-cli claude
```

### GOV-02

**Model trust boundaries and attack paths** · Governance · validation: `manual`

Describe where identities, data and authority cross between components, then trace possible attack paths.

**Why it matters:** A harmless-looking input can become a privileged action after several tool or delegation steps.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **GOV-02:1:** Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials.
- **GOV-02:2:** Identify who controls each input and the highest-impact action reachable if that input is malicious.

**Sources:** [MITRE-ATLAS](https://github.com/mitre-atlas/atlas-data) (MITRE; primary control source); [NIST-AML](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) (NIST; primary control source); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [MITRE-ATLAS-202609](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09) (MITRE; thematic alignment).

```sh
invscan --explain-scan GOV-02
invscan TARGET --scans GOV-02 --judge-cli claude
```

### GOV-03

**Define authorized use and accountable owners** · Governance · validation: `manual`

Define the permitted purpose and consequences of autonomous actions and name the accountable owner.

**Why it matters:** An agent can act within its technical permissions while still performing an unauthorized business operation.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **GOV-03:1:** Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes.
- **GOV-03:2:** Record impact, reversibility, approval requirements, and accepted residual risk before production use.

**Sources:** [NIST-RMF](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10) (NIST; primary control source); [JOINT-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services) (ASD ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [CSA-AISMM](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model) (Cloud Security Alliance; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan GOV-03
invscan TARGET --scans GOV-03 --judge-cli claude
```

### GOV-04

**Maintain evidence and risk exceptions** · Governance · validation: `manual`

Keep dated evidence and explicitly governed exceptions for each applicable safeguard.

**Why it matters:** An undocumented acceptance or expired exception can conceal an untested boundary for later releases.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **GOV-04:1:** Give each control an owner, evidence link, validation date, result, and next review date.
- **GOV-04:2:** Time-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure.

**Sources:** [NIST-GENAI](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) (NIST; primary control source); [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-AISMM](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model) (Cloud Security Alliance; thematic alignment); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment).

```sh
invscan --explain-scan GOV-04
invscan TARGET --scans GOV-04 --judge-cli claude
```

### GOV-05

**Reassess changes in autonomy and integrations** · Governance · validation: `manual`

Reassess the complete system when models, tools, data sources or autonomy change.

**Why it matters:** A previously reviewed component can gain new authority through a new integration or configuration.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **GOV-05:1:** Review security impact when adding a model, tool, server, data source, skill, or broader permission.
- **GOV-05:2:** Require deployment evidence for the complete configured system; a model-only score is insufficient.

**Sources:** [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment).

```sh
invscan --explain-scan GOV-05
invscan TARGET --scans GOV-05 --judge-cli claude
```

### GOV-06

**Assign shared security responsibilities across AI providers** · Governance · validation: `manual`

Assign each security responsibility across suppliers and the customer-operated components.

**Why it matters:** A safeguard can remain unimplemented when every party assumes another provider owns it.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **GOV-06:1:** For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on.
- **GOV-06:2:** Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review.

**Sources:** [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; primary control source).

```sh
invscan --explain-scan GOV-06
invscan TARGET --scans GOV-06 --judge-cli claude
```

### AUTH-01

**Authenticate protected operations on every request** · Identity and authorization · validation: `hybrid`

Require verified authentication at every protected operation, including alternate routes and retries.

**Why it matters:** A single reachable bypass can expose tools even when the normal client login succeeds.

**Deterministic:** Partial rules [AI026](#ai026), [AI041](#ai041).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-01:1:** Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries.
- **AUTH-01:2:** Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation.

**Sources:** [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AUTH-01
invscan TARGET --scans AUTH-01 --judge-cli claude
```

### AUTH-02

**Authorize the exact action and target** · Identity and authorization · validation: `hybrid`

Authorize the exact identity, tenant, operation and resource immediately before the action.

**Why it matters:** Being logged in does not grant permission to every tool or every other user's objects.

**Deterministic:** Partial rules [AI027](#ai027).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-02:1:** Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution.
- **AUTH-02:2:** Deny by default; test read-only callers against write tools and object identifiers owned by another user.

**Sources:** [JOINT-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services) (ASD ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK; primary control source); [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AUTH-02
invscan TARGET --scans AUTH-02 --judge-cli claude
```

### AUTH-03

**Validate access-token cryptography and claims** · Identity and authorization · validation: `hybrid`

Verify access-token signatures and required claims using trusted keys and explicit algorithms.

**Why it matters:** Decoded claims can be forged or valid for a different service if validation is incomplete.

**Deterministic:** Partial rules [AI017](#ai017).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-03:1:** Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes.
- **AUTH-03:2:** Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation.

**Sources:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AUTH-03
invscan TARGET --scans AUTH-03 --judge-cli claude
```

### AUTH-04

**Prevent token passthrough and confused deputy use** · Identity and authorization · validation: `hybrid`

Keep caller authorization distinct from downstream service credentials.

**Why it matters:** A proxy may otherwise lend its broader identity to a caller or forward tokens to an unintended recipient.

**Deterministic:** Partial rules [AI028](#ai028).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-04:1:** Use audience-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens.
- **AUTH-04:2:** Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize.

**Sources:** [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AUTH-04
invscan TARGET --scans AUTH-04 --judge-cli claude
```

### AUTH-05

**Constrain credential lifetime and exposure** · Identity and authorization · validation: `hybrid`

Limit credential scope and lifetime and prevent unnecessary copies or disclosure.

**Why it matters:** A leaked long-lived token can preserve an agent's access after the original task or session ends.

**Deterministic:** Partial rules [AI010](#ai010), [AI011](#ai011), [AI030](#ai030), [AI034](#ai034).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-05:1:** Use short-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation.
- **AUTH-05:2:** Avoid tokens in query strings, model context, source, child-process arguments, and diagnostic output.

**Sources:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AUTH-05
invscan TARGET --scans AUTH-05 --judge-cli claude
```

### AUTH-06

**Bind OAuth flows and validate redirects** · Identity and authorization · validation: `hybrid`

Bind an OAuth authorization response to the intended transaction and registered redirect.

**Why it matters:** A valid-looking callback can be replayed or redirected into the wrong client or authorization flow.

**Deterministic:** Partial rules [AI038](#ai038).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-06:1:** Test PKCE support and S256, exact registered redirects, transaction binding, and authorization-response issuer validation.
- **AUTH-06:2:** Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions.

**Sources:** [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) (Model Context Protocol maintainers; primary control source); [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan AUTH-06
invscan TARGET --scans AUTH-06 --judge-cli claude
```

### AUTH-07

**Secure OAuth discovery and registration** · Identity and authorization · validation: `hybrid`

Constrain OAuth metadata discovery and client registration to trusted, bounded inputs.

**Why it matters:** Fetching attacker-chosen metadata can cross an internal network boundary before authentication completes.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-07:1:** Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes.
- **AUTH-07:2:** Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services.

**Sources:** [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan AUTH-07
invscan TARGET --scans AUTH-07 --judge-cli claude
```

### AUTH-08

**Bind delegation to identity, scope, and expiry** · Identity and authorization · validation: `hybrid`

Carry authenticated delegation identity and bound the authority passed to another agent.

**Why it matters:** Text that names a trusted initiator must not create that initiator's privileges.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-08:1:** Carry authenticated initiator and delegation identity through multi-agent calls instead of trusting identity fields in text.
- **AUTH-08:2:** Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences.

**Sources:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [NIST-AGENT-IDENTITY-DRAFT](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept) (NIST National Cybersecurity Center of Excellence; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AUTH-08
invscan TARGET --scans AUTH-08 --judge-cli claude
```

### AUTH-09

**Manage agent identity enrollment and retirement** · Identity and authorization · validation: `dynamic`

Govern agent identity creation, sponsorship and retirement as a workload lifecycle.

**Why it matters:** Stale identities can retain credentials, registrations or cached grants after their sponsor or deployment disappears.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **AUTH-09:1:** Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access.
- **AUTH-09:2:** Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access.

**Sources:** [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; primary control source); [NIST-AGENT-IDENTITY-DRAFT](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept) (NIST National Cybersecurity Center of Excellence; primary control source).

```sh
invscan --explain-scan AUTH-09
invscan TARGET --scans AUTH-09 --judge-cli claude
```

### MCP-01

**Validate transport exposure and origin** · MCP protocol and tools · validation: `hybrid`

Constrain network exposure and verify the origin and transport of MCP HTTP traffic.

**Why it matters:** An unintended browser origin, interface or unverified TLS connection can reach or impersonate a service.

**Deterministic:** Partial rules [AI006](#ai006), [AI007](#ai007), [AI008](#ai008), [AI029](#ai029).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-01:1:** For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces.
- **MCP-01:2:** Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment.

**Sources:** [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) (Model Context Protocol maintainers; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan MCP-01
invscan TARGET --scans MCP-01 --judge-cli claude
```

### MCP-02

**Validate tool arguments and results** · MCP protocol and tools · validation: `hybrid`

Validate tool inputs and outputs against schemas and semantic limits.

**Why it matters:** Well-formed JSON can still request an unauthorized target, consume excessive resources or carry misleading results.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-02:1:** Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate.
- **MCP-02:2:** Bound sizes and nesting; validate declared structured output and render errors without leaking secrets.

**Sources:** [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan MCP-02
invscan TARGET --scans MCP-02 --judge-cli claude
```

### MCP-03

**Treat descriptions and annotations as untrusted** · MCP protocol and tools · validation: `hybrid`

Treat tool descriptions, annotations, resources and results as untrusted claims.

**Why it matters:** A malicious server can present instructions or safety hints that influence tool selection or approval.

**Deterministic:** Partial rules [AI043](#ai043), [AI044](#ai044), [AI046](#ai046).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-03:1:** Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries.
- **MCP-03:2:** Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy.

**Sources:** [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan MCP-03
invscan TARGET --scans MCP-03 --judge-cli claude
```

### MCP-04

**Detect tool substitution and metadata changes** · MCP protocol and tools · validation: `hybrid`

Bind approved tools to verified server identity and reviewed definitions, and recheck changes.

**Why it matters:** A tool can keep its display name while changing its arguments or effects after approval.

**Deterministic:** Partial rules [AI046](#ai046).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-04:1:** Bind tool approval to verified server identity and the reviewed tool definition or version.
- **MCP-04:2:** Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names.

**Sources:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan MCP-04
invscan TARGET --scans MCP-04 --judge-cli claude
```

### MCP-05

**Protect state handles and legacy sessions** · MCP protocol and tools · validation: `dynamic`

Authorize state handles and, where applicable, legacy session resumption.

**Why it matters:** Possession of a handle can become unauthorized access if ownership, tenant or expiry checks are missing.

**Deterministic:** Partial rules [AI038](#ai038).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-05:1:** Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries.
- **MCP-05:2:** For older sessionful protocol versions, test session hijacking and cross-user resumption; a session ID is not authentication.

**Sources:** [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) (Model Context Protocol maintainers; primary control source); [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan MCP-05
invscan TARGET --scans MCP-05 --judge-cli claude
```

### MCP-06

**Constrain sampling and returned model context** · MCP protocol and tools · validation: `dynamic`

Apply host policy and user control to server-requested sampling and shared context.

**Why it matters:** An untrusted server may induce access to unrelated conversations or recursive model consumption.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-06:1:** Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access.
- **MCP-06:2:** Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget.

**Sources:** [MCP-SAMPLING](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan MCP-06
invscan TARGET --scans MCP-06 --judge-cli claude
```

### MCP-07

**Secure elicitation and URL interactions** · MCP protocol and tools · validation: `hybrid`

Constrain elicitation requests and visibly identify URL interactions.

**Why it matters:** An apparently helpful workflow can collect credentials or direct a user to an attacker-controlled destination.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-07:1:** Keep sensitive credential collection out of form-mode elicitation; validate and visibly identify URL destinations.
- **MCP-07:2:** Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version.

**Sources:** [MCP-ELICITATION](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan MCP-07
invscan TARGET --scans MCP-07 --judge-cli claude
```

### MCP-08

**Enforce filesystem isolation independently of roots** · MCP protocol and tools · validation: `hybrid`

Enforce actual filesystem permissions independently of declared MCP roots.

**Why it matters:** Roots describe intended scope but cannot prevent a server process from accessing other paths.

**Deterministic:** Partial rules [AI015](#ai015).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-08:1:** Treat declared roots as scoped information, not an operating-system sandbox or complete authorization mechanism.
- **MCP-08:2:** Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace.

**Sources:** [MCP-ROOTS](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan MCP-08
invscan TARGET --scans MCP-08 --judge-cli claude
```

### MCP-09

**Constrain local server launch and inherited environment** · MCP protocol and tools · validation: `hybrid`

Approve local server executables and constrain their inherited environment and process access.

**Why it matters:** Launching a stdio server can give package code the host user's credentials and filesystem access.

**Deterministic:** Partial rules [AI018](#ai018), [AI031](#ai031).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-09:1:** Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment.
- **MCP-09:2:** Restrict proxy process-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs.

**Sources:** [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source); [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan MCP-09
invscan TARGET --scans MCP-09 --judge-cli claude
```

### MCP-10

**Apply version-aware metadata, caching, and cancellation** · MCP protocol and tools · validation: `dynamic`

Apply the deployed protocol revision's capability, stream, cache and cancellation rules.

**Why it matters:** Assuming another revision's handshake or state model can leave authorization context inconsistent.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **MCP-10:1:** Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules.
- **MCP-10:2:** Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally.

**Sources:** [MCP-TRANSPORTS](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) (Model Context Protocol maintainers; primary control source); [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan MCP-10
invscan TARGET --scans MCP-10 --judge-cli claude
```

### AGT-01

**Enforce action policy outside the model** · Agent behavior and context · validation: `hybrid`

Enforce trusted action policy at the tool execution boundary outside the model.

**Why it matters:** An instruction-following model can be redirected; its refusal or approval is not an access-control decision.

**Deterministic:** Partial rules [AI027](#ai027), [AI031](#ai031).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-01:1:** Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities.
- **AGT-01:2:** Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval.

**Sources:** [ASD-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses) (ASD ACSC; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan AGT-01
invscan TARGET --scans AGT-01 --judge-cli claude
```

### AGT-02

**Bind approval to the action executed** · Agent behavior and context · validation: `dynamic`

Bind human approval to the precise action that will execute.

**Why it matters:** A changed recipient, argument or delayed retry can exceed what the person approved.

**Deterministic:** Partial rules [AI031](#ai031), [AI045](#ai045).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-02:1:** Present actual recipient, target, arguments, data disclosure, and consequences for high-impact approval.
- **AGT-02:2:** Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse.

**Sources:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AGT-02
invscan TARGET --scans AGT-02 --judge-cli claude
```

### AGT-03

**Separate untrusted content from authoritative instructions** · Agent behavior and context · validation: `hybrid`

Preserve the distinction between trusted instructions and externally controlled content.

**Why it matters:** Retrieved text, tool results or repository files can try to redirect the agent's objective or authority.

**Deterministic:** Partial rules [AI032](#ai032), [AI043](#ai043).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-03:1:** Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions.
- **AGT-03:2:** Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls.

**Sources:** [OWASP-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) (OWASP GenAI Security Project; primary control source).

```sh
invscan --explain-scan AGT-03
invscan TARGET --scans AGT-03 --judge-cli claude
```

### AGT-04

**Protect retrieval and persistent memory** · Agent behavior and context · validation: `hybrid`

Protect retrieval and persistent memory at both read and update boundaries.

**Why it matters:** Poisoned memory can influence later sessions, and incomplete retrieval filters can expose another tenant's data.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-04:1:** Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters.
- **AGT-04:2:** Test poisoned memory persistence, cross-tenant retrieval, provenance loss, deletion, and stale privileged context.

**Sources:** [OWASP-AGENTIC](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (OWASP GenAI Security Project; primary control source); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment).

```sh
invscan --explain-scan AGT-04
invscan TARGET --scans AGT-04 --judge-cli claude
```

### AGT-05

**Keep objectives and authority bounded across agents** · Agent behavior and context · validation: `dynamic`

Keep delegated goals and privileges bounded across multi-agent handoffs.

**Why it matters:** A chain of agents can amplify authority, lose the original objective or accept impersonated messages.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-05:1:** Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions.
- **AGT-05:2:** Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs.

**Sources:** [OWASP-AGENTIC](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (OWASP GenAI Security Project; primary control source); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan AGT-05
invscan TARGET --scans AGT-05 --judge-cli claude
```

### AGT-06

**Protect agent configuration and skills** · Agent behavior and context · validation: `hybrid`

Protect the configuration and workflow files that define agent behavior.

**Why it matters:** A changed skill, hook or seed file can silently add commands, access or persistence.

**Deterministic:** Partial rules [AI043](#ai043), [AI044](#ai044), [AI045](#ai045).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-06:1:** Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs.
- **AGT-06:2:** Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy.

**Sources:** [MITRE-ATLAS](https://github.com/mitre-atlas/atlas-data) (MITRE; primary control source); [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [AGENT-SKILLS-SPEC](https://agentskills.io/specification) (Agent Skills maintainers; primary control source); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan AGT-06
invscan TARGET --scans AGT-06 --judge-cli claude
```

### AGT-07

**Prevent sensitive context leaving through legitimate tools** · Agent behavior and context · validation: `dynamic`

Apply data and destination policy to otherwise legitimate tool calls.

**Why it matters:** An allowed message, search or upload tool can still move sensitive context to an unauthorized recipient.

**Deterministic:** Partial rules [AI044](#ai044).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **AGT-07:1:** Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents.
- **AGT-07:2:** Use canary data to test encoded leakage and combinations of otherwise permitted tools.

**Sources:** [OWASP-MCP-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source).

```sh
invscan --explain-scan AGT-07
invscan TARGET --scans AGT-07 --judge-cli claude
```

### EXEC-01

**Prevent shell and command injection** · Execution and application security · validation: `hybrid`

Keep untrusted values out of shell syntax and constrain allowed command arguments.

**Why it matters:** Agent-generated text may become a command or option rather than inert data.

**Deterministic:** Partial rules [AI002](#ai002), [AI003](#ai003), [AI012](#ai012).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-01:1:** Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values.
- **EXEC-01:2:** Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames.

**Sources:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source).

```sh
invscan --explain-scan EXEC-01
invscan TARGET --scans EXEC-01 --judge-cli claude
```

### EXEC-02

**Constrain generated-code execution** · Execution and application security · validation: `hybrid`

Constrain any feature that evaluates generated code in a disposable execution environment.

**Why it matters:** A model or tool result reaching an interpreter gains the process's effective authority.

**Deterministic:** Partial rules [AI001](#ai001), [AI013](#ai013).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-02:1:** Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content.
- **EXEC-02:2:** Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits.

**Sources:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan EXEC-02
invscan TARGET --scans EXEC-02 --judge-cli claude
```

### EXEC-03

**Parameterize database and query operations** · Execution and application security · validation: `hybrid`

Parameterize query values and constrain permitted query shapes and database identities.

**Why it matters:** Generated queries can escape an intended object or operation even when the database connection is authorized.

**Deterministic:** Partial rules [AI036](#ai036).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-03:1:** Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search-language construction.
- **EXEC-03:2:** Separate read/write database identities and test whether generated queries can escape permitted objects or operations.

**Sources:** [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source).

```sh
invscan --explain-scan EXEC-03
invscan TARGET --scans EXEC-03 --judge-cli claude
```

### EXEC-04

**Constrain file and archive access** · Execution and application security · validation: `hybrid`

Constrain file, archive and temporary-file operations at the moment of access.

**Why it matters:** Traversal, overwrite and link races can move data or execution beyond the approved workspace.

**Deterministic:** Partial rules [AI015](#ai015), [AI016](#ai016), [AI037](#ai037).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-04:1:** Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions.
- **EXEC-04:2:** Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret-directory reads.

**Sources:** [MCP-ROOTS](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) (Model Context Protocol maintainers; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source).

```sh
invscan --explain-scan EXEC-04
invscan TARGET --scans EXEC-04 --judge-cli claude
```

### EXEC-05

**Prevent SSRF and unsafe network destinations** · Execution and application security · validation: `hybrid`

Restrict actual network destinations, including DNS resolution and redirects.

**Why it matters:** A user-selected URL can turn an agent tool into a route to internal services or cloud metadata.

**Deterministic:** Partial rules [AI014](#ai014).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-05:1:** Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect.
- **EXEC-05:2:** Test loopback, private/link-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect-to-private cases.

**Sources:** [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (Model Context Protocol maintainers; primary control source).

```sh
invscan --explain-scan EXEC-05
invscan TARGET --scans EXEC-05 --judge-cli claude
```

### EXEC-06

**Reject unsafe parsing and deserialization** · Execution and application security · validation: `hybrid`

Use data-only parsers with explicit type and resource bounds.

**Why it matters:** Object construction or parser expansion can execute code or exhaust a tool process.

**Deterministic:** Partial rules [AI004](#ai004), [AI005](#ai005), [AI035](#ai035).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-06:1:** Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers.
- **EXEC-06:2:** Use data-only formats with byte, nesting, and type limits; test malformed input and expansion attacks.

**Sources:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source).

```sh
invscan --explain-scan EXEC-06
invscan TARGET --scans EXEC-06 --judge-cli claude
```

### EXEC-07

**Render model and tool output safely** · Execution and application security · validation: `hybrid`

Render model and tool output using context-appropriate escaping and safe URL handling.

**Why it matters:** Untrusted output can become executable content in a browser, terminal or exported document.

**Deterministic:** Partial rules [AI039](#ai039), [AI040](#ai040).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **EXEC-07:1:** Use context-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media.
- **EXEC-07:2:** Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports.

**Sources:** [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source).

```sh
invscan --explain-scan EXEC-07
invscan TARGET --scans EXEC-07 --judge-cli claude
```

### DATA-01

**Detect and remove embedded credentials** · Data and privacy · validation: `static`

Locate embedded credential-like material and investigate its real exposure.

**Why it matters:** Source, fixtures or built artifacts may distribute a usable credential beyond its intended audience.

**Deterministic:** Partial rules [AI010](#ai010), [AI011](#ai011), [AI030](#ai030), [AI034](#ai034).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **DATA-01:1:** Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret-like values.
- **DATA-01:2:** Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts.

**Sources:** [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan DATA-01
invscan TARGET --scans DATA-01 --judge-cli claude
```

### DATA-02

**Minimize data sent to models and gateways** · Data and privacy · validation: `manual`

Minimize and authorize data sent to each model or gateway recipient.

**Why it matters:** Prompts and tool outputs may disclose information under a provider's processing or retention terms.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **DATA-02:1:** Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway.
- **DATA-02:2:** Document allowed data classes, processing location, retention, and training use; redact before transmission where required.

**Sources:** [NIST-GENAI](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) (NIST; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan DATA-02
invscan TARGET --scans DATA-02 --judge-cli claude
```

### DATA-03

**Protect logs, traces, and error responses** · Data and privacy · validation: `hybrid`

Prevent logs, traces and error messages from becoming secondary data leaks.

**Why it matters:** Diagnostic paths can retain credentials and private prompts even when normal responses are sanitized.

**Deterministic:** Partial rules [AI009](#ai009), [AI033](#ai033).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **DATA-03:1:** Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them.
- **DATA-03:2:** Test the failure paths and provider errors as well as success paths; restrict access and export destinations.

**Sources:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan DATA-03
invscan TARGET --scans DATA-03 --judge-cli claude
```

### DATA-04

**Track provenance and integrity of AI data** · Data and privacy · validation: `manual`

Track the origin, transformations and integrity of the data that drives AI behavior.

**Why it matters:** Poisoned or stale retrieval and training inputs can outlive the event that introduced them.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **DATA-04:1:** Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds.
- **DATA-04:2:** Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced.

**Sources:** [NSA-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) (NSA, CISA, FBI and international partners; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment).

```sh
invscan --explain-scan DATA-04
invscan TARGET --scans DATA-04 --judge-cli claude
```

### DATA-05

**Enforce retention and deletion across copies** · Data and privacy · validation: `dynamic`

Apply retention and deletion across derived and replicated data.

**Why it matters:** Deleting a source record may leave retrievable embeddings, cached prompts or provider-held copies.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **DATA-05:1:** Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider-held data.
- **DATA-05:2:** Verify deleting a source record removes or invalidates dependent retrieval content and access grants.

**Sources:** [NIST-GENAI](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) (NIST; primary control source); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment).

```sh
invscan --explain-scan DATA-05
invscan TARGET --scans DATA-05 --judge-cli claude
```

### DATA-06

**Protect stored data and keys** · Data and privacy · validation: `hybrid`

Protect stored data with restricted identities, key separation and tested access controls.

**Why it matters:** Encryption settings alone cannot stop an authorized but overprivileged agent identity from reading data.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **DATA-06:1:** Check transport verification, storage access controls, encryption settings, key separation, and backup permissions.
- **DATA-06:2:** Validate key rotation and denied access using a principal outside the authorized tenant or operational role.

**Sources:** [NSA-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) (NSA, CISA, FBI and international partners; primary control source); [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment).

```sh
invscan --explain-scan DATA-06
invscan TARGET --scans DATA-06 --judge-cli claude
```

### SUP-01

**Pin and inventory executable dependencies** · Supply chain · validation: `static`

Record and constrain the executable versions and immutable artifacts used by the system.

**Why it matters:** A floating dependency or runtime install can change the code behind an approved agent or MCP server.

**Deterministic:** Partial rules [AI018](#ai018), [AI024](#ai024), [AI025](#ai025).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **SUP-01:1:** Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins.
- **SUP-01:2:** Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries.

**Sources:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan SUP-01
invscan TARGET --scans SUP-01 --judge-cli claude
```

### SUP-02

**Check vulnerability and maintenance exposure** · Supply chain · validation: `manual`

Assess known vulnerabilities and maintenance status in the resolved dependencies.

**Why it matters:** An apparently clean source scan can still ship a vulnerable or unsupported library or base image.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **SUP-02:1:** Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version.
- **SUP-02:2:** Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage.

**Sources:** [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [CSA-AISMM](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model) (Cloud Security Alliance; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OPENSSF-BASELINE-202608](https://baseline.openssf.org/versions/2026-08-28) (OpenSSF; thematic alignment).

```sh
invscan --explain-scan SUP-02
invscan TARGET --scans SUP-02 --judge-cli claude
```

### SUP-03

**Verify artifact identity and provenance** · Supply chain · validation: `manual`

Verify artifact identity, publisher trust and build provenance before enabling it.

**Why it matters:** A valid digest can identify malicious bytes just as precisely as trusted bytes.

**Deterministic:** Partial rules [AI019](#ai019), [AI024](#ai024), [AI035](#ai035).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **SUP-03:1:** Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts.
- **SUP-03:2:** Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe.

**Sources:** [NSA-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) (NSA, CISA, FBI and international partners; primary control source); [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment); [SLSA-12](https://slsa.dev/spec/v1.2/) (SLSA / OpenSSF; thematic alignment); [OPENSSF-MODEL-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/) (OpenSSF; thematic alignment).

```sh
invscan --explain-scan SUP-03
invscan TARGET --scans SUP-03 --judge-cli claude
```

### SUP-04

**Protect build, release, and configuration changes** · Supply chain · validation: `hybrid`

Protect the build and release path and the credentials it can access.

**Why it matters:** Untrusted changes to workflows or agent configuration may execute with deployment authority.

**Deterministic:** Partial rules [AI020](#ai020).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **SUP-04:1:** Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance.
- **SUP-04:2:** Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies.

**Sources:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OPENSSF-BASELINE-202608](https://baseline.openssf.org/versions/2026-08-28) (OpenSSF; thematic alignment); [SLSA-12](https://slsa.dev/spec/v1.2/) (SLSA / OpenSSF; thematic alignment).

```sh
invscan --explain-scan SUP-04
invscan TARGET --scans SUP-04 --judge-cli claude
```

### SUP-05

**Harden runtime isolation and deployment defaults** · Supply chain · validation: `hybrid`

Use restrictive runtime identities and deployment boundaries around agent execution.

**Why it matters:** Root, privileged mounts or runtime sockets can turn a tool compromise into broader host access.

**Deterministic:** Partial rules [AI021](#ai021), [AI022](#ai022), [AI023](#ai023), [AI031](#ai031), [AI042](#ai042).

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **SUP-05:1:** Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints.
- **SUP-05:2:** Separate agent execution from control-plane credentials and audit storage; test isolation in the deployed environment.

**Sources:** [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely) (NSA, CISA and international partners; ASD host; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; thematic alignment).

```sh
invscan --explain-scan SUP-05
invscan TARGET --scans SUP-05 --judge-cli claude
```

### SUP-06

**Separate and protect model development environments** · Supply chain · validation: `dynamic`

Separate training, evaluation and production authority when developing models.

**Why it matters:** An untrusted training job or altered adapter could replace an approved production artifact.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **SUP-06:1:** When training or fine-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions.
- **SUP-06:2:** Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact.

**Sources:** [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; primary control source).

```sh
invscan --explain-scan SUP-06
invscan TARGET --scans SUP-06 --judge-cli claude
```

### OPS-01

**Produce attributable audit events** · Operations and resilience · validation: `hybrid`

Produce an attributable and protected history of security-relevant actions.

**Why it matters:** Without correlated identities and outcomes, an agent incident may be impossible to reconstruct.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **OPS-01:1:** Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers.
- **OPS-01:2:** Protect log integrity and clock consistency; ensure agents cannot erase their own action history.

**Sources:** [OWASP-MCP10](https://owasp.org/projects/mcp-top-10) (OWASP; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [CIS-AGENTS-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide) (Center for Internet Security; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan OPS-01
invscan TARGET --scans OPS-01 --judge-cli claude
```

### OPS-02

**Bound work, spending, and concurrency** · Operations and resilience · validation: `hybrid`

Enforce resource and spending budgets across the complete unit of work.

**Why it matters:** Loops, retries and child agents can multiply consumption beyond a per-request limit.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `supported_by_code`; this never establishes a validated pass.

**Acceptance checks:**

- **OPS-02:1:** Set server-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time.
- **OPS-02:2:** Exercise stuck loops and amplification paths; verify limits apply across retries and child agents.

**Sources:** [ASD-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses) (ASD ACSC; primary control source); [CSA-SCOPING](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach) (Cloud Security Alliance; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment); [OWASP-AISVS-C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan OPS-02
invscan TARGET --scans OPS-02 --judge-cli claude
```

### OPS-03

**Make cancellation and shutdown effective** · Operations and resilience · validation: `dynamic`

Make cancellation revoke future work and stop consequential effects.

**Why it matters:** Stopping a user interface does not necessarily cancel queued actions, child processes or usable credentials.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **OPS-03:1:** Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks.
- **OPS-03:2:** Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects.

**Sources:** [JOINT-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services) (ASD ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK; primary control source); [CSA-AGENT-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) (Cloud Security Alliance; thematic alignment); [OWASP-AISVS-C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md) (OWASP; thematic alignment).

```sh
invscan --explain-scan OPS-03
invscan TARGET --scans OPS-03 --judge-cli claude
```

### OPS-04

**Fail safely and prevent duplicate side effects** · Operations and resilience · validation: `dynamic`

Keep failure and recovery paths from widening authority or repeating side effects.

**Why it matters:** A timeout, fallback or retry can execute an action twice or bypass a failed policy check.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **OPS-04:1:** Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege.
- **OPS-04:2:** Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects.

**Sources:** [ASD-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses) (ASD ACSC; primary control source).

```sh
invscan --explain-scan OPS-04
invscan TARGET --scans OPS-04 --judge-cli claude
```

### OPS-05

**Monitor behavior and support rollback** · Operations and resilience · validation: `dynamic`

Detect unusual behavior and restore trusted system state after harmful changes.

**Why it matters:** Unexpected destinations or scope growth can remain invisible until many automated actions have occurred.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **OPS-05:1:** Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes.
- **OPS-05:2:** Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory.

**Sources:** [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) (NCSC-UK, CISA and international partners; primary control source); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-AISMM](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model) (Cloud Security Alliance; thematic alignment).

```sh
invscan --explain-scan OPS-05
invscan TARGET --scans OPS-05 --judge-cli claude
```

### OPS-06

**Practice incident response and disclosure** · Operations and resilience · validation: `manual`

Prepare and exercise an incident response process for agent-specific failures.

**Why it matters:** Stopping an agent without revoking credentials or preserving evidence may leave the compromise active.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_human_review`; this never establishes a validated pass.

**Acceptance checks:**

- **OPS-06:1:** Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state.
- **OPS-06:2:** Exercise an AI-specific incident and define approved vulnerability/intelligence-sharing channels without exposing sensitive evidence.

**Sources:** [CISA-JCDC](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet) (CISA; primary control source); [CSA-AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (Cloud Security Alliance; thematic alignment); [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) (Cloud Security Alliance; thematic alignment); [CSA-AISMM](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model) (Cloud Security Alliance; thematic alignment); [OPENSSF-BASELINE-202608](https://baseline.openssf.org/versions/2026-08-28) (OpenSSF; thematic alignment).

```sh
invscan --explain-scan OPS-06
invscan TARGET --scans OPS-06 --judge-cli claude
```

### TEST-01

**Measure prompt-injection security and useful task completion** · Security validation · validation: `dynamic`

Measure adversarial safety alongside authorized task completion in representative workflows.

**Why it matters:** A defense that blocks every useful action can appear safe, while a model-only score misses tool side effects.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-01:1:** Run paired benign and adversarial workflows with representative tools and attacker-controlled external content.
- **TEST-01:2:** Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect.

**Sources:** [BENCH-AGENTDOJO](https://github.com/ethz-spylab/agentdojo) (ETH Zurich / Invariant Labs; primary control source); [BENCH-INJECAGENT](https://github.com/uiuc-kang-lab/InjecAgent) (UIUC Kang Lab; primary control source); [MITRE-ATLAS-202609](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09) (MITRE; thematic alignment).

```sh
invscan --explain-scan TEST-01
invscan TARGET --scans TEST-01 --judge-cli claude
```

### TEST-02

**Test adaptively and repeat scenarios** · Security validation · validation: `dynamic`

Repeat and vary adversarial scenarios under a stated attacker budget.

**Why it matters:** A single fixed prompt or aggregate average can hide failures that appear with another placement or attempt.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-02:1:** Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses.
- **TEST-02:2:** Report per-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average.

**Sources:** [NIST-HIJACK-EVAL](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations) (NIST; primary control source); [MITRE-ATLAS-202609](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09) (MITRE; thematic alignment).

```sh
invscan --explain-scan TEST-02
invscan TARGET --scans TEST-02 --judge-cli claude
```

### TEST-03

**Exercise MCP authentication and protocol abuse** · Security validation · validation: `dynamic`

Exercise authentication and protocol abuse against the actual MCP revision in an isolated environment.

**Why it matters:** Correct-looking source does not establish how a deployed transport handles hostile peers or malformed state.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-03:1:** In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing.
- **TEST-03:2:** Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed.

**Sources:** [BENCH-MCPSECBENCH](https://github.com/AIS2Lab/MCPSecBench) (AIS2Lab; primary control source); [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Model Context Protocol maintainers; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment).

```sh
invscan --explain-scan TEST-03
invscan TARGET --scans TEST-03 --judge-cli claude
```

### TEST-04

**Verify cross-tenant and cross-agent isolation** · Security validation · validation: `dynamic`

Test isolation using distinct principals across every stateful surface.

**Why it matters:** An authorization check may work on objects but fail on caches, memory, subscriptions or resumed work.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-04:1:** Create two principals and attempt cross-access to objects, memory, caches, handles, subscriptions, and execution results.
- **TEST-04:2:** Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation.

**Sources:** [BENCH-ASB](https://github.com/agiresearch/ASB) (Agent Security Bench authors / agiresearch; primary control source).

```sh
invscan --explain-scan TEST-04
invscan TARGET --scans TEST-04 --judge-cli claude
```

### TEST-05

**Test approval, policy, and sandbox bypass** · Security validation · validation: `dynamic`

Test forbidden-action boundaries across approvals, policy and sandbox alternatives.

**Why it matters:** A safeguard on one execution path may be bypassed through a different tool, retry or child agent.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-05:1:** Use explicit forbidden-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution.
- **TEST-05:2:** Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary.

**Sources:** [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) (OWASP Cheat Sheet Series; primary control source); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment).

```sh
invscan --explain-scan TEST-05
invscan TARGET --scans TEST-05 --judge-cli claude
```

### TEST-06

**Verify conventional application security** · Security validation · validation: `dynamic`

Apply conventional application security validation to the interfaces agents can reach.

**Why it matters:** AI-specific controls do not replace ordinary access control, injection prevention or dependency review.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-06:1:** Run language-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services.
- **TEST-06:2:** Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access-control risks with safe fixtures.

**Sources:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) (NIST; primary control source); [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) (OWASP GenAI Security Project; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; thematic alignment); [CIS-MCP-2026](https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide) (Center for Internet Security; thematic alignment); [AIUC1-Q3-2026](https://www.aiuc-1.com/research/2026-q3-standard-update) (Artificial Intelligence Underwriting Company; thematic alignment).

```sh
invscan --explain-scan TEST-06
invscan TARGET --scans TEST-06 --judge-cli claude
```

### TEST-07

**Validate resource exhaustion and observability** · Security validation · validation: `dynamic`

Exercise resource exhaustion and validate the supporting telemetry and shutdown path.

**Why it matters:** A quota can fail operationally if slow peers, stream floods or unavailable dependencies defeat accounting or alerts.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-07:1:** Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies.
- **TEST-07:2:** Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution.

**Sources:** [ASD-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses) (ASD ACSC; primary control source).

```sh
invscan --explain-scan TEST-07
invscan TARGET --scans TEST-07 --judge-cli claude
```

### TEST-08

**Evaluate the optional security judge itself** · Security validation · validation: `dynamic`

Evaluate the optional security reviewer as another untrusted, fallible component.

**Why it matters:** A model may accept repository instructions, invent evidence or emit malformed judgments.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-08:1:** Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts.
- **TEST-08:2:** Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation.

**Sources:** [NIST-HIJACK-EVAL](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations) (NIST; primary control source); [NIST-GENAI](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) (NIST; primary control source).

```sh
invscan --explain-scan TEST-08
invscan TARGET --scans TEST-08 --judge-cli claude
```

### TEST-09

**Evaluate model-layer attacks for hosted or customized models** · Security validation · validation: `dynamic`

Evaluate model-layer threats when hosting, acquiring or customizing models.

**Why it matters:** Behavioral triggers, extraction or training-data disclosure may not be visible in application source patterns.

**Deterministic:** No mapped detector; retain the human/runtime review requirement.

**Optional AI review:** Review every active selected acceptance check against bounded submitted source excerpts, including checks with no deterministic detector and supported checks with inconclusive source evidence. Code support is reported as `needs_runtime_validation`; this never establishes a validated pass.

**Acceptance checks:**

- **TEST-09:1:** Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget.
- **TEST-09:2:** Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk.

**Sources:** [CSA-MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Cloud Security Alliance; primary control source); [NIST-SSDF-AI](https://csrc.nist.gov/pubs/sp/800/218/a/final) (NIST; primary control source).

```sh
invscan --explain-scan TEST-09
invscan TARGET --scans TEST-09 --judge-cli claude
```

## Evidence, validation and maintaining this inventory

These algorithms describe implemented predicates, not a guarantee of zero false positives or false negatives. Use [measured accuracy and unresolved cases](RULE_ACCURACY.md), [the public benchmark dashboard](BENCHMARK_DASHBOARD.md) and [test evidence](VALIDATION.md) to assess their limits. Pinned benchmark artifacts keep their original version and inputs; a new detector is not retroactively credited in an old report.

Developers: update [scan_catalog.py](../ai_security_scan/scan_catalog.py) when a rule's predicate or supported context changes, then run `python scripts/build_scan_coverage.py`. `python scripts/build_scan_coverage.py --check` rejects stale generated documentation. See [inventory and selection architecture](developer/scan-inventory.md).
