# Deterministic rule accuracy

Invarune includes repeatable accuracy evaluation for its bounded Python, JavaScript/TypeScript and configuration checks. Determinism means repeatable results for stable inputs. It does **not** mean zero false positives or false negatives. The scanner identifies reviewable source patterns; it does not prove vulnerabilities or certify control effectiveness.

## Reproduce the measurements

```sh
# Default: gate regression failures; also show every challenge result.
python3 scripts/evaluate_accuracy.py --format markdown
python3 scripts/evaluate_accuracy.py --output accuracy.json

# Fail on any labeled mismatch, including documented challenges.
python3 scripts/evaluate_accuracy.py --fail-on any

# Evaluate another labeled corpus without executing its source.
python3 scripts/evaluate_accuracy.py --corpus /path/to/labeled-cases.json
```

The corpus contains **113 labeled cases**: **105 regression cases** and **8 challenge cases**. Every one of the 42 rules has at least one positive and one comparison label. A case labels whether a particular rule should fire; unrelated detections are retained as unscored output. A comparison label is not a declaration that the application is secure.

The project authored this synthetic corpus. It is not an independent industry benchmark, representative production sample, or exploitability test. Examples were selected to probe API semantics and known difficult boundaries, so percentages cannot be interpreted as production accuracy. Fixes were developed against some of these cases; this is a regression corpus, not a held-out evaluation. Use a separate labeled sample of your own repositories before setting organization-wide severity gates.

- [Corpus, labels, rationale, and provenance](../benchmarks/static_accuracy.json)
- [Current paired before/after results and every mismatch](../benchmarks/comparison-v013/README.md)
- [Historical v0.10 readable results](../benchmarks/accuracy-current.md)
- [Current v0.13 JSON with per-rule confusion counts](../benchmarks/comparison-v013/accuracy-after.json)
- [Frozen v0.12 baseline on identical labels](../benchmarks/comparison-v013/accuracy-before.json)
- [Historical v0.10 scanner on unchanged 1.1.0 labels](../benchmarks/accuracy-previous-corpus.md), including the historical incorrect AI041 label
- [Preserved v0.9.0 results on corpus 1.1.0](../benchmarks/accuracy-v090-current.md)
- [Archived corpus version 1.1.0](../benchmarks/static_accuracy-v110.json)
- [Archived corpus version 1.0.0](../benchmarks/static_accuracy-v100.json)
- [Version 0.2.1 baseline against corpus 1.0.0](../benchmarks/accuracy-v021.json)
- [Historical v0.10 scanner against the unchanged original 1.0.0 corpus](../benchmarks/accuracy-original-corpus.md), including its intentional AI011 mismatch and disagreement with the historical incorrect AI041 label ([JSON](../benchmarks/accuracy-original-corpus.json))

### Corpus version and comparison integrity

The current corpus is **1.2.0**. The Inspector authorization-bypass correction changes one existing label and adds four cases. The unchanged string `DANGEROUSLY_OMIT_AUTH="false"` is now correctly labeled a detection: Inspector disables authentication for **every nonempty environment value**, including `false`, `0`, and `no`. Empty and unset values are the negative fixtures. This follows the [official Inspector environment-variable semantics](https://github.com/modelcontextprotocol/inspector/blob/main/docs/environment-variables.md). The scanner was corrected across supported source/configuration/image evidence paths.

This is a ground-truth correction and expanded regression coverage, **not an accuracy improvement on identical corpus bytes**. The exact previous 1.1.0 bytes are retained in `static_accuracy-v110.json` with SHA-256 `aa4e3b2a95fdf5d5ea09721c0316c72a654d90d58281be5caab249d87510dff8`. A correct detector now disagrees with its old `false` label; that historical disagreement must not be presented as a newly introduced false alarm. [Correction record](../benchmarks/AI041_LABEL_CORRECTION.md).

The earlier **1.1.0** revision changed exactly one positive fixture: `ai011-risk` now contains a nonfunctional synthetic 64-character encoded body after its PEM header. All 109 assertion labels and all other cases remain unchanged. This follows the AI011 rule refinement from a header-only review signal to plausible encoded private-key material, prompted by real public-project scans finding a marker-only documentation example. The four corresponding unit-test fixtures were updated consistently. No real secret was introduced.

The scanner before the Inspector correction reported **52 TP, 50 TN, 2 FP and 5 FN** on corpus 1.1.0, with no supported regression mismatches. Against the **unchanged original 1.0.0 bytes**, that same scanner reported **51 TP, 50 TN, 2 FP and 6 FN**: the old marker-only positive intentionally becomes a mismatch. Those are historical observations; consult each published result’s version and corpus digest. The 0.2.1 baseline remains untouched and applies to 1.0.0; comparisons across revised corpora must disclose the changed fixture and corpus digest. Equal aggregate counts do not make different corpus bytes equivalent.

```sh
# Preserve an apples-to-apples observation against the archived bytes.
python3 scripts/evaluate_accuracy.py --corpus benchmarks/static_accuracy-v100.json --fail-on none
```

The [public-project scans](../benchmarks/real-world/README.md) are a separate development-visible track with [initial manual triage](../benchmarks/real-world/TRIAGE.md). They have no established vulnerability ground truth and do not supply a precision/recall denominator. Detector fixes made after viewing those projects are disclosed rather than treating the corpus as a held-out evaluation.

Precision is TP / (TP + FP), and recall is TP / (TP + FN). The unit is **explicitly labeled rule presence**, not confirmed vulnerabilities. Overall counts include the challenge cases. The default CI gate checks the supported regression subset and is not a claim of perfect overall accuracy. Parse errors are separate operational failures, never true negatives. The runtime-placeholder challenge expects no invented wildcard finding because its environment value is unavailable; production permissions remain unknown.


## v0.13 fixes developed from benchmark evidence

The [fresh comparison](../benchmarks/comparison-v013/README.md) freezes the original 113-case corpus and v0.12 implementation, then executes both versions independently. No label, case, pinned revision or exported source file was removed to improve the result. The [dashboard](BENCHMARK_DASHBOARD.md) presents the resulting confusion counts and remaining cases.

Rules now recognize bounded literal `getattr` attributes, supported preceding or direct YAML literal anchors, and a direct shell `-c` argument supplied by a download substitution. YAML scalar bodies are treated as data for configuration-key checks. Within recognized block-mapping fields, unknown/forward/complex security-field aliases remain explicit coverage gaps. Paired tests cover shadowing, quoted scalar data, anchor redefinitions, malformed references, downloader output modes and inert shell strings/heredocs.

Source review also refined three precise false-alarm patterns: local requirement paths are not named version ranges; explicit environment-variable-name fields with identifier values are not credential literals; recognized tokens with all-`x` placeholder payloads use the existing placeholder policy. Realistic literals and other repeated characters remain detectable. This does not broadly suppress documentation or prove that a deployed credential is safe.

## Earlier detector changes

The public-project regressions refine three narrow patterns. AI011 requires a plausible encoded body and still detects such material in Python docstrings and escaped strings; it does not validate a key cryptographically. AI010 recognizes two exact SDK dummy values (`api-key-not-set` and `codex-subscription-auth`) and requires both an error/message identifier role and a narrowly recognized error sentence before excluding an error label. Other literal credentials remain detectable. AI021 tracks the effective explicit root state of the default final Docker stage, including named-stage inheritance, later `USER` changes, line continuations and heredoc contents. External image defaults, variables and non-default build targets remain unproven. No broad docstring suppression or parameterized-SQL waiver was added.

Python rules now track bounded local callable aliases, known constant expressions, assignments, parameter/import shadowing, scoped classes/functions/comprehensions, and possible bindings across branches, loops, and exceptions. Dynamic keyword sinks, assigned SQL expressions, explicit unsafe flags in conditional branches, and recognized YAML loader origins receive regression coverage. Unknown branches conservatively retain possible hazards. The visitor limits tracked work to 1,000,000 units and alternative bindings to 64; exhaustion is a visible coverage error.

JavaScript/TypeScript checks now use bounded lexical tokens and balanced argument ranges. Quoted examples, comments, regex literals, fake import strings, harmless logging labels, multiline calls, dynamic Function bodies, local aliases, escaped identifiers, optional/bracket member calls, template expressions, and reordered message fields have paired regression tests. This remains a lexer, not a complete parser or whole-program analysis.

Configuration improvements cover actual IP loopback classification, mapped loopback addresses, URL-leading whitespace, multiple and attached MCP package selectors, executable names distinct from package names, exact prerelease/build versions, container flags in JSON, complete SHA-256 image references, and unrelated image fields. Duplicate JSON keys, nonstandard numeric constants, and numeric overflow produce coverage gaps instead of silently discarding ambiguous configuration.

Package-selector behavior follows the official [npm npx documentation](https://docs.npmjs.com/cli/v11/commands/npx/) and [uv tool documentation](https://docs.astral.sh/uv/concepts/tools/). IP classification uses the standard-library [ipaddress API](https://docs.python.org/3/library/ipaddress.html). These checks do not resolve registries, lockfiles, transitive dependencies, shell wrappers, or runtime configuration.

The CLI includes grouped help with defaults/examples, `--explain-rule ID` with control/source mappings, `--quiet`, and `--summary-json`. JSON and Markdown reports identify each file's analysis profile and summarize how many files received AST, lexical, structured configuration, or generic text checks. See the [CLI reference](CLI.md).

## Tests designed to catch missing detection

The unit suite adds adversarial pairs and transformations rather than relying only on one triggering snippet per rule. Python scope and branch tests include safer alternatives; JS tests include inert copies of risky-looking code and transformations that preserve executable behavior; configuration tests compare equivalent JSON formatting and package selector forms.

A mutation check disables each of the 42 rule emitters in turn and verifies that a labeled positive fails. Another injects a false alarm and verifies the precision calculation and failure gate. These are whole-rule removal/injection mutations, not exhaustive mutation testing of every operator or branch. They prove that loss of a detector cannot silently pass the corpus, not that every implementation error is detectable.

Existing tests retain real local HTTP/TLS gateway checks, offline-only defaults, source confinement, byte budgets, redaction, strict optional analyst schemas, stable artifacts, and preservation of static findings when a model disagrees. No target fixture is executed by the scanner or accuracy evaluator.

## Remaining limitations

The v0.13 paired run still lists misses involving cross-function URL flow and JavaScript wrapper propagation, plus a false alarm involving a URL equality guard that needs path-sensitive constraint analysis. The supported constant-reflection, preceding literal YAML anchor, scalar-body and direct downloaded shell-command cases now have bounded detectors and paired tests. Arbitrary reflection, full YAML semantics and general shell expansion remain outside those subsets. A source placeholder cannot establish its deployed value.

Other unresolved cases include cross-module execution, dynamic imports, monkey patches and prototype mutation, complex heap aliases, full loop fixed-point analysis, uncommon JS/TS grammar, unsupported languages, deployment reachability, and sanitizer effectiveness. Generic secret heuristics may flag example data or miss unusual secrets. A rule firing on a dangerous API may be a correct pattern detection even when trusted inputs make exploitation impossible.

The optional analyst can investigate code context and propose additional concerns. It remains nondeterministic, may also make mistakes, and cannot prove unavailable runtime facts. Its conclusions never suppress or downgrade deterministic findings. Missing code/runtime/human evidence stays visible.
