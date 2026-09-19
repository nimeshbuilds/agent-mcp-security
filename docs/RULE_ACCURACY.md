# Deterministic rule accuracy

Version 0.3.0 adds a repeatable accuracy evaluation and substantially improves Python, JavaScript/TypeScript, and configuration handling. Determinism means repeatable results for stable inputs. It does **not** mean zero false positives or false negatives. The scanner identifies reviewable source patterns; it does not prove vulnerabilities or certify control effectiveness.

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

The corpus contains **109 labeled cases**: **101 regression cases** and **8 challenge cases**. Every one of the 42 rules has at least one positive and one comparison label. A case labels whether a particular rule should fire; unrelated detections are retained as unscored output. A comparison label is not a declaration that the application is secure.

The project authored this synthetic corpus. It is not an independent industry benchmark, representative production sample, or exploitability test. Examples were selected to probe API semantics and known difficult boundaries, so percentages cannot be interpreted as production accuracy. Fixes were developed against some of these cases; this is a regression corpus, not a held-out evaluation. Use a separate labeled sample of your own repositories before setting organization-wide severity gates.

- [Corpus, labels, rationale, and provenance](../benchmarks/static_accuracy.json)
- [Current readable results, including every mismatch](../benchmarks/accuracy-current.md)
- [Current JSON with per-rule confusion counts](../benchmarks/accuracy-current.json)
- [Version 0.2.1 baseline against the same corpus](../benchmarks/accuracy-v021.json)

Precision is TP / (TP + FP), and recall is TP / (TP + FN). The unit is **explicitly labeled rule presence**, not confirmed vulnerabilities. Overall counts include the challenge cases. The default CI gate checks the supported regression subset and is not a claim of perfect overall accuracy. Parse errors are separate operational failures, never true negatives. The runtime-placeholder challenge expects no invented wildcard finding because its environment value is unavailable; production permissions remain unknown.

## What changed

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

The current report deliberately lists misses involving reflection, cross-function URL flow, JavaScript wrappers, YAML aliases, and nested shell expansion, plus false alarms involving YAML block-scalar text and a URL guard that would need path-sensitive constraint analysis. A source placeholder cannot establish its deployed value.

Other unresolved cases include cross-module execution, dynamic imports, monkey patches and prototype mutation, complex heap aliases, full loop fixed-point analysis, uncommon JS/TS grammar, unsupported languages, deployment reachability, and sanitizer effectiveness. Generic secret heuristics may flag example data or miss unusual secrets. A rule firing on a dangerous API may be a correct pattern detection even when trusted inputs make exploitation impossible.

The optional analyst can investigate code context and propose additional concerns. It remains nondeterministic, may also make mistakes, and cannot prove unavailable runtime facts. Its conclusions never suppress or downgrade deterministic findings. Missing code/runtime/human evidence stays visible.
