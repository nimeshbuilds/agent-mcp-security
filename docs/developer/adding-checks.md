# Add a detector or catalog entry

A useful detector has a precise predicate, a counterexample and an honest limit. Start by stating the source behavior you can establish. For example, “a recognized subprocess call enables shell interpretation” is testable from a local expression; “an attacker can execute commands in production” usually requires additional evidence.

## Define the detection contract

Before changing code, identify:

| Question | What to record |
|---|---|
| Which syntax is recognized? | Language, API, aliases, arguments, configuration keys and literal values. |
| What makes the pattern relevant? | The execution, identity, data or tool boundary involved. Keep external influence conditional unless established. |
| What should not match? | Safe API alternatives, unrelated same-named functions, comments, examples and values that do not enable the behavior. |
| What remains unknown? | Cross-file callers, runtime configuration, deployed authorization, compensating layers or unsupported syntax. |
| Where can the same condition appear? | Source, final image filesystem, image defaults or retained layers. These need distinct provenance. |

Read the actual API documentation before changing a value predicate. The [AI041 label correction](../../benchmarks/AI041_LABEL_CORRECTION.md) is a concrete example: any nonempty Inspector `DANGEROUSLY_OMIT_AUTH` value disables authentication, including the strings `false` and `0`. A conventional boolean interpretation was incorrect. The old corpus was retained, and the correction was disclosed as changed ground truth rather than a same-input accuracy gain.

## Implement at the narrowest supported boundary

[`analyzer.py`](../../ai_security_scan/analyzer.py) exposes `analyze_file(path, text)` and `analyze_file_errors(path, text)`. Python uses `_PythonAnalyzer`; JavaScript/TypeScript uses `_js_analysis`; structured JSON uses `_json_analysis`; applicable configuration and generic signals use `_generic_analysis`.

Use the existing parser/tracker for the language. A repository-wide text match can confuse comments, strings, shadowed symbols and unrelated APIs with a security sink. Do not add imports, dependency installation, target execution or outbound requests to resolve uncertainty. Emit a limitation or leave unsupported cases outside the claimed predicate.

Emit through `_Findings.add()` or `_Findings.offset()`, preserving bounded evidence, stable locations and deduplication. Severity, title, description, remediation, category, CWE and reference URLs come from [`rules.py`](../../ai_security_scan/rules.py). Do not embed machine paths, timestamps or model advice in finding identity.

For image metadata or retained artifacts, inspect [`image_assessment.py`](../../ai_security_scan/image_assessment.py) as well. Reuse the rule only when its predicate applies in that context; record whether the evidence is a final file, runtime default, deleted layer revision or build-history entry. A source change does not automatically test image behavior.

## Keep the connected catalogs complete

Adding a rule involves more than an analyzer branch:

| File | Required contribution |
|---|---|
| [`scan_catalog.py`](../../ai_security_scan/scan_catalog.py) | Exact predicate, algorithm, profiles/image contexts, blind spots and optional review boundary. Regenerate [complete coverage](../SCAN_COVERAGE.md). |
| [`rules.py`](../../ai_security_scan/rules.py) | Unique stable rule ID, detection description, severity rationale, remediation and primary technical references. Coordinate the ruleset version with the release. |
| [`data/controls.json`](../../ai_security_scan/data/controls.json) | Applicable `automated_rule_ids` mappings. These indicate partial control-level coverage, never proof of every acceptance check. |
| [`data/mitigations.json`](../../ai_security_scan/data/mitigations.json) | Plausible impact, immediate action, proposed owner and independently verifiable defense layers. |
| [`data/remediations.json`](../../ai_security_scan/data/remediations.json) | Agent/MCP relevance, applicability conditions, concrete steps, verification scenarios, residual limits and source IDs. |
| [`data/sources.json`](../../ai_security_scan/data/sources.json) | Registered technical reference URLs and truthful scope/limitations. |
| Tests and accuracy corpus | Positive and negative cases, plus explicit hard cases when current support is limited. |

Mitigation and remediation records are consumed during report generation. Missing mappings can break an otherwise successful scan, so test both detection and report enrichment. Suggested protections remain proposals; a WAF, sandbox or approval step in guidance is not an observed deployment control and must not lower severity automatically.

## Write positive and negative tests

Use source strings that are parsed but never executed. This minimal example checks the existing AI002 predicate:

```python
from ai_security_scan.analyzer import analyze_file, analyze_file_errors

positive = "import subprocess\nsubprocess.run(task.command, shell=True)\n"
negative = 'import subprocess\nsubprocess.run(["echo", task.text], shell=False)\n'

for text in (positive, negative):
    assert not analyze_file_errors("worker.py", text)
assert "AI002" in {item["rule_id"] for item in analyze_file("worker.py", positive)}
assert "AI002" not in {item["rule_id"] for item in analyze_file("worker.py", negative)}
```

The negative assertion concerns AI002 only; it does not claim the whole program is safe. Add cases for recognized aliases, shadowing/reassignment, multiline syntax, ambiguous branches, empty/nonempty configuration values and malformed inputs when those affect the predicate. Check locations and evidence, not only the number of findings. Add a scanner-level case when the change depends on traversal, redaction, baselines, controls or image merging.

Existing suites provide patterns:

- [`test_python_accuracy.py`](../../tests/test_python_accuracy.py), [`test_javascript_accuracy.py`](../../tests/test_javascript_accuracy.py) and [`test_configuration_accuracy.py`](../../tests/test_configuration_accuracy.py): language-specific positives and counterexamples.
- [`test_security_boundaries.py`](../../tests/test_security_boundaries.py), [`test_inspector_auth_values.py`](../../tests/test_inspector_auth_values.py) and [`test_real_world_regressions.py`](../../tests/test_real_world_regressions.py): semantic boundaries and previously observed mistakes.
- [`test_image_assessment.py`](../../tests/test_image_assessment.py) and [`test_image_cli.py`](../../tests/test_image_cli.py): archive/source consistency and provenance.
- [`test_remediation.py`](../../tests/test_remediation.py), [`test_report_assessment.py`](../../tests/test_report_assessment.py) and [`test_catalog.py`](../../tests/test_catalog.py): complete guidance and valid mappings.

## Add explicit accuracy labels

[`benchmarks/static_accuracy.json`](../../benchmarks/static_accuracy.json) scores explicitly labeled rule-presence assertions. It is a project-authored synthetic corpus, not an independent benchmark or a representative production sample. Other findings in the same snippet are not scored without labels.

Each case includes a unique `id`, `suite` (`regression` or `challenge`), relative `path`, inert `source`, an `expect` mapping from known rule IDs to booleans, and a rationale. Every rule needs both positive and negative coverage. Use `challenge` for a documented unresolved case; do not remove a difficult case simply to improve the percentage.

```sh
python -m unittest tests.test_rules tests.test_accuracy_corpus -v
python scripts/evaluate_accuracy.py --format markdown
```

The default evaluator gate fails on regression-suite mistakes. Challenge results remain included in reported metrics. `--fail-on any` is a stricter gate and can fail on the currently documented challenges; `--fail-on none` produces measurements without enforcing a pass threshold. Preserve prior corpus bytes when changing labels and explain whether a comparison uses identical inputs. See [accuracy methodology](../RULE_ACCURACY.md).

## Add a control, source or explanation

Controls have stable IDs, titles, categories, ordered acceptance checks, a validation type, rule mappings and source relationships. Current checks use one-based IDs such as `AUTH-01:1`. Reordering checks changes what a positional ID means; treat that as a review-contract change, not cosmetic formatting.

1. Add or update the primary source in `sources.json`. Record organization, title, exact URL, kind, version/date, access date, scope and limitations. If only a listing, draft or announcement is available, say so; do not invent requirements from an inaccessible document.
2. Set the control's `source_ids` and matching `sources` URLs in the same order. Put broader relationships in `alignment_source_ids`. Announcement IDs do not inherit mappings from a separate joint publication.
3. Choose `static`, `hybrid`, `dynamic` or `manual` honestly. An empty rule mapping is valid and means human/runtime evidence is needed. Do not create a weak detector merely to make a control appear automated.
4. Add an entry to [`control_explanations.json`](../../ai_security_scan/data/control_explanations.json): `what_it_is`, `why_it_matters`, `agent_mcp_context` and curated `aliases`. Explain the specific control; avoid repeating generic security text across entries.
5. If introducing a category, update the fixed topic inventory in `catalog.py` deliberately. Verify exact IDs, ordinary questions, no matches, case variants and organization aliases through explorer tests.

The explorer labels relationships as `primary_control_source`, `thematic_alignment` and `rule_technical_reference`. These are project-authored relationships, not a claim of an official clause-level compliance crosswalk. Keep CISA distinct from CIS, and MITRE ATLAS distinct from ATT&CK. Benchmarks describe evaluation work; listing one does not mean Invarune executes it.

```sh
python scripts/sync_control_docs.py
python scripts/build_scan_coverage.py
python scripts/build_scan_coverage.py --check
python -m unittest tests.test_catalog tests.test_catalog_explorer tests.test_catalog_explorer_integration -v
invscan --explain-control AUTH-01
invscan --explain-check AUTH-01:1 --catalog-format json
invscan --explain-source MCP-AUTH
```

Review generated documentation diffs and any changed counts. Finish with the relevant report tests and [release validation](testing-and-releasing.md); catalog edits can change review bindings even when rule detections stay the same.

The [scan inventory and selection guide](scan-inventory.md) explains stable scan IDs, narrowed source/image/AI scope, terminal defaults and metric denominators.
