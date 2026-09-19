# AI041 Inspector authorization-bypass label correction

The [official MCP Inspector environment-variable documentation](https://github.com/modelcontextprotocol/inspector/blob/main/docs/environment-variables.md) states that any nonempty `DANGEROUSLY_OMIT_AUTH` value disables Inspector authentication. Consequently, the strings `false`, `0`, and `no` are bypasses. An empty or unset environment value does not request that bypass.

Corpus 1.1.0 incorrectly labeled `ai041-comparison`, whose unchanged source is `{"DANGEROUSLY_OMIT_AUTH":"false"}`, as absent. The detector shared that Boolean interpretation. Corpus **1.2.0** corrects this label to present and adds four explicit cases: empty and unset negatives, and `0` and `no` string positives. All other prior fixture bytes and labels are retained. The corpus now has 113 labeled cases: 105 regression cases and eight challenge cases.

The exact prior corpus is preserved as [static_accuracy-v110.json](static_accuracy-v110.json), SHA-256 `aa4e3b2a95fdf5d5ea09721c0316c72a654d90d58281be5caab249d87510dff8`. This is changed ground truth and expanded coverage. Aggregate metrics on corpus 1.2.0 must not be claimed as improved accuracy against the unchanged 1.1.0 corpus. Applying the corrected detector to the old `false` label necessarily produces a disagreement with that incorrect historical label.

The implementation uses the special Inspector string semantics only for this environment variable. Other authorization flags keep their own Boolean interpretation. Supported source/configuration/image paths are covered by [targeted tests](../tests/test_inspector_auth_values.py), including documentation and empty/dynamic-value counterexamples. YAML list-form environment strings such as `- DANGEROUSLY_OMIT_AUTH=0` are detected. A numeric YAML mapping value is conservatively unassessed because the bounded generic check does not establish a particular runtime's string-coercion behavior; inspect the final image's environment to resolve that case. Static patterns still cannot establish the final deployed environment, whether Inspector is reachable, or the behavior of unsupported syntax.

To inspect the current measurements and preserve the historical comparison:

```sh
python3 scripts/evaluate_accuracy.py --corpus benchmarks/static_accuracy.json --format markdown
python3 scripts/evaluate_accuracy.py --corpus benchmarks/static_accuracy-v110.json --fail-on none --format markdown
```

Neither this correction nor the synthetic corpus establishes a production false-positive or false-negative rate.
