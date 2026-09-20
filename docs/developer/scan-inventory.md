# Scan inventory, selection and coverage claims

The user-facing [complete coverage guide](../SCAN_COVERAGE.md), <code>invscan --list-scans</code> and <code>invscan --explain-scan ID</code> share one metadata API. Keep the detector, inventory and report scope aligned.

## One rule is one documented predicate

<code>ai_security_scan/scan_catalog.py</code> adds execution metadata to the canonical rules, controls, explanation and remediation catalogs. Its explicit per-rule contract records:

- The recognized predicate and algorithm, supported analysis profiles and principal false-positive/false-negative boundaries.
- Agent/MCP/skill relevance and the specific built-image evidence contexts in which the rule runs.
- Partial parent-control mappings, acceptance checks and original primary/thematic source relationships.
- Optional model triage and full-control review scope, preserving their advisory nature.
- Remediation and executable CLI discovery/selection examples.

Adding a rule without corresponding coverage metadata raises an error during inventory generation. An unfamiliar implementation must not inherit optimistic catch-all coverage. The inventory is metadata, not a second detection engine: it cannot add a finding or mark a control satisfied.

<code>describe_scans()</code> returns a new JSON-serializable envelope with <code>schema_version</code>, <code>mode</code>, <code>ruleset_version</code>, counts, limits, <code>scans</code> and <code>controls</code>. A known rule/control ID returns a singular <code>scan</code>/<code>control</code>. IDs are case-insensitive; unknown IDs are errors. <code>render_scans()</code> produces terminal text. Returned records are isolated from the cached catalog, so callers cannot mutate later responses.

Lookup reads bundled metadata only. It never opens a target, fetches a reference URL, loads judge configuration, spawns a CLI or contacts a model. Existing <code>--ask</code> remains deterministic lexical lookup; it does not become a scan or agent because scan commands exist.

## Selection is explicit scope

<code>--scans</code>/<code>--scan</code> accepts repeatable comma-separated rule and control IDs. The resolver validates, normalizes and deduplicates selectors before scanning. A rule contributes that rule and mapped controls. A control contributes itself and mapped rules. Mixed selections use the union; a control-only selector does not recursively add controls sharing its rules.

Controls with no mapped rule contribute an empty rule set. Preserve it: treating an empty selection as a falsey default and restoring all rules silently expands the request. Full optional review still queues selected active control checks. All default rules/controls remain selected only when selection is omitted.

Selection constrains result findings, checklist, optional review and metric denominators. Shared parsing, resource enforcement and safe image reconstruction still occur. Malformed selected files cannot become successful scans because the requested rule is unrelated to a parse error. User exceptions are separate: justified/disabled preserve explicit decisions and evidence; unselected rules are outside this request.

Test control-only selections without mapped rules, shared-rule controls, mixed selectors, duplicate/case-varied selectors, unknown/empty IDs, source/image parity, exemptions, analyst requests and fresh review bindings.

## Terminal output and exports

Default scans print results without creating report directories. <code>--output DIR</code> or <code>--report [DIR]</code> requests four portable formats. <code>--report</code> alone uses <code>./scan-report</code>. <code>--pdf</code> requests exports and uses that directory unless another is provided.

Terminal, JSON stdout and file reports derive the same findings, assessment, scope, metrics and exit decision. Writing HTML is not a prerequisite for enrichment. Keep target/output exclusion and review-input protection consistent across modes. Tests should check output and the absence of unexpected filesystem artifacts.

## Evidence measures, not an invented assurance grade

<code>ai_security_scan/scoring.py</code> derives counts and denominators locally. <code>overall_security_score</code> is null because patterns/model interpretations do not establish a defensible universal percentage. Metrics expose findings by severity, partial mapped-control reach, optional answer coverage, advisory outcomes and exclusions.

Answer coverage includes explicit unknowns but excludes missing/synthesized/duplicate answers. Justified/disabled checks leave denominators without pass credit. Zero denominators are null, not 100%. AI cannot lower severity, erase findings or alter the gate. Do not label mapping reach or answer completion as security, effectiveness, precision or compliance.

Benchmark true/false-positive/false-negative metrics are separate evaluation artifacts. They are not scores for a customer repository.

## Generate and verify documentation

Edit <code>scripts/templates/scan_coverage_intro.md</code> and rule metadata in <code>scan_catalog.py</code>. Examples must be executable; do not describe future flags as shipped features.

~~~sh
python scripts/build_scan_coverage.py
python scripts/build_scan_coverage.py --check
python -m unittest tests.test_scan_inventory tests.test_catalog_explorer tests.test_cli_usability -v
invscan --list-scans
invscan --explain-scan AI043
invscan --list-scans --catalog-format json
~~~

Do not hand-edit generated <code>docs/SCAN_COVERAGE.md</code>. The generator preserves all current rules, controls, checks and source relationships. Commit generated changes with implementation. Rerun pinned accuracy/public-project inputs and publish versioned reports after detector/report changes; retain old receipts and disclose changed labels or scope.

See [adding checks](adding-checks.md), [reports and reviews](reports-and-reviews.md) and [testing and releasing](testing-and-releasing.md).
