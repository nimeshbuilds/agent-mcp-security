# Fresh scanner comparison and adjudication ledger

Invarune by NimeshBuild · 19 September 2026

The published evidence includes **40 initial source-scan executions** against eight pinned public projects: two Invarune executions per project and one execution each of Semgrep, Bandit and Gitleaks. It also retains **16 final Invarune 0.10.0 executions**, two per project after the release freeze. Intermediate development reruns are outside this retained-invocation count. All 4,120 exported input files were verified against the same per-file source manifests before and after analysis. No target program, dependency install hook, MCP server or exploit was executed.

The final engine is Invarune **0.10.0**, producing **149 observations** and **15 coverage gaps**. The preserved initial 0.9.0 run had the same counts and observation identities. Semgrep CE **1.177.0** produced **27 observations** and seven parser warnings; Bandit **1.9.4** produced **938 observations** and five parser errors; Gitleaks **8.30.1** produced **three observations**. Bandit explicitly reports unsupported input for the two exports without Python. A fresh separate Cisco MCP Scanner **4.8.4** YARA run inspected 14 literal filesystem tool descriptions with zero findings; this is partial static metadata, not a live MCP inventory.

These are different units of review work, not confirmed vulnerability totals. No TP percentage is inferred from tool agreement. [Every one of the 1,117 source observations](FINDINGS.md) is published with a stable identifier, tool/rule, source location and cross-tool relation. The full machine-readable [observation ledger](observations.json) retains version, pinned source identity, raw-output hash, family rationale and a review predicate. [Run statuses](run-status.json) keep errors, coverage gaps and unsupported inputs separate.

## Finding-by-finding overlap

Matching requires the same project, pinned source path, explicitly compatible family and intersecting inclusive line spans. There is no nearest-line heuristic. An unambiguous pair requires each observation to have exactly one candidate counterpart. Multiple candidates remain ambiguous. Overlapping source spans with different or unmapped families remain location-only relations.

| Pair | One-to-one pairs | Ambiguous edges | Location-only edges | Left without a family match | Right without a family match |
|---|---:|---:|---:|---:|---:|
| Invarune / Semgrep | 7 | 0 | 0 | 142 | 20 |
| Invarune / Bandit | 12 | 5 | 0 | 132 | 925 |
| Invarune / Gitleaks | 1 | 0 | 0 | 148 | 2 |
| Semgrep / Bandit | 15 | 0 | 3 | 12 | 923 |
| Semgrep / Gitleaks | 0 | 0 | 0 | 27 | 3 |
| Bandit / Gitleaks | 0 | 0 | 0 | 938 | 3 |

The five ambiguous Invarune/Bandit edges involve five Invarune observations and one Bandit observation. They are not counted as five unique shared vulnerabilities or greedily reduced to one arbitrary match. [overlaps.json](overlaps.json) contains every counterpart edge and the exhaustive unmatched observation IDs for all six pairs. It does not collapse separate scanner observations into a fabricated common vulnerability denominator.

**Tool-only does not mean missed vulnerability.** A dependency pinning policy signal may have no corresponding rule in another selected pack. A pickle import differs from an unpickling call. A shell-disabled subprocess is not a shell-injection finding. Bandit's assertion/exception-handling observations are not equivalent to all of Invarune's agent/MCP checks. Source span choices also differ; semantically related reports on different lines remain unmatched under this conservative method. Review common rule applicability, source context and the other tool's successful analysis coverage before using the word “missed.”

The [explicit family map](rule-family-map.json) documents those boundaries and provides review predicates. External short messages are benchmark-authored family summaries, rather than copied licensed Semgrep rule text. Native rule IDs identify the original rule for independent inspection. The map deliberately notes broad rules: a pickle-family rule can report serialization as well as deserialization, and a weak-randomness or hash rule may report non-security uses.

## Predefined adjudication selection

Before reading any model outcomes, the deterministic selection was frozen at **120 exact source spans / 153 observations**, covering every one of the **101 observed tool × project × family strata**. It includes all 27 Semgrep observations, all three Gitleaks observations, 28 Invarune observations and 95 Bandit observations. Every tool with an unmatched-family observation has one represented.

The algorithm first includes all Semgrep/Gitleaks spans, greedily covers uncovered strata using a fixed hash order, ensures an unmatched-family example for each tool, and fills the remaining slots with a fixed hash ranking. No assessment outcome is an input. [adjudication-selection.json](adjudication-selection.json) contains every selected ID and the exact algorithm/seed. Its canonical input digest corresponds to the preserved [pre-selection ledger](observations-selection-v1.json). Later additions of textual review predicates did not change selected observation IDs.

This is a purposive diagnostic sample, not a random production prevalence sample. Any percentage from it must state its denominator, review coverage, uncertain/excluded cases and whether the labels were model-produced or independently evidence-reviewed. Unreviewed observations remain unknown; they are not false positives. Likewise, a model's likely-TP judgment is not a confirmed exploitable vulnerability. No real-project TP/FP labels have been supplied by this matching harness. The separate [blinded review harness](ADJUDICATION.md) prepared all 153 selected cases against final 0.10.0 source receipts. Its one actual Claude attempt failed authentication and stopped the remaining 19 batches: **zero valid model answers, 153 unknown observations and no measurable likely-TP percentage**. The [attempt receipt](adjudication-live/model-adjudication.json) preserves that limitation explicitly.

The separately executed [shared fixture check](external-results/shared-pattern-fixtures.json) uses ten development-visible API-pattern labels. Invarune, Semgrep and Bandit each matched five positive and five negative labels. That supports a **100% positive-label hit rate on these five specific positive fixtures** and zero mismatches on the ten-case set, not 100% production recall, precision or security. Gitleaks and metadata tools are outside this fixture scope and receive no artificial true negatives.

## Provenance and historical engine versions

- [Pinned projects and source scope](../real-world/manifest.json), [source manifests](../real-world/snapshots/) and [upstream licenses](../real-world/licenses/).
- [Final Invarune 0.10.0 receipts](invarune-receipts-v0100/) record two identical four-format runs per project and implementation SHA-256 `b2ed4a3b8f476586fd723d45c68c388d13874b09ab451d9a61c74cf57874d426`.
- [Initial fresh Invarune receipts](invarune-receipts/) record 0.9.0 and actual repeatability hashes; initial [observations](observations-v090.json), [overlaps](overlaps-v090.json) and [run statuses](run-status-v090.json) are preserved.
- [External receipts](external-results/summary.json), [tool versions/ruleset lock](tool-lock.json), [Cisco partial metadata receipt](external-results/cisco-metadata.json), and [current tool research](RESEARCH.md).
- Raw outputs and full Invarune reports remain in ignored `tmp/comparison-v010/`; they can contain source excerpts or licensed rule messages. Published normalized results omit raw credential values and full source. Local source-root mappings live only in `tmp/comparison-v010/source-roots.json`.

All observation IDs exclude the scanner version so unchanged detections can be compared after an engine update; the version and raw-output provenance remain explicit fields. Changes in detections, mapping definitions or scope must be reported as changes rather than retroactively presented as the original run. The corpus is development-visible and not independent or held out. Initial manual triage and detector changes are documented in the [earlier public-project review](../real-world/TRIAGE.md).

## Reproduce or inspect

Verify/export the pinned source with `python3 scripts/scan_public_projects.py --fetch --prepare-only`. The original tool installations and rule-pack verification commands are in [the external reproduction guide](../external-tools/README.md#reproduce). Fresh external executions used:

```bash
python3 scripts/benchmark_competitors.py \
  --source-root tmp/real-world-src \
  --output benchmarks/comparison-v010/external-results \
  --raw-output tmp/comparison-v010/external-raw \
  --semgrep tmp/benchmark-tools/python/bin/semgrep \
  --semgrep-config tmp/benchmark-tools/semgrep-security-audit.yaml \
  --bandit tmp/benchmark-tools/python/bin/bandit \
  --gitleaks tmp/benchmark-tools/gitleaks \
  --cisco tmp/benchmark-tools/cisco/bin/mcp-scanner
```

Invarune was invoked through `scan_project` in the public-project runner with the manifest's scanner limits, two repeats and a 600-second invocation timeout. Final four-format outputs are under `tmp/comparison-v010/invarune-v0100/<project>/`; corresponding public receipts are in `invarune-receipts-v0100/`. Initial 0.9.0 outputs and receipts retain their original `invarune/` and `invarune-receipts/` paths.

With those actual outputs retained, regenerate normalization and conservative matches using:

```bash
python3 scripts/compare_scanner_findings.py
python3 scripts/compare_scanner_findings.py --help
python3 -m unittest discover -s tests -p test_scanner_comparison.py
```

The matching harness verifies each report's raw digest, re-normalizes external output, checks source identity against the actual scan receipt, and rejects duplicate observation IDs. Tests cover exact spans, cross-file/project separation, unmapped/location-only relations, ambiguous matching, exhaustive accounting, imports versus calls, stable IDs, path boundaries and outcome-independent selection. It never supplies an adjudication label.
