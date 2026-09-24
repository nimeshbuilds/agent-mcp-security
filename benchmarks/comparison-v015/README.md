# Invarune 0.15 benchmark: stronger boundaries, visible misses

This release fixes three errors on the unchanged 113-assertion development corpus, adds a world-writable agent-workspace check found through peer review, and improves recognized MCP parameter flow and composed malicious instructions. A harder first blind test exposed a substantial gap: **4 TP / 16 TN / 0 FP / 12 FN**. After those cases were disclosed and fixed, the same set returned **16 TP / 16 TN / 0 FP / 0 FN**. A separate eight-case temporal holdout still has **two misses**. Those results do not establish production vulnerability accuracy or an overall product ranking.

Start with the [visual dashboard](../../docs/BENCHMARK_DASHBOARD.md), [branded PDF](../../output/pdf/invarune-benchmark-v015.pdf), [all 1,115 source observations](FINDINGS.md), [challenge cases and outcomes](CHALLENGE.md), or [12 contextual source reviews](SOURCE_REVIEW.md). All historical benchmark directories and original corpus bytes remain unchanged.

## Results with separate denominators

| Track | Earlier result: TP / TN / FP / FN | Current result: TP / TN / FP / FN | Meaning |
| --- | --- | --- | --- |
| Original 113 source assertions | 58 / 52 / 1 / 2 | 60 / 53 / 0 / 0 | Same development-visible input bytes and labels |
| Original 331 skill/tool assertions | 40 / 288 / 0 / 3 | 43 / 287 / 1 / 0 | Original scope label retained, including its false-positive score |
| Revised 331 skill/tool assertions | 40 / 287 / 0 / 4 | 44 / 287 / 0 / 0 | Exactly one explicit label correction; all 81 source inputs identical |
| Additional call-flow/permission assertions | Not a paired historical denominator | 30 / 33 / 0 / 2 | 65 development assertions; two known misses retained |
| Additional instruction/contract assertions | Not a paired historical denominator | 11 / 113 / 0 / 0 | 124 development assertions, distinct from prior corpora |
| Sealed 32-case challenge | v0.14: 3 / 16 / 0 / 13; first v0.15: 4 / 16 / 0 / 12 | 16 / 16 / 0 / 0 | Current result was measured after disclosure and tuning |
| Second sealed eight-case confirmation | First execution: 2 / 4 / 0 / 2 | Presentation-only repeat: 2 / 4 / 0 / 2 | No detector changes after disclosure; not a second blind test |
| Ten equivalent API-pattern assertions | Invarune, Semgrep CE and Bandit each 5 / 5 / 0 / 0 | All three still 5 / 5 / 0 / 0 | A narrow development fixture tie |

TP here means a match to an authored static predicate. Precision is TP / (TP + FP), recall is TP / (TP + FN); these ratios describe only each displayed denominator. No unlabeled finding is counted as a true positive. No unsupported feature receives an artificial true negative. Fixtures were authored within this project, and even the temporal holdouts are not independent third-party validation.

The original skill case `hierarchy-json-schema-field` labels an override inside a tool parameter description out of scope. MCP tool schemas are model-visible metadata, so the expanded detector deliberately inspects those descriptions. The [separate v1.1 corpus](../skills_tools_accuracy-v110.json) changes only that expected AI043 label. Both [legacy paired results](before-after-skills-legacy.json) and [corrected paired results](before-after-skills-corrected.json) remain published; this is not a silent relabeling.

## Same public source, fresh executions

Eight pinned first-party exports contain **4,120 files**. The primary measured comparison includes **56 source CLI executions**: two baseline and two final Invarune scans per project, plus one fresh Semgrep, Bandit and Gitleaks execution per project. Earlier preparation and pre-presentation runs are not represented as additional independent samples. Thirty-two final HTML/JSON/Markdown/SARIF files are byte-identical across their two actual executions and bound to [per-file hashes](published-report-manifest.json).

| Scanner/configuration | Native source observations | Retained limitations |
| --- | ---: | --- |
| Invarune 0.15.0, rules 1.6.0, static defaults | 147 | 24 explicit coverage gaps; no target runtime or model |
| Semgrep CE 1.177.0, frozen 225-rule security-audit pack | 27 | Seven native parser warnings |
| Bandit 1.9.4, packaged default plugins, no inline suppression | 938 | Five parser errors; two non-Python exports unsupported |
| Gitleaks 8.30.1, default rules and full redaction | 3 | Credential validity not checked |

The [tool lock](tool-lock.json) deliberately preserves prior versions/rule bytes for comparability; these are not represented as the latest versions. The original lock's Snyk wording is corrected by a separate [research update](snyk-research-update.json): direct skill files are supported, but the authenticated analysis service was not executed. Cisco's source-derived 14-descriptor YARA track ran freshly and found no matches; untested analyzers have no score. [Official capability research](RESEARCH.md) describes broader peer functionality.

Invarune's source count changes from 146 to 147. The added AI047 observation is the existing optional AutoGen Jupyter workspace receiving mode `0o777`, also surfaced by Bandit B103. It is an explicit other-write permission predicate, not a demonstrated exploit. Exploitability depends on mount, namespace, ownership and local-principal access. The [source delta](source-delta.json) records every identity and span change.

Coverage gaps increase from 21 to 24 because the new analysis explicitly reports an unsupported complex `registerTool` callback parameter shape and two unresolved unawaited async helper calls. These inputs are incomplete, not clean. The exported corpus excludes most documentation, examples, generated/vendor files and agent-instruction files; it mainly tests library source/configuration. It cannot substitute for the separate agent/MCP challenge or live deployment validation.

## Finding-by-finding comparison and source review

| Peer compared with Invarune | Unambiguous one-to-one pairs | Ambiguous match edges | Invarune unmatched | Peer unmatched |
| --- | ---: | ---: | ---: | ---: |
| Semgrep | 7 | 0 | 140 | 20 |
| Bandit | 13 | 5 | 129 | 924 |
| Gitleaks | 1 | 0 | 146 | 2 |

Matching requires compatible risk-family semantics, the same pinned path, and overlapping spans. Ambiguous edges are reported separately; overlap is not truth. A peer-only finding may be a real missing risk, broader intended scope, a narrower predicate, or an irrelevant alert. The [complete ledger](observations.json), [overlap partitions](overlaps.json), [family predicates](rule-family-map.json) and [native statuses](run-status.json) permit individual review.

The benchmark assistant inspected 12 purposively chosen source locations, recording file/span hashes, pinned links, exact predicates, context and qualifications. This review identified the useful workspace permission gap and documented why BaseLoader, serialization, public OAuth URLs, trusted Markdown and archive wrappers cannot simply be called missed vulnerabilities. It is not independent human adjudication, a random sample or a basis for an aggregate production true-positive percentage. A model's opinion is not ground truth. [Review evidence](source-review.json).

## Equivalent MCP metadata

| Input set / analyzer | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| Original 16 descriptors, Invarune after disclosure | 8 | 8 | 0 | 0 |
| Same 16, Cisco MCP Scanner 4.8.4 YARA only | 0 | 8 | 0 | 8 |
| Separate four sealed descriptors, Invarune first execution | 0 | 2 | 0 | 2 |
| Same four, Cisco YARA first execution | 1 | 1 | 1 | 1 |

This measures a tool-level operative-instruction predicate, not agreement between native rule taxonomies. Cisco's enabled YARA engine passed a separate positive/safe sanity pair. API, LLM, behavioral and runtime capabilities were not enabled and are never assigned misses. On the small second set, both tools miss a system-message precedence instruction; Cisco also matches a public `.env.example` template that is negative for the specified credential-transfer predicate. This is a narrow, project-authored comparison, not a full-product ranking.

## Reproduce the artifacts

Use an installed development environment as described in [developer setup](../../docs/developer/index.md). Public users run `invscan`; the commands below are repository benchmark-authoring tools.

1. Recreate exports from [the pinned manifest](../real-world/manifest.json) and verify each [snapshot](../real-world/snapshots). Preserve the selection policy and bytes.
2. Use Git revision `cffcd8873e3830d2200575fc05c61989cf2532c5` for the actual 0.14 baseline. Its implementation digest is `a10cff2be83ee83ef7f016e0d9644b42b2cc9869528a91763840970dc87765f1`; use the independently extracted package and absolute harness paths. Do not relabel old report files as fresh runs.
3. Run `scripts/scan_public_projects.py --source-root <absolute exports> --output-root <absolute reports> --records-root <absolute records> --repeats 2` for each frozen implementation. Each records directory needs the pinned `snapshots/` inputs. The final implementation digest is `02c1a309226db622fe6ab86ae72b3c652e370d2faae3876b7ec64049d8f5e1c5`.
4. Run `scripts/benchmark_competitors.py --help` and supply the exact executables, frozen rule pack, source exports, snapshots, tool lock, private raw-output directory and published normalized-output directory. Source, ten shared API cases and Cisco metadata are distinct tracks. [Recorded tool-byte verification](tool-byte-verification.json) binds actual binaries/rules.
5. Run `scripts/evaluate_accuracy.py` separately for the original 113 corpus, original 331 corpus, revised 331 corpus, 65 flow/permission assertions and 124 instruction assertions; keep `--fail-on none` for measurement so all mismatches remain visible. This measurement setting does not change CI regression policy.
6. Run `scripts/benchmark_agent_challenge.py --help` against the immutable corpus and commitment files, with a fresh output path per execution. The historical first results cannot be reproduced as blind once their labels are public. New independent validation needs a new sealed corpus and a frozen detector.
7. Run `scripts/finalize_benchmark_comparison.py --help` to bind source reports and paired labels, then `scripts/compare_scanner_findings.py --help` to validate raw peers and build every observation/overlap. Raw reports stay outside Git; published reports contain portable paths.
8. Run `python scripts/build_benchmark_dashboard.py --check` and `python scripts/build_benchmark_update.py --input-dir benchmarks/comparison-v015 --output output/pdf/invarune-benchmark-v015.pdf`. Builders reject mismatched labels, incomplete cases, changed commitments, report/implementation inconsistencies, and incorrect overlap totals. Render all PDF pages and inspect them before publication.

The first eight-case confirmation used implementation `525747fc453830a4bc93b887c21161ff44c21212af1a525bbd5a9d615086954b`. Only `report_html.py` and `report_pdf.py` then changed to expose optional-review uncertainty in report summaries. [Module hashes](presentation-only-change.json), the [original first result](confirmation-first.json), and the [explicit repeat](confirmation-final.json) show identical detector outcomes. All final source reports were regenerated on the release implementation.

## Open work

The second holdout leaves one .env contents-transfer instruction and one hierarchy-override phrasing unresolved. The larger development corpus also preserves a potentially replaced decorated Python callable and a multi-statement JavaScript wrapper as known misses. Cross-file calls, arbitrary aliases, reflection, DNS/redirect effects, runtime policy enforcement, tenant isolation and model obedience require other evidence. Optional bounded AI investigation may help inspect those ambiguities using permitted evidence, but it remains advisory and does not erase static findings or prove the deployment safe. [AgentDojo and InjecAgent](RESEARCH.md#runtime-benchmarks-that-cannot-be-replaced-by-a-repository-scan) are meaningful future runtime tracks; neither was executed here.

No patentability, uniqueness, universal accuracy guarantee, market leadership or endorsement by compared products is claimed.
