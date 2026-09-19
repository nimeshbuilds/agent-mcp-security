# Implementation validation

Validated on **2026-09-19** with **Python 3.9.6 and Python 3.12.14**. This document records scanner implementation checks, not a security certification or a behavioral benchmark score.

## Automated tests

For version **0.4.1**, **426 tests passed, 0 failures, 0 errors, 0 skipped**, on Python 3.9.6 and Python 3.12.14. Many methods contain multiple scenario cases. Run them with:

```sh
python3 -m unittest discover -s tests -v
```

Three additional help regressions verify that every registered public option has visible help/defaults/choices, live format/adapter inventories appear intact, twenty displayed CLI examples parse, and the displayed gateway/baseline JSON is accepted by the actual loaders. Both help aliases are checked for identical output and no scan, config-load, runtime, archive or network side effects. Script/module subprocesses and the installed CLI also render the full reference.

Four catalog-integrity tests also verify every control source, thematic alignment, scanner rule, and technical-reference URL against the expanded 75-source registry.

The tests cover vulnerable and safer Python/JavaScript/configuration cases, multiline and aliased calls, local source tracking, exact versus mutable package references, narrow versus wildcard approvals, Python/JSON parse failures, and AST resource failures. Integration tests verify deterministic results, severity exits, suppressions, SARIF structure, secret redaction, explicit coverage gaps, resource limits, and repeated scans that exclude their own output.

Filesystem regressions cover symbolic links, special/binary inputs, output paths containing `..`, and a directory replaced by a symlink during traversal. Redaction regressions include prefixed environment keys, private-key fields, bearer tokens, URL credentials, and long credentials truncated inside unrelated findings. These cases improve protection; redaction remains best-effort.

Judge tests exercise all five native response protocols and the custom adapter, environment-based authentication, malformed/unknown/duplicate finding IDs, omitted assessments, truncation and response-size errors, timeouts, TLS/configuration failures, header validation, and redirect rejection. Actual loopback HTTP roundtrips include an end-to-end `scan.py` subprocess against a custom JSON gateway. A model calling every finding a false positive is verified not to change deterministic findings, severity, controls, SARIF, or the finding gate.

Analyst tests cover all-control routing on a zero-finding repository, all 132 acceptance-check records, stable evidence/batch ordering, call and elapsed-time limits, omitted answers, first-error stopping, and preserved static results. The full CLI path is exercised against actual loopback HTTP servers for all six adapters: 22 scenario cases, 23 subprocess scans and 135 requests in `test_full_gateway_e2e.py`. Another protocol test covers six adapters across both stages with 12 additional HTTP roundtrips. Both finding triage and control review reject tool-enabled configuration and tool invocation output.

Analyst evidence tests cover unchanged manifest hashes, symlink confinement, post-scan mutations, excluded credential files, secret-line redaction, precise line/truncation metadata, bounded retrieval, and conservative byte charging after failed reads. Protocol tests reject invented or unrelated citations, unknown IDs, invalid statuses, extra fields, duplicate keys, oversized explanations, tool calls, and credential collisions with structural IDs. Quotes cannot be silently sanitized into text that differs from the submitted evidence. Source support for manual and dynamic controls is downgraded to required human/runtime validation.

The expanded audit found and fixed six classes of defect: uncharged raced/failed reads, credential reconstruction during text cleanup, finding-mode tool output acceptance, late EOF deadline acceptance, invalid Unicode configuration/report handling, and deeply nested gateway configuration escaping the error boundary. Each has a regression test. [The scenario matrix](TEST_MATRIX.md) lists the cases and test files, including positive and negative examples for all 42 rules.

Real HTTPS tests verify rejection of untrusted certificates, acceptance with an explicit CA bundle, and rejection of a hostname mismatch. The fixture uses temporary certificates and synthetic credentials. The TLS test skips explicitly if `openssl` is unavailable; platform-specific filesystem tests also skip where their OS primitives do not exist.

Image scanning adds **133 tests**: 61 archive-reader methods, 31 image-assessment methods, 23 runtime-acquisition methods, and 18 CLI/integration methods. These cover Docker-save/OCI archives, platform selection, layer order and whiteouts, hardlink snapshots, retained secrets, source-free images, malicious paths, integrity failures, byte/entry/layer limits, subprocess backpressure/deadlines, private-workspace cleanup, image baselines, and full optional analyst review. Final packaged code in `dist`, `node_modules` and virtual environments is tested. Redacted image paths retain layer/content provenance; ambiguous redacted-path collisions produce explicit gaps. Historical-file exclusions are enforced before renaming, and sensitive historical files cannot enter either optional model source-excerpt path. Current and historical context accompanies model evidence independently of findings. The portable reader fallback is explicitly exercised with canonical temporary paths, matching production workspace creation on hosts with path aliases.

Local runtime tests use controlled subprocesses because Docker and Podman are not installed on the validation Mac. A separate Linux CI job builds actual Docker artifacts using controlled `FROM scratch`/`COPY` fixtures, then checks image-reference acquisition, saved archives, retained credentials, packaged source and binary-only scope reporting. It never starts a container. See [image behavior and reproduction instructions](IMAGE_SCANNING.md).

## Rule accuracy evaluation

The frozen project-authored corpus has **109 labeled rule-presence assertions**. Version 0.2.1 produced 44 true positives, 45 true negatives, 7 false positives and 13 false negatives. Version 0.4.1 preserves the version 0.3.0 result: **52 true positives, 50 true negatives, 2 false positives and 5 false negatives**. All **101 supported regression cases match**; 7 of the 8 challenge cases remain mismatched. The one matched runtime-placeholder case is explicitly not a claim that deployment permissions are safe. This source-pattern corpus does not measure container-image detector accuracy.

On this synthetic corpus, overall precision increased from **86.27% to 96.30%**, and recall from **77.19% to 91.23%**. These are selected source-pattern cases used during development, **not** production accuracy estimates or held-out benchmark results. Every remaining mismatch is published. See [methodology and limits](RULE_ACCURACY.md), [current results](../benchmarks/accuracy-current.md), and the [same-corpus baseline](../benchmarks/accuracy-v021.json).

Whole-rule removal tests deliberately disable all 42 detectors one at a time and confirm the corpus catches each loss. A false-alarm injection verifies precision and failure-gate handling. These do not constitute exhaustive branch/operator mutation testing. Additional Python/JS/configuration regressions exercise scope, branch, literal, token, whitespace, alias and parser variations. Python findings were identical across four hash-seed settings.

## Coverage and distribution checks

Coverage.py **7.16.1** on Python 3.12.14 measured **3,796 / 4,046 statements (93.82%)** and **1,782 / 2,014 branches (88.48%)**; combined coverage was **92.05%**, with no excluded paths. This configuration measures the parent test process; separately tested subprocess entry points are not included in its counters. Uncovered branches remain visible in the coverage report. This is execution coverage, not a security assurance score.

The version 0.4.1 wheel was built, installed without application dependencies into an isolated environment, and invoked from outside the checkout. The installed CLI scanned the shipped image archive without a container runtime, loaded the 66-control packaged catalog, and produced Markdown, JSON and SARIF with three expected findings, zero gaps and exit 1. The installed `-h` and `--help` output was identical and included the complete source/image/gateway reference without relying on repository Markdown files. This guards against source-tree imports hiding packaging errors.

Five generated SARIF reports (vulnerable fixture, safer fixture, scanner itself, image fixture and installed package) passed JSON Schema validation with jsonschema **4.26.0** against the official [OASIS SARIF 2.1.0 Errata 01 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json), SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`. The repeatable validation script rejects a different schema hash and performs no network access.

CI now includes Linux Python 3.9/3.12/3.14, macOS Python 3.12, Windows Python 3.12, a separate coverage/package/schema job, and an actual Docker-built-image integration job. Current run results are available in [GitHub Actions](https://github.com/nimeshbuilds/agent-mcp-security/actions).

## CLI fixture results

| Target | Scanned files | Open findings | Coverage gaps | Exit |
|---|---:|---:|---:|---:|
| `examples/vulnerable` | 3 | 11 | 0 | 1 with default high threshold |
| `examples/safer` | 2 | 0 | 0 | 0 |
| Scanner package itself | 19 | 0 | 0 | 0 with findings gate disabled |
| Shipped image archive | 4 (1 source + 3 generated evidence) | 3 | 0 | 1 with default high threshold |

The vulnerable fixture produces 8 high, 2 medium, and 1 low finding. It demonstrates dynamic execution, shell use, unsafe deserialization, disabled TLS, an embedded demo credential, a remote plaintext MCP endpoint, wildcard automatic approvals, an unpinned server package, and container configuration risks. It is never executed by the scan.

All four targets were scanned twice with identical settings. **Markdown, JSON, and SARIF outputs were byte-for-byte identical** on the second run. The sample reports contain the scanner implementation hash and Python version. No timestamps or remote data enter the deterministic result. The CLI policy/exit result is recorded separately from the evidence scan ID.

- [Vulnerable fixture report](../examples/reports/vulnerable/report.md)
- [Vulnerable JSON](../examples/reports/vulnerable/report.json)
- [Vulnerable SARIF](../examples/reports/vulnerable/report.sarif)
- [Safer fixture report](../examples/reports/safer/report.md)
- [Image fixture report](../examples/reports/image/report.md)

The refreshed fixture repeatability and coverage summary are recorded locally in `test-output/validation-v041.json`, with detailed counters in `test-output/coverage-v041.json` (generated artifacts excluded from version control). The unchanged controlbook artifact has its own [PDF validation record](PDF_VALIDATION.md).

## Boundaries of this validation

No vendor-hosted LLM API was called. Protocol-shape and local-transport tests do not prove compatibility with every account, model, gateway, or authentication system. Configure an approved endpoint and run a controlled integration check before relying on it operationally.

No user production codebase was supplied, so the delivered sample reports are fixture results. No AgentDojo, InjecAgent, ASB, or MCPSecBench benchmark was installed or executed. No real MCP service was probed, no dependency CVE feed was queried, and no exploitability, prompt-injection resistance, or production control effectiveness was established.

Podman acquisition is covered by controlled subprocess tests; a live Podman engine was not exercised. Actual Docker CI uses deliberately small built fixtures, not a representative production-image corpus. Compiled application logic, runtime deployment overrides, signature trust and dependency CVEs remain unassessed even when an image scan exits 0.

SARIF passed the pinned JSON Schema check; this does not establish every semantic SARIF requirement or integration with every consumer. The static rules deliberately provide limited coverage and can have false positives and false negatives. Zero findings in the small comparison fixture or the scanner's own sources does not establish security.
