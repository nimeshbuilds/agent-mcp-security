# Implementation validation

Validated on **2026-09-19** with **Python 3.9.6 and Python 3.12.14**. This document records scanner implementation checks, not a security certification or a behavioral benchmark score.

## Automated tests

For version **0.2.0**, **153 tests passed, 0 failures, 0 errors, 0 skipped**, on Python 3.9.6 and Python 3.12.14. Run them with:

```sh
python3 -m unittest discover -s tests -v
```

Four catalog-integrity tests also verify every control source, thematic alignment, scanner rule, and technical-reference URL against the expanded 75-source registry.

The tests cover vulnerable and safer Python/JavaScript/configuration cases, multiline and aliased calls, local source tracking, exact versus mutable package references, narrow versus wildcard approvals, Python/JSON parse failures, and AST resource failures. Integration tests verify deterministic results, severity exits, suppressions, SARIF structure, secret redaction, explicit coverage gaps, resource limits, and repeated scans that exclude their own output.

Filesystem regressions cover symbolic links, special/binary inputs, output paths containing `..`, and a directory replaced by a symlink during traversal. Redaction regressions include prefixed environment keys, private-key fields, bearer tokens, URL credentials, and long credentials truncated inside unrelated findings. These cases improve protection; redaction remains best-effort.

Judge tests exercise all five native response protocols and the custom adapter, environment-based authentication, malformed/unknown/duplicate finding IDs, omitted assessments, truncation and response-size errors, timeouts, TLS/configuration failures, header validation, and redirect rejection. Actual loopback HTTP roundtrips include an end-to-end `scan.py` subprocess against a custom JSON gateway. A model calling every finding a false positive is verified not to change deterministic findings, severity, controls, SARIF, or the finding gate.

The **62 analyst tests** cover all-control routing on a zero-finding repository, all 132 acceptance-check records, stable evidence/batch ordering, call and elapsed-time limits, omitted answers, first-error stopping, and preserved static results. The full custom-gateway CLI path is exercised through mocked transport with the real request builder and strict response validator. Full mode rejects tool-enabled custom configuration before either review stage sends a request.

Analyst evidence tests cover unchanged manifest hashes, symlink confinement, post-scan mutations, excluded credential files, secret-line redaction, precise line/truncation metadata, bounded retrieval, and conservative byte charging after failed reads. Protocol tests reject invented or unrelated citations, unknown IDs, invalid statuses, extra fields, duplicate keys, oversized explanations, tool calls, and credential collisions with structural IDs. Quotes cannot be silently sanitized into text that differs from the submitted evidence. Source support for manual and dynamic controls is downgraded to required human/runtime validation.

## CLI fixture results

| Target | Scanned files | Open findings | Coverage gaps | Exit |
|---|---:|---:|---:|---:|
| `examples/vulnerable` | 3 | 11 | 0 | 1 with default high threshold |
| `examples/safer` | 2 | 0 | 0 | 0 |
| Scanner package itself | 14 | 0 | 0 | 0 with findings gate disabled |

The vulnerable fixture produces 8 high, 2 medium, and 1 low finding. It demonstrates dynamic execution, shell use, unsafe deserialization, disabled TLS, an embedded demo credential, a remote plaintext MCP endpoint, wildcard automatic approvals, an unpinned server package, and container configuration risks. It is never executed by the scan.

All three targets were scanned twice with identical settings. **Markdown, JSON, and SARIF outputs were byte-for-byte identical** on the second run. The sample reports contain the scanner implementation hash and Python version. No timestamps or remote data enter the deterministic result. The CLI policy/exit result is recorded separately from the evidence scan ID.

- [Vulnerable fixture report](../examples/reports/vulnerable/report.md)
- [Vulnerable JSON](../examples/reports/vulnerable/report.json)
- [Vulnerable SARIF](../examples/reports/vulnerable/report.sarif)
- [Safer fixture report](../examples/reports/safer/report.md)

The refreshed fixture repeatability summary and PDF hash are recorded locally in `test-output/validation-v02.json` (a generated artifact excluded from version control).

## Boundaries of this validation

No vendor-hosted LLM API was called. Protocol-shape and local-transport tests do not prove compatibility with every account, model, gateway, or authentication system. Configure an approved endpoint and run a controlled integration check before relying on it operationally.

No user production codebase was supplied, so the delivered sample reports are fixture results. No AgentDojo, InjecAgent, ASB, or MCPSecBench benchmark was installed or executed. No real MCP service was probed, no dependency CVE feed was queried, and no exploitability, prompt-injection resistance, or production control effectiveness was established.

SARIF was inspected through structural and integration assertions; a separate full JSON Schema conformance run was not performed. The static rules deliberately provide limited coverage and can have false positives and false negatives. Zero findings in the small comparison fixture or the scanner's own sources does not establish security.
