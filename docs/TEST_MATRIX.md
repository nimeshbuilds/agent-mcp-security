# Scenario test matrix

This matrix records concrete scanner and controller behavior tested for version **0.4.0**. It is a finite regression suite, not a claim that every possible input, model, framework, or deployment has been tested. Tests use synthetic secrets, repository fixtures, mocked responses, and real loopback HTTP/HTTPS. They never execute the target application or use a paid model API.

## Reproducible scenario coverage

All filenames below are under `tests/` unless another path is given.

| Area | Scenarios exercised | Evidence |
| --- | --- | --- |
| All 42 static rules | A detecting example and a corresponding non-triggering or safer alternative for every rule ID; aliases, multiline calls, local source tracking, fixed/dynamic execution, pinned/mutable dependencies | `test_rules.py`, `test_security_boundaries.py` |
| Labeled accuracy and detector mutations | 109 labeled assertions, all 42 rules with positive/negative labels, each whole-rule removal caught, synthetic false-alarm injection, visible challenge failures, metric denominators and CLI gates | `test_accuracy_corpus.py`, `benchmarks/static_accuracy.json` |
| Python semantic boundaries | 32 regression methods for aliases, rebinding, scope, fixed/dynamic values, keyword sinks, branches, exceptions, loop zero iterations, mutable data, unsafe loader origins and explicit analysis work limits | `test_python_accuracy.py` |
| JavaScript lexical boundaries | 26 methods / 174 explicit subcases: quoted/regex/comment examples, fake imports, aliases, shadowing, multiline calls, templates, function bodies, escaping, configuration properties and logging labels | `test_javascript_accuracy.py` |
| Configuration accuracy | Real/mapped loopback, deceptive DNS prefixes, whitespace, package-selector forms, every additional distribution, exact versions, JSON container context, image digest length, ambiguous/nonfinite JSON | `test_configuration_accuracy.py` |
| CLI usability and analysis depth | Grouped help/defaults, no abbreviated flags, quiet/JSON output, rule explanations, invalid combinations, artifact/gate equivalence, per-file language analysis profiles | `test_cli_usability.py`, `test_analysis_profiles.py` |
| Image archives | Docker-save/OCI, gzip, multi-platform selection, digest/size/DiffID verification, whiteouts/opq order, replacements, retained revisions, links, hostile paths/collisions, special/sparse/PAX entries, decompression/truncation and resource bounds | `test_image_archive.py` |
| Image assessment | Default/named users, null fields, env/labels/history secrets, command bypasses, retained credentials, history-vs-runtime provenance, OS/package/permission inventory, binary scope and record budgets | `test_image_assessment.py` |
| Image runtime acquisition | Real controlled subprocesses, Docker/Podman argument contracts, explicit pulls, no execution, stream caps, pressure/deadlines, atomic cleanup, errors without diagnostic secrets | `test_image_runtime.py` |
| Image CLI | Runtime-free Docker/OCI, packaged build/dependency source, binary-only metadata scope, source/metadata baselines, secret rotation, redacted-path provenance, report repeatability, optional all-control analyst and cleanup | `test_image_cli.py` |
| Actual Docker artifact | FROM-scratch COPY-only builds, reference and saved-archive scans, native executable plus packaged source, retained-layer/config secrets, binary-only scope; no container start | `scripts/validate_image_scan.py`, `built-image-integration` CI job |
| Input and traversal | Empty/invalid targets; supported/unsupported files; exclusions; malformed Python/JSON; binary, BOM, non-UTF-8 and CRLF data; symlinks, FIFO, changed inode/root; repeatability | `test_scanner.py`, `test_rules.py`, `test_security_boundaries.py` |
| Resource accounting | File, entry, per-file and total-byte limits; rejected/failed reads charged; remaining-budget/sentinel boundary; AST recursion failures | `test_scanner.py`, `test_security_boundaries.py`, `test_rules.py` |
| CLI policy | All six severity settings; operational failure precedence; invalid flags; listing/version commands; script/module entry points; baseline candidate, suppression, stale IDs and malformed baselines | `test_cli_contract.py`, `test_scanner.py`, `test_security_boundaries.py`, `test_judge_integration.py` |
| Evidence selection | Stable ranking and IDs; manifest hashes; confinement; source replacement; duplicate entries; credential exclusions; redaction before truncation; zero/exhausted budgets | `test_evidence.py`, `test_security_boundaries.py` |
| All-control routing | Zero findings still queue 66 controls and 132 checks; batch/call/time limits; first-error stopping; every omitted/unscheduled check retained | `test_analyst_controller.py`, `test_analyst_cli.py` |
| All six protocols | Chat Completions, Responses, Anthropic, Gemini, Ollama and custom JSON gateway; both stages; exact endpoints and environment authentication | `test_judge.py`, `test_protocol_adversarial.py`, `test_full_gateway_e2e.py` |
| Actual CLI HTTP flows | 22 scenario cases / 23 subprocess scans / 135 HTTP requests; all providers complete 11 control batches plus finding triage | `test_full_gateway_e2e.py` |
| Additional protocol HTTP flows | 12 real HTTP roundtrips: six adapters times two review modes | `test_protocol_adversarial.py` |
| Actual TLS | Untrusted certificate rejection; explicit CA success; hostname mismatch rejection | `test_protocol_adversarial.py` (requires `openssl`) |
| Hostile/failed transport | Redirects, HTTP errors, timeouts, late EOF, compression, size limits, bad UTF-8/JSON, duplicate keys, nonfinite numbers, refused/truncated output | `test_judge.py`, `test_protocol_adversarial.py`, `test_full_gateway_e2e.py` |
| Output trust boundary | Unknown/duplicate IDs, fabricated/unrelated quotes, extra fields, oversized reasons, tool calls/configuration, malicious repository instructions, dynamic/manual downgrades | `test_analyst_protocol.py`, `test_protocol_adversarial.py`, `test_full_gateway_e2e.py` |
| Credentials and Unicode | Source/API secret scrubbing; secret reconstruction through text cleanup; credential/ID collisions; quote sanitization; invalid Unicode in identifiers, URLs, advice and paths | `test_protocol_adversarial.py`, `test_analyst_protocol.py`, `test_security_boundaries.py` |
| Configuration failure | Invalid types, unset keys, unsafe headers/endpoints, oversized/deep configuration; static reports survive requested judge failures | `test_judge.py`, `test_protocol_adversarial.py`, `test_cli_contract.py` |
| Report integrity | Advice preserves static findings, severity, controls, scan ID and SARIF; HTML/Markdown escaping; code fences/URI encoding; atomic writes and cleanup | `test_analyst_cli.py`, `test_full_gateway_e2e.py`, `test_security_boundaries.py` |
| Catalog integrity | Control sources, alignments, rule mappings, metadata and reference URLs checked against the packaged catalog | `test_catalog.py`, `test_rules.py` |
| Installed distribution | Wheel build/install without target dependencies; installed CLI outside checkout; packaged catalog available | `package-and-schema` CI job |
| SARIF schema | Generated reports validate against the hash-pinned official OASIS SARIF 2.1.0 Errata 01 JSON Schema | `scripts/validate_sarif.py`, `package-and-schema` CI job |

The HTTP counts describe those specific test files; other tests add local requests. Fixture responses exercise controller decisions and error paths. They do not measure a real LLM's judgment quality or prompt-injection resistance.

Version 0.3.0 also fixes 13 previously failing accuracy-corpus cases. [The accuracy methodology](RULE_ACCURACY.md) records those improvements and all remaining labeled mismatches. Passing regression tests does not erase known challenge failures.

## Defects found and fixed

1. **File races could evade the total read budget.** Successful reads now count before inode rejection; failed reads are charged conservatively and reserve a growth-detection byte.
2. **Text cleanup could reconstruct a secret.** Credential scrubbing now considers normalized text and credential variants after control-character/Unicode handling.
3. **Finding-only review accepted tool output accompanying valid text.** Tool configuration and invocation checks now apply to both stages.
4. **A response could finish after its deadline on the final read.** Time is checked after each read, including EOF. This rejects late results; DNS/socket timeouts remain short of a hard process deadline.
5. **Malformed Unicode could escape the error boundary or break report writing.** Model/endpoint validation rejects invalid Unicode, display text escapes lone surrogates, and SARIF encodes filesystem path bytes safely.
6. **Deep gateway templates could cause uncaught recursion.** Configuration depth is capped at 64; request recursion/encoding failures become safe judge errors with static results preserved.

## Run the suite

```sh
python3 -m unittest discover -s tests -v
```

The standard-library suite needs no QA packages. `openssl` enables the real TLS fixture. Filesystem tests explicitly skip absent primitives, such as POSIX FIFOs and directory-descriptor root checks on Windows; the Windows job exercises the portable filesystem fallback.

CI runs Python 3.9, 3.12 and 3.14 on Linux, plus Python 3.12 on macOS and Windows. A separate Linux job measures coverage, builds/installs the wheel, invokes it outside the checkout, and validates SARIF. [Implementation validation](VALIDATION.md) records results and the run link.

For coverage with Python 3.12 and optional QA tools:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-qa.txt
.venv/bin/python -m coverage run --branch --source=ai_security_scan -m unittest discover -s tests -v
.venv/bin/python -m coverage report --show-missing
```

On Windows use `.venv\Scripts\python.exe`. Coverage measures parent-process code; subprocess CLI behavior is tested separately and is not included in this coverage configuration. No paths are excluded to inflate the result. Coverage is not a security score.

Validate against the official [OASIS schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json):

```sh
mkdir -p test-output
curl --fail --location --proto '=https' --tlsv1.2 --max-time 30 \
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json \
  --output test-output/sarif-schema.json
.venv/bin/python scripts/validate_sarif.py \
  --schema test-output/sarif-schema.json \
  examples/reports/vulnerable/report.sarif examples/reports/safer/report.sarif
```

The validator performs no network access and rejects a schema with a different SHA-256. Schema conformance does not establish every semantic SARIF requirement or compatibility with every consuming product.

## Checks requiring another environment

- Live vendor/enterprise-gateway compatibility with actual credentials, selected models, policies, rate limits and retention settings.
- A real model's security accuracy, calibration, repeatability and response to adaptive prompt injection.
- Production agent/MCP behavior: authorization, tenant boundaries, side effects, egress, approvals, memory isolation and operational controls.
- Referenced behavioral benchmarks such as AgentDojo, ASB, InjecAgent and MCP attack suites, which require configured targets and authorized harnesses.

This run used no production repository or live model credentials. Those checks remain explicit instead of being inferred from passing unit tests or a clean pattern scan.
