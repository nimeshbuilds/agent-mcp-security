# Scenario test matrix

## Current v0.13 release

[Executed v0.13 validation](../benchmarks/validation-v013/README.md) covers benchmark-driven detector fixes, unchanged-corpus comparison, fresh pinned-project scans, the installed CLI quickstart, publication provenance and PDF/site QA. Historical counts below retain their original version scopes.

This matrix records concrete scanner and controller behavior tested for version **0.10.0**. It is a finite regression suite, not a claim that every possible input, model, framework, or deployment has been tested. The prior v0.8.0 suite had 588 passing tests. Historical v0.9 and current v0.10 runs and dependency-specific skips are recorded in [implementation validation](VALIDATION.md). It uses synthetic secrets, repository fixtures, mocked provider responses, real bounded subprocesses and loopback HTTP/HTTPS. The automated suite never executes the target application or calls a live model. Separate empirical public-project, competitor and official CLI-provider checks are recorded below and in [implementation validation](VALIDATION.md).

## Reproducible scenario coverage

All filenames below are under `tests/` unless another path is given.

| Area | Scenarios exercised | Evidence |
| --- | --- | --- |
| All 42 static rules | A detecting example and a corresponding non-triggering or safer alternative for every rule ID; aliases, multiline calls, local source tracking, fixed/dynamic execution, pinned/mutable dependencies | `test_rules.py`, `test_security_boundaries.py` |
| Labeled accuracy and detector mutations | 113 labeled assertions, all 42 rules with positive/negative labels, each whole-rule removal caught, false-alarm injection, visible challenge failures, metric denominators and gates; corpus 1.2.0 with explicit AI041 label correction; unchanged 1.1.0 and 1.0.0 bytes/results retained separately | `test_accuracy_corpus.py`, `benchmarks/static_accuracy.json`, `benchmarks/static_accuracy-v100.json`, `benchmarks/accuracy-original-corpus.json` |
| Python semantic boundaries | 32 regression methods for aliases, rebinding, scope, fixed/dynamic values, keyword sinks, branches, exceptions, loop zero iterations, mutable data, unsafe loader origins and explicit analysis work limits | `test_python_accuracy.py` |
| JavaScript lexical boundaries | 26 methods / 174 explicit subcases: quoted/regex/comment examples, fake imports, aliases, shadowing, multiline calls, templates, function bodies, escaping, configuration properties and logging labels | `test_javascript_accuracy.py` |
| Configuration accuracy | Real/mapped loopback, deceptive DNS prefixes, whitespace, package-selector forms, every additional distribution, exact versions, JSON container context, image digest length, ambiguous/nonfinite JSON | `test_configuration_accuracy.py` |
| CLI usability and analysis depth | Grouped help/defaults, no abbreviated flags, quiet/JSON output, rule explanations, invalid combinations, artifact/gate equivalence, per-file language analysis profiles | `test_cli_usability.py`, `test_analysis_profiles.py` |
| Complete offline CLI help | Every public option/default/choice, live inventories, parsable command examples and accepted gateway/baseline JSON; identical -h/--help with no scan/runtime/network side effects; script/module/installed entry points | `test_cli_usability.py`, `package-and-schema` CI job |
| Image archives | Docker-save/OCI, gzip, multi-platform selection, digest/size/DiffID verification, whiteouts/opq order, replacements, retained revisions, links, hostile paths/collisions, special/sparse/PAX entries, decompression/truncation and resource bounds | `test_image_archive.py` |
| Image assessment | Default/named users, null fields, env/labels/history secrets, command bypasses, retained credentials, history-vs-runtime provenance, OS/package/permission inventory, binary scope and record budgets | `test_image_assessment.py` |
| Image runtime acquisition | Real controlled subprocesses, Docker/Podman argument contracts, explicit pulls, no execution, stream caps, pressure/deadlines, atomic cleanup, errors without diagnostic secrets | `test_image_runtime.py` |
| Image CLI | Runtime-free Docker/OCI, packaged build/dependency source, binary-only metadata scope, source/metadata baselines, secret rotation, redacted-path provenance, report repeatability, optional all-control analyst and cleanup | `test_image_cli.py` |
| Actual Docker artifact | FROM-scratch COPY-only builds, reference and saved-archive scans, native executable plus packaged source, retained-layer/config secrets, binary-only scope; no container start | `scripts/validate_image_scan.py`, `built-image-integration` CI job |
| Input and traversal | Empty/invalid targets; supported/unsupported files; exclusions; malformed Python/JSON; binary, BOM, non-UTF-8 and CRLF data; symlinks, FIFO, changed inode/root; repeatability | `test_scanner.py`, `test_rules.py`, `test_security_boundaries.py` |
| Resource accounting | File, entry, per-file and total-byte limits; rejected/failed reads charged; remaining-budget/sentinel boundary; AST recursion failures | `test_scanner.py`, `test_security_boundaries.py`, `test_rules.py` |
| CLI policy | All six severity settings; operational failure precedence; invalid flags; listing/version commands; script/module entry points; baseline candidate, suppression, stale IDs and malformed baselines | `test_cli_contract.py`, `test_scanner.py`, `test_security_boundaries.py`, `test_judge_integration.py` |
| User review configuration | Both dispositions for all 42 rules, all 66 controls and 132 check IDs; strict schema/types/IDs/duplicates/Unicode/size; baseline precedence, stable IDs and hashes, no false pass, retained gaps | `test_review_policy.py` |
| Review CLI and reports | Source/image parity, active denominators, retained evidence, no auto-discovery, conflicting/invalid policy, original baseline reasons, all formats and output modes, config overwrite and symlink-loop rejection, all-exempt scopes | `test_review_policy_cli.py`, `test_review_policy_reports.py` |
| Policy-aware analyst | Compact-to-original check mapping, exempt text/rationale excluded from requests, zero-call fully exempt scope, omissions/budgets/errors, user provenance retained | `test_analyst_review_policy.py` |
| Review gateway integration | Six actual CLI subprocesses and 12 loopback HTTP requests, one triage plus one partial-check request per native/custom protocol | `test_review_policy_cli.py` |
| Trusted path identity | Case aliases, explicit file hardlinks, external trusted configs, generated output directory aliases, manifest/model exclusion, stable reports and unchanged ordinary files | `test_exclusion_identity.py` |
| Evidence selection | Stable ranking and IDs; manifest hashes; confinement; source replacement; duplicate entries; credential exclusions; redaction before truncation; zero/exhausted budgets | `test_evidence.py`, `test_security_boundaries.py` |
| All-control routing | Zero findings still queue 66 controls and 132 checks; batch/call/time limits; first-error stopping; every omitted/unscheduled check retained | `test_analyst_controller.py`, `test_analyst_cli.py` |
| All six protocols | Chat Completions, Responses, Anthropic, Gemini, Ollama and custom JSON gateway; both stages; exact endpoints and environment authentication | `test_judge.py`, `test_protocol_adversarial.py`, `test_full_gateway_e2e.py` |
| Official CLI transport/configuration | 19 methods: all three provider defaults/contracts; strict versions/flags/envelopes; minimized child environment; private prompt input; exact startup warning; Grok extension preflight; stdout/stderr caps, timeout, blocked stdin, nonzero exits and descendant cleanup | `test_cli_judge.py` |
| CLI review integration | 12 methods: deterministic default never launches providers; all three mocked providers preserve finding gates and review all checks; shortcut/config parity; errors retain reports; policy exclusions, image provenance, exact IDs/citations, tool-output rejection and duplicate config keys | `test_cli_judge_integration.py` |
| Official authentication flow | 15 methods: read-only status, login delegation, no noninteractive browser launch, successful login/resume, expired-auth retry once, timeout/cancellation, control-call budget, quiet/JSON/never modes, standalone login and static-result preservation | `test_cli_login.py` |
| Actual CLI HTTP flows | 22 scenario cases / 23 subprocess scans / 135 HTTP requests; all providers complete 11 control batches plus finding triage | `test_full_gateway_e2e.py` |
| Additional protocol HTTP flows | 12 real HTTP roundtrips: six adapters times two review modes | `test_protocol_adversarial.py` |
| Actual TLS | Untrusted certificate rejection; explicit CA success; hostname mismatch rejection | `test_protocol_adversarial.py` (requires `openssl`) |
| Hostile/failed transport | Redirects, HTTP errors, timeouts, late EOF, compression, size limits, bad UTF-8/JSON, duplicate keys, nonfinite numbers, refused/truncated output | `test_judge.py`, `test_protocol_adversarial.py`, `test_full_gateway_e2e.py` |
| Output trust boundary | Unknown/duplicate IDs, fabricated/unrelated quotes, extra fields, oversized reasons, tool calls/configuration, malicious repository instructions, dynamic/manual downgrades | `test_analyst_protocol.py`, `test_protocol_adversarial.py`, `test_full_gateway_e2e.py` |
| Credentials and Unicode | Source/API secret scrubbing; secret reconstruction through text cleanup; credential/ID collisions; quote sanitization; invalid Unicode in identifiers, URLs, advice and paths | `test_protocol_adversarial.py`, `test_analyst_protocol.py`, `test_security_boundaries.py` |
| Configuration failure | Invalid types, unset keys, unsafe headers/endpoints, oversized/deep configuration; static reports survive requested judge failures | `test_judge.py`, `test_protocol_adversarial.py`, `test_cli_contract.py` |
| Report integrity | Advice preserves static findings, severity, controls, scan ID and SARIF; HTML/Markdown escaping; code fences/URI encoding; atomic writes and cleanup | `test_analyst_cli.py`, `test_full_gateway_e2e.py`, `test_security_boundaries.py` |
| Catalog integrity | Control sources, alignments, rule mappings, metadata and reference URLs checked against the packaged catalog | `test_catalog.py`, `test_rules.py` |
| Public-scan detector regressions | 9 methods with paired cases: plausible PEM material versus marker-only examples, full material in docstrings/escaped strings, SDK dummy values, error role plus error sentence, final Docker USER/stage inheritance/overrides/continuations/heredocs | `test_real_world_regressions.py` |
| Public-project reproduction boundaries | 8 methods: frozen scope selection, safe paths, source/manifest drift, extra/missing files, symlink rejection, pinned revisions/URLs, regular Git blob export without execution, actual scanner repeatability across four artifacts | `test_public_project_runner.py`, `scripts/scan_public_projects.py` |
| Competitor harness | 13 methods: findings exits versus execution failures, timeouts/missing JSON, sanitized source/secret diagnostics, coverage gaps, explicit rule mappings, unsupported cases without false true negatives, source-byte verification, Windows rooted/drive-path normalization, literal metadata extraction and false-inventory rejection, pinned tool/rule-pack commands | `test_competitor_benchmarks.py`, `scripts/benchmark_competitors.py` |
| Installed distribution | Wheel build/install without target dependencies; installed CLI outside checkout; packaged catalog available | `package-and-schema` CI job |
| SARIF schema | Generated reports validate against the hash-pinned official OASIS SARIF 2.1.0 Errata 01 JSON Schema | `scripts/validate_sarif.py`, `package-and-schema` CI job |

The HTTP counts describe those specific test files; other tests add local requests. Fixture responses exercise controller decisions and error paths. They do not measure a real LLM's judgment quality or prompt-injection resistance.

The historical version 0.3.0 accuracy improvements were measured on corpus 1.0.0. Historical corpus 1.1.0 changed the synthetic AI011 positive body. Current corpus 1.2.0 also corrects the AI041 nonempty-string label and adds four cases. Current results on both byte sets are published, including the intentional mismatch against the unchanged original marker-only positive. [The accuracy methodology](RULE_ACCURACY.md) records versions, digests and all remaining mismatches. Passing regression tests does not erase known challenge failures.

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

CI is configured for Python 3.9, 3.12 and 3.14 on Linux, plus Python 3.12 on macOS and Windows. A separate Linux job measures coverage, builds/installs the wheel, invokes it outside the checkout, and validates SARIF. [Implementation validation](VALIDATION.md) records results and the run link.

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

## Empirical checks outside the unit suite

| Experiment | Actual execution and result | Evidence and limits |
|---|---|---|
| Pinned public agent/MCP source | Eight projects, 4,120 exported files, 4,081 Invarune-examined files, 149 static review candidates and 15 explicit coverage gaps; 16 scans produced 32 byte-identical paired artifacts | [Results and source manifests](../benchmarks/real-world/README.md), [initial diagnostic triage](../benchmarks/real-world/TRIAGE.md); no target execution or vulnerability ground truth |
| External source scanners | 24 runs: eight exported scopes each for Semgrep CE, Bandit and Gitleaks, with source identity checked and errors/coverage retained | [Combined report](BENCHMARK_RESULTS.md), [pinned tools and receipts](../benchmarks/external-tools/README.md); different scopes/counts are not a scanner ranking |
| Partial MCP metadata | Cisco MCP Scanner's YARA analyzer scanned 14 literal descriptions extracted from one pinned reference-server implementation | [Metadata receipt](../benchmarks/external-tools/results/cisco-metadata.json); not live `tools/list`, computed inventory, runtime behavior or all MCP servers |
| Shared development fixtures | Ten positive/negative API-pattern fixtures; Invarune, Semgrep and Bandit each matched five positives and five negatives | [Case mappings and receipts](../benchmarks/external-tools/results/shared-pattern-fixtures.json); tiny development-visible check, no artificial true negatives for out-of-scope tools |
| Installed Codex CLI | Synthetic finding triage and grounded control review completed through the production adapter; a subsequent public-CLI fixture scan completed two selected `needs_review` assessments with nine omitted findings explicit, retaining all 11 static findings, zero gaps and exit 1; same-runtime no-judge comparison preserved the scan ID/static fields and identical SARIF bytes | [Provider evidence](CLI_PROVIDER_RESEARCH.md), [actual limited fixture report](../examples/reports/cli-codex/report.md); transport/schema checks, not an all-finding review or a security-judge accuracy benchmark |
| Installed Claude Code CLI | Live request reported missing/expired authentication; later Invarune login launched the official browser flow and timed out after 300 seconds without completed authorization | [Provider evidence](CLI_PROVIDER_RESEARCH.md); unsuccessful authentication is not successful live model coverage |
| Installed Grok Build CLI | Active profile extensions failed preflight before inference | [Provider evidence](CLI_PROVIDER_RESEARCH.md); no successful live Grok review claimed |
| Distribution and export | Version 0.8.0 wheel built/installed outside checkout; all four CI inline validation programs passed; five fixture targets produced identical repeated reports; 18 SARIF reports passed the pinned official schema | [Implementation validation](VALIDATION.md); includes 24 scanner package files, policy-aware source/image checks and unchanged machine identities |

The public corpus and diagnostic fixtures are development-visible. Real scans prompted narrow detector fixes whose initial evidence and implementation hashes remain published. No evaluation in this release establishes a universal best scanner, production precision/recall, behavioral benchmark score or security certification.

## Checks requiring another environment

- Live vendor/enterprise-gateway compatibility with actual credentials, selected models, policies, rate limits and retention settings.
- A real model's security accuracy, calibration, repeatability and response to adaptive prompt injection.
- Production agent/MCP behavior: authorization, tenant boundaries, side effects, egress, approvals, memory isolation and operational controls.
- Referenced behavioral benchmarks such as AgentDojo, ASB, InjecAgent and MCP attack suites, which require configured targets and authorized harnesses.

Eight pinned public repositories were scanned offline, and the installed Codex CLI completed two synthetic review stages plus a bounded two-finding public-CLI fixture review through its existing managed authentication. No target code or public MCP server was executed. Claude authentication did not complete and Grok was blocked before inference. These observations do not establish production security effectiveness or live compatibility across all three providers.

## Brand and command compatibility

`test_brand_compatibility.py` checks pre-brand source/image finding IDs and baselines, stable JSON/SARIF machine identities, additive display metadata, and equivalent primary/legacy help and version behavior. The packaging CI job installs both command names and compares source/image HTML, Markdown, JSON, and SARIF bytes and exit codes from outside the checkout.

## Executive reports and mitigation guidance

`test_report_assessment.py` verifies severity ordering, repeated locations, category counts, open versus accepted findings, source/image coverage gaps, current versus historical image evidence, every rule's sourced guidance, and assessment independence from model verdicts and exit thresholds. `test_report_html.py` checks summary-local review status, all finding/control evidence, valid internal navigation, escaping of malicious source/model/exception text, URL rejection, a CSP allowing only the fixed, hash-authorized local review editor, and lone-surrogate text. Existing CLI and gateway tests verify all four outputs, redaction, policy parity, package data, and repeatability. Suggested defense layers remain unverified and never reduce finding severity.

## Explicit user dispositions

Justified and disabled findings/checks retain their evidence and reason but never count as passes. Tests distinguish rule findings-gate exceptions from control/check review-scope exceptions. The all-exempt case requires zero control calls and produces zero active-check omissions; requested triage or operational failure still returns exit 2. The six new gateway cases verify that a response for compact index 1 is restored to original `AUTH-01:2`, without sending the exempt first check or either private user reason.

Independent review also reproduced and fixed config/report filename collisions and trusted-config source disclosure through case aliases. Filesystem identity checks exclude explicit trusted-file hardlinks as well. Case-sensitive filesystems skip the case-alias-only cases; the portable hardlink and ordinary-path cases still run. These checks assume a stable filesystem during the scan and are not a general defense against a hostile actor modifying the host concurrently.

## Editable report and fresh-scan coverage (v0.9.0)

| Area | Tested behavior | Evidence |
|---|---|---|
| Bound review capsules | Five input formats; strict fields/decisions/dates, source/image/catalog/version/scope changes, stale decisions, absent items, no arbitrary pass or command/config replay | `test_review_workspace.py` |
| Granular decisions | Individual findings and checks, active denominators, kept reasons/reviewer/evidence, runtime/human follow-up exit 2, no automatic note transmission to model | `test_review_roundtrip_cli.py` |
| HTML editor | Actual local editor JavaScript under a Node DOM harness, saved HTML/JSON through the real importer, field validation, escaped data, fixed script hash and no external connections | `test_report_review_editor.py`, `tests/fixtures/review_editor_dom.cjs` |
| PDF forms | Canonical/widget/appearance consistency, attachments, repeatable exports, supported text, invalid/missing fields, bounded parsing, malformed/flattened documents | `test_report_pdf.py` |
| Failure preservation | Oversized capsules and optional PDF dependency/render failures preserve all static findings in four portable reports and return exit 2 | `test_review_roundtrip_cli.py` |

PDF tests use the optional extra; the ordinary Python matrix exercises the dependency-free path and skips PDF-dependent tests explicitly. The package/coverage job installs pinned PDF libraries and exercises those tests. These checks do not establish compatibility with every PDF editor or browser.

## Remediation, comparative findings and quickstart (v0.10.0)

| Boundary | Concrete checks | Evidence |
|---|---|---|
| Per-finding engineering advice | All 42 real detector positives, 126 action/verification pairs, five evidence contexts, per-rule engineering requirements, no finding/state mutation, no model-text control over catalog selection | `test_remediation.py` |
| Optional advice schema and rendering | Bounded exact fields, malformed/oversized content, known-secret redaction, missing legacy advice, synthesized omission counts, additional-concern indices, grounded check status preservation, HTML/MD/PDF text, static SARIF independence | `test_recommended_actions.py` |
| Inspector bypass semantics | Nonempty string values including false/0/no, empty/unset counterexamples, supported Python/JS/config/image paths and inert documentation strings | `test_inspector_auth_values.py`, `AI041_LABEL_CORRECTION.md` |
| Comparison accounting | Exact source spans and family matching, cross-file/project separation, ambiguous edges, exhaustive unmatched accounting, stable IDs, frozen outcome-independent selection | `test_scanner_comparison.py` |
| Blinded review harness | Source manifests/confinement, redaction, exact bounded quotes, unknown/duplicate/missing/invalid answers, explicit uncertainty denominators, dry-run isolation, authentication fail-stop and CLI capability restrictions | `test_benchmark_adjudication.py` |
| Quickstart | Fresh clone/venv/install, both aliases, expected exits, source/image/config scans, PDF edit/import/final exports, six loopback protocols; receipt privacy on Windows and POSIX | `scripts/validate_quickstart.py`, `test_quickstart_validation.py`, `benchmarks/quickstart-v010/` |

The source audit is agent-assisted and development-visible. Neither it nor a model-generated likely-TP label establishes independent vulnerability ground truth. Live account-dependent failures remain failures. All deterministic scans remain usable without an optional judge.
