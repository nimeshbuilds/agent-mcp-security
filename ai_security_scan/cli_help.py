"""Offline CLI reference shipped in the wheel, with live format/adapter inventories."""
import textwrap

from . import DISPLAY_NAME


DESCRIPTION = DISPLAY_NAME + """
Read-only AI agent and MCP source or container-image security scan.
Source/archive scans are offline unless --judge-config is provided. No model,
API key, or third-party Python package is required for deterministic scanning.
Image references use Docker/Podman; only --pull explicitly fetches an image.
Static findings are review signals; a clean scan does not establish security or compliance.
"""


def complete_reference():
    from .scanner import EXCLUDED_DIRS, EXTENSIONS, MANIFESTS
    from .image_scan import IMAGE_EXCLUDED_DIRS
    from .judge import ALIASES, DEFAULT_ENDPOINTS, PROVIDERS

    def inventory(label, values):
        return label + "\n" + textwrap.fill(", ".join(sorted(values)), width=79,
                                            initial_indent="  ", subsequent_indent="  ",
                                            break_long_words=False, break_on_hyphens=False) + "\n"

    return """Invocation and mode selection:
  python3 scan.py [OPTIONS] TARGET
  python3 -m ai_security_scan [OPTIONS] TARGET
  invarune [OPTIONS] TARGET                       (after pip install .)
  ai-security-scan [OPTIONS] TARGET               (compatible legacy alias)
  Replace TARGET with --image REFERENCE or --image-archive PATH for image scans.
  Choose exactly one input. Catalog commands need no target and write no reports.
  -h and --help print this complete reference; --version prints the version.
  Help/version exit 0 without scanning, loading a judge config, or using a runtime
  or network. Full long-option spelling is required; abbreviations are rejected.
  Relative paths use the current working directory. Use an absolute scan.py path
  when running the script elsewhere. Python 3.9+ is required.
  The invarune and ai-security-scan commands are equivalent. The ai_security_scan
  module, distribution agent-mcp-security-scan, report schema and rule/finding IDs
  remain compatible. JSON tool.name and SARIF driver.name retain the stable
  agent-mcp-security-scan identifier; display_name/fullName carry the product brand.

Source analysis and selected scope:
  Python uses bounded AST/local value tracking. JavaScript/TypeScript uses lexical
  tokens, not full program dataflow. JSON/JSONC uses structured checks; YAML and
  other configuration use selected text patterns. Other supported languages/text
  receive generic checks, not complete language-specific vulnerability analysis.
  Dependency manifests, agent/MCP signals, file hashes, and analysis profiles are
  inventoried. No target code, tests, build commands, or dependencies are executed.
  No deployed MCP service, vulnerability feed, or runtime control is probed.
  Supported selected files must be UTF-8 (UTF-8 BOM accepted). Selected-file parse,
  encoding, read, or resource failures remain coverage gaps, never silent passes.
  Symlinks/special files are not followed. The source target must be a real
  directory, not a symlink. Unsupported extensions are outside the selected scope.
""" + inventory("Supported suffixes:", EXTENSIONS) + inventory("Named dependency manifests:", MANIFESTS) + """  Names beginning .env, dockerfile, or requirements are also selected, as are
  Makefile, Jenkinsfile, .npmrc, .pypirc and .netrc (case-insensitive names).
""" + inventory("Default source directory exclusions:", EXCLUDED_DIRS) + inventory("Default image directory exclusions:", IMAGE_EXCLUDED_DIRS) + """
Exclusions, budgets, and reproducibility:
  --exclude is repeatable, case-sensitive fnmatch matching against relative paths
  (also slash-prefixed/trailing-slash forms); quote globs to prevent shell expansion.
  Matching directories prune their descendants. This is not .gitignore syntax;
  the target's .gitignore is not loaded. Default exclusions cannot be re-included.
  Source exclusions are relative to TARGET. Image exclusions are relative to the
  container root, without the report's rootfs/ prefix; they also exclude retained
  file revisions. Image config, build history, OS/package inventory and permission
  review remain independently assessed. Exclusions are visible in coverage.
  Scan/output, baseline, baseline-output, review-config and judge-config paths inside a source
  target are automatically excluded. Keep redirected stdout outside the target.
  Source/image byte, file, entry and layer limits must be positive integers.
  Hitting a limit returns exit 2 with explicit gaps or an acquisition error.
  File-read budgets charge rejected/failed reads and reserve a growth-check byte.
  Identical inputs/settings/runtime/scanner produce reproducible static reports.
  Optional model responses remain nondeterministic, even with temperature zero.

Container images without a source checkout:
  --image saves a local image with the selected trusted Docker/Podman executable.
  Docker needs its daemon; Podman uses its configured image store/connection.
  Runtime connections may be remote. Registry authentication stays with the runtime.
  A missing image never implicitly pulls. --pull requires --image and explicitly
  populates the runtime's image store before export; that store is outside scan
  disk limits. --image-runtime and --image-timeout affect reference acquisition only.
  --image-archive needs no runtime or daemon. Supported targets are Linux images;
  the scanner host may be Linux, macOS or Windows.
  Supported: Docker-save or OCI-layout tar archives, optional outer gzip, and
  plain-tar/gzip layers. Not supported: docker export raw rootfs, OCI directories,
  zstd/xz/bzip2 layers, sparse tar or Windows container filesystem semantics.
  --image-platform accepts OS/ARCH[/VARIANT], e.g. linux/amd64 or linux/arm64/v8.
  Ambiguous archives require a platform selecting one image; otherwise re-export
  one image. Docker platform export needs save --platform support. Podman selects
  during an explicit pull and the resulting archive platform is verified.
  The image is never started. Layers/whiteouts are reconstructed privately with
  traversal, link, collision and digest checks. Archive consistency is verified;
  publisher identity/signatures are not. Unsupported semantics fail or create gaps.
  Packaged dist/build/node_modules/vendor/virtual-environment files are inspected.
  Checks include packaged source/config, configured user/environment/labels/commands,
  build-history signals and deleted/overwritten credentials. Historical code defects
  are not presented as live application defects. Findings carry path/layer context.
  OS release, dpkg/apk/Python/npm package versions and stored permissions are inventory
  and review signals. Package inventory is not a CVE assessment.
  Report scopes: packaged_source_and_metadata, metadata_and_text_only, metadata_only.
  Binary-only images can complete metadata checks; binary logic stays unassessed.
  No decompilation, malware engine, registry signature check or runtime validation.
  Archive/layer expansion, final filesystem scan, and metadata/retained-layer reads
  have separate budgets/counters. The image metadata phase reuses --max-file-bytes
  and --max-total-bytes with a separate budget and a 10000-record ceiling.
  --image-max-unpacked-bytes bounds cumulative expanded layer data and separately
  final materialized bytes. --image-max-entries also counts implicit directories.
  Archive/revision/rootfs content can require max(2*archive, archive+2*unpacked),
  about 10 GB at defaults, plus generated evidence, reports and filesystem overhead.
  Private evidence is removed after scanning and optional review.
  --image-timeout is the shared pull/export deadline, not an archive/source-analysis
  wall-clock timeout; those phases use resource bounds.

Reports, output modes, and Exit codes:
  Every scan that produces reports writes report.html, report.json, report.md and
  report.sarif to --output. Open report.html locally for the branded report; it is
  self-contained, works offline, and needs no external scripts, fonts or images.
  HTML and Markdown begin with an executive summary: detected findings, immediate
  concerns, affected locations, accepted baseline risks, and coverage limitations.
  Findings are grouped by rule, status and image context. Priorities P0/P1/P2/P3
  mean critical/high/medium/low-or-info review order, not an SLA or security score.
  Each group includes a suggested owner, direct remediation, and additional defense
  layers with expected benefit, verification steps, residual limits and sources.
  These layers are proposals, not observed controls or proven risk reductions.
  Suppression is a reviewed exception, not proof of remediation. Zero findings do
  not establish security; incomplete coverage and manual/runtime checks stay visible.
  JSON includes the same deterministic assessment for automation. Model opinions
  cannot lower its priority, suppress findings, or establish mitigation effectiveness.
  HTML/JSON/Markdown include all controls, evidence, remediation, primary sources,
  suppressions, gaps, inventories and optional advisory review. SARIF 2.1.0 carries
  deterministic findings for CI/code-review consumers; checklist detail stays in
  HTML/JSON/Markdown. Existing report filenames are replaced; files are written atomically.
  --output must differ from a source target root. Parent directories are created.
  Default output is human-readable. --quiet suppresses summaries/progress while
  preserving stderr errors. --summary-json emits one JSON object on stdout, with
  diagnostics on stderr. --quiet and --summary-json cannot be combined.
  Summary fields include status, tool, scan_id, summary, assessment, scope, coverage,
  optional_review, execution, exit_code and reports; image scans also include image.
  With --review-config, review_policy records every user disposition and active,
  justified, disabled and catalog counts. Coverage total_controls/total_checks use
  active denominators; catalog_controls/catalog_checks retain the full inventory.
  Operational errors emit status=operational_error with --summary-json when possible.
  Argument syntax/combination errors use stderr and exit 2, without a JSON document.
  A completed summary may still contain findings and exit 1.

Exit codes:
  0  Selected scan scope completed below the configured open-finding threshold.
  1  Open deterministic findings meet --fail-on (default high).
  2  Invalid input, operational failure, incomplete scan, or incomplete requested
     analyst review/judge error. Incompleteness takes precedence over findings.
  Severity order: critical > high > medium > low > info.
  --fail-on none disables only the severity gate; errors/gaps still exit 2.
  Zero findings, no_pattern_detected, findings_suppressed or exit 0 do not establish
  security, exploitability, compliance or complete application/control coverage.

Reviewed baselines:
  --write-baseline PATH requires a nonempty --baseline-reason TEXT and writes all
  current findings as a candidate; it does not suppress the current scan. Review
  the candidate, retain only accepted exceptions, then use --baseline PATH.
  Accepted IDs remain in reports as suppressed; unmatched IDs are reported. IDs
  depend on rule, location and content evidence; changed evidence can need review.
  Baseline JSON shape:
    {"schema_version":"1.0","findings":[{"id":"FINDING_ID","reason":"Reviewed exception"}]}
  Each entry needs a unique ID and nonempty reason. An exception is a review
  decision, not proof of safety. The model cannot create accepted exceptions.

User review dispositions:
  --review-config PATH loads an explicitly selected, trusted UTF-8 JSON file.
  No policy is auto-discovered in the target or its parent directories. The same
  policy works for source directories, image references and image archives.
  Review config JSON shape:
    {"schema_version":"1.0",
     "rules":{"AI003":{"status":"justified","reason":"Reviewed deployment-specific exception; track evidence with the owner."}},
     "controls":{"GOV-01":{"status":"disabled","reason":"Outside this selected review scope."}},
     "checks":{"AUTH-01:2":{"status":"justified","reason":"Owner-reviewed evidence is recorded in the external assessment."}}}
  rules, controls and checks are optional maps keyed by exact catalog IDs.
  Check IDs are CONTROL:INDEX with a one-based index; --list-controls prints them.
  The only statuses are justified and disabled. justified requires a nonblank
  reason; disabled permits an optional reason (a default reason is recorded).
  Each reason is limited to 8000 characters and the file to 1,000,000 bytes. Unknown fields,
  unknown IDs, duplicate JSON keys, invalid types/Unicode, and overlapping whole
  control plus child-check entries fail with exit 2 before scanning/model calls.
  Rule dispositions apply to every matching finding, including image metadata,
  and take precedence over baseline suppression. Evidence, original status and
  baseline reason remain in the audit. Shared analysis still runs; disabled means
  excluded from assessment and gating, not skipped file parsing or evidence erasure.
  Control/check dispositions exclude only the named checklist review items; they
  cannot waive mapped rule findings. Configure rules explicitly for that purpose.
  justified and disabled never mean pass: neither contributes to active finding
  counts, severity gates, checklist denominators or optional analyst omissions.
  The scanner has no numerical security score. Catalog totals and excluded-item
  counts remain visible separately. Remaining active checks still need validation.
  The analyst receives only active checklist items and cannot create dispositions.
  Rule disposition alone does not exempt a mapped control from analyst review.
  Reasons are redacted best-effort in reports; the canonical policy hash affects
  scan_id. Keep sensitive values out of reasons. Protect this trusted policy in CI.
  Configured exceptions never waive parse/read/budget gaps, invalid input or an
  optional model failure. All still exit 2. Use --baseline for individual finding
  ID exceptions; its existing status remains suppressed. Exit 0 is not a pass.

Catalog inspection:
  --list-rules prints the rule array with severity, remediation, CWE and sources.
  --list-controls prints all controls, acceptance checks, check IDs, rule mappings and sources.
  --explain-rule ID prints one rule, mapped controls and interpretation limits.
  These three commands are mutually exclusive and reject target/image inputs,
  --quiet and --summary-json. Unknown rule IDs are errors. No reports are written.

Optional security analyst and data disclosure:
  No LLM call occurs without --judge-config PATH. Use a trusted UTF-8 JSON file
  outside untrusted target repositories; it controls the recipient and requested
  environment variables. Config files are limited to 256 KiB and 64 nesting levels.
  --judge-mode full (default) triages findings, then reviews every active catalog check,
  including those without findings. It sends bounded redacted source excerpts even
  when --judge-include-source is absent. --judge-mode findings sends finding triage
  only; --judge-include-source adds neighboring source to that stage.
  Triage context is capped at 3000 characters per finding and 30000 total;
  full analyst evidence is selected separately under its own budgets.
  Triage makes one request and selects up to --judge-max-findings in deterministic
  report order. Omitted findings/answers stay visible; static findings remain intact.
  Full control calls have separate --analyst-* budgets, plus the one triage call.
  Smaller batches may require more calls: allow ceil(control_count / batch_size).
  --analyst-max-calls 0 leaves active controls unreviewed and returns exit 2 in full
  mode when active checks remain. Fully exempt controls need no analyst calls.
  Zero evidence-file/byte/character budgets send no control-review source excerpts;
  --judge-include-source can still send triage context independently. Missing source
  remains an evidence limitation, not a security pass. Analyst flags affect full mode.
  Evidence comes only from the scanned, hash-verified manifest, with bounded reads,
  sensitive-file exclusions and redaction. Image excerpts retain original layer/path
  context; renaming historical files cannot bypass sensitive-path exclusions.
  Redaction is best-effort: code and unusual secrets may still be sent. Use an
  endpoint approved for that data. Treat target instructions as untrusted data.
  Output schemas, IDs, exact evidence quotes and budgets are checked deterministically.
  The model's conclusions are advisory and nondeterministic. The scanner dispatches
  no model tools/actions; custom gateways must disable their own server-side tools.
  No target files change and no deterministic finding/severity/gate is overridden.
  Code support cannot establish runtime or manual control effectiveness.
  Requested review errors preserve deterministic reports. A failed control batch
  stops further batches; unanswered controls/checks remain explicit and exit 2.

Judge protocols and endpoint configuration (JSON fields, not CLI flags):
""" + inventory("  Supported provider values:", PROVIDERS) + """  Provider aliases:
""" + "\n".join("    " + alias + " -> " + target for alias, target in sorted(ALIASES.items())) + """
  Default endpoints (each accepts an exact endpoint override):
""" + "\n".join("    " + provider + ": " + endpoint for provider, endpoint in sorted(DEFAULT_ENDPOINTS.items())) + """
    custom: no default; supply endpoint explicitly.
  Native adapters cover both triage and control review. Other synchronous JSON
  HTTP POST APIs can use custom. There is no automatic OAuth refresh, AWS SigV4,
  mTLS, WebSocket, SSE-only stream, multipart/binary API or async polling adapter;
  use an appropriate gateway for those protocols.

  provider           Default openai_chat; choose a supported protocol above.
  model              Required nonempty model/deployment ID, at most 256 characters.
  endpoint           Exact request URL, including path and nonsecret query/version.
                     No path is appended. ${MODEL} is URL-encoded before insertion.
  api_key_env        Environment variable NAME for an existing key/token. No key
                     is inferred from standard provider environment variables.
  api_key_header     Default Authorization; x-api-key for anthropic and
                     x-goog-api-key for gemini. May be changed for a gateway.
  api_key_prefix     Default 'Bearer ' for Authorization, otherwise empty string.
  headers            String map supporting ${ENV:NAME}; credential headers must
                     use environment placeholders, not literal credentials.
  extra_body         Additional provider fields; null removes a default field.
                     Cannot replace model/prompt/tools/storage/streaming fields.
                     Generation options vary by model; none guarantees determinism.
  request_template   Required custom-provider JSON object containing ${PROMPT}.
                     String values support ${PROMPT}, ${MODEL}, ${ENV:NAME}.
                     Keys are not templates. Expansion is single-pass, never code.
  response_path      Required for custom: dotted keys/zero-based array indexes,
                     e.g. result.outputs.0.text; empty string selects the whole body.
                     Select model JSON text or an assessment object. Keys containing
                     periods need normalization in a gateway; this is not JSONPath.
  timeout_seconds    Default 60; 0.1..300 seconds per HTTP request. DNS resolution
                     is not covered by a guaranteed hard wall-clock deadline.
  max_request_bytes  Default 524288; integer 1024..5242880. Oversized input fails.
  max_response_bytes Default 1048576; integer 1024..5242880, including HTTP JSON.
  max_output_tokens  Default 4096; integer 128..32768 for native generation limits.
                     Custom templates must set their provider's token-limit field.
  allow_insecure_http Default false. Loopback HTTP is allowed; remote HTTP requires
                     explicit true. Remote endpoints should use HTTPS.
  ca_file            Optional PEM CA bundle; certificate/hostname checks stay on.
  anthropic_version  Default 2023-06-01 for the Anthropic protocol header.
  Unknown config fields are rejected. No automatic retries, redirects, proxy-env
  routing, or credential acquisition. Responses requests set store=false; this is
  not an assurance about a provider's retention policy. Native Chat uses
  max_completion_tokens; older gateways may use extra_body to remove it with null
  and set max_tokens. Authentication values belong in environment/secret management.

OpenAI-compatible gateway configuration:
  {"provider":"openai_chat","model":"YOUR_MODEL_ID",
   "endpoint":"https://gateway.example.com/v1/chat/completions",
   "api_key_env":"AI_JUDGE_API_KEY","timeout_seconds":60,
   "max_output_tokens":4096}

Custom JSON gateway configuration:
  {"provider":"custom","model":"YOUR_MODEL_ID",
   "endpoint":"https://gateway.example.com/review",
   "headers":{"Authorization":"Bearer ${ENV:AI_JUDGE_API_KEY}"},
   "request_template":{"model":"${MODEL}","input":"${PROMPT}","max_tokens":4096},
   "response_path":"result.outputs.0.text"}

Examples:
  # Explicit reviewed exceptions; all evidence and user reasons remain auditable.
  invarune ./repository --review-config ./trusted-review.json --output ./reports
  invarune --image-archive ./agent-image.tar --review-config ./trusted-review.json
  # Offline source scan; output includes every control and explicit gaps.
  invarune ./repository --output ./reports
  # Docker local image; no source checkout, pull, or container start.
  invarune --image my-agent:latest --output ./image-report
  # Podman local image, or explicitly pull a registry image and select a platform.
  invarune --image my-mcp-server:latest --image-runtime podman
  invarune --image ghcr.io/example/agent:1.2.3 --pull --image-platform linux/amd64
  # Export elsewhere, then scan an archive offline without Docker/Podman.
  docker image save --output agent-image.tar my-agent:latest
  invarune --image-archive ./agent-image.tar --output ./image-report
  invarune --image-archive ./agent.oci.tar --image-platform linux/arm64
  # Increase image and packaged-file budgets for larger artifacts.
  invarune --image-archive ./agent-image.tar --image-max-unpacked-bytes 8000000000 --max-total-bytes 200000000
  # Repeated exclusions, CI severity gating, and machine-readable stdout.
  invarune ./repository --exclude 'generated/*' --exclude 'fixtures/*'
  invarune ./repository --summary-json --fail-on medium --output ./reports
  invarune ./repository --quiet --fail-on none
  invarune ./repository --max-file-bytes 2000000 --max-total-bytes 100000000
  # Create a candidate; review/edit it before accepting a baseline.
  invarune ./repository --write-baseline ./candidate.json --baseline-reason 'Owner review required'
  invarune ./repository --baseline ./reviewed.json --summary-json
  # Offline catalogs and exact rule explanations, including source references.
  invarune --list-rules
  invarune --list-controls
  invarune --explain-rule AI002
  # Optional full analyst; trusted-judge.json follows the JSON examples above.
  invarune ./repository --judge-config ./trusted-judge.json
  invarune --image-archive ./agent-image.tar --judge-config ./trusted-judge.json
  # Finding-only triage with explicitly requested neighboring source.
  invarune ./repository --judge-config ./trusted-judge.json --judge-mode findings --judge-include-source
  # Smaller full-review batches with larger call/time budgets.
  invarune ./repository --judge-config ./trusted-judge.json --analyst-batch-size 3 --analyst-max-calls 24 --analyst-time-budget 600

Detailed guides and controlbook (also in the repository):
  https://github.com/nimeshbuilds/agent-mcp-security/blob/main/docs/CLI.md
  docs/IMAGE_SCANNING.md   Formats, extraction safety, budgets and image scopes.
  docs/JUDGE.md           API configuration and expected finding response schema.
  docs/ANALYST.md         Control response schema, citations and evidence routing.
  docs/SECURITY_CHECKLIST.md and docs/RESEARCH.md   Controls and primary sources.
  docs/RULE_ACCURACY.md and docs/VALIDATION.md     Tests, measured limits and gaps.
  output/pdf/invarune-security-controlbook.pdf   Branded controlbook.
"""
