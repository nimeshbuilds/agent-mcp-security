"""Offline CLI reference shipped in the wheel, with live format/adapter inventories."""
import textwrap

from . import DISPLAY_NAME


DESCRIPTION = DISPLAY_NAME + """
Read-only AI agent and MCP source or container-image security scan.
Offline security explorer: ask about the bundled controls, checks and sources.
Source/archive scans are offline unless --judge-config or --judge-cli is provided. No model,
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
  invscan [OPTIONS] TARGET                        (primary installed CLI)
  invarune [OPTIONS] TARGET                       (compatible alias)
  ai-security-scan [OPTIONS] TARGET               (compatible legacy alias)
  python3 -m ai_security_scan [OPTIONS] TARGET     (compatible module invocation)
  python3 scan.py [OPTIONS] TARGET                (checkout-only fallback)
  Install from the checkout: python -m pip install .
  Optional AI optimizer and PDF support: python -m pip install '.[ai,pdf]'
  Quick navigation: invscan --examples; invscan --help-topic images
  Topic names: all, quickstart, source, images, reports, review, baseline, ai,
  login, gateways, limits, exit-codes, catalog, security. --help includes every topic.
  Replace TARGET with --image REFERENCE or --image-archive PATH for image scans.
  Choose exactly one input. Catalog commands and --login need no target and write no reports.
  -h and --help print this complete reference; --version prints the version.
  Help/version exit 0 without scanning, loading a judge config, or using a runtime
  or network. Full long-option spelling is required; abbreviations are rejected.
  Relative paths use the current working directory. Use an absolute scan.py path
  when running the script elsewhere. Python 3.9+ is required.
  The invscan, invarune and ai-security-scan commands are equivalent. The ai_security_scan
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
  Scan/output, baseline, baseline-output, review-config, review-report and judge-config paths inside a source
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
  One fixed CSP-hashed local script saves HTML review edits; source/model text is
  never executed. Use Download reviewed HTML, not browser Save As, to save edits.
  --pdf additionally writes a fillable report.pdf with charts, clickable contents
  and the same review fields. Install optional dependencies with pip install '.[pdf]'.
  Default HTML/JSON/Markdown/SARIF output needs no additional Python packages.
  Missing/failed PDF support returns exit 2 while preserving the four other reports.
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
     analyst review/judge error, stale/pending imported review, or PDF export error.
     Incompleteness takes precedence over findings.
  Severity order: critical > high > medium > low > info.
  --fail-on none disables only the severity gate; errors/gaps still exit 2.
  Zero findings, no_pattern_detected, findings_suppressed or exit 0 do not establish
  security, exploitability, compliance or complete application/control coverage.

Editable report review and fresh scans:
  --review-report PATH accepts current-format HTML, Markdown, JSON, SARIF or a
  fillable scan PDF. A fresh explicit TARGET, --image or --image-archive is required.
  This option is mutually exclusive with --review-config. It never executes report
  commands, follows evidence URLs, restores credentials or enables model review.
  Add --judge-cli/--judge-config separately if a new advisory review is desired.
  Reports carry a versioned review_workspace capsule with stable finding/check/gap
  identifiers, immutable bindings, origin/settings hashes and editable user fields.
  HTML: edit the form and use Download reviewed HTML. PDF: save the form fields in
  a compatible PDF editor; do not flatten or print to PDF. JSON: edit review_workspace.
  SARIF: edit runs[0].properties.invarune_review. Markdown: edit the fenced JSON
  between INVARUNE_REVIEW_BEGIN and INVARUNE_REVIEW_END markers.
  Editable fields: decision, reason, reviewer, reviewed_at, evidence_ref. Decisions:
  empty, justified, disabled, note, needs_runtime_validation, needs_human_review.
  All nonempty decisions require a reason; justified/disabled require a reviewer.
  Limits: reason 8000 chars, reviewer 200, reviewed_at 64, evidence_ref 2000.
  reviewed_at is optional ISO date/timestamp metadata; it does not enforce expiry.
  A blank decision must have blank accompanying fields; use note to save comments.
  Input reports are bounded to 50000000 bytes; review capsules to 4000000 bytes
  and 10000 items. Imports reject ambiguous/duplicate metadata and unknown schemas.
  PDF export/import additionally supports at most 2000 review items and portable
  Western-text AcroForms. Use JSON/Markdown/HTML/SARIF for other Unicode review text
  or unsupported PDF-editor appearances. PDF fields must remain editable and intact.
  Only matching fresh source/configuration/scanner bindings carry a decision forward.
  A finding exception applies to that finding, not every match of its rule.
  Justified/disabled states retain evidence and earn no pass/fail credit in active
  counts. Checks do not waive mapped findings; scan gaps cannot be exempted.
  Changed/out-of-scope decisions remain unapplied in the audit. Explicit pending
  runtime/human validation and stale imports make the requested review incomplete
  and return 2, even with --fail-on none. Not redetected never means proven fixed.
  Keep original and reviewed reports outside the source target; use a new --output
  directory. The importer prevents overwriting its input, including through aliases.
  Digests bind review context; they are not signatures or proof of reviewer identity.
  Only import files whose user decisions you authorize. Unedited or older reports
  without a review capsule do not supply accepted exceptions; regenerate old reports.

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
  Explore the bundled security catalog without a scan, target, provider config,
  login or model. No target files are read, source URLs fetched or reports written.
  --list-topics groups the control inventory by security subject and static mapping.
  --ask QUERY matches literal query tokens and aliases against the local catalog.
    Quote a multiword query, e.g. --ask 'What do you check for prompt injection?'.
    Queries accept at most 1000 characters and return at most 8 ranked matches.
    Ranking is lexical relevance, not confidence, risk or detection accuracy.
    This is deterministic lookup, not generative chat or analysis of your system.
    Unsupported/no-match questions remain explicit; try --list-topics or exact IDs.
  --explain-control ID explains why a control matters, all acceptance checks,
    mapped deterministic rules, source organizations and required other evidence.
  --explain-check ID explains one CONTROL:INDEX check; indexes start at 1.
  --list-sources prints the bundled source registry, organizations and limitations.
  --explain-source ID shows provenance and linked controls, keeping primary control
    citations distinct from suggested thematic alignment. Neither proves compliance.
  --list-rules prints the legacy rule array with severity, remediation, CWE and sources.
  --list-controls prints the legacy controls, check IDs, rule mappings and sources.
  --explain-rule ID prints the legacy rule, mapped controls and interpretation limits.
  --catalog-format text|json selects catalog output; it requires a catalog command.
    New commands default to readable text. Existing --list-rules, --list-controls
    and --explain-rule keep their existing default JSON. Choose text for their
    readable explanations; choose json with a new command for structured output.
  Choose one catalog command. Catalog modes reject explicit target/image, scan,
  model/login and output options, including --quiet and --summary-json. Unknown
  IDs in explain commands are errors; --list-controls and --list-sources expose IDs.
  A completed lookup, including no match, exits 0. Invalid queries, unknown explain
  IDs and incompatible options exit 2. No catalog command produces a scan verdict.
  The 42 rules map partially to 26 of 66 controls; all 132 acceptance checks remain
  broader than static detection. No match or mapped rule establishes a control pass.
  Source dates/versions/access limits are recorded snapshots, not live verification.

Optional security analyst and data disclosure:
  No LLM call occurs without --judge-config PATH or --judge-cli PROVIDER.
  For file configuration use a trusted UTF-8 JSON file
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
  Prompt token optimization defaults to headroom for enabled model review only.
  Install the ai extra for Headroom 0.37.0 on Python 3.10+: pip install '.[ai]'.
  The guarded profile performs lossless JSON compaction, preserving all evidence;
  it does not summarize, remove source, start retrieval tools or run another model.
  Missing/unsupported/failed Headroom falls back to built-in compact encoding with
  a visible receipt. Python 3.9 uses that fallback. compact explicitly selects the
  built-in encoder; off preserves spaced JSON. Savings vary by payload/tokenizer;
  this is not a guaranteed token, cost or accuracy improvement.
  --token-optimizer headroom|compact|off overrides the selected config for this run.
  It requires --judge-cli or --judge-config. Deterministic scans never need it.

Official CLI login integrations:
  --judge-cli codex|claude|grok runs an installed official vendor CLI with its own
  login. No separate API key is required by Invarune for this route.
  Subscription eligibility, usage limits and model access are vendor/account
  dependent. API keys are not inherited by the child environment. The scanner
  never reads or copies auth tokens; the official CLI owns its credential store.
  Interactive scans use --judge-login auto (default): missing login opens the
  official browser/device flow and the scan resumes after successful sign-in.
  Expired credentials in either review stage can trigger one login per scan,
  then retry the interrupted request. Control retries consume --analyst-max-calls;
  completed batches remain intact. Login time uses its separate deadline and is
  excluded from the control analyst scheduling clock. Finding triage can retry
  once beyond its normal single request; no automatic model-error retry loop runs.
  --judge-login never requires existing authentication. Quiet, JSON-summary and
  noninteractive scans never open a browser or wait for sign-in; errors preserve
  static reports and exit 2. Use --login codex|claude|grok to sign in directly
  from Invarune without scanning. It requires an interactive terminal, rejects
  target/image/judge selection and quiet/JSON output, and writes no scan reports.
  --login-timeout is separate from inference budgets: default 300, range 1..900
  seconds. Cancellation, timeout or failure returns exit 2. Vendor login output
  stays on the terminal, never in a report. Login process cleanup is direct-child
  only; it does not close the user's browser. Account/browser approval stays with
  the user. Invarune does not purchase credits or bypass vendor account policies.
  Minimum tested versions: Codex 0.154.0, Claude Code 2.1.214, Grok Build 0.2.60.
  Version/help capability probes run before any advisory request. Older or
  incompatible CLIs fail explicitly; help and deterministic scans never probe.
  Invarune selects gpt-6-astra for Codex, opus for Claude, and grok-build for Grok.
  These are documented quality-focused review defaults, not a measured universal
  model ranking. Codex and Claude use high reasoning effort. Vendor aliases can
  resolve differently by installed version/account. Model access and limits still
  apply; there is no silent fallback to a different provider or billing route.
  --judge-model overrides this selection; default explicitly requests the vendor
  CLI's configured model instead. The selected model is recorded in the report.
  --judge-executable selects a trusted absolute executable path or bare PATH name
  for a CLI scan or standalone login.
  Relative executable paths, shell command files and arbitrary extra arguments
  are rejected. The installed executable and host administrator policy are trusted.
  --judge-timeout bounds one invocation, including preflight (default 60 seconds,
  range 0.1..300). stdout/stderr and request sizes are bounded. Child processes
  run in a private temporary directory; prompts use stdin or a private file.
  Target repositories are never the CLI working directory. Tools, MCP, user
  customizations and persistence are restricted using vendor-specific controls.
  These controls are not an OS sandbox or a guarantee about provider retention.
  POSIX cleanup kills the child process group; Windows kills the direct process
  only. Use an external job/container boundary for descendant isolation on Windows.
  Grok profiles with active extensions/instructions are rejected before inference.
  --judge-cli-home is Grok-only and selects an existing absolute clean GROK_HOME
  profile for scan or --login. Keep this profile outside scan targets.
  No auth files are copied; the scanner does not change your existing profile.
  CLI invocations have no uniform token/cost cap. max_output_tokens is rejected
  for CLI providers. Time/byte limits cannot undo usage already consumed remotely.
  Reports retain CLI version, capability flags, request/response hashes and sizes,
  auth_mode=cli_managed, and lifecycle/isolation limits. They never claim a plan.
  All finding/control validation, user dispositions, source budgets, advisory-only
  boundaries and error exit codes above apply to CLI providers as to HTTP providers.

  CLI configuration fields (use --judge-config instead of --judge-cli):
    provider           codex_cli, claude_cli or grok_cli (required).
    model              Optional; omission selects Invarune's provider default.
                       Explicit default uses the vendor CLI's configured model.
    executable         Optional; defaults to codex, claude or grok respectively.
    timeout_seconds    Default 60, range 0.1..300, including capability probes.
    max_request_bytes  Default 524288, integer 1024..5242880, full UTF-8 prompt.
    max_response_bytes Default 1048576, integer 1024..5242880, CLI output envelope.
    cli_home           Optional existing absolute Grok profile directory only.
    token_optimizer    headroom (default), compact or off; same guarded behavior
                       as --token-optimizer. The explicit CLI flag takes precedence.
  Unknown fields, API/gateway fields and token limits are rejected for CLI configs.
  --judge-model/--judge-timeout require --judge-cli. --judge-executable and the
  Grok-only --judge-cli-home also work with --login. Put corresponding fields
  inside JSON when using --judge-config. Login policy/time limits remain CLI flags.
  Minimal CLI configuration:
    {"provider":"codex_cli","timeout_seconds":120}

Judge protocols and HTTP endpoint configuration (JSON fields, not CLI flags):
""" + inventory("  Supported provider values:", PROVIDERS) + """  Provider aliases:
""" + "\n".join("    " + alias + " -> " + target for alias, target in sorted(ALIASES.items())) + """
  Default endpoints (each accepts an exact endpoint override):
""" + "\n".join("    " + provider + ": " + endpoint for provider, endpoint in sorted(DEFAULT_ENDPOINTS.items())) + """
    custom: no default; supply endpoint explicitly.
  The following HTTP fields apply only to the six HTTP providers, not *_cli.
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
  token_optimizer    headroom (default), compact or off; lossless prompt encoding.
                     --token-optimizer overrides this field for the selected run.
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

""" + examples_reference() + """

Detailed guides and controlbook (also in the repository):
  https://github.com/nimeshbuilds/invarune/blob/main/docs/CLI.md
  Repository-relative paths below refer to the checkout, not installed files.
  https://github.com/nimeshbuilds/invarune/blob/main/docs/QUICKSTART.md
  docs/IMAGE_SCANNING.md   Formats, extraction safety, budgets and image scopes.
  docs/JUDGE.md           API configuration and expected finding response schema.
  docs/ANALYST.md         Control response schema, citations and evidence routing.
  docs/SECURITY_EXPLORER.md  Offline questions, control/check/source explanations.
  docs/SECURITY_CHECKLIST.md and docs/RESEARCH.md   Controls and primary sources.
  docs/RULE_ACCURACY.md and docs/VALIDATION.md     Tests, measured limits and gaps.
  output/pdf/invarune-security-controlbook.pdf   Branded controlbook.
"""


# Each focused view is assembled from the same complete reference and cookbook.
# Section boundaries deliberately exclude nested inventory/config subheadings.
_TOPIC_SECTIONS = {
    "quickstart": ("Invocation and mode selection:", "Reports, output modes, and Exit codes:"),
    "source": ("Source analysis and selected scope:", "Exclusions, budgets, and reproducibility:"),
    "images": ("Container images without a source checkout:", "Exclusions, budgets, and reproducibility:"),
    "reports": ("Reports, output modes, and Exit codes:", "Exit codes:"),
    "review": ("Editable report review and fresh scans:", "User review dispositions:"),
    "baseline": ("Reviewed baselines:",),
    "ai": ("Optional security analyst and data disclosure:",),
    "login": ("Official CLI login integrations:",),
    "gateways": ("Judge protocols and HTTP endpoint configuration (JSON fields, not CLI flags):",
                 "OpenAI-compatible gateway configuration:", "Custom JSON gateway configuration:"),
    "limits": ("Exclusions, budgets, and reproducibility:", "Container images without a source checkout:",
               "Optional security analyst and data disclosure:"),
    "exit-codes": ("Exit codes:",),
    "catalog": ("Catalog inspection:",),
    "security": ("Catalog inspection:",),
}
HELP_TOPICS = ("all", *_TOPIC_SECTIONS)

_EXAMPLE_GROUPS = (
    (("quickstart", "source"), "Start with deterministic scanning; no model or API key is needed.", (
        "invscan --help", "invscan --help-topic images", "invscan --examples", "invscan --version",
        "invscan ./repository --output ./reports",
        "invscan ./repository --exclude 'generated/*' --exclude 'fixtures/*'")),
    (("images",), "Scan a built Linux image without starting it or requiring source checkout.", (
        "invscan --image my-agent:latest --output ./image-report",
        "invscan --image my-mcp-server:latest --image-runtime podman --image-timeout 600",
        "invscan --image ghcr.io/example/agent:1.2.3 --pull --image-platform linux/amd64",
        "docker image save --output agent-image.tar my-agent:latest",
        "invscan --image-archive ./agent-image.tar --output ./image-report",
        "invscan --image-archive ./agent.oci.tar --image-platform linux/arm64")),
    (("reports", "exit-codes"), "CI output and severity gates; none never hides scan/review failures.", (
        "invscan ./repository --summary-json --fail-on medium --output ./reports",
        "invscan ./repository --quiet --fail-on none")),
    (("limits", "source"), "Increase selected-source limits; exhausted budgets remain coverage gaps.", (
        "invscan ./repository --max-file-bytes 2000000 --max-total-bytes 100000000 --max-files 40000 --max-entries 200000",)),
    (("limits", "images"), "Image limits are separate from packaged-file and optional analyst budgets.", (
        "invscan --image-archive ./agent-image.tar --image-max-archive-bytes 4000000000 --image-max-unpacked-bytes 8000000000 --image-max-entries 1000000 --image-max-layers 300 --max-total-bytes 200000000",)),
    (("review", "reports"), "Fillable fifth report and explicit reviewed-report round trips (PDF extra required).", (
        "invscan ./repository --pdf --output ./initial-report",
        "invscan ./repository --review-report ./reviewed-report.html --pdf --output ./final-report",
        "invscan --image-archive ./agent-image.tar --review-report ./reviewed-report.pdf --output ./final-image-report",
        "invscan ./repository --review-report ./reviewed-report.json --output ./final-json-review",
        "invscan ./repository --review-report ./reviewed-report.md --output ./final-markdown-review",
        "invscan ./repository --review-report ./reviewed-report.sarif --output ./final-sarif-review")),
    (("review",), "Explicit trusted exceptions: justified and disabled never mean validated pass.", (
        "invscan ./repository --review-config ./trusted-review.json --output ./reports",
        "invscan --image-archive ./agent-image.tar --review-config ./trusted-review.json")),
    (("baseline",), "Create a candidate; review/edit it before accepting individual finding exceptions.", (
        "invscan ./repository --write-baseline ./candidate.json --baseline-reason 'Owner review required'",
        "invscan ./repository --baseline ./reviewed.json --summary-json")),
    (("catalog", "security"), "Offline security questions and exact control/check/source explanations; no scan or model.", (
        "invscan --help-topic security", "invscan --list-topics",
        "invscan --ask 'What do you check for prompt injection?'",
        "invscan --ask 'MCP authentication' --catalog-format json",
        "invscan --ask 'What NSA and CISA guidance do you use?'",
        "invscan --explain-control AUTH-01", "invscan --explain-check AUTH-01:1",
        "invscan --list-sources", "invscan --explain-source JOINT-AGENTIC",
        "invscan --list-rules", "invscan --list-controls", "invscan --explain-rule AI002",
        "invscan --explain-rule AI002 --catalog-format text")),
    (("ai", "login"), "Optional full security analyst through an installed, supported official vendor CLI.", (
        "invscan ./repository --judge-cli codex --judge-timeout 120 --analyst-time-budget 600",
        "invscan ./repository --judge-cli claude --judge-model opus --judge-login never --summary-json",
        "invscan ./repository --judge-cli grok --judge-cli-home /absolute/path/to/clean-grok-profile",
        "invscan --login claude --login-timeout 600",
        "invscan --login codex --judge-executable /absolute/path/to/codex")),
    (("ai", "gateways"), "API/native/custom gateway: trusted-judge.json follows the configuration examples.", (
        "invscan ./repository --judge-config ./trusted-judge.json --analyst-time-budget 600",
        "invscan --image-archive ./agent-image.tar --judge-config ./trusted-judge.json",
        "invscan ./repository --judge-config ./trusted-judge.json --token-optimizer off")),
    (("ai", "limits"), "Finding-only triage and independent full-review evidence/call budgets.", (
        "invscan ./repository --judge-cli claude --judge-mode findings --judge-include-source --judge-max-findings 200",
        "invscan ./repository --judge-config ./trusted-judge.json --analyst-batch-size 3 --analyst-max-calls 24 --analyst-time-budget 600",
        "invscan ./repository --judge-config ./trusted-judge.json --analyst-max-files 400 --analyst-max-bytes 4000000 --analyst-max-chars 240000",
        "invscan ./repository --judge-cli codex --token-optimizer compact")),
)


def examples_reference(topic=None):
    lines = ["Examples:", "  Replace ./repository, image names, endpoints and reviewed files with your inputs.",
             "  Paths are relative to your working directory. Quote paths containing spaces."]
    if topic in ("catalog", "security"):
        lines.append("  Catalog examples need no target, optional packages, model, login or network.")
    else:
        lines.extend(("  Install optional support from the checkout: python -m pip install '.[ai,pdf]'.",
                      "  AI examples explicitly opt in to evidence disclosure and provider usage."))
    for topics, description, commands in _EXAMPLE_GROUPS:
        if topic is None or topic in topics:
            lines.append("  # " + description)
            lines.extend("  " + command for command in commands)
    lines.append("  See invscan --help for all options, exact JSON schemas, defaults and limitations.")
    return "\n".join(lines) + "\n"


def topic_reference(topic):
    if topic not in _TOPIC_SECTIONS:
        raise ValueError("Unknown help topic: " + str(topic))
    reference = complete_reference()
    headings = {heading for values in _TOPIC_SECTIONS.values() for heading in values}
    headings.update(("Examples:", "Detailed guides and controlbook (also in the repository):"))
    positions = sorted((reference.index("\n" + heading) + 1 if "\n" + heading in reference else reference.index(heading), heading)
                       for heading in headings)
    sections = {heading: reference[start:positions[index + 1][0] if index + 1 < len(positions) else len(reference)].rstrip()
                for index, (start, heading) in enumerate(positions)}
    selected = "\n\n".join(sections[heading] for heading in _TOPIC_SECTIONS[topic])
    return (DISPLAY_NAME + " — invscan help: " + topic + "\n\n" + selected + "\n\n" +
            examples_reference(topic) + "\nOffline topics: " + ", ".join(HELP_TOPICS) + "\n")
