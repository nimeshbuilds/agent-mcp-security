# Detection algorithms and controlled evidence investigation

Invarune combines repeatable source predicates with optional, bounded model investigation. Its useful distinction is the explicit evidence boundary: source matches, coverage gaps, model interpretation and operator decisions remain separate records. These are purpose-built engineering choices, not claims of algorithmic novelty, patentability or universal detection accuracy.

The [generated scan inventory](../SCAN_COVERAGE.md) describes every rule, control, source and limitation. This guide explains how the main algorithms compose and how to extend them safely.

## From files to a finding

```text
confined manifest + source hashes
    -> selected syntax/text profiles
    -> rule witnesses + explicit incomplete-analysis records
    -> stable finding identities + partial control mappings
    -> fixes, defense layers, scope metrics and reports
```

`scanner.py` chooses and reads bounded files. `analyzer.py` performs ordinary code/configuration predicates; `threats.py` extracts supported instruction surfaces; `tool_effects.py` checks a narrow annotation/effect contract. No module imports, target functions, registration callbacks, skills or containers are executed.

`analyze_file(..., analysis_errors=collector)` returns findings while appending recoverable flow gaps. The scanner then calls `analyze_file_errors(..., include_flow=False)` for remaining syntax/instruction diagnostics without repeating the flow pass. Standalone `analyze_file_errors()` includes flow diagnostics by default and converts visitor/resource exhaustion to incomplete coverage. Never discard a direct finding because a separate wrapper could not be resolved.

## Python boundary and argument propagation

The Python visitor tracks possible API aliases, external-input facts, supported object types, literal alternatives, constant expressions and selected interpolation facts. Branch joins retain possible unsafe values; uncertain bindings cannot silently become safe. Assignment and lexical scope handling invalidate overwritten aliases and values.

A function's name maps to an internal identity only when its direct binding is supported. The call pass binds actual positional/keyword arguments, captures default values at declaration time and propagates supported argument/return facts through local helper calls. Findings remain anchored at the sensitive sink and identify the bounded helper chain. No call expression is evaluated by Python.

Supported entrypoints supply evidence that generic parameter names such as `address` or `filename` are external:

- A tool decorator on a recognized `fastmcp.FastMCP` or `mcp.server.fastmcp.FastMCP` instance.
- An explicitly imported `langchain_core.tools.tool` or `langchain.tools.tool` decorator.
- Conventional, otherwise unbound `mcp.tool` and `server.tool` declarations in partial source. These are declared-boundary patterns; they do not verify the SDK or deployment.

Known rebindings and unrelated decorators do not receive these facts. Additional decorators leave binding uncertainty. Recognized injected FastMCP `Context` annotations are not treated as user arguments. Methods, arbitrary decorators, dynamic registration and cross-file dispatch are not complete entrypoint models.

The engine refines only narrow constraints: exact string equality; direct literal tuple/set membership; and a finite literal dictionary of complete string destinations. A rejecting return/raise can restrict a subsequent path. Mutations, aliases and unknown-call escapes invalidate a mutable dictionary proof. Substring checks, hostname logging, named validators and guards on another variable cannot prove the destination safe. Even a fixed URL does not establish safe DNS resolution or redirects.

Limits are eight expanded call levels, 512 call expansions and the shared deterministic work budget. Recursive calls and unsupported argument splats become explicit gaps. A direct awaited async call is supported; a created coroutine or generator requires execution/iteration context. Global/nonlocal side effects remain incomplete. The visitor preserves partial findings when these recoverable limits are reached.

## JavaScript wrapper summaries

`callflow.py` consumes the scanner's bounded lexical tokens and balanced delimiters. It summarizes top-level named functions and arrow assignments only when the supported body is a direct returned call. A summary links parameter dependencies to a recognized HTTP sink or an actually imported filesystem operation. It may compose direct wrapper summaries up to eight levels, with an 8,192-step summary budget.

Literal `server.registerTool` and `mcp.registerTool` calls can seed inline arrow-callback inputs when they contain a literal name and an inputSchema-bearing object. Simple names and shallow object destructuring/renaming are supported. Recognized SDK server construction and known receiver rebindings are tracked; conventional unbound names remain declared-boundary signals. Complex/default/rest bindings leave a gap when recognized. The model does not execute the callback.

Assignments, known API imports and parameter shadows affect the matching alias state. A wrapper receiving a fixed argument is distinct from one receiving the tool argument. Named callback references, arbitrary control flow, multi-statement wrappers, callback factories, module resolution, types and runtime monkey-patching remain outside this token-based algorithm. Do not describe it as a complete JavaScript parser or whole-program taint engine.

## Tool and skill instruction semantics

`threats.py` first establishes an applicable instruction surface: recognized skill/agent documents, bounded local skill references, literal tool descriptors or recognized schema description fields. The predicates then work on normalized text. NFKC, HTML entities, selected markup and format characters are normalized; at most one explicitly labelled base64 layer is decoded.

The instruction rules look for operative actions and objects, not a bag of security keywords. Recognized quoting, educational labels and local negation exclude specified safe forms. AI043 includes selected English and Spanish/French/German override forms, paired authority replacement and supported conditional conflict claims. AI044 pairs sensitive objects or linked read results with a transfer and explicit destination, including selected vault/attachment forms. AI045 pairs a consequential action with concealment, recognizes specified audit-erasure instructions or identifies an explicit approval bypass. These grammars are bounded; multilingual support is not general translation.

JSON input-schema traversal visits recognized description-bearing schema nodes, including properties, definitions, combinators and items. Examples and const values remain data. The schema traversal cap is 20,000 nodes. Instruction caps are 262,144 Markdown characters or 1,000,000 metadata-source characters; 2,048 segments; 8,192 characters per segment; and 32 labelled encodings of at most 8,192 decoded bytes. Truncation, unresolved recognized values and local reference failures remain coverage gaps.

`tool_effects.py` supplies an additional AI046 witness. A supported top-level Python tool declares `readOnlyHint=True`, but its handler contains an unambiguously bound direct `os`/`shutil` mutation or inline `pathlib.Path` write. Imported names must survive shadowing checks. Uncalled nested bodies and recognized dead branches are excluded. The pass has a shared 20,000-handler-node budget; nested/class bindings remain unresolved. A write witness conflicts with the declared contract but does not establish actual branch execution, malicious intent or missing authorization.

AI047 independently checks explicit chmod modes for the other-write bit. Only bounded integers, local literal facts, known stat flags and supported bitwise expressions are folded. No target expression is evaluated. The rule is narrower than a generic permissive-mode check: group-only writes are not a match, and OS/ACL/ownership effects remain unverified.

## Optional investigation is a validated data loop

```text
completed static scan + active selected checks
    -> confined hash-verified reads and redacted snapshot
    -> deterministic seed excerpts + bounded inventory IDs
    -> model requests permitted file-ID/line ranges OR final conclusions
    -> deterministic schema, identity, range and budget validation
    -> captured excerpt + request receipt
    -> final exact-quote validation and advisory check outcomes
```

The default full analyst permits two investigation rounds per batch. There are 36 shared control-stage requests, six controls per batch, 200 file attempts, 2,000,000 read bytes, 120,000 retained source characters and a 600-second scheduling budget. Triage uses an additional request. These are bounded defaults, not a wall-clock or billing guarantee. `--analyst-investigation-rounds 0` uses the seed-only path; disabled AI runs no model review.

`EvidenceInvestigation` cannot open a path or contact a URL. It serves only redacted lines already captured from verified manifest files. Inventory is limited to 200 files and 32,000 metadata characters, with at most 12 lexical definition hints per file. Hints locate text; they are not resolved symbols or call graphs. Requested ranges are capped at eight requests per round, 128 total, 80 lines and 4,000 characters per request. Seed and requested text share the overall character budget. Repeated evidence is not charged twice, while attempted requests still consume their request budget.

The model must tie a request to an active control/check, state its hypothesis and identify counterevidence to seek. The controller validates IDs and ranges, records accepted and denied requests, reserves conclusion calls for later batches and stops on provider/schema failures. Final structured analysis records `risk_hypothesis`, `boundary`, `counterevidence` and `conclusion_limits`. Legacy final responses remain compatible; receipts count missing structured analysis explicitly.

Final conclusions require the accepted response schema and, for grounded statuses, exact quotes from evidence assigned to that control. Dynamic/manual checks retain runtime/human requirements. A valid quote proves submitted text, not the model's interpretation. Static findings, severity, exclusions, error records and severity gates cannot be changed by a model answer. Custom gateways and trusted vendor CLIs remain separate trust boundaries; client-side controls do not prove a remote gateway runs no hidden tools.

## Verification and interpretation

Use paired fixtures for unsafe flows and constrained inputs, then adversarial tests for shadows, aliases, branch joins, default capture, map escape, deep syntax, lazy execution and budget exhaustion. Permission checks need unsafe and safe numeric/flag pairs; tool effects need imports, nested definitions and false-hint cases. Investigation tests must exercise forged IDs, quotes, mixed actions/conclusions, exhausted budgets, changed files and provider failures.

Keep the frozen 113-case corpus separate from new development cases and independently authored challenges. After a held-out case is disclosed and used for a fix, subsequent runs are development evaluation; preserve the first result. Publish actual errors and misses rather than altering labels to fit the implementation. Synthetic precision/recall does not estimate production accuracy or become the scanned application's security score.

See [adding checks](adding-checks.md), [AI adapters](ai-adapters.md), [scan selection and metrics](scan-inventory.md), and [test/release workflow](testing-and-releasing.md).
