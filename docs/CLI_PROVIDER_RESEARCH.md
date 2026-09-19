# Official CLI providers: authentication and containment research

Research date: **2026-09-19**. Product: **Invarune by NimeshBuild**.

Invarune can send its optional, minimized security-review payload through an installed official Codex, Claude Code or Grok Build CLI. Those CLIs can authenticate through their own account sign-in flows. An eligible subscription can therefore supply access without a separately configured API key. Account entitlement, remaining usage and provider policy still apply; “CLI authentication” does not mean unlimited or free inference.

This document records the implementation evidence and its limits. [CLI usage](CLI.md), the executable's `--help`, and [validation](VALIDATION.md) describe the released behavior. The source of the adapter is [cli_judge.py](../ai_security_scan/cli_judge.py).

## Verified official products

| Provider setting | Official executable inspected | Local version inspected | Sign-in mechanism | Machine-oriented request interface |
|---|---|---|---|---|
| `codex_cli` | `codex` | `codex-cli 0.154.0` | ChatGPT account sign-in; official CLI also supports API-key authentication | `codex exec`, stdin, JSON Lines events, JSON response schema |
| `claude_cli` | `claude` | `2.1.214 (Claude Code)` | Claude account/subscription sign-in; separate Console and third-party arrangements also exist | `--print`, stdin, JSON result envelope, JSON response schema |
| `grok_cli` | `grok` | `grok 0.2.60 (474c2bbfca2) [stable]` | Official Grok Build browser OAuth or device authorization; an API-key route also exists | `--prompt-file`, JSON result envelope |

These versions were read using the installed programs' `--version` and `--help`; no credential files were inspected. Invarune checks a minimum version and the presence of required flags before inference. A newer version is not automatically evidence that its semantics are unchanged: incompatible results fail the protocol validator.

OpenAI explicitly documents subscription sign-in and API-key sign-in as separate access paths. [OpenAI authentication](https://learn.chatgpt.com/docs/auth). Anthropic documents the official authentication choices and account prerequisites. [Claude Code authentication](https://code.claude.com/docs/en/authentication). xAI documents Grok Build's OAuth, device-code, external-auth-provider and API-key mechanisms. [Grok Build enterprise authentication](https://docs.x.ai/build/enterprise#authentication). Grok's consumer documentation connects Build usage to the shared subscription allowance. [Grok subscription usage](https://docs.x.ai/grok/faq).

The Grok adapter targets **official Grok Build**, whose package is `@xai-official/grok`. It does not target similarly named community `grok-cli` packages. [Official Grok Build overview](https://docs.x.ai/build/overview), [official source repository](https://github.com/xai-org/grok-build).

## Default model selection

| Provider | Invarune default | Reason for the choice |
|---|---|---|
| Codex | `gpt-6-astra`, high reasoning effort | OpenAI describes Astra as its most capable option for demanding coding, reasoning and research work. [Codex models](https://learn.chatgpt.com/docs/models). |
| Claude Code | `opus`, high effort | Anthropic recommends the Opus family for complex reasoning. The alias resolves according to the installed CLI and account. [Claude model configuration](https://code.claude.com/docs/en/model-config). |
| Grok Build | `grok-build` | Uses Grok Build's coding-agent model selection. [Grok Build settings](https://docs.x.ai/build/settings). |

These are documented capability choices, **not the outcome of a comparative security-judge accuracy benchmark**. Model availability and subscription access can differ. An explicit model override is supported; an explicit `default` value lets the vendor CLI select its configured default. Requested model names are recorded in the request audit. A vendor alias alone is not a pinned model version.

## Codex: restricted noninteractive review

The adapter uses a private working directory and passes evidence through stdin. It requests schema-constrained output, receives JSONL events, and accepts only the expected response stream. `--ignore-user-config` keeps the official authentication location while avoiding the user's normal configuration. `--ignore-rules` prevents execution-policy discovery, and `--ephemeral` avoids normal session persistence. These behaviors are documented in [Codex noninteractive mode](https://learn.chatgpt.com/docs/non-interactive-mode).

The generated command also disables shell execution, Code Mode, browser/computer use, plugins, hooks, apps, subagents, image operations, memory, skill search and related capabilities; sets a read-only sandbox; disables web search; supplies an empty MCP configuration; and omits project instruction content. Exact generated arguments are auditable in each successful review report. Configuration field definitions are available in the [official Codex configuration schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json).

A real run exposed a useful protocol detail: Codex emits a startup `item.completed` event whose item type is `error` when the selected model expects the deliberately disabled Code Mode host. The adapter recognizes only the exact upstream message for that condition, only before the turn, and records the fixed audit code `codex_code_mode_intentionally_disabled`. It does not expose arbitrary warning text or accept other error events. The upstream formatting is visible in [the pinned Code Mode implementation](https://github.com/openai/codex/blob/ed0ee704b44059229e74a030742804916451dadf/codex-rs/core/src/tools/code_mode/mod.rs).

## Claude Code: safe mode preserves subscription authentication

The adapter uses `--safe-mode`, an empty built-in tool set, an empty strict MCP configuration, `dontAsk` permission mode, disabled session persistence, disabled Chrome integration and disabled slash commands. It supplies a JSON schema and validates the returned envelope independently. The official result envelope uses `result` for text and `structured_output` when schema output is supplied. A success-looking subtype is insufficient: an `is_error: true` response is rejected. [Programmatic Claude Code](https://code.claude.com/docs/en/headless).

**Do not substitute `--bare`.** The inspected CLI help says bare mode does not use OAuth or the keychain. Safe mode preserves authentication while disabling customizations. Administrator-managed policy can still apply, including managed hooks; the scanner does not override enterprise policy. The exact distinction and the empty `--tools` argument are documented in [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference).

## Grok Build: additional preflight is necessary

Grok Build's JSON response has `text` and `stopReason`; a successful bounded completion requires `end_turn`. Truncation, refusal, cancellation and incompatible envelopes are errors. File input avoids placing submitted evidence on the process command line. [Grok headless and scripting](https://docs.x.ai/build/cli/headless-scripting), [pinned headless implementation](https://github.com/xai-org/grok-build/blob/4247f661689354b831191f11eeeac8424993fe3d/crates/codegen/xai-grok-pager/src/headless.rs).

Two differences from Claude were established by inspecting official source:

1. An empty Grok `--tools` value becomes an absent allowlist; it does **not** mean no tools. [Pinned comma-list parsing](https://github.com/xai-org/grok-build/blob/4247f661689354b831191f11eeeac8424993fe3d/crates/codegen/xai-grok-pager/src/headless/cli.rs).
2. An unknown tool name can cause Grok to keep its full tool set. The adapter therefore uses the known `Bash` allowlist type and explicitly removes its backing shell tools plus the dynamic search/use routers, alongside deny-all permissions, disabled web search/subagents/memory, a read-only sandbox and one turn. [Pinned agent builder](https://github.com/xai-org/grok-build/blob/4247f661689354b831191f11eeeac8424993fe3d/crates/codegen/xai-grok-agent/src/builder.rs).

Those source findings are from the pinned official repository commit shown in the links. They are not proof that every binary release has identical behavior. The installed binary's compatibility and the release's live-test status must be considered separately.

Before a Grok model request, Invarune runs the read-only `grok inspect --json` command in the private directory. It rejects active hooks, external instructions, custom agents, plugins, skills, MCP/LSP servers and marketplaces. An unexpected inspection shape is also rejected. Discovery is relevant because Grok can load personal hooks and compatibility settings even when its working directory contains no source repository. [Grok hooks](https://docs.x.ai/build/features/hooks), [Grok CLI inspection](https://docs.x.ai/build/cli/reference).

The optional `cli_home` setting selects an **existing**, dedicated `GROK_HOME` directory. It does not copy credentials. The user signs into that profile through the official login flow. Grok documents that variable as the location for authentication, configuration and local state. [Grok environment reference](https://docs.x.ai/build/settings/reference). A dedicated Grok directory may still inherit other user or administrator configuration; it must pass inspection. Creating an empty directory alone is not sufficient evidence of isolation.

## Login and the trust boundary

Invarune delegates interactive login to the official executable. It does not implement an unofficial subscription API, scrape browser cookies, print tokens, or copy authentication files. The scanner can invoke the official login from its CLI, then verify status where the provider exposes a status command. Unattended scans do not open browser login prompts.

The installed executable and its trusted authentication/configuration infrastructure remain outside the scanner's security boundary. A malicious replacement executable, compromised provider, unsafe administrator hook, or future CLI behavior change cannot be made safe by prompt wording. CLI capability restrictions are **not** an operating-system containment guarantee.

Inference requests use bounded input, stdout, stderr and wall time, and a fresh private working directory. The adapter strips ordinary API-key variables and common runtime-injection variables from the child environment. It preserves identity paths and documented CLI authentication locations; existing CLI-managed credentials can still be API-backed, so reports say `cli_managed` rather than asserting a subscription billing plan. The original `HOME` and `CODEX_HOME` are not repurposed.

POSIX inference cleanup targets the process group, including ordinary descendants. Windows inference cleanup currently targets the direct process. Interactive login has a separate terminal and lifecycle boundary. Use a suitably isolated host or container when stronger process/filesystem guarantees are required. Provider-managed retention, accounting and CLI-local storage are governed by that provider and deployment; Grok does not supply the same no-session-persistence flag used for Codex and Claude.

There is no uniform enforceable output-token or monetary cap across these three CLI interfaces. Invarune consequently rejects unsupported CLI `max_output_tokens` configuration instead of pretending to enforce it. Time/byte limits constrain the local request, but do not guarantee that a cancelled remote inference immediately stops billing or consuming subscription usage.

## Evidence from actual testing

Published, sanitized receipts and reproduction instructions are available in [CLI-provider validation](../benchmarks/cli-providers/README.md). They distinguish successful Codex requests from the actual Claude authentication failures and Grok preflight rejection. The opt-in [reusable validation harness](../scripts/validate_cli_providers.py) submits only the fixed synthetic fixtures described there.

The initial research involved installed version/help checks, read-only authentication status and Grok configuration inspection, real bounded Codex requests, and real Claude requests that returned an authentication error. No target repository code was executed to perform these checks.

At the recorded implementation checkpoint, Codex/Astra completed both a synthetic finding-triage request and a grounded control-review request through the production adapter and deterministic validators. Claude's installed CLI reported absent/expired sign-in; that operational failure was preserved rather than counted as successful model validation. Grok's installed profile contained active extensions and was rejected before inference. Subsequent sign-in retries and final release outcomes belong in the release validation record; these initial failures must not be presented as successful live provider coverage.

A subsequent real `invarune --login claude` attempt successfully launched the official browser authorization flow. Account authorization was not completed within the configured 300-second window, so Invarune returned an authentication timeout. This verifies invocation of the official flow and timeout handling; it does **not** verify a successful Claude sign-in or a successful live Claude security review.

Automated subprocess tests exercise real stdin/stdout/stderr handling, output overflow, timeout, nonzero exit, blocked input and POSIX descendant cleanup. Protocol and integration tests separately cover all three adapters, invalid envelopes, exact IDs/citations, optional-mode behavior, image scans, configuration exceptions, deterministic-result preservation, and authentication routing. Mocked-provider tests establish adapter behavior; they do not establish that a live account is entitled to a model or that its security judgments are accurate.
