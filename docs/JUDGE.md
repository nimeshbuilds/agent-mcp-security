# Optional LLM security judge

The deterministic scanner works offline and does not need a model. Enable the optional judge explicitly with `--judge-config /path/to/trusted-judge.json` or `--judge-cli codex|claude|grok`. The judge adds advisory assessments; it cannot delete baseline findings, change their severity, or override the deterministic scan result. It is nondeterministic even if a provider accepts temperature zero or a seed.

The default configured mode is **full**: one finding-triage request followed by a bounded security analyst review of active checks from the **66-control, 132-check catalog**, including checks without findings. Explicit user exceptions remove checks from the active review denominator. This sends redacted source excerpts selected deterministically from the scanned manifest, even when the static scan is clean. The [security analyst guide](ANALYST.md) describes routing, exact-quote validation, the control-output schema, request budgets, evidence limits, and explicit unresolved outcomes. All protocols below work for both stages.

Use `--judge-mode findings` for the previous one-request scope: minimized findings, redacted evidence, and scan metadata. `--judge-include-source` adds bounded neighboring source excerpts to finding triage only; full analyst evidence is independent of that flag. Redaction reduces accidental disclosure; it cannot guarantee that all proprietary information or unusual secret formats are removed. Choose an endpoint approved for the data you send. Repository instructions are untrusted review material. The prompt states that boundary, but prompting alone cannot eliminate prompt injection; separate static findings, fixed evidence retrieval, strict output validation, and no tool dispatch are the enforcement boundaries.

## Supported protocols

Invarune also supports **official CLI transports**: `codex_cli`, `claude_cli`, and `grok_cli`. Their configuration and login behavior are separate from the HTTP fields below.

```sh
invarune ./repository --judge-cli codex --judge-timeout 120
invarune ./repository --judge-cli claude --judge-mode findings
invarune ./repository --judge-cli grok
invarune --login claude
```

An interactive scan uses `--judge-login auto` by default. It opens the vendor's official login when signed out, then resumes. An explicitly reported authentication expiry in either review stage can trigger one login and retry per scan. Control retries consume the control-call budget; completed batches are preserved. Login has its own `--login-timeout` (300 seconds, range 1–900), excluded from the analyst scheduling clock. Cancellation/failure preserves static reports and returns exit 2. `--judge-login never`, `--quiet`, `--summary-json` and noninteractive terminals never prompt. `--login PROVIDER` signs in directly through Invarune without scanning or creating reports.

Invarune's default models are `gpt-6-astra` for Codex, `opus` for Claude, and `grok-build` for Grok. Codex and Claude use high reasoning effort. An explicit `--judge-model MODEL` overrides the model; `--judge-model default` selects the vendor CLI's configured default. Account entitlement and model compatibility still apply. The requested model is recorded, and aliases can change with vendor versions. See the [dated rationale and official sources](CLI_PROVIDER_RESEARCH.md).

Equivalent trusted JSON configuration:

```json
{"provider":"codex_cli","timeout_seconds":120}
```

CLI JSON permits only `provider`, optional `model`, `executable`, `timeout_seconds` (default 60, range 0.1–300), `max_request_bytes` (default 524288), `max_response_bytes` (default 1048576), and Grok-only `cli_home`. Byte limits are integers from 1024 through 5242880. `executable` must be a trusted absolute executable path or a bare command name. Shell command files, relative paths, arbitrary extra arguments, HTTP configuration fields, and output-token budgets are rejected. The CLI flags `--judge-executable` and `--judge-cli-home` also work for standalone login; `--judge-model` and `--judge-timeout` require `--judge-cli`. When using JSON, put their equivalents inside that file.

Minimum inspected versions are Codex 0.154.0, Claude Code 2.1.214 and official Grok Build 0.2.60. Version/help probes verify the required flags. The installed executable, vendor service and host administrator configuration remain trusted. Inference uses a private temporary working directory, restricted tools/customizations, bounded input/output and time, strict schemas and the existing citation validator. This is not OS-level containment or a provider-retention guarantee. POSIX inference cleanup targets the process group; Windows and interactive login cleanup target the direct child. No credential file is read or copied by Invarune, and API-key variables are not inherited. The official CLI manages its own login state, which can be subscription-backed or API-backed; Invarune cannot guarantee the billing plan.

Grok performs an additional fail-closed inspection for active extensions/instructions. `cli_home` / `--judge-cli-home` selects an existing absolute `GROK_HOME` directory; keep it outside source targets. A fresh profile can still inherit user/admin extensions and must pass inspection. Invarune does not rewrite an existing profile or copy its credentials. Use `invarune --login grok --judge-cli-home /absolute/profile` to sign into a suitable profile directly.

No CLI-wide output-token/cost cap can be enforced uniformly. Local time/byte limits do not reverse remote usage already consumed. The API/gateway adapters retain their existing explicit token limits and exact endpoint settings.

### HTTP protocols

| `provider` | Default endpoint | Native response extraction |
| --- | --- | --- |
| `openai_chat` | `https://api.openai.com/v1/chat/completions` | First choice's message content |
| `openai_responses` | `https://api.openai.com/v1/responses` | Text parts from message items; skips reasoning items |
| `anthropic` | `https://api.anthropic.com/v1/messages` | Text content blocks |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent` | First candidate's text parts; excludes thought parts |
| `ollama` | `http://127.0.0.1:11434/api/chat` | Message content |
| `custom` | Required | Configured dotted `response_path` |

`openai` and `openai_compatible` are aliases for `openai_chat`; `responses` aliases `openai_responses`. Every protocol accepts an exact `endpoint` URL, including custom gateway paths and nonsecret query parameters such as an API version. The adapter never guesses or appends a path. `${MODEL}` in an endpoint is URL-encoded before insertion.

These protocols cover many model services and gateways. The custom adapter supports other synchronous JSON-over-HTTP POST APIs. This is not a claim that every LLM API works without adaptation: AWS SigV4 signing, OAuth token acquisition or refresh, mTLS, WebSockets, SSE-only services, binary encodings, multipart uploads, asynchronous polling, and proprietary non-JSON protocols require a compatible gateway or another adapter. Supply existing bearer tokens through environment variables; the scanner does not obtain or refresh credentials.

## Example configurations

Choose a model available to your account or local server; the examples intentionally do not prescribe a model version. No paid or remote provider call is part of the test suite.

OpenAI-compatible gateway:

```json
{
  "provider": "openai_chat",
  "model": "YOUR_MODEL_ID",
  "endpoint": "https://gateway.example.com/v1/chat/completions",
  "api_key_env": "AI_JUDGE_API_KEY",
  "timeout_seconds": 60,
  "max_output_tokens": 4096
}
```

Set `AI_JUDGE_API_KEY` through your normal secret manager or environment. The configuration contains the variable's **name**, never its secret value. Omitting `api_key_env` sends no automatic API key, even if standard provider variables such as `OPENAI_API_KEY` are present. This prevents an unrelated gateway from receiving a key implicitly.

OpenAI Responses:

```json
{
  "provider": "openai_responses",
  "model": "YOUR_MODEL_ID",
  "api_key_env": "OPENAI_API_KEY"
}
```

Responses requests explicitly set `store: false`. This request flag is not a guarantee about a provider's contractual retention, monitoring, or training policies.

Anthropic:

```json
{
  "provider": "anthropic",
  "model": "YOUR_MODEL_ID",
  "api_key_env": "ANTHROPIC_API_KEY",
  "anthropic_version": "2023-06-01"
}
```

Gemini:

```json
{
  "provider": "gemini",
  "model": "YOUR_MODEL_ID",
  "api_key_env": "GEMINI_API_KEY"
}
```

Local Ollama:

```json
{
  "provider": "ollama",
  "model": "YOUR_INSTALLED_MODEL",
  "endpoint": "http://127.0.0.1:11434/api/chat"
}
```

Azure-style or other gateway authentication:

```json
{
  "provider": "openai_chat",
  "model": "YOUR_DEPLOYMENT_OR_MODEL",
  "endpoint": "https://YOUR_RESOURCE.example.com/YOUR_CHAT_PATH?api-version=YOUR_SUPPORTED_VERSION",
  "api_key_env": "AI_JUDGE_API_KEY",
  "api_key_header": "api-key",
  "api_key_prefix": "",
  "headers": {
    "X-Tenant": "${ENV:AI_JUDGE_TENANT}"
  }
}
```

Use the endpoint path and API version documented by your gateway. For a gateway accepting an already-issued bearer token, use `api_key_env` with its token variable and omit `api_key_header`/`api_key_prefix`.

Generic JSON API:

```json
{
  "provider": "custom",
  "model": "YOUR_MODEL_ID",
  "endpoint": "https://gateway.example.com/review",
  "headers": {
    "Authorization": "Bearer ${ENV:AI_JUDGE_API_KEY}"
  },
  "request_template": {
    "deployment": "${MODEL}",
    "parameters": {"max_new_tokens": 4096},
    "inputs": [{"text": "${PROMPT}"}]
  },
  "response_path": "result.outputs.0.text"
}
```

`request_template` is a JSON object. Placeholders are substituted in string values after JSON parsing, then the result is safely serialized. `${PROMPT}` contains the complete review instructions and untrusted JSON payload; `${MODEL}` is the configured model; `${ENV:VARIABLE_NAME}` resolves an environment variable. Replacement is a single pass: text such as `${ENV:SECRET}` inside a repository finding stays literal and cannot read the scanner's environment. No Python, JavaScript, Jinja, shell, `eval`, or JSONPath expressions are executed. Object keys are not templates. A custom template must include `${PROMPT}`.

`response_path` traverses JSON object keys and zero-based array indexes separated by periods. It can select either the model's JSON text or an already-parsed assessment object. Set it to `""` if the entire response is the assessment. Keys containing periods cannot be addressed by this simple adapter; normalize them in a gateway. Credentials can be injected into a custom body through an environment placeholder when a provider requires it.

## Configuration reference

| Field | Behavior |
| --- | --- |
| `provider` | Defaults to `openai_chat`; supported names listed above. |
| `model` | Required nonempty model or deployment identifier, at most 256 characters. |
| `endpoint` | Exact URL; provider default used when omitted, required for `custom`. |
| `api_key_env` | Explicit environment variable to use for authentication; never a literal key. |
| `api_key_header` | Default `Authorization`, `x-api-key` for Anthropic, or `x-goog-api-key` for Gemini. |
| `api_key_prefix` | Defaults to `Bearer ` for an Authorization header, otherwise empty. |
| `headers` | String-to-string map; supports environment placeholders. Credential headers require an environment placeholder. |
| `extra_body` | Optional provider parameters. A top-level `null` removes a default field. Cannot override model, prompt, native tool, storage, or streaming fields. |
| `request_template` | Custom-provider JSON request object. |
| `response_path` | Custom-provider dotted extraction path. |
| `timeout_seconds` | Default 60; accepted 0.1–300. Socket timeout plus elapsed-time checks between response reads. Not a guaranteed wall-clock deadline for DNS resolution. |
| `max_request_bytes` | Default 524288; accepted 1024–5242880. Excess input fails explicitly; findings are not silently dropped. |
| `max_response_bytes` | Default 1048576; accepted 1024–5242880. Limits the complete HTTP response. |
| `max_output_tokens` | Default 4096; accepted 128–32768. Sets native default generation limits. Custom templates must supply their provider's token-limit field. |
| `allow_insecure_http` | Default false. Nonloopback HTTP needs explicit `true`; HTTPS is recommended for remote endpoints. |
| `ca_file` | Optional PEM CA bundle for an enterprise gateway; certificate and hostname verification stay enabled. |
| `anthropic_version` | Defaults to `2023-06-01`. |

The native Chat Completions adapter uses `max_completion_tokens`. For older OpenAI-compatible implementations, use:

```json
{
  "extra_body": {
    "max_completion_tokens": null,
    "max_tokens": 4096
  }
}
```

Some models do not accept `temperature`, a seed, JSON response-format parameters, or particular reasoning options. Those parameters are deliberately not imposed on all native providers. Use `extra_body` for your model's documented options. Native Gemini and Ollama requests ask for JSON using their protocol fields. Review model context limits and set provider generation parameters large enough for the submitted findings.

Configuration files are capped at 256 KiB and 64 nesting levels. Invalid Unicode in a model identifier or endpoint is rejected before transmission. Excessively nested configurations produce an explicit judge error while preserving the static report.

The finding-triage stage sends up to 100 unsuppressed findings by default. `--judge-max-findings` accepts 1–500. Selection follows deterministic report order. The payload and report record `omitted_open_findings` for findings excluded by this cap, separately from `omitted_assessments` for submitted findings that the model left unanswered. The report also records `source_context_sent_count`. All findings remain in the deterministic report. This stage makes one bounded request; an oversized request fails explicitly. Full mode then uses stable control batches (six controls by default) up to the separate analyst call/time budgets. There are no automatic retries. Increase model output limits or reduce `--analyst-batch-size` if your provider truncates control responses, and increase the call budget to accommodate smaller batches.

## Finding-triage output and failure behavior

The finding-triage model output is shown below. Full mode uses a separate strict `control_assessments` schema for subsequent requests, documented in [ANALYST.md](ANALYST.md); the controller supplies the appropriate instructions for each stage.

```json
{
  "assessments": [
    {
      "finding_id": "EXACT_SCANNER_FINDING_ID",
      "verdict": "needs_review",
      "reason": "Explain the evidence and what must be verified.",
      "recommended_actions": {
        "agent_mcp_relevance": "If model-selected arguments reach this shell call, they can change the tool's executed command.",
        "applicability": "Confirm the input producer and the permissions of the process executing this call.",
        "steps": [
          "Use a fixed executable and argument array with shell=False, and allowlist the options the tool permits."
        ],
        "verification": [
          "In a test environment, verify metacharacters stay literal and an unauthorized executable or option is rejected."
        ]
      }
    }
  ],
  "additional_concerns": ["The supplied evidence does not establish deployment-level tool approvals."],
  "additional_concern_actions": [
    {
      "concern_index": 1,
      "recommended_actions": {
        "agent_mcp_relevance": "Sensitive tool actions may require an approval bound to the actual destination and arguments.",
        "applicability": "First obtain the effective deployment policy; absence from the excerpts does not establish a missing safeguard.",
        "steps": ["Review the deployed approval policy and identify the operations requiring explicit consent."],
        "verification": ["Use an authorized test to confirm denied actions and changed arguments cannot reuse a prior approval."]
      }
    }
  ]
}
```

Allowed verdicts are `likely_true_positive`, `likely_false_positive`, and `needs_review`. Finding IDs must match those submitted. Unknown or duplicate IDs, invalid verdicts, malformed JSON, obvious truncation, and invalid extraction paths fail the judge. Missing assessments become explicit `needs_review` entries with an omission count. Additional concerns remain unverified advice and are not inserted as deterministic findings. Reasons and concerns are capped at 4000 characters, and there can be at most 100 concerns.

Current prompts and official CLI response schemas request `recommended_actions` for every assessment and additional concern. This object has exactly four fields: nonempty `agent_mcp_relevance` and `applicability` strings of at most 1,200 characters each, plus `steps` and `verification`, each an array of one to five nonempty strings of at most 1,000 characters. Unexpected keys, wrong types, empty arrays and oversized fields fail validation. Known adapter credentials are redacted from all action fields. `concern_index` is a unique one-based integer referring to an existing `additional_concerns` entry; booleans, duplicates and out-of-range indexes are rejected.

Action guidance should name a concrete API or setting only when the evidence supports it, preserve required behavior and say which agent/MCP boundary is relevant. When applicability is uncertain, it should identify the evidence needed before changing code. These fields are untrusted prose, not commands, patches, validated citations or permission grants. The scanner does not run them or follow their URLs. A generic risk pattern is not proof of an active agent call path or an absent deployment safeguard.

For compatibility, the response normalizer still accepts older assessments without `recommended_actions` and responses without `additional_concern_actions`. It retains the assessment and reports the missing plan through `advice_coverage`; it does not invent model advice. Absence of action guidance alone does not fail an otherwise accepted review. A provided but malformed action object does fail. Finding omissions and control-check omissions retain their separate existing semantics. Longer detailed answers may require a larger provider output budget or smaller analyst batches; byte/token limits are still enforced and no truncated response is silently accepted.

Every static finding also has an independent [catalog fix plan](REPORTS.md#per-finding-fix-plans-and-agentmcp-relevance), including when the judge is disabled, fails or omits advice. Model guidance is labeled separately in HTML, Markdown, JSON and PDF. SARIF includes the static catalog guidance only. Neither kind of plan changes finding severity or establishes that a repair was performed.

The returned object also records `status`, `provider`, configured `model`, optional provider-reported model, `adapter_version`, `advisory_only`, `nondeterministic`, `findings_submitted`, and `omitted_assessments`. Reports must escape model text as untrusted text. Output links are not retrieved, commands are not run, and tool calls are not dispatched. Model advice must not be used as an authorization decision.

The transport verifies TLS, rejects redirects, has no retries, ignores environment proxy settings, does not store cookies, rejects compressed responses, and reads a bounded response. Remote HTTP requires explicit configuration; loopback HTTP supports local model servers. Credentials in URL user information or common credential query parameters are rejected. Header injection and reserved transport headers are rejected. Request and response bodies, authentication headers, full endpoint URLs, and raw provider error details are not included in judge error messages. Environment values explicitly used by the adapter are removed if echoed in model output; this is additional protection, not a general data-loss-prevention system.

Configuration is trusted operator input: do not load a judge configuration supplied by the repository under examination. A malicious configuration can choose a data recipient and explicitly request environment variables. Keep it outside untrusted repositories and review custom templates before use.

Both finding triage and control review reject recognized tool configuration fields and tool invocation output, including nested custom payload fields. Configure the gateway itself to disable server-side tools; a client cannot attest to a remote service's internal behavior. A first failed control batch stops further calls and preserves completed advice. Every unanswered control/check remains explicit, and incomplete control review returns exit code 2. `supported_by_code` is advisory source support, never a compliance pass. Proposed verification steps are text only and are not executed.

## API references

Protocol shapes were checked against official documentation on 2026-09-19:

- [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat) documents the messages request and choice/message response.
- [OpenAI Responses](https://developers.openai.com/api/reference/cli/resources/responses/methods/create) documents the input/instructions request, output item array, output token limit, and storage flag.
- [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create) documents the top-level system prompt, messages, maximum tokens, and content blocks; [authentication](https://platform.claude.com/docs/en/manage-claude/authentication) documents supported key headers.
- [Gemini generateContent](https://ai.google.dev/api/generate-content) documents contents, generation configuration, and candidates; [API overview](https://ai.google.dev/api) documents `x-goog-api-key` authentication.
- [Ollama chat](https://docs.ollama.com/api/chat) documents message input, JSON format, options, and disabling streaming.
