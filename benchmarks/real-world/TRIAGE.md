# Manual review of initial public-project results

These are observations from actual scans of the pinned corpus. The selection is diagnostic and development-visible, not a statistically valid precision/recall sample. No project code or service was executed. Counts are static review candidates, not confirmed vulnerabilities.

These observations informed detector improvements before the final rescan. The original finding IDs, severities, scanner implementation hashes and scan IDs remain in [triage-initial.json](triage-initial.json). Final reports may no longer emit a corrected pattern.

## CrewAI / AI011

**Review:** false positive.

The matched PEM opening marker is followed by an ellipsis inside an embedded API docstring example; no PEM body or usable private key is present. [Pinned source](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/a2a/utils/agent_card_signing.py#L106).

**Next validation:** A secret rule should require plausible key material, not the marker alone. Do not classify a marker-only documentation example as leaked credentials.

## CrewAI / AI010

**Review:** false positive.

The dictionary maps environment-variable names to provider display names. The values are labels used by a validation tool, not authentication credentials. [Pinned source](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/cli/src/crewai_cli/deploy/validate.py#L86).

**Next validation:** Follow the value role and consumer before treating a credential-related identifier as a literal secret.

## Pydantic AI / AI010

**Review:** false positive.

The value api-key-not-set is explicitly a dummy API key for compatible local services because the client SDK requires a nonempty string. [Pinned source](https://github.com/pydantic/pydantic-ai/blob/c4898abb54dc25ae6f6aef208a4c0661b30a455e/pydantic_ai_slim/pydantic_ai/providers/openai.py#L122).

**Next validation:** Determine whether a literal is a genuine authentication secret or an SDK placeholder; still validate any externally configured service authentication independently.

## Pydantic AI / AI010

**Review:** false positive.

The value codex-subscription-auth is a placeholder. The surrounding auth object replaces the SDK bearer header. This finding does not establish a credential leak. [Pinned source](https://github.com/pydantic/pydantic-ai/blob/c4898abb54dc25ae6f6aef208a4c0661b30a455e/pydantic_ai_slim/pydantic_ai/providers/openai_codex.py#L562).

**Next validation:** Review the credential-injecting auth handler and actual credential storage separately; the placeholder itself is not a secret.

## OpenHands / AI010

**Review:** false positive.

INVALID_BACKEND_API_KEY_ERROR contains the human-readable sentinel message Invalid API key. It is an error label, not a key. [Pinned source](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/src/api/agent-server-compatibility.ts#L32).

**Next validation:** Exclude error/status message roles from credential classifications while retaining scans of actual secret values.

## LangGraph / AI036

**Review:** false positive for this reviewed call.

This call supplies query values as separate parameters. Its helper builds fixed SQL predicates with placeholders, and LIMIT is bound through a parameter. The composed-query signal alone does not demonstrate injection here. [Pinned source](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/checkpoint-postgres/langgraph/checkpoint/postgres/__init__.py#L160). [SQL predicate helper](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/checkpoint-postgres/langgraph/checkpoint/postgres/base.py#L624).

**Next validation:** Verify the helper and every interpolation separately; this disposition applies only to this reviewed call, not all 23 SQL findings or all calls that accept a parameter list.

## AutoGen / AI001

**Review:** expected risk bearing capability.

FunctionTool config loading deliberately executes supplied Python source. The upstream code warns to load configs only from trusted sources. The execution sink is real; reachability from an untrusted actor was not tested. [Pinned source](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/tools/_function_tool.py#L171).

**Next validation:** Enforce trusted provenance and authorization for serialized tool configuration; isolate any intentional untrusted execution with separate credentials, filesystem and network boundaries.

## AutoGen / AI005

**Review:** review required.

The experimental memory bank loads a local pickle file. Whether an attacker can influence that file depends on the application and deployment. The scan did not prove such access. [Pinned source](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py#L82).

**Next validation:** Prefer a non-executable data format or verify a trusted, access-controlled artifact. Validate directory permissions and model/tool write access to the memory location.

## MCP reference servers / AI007

**Review:** intentional reference configuration.

The reference server deliberately enables wildcard CORS for Inspector direct-connect testing, and its code cautions about production use. Upstream labels this repository as reference implementations. [Pinned source](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/everything/transports/sse.ts#L12).

**Next validation:** For deployments derived from this reference, validate origin handling, authentication and host/network exposure; this result does not claim the reference project is a vulnerable production service.

## GitHub MCP Server / AI025

**Review:** policy advisory not demonstrated vulnerability.

The package declares a semver range. A committed UI lockfile is also in the selected snapshot. This signal does not determine whether builds use frozen installs or resolve a floating dependency. [Pinned source](https://github.com/github/github-mcp-server/blob/85598ba6e1256f7ebf4867b95d63b833c4549264/ui/package.json#L17).

**Next validation:** Verify the lockfile, package manager frozen-install setting, integrity verification and release provenance. A semver range by itself is not an exploitable supply-chain vulnerability.

## OpenHands / AI021

**Review:** false positive for final runtime user.

The source Dockerfile temporarily switches to root for image setup but switches to USER openhands at line 158 before the final ENTRYPOINT. The finding omits that later effective-user change. [Pinned source](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/docker/Dockerfile#L95).

**Next validation:** Evaluate the final effective USER per Docker stage, and separately verify runtime user overrides. This source review did not build or run the image.

## Interpretation

No blanket suppression was applied to these public projects. Other occurrences of the same rule remain independently unverified. A zero-finding result is not a clean bill of health; runtime authentication, prompt injection, tool authorization, sandboxing, dependency vulnerabilities and deployment behavior need their own validation.

Four initial analysis errors came from the scanner's bounded Python analysis work budget (CrewAI flow runtime, LangGraph pregel runtime, and two large Pydantic AI provider files). CrewAI templates and OpenHands JSON syntax exposed structured-parser limitations. These gaps remain visible rather than being excluded after observing results.
