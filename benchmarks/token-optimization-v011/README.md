# Evidence-preserving token optimization proof

The actual installed Headroom 0.37.0 SDK and Invarune 0.11.0 optimizer preserve the tested evidence JSON. This benchmark measures bytes, with no model call, provider billing estimate or claim about model accuracy. The [source research](../../docs/HEADROOM_RESEARCH.md) explains the private API, release pin, dependency footprint and validation boundary.

## Measured request-payload savings

The primary baseline is the scanner's previous **one-space, sorted-key JSON serialization**, not pretty-printed files. Twenty frozen blinded security-review payloads were processed through the actual installed Headroom static minifier and the production optimizer. Every payload retained strict typed canonical JSON equality; `headroom`, `compact` and `off` mode outputs were checked.

| Evidence payload profile | Baseline bytes | Headroom bytes | Saved bytes | Reduction | Built-in compact bytes |
|---|---:|---:|---:|---:|---:|
| HTTP, escaped Unicode baseline | 326,245 | 307,466 | 18,779 | 5.76% | 308,091 |
| CLI, Unicode baseline | 325,620 | 307,466 | 18,154 | 5.58% | 307,466 |

These counts cover serialized evidence JSON, excluding security instructions, output schemas and provider/CLI wrappers. The HTTP and CLI baselines differ in `ensure_ascii`. Headroom additionally converts Unicode escapes to their actual characters; built-in compaction retains the caller's serialization setting. Both represent the same string values.

[Payload receipt](payload-wire-proof.json) records each input/output digest, byte count and production optimizer receipt. It confirms zero network attempts, zero child-process attempts and zero model calls. No verified cached `cl100k_base` tokenizer asset existed, so tokenizer measurements are explicitly unavailable; no asset was downloaded. Byte reductions must not be presented as measured token savings or billed cost savings.

The earlier SDK-only experiment compared the same payloads as stored with indentation: 543,505 to 307,466 bytes, or 43.43%. That is a **pretty-print formatting comparison**, not the baseline used for the primary production request results above.

## Installed SDK and safety boundaries

The [SDK import proof](sdk-import-proof.json) used the real installed official wheel, not a mock or extracted-function substitute. It checked 1,002 synthetic round trips and all twenty real payloads. Cases cover source/citation whitespace, Unicode, control IDs, booleans, null, numbers, negation and hostile instruction strings. These remain data; no instructions from the payloads were followed.

The SDK import and direct static helper operation ran on macOS ARM64 / Python 3.12.14 under an OS-level deny-network sandbox plus a Python audit hook blocking socket and child-process operations. No network/process attempt occurred. The native `headroom._core` extension loaded; no ML runtime/provider modules were imported. That native dependency remains part of the trusted package boundary. This does not claim equivalent platform testing on Windows or Linux.

The upstream minifier accepts some duplicate-key and nonfinite-number inputs; the proof demonstrates why Invarune independently rejects them and verifies the entire typed structure. The public compression pipeline, retrieval/CCR, proxy, model inference and provider configuration are not used. The [exact upstream provenance](upstream-provenance.json) and [resolved dependency versions](dependency-lock.json) support independent inspection.

The integration audit found no correctness blocker in the inspected optimizer. The [receipt](payload-wire-proof.json) binds the actual tested `token_optimizer.py` SHA-256. This is a bounded code review and runtime exercise, not an assurance against a malicious installed dependency or all future upstream changes.

## Reproduce

Install the pinned optional package into a separate environment using wheels only. Verify its wheel digest against [upstream-provenance.json](upstream-provenance.json). Recreate the frozen payloads using the [blinded preparation workflow](../comparison-v010/ADJUDICATION.md); source evidence stays under ignored `tmp/`.

On the tested macOS host, the actual commands are:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/sandbox-exec \
  -p '(version 1)(allow default)(deny network*)' \
  tmp/headroom-proof-venv/bin/python \
  benchmarks/token-optimization-v011/prove_sdk_import.py

PYTHONDONTWRITEBYTECODE=1 /usr/bin/sandbox-exec \
  -p '(version 1)(allow default)(deny network*)' \
  tmp/headroom-proof-venv/bin/python \
  benchmarks/token-optimization-v011/prove_payloads.py
```

The proof scripts also install Python socket/process audit guards; the macOS sandbox supplies the additional native network boundary. Raw source/payload content, provider configuration and model responses are absent from published receipts. Regeneration uses the local frozen evidence files and does not launch a security judge.
