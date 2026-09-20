# Headroom integration research

Research date: 19 September 2026. This review concerns **Headroom**, the `headroom-ai` package maintained at [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom). It does not establish that a differently named “Headliner” product is the same tool.

A narrow local integration is feasible: use the pinned Headroom 0.37.0 JSON-minification helper and independently verify the candidate before accepting it. This preserves every parsed JSON value, including exact source/citation strings, without invoking its compression pipeline, proxy, retrieval tools or model. Because the helper is private, version checks and a visible local fallback are necessary.

## Verified package and source

The [PyPI release metadata](https://pypi.org/pypi/headroom-ai/0.37.0/json) reports version **0.37.0**, Python **>=3.10**, uploaded 27 August 2026. Its release tag resolves to commit [`32d7ca4577d599b8a5f811ada74cf31504302c9d`](https://github.com/headroomlabs-ai/headroom/tree/32d7ca4577d599b8a5f811ada74cf31504302c9d). The separately inspected main checkout was [`67eb910e38b9879bb0bcbacdc36db69e36901075`](https://github.com/headroomlabs-ai/headroom/tree/67eb910e38b9879bb0bcbacdc36db69e36901075). Main still labels itself 0.37.0 but contains newer source and dependency changes; the published wheel and release commit are the integration authority.

The tested official macOS ARM wheel was `headroom_ai-0.37.0-cp310-abi3-macosx_11_0_arm64.whl`, 13,780,628 bytes, SHA-256 `b4392f68a8d02d74c62c1734cf5bf327511dcc72678f01669f44f0612944d59c`. The release's `headroom/transforms/content_router.py` has SHA-256 `3cb0c0572c504409763e66c4adf240abc939212a1e0c1f43d76135088498e8be`; the release commit and wheel contain identical bytes for that file. The exact helper source returned by `inspect.getsource`, including its decorator and docstring, has SHA-256 `a8ac6e95385615073e707141333449e711f8ad954494c679f5e2824146a4aaa7`.

PyPI supplies CPython stable-ABI wheels for macOS ARM and Intel, Linux ARM64 and x86_64 with glibc 2.28+, and Windows x86_64. This is package availability, not an integration test on every platform. Python 3.9, PyPy, Windows ARM and musl/Alpine are outside those wheel guarantees. Prefer wheel-only installation to avoid an unexpected native build.

The base package is not a small pure-Python minifier. Its published dependencies include tiktoken, Pydantic, LiteLLM on Python <3.14, Click, Rich, OpenTelemetry API, ast-grep-cli, PyYAML and TOML helpers. The actual isolated Python 3.12 installation resolved 63 packages. No proxy, MCP, ML, image, code or memory extras were installed. [Release package configuration](https://github.com/headroomlabs-ai/headroom/blob/32d7ca4577d599b8a5f811ada74cf31504302c9d/pyproject.toml).

## Concrete API and acceptance boundary

The inspected method is:

```python
from headroom.transforms.content_router import ContentRouter
candidate = ContentRouter._minify_json_data_lossless(original_json)
```

No `ContentRouter` instance is needed. The [release implementation](https://github.com/headroomlabs-ai/headroom/blob/32d7ca4577d599b8a5f811ada74cf31504302c9d/headroom/transforms/content_router.py#L5756) parses a complete JSON object/array, serializes it with compact separators and Unicode enabled, and returns the result only if its character count is smaller. Otherwise it returns `None`. Malformed JSON can raise an exception. Plain text, an instruction-prefixed message or a top-level scalar is not a supported input. Apply it to the serialized evidence JSON, then retain the surrounding security instructions unchanged.

The scanner must enforce its own acceptance boundary:

1. Bound input and output bytes. Operate only on the scanner's already structured, redacted payload.
2. Strictly reject duplicate object keys, nonfinite numeric values and malformed/trailing JSON.
3. Accept only a string candidate whose UTF-8 byte length is no greater than the original and whose complete typed JSON structure equals the original. Canonical strict serialization distinguishes `true`, `1` and `1.0`; ordinary Python equality alone does not.
4. Preserve list ordering, all keys, all scalar values and exact string contents. Citation whitespace, negation, control IDs and untrusted instructions embedded in source remain data, unchanged.
5. On missing dependency, version drift, exceptions, `None`, inflation or evidence mismatch, retain the original or independently compact it locally and report the fallback accurately.

The upstream helper alone accepts duplicate-key input and Python's non-standard `NaN`/`Infinity`; the isolated proof reproduced those behaviors. It does not implement the scanner's stricter trust boundary. Parsed-data preservation also differs from preserving original JSON whitespace or numeric token spelling: source code and citations belong inside strings, where their exact content must remain unchanged.

## Why the public compression pipeline is unsuitable here

The public [`compress()` / `CompressConfig`](https://github.com/headroomlabs-ai/headroom/blob/32d7ca4577d599b8a5f811ada74cf31504302c9d/headroom/compress.py) does not expose a `lossless` field. Unknown keyword arguments are ignored; `compress(..., lossless=True)` therefore does not enforce losslessness. The standard pipeline routes content through SmartCrusher, code compression and potentially Kompress, with broader behavior than evidence-preserving JSON formatting.

`ContentRouterConfig(lossless=True)` exists in the lower-level router, but its general compression path applies format folds rather than this JSON-minification helper. It is not a reliable JSON formatting API. `SmartCrusher(lossless_only=True, compaction_format="json")` can produce a different compact structured representation requiring interpretation or reconstruction; that is not the scanner's requirement that `json.loads(original) == json.loads(output)`. The private static minifier avoids creating those components. [Router dispatch](https://github.com/headroomlabs-ai/headroom/blob/32d7ca4577d599b8a5f811ada74cf31504302c9d/headroom/transforms/content_router.py#L3204), [SmartCrusher implementation](https://github.com/headroomlabs-ai/headroom/blob/32d7ca4577d599b8a5f811ada74cf31504302c9d/headroom/transforms/smart_crusher.py#L254).

Package import still loads Headroom's native `headroom._core` extension. Its [`_ort` import helper](https://github.com/headroomlabs-ai/headroom/blob/32d7ca4577d599b8a5f811ada74cf31504302c9d/headroom/_ort.py) can set process-local `ORT_DYLIB_PATH` when an ONNX Runtime installation already exists. No model download occurs in this helper. This narrow API reduces runtime behavior, but it is not an assertion that the package has no native code or import effects.

## Actual isolated SDK proof

The verified wheel and its base dependencies were installed into a separate Python 3.12.14 environment on macOS ARM64. Installation used wheels only. The subsequent operation ran under an OS-level deny-network sandbox and a Python audit guard rejecting socket and child-process operations. It imported the actual installed SDK, then invoked only the static helper.

Results:

- **1,002 synthetic round trips** preserved strict typed canonical JSON, including Unicode, booleans/null/numbers, control IDs, citation whitespace, negation and hostile instruction strings.
- **20 real blinded review payloads** preserved every parsed value. Their aggregate size changed from **543,505 to 307,466 UTF-8 bytes**, a **43.43% byte reduction** from the stored pretty-printed payload files.
- Compact JSON, instruction-prefixed text and top-level scalar inputs correctly produced no candidate. Duplicate-key and nonfinite-number examples demonstrated the need for independent rejection.
- **Zero network attempts and zero child-process attempts** were observed during import and operation. No Torch, ONNX Runtime, Transformers, LiteLLM, Hugging Face Hub or tiktoken module was imported. The native Headroom core was imported. Observed imports ranged from approximately 76 to 120ms across these proof runs on this machine.

A follow-up using the actual legacy one-space request serialization measured **5.76% HTTP evidence-byte reduction** and **5.58% CLI evidence-byte reduction** on the same twenty payloads. See the [published production-payload proof](../benchmarks/token-optimization-v011/README.md) and [per-payload receipts](../benchmarks/token-optimization-v011/payload-wire-proof.json). These are byte and equality measurements, not provider token counts, monetary savings, model-quality measurements or a cross-platform guarantee. The comparison used stored indented payloads; it does not imply the same savings for an already compact production request. No LLM request was made by this proof and no provider configuration was changed.

Published receipts and reproducible scripts are in [benchmarks/token-optimization-v011](../benchmarks/token-optimization-v011/README.md). They retain exact package versions and source/payload hashes without publishing evidence text. The original local proof also retained `tmp/headroom-private-helper.txt` and its exact source hash. The proof command was:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/sandbox-exec \
  -p '(version 1)(allow default)(deny network*)' \
  tmp/headroom-proof-venv/bin/python tmp/prove_headroom_sdk.py
```

This macOS-specific proof is intentionally separate from a portable production implementation. A missing compatible optional package must not prevent deterministic scanning or remove the scanner's local evidence-preserving fallback.
