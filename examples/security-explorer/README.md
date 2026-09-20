# Actual installed security-explorer examples

These are outputs from **Invarune 0.12.0's installed `invscan` wheel**, run outside the checkout in a fresh Python environment. Every command ran twice with identical output; all three CLI aliases produced identical prompt-injection JSON. No target was scanned and no model review was enabled.

| Actual command | Saved output |
| --- | --- |
| `invscan --list-topics` | [All nine topics and 66 controls](topics.txt) |
| `invscan --ask 'What do you check for prompt injection?'` | [Readable answer](prompt-injection.txt) |
| Same question with `--catalog-format json` | [Structured answer](prompt-injection.json) |
| `invscan --explain-control AUTH-01` | [Authentication control](authentication.txt) |
| `invscan --explain-check AUTH-02:2` | [Authorization acceptance check](authorization-check.txt) |
| `invscan --explain-source MITRE-ATLAS` | [MITRE source and exact mappings](mitre-atlas.txt) |
| `invscan --ask benchmarks` | [Benchmark source matches](benchmarks.txt) |

The explorer explains bundled controls and source relationships. A mapped rule is partial static coverage; it does not prove the whole control or any individual acceptance check. These outputs are catalog lookups, not a security assessment or evidence that the referenced benchmarks were executed. Source versions, dates and limitations remain the recorded research snapshot.

[Executed receipt and hashes](../../benchmarks/validation-v012/explorer-receipt.json) · [Explorer guide](../../docs/SECURITY_EXPLORER.md) · [Quickstart](../../docs/QUICKSTART.md).
