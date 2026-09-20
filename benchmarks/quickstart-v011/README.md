# Executed quickstart validation

Status: **passed**. Scanner: **0.11.0**. Python: **3.12.14**.

[Machine-readable receipt](receipt.json) includes sanitized commands, exit codes, asserted fixture counts, report hashes, source snapshot and package versions.

All **43 steps passed**, including all three installed CLI aliases (`invscan`, `invarune`, `ai-security-scan`), source/image PDF edit-and-rescan workflows, baseline acceptance, and six local gateway adapters. The **72 gateway requests** used installed **Headroom 0.37.0**; captured JSON matched each original-input digest, and transmitted source excerpts exactly matched recorded evidence. These are local fixture responses, not real model judgments.

All **19 scan summaries** record production implementation SHA-256 `993d77b77bac8f0f4758ce931da596ce03eb31a36a4fec4302efb2da601ffb80`. The **156-file** source snapshot has aggregate SHA-256 `42cdf742c910b9bd53e5fe97601e0f232930782ebd59a565121f801fcd3b2b36`; all recorded file hashes matched the release worktree at post-run verification. Receipt SHA-256: `151fde8d50867d68fc5de5852c2f69064bbd3fc724e22c3db538892c306c29e9`. Host paths in commands and output are replaced with placeholders.

The validator uses a new local Git clone with the explicit current-worktree project inputs overlaid, creates a new virtual environment, and executes the documented source/image/exception commands. Installed aliases run outside the checkout. Enabled PDF checks use real form editing and a fresh scan. Gateway checks use loopback fixture responses, never a real model. Login and live provider capability are separate validation work.

| Step | Exit | Result |
|---|---:|---|
| source_git_revision | 0 | passed |
| source_git_state | 0 | passed |
| fresh_clone | 0 | passed |
| create_venv | 0 | passed |
| install_checkout | 0 | passed |
| installed_versions | 0 | passed |
| installed_primary_h | 0 | passed |
| installed_primary_help | 0 | passed |
| installed_primary_safer | 0 | passed |
| installed_compatible_h | 0 | passed |
| installed_compatible_help | 0 | passed |
| installed_compatible_safer | 0 | passed |
| installed_legacy_h | 0 | passed |
| installed_legacy_help | 0 | passed |
| installed_legacy_safer | 0 | passed |
| installed_version | 0 | passed |
| installed_image_help | 0 | passed |
| installed_gateway_help | 0 | passed |
| installed_examples | 0 | passed |
| installed_rules | 0 | passed |
| installed_controls | 0 | passed |
| installed_rule_explanation | 0 | passed |
| installed_vulnerable | 1 | passed |
| installed_review_config | 1 | passed |
| installed_baseline_candidate | 1 | passed |
| installed_baseline_accepted | 0 | passed |
| direct_compatibility_safer | 0 | passed |
| installed_image | 1 | passed |
| install_ai_pdf_extras | 0 | passed |
| pdf_dependency_versions | 0 | passed |
| pdf_source_initial | 1 | passed |
| pdf_source_form_edit | 0 | passed |
| pdf_source_fresh_import | 1 | passed |
| pdf_image_initial | 1 | passed |
| pdf_image_form_edit | 0 | passed |
| pdf_image_fresh_import | 1 | passed |
| ai_dependency_versions | 0 | passed |
| gateway_custom | 0 | passed |
| gateway_openai_chat | 0 | passed |
| gateway_openai_responses | 0 | passed |
| gateway_anthropic | 0 | passed |
| gateway_gemini | 0 | passed |
| gateway_ollama | 0 | passed |

Rerun from this checkout:

```sh
python3 scripts/validate_quickstart.py --output test-output/quickstart
```

Installation can download Python build/PDF packages. `--skip-pdf` and `--skip-gateway` record explicit skipped coverage. The receipt never claims Windows or live provider validation merely from a macOS/Linux run.
