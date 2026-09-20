# Executed quickstart validation

Status: **passed**. Scanner: **0.13.0**. Python: **3.12.14**.

[Machine-readable receipt](receipt.json) includes sanitized commands, exit codes, asserted fixture counts, report hashes, source snapshot and package versions.

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
| installed_security_topics | 0 | passed |
| installed_security_question | 0 | passed |
| installed_control_explanation | 0 | passed |
| installed_check_explanation | 0 | passed |
| installed_source_registry | 0 | passed |
| installed_source_explanation | 0 | passed |
| installed_security_help | 0 | passed |
| installed_security_question_text | 0 | passed |
| installed_rule_explanation_text | 0 | passed |
| installed_unknown_security_question | 0 | passed |
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
