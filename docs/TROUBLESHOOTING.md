# Troubleshooting invscan

Start with `invscan --version`, `invscan --help` and the relevant `invscan --help-topic` section. The supported topics include `quickstart`, `source`, `images`, `reports`, `review`, `baseline`, `ai`, `login`, `gateways`, `limits`, `exit-codes`, `catalog` and `security`.

## Ask without an agent or login

`invscan --ask` reads bundled JSON reference data using a deterministic token/alias lookup. It does not start an AI agent, load your provider configuration, scan a target, access the network or require model credentials.

```sh
invscan --list-topics
invscan --ask 'prompt injection'
invscan --explain-control AUTH-01
invscan --explain-check AUTH-01:1
invscan --explain-source MITRE-ATLAS
```

Use topic terms or exact identifiers if a question has no match. Queries are bounded to 1,000 characters and at most eight ranked results. A no-match response is not a security finding. Catalog options cannot be mixed with a scan target, AI configuration, login or output options. [Full lookup behavior](SECURITY_EXPLORER.md).

## Installation and command discovery

| Symptom | What to do |
|---|---|
| `invscan: command not found` | Activate the environment where you installed the package, or call `.venv/bin/invscan` (Windows: `.venv\Scripts\invscan.exe`). Follow the [quick start](QUICKSTART.md). |
| `No module named ...` while generating a PDF | Install the PDF extra in the same environment: `python -m pip install '.[pdf]'` from the checkout. The base CLI does not include PDF packages. |
| Wrong version after an upgrade | Run the environment's executable directly and check its version; a second installation may appear earlier on `PATH`. |
| Clone fails | Use `https://github.com/nimeshbuilds/invarune.git`. The public repository needs no GitHub login to clone; check network, proxy and Git configuration. |

## Exit codes are part of the result

| Code | Meaning | Next step |
|---|---|---|
| `0` | No open finding meets the configured threshold within the selected completed scope. | Read coverage and unassessed controls. This is not certification. |
| `1` | Findings meet the threshold (high/critical by default). | Open the report's immediate concerns and remediation sections. Fix or explicitly review the applicable items. |
| `2` | Input/operational failure, incomplete scan, export problem, pending/stale imported review, or incomplete requested AI review. | Read diagnostics and any report produced. Correct the cause and rerun. |

`--fail-on none` disables the findings threshold only; it does not suppress incomplete work. Do not wrap every invocation with an unconditional shell success override in CI. [Report interpretation](REPORTS.md).

## Image scans

Use a Docker **save** archive or an OCI image-layout archive. A container filesystem from `docker export` is not the same format. Archive inspection does not need a daemon; `--image` needs the selected Docker/Podman runtime. A remote pull requires `--pull` explicitly.

No container is started. Compiled-only images cannot provide source-level application logic; image metadata and visible files are all the scanner can inspect. OS/package CVEs need a complementary image/dependency scanner. Do not treat fewer findings in a stripped image as evidence of fewer vulnerabilities. [Image support and limits](IMAGE_SCANNING.md).

## Optional AI, authentication and gateways

Both model stages remain off unless `--judge-cli` or `--judge-config` enables them. A requested AI stage that cannot authenticate does not silently become a successful review. Existing deterministic findings are retained where reports can be produced.

Use the [provider guide](JUDGE.md) for supported official CLI binaries, the integrated login path, API protocols, environment-variable keys and custom gateway URLs. Subscription access and model availability belong to the provider and account; a local CLI installation alone does not establish entitlement.

Headroom is enabled by default only when AI review is enabled. The optional `ai` extra installs the pinned integration on supported Python versions. Missing/unsupported Headroom uses the recorded built-in compaction fallback. Reported byte savings are not a measured token-price saving. [Headroom research and receipts](HEADROOM_RESEARCH.md).

If AI review reaches a time, evidence or item budget, inspect the report's explicit coverage and unanswered items. Increase the relevant documented limit only after checking the scope and expected cost. Do not infer full coverage from a partially completed model answer.

## An edited report is rejected or remains pending

Keep the original report binding fields and edit only supported review inputs. Import the saved file with `--review-report` while selecting the target for a **fresh scan**. A changed target, fingerprint or finding can invalidate an earlier justification. PDF forms must be saved without flattening; HTML inputs must be exported using the report's save action, not merely typed into a browser tab.

Justifications are user attestations and are reported as **justified**, excluded from the applicable scored denominator. They are not verified passes. Benchmark/controlbook PDFs are explanatory publications, not editable operational review reports. [Format-specific workflow](REVIEW_WORKFLOW.md) · [PDF instructions](PDF_REVIEW.md).

## Reporting a defect

Include the CLI version, operating system, exact options with credentials removed, exit code and a minimal reproducible fixture. Describe whether the result is a missed finding, false positive, incorrect coverage, report problem or provider failure. Do not post customer code, access tokens or private report evidence in a public issue. [Developer workflow](../CONTRIBUTING.md).
