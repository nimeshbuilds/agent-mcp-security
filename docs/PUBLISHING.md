# Building the documentation site and publications

**Invarune by NimeshBuild** - Evidence for agent security.

## Documentation website

The searchable [GitHub Pages site](https://nimeshbuilds.github.io/agent-mcp-security/) uses MkDocs 1.6.1 and Material 9.7.7. It includes user guides, developer documentation, source mapping, benchmark receipts and all seven checked-in PDF publications/reports. Search runs in the browser. The site does not call a model, run scans, collect review form submissions or require a login. Operational HTML reports retain their local export behavior; download a report before editing it for your own review.

The repository Markdown remains canonical. `scripts/prepare_docs.py` stages **Git-indexed files** from explicit documentation/evidence directories and a narrow set of file extensions. It never copies the workspace wholesale. `tmp/`, virtual environments, `.git/`, private configuration and local scan outputs are not selected. Symlinks are rejected. Original PDF/JSON/HTML evidence is copied byte-for-byte; Markdown links to source code outside the site are adapted to GitHub. The public [artifact manifest](https://nimeshbuilds.github.io/agent-mcp-security/publication-manifest.json) records source paths and hashes.

### Build and preview locally

Use a separate authoring environment with **Python 3.12**. This environment is independent of the scanner's supported Python 3.9+ installation.

```sh
python3.12 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r requirements-docs.txt

# Add new documentation/artifacts to the Git index before staging the site.
# Use explicit paths; do not add local reports or private files by accident.
git add docs/my-new-guide.md

python scripts/prepare_docs.py
python -m mkdocs build --strict
python scripts/verify_docs_site.py --receipt site/site-validation.json
python -m mkdocs serve
```

The `git add` line is an example for a new guide: omit it when rebuilding an existing checkout, and replace the path with the actual new file when authoring. On Windows, create the environment with `py -3.12 -m venv .venv-docs` and use `.venv-docs\Scripts\python.exe` for the Python commands. Add navigation entries in `mkdocs.yml`. After editing original Markdown, run `prepare_docs.py` again before previewing; the server reads the staged copy. Open `http://127.0.0.1:8000/agent-mcp-security/`.

The validation step checks rendered internal links and fragment anchors, required entry pages, a nonempty search index, and every verbatim download against the manifest. Strict MkDocs validation also rejects broken Markdown links and anchors. The build needs package installation/network access initially; subsequent builds use installed tooling and local inputs. External source websites are linked, not mirrored, and can change independently.

`requirements-docs.in` pins the two authoring applications; `requirements-docs.txt` pins their resolved dependencies. To refresh the lock intentionally, use `uv pip compile requirements-docs.in --python-version 3.12 --output-file requirements-docs.txt`, inspect the changes and repeat build/visual validation. These packages are never core scanner dependencies.

### Deployment and recovery

[The documentation workflow](../.github/workflows/docs.yml) builds and validates pull requests with read-only repository permissions. Pushes to `main` and manual runs on `main` upload the verified `site/` artifact and deploy through GitHub's `github-pages` environment. Only the deploy job receives `pages: write` and `id-token: write`; all actions are pinned to commit SHAs. No `gh-pages` branch, personal access token or custom web server is needed.

GitHub repository **Settings → Pages → Build and deployment → Source** must be **GitHub Actions**. The repository is public with the owner's authorization. Public visibility is separate from licensing; [the publication notice](../NOTICE.md) still applies. The workflow follows [GitHub's custom Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages) and [MkDocs' validation configuration](https://www.mkdocs.org/user-guide/configuration/#validation).

If deployment fails, inspect the `Invarune documentation` workflow run. Fix the missing indexed file, broken link or changed artifact that caused validation to fail and push the correction. Do not disable strict validation. For a successful build with a deployment failure, check Pages configuration and the `github-pages` environment, then rerun the failed job. To restore an older document state, revert the relevant documentation commit through normal review and let the workflow republish it; do not regenerate old benchmark measurements under a new label.

Before changing PDFs, follow the rendering procedure below. Merely publishing an existing verified PDF does not change its measurement date, implementation fingerprint or validation scope.

The canonical catalogs live in `ai_security_scan/data/controls.json` and `ai_security_scan/data/sources.json`. The PDF, Markdown checklist, and source map use these same inputs. The source registry preserves publisher links, dates, scope, limitations, and thematic mapping notes. It does not bundle third-party standards or benchmark data.

## Rebuild

The scanner itself needs only Python's standard library. PDF authoring is separate:

```sh
python3 -m pip install -r requirements-pdf.txt
python3 scripts/sync_control_docs.py
python3 scripts/build_controlbook.py
python3 scripts/build_benchmark_report.py
```

The output is `output/pdf/invarune-security-controlbook.pdf`. The builder uses available Arial, Liberation Sans, or DejaVu Sans fonts and falls back to PDF-standard Helvetica. Font choice can affect layout; inspect the result on the build system. The Invarune wordmark and original geometric symbol use the same geometry and palette as the repository's brand assets. NimeshBuild remains the publisher attribution. No third-party logos are reproduced.

The optional pinned authoring dependencies are a reproducible starting point, not a claim that those versions are the latest or universally appropriate. Review and update them for your build environment. The shipped PDF was generated using the bundled workspace runtime; exact runtime versions are recorded in `docs/PDF_VALIDATION.md`.

## Verify the artifact

The second builder creates `output/pdf/invarune-benchmark-report.pdf` from the checked-in public-project and external-tool receipts. It does not rerun scanners or contact a model. Reproduce the underlying executions using [the public-project runner](../benchmarks/real-world/README.md) and [external-tool instructions](../benchmarks/external-tools/README.md) before publishing results for a changed scanner or corpus. Do not reuse old receipts under a new version label. Render every page of this PDF as well; its detailed Markdown counterpart is [the comparative evaluation](BENCHMARK_RESULTS.md).

1. Run `python3 -m unittest discover -s tests -v` for scanner and adapter regressions.
2. Run `python3 scripts/verify_controlbook.py` for catalog references and PDF text/link checks.
3. Render **every page** with Poppler: `pdftoppm -r 100 -png output/pdf/invarune-security-controlbook.pdf tmp/pdfs/page`.
4. Inspect layout, typography, control cards, links, and source entries. The builder raises on known page/card overflows, but rendering is still required after content or font changes.
5. Regenerate fixture reports after catalog or scanner changes so their control inventory and implementation fingerprints agree with the shipped version.

The PDF keeps the original engineering checks distinct from external requirements. Its citations are context and thematic alignments unless a reviewed section is explicitly identified in the source map. Release-page-only reviews, draft publications, and gated full benchmarks stay visibly qualified. Research benchmark names in the guide do not imply that their code was executed.

## Repository contents

- `scan.py`, `ai_security_scan/`: scanner and optional judge.
- `docs/`: research, checklist, provenance, API guide, and validation evidence.
- `output/pdf/`: final branded handbook.
- `examples/`: deliberately vulnerable and safer fixtures, judge configurations, and sample reports.
- `scripts/`: reproducible document generation and verification.
- `tests/`: offline/mocked tests and local HTTP integration tests.

Generated scratch data, render QA sheets, runtime logs, credentials, and private configuration are excluded. No external publication PDFs or benchmark datasets are redistributed.

## Operational PDF and editable reports (v0.9.0)

Install the optional PDF extra and use `--pdf` on a source/image scan to generate `report.pdf` alongside HTML, Markdown, JSON and SARIF. Each operational format supports explicit `--review-report` import on a fresh selected target. The controlbook and comparative benchmark PDF are explanatory publications and do not carry scan-specific editable capsules. See [review workflow](REVIEW_WORKFLOW.md) for field limits and edit/save instructions.

## Finding-by-finding comparison (0.10)

Validate its frozen/current ledger and review bindings with `python3 scripts/build_finding_comparison_report.py --validate-only`. Generate the branded PDF with `python3 scripts/build_finding_comparison_report.py --output output/pdf/invarune-finding-comparison-v010.pdf` using the authoring ReportLab environment. This never scans a target or invokes a model. The current comparison preserves the failed Claude attempt and explicitly unknown TP rate. Render and visually inspect all pages after edits; [the current QA receipt](../benchmarks/validation-v010/pdf-receipt.json) is tied to exact artifact hashes.
