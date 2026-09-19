# Building and reviewing the NimeshBuild controlbook

The canonical catalogs live in `ai_security_scan/data/controls.json` and `ai_security_scan/data/sources.json`. The PDF, Markdown checklist, and source map use these same inputs. The source registry preserves publisher links, dates, scope, limitations, and thematic mapping notes. It does not bundle third-party standards or benchmark data.

## Rebuild

The scanner itself needs only Python's standard library. PDF authoring is separate:

```sh
python3 -m pip install -r requirements-pdf.txt
python3 scripts/sync_control_docs.py
python3 scripts/build_controlbook.py
```

The output is `output/pdf/nimeshbuild-agent-mcp-security-controlbook.pdf`. The builder uses available Arial, Liberation Sans, or DejaVu Sans fonts and falls back to PDF-standard Helvetica. Font choice can affect layout; inspect the result on the build system. The visual identity is a NimeshBuild wordmark and original vector motif created for this publication; no third-party logos are reproduced.

The optional pinned authoring dependencies are a reproducible starting point, not a claim that those versions are the latest or universally appropriate. Review and update them for your build environment. The shipped PDF was generated using the bundled workspace runtime; exact runtime versions are recorded in `docs/PDF_VALIDATION.md`.

## Verify the artifact

1. Run `python3 -m unittest discover -s tests -v` for scanner and adapter regressions.
2. Run `python3 scripts/verify_controlbook.py` for catalog references and PDF text/link checks.
3. Render **every page** with Poppler: `pdftoppm -r 100 -png output/pdf/nimeshbuild-agent-mcp-security-controlbook.pdf tmp/pdfs/page`.
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
