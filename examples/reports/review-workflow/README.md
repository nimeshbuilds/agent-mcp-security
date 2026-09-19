# Actual five-format review roundtrips

These are **v0.9.0 installed-CLI test results**, generated on 2026-09-19 from the shipped inert source and image fixtures. No target application, container or model was run. The justifications explicitly describe regression fixtures; they validate no production safeguard.

| Target | Initial open | Final open | Justified findings | Active checks | Justified checks | Exit |
|---|---:|---:|---:|---:|---:|---:|
| Source fixture | 11 | 10 | 1 | 131 | 1 | 1 |
| Image fixture | 3 | 2 | 1 | 131 | 1 | 1 |

Two initial scans generated all five formats. Ten more actual CLI scans imported a reviewed **HTML, Markdown, JSON, SARIF or PDF** for each target. Every case applied exactly one finding justification and one check justification, retained the original evidence/severity, and kept the remaining high findings actionable. The result contains **justified**, never a verified pass. The PDF input was filled and saved with pypdf, updating real AcroForm fields and appearances; this is not a claim that every viewer was tested.

- [Initial source report](source/initial/report.html)
- [Reviewed source HTML input](source/reviewed.html), [Markdown input](source/reviewed.md), [JSON input](source/reviewed.json), [SARIF input](source/reviewed.sarif), [PDF input](source/reviewed.pdf)
- [Final source report](source/final-pdf/report.html), [fillable final PDF](source/final-pdf/report.pdf), [final JSON audit](source/final-pdf/report.json)
- [Final image report](image/final-pdf/report.html), [final image JSON audit](image/final-pdf/report.json)
- [Execution receipt for all 12 scans](receipt.json)

The receipt records tool fingerprints, initial/final scan identities, exact input hashes, output hashes, summaries and review counts. The repository retains the source inputs, four initial source formats, all five final source formats and four final image formats as a representative subset. Reproduction generates every artifact named in the receipt.

From a checkout with the optional PDF extra installed:

```sh
python3 scripts/validate_report_review.py --output ./test-output/my-review-validation
```

To exercise an installed package outside the source checkout, provide `--command /absolute/path/to/invarune`. Use a new/empty output directory. The script performs 12 bounded fixture scans; it makes no provider calls. Artifact bytes can differ with the Python/PDF-library version while the validated decision semantics remain the same.

To use the published reviewed input directly with the matching scanner/source version:

```sh
invarune examples/vulnerable --review-report examples/reports/review-workflow/source/reviewed.pdf --pdf --output ./scan-report/review-replay
```

Scanner/catalog/scope changes can correctly make stored decisions stale. Regenerate and re-review rather than copying old bindings. See the [workflow guide](../../../docs/REVIEW_WORKFLOW.md) for fields, limits and runtime follow-ups.
