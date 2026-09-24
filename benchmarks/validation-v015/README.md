# Invarune 0.15 validation

These are actual final-code validation results, recorded on 23 September 2026. The final implementation SHA-256 is `02c1a309226db622fe6ab86ae72b3c652e370d2faae3876b7ec64049d8f5e1c5`. The [test receipt](test-receipt.json) binds the local suite, coverage, quickstart, review roundtrip and wheel-content checks to their exact evidence.

| Validation | Actual result | Evidence and scope |
| --- | --- | --- |
| Full regression suite | **1,016 passed**, zero failures/errors/skips, Python **3.12.14** on macOS | [Test receipt](test-receipt.json); finite implementation tests, not exhaustive security scenarios |
| Parent-process coverage | **94.57% statements**, **89.82% branches**, **92.97% combined** | [Coverage data](coverage.json); 9,123/9,647 statements and 4,410/4,910 branches; subprocess execution is tested separately and not measured by this configuration |
| Fresh installed quickstart | **63 steps passed** in a fresh local clone and virtual environment | [Executed steps](../quickstart-v015/README.md); current worktree inputs explicitly overlaid, installed commands invoked outside checkout |
| Local gateway integration | **72 actual HTTP requests**, six protocols, real **Headroom 0.37.0** | [Quickstart receipt](../quickstart-v015/receipt.json); fixture responses, zero real-model calls; exact original payload/evidence preserved |
| Five-format review roundtrip | **12 actual installed-CLI scans**: two initial scans and ten fresh review imports | [Receipt](report-review-receipt.json); HTML, Markdown, JSON, SARIF and PDF for inert source and image fixtures; no target/container execution |
| Final wheel contents | All **40 package files** match checkout byte-for-byte: 35 Python modules and five data files | [Package receipt](wheel-content-receipt.json); no missing/extra package files; local wheel verification, not a downloaded-release claim |
| SARIF schema | **28 files passed** the hash-pinned OASIS SARIF 2.1.0 Errata 01 schema | [Schema receipt](sarif-receipt.json); three current examples, eight pinned-project reports, three earlier examples and fourteen local review-workflow artifacts |
| Security controlbook | **123 pages**; 47 rule contracts, 66 controls, 132 checks and 78 sources | [Controlbook QA](controlbook-receipt.json); complete text/links, all pages visually inspected and repeat build byte-identical |

The final wheel SHA-256 is `7ef8f2fbd269c48a8cd3d0e17efc8de80f9ea66d820a4a9c3c33d81cbad60941`. The quickstart's captured package snapshot and every roundtrip report use the final implementation above. The roundtrip artifacts remain local with their hashes in the public receipt; those additional generated PDFs are not published or represented as visually reviewed.

The final suite includes two additional benchmark-publication integrity tests that preserve the original blind result, distinguish its presentation-only repeat, and reject a hidden detector edit. The [earlier 1,014-test receipt](earlier-tests-1014.json) and [earlier coverage](earlier-coverage-1014.json) remain unchanged. The full suite and coverage were rerun after those tests were added; unchanged installed quickstart and roundtrip receipts were retained. SARIF schema validation reads existing reports without network access or target execution; it does not establish every semantic SARIF requirement or compatibility with every consumer.

The quickstart verifies `invscan`, `invarune` and `ai-security-scan`, detailed help, offline inventory/explanations, exact selections, source/image/skill scans, terminal-only behavior, review exceptions, real PDF field edits and fresh rescans. Authentication and live model behavior require separate evidence. This macOS run does not claim Windows, Linux or another Python version passed; executed CI receipts are published separately when available.

The [strict documentation-build receipt](site-build-receipt.json) records **224 HTML pages, 116,635 checked local links and 685 byte-preserved artifacts** for its recorded site snapshot. The [publication audit](publication-audit.json) identifies its exact **279-file** indexed input manifest, collected before the final small validation-receipt/documentation additions. Its two native Gitleaks observations were verified file-checksum false positives; host-home-pattern matches were zero, and reserved fixture addresses/decorator syntax were reviewed separately. These are bounded, recorded checks of that manifest, not a claim that every later file was audited or that all sensitive content can be ruled out.

New regression scenarios cover registered tool inputs, argument/return propagation, function aliases and shadowing, exact literal guards, finite-map mutations/escapes, lazy execution, recursive and resource-bounded gaps, narrow JavaScript wrappers, explicit world-writable modes, schema descriptions, instruction composition and supported handler effects. Optional-review tests exercise snapshot-only range requests, exact citations, counterevidence requirements, request denials, shared budgets, conclusion-call reservation, authentication retries and unchanged deterministic results. See the [scenario matrix](../../docs/TEST_MATRIX.md) and [algorithm guide](../../docs/developer/detection-algorithms.md) for scope and limitations.

The final HTML/PDF summary change exposes advisory outcomes near the beginning of reports. Earlier successful validation against presentation candidate `525747fc453830a4bc93b887c21161ff44c21212af1a525bbd5a9d615086954b` is retained unchanged in [earlier quickstart](earlier-quickstart-525.json), [earlier coverage](earlier-coverage-525.json) and [earlier roundtrip](earlier-report-review-525.json) receipts. These are provenance, not substitutes for the final reruns above.

Reproduce from the trusted checkout with the QA dependencies installed:

```sh
python -m coverage run --branch --source=ai_security_scan -m unittest discover -s tests -v
python -m coverage json -o test-output/coverage.json
python scripts/validate_quickstart.py --output test-output/quickstart
python scripts/validate_report_review.py --command /absolute/path/to/installed/invscan --output /new/empty/directory
```

Passing these checks does not establish zero false positives/negatives, production vulnerability ground truth, live provider accuracy, deployed control effectiveness or a universal scanner ranking. Benchmark outcomes and live review results keep their own denominators and provenance.
