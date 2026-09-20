# Invarune 0.12 validation evidence

This release adds an offline deterministic security explorer. It does not change the detector rules, existing controls/source mappings, benchmark scores or report rendering.

- **793 tests passed** on Python 3.12.14 with optional PDF packages. Python 3.9.6 passed the same suite with **28 explicit optional-PDF skips** and no failures/errors.
- Parent-process coverage: **7,104/7,501 statements (94.71%)**, **3,249/3,620 branches (89.75%)**, **93.09% combined**, no exclusions. This is implementation execution coverage, not detection accuracy.
- **53 actual quickstart steps passed** in a fresh clone and virtual environment. Ten new steps exercise installed topic/question/control/check/source explanations, readable output, source metadata and an honest no-match response. Existing source/image, edited-PDF import and six-protocol loopback workflows still pass.
- **28 new core/integration tests** cover all 66 control explanations, 132 check identities, 42 rule references and 75 exact source records/backlinks. They check mutation isolation, finite/Unicode input bounds, explicit mode conflicts, offline side-effect guards, byte repeatability, preserved legacy JSON and lexical lookup regressions. The combined 56 catalog/explorer/usability tests passed on Python 3.9 and 3.12.
- **Seven actual installed-wheel example commands** ran twice with identical output, outside the checkout. All three CLI names produced the same structured question answer. No optional package or model was required for the explorer.
- Complete help contains **59 public option spellings and 50 command examples**. An independent documentation audit executed 26 documented catalog commands and eight error/no-match cases with scan/config/network/process hooks disabled.

Search tests found and verified corrections for authentication-versus-authorization ranking, generic benchmark discovery, unknown identifier handling and uppercase hyphenated topic names. They are finite regression cases, not a claim that lexical lookup understands every possible question. Unsupported vocabulary can return no match; query results are not scan findings or a safety verdict.

[Unit/coverage/wheel receipt](test-receipt.json) · [53-step quickstart](../quickstart-v012/README.md) · [installed explorer receipt](explorer-receipt.json) · [actual outputs](../../examples/security-explorer/README.md) · [explorer guide](../../docs/SECURITY_EXPLORER.md).

Reproduce tests with `python3 -m unittest discover -s tests -v`; reproduce installed workflows with `python3 scripts/validate_quickstart.py`. Those are developer validation commands; users inspect and scan through `invscan` after installation. No live model request, provider sign-in, target application execution or new research benchmark run was part of this feature validation.
