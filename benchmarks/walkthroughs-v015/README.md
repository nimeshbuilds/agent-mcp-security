# Guided walkthrough validation — Invarune 0.15.0

The [walkthrough overview](../../docs/SCENARIOS.md) now links to ten task pages and a shared setup guide. Each action has its own copyable command and expected result. Optional variants use expandable sections. This is a documentation/interface change; scanner code, release packages and detector benchmarks are unchanged.

## Installed command validation

The [fresh execution receipt](receipt.json) records **all 10 scenarios / 59 command steps passing** with a newly installed CLI outside its source checkout. It binds the exact hub, setup and ten walkthrough files to the execution snapshot. The manifest commands remain identical to the previous scenario guide; their layout and reading order changed.

The scripted API lab made **17 local HTTP requests through six adapters**, including one bounded evidence follow-up, with actual Headroom. The runner exercised source, skills, saved images, CI gates, baseline/exception handling, five report formats, stale reviews and incomplete-review outcomes. It made **zero real model calls or account logins** and did not execute target programs or containers. Live provider and runtime alternatives retain their explicit prerequisites.

**14 focused tests passed.** New checks reject missing, duplicate, unknown, malformed, moved and changed command blocks, and verify that all 12 guide files match the execution snapshot. Existing command generation and fixture tests remain covered.

## Browser and site checks

The [browser review receipt](browser-review.json) records real Chrome checks of overview navigation, step cards, copy-button feedback, expandable options, mobile layout and the dark palette. Long commands wrap without adding line breaks to the underlying command text. Mobile checks used a 390 × 844 viewport override; the page's measured content width was 375 pixels, with no horizontal overflow.

The browser automation's virtual clipboard did not expose the native copy operation's bytes; the receipt therefore records the visible copied confirmation and exact DOM source text, not a verified clipboard round trip. No new live-provider or report-editor compatibility claim is made by this UI review. The [previous actual HTML edit/download/import test](../scenarios-v015/html-ui-receipt.json) remains separate evidence for the report editor.

The strict site build verifies internal links and anchors and requires every walkthrough page to exist. The default page and command content remain readable without custom JavaScript; the theme supplies command copying and platform tabs.

## Reproduce

From a prepared source workspace:

```sh
python scripts/validate_scenarios.py --check-docs-only
```

Run the installed command matrix using a new output directory:

```sh
python scripts/validate_scenarios.py --output test-output/walkthroughs
```

The command matrix is also executed on Linux and Windows by the existing CI workflow. A configured CI job is not by itself evidence that an individual run passed; inspect the [current test runs](https://github.com/nimeshbuilds/invarune/actions/workflows/tests.yml).
