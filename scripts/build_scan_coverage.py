#!/usr/bin/env python3
"""Generate the complete user-facing executable scan/control matrix offline."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ai_security_scan.scan_catalog import describe_scans

B = chr(96)


def code(text):
    return B + text + B


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def source_links(sources):
    return "; ".join("[" + str(source.get("id") or "Technical reference") + "](" + source["url"] + ") (" +
                     str(source.get("organization") or "primary documentation") + "; " + source["relationship"].replace("_", " ") + ")"
                     for source in sources)


def document():
    data = describe_scans()
    counts = data["counts"]
    # The narrative is maintained separately; all rule/control inventories below
    # are generated from the bundled APIs consumed by the installed CLI.
    intro = (ROOT / "scripts/templates/scan_coverage_intro.md").read_text(encoding="utf-8")
    intro = intro.replace("{{RULE_COUNT}}", str(counts["scans"])).replace("{{CONTROL_COUNT}}", str(counts["controls"]))
    intro = intro.replace("{{CHECK_COUNT}}", str(counts["acceptance_checks"])).replace("{{RULESET_VERSION}}", data["ruleset_version"])
    lines = [intro.rstrip(), "", "## Supported analysis algorithms and their limits", "",
             "| Profile | Deterministic boundary |", "| --- | --- |"]
    for key, limit in data["algorithm_limits"].items():
        lines.append("| " + code(key) + " | " + cell(limit) + " |")
    lines += ["", "Selected files must be supported UTF-8 text (BOM accepted). Source scans skip configured exclusions and dependency/build/cache directories by default; image scans intentionally include packaged dependency/build content. "
              "Unreadable files, invalid supported syntax and exhausted budgets remain coverage gaps. Unknown file types are outside selected source coverage. "
              "No dependency installation, target imports, build commands, target network probes, CVE-feed calls, decompilation, publisher-signature verification or runtime execution is implied. "
              "Run " + code("invscan --help-topic source") + " for the live file-extension inventory and " + code("invscan --help-topic limits") + " for every budget.", "",
              "## All deterministic scans", "",
              "Each entry gives its supported predicate, algorithm, blind spots, mapped controls and technical/provenance references. "
              "References do not mean Invarune executes every external benchmark or has an official certification.", "",
              "| ID | Scan | Severity | Profiles | Mapped controls |", "| --- | --- | --- | --- | --- |"]
    for scan in data["scans"]:
        lines.append("| [" + scan["id"] + "](#" + scan["id"].lower() + ") | " + cell(scan["title"]) + " | " + scan["severity"] + " | " +
                     ", ".join(code(key) for key in scan["deterministic"]["analysis_profiles"]) + " | " +
                     (", ".join(item["id"] for item in scan["controls"]) or "none") + " |")
    for scan in data["scans"]:
        lines += ["", "### " + scan["id"], "", "**" + scan["title"] + "** · " + scan["severity"] + " · " + code(scan["category"]), "",
                  "**Looks for:** " + scan["what_it_detects"], "", "**Why it matters for agents/MCP/skills:** " + scan["why_it_matters"], "",
                  "**Deterministic algorithm:** " + scan["deterministic"]["algorithm"] + ". Profiles: " + ", ".join(code(profile) for profile in scan["deterministic"]["analysis_profiles"]) + ".", "",
                  "**Can miss or require context:** " + scan["deterministic"]["limits"], "",
                  "**Image context:** " + ", ".join(code(context) for context in scan["image_contexts"]) + ". Packaged-file analysis still needs the supported source/descriptor form.", "",
                  "**Optional AI adds:** " + scan["optional_ai_review"]["finding_triage"] + " " + scan["optional_ai_review"]["broader_review"], "",
                  "**Fix direction:** " + scan["remediation"], "",
                  "**Partial control mapping:** " + (", ".join("[" + item["id"] + "](#" + item["id"].lower() + ")" for item in scan["controls"]) or "none") + ".", "",
                  "**Source organizations and relationships:** " + source_links(scan["sources"]) + ".", "",
                  B * 3 + "sh", scan["commands"]["explain"], scan["commands"]["select"], B * 3]
    lines += ["", "## All control review plans", "",
              "These %d controls and %d acceptance checks are the broader scope reviewed in full optional mode, subject to selection, explicit exceptions and budgets. "
              "%d controls have at least one mapped deterministic pattern. Each rule is partial control-level coverage; it does not prove either acceptance check is automated. "
              "Controls with no mapped rules remain visible. Exact primary and thematic source roles are preserved below." %
              (counts["controls"], counts["acceptance_checks"], counts["partially_mapped_controls"]), ""]
    for control in data["controls"]:
        review = control["optional_ai_review"]
        lines += ["### " + control["id"], "", "**" + control["title"] + "** · " + control["category"] + " · validation: " + code(control["validation"]), "",
                  control["what_it_is"], "", "**Why it matters:** " + control["why_it_matters"], "",
                  "**Deterministic:** " + ("Partial rules " + ", ".join("[" + key + "](#" + key.lower() + ")" for key in control["automated_rule_ids"]) + "." if control["automated_rule_ids"] else "No mapped detector; retain the human/runtime review requirement."), "",
                  "**Optional AI review:** " + review["review_plan"] + " Code support is reported as " + code(review["code_support_normalized_to"].split(" (")[0]) + "; this never establishes a validated pass.", "",
                  "**Acceptance checks:**", ""]
        lines += ["- **" + check["id"] + ":** " + check["text"] for check in control["checks"]]
        lines += ["", "**Sources:** " + source_links(control["sources"]) + ".", "",
                  B * 3 + "sh", "invscan --explain-scan " + control["id"], control["scan_selection"]["command"] + " --judge-cli claude", B * 3, ""]
    lines += ["## Evidence, validation and maintaining this inventory", "",
              "These algorithms describe implemented predicates, not a guarantee of zero false positives or false negatives. "
              "Use [measured accuracy and unresolved cases](RULE_ACCURACY.md), [the public benchmark dashboard](BENCHMARK_DASHBOARD.md) and [test evidence](VALIDATION.md) to assess their limits. "
              "Pinned benchmark artifacts keep their original version and inputs; a new detector is not retroactively credited in an old report.", "",
              "Developers: update [scan_catalog.py](../ai_security_scan/scan_catalog.py) when a rule's predicate or supported context changes, then run " + code("python scripts/build_scan_coverage.py") + ". "
              + code("python scripts/build_scan_coverage.py --check") + " rejects stale generated documentation. "
              "See [inventory and selection architecture](developer/scan-inventory.md).", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail on stale documentation; write nothing.")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/SCAN_COVERAGE.md", help="Destination coverage guide.")
    args = parser.parse_args()
    content = document()
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != content:
            parser.exit(1, "Scan coverage documentation is stale. Run python scripts/build_scan_coverage.py.\n")
        print("Scan coverage documentation is current.")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        print("Generated " + str(args.output))


if __name__ == "__main__":
    main()
