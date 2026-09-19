#!/usr/bin/env python3
"""Build a branded comparison PDF from actual checked-in scan receipts.

Authoring-only dependency: ReportLab. No network or target code execution.
"""
import hashlib
import html
import json
from pathlib import Path
import sys

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_controlbook import FONT, BOLD, clean

REPO = "https://github.com/nimeshbuilds/agent-mcp-security"
NAVY, TEAL, GREY = colors.HexColor("#0b1220"), colors.HexColor("#087e78"), colors.HexColor("#526276")
LIGHT, LINE = colors.HexColor("#f2f6fa"), colors.HexColor("#d8e2ed")
STYLE = {"body": ParagraphStyle("body", fontName=FONT, fontSize=10, leading=14, textColor=NAVY, spaceAfter=9),
         "small": ParagraphStyle("small", fontName=FONT, fontSize=8.2, leading=11, textColor=GREY, spaceAfter=6),
         "heading": ParagraphStyle("heading", fontName=BOLD, fontSize=22, leading=27, textColor=NAVY, spaceAfter=15),
         "sub": ParagraphStyle("sub", fontName=BOLD, fontSize=12, leading=16, textColor=TEAL, spaceBefore=9, spaceAfter=8),
         "cell": ParagraphStyle("cell", fontName=FONT, fontSize=8.5, leading=11, textColor=NAVY),
         "headcell": ParagraphStyle("headcell", fontName=BOLD, fontSize=8.5, leading=11, textColor=colors.white)}


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def p(text, kind="body"):
    return Paragraph(html.escape(clean(text)), STYLE[kind])


def link(label, url, kind="small"):
    return Paragraph('<link color="#087e78" href="' + html.escape(url, quote=True) + '">' + html.escape(clean(label)) + '</link>', STYLE[kind])


def table(rows, widths):
    cells = [[p(cell, "headcell" if i == 0 else "cell") for cell in row] for i, row in enumerate(rows)]
    result = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
    result.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 9), ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9), ("LINEBELOW", (0, -1), (-1, -1), .6, LINE)]))
    return result


def frame(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 800, 595.276, 42, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont(BOLD, 10)
    canvas.drawString(44, 816, "INVARUNE  /  NIMESHBUILD")
    canvas.setFont(FONT, 8)
    canvas.setFillColor(GREY)
    canvas.drawString(44, 28, "Evidence for agent security  |  Research edition: September 2026")
    canvas.drawRightString(550, 28, str(doc.page))
    canvas.restoreState()


def main():
    manifest = read("benchmarks/real-world/manifest.json")
    external = read("benchmarks/external-tools/results/summary.json")
    shared = read("benchmarks/external-tools/results/shared-pattern-fixtures.json")
    lock = read("benchmarks/external-tools/tool-lock.json")
    receipts = {project["id"]: read("benchmarks/real-world/receipts/" + project["id"] + ".json") for project in manifest["projects"]}
    versions = {r["tool"]["version"] for r in receipts.values()}
    implementations = {r["tool"]["implementation_sha256"] for r in receipts.values()}
    if len(versions) != 1 or len(implementations) != 1:
        raise ValueError("Real-project receipts must use one frozen scanner implementation")
    total = sum(r["summary"]["open_findings"] for r in receipts.values())
    gaps = sum(r["summary"]["coverage_gaps"] for r in receipts.values())
    version = next(iter(versions))
    story = [Spacer(1, 26), Image(str(ROOT / "docs/assets/brand/invarune-mark.png"), width=76, height=76, hAlign="LEFT"),
             Spacer(1, 20), p("Security scanning, tested.", "heading"),
             p("Real agent and MCP projects. Reproducible results. Explicit limits.", "sub"),
             p("Invarune " + version + " | Comparative research report | 19 September 2026", "small"), Spacer(1, 18),
             table([["PUBLIC PROJECTS", "INVARUNE PATTERNS", "COVERAGE GAPS"], [str(len(receipts)), str(total), str(gaps)]], [169, 169, 169]),
             Spacer(1, 19), p("What this evaluation establishes", "sub"),
             p("We actually ran Invarune, Semgrep CE, Bandit and Gitleaks against the same selected source bytes from eight public projects at pinned commits. Cisco MCP Scanner ran a separate offline YARA test on 14 literal tool descriptions. No target application or MCP server was executed."),
             p("The real-project counts are a review workload, not confirmed vulnerabilities or precision/recall estimates. Manual inspection found false positives and deployment-dependent capabilities. Coverage failures stay visible."),
             p("A separate ten-case development fixture comparison exercises five shared API-level patterns with positive and negative examples. It is intentionally small and cannot identify a universal winner."),
             link("Repository, detailed reports and reproduction scripts", REPO), PageBreak(),
             p("01 / Observed findings", "heading"),
             p("The same source export was offered to every tool. Supported languages, enabled rules and definitions of a finding differ. A larger or smaller count is not a quality ranking.")]
    rows = [["Project", "Invarune", "Semgrep", "Bandit", "Gitleaks"]]
    for project in external["projects"]:
        own = receipts[project["id"]]
        items = {x["tool"]: x for x in project["tools"]}
        row = [project["id"], str(own["summary"]["open_findings"]) + (" *" if own["summary"]["coverage_gaps"] else "")]
        for tool in ("semgrep", "bandit", "gitleaks"):
            item = items[tool]
            row.append("N/A" if item["finding_count"] is None else str(item["finding_count"]) + (" *" if item["errors"] else ""))
        rows.append(row)
    story += [table(rows, [143, 91, 91, 91, 91]), Spacer(1, 12),
              p("* Analysis gaps or parser errors are present. N/A means no supported Python files for Bandit; it is not a clean result. Source-only scans do not establish deployed behavior, full framework coverage or exploitability.", "small"),
              p("Scope and timing", "sub"),
              p("First-party implementation and package/runtime configuration were selected before results were inspected. Tests, docs, examples, vendored/generated directories and non-code assets were excluded uniformly. Each receipt records exact file hashes, options, elapsed time, tool exit status and analysis scope. Timings are single-host observations, not a controlled performance benchmark."),
              link("Pinned corpus, project scope and licenses", REPO + "/tree/main/benchmarks/real-world"),
              link("Full per-project reports: HTML, Markdown, JSON and SARIF", REPO + "/tree/main/examples/reports/real-world"), PageBreak(),
              p("02 / What each tool tested", "heading")]
    story.append(table([["Tool / version", "Executed scope", "Interpretation"],
        ["Invarune " + version, "42 source/configuration rules; control mapping and coverage evidence", "Selected static signals. Whole-program behavior and runtime controls remain open."],
        ["Semgrep CE " + lock["semgrep"]["version"], "Frozen p/security-audit pack; 225 rules; metrics off", "CE and this pack only. Not Semgrep's commercial engine or a complete rule portfolio."],
        ["Bandit " + lock["bandit"]["version"], "All packaged Python plugins; no severity/confidence filter", "Includes capability/import warnings; different finding granularity from Invarune."],
        ["Gitleaks " + lock["gitleaks"]["version"], "Packaged secret rules; selected source tree; fully redacted", "No Git-history scan, credential validity check or general SAST."],
        ["Cisco MCP Scanner " + lock["cisco-mcp-scanner"]["version"], "YARA only on 14 literal filesystem-tool descriptions", "0 matches; partial metadata only. No real tools/list capture, behavioral or LLM analysis."],
        ["Snyk Agent Scan", "Researched; not executed", "Its normal MCP discovery starts configured servers and uses a cloud analysis token. Not a source-only equivalent."]], [115, 198, 194]))
    story += [Spacer(1, 12), p("The shortlist covers complementary source analysis, secret detection and MCP metadata inspection. It is a researched, practical sample of established tools, not an exhaustive market survey or an independently adjudicated 'best scanner' award."),
              link("Tool provenance, exact rule-pack hash, methodology and restrictions", REPO + "/tree/main/benchmarks/external-tools"), PageBreak(),
              p("03 / Review findings in context", "heading"),
              p("The corpus was visible during development. These observations led to narrow detector corrections before the final scan; the original findings and scanner fingerprints remain in the initial triage record."),
              table([["Observed pattern", "Manual interpretation / response"],
                ["CrewAI PEM marker in an API docstring", "False positive: marker followed by an ellipsis, no key body. The detector now requires plausible encoded material."],
                ["Pydantic AI dummy SDK API keys", "False positives: exact documented placeholder sentinels. Those sentinels are excluded; real credentials remain in scope."],
                ["OpenHands Dockerfile USER root", "Build setup later switches to a nonroot runtime user. Final-stage USER tracking removes this misleading runtime signal."],
                ["LangGraph composed SQL", "One reviewed call uses parameterized values and a fixed-predicate helper. Local composition detection cannot establish that whole call chain; review remains required."],
                ["AutoGen dynamic Python config loading", "An intentional execution capability with an upstream trusted-config warning. It requires a provenance/authorization boundary; no external exploit was demonstrated."],
                ["CrewAI environment/provider labels", "Credential-named dictionary keys can map to display labels. This context-sensitive false-positive class remains documented."]], [185, 322]),
              Spacer(1, 12), p("Immediate review priorities", "sub"),
              p("Validate actual input provenance for dynamic execution and deserialization. Review secret-like values without disclosing them. Resolve parser/work-budget gaps before relying on clean subsets. Check deployed authorization, tool permissions and network exposure independently."),
              p("Mitigating layers include isolated execution, least-privilege credentials, per-tool authorization, constrained egress, approval for sensitive actions and monitoring. These are proposed defenses, not observed protections or automatic severity reductions."),
              link("Pinned source links and original finding evidence", REPO + "/blob/main/benchmarks/real-world/TRIAGE.md"), PageBreak(),
              p("04 / Shared-pattern checks", "heading"),
              p("Ten existing, project-authored development fixtures: eval, subprocess shell=True, unsafe YAML loading, pickle loading and disabled TLS verification, each paired with a negative example. Only the explicitly mapped rule is scored; unrelated import/capability warnings do not become false positives for that assertion.")]
    score_rows = [["Tool", "True positive", "True negative", "False positive", "False negative"]]
    for tool in ("invarune", "semgrep", "bandit"):
        counts = shared["results"][tool]["counts"]
        score_rows.append([tool, *[str(counts[x]) for x in ("true_positive", "true_negative", "false_positive", "false_negative")]])
    story += [table(score_rows, [119, 97, 97, 97, 97]), Spacer(1, 14),
              p("These cases demonstrate bounded compatibility on five selected API patterns. They do not establish production accuracy, broad language coverage, resistance to adversarial code or agent prompt-injection behavior. Gitleaks, Cisco metadata YARA and unexecuted tools receive no artificial true negatives."),
              p("Separate Invarune accuracy corpus", "sub"),
              p("The repository also publishes a larger 109-assertion source-pattern corpus with unresolved false positives and false negatives. A versioned PEM fixture update accompanies the narrower key-material rule; the original corpus and results are retained so the change is auditable."),
              link("Shared cases, rule mappings and every result", REPO + "/blob/main/benchmarks/external-tools/results/shared-pattern-fixtures.json"),
              link("Larger Invarune accuracy report and known limitations", REPO + "/blob/main/docs/RULE_ACCURACY.md"),
              p("Optional model review", "sub"),
              p("Deterministic scanning remains the default. Optional API/gateway or official CLI review adds advisory assessments only. Invarune selects Astra, Opus and Grok Build defaults, validates IDs and exact evidence quotes, and keeps model advice separate from findings and CI gates. Interactive login happens through the official CLI and resumes within the scan."),
              link("Dated live CLI validation receipts and limitations", REPO + "/blob/main/docs/CLI_PROVIDER_RESEARCH.md"), PageBreak(),
              p("05 / Reproduce and inspect", "heading"),
              p("Every project is pinned to a full commit in the manifest. The exporter reads Git blobs without checking out or executing target scripts; it verifies the exported file manifest before scans. Reruns reject modified or unexpected files. Detailed source licenses and exclusions accompany each project.")]
    for project in manifest["projects"]:
        story.append(link(project["id"] + " / " + project["revision"], project["repository"] + "/tree/" + project["revision"]))
    story += [Spacer(1, 9), p("Reproduction entry points", "sub"),
              p("Use scripts/scan_public_projects.py --help for explicit fetch/export/scan/repeat options. Use scripts/benchmark_competitors.py --help with separately installed pinned tools and the verified Semgrep rule pack. Exact commands, tool distributions, source hashes and normalized output are published; private raw logs are excluded.", "small"),
              p("The Semgrep rule pack is not redistributed. Its recorded URL and SHA-256 identify the artifact used; if the upstream pack changes, do not silently replace it and call the run identical.", "small"),
              p("Scanner implementation SHA-256: " + next(iter(implementations)), "small"),
              p("Corpus manifest SHA-256: " + hashlib.sha256((ROOT / "benchmarks/real-world/manifest.json").read_bytes()).hexdigest(), "small"),
              link("Source runner and complete reproducibility instructions", REPO + "/blob/main/benchmarks/real-world/README.md"),
              link("External-tool reproduction commands and primary sources", REPO + "/blob/main/benchmarks/external-tools/README.md"),
              link("Controlbook: 66 controls, 132 checks, 75 primary references", REPO + "/blob/main/output/pdf/invarune-security-controlbook.pdf"),
              p("Publication scope", "sub"),
              p("This report is published in the existing NimeshBuild repository. It does not certify the scanned projects, establish an exploit, claim endorsement by a vendor or standards body, or assert universal scanner/model superiority.", "small")]
    output = ROOT / "output/pdf/invarune-benchmark-report.pdf"
    output.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(str(output), pagesize=(595.276, 841.89), topMargin=70, bottomMargin=50,
        leftMargin=44, rightMargin=44, title="Invarune | Real-world scanner benchmark report", author="NimeshBuild")
    document.build(story, onFirstPage=frame, onLaterPages=frame)
    print(output)


if __name__ == "__main__":
    main()
