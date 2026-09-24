#!/usr/bin/env python3
"""Build the Invarune controlbook from the same catalog used by the scanner.

Requires ReportLab. No web requests or target-code execution. Use --output to
choose a destination. Source URLs are clickable throughout the PDF.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
import html
import json
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

ROOT = Path(__file__).resolve().parents[1]
W, H = 595.276, 841.89
M = 45
CW = W - 2 * M
NAVY = colors.HexColor("#0B1220")
INK = colors.HexColor("#243247")
TEAL = colors.HexColor("#087E78")
MINT = colors.HexColor("#35E3B1")
PAPER = colors.HexColor("#F2F6FA")
GREY = colors.HexColor("#526276")
LINE = colors.HexColor("#D8E2ED")
WHITE = colors.white


def clean(value):
    return str(value).translate(str.maketrans({"\u2011": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u00a0": " "}))


def esc(value):
    return html.escape(clean(value), quote=True)


def fonts():
    candidates = [Path("/System/Library/Fonts/Supplemental"), Path("/usr/share/fonts/truetype/liberation2"), Path("/usr/share/fonts/truetype/dejavu")]
    for folder in candidates:
        for normal, bold in [("Arial.ttf", "Arial Bold.ttf"), ("LiberationSans-Regular.ttf", "LiberationSans-Bold.ttf"), ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf")]:
            if (folder / normal).exists() and (folder / bold).exists():
                pdfmetrics.registerFont(TTFont("NB", str(folder / normal)))
                pdfmetrics.registerFont(TTFont("NB-Bold", str(folder / bold)))
                pdfmetrics.registerFontFamily("NB", normal="NB", bold="NB-Bold", italic="NB", boldItalic="NB-Bold")
                return "NB", "NB-Bold"
    return "Helvetica", "Helvetica-Bold"


FONT, BOLD = fonts()


class Book:
    def __init__(self, output, controls, sources, rules):
        self.controls, self.sources, self.rules = controls, sources, rules
        from ai_security_scan import __version__
        from ai_security_scan.scan_catalog import describe_scans
        self.version = __version__
        self.scan_catalog = describe_scans()
        self.scans = self.scan_catalog["scans"]
        self.by_url = {s["url"]: s for s in sources}
        self.by_id = {s["id"]: s for s in sources}
        self.canvas = canvas.Canvas(str(output), pagesize=(W, H), pageCompression=1, invariant=1)
        self.canvas.setTitle("Invarune | Agent, MCP & Skill Security Controlbook")
        self.canvas.setAuthor("NimeshBuild")
        self.canvas.setSubject("Source-linked controls, deterministic algorithms, optional review and validation for agents, MCP servers and skills")
        self.canvas.setCreator("Invarune by NimeshBuild / ReportLab")
        self.page = 0
        self.page_map = []
        self.specs = []
        self.groups = OrderedDict()
        for control in controls:
            self.groups.setdefault(control["category"], []).append(control)
        self.plan()

    def text(self, value, x, y, size=10, color=INK, bold=False):
        c = self.canvas
        c.setFillColor(color)
        c.setFont(BOLD if bold else FONT, size)
        c.drawString(x, y, clean(value))

    def para(self, value, x, top, width, size=10, leading=None, color=INK, bold=False):
        style = ParagraphStyle("p", fontName=BOLD if bold else FONT, fontSize=size, leading=leading or size * 1.4, textColor=color, alignment=TA_LEFT, spaceAfter=0, splitLongWords=True)
        paragraph = Paragraph(value, style)
        _, height = paragraph.wrap(width, H)
        if top - height < 43:
            raise ValueError(f"Page {self.page}: content overflows page: {value[:90]}")
        paragraph.drawOn(self.canvas, x, top - height)
        return top - height

    def mark(self, x, y, scale=1, light=False):
        """Draw the original Invarune mark using the brand SVG's 64-unit geometry."""
        c = self.canvas
        unit = 30 * scale / 64
        shapes = [
            ([(26, 4), (8, 14), (8, 50), (26, 60), (26, 47), (19, 43), (19, 21), (26, 17)], PAPER if light else NAVY),
            ([(38, 4), (56, 14), (56, 50), (38, 60), (38, 47), (45, 43), (45, 21), (38, 17)], MINT if light else TEAL),
            ([(32, 22), (42, 32), (32, 42), (22, 32)], MINT if light else TEAL),
        ]
        for points, fill in shapes:
            c.setFillColor(fill)
            path = c.beginPath()
            path.moveTo(x + points[0][0] * unit, y + (64 - points[0][1]) * unit)
            for px, py in points[1:]:
                path.lineTo(x + px * unit, y + (64 - py) * unit)
            path.close()
            c.drawPath(path, fill=1, stroke=0)
        self.text("Invarune", x + 39 * scale, y + 13 * scale, 20 * scale, PAPER if light else NAVY, True)
        self.text("by NimeshBuild", x + 40 * scale, y + 2 * scale, 7.5 * scale, MINT if light else TEAL)

    def start(self, section, title, subtitle=None):
        self.page += 1
        self.canvas.setFillColor(PAPER)
        self.canvas.rect(0, 0, W, H, fill=1, stroke=0)
        self.mark(M, H - 49, .76)
        self.text("SECURITY ENGINEERING / 2026.09", 319, H - 43, 7.4, GREY)
        self.canvas.setStrokeColor(LINE)
        self.canvas.line(M, H - 65, W - M, H - 65)
        self.text(section.upper(), M, H - 92, 8.4, TEAL, True)
        y = self.para(esc(title), M, H - 108, CW, 26, 30, NAVY, True)
        if subtitle:
            y = self.para(esc(subtitle), M, y - 12, CW, 9.6, 14, GREY)
        self.canvas.bookmarkPage("page-%s" % self.page)
        self.canvas.addOutlineEntry(clean(title), "page-%s" % self.page, level=0, closed=False)
        self.page_map.append({"page": self.page, "section": section, "title": title})
        return y - 24

    def end(self):
        c = self.canvas
        c.setStrokeColor(LINE)
        c.line(M, 45, W - M, 45)
        self.text("Invarune by NimeshBuild  /  Source-linked controls  /  23 Sep 2026", M, 29, 7.2, GREY)
        c.setFillColor(TEAL)
        c.setFont(BOLD, 9)
        c.drawRightString(W - M, 28, f"{self.page:02d} / {len(self.specs):02d}")
        c.showPage()

    def plan(self):
        from ai_security_scan.methodology import build_methodology
        self.methodology = build_methodology({"controls": self.controls})
        self.specs = [("cover", None), ("contents", None), ("guide", None), ("sources", None), ("workflow", None)]
        # Bounded batches prevent a growing methodology from silently putting
        # every remaining area on its last page. All destinations derive from
        # this final plan, never hardcoded page numbers.
        for index in range(0, len(self.methodology["areas"]), 2):
            self.specs.append(("coverage", self.methodology["areas"][index:index + 2]))
        self.specs += [("configuration", None), ("quickstart", None), ("scoring", None), ("review_flow", None), ("analyst", None)]
        benchmarks = [s for s in self.sources if "benchmark" in s.get("kind", "").lower() and not any(word in s.get("organization", "").lower() for word in ("cis", "center for internet"))]
        for i in range(0, len(benchmarks), 3):
            self.specs.append(("benchmarks", benchmarks[i:i + 3]))
        self.category_pages = {}
        for category, controls in self.groups.items():
            self.category_pages[category] = len(self.specs) + 1
            for i in range(0, len(controls), 2):
                self.specs.append(("controls", (category, controls[i:i + 2])))
        self.rule_start = len(self.specs) + 1
        for i in range(0, len(self.rules), 14):
            self.specs.append(("rules", self.rules[i:i + 14]))
        self.rule_detail_start = len(self.specs) + 1
        self.rule_pages = {}
        for rule in self.scans:
            self.rule_pages[rule["id"]] = len(self.specs) + 1
            self.specs.append(("rule_detail", rule))
        self.ref_start = len(self.specs) + 1
        for i in range(0, len(self.sources), 4):
            self.specs.append(("references", self.sources[i:i + 4]))
        self.first_page = {}
        for page, (kind, _) in enumerate(self.specs, 1):
            self.first_page.setdefault(kind, page)

    def contents(self, _):
        y = self.start("Navigation", "Contents", "Click a row or use the PDF bookmarks to move through the complete source-linked controlbook.")
        labels = {"guide": "Reading guide and assurance labels", "sources": "Source landscape", "workflow": "Security review workflow",
                  "configuration": "Scan configuration and optional review", "quickstart": "CLI examples and selected scans",
                  "scoring": "Transparent metrics and score calculation", "review_flow": "Human review and evidence-bound import",
                  "analyst": "Controlled security analyst", "benchmarks": "Benchmarks and attack suites"}
        entries = []
        for page, (kind, content) in enumerate(self.specs, 1):
            if kind == "coverage":
                entries.append(("Coverage: " + " / ".join(area["area"].split(",")[0] for area in content), page))
            elif kind in labels and page == self.first_page[kind]:
                entries.append((labels[kind], page))
        entries += [(category, page) for category, page in self.category_pages.items()]
        entries += [(str(len(self.rules)) + "-rule clickable inventory", self.rule_start),
                    ("Every scan: algorithm, limits, fixes and source mapping", self.rule_detail_start), ("Full primary-source directory", self.ref_start)]
        spacing = min(26, (y - 66) / len(entries))
        for label, page in entries:
            self.text(label, M, y, 8.4, INK)
            self.canvas.setFont(BOLD, 9.5)
            self.canvas.setFillColor(TEAL)
            self.canvas.drawRightString(W - M, y, str(page))
            self.canvas.linkRect("", "page-%s" % page, (M, y - 6, W - M, y + 13), relative=0, thickness=0)
            self.canvas.setStrokeColor(LINE)
            self.canvas.line(M, y - 9, W - M, y - 9)
            y -= spacing
        self.end()

    def coverage(self, areas):
        y = self.start("Method coverage", "What each layer can establish", "Real catalog counts and explicit blind spots. Mapping is not accuracy, compliance, or percent secure.")
        catalog = self.methodology["catalog"]
        if areas[0] == self.methodology["areas"][0]:
            for label, number in [("Controls with static rule mappings", catalog["statically_mapped_controls"]),
                                  ("Controls without static rule mappings", catalog["controls_without_static_mapping"])]:
                self.text(label, M, y, 8.7, INK)
                self.canvas.setFillColor(LINE)
                self.canvas.rect(M + 236, y - 2, 215, 11, fill=1, stroke=0)
                self.canvas.setFillColor(TEAL)
                self.canvas.rect(M + 236, y - 2, 215 * number / max(catalog["controls"], 1), 11, fill=1, stroke=0)
                self.text(str(number), W - M - 28, y, 9, TEAL, True)
                y -= 25
            y -= 13
        for area in areas:
            y = self.para(esc(area["area"]), M, y, CW, 16, 20, NAVY, True) - 9
            for label, key in [("DETERMINISTIC", "deterministic"), ("OPTIONAL ANALYST", "optional_review"),
                               ("CAN MISS OR MISCLASSIFY", "can_miss_or_misclassify"), ("VALIDATE ELSEWHERE", "runtime_or_human_validation")]:
                y = self.para("<b>" + label + ":</b> " + esc(area[key]), M, y, CW, 8.7, 12.3) - 8
            y -= 14
        self.end()

    def configuration(self, _):
        y = self.start("Configuration", "Choose the evidence, then the limits", "The default scan is offline and deterministic. Optional review and PDF dependencies are selected explicitly.")
        rows = [("TARGET", "Source directory, local Docker/Podman image reference, or Docker-save/OCI archive. No target program or container is started."),
                ("BOUNDS + EXCLUSIONS", "Declare file/byte/entry/image limits and exclusions. Unsupported syntax, truncated evidence and exhausted budgets remain visible gaps."),
                ("DETERMINISTIC OUTPUT", "Without --report/--output, results stay in the terminal. --report [DIR] or --output DIR saves HTML, Markdown, JSON and SARIF without LLM credentials; --pdf adds an interactive PDF."),
                ("OPTIONAL ANALYST", "Select an API/custom gateway configuration or the official Codex, Claude Code or Grok Build CLI. Review can be full-control or findings-only, with explicit call/time/evidence bounds."),
                ("USER DISPOSITIONS", "--review-config applies explicit rule/control/check exceptions. --review-report imports edited report fields into a fresh scan. Neither is automatically loaded from the target."),
                ("EXIT + ASSURANCE", "The findings threshold is a policy gate, not a security grade. Operational gaps and required human/runtime validation remain incomplete. Justified is distinct from pass.")]
        for title, body in rows:
            self.canvas.setFillColor(WHITE)
            self.canvas.roundRect(M, y - 68, CW, 68, 5, fill=1, stroke=0)
            self.text(title, M + 12, y - 18, 8.6, TEAL, True)
            self.para(esc(body), M + 12, y - 27, CW - 24, 8.7, 12.2)
            y -= 80
        self.end()

    def quickstart(self, _):
        y = self.start("CLI field guide", "Choose exactly what to inspect", "The invscan command works without an LLM. Inventory, explanations and control mappings are bundled for offline use.")
        rows = [
            ("DISCOVER", "invscan --list-scans", "List all deterministic rules and control review plans. Use --catalog-format json for automation and --help-topic all for the complete CLI guide."),
            ("UNDERSTAND", "invscan --explain-scan AI043", "Show the predicate, algorithm, applicability, limits, remediation, mapped controls and source relationships for a rule. Control IDs work too."),
            ("TERMINAL ONLY", "invscan ./my-agent", "Inspect supported source/configuration, agent instructions and skills. Without a report flag, no report directory is written."),
            ("SELECT SCANS", "invscan ./my-agent --scans AI001,AI043 --scans MCP-03", "Rule IDs select their patterns and mapped control review; control IDs select their mapped rules/checks. Shared parsing and integrity gaps remain visible."),
            ("WRITE REPORTS", "invscan ./my-agent --report ./results --pdf", "Save HTML, Markdown, JSON, SARIF and optional fillable PDF. PDF needs the pdf extra; deterministic output needs no model credentials."),
            ("IMAGE + OPTIONAL REVIEW", "invscan --image-archive ./agent.tar --judge-cli claude", "Inspect a supported archive without starting the container. Optional full review uses bounded evidence; missing packaged source and unresolved runtime behavior stay unknown."),
        ]
        for label, command, detail in rows:
            self.text(label, M, y, 8.4, TEAL, True)
            y = self.para(esc(command), M, y - 9, CW, 10, 14, NAVY, True)
            y = self.para(esc(detail), M, y - 7, CW, 8.8, 12.4) - 22
        self.para("A control with no mapped detector remains explicitly unvalidated. --scans does not silently substitute all rules. --judge-mode findings narrows optional review to finding triage; full mode also reviews active selected checks, including zero-match and inconclusive evidence.", M, y, CW, 9, 12.6, GREY)
        self.end()

    def scoring(self, _):
        y = self.start("Interpretation", "Metrics, not a security grade", "A percentage can describe review coverage. It cannot establish the chance that an agent, server or skill is secure.")
        rows = [
            ("DETERMINISTIC ATTENTION", "Count open findings by severity; urgent = critical + high. No arbitrary severity weights or probability of compromise are assigned. The finding gate uses the configured severity threshold."),
            ("PARTIAL MAPPING REACH", "100 x active selected controls with at least one active selected mapped rule / active selected controls. This measures available partial rule coverage, not completed tests or passes."),
            ("OPTIONAL AI ANSWER COVERAGE", "100 x unique active selected acceptance checks with a valid received model answer / active selected acceptance checks. Concerns and explicit unknowns count as answers; synthesized omissions do not."),
            ("EMPTY SCOPE + EXCEPTIONS", "An empty denominator is null (not applicable), never 100%. Justified and disabled checks/rules are excluded from active denominators without positive or negative credit. Observed evidence and reasons remain visible."),
            ("AI DOES NOT ERASE EVIDENCE", "AI-disabled means zero answered checks. Enabling AI cannot lower recorded severity, erase a deterministic finding or change the deterministic severity gate. Runtime/human validation stays open; model code support is advisory."),
        ]
        for label, detail in rows:
            self.text(label, M, y, 8.6, TEAL, True)
            y = self.para(esc(detail), M, y - 11, CW, 9.5, 13.4) - 22
        mapped = self.scan_catalog['counts']['partially_mapped_controls']
        y = self.para("<b>Worked example using this catalog</b><br/>With every control selected and no exceptions: " + str(mapped) + "/" + str(len(self.controls)) + " = " + format(100 * mapped / len(self.controls), '.2f') + "% partial mapping reach. That is not a security score. If 3 of 6 active checks receive valid model answers, answer coverage is 50% even when every answer says runtime validation is required.", M, y, CW, 10, 14) - 22
        self.canvas.setFillColor(NAVY)
        self.canvas.roundRect(M, y - 82, CW, 82, 6, fill=1, stroke=0)
        self.para("<b>Read the final result in order</b><br/>1. Scope completion and coverage gaps. 2. Open critical/high concerns and fixes. 3. User exceptions and retained evidence. 4. Optional advice, actual answered checks and unknowns. 5. Required runtime/human validation. A clean pattern scan is never a validated pass.", M + 15, y - 12, CW - 30, 9.3, 13.4, WHITE)
        self.end()

    def review_flow(self, _):
        y = self.start("Human review", "From a report to an auditable decision", "Review fields carry evidence bindings. Edited reports cannot replay a target, command, gateway or model automatically.")
        steps = [("01", "SCAN", "Choose source/image and configuration. Collect static evidence and a bound review workspace."),
                 ("02", "REVIEW", "Inspect the finding or check. Run required human/runtime validation in the authorized environment."),
                 ("03", "RECORD", "Choose a decision. Record reason, reviewer, reviewed-at date and a reference to supporting evidence."),
                 ("04", "SAVE", "Save HTML/Markdown/JSON/SARIF review data or a compatible fillable PDF with current appearances."),
                 ("05", "IMPORT", "Run a fresh explicit target scan with --review-report. Origin, source, catalog and item bindings are rechecked."),
                 ("06", "RESOLVE", "Stale or invalid edits stay visible for re-review. Only valid, applicable decisions affect the result.")]
        for number, title, body in steps:
            self.canvas.setFillColor(TEAL)
            self.canvas.circle(M + 17, y - 23, 16, fill=1, stroke=0)
            self.text(number, M + 8, y - 26, 10, WHITE, True)
            self.text(title, M + 46, y - 10, 9.5, TEAL, True)
            self.para(esc(body), M + 46, y - 20, CW - 46, 9, 12.5)
            y -= 68
        y -= 3
        self.para("<b>Decision semantics:</b> justified/disabled require an accountable reviewer and reason; they are excluded from active denominators, never counted as passes. Notes do not waive findings. Runtime/human-validation decisions keep work outstanding. Coverage gaps cannot be waived. PDF canonical fields, widgets and appearance text must agree; ambiguous or flattened forms need JSON review instead.", M, y, CW, 9, 13)
        self.end()

    def cover(self, _):
        self.page += 1
        c = self.canvas
        c.setFillColor(NAVY)
        c.rect(0, 0, W, H, fill=1, stroke=0)
        # Evidence paths are original vector artwork, not copied brand assets.
        c.setStrokeColor(colors.HexColor("#203348"))
        for x in range(327, 650, 41):
            c.line(x, 0, x - 125, H)
        for y in range(100, 760, 70):
            c.line(325, y, W, y + 88)
        for x, y in [(439, 172), (516, 266), (412, 448), (543, 592)]:
            c.setFillColor(MINT)
            c.circle(x, y, 5, fill=1, stroke=0)
        self.mark(M - 7, H - 98, 2, True)
        self.text("SECURITY CONTROLBOOK  /  SCANNER " + self.version, M, H - 157, 9, MINT, True)
        y = H - 198
        for line in ("AI Agent", "& MCP", "Security"):
            self.text(line, M - 2, y - 47, 53, WHITE, True)
            y -= 61
        self.text("Evidence for agent security.", M, y - 43, 19, MINT, True)
        self.para("Agents, MCP servers, skills and built images.<br/>Source-linked controls for systems that reason and act.", M, y - 65, 420, 11, 16, colors.HexColor("#CFDCEB"))
        y = 280
        for x, value, label in [(M, len(self.controls), "CONTROLS"), (M + 170, sum(len(c["checks"]) for c in self.controls), "ACCEPTANCE CHECKS"), (M + 340, len(self.rules), "STATIC RULES")]:
            self.text(str(value), x, y, 34, MINT, True)
            self.text(label, x, y - 22, 7.9, WHITE, True)
        self.para("NSA + CISA  /  CSA  /  MITRE  /  NIST<br/>OWASP  /  MCP  /  CIS  /  standards + research benchmarks", M, 174, CW, 9.5, 17, colors.HexColor("#CFDCEB"))
        c.setStrokeColor(colors.HexColor("#40546E"))
        c.line(M, 92, W - M, 92)
        self.text("CONTROLS RESEARCH 19 SEP  /  DETECTOR UPDATE 23 SEP 2026", M, 69, 8.4, WHITE, True)
        self.text("github.com/nimeshbuilds/invarune", M, 50, 8, MINT)
        c.linkURL("https://github.com/nimeshbuilds/invarune", (M, 47, W - M, 63), relative=0)
        c.bookmarkPage("page-1")
        c.addOutlineEntry("Invarune controlbook / " + self.version, "page-1", level=0, closed=False)
        self.page_map.append({"page": self.page, "section": "Cover", "title": "Invarune | AI Agent & MCP Security"})
        c.showPage()

    def guide(self, _):
        y = self.start("01 / Reading guide", "From code patterns to assurance", "The Invarune catalog by NimeshBuild, with evidence requirements and a traceable source for every control.")
        y = self.para("Use this book to review agents, MCP clients and servers, gateways, tools, retrieval, memory, and the infrastructure that grants them authority. It is a synthesized engineering checklist, not a reproduction of every external framework or a certification claim.", M, y, CW, 11, 16)
        y -= 26
        self.text("FIND THE CONTROL YOU NEED", M, y, 8.5, TEAL, True)
        y -= 22
        for category, controls in self.groups.items():
            self.text(category, M, y, 10.3, INK, True)
            self.text(f"{len(controls):02d} controls", M + 332, y, 9, GREY)
            self.canvas.setFont(BOLD, 10)
            self.canvas.setFillColor(TEAL)
            self.canvas.drawRightString(W - M, y, str(self.category_pages[category]))
            self.canvas.linkRect("", "page-%s" % self.category_pages[category], (M, y - 5, W - M, y + 13), relative=0, thickness=0)
            self.canvas.setStrokeColor(LINE)
            self.canvas.line(M, y - 10, W - M, y - 10)
            y -= 29
        y -= 12
        y = self.para(f"<b>Controlled security analyst:</b> page {self.first_page['analyst']}<br/><b>Static-rule index:</b> page {self.rule_start} &nbsp; / &nbsp; <b>Full source directory:</b> page {self.ref_start}", M, y, CW, 9.5)
        y -= 23
        y = self.para("<b>Read the labels carefully.</b> A source link shows provenance or thematic alignment. It does not mean that every acceptance check is quoted from that source, or that a rule satisfies an entire external requirement. The applicability and limitations of each source appear in the directory.", M, y, CW, 9.8, 14)
        self.para("This controlbook is a reference, not a bound scan report. For editable findings and fresh-scan import, use the report created by invscan --report, then pass the edited artifact with --review-report.", M, y - 16, CW, 8.8, 12.4, GREY)
        self.end()

    def sources_page(self, _):
        y = self.start("02 / Source landscape", "Different sources. Different jobs.", "Combine guidance, control catalogs, protocol obligations, deployment baselines, and measured attack behavior.")
        rows = [
            ("NSA + CISA", "Government guidance", "Agent adoption, secure deployment, data protection, lifecycle practices, and incident readiness."),
            ("CSA", "AI + cloud controls", "AI Controls Matrix, MAESTRO threat modeling, cloud shared responsibility, and supplier evidence."),
            ("NIST", "Risk + secure development", "AI RMF, GenAI Profile, adversarial ML taxonomy, SSDF and its AI-specific profile."),
            ("MITRE ATLAS", "Threat knowledge base", "Attacker techniques and attack paths. Use to build scenarios; it is not an assurance score."),
            ("OWASP", "Risk + verification catalogs", "Agentic and LLM risks, MCP guidance, and AI security verification requirements."),
            ("MCP", "Protocol specification", "Version-sensitive transport, authorization, tool, sampling, elicitation, and trust requirements."),
            ("CIS", "Hardening benchmarks", "Agent/MCP companion guidance and configuration baselines for applicable server and deployment layers."),
            ("ISO / OpenSSF / SLSA", "Management + software integrity", "Governance context, project security practices, and build provenance. Applicability varies by artifact."),
            ("AIUC + research suites", "Assurance + experiments", "Additional agent-control context and executable attacks under explicit harness assumptions."),
        ]
        for name, kind, description in rows:
            self.canvas.setFillColor(WHITE)
            self.canvas.roundRect(M, y - 53, CW, 53, 5, fill=1, stroke=0)
            self.text(name, M + 12, y - 17, 10.2, NAVY, True)
            self.text(kind.upper(), M + 12, y - 34, 6.8, TEAL, True)
            self.para(esc(description), M + 191, y - 10, CW - 204, 8.8, 12, GREY)
            y -= 60
        self.para("This is a broad, curated landscape verified for this edition. No finite snapshot covers every publication or future benchmark. External catalogs retain their own scope, version, terms, and assessment procedures.", M, y - 7, CW, 8.8, 12.5, GREY)
        self.end()

    def workflow(self, _):
        y = self.start("03 / Validation method", "Make every decision reviewable", "Keep deterministic signals, runtime evidence, human assessment, and LLM opinions separate.")
        blocks = [
            ("1", "Scope the system", "Record agent/server identity, tools, model and gateway versions, MCP revision, data classes, deployment, and who can influence each input. Include downstream side effects and credentials."),
            ("2", "Run the static scan", "The CLI offers " + str(len(self.rules)) + " deterministic rules; --scans selects rules or controls. Keep findings, evidence, severity, confidence, remediation, exceptions, and coverage gaps. An absent pattern is not a passed control."),
            ("3", "Test the effective boundary", "Use isolated deployments, synthetic credentials, explicit canaries, and safe effect sinks. Verify identities, tenant boundaries, approvals, egress, cancellation, quotas, and audit records."),
            ("4", "Measure attacks and useful work", "Pin the benchmark, model, tools, settings, and attack budget. Report unauthorized actions and data leakage alongside benign task completion, false blocking, sample size, and repeated attempts."),
            ("5", "Record a human disposition", "Retain owner, scope, evidence and review date. Report decisions are justified, disabled, note, needs_runtime_validation or needs_human_review. Justified and disabled are exceptions, never validated passes."),
        ]
        for number, title, body in blocks:
            self.canvas.setFillColor(TEAL)
            self.canvas.circle(M + 14, y - 15, 14, fill=1, stroke=0)
            self.text(number, M + 10.5, y - 19, 11, WHITE, True)
            self.text(title, M + 42, y - 13, 12, NAVY, True)
            bottom = self.para(esc(body), M + 42, y - 25, CW - 42, 9.8, 14)
            y = bottom - 28
        y -= 2
        self.canvas.setFillColor(NAVY)
        self.canvas.roundRect(M, y - 94, CW, 94, 7, fill=1, stroke=0)
        self.para("<b>Optional controlled security analyst</b><br/>When enabled in full mode, every active selected check is queued through deterministic retrieval, bounded requests, strict schemas and exact-quote checks. Missing answers remain unreviewed. The LLM remains nondeterministic; runtime and owner verification stay open. Static findings and the severity gate remain intact. Review contract: page " + str(self.first_page['analyst']) + ".", M + 16, y - 13, CW - 32, 9.5, 14, WHITE)
        self.end()

    def analyst(self, _):
        y = self.start("03 / Validation method / continued", "Controlled security analyst", "Deterministic boundaries around nondeterministic expertise. Source review produces advice; it does not establish deployed security.")
        stages = [
            ("01", "Route every active selected check", "Static rules provide partial evidence. Full mode queues active selected checks, including controls with no matches or no mapped rule. With the full catalog and no exceptions, this is " + str(len(self.controls)) + " controls / " + str(sum(len(c['checks']) for c in self.controls)) + " checks. An empty scan never closes a control."),
            ("02", "Collect evidence deterministically", "Read only unchanged files in the scan manifest. Check file hashes and path confinement, exclude credential files, redact excerpts, and select bounded context using fixed control terms and finding locations."),
            ("03", "Run the bounded analyst", "Use the configured model or custom JSON gateway. Fixed batches and call, size, and time budgets constrain review. The model may request exact ranges from captured file IDs with a risk and counterevidence rationale. The controller authorizes snapshot-only reads; no arbitrary paths, URLs, tools or target execution."),
            ("04", "Validate the response contract", "Require known control/check IDs, allowed statuses, and exact evidence quotes for support, gaps, or proposed non-applicability. Derive file and line metadata from submitted excerpts. Reject malformed or fabricated output."),
            ("05", "Keep gaps visible and auditable", "Record every check, explanation, citation, verification step, and request receipt. Omitted checks and exhausted budgets remain unreviewed. The first failed batch stops further calls; static results are preserved."),
        ]
        for number, title, body in stages:
            self.text(number, M, y - 12, 15, TEAL, True)
            self.text(title, M + 38, y - 12, 11.5, NAVY, True)
            y = self.para(esc(body), M + 38, y - 23, CW - 38, 9.1, 12.7) - 16
        y = self.para("<b>Advisory outcomes</b><br/>Code support / potential gap / runtime validation needed / human review needed / insufficient evidence / non-applicability proposed. Code support cannot complete manual or dynamic controls. Quote validation proves presence in an excerpt, not the model's interpretation.", M, y - 2, CW, 9.2, 13)
        y -= 18
        self.canvas.setFillColor(NAVY)
        self.canvas.roundRect(M, y - 96, CW, 96, 7, fill=1, stroke=0)
        self.para("<b>Default full-catalog review envelope</b><br/>Up to 36 shared requests, plus finding triage; batches of 6 and 2 optional evidence rounds. Reserve a conclusion call for every remaining batch. Evidence: 200 files / 2 MB; 240 seed excerpts, 120,000 shared characters. Scheduling: 600 seconds, not a hard deadline. Record served/denied range requests and unresolved checks. Use --analyst-investigation-rounds 0 for seed-only review.", M + 15, y - 11, CW - 30, 9, 12.6, WHITE)
        self.end()

    def benchmarks(self, items):
        y = self.start("04 / Executable evaluation", "Test behavior, not just code", "Research benchmark results apply to a defined harness and threat model. None was executed to produce this handbook.")
        for s in items:
            y = self.para(esc(s["title"]), M, y, CW, 14, 18, NAVY, True)
            y = self.para(f"<font color='#087E78'>{esc(s['id'])} / {esc(s.get('version') or s.get('date') or 'living research')}</font>", M, y - 7, CW, 8.3, 12)
            y = self.para(esc(s.get("scope", "")), M, y - 6, CW, 9.8, 14)
            y = self.para("<b>Use with care:</b> " + esc(s.get("limitations", "")), M, y - 6, CW, 8.8, 12.5, GREY)
            y = self.para(f"<link href='{esc(s['url'])}' color='#087E78'>Open the primary source</link>", M, y - 7, CW, 8.3, 12)
            self.canvas.setStrokeColor(LINE)
            self.canvas.line(M, y - 12, W - M, y - 12)
            y -= 29
        self.end()

    def control_card(self, control, top, height=268):
        c = self.canvas
        bottom = top - height
        c.setFillColor(WHITE)
        c.setStrokeColor(LINE)
        c.roundRect(M, bottom, CW, height, 7, fill=1, stroke=1)
        c.setFillColor(TEAL)
        c.roundRect(M + 15, top - 30, 67, 18, 4, fill=1, stroke=0)
        self.text(control["id"], M + 23, top - 25, 9, WHITE, True)
        self.text(control["validation"].upper() + " VALIDATION", M + 94, top - 24, 7.5, GREY, True)
        y = self.para(esc(control["title"]), M + 16, top - 43, CW - 32, 14.2, 18, NAVY, True)
        y -= 11
        for check in control["checks"]:
            c.setStrokeColor(TEAL)
            c.rect(M + 17, y - 9, 6, 6, fill=0, stroke=1)
            y = self.para(esc(check), M + 31, y, CW - 47, 9.8, 13.6)
            y -= 7
        evidence = {"static": "Code/configuration location, applicable version, and reviewer disposition.", "hybrid": "Source/configuration trace plus negative-test result from the effective deployment.", "dynamic": "Pinned scenario, expected policy, observed effects, and repeatable test results.", "manual": "Named owner, approved scope, evidence record, review date, and exceptions."}.get(control["validation"], "Document the effective boundary and retain reproducible evidence.")
        y = self.para("<b>Evidence:</b> " + esc(evidence), M + 16, y - 1, CW - 32, 8.6, 12, GREY)
        rules = ", ".join(control.get("automated_rule_ids", []))
        y = self.para("<b>Static coverage:</b> " + (esc(rules) + " (partial)" if rules else "No mapped rule; obtain review or runtime evidence."), M + 16, y - 8, CW - 32, 8.6, 12, GREY)
        refs = []
        urls = list(control["sources"])
        urls += [self.by_id[sid]["url"] for sid in control.get("alignment_source_ids", []) if self.by_id[sid]["url"] not in urls]
        for url in urls:
            source = self.by_url.get(url)
            if source is None:
                raise ValueError("No source catalog entry for " + url)
            refs.append(f"<link href='{esc(url)}' color='#087E78'>{esc(source['id'])}</link>")
        y = self.para("<b>Source context:</b> " + " &nbsp; / &nbsp; ".join(refs), M + 16, y - 8, CW - 32, 8.2, 11.5, GREY)
        if y < bottom + 12:
            raise ValueError(f"Control card overflow {control['id']}: {bottom+12-y:.1f}pt")

    def control_pages(self, data):
        category, controls = data
        first, last = controls[0]["id"], controls[-1]["id"]
        y = self.start("05 / Control catalog", category, f"{first} - {last}  /  Check applicability, retain evidence, and resolve exceptions.")
        for control in controls:
            self.control_card(control, y, 273)
            y -= 287
        if len(controls) == 1:
            self.text("ASSESSMENT RECORD", M + 16, y - 15, 8.5, TEAL, True)
            self.para("Use this space to record evidence for the control above. A source citation or a clean scan alone is not a validation result.", M + 16, y - 29, CW - 32, 9, 13, GREY)
            for offset, label in [(74, "Owner / review date"), (112, "Evidence / test run"), (150, "Result / exception / next action")]:
                self.text(label, M + 16, y - offset, 8, GREY)
                self.canvas.setStrokeColor(LINE)
                self.canvas.line(M + 16, y - offset - 18, W - M - 16, y - offset - 18)
        self.end()

    def rules_page(self, items):
        y = self.start("06 / Automation index", "What the scanner can flag", "All rules are static signals. Confidence and context determine the next investigation step; no rule proves full control effectiveness.")
        self.text("RULE", M + 3, y, 8, TEAL, True)
        self.text("SEVERITY", M + 67, y, 8, TEAL, True)
        self.text("RISK PATTERN", M + 140, y, 8, TEAL, True)
        y -= 14
        for r in items:
            c = self.canvas
            c.setFillColor(WHITE)
            c.rect(M, y - 32, CW, 32, fill=1, stroke=0)
            self.text(r["id"], M + 4, y - 18, 9.5, NAVY, True)
            self.text(r["severity"].upper(), M + 67, y - 18, 8, TEAL, True)
            self.para(esc(r["title"]), M + 140, y - 5, CW - 148, 9.1, 12)
            c.linkRect("", "page-%s" % self.rule_pages[r["id"]], (M, y - 32, W - M, y), relative=0, thickness=0)
            y -= 39
        self.para("The machine-readable catalog maps these rules to selected controls. A rule match requires investigation. A suppressed finding remains visible as an accepted exception; an unmapped or untested control remains unvalidated.", M, y - 6, CW, 9.2, 13, GREY)
        self.end()

    def rule_detail(self, rule):
        y = self.start("06 / Exact scan contract / " + rule["id"], rule["title"],
                       rule["id"] + " / " + rule["severity"].upper() + " / " + rule["category"].replace('_', ' '))
        sections = [
            ("WHAT THE DETERMINISTIC RULE DETECTS", rule["what_it_detects"]),
            ("ALGORITHM + SUPPORTED PATHS", rule["deterministic"]["algorithm"] + ". Profiles: " + ", ".join(rule["deterministic"]["analysis_profiles"]) + ". Image evidence contexts: " + ", ".join(rule["image_contexts"]) + "."),
            ("WHY THIS MATTERS FOR AGENTS, MCP AND SKILLS", rule["why_it_matters"]),
            ("CAN MISS OR MISCLASSIFY", rule["deterministic"]["limits"]),
            ("OPTIONAL AI REVIEW", rule["optional_ai_review"]["finding_triage"] + " " + rule["optional_ai_review"]["broader_review"]),
            ("HOW TO FIX OR VALIDATE", rule["remediation"]),
        ]
        for label, value in sections:
            self.text(label, M, y, 8.0, TEAL, True)
            y = self.para(esc(value), M, y - 9, CW, 9.1, 12.7) - 16
        mapped = ", ".join(control["id"] for control in rule["controls"]) or "No mapped control"
        y = self.para("<b>Partial control mappings:</b> " + esc(mapped) + ". A mapping does not satisfy the full control.", M, y, CW, 8.7, 12.2) - 12
        groups = OrderedDict()
        for source in rule["sources"]:
            groups.setdefault(source["relationship"], []).append(source)
        for relation, sources in groups.items():
            links = " / ".join("<link href='" + esc(source["url"]) + "' color='#087E78'>" + esc(source["id"]) + "</link>" for source in sources)
            y = self.para("<b>" + esc(relation.replace('_', ' ').capitalize()) + ":</b> " + links, M, y, CW, 8.0, 11.3) - 7
        y = self.para("<b>Explore:</b> " + esc(rule["commands"]["explain"]) + "<br/><b>Run:</b> " + esc(rule["commands"]["select"]), M, y - 4, CW, 8.6, 12.1) - 8
        self.para("Full per-check requirements and runtime/human evidence remain in the mapped control cards. Model interpretation is advisory; citations confirm quoted text, not correctness. Nothing on this page establishes malicious intent or exploitability.", M, y, CW, 8.1, 11.4, GREY)
        self.end()

    def references(self, items):
        y = self.start("07 / Source directory", "Follow the evidence", "Primary-source links, version context and the recorded access date for each source.")
        for s in items:
            self.text(s["id"], M, y - 9, 8.4, TEAL, True)
            y = self.para(esc(s["title"]), M, y - 20, CW, 11.5, 15, NAVY, True)
            meta = " / ".join(str(v) for v in [s.get("organization"), s.get("kind"), s.get("version"), s.get("date"), "Accessed " + s["accessed"] if s.get("accessed") else None] if v)
            y = self.para(esc(meta), M, y - 5, CW, 7.6, 10.5, GREY)
            y = self.para(esc(s.get("scope", "")) + " <b>Limit:</b> " + esc(s.get("limitations", "")), M, y - 6, CW, 8.6, 12)
            url = s["url"]
            display = re.sub(r"^https?://", "", url)
            # Short visible URLs remain readable; the complete URL is embedded
            # in every link and preserved in the machine-readable registry.
            if len(display) > 100:
                display = display[:96] + "..."
            y = self.para(f"<link href='{esc(url)}' color='#087E78'>{esc(display)}</link>", M, y - 5, CW, 7.6, 10.5)
            self.canvas.setStrokeColor(LINE)
            self.canvas.line(M, y - 11, W - M, y - 11)
            y -= 26
        self.end()

    def build(self):
        handlers = {"cover": self.cover, "contents": self.contents, "guide": self.guide, "sources": self.sources_page, "workflow": self.workflow,
                    "coverage": self.coverage, "configuration": self.configuration, "review_flow": self.review_flow,
                    "analyst": self.analyst, "benchmarks": self.benchmarks, "controls": self.control_pages, "rules": self.rules_page,
                    "rule_detail": self.rule_detail, "quickstart": self.quickstart, "scoring": self.scoring, "references": self.references}
        for kind, content in self.specs:
            handlers[kind](content)
        self.canvas.save()
        return self.page_map


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", default=str(ROOT / "output/pdf/invarune-security-controlbook.pdf"))
    args = p.parse_args()
    controls = json.loads((ROOT / "ai_security_scan/data/controls.json").read_text())
    sources = json.loads((ROOT / "ai_security_scan/data/sources.json").read_text())
    import sys
    sys.path.insert(0, str(ROOT))
    from ai_security_scan.rules import RULES
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pages = Book(output, controls, sources, RULES).build()
    tmp = ROOT / "tmp/pdfs"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "page-map.json").write_text(json.dumps(pages, indent=2) + "\n")
    print(json.dumps({"output": str(output), "pages": len(pages), "controls": len(controls), "sources": len(sources)}))


if __name__ == "__main__":
    main()
