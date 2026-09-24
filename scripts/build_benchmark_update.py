#!/usr/bin/env python3
"""Build a benchmark publication from verified local execution receipts.

No target code, scanner, model or network call is executed by this builder.
The historical v0.10 publication and its provenance contract remain unchanged.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from html import escape
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.build_benchmark_dashboard import check_accuracy, check_comparison, check_pair

REPO = "https://github.com/nimeshbuilds/invarune"
SITE = "https://nimeshbuilds.github.io/invarune/"
INPUT = ROOT / "benchmarks/comparison-v013"
OUTPUT = ROOT / "output/pdf/invarune-benchmark-v013.pdf"
TOOLS = ("invarune", "semgrep", "bandit", "gitleaks")
LABELS = {"invarune": "Invarune", "semgrep": "Semgrep CE", "bandit": "Bandit", "gitleaks": "Gitleaks"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def load(directory):
    names = ("accuracy-before.json", "accuracy-after.json", "observations.json", "overlaps.json", "run-status.json", "baseline-identity.json", "before-after-accuracy.json")
    data, hashes = {}, {}
    for name in names:
        raw = (directory / name).read_bytes()
        data[name] = json.loads(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    before, after = data["accuracy-before.json"], data["accuracy-after.json"]
    corpus_bytes = (ROOT / "benchmarks/static_accuracy.json").read_bytes()
    corpus, corpus_hash = json.loads(corpus_bytes), hashlib.sha256(corpus_bytes).hexdigest()
    for report in (before, after):
        check_accuracy(report, corpus, corpus_hash)
    if before["corpus_sha256"] != after["corpus_sha256"] or before["case_count"] != after["case_count"]:
        raise ValueError("Before/after must use identical corpus bytes and case counts")
    def identities(report):
        return [(c["id"], c["path"], [(a["rule_id"], a["expected"]) for a in c["assertions"]]) for c in report["cases"]]
    if identities(before) != identities(after):
        raise ValueError("Before/after labels or case identities changed")
    for report in (before, after):
        counts = Counter(a["outcome"] for c in report["cases"] for a in c["assertions"])
        if any(report["overall"][key] != counts[key] for key in ("true_positive", "true_negative", "false_positive", "false_negative")):
            raise ValueError("Fixture confusion counts disagree with case outcomes")
        if report["analysis_error_cases"]:
            raise ValueError("Fixture analysis errors must be resolved before this comparison")
    ledger = data["observations.json"]
    rows = ledger["observations"]
    by_id = {r["id"]: r for r in rows}
    if len(by_id) != len(rows) or len(rows) != ledger["observation_count"] or dict(Counter(r["tool"] for r in rows)) != ledger["counts_by_tool"]:
        raise ValueError("Observation ledger counts or identities disagree")
    if {r["tool_version"] for r in rows if r["tool"] == "invarune"} != {after["tool_version"]}:
        raise ValueError("Source and fixture scanner versions disagree")
    overlaps = data["overlaps.json"]
    if overlaps["observation_ledger_sha256"] != hashlib.sha256(canonical(ledger)).hexdigest():
        raise ValueError("Overlap receipt does not bind this ledger")
    for pair in overlaps["pairs"]:
        for side in ("left", "right"):
            expected = {r["id"] for r in rows if r["tool"] == pair[side + "_tool"]}
            matched = {r[side + "_id"] for key in ("one_to_one_matches", "ambiguous_family_location_edges") for r in pair[key]}
            unmatched = set(pair[side + "_without_family_match"])
            if matched & unmatched or matched | unmatched != expected:
                raise ValueError("Matched/unmatched observation partition is invalid")
        if pair["counts"]["one_to_one_pairs"] != len(pair["one_to_one_matches"]) or pair["counts"]["ambiguous_edges"] != len(pair["ambiguous_family_location_edges"]):
            raise ValueError("Overlap edge counts disagree")
    runs = data["run-status.json"]["runs"]
    check_comparison(ledger, overlaps, runs)
    pair = data["before-after-accuracy.json"]
    if pair["experiment"] != ledger["experiment"]:
        raise ValueError("Paired accuracy and source ledger belong to different experiments")
    check_pair(pair, before, after, hashes["accuracy-before.json"], hashes["accuracy-after.json"],
               "benchmarks/static_accuracy.json", data["baseline-identity.json"], runs)
    for tool in TOOLS:
        if sum(r.get("finding_count") or 0 for r in runs if r["tool"] == tool) != ledger["counts_by_tool"].get(tool, 0):
            raise ValueError("Run totals disagree with observation ledger")
    def receipts(folder):
        found = []
        for path in sorted((directory / folder).glob("*.json")):
            raw = path.read_bytes()
            hashes[folder + "/" + path.name] = hashlib.sha256(raw).hexdigest()
            found.append(json.loads(raw))
        return found
    before_receipts, after_receipts = receipts("invarune-receipts-before"), receipts("invarune-receipts-after")
    source = {r["project_id"]: r for r in ledger["inputs"]}
    if len(source) != 8:
        raise ValueError("Exactly eight pinned projects are required")
    for collection, phase in ((before_receipts, "before"), (after_receipts, "after")):
        if len(collection) != 8 or {r["project"] for r in collection} != set(source):
            raise ValueError("Receipts must contain each pinned project exactly once")
        for row in collection:
            project = source[row["project"]]
            if (row["revision"] != project["revision"] or row["source_manifest_sha256"] != project["source_manifest_sha256"]
                    or row["source_files"] != project["files"] or row["tool"]["version"] != pair[phase]["tool_version"]
                    or row["tool"]["implementation_sha256"] != pair[phase]["implementation_sha256"]):
                raise ValueError("Project receipt does not bind its source and implementation")
            repeated = row["repeated_runs"]
            if (row["byte_identical_reports"] is not True or len(repeated) != 2
                    or [r["run"] for r in repeated] != [1, 2]
                    or repeated[0]["report_sha256"] != repeated[1]["report_sha256"]
                    or set(repeated[0]["report_sha256"]) != {"report.html", "report.json", "report.md", "report.sarif"}
                    or repeated[0]["exit_code"] != repeated[1]["exit_code"]):
                raise ValueError("Each project must have two byte-identical executions")
    old = {r["project"]: r for r in before_receipts}
    current_runs = {r["project_id"]: r for r in runs if r["tool"] == "invarune"}
    catalog_counts = None
    for row in after_receipts:
        if any(row[key] != old[row["project"]][key] for key in ("revision", "source_manifest_sha256", "source_files", "source_bytes")):
            raise ValueError("Before/after public source inputs changed")
        run, summary = current_runs[row["project"]], row["summary"]
        if (run["raw_report_sha256"] != row["repeated_runs"][0]["report_sha256"]["report.json"]
                or run["finding_count"] != summary["open_findings"] + summary["suppressed_findings"]
                or run["coverage_gaps"] != summary["coverage_gaps"] or run["files_reported_scanned"] != summary["files_scanned"]):
            raise ValueError("Project receipt summary differs from the normalized run")
        for name, digest in row["repeated_runs"][0]["report_sha256"].items():
            path = directory / "invarune-reports" / row["project"] / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("Published source report differs from its repeated execution receipt")
        frozen_report = json.loads((directory / "invarune-reports" / row["project"] / "report.json").read_bytes())
        counts = {"rules": len(frozen_report["coverage"]["rules_enabled"]), "controls": len(frozen_report["controls"]),
                  "checks": sum(len(control["checks"]) for control in frozen_report["controls"]),
                  "mapped_controls": sum(bool(control["automated_rule_ids"]) for control in frozen_report["controls"])}
        if catalog_counts is not None and counts != catalog_counts:
            raise ValueError("Published source reports used different selected catalog scopes")
        catalog_counts = counts
    if after['tool_version'].startswith(('0.14.', '0.15.')):
        name = 'skills-tools-accuracy.json'
        raw = (directory / name).read_bytes()
        skills = json.loads(raw)
        corpus_raw = (ROOT / 'benchmarks/skills_tools_accuracy.json').read_bytes()
        check_accuracy(skills, json.loads(corpus_raw), hashlib.sha256(corpus_raw).hexdigest())
        if skills['tool_version'] != after['tool_version']:
            raise ValueError('Skill/tool accuracy and source scanner versions disagree')
        hashes[name] = hashlib.sha256(raw).hexdigest()
        receipt_name = 'skills-tools-evaluation-receipt.json'
        receipt_raw = (directory / receipt_name).read_bytes()
        receipt = json.loads(receipt_raw)
        failed = [case['id'] for case in skills['cases'] if any(a['outcome'] in ('false_positive', 'false_negative') for a in case['assertions'])]
        if (receipt['experiment'] != ledger['experiment'] or receipt['tool_version'] != after['tool_version']
                or receipt['implementation_sha256'] != pair['after']['implementation_sha256']
                or receipt['report'] != {'path': name, 'sha256': hashes[name]}
                or receipt['corpus'] != {'path': 'benchmarks/skills_tools_accuracy.json', 'sha256': skills['corpus_sha256'], 'version': skills['corpus_version']}
                or receipt['case_count'] != skills['case_count'] or receipt['overall'] != skills['overall']
                or receipt['analysis_error_cases'] != 0 or receipt['separate_denominator'] is not True
                or sorted(receipt['failed_case_ids']) != sorted(failed)):
            raise ValueError('Skill/tool evaluation receipt does not bind the final implementation and complete measured corpus')
        hashes[receipt_name] = hashlib.sha256(receipt_raw).hexdigest()
        data['skills'] = skills
    from scripts.benchmark_v015_data import load_extensions
    def extension_reader(path):
        raw = path.read_bytes()
        key = path.relative_to(directory).as_posix() if path.is_relative_to(directory) else path.relative_to(ROOT).as_posix()
        hashes[key] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)
    data['extensions'] = load_extensions(directory, after['tool_version'], pair['after']['implementation_sha256'], extension_reader, check_accuracy)
    data.update(hashes=hashes, directory=directory, before=before, after=after, before_receipts=before_receipts, after_receipts=after_receipts, catalog_counts=catalog_counts)
    return data


def build(data, output):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import BaseDocTemplate, Flowable, Frame, KeepTogether, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle

    version = data["after"]["tool_version"]
    catalog = data["catalog_counts"]
    comparison_path = "/blob/main/benchmarks/" + data["observations.json"]["experiment"]
    navy, teal, mint = colors.HexColor("#0B1220"), colors.HexColor("#087E78"), colors.HexColor("#35E3B1")
    muted, paper, line = colors.HexColor("#536572"), colors.HexColor("#F2F6FA"), colors.HexColor("#D4E1E5")
    regular, bold = "Helvetica", "Helvetica-Bold"
    for directory in (Path("/System/Library/Fonts/Supplemental"), Path("/usr/share/fonts/truetype/liberation2")):
        a, b = (directory / "Arial.ttf", directory / "Arial Bold.ttf") if directory.name == "Supplemental" else (directory / "LiberationSans-Regular.ttf", directory / "LiberationSans-Bold.ttf")
        if a.is_file() and b.is_file():
            pdfmetrics.registerFont(TTFont("InvRegular", str(a)))
            pdfmetrics.registerFont(TTFont("InvBold", str(b)))
            regular, bold = "InvRegular", "InvBold"
            break
    styles = {
        "body": ParagraphStyle("body", fontName=regular, fontSize=9.5, leading=14, textColor=navy, spaceAfter=9),
        "small": ParagraphStyle("small", fontName=regular, fontSize=8, leading=11.5, textColor=muted, spaceAfter=7),
        "h1": ParagraphStyle("h1", fontName=bold, fontSize=27, leading=31, textColor=navy, spaceAfter=17),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=14, leading=19, textColor=teal, spaceBefore=12, spaceAfter=8),
        "table": ParagraphStyle("table", fontName=regular, fontSize=8, leading=11, textColor=navy),
        "thead": ParagraphStyle("thead", fontName=bold, fontSize=8, leading=11, textColor=colors.white),
    }
    def p(text, style="body"):
        return Paragraph(text, styles[style])
    def safe(text):
        return escape(str(text)).replace("\u2014", " - ").replace("\u2013", "-")
    def table(rows, widths):
        wrapped = [[p(safe(cell), "thead" if index == 0 else "table") for cell in row] for index, row in enumerate(rows)]
        t = Table(wrapped, colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), navy), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, paper]), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LINEBELOW", (0, 0), (-1, 0), 1, teal)]))
        return t
    def link(label, url):
        return p('<a color="#087E78" href="' + escape(url, quote=True) + '">' + safe(label) + "</a>", "small")

    class Bars(Flowable):
        def __init__(self, before, after):
            super().__init__(); self.width = 499; self.height = 158; self.before = before; self.after = after
        def draw(self):
            c = self.canv
            c.setFillColor(paper); c.roundRect(0, 0, 499, 158, 10, fill=1, stroke=0)
            for i, (key, label) in enumerate((("precision", "Precision"), ("recall", "Recall"))):
                x, y = 16 + i * 251, 132
                c.setFont(bold, 10); c.setFillColor(navy); c.drawString(x, y, label)
                for j, (report, fill) in enumerate(((self.before, colors.HexColor("#809AA4")), (self.after, teal))):
                    score = report["overall"][key] * 100
                    yy = 89 - j * 45
                    c.setFont(regular, 8); c.setFillColor(muted); c.drawString(x, yy + 17, "v" + report["tool_version"])
                    c.setFillColor(line); c.roundRect(x, yy, 164, 10, 3, fill=1, stroke=0)
                    c.setFillColor(fill); c.roundRect(x, yy, 164 * score / 100, 10, 3, fill=1, stroke=0)
                    c.setFont(bold, 10); c.setFillColor(navy); c.drawString(x + 174, yy, f"{score:.2f}%")

    class Doc(BaseDocTemplate):
        def afterFlowable(self, flow):
            if isinstance(flow, Paragraph) and getattr(flow, "section_key", None):
                self.canv.bookmarkPage(flow.section_key)
                self.canv.addOutlineEntry(flow.getPlainText(), flow.section_key, level=0)

    def heading(title, key):
        item = p(safe(title), "h1"); item.section_key = key; return item
    def chrome(canvas, doc):
        width, height = A4
        canvas.setStrokeColor(line); canvas.line(48, height - 42, width - 48, height - 42)
        for points, fill in (((26, 4, 8, 14, 8, 50, 26, 60, 26, 47, 19, 43, 19, 21, 26, 17), navy),
                             ((38, 4, 56, 14, 56, 50, 38, 60, 38, 47, 45, 43, 45, 21, 38, 17), teal),
                             ((32, 22, 42, 32, 32, 42, 22, 32), teal)):
            mark = canvas.beginPath()
            for index in range(0, len(points), 2):
                x, y = 46 + points[index] * .28, height - 20 - points[index + 1] * .28
                (mark.moveTo if index == 0 else mark.lineTo)(x, y)
            mark.close(); canvas.setFillColor(fill); canvas.drawPath(mark, fill=1, stroke=0)
        canvas.setFillColor(teal); canvas.setFont(bold, 9); canvas.drawString(70, height - 30, "INVARUNE / NIMESHBUILD")
        canvas.setFillColor(muted); canvas.setFont(regular, 7.5); canvas.drawRightString(width - 48, height - 30, "BENCHMARK EVIDENCE | " + version)
        canvas.line(48, 40, width - 48, 40); canvas.drawString(48, 27, "Project-authored fixtures. Source observations are not confirmed vulnerabilities.")
        canvas.drawRightString(width - 48, 27, str(doc.page))
        canvas.linkURL(SITE + "docs/BENCHMARK_DASHBOARD/", (48, height - 37, 230, height - 23), relative=0)

    before, after = data["before"], data["after"]
    b, a = before["overall"], after["overall"]
    def matched(case):
        return all(a["outcome"] in ("true_positive", "true_negative") for a in case["assertions"])
    fixed = [c for c, old in zip(after["cases"], before["cases"]) if matched(c) and not matched(old)]
    remaining = [c for c in after["cases"] if not matched(c)]
    regressed = [c for c, old in zip(after["cases"], before["cases"]) if not matched(c) and matched(old)]
    rows, runs = data["observations.json"]["observations"], data["run-status.json"]["runs"]
    counts = Counter(r["tool"] for r in rows)
    scope_files = sum(r["source_files"] for r in data["after_receipts"])
    gaps = sum(r.get("coverage_gaps", 0) for r in runs if r["tool"] == "invarune")
    story = [Spacer(1, 28), p("INVARUNE BY NIMESHBUILD", "h2"), heading("Broader inspection.<br/>Measured against the same evidence.", "summary")]
    story[-1] = p("Broader inspection.<br/>Measured against the same evidence.", "h1"); story[-1].section_key = "summary"
    story += [p("Benchmark update / Invarune " + safe(after["tool_version"]), "h2"), p("The unchanged development-visible fixture corpus and eight pinned public projects were scanned again after targeted detector fixes. This publication records the measured changes, comparison scope and unresolved work."), Bars(before, after), Spacer(1, 14), table([["Unchanged fixture comparison", "Observed result"], ["Cases / original corpus", f"{after['case_count']} / {after['corpus_version']}"], ["Previously failing cases now correct", str(len(fixed))], ["New mismatches on previously correct cases", str(len(regressed))], ["Remaining labeled mismatches", str(len(remaining))], ["Pinned public-project scope", f"8 projects / {scope_files:,} exported files"], ["Current Invarune source observations / coverage gaps", f"{counts['invarune']} / {gaps}"]], [310, 189]), Spacer(1, 10), p("These percentages describe project-authored rule-presence labels used during development. They are not production accuracy, independent validation or a claim that Invarune is better than every scanner.", "small"), link("Interactive benchmark dashboard and downloadable evidence", SITE + "docs/BENCHMARK_DASHBOARD/")]

    if data.get("extensions"):
        story += [p("Harder unseen cases still expose limits", "h2"),
                  p("First blind 32-case result: 4 TP / 16 TN / 0 FP / 12 FN. After disclosure and fixes: 16 TP / 16 TN / 0 FP / 0 FN. A separate eight-case holdout still has 2 false negatives. The original 331 skill/tool labels retain one false-positive score. These separate denominators are detailed inside.", "small")]
    story += [PageBreak(), heading("Read the evidence in layers", "contents")]
    sections = [("Fixture accuracy and unchanged labels", "accuracy"), ("What was fixed and what still needs work", "fixes"), ("Source scope and release additions", "source-fixes"), ("Fresh comparison on eight public projects", "projects"), ("Finding overlap and complementary coverage", "overlap"), ("Why use invscan in an agent/MCP review", "workflow"), ("Reproduce, validate and inspect the complete ledger", "provenance")]
    if data.get("extensions"):
        sections.insert(3, ("A harder challenge exposed a real gap", "challenge"))
        sections.insert(4, ("Label changes and a second sealed check", "confirmation"))
    for title, key in sections:
        story.append(p('<a color="#087E78" href="#' + key + '">' + safe(title) + "</a>", "h2"))
    story += [Spacer(1, 20), table([["Evidence layer", "What it establishes"], ["Deterministic fixtures", "Agreement with explicitly authored rule-presence labels; supports regression and before/after analysis."], ["Public source observations", "Patterns reported by configured tools on exact pinned files; requires source and deployment review."], ["Optional model review", "Advisory judgments only when actually requested and completed; not a replacement for independent truth."], ["Runtime validation", "Still needed for authentication, reachability, tenant isolation, prompt-injection resistance and deployed safeguards."]], [135, 364]), p("All measurements in this update preserve target isolation: no upstream project code, service or exploit was executed. Tool support, parser warnings and incomplete work remain visible.", "small")]

    story += [PageBreak(), heading("Fixture accuracy", "accuracy"), p(f"The before and after runs use the exact same {after['case_count']} cases, source bytes, paths and expected labels. Corpus SHA-256:", "body"), p(safe(after["corpus_sha256"]), "small"), Bars(before, after), Spacer(1, 14), table([["Outcome", "Before " + before["tool_version"], "After " + after["tool_version"]], ["True positive", b["true_positive"], a["true_positive"]], ["True negative", b["true_negative"], a["true_negative"]], ["False positive", b["false_positive"], a["false_positive"]], ["False negative", b["false_negative"], a["false_negative"]], ["Analysis errors", before["analysis_error_cases"], after["analysis_error_cases"]]], [249, 125, 125]), Spacer(1, 12), p("Precision = TP / (TP + FP). Recall = TP / (TP + FN). A true-positive label here means that the designated detector correctly recognized the fixture's specified source pattern. It is not an independently confirmed vulnerability."), p("All challenge failures remain in these denominators. Default regression gating is a narrower CI policy and must not be read as zero mistakes. Fixes were developed with knowledge of these cases; this is a transparent development benchmark, not a held-out test.", "small"), link("Before accuracy JSON", REPO + comparison_path + "/accuracy-before.json"), link("After accuracy JSON", REPO + comparison_path + "/accuracy-after.json")]

    story += [PageBreak(), heading("Fixes and remaining limits", "fixes"), p("Previously failing cases now agree with the unchanged label" if fixed else "No prior fixture outcome changed in this release", "h2")]
    fixes = {"gap-reflection-python": "Resolve a small literal or concatenated getattr attribute while respecting local shadowing.",
             "gap-yaml-alias": "Resolve a supported preceding same-document literal anchor without evaluating tags or general alias graphs.",
             "gap-yaml-block-string": "Mask YAML scalar contents before configuration-key checks; documentation is data.",
             "gap-shell-wrapper": "Recognize a direct downloaded command substitution passed as shell -c command text.",
             "gap-interprocedural-url": "Propagate known input through bounded local Python arguments and returns.",
             "gap-js-wrapper-taint": "Summarize supported compact JavaScript wrappers and connect supplied arguments to sinks.",
             "gap-validated-user-url": "Recognize a supported reject branch that restricts the remaining URL to a fixed destination."}
    if fixed:
        story.append(table([["Fixture", "Bounded detector improvement"]] + [[c["id"], fixes.get(c["id"], c["rationale"])] for c in fixed], [177, 322]))
    else:
        story.append(p("The unchanged baseline cases retain their prior outcomes. The separate skill/tool measurements on the next page describe the added inspection scope; they do not increase the original corpus denominator."))
    if remaining:
        story += [p("Still unresolved on this corpus", "h2"), table([["Fixture", "Remaining mismatch"]] + [[c["id"], c["rationale"]] for c in remaining], [177, 322])]
    else:
        story += [p("No remaining mismatch on these 113 assertions", "h2"), p("The separate blind challenge and development extension corpora still contain misses. Matching this older, development-visible corpus does not establish complete security coverage.")]
    story += [p("The release's paired and adversarial regression tests cover the supported interpretations and counterexamples. General interprocedural flow, dynamic runtime values, full YAML semantics and arbitrary shell expansion are not proven by these targeted changes. Review an uncertain finding in context instead of silently suppressing it.", "small"), link("Detailed change analysis and remaining gaps", REPO + comparison_path + "/README.md")]

    source_before = sum(r["summary"]["open_findings"] + r["summary"]["suppressed_findings"] for r in data["before_receipts"])
    if version.startswith("0.13."):
        story += [PageBreak(), heading("Less noise on the same source", "source-fixes"),
                  p(f"On the same {scope_files:,} exported files, Invarune observations changed from {source_before} to {counts['invarune']}. The source review identified three narrowly defined false-alarm patterns. Their removal is a precision refinement, not evidence that the target projects fixed vulnerabilities."),
                  table([["Observed source role", "Detector correction"],
                         ["AutoGen: local requirements dot path", "A local self-install path is no longer treated as an unpinned named dependency range."],
                         ["CrewAI: api_key_env_var identifier", "An explicit environment-variable-name field with an uppercase identifier is distinguished from a literal credential value."],
                         ["AutoGen: all-x token placeholder", "Recognized token formats now share the narrow all-x placeholder filter; realistic token-like literals remain review signals."]], [205, 294]),
                  Spacer(1, 14), p("Evidence spans also became more precise", "h2"),
                  p("An OpenHands image-reference observation moved its starting line from a preceding blank line onto the image field. The delta ledger records the old/new identities transparently; this is one location refinement, not a newly discovered risk."),
                  p("Coverage did not improve by dropping inputs", "h2"),
                  p(f"All eight pinned revisions, source manifests and scan budgets were held stable. Invarune examined {sum(r['summary']['files_scanned'] for r in data['after_receipts']):,} files, with {gaps} explicit coverage gaps. Unsupported extensions remain outside analysis. The benchmark preserves those limits instead of treating them as clean results."),
                  link("Exact source observation delta", REPO + comparison_path + "/source-delta.json"),
                  link("Scoped source review, rationale and pinned evidence", REPO + comparison_path + "/gap-review.json"),
                  link("Download all eight detailed source reports", SITE + "docs/BENCHMARK_DASHBOARD/")]
    else:
        skills = data['skills']
        skill_counts = skills['overall']
        skill_precision = 'unavailable' if skill_counts['precision'] is None else format(100 * skill_counts['precision'], '.2f') + '%'
        skill_recall = 'unavailable' if skill_counts['recall'] is None else format(100 * skill_counts['recall'], '.2f') + '%'
        story += [PageBreak(), heading("Skills, tools and honest scope", "source-fixes"),
                  p(f"On the unchanged {scope_files:,} exported files, Invarune observations changed from {source_before} to {counts['invarune']}. The final scan retains {gaps} analysis gaps. New metadata inspection can expose additional unknowns without changing the finding count."),
                  p("Instruction checks and expanded deterministic scope" if data.get("extensions") else "Four new deterministic checks", "h2"),
                  table([["Rule", "Risk evidence"], ["AI043", "Explicit instruction-hierarchy overrides in supported skill/tool text."], ["AI044", "Sensitive-data transfer instructions with an explicit destination."], ["AI045", "Concealed actions and approval/security-boundary bypass directives."], ["AI046", "Read-only hints conflicting with a destructive description or supported direct handler write." if data.get("extensions") else "Literal read-only annotations contradicting destructive tool descriptions."]] + ([["AI047", "Explicit other-write permission bits on recognized filesystem calls."]] if data.get("extensions") else []), [65, 434]),
                  p("Separate measurement: " + str(skills['case_count']) + " cases / " + str(skill_counts['assertions']) + " rule-presence assertions. TP " + str(skill_counts['true_positive']) + "; TN " + str(skill_counts['true_negative']) + "; FP " + str(skill_counts['false_positive']) + "; FN " + str(skill_counts['false_negative']) + ". Precision " + skill_precision + "; recall " + skill_recall + ". All authored challenge misses remain in these denominators.", "small"),
                  p("The separate skill/tool corpus is not added to the original 113 assertions. Each label describes a source pattern, not malicious authorship or exploitation. The public-source export excludes most skill documentation and cannot measure complete skill-package coverage."),
                  link("Separate skill/tool measurement and known misses", REPO + comparison_path + "/skills-tools-accuracy.json"),
                  link("Every scan: algorithms, controls, sources and uncertainty", SITE + "docs/SCAN_COVERAGE/"),
                  p("Interpreting a score", "h2"),
                  p("There is no overall security percentage. Findings use exact severity counts. Partial mapping reach = active selected controls with an active mapped rule / active selected controls. Optional AI answer coverage = uniquely answered active checks / active selected checks. Both are multiplied by 100; zero denominators are null. Neither is a control pass rate."),
                  p("Exceptions receive no pass credit. AI may add advisory concerns or help investigate inconclusive evidence; it cannot clear static findings or coverage gaps. Missing runtime proof remains unresolved.", "small"),
                  link("Exact source observation delta", REPO + comparison_path + "/source-delta.json")]

    if data.get("extensions"):
        ext = data['extensions']
        def counts_row(label, value):
            return [label, *[value[key] for key in ('true_positive','true_negative','false_positive','false_negative')]]
        challenge_rows = [["Same 32-case challenge", "TP", "TN", "FP", "FN"]]
        for label,key in [('Earlier v0.14 release','baseline'),('First blind v0.15 candidate','initial'),('After disclosure and fixes','final')]:
            challenge_rows.append(counts_row(label, ext['challenge'][key]['invarune']['overall']))
        story += [PageBreak(), heading("A harder test exposed a real gap", "challenge"),
                  p("A separate benchmark assistant sealed 32 cases before the first candidate freeze: 16 source-flow cases and 16 literal tool descriptions. The first result remains visible. It revealed that declared tool-handler parameters were not being treated as entrypoint input, and that several composed instructions were missed."),
                  table(challenge_rows, [299,50,50,50,50]), Spacer(1,12),
                  p("What changed after disclosure", "h2"),
                  p("The implementation work targets recognized MCP entrypoints, bounded local argument flow, operative instruction composition and defensive counterexamples. The third row is development performance because the cases and labels were disclosed before those fixes. It must never be presented as a second blind result."),
                  p("Equivalent offline metadata input", "h2"),
                  table([["Same 16 descriptions", "TP", "TN", "FP", "FN"],
                         counts_row('Invarune final deterministic',ext['challenge']['final']['invarune']['tracks']['heldout-metadata']),
                         counts_row('Cisco MCP Scanner: YARA only',ext['challenge']['final']['cisco_metadata']['overall'])], [299,50,50,50,50]),
                  p("Cisco's enabled YARA engine also passed a separate known-positive/safe sanity pair. Its API, LLM and behavioral analyzers were not enabled. These rows do not compare Cisco's full product to Invarune or establish production prompt-injection resistance.", "small"),
                  table([["Separate four sealed descriptions", "TP", "TN", "FP", "FN"],
                         counts_row('Invarune first execution',ext['confirmation']['invarune']['tracks']['heldout-metadata']),
                         counts_row('Cisco MCP Scanner: YARA only',ext['confirmation']['cisco_metadata']['overall'])], [299,50,50,50,50]),
                  link("Sealed inputs, first result and all post-disclosure outcomes", REPO + comparison_path + "/CHALLENGE.md"),
                  link("Peer scope, official sources and benchmark design", REPO + comparison_path + "/RESEARCH.md")]
        conf=ext['confirmation']['invarune']['overall']
        legacy=data['skills']['overall'];corrected=ext['corrected_after']['overall']
        story += [PageBreak(), heading("Keep labels and uncertainty visible", "confirmation"),
                  p("A second, smaller eight-case set was sealed after the first challenge was disclosed and before the detector freeze. It uses four source cases and four metadata cases. This is a within-project temporal holdout, not third-party independent validation or a statistically representative sample."),
                  table([["Final sealed confirmation", "TP", "TN", "FP", "FN"],counts_row('Eight cases, first execution',conf)], [299,50,50,50,50]),
                  p("Two misses remain open: a .env contents-transfer instruction and a precedence instruction referring to a system message. A report-presentation-only release change required a repeat; all eight detector outcomes stayed identical. That repeat is not a new blind test.", "small"),
                  p("One old scope label was explicitly corrected", "h2"),
                  p("The legacy skill corpus labels an override inside a tool input-schema field as out of scope. The expanded detector inspects model-visible schema descriptions. The old 331 assertions remain untouched and scored; a separate revision changes only that label, preserving all 81 source inputs."),
                  table([["331-assertion label set", "TP", "TN", "FP", "FN"],counts_row('Original legacy labels',legacy),counts_row('Explicitly corrected label revision',corrected)], [299,50,50,50,50]),
                  p("Source observations are a different question", "h2"),
                  p("Twelve purposively selected source locations were inspected by the benchmark assistant. The optional AutoGen execution directory is made world writable; AI047 now checks the other-write permission bit. Other peer-only observations concern safe YAML loaders, serialization, public OAuth URLs or existing archive checks. None of this establishes an aggregate deployed-vulnerability true-positive rate."),
                  link("Twelve pinned source reviews and qualifications", REPO + comparison_path + "/SOURCE_REVIEW.md"),
                  link("Explicit corpus-label correction and both paired outcomes", REPO + comparison_path + "/README.md"),
                  p("Runtime authorization, model behavior, DNS/redirect effects and deployed isolation remain separate evidence. Optional AI investigation is advisory and cannot erase deterministic findings.", "small")]

    story += [PageBreak(), heading("Eight projects. Fresh executions.", "projects"), p("The same exported first-party source/configuration bytes were offered to Invarune, Semgrep CE, Bandit and Gitleaks. Equal input does not make their languages, rule scope or supported inputs identical. Counts below are observations, not unique vulnerabilities.")]
    project_rows = [["Project", "Files", "Invarune", "Semgrep", "Bandit", "Gitleaks"]]
    by_run = {(r["project_id"], r["tool"]): r for r in runs}
    for receipt in data["after_receipts"]:
        ident = receipt["project"]
        c = Counter(r["tool"] for r in rows if r["project_id"] == ident)
        project_rows.append([ident, receipt["source_files"], *["unsupported" if by_run[(ident, t)]["finding_count"] is None else c[t] for t in TOOLS]])
    story += [table(project_rows, [124, 47, 82, 82, 82, 82]), Spacer(1, 14)]
    tool_rows = [["Tool", "Recorded version", "Observations", "Scope status"]]
    for tool in TOOLS:
        selected = [r for r in runs if r["tool"] == tool]
        statuses = Counter(r["status"] for r in selected)
        tool_rows.append([LABELS[tool], ", ".join(sorted({r["version"] for r in selected})), counts[tool], "; ".join(f"{v} {k}" for k, v in sorted(statuses.items()))])
    story += [table(tool_rows, [88, 80, 76, 255]), Spacer(1, 10), p(f"Invarune reports {gaps} coverage gaps. Those inputs are incomplete, not clean. Semgrep parser warnings, Bandit parser errors and unsupported exports are retained in the run-status receipts. All eight Invarune projects have two byte-identical repeated outputs under the recorded runtime and settings.", "small"), link("All normalized run statuses and coverage details", REPO + comparison_path + "/run-status.json")]

    story += [PageBreak(), heading("What overlaps - and what does not", "overlap"), p("A compatible family, the same pinned project/path and intersecting line spans are required for a match. One-to-one pairs require exactly one candidate on each side. Ambiguous and location-only relations remain separate; matching does not establish a true-positive label.")]
    overlap_rows = [["Compared with", "1:1 pairs", "Ambiguous edges", "Invarune unmatched", "Other tool unmatched"]]
    for pair in data["overlaps.json"]["pairs"]:
        if pair["left_tool"] == "invarune":
            c = pair["counts"]
            overlap_rows.append([LABELS[pair["right_tool"]], c["one_to_one_pairs"], c["ambiguous_edges"], c["left_without_family_match"], c["right_without_family_match"]])
    story += [table(overlap_rows, [111, 70, 90, 114, 114]), Spacer(1, 12), p("The complete ledger exposes what each scanner reported, the other-tool match candidates, exact pinned paths and rule-family predicates. A tool-only record may reflect useful additional scope, a differently defined rule, unsupported analysis, a false alarm or a genuine missed risk; count alone does not decide which."), p("Native findings remain review signals", "h2"), p("Broad source scanners can surface assertions, weak-hash uses, serialization APIs and import-only records. Invarune emphasizes selected agent/MCP configuration and execution risks with control/source mappings. Secret scanners, dependency/CVE scanners and runtime/adversarial tests add other evidence. No tool is awarded false positives merely because another tool lacks the same rule."), p("No new ground-truth percentage is claimed for public projects", "h2"), p("This deterministic rerun does not perform Claude adjudication or independent exploit validation. Earlier model-authentication failures remain historical failures, and earlier selected source audits remain separate evidence. Confirmed-vulnerability precision and public-project recall are unavailable."), link("Complete finding-by-finding ledger", REPO + comparison_path + "/FINDINGS.md"), link("Machine-readable overlap and unmatched sets", REPO + comparison_path + "/overlaps.json")]

    story += [PageBreak(), heading("An agent/MCP review workflow", "workflow"), p("Invarune's value is the traceable review workflow around selected security checks. These are product capabilities documented and tested by this project, not a score against untested competitor editions.")]
    story += [table([["Capability", "How to use the evidence"], ["Source or built Linux image", "Inspect supported source/configuration and image metadata without starting target code or a container. Compiled-only logic remains unassessed."], ["Offline control explorer", "Use invscan --ask and explain commands without a model, login or network. Each answer explains control meaning, sources and limits."], ["{rules} rules / {controls} controls / {checks} checks".format(**catalog), "Rules partially map to " + str(catalog["mapped_controls"]) + " controls; the remaining controls and complete acceptance checks need other evidence. No inferred compliance pass."], ["Concrete remediation", "Reports connect findings to agent/MCP context, proposed fixes, verification steps and possible mitigating layers. Undeployed defenses do not lower risk automatically."], ["Optional bounded AI review", "Enable official CLI or API/gateway review explicitly. Deterministic validation constrains evidence/citations/budgets; model judgments stay advisory."], ["Review and justification roundtrip", "Carry edited supported report inputs into a fresh scan. Accepted justifications stay justified, excluded from the applicable scored denominator, and retain evidence bindings."]], [142, 357]), Spacer(1, 12), p("Use complementary runtime validation for MCP authorization, tenant separation, sandbox escape resistance, egress enforcement and prompt-injection task outcomes. A repository or image cannot establish the deployed identity, network policy or human approval process.", "small"), link("CLI quick start", SITE + "docs/QUICKSTART/"), link("Controls, benchmarks and primary source mappings", SITE + "docs/SOURCE_MAP/")]

    story += [PageBreak(), heading("Reproduce and audit the result", "provenance"), p("Every published count is derived from the linked local execution artifacts. The PDF builder rejects mismatched fixture hashes/labels, invalid ledger totals, overlap partition errors, mismatched scanner versions and changed before/after project inputs."), table([["Input", "SHA-256"]] + [[name, digest] for name, digest in list((item for item in data["hashes"].items() if "/" not in item[0]))[:7 if data.get("extensions") else None]], [169, 330]), Spacer(1, 12), p("Reproduction sequence", "h2"), p("1. Read this benchmark README and exact tool/source lock.<br/>2. Recreate the pinned source exports and verify their manifests.<br/>3. Run the frozen baseline and final scanner independently; preserve both receipts.<br/>4. Run the recorded external versions and rule pack on the same exports.<br/>5. Regenerate the exhaustive observation/overlap ledger and fixture evaluations.<br/>6. Build the dashboard/PDF from those receipts, then render and visually inspect every page."), link("Reproduction protocol and tool configuration", REPO + comparison_path + "/README.md"), link("Source selection and pinned repositories", REPO + "/blob/main/benchmarks/real-world/manifest.json"), link("PDF and site authoring instructions", SITE + "docs/PUBLISHING/"), p("Invarune by NimeshBuild is an original engineering synthesis. Referenced publishers and compared projects do not endorse it. Third-party materials retain their own terms. Public repository visibility does not independently grant an open-source license.", "small")]

    output.parent.mkdir(parents=True, exist_ok=True)
    document = Doc(str(output), pagesize=A4, leftMargin=48, rightMargin=48, topMargin=60, bottomMargin=55, invariant=1, title="Invarune | Benchmark update " + version, author="NimeshBuild", subject="Paired fixture improvement, fresh public-project scanner comparison, and traceable limits")
    document.addPageTemplates(PageTemplate(id="brand", frames=[Frame(48, 55, A4[0] - 96, A4[1] - 115, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=chrome))
    document.build(story)
    return {"path": output.relative_to(ROOT).as_posix() if output.is_relative_to(ROOT) else output.name, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "inputs": data["hashes"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=INPUT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    data = load(args.input_dir)
    result = {"status": "validated", "cases": data["after"]["case_count"], "observations": data["observations.json"]["observation_count"]} if args.validate_only else build(data, args.output)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
