#!/usr/bin/env python3
"""Build deterministic, branded dashboard charts from recorded benchmark evidence.

Only local JSON receipts are read. No scanner, target, model, network request,
JavaScript or PDF renderer runs. Final builds require paired unchanged-corpus
accuracy reports; --preview labels an unfinished after measurement explicitly.
"""
import argparse
from collections import Counter
import csv
import hashlib
import html
import io
import itertools
import json
from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs/BENCHMARK_DASHBOARD.md"
ASSETS = ROOT / "docs/assets/benchmarks"
TOOLS = ("invarune", "semgrep", "bandit", "gitleaks")
NAMES = {"invarune": "Invarune", "semgrep": "Semgrep CE", "bandit": "Bandit", "gitleaks": "Gitleaks"}
OUTCOMES = ("true_positive", "true_negative", "false_positive", "false_negative")
SHORT = {"true_positive": "TP", "true_negative": "TN", "false_positive": "FP", "false_negative": "FN"}
COLORS = {"true_positive": "#59dec2", "true_negative": "#7da8f7", "false_positive": "#ffc16f", "false_negative": "#ff8598"}
BG, PANEL, INK, MUTED, LINE = "#081d29", "#102e3c", "#edf9fc", "#aac4cd", "#294755"
PROJECT_NAMES = {"mcp-reference": "MCP reference", "github-mcp": "GitHub MCP", "autogen": "AutoGen", "crewai": "CrewAI", "langgraph": "LangGraph", "openhands": "OpenHands", "pydantic-ai": "Pydantic AI", "fastmcp": "FastMCP"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fail(message):
    raise ValueError(message)


def integer(value):
    return type(value) is int and value >= 0


def load(path, inputs):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT):
        fail("Dashboard inputs must be inside the repository for portable provenance links")
    raw = path.read_bytes()
    if len(raw) > 30_000_000:
        fail("Dashboard input exceeds the 30 MB bound")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail("Duplicate JSON key in dashboard evidence")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: fail("Nonfinite JSON in dashboard evidence"))
    inputs[path.relative_to(ROOT).as_posix()] = {"sha256": sha(raw), "bytes": len(raw)}
    return value


def check_accuracy(report, corpus, corpus_hash):
    if report["corpus_sha256"] != corpus_hash or report["corpus_version"] != corpus["version"]:
        fail("Accuracy report does not bind the selected corpus bytes/version")
    expected = {item["id"]: item for item in corpus["cases"]}
    cases = {item["id"]: item for item in report["cases"]}
    if len(cases) != len(report["cases"]) or set(cases) != set(expected) or report["case_count"] != len(cases):
        fail("Accuracy report has missing, duplicate or different case identities")
    if report["analysis_error_cases"] or any(item.get("analysis_errors") for item in cases.values()):
        fail("This accuracy dashboard requires explicitly complete fixture analysis")
    counts = Counter()
    for identifier, item in cases.items():
        source = expected[identifier]
        if item["path"] != source["path"] or item["suite"] != source["suite"]:
            fail("Accuracy case identity or suite differs from the selected corpus")
        labels = {a["rule_id"]: a for a in item["assertions"]}
        if len(labels) != len(item["assertions"]) or set(labels) != set(source["expect"]):
            fail("Accuracy assertions do not account for the corpus labels")
        for rule, label in labels.items():
            if type(label["expected"]) is not bool or type(label["detected"]) is not bool or label["expected"] != source["expect"][rule]:
                fail("Accuracy assertion altered an expected label or contains a non-boolean outcome")
            outcome = ("true_positive" if label["expected"] else "false_positive") if label["detected"] else ("false_negative" if label["expected"] else "true_negative")
            if label["outcome"] != outcome:
                fail("Accuracy outcome disagrees with its label and actual detection")
            counts[outcome] += 1
    for key in OUTCOMES:
        if not integer(report["overall"][key]) or report["overall"][key] != counts[key]:
            fail("Accuracy summary differs from case-level outcomes")
    if report["overall"]["assertions"] != sum(counts.values()):
        fail("Accuracy summary denominator differs from case-level outcomes")
    for key, numerator, denominator in (
        ("precision", counts["true_positive"], counts["true_positive"] + counts["false_positive"]),
        ("recall", counts["true_positive"], counts["true_positive"] + counts["false_negative"]),
        ("false_positive_rate", counts["false_positive"], counts["false_positive"] + counts["true_negative"]),
        ("false_negative_rate", counts["false_negative"], counts["false_negative"] + counts["true_positive"]),
    ):
        expected_rate = round(numerator / denominator, 6) if denominator else None
        if report["overall"][key] != expected_rate:
            fail("Accuracy summary rate differs from its explicit denominator")
    return dict(counts)


def check_comparison(ledger, overlaps, runs):
    observations = ledger["observations"]
    by_id = {item["id"]: item for item in observations}
    counts = dict(Counter(item["tool"] for item in observations))
    if set(counts) - set(TOOLS) or len(by_id) != len(observations) or ledger["observation_count"] != len(observations) or ledger["counts_by_tool"] != counts:
        fail("Observation IDs or tool totals are inconsistent")
    if overlaps["observation_ledger_sha256"] != sha(canonical(ledger)):
        fail("Overlap input does not bind the current observation ledger")
    pairs = set()
    for pair in overlaps["pairs"]:
        left, right, totals = pair["left_tool"], pair["right_tool"], pair["counts"]
        identity = frozenset((left, right))
        if len(identity) != 2 or identity in pairs or not identity <= set(TOOLS):
            fail("Duplicate or invalid comparison pair")
        pairs.add(identity)
        for field, counter in (("one_to_one_matches", "one_to_one_pairs"), ("ambiguous_family_location_edges", "ambiguous_edges"), ("location_only_edges", "location_only_edges")):
            if len(pair[field]) != totals[counter]:
                fail("Overlap edge count differs from its summary")
            for edge in pair[field]:
                if edge["left_id"] not in by_id or edge["right_id"] not in by_id or by_id[edge["left_id"]]["tool"] != left or by_id[edge["right_id"]]["tool"] != right:
                    fail("Overlap edge refers to a missing or wrong-tool observation")
        for side, tool in (("left", left), ("right", right)):
            unmatched = pair[side + "_without_family_match"]
            matched = {edge[side + "_id"] for kind in ("one_to_one_matches", "ambiguous_family_location_edges") for edge in pair[kind]}
            all_ids = {identifier for identifier, item in by_id.items() if item["tool"] == tool}
            if (totals[side + "_observations"] != counts.get(tool, 0) or len(unmatched) != totals[side + "_without_family_match"]
                    or len(unmatched) != len(set(unmatched)) or matched & set(unmatched) or matched | set(unmatched) != all_ids):
                fail("Overlap accounting is not exhaustive and disjoint")
    if pairs != {frozenset(pair) for pair in itertools.combinations(TOOLS, 2)}:
        fail("Comparison must retain all six tool pairs")
    source = {item["project_id"]: item for item in ledger["inputs"]}
    if len(source) != len(ledger["inputs"]):
        fail("Duplicate project input in observation ledger")
    run_ids = {(item["tool"], item["project_id"]) for item in runs}
    if len(run_ids) != len(runs) or run_ids != set(itertools.product(TOOLS, source)):
        fail("Run receipts do not cover each tool and selected project exactly once")
    observed = Counter((item["tool"], item["project_id"]) for item in observations)
    run_by_id = {(item["tool"], item["project_id"]): item for item in runs}
    for item in observations:
        project = source.get(item["project_id"])
        run = run_by_id.get((item["tool"], item["project_id"]))
        if (not project or not run or item["revision"] != project["revision"]
                or item["source_manifest_sha256"] != project["source_manifest_sha256"]
                or item["tool_version"] != run["version"]
                or item["raw_report_sha256"] != run["raw_report_sha256"]):
            fail("Observation does not bind its pinned source and tool run")
    for run in runs:
        if (run.get("finding_count") or 0) != observed[(run["tool"], run["project_id"])]:
            fail("Run finding count differs from its observations")
        if run["source_manifest_sha256"] != source[run["project_id"]]["source_manifest_sha256"]:
            fail("Run and ledger disagree on pinned source identity")
        if run["tool"] == "invarune" and (not integer(run["files_reported_scanned"]) or run["files_reported_scanned"] > source[run["project_id"]]["files"] or not integer(run.get("coverage_gaps"))):
            fail("Invarune source coverage has an invalid denominator")


def changed_assertions(before, after):
    changes = []
    old = {item["id"]: item for item in before["cases"]}
    for item in after["cases"]:
        for a, b in zip(sorted(old[item["id"]]["assertions"], key=lambda x: x["rule_id"]), sorted(item["assertions"], key=lambda x: x["rule_id"])):
            if a["outcome"] != b["outcome"]:
                changes.append({"case_id": item["id"], "rule_id": b["rule_id"], "expected": b["expected"],
                                "before_outcome": a["outcome"], "after_outcome": b["outcome"],
                                "before_detected": a["detected"], "after_detected": b["detected"]})
    return sorted(changes, key=lambda item: (item["case_id"], item["rule_id"]))


def check_pair(pair, before, after, before_hash, after_hash, corpus_path, baseline, runs):
    corpus = pair["corpus"]
    if (corpus["path"] != corpus_path or corpus["sha256"] != before["corpus_sha256"]
            or corpus["version"] != before["corpus_version"] or corpus["case_count"] != before["case_count"]
            or pair["input_invariants"]["identical_corpus_sha256"] is not True
            or pair["input_invariants"]["identical_case_ids_and_labels"] is not True):
        fail("Paired receipt does not bind the unchanged selected corpus")
    for key, report, report_hash in (("before", before, before_hash), ("after", after, after_hash)):
        bound = pair[key]
        if (bound["accuracy_report"] != "accuracy-" + key + ".json"
                or bound["accuracy_report_sha256"] != report_hash
                or any(bound[field] != report[field] for field in ("tool_version", "overall", "by_suite", "failed_case_ids", "analysis_error_cases"))):
            fail("Paired receipt differs from the recorded " + key + " accuracy report")
    if (baseline["scanner_version"] != before["tool_version"] or baseline["corpus_sha256"] != before["corpus_sha256"]
            or baseline["corpus_version"] != before["corpus_version"] or baseline["cases"] != before["case_count"]
            or pair["before"]["implementation_sha256"] != baseline["implementation_sha256"]):
        fail("Paired before result does not bind the frozen baseline identity")
    if {run["implementation_sha256"] for run in runs if run["tool"] == "invarune"} != {pair["after"]["implementation_sha256"]}:
        fail("Paired after result and source runs use different implementations")
    if sorted(pair["changes"], key=lambda item: (item["case_id"], item["rule_id"])) != changed_assertions(before, after):
        fail("Paired changed assertions differ from the recorded case-level outcomes")
    remaining = [{"case_id": item["id"], **{key: assertion[key] for key in ("rule_id", "expected", "detected", "outcome")}}
                 for item in after["cases"] for assertion in item["assertions"]
                 if assertion["outcome"] in ("false_positive", "false_negative")]
    if sorted(pair["remaining_mismatches"], key=lambda item: (item["case_id"], item["rule_id"])) != sorted(remaining, key=lambda item: (item["case_id"], item["rule_id"])):
        fail("Paired receipt hides or changes remaining labeled mismatches")


def recorded_catalog_counts(directory, runs, inputs):
    """Read selected catalog scope only from reports bound to actual executions."""
    counts = None
    for run in runs:
        if run["tool"] != "invarune":
            continue
        project = run["project_id"]
        receipt = load(directory / "invarune-receipts-after" / (project + ".json"), inputs)
        path = directory / "invarune-reports" / project / "report.json"
        report = load(path, inputs)
        digest = inputs[path.resolve().relative_to(ROOT).as_posix()]["sha256"]
        repeated = receipt.get("repeated_runs", [])
        if (not repeated or any(item.get("report_sha256", {}).get("report.json") != digest for item in repeated)
                or run["raw_report_sha256"] != digest or receipt["scan_id"] != report["scan_id"]
                or receipt["tool"] != report["tool"] or receipt["source_manifest_sha256"] != run["source_manifest_sha256"]
                or report["tool"]["version"] != run["version"]
                or report["tool"]["implementation_sha256"] != run["implementation_sha256"]):
            fail("Catalog source report differs from its recorded execution")
        rules = set(report["coverage"]["rules_enabled"])
        controls = report["controls"]
        selected = {"rules": len(rules), "controls": len(controls),
                    "checks": sum(len(control["checks"]) for control in controls),
                    "mapped_controls": sum(bool(rules.intersection(control["automated_rule_ids"])) for control in controls)}
        if counts is not None and selected != counts:
            fail("Recorded source reports have inconsistent selected catalog scopes")
        counts = selected
    if counts is None:
        fail("No recorded source report supplies catalog scope")
    return counts


def inputs_for(args):
    inputs = {}
    directory = args.comparison.resolve()
    corpus = load(args.corpus, inputs)
    corpus_hash = inputs[args.corpus.resolve().relative_to(ROOT).as_posix()]["sha256"]
    before = load(args.before, inputs)
    check_accuracy(before, corpus, corpus_hash)
    after = None if args.preview else load(args.after, inputs)
    if after is not None:
        check_accuracy(after, corpus, corpus_hash)
        if before["corpus_sha256"] != after["corpus_sha256"] or before["case_count"] != after["case_count"]:
            fail("Paired accuracy requires the same exact corpus bytes and case identities")
    ledger, overlaps, run_file = (load(directory / name, inputs) for name in ("observations.json", "overlaps.json", "run-status.json"))
    check_comparison(ledger, overlaps, run_file["runs"])
    metadata = load(directory / "external-results/cisco-metadata.json", inputs)
    if (metadata["tool"] != "cisco-ai-mcp-scanner" or metadata["project_id"] not in {item["project_id"] for item in ledger["inputs"]}
            or len(metadata["items"]) != len(metadata["declarations"])
            or {item["name"] for item in metadata["items"]} != {item["name"] for item in metadata["declarations"]}
            or metadata["finding_count"] != sum(item["finding_count"] for item in metadata["items"])):
        fail("MCP metadata receipt has inconsistent input or finding accounting")
    if after and {run["version"] for run in run_file["runs"] if run["tool"] == "invarune"} != {after["tool_version"]}:
        fail("Final source comparison and after fixture receipt use different Invarune versions")
    changes, pair, baseline = [], None, None
    if after:
        pair = load(directory / "before-after-accuracy.json", inputs)
        baseline = load(directory / "baseline-identity.json", inputs)
        if pair["experiment"] != ledger["experiment"]:
            fail("Paired fixture receipt and source ledger belong to different experiments")
        check_pair(pair, before, after, inputs[args.before.resolve().relative_to(ROOT).as_posix()]["sha256"],
                   inputs[args.after.resolve().relative_to(ROOT).as_posix()]["sha256"],
                   args.corpus.resolve().relative_to(ROOT).as_posix(), baseline, run_file["runs"])
        changes = [{"case_id": item["case_id"], "rule_id": item["rule_id"], "before": item["before_outcome"], "after": item["after_outcome"]}
                   for item in changed_assertions(before, after)]
    data = {"inputs": inputs, "directory": directory.relative_to(ROOT).as_posix(), "before_path": args.before.resolve().relative_to(ROOT).as_posix(),
            "after_path": None if after is None else args.after.resolve().relative_to(ROOT).as_posix(), "before": before, "after": after,
            "current": after or before, "corpus": corpus, "ledger": ledger, "overlaps": overlaps, "runs": run_file["runs"], "changes": changes,
            "pair": pair, "baseline": baseline, "metadata": metadata, "preview": args.preview,
            "catalog_counts": recorded_catalog_counts(directory, run_file["runs"], inputs) if after else None}
    skills_path = directory / "skills-tools-accuracy.json"
    if after and skills_path.exists():
        skills = load(skills_path, inputs)
        skills_corpus_path = ROOT / "benchmarks/skills_tools_accuracy.json"
        skills_corpus = load(skills_corpus_path, inputs)
        check_accuracy(skills, skills_corpus, sha(skills_corpus_path.read_bytes()))
        if skills["tool_version"] != after["tool_version"]:
            fail("Skill evidence uses a different scanner version")
        skill_receipt = load(directory / "skills-tools-evaluation-receipt.json", inputs)
        if (skill_receipt["implementation_sha256"] != pair["after"]["implementation_sha256"]
                or skill_receipt["tool_version"] != after["tool_version"]
                or skill_receipt.get("separate_denominator") is not True):
            fail("Skill evaluation receipt does not bind the final implementation and separate scope")
        if (skill_receipt["corpus"]["path"] != "benchmarks/skills_tools_accuracy.json"
                or skill_receipt["corpus"]["sha256"] != sha(skills_corpus_path.read_bytes())
                or skill_receipt["report"]["path"] != "skills-tools-accuracy.json"
                or skill_receipt["report"]["sha256"] != sha(skills_path.read_bytes())
                or skill_receipt["overall"] != skills["overall"]
                or skill_receipt["case_count"] != skills["case_count"]):
            fail("Skill receipt differs from recorded corpus/report bytes or counts")
        data["skills"] = skills
    return data



def esc(value):
    return html.escape(str(value), quote=True)


class SVG:
    def __init__(self, height, title, description):
        self.height = height
        self.parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 %s" role="img" aria-labelledby="title desc">' % height,
                      '<title id="title">%s</title><desc id="desc">%s</desc>' % (esc(title), esc(description)),
                      '<rect width="1000" height="%s" rx="24" fill="%s"/>' % (height, BG),
                      '<g font-family="Arial, Helvetica, sans-serif">']
        self.text(36, 42, "INVARUNE  /  BENCHMARK LAB", 13, "#59dec2", weight="700", spacing="2")
        self.text(36, 81, title, 28, INK, weight="700")

    def text(self, x, y, value, size=18, color=INK, weight="400", anchor="start", spacing="0"):
        self.parts.append('<text x="%s" y="%s" fill="%s" font-size="%s" font-weight="%s" text-anchor="%s" letter-spacing="%s">%s</text>' % (x, y, color, size, weight, anchor, spacing, esc(value)))

    def wrap(self, x, y, value, width=100, size=16, color=MUTED, step=23):
        for index, line in enumerate(textwrap.wrap(value, width, break_long_words=False, break_on_hyphens=False)):
            self.text(x, y + index * step, line, size, color)

    def rect(self, x, y, width, height, color=PANEL, radius=10):
        self.parts.append('<rect x="%s" y="%s" width="%s" height="%s" rx="%s" fill="%s"/>' % (x, y, width, height, radius, color))

    def line(self, x1, y1, x2, y2, color=LINE):
        self.parts.append('<path d="M%s %sH%s" stroke="%s"/>' % (x1, y1, x2, color) if y1 == y2 else '<path d="M%s %sL%s %s" stroke="%s"/>' % (x1, y1, x2, y2, color))

    def finish(self, footer):
        self.line(36, self.height - 48, 964, self.height - 48)
        self.text(36, self.height - 22, footer, 13, MUTED)
        return "\n".join(self.parts + ["</g></svg>\n"])


def metric(report, key):
    values = report["overall"]
    return values[key]


def fraction(numerator, denominator):
    return "n/a" if not denominator else "%.1f%%" % (100 * numerator / denominator)


def progress_svg(data):
    n = metric(data["before"], "assertions")
    chart = SVG(530, "Same fixtures. Measured outcomes.", "Before and after outcomes on identical labeled corpus bytes. These are synthetic rule-presence labels, not production vulnerabilities.")
    chart.text(36, 113, "%s labeled assertions · corpus %s · identical source and expected labels" % (n, data["before"]["corpus_version"]), 16, MUTED)
    for index, report in enumerate((data["before"], data["after"])):
        x = 36 + 480 * index
        chart.rect(x, 142, 448, 278)
        chart.text(x + 24, 175, "BEFORE" if index == 0 else "AFTER", 13, MUTED, "700", spacing="2")
        if report is None:
            chart.text(x + 24, 235, "Measurement pending", 25, INK, "700")
            chart.wrap(x + 24, 276, "Preview only. The final dashboard requires the recorded after run; no outcome is estimated.", 45, 17)
            continue
        values = report["overall"]
        correct = values["true_positive"] + values["true_negative"]
        chart.text(x + 24, 232, "%s / %s" % (correct, n), 48, INK, "700")
        chart.text(x + 24, 264, "labels matched · " + fraction(correct, n), 18, MUTED)
        chart.text(x + 24, 296, "Invarune " + report["tool_version"], 16, "#59dec2")
        cursor = x + 24
        for kind in OUTCOMES:
            width = 400 * values[kind] / n
            if width:
                chart.rect(round(cursor, 2), 320, round(width, 2), 18, COLORS[kind], 0)
            cursor += width
        for j, kind in enumerate(OUTCOMES):
            chart.text(x + 24 + j * 99, 372, "%s %s" % (SHORT[kind], values[kind]), 18, COLORS[kind], "700")
        chart.text(x + 24, 399, "%s mismatches retained in the result" % (values["false_positive"] + values["false_negative"]), 15, MUTED)
    chart.text(36, 454, "TP/TN: matched labels     FP: unexpected detection     FN: missed expected detection", 16, MUTED)
    return chart.finish("Development-visible, project-authored fixtures. Counts are not a security score or production accuracy.")


def confusion_svg(data):
    report = data["current"]
    c = report["overall"]
    chart = SVG(510, "The full confusion counts", "All fixture outcomes, including challenge cases. Precision and recall denominators are displayed explicitly.")
    chart.text(36, 114, "Recorded " + ("baseline only" if data["preview"] else "after result") + " · Invarune " + report["tool_version"] + " · " + str(c["assertions"]) + " assertions", 16, MUTED)
    for i, kind in enumerate(("true_positive", "false_negative", "false_positive", "true_negative")):
        x, y = 36 + (i % 2) * 242, 145 + (i // 2) * 137
        chart.rect(x, y, 224, 119)
        chart.text(x + 19, y + 31, SHORT[kind] + "  " + kind.replace("_", " "), 15, COLORS[kind], "700")
        chart.text(x + 19, y + 87, c[kind], 47, INK, "700")
    chart.text(566, 177, "PRECISION", 13, MUTED, "700", spacing="2")
    chart.text(566, 223, fraction(c["true_positive"], c["true_positive"] + c["false_positive"]), 37, "#59dec2", "700")
    chart.text(566, 252, "%s / %s positive detections matched labels" % (c["true_positive"], c["true_positive"] + c["false_positive"]), 16, MUTED)
    chart.text(566, 305, "RECALL", 13, MUTED, "700", spacing="2")
    chart.text(566, 351, fraction(c["true_positive"], c["true_positive"] + c["false_negative"]), 37, "#7da8f7", "700")
    chart.text(566, 380, "%s / %s expected detections were found" % (c["true_positive"], c["true_positive"] + c["false_negative"]), 16, MUTED)
    chart.text(36, 441, "Includes every regression and challenge case. Unlabeled detections are not scored.", 16, MUTED)
    return chart.finish("Positive = the named rule should fire. Negative = that rule should not fire; neither label proves safety.")


def coverage_svg(data):
    runs = {item["project_id"]: item for item in data["runs"] if item["tool"] == "invarune"}
    inputs = data["ledger"]["inputs"]
    chart = SVG(255 + 48 * len(inputs), "Source coverage stays beside findings", "Examined versus offered source files, with Invarune coverage gaps separately reported for each project.")
    versions = ", ".join(sorted({item["version"] for item in runs.values()}))
    chart.text(36, 112, "Invarune " + versions + " · selected pinned implementation files", 16, MUTED)
    chart.text(36, 153, "PROJECT", 12, MUTED, "700", spacing="1")
    chart.text(693, 153, "EXAMINED / OFFERED", 12, MUTED, "700")
    chart.text(934, 153, "GAPS", 12, MUTED, "700", anchor="end")
    for i, source in enumerate(inputs):
        y = 178 + i * 48
        run = runs[source["project_id"]]
        actual, total, gaps = run["files_reported_scanned"], source["files"], run["coverage_gaps"]
        chart.text(36, y + 18, PROJECT_NAMES.get(source["project_id"], source["project_id"]), 17)
        chart.rect(210, y, 450, 21, LINE, 4)
        if total:
            chart.rect(210, y, round(450 * actual / total, 2), 21, "#59dec2", 4)
        chart.text(694, y + 18, "%s / %s" % (format(actual, ","), format(total, ",")), 17)
        chart.rect(886, y - 4, 61, 32, "#483824" if gaps else PANEL, 8)
        chart.text(917, y + 18, gaps, 17, "#ffc16f" if gaps else MUTED, "700", anchor="middle")
    return chart.finish("File counts describe selected scope. Examined files can receive partial analysis; gaps are a separate measure.")


def family_rows(data):
    families = sorted({item["family"] for item in data["ledger"]["observations"]})
    counts = Counter((item["family"], item["tool"]) for item in data["ledger"]["observations"])
    return [(family, [counts[(family, tool)] for tool in TOOLS]) for family in families]


def run_categories(runs, tool):
    counts = Counter({"completed": 0, "partial": 0, "unsupported": 0, "other": 0})
    for run in runs:
        if run["tool"] != tool:
            continue
        status = run["status"]
        if status.startswith("unsupported"):
            counts["unsupported"] += 1
        elif not status.startswith("completed") or run.get("finding_count") is None:
            counts["other"] += 1
        elif "errors" in status or "gaps" in status or run.get("errors") or run.get("coverage_gaps", 0):
            counts["partial"] += 1
        else:
            counts["completed"] += 1
    return counts


def families_svg(data):
    rows = family_rows(data)
    chart = SVG(279 + len(rows) * 29, "Different tools expose different review work", "Every observed family is shown. Cell numbers are scanner observations, not unique vulnerabilities or tool quality scores.")
    chart.text(36, 113, "Observed families on this corpus · no intensity scale or winner ranking", 16, MUTED)
    xs = [556, 678, 800, 922]
    for x, tool in zip(xs, TOOLS):
        chart.text(x, 158, NAMES[tool], 17, "#59dec2" if tool == "invarune" else INK, "700", anchor="middle")
    for i, (family, values) in enumerate(rows):
        y = 184 + i * 29
        if i % 2 == 0:
            chart.rect(27, y - 18, 946, 29, PANEL, 0)
        chart.text(38, y + 1, family.replace("_", " "), 16, INK)
        for x, value in zip(xs, values):
            chart.text(x, y + 1, str(value) if value else "—", 16, "#79e5cf" if value else "#617d88", "700" if value else "400", anchor="middle")
    chart.text(36, chart.height - 75, "A dash means no observation in this family. It is not a verified absence of risk or a missing-vulnerability label.", 14, MUTED)
    return chart.finish("All %s observed families retained. Family semantics and rule packs differ; inspect the linked family map." % len(rows))


def overlap_rows(data):
    return [pair for pair in data["overlaps"]["pairs"] if pair["left_tool"] == "invarune"]


def overlaps_svg(data):
    chart = SVG(437, "Agreement is a starting point for review", "Conservative source-family overlap: one-to-one matches, ambiguous edges and unmatched observation counts with their denominators.")
    chart.text(36, 113, "Same project + path + compatible family + intersecting lines", 16, MUTED)
    for x, label in ((36, "PAIR"), (402, "1:1 PAIRS"), (554, "AMBIGUOUS"), (737, "INVARUNE ONLY*"), (909, "PARTNER ONLY*")):
        chart.text(x, 161, label, 12, MUTED, "700", anchor="start" if x == 36 else "middle")
    for i, pair in enumerate(overlap_rows(data)):
        y, c = 187 + i * 56, pair["counts"]
        chart.rect(27, y - 14, 946, 46, PANEL)
        chart.text(38, y + 15, "Invarune × " + NAMES[pair["right_tool"]], 18)
        chart.text(402, y + 15, c["one_to_one_pairs"], 24, "#59dec2", "700", anchor="middle")
        chart.text(554, y + 15, c["ambiguous_edges"], 21, "#ffc16f", "700", anchor="middle")
        chart.text(737, y + 15, "%s / %s" % (c["left_without_family_match"], c["left_observations"]), 19, INK, anchor="middle")
        chart.text(909, y + 15, "%s / %s" % (c["right_without_family_match"], c["right_observations"]), 19, INK, anchor="middle")
    chart.text(36, 374, "* No compatible-family counterpart in that tool. These are not measured false negatives.", 15, MUTED)
    return chart.finish("Ambiguous edges are not unique vulnerability pairs. Every observation and all six tool pairs remain in the ledger.")


def csv_text(headers, rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()


def page_text(data):
    current, before, after = data["current"], data["before"], data["after"]
    ledger = data["ledger"]
    comparison = "../" + data["directory"]
    projects = len(ledger["inputs"])
    offered = sum(item["files"] for item in ledger["inputs"])
    gaps = sum(item["coverage_gaps"] for item in data["runs"] if item["tool"] == "invarune")
    count = current["overall"]
    mismatch = count["false_positive"] + count["false_negative"]
    run_versions = {tool: ", ".join(sorted({run["version"] for run in data["runs"] if run["tool"] == tool})) for tool in TOOLS}
    if data["preview"]:
        lead = "> **Design preview — final after measurement pending.** Source charts retain the historical " + ledger["experiment"] + " inputs; the fixture baseline is the actual Invarune " + before["tool_version"] + " run. No new after result is implied.\n\n"
    else:
        lead = ""
    text = lead + '''<div class="ivb-dashboard" markdown>

<div class="ivb-hero" markdown>
<p class="ivb-kicker">INVARUNE BY NIMESHBUILD · BENCHMARK LAB</p>

# Know what changed. See what needs review.

Explore measured fixture outcomes, pinned source coverage and complementary scanner observations. Every chart links back to the recorded evidence; no chart is a production security score.

[Fixture progress](#fixture-progress){ .md-button .md-button--primary }
[Compare review surfaces](#complementary-review-surfaces){ .md-button }
[Read the method](BENCHMARK_GUIDE.md){ .md-button }

'''
    if after:
        text += '[Download the benchmark PDF](../output/pdf/invarune-benchmark-v' + after["tool_version"].replace(".", "")[:-1] + '.pdf){ .md-button }\n\n'
    text += '''
<div class="ivb-stats">
'''
    for value, label in ((str(projects), "pinned public projects"), (format(offered, ","), "shared source files offered"), (str(current["case_count"]), "labeled development fixtures"), (str(gaps), "Invarune analysis gaps retained")):
        text += '<div class="ivb-stat"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>\n'
    text += '</div>\n\n</div>\n\n'
    text += '**Recorded scope:** ' + '; '.join(NAMES[tool] + ' **' + esc(run_versions[tool]) + '**' for tool in TOOLS) + '. The source comparison and fixture experiment have separate denominators. [Input hashes and chart data](assets/benchmarks/dashboard-data.json).\n\n'
    text += '''## Fixture progress

The before/after comparison uses the **same corpus bytes, case IDs, source text and expected labels**. Every regression and challenge case remains in the result. These project-authored fixtures were visible during development; they are not an independent sample of production vulnerabilities.

![Paired fixture outcomes, with all TP, TN, FP and FN counts](assets/benchmarks/fixture-progress.svg)

'''
    if after:
        text += 'Invarune **' + before['tool_version'] + '** → **' + after['tool_version'] + '**. ' + str(len(data['changes'])) + ' case-level assertions changed outcome. [Before receipt](../' + data['before_path'] + ') · [After receipt](../' + data['after_path'] + ') · [Paired provenance](' + comparison + '/before-after-accuracy.json) · [Every changed assertion](assets/benchmarks/fixture-changes.csv).\n\n'
        text += '| Outcome | Before | After |\n| --- | ---: | ---: |\n'
        for key in OUTCOMES:
            text += '| ' + SHORT[key] + ' — ' + key.replace('_', ' ') + ' | ' + str(before['overall'][key]) + ' | ' + str(after['overall'][key]) + ' |\n'
        text += '\n'
        if data["changes"]:
            text += '### Inspect the changed cases\n\n| Fixture assertion | Rule | Before | After |\n| --- | --- | --- | --- |\n'
            for change in data["changes"][:12]:
                text += '| `' + esc(change['case_id']) + '` | `' + esc(change['rule_id']) + '` | ' + SHORT[change['before']] + ' | ' + SHORT[change['after']] + ' |\n'
            text += '\n'
            if len(data["changes"]) > 12:
                text += 'The table shows the first 12 changed assertions in case-ID order. The linked CSV retains all ' + str(len(data["changes"])) + '.\n\n'
    else:
        text += 'The recorded [before receipt](../' + data['before_path'] + ') is available. The after run is pending; no improvement is estimated.\n\n'
    text += 'Corpus **' + current['corpus_version'] + '** · SHA-256 `' + current['corpus_sha256'] + '`. Source/label revisions are not silently combined with this pair. [Corpus and rationale](../benchmarks/static_accuracy.json) · [Accuracy methodology and label corrections](RULE_ACCURACY.md).\n\n'
    text += '''### Keep the complete outcome visible

![Full fixture confusion counts and explicit precision/recall denominators](assets/benchmarks/confusion.svg)

'''
    text += '**' + str(mismatch) + ' labeled mismatches remain** in the recorded ' + ('baseline' if data['preview'] else 'after result') + ': **' + str(count['false_positive']) + ' false-positive labels** and **' + str(count['false_negative']) + ' false-negative labels**. A negative fixture says only that its named rule should not fire; it does not establish that an application is safe. Unlabeled detections are retained by the evaluator but are not assigned invented labels.\n\n'
    if after and data["pair"]["remaining_mismatches"]:
        text += '| Remaining fixture | Rule | Outcome |\n| --- | --- | --- |\n'
        for item in sorted(data["pair"]["remaining_mismatches"], key=lambda row: (row["case_id"], row["rule_id"]))[:12]:
            text += '| `' + esc(item['case_id']) + '` | `' + esc(item['rule_id']) + '` | ' + SHORT[item['outcome']] + ' |\n'
        text += '\nRead the exact source and authored rationale in the linked corpus before generalizing these outcomes. The [paired receipt](' + comparison + '/before-after-accuracy.json) retains every remaining mismatch.\n\n'
    if data.get("skills"):
        skills = data["skills"]
        text += "## Skills and malicious-tool indicators\n\n![Separate skill/tool fixture outcomes](assets/benchmarks/skills-tools.svg)\n\n"
        text += ("The new **" + str(skills["case_count"]) + "-case / " + str(skills["overall"]["assertions"]) + "-assertion** corpus is separate from the unchanged 113-assertion comparison. It covers direct instruction hijacking, credential-transfer directives, concealed/approval-bypassing actions, contradictory tool annotations, safe counterexamples and obfuscation.\n\n")
        text += ("All known misses remain visible. These authored risk-pattern labels do not establish malicious intent or deployed exploitability. The eight-project export excludes most skill documentation, so those source runs do not measure complete skill-package coverage. [Skill labels](../benchmarks/skills_tools_accuracy.json) · [Actual outcomes](" + comparison + "/skills-tools-accuracy.json) · [Every scan and its limits](SCAN_COVERAGE.md).\n\n")
        text += "| Known skill/tool miss | Why it remains |\n| --- | --- |\n"
        for case in skills["cases"]:
            if any(a["outcome"] in {"false_positive", "false_negative"} for a in case["assertions"]):
                text += "| `" + esc(case["id"]) + "` | " + esc(case["rationale"]) + " |\n"
        text += "\n"
    text += '''## Source coverage

Equal exported input does not mean equal language support, rule scope or successful analysis. The chart shows Invarune's examined-file inventory with coverage gaps alongside it. Neither the bar length nor a zero-gap count proves runtime control effectiveness.

![Per-project examined and offered files with separate coverage gaps](assets/benchmarks/source-coverage.svg)

'''
    text += '[Exact run statuses](' + comparison + '/run-status.json) · [Pinned source manifest](../benchmarks/real-world/manifest.json) · [Readable comparison](' + comparison + '/README.md). No target application, MCP server, dependency install hook or exploit is executed by this source protocol. Optional model review is outside the deterministic comparison.\n\n'
    text += '### Retain unsupported and partial runs\n\nEvery tool has ' + str(projects) + ' selected project inputs. These status counts describe the recorded execution; a completed run does not prove full coverage.\n\n| Tool | Completed, no recorded analysis errors/gaps | Completed with errors/gaps | Unsupported | Other/incomplete |\n| --- | ---: | ---: | ---: | ---: |\n'
    for tool in TOOLS:
        categories = run_categories(data["runs"], tool)
        text += '| ' + NAMES[tool] + ' | ' + ' | '.join(str(categories[key]) for key in ("completed", "partial", "unsupported", "other")) + ' |\n'
    text += '\nUnsupported input has no finding verdict; its missing count is never presented as a clean zero. File-count fields also differ by tool: a null inventory is unknown, not zero files. Exact project statuses and native errors remain in the linked receipts.\n\n'
    if after:
        text += '### Open a full project report\n\nThese are the final deterministic source scans behind this comparison. Each download retains findings, precise remediation, control/check review scope and analysis gaps. The report count is not a vulnerability verdict.\n\n| Pinned project | Review report | Machine-readable evidence |\n| --- | --- | --- |\n'
        for source in ledger['inputs']:
            project = source['project_id']
            location = comparison + '/invarune-reports/' + project + '/report.'
            raw_markdown = 'https://raw.githubusercontent.com/nimeshbuilds/invarune/main/' + data['directory'] + '/invarune-reports/' + project + '/report.md'
            text += '| ' + esc(PROJECT_NAMES.get(project, project)) + ' | [HTML](' + location + 'html) · [Markdown](' + raw_markdown + ') | [JSON](' + location + 'json) · [SARIF](' + location + 'sarif) |\n'
        text += '\n'
    text += '''## Complementary review surfaces

Each cell below records observations in an explicit family. The display uses the same visual emphasis for every tool and deliberately avoids a "more findings wins" scale. Imports, audit observations, unsafe calls and policy signals are different units of work. Review the family predicate and successful analysis scope before calling a tool-only result a missed vulnerability.

![All observed security families across the four source scanners](assets/benchmarks/family-footprint.svg)

'''
    text += '[Accessible family/count table](assets/benchmarks/family-counts.csv) · [Exact family definitions](' + comparison + '/rule-family-map.json) · [Every source observation](' + comparison + '/FINDINGS.md). All **' + format(ledger['observation_count'], ',') + '** observations remain separate records; their total is not a confirmed vulnerability count.\n\n'
    text += '''### Where observations meet

![Conservative one-to-one overlap, ambiguity and unmatched denominators](assets/benchmarks/overlap.svg)

'''
    text += 'Matching requires the same project and source path, a compatible family and intersecting inclusive lines. No nearest-line heuristic is used. Multiple possible counterparts stay ambiguous. [All six pairwise comparisons](' + comparison + '/overlaps.json) retain the complete matched/unmatched accounting. Agreement is not a true-positive label, and lack of a counterpart is not a false-negative label.\n\n'
    metadata = data["metadata"]
    text += '### Separate MCP metadata track\n\nCisco AI MCP Scanner **' + esc(metadata['version']) + '** has a separate recorded YARA-only run on **' + str(len(metadata['items'])) + ' literal tool names/descriptions** extracted from the MCP filesystem reference server. Recorded status: `' + esc(metadata['status']) + '`; **' + str(metadata['finding_count']) + ' reported findings**. [Metadata input, results and limits](' + comparison + '/external-results/cisco-metadata.json).\n\n'
    text += 'This is partial offline metadata, not a captured `tools/list` response or a complete MCP server assessment. Schemas are placeholders; computed descriptions, runtime behavior, other servers and Cisco’s API/model/behavioral analyzers were outside this track. A zero here does not establish tool safety and is not mixed into source-scanner accuracy or overlap.\n\n'
    text += '''## What Invarune brings to the review

These are product capabilities, not claims that another tool lacks them.

<div class="ivb-capabilities" markdown>

<div class="ivb-capability" markdown>
<span class="ivb-number">01 / CONTEXT</span>
### Agent and MCP control context
__RECORDED_CATALOG_CONTEXT__
[Explore the controls](SECURITY_EXPLORER.md)
</div>

<div class="ivb-capability" markdown>
<span class="ivb-number">02 / ARTIFACTS</span>
### Source or a built image
Inspect supported packaged files, image metadata and retained-layer signals without starting the target. Binary logic, deployed identity and CVEs remain separate work.
[Understand image scope](IMAGE_SCANNING.md)
</div>

<div class="ivb-capability" markdown>
<span class="ivb-number">03 / REVIEW</span>
### Findings with a next step
Every static finding has concrete fix guidance, agent/MCP relevance and verification steps. Evidence-bound justifications remain visible and never become verified passes.
[Browse reports and PDFs](REPORT_LIBRARY.md)
</div>

<div class="ivb-capability" markdown>
<span class="ivb-number">04 / OPTIONAL AI</span>
### Advisory review with boundaries
The deterministic scan runs without a model. Optional review uses bounded evidence and validated responses; model opinions cannot lower static severity or waive findings.
[Read analyst limits](ANALYST.md)
</div>

</div>

## Know what this dashboard does not establish

- Fixture precision/recall is about explicit rule-presence labels, not production vulnerability truth. The test corpus is development-visible.
- Source observations do not establish reachability, attacker control, effective tenant isolation, sandbox resistance or deployed OAuth behavior.
- Different tool versions, rule packs, language coverage and parser outcomes must accompany any comparison. Unsupported input is not a clean result.
- No historical source-audit or model label is silently carried onto a new run. The earlier [50-observation source audit](../benchmarks/comparison-v010/SOURCE_AUDIT.md) and [failed Claude adjudication](../benchmarks/comparison-v010/ADJUDICATION.md) retain their original versions and limitations.

## Follow or reproduce the evidence

'''
    text += '| Evidence | Open it |\n| --- | --- |\n| Current source comparison | [Method and outcomes](' + comparison + '/README.md) · [full finding ledger](' + comparison + '/FINDINGS.md) |\n'
    if after:
        text += '| Current benchmark PDF | [Download Invarune ' + after['tool_version'] + ' benchmark update](../output/pdf/invarune-benchmark-v' + after['tool_version'].replace('.', '')[:-1] + '.pdf) |\n'
    text += '| Fixture labels | [Corpus](../benchmarks/static_accuracy.json) · [changed assertions](assets/benchmarks/fixture-changes.csv) |\n| Dashboard provenance | [Input hashes, exact counters and interpretation](assets/benchmarks/dashboard-data.json) |\n| Benchmark reading guide | [Denominators, source audits, protocols and unknowns](BENCHMARK_GUIDE.md) |\n| Downloadable reference and scan reports | [PDF library](REPORT_LIBRARY.md) |\n\n'
    text += '''The dashboard builder reads local receipts and emits deterministic SVG, CSV and Markdown. It does not rerun scanners or invoke a model. Preserve original receipts and use fresh output locations for a new experiment.

```sh
python3 scripts/build_benchmark_dashboard.py
python3 scripts/build_benchmark_dashboard.py --check
```

Read the [publication and source notice](../NOTICE.md). The research is an engineering synthesis, not publisher endorsement or a license grant for third-party standards, code or rules.

</div>
'''
    counts = data.get("catalog_counts")
    context = ("Within this recorded scope, {rules} deterministic rules map partially to {mapped_controls} of {controls} controls. "
               "All {checks} acceptance checks retain their source context and remaining human/runtime evidence needs.").format(**counts) if counts else (
                   "Rules provide partial static mappings to controls. Exact catalog totals are omitted because this preview has no bound final source report; acceptance checks still need human/runtime evidence.")
    text = text.replace("__RECORDED_CATALOG_CONTEXT__", context)
    # Keep chart labels readable on narrow screens with local horizontal scrolling.
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("![") and "assets/benchmarks/" in line:
            lines[index] = '<div class="ivb-chart" markdown>\n\n' + line + '\n\n</div>'
    return "\n".join(lines) + "\n"


def skills_svg(report):
    chart = SVG(435, "Skills and tools: direct evidence, explicit limits", "Separate development-visible corpus. Every safe and adversarial label remains in the denominator; not a maliciousness or production safety score.")
    chart.text(36, 117, "%s cases / %s explicit rule-presence assertions" % (report["case_count"], report["overall"]["assertions"]), 19, MUTED)
    for index, key in enumerate(OUTCOMES):
        x = 36 + 236 * index
        chart.rect(x, 148, 216, 142)
        chart.text(x + 20, 183, SHORT[key], 18, COLORS[key], "700")
        chart.text(x + 20, 248, report["overall"][key], 48, INK, "700")
    chart.wrap(36, 329, "Known semantic and language misses remain in the result. Optional AI can investigate bounded evidence; its judgment is advisory and does not establish detection guarantees.", 110, 17)
    return chart.finish("Separate fixture scope: not added to the 113-assertion before/after denominator.")


def outputs(data):
    charts = {"fixture-progress.svg": progress_svg(data), "confusion.svg": confusion_svg(data), "source-coverage.svg": coverage_svg(data), "family-footprint.svg": families_svg(data), "overlap.svg": overlaps_svg(data)}
    if data.get("skills"):
        charts["skills-tools.svg"] = skills_svg(data["skills"])
    provenance = {"schema_version": "1.0", "product": "Invarune by NimeshBuild", "generator": "scripts/build_benchmark_dashboard.py", "preview": data["preview"],
                  "comparison": data["ledger"]["experiment"], "inputs": data["inputs"], "fixture_corpus_sha256": data["current"]["corpus_sha256"],
                  "catalog_counts": data.get("catalog_counts"),
                  "before": {"tool_version": data["before"]["tool_version"], "overall": data["before"]["overall"]},
                  "after": None if data["after"] is None else {"tool_version": data["after"]["tool_version"], "overall": data["after"]["overall"]},
                  "skills": {"case_count": data["skills"]["case_count"], "overall": data["skills"]["overall"], "corpus_sha256": data["skills"]["corpus_sha256"]} if data.get("skills") else None,
                  "changed_assertions": data["changes"], "observations_by_tool": data["ledger"]["counts_by_tool"],
                  "metadata_track": {key: data["metadata"][key] for key in ("tool", "version", "status", "finding_count", "input_sha256", "raw_result_sha256")},
                  "interpretation": "Fixture counts use explicit development-visible rule-presence labels. Source observations and cross-tool overlap provide no confirmed-vulnerability, TP/FP or production-accuracy label.",
                  "charts": {name: {"sha256": sha(text.encode("utf-8"))} for name, text in charts.items()}}
    rendered = {PAGE: page_text(data)}
    rendered.update({ASSETS / name: text for name, text in charts.items()})
    rendered[ASSETS / "dashboard-data.json"] = json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    rendered[ASSETS / "family-counts.csv"] = csv_text(["family", *TOOLS], [(name, *counts) for name, counts in family_rows(data)])
    rendered[ASSETS / "fixture-changes.csv"] = csv_text(["case_id", "rule_id", "before", "after"], [[item[key] for key in ("case_id", "rule_id", "before", "after")] for item in data["changes"]])
    return rendered


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--comparison", type=Path, default=ROOT / "benchmarks/comparison-v014", help="Recorded comparison with observations, overlaps and run statuses")
    parser.add_argument("--before", type=Path, default=ROOT / "benchmarks/comparison-v014/accuracy-before.json", help="Actual before accuracy report")
    parser.add_argument("--after", type=Path, default=ROOT / "benchmarks/comparison-v014/accuracy-after.json", help="Actual after accuracy report; mandatory for final generation")
    parser.add_argument("--corpus", type=Path, default=ROOT / "benchmarks/static_accuracy.json", help="Exact unchanged corpus bound by both accuracy reports")
    parser.add_argument("--preview", action="store_true", help="Render a visibly labeled design preview without an after result; not final benchmark evidence")
    parser.add_argument("--check", action="store_true", help="Verify committed page/assets match the inputs without changing files")
    args = parser.parse_args(argv)
    try:
        rendered = outputs(inputs_for(args))
        mismatches = []
        for path, text in rendered.items():
            expected = text.encode("utf-8")
            if args.check:
                if not path.is_file() or path.read_bytes() != expected:
                    mismatches.append(path.relative_to(ROOT).as_posix())
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(expected)
        if mismatches:
            fail("Dashboard outputs need regeneration: " + ", ".join(mismatches))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, "Dashboard build failed: " + str(exc) + "\n")
    print(("Verified" if args.check else "Built") + " %s dashboard artifacts; mode=%s" % (len(rendered), "preview" if args.preview else "recorded"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
