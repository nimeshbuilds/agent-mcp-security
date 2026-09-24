#!/usr/bin/env python3
"""Verify catalog relationships and all control text/links in the final PDF."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ai_security_scan.rules import RULES
from ai_security_scan import __version__
from ai_security_scan.scan_catalog import describe_scans


def normalize(value):
    value = str(value).translate(str.maketrans({"\u2011": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u00a0": " "}))
    return re.sub(r"\s+", " ", value).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", default=str(ROOT / "output/pdf/invarune-security-controlbook.pdf"))
    parser.add_argument("--receipt", help="Write a compact validation receipt as JSON")
    args = parser.parse_args()
    controls = json.loads((ROOT / "ai_security_scan/data/controls.json").read_text())
    sources = json.loads((ROOT / "ai_security_scan/data/sources.json").read_text())
    ids = {s["id"] for s in sources}
    urls = {s["url"] for s in sources}
    rule_ids = {r["id"] for r in RULES}
    assert len({c["id"] for c in controls}) == len(controls), "Duplicate control ID"
    assert len(ids) == len(urls) == len(sources), "Duplicate source ID or URL"
    for c in controls:
        assert c["sources"] and all(u in urls for u in c["sources"]), c["id"]
        assert all(s in ids for s in c.get("source_ids", []) + c.get("alignment_source_ids", [])), c["id"]
        assert all(r in rule_ids for r in c["automated_rule_ids"]), c["id"]
    for r in RULES:
        assert all(u in urls for u in r["references"]), "Uncataloged rule reference: " + r["id"]
    pdf = PdfReader(args.pdf)
    text = normalize(" ".join(page.extract_text() or "" for page in pdf.pages))
    assert "\ufffd" not in text, "Replacement glyph in extracted PDF"
    cover_text = normalize(pdf.pages[0].extract_text() or "")
    assert "Invarune" in cover_text, "Missing product brand on cover"
    assert "by NimeshBuild" in cover_text, "Missing publisher attribution on cover"
    assert "Evidence for agent security." in cover_text, "Missing product strapline"
    assert "Invarune" in (pdf.metadata.title or ""), "Missing product brand in metadata"
    for c in controls:
        for value in [c["id"], c["title"]] + c["checks"]:
            assert normalize(value) in text, "Missing control content: " + c["id"]
    for s in sources:
        assert normalize(s["id"]) in text, "Missing source ID: " + s["id"]
        assert normalize(s["title"]) in text, "Missing source title: " + s["id"]
    for r in RULES:
        assert r["id"] in text, "Missing rule: " + r["id"]
    scan_catalog = describe_scans()
    for rule in scan_catalog['scans']:
        for key, value in [("predicate", rule['what_it_detects']), ("algorithm", rule['deterministic']['algorithm']),
                           ("limits", rule['deterministic']['limits']), ("agent relevance", rule['why_it_matters']),
                           ("remediation", rule['remediation']), ("explain command", rule['commands']['explain'])]:
            assert normalize(value) in text, "Missing scan " + key + ": " + rule['id']
    for phrase in ("Metrics, not a security grade", "active selected acceptance checks", "null (not applicable)",
                   "invscan --list-scans", "--catalog-format json", "--help-topic all",
                   "invscan ./my-agent --scans AI001,AI043 --scans MCP-03",
                   "Without a report flag", "Skills and malicious-tool indicators"):
        assert phrase in text, "Missing scope/metrics/skills explanation: " + phrase
    links = set()
    internal_links = 0
    page_refs = {page.indirect_reference.idnum for page in pdf.pages}
    for page in pdf.pages:
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            action = annotation.get("/A", {})
            if action.get("/URI"):
                links.add(str(action["/URI"]))
            if annotation.get('/Dest') is not None or action.get('/S') == '/GoTo':
                internal_links += 1
                destination = annotation.get('/Dest', action.get('/D'))
                assert isinstance(destination, list) and destination and getattr(destination[0], 'idnum', None) in page_refs, 'Invalid internal link destination'
    assert urls <= links, "Missing source links: " + str(sorted(urls - links))
    destinations = [item for item in pdf.outline if not isinstance(item, list)]
    assert len(destinations) == len(pdf.pages), "Every page must have one navigable bookmark"
    assert {pdf.get_destination_page_number(item) for item in destinations} == set(range(len(pdf.pages))), "Missing or invalid bookmark destination"
    assert internal_links >= len(RULES), "Rule index and contents must link to their pages"
    pdf_path = Path(args.pdf).resolve()
    display_path = str(pdf_path.relative_to(ROOT)) if pdf_path.is_relative_to(ROOT) else str(pdf_path)
    result = {"schema_version": "1.0", "scanner_version": __version__, "pdf": display_path,
              "pdf_sha256": hashlib.sha256(Path(args.pdf).read_bytes()).hexdigest(),
              "pages": len(pdf.pages), "bookmarks": len(destinations), "internal_links": internal_links,
              "controls": len(controls), "acceptance_checks": sum(len(c["checks"]) for c in controls), "sources": len(sources), "static_rules": len(RULES),
              "partially_mapped_controls": scan_catalog['counts']['partially_mapped_controls'],
              "unique_external_links": len(links), "all_control_text_present": True, "all_source_links_present": True,
              "all_scan_algorithms_predicates_limits_remediation_present": True,
              "catalog_sha256": {name: hashlib.sha256((ROOT / 'ai_security_scan/data' / name).read_bytes()).hexdigest()
                                  for name in ('controls.json', 'sources.json')},
              "scan_catalog_sha256": hashlib.sha256(json.dumps(scan_catalog, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest(),
              "validation_scope": "Text completeness, external URLs and bookmark destinations. Visual page QA is recorded separately; this receipt makes no scanner accuracy or control-compliance claim."}
    if args.receipt:
        destination = Path(args.receipt)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
