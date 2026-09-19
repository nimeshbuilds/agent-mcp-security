#!/usr/bin/env python3
"""Verify catalog relationships and all control text/links in the final PDF."""
import argparse
import json
from pathlib import Path
import re
import sys

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ai_security_scan.rules import RULES


def normalize(value):
    value = str(value).translate(str.maketrans({"\u2011": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u00a0": " "}))
    return re.sub(r"\s+", " ", value).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", default=str(ROOT / "output/pdf/nimeshbuild-agent-mcp-security-controlbook.pdf"))
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
    for c in controls:
        for value in [c["id"], c["title"]] + c["checks"]:
            assert normalize(value) in text, "Missing control content: " + c["id"]
    for s in sources:
        assert normalize(s["id"]) in text, "Missing source ID: " + s["id"]
        assert normalize(s["title"]) in text, "Missing source title: " + s["id"]
    for r in RULES:
        assert r["id"] in text, "Missing rule: " + r["id"]
    links = set()
    for page in pdf.pages:
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            action = annotation.get("/A", {})
            if action.get("/URI"):
                links.add(str(action["/URI"]))
    assert urls <= links, "Missing source links: " + str(sorted(urls - links))
    result = {"pages": len(pdf.pages), "controls": len(controls), "acceptance_checks": sum(len(c["checks"]) for c in controls), "sources": len(sources), "static_rules": len(RULES), "unique_external_links": len(links), "all_control_text_present": True, "all_source_links_present": True}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
