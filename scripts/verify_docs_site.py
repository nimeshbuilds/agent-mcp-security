#!/usr/bin/env python3
"""Validate the built Pages site's local links, anchors and public downloads."""
from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://nimeshbuilds.github.io/invarune/"


class Page(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("name"):
            self.ids.add(attrs["name"])
        for key in ("href", "src"):
            if attrs.get(key):
                self.links.append(attrs[key])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "site")
    parser.add_argument("--receipt", type=Path, help="Write a portable JSON validation receipt")
    args = parser.parse_args()
    site = args.site.resolve()
    if not (site / "index.html").is_file():
        raise SystemExit("Build the site before validation")
    pages = {p.relative_to(site).as_posix(): Page(p.read_text(encoding="utf-8")) for p in site.rglob("*.html")}
    errors = []
    checked = 0
    for name, page in pages.items():
        url = BASE + (name[:-10] if name.endswith("index.html") else name)
        for link in page.links:
            resolved = urlsplit(urljoin(url, link))
            if resolved.scheme not in {"https", "http"} or resolved.netloc != urlsplit(BASE).netloc:
                continue
            if not resolved.path.startswith(urlsplit(BASE).path):
                errors.append(name + ": local link escapes project site: " + link)
                continue
            relative = unquote(resolved.path[len(urlsplit(BASE).path):])
            target = site / posixpath.normpath(relative)
            if target.is_dir():
                target /= "index.html"
            if not target.is_file() or not target.resolve().is_relative_to(site):
                errors.append(name + ": missing local target: " + link)
                continue
            checked += 1
            key = target.relative_to(site).as_posix()
            if resolved.fragment and key in pages:
                anchor = unquote(resolved.fragment)
                if anchor not in pages[key].ids:
                    errors.append(name + ": missing anchor: " + link)
    manifest = json.loads((site / "publication-manifest.json").read_text(encoding="utf-8"))
    preserved = 0
    pdfs = []
    for entry in manifest["files"]:
        if not entry["verbatim"]:
            continue
        path = site / entry["destination"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            errors.append("Artifact bytes changed: " + entry["destination"])
        else:
            preserved += 1
        if entry["destination"].endswith(".pdf"):
            pdfs.append({"path": entry["destination"], "sha256": entry["sha256"], "bytes": entry["bytes"]})
    search = json.loads((site / "search/search_index.json").read_text(encoding="utf-8"))
    search_count = len(search.get("docs", []))
    if not search_count:
        errors.append("Search index is empty")
    for essential in ("docs/QUICKSTART/index.html", "docs/SECURITY_EXPLORER/index.html", "docs/REPORT_LIBRARY/index.html", "docs/BENCHMARK_GUIDE/index.html", "docs/BENCHMARK_DASHBOARD/index.html", "CONTRIBUTING/index.html"):
        if essential not in pages:
            errors.append("Essential guide absent: " + essential)
    receipt = {"schema_version": 1, "result": "passed" if not errors else "failed", "html_pages": len(pages), "local_links_checked": checked, "search_entries": search_count, "artifacts_preserved": preserved, "pdf_downloads": pdfs, "errors": errors}
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
