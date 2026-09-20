#!/usr/bin/env python3
"""Stage only allowlisted Git-indexed documentation and public evidence.

No scanner, target, container, model, login, PDF renderer or network is invoked.
New documentation must be added to the Git index before it can be published.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".docs-build" / "content"
REPO = "https://github.com/nimeshbuilds/agent-mcp-security"
SITE_PREFIX = "/agent-mcp-security/"
PREFIXES = ("docs/", "benchmarks/", "examples/", "output/pdf/", "ai_security_scan/data/")
EXTENSIONS = {".md", ".json", ".sarif", ".html", ".pdf", ".txt", ".csv", ".svg", ".png", ".css"}
ROOT_FILES = {"README.md", "CONTRIBUTING.md", "NOTICE.md"}
RENAMES = {"README.md": "overview.md", "docs/site-home.md": "index.md"}


def indexed_paths() -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return sorted(set(p for p in raw.decode("utf-8").split("\0") if p))


def selected(path: str) -> bool:
    return path in ROOT_FILES or (
        path.startswith(PREFIXES)
        and Path(path).suffix.lower() in EXTENSIONS
        and not any(part.startswith(".") for part in Path(path).parts)
    )


def main() -> None:
    tracked = indexed_paths()
    sources = [p for p in tracked if selected(p)]
    destinations = {p: RENAMES.get(p, p) for p in sources}
    if "docs/site-home.md" not in destinations:
        raise SystemExit("Add new documentation to the Git index before building the site.")
    if len(set(destinations.values())) != len(destinations):
        raise SystemExit("Duplicate staged documentation path")
    # Reject symlinks in any component before reading/copying public inputs.
    for name in sources:
        path = ROOT / name
        if not path.is_file() or any(part.is_symlink() for part in (path, *path.parents)):
            raise SystemExit("Missing or symlinked documentation input: " + name)
    if STAGE.is_symlink() or STAGE.parent.is_symlink():
        raise SystemExit("Refusing a symlinked documentation staging directory")
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)
    tracked_set = set(tracked)
    remapped_links = 0

    def target_url(raw: str, source: str, dest: str, html: bool = False) -> str:
        nonlocal remapped_links
        parsed = urlsplit(raw)
        if not raw or raw.startswith(("#", "/")) or parsed.scheme or parsed.netloc:
            return raw
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(parsed.path)))
        # The home page is authored with root-relative repository paths.
        if source == "docs/site-home.md":
            resolved = posixpath.normpath(unquote(parsed.path))
        suffix = ("?" + parsed.query if parsed.query else "") + ("#" + parsed.fragment if parsed.fragment else "")
        if resolved in destinations:
            destination = destinations[resolved]
            if html:
                if destination.endswith(".md"):
                    base = posixpath.basename(destination)
                    destination = (posixpath.dirname(destination) + "/" if posixpath.dirname(destination) else "") + ("" if base in {"index.md", "README.md"} else base[:-3] + "/")
                return SITE_PREFIX + quote(destination, safe="/") + suffix
            relative = posixpath.relpath(destination, posixpath.dirname(dest) or ".")
            return quote(relative, safe="/") + suffix
        if resolved in tracked_set:
            remapped_links += 1
            return REPO + "/blob/main/" + quote(resolved, safe="/") + suffix
        if any(p.startswith(resolved.rstrip("/") + "/") for p in tracked_set):
            remapped_links += 1
            return REPO + "/tree/main/" + quote(resolved, safe="/") + suffix
        return raw  # MkDocs/HTML verification must reject unresolved local links.

    manifest = []
    for source, dest in destinations.items():
        content = (ROOT / source).read_bytes()
        output = STAGE / dest
        output.parent.mkdir(parents=True, exist_ok=True)
        if source.endswith(".md"):
            text = content.decode("utf-8")
            # Rewrite link destinations, never source code blocks or prose.
            blocks = re.split(r"(^```[^\n]*\n.*?^```[^\n]*$|^~~~[^\n]*\n.*?^~~~[^\n]*$)", text, flags=re.M | re.S)
            for i in range(0, len(blocks), 2):
                blocks[i] = re.sub(r"(\]\()([^\s)]+)(\))", lambda m: m[1] + target_url(m[2], source, dest) + m[3], blocks[i])
                blocks[i] = re.sub(r'((?:href|src)=")([^"]+)(")', lambda m: m[1] + target_url(m[2], source, dest, html=True) + m[3], blocks[i])
            output.write_text("".join(blocks), encoding="utf-8")
        else:
            output.write_bytes(content)
        manifest.append({"source": source, "destination": dest, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(), "verbatim": not source.endswith(".md")})
    receipt = {
        "schema_version": 1,
        "policy": "Git-indexed allowlisted documentation and evidence only; Markdown links adapted for Pages; other files preserved byte-for-byte",
        "files": manifest,
        "source_links_remapped_to_github": remapped_links,
    }
    (STAGE / "publication-manifest.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("Staged %d indexed files (%d PDF downloads); %d source links point to GitHub." % (len(manifest), sum(p.endswith(".pdf") for p in sources), remapped_links))


if __name__ == "__main__":
    main()
