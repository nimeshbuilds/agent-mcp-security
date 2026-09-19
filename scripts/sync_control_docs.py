#!/usr/bin/env python3
"""Generate Markdown control/provenance documents from the canonical JSON catalogs."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    controls = json.loads((ROOT / "ai_security_scan/data/controls.json").read_text())
    sources = json.loads((ROOT / "ai_security_scan/data/sources.json").read_text())
    source_by_url = {s["url"]: s for s in sources}
    header = """# Invarune AI agent and MCP security checklist

**Invarune by NimeshBuild** - Evidence for agent security.

Research snapshot: **2026-09-19**. This catalog contains **%d controls and %d acceptance checks**. These are original engineering review questions synthesized from the sources in [RESEARCH.md](RESEARCH.md), [CSA_AND_CLOUD.md](CSA_AND_CLOUD.md), and [BENCHMARK_LANDSCAPE.md](BENCHMARK_LANDSCAPE.md). This is not an official NSA, CISA, CSA, NIST, MITRE, OWASP, MCP, CIS, or ISO certification checklist.

Source links explain provenance or thematic alignment; they do not claim that every test is a verbatim requirement of that source. All referenced publications, versions, limitations, and control alignments appear in [SOURCE_MAP.md](SOURCE_MAP.md). The complete machine-readable source registry is [sources.json](../ai_security_scan/data/sources.json).

## How to use this list

For every applicable control, record **owner, scope, evidence, result, exception, and review date**. Use `validated`, `failed`, `not_applicable` with rationale, or `not_validated` for the human assessment. Keep this separate from scanner statuses. Prioritize reachable high-impact operations, exposed remote MCP endpoints, secrets, and cross-tenant access.

A missing source-code pattern is not a passed control. The optional LLM judge supplies advisory hypotheses, not deterministic evidence or authorization. Validation labels below identify the required review method, not implemented automation coverage:

- **static**: source/configuration evidence can reveal a risk; absence remains inconclusive.
- **hybrid**: inspect source and verify effective behavior in a controlled deployment.
- **dynamic**: execute authorized tests against a representative isolated system.
- **manual**: assess architecture, operating procedures, and external evidence.

The 42 implemented rules provide partial coverage of 26 controls. An empty `automated_rule_ids` list means no mapped static rule. A rule match does not establish that all acceptance checks under that control failed.

## Version and applicability

HTTP OAuth checks apply to protected HTTP implementations. Stdio uses local process/credential controls. Record the actual MCP revision; 2026-07-28 and older session-based transports differ. Model instructions, tool annotations, advertised roots, and the judge are not enforcement boundaries. Verify host, server, operating-system, and downstream controls.

## Controls
""" % (len(controls), sum(len(c["checks"]) for c in controls))
    lines = [header]
    category = None
    for c in controls:
        if c["category"] != category:
            category = c["category"]
            lines += ["", "### " + category, ""]
        lines += ["#### " + c["id"] + " - " + c["title"], "", "Validation: **" + c["validation"] + "**.", ""]
        lines += ["- [ ] " + check for check in c["checks"]]
        lines += ["", "Primary context: " + "; ".join("[" + source_by_url[u]["id"] + ": " + source_by_url[u]["title"] + "](" + u + ")" for u in c["sources"]) + ".", ""]
        if c.get("alignment_source_ids"):
            lines += ["Additional thematic alignment: " + ", ".join(c["alignment_source_ids"]) + ". See the source map for limits; these are not exact external clause mappings.", ""]
        lines += ["Partial static rules: " + (", ".join(c["automated_rule_ids"]) if c["automated_rule_ids"] else "none; review/runtime evidence required") + ".", ""]
    (ROOT / "docs/SECURITY_CHECKLIST.md").write_text("\n".join(lines))
    lines = ["# Source map and scope of alignment", "", "Invarune by NimeshBuild. Research snapshot: 2026-09-19. Sources can support a project control without prescribing its exact wording. This is a thematic engineering crosswalk, not a statement of compliance with every clause in an external framework. Some references provide landscape/provenance context without a direct control mapping.", "", "All URLs are primary publisher or benchmark-author sources. Source-specific limitations disclose release-page-only reviews, drafts, gated benchmark content, version differences, and implementation assumptions.", ""]
    for s in sources:
        direct = [c["id"] for c in controls if s["url"] in c["sources"]]
        align = [c["id"] for c in controls if s["id"] in c.get("alignment_source_ids", [])]
        lines += ["## " + s["id"] + " - " + s["title"], "", "[Primary source](" + s["url"] + ")", "", "**Publisher:** " + s["organization"] + "  ", "**Kind:** " + s["kind"] + "  ", "**Version/date:** " + str(s.get("version") or "living publication") + " / " + str(s.get("date") or "not specified") + "  ", "**Accessed:** " + s["accessed"], "", s["scope"], "", "**Limits:** " + s["limitations"], "", "**Primary context for:** " + (", ".join(direct) or "landscape/provenance only") + ".", "", "**Additional thematic alignment:** " + (", ".join(align) or "none assigned") + ".", ""]
        if s.get("mapping_notes"):
            lines += ["**Mapping notes:** " + str(s["mapping_notes"]), ""]
        for mapping in s.get("suggested_control_mappings", []):
            lines += ["- **" + ", ".join(mapping["control_ids"]) + ":** " + mapping.get("locator", "") + ". " + mapping.get("note", "")]
        lines.append("")
    (ROOT / "docs/SOURCE_MAP.md").write_text("\n".join(lines))
    print(f"Generated checklist and source map: {len(controls)} controls, {len(sources)} sources")


if __name__ == "__main__":
    main()
