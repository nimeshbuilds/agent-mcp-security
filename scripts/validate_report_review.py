#!/usr/bin/env python3
"""Execute reproducible five-format review roundtrips on shipped inert fixtures.

The reasons are labeled test assertions, never production control validation.
Requires the PDF extra. Does not run target code, a model, or a container.
"""
import argparse
import copy
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def edit_report(initial, workspace, suffix, destination):
    if suffix == "pdf":
        from pypdf import PdfReader, PdfWriter
        writer = PdfWriter()
        writer.clone_document_from_reader(PdfReader(initial / "report.pdf"))
        values = {"ivr.{}.{}".format(index, field): item[field]
                  for index, item in enumerate(workspace["items"]) if item["decision"]
                  for field in ("decision", "reason", "reviewer", "reviewed_at", "evidence_ref")}
        writer.update_page_form_field_values(None, values, auto_regenerate=False)
        with destination.open("wb") as stream:
            writer.write(stream)
        return
    text = (initial / ("report." + suffix)).read_text(encoding="utf-8")
    raw = json.dumps(workspace, indent=2, sort_keys=True, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e")
    if suffix == "json":
        value = json.loads(text)
        value["review_workspace"] = workspace
        text = json.dumps(value, indent=2, sort_keys=True)
    elif suffix == "sarif":
        value = json.loads(text)
        value["runs"][0]["properties"]["invarune_review"] = workspace
        text = json.dumps(value, indent=2, sort_keys=True)
    elif suffix == "md":
        text, count = re.subn(r"(?<=<!-- INVARUNE_REVIEW_BEGIN -->)[\s\S]*?(?=<!-- INVARUNE_REVIEW_END -->)",
                             lambda _: "\n```json\n" + raw + "\n```\n", text)
        assert count == 1
    else:
        text, count = re.subn(r'(<script type="application/json" id="invarune-review">)[\s\S]*?(</script>)',
                             lambda m: m.group(1) + raw + m.group(2), text)
        assert count == 1
        # Keep the displayed form state consistent with the saved capsule, as
        # the local HTML Download button does. This is a scripted fixture edit,
        # not a claim that an actual browser was exercised by this harness.
        for item in workspace["items"]:
            if not item["decision"]:
                continue
            def update_editor(match):
                block = match.group()
                block = re.sub(r'(<option value="[^"]*") selected', r'\1', block)
                block = block.replace('<option value="' + item["decision"] + '">',
                                      '<option value="' + item["decision"] + '" selected>')
                block = re.sub(r'(<textarea[^>]*data-field="reason"[^>]*>)[\s\S]*?(</textarea>)',
                               lambda m: m.group(1) + html.escape(item["reason"]) + m.group(2), block)
                for field in ("reviewer", "reviewed_at", "evidence_ref"):
                    block = re.sub(r'(<input[^>]*data-field="' + field + r'"[^>]*value=")[^"]*(")',
                                   lambda m: m.group(1) + html.escape(item[field], quote=True) + m.group(2), block)
                return block
            text, count = re.subn(r'<fieldset data-review-id="' + re.escape(item["id"]) + r'">[\s\S]*?</fieldset>',
                                 update_editor, text)
            assert count == 1
    destination.write_text(text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New empty evidence directory; existing content is refused.")
    parser.add_argument("--command", help="Installed CLI executable to test; default runs this checkout using the current Python.")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("Output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    command = [args.command] if args.command else [sys.executable, str(ROOT / "scan.py")]
    records = []

    def run(target, path, review=None):
        invocation = command + target + ["--output", str(path), "--pdf", "--summary-json"]
        if review:
            invocation += ["--review-report", str(review)]
        process = subprocess.run(invocation, cwd=str(output), capture_output=True, text=True, timeout=180)
        if process.returncode not in (0, 1):
            raise RuntimeError("Fixture report command failed: " + process.stderr)
        summary = json.loads(process.stdout)
        report = json.loads((path / "report.json").read_text())
        assert set(summary["reports"]) == {"html", "json", "markdown", "sarif", "pdf"}
        assert report["summary"]["coverage_gaps"] == 0
        assert not report["judge"]["enabled"] and not report["analyst"]["enabled"]
        return report, process.returncode

    for kind, target in (("source", [str(ROOT / "examples/vulnerable")]),
                         ("image", ["--image-archive", str(ROOT / "examples/images/demo-agent.tar")])):
        folder = output / kind
        folder.mkdir()
        initial, initial_exit = run(target, folder / "initial")
        workspace = copy.deepcopy(initial["review_workspace"])
        for item in (next(i for i in workspace["items"] if i["kind"] == "finding"),
                     next(i for i in workspace["items"] if i["kind"] == "check")):
            item.update(decision="justified", reason="TEST ONLY: deliberate inert fixture retained for scanner regression. This assertion validates no production safeguard.",
                        reviewer="Invarune workflow test", reviewed_at="2026-09-19", evidence_ref="scripts/validate_report_review.py")
        for suffix in ("html", "md", "json", "sarif", "pdf"):
            reviewed = folder / ("reviewed." + suffix)
            edit_report(folder / "initial", workspace, suffix, reviewed)
            final_path = folder / ("final-" + suffix)
            final, final_exit = run(target, final_path, reviewed)
            assert final["summary"]["open_findings"] == initial["summary"]["open_findings"] - 1
            assert final["summary"]["justified_findings"] == 1
            assert final["review_policy"]["counts"]["active_checks"] == 131
            assert final["review_policy"]["counts"]["justified_checks"] == 1
            assert final["review_import"]["counts"]["applied"] == 2
            assert not final["review_import"]["incomplete"]
            assert final["review_import"]["source_sha256"] == digest(reviewed)
            assert len(final["controls"]) == 66
            assert not any(f["status"] == "pass" for f in final["findings"])
            assert [(f["id"], f["severity"], f["evidence"]) for f in initial["findings"]] == [
                (f["id"], f["severity"], f["evidence"]) for f in final["findings"]]
            if kind == "image":
                assert final["image"]["container_started"] is False
            records.append({"target": kind, "review_format": suffix, "initial_exit": initial_exit,
                            "final_exit": final_exit, "tool": final["tool"],
                            "initial_scan_id": initial["scan_id"], "final_scan_id": final["scan_id"],
                            "review_artifact": str(reviewed.relative_to(output)), "review_sha256": digest(reviewed),
                            "summary": final["summary"], "review_counts": final["review_import"]["counts"],
                            "report_sha256": {str(p.relative_to(output)): digest(p) for p in sorted(final_path.glob("report.*"))}})
    receipt = {"schema_version": "1.0", "scenario": "actual CLI five-format review roundtrip",
               "initial_scans": 2, "reviewed_scans": 10, "model_calls": 0, "target_execution": False,
               "scope": "Shipped inert source and image fixtures; test exceptions do not establish control effectiveness.",
               "records": records}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"initial_scans": 2, "reviewed_scans": 10, "receipt": str(output / "receipt.json")}))


if __name__ == "__main__":
    main()
