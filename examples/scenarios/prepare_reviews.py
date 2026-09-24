#!/usr/bin/env python3
"""Prepare labeled demonstration edits; never treat these reasons as real approval.

Uses the same five-format form editor as the repository's review validation.
The target is an inert shipped fixture; no fixture source is executed.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initial", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--stale-target", type=Path, help="Create a deliberately changed inert source copy for the stale-review demonstration")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("invarune_review_fixture_editor", root / "scripts/validate_report_review.py")
    editor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(editor)
    report = json.loads((args.initial / "report.json").read_text())
    workspace = copy.deepcopy(report["review_workspace"])
    for item in (next(x for x in workspace["items"] if x["kind"] == "finding"), next(x for x in workspace["items"] if x["kind"] == "check")):
        item.update(decision="justified", reason="TEST ONLY: inert documentation fixture; this assertion validates no production safeguard.",
                    reviewer="Scenario fixture", reviewed_at="2026-09-24", evidence_ref="examples/scenarios/prepare_reviews.py")
    args.output.mkdir(parents=True, exist_ok=True)
    for suffix in ("html", "md", "json", "sarif", "pdf"):
        editor.edit_report(args.initial, workspace, suffix, args.output / ("reviewed." + suffix))
    pending = copy.deepcopy(report["review_workspace"])
    check = next(item for item in pending["items"] if item["kind"] == "check")
    check.update(decision="needs_runtime_validation", reason="TEST ONLY: deployment authorization needs runtime validation.",
                 reviewer="Scenario fixture", reviewed_at="2026-09-24", evidence_ref="examples/scenarios/prepare_reviews.py")
    editor.edit_report(args.initial, pending, "json", args.output / "runtime-pending.json")
    if args.stale_target:
        if args.stale_target.exists():
            raise ValueError("Stale target destination must not already exist")
        shutil.copytree(root / "examples/vulnerable", args.stale_target)
        # Change every source/config byte while retaining the fixture's meaning.
        # This must invalidate old evidence identity, not silently inherit review.
        for path in args.stale_target.rglob("*"):
            if path.is_file():
                path.write_bytes(path.read_bytes() + b"\n")
    print(json.dumps({"edited_formats": ["html", "md", "json", "sarif", "pdf"], "decisions": 2, "fixture_only": True}))


if __name__ == "__main__":
    main()
