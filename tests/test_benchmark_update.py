"""The v0.13 publication must bind its claims to the actual execution artifacts."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts import build_benchmark_update as B


HAS_PDF = all(importlib.util.find_spec(name) is not None for name in ("reportlab", "pypdf"))
REPORT_NAMES = {"report.html", "report.json", "report.md", "report.sarif"}


class BenchmarkUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        for name in ("accuracy-before.json", "accuracy-after.json", "observations.json",
                     "overlaps.json", "run-status.json", "baseline-identity.json",
                     "before-after-accuracy.json"):
            shutil.copyfile(B.INPUT / name, self.inputs / name)
        for name in ("invarune-receipts-before", "invarune-receipts-after", "invarune-reports"):
            shutil.copytree(B.INPUT / name, self.inputs / name)

    def read(self, name):
        return json.loads((self.inputs / name).read_text(encoding="utf-8"))

    def write(self, name, value):
        path = self.inputs / name
        path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @contextmanager
    def edited(self, name):
        """Restore each experiment so one rejected mutation cannot hide another."""
        path = self.inputs / name
        original = path.read_bytes()
        value = json.loads(original)
        try:
            yield value
        finally:
            path.write_bytes(original)

    def test_actual_receipts_and_all_published_report_bytes_are_accepted(self):
        data = B.load(self.inputs)
        self.assertEqual(data["after"]["case_count"], 113)
        self.assertEqual(data["before"]["corpus_sha256"], data["after"]["corpus_sha256"])
        projects = {item["project_id"] for item in data["observations.json"]["inputs"]}
        self.assertEqual(len(projects), 8)
        for side in ("before_receipts", "after_receipts"):
            self.assertEqual({item["project"] for item in data[side]}, projects)
            self.assertEqual(len(data[side]), 8)
        reports = list((self.inputs / "invarune-reports").glob("*/report.*"))
        self.assertEqual(len(reports), 32)
        self.assertEqual({path.name for path in reports}, REPORT_NAMES)
        self.assertEqual(len(data["hashes"]), 23)  # Seven aggregate inputs and sixteen receipts.

    def test_changed_pair_report_hashes_and_hidden_mismatches_are_rejected(self):
        name = "before-after-accuracy.json"
        for change in ("before_hash", "after_hash", "remaining", "changes", "experiment"):
            with self.subTest(change=change), self.edited(name) as pair:
                if change.endswith("_hash"):
                    pair[change.split("_")[0]]["accuracy_report_sha256"] = "0" * 64
                elif change == "remaining":
                    self.assertTrue(pair["remaining_mismatches"])
                    pair["remaining_mismatches"].clear()
                elif change == "changes":
                    self.assertTrue(pair["changes"])
                    pair["changes"].clear()
                else:
                    pair["experiment"] = "unrelated-experiment"
                self.write(name, pair)
                with self.assertRaises(ValueError):
                    B.load(self.inputs)

    def test_baseline_and_after_implementation_binding_is_enforced(self):
        for name, field in (("baseline-identity.json", None),
                            ("before-after-accuracy.json", "before"),
                            ("before-after-accuracy.json", "after"),
                            ("run-status.json", "runs")):
            with self.subTest(name=name, field=field), self.edited(name) as value:
                if field == "runs":
                    target = next(row for row in value["runs"] if row["tool"] == "invarune")
                else:
                    target = value[field] if field else value
                target["implementation_sha256"] = "0" * 64
                self.write(name, value)
                with self.assertRaisesRegex(ValueError, "implementation|baseline identity"):
                    B.load(self.inputs)

    def test_duplicate_project_receipts_cannot_replace_a_missing_project(self):
        for phase in ("before", "after"):
            folder = self.inputs / ("invarune-receipts-" + phase)
            first, second = sorted(folder.glob("*.json"))[:2]
            name = second.relative_to(self.inputs).as_posix()
            with self.subTest(phase=phase), self.edited(name):
                second.write_bytes(first.read_bytes())
                with self.assertRaisesRegex(ValueError, "each pinned project exactly once"):
                    B.load(self.inputs)

    def test_unknown_missing_or_extra_project_receipts_are_rejected(self):
        for change in ("unknown", "missing", "extra"):
            name = "invarune-receipts-after/autogen.json"
            with self.subTest(change=change), self.edited(name) as row:
                extra = self.inputs / "invarune-receipts-after/extra.json"
                try:
                    if change == "unknown":
                        row["project"] = "not-a-pinned-project"
                        self.write(name, row)
                    elif change == "missing":
                        (self.inputs / name).unlink()
                    else:
                        extra.write_bytes((self.inputs / name).read_bytes())
                    with self.assertRaisesRegex(ValueError, "each pinned project exactly once"):
                        B.load(self.inputs)
                finally:
                    if extra.exists():
                        extra.unlink()

    def test_each_receipt_binds_source_version_and_implementation(self):
        for phase in ("before", "after"):
            name = "invarune-receipts-" + phase + "/autogen.json"
            for field in ("revision", "source_manifest_sha256", "source_files", "version", "implementation_sha256"):
                with self.subTest(phase=phase, field=field), self.edited(name) as row:
                    if field in ("version", "implementation_sha256"):
                        row["tool"][field] = "99.0.0" if field == "version" else "0" * 64
                    else:
                        row[field] = row[field] + 1 if field == "source_files" else "0" * len(row[field])
                    self.write(name, row)
                    with self.assertRaisesRegex(ValueError, "bind its source and implementation"):
                        B.load(self.inputs)

    def test_repeat_claim_requires_two_ordered_matching_four_format_executions(self):
        for phase in ("before", "after"):
            name = "invarune-receipts-" + phase + "/autogen.json"
            for change in ("claim_false", "claim_integer", "one_run", "duplicate_run_number",
                           "different_hash", "missing_format", "extra_format", "different_exit"):
                with self.subTest(phase=phase, change=change), self.edited(name) as row:
                    first, second = row["repeated_runs"]
                    if change.startswith("claim_"):
                        row["byte_identical_reports"] = False if change == "claim_false" else 1
                    elif change == "one_run":
                        row["repeated_runs"].pop()
                    elif change == "duplicate_run_number":
                        second["run"] = 1
                    elif change == "different_hash":
                        second["report_sha256"]["report.md"] = "0" * 64
                    elif change == "missing_format":
                        for run in (first, second):
                            del run["report_sha256"]["report.sarif"]
                    elif change == "extra_format":
                        for run in (first, second):
                            run["report_sha256"]["unexpected.txt"] = "0" * 64
                    else:
                        second["exit_code"] = first["exit_code"] + 1
                    self.write(name, row)
                    with self.assertRaisesRegex(ValueError, "two byte-identical executions"):
                        B.load(self.inputs)

    def test_before_after_source_byte_totals_cannot_change(self):
        for phase in ("before", "after"):
            name = "invarune-receipts-" + phase + "/autogen.json"
            with self.subTest(phase=phase), self.edited(name) as row:
                row["source_bytes"] += 1
                self.write(name, row)
                with self.assertRaisesRegex(ValueError, "public source inputs changed"):
                    B.load(self.inputs)

    def test_after_summary_cannot_disagree_with_normalized_source_run(self):
        name = "invarune-receipts-after/autogen.json"
        for field in ("open_findings", "suppressed_findings", "coverage_gaps", "files_scanned"):
            with self.subTest(field=field), self.edited(name) as row:
                row["summary"][field] += 1
                self.write(name, row)
                with self.assertRaisesRegex(ValueError, "summary differs from the normalized run"):
                    B.load(self.inputs)

    def test_matching_repeat_hashes_must_still_bind_the_normalized_json_run(self):
        name = "invarune-receipts-after/autogen.json"
        with self.edited(name) as row:
            for run in row["repeated_runs"]:
                run["report_sha256"]["report.json"] = "0" * 64
            self.write(name, row)
            with self.assertRaisesRegex(ValueError, "summary differs from the normalized run"):
                B.load(self.inputs)

    def test_all_32_published_reports_are_verified_by_actual_bytes(self):
        reports = sorted((self.inputs / "invarune-reports").glob("*/report.*"))
        self.assertEqual(len(reports), 32)
        for path in reports:
            with self.subTest(report=path.relative_to(self.inputs).as_posix()):
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\nchanged publication bytes\n")
                    with self.assertRaisesRegex(ValueError, "Published source report differs"):
                        B.load(self.inputs)
                finally:
                    path.write_bytes(original)

    def test_missing_published_report_is_not_replaced_by_its_receipt_claim(self):
        path = self.inputs / "invarune-reports/autogen/report.html"
        path.unlink()
        with self.assertRaisesRegex(ValueError, "Published source report differs"):
            B.load(self.inputs)

    @unittest.skipUnless(HAS_PDF, "Optional PDF extra is not installed")
    def test_pdf_uses_assertions_despite_misleading_matched_labels_and_keeps_unsupported(self):
        from pypdf import PdfReader

        # These convenience flags are not authoritative. Rebind the edited file
        # bytes so the paired-hash guard passes and the renderer itself is tested.
        pair = self.read("before-after-accuracy.json")
        expected = {}
        for phase in ("before", "after"):
            name = "accuracy-" + phase + ".json"
            report = self.read(name)
            expected[phase] = {case["id"]: all(assertion["outcome"] in ("true_positive", "true_negative")
                                               for assertion in case["assertions"])
                               for case in report["cases"]}
            for case in report["cases"]:
                case["matched_labels"] = not expected[phase][case["id"]]
            pair[phase]["accuracy_report_sha256"] = self.write(name, report)
        self.write("before-after-accuracy.json", pair)
        data = B.load(self.inputs)
        destination = self.root / "publication.pdf"
        B.build(data, destination)
        pages = [" ".join(page.extract_text().split()) for page in PdfReader(destination).pages]
        text = " ".join(pages)
        fixed = [ident for ident, matched in expected["after"].items() if matched and not expected["before"][ident]]
        remaining = [ident for ident, matched in expected["after"].items() if not matched]
        regressed = [ident for ident in remaining if expected["before"][ident]]
        self.assertTrue(fixed)
        self.assertTrue(remaining)
        for label, count in (("Previously failing cases now correct", len(fixed)),
                             ("New mismatches on previously correct cases", len(regressed)),
                             ("Remaining labeled mismatches", len(remaining))):
            self.assertIn(label + " " + str(count), pages[0])
        for ident in fixed + remaining:
            self.assertIn(ident, text)
        projects = next(page for page in pages if "Eight projects. Fresh executions." in page)
        for run in data["run-status.json"]["runs"]:
            if run["finding_count"] is None:
                receipt = next(row for row in data["after_receipts"] if row["project"] == run["project_id"])
                counts = {tool: next(row["finding_count"] for row in data["run-status.json"]["runs"]
                                    if row["project_id"] == run["project_id"] and row["tool"] == tool)
                          for tool in B.TOOLS}
                row_text = " ".join([run["project_id"], str(receipt["source_files"])] +
                                    ["unsupported" if counts[tool] is None else str(counts[tool]) for tool in B.TOOLS])
                self.assertIn(row_text, projects)
        self.assertIn("not production accuracy", text)
        self.assertIn("Confirmed-vulnerability precision and public-project recall are unavailable", text)


if __name__ == "__main__":
    unittest.main()
