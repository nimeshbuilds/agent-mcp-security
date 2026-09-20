"""Editable report decisions are bound to fresh static evidence, never report prose."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from ai_security_scan.rules import RULES
from unittest import mock

from ai_security_scan.image_scan import scan_image
from ai_security_scan.review_policy import apply_review_config
from ai_security_scan.review_workspace import (
    DECISIONS, EDITABLE_FIELDS, FIELD_LIMITS, MD_BEGIN, MD_END,
    ReviewWorkspaceLimitError,
    apply_review_workspace, build_workspace, load_review_report, validate_workspace,
)
from ai_security_scan.scanner import scan
from tests.image_fixtures import docker_archive


class ReviewWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        self.report = scan(self.root)
        self.workspace = build_workspace(self.report)

    def decide(self, workspace=None, kind="finding", decision="justified", index=0, **fields):
        workspace = workspace if workspace is not None else self.workspace
        item = [item for item in workspace["items"] if item["kind"] == kind][index]
        item.update(decision=decision, reason="Owner-reviewed test exception.", reviewer="Security reviewer", **fields)
        return item

    def write(self, filename, value):
        path = self.base / filename
        path.write_text(value, encoding="utf-8")
        return path

    def load_json(self, value):
        return load_review_report(self.write("report.json", json.dumps(value)))

    def test_workspace_is_deterministic_static_only_and_does_not_mutate_report(self):
        before = copy.deepcopy(self.report)
        first = build_workspace(self.report)
        self.assertEqual(self.report, before)
        self.assertEqual(first, build_workspace(self.report))
        self.assertEqual(len(first["items"]), 133)
        self.assertEqual({item["kind"] for item in first["items"]}, {"finding", "check"})
        self.assertTrue(all(not item[field] for item in first["items"] for field in EDITABLE_FIELDS))
        model = copy.deepcopy(self.report)
        model["judge"] = {"enabled": True, "status": "error", "error": "SECRET_PROVIDER"}
        model["analyst"] = {"enabled": True, "control_assessments": [{"override": "ALL PASSED"}]}
        model["run_configuration"] = {"judge_config": {"url": "https://private.invalid", "token": "SECRET_PROVIDER"}}
        model["execution"] = {"exit_code": 2}
        self.assertEqual(build_workspace(model), first)
        self.assertNotIn("SECRET_PROVIDER", json.dumps(first))

    def test_individual_finding_exception_never_waives_other_same_rule_finding(self):
        (self.root / "second.py").write_text("import os\nos.system(second_input)\n", encoding="utf-8")
        report = scan(self.root)
        workspace = build_workspace(report)
        original = copy.deepcopy(report)
        selected = self.decide(workspace)
        result = apply_review_workspace(report, workspace)
        self.assertEqual(report, original)
        self.assertEqual(result["summary"]["open_findings"], 1)
        self.assertEqual(result["summary"]["justified_findings"], 1)
        finding = next(item for item in result["findings"] if "finding:" + item["id"] == selected["id"])
        self.assertEqual(finding["disposition"]["scope"], "finding")
        self.assertEqual(finding["human_review"]["reviewer"], "Security reviewer")
        self.assertEqual(result["review_policy"]["counts"]["active_rules"], len(RULES))
        self.assertEqual(result["review_import"]["counts"]["applied"], 1)
        self.assertFalse(result["review_import"]["incomplete"])
        self.assertEqual(result["review_workspace"]["items"][0]["decision"], "justified")
        self.assertEqual(build_workspace(result), result["review_workspace"])

    def test_all_supported_finding_decisions_have_correct_gating_semantics(self):
        for decision in DECISIONS:
            with self.subTest(decision=decision):
                workspace = copy.deepcopy(self.workspace)
                if decision:
                    self.decide(workspace, decision=decision)
                result = apply_review_workspace(self.report, workspace)
                self.assertEqual(result["summary"]["open_findings"], 0 if decision in {"justified", "disabled"} else 1)
                self.assertEqual(result["review_import"]["incomplete"], decision in {"needs_runtime_validation", "needs_human_review"})
                self.assertEqual(result["review_import"]["counts"]["applied"], int(bool(decision)))
                self.assertEqual(result["review_import"]["counts"]["unresolved"], int(decision in {"needs_runtime_validation", "needs_human_review"}))

    def test_partial_check_exception_preserves_sibling_and_static_findings(self):
        selected = self.decide(kind="check", decision="disabled", index=0)
        result = apply_review_workspace(self.report, self.workspace)
        self.assertEqual(result["summary"]["open_findings"], 1)
        self.assertEqual(result["review_policy"]["counts"]["active_checks"], 131)
        self.assertEqual(result["review_policy"]["counts"]["active_controls"], 66)
        control_id = selected["id"].split(":")[1]
        control = next(item for item in result["controls"] if item["id"] == control_id)
        self.assertEqual([item["status"] for item in control["check_dispositions"]], ["disabled", "active"])
        self.assertEqual(control["check_dispositions"][0]["human_review"]["reviewer"], "Security reviewer")

    def test_same_finding_id_with_changed_file_content_is_stale(self):
        self.decide()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n# changed context\n", encoding="utf-8")
        fresh = scan(self.root)
        self.assertEqual(fresh["findings"][0]["id"], self.report["findings"][0]["id"])
        result = apply_review_workspace(fresh, self.workspace)
        self.assertEqual(result["summary"]["open_findings"], 1)
        self.assertTrue(result["review_import"]["incomplete"])
        self.assertEqual(result["review_import"]["counts"]["stale"], 1)
        self.assertEqual(result["review_import"]["counts"]["applied"], 0)
        self.assertFalse(result["review_workspace"]["items"][0]["decision"])

    def test_check_binding_covers_other_files_and_new_files(self):
        self.decide(kind="check")
        (self.root / "other.py").write_text("authorization = 'changed'\n", encoding="utf-8")
        result = apply_review_workspace(scan(self.root), self.workspace)
        self.assertEqual(result["review_import"]["counts"]["stale"], 1)
        self.assertEqual(result["review_policy"]["counts"]["active_checks"], 132)
        self.assertTrue(result["review_import"]["incomplete"])

    def test_version_configuration_catalog_and_immutable_subject_drift_are_stale(self):
        self.decide()
        mutations = [lambda report: report["tool"].update(version="100.0.0"),
                     lambda report: report["tool"].update(implementation_sha256="f" * 64),
                     lambda report: report["configuration"].update(max_files=1),
                     lambda report: report["findings"][0].update(severity="low"),
                     lambda report: report["findings"][0].update(title="Edited title")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fresh = copy.deepcopy(self.report)
                mutation(fresh)
                result = apply_review_workspace(fresh, self.workspace)
                self.assertEqual(result["review_import"]["counts"]["stale"], 1)
                self.assertTrue(result["review_import"]["incomplete"])
        capsule = copy.deepcopy(self.workspace)
        capsule["items"][0]["subject"] = "Forged benign report row"
        self.assertEqual(apply_review_workspace(self.report, capsule)["review_import"]["counts"]["stale"], 1)

    def test_absent_finding_is_not_redetected_only_with_complete_compatible_scope(self):
        self.decide()
        (self.root / "agent.py").write_text("safe = 'different code'\n", encoding="utf-8")
        fresh = scan(self.root)
        result = apply_review_workspace(fresh, self.workspace)
        self.assertEqual(result["review_import"]["counts"]["not_redetected"], 1)
        self.assertFalse(result["review_import"]["incomplete"])
        self.assertIn("no remediation or fix", result["review_import"]["not_redetected"][0]["reason_for_status"])
        for mutate in (lambda report: report["summary"].update(scan_complete_within_selected_scope=False),
                       lambda report: report["configuration"].update(exclude=["private/**"]),
                       lambda report: report["tool"].update(version="100.0.0")):
            changed = copy.deepcopy(fresh)
            mutate(changed)
            result = apply_review_workspace(changed, self.workspace)
            self.assertEqual(result["review_import"]["counts"]["out_of_scope"], 1)
            self.assertTrue(result["review_import"]["incomplete"])

    def test_gap_decisions_cannot_waive_operational_failures(self):
        (self.root / "broken.py").write_text("def broken(\n", encoding="utf-8")
        report = scan(self.root)
        workspace = build_workspace(report)
        item = self.decide(workspace, kind="gap", decision="note")
        result = apply_review_workspace(report, workspace)
        self.assertFalse(result["summary"]["scan_complete_within_selected_scope"])
        self.assertEqual(result["summary"]["coverage_gaps"], report["summary"]["coverage_gaps"])
        self.assertFalse(result["review_import"]["incomplete"])
        for decision in ("justified", "disabled", "pass", "fixed"):
            item["decision"] = decision
            with self.subTest(decision=decision), self.assertRaises(ValueError):
                validate_workspace(workspace)

    def test_baseline_provenance_is_retained_and_changed_baseline_is_stale(self):
        identifier = self.report["findings"][0]["id"]
        baseline = scan(self.root, baseline={identifier: "Legacy review"})
        workspace = build_workspace(baseline)
        self.decide(workspace)
        result = apply_review_workspace(baseline, workspace)
        self.assertEqual(result["findings"][0]["original_status"], "suppressed")
        self.assertEqual(result["findings"][0]["suppression_reason"], "Legacy review")
        stale = apply_review_workspace(self.report, workspace)
        self.assertEqual(stale["review_import"]["counts"]["stale"], 1)

    def test_preexisting_explicit_config_is_exported_as_user_owned_review(self):
        configured = apply_review_config(self.report, {"schema_version": "1.0", "rules": {"AI003": {"status": "justified", "reason": "Reviewed external safeguard"}},
                                                      "checks": {"GOV-01:1": {"status": "disabled"}}})
        workspace = build_workspace(configured)
        decided = [item for item in workspace["items"] if item["decision"]]
        self.assertEqual(len(decided), 2)
        self.assertTrue(all(item["reviewer"] == "Explicit review configuration" for item in decided))
        self.assertEqual(apply_review_workspace(self.report, workspace)["review_import"]["counts"]["applied"], 2)
        with self.assertRaisesRegex(ValueError, "original fresh static report"):
            apply_review_workspace(configured, workspace)

    def test_generated_workspace_preserves_existing_config_unicode_reasons(self):
        reason = "Reviewed\u0085unicode reason\twith newline\nrecord"
        configured = apply_review_config(self.report, {"schema_version": "1.0", "rules": {
            "AI003": {"status": "justified", "reason": reason}}})
        workspace = build_workspace(configured)
        self.assertEqual(workspace["items"][0]["reason"], reason)
        self.assertEqual(apply_review_workspace(self.report, workspace)["findings"][0]["disposition"]["reason"], reason)

    def test_plain_notes_are_recorded_without_suppressing_or_failing(self):
        item = self.decide(decision="note", reviewed_at="2026-09-19T12:30:15Z", evidence_ref="Ticket SEC-42")
        result = apply_review_workspace(self.report, self.workspace)
        self.assertEqual(result["summary"]["open_findings"], 1)
        self.assertFalse(result["review_import"]["incomplete"])
        self.assertEqual(result["findings"][0]["human_review"]["evidence_ref"], "Ticket SEC-42")
        self.assertEqual(result["review_workspace"]["items"][0]["reviewed_at"], item["reviewed_at"])

    def test_secret_text_is_redacted_but_changes_provenance_hash(self):
        outcomes = []
        for token in ("sk-" + "a" * 30, "sk-" + "b" * 30):
            workspace = copy.deepcopy(self.workspace)
            item = self.decide(workspace)
            item["reason"] = "Reviewed credential " + token
            item["evidence_ref"] = "https://user:secret@example.invalid/?token=" + token
            result = apply_review_workspace(self.report, workspace)
            self.assertNotIn(token, json.dumps(result))
            self.assertIn("REDACTED", json.dumps(result))
            outcomes.append(result)
        self.assertNotEqual(outcomes[0]["scan_id"], outcomes[1]["scan_id"])
        self.assertNotEqual(outcomes[0]["review_import"]["source_sha256"], outcomes[1]["review_import"]["source_sha256"])

    def test_tampered_subject_is_stale_and_redacted_before_retaining_audit(self):
        item = self.decide(decision="note")
        token = "sk-" + "a" * 30
        item["subject"] = "Tampered subject " + token
        result = apply_review_workspace(self.report, self.workspace)
        self.assertEqual(result["review_import"]["counts"]["stale"], 1)
        self.assertNotIn(token, json.dumps(result))
        self.assertIn("REDACTED", result["review_import"]["stale"][0]["subject"])

    def test_json_capsule_location_ignores_forged_report_fields(self):
        self.decide()
        document = {"review_workspace": self.workspace, "findings": [{"status": "pass", "severity": "info"}],
                    "judge": {"commands": ["EXECUTE_NOTHING"]}, "configuration": {"gateway": "DO_NOT_REPLAY"}}
        loaded = self.load_json(document)
        result = apply_review_workspace(self.report, loaded)
        self.assertEqual(result["findings"][0]["severity"], "high")
        self.assertNotIn("EXECUTE_NOTHING", json.dumps(result))
        self.assertNotIn("DO_NOT_REPLAY", json.dumps(result))
        self.assertEqual(loaded.source_sha256, hashlib.sha256((self.base / "report.json").read_bytes()).hexdigest())
        self.assertEqual(self.load_json(self.workspace), self.workspace)

    def test_markdown_html_and_sarif_capsules_round_trip_without_execution(self):
        self.decide(decision="note")
        raw = json.dumps(self.workspace).replace("<", "\\u003c").replace(">", "\\u003e")
        documents = {
            "review.md": "# Edited narrative is not authoritative\n" + MD_BEGIN + "\n````json\n" + raw + "\n````\n" + MD_END,
            "review.html": '<!doctype html><html><script>throw new Error("DO_NOT_EXECUTE")</script><script id="invarune-review" type="application/json">' + raw + '</script></html>',
            "review.sarif": json.dumps({"version": "2.1.0", "runs": [{"properties": {"invarune_review": self.workspace}}]}),
        }
        for filename, document in documents.items():
            with self.subTest(filename=filename), mock.patch("subprocess.Popen", side_effect=AssertionError("No execution")):
                loaded = load_review_report(self.write(filename, document))
            self.assertEqual(loaded, self.workspace)
            self.assertEqual(apply_review_workspace(self.report, loaded)["summary"]["open_findings"], 1)

    def test_html_loader_does_not_take_markdown_markers_in_page_as_authority(self):
        raw = json.dumps(self.workspace)
        html = '<!doctype html><html>' + MD_BEGIN + '\n```json\n{}\n```\n' + MD_END
        html += '<script type="application/json" id="invarune-review">' + raw + '</script></html>'
        self.assertEqual(load_review_report(self.write("review.html", html)), self.workspace)

    def test_pdf_loader_passes_bounded_bytes_to_extractor_and_validates_result(self):
        path = self.base / "review.pdf"
        path.write_bytes(b"%PDF-1.7\nsynthetic extractor fixture")
        fake = mock.Mock(extract_review_workspace=mock.Mock(return_value=self.workspace))
        with mock.patch.dict("sys.modules", {"ai_security_scan.report_pdf": fake}):
            loaded = load_review_report(path)
        self.assertEqual(loaded, self.workspace)
        fake.extract_review_workspace.assert_called_once_with(path.read_bytes())
        fake.extract_review_workspace.return_value = {"kind": "invalid"}
        with mock.patch.dict("sys.modules", {"ai_security_scan.report_pdf": fake}), self.assertRaises(ValueError):
            load_review_report(path)

    def test_duplicate_json_keys_and_ambiguous_markers_are_rejected(self):
        raw = json.dumps(self.workspace)
        invalid = [
            ("review.json", '{"review_workspace":' + raw + ',"review_workspace":' + raw + '}'),
            ("review.json", raw.replace('"schema_version": "1.0"', '"schema_version":"1.0","schema_version":"1.0"')),
            ("review.md", MD_BEGIN + '\n```json\n' + raw + '\n```\n' + MD_END + MD_BEGIN),
            ("review.md", MD_BEGIN + '\n```json\n' + raw + '\n````\n' + MD_END),
            ("review.md", MD_END + MD_BEGIN),
            ("review.md", MD_BEGIN + raw + MD_END),
            ("review.html", '<script id="invarune-review" type="application/json">' + raw),
            ("review.html", '<script id="invarune-review" type="text/javascript">' + raw + '</script>'),
            ("review.html", '<script id="invarune-review" id="invarune-review" type="application/json">' + raw + '</script>'),
            ("review.html", ('<script id="invarune-review" type="application/json">' + raw + '</script>') * 2),
            ("review.html", '<div id="invarune-review">' + raw + '</div>'),
            ("review.sarif", json.dumps({"version": "2.1.0", "runs": [{"properties": []}]})),
            ("review.sarif", json.dumps({"version": "2.1.0", "runs": [None]})),
            ("review.sarif", json.dumps({"version": "2.1.0", "runs": []})),
        ]
        for filename, document in invalid:
            with self.subTest(filename=filename, prefix=document[:70]), self.assertRaises(ValueError):
                load_review_report(self.write(filename, document))

    def test_unknown_fields_unknown_check_ids_duplicate_items_and_bad_digests_rejected(self):
        mutations = [lambda w: w.update(extra=True), lambda w: w.update(kind="other"),
                     lambda w: w.update(schema_version="2.0"), lambda w: w.update(items={}),
                     lambda w: w["origin"].update(gateway="evil"),
                     lambda w: w["origin"]["target"].update(kind=[]),
                     lambda w: w["origin"]["configuration"].update(command="evil"),
                     lambda w: w["origin"]["configuration"].update(max_files=True),
                     lambda w: w["origin"]["configuration"].update(exclude="invalid"),
                     lambda w: w["origin"].update(image_limits={"shell": "execute"}),
                     lambda w: w["origin"].update(manifest_sha256="invalid"),
                     lambda w: w["items"][0].update(binding_sha256="F" * 64),
                     lambda w: w["items"][0].update(status="pass"),
                     lambda w: w["items"][0].update(id="check:UNKNOWN:1", kind="check"),
                     lambda w: w["items"][0].update(id="finding:bad"),
                     lambda w: w["items"].append(copy.deepcopy(w["items"][0]))]
        for mutation in mutations:
            w = copy.deepcopy(self.workspace)
            mutation(w)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_workspace(w)

    def test_editable_fields_enforce_types_unicode_limits_metadata_and_dates(self):
        invalid = [("decision", "pass"), ("decision", "fixed"), ("reason", "  "), ("reviewer", ""),
                   ("reason", "\ud800"), ("reviewer", "reviewer\nforged"), ("evidence_ref", "\x00hidden"),
                   ("reviewed_at", "2026-02-30"), ("reviewed_at", "2026-09-19T25:20:00"),
                   ("reviewed_at", "September 19"), ("decision", []), ("reason", None)]
        invalid += [(field, "x" * (limit + 1)) for field, limit in FIELD_LIMITS.items()]
        for field, value in invalid:
            w = copy.deepcopy(self.workspace)
            item = self.decide(w)
            item[field] = value
            with self.subTest(field=field, value=repr(value)[:40]), self.assertRaises(ValueError):
                validate_workspace(w)
        w = copy.deepcopy(self.workspace)
        w["items"][0]["reason"] = "No decision selected"
        with self.assertRaisesRegex(ValueError, "explicit decision"):
            validate_workspace(w)
        for date in ("2026-09-19", "2026-09-19T12:30:00", "2026-09-19T12:30:00.123456-05:00", "2026-09-19T12:30:00Z"):
            w = copy.deepcopy(self.workspace)
            self.decide(w, reviewed_at=date)
            self.assertEqual(validate_workspace(w), w)

    def test_reader_is_bounded_nonblocking_and_rejects_symlink_loops(self):
        actual = self.write("review.json", json.dumps(self.workspace))
        for path in (self.base, self.base / "missing" / "review.json"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                load_review_report(path)
        with mock.patch("ai_security_scan.review_workspace.MAX_REPORT_BYTES", 8), self.assertRaisesRegex(ValueError, "50000000"):
            load_review_report(actual)
        try:
            (self.base / "link.json").symlink_to(actual)
            (self.base / "loop").symlink_to("loop", target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlinks requires platform permission")
        for path in (self.base / "link.json", self.base / "loop" / "report.json"):
            with self.assertRaises(ValueError):
                load_review_report(path)
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.base / "pipe.json")
            with self.assertRaises(ValueError):
                load_review_report(self.base / "pipe.json")

    def test_workspace_generation_and_import_have_explicit_capsule_size_errors(self):
        with mock.patch("ai_security_scan.review_workspace.MAX_WORKSPACE_BYTES", 10):
            with self.assertRaisesRegex(ReviewWorkspaceLimitError, "capsule limit"):
                build_workspace(self.report)
        with mock.patch("ai_security_scan.review_workspace.MAX_ITEMS", 1):
            with self.assertRaisesRegex(ReviewWorkspaceLimitError, "item limit"):
                validate_workspace(self.workspace)
            with self.assertRaisesRegex(ReviewWorkspaceLimitError, "item limit"):
                build_workspace(self.report)

    def test_invalid_utf8_unrecognized_and_nonstandard_json_are_rejected(self):
        path = self.base / "report.bin"
        for data in (b"\xff", b"unsupported", b'{"review_workspace":NaN}', b"{" + b"[" * 2000):
            path.write_bytes(data)
            with self.subTest(data=data[:40]), self.assertRaises(ValueError):
                load_review_report(path)

    def test_empty_or_blank_import_does_not_infer_manual_passes(self):
        blank = apply_review_workspace(self.report, self.workspace)
        self.assertEqual(blank["summary"]["open_findings"], 1)
        self.assertEqual(blank["review_import"]["counts"]["decisions"], 0)
        self.assertEqual(blank["review_policy"]["counts"]["active_checks"], 132)
        self.assertFalse(blank["review_import"]["incomplete"])
        with self.assertRaisesRegex(ValueError, "original fresh static report"):
            apply_review_workspace(blank, self.workspace)

    def test_source_and_image_decisions_cannot_cross_contexts(self):
        self.decide()
        image_path = docker_archive(self.base / "agent.tar", [[("agent.py", "import os\nos.system(user_input)\n")]],
                                    config={"config": {"User": "1001"}})
        with scan_image(archive=image_path) as (image, _):
            workspace = build_workspace(image)
            selected = self.decide(workspace)
            result = apply_review_workspace(image, workspace)
            self.assertEqual(result["summary"]["justified_findings"], 1)
            self.assertEqual(result["review_import"]["counts"]["applied"], 1)
            self.assertEqual(result["findings"][0]["image_context"], "final_filesystem")
            self.assertEqual(result["review_workspace"]["origin"]["target"]["kind"], "image")
            self.assertEqual(apply_review_workspace(image, self.workspace)["review_import"]["counts"]["out_of_scope"], 1)
            changed = copy.deepcopy(image)
            changed["image"]["identity"]["config_digest"] = "sha256:" + "f" * 64
            stale = apply_review_workspace(changed, workspace)
            self.assertEqual(stale["review_import"]["counts"]["stale"], 1)
            self.assertEqual(stale["summary"]["open_findings"], 1)

    def test_image_metadata_and_retained_evidence_are_independently_bound(self):
        image_path = docker_archive(self.base / "agent.tar", [[("old.py", 'API_KEY="syntheticOldCredential123456789"\n')],
                                                             [(".wh.old.py", ""), ("agent.py", "name='agent'\n")]],
                                    config={"config": {"User": "root"}})
        with scan_image(archive=image_path) as (image, _):
            workspace = build_workspace(image)
            for item in workspace["items"]:
                if item["kind"] == "finding":
                    item.update(decision="disabled", reason="Artifact review exception", reviewer="Owner")
            result = apply_review_workspace(image, workspace)
            self.assertEqual(result["summary"]["open_findings"], 0)
            self.assertGreaterEqual(result["summary"]["disabled_findings"], 2)
            self.assertEqual({finding["image_context"] for finding in result["findings"]}, {"retained_layer", "runtime_configuration"})

    def test_granular_policy_extension_validates_ids_and_preserves_legacy_schema(self):
        identifier = self.report["findings"][0]["id"]
        for value in ([], {"unknown": {"status": "disabled"}}, {identifier: {"status": "pass"}},
                      {identifier: {"status": "justified"}}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                apply_review_config(self.report, {"schema_version": "1.0"}, finding_dispositions=value)
        with self.assertRaises(ValueError):
            apply_review_config(self.report, {"schema_version": "1.0", "findings": {identifier: {"status": "disabled"}}})
        value = {identifier: {"status": "justified", "reason": "Specific exception"}}
        result = apply_review_config(self.report, None, finding_dispositions=value)
        self.assertEqual(result["findings"][0]["disposition"]["scope"], "finding")
        self.assertEqual(apply_review_config(result, None, finding_dispositions=value), result)

    def test_edited_origin_configuration_must_match_its_scope_digest(self):
        self.workspace["origin"]["configuration"]["max_files"] += 1
        with self.assertRaisesRegex(ValueError, "selected-scope digest"):
            validate_workspace(self.workspace)


if __name__ == "__main__":
    unittest.main()
