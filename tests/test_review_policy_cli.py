"""User policy at the public source/image/optional-gateway boundary."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ai_security_scan.cli import main, parser
from ai_security_scan.judge import JudgeError
from ai_security_scan.rules import RULES
from ai_security_scan.scanner import load_controls
from tests.test_analyst_cli import triage_response
from tests.test_full_gateway_e2e import PROVIDERS, fixture_answer, gateway


PROJECT = Path(__file__).resolve().parents[1]
ARTIFACTS = ("report.html", "report.md", "report.json", "report.sarif")


class ReviewPolicyCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repository"
        self.repo.mkdir()
        (self.repo / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        self.policy = self.base / "trusted-review.json"
        self.output = self.base / "report"
        self.judge = self.base / "judge.json"
        self.judge.write_text(json.dumps({"provider": "openai_chat", "model": "fixture"}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def write_policy(self, **sections):
        self.policy.write_text(json.dumps({"schema_version": "1.0", **sections}), encoding="utf-8")

    def invoke(self, *arguments, image=False, policy=True):
        source = ["--image-archive", str(PROJECT / "examples/images/demo-agent.tar")] if image else [str(self.repo)]
        args = source + ["--output", str(self.output), *arguments]
        if policy:
            args.extend(["--review-config", str(self.policy)])
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def report(self):
        return json.loads((self.output / "report.json").read_text(encoding="utf-8"))

    def test_rule_exceptions_remove_gate_without_passing_or_erasing_evidence(self):
        self.assertEqual(self.invoke(policy=False)[0], 1)
        original = self.report()["findings"][0]
        for status in ("justified", "disabled"):
            with self.subTest(status=status):
                self.write_policy(rules={"AI003": {"status": status, "reason": "Owner reviewed the fixture boundary."}})
                with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Offline policy must not use a model")):
                    code, stdout, stderr = self.invoke("--summary-json", "--fail-on", "info")
                self.assertEqual((code, stderr), (0, ""))
                report, summary = self.report(), json.loads(stdout)
                finding = report["findings"][0]
                self.assertEqual(finding["status"], status)
                self.assertEqual(finding["original_status"], "open")
                for field in ("id", "finding_id", "evidence", "severity", "line", "path"):
                    self.assertEqual(finding[field], original[field])
                self.assertEqual(report["summary"]["open_findings"], 0)
                self.assertEqual(report["summary"][status + "_findings"], 1)
                self.assertEqual(report["summary"]["suppressed_findings"], 0)
                self.assertEqual(sum(report["summary"]["severity_counts"].values()), 0)
                self.assertEqual(report["assessment"]["immediate_actions"], [])
                self.assertEqual(summary["review_policy"], report["review_policy"])
                self.assertFalse(summary["execution"]["finding_gate_triggered"])
                for name in ARTIFACTS:
                    self.assertTrue("Owner reviewed the fixture boundary" in (self.output / name).read_text(encoding="utf-8"), name)

    def test_controls_and_individual_checks_change_only_active_check_denominators(self):
        self.write_policy(controls={"EXEC-01": {"status": "justified", "reason": "External review record."}},
                          checks={"AUTH-01:2": {"status": "disabled"}})
        code, stdout, _ = self.invoke("--summary-json")
        self.assertEqual(code, 1)
        report, summary = self.report(), json.loads(stdout)
        self.assertEqual(report["findings"][0]["status"], "open")
        self.assertEqual(summary["coverage"]["total_checks"], 129)
        self.assertEqual(summary["coverage"]["total_controls"], 65)
        self.assertEqual(summary["coverage"]["catalog_checks"], 132)
        self.assertEqual(summary["coverage"]["catalog_controls"], 66)
        self.assertEqual(report["review_policy"]["counts"]["justified_checks"], 2)
        self.assertEqual(report["review_policy"]["counts"]["disabled_checks"], 1)
        self.assertEqual(report["assessment"]["metrics"]["controls_requiring_validation"], 65)

    def test_source_and_image_all_rules_can_be_excepted_with_stable_evidence_ids(self):
        for image in (False, True):
            self.assertEqual(self.invoke(image=image, policy=False)[0], 1)
            original = {f["id"] for f in self.report()["findings"]}
            for status in ("justified", "disabled"):
                with self.subTest(image=image, status=status):
                    self.write_policy(rules={r["id"]: {"status": status, "reason": "Synthetic review test."} for r in RULES})
                    code, _, _ = self.invoke("--fail-on", "info", image=image)
                    report = self.report()
                    self.assertEqual(code, 0)
                    self.assertEqual({f["id"] for f in report["findings"]}, original)
                    self.assertEqual({f["status"] for f in report["findings"]}, {status})
                    self.assertEqual(report["coverage"]["rules_enabled"], [])
                    self.assertEqual(report["review_policy"]["counts"]["active_rules"], 0)
                    self.assertEqual(report["review_policy"]["counts"]["active_checks"], 132)
                    if image:
                        self.assertTrue(all("image_context" in f for f in report["findings"]))
                        self.assertFalse(report["image"]["container_started"])

    def test_explicit_policy_takes_precedence_over_baseline_and_retains_reason(self):
        self.invoke(policy=False)
        finding_id = self.report()["findings"][0]["id"]
        baseline = self.base / "baseline.json"
        baseline.write_text(json.dumps({"schema_version": "1.0", "findings": [{"id": finding_id, "reason": "Earlier baseline review."}]}), encoding="utf-8")
        self.write_policy(rules={"AI003": {"status": "justified", "reason": "Current rule review."}})
        self.assertEqual(self.invoke("--baseline", str(baseline))[0], 0)
        finding = self.report()["findings"][0]
        self.assertEqual(finding["status"], "justified")
        self.assertEqual(finding["original_status"], "suppressed")
        self.assertEqual(finding["suppression_reason"], "Earlier baseline review.")
        self.assertEqual(finding["disposition"]["reason"], "Current rule review.")
        sarif = json.loads((self.output / "report.sarif").read_text(encoding="utf-8"))
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["baselineSuppressionReason"], "Earlier baseline review.")

    def test_no_policy_autodiscovery_and_explicit_file_is_excluded_from_manifest(self):
        self.policy = self.repo / "trusted-review.json"
        self.write_policy(rules={"AI003": {"status": "disabled"}})
        self.assertEqual(self.invoke(policy=False)[0], 1)
        self.assertNotIn("review_policy", self.report())
        self.assertEqual(self.invoke()[0], 0)
        self.assertNotIn(self.policy.name, [f["path"] for f in self.report()["files"]])

    def test_invalid_policy_fails_before_static_or_model_side_effects(self):
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Must validate first")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Must validate first")):
            for policy in ({"schema_version": "1.0", "rules": {"AI999": {"status": "disabled"}}},
                           {"schema_version": "1.0", "rules": {"AI003": {"status": "justified"}}},
                           {"schema_version": "1.0", "rules": {"AI003": {"status": "pass"}}}):
                self.policy.write_text(json.dumps(policy), encoding="utf-8")
                code, stdout, _ = self.invoke("--summary-json", "--judge-config", str(self.judge))
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(stdout)["status"], "operational_error")
                self.assertFalse(self.output.exists())

    def test_exceptions_cannot_waive_parse_or_resource_gaps(self):
        self.write_policy(rules={r["id"]: {"status": "disabled"} for r in RULES})
        for source, options in (("broken python !!!", ()), ("x = '" + "a" * 100 + "'", ("--max-file-bytes", "20"))):
            (self.repo / "agent.py").write_text(source, encoding="utf-8")
            code, _, _ = self.invoke(*options, "--fail-on", "none")
            self.assertEqual(code, 2)
            self.assertGreater(self.report()["summary"]["coverage_gaps"], 0)
            self.assertEqual(self.report()["assessment"]["posture"]["code"], "incomplete_scope")

    def test_optional_triage_gets_only_open_findings_and_failure_remains_exit_two(self):
        self.write_policy(rules={"AI003": {"status": "justified", "reason": "Local decision only."}})
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as triage:
            self.assertEqual(self.invoke("--judge-config", str(self.judge), "--judge-mode", "findings")[0], 0)
        self.assertEqual(triage.call_args[0][1]["findings"], [])
        with mock.patch("ai_security_scan.judge.review", side_effect=JudgeError("Fixture failure.")):
            self.assertEqual(self.invoke("--judge-config", str(self.judge), "--judge-mode", "findings")[0], 2)
        self.assertEqual(self.report()["findings"][0]["status"], "justified")

    def test_all_exempt_controls_need_no_analyst_budget_but_triage_still_runs(self):
        self.write_policy(rules={"AI003": {"status": "disabled"}},
                          controls={c["id"]: {"status": "justified", "reason": "External review fixture."} for c in load_controls()})
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("No active checks")) as analyst:
            code, stdout, _ = self.invoke("--summary-json", "--judge-config", str(self.judge), "--analyst-max-calls", "0")
        self.assertEqual(code, 0)
        self.assertEqual(triage.call_count, 1)
        analyst.assert_not_called()
        report = self.report()
        self.assertEqual(json.loads(stdout)["coverage"]["total_checks"], 0)
        self.assertEqual(json.loads(stdout)["coverage"]["statically_mapped_controls"], 0)
        self.assertEqual(json.loads(stdout)["coverage"]["catalog_statically_mapped_controls"], 26)
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 0)
        self.assertEqual(report["analyst"]["coverage"]["validated_controls"], 0)
        self.assertEqual(sum(len(c["check_assessments"]) for c in report["analyst"]["control_assessments"]), 132)
        execution = next(c for c in report["analyst"]["control_assessments"] if c["control_id"] == "EXEC-01")
        self.assertEqual(execution["static_status"], "findings_detected")
        self.assertEqual(execution["effective_status"], "justified")

    def test_all_output_modes_are_byte_repeatable_with_review_configuration(self):
        self.write_policy(rules={"AI003": {"status": "justified", "reason": "Review fixture."}}, checks={"AUTH-01:2": {"status": "disabled"}})
        artifacts = []
        for options in ((), ("--quiet",), ("--summary-json",), ()):
            self.assertEqual(self.invoke(*options)[0], 0)
            artifacts.append({name: (self.output / name).read_bytes() for name in ARTIFACTS})
        self.assertTrue(all(item == artifacts[0] for item in artifacts))

    def test_policy_cannot_be_overwritten_by_output(self):
        self.output.mkdir()
        for filename in ARTIFACTS:
            self.policy = self.output / filename
            self.write_policy()
            before = self.policy.read_bytes()
            self.assertEqual(self.invoke()[0], 2)
            self.assertEqual(self.policy.read_bytes(), before)
        self.policy = self.base / "trusted-review.json"
        self.write_policy()
        before = self.policy.read_bytes()
        self.assertEqual(self.invoke("--write-baseline", str(self.policy), "--baseline-reason", "Reviewed")[0], 2)
        self.assertEqual(self.policy.read_bytes(), before)

    def test_help_example_and_check_identifiers_match_loader_and_catalog(self):
        from ai_security_scan.review_policy import load_review_config
        value, _ = json.JSONDecoder().raw_decode(parser().format_help().split("Review config JSON shape:", 1)[1].lstrip())
        self.policy.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(load_review_config(self.policy)["schema_version"], "1.0")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--list-controls"]), 0)
        controls = json.loads(output.getvalue())
        self.assertEqual(sum(len(c["check_ids"]) for c in controls), 132)
        for control in controls:
            self.assertEqual(control["check_ids"], [control["id"] + ":" + str(i) for i in range(1, len(control["checks"]) + 1)])
        load_review_config(PROJECT / "examples/review-config.json")

    def test_case_alias_config_collision_cannot_overwrite_trusted_policy(self):
        self.output.mkdir()
        self.policy = self.output / "REPORT.JSON"
        self.write_policy()
        if not (self.output / "report.json").exists():
            self.skipTest("Filesystem is case sensitive")
        before = self.policy.read_bytes()
        self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.policy.read_bytes(), before)
        self.policy = self.base / "REVIEW.JSON"
        self.write_policy()
        before = self.policy.read_bytes()
        self.assertEqual(self.invoke("--write-baseline", str(self.base / "review.json"), "--baseline-reason", "Fixture review")[0], 2)
        self.assertEqual(self.policy.read_bytes(), before)

    def test_symlink_loop_policy_returns_configuration_error_without_traceback(self):
        loop = self.base / "loop"
        try:
            loop.symlink_to("loop", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        self.policy = loop / "review.json"
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Invalid config must fail first")):
            code, stdout, stderr = self.invoke("--summary-json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout)["status"], "operational_error")
        self.assertNotIn("Traceback", stderr)
        self.policy = self.base / "valid-review.json"
        self.write_policy()
        code, _, stderr = self.invoke("--write-baseline", str(loop / "baseline.json"), "--baseline-reason", "Fixture review")
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", stderr)

    def test_all_six_actual_gateway_protocols_preserve_partial_check_identity(self):
        controls = load_controls()
        self.write_policy(rules={"AI003": {"status": "justified", "reason": "Private local review reason."}},
                          controls={c["id"]: {"status": "disabled"} for c in controls if c["id"] != "AUTH-01"},
                          checks={"AUTH-01:1": {"status": "justified", "reason": "Private checklist reason."}})
        expected_check = next(c for c in controls if c["id"] == "AUTH-01")["checks"][1]
        for provider in PROVIDERS:
            with self.subTest(provider=provider):
                with gateway(provider, lambda payload, number: {"answer": fixture_answer(payload)}) as (endpoint, captured, errors):
                    config = {"provider": provider, "model": "local-fixture", "endpoint": endpoint, "timeout_seconds": 3}
                    if provider == "custom":
                        config.update({"request_template": {"review_prompt": "${PROMPT}"}, "response_path": "data.review"})
                    self.judge.write_text(json.dumps(config), encoding="utf-8")
                    result = subprocess.run([sys.executable, str(PROJECT / "scan.py"), str(self.repo), "--output", str(self.output),
                                             "--review-config", str(self.policy), "--judge-config", str(self.judge),
                                             "--analyst-max-calls", "1"], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(errors, [])
                self.assertEqual(len(captured), 2)
                self.assertEqual(captured[0]["payload"]["findings"], [])
                sent = captured[1]["payload"]["controls"]
                self.assertEqual([(c["id"], c["checks"]) for c in sent], [("AUTH-01", [expected_check])])
                self.assertNotIn("Private local review reason.", json.dumps(captured))
                self.assertNotIn("Private checklist reason.", json.dumps(captured))
                report = self.report()
                checks = next(c for c in report["analyst"]["control_assessments"] if c["control_id"] == "AUTH-01")["check_assessments"]
                self.assertEqual([c["check_index"] for c in checks], [1, 2])
                self.assertEqual(checks[0]["status"], "justified")
                self.assertFalse(checks[0]["model_supplied"])
                self.assertTrue(checks[1]["model_supplied"])
                self.assertEqual(checks[1]["check"], expected_check)
                self.assertEqual(report["analyst"]["coverage"]["total_checks"], 1)
                self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 0)
                self.assertEqual(report["analyst"]["requests"][0]["check_index_map"], {"AUTH-01": [2]})


if __name__ == "__main__":
    unittest.main()
