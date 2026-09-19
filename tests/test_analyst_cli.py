"""Public CLI integration for the default, controlled full-security review."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.cli import main
from ai_security_scan.judge import JudgeError

from tests.test_analyst_controller import review_response


def triage_response(config, payload):
    return {
        "provider": "openai_chat", "model": "test-only-model",
        "advisory_only": True, "nondeterministic": True,
        "assessments": [
            {"finding_id": finding["finding_id"], "verdict": "likely_false_positive",
             "reason": "Advisory fixture response; deterministic evidence remains unchanged."}
            for finding in payload["findings"]
        ],
        "additional_concerns": [], "omitted_assessments": 0,
        "findings_submitted": len(payload["findings"]),
    }


class AnalystCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repository"
        self.repo.mkdir()
        self.config = self.base / "trusted-judge.json"
        self.config.write_text(json.dumps({"provider": "openai_chat", "model": "test-only-model"}), encoding="utf-8")
        (self.repo / "agent.py").write_text('agent_name = "test agent"\n', encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, output_name, *arguments):
        output = self.base / output_name
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([str(self.repo), "--output", str(output), *arguments])
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        return code, report, output

    def test_default_static_scan_never_invokes_either_model_layer(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=AssertionError("No model permission")) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("No model permission")) as analyst:
            code, report, _ = self.cli("static")
        self.assertEqual(code, 0)
        triage.assert_not_called()
        analyst.assert_not_called()
        self.assertFalse(report["judge"]["enabled"])
        self.assertFalse(report.get("analyst", {}).get("enabled", False))

    def test_default_configured_mode_reviews_zero_finding_control_gaps(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as analyst:
            code, report, output = self.cli("full", "--judge-config", str(self.config))
        self.assertEqual(code, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(triage.call_count, 1)
        self.assertEqual(analyst.call_count, 11)
        self.assertEqual(report["analyst"]["status"], "completed")
        self.assertEqual(len(report["analyst"]["control_assessments"]), 66)
        self.assertEqual(report["analyst"]["coverage"]["total_checks"], 132)
        self.assertEqual(report["execution"]["exit_code"], 0)
        self.assertEqual({path.name for path in output.iterdir()}, {"report.json", "report.md", "report.sarif"})
        self.assertIn("insufficient_evidence", (output / "report.md").read_text(encoding="utf-8").replace("\\_", "_"))

    def test_findings_mode_keeps_control_calls_disabled(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Control review not selected")) as analyst:
            code, report, _ = self.cli("findings", "--judge-config", str(self.config), "--judge-mode", "findings")
        self.assertEqual(code, 0)
        self.assertEqual(triage.call_count, 1)
        analyst.assert_not_called()
        self.assertFalse(report.get("analyst", {}).get("enabled", False))

    def test_incomplete_control_budget_preserves_findings_sarif_and_gate(self):
        (self.repo / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        baseline_code, baseline, baseline_output = self.cli("baseline")
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response), \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as analyst:
            code, report, output = self.cli("bounded", "--judge-config", str(self.config), "--analyst-max-calls", "1")
        self.assertEqual(baseline_code, 1)
        self.assertEqual(code, 2)
        self.assertEqual(analyst.call_count, 1)
        self.assertEqual(report["analyst"]["status"], "incomplete")
        self.assertEqual(report["analyst"]["coverage"]["reviewed_controls"], 6)
        self.assertEqual(len(report["analyst"]["coverage"]["unreviewed_control_ids"]), 60)
        for field in ("findings", "controls", "summary", "scan_id"):
            self.assertEqual(report[field], baseline[field])
        self.assertTrue(report["execution"]["finding_gate_triggered"])
        self.assertEqual((output / "report.sarif").read_bytes(), (baseline_output / "report.sarif").read_bytes())

    def test_zero_control_call_budget_is_an_explicit_incomplete_report(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response), \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Budget forbids network")) as analyst:
            code, report, _ = self.cli("zero", "--judge-config", str(self.config), "--analyst-max-calls", "0")
        self.assertEqual(code, 2)
        analyst.assert_not_called()
        self.assertEqual(report["analyst"]["status"], "incomplete")
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 132)
        self.assertEqual(len(report["analyst"]["control_assessments"]), 66)

    def test_finding_triage_failure_preserves_report_and_prevents_control_calls(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=JudgeError("Judge response was invalid.")), \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Fail-closed after error")) as analyst:
            code, report, output = self.cli("failure", "--judge-config", str(self.config))
        self.assertEqual(code, 2)
        analyst.assert_not_called()
        self.assertEqual(report["judge"]["status"], "error")
        self.assertEqual(report["analyst"]["status"], "error")
        self.assertEqual(len(report["analyst"]["control_assessments"]), 66)
        self.assertEqual(report["analyst"]["coverage"]["reviewed_controls"], 0)
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 132)
        self.assertTrue((output / "report.sarif").exists())

    def test_full_mode_rejects_custom_tool_config_before_finding_triage(self):
        self.config.write_text(json.dumps({
            "provider": "custom", "model": "internal-analyst",
            "endpoint": "https://gateway.example.test/security/review",
            "request_template": {
                "review_prompt": "${PROMPT}",
                "tools": [{"type": "function", "function": {"name": "execute_code"}}],
            },
            "response_path": "data.review",
        }), encoding="utf-8")
        with mock.patch("ai_security_scan.judge.review", side_effect=AssertionError("Tool config must be rejected before triage")) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Tool config must be rejected before controls")) as analyst:
            code, report, output = self.cli("forbidden-tools", "--judge-config", str(self.config))
        self.assertEqual(code, 2)
        triage.assert_not_called()
        analyst.assert_not_called()
        self.assertEqual(report["judge"]["status"], "error")
        self.assertEqual(report["analyst"]["status"], "error")
        self.assertEqual(report["analyst"]["coverage"]["calls_made"], 0)
        self.assertEqual(report["analyst"]["coverage"]["reviewed_controls"], 0)
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 132)
        self.assertEqual(len(report["analyst"]["control_assessments"]), 66)
        self.assertTrue((output / "report.sarif").exists())

    def test_custom_gateway_full_pipeline_validates_every_control_batch(self):
        self.config.write_text(json.dumps({
            "provider": "custom", "model": "internal-analyst",
            "endpoint": "https://gateway.example.test/security/review",
            "request_template": {"deployment": "${MODEL}", "review_prompt": "${PROMPT}"},
            "response_path": "data.review",
        }), encoding="utf-8")
        requests = []

        def gateway(config, headers, body):
            request = json.loads(body)
            payload = json.loads(request["review_prompt"].split("UNTRUSTED_REPOSITORY_DATA_JSON:\n", 1)[1])
            requests.append({"config": config, "request": request, "payload": payload})
            if "controls" in payload:
                answer = {"control_assessments": review_response(config, payload)["control_assessments"]}
            else:
                answer = {"assessments": [], "additional_concerns": []}
            return {"data": {"review": answer}}

        with mock.patch("ai_security_scan.judge._post_json", side_effect=gateway):
            code, report, _ = self.cli("custom-full", "--judge-config", str(self.config))
        self.assertEqual(code, 0)
        self.assertEqual(report["judge"]["status"], "completed")
        self.assertEqual(report["analyst"]["status"], "completed")
        self.assertEqual(len(requests), 12)
        self.assertTrue(all(request["config"]["endpoint"] == "https://gateway.example.test/security/review" for request in requests))
        self.assertTrue(all(request["request"]["deployment"] == "internal-analyst" for request in requests))
        controls = [control["id"] for request in requests if "controls" in request["payload"] for control in request["payload"]["controls"]]
        self.assertEqual(controls, [control["id"] for control in report["controls"]])
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 0)
        self.assertEqual(report["analyst"]["coverage"]["reviewed_controls"], 66)

    def test_omitted_model_checks_are_explicit_and_make_run_incomplete(self):
        batches = []

        def provider(config, headers, body):
            request = json.loads(body)
            payload = json.loads(request["messages"][1]["content"].split("UNTRUSTED_REPOSITORY_DATA_JSON:\n", 1)[1])
            if "controls" in payload:
                answer = {"control_assessments": review_response(config, payload)["control_assessments"]}
                batches.append(payload)
                if len(batches) == 1:
                    for control in answer["control_assessments"]:
                        control["check_assessments"] = control["check_assessments"][:1]
            else:
                answer = {"assessments": [], "additional_concerns": []}
            return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(answer)}}]}

        with mock.patch("ai_security_scan.judge._post_json", side_effect=provider):
            code, report, _ = self.cli("partial", "--judge-config", str(self.config))
        self.assertEqual(code, 2)
        self.assertEqual(len(batches), 11)
        self.assertEqual(report["analyst"]["status"], "incomplete")
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 6)
        self.assertEqual(report["analyst"]["coverage"]["reviewed_controls"], 60)
        assessments = report["analyst"]["control_assessments"]
        self.assertEqual(len(assessments), 66)
        for control in assessments[:6]:
            self.assertEqual(control["review_status"], "partial")
            self.assertEqual(len(control["check_assessments"]), 2)
            self.assertTrue(control["check_assessments"][0]["model_supplied"])
            self.assertFalse(control["check_assessments"][1]["model_supplied"])
            self.assertEqual(control["check_assessments"][1]["status"], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
