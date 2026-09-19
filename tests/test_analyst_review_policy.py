"""User dispositions are exclusions, never model passes or missing reviews."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.analyst import run_analyst, unreviewed_analyst
from ai_security_scan.evidence import build_evidence
from ai_security_scan.judge import JudgeError
from ai_security_scan.scanner import scan
from tests.test_analyst_controller import review_response


def disposition(control, index, status, reason="User-owned deployment evidence."):
    return {"check_id": control["id"] + ":" + str(index), "check_index": index,
            "status": status, "reason": reason, "scope": "check"}


class AnalystReviewPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "agent.py").write_text('agent_name = "sample"\n', encoding="utf-8")
        self.report = scan(self.root)
        self.config = {"provider": "openai_chat", "model": "test-only-model"}

    def tearDown(self):
        self.temp.cleanup()

    def exclude_all(self, status="justified"):
        for control in self.report["controls"]:
            control["check_dispositions"] = [disposition(control, index, status)
                                             for index in range(1, len(control["checks"]) + 1)]

    def test_partial_control_compacts_request_and_restores_original_second_index(self):
        self.report["controls"] = self.report["controls"][:1]
        control = self.report["controls"][0]
        control["checks"][0] = "EXEMPT_CHECK_TEXT_NOT_FOR_PROVIDER"
        control["check_dispositions"] = [disposition(control, 1, "justified", "EXEMPT_REASON_NOT_FOR_PROVIDER")]
        original = copy.deepcopy(self.report)
        with mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as review, \
             mock.patch("ai_security_scan.analyst.build_evidence", wraps=build_evidence) as retrieve:
            result = run_analyst(self.config, self.report, self.root)
        self.assertEqual(self.report, original)
        payload = review.call_args.args[1]
        self.assertEqual(payload["controls"][0]["checks"], [control["checks"][1]])
        self.assertNotIn("EXEMPT_CHECK_TEXT_NOT_FOR_PROVIDER", json.dumps(payload))
        self.assertNotIn("EXEMPT_REASON_NOT_FOR_PROVIDER", json.dumps(payload))
        self.assertEqual(retrieve.call_args.args[0]["controls"][0]["checks"], [control["checks"][1]])
        self.assertEqual(result["requests"][0]["check_index_map"], {control["id"]: [2]})
        assessed = result["control_assessments"][0]
        self.assertEqual(assessed["review_status"], "reviewed")
        first, second = assessed["check_assessments"]
        self.assertEqual(first["status"], "justified")
        self.assertEqual(first["reason"], "EXEMPT_REASON_NOT_FOR_PROVIDER")
        self.assertFalse(first["model_supplied"])
        self.assertFalse(first["provenance"]["verified"])
        self.assertEqual(first["provenance"]["source"], "user_review_config")
        self.assertEqual(second["check_index"], 2)
        self.assertTrue(second["model_supplied"])
        self.assertEqual(second["check"], control["checks"][1])
        coverage = result["coverage"]
        self.assertEqual((coverage["catalog_controls"], coverage["catalog_checks"]), (1, 2))
        self.assertEqual((coverage["total_controls"], coverage["total_checks"]), (1, 1))
        self.assertEqual((coverage["excluded_controls"], coverage["excluded_checks"]), (0, 1))
        self.assertEqual(coverage["justified_checks"], 1)
        self.assertEqual(coverage["omitted_checks"], 0)
        self.assertEqual(result["status"], "completed")

    def test_all_catalog_checks_excluded_needs_no_model_or_evidence_even_zero_budget(self):
        for status in ("justified", "disabled"):
            with self.subTest(status=status):
                self.exclude_all(status)
                with mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Forbidden API call")) as review, \
                     mock.patch("ai_security_scan.analyst.build_evidence", side_effect=AssertionError("No evidence is required")) as evidence:
                    result = run_analyst(self.config, self.report, self.root, max_calls=0)
                review.assert_not_called()
                evidence.assert_not_called()
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["evidence"], [])
                self.assertEqual(result["requests"], [])
                self.assertEqual(len(result["control_assessments"]), 66)
                coverage = result["coverage"]
                self.assertEqual((coverage["catalog_controls"], coverage["catalog_checks"]), (66, 132))
                self.assertEqual((coverage["total_controls"], coverage["total_checks"]), (0, 0))
                self.assertEqual((coverage["excluded_controls"], coverage["excluded_checks"]), (66, 132))
                self.assertEqual(coverage[status + "_controls"], 66)
                self.assertEqual(coverage[status + "_checks"], 132)
                self.assertEqual(coverage["unreviewed_control_ids"], [])
                self.assertEqual(coverage["omitted_checks"], 0)
                self.assertEqual(coverage["reviewed_controls"], 0)
                self.assertEqual(coverage["validated_controls"], 0)
                for item in result["control_assessments"]:
                    self.assertEqual(item["review_status"], status)
                    self.assertFalse(item["validation_established"])
                    self.assertTrue(all(not check["model_supplied"] for check in item["check_assessments"]))

    def test_mixed_excluded_control_never_queues_and_later_control_maps_correctly(self):
        self.report["controls"] = self.report["controls"][:3]
        first, middle, last = self.report["controls"]
        first["check_dispositions"] = [disposition(first, 1, "justified"), disposition(first, 2, "disabled")]
        last["check_dispositions"] = [disposition(last, 2, "disabled")]
        with mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as review:
            result = run_analyst(self.config, self.report, self.root, batch_size=1)
        submitted = [item["id"] for call in review.call_args_list for item in call.args[1]["controls"]]
        self.assertEqual(submitted, [middle["id"], last["id"]])
        assessments = result["control_assessments"]
        self.assertEqual([item["control_id"] for item in assessments], [first["id"], middle["id"], last["id"]])
        self.assertEqual([item["review_status"] for item in assessments], ["excluded_from_review", "reviewed", "reviewed"])
        self.assertEqual(result["requests"][1]["check_index_map"], {last["id"]: [1]})
        self.assertEqual(result["coverage"]["total_checks"], 3)
        self.assertEqual(result["coverage"]["excluded_checks"], 3)
        self.assertEqual(result["coverage"]["reviewed_controls"], 2)
        self.assertEqual(result["coverage"]["omitted_checks"], 0)

    def test_budget_and_provider_error_preserve_exempt_reasons_and_active_denominators(self):
        self.report["controls"] = self.report["controls"][:2]
        first, second = self.report["controls"]
        first["check_dispositions"] = [disposition(first, 1, "justified", "Retain first owner reason.")]
        second["check_dispositions"] = [disposition(second, 2, "disabled", "Retain second owner reason.")]
        for mode in ("zero_budget", "provider_error"):
            with self.subTest(mode=mode):
                with mock.patch("ai_security_scan.judge.review_controls", side_effect=JudgeError("Provider fixture failure.")):
                    result = run_analyst(self.config, self.report, self.root, max_calls=0 if mode == "zero_budget" else 2)
                self.assertEqual(result["status"], "incomplete" if mode == "zero_budget" else "error")
                self.assertEqual(result["coverage"]["total_checks"], 2)
                self.assertEqual(result["coverage"]["omitted_checks"], 2)
                self.assertEqual(result["coverage"]["unreviewed_control_ids"], [first["id"], second["id"]])
                assessments = result["control_assessments"]
                self.assertEqual(assessments[0]["check_assessments"][0]["reason"], "Retain first owner reason.")
                self.assertEqual(assessments[1]["check_assessments"][1]["reason"], "Retain second owner reason.")
                self.assertIn("stopped" if mode == "provider_error" else "budget", assessments[0]["check_assessments"][1]["reason"])

    def test_earlier_stage_error_is_not_converted_to_success_by_full_exclusion(self):
        self.exclude_all()
        result = unreviewed_analyst(self.report, "Earlier stage failed.")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"], ["Earlier stage failed."])
        self.assertEqual(result["coverage"]["omitted_checks"], 0)
        self.assertEqual(result["coverage"]["unreviewed_control_ids"], [])
        self.assertEqual(result["control_assessments"][0]["check_assessments"][0]["reason"], "User-owned deployment evidence.")

    def test_missing_active_answer_remains_omitted_using_actual_judge_validation(self):
        self.report["controls"] = self.report["controls"][:1]
        control = self.report["controls"][0]
        control["check_dispositions"] = [disposition(control, 1, "disabled")]
        response = {"control_assessments": [{"control_id": control["id"], "check_assessments": []}]}
        envelope = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(response)}}]}
        with mock.patch("ai_security_scan.judge._post_json", return_value=envelope):
            result = run_analyst(self.config, self.report, self.root)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["coverage"]["omitted_checks"], 1)
        first, second = result["control_assessments"][0]["check_assessments"]
        self.assertEqual(first["status"], "disabled")
        self.assertEqual(second["status"], "insufficient_evidence")
        self.assertEqual(second["check_index"], 2)
        self.assertFalse(second["model_supplied"])
        self.assertEqual(result["requests"][0]["omitted_checks"], 1)

    def test_provider_cannot_use_catalog_index_to_overwrite_excluded_check(self):
        self.report["controls"] = self.report["controls"][:1]
        control = self.report["controls"][0]
        control["check_dispositions"] = [disposition(control, 1, "justified", "Protected owner reason.")]
        for submitted_index in (1, 2):
            with self.subTest(submitted_index=submitted_index):
                answer = {
                    "control_assessments": [{"control_id": control["id"], "check_assessments": [{
                        "check_index": submitted_index, "status": "insufficient_evidence",
                        "reason": "Runtime evidence is needed.", "citations": [],
                        "verification_steps": ["Inspect deployment evidence."],
                    }]}],
                }
                envelope = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(answer)}}]}
                with mock.patch("ai_security_scan.judge._post_json", return_value=envelope):
                    result = run_analyst(self.config, self.report, self.root)
                first, second = result["control_assessments"][0]["check_assessments"]
                self.assertEqual(first["status"], "justified")
                self.assertEqual(first["reason"], "Protected owner reason.")
                self.assertFalse(first["model_supplied"])
                self.assertEqual(second["check_index"], 2)
                if submitted_index == 1:
                    self.assertEqual(result["status"], "completed")
                    self.assertTrue(second["model_supplied"])
                    self.assertEqual(second["reason"], "Runtime evidence is needed.")
                else:
                    self.assertEqual(result["status"], "error")
                    self.assertFalse(second["model_supplied"])
                    self.assertEqual(result["coverage"]["omitted_checks"], 1)


if __name__ == "__main__":
    unittest.main()
