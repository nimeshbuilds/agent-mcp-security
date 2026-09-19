"""Controlled analyst scheduling invariants, without provider calls or credentials."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.analyst import run_analyst
from ai_security_scan.judge import JudgeError
from ai_security_scan.scanner import scan


def review_response(config, payload):
    """A valid advisory answer that makes no unsupported security claim."""
    return {
        "provider": "openai_chat",
        "model": "test-only-model",
        "advisory_only": True,
        "nondeterministic": True,
        "omitted_controls": 0,
        "omitted_checks": 0,
        "control_assessments": [
            {
                "control_id": control["id"],
                "check_assessments": [
                    {
                        "check_index": index,
                        "status": "insufficient_evidence",
                        "reason": "This repository sample does not establish the acceptance check.",
                        "citations": [],
                        "verification_steps": ["Obtain deployment evidence and have an owner validate this check."],
                    }
                    for index, _ in enumerate(control["checks"], start=1)
                ],
            }
            for control in payload["controls"]
        ],
    }


class AnalystControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "repository"
        self.root.mkdir()
        # The controller must read evidence only; importing this target fails.
        (self.root / "agent.py").write_text(
            'agent_name = "example"\nraise RuntimeError("TARGET_MUST_NOT_EXECUTE")\n',
            encoding="utf-8",
        )
        self.config = {"provider": "openai_chat", "model": "test-only-model"}
        self.report = scan(self.root)
        self.ids = [control["id"] for control in self.report["controls"]]
        self.total_checks = sum(len(control["checks"]) for control in self.report["controls"])

    def tearDown(self):
        self.temp.cleanup()

    def assert_every_check_present(self, result):
        assessments = result["control_assessments"]
        self.assertEqual([item["control_id"] for item in assessments], self.ids)
        for original, assessed in zip(self.report["controls"], assessments):
            self.assertEqual(
                [check["check_index"] for check in assessed["check_assessments"]],
                list(range(1, len(original["checks"]) + 1)),
            )
            self.assertIn(assessed["review_status"], {"reviewed", "partial", "not_reviewed"})
            self.assertFalse(assessed["provenance"]["runtime_execution"])
            self.assertTrue(all(check["status"] not in {"pass", "compliant", "secure"}
                                for check in assessed["check_assessments"]))

    def test_zero_findings_still_reviews_every_control_and_check(self):
        self.assertEqual(self.report["findings"], [])
        with mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as review:
            result = run_analyst(self.config, self.report, self.root)
        self.assertEqual(len(self.ids), 66)
        self.assertEqual(self.total_checks, 132)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["enabled"])
        self.assertTrue(result["advisory_only"])
        self.assertTrue(result["nondeterministic"])
        self.assert_every_check_present(result)
        coverage = result["coverage"]
        self.assertEqual(coverage["total_controls"], 66)
        self.assertEqual(coverage["total_checks"], 132)
        self.assertEqual(coverage["attempted_controls"], 66)
        self.assertEqual(coverage["reviewed_controls"], 66)
        self.assertEqual(coverage["unreviewed_control_ids"], [])
        self.assertEqual(coverage["omitted_checks"], 0)
        self.assertEqual(review.call_count, 11)
        self.assertEqual(coverage["calls_made"], review.call_count)
        submitted = [control["id"] for call in review.call_args_list for control in call.args[1]["controls"]]
        self.assertEqual(submitted, self.ids)
        self.assertTrue(all(len(call.args[1]["controls"]) <= 6 for call in review.call_args_list))

    def test_call_budget_keeps_every_unreviewed_check_explicit(self):
        with mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as review:
            result = run_analyst(self.config, self.report, self.root, max_calls=1, batch_size=6)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(review.call_count, 1)
        self.assert_every_check_present(result)
        coverage = result["coverage"]
        self.assertEqual(coverage["call_budget"], 1)
        self.assertEqual(coverage["calls_made"], 1)
        self.assertEqual(coverage["attempted_controls"], 6)
        self.assertEqual(coverage["reviewed_controls"], 6)
        self.assertEqual(coverage["unreviewed_control_ids"], self.ids[6:])
        self.assertEqual(coverage["omitted_checks"], self.total_checks - 12)
        for assessment in result["control_assessments"][6:]:
            self.assertEqual(assessment["review_status"], "not_reviewed")
            for check in assessment["check_assessments"]:
                self.assertEqual(check["status"], "insufficient_evidence")
                self.assertTrue(check["reason"])
                self.assertEqual(check["citations"], [])

    def test_zero_call_budget_never_invokes_model(self):
        with mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Network forbidden")) as review:
            result = run_analyst(self.config, self.report, self.root, max_calls=0)
        self.assertEqual(result["status"], "incomplete")
        review.assert_not_called()
        self.assert_every_check_present(result)
        self.assertEqual(result["coverage"]["attempted_controls"], 0)
        self.assertEqual(result["coverage"]["unreviewed_control_ids"], self.ids)
        self.assertEqual(result["coverage"]["omitted_checks"], self.total_checks)

    def test_provider_failure_stops_requests_and_preserves_all_static_results(self):
        original = copy.deepcopy(self.report)
        calls = []

        def fail_second(config, payload):
            calls.append(copy.deepcopy(payload))
            if len(calls) == 2:
                raise JudgeError("Judge response failed grounding validation.")
            return review_response(config, payload)

        with mock.patch("ai_security_scan.judge.review_controls", side_effect=fail_second):
            result = run_analyst(self.config, self.report, self.root)
        self.assertEqual(result["status"], "error")
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.report, original)
        self.assert_every_check_present(result)
        self.assertEqual(result["coverage"]["calls_made"], 2)
        self.assertEqual(result["coverage"]["attempted_controls"], 12)
        self.assertEqual(result["coverage"]["reviewed_controls"], 6)
        self.assertEqual(result["coverage"]["unreviewed_control_ids"], self.ids[6:])
        self.assertTrue(result["errors"])

    def test_schedule_and_evidence_are_deterministic_but_advice_is_separate(self):
        before = copy.deepcopy(self.report)
        submitted = []

        def capture(config, payload):
            submitted.append(copy.deepcopy(payload))
            return review_response(config, payload)

        with mock.patch("ai_security_scan.judge.review_controls", side_effect=capture):
            first = run_analyst(self.config, self.report, self.root)
            count = len(submitted)
            second = run_analyst(self.config, self.report, self.root)
        self.assertEqual(submitted[:count], submitted[count:])
        self.assertEqual(first["control_assessments"], second["control_assessments"])
        self.assertEqual(self.report, before)
        self.assertTrue(first["nondeterministic"])
        self.assert_every_check_present(first)

    def test_elapsed_budget_stops_later_batches_and_bounds_request_timeout(self):
        clock = [0.0]
        seen_configs = []

        def exhaust_budget(config, payload):
            seen_configs.append(config)
            clock[0] = 20.0
            return review_response(config, payload)

        with mock.patch("ai_security_scan.analyst.time.monotonic", side_effect=lambda: clock[0]), \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=exhaust_budget) as review:
            result = run_analyst(self.config, self.report, self.root, max_seconds=10)
        self.assertEqual(review.call_count, 1)
        self.assertLessEqual(seen_configs[0]["timeout_seconds"], 10)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["coverage"]["reviewed_controls"], 6)
        self.assertEqual(result["coverage"]["unreviewed_control_ids"], self.ids[6:])
        self.assert_every_check_present(result)

    def test_invalid_limits_are_rejected_before_any_model_call(self):
        cases = [
            {"max_calls": -1}, {"max_calls": True},
            {"batch_size": 0}, {"batch_size": 21}, {"batch_size": True},
            {"max_files": -1}, {"max_bytes": -1}, {"max_chars": -1},
            {"max_seconds": 0}, {"max_seconds": 3601}, {"max_seconds": float("nan")},
            {"max_seconds": 10 ** 1000},
        ]
        with mock.patch("ai_security_scan.judge.review_controls") as review:
            for limits in cases:
                with self.subTest(limits=limits), self.assertRaises((ValueError, JudgeError)):
                    run_analyst(self.config, self.report, self.root, **limits)
        review.assert_not_called()


if __name__ == "__main__":
    unittest.main()
