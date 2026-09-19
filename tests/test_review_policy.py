"""User dispositions must be explicit, bounded, auditable, and never become passes."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from ai_security_scan.review_policy import (
    DEFAULT_DISABLED_REASON, MAX_CONFIG_BYTES, MAX_REASON_CHARS,
    apply_review_config, load_review_config, validate_review_config,
)
from ai_security_scan.rules import RULES
from ai_security_scan.scanner import load_controls, scan


class ReviewPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")

    def config(self, value):
        path = self.base / "review.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def policy(self, **entries):
        return validate_review_config({"schema_version": "1.0", **entries})

    def test_empty_config_and_omitted_sections_are_canonical(self):
        policy = load_review_config(self.config({"schema_version": "1.0"}))
        self.assertEqual(policy, {"schema_version": "1.0", "rules": {}, "controls": {}, "checks": {}})
        report = scan(self.root)
        updated = apply_review_config(report, policy)
        self.assertEqual(updated["findings"], report["findings"])
        self.assertEqual(updated["summary"]["open_findings"], 1)
        self.assertEqual(updated["review_policy"]["counts"], {
            "catalog_rules": 42, "catalog_controls": 66, "catalog_checks": 132,
            "active_rules": 42, "justified_rules": 0, "disabled_rules": 0,
            "active_controls": 66, "justified_controls": 0, "disabled_controls": 0,
            "excluded_controls": 0, "mixed_excluded_controls": 0,
            "active_checks": 132, "justified_checks": 0, "disabled_checks": 0,
        })
        self.assertNotEqual(updated["scan_id"], report["scan_id"])

    def test_none_does_not_change_report_and_output_is_independent(self):
        original = scan(self.root)
        updated = apply_review_config(original, None)
        self.assertEqual(updated, original)
        updated["findings"][0]["status"] = "mutated"
        self.assertEqual(original["findings"][0]["status"], "open")

    def test_strict_schema_rejects_unknown_fields_types_and_identifiers(self):
        invalid = [None, [], True, {}, {"schema_version": 1.0},
                   {"schema_version": "2.0"}, {"schema_version": "1.0", "extra": True}]
        for scope in ("rules", "controls", "checks"):
            for value in ([], None, True, "disabled", 1):
                invalid.append({"schema_version": "1.0", scope: value})
            for identifier in ("UNKNOWN", "", "AI001:1", "GOV-01:0", "GOV-01:3", "GOV-01:01", 7, "\ud800"):
                invalid.append({"schema_version": "1.0", scope: {identifier: {"status": "disabled"}}})
        for value in invalid:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                validate_review_config(value)

    def test_disposition_fields_are_strict_and_justification_is_required(self):
        invalid = [None, [], "disabled", {}, {"status": True}, {"status": []},
                   {"status": "pass"}, {"status": "suppressed"}, {"status": "active"},
                   {"status": "justified"}, {"status": "justified", "reason": "  \n\t"},
                   {"status": "disabled", "reason": ""}, {"status": "disabled", "reason": None},
                   {"status": "justified", "reason": "valid", "expiry": "2026-09-19"},
                   {"status": "justified", "reason": 5}, {"status": "justified", "reason": []},
                   {"status": "justified", "reason": "A" * (MAX_REASON_CHARS + 1)},
                   {"status": "justified", "reason": "\ud800"},
                   {"status": "justified", "reason": "reason\x00hidden"},
                   {"status": "justified", "reason": "reason\x1b[31m"}]
        for item in invalid:
            with self.subTest(item=repr(item)), self.assertRaises(ValueError):
                self.policy(rules={"AI001": item})
        policy = self.policy(rules={"AI001": {"status": "disabled"},
                                    "AI002": {"status": "justified", "reason": "Résumé ✔\n\tReviewed."},
                                    "AI003": {"status": "justified", "reason": "A" * MAX_REASON_CHARS}})
        self.assertEqual(policy["rules"]["AI001"]["reason"], DEFAULT_DISABLED_REASON)
        self.assertEqual(len(policy["rules"]["AI003"]["reason"]), MAX_REASON_CHARS)

    def test_duplicate_keys_rejected_at_every_json_level(self):
        values = [
            '{"schema_version":"1.0","schema_version":"1.0"}',
            '{"schema_version":"1.0","rules":{"AI001":{"status":"disabled"},"AI001":{"status":"justified","reason":"x"}}}',
            '{"schema_version":"1.0","rules":{"AI001":{"status":"disabled","status":"justified","reason":"x"}}}',
            '{"schema_version":"1.0","rules":{"AI001":{"status":"justified","reason":"x","reason":"y"}}}',
        ]
        for raw in values:
            with self.subTest(raw=raw):
                path = self.base / "review.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    load_review_config(path)

    def test_file_reader_rejects_malformed_nonstandard_and_excessive_json(self):
        path = self.base / "review.json"
        for raw in (b"{", b"\xff", b'{"schema_version":"1.0","rules":NaN}',
                    b'{"schema_version":"1.0","rules":Infinity}',
                    b"[" * 2000 + b"]" * 2000, b" " * (MAX_CONFIG_BYTES + 1)):
            with self.subTest(prefix=raw[:60]):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    load_review_config(path)
        path.write_bytes(b'\xef\xbb\xbf{"schema_version":"1.0"}')
        self.assertEqual(load_review_config(path), self.policy())

    def test_programmatic_policy_also_has_a_total_size_budget(self):
        policy = {"schema_version": "1.0", "checks": {
            "{}:{}".format(control["id"], index): {"status": "justified", "reason": "x" * MAX_REASON_CHARS}
            for control in load_controls() for index in range(1, len(control["checks"]) + 1)}}
        with self.assertRaisesRegex(ValueError, "byte limit"):
            validate_review_config(policy)

    def test_file_reader_rejects_directory_and_symlink(self):
        with self.assertRaises(ValueError):
            load_review_config(self.base)
        actual = self.config({"schema_version": "1.0"})
        link = self.base / "link.json"
        try:
            link.symlink_to(actual)
        except OSError:
            self.skipTest("Creating symlinks requires platform permission")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            load_review_config(link)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_file_reader_rejects_fifo_without_blocking(self):
        fifo = self.base / "pipe.json"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            load_review_config(fifo)

    def test_file_reader_turns_missing_or_looped_parent_into_config_error(self):
        with self.assertRaises(ValueError):
            load_review_config(self.base / "missing-parent" / "review.json")
        link = self.base / "loop"
        try:
            link.symlink_to("loop", target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlinks requires platform permission")
        with self.assertRaises(ValueError):
            load_review_config(link / "review.json")

    def test_control_and_child_check_overlap_is_rejected_even_when_same(self):
        for control_status in ("disabled", "justified"):
            for check_status in ("disabled", "justified"):
                with self.subTest(control=control_status, check=check_status), self.assertRaisesRegex(ValueError, "both a whole control"):
                    self.policy(controls={"GOV-01": {"status": control_status, "reason": "Reviewed"}},
                                checks={"GOV-01:1": {"status": check_status, "reason": "Reviewed"}})

    def test_rule_disposition_retains_evidence_and_excludes_only_its_findings(self):
        (self.root / "second.py").write_text("eval(untrusted_input)\n", encoding="utf-8")
        original = scan(self.root)
        snapshot = copy.deepcopy(original)
        original["assessment"] = {"stale": True}
        for status in ("justified", "disabled"):
            with self.subTest(status=status):
                result = apply_review_config(original, self.policy(rules={"AI003": {"status": status, "reason": "Test fixture intentionally uses the API"}}))
                finding = next(f for f in result["findings"] if f["rule_id"] == "AI003")
                before = next(f for f in original["findings"] if f["rule_id"] == "AI003")
                self.assertEqual(finding["status"], status)
                self.assertEqual(finding["original_status"], "open")
                self.assertEqual(finding["disposition"], {"status": status, "scope": "rule", "id": "AI003", "reason": "Test fixture intentionally uses the API"})
                for field in ("id", "finding_id", "rule_id", "path", "line", "evidence", "severity", "confidence"):
                    self.assertEqual(finding[field], before[field])
                self.assertEqual(result["summary"]["open_findings"], 1)
                self.assertEqual(result["summary"][status + "_findings"], 1)
                self.assertEqual(result["summary"]["suppressed_findings"], 0)
                self.assertEqual(result["summary"]["severity_counts"]["high"], 1)
                self.assertNotIn("AI003", result["coverage"]["rules_enabled"])
                self.assertEqual(result["coverage"]["rules_" + status], ["AI003"])
                self.assertNotIn("assessment", result)
                self.assertEqual(result["review_policy"]["counts"]["active_checks"], 132)
        original.pop("assessment")
        self.assertEqual(original, snapshot)

    def test_rule_override_takes_precedence_over_baseline_and_retains_reason(self):
        first = scan(self.root)
        identifier = first["findings"][0]["id"]
        original = scan(self.root, baseline={identifier: "Legacy accepted exception"})
        for status in ("justified", "disabled"):
            result = apply_review_config(original, self.policy(rules={"AI003": {"status": status, "reason": "Explicit review override"}}))
            finding = result["findings"][0]
            self.assertEqual(finding["original_status"], "suppressed")
            self.assertEqual(finding["suppression_reason"], "Legacy accepted exception")
            self.assertEqual(result["summary"]["suppressed_findings"], 0)
            self.assertEqual(result["summary"][status + "_findings"], 1)
            self.assertEqual(result["summary"]["open_findings"], 0)

    def test_unrelated_disposition_preserves_suppressed_baseline_accounting(self):
        first = scan(self.root)
        identifier = first["findings"][0]["id"]
        original = scan(self.root, baseline={identifier: "Existing baseline reason"})
        result = apply_review_config(original, self.policy(rules={"AI001": {"status": "disabled"}}))
        self.assertEqual(result["findings"], original["findings"])
        self.assertEqual(result["summary"]["suppressed_findings"], 1)
        self.assertEqual(result["summary"]["open_findings"], 0)
        for control in result["controls"]:
            if "AI003" in control["automated_rule_ids"]:
                self.assertEqual(control["status"], "findings_suppressed")
                self.assertEqual(control["suppressed_finding_ids"], [identifier])

    def test_all_rules_support_both_states_and_preserve_zero_denominator(self):
        original = scan(self.root)
        template = original["findings"][0]
        original["findings"] = [{**template, "id": rule["id"], "finding_id": rule["id"], "rule_id": rule["id"], "severity": rule["severity"]} for rule in RULES]
        for status in ("justified", "disabled"):
            policy = self.policy(rules={rule["id"]: {"status": status, "reason": "Reviewed scope exception"} for rule in RULES})
            result = apply_review_config(original, policy)
            self.assertEqual(len(result["findings"]), 42)
            self.assertEqual({finding["status"] for finding in result["findings"]}, {status})
            self.assertEqual(result["summary"]["open_findings"], 0)
            self.assertEqual(result["summary"][status + "_findings"], 42)
            self.assertEqual(sum(result["summary"]["severity_counts"].values()), 0)
            self.assertEqual(result["coverage"]["rules_enabled"], [])
            self.assertEqual(result["review_policy"]["counts"]["active_rules"], 0)
            self.assertEqual(result["review_policy"]["counts"][status + "_rules"], 42)

    def test_control_dispositions_never_waive_static_findings(self):
        original = scan(self.root)
        for status in ("justified", "disabled"):
            result = apply_review_config(original, self.policy(controls={control["id"]: {"status": status, "reason": "Externally reviewed"} for control in original["controls"]}))
            self.assertEqual(result["findings"], original["findings"])
            self.assertEqual(result["summary"]["open_findings"], 1)
            self.assertEqual(result["summary"]["severity_counts"]["high"], 1)
            counts = result["review_policy"]["counts"]
            self.assertEqual(counts["active_controls"], 0)
            self.assertEqual(counts["active_checks"], 0)
            self.assertEqual(counts[status + "_controls"], 66)
            self.assertEqual(counts["excluded_controls"], 66)
            self.assertEqual(counts["mixed_excluded_controls"], 0)
            self.assertEqual(counts[status + "_checks"], 132)
            self.assertEqual(counts["active_rules"], 42)
            for control, before in zip(result["controls"], original["controls"]):
                self.assertEqual(control["status"], status)
                self.assertEqual(control["static_status"], before["status"])
                self.assertEqual(control["finding_ids"], before["finding_ids"])
                self.assertEqual(control["disposition"]["scope"], "control")
                self.assertTrue(all(item["status"] == status and item["scope"] == "control" for item in control["check_dispositions"]))

    def test_partial_check_disposition_keeps_its_sibling_active(self):
        original = scan(self.root)
        result = apply_review_config(original, self.policy(checks={"GOV-01:2": {"status": "justified", "reason": "Evidence reviewed separately"}}))
        control = next(control for control in result["controls"] if control["id"] == "GOV-01")
        self.assertEqual(control["status"], control["static_status"])
        self.assertEqual(control["check_dispositions"], [
            {"check_id": "GOV-01:1", "check_index": 1, "status": "active", "reason": ""},
            {"check_id": "GOV-01:2", "check_index": 2, "status": "justified", "reason": "Evidence reviewed separately", "scope": "check", "id": "GOV-01:2"},
        ])
        counts = result["review_policy"]["counts"]
        self.assertEqual(counts["active_controls"], 66)
        self.assertEqual(counts["active_checks"], 131)
        self.assertEqual(counts["justified_checks"], 1)
        self.assertEqual(counts["justified_controls"], 0)
        self.assertEqual(result["findings"], original["findings"])

    def test_all_check_exemptions_have_homogeneous_or_mixed_control_state(self):
        for first, second, control_state in (("disabled", "disabled", "disabled"),
                                              ("justified", "justified", "justified"),
                                              ("disabled", "justified", "excluded_from_review")):
            result = apply_review_config(scan(self.root), self.policy(checks={
                "GOV-01:1": {"status": first, "reason": "First exception"},
                "GOV-01:2": {"status": second, "reason": "Second exception"},
            }))
            control = next(control for control in result["controls"] if control["id"] == "GOV-01")
            self.assertEqual(control["status"], control_state)
            counts = result["review_policy"]["counts"]
            self.assertEqual(counts["active_controls"], 65)
            self.assertEqual(counts["active_checks"], 130)
            key = "mixed_excluded_controls" if first != second else first + "_controls"
            self.assertEqual(counts[key], 1)
            self.assertEqual(counts["excluded_controls"], 1)
            self.assertEqual(sum(counts[key] for key in ("active_controls", "justified_controls", "disabled_controls", "mixed_excluded_controls")), 66)
            self.assertEqual(sum(counts[key] for key in ("active_checks", "justified_checks", "disabled_checks")), 132)

    def test_every_catalog_check_can_be_addressed_individually(self):
        original = scan(self.root)
        checks = {"{}:{}".format(control["id"], index): {
            "status": "justified" if index % 2 else "disabled", "reason": "Recorded decision for this check"}
            for control in original["controls"] for index in range(1, len(control["checks"]) + 1)}
        result = apply_review_config(original, self.policy(checks=checks))
        self.assertEqual({entry["check_id"] for control in result["controls"] for entry in control["check_dispositions"]}, set(checks))
        self.assertEqual(result["review_policy"]["counts"]["active_checks"], 0)
        self.assertEqual(result["review_policy"]["counts"]["active_controls"], 0)
        self.assertEqual(result["review_policy"]["counts"]["justified_checks"], 66)
        self.assertEqual(result["review_policy"]["counts"]["disabled_checks"], 66)
        self.assertEqual(result["review_policy"]["counts"]["excluded_controls"], 66)
        self.assertEqual(result["review_policy"]["counts"]["mixed_excluded_controls"], 66)
        self.assertEqual(result["findings"], original["findings"])

    def test_mapping_distinguishes_exempt_evidence_from_absence_of_pattern(self):
        original = scan(self.root)
        target = next(control for control in original["controls"] if "AI003" in control["automated_rule_ids"])
        for status in ("justified", "disabled"):
            result = apply_review_config(original, self.policy(rules={"AI003": {"status": status, "reason": "Reviewed"}}))
            control = next(control for control in result["controls"] if control["id"] == target["id"])
            self.assertEqual(control["status"], "findings_" + status)
            self.assertEqual(control["static_status"], "findings_detected")
            self.assertEqual(control["finding_ids"], [])
            self.assertEqual(control[status + "_finding_ids"], target["finding_ids"])
        second = copy.deepcopy(original["findings"][0])
        second.update(id="another-finding", finding_id="another-finding", rule_id="AI002")
        original["findings"].append(second)
        target["automated_rule_ids"].append("AI002")
        result = apply_review_config(original, self.policy(rules={"AI003": {"status": "justified", "reason": "Reviewed"}, "AI002": {"status": "disabled"}}))
        control = next(control for control in result["controls"] if control["id"] == target["id"])
        self.assertEqual(control["status"], "findings_exempted")

    def test_justified_reason_is_redacted_everywhere_but_full_reason_affects_digest(self):
        first_secret = "sk-" + "a" * 30
        second_secret = "sk-" + "b" * 30
        results = []
        for secret in (first_secret, second_secret):
            reason = "Reviewed with credential " + secret
            policy = self.policy(rules={"AI003": {"status": "justified", "reason": reason}},
                                 controls={"GOV-01": {"status": "justified", "reason": reason}},
                                 checks={"GOV-02:1": {"status": "justified", "reason": reason}})
            report = apply_review_config(scan(self.root), policy)
            serialized = json.dumps(report)
            self.assertNotIn(secret, serialized)
            self.assertIn("[REDACTED TOKEN]", serialized)
            self.assertEqual(policy["rules"]["AI003"]["reason"], reason)
            results.append(report)
        self.assertNotEqual(results[0]["review_policy"]["sha256"], results[1]["review_policy"]["sha256"])
        self.assertNotEqual(results[0]["scan_id"], results[1]["scan_id"])
        self.assertEqual(results[0]["review_policy"]["entries"], results[1]["review_policy"]["entries"])

    def test_canonical_order_whitespace_and_paths_do_not_change_semantic_identity(self):
        value = {"schema_version": "1.0", "rules": {"AI003": {"status": "justified", "reason": "Reviewed"}, "AI001": {"status": "disabled"}}}
        first = self.config(value)
        second = self.base / "another.json"
        second.write_text(json.dumps(value, sort_keys=True, indent=4), encoding="utf-8")
        original = scan(self.root)
        a = apply_review_config(original, load_review_config(first))
        b = apply_review_config(original, load_review_config(second))
        self.assertEqual(a, b)
        self.assertEqual(apply_review_config(a, load_review_config(first)), a)
        self.assertEqual(a, apply_review_config(original, load_review_config(first)))
        with self.assertRaisesRegex(ValueError, "original static report"):
            apply_review_config(a, self.policy())

    def test_policy_never_waives_coverage_or_operational_failures(self):
        (self.root / "broken.py").write_text("def broken(\n", encoding="utf-8")
        original = scan(self.root)
        original["judge"] = {"enabled": True, "error": "unavailable"}
        original["analyst"] = {"enabled": True, "status": "error"}
        original["execution"] = {"exit_code": 2, "finding_gate_triggered": True}
        result = apply_review_config(original, self.policy(rules={rule["id"]: {"status": "disabled"} for rule in RULES},
                                                          controls={control["id"]: {"status": "disabled"} for control in original["controls"]}))
        self.assertFalse(result["summary"]["scan_complete_within_selected_scope"])
        self.assertEqual(result["summary"]["coverage_gaps"], original["summary"]["coverage_gaps"])
        self.assertGreater(result["summary"]["coverage_gaps"], 0)
        self.assertEqual(result["coverage"]["errors"], original["coverage"]["errors"])
        self.assertEqual(result["judge"], original["judge"])
        self.assertEqual(result["analyst"], original["analyst"])
        self.assertEqual(result["execution"]["exit_code"], 2)


if __name__ == "__main__":
    unittest.main()
