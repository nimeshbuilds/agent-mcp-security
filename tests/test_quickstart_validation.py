"""Receipt privacy across raw command output and JSON-escaped Windows paths."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "quickstart_validation", Path(__file__).resolve().parents[1] / "scripts/validate_quickstart.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class QuickstartReceiptTests(unittest.TestCase):
    def optimizer_fixture(self):
        evidence = {"evidence_id": "E001", "text": "literal source with  spaces\nnext line\n", "path": "agent.py"}
        payloads = [{"findings": []}, {"controls": [{"id": "GOV-01"}], "evidence": [evidence]}]
        requests = []
        for payload in payloads:
            original = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
            requests.append({"token_optimization": {"requested": "headroom", "engine": "headroom", "evidence_preserved": True,
                "original_payload_sha256": hashlib.sha256(original).hexdigest(), "payload_bytes_before": len(original)},
                "payload_sha256": hashlib.sha256(canonical).hexdigest()})
        return {"judge": requests[0], "analyst": {"requests": requests[1:], "evidence": [evidence]}}, [{"payload": value} for value in payloads]

    def test_optimizer_receipts_bind_all_captured_payloads_and_source_strings(self):
        report, captured = self.optimizer_fixture()
        result = validator.assert_optimizer_receipts(report, captured, "headroom")
        self.assertEqual(result["requests_verified"], 2)
        self.assertTrue(result["captured_payloads_equal_original_inputs"])
        self.assertTrue(result["source_evidence_exactly_preserved"])

    def test_optimizer_receipts_reject_fallback_missing_calls_and_changed_evidence(self):
        report, captured = self.optimizer_fixture()
        cases = []
        changed = copy.deepcopy(report)
        changed["judge"]["token_optimization"]["engine"] = "builtin_compact"
        cases.append((changed, captured))
        cases.append((report, captured[:1]))
        changed = copy.deepcopy(captured)
        changed[1]["payload"]["evidence"][0]["text"] = "changed evidence"
        cases.append((report, changed))
        changed = copy.deepcopy(report)
        changed["analyst"]["evidence"][0]["text"] = "different published evidence"
        cases.append((changed, captured))
        changed = copy.deepcopy(report)
        changed["analyst"]["requests"][0]["payload_sha256"] = "0" * 64
        cases.append((changed, captured))
        for candidate, payloads in cases:
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                validator.assert_optimizer_receipts(candidate, payloads, "headroom")

    def test_windows_raw_forward_slash_and_json_paths_are_sanitized(self):
        prefix = r"C:\Users\fixture\AppData\Local\Temp\invarune\venv"
        replacements = [(prefix, "<VENV>")]
        path = prefix + r"\Scripts\python.exe"
        self.assertEqual(validator.replace_paths(path, replacements), r"<VENV>\Scripts\python.exe")
        self.assertEqual(validator.replace_paths(path.replace("\\", "/"), replacements), "<VENV>/Scripts/python.exe")
        cleaned = validator.replace_paths(json.dumps({"executable": path}), replacements)
        self.assertEqual(json.loads(cleaned), {"executable": r"<VENV>\Scripts\python.exe"})
        self.assertNotIn("fixture", cleaned)

    def test_specific_posix_location_precedes_home_and_preserves_json(self):
        replacements = [("/Users/fixture/project/.venv", "<VENV>"),
                        ("/Users/fixture/project", "<SOURCE>"), ("/Users/fixture", "<USER_HOME>")]
        payload = {"executable": "/Users/fixture/project/.venv/bin/python", "source": "/Users/fixture/project/scan.py",
                   "cache": "/Users/fixture/.cache/pip", "public_reference": "https://example.com/docs"}
        result = json.loads(validator.replace_paths(json.dumps(payload), replacements))
        self.assertEqual(result, {"executable": "<VENV>/bin/python", "source": "<SOURCE>/scan.py",
                                  "cache": "<USER_HOME>/.cache/pip", "public_reference": "https://example.com/docs"})


if __name__ == "__main__":
    unittest.main()
