"""Receipt privacy across raw command output and JSON-escaped Windows paths."""
import importlib.util
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "quickstart_validation", Path(__file__).resolve().parents[1] / "scripts/validate_quickstart.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class QuickstartReceiptTests(unittest.TestCase):
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
