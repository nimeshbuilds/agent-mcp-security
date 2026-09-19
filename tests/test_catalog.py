import json
from pathlib import Path
import unittest

from ai_security_scan.rules import RULES

DATA = Path(__file__).resolve().parents[1] / "ai_security_scan" / "data"


class CatalogIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controls = json.loads((DATA / "controls.json").read_text())
        cls.sources = json.loads((DATA / "sources.json").read_text())

    def test_unique_ids_and_complete_source_provenance(self):
        self.assertEqual(len({c["id"] for c in self.controls}), len(self.controls))
        self.assertEqual(len({s["id"] for s in self.sources}), len(self.sources))
        self.assertEqual(len({s["url"] for s in self.sources}), len(self.sources))
        for s in self.sources:
            for field in ("id", "organization", "title", "url", "kind", "accessed", "scope", "limitations"):
                self.assertTrue(isinstance(s.get(field), str) and s[field].strip(), (s["id"], field))
            self.assertTrue(s["url"].startswith("https://"))

    def test_every_control_source_and_alignment_resolves(self):
        by_id = {s["id"]: s for s in self.sources}
        for c in self.controls:
            self.assertEqual([by_id[s]["url"] for s in c["source_ids"]], c["sources"])
            self.assertTrue(set(c.get("alignment_source_ids", [])) <= set(by_id))
            self.assertTrue(c["checks"])
            self.assertIn(c["validation"], {"static", "hybrid", "dynamic", "manual"})

    def test_rule_mapping_and_technical_references_are_complete(self):
        known_rules = {r["id"] for r in RULES}
        mapped = {r for c in self.controls for r in c["automated_rule_ids"]}
        self.assertEqual(mapped, known_rules)
        urls = {s["url"] for s in self.sources}
        for r in RULES:
            self.assertTrue(set(r["references"]) <= urls, r["id"])

    def test_no_automation_claim_for_added_manual_runtime_controls(self):
        for c in self.controls:
            if c["id"] in {"GOV-06", "AUTH-09", "SUP-06", "TEST-09"}:
                self.assertEqual(c["automated_rule_ids"], [])
                self.assertIn(c["validation"], {"manual", "dynamic"})


if __name__ == "__main__":
    unittest.main()
