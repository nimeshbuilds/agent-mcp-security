"""The offline HTML report treats every repository/model string as untrusted."""
import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit

from ai_security_scan.analyst import unreviewed_analyst
from ai_security_scan.assessment import build_assessment
from ai_security_scan.report_html import html_report
from ai_security_scan.scanner import scan


class Document(HTMLParser):
    def __init__(self, content):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.sections = {}
        self.section_order = []
        self.section_stack = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "section":
            identifier = attrs.get("id")
            self.section_stack.append(identifier)
            if identifier:
                self.section_order.append(identifier)
                self.sections[identifier] = []

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        self.text.append(data)
        for identifier in self.section_stack:
            if identifier:
                self.sections[identifier].append(data)

    def handle_endtag(self, tag):
        if tag == "section" and self.section_stack:
            self.section_stack.pop()


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        (root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        self.report = scan(root)
        self.report["assessment"] = build_assessment(self.report)

    def test_executive_summary_and_all_evidence_are_visible_without_model(self):
        page = html_report(self.report)
        doc = Document(page)
        text = " ".join(doc.text)
        self.assertIn("Invarune", text)
        self.assertIn("NimeshBuild", text)
        self.assertIn(self.report["assessment"]["posture"]["title"], text)
        self.assertIn(self.report["scan_id"], text)
        for finding in self.report["findings"]:
            self.assertIn(finding["rule_id"], text)
            self.assertIn(finding["path"], text)
            self.assertIn(finding["evidence"], text)
        for control in self.report["controls"]:
            self.assertIn(control["id"], text)
        for group in self.report["assessment"]["finding_groups"]:
            self.assertIn(group["immediate_action"], text)
            for layer in group["defense_layers"]:
                self.assertIn(layer["how_it_helps"], text)
                self.assertIn(layer["residual_limit"], text)
                for source in layer["sources"]:
                    self.assertIn(source["url"], [attrs.get("href") for _, attrs in doc.tags])

    def test_html_is_standalone_and_uses_restrictive_content_security_policy(self):
        page = html_report(self.report)
        doc = Document(page)
        self.assertNotIn("script", [tag for tag, _ in doc.tags])
        policies = [attrs.get("content", "") for tag, attrs in doc.tags
                    if tag == "meta" and attrs.get("http-equiv", "").lower() == "content-security-policy"]
        self.assertEqual(len(policies), 1)
        self.assertIn("default-src 'none'", policies[0])
        # Absence of a script directive inherits the already-checked default.
        script_directives = [part.strip() for part in policies[0].split(";") if part.strip().startswith("script-src")]
        self.assertTrue(all(part.endswith("'none'") for part in script_directives))
        self.assertIn("base-uri 'none'", policies[0])
        self.assertIn("form-action 'none'", policies[0])
        for tag, attrs in doc.tags:
            self.assertFalse(any(name.lower().startswith("on") for name in attrs))
            self.assertNotIn(tag, {"iframe", "object", "embed", "base", "form"})
            for name in ("src", "srcset", "poster", "data", "action"):
                if attrs.get(name):
                    self.assertFalse(attrs[name].startswith(("http:", "https:", "//")), (tag, name, attrs[name]))
            if tag == "link":
                self.assertFalse(attrs.get("href", "").startswith(("http:", "https:", "//")))
        self.assertNotIn("@import", page.lower())
        self.assertNotIn("url(https:", page.lower())
        self.assertNotIn("url(http:", page.lower())

    def test_finding_navigation_has_unique_existing_anchors(self):
        doc = Document(html_report(self.report))
        identifiers = [attrs["id"] for _, attrs in doc.tags if "id" in attrs]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        links = [attrs["href"][1:] for _, attrs in doc.tags if attrs.get("href", "").startswith("#")]
        self.assertTrue(links)
        self.assertTrue(set(links) <= set(identifiers), set(links) - set(identifiers))

    def test_hostile_repository_baseline_and_model_text_never_becomes_markup(self):
        payload = '<img src="https://attacker.test/leak" onerror="alert(1)"><script>alert(2)</script>'
        report = copy.deepcopy(self.report)
        finding = report["findings"][0]
        for key in ("path", "title", "description", "evidence", "remediation"):
            finding[key] = payload
        finding.update(status="suppressed", suppression_reason=payload)
        report["summary"]["open_findings"] = 0
        report["summary"]["suppressed_findings"] = 1
        report["coverage"]["errors"].append({"path": payload, "error": payload, "kind": "test"})
        report["controls"][0]["title"] = payload
        report["controls"][0]["checks"][0] = payload
        report["judge"] = {"enabled": True, "status": "completed", "advisory_only": True,
                           "assessments": [{"finding_id": finding["id"], "verdict": "uncertain", "reason": payload}],
                           "additional_concerns": [payload]}
        report["analyst"] = unreviewed_analyst(report, payload, max_calls=0)
        report["assessment"] = build_assessment(report)
        page = html_report(report)
        self.assertNotIn(payload, page)
        doc = Document(page)
        self.assertNotIn("script", [tag for tag, _ in doc.tags])
        self.assertNotIn("img", [tag for tag, _ in doc.tags])
        self.assertIn(payload, " ".join(doc.text))
        for _, attrs in doc.tags:
            self.assertFalse(any(name.startswith("on") for name in attrs))

    def test_external_reference_links_reject_unsafe_or_ambiguous_urls(self):
        unsafe = ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "file:///etc/passwd",
                  "//attacker.test/path", "http://attacker.test", "https://user:pass@attacker.test/path",
                  "https://", "https://good.test\n.attacker.test/path", "https://good.test\x00.attacker.test/path",
                  "https://good.test/%0aheader", "https://good.test\\@attacker.test/path",
                  "https://good.test:70000/path", "https://good.test:bad/path", "https://[broken]/path",
                  "https://999.999.999.999/path", "https://bad_host.test/path", "https://bad\udcff.test/path"]
        report = copy.deepcopy(self.report)
        safe = ["https://docs.example.test/control?q=one&scope=two#anchor", "https://[2001:db8::1]:8443/control",
                "https://127.0.0.1:8443/control"]
        report["findings"][0]["references"] = unsafe + safe
        report["controls"][0]["sources"] = unsafe + safe
        doc = Document(html_report(report))
        hrefs = [attrs["href"] for _, attrs in doc.tags if "href" in attrs]
        self.assertTrue(set(safe) <= set(hrefs))
        self.assertTrue(set(unsafe).isdisjoint(hrefs))
        for href in hrefs:
            if href.startswith("#"):
                continue
            split = urlsplit(href)
            self.assertEqual(split.scheme, "https")
            self.assertTrue(split.netloc)
            self.assertIsNone(split.username)
            self.assertFalse(any(ord(char) < 32 for char in href))

    def test_model_claims_are_advisory_and_do_not_change_static_summary(self):
        before = copy.deepcopy(self.report)
        self.report["judge"] = {"enabled": True, "status": "error", "advisory_only": True,
                                "error": "Advisory gateway unavailable"}
        self.report["analyst"] = unreviewed_analyst(self.report, "Requested review failed", max_calls=12)
        self.report["execution"] = {"failure_threshold": "high", "exit_code": 2, "finding_gate_triggered": True}
        page = html_report(self.report)
        doc = Document(page)
        text = " ".join(doc.text).lower()
        self.assertIn("advisory", text)
        self.assertIn("error", text)
        self.assertIn(before["assessment"]["posture"]["title"].lower(), text)
        summary = " ".join(doc.sections["summary"]).lower()
        self.assertIn("optional review", summary)
        self.assertIn("incomplete", summary)
        self.assertIn("error", summary)
        self.assertIn("static findings are preserved", summary)
        self.assertLess(doc.section_order.index("summary"), doc.section_order.index("actions"))
        for field in ("assessment", "scan_id", "findings", "controls", "summary"):
            self.assertEqual(self.report[field], before[field])

    def test_executive_summary_exposes_disabled_completed_and_incomplete_review(self):
        disabled = Document(html_report(self.report))
        summary = " ".join(disabled.sections["summary"]).lower()
        self.assertIn("optional review", summary)
        self.assertIn("disabled", summary)
        self.assertIn("no llm request", summary)
        for status, omitted in (("completed", 0), ("incomplete", 132)):
            report = copy.deepcopy(self.report)
            report["judge"] = {"enabled": True, "status": "completed", "omitted_open_findings": 0}
            report["analyst"] = {"enabled": True, "status": status, "control_assessments": [],
                                 "coverage": {"total_controls": 66, "reviewed_controls": 66 if not omitted else 0,
                                              "omitted_checks": omitted}}
            with self.subTest(status=status):
                doc = Document(html_report(report))
                summary = " ".join(doc.sections["summary"]).lower()
                self.assertIn("optional review", summary)
                self.assertIn("control analyst " + status, summary)
                self.assertIn("unanswered checks", summary)
                self.assertIn(str(omitted), summary)
                self.assertIn("review completion does not mean the checks passed", summary)
                self.assertEqual("static findings are preserved" in summary, bool(omitted))
                self.assertLess(doc.section_order.index("summary"), doc.section_order.index("actions"))
                self.assertEqual(report["assessment"], self.report["assessment"])

    def test_surrogates_are_printable_and_renderer_does_not_mutate_report(self):
        self.report["findings"][0]["path"] = "odd\udcff.py"
        self.report["findings"][0]["evidence"] = "model text \ud800"
        self.report["assessment"] = build_assessment(self.report)
        original = copy.deepcopy(self.report)
        page = html_report(self.report)
        page.encode("utf-8", "strict")
        self.assertIn("\\udcff", page)
        self.assertIn("\\ud800", page)
        self.assertEqual(self.report, original)
        self.assertEqual(page, html_report(json.loads(json.dumps(original))))


if __name__ == "__main__":
    unittest.main()
