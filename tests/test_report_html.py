"""The offline HTML report treats every repository/model string as untrusted."""
import base64
import copy
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit

from ai_security_scan.analyst import unreviewed_analyst
from ai_security_scan.assessment import build_assessment
from ai_security_scan.report_html import _REVIEW_SCRIPT, html_report
from ai_security_scan.scanner import scan


class Document(HTMLParser):
    def __init__(self, content):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.sections = {}
        self.section_order = []
        self.section_stack = []
        self.scripts = []
        self.current_script = None
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "script":
            self.current_script = {"attrs": attrs, "text": ""}
            self.scripts.append(self.current_script)
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
        if self.current_script is not None:
            self.current_script["text"] += data
        for identifier in self.section_stack:
            if identifier:
                self.sections[identifier].append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            self.current_script = None
        if tag == "section" and self.section_stack:
            self.section_stack.pop()


def assert_trusted_script_boundary(test, page):
    doc = Document(page)
    test.assertEqual(len(doc.scripts), 2)
    capsules = [item for item in doc.scripts if item["attrs"].get("id") == "invarune-review"]
    test.assertEqual(len(capsules), 1)
    test.assertEqual(capsules[0]["attrs"], {"type": "application/json", "id": "invarune-review"})
    test.assertNotIn("<", capsules[0]["text"])
    test.assertEqual(json.loads(capsules[0]["text"])["kind"], "invarune_review")
    scripts = [item for item in doc.scripts if item["attrs"].get("id") == "invarune-review-editor"]
    test.assertEqual(len(scripts), 1)
    test.assertEqual(scripts[0]["attrs"], {"id": "invarune-review-editor"})
    test.assertEqual(scripts[0]["text"], _REVIEW_SCRIPT)
    return doc


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        (root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        self.report = scan(root)
        self.report["assessment"] = build_assessment(self.report)

    def test_compact_priority_table_has_locations_counts_and_valid_internal_targets(self):
        doc = Document(html_report(self.report))
        text = ' '.join(doc.sections['summary'])
        for term in ('Deterministic layer', 'Selected scope completed', 'Optional model layer', 'Disabled - no model review requested',
                     'Priority / count', 'Observed locations', 'agent.py:2', '1 open'):
            self.assertIn(term, text)
        ids = {attrs['id'] for _, attrs in doc.tags if attrs.get('id')}
        links = [attrs['href'][1:] for tag, attrs in doc.tags if tag == 'a' and attrs.get('href', '').startswith('#')]
        self.assertTrue(all(target in ids for target in links))
        self.assertTrue(any(tag == 'table' and attrs.get('class') == 'priority-table' for tag, attrs in doc.tags))

    def test_optimization_receipt_is_escaped_and_keeps_actual_bytes_separate_from_tokens(self):
        report = copy.deepcopy(self.report)
        payload = '<img src=x onerror=alert(1)>'
        report['judge'] = {'enabled': True, 'status': 'completed', 'token_optimization': {
            'requested': 'headroom', 'engine': 'builtin_compact', 'status': 'fallback', 'fallback_reason': payload,
            'payload_bytes_before': 1000, 'payload_bytes_after': 750, 'bytes_saved': 250, 'token_savings_measured': False}}
        page = html_report(report)
        doc = assert_trusted_script_boundary(self, page)
        self.assertNotIn(payload, page)
        text = ' '.join(doc.sections['advisory'])
        for term in ('Optional request payload optimization', 'headroom / builtin_compact', '1000 → 750', '250 bytes saved',
                     'Token and cost savings were not measured', payload):
            self.assertIn(term, text)
        self.assertNotIn('Optional request payload optimization', ' '.join(Document(html_report(self.report)).text))

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
        assert_trusted_script_boundary(self, page)
        policies = [attrs.get("content", "") for tag, attrs in doc.tags
                    if tag == "meta" and attrs.get("http-equiv", "").lower() == "content-security-policy"]
        self.assertEqual(len(policies), 1)
        self.assertIn("default-src 'none'", policies[0])
        digest = base64.b64encode(hashlib.sha256(_REVIEW_SCRIPT.encode()).digest()).decode("ascii")
        script_directives = [part.strip() for part in policies[0].split(";") if part.strip().startswith("script-src ")]
        self.assertEqual(script_directives, ["script-src 'sha256-" + digest + "'"])
        self.assertIn("script-src-attr 'none'", policies[0])
        self.assertIn("connect-src 'none'", policies[0])
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
        assert_trusted_script_boundary(self, page)
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
