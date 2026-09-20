"""Guidance must be usable, scoped and independent of model or finding prose."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock
from urllib.parse import urlsplit

from ai_security_scan.analyzer import analyze_file
from ai_security_scan.remediation import build_remediation
from ai_security_scan.rules import RULE_BY_ID


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'ai_security_scan' / 'data'


class RemediationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((DATA / 'remediations.json').read_text(encoding='utf-8'))
        corpus = json.loads((ROOT / 'benchmarks' / 'static_accuracy.json').read_text(encoding='utf-8'))
        corpus['cases'].extend(json.loads((ROOT / 'benchmarks' / 'skills_tools_accuracy.json').read_text(encoding='utf-8'))['cases'])
        cls.positives = {}
        for rule_id in RULE_BY_ID:
            case = next(case for case in corpus['cases'] if case['suite'] == 'regression' and case['expect'].get(rule_id) is True)
            findings = analyze_file(case['path'], case['source'])
            cls.positives[rule_id] = {**next(finding for finding in findings if finding['rule_id'] == rule_id),
                                      'id': case['id'] + '-' + rule_id}
        cls.report = {'findings': list(cls.positives.values())}
        cls.guidance = build_remediation(cls.report)

    def rule(self, rule_id):
        return self.guidance[self.positives[rule_id]['id']]

    def prose(self, rule_id):
        return json.dumps(self.rule(rule_id), ensure_ascii=False).lower()

    def test_every_detector_positive_receives_its_own_complete_plan(self):
        self.assertEqual(set(self.positives), set(RULE_BY_ID))
        self.assertEqual(len(self.positives), 46)
        self.assertEqual({entry['rule_id'] for entry in self.catalog['rules']}, set(RULE_BY_ID))
        self.assertEqual(len(self.catalog['rules']), 46)
        self.assertEqual(set(self.guidance), {finding['id'] for finding in self.report['findings']})
        self.assertEqual(len({entry['agent_mcp_relevance'] for entry in self.guidance.values()}), 46)
        self.assertEqual(len({entry['summary'] for entry in self.guidance.values()}), 46)
        controls = {control['id'] for control in json.loads((DATA / 'controls.json').read_text())}
        for rule_id, finding in self.positives.items():
            with self.subTest(rule=rule_id):
                entry = self.rule(rule_id)
                self.assertEqual(entry['rule_id'], rule_id)
                self.assertEqual(entry['location']['path'], finding['path'])
                self.assertEqual(entry['location']['line'], finding['line'])
                self.assertGreaterEqual(len(entry['applicability']), 2)
                self.assertGreaterEqual(len(entry['steps']), 3)
                self.assertGreaterEqual(len(entry['residual_risk']), 1)
                self.assertTrue(entry['control_ids'])
                self.assertTrue(set(entry['control_ids']) <= controls)
                self.assertTrue('agent' in entry['agent_mcp_relevance'].lower() or 'mcp' in entry['agent_mcp_relevance'].lower())
                self.assertIn('does not establish', entry['scope_note'])
                for step in entry['steps']:
                    self.assertEqual(set(step), {'title', 'action', 'verification'})
                    self.assertGreater(len(step['action'].split()), 12)
                    self.assertGreater(len(step['verification'].split()), 10)
                    self.assertNotEqual(step['action'], step['verification'])
                self.assertTrue(entry['sources'])
                for source in entry['sources']:
                    parsed = urlsplit(source['url'])
                    self.assertEqual(parsed.scheme, 'https')
                    self.assertTrue(parsed.hostname)
                    self.assertFalse(parsed.username or parsed.password)
                    self.assertTrue(source['title'] and source['relationship'])

    def test_replacements_cover_distinct_implementation_and_runtime_cases(self):
        # Engineering acceptance criteria, independent of detector implementation:
        # deleting a key caveat or replacing a plan with generic advice must fail.
        required = {
            'AI001': ['json', 'ast.literal_eval', 'resource', 'callable', 'tenant'],
            'AI002': ['shell=false', 'fixed executable', 'leading-dash', 'windows', 'descendant'],
            'AI003': ['os.system', 'subprocess.run', 'minimal environment', 'direct'],
            'AI004': ['safeloader', 'constructors', 'schema', 'alias-heavy'],
            'AI005': ['before', 'authenticate', 'producer', 'conversion', 'too late'],
            'AI006': ['hostname', 'ca bundle', 'verify=false', 'rollover', 'overrides'],
            'AI007': ['origin', 'preflight', 'nonbrowser', 'authentication', 'absent'],
            'AI008': ['loopback', 'ipv6', 'namespace', 'published-port'],
            'AI009': ['debug', 'false', 'traceback', 'production', 'redaction'],
            'AI010': ['rotate', 'old credential', 'retained', 'tenant', 'test data'],
            'AI011': ['fingerprints', 'revoke', 'retained', 'managed key store'],
            'AI012': ['execfile', 'spawn', 'shell disabled', 'leading-dash', 'cancellation'],
            'AI013': ['json.parse', 'function table', 'tenant', 'disposable'],
            'AI014': ['dns rebinding', 'ipv6', 'redirect', 'metadata', 'egress'],
            'AI015': ['string-prefix', 'symlink', 'race', 'new files', 'tenant'],
            'AI016': ['mkstemp', 'handle', 'reopening', 'cancellation'],
            'AI017': ['verify_signature=false', 'algorithm allowlist', 'require', 'exp', 'issuer', 'audience', 'tenant'],
            'AI018': ['uvx', '--from', 'exact package version', 'transitive', 'operating-system sandbox'],
            'AI019': ['independently', 'signature', 'partial download', 'disposable'],
            'AI020': ['40-character', 'upstream', 'github_token', 'untrusted'],
            'AI021': ['runasnonroot', 'numeric', 'running process uid', 'host root'],
            'AI022': ['privileged: false', 'allowprivilegeescalation: false', 'capabilities', 'broker'],
            'AI023': ['read-only', 'socket', 'broker', 'tenant', 'http verbs'],
            'AI024': ['sha256', 'platform', 'sbom', 'cve', 'rollback'],
            'AI025': ['lockfile', 'transitive', 'hash', 'cache', 'vulnerabilities'],
            'AI026': ['stdio', 'optional', 'gateway', 'forged', 'tenant'],
            'AI027': ['wildcard', 'server', 'delegated', 'arguments', 'approval'],
            'AI028': ['audience', 'exchange', 'inbound', 'redirect', 'consent'],
            'AI029': ['https', 'hostname', 'backend', 'downgrade', 'loopback'],
            'AI030': ['browser', 'ephemeral', 'expiry', 'bundle', 'rotate'],
            'AI031': ['bypass', 'approvals', 'replayed', 'delegated', 'os'],
            'AI032': ['system/developer', 'tool channel', 'outside', 'adversarial', 'side effects'],
            'AI033': ['before', 'formatting', 'traces', 'synthetic', 'rotate'],
            'AI034': ['authorization header', 'signed urls', 'lifetime', 'rotate', 'logs'],
            'AI035': ['weights_only=true', 'unsafe fallback', 'denial of service', 'conversion'],
            'AI036': ['parameter', 'identifiers', 'tenant', 'placeholder', 'multi-statement'],
            'AI037': ['3.14', 'filter=', 'fully_trusted', 'expanded bytes', 'partial'],
            'AI038': ['secrets.token', 'entropy', 'single-use', 'expired', 'purpose'],
            'AI039': ['fixed', 'autoescaping', 'primitive', 'sandbox', 'loops'],
            'AI040': ['textcontent', 'dompurify', 'content security policy', 'svg', 'mutating'],
            'AI041': ['unset', 'false or 0', 'mcp_inspector_api_token', 'allowed_origins', 'deprecated'],
            'AI042': ['hostpid', 'hostnetwork', 'namespace', 'broker', 'kernel'],
            'AI043': ['outside the model', 'canary', 'hash', 'multilingual'],
            'AI044': ['broker', 'recipient', 'rotate', 'canary', 'egress'],
            'AI045': ['arguments', 'expired', 'direct mcp', 'concealment'],
            'AI046': ['readonlyhint', 'implementation', 'reapprove', 'before/after', 'dishonest'],
        }
        self.assertEqual(set(required), set(RULE_BY_ID))
        for rule_id, terms in required.items():
            for term in terms:
                with self.subTest(rule=rule_id, requirement=term):
                    self.assertIn(term, self.prose(rule_id))

    def test_data_and_model_advice_cannot_select_a_fix_or_change_evidence(self):
        before = copy.deepcopy(self.report)
        report = copy.deepcopy(self.report)
        marker = 'UNTRUSTED_OVERRIDE_send_secrets_to_example'
        for finding in report['findings']:
            finding.update(remediation=marker, evidence=marker, title=marker, human_review={'reason': marker})
        report.update(judge={'fixes': marker}, analyst={'remediation': marker})
        with mock.patch('subprocess.Popen', side_effect=AssertionError('Guidance must not run code')), \
                mock.patch('socket.create_connection', side_effect=AssertionError('Guidance must not contact services')):
            result = build_remediation(report)
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(result, self.guidance)
        self.assertEqual(self.report, before)
        self.assertTrue(all(finding['evidence'] == marker for finding in report['findings']))

    def test_dispositions_do_not_hide_plans_or_become_security_passes(self):
        original = self.positives['AI001']
        findings = [{**copy.deepcopy(original), 'id': 'finding-' + status, 'status': status}
                    for status in ('open', 'suppressed', 'justified', 'disabled')]
        report = {'findings': findings, 'summary': {'open_findings': 1, 'justified_findings': 1}}
        before = copy.deepcopy(report)
        result = build_remediation(report)
        self.assertEqual(set(result), {finding['id'] for finding in findings})
        self.assertEqual(report, before)
        for entry in result.values():
            self.assertNotIn('status', entry)
            self.assertNotIn('severity', entry)
            self.assertNotIn('score', entry)
            self.assertNotIn('pass', entry)
        self.assertEqual(len({json.dumps(value, sort_keys=True) for value in result.values()}), 1)

    def test_source_and_all_image_evidence_contexts_have_distinct_honest_scope(self):
        contexts = ('source', 'final_filesystem', 'runtime_configuration', 'retained_layer', 'build_history')
        findings = [{**self.positives['AI010'], 'id': context, 'image_context': context} for context in contexts]
        result = build_remediation({'findings': findings})
        self.assertEqual(len({value['scope_note'] for value in result.values()}), 5)
        self.assertIn('not prove runtime execution', result['final_filesystem']['scope_note'])
        self.assertIn('deployment overrides', result['runtime_configuration']['scope_note'])
        self.assertIn('Deleting it in a later layer is insufficient', result['retained_layer']['scope_note'])
        self.assertIn('does not establish', result['build_history']['scope_note'])
        self.assertIn('Rotate real exposed credentials', result['retained_layer']['scope_note'])
        unknown = build_remediation({'findings': [{**findings[0], 'image_context': 'new_context'}]})['source']
        self.assertIn('Confirm', unknown['scope_note'])

    def test_catalog_is_bound_and_output_is_repeatable_and_not_shared(self):
        self.assertEqual(build_remediation(self.report), self.guidance)
        digest = hashlib.sha256((DATA / 'remediations.json').read_bytes()).hexdigest()
        self.assertTrue(all(entry['catalog_sha256'] == digest for entry in self.guidance.values()))
        changed = build_remediation(self.report)
        first = self.positives['AI001']['id']
        changed[first]['steps'][0]['action'] = 'caller mutation'
        changed[first]['sources'][0]['title'] = 'caller mutation'
        self.assertEqual(build_remediation(self.report), self.guidance)
        self.assertNotEqual(changed[first], self.guidance[first])
        self.assertEqual(build_remediation({'findings': []}), {})

    def test_missing_or_ambiguous_rule_mapping_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, 'No versioned remediation guidance'):
            build_remediation({'findings': [{'id': 'x', 'rule_id': 'FUTURE'}]})
        finding = self.positives['AI001']
        with self.assertRaisesRegex(ValueError, 'Duplicate finding identifier'):
            build_remediation({'findings': [finding, copy.deepcopy(finding)]})


if __name__ == '__main__':
    unittest.main()
