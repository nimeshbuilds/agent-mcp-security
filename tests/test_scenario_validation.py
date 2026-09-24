"""Documentation/manifest contracts and scripted gateway boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


validator = module('scenario_validator', 'scripts/validate_scenarios.py')
gateway = module('scenario_fixture_gateway', 'examples/scenarios/local_gateway.py')


class ScenarioDocumentationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = validator.load_manifest(ROOT / validator.MANIFEST)
        self.blocks = validator.documentation_blocks(self.manifest)
        self.guide = '\n'.join('<!-- invscan-scenario:' + key + ' -->\n```sh\n' + content + '\n```' for key, content in self.blocks.items())

    def test_manifest_and_tagged_fences_are_an_exact_contract(self):
        self.assertEqual(len(self.manifest['scenarios']), 10)
        self.assertEqual(validator.verify_documentation(self.manifest, self.guide), 11)
        for changed in (self.guide.replace('--summary-json', '--quiet', 1), self.guide.replace('<!-- invscan-scenario:01 -->', '<!-- invscan-scenario:99 -->'), self.guide + '\n' + self.guide):
            with self.subTest(changed=changed[:30]), self.assertRaises(RuntimeError):
                validator.verify_documentation(self.manifest, changed)

    def test_missing_feature_or_guide_flag_is_rejected(self):
        guide = self.guide + '\n' + ' '.join(self.manifest['feature_scenarios'])
        result = validator.verify_feature_map(self.manifest, (ROOT / 'ai_security_scan/cli.py').read_text(), guide)
        self.assertEqual(result, {'option_spellings': 65, 'positional_target': True})
        changed = copy.deepcopy(self.manifest)
        del changed['feature_scenarios']['--review-report']
        with self.assertRaises(RuntimeError):
            validator.verify_feature_map(changed, (ROOT / 'ai_security_scan/cli.py').read_text(), guide)
        with self.assertRaises(RuntimeError):
            validator.verify_feature_map(self.manifest, (ROOT / 'ai_security_scan/cli.py').read_text(), guide.replace('--judge-cli-home', 'missing'))

    def test_longer_flags_cannot_stand_in_for_missing_exact_spelling(self):
        guide = ' '.join(self.manifest['feature_scenarios'])
        guide = guide.replace('--image ', '')
        self.assertIn('--image-archive', guide)
        with self.assertRaises(RuntimeError):
            validator.verify_feature_map(self.manifest, (ROOT / 'ai_security_scan/cli.py').read_text(), guide)

    def test_documented_commands_have_no_host_paths_or_shell_variables(self):
        for block in self.blocks.values():
            self.assertNotIn('{repo}', block)
            self.assertNotIn('{work}', block)
            self.assertNotIn('/Users/', block)
            self.assertNotIn('$INVSCAN', block)
        self.assertIn('invarune --version', self.blocks['01'])
        self.assertIn('reviewed.pdf', self.blocks['08'])
        self.assertIn('Expected exit 2', self.blocks['04'])

    def test_assertions_are_not_truthiness_checks(self):
        validator.assert_values({'ok': False, 'count': 0, 'score': None}, {'ok': False, 'count': 0, 'score': None}, 'test')
        for value in ({'ok': 0}, {'ok': True}, {}):
            with self.assertRaises(RuntimeError):
                validator.assert_values(value, {'ok': False}, 'test')


class ScenarioGatewayTests(unittest.TestCase):
    def test_triage_accepts_cli_ids_and_protocol_fixture_ids(self):
        for finding in ({'id': 'F1'}, {'finding_id': 'F1'}):
            response = gateway.answer({'findings': [finding]})
            self.assertEqual(response['assessments'][0]['finding_id'], 'F1')
            self.assertEqual(response['assessments'][0]['verdict'], 'needs_review')
            self.assertIn('SCRIPTED', response['assessments'][0]['reason'])

    def test_scripted_request_stops_when_controller_disallows_it(self):
        payload = {'controls': [{'id': 'EXEC-05', 'checks': ['one', 'two']}], 'investigation': {'requests_allowed': True, 'inventory': [{'path': 'delivery.py', 'file_id': 'file-1', 'line_count': 41}]}}
        response = gateway.answer(payload, investigate=True)
        self.assertEqual(response['evidence_requests'][0]['file_id'], 'file-1')
        payload['investigation']['requests_allowed'] = False
        response = gateway.answer(payload, investigate=True)
        self.assertEqual(response['evidence_requests'], [])
        self.assertEqual([item['status'] for item in response['control_assessments'][0]['check_assessments']], ['insufficient_evidence'] * 2)

    def test_all_six_response_envelopes_are_explicit(self):
        self.assertEqual(len(gateway.PROVIDERS), 6)
        for provider in gateway.PROVIDERS:
            self.assertIsInstance(gateway.envelope(provider, {'control_assessments': []}), dict)


if __name__ == '__main__':
    unittest.main()
