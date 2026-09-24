"""Documentation/manifest contracts and scripted gateway boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


class WalkthroughContractTests(unittest.TestCase):
    def setUp(self):
        self.manifest = validator.load_manifest(ROOT / validator.MANIFEST)
        self.documents = {p.as_posix(): '# Guide\n' for p in
                          (validator.DOC, validator.SETUP_DOC, *validator.GUIDE_PAGES.values())}
        for identity, command in validator.documentation_steps(self.manifest).items():
            page = validator.GUIDE_PAGES[identity.split(':')[0]].as_posix()
            self.documents[page] += self.fence(identity, command)

    @staticmethod
    def fence(identity, command):
        return '\n<!-- invscan-step:' + identity + ' -->\n```sh\n' + command + '\n```\n'

    def test_individual_commands_are_complete_and_render_order_can_follow_the_task(self):
        self.assertEqual(validator.verify_walkthrough_documentation(self.manifest, self.documents), 59)
        page = validator.GUIDE_PAGES['01'].as_posix()
        command = self.fence('01:version', 'invscan --version')
        self.documents[page] = self.documents[page].replace(command, '') + command
        self.assertEqual(validator.verify_walkthrough_documentation(self.manifest, self.documents), 59)

    def test_missing_duplicate_unknown_and_changed_commands_fail(self):
        page = validator.GUIDE_PAGES['01'].as_posix()
        original = self.documents[page]
        changes = [original.replace(self.fence('01:version', 'invscan --version'), ''),
                   original + self.fence('01:version', 'invscan --version'),
                   original.replace('invscan-step:01:version', 'invscan-step:01:unknown'),
                   original.replace('invscan --version', 'invscan --quiet')]
        for changed in changes:
            with self.subTest(changed=changed[-80:]), self.assertRaises(RuntimeError):
                validator.verify_walkthrough_documentation(self.manifest, dict(self.documents, **{page: changed}))

    def test_commands_cannot_move_to_another_scenario_or_an_untracked_page(self):
        page = validator.GUIDE_PAGES['01'].as_posix()
        moved = dict(self.documents)
        command = self.fence('01:version', 'invscan --version')
        moved[page] = moved[page].replace(command, '')
        moved[validator.GUIDE_PAGES['02'].as_posix()] += command
        with self.assertRaisesRegex(RuntimeError, 'wrong guide'):
            validator.verify_walkthrough_documentation(self.manifest, moved)
        for changed in ({k: v for k, v in self.documents.items() if k != page},
                        dict(self.documents, **{'docs/scenarios/untracked.md': '# Extra'})):
            with self.assertRaisesRegex(RuntimeError, 'file set'):
                validator.verify_walkthrough_documentation(self.manifest, changed)

    def test_orphan_and_malformed_markers_are_not_silently_ignored(self):
        page = validator.GUIDE_PAGES['01'].as_posix()
        original = self.documents[page]
        variants = [original + '\n<!-- invscan-step:01:orphan -->\n',
                    original.replace('```sh', '```python', 1),
                    original.replace('invscan --version\n', 'invscan --version\ninvscan --quiet\n', 1),
                    original + '\n<!-- invscan-scenario:01 -->\n']
        for changed in variants:
            with self.subTest(changed=changed[-80:]), self.assertRaises(RuntimeError):
                validator.verify_walkthrough_documentation(self.manifest, dict(self.documents, **{page: changed}))

    def test_snapshot_binds_all_guides_and_rejects_changed_or_missing_files(self):
        hashes = validator.documentation_hashes(self.documents)
        self.assertEqual(len(hashes['files']), 12)
        self.assertEqual(hashes, validator.documentation_hashes(dict(reversed(list(self.documents.items())))))
        snapshot = {'files': [{'path': p, 'sha256': h} for p, h in hashes['files'].items()]}
        validator.verify_documentation_snapshot(hashes, snapshot)
        for changed in ({'files': snapshot['files'][1:]},
                        {'files': [dict(x, sha256='0' * 64) for x in snapshot['files']]}):
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                validator.verify_documentation_snapshot(hashes, changed)


class ScenarioGatewayTests(unittest.TestCase):
    def test_numeric_loopback_gateway_starts_without_dns(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch('socket.getfqdn', side_effect=AssertionError('No DNS permitted')):
            output = Path(directory)
            server = gateway.create_server(output)
            try:
                self.assertEqual(server.server_address[0], '127.0.0.1')
                self.assertGreater(server.server_port, 0)
                self.assertTrue((output / 'ready.json').is_file())
                for provider in gateway.PROVIDERS:
                    config = json.loads((output / (provider + '.json')).read_text())
                    self.assertIn('http://127.0.0.1:%d/' % server.server_port, config['endpoint'])
            finally:
                server.server_close()

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
