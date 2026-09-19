"""Configuration equivalence, ambiguity, and parser bypass regressions."""
import json
from pathlib import Path
import tempfile
import unittest

from ai_security_scan.analyzer import analyze_file, analyze_file_errors
from ai_security_scan.scanner import scan


def ids(path, source):
    return {item['rule_id'] for item in analyze_file(path, source)}


class ConfigurationAccuracyTests(unittest.TestCase):
    def test_loopback_requires_an_actual_ip_or_exact_localhost(self):
        for host in ('127.attacker.example', '127.0.0.1.attacker.example', '127.999.999.999', '[::ffff:192.0.2.1]', 'localhost.attacker.example'):
            with self.subTest(host=host):
                self.assertIn('AI029', ids('mcp.json', json.dumps({'url': 'http://' + host + '/mcp'})))
        for host in ('localhost', 'LOCALHOST', '127.0.0.1', '127.255.255.254', '[::1]', '[::ffff:127.0.0.1]'):
            with self.subTest(host=host):
                self.assertNotIn('AI029', ids('mcp.json', json.dumps({'url': 'http://' + host + '/mcp'})))

    def test_url_leading_whitespace_and_unrelated_json_images(self):
        for prefix in (' ', '\t', '\n', '\x00'):
            self.assertIn('AI029', ids('mcp.json', json.dumps({'url': prefix + 'http://remote.example/mcp'})))
        self.assertNotIn('AI024', ids('site.json', '{"image":"logo.png"}'))
        self.assertNotIn('AI025', ids('package.json', '{"dependencies":{"worker":"1.2.3-rc.1+build.1"}}'))

    def test_runner_selector_forms_and_all_distributions(self):
        cases = [
            ('npx', ['--package=@vendor/worker@1.2.3', 'worker'], False),
            ('npx', ['-p@vendor/worker@1.2.3', 'worker'], False),
            ('npx', ['worker@1.2.3-rc.1+build.1'], False),
            ('uvx', ['--from', 'worker==1', 'worker'], False),
            ('npx', ['--package', '@vendor/worker@1.2.3', '--package=helper@latest', 'worker'], True),
            ('npx', ['--package', '@vendor/worker@1.2.3', '--package', 'helper@2.0.0', '-c', 'worker'], False),
            ('npx', ['--registry', 'https://registry.example', '-y', 'worker@1.2.3', '--package=child-option'], False),
            ('npx', ['--', 'worker@latest'], True),
            ('npx', ['-y', 'worker@1.2.3', '--child-arg', 'unpinned'], False),
            ('uvx', ['--from=worker==1.2.3', 'worker'], False),
            ('uvx', ['--from', 'worker==1.2.3', '--with=helper', 'worker'], True),
            ('uvx', ['--with', 'helper==2.0.1', '--python', '3.12', 'worker==1.2.3'], False),
            ('uv', ['tool', 'run', '--from', 'worker==1.2.3', 'worker'], False),
            ('uv', ['tool', 'run', '--from', 'worker', 'worker'], True),
            (r'C:\tools\npx.cmd', ['worker'], True),
            ('/opt/bin/uvx', ['worker==1.2.3'], False),
        ]
        for command, args, expected in cases:
            with self.subTest(command=command, args=args):
                source = json.dumps({'mcpServers': {'worker': {'command': command, 'args': args}}})
                self.assertEqual('AI018' in ids('mcp.json', source), expected)

    def test_json_container_flags_match_yaml_semantics(self):
        for key, unsafe, safer, rule in [
            ('privileged', True, False, 'AI022'),
            ('allowPrivilegeEscalation', True, False, 'AI022'),
            ('hostPID', True, False, 'AI042'),
            ('hostNetwork', True, False, 'AI042'),
            ('network_mode', 'host', 'bridge', 'AI042'),
            ('pid', 'host', 'private', 'AI042'),
            ('mountPath', '/var/run/docker.sock', '/app/data', 'AI023'),
        ]:
            for value, expected in ((unsafe, True), (safer, False)):
                with self.subTest(key=key, value=value):
                    self.assertEqual(rule in ids('deployment.json', json.dumps({'spec': {key: value}})), expected)

    def test_digest_marker_without_full_hash_is_not_a_pin(self):
        for image, expected in [('image@sha256:abc', True), ('image@sha256:' + 'g' * 64, True), ('image@sha256:' + 'a' * 63, True), ('image@sha256:' + 'a' * 64, False)]:
            for path, source in [('Dockerfile', 'FROM ' + image + '\n'), ('deployment.yml', 'image: ' + image + '\n'), ('deployment.json', json.dumps({'spec': {'containers': [{'name': 'worker', 'image': image}]}}))]:
                with self.subTest(path=path, image=image):
                    self.assertEqual('AI024' in ids(path, source), expected)

    def test_ambiguous_and_nonfinite_json_create_coverage_gaps(self):
        for path in ('mcp.json', 'mcp.jsonc'):
            for source in ('{"authentication":false,"authentication":true}', '{"nested":{"key":1,"key":2}}', '{"authentication":false,"n":NaN}', '{"n":Infinity}', '{"n":1e999}'):
                with self.subTest(path=path, source=source):
                    self.assertTrue(analyze_file_errors(path, source))
                    self.assertNotIn('AI026', ids(path, source))
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        (root / path).write_text(source, encoding='utf-8')
                        report = scan(root)
                        self.assertFalse(report['summary']['scan_complete_within_selected_scope'])
                        self.assertGreater(report['summary']['coverage_gaps'], 0)
                        self.assertEqual(report['coverage']['errors'][0]['kind'], 'parse_error')

    def test_json_formatting_and_key_order_do_not_change_rule_ids(self):
        original = {'mcpServers': {'worker': {'url': 'http://remote.example/mcp', 'command': 'npx', 'args': ['worker@latest'], 'autoApprove': ['*']}}}
        expected = {'AI018', 'AI029', 'AI031'}
        for indent, sort_keys in [(None, False), (2, False), (4, True)]:
            self.assertEqual(ids('config.json', json.dumps(original, indent=indent, sort_keys=sort_keys)), expected)


if __name__ == '__main__':
    unittest.main()
