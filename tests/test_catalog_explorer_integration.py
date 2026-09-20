"""Public offline explorer contracts: grounded answers, exact provenance and no scan side effects."""
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

from ai_security_scan.cli import main
from ai_security_scan.rules import RULES

DATA = Path(__file__).resolve().parents[1] / 'ai_security_scan/data'


class CatalogExplorerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controls = {x['id']: x for x in json.loads((DATA / 'controls.json').read_bytes())}
        cls.sources = {x['id']: x for x in json.loads((DATA / 'sources.json').read_bytes())}

    @contextlib.contextmanager
    def offline(self):
        with contextlib.ExitStack() as stack:
            for target in ('ai_security_scan.cli.scan', 'ai_security_scan.cli.write_reports',
                           'ai_security_scan.cli.atomic_write', 'ai_security_scan.judge.load_config',
                           'ai_security_scan.cli_judge.login_cli', 'subprocess.Popen',
                           'urllib.request.OpenerDirector.open', 'socket.socket.connect', 'socket.getaddrinfo',
                           'builtins.input', 'pathlib.Path.write_bytes', 'pathlib.Path.write_text'):
                stack.enter_context(mock.patch(target, side_effect=AssertionError('Catalog attempted side effect: ' + target)))
            yield

    def invoke(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(list(arguments))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def document(self, *arguments):
        code, out, err = self.invoke(*arguments, '--catalog-format', 'json')
        self.assertEqual((code, err), (0, ''))
        value = json.loads(out)
        self.assertEqual(value['mode'], 'deterministic_catalog')
        self.assertEqual(value['schema_version'], '1.0')
        self.assertIn(value['status'], ('ok', 'no_match'))
        self.assertTrue(value['assurance'])
        self.assertEqual(value['catalog']['controls'], len(self.controls))
        self.assertEqual(value['catalog']['sources'], len(self.sources))
        return value

    def test_legacy_catalog_json_contracts_and_explicit_json_remain_unchanged(self):
        with self.offline():
            for arguments in (('--list-rules',), ('--list-controls',), ('--explain-rule', 'AI001')):
                with self.subTest(arguments=arguments):
                    default = self.invoke(*arguments)
                    explicit = self.invoke(*arguments, '--catalog-format', 'json')
                    self.assertEqual(default, explicit)
                    self.assertEqual(default[0], 0)
            self.assertEqual(len(json.loads(self.invoke('--list-rules')[1])), len(RULES))
            controls = json.loads(self.invoke('--list-controls')[1])
            self.assertEqual(len(controls), len(self.controls))
            for item in controls:
                original = self.controls[item['id']]
                for field, value in original.items():
                    self.assertEqual(item[field], value)
                self.assertEqual(item['check_ids'], [item['id'] + ':' + str(i) for i in range(1, len(item['checks']) + 1)])
            explanation = json.loads(self.invoke('--explain-rule', 'AI001')[1])
            self.assertEqual(explanation['rule']['id'], 'AI001')
            self.assertIn('mapped_control_ids', explanation)
            self.assertNotIn('mode', explanation)

    def test_new_actions_default_to_readable_offline_text(self):
        actions = [('--list-topics',), ('--list-sources',), ('--ask', 'prompt injection'),
                   ('--explain-control', 'AGT-03'), ('--explain-check', 'AUTH-02:2'),
                   ('--explain-source', 'BENCH-AGENTDOJO')]
        with self.offline():
            for arguments in actions:
                with self.subTest(arguments=arguments):
                    code, out, err = self.invoke(*arguments)
                    self.assertEqual((code, err), (0, ''))
                    self.assertTrue(out.strip())
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(out)
                    self.assertEqual(self.invoke(*arguments, '--catalog-format', 'text'), (code, out, err))

    def test_all_sources_keep_exact_registry_metadata_and_limitations(self):
        with self.offline():
            for source_id, source in self.sources.items():
                with self.subTest(source=source_id):
                    actual = self.document('--explain-source', source_id)['source']
                    for field, value in source.items():
                        self.assertEqual(actual[field], value, field)
                    self.assertTrue(actual['limitations'])
                    self.assertTrue(actual['version'])
                    self.assertTrue(actual['accessed'])
                    expected_links = {(control['id'], relationship)
                                      for control in self.controls.values()
                                      for field, relationship in (('source_ids', 'primary_control_source'),
                                                                  ('alignment_source_ids', 'thematic_alignment'))
                                      if source_id in control.get(field, [])}
                    self.assertEqual({(link['id'], link['relationship']) for link in actual['related_controls']},
                                     expected_links)

    def test_all_control_explanations_preserve_acceptance_checks_and_mapping_status(self):
        with self.offline():
            for control_id, original in self.controls.items():
                with self.subTest(control=control_id):
                    item = self.document('--explain-control', control_id)['control']
                    self.assertEqual((item['id'], item['title'], item['category']),
                                     (control_id, original['title'], original['category']))
                    for field in ('what_it_is', 'why_it_matters', 'agent_mcp_context'):
                        self.assertTrue(item[field].strip(), field)
                    self.assertEqual([x['text'] for x in item['checks']], original['checks'])
                    self.assertEqual([x['id'] for x in item['checks']], [control_id + ':' + str(i) for i in range(1, len(original['checks']) + 1)])
                    coverage = item['deterministic_coverage']
                    self.assertEqual(coverage['status'], 'partial' if original['automated_rule_ids'] else 'not_automated')
                    self.assertEqual({x['id'] for x in coverage['rules']}, set(original['automated_rule_ids']))
                    self.assertTrue(coverage['limits'])
                    actual_sources = {x['id']: x for x in item['sources']}
                    self.assertEqual(set(actual_sources), set(original['source_ids']) | set(original.get('alignment_source_ids', [])))
                    for ident in original['source_ids']:
                        self.assertEqual(actual_sources[ident]['relationship'], 'primary_control_source')
                    for ident in original.get('alignment_source_ids', []):
                        self.assertEqual(actual_sources[ident]['relationship'], 'thematic_alignment')
                    for ident, source in actual_sources.items():
                        for field in ('organization', 'title', 'url', 'version', 'date', 'accessed', 'scope', 'limitations'):
                            self.assertEqual(source[field], self.sources[ident][field])

    def test_stable_check_ids_resolve_to_exact_acceptance_text(self):
        with self.offline():
            for control_id, index in (('AUTH-01', 1), ('AUTH-02', 2), ('AGT-04', 2), ('TEST-01', 1), ('TEST-09', 2)):
                with self.subTest(control=control_id, index=index):
                    check = self.document('--explain-check', control_id + ':' + str(index))['check']
                    self.assertEqual(check['id'], control_id + ':' + str(index))
                    self.assertEqual(check['text'], self.controls[control_id]['checks'][index - 1])
                    self.assertEqual(check['index'], index)

    def test_scan_model_login_and_report_options_rejected_even_when_equal_to_defaults(self):
        conflicts = [('--fail-on', 'high'), ('--output', 'unused-output'), ('--quiet',), ('--summary-json',),
                     ('--judge-cli', 'claude'), ('--judge-config', 'does-not-exist.json'), ('--login', 'claude'),
                     ('--judge-login', 'auto'), ('--judge-mode', 'full'), ('--token-optimizer', 'headroom'),
                     ('--max-files', '20000'), ('--max-total-bytes', '50000000'), ('--include-tests',),
                     ('--image', 'absent:tag'), ('--image-archive', 'missing.tar'), ('--pull',), ('--pdf',),
                     ('--review-report', 'missing-report.json'), ('--review-config', 'missing-policy.json'),
                     ('--baseline', 'missing-baseline.json'), ('--include', '*.py'), ('--format', 'json')]
        with self.offline():
            for extra in conflicts:
                with self.subTest(extra=extra):
                    code, out, err = self.invoke('--ask', 'MCP roots', *extra)
                    self.assertEqual((code, out), (2, ''))
                    self.assertIn('error:', err)
                    self.assertIn(extra[0], err)
            code, out, err = self.invoke('nonexistent-repository', '--list-topics')
            self.assertEqual((code, out), (2, ''))
            self.assertIn('target', err)

    def test_catalog_actions_are_mutually_exclusive_and_format_needs_an_action(self):
        cases = [('--list-topics', '--list-sources'), ('--ask', 'memory poisoning', '--explain-control', 'AGT-04'),
                 ('--list-controls', '--explain-source', 'MITRE-ATLAS'), ('--catalog-format', 'json'),
                 ('--ask', 'prompt injection', '--catalog-format', 'xml')]
        with self.offline():
            for args in cases:
                with self.subTest(args=args):
                    code, out, err = self.invoke(*args)
                    self.assertEqual((code, out), (2, ''))
                    self.assertIn('error:', err)

    def test_catalog_read_failure_is_actionable_and_does_not_expose_host_paths(self):
        with self.offline(), mock.patch('ai_security_scan.catalog.describe_catalog',
                                        side_effect=FileNotFoundError('/private/local/catalog/source.json')):
            code, out, err = self.invoke('--ask', 'prompt injection')
        self.assertEqual((code, out), (2, ''))
        self.assertIn('Unable to read the bundled security catalog', err)
        self.assertIn('reinstall', err)
        self.assertNotIn('/private/local', err)

    def test_invalid_ids_and_empty_or_overlong_questions_are_actionable_errors(self):
        cases = [('--explain-control', 'AGT-999'), ('--explain-control', 'AI001'),
                 ('--explain-check', 'AUTH-01'), ('--explain-check', 'AUTH-01:0'), ('--explain-check', 'AUTH-01:999'),
                 ('--explain-source', 'NONEXISTENT-SOURCE'), ('--ask', ''), ('--ask', '   '), ('--ask', 'x' * 1001)]
        with self.offline():
            for args in cases:
                with self.subTest(args=args):
                    code, out, err = self.invoke(*args)
                    self.assertEqual((code, out), (2, ''))
                    self.assertIn('error:', err)

    def test_unknown_question_and_unknown_id_are_explicit_successful_no_matches(self):
        with self.offline():
            for query in ('quuxfrobulator xylophone nebula', 'UNKNOWN-CONTROL-999', 'AI999'):
                with self.subTest(query=query):
                    value = self.document('--ask', query)
                    self.assertEqual(value['status'], 'no_match')
                    self.assertEqual(value['total_matches'], 0)
                    self.assertEqual(value['results'], [])

    def test_specific_security_questions_retrieve_relevant_controls(self):
        questions = [('prompt injection', {'AGT-03', 'TEST-01'}),
                     ('What do you check for prompt injection?', {'AGT-03', 'TEST-01'}),
                     ('memory poisoning', {'AGT-04'}),
                     ('MCP roots filesystem isolation', {'MCP-08'}),
                     ('authentication versus authorization', {'AUTH-01', 'AUTH-02'}),
                     ('tool metadata poisoning', {'MCP-03'}),
                     ('How can MCP agents prevent memory poisoning?', {'AGT-04'}),
                     ('Why should MCP tools not trust readOnlyHint?', {'MCP-03'}),
                     ('Why are MCP roots not a sandbox?', {'MCP-08'})]
        with self.offline():
            for query, expected in questions:
                with self.subTest(query=query):
                    value = self.document('--ask', query)
                    self.assertEqual(value['status'], 'ok')
                    self.assertTrue(expected <= {x['id'] for x in value['results']})
                    self.assertLessEqual(value['returned_matches'], value['limit'])
                    self.assertEqual(value['returned_matches'], len(value['results']))
                    for result in value['results']:
                        self.assertTrue(result['matched_fields'])
                        self.assertTrue(result['command'].startswith('invscan '))
                        self.assertTrue(result['detail'])

    def test_organization_and_named_benchmark_aliases_preserve_source_identity(self):
        queries = [('AgentDojo', {'BENCH-AGENTDOJO'}), ('MCPSecBench', {'BENCH-MCPSECBENCH'}),
                   ('MCP-SafetyBench', {'BENCH-MCP-SAFETY'}), ('MITRE ATLAS', {'MITRE-ATLAS', 'MITRE-ATLAS-202609'}),
                   ('National Security Agency', {'NSA-AGENTIC', 'NSA-DATA', 'JOINT-AGENTIC'}),
                   ('Cloud Security Alliance', {'CSA-AICM', 'CSA-MAESTRO'}),
                   ('CISA', {'CISA-AGENTIC', 'CISA-JCDC'}), ('CIS', {'CIS-CONTROLS-81', 'CIS-MCP-BENCH-1'})]
        with self.offline():
            for query, alternatives in queries:
                with self.subTest(query=query):
                    value = self.document('--ask', query)
                    source_ids = {x['id'] for x in value['results'] if x['kind'] == 'source'}
                    self.assertTrue(source_ids & alternatives, (query, source_ids))
                    if query == 'CIS':
                        self.assertFalse(any(x.startswith('CISA-') for x in source_ids))
                    if query == 'CISA':
                        self.assertFalse(any(x.startswith('CIS-') for x in source_ids))

    def test_hyphenated_security_terms_and_source_names_are_case_insensitive(self):
        with self.offline():
            for query, expected in (('prompt-injection', 'AGT-03'),
                                    ('mcp-safetybench', 'BENCH-MCP-SAFETY'),
                                    ('cloud-security-alliance', 'CSA-AICM')):
                with self.subTest(query=query):
                    lower = self.document('--ask', query)
                    upper = self.document('--ask', query.upper())
                    self.assertEqual(upper['status'], 'ok')
                    self.assertIn(expected, {x['id'] for x in upper['results']})
                    self.assertEqual(upper['results'], lower['results'])

    def test_benchmark_lookup_is_bounded_and_does_not_claim_a_suite_was_run(self):
        with self.offline():
            value = self.document('--ask', 'benchmarks')
            self.assertEqual(value['status'], 'ok')
            self.assertTrue(any(x['kind'] == 'source' and x['id'].startswith('BENCH-') for x in value['results']))
            self.assertEqual(value['truncated'], value['total_matches'] > value['returned_matches'])
            self.assertLessEqual(value['returned_matches'], 8)
            source = self.document('--explain-source', 'BENCH-AGENTDOJO')['source']
            self.assertIn('Not executed here.', source['limitations'])

    def test_draft_listing_and_unexecuted_benchmark_caveats_survive_text_rendering(self):
        checks = [('NIST-AGENT-IDENTITY-DRAFT', ('draft', 'not a completed practice guide')),
                  ('CIS-MCP-BENCH-1', ('full controls not reviewed', 'registration')),
                  ('CSA-AICM-MACHINE', ('bundle not imported', 'licensing')),
                  ('BENCH-AGENTDOJO', ('not executed here', '2024')),
                  ('MITRE-ATLAS-202609', ('v2026.09', 'not a security score'))]
        with self.offline():
            for source_id, phrases in checks:
                with self.subTest(source=source_id):
                    code, out, err = self.invoke('--explain-source', source_id)
                    self.assertEqual((code, err), (0, ''))
                    flattened = ' '.join(out.lower().split())
                    for phrase in phrases:
                        self.assertIn(phrase, flattened)
                    self.assertIn(self.sources[source_id]['url'], out)

    def test_repeated_questions_and_catalog_formats_are_byte_deterministic(self):
        with self.offline():
            for args in (('--ask', 'memory poisoning'), ('--ask', 'AgentDojo', '--catalog-format', 'json'),
                         ('--explain-source', 'CIS-MCP-BENCH-1'), ('--list-topics', '--catalog-format', 'json')):
                with self.subTest(args=args):
                    first = self.invoke(*args)
                    self.assertEqual(first[0], 0)
                    self.assertEqual(self.invoke(*args), first)


if __name__ == '__main__':
    unittest.main()
