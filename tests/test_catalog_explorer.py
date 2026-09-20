"""Core offline catalog provenance, query boundaries and stable explanations."""
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from ai_security_scan.catalog import describe_catalog, render_catalog, MAX_QUERY_CHARS
from ai_security_scan.rules import RULES


DATA = Path(__file__).resolve().parents[1] / 'ai_security_scan' / 'data'


class CatalogExplorerTests(unittest.TestCase):
    def test_every_control_has_distinct_context_all_checks_and_exact_source_roles(self):
        original = json.loads((DATA / 'controls.json').read_text())
        response = describe_catalog('controls')
        self.assertEqual(response['catalog']['controls'], 66)
        self.assertEqual(response['catalog']['checks'], 132)
        self.assertEqual(response['catalog']['statically_mapped_controls'], sum(bool(item['automated_rule_ids']) for item in original))
        self.assertEqual([item['id'] for item in response['controls']], [item['id'] for item in original])
        for before, after in zip(original, response['controls']):
            with self.subTest(control=before['id']):
                for field in ('what_it_is', 'why_it_matters', 'agent_mcp_context'):
                    self.assertGreater(len(after[field]), 55)
                    self.assertEqual(sum(item[field] == after[field] for item in response['controls']), 1)
                self.assertEqual([check['text'] for check in after['checks']], before['checks'])
                self.assertEqual([check['id'] for check in after['checks']], [before['id'] + ':1', before['id'] + ':2'])
                self.assertEqual([rule['id'] for rule in after['deterministic_coverage']['rules']], before['automated_rule_ids'])
                self.assertEqual(after['deterministic_coverage']['status'], 'partial' if before['automated_rule_ids'] else 'not_automated')
                for field, role in (('source_ids', 'primary_control_source'), ('alignment_source_ids', 'thematic_alignment')):
                    self.assertEqual([source['id'] for source in after['sources'] if source['relationship'] == role], before.get(field, []))
                self.assertTrue(all(check['static_check_proof'] == 'not_established_by_rule_mapping' for check in after['checks']))

    def test_all_source_metadata_is_preserved_without_announcement_mapping_inference(self):
        originals = json.loads((DATA / 'sources.json').read_text())
        sources = describe_catalog('sources')['sources']
        self.assertEqual(len(sources), len(originals))
        for before, after in zip(originals, sources):
            for key, value in before.items():
                self.assertEqual(after[key], value)
        for key in ('NSA-AGENTIC', 'CISA-AGENTIC'):
            self.assertEqual(describe_catalog('source', key)['source']['related_controls'], [])
        self.assertIn('catalog', describe_catalog('source', 'CIS-MCP-BENCH-1')['source']['limitations'].lower())

    def test_all_rules_preserve_detection_and_existing_remediation(self):
        response = describe_catalog('rules')
        self.assertEqual(response['catalog']['rules'], len(RULES))
        for before, after in zip(RULES, response['rules']):
            for key, value in before.items():
                self.assertEqual(after[key], value)
            self.assertTrue(after['implementation_guidance']['steps'])
            self.assertTrue(all(ref['relationship'] == 'rule_technical_reference' for ref in after['technical_references']))
            self.assertIn('not proof', after['assurance'])

    def test_topics_partition_all_controls_and_offer_executable_lookup_questions(self):
        topics = describe_catalog('topics')['topics']
        self.assertEqual(len(topics), 9)
        ids = [control['id'] for topic in topics for control in topic['controls']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 66)
        self.assertEqual(sum(topic['check_count'] for topic in topics), 132)
        for topic in topics:
            for query in topic['example_queries']:
                self.assertEqual(describe_catalog('ask', query)['status'], 'ok')

    def test_exact_ids_and_one_based_checks_are_rich_while_unknown_ids_do_not_scan(self):
        for action, identifier in (('control', 'auth-01'), ('check', 'auth-01:1'), ('rule', 'ai017'), ('source', 'nist-rmf')):
            detail = describe_catalog(action, identifier)[action]
            self.assertEqual(detail['id'], identifier.upper())
            result = describe_catalog('ask', identifier)['results']
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['detail'], detail)
        for identifier in ('AI999', 'AUTH-99', 'AUTH-01:0', 'AUTH-01:01', 'AUTH-01:99', 'AUTH-01:abc', 'UNKNOWN-CONTROL-999'):
            result = describe_catalog('ask', identifier)
            self.assertEqual((result['status'], result['total_matches'], result['results']), ('no_match', 0, []))
        for action, identifier in (('control', 'AI001'), ('check', 'AUTH-01:0'), ('source', 'NOT-A-SOURCE'), ('rule', 'AI999')):
            with self.assertRaises(ValueError):
                describe_catalog(action, identifier)

    def test_literal_queries_cover_expected_concepts_and_keep_frameworks_distinct(self):
        cases = {'memory poisoning': ['AGT-04'], 'MCP roots': ['MCP-08', 'EXEC-04'],
                 'What do you check for prompt injection?': ['AGT-03', 'TEST-01'],
                 'authentication versus authorization': ['AUTH-01', 'AUTH-02'],
                 'AgentDojo': ['BENCH-AGENTDOJO', 'TEST-01'],
                 'MCP security benchmark': ['CIS-MCP-BENCH-1', 'BENCH-MCPSECBENCH', 'BENCH-MSB', 'BENCH-MCP-SAFETY']}
        for query, expected in cases.items():
            ids = [item['id'] for item in describe_catalog('ask', query)['results']]
            for identifier in expected:
                self.assertIn(identifier, ids, query)
        for query, forbidden_prefix in (('CIS', 'CISA-'), ('CISA', 'CIS-')):
            self.assertFalse(any(item['id'].startswith(forbidden_prefix) for item in describe_catalog('ask', query)['results']))
        self.assertEqual(describe_catalog('ask', 'MITRE ATT&CK')['status'], 'no_match')
        self.assertTrue(all(item['kind'] == 'source' for item in describe_catalog('ask', 'benchmarks')['results']))

    def test_query_case_and_hyphenated_concepts_are_equivalent(self):
        for query in ('prompt-injection', 'mcp-safetybench', 'cloud-security-alliance'):
            lower = describe_catalog('ask', query)
            upper = describe_catalog('ask', query.upper())
            self.assertEqual(lower['status'], 'ok')
            self.assertEqual(lower['results'], upper['results'])

    def test_questions_about_scope_are_explicit_overviews_not_automation_claims(self):
        for query in ('what does invscan scan?', 'what can you scan?', 'what all AI things do you scan?'):
            result = describe_catalog('ask', query)
            self.assertEqual(result['results'][0]['kind'], 'topics')
            self.assertEqual(len(result['results'][0]['detail']['topics']), 9)
            self.assertIn('does not scan or select rules', result['scan_guidance']['meaning'])
            self.assertIn('partial', result['assurance']['automation'])

    def test_invalid_queries_reject_control_format_and_excessive_input(self):
        for query in (None, True, 1, '', '   ', 'x' * (MAX_QUERY_CHARS + 1), 'a\nsource', 'a\tquery', '\x1b[31m', '\x85', '\u202e', '\u200b', '\ud800', '\ufeff'):
            with self.subTest(query=repr(query)), self.assertRaises(ValueError):
                describe_catalog('ask', query)
        self.assertEqual(describe_catalog('ask', 'x' * MAX_QUERY_CHARS)['status'], 'no_match')
        with self.assertRaises(ValueError):
            describe_catalog('ask', '\ufdfa' * 300)  # NFKC expansion is bounded too.

    def test_search_is_literal_bounded_repeatable_and_has_no_external_execution(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No subprocess')), \
             mock.patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('No network')):
            for query in ('prompt injection', '.*', 'zzzinvscannoknowntopiczz', '$(touch malicious)', 'NSA/CISA'):
                first = describe_catalog('ask', query)
                self.assertEqual(first, describe_catalog('ask', query))
                self.assertLessEqual(len(first['results']), 8)
                self.assertEqual(first['returned_matches'], len(first['results']))
                self.assertTrue(render_catalog(first))
        self.assertEqual(describe_catalog('ask', '.*')['status'], 'no_match')

    def test_response_mutations_cannot_change_cached_catalogs(self):
        original = describe_catalog('control', 'AUTH-01')
        modified = copy.deepcopy(original)
        modified['control']['sources'][0]['title'] = 'changed'
        modified['control']['deterministic_coverage']['rules'][0]['description'] = 'changed'
        modified['control']['aliases'].append('changed')
        original['control']['checks'][0]['text'] = 'changed'
        fresh = describe_catalog('control', 'AUTH-01')
        self.assertNotEqual(fresh['control']['checks'][0]['text'], 'changed')
        self.assertNotEqual(fresh['control']['sources'][0]['title'], 'changed')
        self.assertNotIn('changed', fresh['control']['aliases'])

    def test_text_leads_with_meaning_and_retains_provenance_limitations(self):
        text = render_catalog(describe_catalog('control', 'AUTH-01'))
        self.assertLess(text.index('What it is:'), text.index('Interpretation and source relationships:'))
        for required in ('Why it matters:', 'AI agent / MCP context:', 'AUTH-01:1', 'AUTH-01:2',
                         'primary_control_source', 'thematic_alignment', 'rule_technical_reference', 'Scope:', 'Limitations:',
                         'invscan TARGET', 'no per-check automated pass', 'official clause-level'):
            self.assertIn(required, text)


if __name__ == '__main__':
    unittest.main()
