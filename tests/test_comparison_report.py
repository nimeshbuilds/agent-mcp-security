"""The research PDF must not conflate historical selection and current review."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts import build_finding_comparison_report as B


class ComparisonReportProvenanceTests(unittest.TestCase):
    names = (
        'observations.json', 'overlaps.json', 'run-status.json',
        'adjudication-selection.json', 'observations-selection-v1.json',
        'observations-v090.json', 'run-status-v090.json', 'tool-lock.json',
        'external-results/shared-pattern-fixtures.json', 'external-results/cisco-metadata.json',
        'source-audit.json', 'adjudication-live/model-adjudication.json',
        'adjudication-live/preparation.json',
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in self.names:
            with (B.DEFAULT_INPUT / name).open('rb') as stream:
                raw = stream.read(15_000_001)
            self.assertLessEqual(len(raw), 15_000_000)
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def read(self, name):
        return json.loads((self.root / name).read_text(encoding='utf-8'))

    def write(self, name, data):
        (self.root / name).write_text(json.dumps(data, ensure_ascii=True), encoding='utf-8')

    def update_adjudication(self, change):
        result = self.read('adjudication-live/model-adjudication.json')
        change(result)
        self.write('adjudication-live/model-adjudication.json', result)

    def test_actual_current_review_and_historical_selection_are_distinct_and_accepted(self):
        data = B.load_inputs(self.root)
        record = data['adjudication']
        self.assertEqual(record['review_ledger'], 'observations.json')
        self.assertEqual(record['review_invarune_versions'], '0.10.0')
        self.assertNotEqual(record['data']['original_selection_ledger_sha256'], record['data']['review_ledger_sha256'])
        counts = B.likelihood_counts(record['data']['judgments'])
        self.assertEqual(counts['selected_observations'], 153)
        self.assertEqual(counts['valid_model_answers'], 0)
        text = '\n'.join(str(x) for x in B.adjudication_story(data, lambda x, *_: x, lambda rows, _: str(rows), lambda label, url: label))
        self.assertIn('point estimate: unavailable', text)
        self.assertIn('observations.json (Invarune 0.10.0)', text)
        self.assertEqual(data['source_audit']['summary']['source_pattern_counts']['supported_source_pattern'], 42)
        self.assertEqual(data['source_audit']['summary']['source_pattern_counts']['conditional_rule_mismatch'], 8)

    def test_preserved_review_ledger_requires_its_own_matching_preparation_and_versions(self):
        historical = self.read('observations-v090.json')
        by_id = {row['id']: row for row in historical['observations']}
        preparation = self.read('adjudication-live/preparation.json')
        preparation['review_ledger_sha256'] = B.digest(historical)
        preparation['engine_versions'] = ['0.9.0']
        self.write('adjudication-live/preparation.json', preparation)
        def change(result):
            result['review_ledger_sha256'] = B.digest(historical)
            result['preparation_sha256'] = B.digest(preparation)
            for row in result['judgments']:
                row['tool_version'] = by_id[row['observation_id']]['tool_version']
        self.update_adjudication(change)
        data = B.load_inputs(self.root)
        self.assertEqual(data['adjudication']['review_ledger'], 'observations-v090.json')
        self.assertEqual(data['adjudication']['review_invarune_versions'], '0.9.0')

    def test_tampered_review_digest_is_rejected(self):
        self.update_adjudication(lambda result: result.update(review_ledger_sha256='0' * 64))
        with self.assertRaisesRegex(ValueError, 'known review ledger'):
            B.load_inputs(self.root)

    def test_changed_selected_identity_is_rejected_even_with_updated_current_digest(self):
        (self.root / 'source-audit.json').unlink()  # Isolate model-track checks.
        selected = self.read('adjudication-selection.json')['selected_observation_ids'][0]
        current = self.read('observations.json')
        next(row for row in current['observations'] if row['id'] == selected)['path'] = 'different-source.py'
        self.write('observations.json', current)
        overlaps = self.read('overlaps.json')
        overlaps['observation_ledger_sha256'] = B.digest(current)
        self.write('overlaps.json', overlaps)
        preparation = self.read('adjudication-live/preparation.json')
        preparation['review_ledger_sha256'] = B.digest(current)
        self.write('adjudication-live/preparation.json', preparation)
        self.update_adjudication(lambda result: result.update(review_ledger_sha256=B.digest(current), preparation_sha256=B.digest(preparation)))
        with self.assertRaisesRegex(ValueError, 'changed a selected observation identity'):
            B.load_inputs(self.root)

    def test_tampered_preparation_is_rejected(self):
        preparation = self.read('adjudication-live/preparation.json')
        preparation['prepared_observations'] -= 1
        self.write('adjudication-live/preparation.json', preparation)
        with self.assertRaisesRegex(ValueError, 'preparation digest'):
            B.load_inputs(self.root)

    def test_tampered_model_summary_cannot_be_promoted_to_measured_answers(self):
        def change(result):
            result['summary']['valid_model_answers'] = 1
        self.update_adjudication(change)
        with self.assertRaisesRegex(ValueError, 'summary counts'):
            B.load_inputs(self.root)

    def test_source_audit_named_archive_and_current_raw_digest_are_checked(self):
        original = self.read('source-audit.json')
        for field in ('archive_name', 'current_digest', 'labels'):
            with self.subTest(field=field):
                audit = json.loads(json.dumps(original))
                if field == 'archive_name':
                    audit['selection']['input_ledger_path'] = 'observations.json'
                elif field == 'current_digest':
                    audit['current_ledger_correspondence']['raw_sha256'] = '0' * 64
                else:
                    audit['summary']['source_pattern_counts']['supported_source_pattern'] += 1
                self.write('source-audit.json', audit)
                with self.assertRaises(ValueError):
                    B.load_inputs(self.root)


if __name__ == '__main__':
    unittest.main()
