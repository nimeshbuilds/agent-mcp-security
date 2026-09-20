"""Measure rule accuracy, and verify deliberate detector mutations are caught."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan import analyzer
from ai_security_scan.rules import RULE_BY_ID

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('accuracy_evaluator', PROJECT / 'scripts/evaluate_accuracy.py')
accuracy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(accuracy)


class AccuracyCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus, cls.digest = accuracy.load_corpus(PROJECT / 'benchmarks/static_accuracy.json')

    def test_inspector_label_correction_preserves_exact_previous_corpus(self):
        archived = (PROJECT / 'benchmarks/static_accuracy-v110.json').read_bytes()
        self.assertEqual(hashlib.sha256(archived).hexdigest(),
                         'aa4e3b2a95fdf5d5ea09721c0316c72a654d90d58281be5caab249d87510dff8')
        previous = {case['id']: case for case in json.loads(archived)['cases']}
        current = {case['id']: case for case in self.corpus['cases']}
        self.assertEqual(previous['ai041-comparison']['source'], current['ai041-comparison']['source'])
        self.assertFalse(previous['ai041-comparison']['expect']['AI041'])
        self.assertTrue(current['ai041-comparison']['expect']['AI041'])
        self.assertFalse(current['ai041-empty']['expect']['AI041'])
        self.assertFalse(current['ai041-unset']['expect']['AI041'])
        self.assertTrue(current['ai041-zero-string']['expect']['AI041'])
        self.assertTrue(current['ai041-nonempty-string']['expect']['AI041'])

    def test_supported_cases_and_every_rule_have_both_labels(self):
        report = accuracy.evaluate(self.corpus, self.digest)
        self.assertEqual(report['regression_failure_ids'], [])
        self.assertEqual(report['analysis_error_cases'], 0)
        for rule in {rule for case in self.corpus['cases'] for rule in case['expect']}:
            labels = {case['expect'][rule] for case in self.corpus['cases'] if case['suite'] == 'regression' and rule in case['expect']}
            self.assertEqual(labels, {True, False}, rule)

    def test_challenge_failures_are_included_in_overall_metrics(self):
        report = accuracy.evaluate(self.corpus, self.digest)
        for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative', 'assertions'):
            self.assertEqual(report['overall'][key], sum(suite[key] for suite in report['by_suite'].values()))
        self.assertEqual(report['overall']['assertions'], sum(len(c['expect']) for c in self.corpus['cases']))
        self.assertIn('not production accuracy estimates', report['scope'])
        self.assertEqual(report, accuracy.evaluate(self.corpus, self.digest))

    def test_removing_each_of_42_detectors_is_caught(self):
        original = analyzer._Findings.add
        positives = {rule: next(case for case in self.corpus['cases'] if case['suite'] == 'regression' and case['expect'].get(rule) is True) for rule in {rule for case in self.corpus['cases'] for rule in case['expect']}}
        for removed, case in positives.items():
            def skip_rule(self, rule_id, *args, **kwargs):
                if rule_id != removed:
                    return original(self, rule_id, *args, **kwargs)
            with self.subTest(rule=removed), patch.object(analyzer._Findings, 'add', skip_rule):
                report = accuracy.evaluate({'cases': [case]}, 'mutation-fixture')
                self.assertEqual(report['overall']['false_negative'], 1)
                self.assertEqual(report['regression_failure_ids'], [case['id']])

    def test_false_alarm_mutations_and_metric_denominators(self):
        sample = {'cases': [dict(id='negative', suite='regression', path='fixture.py', source='pass\n', expect={'AI001': False}),
                            dict(id='positive', suite='regression', path='fixture.py', source='eval(user_input)', expect={'AI001': True})]}
        result = accuracy.evaluate(sample, 'fixture', analyzer=lambda path, text: [{'rule_id': 'AI001'}])
        self.assertEqual(result['overall']['true_positive'], 1)
        self.assertEqual(result['overall']['false_positive'], 1)
        self.assertEqual(result['overall']['precision'], 0.5)
        self.assertEqual(result['overall']['recall'], 1)
        self.assertEqual(result['regression_failure_ids'], ['negative'])
        self.assertIsNone(accuracy.metrics({})['precision'])
        self.assertIsNone(accuracy.metrics({})['recall'])

    def test_bad_corpus_contract_is_rejected(self):
        for modify in [lambda c: c.update(schema_version='99'), lambda c: c.update(cases=[]),
                       lambda c: c['cases'].append(c['cases'][0]),
                       lambda c: c['cases'][0].update(expect={'UNKNOWN': True}),
                       lambda c: c['cases'][0].update(expect={'AI001': 'false'}),
                       lambda c: c['cases'][0].update(suite='hidden')]:
            corpus = copy.deepcopy(self.corpus)
            modify(corpus)
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'corpus.json'
                path.write_text(json.dumps(corpus), encoding='utf-8')
                with self.assertRaises(ValueError):
                    accuracy.load_corpus(path)

    def test_analysis_error_cannot_be_scored_as_true_negative(self):
        sample = {'cases': [dict(id='broken', suite='regression', path='fixture.py', source='def (', expect={'AI001': False})]}
        result = accuracy.evaluate(sample, 'fixture')
        self.assertEqual(result['analysis_error_cases'], 1)
        self.assertEqual(result['overall']['assertions'], 0)
        self.assertEqual(result['regression_failure_ids'], ['broken'])

    def test_cli_gates_and_output_formats(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'fixture.json'
            path.write_text(json.dumps(dict(schema_version='1.0', cases=[dict(id='miss', suite='challenge', path='fixture.py', source='pass', expect={'AI001': True})])), encoding='utf-8')
            for gate, expected in [('regression', 0), ('any', 1), ('none', 0)]:
                for format in ('json', 'markdown'):
                    output = Path(temporary) / ('report.' + format)
                    self.assertEqual(accuracy.main(['--corpus', str(path), '--fail-on', gate, '--format', format, '--output', str(output)]), expected)
                    content = output.read_text(encoding='utf-8')
                    self.assertIn('miss', content)
                    if format == 'json':
                        self.assertEqual(json.loads(content)['overall']['false_negative'], 1)
            path.write_text('{invalid', encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(accuracy.main(['--corpus', str(path)]), 2)


if __name__ == '__main__':
    unittest.main()
