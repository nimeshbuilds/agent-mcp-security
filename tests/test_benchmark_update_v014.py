"""Additional-scope evidence must remain bound to the final scanner run."""
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from scripts import build_benchmark_update as builder


class SkillBenchmarkPublicationTests(unittest.TestCase):
    directory = builder.ROOT / 'benchmarks/comparison-v014'

    def test_new_scope_uses_separate_denominators_and_frozen_catalog_counts(self):
        data = builder.load(self.directory)
        self.assertEqual(data['after']['case_count'], 113)
        self.assertEqual(data['skills']['case_count'], 81)
        self.assertEqual(data['skills']['overall']['assertions'], 331)
        self.assertEqual(data['skills']['overall']['false_negative'], 3)
        self.assertEqual(data['catalog_counts'], {'rules': 46, 'controls': 66, 'checks': 132, 'mapped_controls': 30})
        self.assertIn('skills-tools-evaluation-receipt.json', data['hashes'])

    def test_skill_receipt_cannot_hide_misses_or_replace_the_scanner_implementation(self):
        path = self.directory / 'skills-tools-evaluation-receipt.json'
        original = json.loads(path.read_bytes())
        read = Path.read_bytes
        changes = [lambda value: value.update(implementation_sha256='0' * 64),
                   lambda value: value.update(failed_case_ids=[]),
                   lambda value: value.update(separate_denominator=False),
                   lambda value: value['report'].update(sha256='0' * 64)]
        for index, change in enumerate(changes):
            value = copy.deepcopy(original)
            change(value)
            modified = json.dumps(value).encode()
            with self.subTest(change=index), mock.patch.object(Path, 'read_bytes', lambda item: modified if item == path else read(item)):
                with self.assertRaisesRegex(ValueError, 'evaluation receipt'):
                    builder.load(self.directory)


if __name__ == '__main__':
    unittest.main()
