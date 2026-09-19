"""A scanned file count must not imply equal semantic analysis in every language."""
from pathlib import Path
import tempfile
import unittest

from ai_security_scan.scanner import scan
from ai_security_scan.report import markdown


class AnalysisProfileTests(unittest.TestCase):
    def test_each_file_and_report_expose_analysis_depth(self):
        sources = {'agent.py': ('value = 1\n', 'python_ast'),
                   'worker.ts': ('const value = 1;', 'javascript_lexical'),
                   'mcp.json': ('{}', 'json_structured'),
                   'mcp.yml': ('name: worker', 'configuration_lexical'),
                   'Dockerfile': ('FROM scratch', 'configuration_lexical'),
                   'worker.rs': ('fn main() {}', 'generic_text')}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, (source, _) in sources.items():
                (root / name).write_text(source, encoding='utf-8')
            report = scan(root)
        self.assertEqual(report['summary']['files_scanned'], 6)
        self.assertEqual(report['findings'], [])
        for file in report['files']:
            self.assertEqual(file['analysis_profile'], sources[file['path']][1])
        profiles = report['coverage']['analysis_profiles']
        self.assertEqual(sum(item['files'] for item in profiles.values()), 6)
        self.assertEqual(profiles['generic_text']['files'], 1)
        self.assertIn('not analyzed', profiles['generic_text']['scope'])
        self.assertIn('Analysis depth', markdown(report))
        self.assertIn('not complete semantic coverage', markdown(report))
        self.assertTrue(all('pass' not in c['status'] for c in report['controls']))


if __name__ == '__main__':
    unittest.main()
