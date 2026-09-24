import unittest
from scripts.finalize_benchmark_comparison import portable, verify_reports
from pathlib import Path
import tempfile

class FinalizationTests(unittest.TestCase):
    def test_private_root_is_replaced_recursively(self):
        self.assertEqual(portable({'x':['/private/work/input']},{'/private/work':'{workspace}'}),{'x':['{workspace}/input']})
    def test_two_real_executions_required(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):verify_reports({'id':'demo'},{'repeated_runs':[]},Path(directory))
    def test_unsupported_raw_report_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'demo';p.mkdir();(p/'report.html').write_text('modified')
            receipt={'byte_identical_reports':True,'repeated_runs':[{'report_sha256':{'report.html':'0'*64}},{'report_sha256':{'report.html':'0'*64}}]}
            with self.assertRaises(ValueError):verify_reports({'id':'demo'},receipt,Path(directory))

if __name__=='__main__':unittest.main()
