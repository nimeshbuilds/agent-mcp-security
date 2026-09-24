import json, unittest
from pathlib import Path
from ai_security_scan.analyzer import analyze_file, analyze_file_errors

class InstructionExtensionTests(unittest.TestCase):
    def test_development_extensions_keep_all_explicit_labels(self):
        root=Path(__file__).resolve().parents[1]
        corpus=json.loads((root/'benchmarks/instruction_extensions-v015.json').read_text())
        self.assertEqual(len(corpus['cases']),31)
        for case in corpus['cases']:
            with self.subTest(case=case['id']):
                self.assertEqual(analyze_file_errors(case['path'],case['source']),[])
                found={f['rule_id'] for f in analyze_file(case['path'],case['source'])}
                for rule,expected in case['expect'].items(): self.assertEqual(rule in found, expected)

    def test_schema_scope_correction_preserves_inputs_and_all_other_labels(self):
        root=Path(__file__).resolve().parents[1]
        before=json.loads((root/'benchmarks/skills_tools_accuracy.json').read_text())
        after=json.loads((root/'benchmarks/skills_tools_accuracy-v110.json').read_text())
        self.assertEqual(len(before['cases']),len(after['cases']))
        changed=[]
        for a,b in zip(before['cases'],after['cases']):
            self.assertEqual((a['id'],a['path'],a['source']),(b['id'],b['path'],b['source']))
            for rule,value in a['expect'].items():
                if value != b['expect'][rule]:changed.append((a['id'],rule,value,b['expect'][rule]))
        self.assertEqual(changed,[('hierarchy-json-schema-field','AI043',False,True)])
