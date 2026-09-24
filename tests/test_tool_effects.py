import unittest
from ai_security_scan.analyzer import analyze_file, analyze_file_errors

class ToolEffectTests(unittest.TestCase):
    def rules(self, source):
        return {f['rule_id'] for f in analyze_file('server.py', source)}

    def test_declared_readonly_known_write_apis(self):
        for imports, body in [('import os', "os.remove('cache.txt')"),
                              ('import os as fs', "fs.replace('a','b')"),
                              ('from shutil import rmtree as erase', "erase('cache')"),
                              ('from pathlib import Path as P', "P('state').write_text('new')"),
                              ('import pathlib', "pathlib.Path('cache').unlink()")]:
            with self.subTest(body=body):
                src=imports+'\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    '+body
                self.assertIn('AI046', self.rules(src))

    def test_readonly_write_witness_is_at_effect_line(self):
        src='import os\n@mcp.tool(annotations={"readOnlyHint": True})\ndef inspect():\n    """Read metadata."""\n    os.remove("cache")\n'
        findings=[f for f in analyze_file('server.py',src) if f['rule_id']=='AI046']
        self.assertEqual([f['line'] for f in findings],[5])
        self.assertIn('os.remove', findings[0]['evidence'])

    def test_unambiguous_readonly_annotation_required(self):
        for annotations in ['{"readOnlyHint": False}', '{"readOnlyHint": "true"}', '{}',
                            '{"readOnlyHint":True, **flags}', '{"readOnlyHint":True,"readOnlyHint":False}']:
            with self.subTest(annotations=annotations):
                self.assertNotIn('AI046',self.rules('import os\n@mcp.tool(annotations='+annotations+')\ndef inspect():\n    os.remove("x")'))

    def test_shadowed_or_unknown_apis_are_not_known_writes(self):
        samples=[
            'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect(os):\n    os.remove("x")',
            'import os\nos = adapter\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    os.remove("x")',
            'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    os = adapter\n    os.remove("x")',
            'import os\nos.remove = fake\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    os.remove("x")',
            '@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    custom.remove("x")',
            'from pathlib import Path\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    return Path("x").read_text()',
            'from pathlib import Path\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    return Path.exists(path)',
            'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    def unused():\n        os.remove("x")\n    return "ready"',
            'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    if False:\n        os.remove("x")',
            'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    return "ready"\n    os.remove("x")',
        ]
        for src in samples:
            with self.subTest(src=src): self.assertNotIn('AI046', self.rules(src))

    def test_nested_tool_resolution_remains_gap(self):
        src='import os\nclass Server:\n    @mcp.tool(annotations={"readOnlyHint":True})\n    def inspect(self):\n        os.remove("x")'
        self.assertNotIn('AI046',self.rules(src))
        self.assertTrue(any('nested/class' in e for e in analyze_file_errors('server.py',src)))

    def test_effect_bound_exposes_remaining_scope(self):
        src='import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n'+('    print("x")\n'*4100)+'    os.remove("x")'
        self.assertTrue(any('20000 AST' in e for e in analyze_file_errors('server.py',src)))

    def test_mutating_tool_without_readonly_claim_is_not_conflict(self):
        self.assertNotIn('AI046',self.rules('import os\n@mcp.tool()\ndef erase():\n    os.remove("x")'))

    def test_import_order_rebinding_and_relative_imports_are_not_false_witnesses(self):
        samples = [
            '@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    os.remove("x")\n    import os',
            '@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    os.remove("x"); import os',
            'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    try:\n        work()\n    except Exception as os:\n        os.remove("x")',
            'import custom as fs\nimport os as fs\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    fs.remove("x")',
            'from .os import remove\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    remove("x")',
        ]
        for source in samples:
            with self.subTest(source=source): self.assertNotIn('AI046', self.rules(source))
        self.assertIn('AI046', self.rules('@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    import os\n    os.remove("x")'))

    def test_nested_definition_defaults_execute_but_function_body_does_not(self):
        for body in ('def unused(value=os.remove("x")):\n        return value',
                     'unused = lambda value=os.remove("x"): value'):
            source = 'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    ' + body
            with self.subTest(body=body): self.assertIn('AI046', self.rules(source))
        self.assertNotIn('AI046', self.rules('import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    def unused():\n        os.remove("x")'))

    def test_dead_constant_loops_and_dead_block_suffixes_are_not_writes(self):
        for body in ('while False:\n        os.remove("x")',
                     'if 0:\n        os.remove("x")',
                     'with guard:\n        return None\n        os.remove("x")',
                     'for value in values:\n        break\n        os.remove("x")'):
            source = 'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    ' + body
            with self.subTest(body=body): self.assertNotIn('AI046', self.rules(source))
        self.assertIn('AI046', self.rules('import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    while False:\n        pass\n    else:\n        os.remove("x")'))

    def test_nested_class_body_resolution_is_an_explicit_gap(self):
        source = 'import os\n@mcp.tool(annotations={"readOnlyHint":True})\ndef inspect():\n    class Local:\n        os.remove("x")'
        self.assertTrue(any('nested class-body' in item for item in analyze_file_errors('server.py', source)))
