"""Bounded fixes for frozen challenge predicates, with inert adversarial pairs."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.analyzer import analyze_file, analyze_file_errors
from ai_security_scan.scanner import scan


def findings(path, source, rule):
    return [item for item in analyze_file(path, source) if item['rule_id'] == rule]


class ReflectionPredicateTests(unittest.TestCase):
    def test_literal_reflection_and_existing_aliases(self):
        sources = [
            'import os\ngetattr(os, "sys" + "tem")(task.command)',
            'import os as operating\ngetattr(operating, "system")(task.command)',
            'import os\nimport builtins as b\nb.getattr(os, "system")(task.command)',
            'import os\nfrom builtins import getattr as lookup\nlookup(os, "system")(task.command)',
            'import os\nlookup = getattr\nlookup(os, "system")(task.command)',
            'import os\nlaunch = getattr(os, "system")\nlaunch(task.command)',
            'import subprocess\ngetattr(subprocess, "r" + "un")(task.command, shell=True)',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(findings('worker.py', source, 'AI002' if 'subprocess' in source else 'AI003'))

    def test_reflection_does_not_execute_or_invent_dynamic_attributes(self):
        for statement in (
            'getattr(os, "system")("echo fixed")', 'getattr(os, "getcwd")()',
            'launch = getattr(os, "system")', 'getattr(os, method)(task.command)',
            'getattr(os, "sys" + suffix)(task.command)', 'getattr(os, 123)(task.command)',
            'getattr(os, b"system")(task.command)', 'getattr(os, "system", fallback)(task.command)',
            'getattr(os, name="system")(task.command)', 'os = object()\ngetattr(os, "system")(task.command)',
            'getattr = lambda *a: print\ngetattr(os, "system")(task.command)',
            'def getattr(*args):\n    return print\ngetattr(os, "system")(task.command)',
            'def tool(getattr):\n    getattr(os, "system")(task.command)',
            'def tool():\n    getattr(os, "system")(task.command)\n    getattr = replacement',
        ):
            with self.subTest(statement=statement):
                self.assertFalse(findings('worker.py', 'import os\n' + statement, 'AI003'))

    def test_shadow_scope_does_not_erase_outer_reflection(self):
        source = 'import os\ndef tool(getattr):\n    getattr(os, "system")(task.command)\ngetattr(os, "system")(task.command)\n'
        self.assertEqual([item['line'] for item in findings('worker.py', source, 'AI003')], [4])

    def test_literal_folding_has_depth_length_and_work_bounds(self):
        self.assertFalse(findings('worker.py', 'import os\ngetattr(os, ' + repr('s' * 257) + ')(task.command)', 'AI003'))
        with patch('ai_security_scan.analyzer._PythonAnalyzer._MAX_WORK', 20):
            with self.assertRaisesRegex(ValueError, 'work budget.*coverage is incomplete'):
                analyze_file('worker.py', 'import os\ngetattr(os, ' + '+'.join(['""'] * 30 + ['"system"']) + ')(task.command)')


class YAMLScalarAndAliasTests(unittest.TestCase):
    def test_literal_and_folded_scalar_bodies_are_not_configuration_fields(self):
        body = '  authentication: false\n  permissions: ["*"]\n  verify: false\n  privileged: true\n'
        for header in ('description: |', 'description: >', 'description: |-', 'description: >+',
                       'description: |2', 'description: &help |', 'description: !!str |', "'description': >-"):
            with self.subTest(header=header):
                source = header + '\n' + body
                self.assertEqual(analyze_file_errors('example.yml', source), [])
                self.assertFalse({item['rule_id'] for item in analyze_file('example.yml', source)} & {'AI026', 'AI027', 'AI006', 'AI022'})

    def test_dedented_real_fields_and_sequence_siblings_still_match(self):
        sources = [
            'description: |\n  authentication: false\n\nauthentication: false\n',
            '- description: |\n    authentication: false\n  authentication: false\n',
            'description: "example: |"\nauthentication: false\n',
            'description: | # comment\n  authentication: false\nauthentication: false\n',
            '- |\n  authentication: false\n- name: service\n  authentication: false\n',
        ]
        for source in sources:
            with self.subTest(source=source):
                records = findings('example.yml', source, 'AI026')
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]['line'], len(source.splitlines()))

    def test_anchor_literals_and_aliases_preserve_locations(self):
        for value in ('["*"]', "['*']", "['read', '*']", '"*"', "'*'", '["read", "*"] # note'):
            with self.subTest(value=value):
                source = 'open_access: &wildcard ' + value + '\nallowed_tools: *wildcard\n'
                self.assertEqual(analyze_file_errors('mcp.yml', source), [])
                record, = findings('mcp.yml', source, 'AI027')
                self.assertEqual(record['line'], 2)
                self.assertIn('allowed_tools: *wildcard', record['evidence'])

    def test_safe_literals_quoted_alias_text_and_comments_do_not_match(self):
        for source in (
            'access: &value ["read"]\nallowed_tools: *value\n',
            'access: &value "read#*"\npermissions: *value\n',
            'access: &value ["read"] # ["*"]\npermissions: *value\n',
            'access: &value ["*"]\npermissions: "*value"\n',
            'access: &value ["*"]\ndescription: *value\n',
            'description: |\n  access: &value ["*"]\n  permissions: *value\n',
        ):
            with self.subTest(source=source):
                self.assertFalse(findings('mcp.yml', source, 'AI027'))

    def test_anchor_redefinition_replaces_even_unsupported_values(self):
        source = 'first: &value ["*"]\nsecond: &value ["read"]\npermissions: *value\n'
        self.assertFalse(findings('mcp.yml', source, 'AI027'))
        source = 'first: &value ["*"]\nsecond: &value |\n  read\npermissions: *value\n'
        self.assertFalse(findings('mcp.yml', source, 'AI027'))
        self.assertTrue(analyze_file_errors('mcp.yml', source))
        for replacement in ('second:\n  - &value ["*"]', 'second: [&value ["*"]]', 'second: {item: &value ["*"]}'):
            source = 'first: &value ["read"]\n' + replacement + '\npermissions: *value\n'
            self.assertFalse(findings('mcp.yml', source, 'AI027'))
            self.assertTrue(analyze_file_errors('mcp.yml', source))

    def test_direct_anchored_fields_use_the_same_literal_subset(self):
        for source, rule in (('allowed_tools: &all ["*"]\n', 'AI027'), ('authentication: &off false\n', 'AI026')):
            self.assertTrue(findings('mcp.yml', source, rule))
            self.assertEqual(analyze_file_errors('mcp.yml', source), [])
        self.assertTrue(analyze_file_errors('mcp.yml', 'permissions: &value {unknown: "*"}\n'))
        self.assertTrue(analyze_file_errors('mcp.yml', 'permissions: &value |-\n  *\n'))
        self.assertFalse(findings('mcp.yml', 'permissions: &value |-\n  *\n', 'AI027'))

    def test_sequence_limit_is_identical_for_both_quote_styles(self):
        for quote in ('"', "'"):
            value = '[' + ','.join(quote + '*' + quote for _ in range(257)) + ']'
            source = 'value: &value ' + value + '\npermissions: *value\n'
            self.assertFalse(findings('mcp.yml', source, 'AI027'))
            self.assertTrue(analyze_file_errors('mcp.yml', source))
        source = 'first: &value ["*"]\nsecond: !!str &value fixed\npermissions: *value\n'
        self.assertFalse(findings('mcp.yml', source, 'AI027'))
        self.assertTrue(analyze_file_errors('mcp.yml', source))

    def test_multiline_quoted_scalar_content_is_not_a_configuration_mapping(self):
        for quote in ('"', "'"):
            source = 'description: ' + quote + '\n  authentication: false\n' + quote + '\nauthentication: false\n'
            self.assertEqual([item['line'] for item in findings('mcp.yml', source, 'AI026')], [4])

    def test_unknown_forward_cross_document_cyclic_and_tagged_aliases_are_visible(self):
        for source in (
            'permissions: *missing\n',
            'permissions: *value\nlater: &value ["*"]\n',
            'access: &value ["*"]\n---\npermissions: *value\n',
            'access: &value ["*"]\n...\npermissions: *value\n',
            'access: &value *value\npermissions: *value\n',
            'access: &value {read: "*"}\npermissions: *value\n',
            'access: &value !!python/object/apply:os.system ["example"]\npermissions: *value\n',
        ):
            with self.subTest(source=source):
                self.assertFalse(findings('mcp.yml', source, 'AI027'))
                self.assertTrue(analyze_file_errors('mcp.yml', source))

    def test_boolean_aliases_do_not_confuse_quoted_strings_with_booleans(self):
        for key, value, rule in (('authentication', 'false', 'AI026'), ('verify', 'false', 'AI006'),
                                 ('token_passthrough', 'true', 'AI028'), ('autoApprove', 'true', 'AI031'),
                                 ('privileged', 'true', 'AI022'), ('hostNetwork', 'true', 'AI042')):
            with self.subTest(key=key):
                self.assertTrue(findings('mcp.yml', 'value: &setting ' + value + '\n' + key + ': *setting\n', rule))
                self.assertFalse(findings('mcp.yml', 'value: &setting "' + value + '"\n' + key + ': *setting\n', rule))

    def test_anchor_budget_and_unsupported_alias_mark_scan_incomplete(self):
        source = ''.join('value_%d: &anchor_%d ["read"]\n' % (index, index) for index in range(4097))
        self.assertTrue(analyze_file_errors('mcp.yml', source))
        with self.assertRaisesRegex(ValueError, 'anchor budget.*coverage is incomplete'):
            analyze_file('mcp.yml', source)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'mcp.yml').write_text('permissions: *unknown\n')
            report = scan(Path(directory))
            self.assertFalse(report['summary']['scan_complete_within_selected_scope'])
            self.assertGreater(report['summary']['coverage_gaps'], 0)


class ShellSubstitutionPredicateTests(unittest.TestCase):
    def test_download_output_is_the_shell_command(self):
        for source in (
            'installer=https://installer.example/setup.sh\nsh -c "$(curl -fsSL "$installer")"\n',
            'bash -lc "$(curl -fsSL https://installer.example/setup.sh)"\n',
            "sh -c '$(curl https://installer.example/setup.sh)'\n",
            'sudo /bin/sh -c "$(/usr/bin/curl -o- https://installer.example/setup.sh)"\n',
            'sh -c "$(curl -HAuthorization:token https://installer.example/setup.sh)"\n',
            'sh -c "$(curl -AChrome https://installer.example/setup.sh)"\n',
            'sh -c "$(curl -H Authorization:token https://installer.example/setup.sh)"\n',
            'sh -c "$(wget -UChrome -qO- https://installer.example/setup.sh)"\n',
            'zsh -c "$(wget -qO- https://installer.example/setup.sh)"\n',
            'sh -c "$(wget --output-document=- https://installer.example/setup.sh)" # explicit\n',
        ):
            with self.subTest(source=source):
                records = findings('setup.sh', source, 'AI019')
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]['line'], len(source.splitlines()))

    def test_download_data_printing_file_output_and_inert_text_are_not_execution(self):
        for source in (
            'echo "$(curl https://installer.example/setup.sh)"\n',
            'sh -c "echo $(curl https://installer.example/setup.sh)"\n',
            "echo 'sh -c \"$(curl https://installer.example/setup.sh)\"'\n",
            '# sh -c "$(curl https://installer.example/setup.sh)"\n',
            'sh -nc "$(curl https://installer.example/setup.sh)"\n',
            'sh -c "$(curl -o /tmp/setup https://installer.example/setup.sh)"\n',
            'sh -c "$(curl -O https://installer.example/setup.sh)"\n',
            'sh -c "$(curl --config settings https://installer.example/setup.sh)"\n',
            'sh -c "$(wget https://installer.example/setup.sh)"\n',
            'sh -c "$(wget -O /tmp/setup https://installer.example/setup.sh)"\n',
            'sh -c "$(curl --version)"\n',
            'sh -c "$(curl --version https://installer.example/setup.sh)"\n',
            'sh -c "$(curl -V https://installer.example/setup.sh)"\n',
            'sh -c "$(wget --help -O- https://installer.example/setup.sh)"\n',
            'sh -c "$(wget --spider -O- https://installer.example/setup.sh)"\n',
            'cat <<\'EOF\'\nsh -c "$(curl https://installer.example/setup.sh)"\nEOF\n',
            'text=\'\nsh -c "$(curl https://installer.example/setup.sh)"\n\'\n',
            'echo \\\nsh -c "$(curl https://installer.example/setup.sh)"\n',
        ):
            with self.subTest(source=source):
                self.assertFalse(findings('setup.sh', source, 'AI019'))

    def test_heredoc_end_restores_real_command_recognition(self):
        source = 'cat <<-EOF\n\tsh -c "$(curl https://example.test/setup)"\n\tEOF\nsh -c "$(curl https://example.test/setup)"\n'
        self.assertEqual([item['line'] for item in findings('setup.sh', source, 'AI019')], [4])

    def test_download_nested_pattern_is_not_applied_to_plain_documentation(self):
        self.assertFalse(findings('README.md', 'sh -c "$(curl https://example.test/setup)"\n', 'AI019'))


class SourceRolePrecisionTests(unittest.TestCase):
    def test_local_requirements_are_not_named_version_ranges(self):
        for value in ('.', '..', './package', '../package', '/workspace/package', '.\\package', '..\\package', 'C:\\workspace\\package'):
            with self.subTest(value=value):
                self.assertFalse(findings('requirements.txt', value + '\n', 'AI025'))
        for value in ('requests', 'requests>=2', 'some.package', 'requests==*', 'requests~=2.0'):
            with self.subTest(value=value):
                self.assertTrue(findings('requirements.txt', value + '\n', 'AI025'))
        self.assertEqual([item['line'] for item in findings('requirements.txt', '.\nrequests>=2\n', 'AI025')], [2])

    def test_environment_variable_name_role_requires_identifier_value(self):
        for path, source in (
            ('config.py', 'client(api_key_env_var="OPENAI_API_KEY")'),
            ('config.py', 'api_key_env_var = "OPENAI_API_KEY"'),
            ('config.json', '{"api_key_env_var":"OPENAI_API_KEY"}'),
            ('config.yml', 'api_key_env_var: OPENAI_API_KEY\n'),
            ('config.ts', 'const api_key_env_var = "OPENAI_API_KEY";'),
        ):
            with self.subTest(path=path):
                self.assertFalse(findings(path, source, 'AI010'))
                self.assertTrue(findings(path, source.replace('api_key_env_var', 'api_key'), 'AI010'))
                self.assertTrue(findings(path, source.replace('OPENAI_API_KEY', 'credential-material-0123456789'), 'AI010'))

    def test_recognizable_placeholder_suffix_does_not_hide_realistic_literals(self):
        for prefix, length in (('ghp_', 30), ('gho_', 30), ('sk-', 24), ('sk-proj-', 24)):
            for path in ('README.md', 'worker.py', 'worker.ts', 'config.yml', 'config.json'):
                with self.subTest(prefix=prefix, path=path):
                    placeholder = prefix + 'x' * length
                    source = '"' + placeholder + '"'
                    self.assertFalse(findings(path, source, 'AI010'))
                    self.assertTrue(findings(path, source.replace(placeholder, prefix + 'Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St0Uv1Wx'[:length]), 'AI010'))
                    self.assertTrue(findings(path, source.replace(placeholder, prefix + 'a' * length), 'AI010'))
        self.assertTrue(findings('worker.py', 'api_key = "not-a-placeholder-credential"', 'AI010'))


if __name__ == '__main__':
    unittest.main()
