"""Inspector's omission flag is a nonempty environment string, not a Boolean.

Reference: modelcontextprotocol/inspector docs/environment-variables.md.
These tests separate valid literal environment strings from invalid typed
configuration, unknown expansion results, and inert reference text.
"""
import json
import tempfile
import unittest
from pathlib import Path

from ai_security_scan.analyzer import analyze_file
from ai_security_scan.image_assessment import assess_image


KEY = "DANGEROUSLY_OMIT_AUTH"


class InspectorAuthValueTests(unittest.TestCase):
    def check(self, path, source, expected):
        findings = [item for item in analyze_file(path, source) if item["rule_id"] == "AI041"]
        self.assertEqual(bool(findings), expected, (path, source, findings))
        if findings:
            self.assertTrue(all(item["confidence"] == "high" for item in findings))

    def test_python_assignments_nonempty_including_false_zero_and_whitespace(self):
        for value in ("false", "0", "true", "1", "anything", " "):
            for target in (KEY, "settings." + KEY, 'os.environ["%s"]' % KEY):
                with self.subTest(value=value, target=target):
                    self.check("agent.py", "import os\n%s = %r\n" % (target, value), True)

    def test_python_dict_update_putenv_and_known_local_string(self):
        for expression in (
            "settings = {%r: 'false'}" % KEY,
            "os.environ.update({%r: '0'})" % KEY,
            "os.environ.update(%s='false')" % KEY,
            "os.putenv(%r, '0')" % KEY,
            "from os import putenv as set_env\nset_env(%r, 'false')" % KEY,
            "value = 'false'\nos.environ[%r] = value" % KEY,
        ):
            with self.subTest(expression=expression):
                self.check("agent.py", "import os\n" + expression, True)

    def test_python_invalid_types_empty_and_dynamic_are_not_proof(self):
        for value in ("''", "False", "True", "0", "1", "None", "[]", "{}", "load_setting()"):
            for expression in ("os.environ[%r] = %s" % (KEY, value), "settings = {%r: %s}" % (KEY, value), "os.environ.update(%s=%s)" % (KEY, value)):
                with self.subTest(expression=expression):
                    self.check("agent.py", "import os\n" + expression, False)
        self.check("agent.py", "import os\ndel os.environ[%r]" % KEY, False)

    def test_python_inert_reference_and_unrelated_function_keyword(self):
        self.check("agent.py", "# %s='false'\nhelp = %r\n" % (KEY, KEY + "='false'"), False)
        self.check("agent.py", "document(%s='false')" % KEY, False)

    def test_json_and_jsonc_actual_strings(self):
        for value in ("false", "0", "true", "1", "custom", " "):
            for path in ("mcp.json", "mcp.jsonc"):
                for data in ({KEY: value}, {"mcpServers": {"inspector": {"env": {KEY: value}}}}):
                    with self.subTest(path=path, data=data):
                        self.check(path, json.dumps(data), True)

    def test_json_empty_unset_and_invalid_nonstring_env_types(self):
        self.check("mcp.json", '{"mcpServers": {}}', False)
        for value in ("", None, False, True, 0, 1, [], {}):
            with self.subTest(value=value):
                self.check("mcp.json", json.dumps({"env": {KEY: value}}), False)

    def test_json_reference_text_is_inert(self):
        for path in ("mcp.json", "mcp.jsonc"):
            self.check(path, json.dumps({"description": KEY + "=false", "example": KEY + "=true"}), False)
        self.check("mcp.jsonc", "// %s=true\n{}" % KEY, False)

    def test_javascript_object_properties_and_setters(self):
        for value in ("'false'", '"0"', "`false`", "' '", '"\\u0030"'):
            for source in ("const env = {%s: %s};" % (KEY, value), "const env = {'%s': %s};" % (KEY, value), "process.env.%s = %s;" % (KEY, value), "process.env['%s'] = %s;" % (KEY, value)):
                with self.subTest(source=source):
                    self.check("agent.ts", source, True)

    def test_node_process_env_scalar_values_are_stringified(self):
        for value in ("false", "true", "0", "1", "0.0", "null", "undefined"):
            with self.subTest(value=value):
                self.check("agent.js", "process.env.%s = %s;" % (KEY, value), True)
                self.check("agent.js", "process.env['%s'] = %s;" % (KEY, value), True)
                self.check("agent.js", "const config={%s:%s};" % (KEY, value), False)

    def test_javascript_empty_unset_dynamic_and_reference(self):
        for source in (
            "process.env.%s = '';" % KEY,
            "delete process.env.%s;" % KEY,
            "process.env.%s = dynamicValue;" % KEY,
            "process.env.%s = `prefix${dynamicValue}`;" % KEY,
            "const help = '%s=false';" % KEY,
            "const help = /%s=true/;" % KEY,
            "/* %s: 'false' */" % KEY,
            "const env = {%s: 'false'.slice(0, 0)};" % KEY,
        ):
            with self.subTest(source=source):
                self.check("agent.js", source, False)

    def test_dotenv_ini_and_shell_text_values(self):
        for path in (".env", ".env.local", "agent.env", "agent.ini", "agent.cfg", "agent.sh", "agent.bash", "agent.zsh"):
            for value in ("false", "0", "true", "1", "custom", "' '"):
                with self.subTest(path=path, value=value):
                    self.check(path, "%s=%s\n" % (KEY, value), True)

    def test_config_quoted_values_and_yaml_plain_strings(self):
        for path in ("agent.yaml", "agent.yml", "agent.toml"):
            for value in ("'false'", '"0"', "' '", '"anything"'):
                with self.subTest(path=path, value=value):
                    self.check(path, "  %s%s %s\n" % (KEY, "=" if path.endswith("toml") else ":", value), True)
        self.check("agent.yaml", "env:\n  %s: disabled\n" % KEY, True)
        for value in ("false", "0", "true", "1"):
            self.check("compose.yaml", "environment:\n  - %s=%s\n" % (KEY, value), True)

    def test_config_empty_null_typed_and_expansion_values_not_proof(self):
        for path in ("agent.yaml", "agent.yml", "agent.toml"):
            for value in ("''", '""', "false", "true", "0", "1", "null", "[]", "{}", '"${UNKNOWN}"'):
                with self.subTest(path=path, value=value):
                    self.check(path, "%s%s %s\n" % (KEY, "=" if path.endswith("toml") else ":", value), False)
        for path in (".env", "agent.sh", "Dockerfile"):
            for value in ("", "''", '""', "$UNKNOWN", '"${UNKNOWN}"', "$(get_value)"):
                with self.subTest(path=path, value=value):
                    self.check(path, ("ENV " if path == "Dockerfile" else "") + KEY + "=" + value + "\n", False)

    def test_docker_env_legacy_and_multiple_assignments(self):
        for source in (
            "ENV %s=false" % KEY,
            "ENV %s false" % KEY,
            "ENV %s='0'" % KEY,
            "ENV OTHER=ordinary %s=0" % KEY,
            "RUN %s=false node inspector.js" % KEY,
            "RUN export %s=false" % KEY,
        ):
            with self.subTest(source=source):
                self.check("Dockerfile", source, True)

    def test_shell_exports_prefix_assignments_and_powershell(self):
        for source in ("export %s=false" % KEY, "env %s=0 node inspector" % KEY, "OTHER=ordinary %s=false node inspector" % KEY):
            with self.subTest(source=source):
                self.check("entrypoint.sh", source, True)
        self.check("start.ps1", "$env:%s = 'false'" % KEY, True)

    def test_config_and_shell_docs_references_comments_and_key_case(self):
        for path, source in (
            ("agent.yaml", "description: '%s=false'" % KEY),
            ("agent.yaml", "# %s=true" % KEY),
            ("entrypoint.sh", 'echo "%s=false"' % KEY),
            ("entrypoint.sh", 'printf "%s=true"' % KEY),
            ("Dockerfile", 'LABEL description="%s=true"' % KEY),
            ("Dockerfile", 'RUN echo "%s=false"' % KEY),
            ("README.md", "%s=false" % KEY),
            (".env", "dangerously_omit_auth=false"),
            (".env", "OTHER_%s=false" % KEY),
            (".env", "%s_OTHER=false" % KEY),
        ):
            with self.subTest(path=path, source=source):
                self.check(path, source, False)

    def test_unrelated_boolean_auth_and_permission_flags_keep_semantics(self):
        for path, source in (
            ("agent.js", "const config={dangerouslyAllowBrowser:false, dangerouslySkipPermissions:false, tokenPassthrough:false};"),
            ("mcp.json", '{"dangerouslyAllowBrowser":false,"dangerouslySkipPermissions":false,"tokenPassthrough":false}'),
        ):
            with self.subTest(path=path):
                rules = {item["rule_id"] for item in analyze_file(path, source)}
                self.assertFalse(rules.intersection({"AI028", "AI030", "AI031", "AI041"}))

    def test_yaml_literal_and_folded_documentation_is_inert(self):
        for marker in ("|", "|-", "|+", "|2", ">", ">-2"):
            with self.subTest(marker=marker):
                source = "description: %s\n  %s=false\n\n  %s: '0'\n" % (marker, KEY, KEY)
                self.check("mcp.yaml", source, False)
                findings = [item for item in analyze_file("mcp.yaml", source + "%s: 'false'\n" % KEY) if item["rule_id"] == "AI041"]
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["line"], 5)

    def test_image_runtime_env_strings_and_old_history_is_not_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for value in ("false", "0", "true", "custom", " ", ""):
                with self.subTest(value=value):
                    materialized = {"root": root, "config": {"config": {"User": "1001", "Env": [KEY + "=" + value]}, "history": [{"created_by": "ENV %s=false" % KEY}]}, "identity": {"format": "oci", "config_digest": "sha256:" + "a" * 64, "platform": "linux/amd64", "layers": []}, "entries": [], "layer_files": [], "coverage": {}}
                    report = assess_image(materialized)
                    findings = [item for item in report["findings"] if item["rule_id"] == "AI041"]
                    runtime = [item for item in findings if item["image_context"] == "runtime_configuration"]
                    history = [item for item in findings if item["image_context"] == "build_history"]
                    self.assertEqual(len(runtime), 1 if value else 0)
                    # The image assessor intentionally limits old history to
                    # supply-chain/secret rules; only current Env proves this.
                    self.assertEqual(len(history), 0)
                    self.assertFalse(report["coverage"]["errors"])


if __name__ == "__main__":
    unittest.main()
