"""Independent Python regression pairs for bounded local source analysis.

These exercise transformations of working code, not just rule regex matches.
They do not assert interprocedural or whole-program taint-analysis guarantees.
"""
import unittest
from unittest.mock import patch

from ai_security_scan.analyzer import analyze_file


def rules(source):
    return {finding["rule_id"] for finding in analyze_file("agent.py", source)}


class PythonAccuracyTests(unittest.TestCase):
    def assert_pair(self, rule, unsafe, safer):
        self.assertIn(rule, rules(unsafe), unsafe)
        self.assertNotIn(rule, rules(safer), safer)

    def test_callable_alias_and_rebinding(self):
        self.assert_pair("AI002", "import subprocess\nlaunch = subprocess.run\nlaunch(user_input, shell=True)",
                         "import subprocess\nlaunch = subprocess.run\nlaunch = lambda *a, **kw: None\nlaunch(user_input, shell=True)")

    def test_module_rebinding(self):
        self.assert_pair("AI002", "import subprocess\nsubprocess.run(user_input, shell=True)",
                         "import subprocess\nsubprocess = object()\nsubprocess.run(user_input, shell=True)")

    def test_parameter_shadowing(self):
        for parameter in ("subprocess", "eval", "open"):
            body = {"subprocess": "subprocess.run(user_input, shell=True)", "eval": "eval(user_input)", "open": "open(user_path)"}[parameter]
            rule = {"subprocess": "AI002", "eval": "AI001", "open": "AI015"}[parameter]
            self.assertNotIn(rule, rules("import subprocess\ndef tool(" + parameter + "):\n    " + body))

    def test_local_rebinding_is_lexically_scoped(self):
        source = "import subprocess\ndef tool():\n    subprocess.run(user_input, shell=True)\n    subprocess = object()\n"
        # Runtime raises UnboundLocalError before reaching a subprocess call.
        self.assertNotIn("AI002", rules(source))
        self.assertIn("AI002", rules(source + "subprocess.run(user_input, shell=True)\n"))

    def test_builtin_rebinding_and_sibling_function_scope(self):
        self.assertNotIn("AI001", rules("def eval(text):\n    return text\neval(user_input)"))
        self.assertIn("AI001", rules("def render():\n    eval = lambda text: text\n    eval(user_input)\ndef execute():\n    eval(user_input)"))

    def test_lambda_scope(self):
        self.assertNotIn("AI001", rules("handler = lambda eval: eval(user_input)"))
        self.assertIn("AI001", rules("handler = lambda text: eval(text)"))

    def test_known_literal_shell_commands(self):
        for expr in ('"echo fixed"', 'f"echo fixed"', '"echo " + "fixed"', '"echo {}".format("fixed")', '"echo %s" % "fixed"'):
            self.assertNotIn("AI002", rules("import subprocess\ncommand = " + expr + "\nsubprocess.run(command, shell=True)"))
        self.assertIn("AI002", rules("import subprocess\ncommand = 'echo ' + user_input\nsubprocess.run(command, shell=True)"))

    def test_static_interpolation_and_dynamic_template_pair(self):
        self.assert_pair("AI039", "from flask import render_template_string\nbody = f'<p>{user_input}</p>'\nrender_template_string(body)",
                         "from flask import render_template_string\nbody = '<p>{{ value }}</p>'\nrender_template_string(body, value=user_input)")

    def test_keyword_sinks(self):
        self.assert_pair("AI015", "open(file=request.args['path'])", "open(file='/tmp/fixed')")
        self.assert_pair("AI003", "import os\nos.system(command=user_input)", "import os\nos.system(command='echo fixed')")
        self.assert_pair("AI002", "import asyncio\nasyncio.create_subprocess_shell(cmd=user_input)", "import asyncio\nasyncio.create_subprocess_shell(cmd='echo fixed')")
        self.assert_pair("AI014", "from urllib.request import urlopen\nurlopen(url=user_url)", "from urllib.request import urlopen\nurlopen(url='https://example.com')")

    def test_static_keyword_configuration_propagates(self):
        self.assert_pair("AI002", "import subprocess\nuse_shell = True\nsubprocess.run(user_input, shell=use_shell)",
                         "import subprocess\nuse_shell = False\nsubprocess.run(user_input, shell=use_shell)")

    def test_assigned_sql_interpolation(self):
        for expression in ("f'SELECT * FROM records WHERE id={user_input}'", "'SELECT * FROM records WHERE id=' + user_input", "'SELECT * FROM records WHERE id={}'.format(user_input)"):
            self.assertIn("AI036", rules("statement = " + expression + "\nalias = statement\ncursor.execute(alias)"))
        self.assertNotIn("AI036", rules("statement = 'SELECT * FROM records WHERE id=?'\ncursor.execute(statement, (user_input,))"))

    def test_static_sql_concatenation_is_not_injection(self):
        for expression in ("'SELECT ' + '1'", "f'SELECT {1}'", "'SELECT {}'.format(1)", "'SELECT %d' % 1"):
            self.assertNotIn("AI036", rules("cursor.execute(" + expression + ")"))

    def test_augmented_assignment_source_and_sql(self):
        self.assertIn("AI014", rules("import requests\ntarget = 'https://example.com/'\ntarget += user_input\nrequests.get(target)"))
        self.assertIn("AI036", rules("query = 'SELECT * FROM records WHERE id='\nquery += user_input\ncursor.execute(query)"))

    def test_tuple_assignment_preserves_sources(self):
        self.assertIn("AI014", rules("import requests\ntarget, label = user_url, 'fixed'\nrequests.get(target)"))
        self.assertNotIn("AI014", rules("import requests\ntarget, user_url = 'https://example.com', 'fixed'\nrequests.get(target)"))

    def test_external_names_can_be_overwritten_with_safe_values(self):
        self.assert_pair("AI014", "import requests\nrequests.get(user_url)", "import requests\nuser_url = 'https://example.com'\nrequests.get(user_url)")
        self.assertNotIn("AI014", rules("import requests\ntarget = user_url\ndef tool(target):\n    requests.get(target)"))

    def test_if_else_order_cannot_erase_possible_source(self):
        for body in ("    target = user_url\nelse:\n    target = 'https://example.com'", "    target = 'https://example.com'\nelse:\n    target = user_url"):
            self.assertIn("AI014", rules("import requests\nif condition:\n" + body + "\nrequests.get(target)"))
        self.assertNotIn("AI014", rules("import requests\nif condition:\n    target = 'https://example.com'\nelse:\n    target = 'https://example.org'\nrequests.get(target)"))

    def test_branch_join_preserves_callable_alias(self):
        self.assertIn("AI002", rules("import subprocess\nif condition:\n    launch = subprocess.run\nelse:\n    launch = lambda *a, **kw: None\nlaunch(user_input, shell=True)"))

    def test_loop_zero_iteration_preserves_source(self):
        self.assertIn("AI014", rules("import requests\ntarget = user_url\nfor unused in items:\n    target = 'https://example.com'\nrequests.get(target)"))

    def test_loop_target_tracks_source(self):
        self.assertIn("AI014", rules("import requests\nfor target in request.json['urls']:\n    requests.get(target)"))

    def test_safe_loader_requires_known_origin(self):
        self.assert_pair("AI004", "import yaml\nclass SafeLoader(yaml.UnsafeLoader):\n    pass\nyaml.load(payload, Loader=SafeLoader)",
                         "import yaml\nfrom yaml import SafeLoader as Restricted\nyaml.load(payload, Loader=Restricted)")
        self.assertIn("AI004", rules("import yaml\nSafeLoader = yaml.UnsafeLoader\nyaml.load(payload, Loader=SafeLoader)"))

    def test_unrelated_http_like_method_is_not_a_tls_client(self):
        self.assert_pair("AI006", "import requests\nrequests.get(url, verify=False)", "class RecordStore:\n    def get(self, key, verify=True):\n        return key\nstore = RecordStore()\nstore.get('record', verify=False)")

    def test_function_call_rhs_keeps_previous_binding(self):
        self.assertIn("AI001", rules("eval = eval(user_input)"))

    def test_alias_transformations_preserve_sink_detection(self):
        for import_line, call in (("import subprocess", "subprocess.run"), ("import subprocess as processes", "processes.run"), ("from subprocess import run as launch", "launch"), ("import subprocess\nlaunch = subprocess.run", "launch")):
            for command in ("user_input", "f'echo {user_input}'", "'echo ' + user_input"):
                source = import_line + "\n" + call + "(" + command + ", shell=True)"
                self.assertIn("AI002", rules(source))
                self.assertNotIn("AI002", rules(source.replace("shell=True", "shell=False")))

    def test_container_mutation_cannot_make_a_false_constant_proof(self):
        self.assertIn("AI002", rules("import subprocess\ncommand = ['echo', 'fixed']\ncommand[0] = user_input\nsubprocess.run(command, shell=True)"))
        self.assertIn("AI014", rules("import requests\ntargets = ['https://example.com']\ntargets[0] = user_url\nrequests.get(targets[0])"))
        self.assertIn("AI014", rules("import requests\ntargets = []\ntargets.append(user_url)\nrequests.get(targets[0])"))

    def test_comprehension_bindings_are_local(self):
        self.assertNotIn("AI001", rules("callbacks = [eval(user_input) for eval in functions]"))
        self.assertIn("AI001", rules("def tool():\n    callbacks = [eval for eval in functions]\n    eval(user_input)"))
        self.assertIn("AI014", rules("import requests\nresponses = [requests.get(target) for target in request.json['urls']]"))

    def test_class_attributes_do_not_shadow_method_globals(self):
        self.assertIn("AI001", rules("class Tool:\n    eval = lambda text: text\n    def run(self):\n        eval(user_input)"))
        self.assertNotIn("AI001", rules("class Tool:\n    def run(self, eval):\n        eval(user_input)"))

    def test_exception_paths_keep_possible_external_sources(self):
        self.assertIn("AI014", rules("import requests\ntarget = user_url\ntry:\n    target = 'https://example.com'\nexcept Exception:\n    pass\nrequests.get(target)"))
        self.assertIn("AI014", rules("import requests\ntarget = 'https://example.com'\ntry:\n    target = user_url\n    may_raise()\n    target = 'https://example.com'\nexcept Exception:\n    requests.get(target)"))
        self.assertNotIn("AI014", rules("import requests\ntarget = user_url\ntry:\n    may_raise()\nfinally:\n    target = 'https://example.com'\nrequests.get(target)"))

    def test_assignment_expressions_and_parallel_assignment(self):
        self.assertIn("AI014", rules("import requests\nif (target := user_url):\n    requests.get(target)"))
        self.assertIn("AI014", rules("import requests\nleft, right = user_url, 'https://example.com'\nleft, right = right, left\nrequests.get(right)"))
        self.assertNotIn("AI014", rules("import requests\nleft, right = user_url, 'https://example.com'\nleft, right = right, left\nrequests.get(left)"))

    def test_conditional_literals_preserve_possible_insecure_flags(self):
        for left, right in (("True", "False"), ("False", "True")):
            branch = "if condition:\n    enabled = " + left + "\nelse:\n    enabled = " + right + "\n"
            self.assertIn("AI002", rules("import subprocess\n" + branch + "subprocess.run(user_input, shell=enabled)"))
            self.assertIn("AI006", rules("import requests\n" + branch + "requests.get(url, verify=enabled)"))
            self.assertIn("AI026", rules(branch + "MCPServer(auth=enabled)"))
        self.assertNotIn("AI002", rules("import subprocess\nif condition:\n    enabled = False\nelse:\n    enabled = False\nsubprocess.run(user_input, shell=enabled)"))

    def test_source_promotion_and_flags_follow_constant_aliases(self):
        self.assertIn("AI032", rules("role = 'system'\nmessages = [{'role': role, 'content': user_input}]"))
        self.assertIn("AI026", rules("require_auth = False\nconfig = {'auth': require_auth}"))

    def test_annotation_and_assignment_target_calls_are_still_analyzed(self):
        for source in ("value: eval(user_input)", "def tool(value: eval(user_input)):\n    pass", "mapping[eval(user_input)] = 1", "mapping[eval(user_input)] += 1"):
            self.assertIn("AI001", rules(source))

    def test_analysis_budget_exhaustion_is_an_explicit_error(self):
        with patch("ai_security_scan.analyzer._PythonAnalyzer._MAX_WORK", 20):
            with self.assertRaisesRegex(ValueError, "work budget.*coverage is incomplete"):
                rules("\n".join("value_%d = 'fixed'" % index for index in range(50)))
        with patch("ai_security_scan.analyzer._PythonAnalyzer._MAX_ALTERNATIVES", 2):
            with self.assertRaisesRegex(ValueError, "literal alternative limit"):
                rules("value = 0\nif first:\n    value = 1\nif second:\n    value = 2")


if __name__ == "__main__":
    unittest.main()
