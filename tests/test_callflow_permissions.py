"""Actual source-to-sink and least-permission contracts, including hard gaps."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.analyzer import analyze_file, analyze_file_errors
from ai_security_scan.scanner import scan


ROOT = Path(__file__).resolve().parents[1]


def detected(source, rule="AI014", path="worker.py"):
    return [finding for finding in analyze_file(path, source) if finding["rule_id"] == rule]


class CallFlowAndPermissionsTests(unittest.TestCase):
    def test_frozen_original_accuracy_labels_are_unchanged(self):
        self.assertEqual(hashlib.sha256((ROOT / "benchmarks/static_accuracy.json").read_bytes()).hexdigest(),
                         "eb7f1eba93f8e9842634cbd12687dde5bea879505d99d367621214583e54dde3")

    def test_separate_development_corpus_has_paired_supported_results(self):
        corpus = json.loads((ROOT / "benchmarks/callflow_permissions_accuracy.json").read_text())
        for case in corpus["cases"]:
            if case["suite"] != "regression":
                continue
            with self.subTest(case=case["id"]):
                errors = []
                rules = {item["rule_id"] for item in analyze_file(case["path"], case["source"], analysis_errors=errors)}
                self.assertEqual(errors, [])
                for rule, expected in case["expect"].items():
                    self.assertEqual(rule in rules, expected)

    def test_known_challenges_remain_visible_without_relabeling(self):
        corpus = json.loads((ROOT / "benchmarks/callflow_permissions_accuracy.json").read_text())
        challenges = [case for case in corpus["cases"] if case["suite"] == "challenge"]
        self.assertEqual(len(challenges), 2)
        for case in challenges:
            self.assertTrue(case["expect"]["AI014"])
            self.assertFalse(detected(case["source"], path=case["path"]))

    def test_flow_findings_cite_sink_and_bound_chain(self):
        source = "import requests\ndef retrieve(address):\n    return requests.get(address)\ndef outer(value):\n    return retrieve(value)\nouter(user_url)\n"
        finding, = detected(source)
        self.assertEqual(finding["line"], 3)
        self.assertIn("outer -> retrieve", finding["description"])
        self.assertIn("requests.get(address)", finding["evidence"])

    def test_defaults_capture_definition_time_values(self):
        dangerous = "import requests\ndefault = user_url\ndef retrieve(address=default):\n    return requests.get(address)\ndefault = 'https://fixed.example'\nretrieve()"
        safe = "import requests\ndefault = 'https://fixed.example'\ndef retrieve(address=default):\n    return requests.get(address)\ndefault = user_url\nretrieve()"
        self.assertTrue(detected(dangerous))
        self.assertFalse(detected(safe))

    def test_module_binding_is_not_callers_shadowed_local(self):
        source = "import requests\ndef retrieve(address):\n    return requests.get(address)\ndef caller():\n    requests=safe\n    return retrieve(user_url)\ncaller()"
        self.assertTrue(detected(source))

    def test_later_global_function_binding_is_visible_when_called(self):
        source = "import requests\ndef outer(value):\n    return inner(value)\ndef inner(value):\n    return requests.get(value)\nouter(user_url)"
        self.assertTrue(detected(source))

    def test_nested_closure_reads_parent_cell_at_call_time(self):
        template = "import requests\ndef outer(value):\n    def inner():\n        return requests.get(value)\n    value=%s\n    return inner()\nouter(%s)"
        self.assertTrue(detected(template % ("user_url", "'https://fixed.example'")))
        self.assertFalse(detected(template % ("'https://fixed.example'", "user_url")))

    def test_async_function_creation_is_not_execution(self):
        source = "import requests\nasync def retrieve(value):\n    return requests.get(value)\nretrieve(user_url)"
        errors = []
        findings = analyze_file("worker.py", source, analysis_errors=errors)
        self.assertNotIn("AI014", {item["rule_id"] for item in findings})
        self.assertTrue(any("not directly awaited" in error for error in errors))
        source = source.rsplit("retrieve(user_url)", 1)[0] + "async def caller():\n    return await retrieve(user_url)\nawait caller()"
        self.assertTrue(detected(source))

    def test_generator_creation_and_global_side_effects_are_explicit_gaps(self):
        generator = "import requests\ndef retrieve(value):\n    yield requests.get(value)\nretrieve(user_url)"
        errors = []
        findings = analyze_file("worker.py", generator, analysis_errors=errors)
        self.assertNotIn("AI014", {item["rule_id"] for item in findings})
        self.assertTrue(any("iteration context" in error for error in errors))
        source = "import requests\ntarget='https://fixed.example'\ndef change():\n    global target\n    target=user_url\nchange()\nrequests.get(target)"
        self.assertTrue(any("side-effect propagation" in error for error in analyze_file_errors("worker.py", source)))

    def test_branch_join_keeps_unsafe_alternative(self):
        source = "import requests\ndef retrieve(address):\n    if choose:\n        address='https://fixed.example'\n    return requests.get(address)\nretrieve(user_url)"
        self.assertTrue(detected(source))

    def test_guard_on_attribute_or_mutable_list_is_not_a_proof(self):
        for condition in ("request.url == 'https://fixed.example'", "user_url in ['https://fixed.example']", "user_url != 'https://fixed.example'"):
            argument = "request.url" if "request.url" in condition else "user_url"
            with self.subTest(condition=condition):
                self.assertTrue(detected("import requests\nif " + condition + ":\n    requests.get(" + argument + ")"))

    def test_branch_guard_negative_exit_and_else_paths(self):
        safe = "import requests\ndef retrieve(address):\n    if address != 'https://fixed.example':\n        raise ValueError()\n    return requests.get(address)\nretrieve(user_url)"
        unsafe = "import requests\ndef retrieve(address):\n    if address != 'https://fixed.example':\n        log(address)\n    return requests.get(address)\nretrieve(user_url)"
        self.assertFalse(detected(safe))
        self.assertTrue(detected(unsafe))

    def test_recursion_keeps_direct_findings_and_reports_gap(self):
        source = "import requests\nrequests.get(user_url)\ndef recur(value):\n    return recur(value)\nrecur(user_url)"
        errors = []
        findings = analyze_file("worker.py", source, analysis_errors=errors)
        self.assertIn("AI014", {item["rule_id"] for item in findings})
        self.assertTrue(any("recursion/depth" in error for error in errors))
        self.assertEqual(analyze_file_errors("worker.py", source), errors)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "worker.py").write_text(source)
            report = scan(directory)
            self.assertTrue(report["coverage"]["errors"])
            self.assertIn("AI014", {item["rule_id"] for item in report["findings"]})

    def test_depth_and_expansion_caps_are_explicit(self):
        chain = "import requests\n" + "\n".join("def f%s(value):\n    return f%s(value)" % (i, i + 1) for i in range(9))
        chain += "\ndef f9(value):\n    return requests.get(value)\nf0(user_url)"
        errors = []
        analyze_file("worker.py", chain, analysis_errors=errors)
        self.assertTrue(any("depth" in error for error in errors))
        source = "def identity(value):\n    return value\n" + "\n".join("identity(%s)" % i for i in range(514))
        errors = []
        analyze_file("worker.py", source, analysis_errors=errors)
        self.assertTrue(any("expansion budget" in error for error in errors))

    def test_splats_are_explicit_gaps_and_other_checks_continue(self):
        source = "import requests\ndef retrieve(address):\n    return requests.get(address)\nretrieve(*tool_args)\nrequests.get(user_url)"
        errors = []
        findings = analyze_file("worker.py", source, analysis_errors=errors)
        self.assertTrue(any("argument expansion" in error for error in errors))
        self.assertIn("AI014", {item["rule_id"] for item in findings})

    def test_js_recursive_summary_is_incomplete(self):
        source = "function one(v) { return two(v); } function two(v) { return one(v); } one(req.body.url); fetch(userUrl);"
        errors = []
        findings = analyze_file("worker.ts", source, analysis_errors=errors)
        self.assertTrue(any("recursion/depth" in error for error in errors))
        self.assertIn("AI014", {item["rule_id"] for item in findings})

    def test_chmod_modes_and_unknown_platform_behavior(self):
        sources = ["import os\nos.fchmod(fd, 0o602)", "import os\nos.lchmod('workspace', mode=0o002)",
                   "from pathlib import Path\nPath('workspace').lchmod(mode=0o777)",
                   "import os\nmode=0o600\nif share:\n    mode=0o666\nos.chmod('workspace',mode)"]
        for source in sources:
            with self.subTest(source=source):
                finding, = detected(source, "AI047")
                self.assertIn("ACLs", finding["description"])
        for source in ("import os\nos.chmod('workspace',-1)", "import os\nos.chmod('workspace',0o77777)",
                       "import os\nmode=0o777\nmode=0o700\nos.chmod('workspace',mode)"):
            self.assertFalse(detected(source, "AI047"))

    def test_scanning_never_invokes_target_or_network(self):
        source = "import requests\ndef retrieve(address):\n    return requests.get(address)\nretrieve(user_url)"
        with patch("subprocess.Popen", side_effect=AssertionError("No target execution")), patch("socket.create_connection", side_effect=AssertionError("No network")):
            self.assertTrue(detected(source))

    def test_registered_python_tools_seed_input_and_preserve_safe_defaults(self):
        source = "from fastmcp import FastMCP\nimport requests\nservice = FastMCP('demo')\ndef transport(destination):\n    return requests.get(destination)\n@service.tool()\ndef lookup(address: str):\n    return transport(address)"
        self.assertTrue(detected(source))
        self.assertFalse(detected(source.replace("transport(address)", "transport('https://fixed.example')")))
        self.assertFalse(detected(source.replace("service = FastMCP('demo')", "service = Fake('demo')")))

    def test_generic_decorators_and_rebound_frameworks_do_not_seed_inputs(self):
        body = "import requests\n%s\ndef lookup(address: str):\n    return requests.get(address)"
        for decorator in ("@tool()", "@other.tool()", "mcp = fake\n@mcp.tool()", "server = fake\n@server.tool()"):
            self.assertFalse(detected(body % decorator))
        self.assertTrue(detected(body % "@mcp.tool()"))

    def test_imported_tool_decorator_and_injected_context(self):
        source = "from langchain_core.tools import tool as registered\nimport requests\n@registered\ndef lookup(address: str):\n    return requests.get(address)"
        self.assertTrue(detected(source))
        source = "from fastmcp import FastMCP, Context\nimport requests\nmcp=FastMCP('demo')\n@mcp.tool()\ndef lookup(context: Context):\n    return requests.get(context)"
        self.assertFalse(detected(source))

    def test_literal_mapping_proof_is_invalidated_by_mutation_or_escape(self):
        prefix = "@mcp.tool()\ndef read_file(name: str):\n    paths={'help':'/srv/help.txt'}\n"
        self.assertFalse(detected(prefix + "    return open(paths[name]).read()", "AI015"))
        for mutation in ("paths[name]=name", "paths.update({name:name})", "paths.__setitem__('help',name)", "modify(paths)", "alias=paths\n    alias[name]=name", "paths |= {name:name}"):
            with self.subTest(mutation=mutation):
                self.assertTrue(detected(prefix + "    " + mutation + "\n    return open(paths[name]).read()", "AI015"))
        self.assertTrue(detected(prefix + "    paths.__setitem__('help',name)\n    return open(paths['help']).read()", "AI015"))

    def test_registered_js_callback_parameters_and_imported_filesystem_alias(self):
        source = "import {readFile as readLocal} from 'node:fs/promises'; const helper = filename => readLocal(filename, 'utf8'); server.registerTool('read', {inputSchema:{path:z.string()}}, async ({path: filename}) => helper(filename));"
        self.assertTrue(detected(source, "AI015", "server.ts"))
        self.assertFalse(detected(source.replace("helper(filename));", "helper('/srv/help.txt'));"), "AI015", "server.ts"))

    def test_registered_js_callback_braces_and_whole_argument(self):
        source = "const transport=(destination)=>fetch(destination); server.registerTool('fetch', {inputSchema:{url:z.string()}}, async (args) => { return transport(args.url); });"
        self.assertTrue(detected(source, path="server.ts"))
        self.assertFalse(detected(source.replace("args.url", "'https://fixed.example'"), path="server.ts"))

    def test_js_registration_requires_literal_shape_and_unshadowed_receiver(self):
        template = "const transport=(destination)=>fetch(destination); %s server.registerTool(%s, %s, async ({url})=>transport(url));"
        for before, name, config in (("const server=fake;", "'fetch'", "{inputSchema:{}}"), ("", "dynamic", "{inputSchema:{}}"), ("", "'fetch'", "{description:'helper'}")):
            self.assertFalse(detected(template % (before, name, config), path="server.ts"))
        known = "import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js'; const server=new McpServer({name:'test'});"
        self.assertTrue(detected(template % (known, "'fetch'", "{inputSchema:{}}"), path="server.ts"))

    def test_js_complex_registered_parameters_are_explicit_gaps(self):
        source = "server.registerTool('fetch',{inputSchema:{}},async ({url='https://fixed.example'})=>fetch(url));"
        self.assertTrue(any("parameters" in error for error in analyze_file_errors("server.ts", source)))
        for parameter in ("", "{}"):
            source = "server.registerTool('fixed',{inputSchema:{}},async (" + parameter + ")=>fetch('https://fixed.example'));"
            self.assertEqual(analyze_file_errors("server.ts", source), [])
            self.assertFalse(detected(source, path="server.ts"))
        self.assertEqual(analyze_file_errors("server.ts", "server.registerTool('metadata',{inputSchema:{},description:'Read data'},handler);"), [])


if __name__ == "__main__":
    unittest.main()
