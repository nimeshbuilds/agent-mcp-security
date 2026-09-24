"""Regression tests for security evidence and important secure counterexamples."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.analyzer import analyze_file, analyze_file_errors
from ai_security_scan.rules import RULES


def ids(source, path="agent.py"):
    return {item["rule_id"] for item in analyze_file(path, source)}


class PythonRuleTests(unittest.TestCase):
    def test_python_rule_examples(self):
        cases = [
            ("AI001", "eval(user_input)"),
            ("AI002", "import subprocess\nsubprocess.run(user_input, shell=True)"),
            ("AI003", "import os\nos.system(user_input)"),
            ("AI004", "import yaml\nyaml.load(payload, Loader=yaml.UnsafeLoader)"),
            ("AI005", "import pickle\npickle.loads(payload)"),
            ("AI006", "import requests\nrequests.get(url, verify=False)"),
            ("AI007", "app.add_middleware(CORSMiddleware, allow_origins=['*'])"),
            ("AI008", "server.run(host='0.0.0.0')"),
            ("AI009", "app.run(debug=True)"),
            ("AI010", "client_secret = 'real-looking-secret-123456789'"),
            ("AI014", "import requests\nrequests.get(request.args['url'])"),
            ("AI015", "open(request.args['path'])"),
            ("AI016", "import tempfile\nfilename = tempfile.mktemp()"),
            ("AI017", "import jwt\njwt.decode(token, options={'verify_signature': False})"),
            ("AI026", "MCPServer(auth=False)"),
            ("AI027", "Agent(allowed_tools=['*'])"),
            ("AI028", "MCPServer(token_passthrough=True)"),
            ("AI032", "messages = [{'role': 'system', 'content': tool_result}]"),
            ("AI033", "logger.info('credential: %s', api_key)"),
            ("AI035", "import torch\ntorch.load(model_path, weights_only=False)"),
            ("AI036", "cursor.execute(f'SELECT * FROM users WHERE id={user_input}')"),
            ("AI037", "tar.extractall(destination)"),
            ("AI038", "import random\naccess_token = str(random.getrandbits(128))"),
            ("AI039", "from flask import render_template_string\nrender_template_string(user_input)"),
        ]
        for rule, source in cases:
            with self.subTest(rule=rule):
                self.assertIn(rule, ids(source))

    def test_aliased_imports_and_multiline_calls(self):
        source = "from subprocess import run as launch\nlaunch(\n    user_input,\n    shell=True,\n)\n"
        finding = next(item for item in analyze_file("agent.py", source) if item["rule_id"] == "AI002")
        self.assertEqual(2, finding["line"])
        self.assertEqual(5, finding["end_line"])
        self.assertEqual("high", finding["confidence"])

    def test_alias_yaml_safe_loader(self):
        self.assertNotIn("AI004", ids("from yaml import load, SafeLoader as SL\nload(payload, Loader=SL)"))
        self.assertIn("AI004", ids("from yaml import unsafe_load as load\nload(payload)"))

    def test_secure_python_counterexamples(self):
        source = '''
import subprocess, yaml, requests, jwt, secrets, torch, random
subprocess.run(['echo', user_input], shell=False)
subprocess.run('echo fixed', shell=True)
yaml.safe_load(payload)
yaml.load(payload, Loader=yaml.SafeLoader)
requests.get('https://example.com', verify=True)
app.run(host='127.0.0.1', debug=False)
jwt.decode(token, key, algorithms=['RS256'], audience='mcp-server')
cursor.execute('SELECT * FROM users WHERE id = ?', (user_input,))
tar.extractall(destination, filter='data')
access_token = secrets.token_urlsafe(32)
jitter = random.random()
torch.load(model_path, weights_only=True)
open('/tmp/fixed-output.txt')
logger.info('request completed: %s', request_id)
messages = [{'role': 'system', 'content': 'Only execute approved tools.'},
            {'role': 'user', 'content': user_input}]
'''
        self.assertEqual(set(), ids(source))

    def test_taint_tracks_local_assignments(self):
        source = "import requests\ndef tool(request):\n    target = request.json['url']\n    requests.get(target)"
        self.assertIn("AI014", ids(source))

    def test_http_session_and_async_context_manager(self):
        source = "import httpx\nasync def tool(request):\n    async with httpx.AsyncClient() as client:\n        await client.get(request.query_params['url'])"
        self.assertIn("AI014", ids(source))

    def test_explicit_shell_and_asyncio_shell(self):
        self.assertIn("AI002", ids("import subprocess\nsubprocess.run(['/bin/sh', '-c', user_input], shell=False)"))
        self.assertIn("AI002", ids("import asyncio\nasyncio.create_subprocess_shell(user_input)"))
        self.assertNotIn("AI002", ids("import subprocess\nsubprocess.run(['/bin/sh', '-c', 'echo fixed'], shell=False)"))

    def test_tar_object_tracking_and_zip_exclusion(self):
        self.assertIn("AI037", ids("import tarfile\nwith tarfile.open(path) as archive:\n    archive.extractall(output)"))
        self.assertNotIn("AI037", ids("import zipfile\nwith zipfile.ZipFile(path) as archive:\n    archive.extractall(output)"))
        self.assertNotIn("AI037", ids("some_other_library.extractall(output)"))

    def test_taint_does_not_leak_between_functions(self):
        source = "import requests\ndef first(request):\n    target = request.json['url']\ndef second():\n    target = 'https://example.com'\n    requests.get(target)"
        self.assertNotIn("AI014", ids(source))

    def test_taint_cleared_when_value_replaced(self):
        source = "import requests\ntarget = request.args['url']\ntarget = 'https://example.com'\nrequests.get(target)"
        self.assertNotIn("AI014", ids(source))

    def test_comments_do_not_trigger_ast_rules(self):
        self.assertEqual(set(), ids("# eval(user_input)\n# requests.get(url, verify=False)\n"))

    def test_parse_failure_is_coverage_error(self):
        source = "def invalid(\n    eval(user_input)"
        self.assertEqual([], analyze_file("broken.py", source))
        self.assertIn("AST-based checks were skipped", analyze_file_errors("broken.py", source)[0])

    def test_deep_parseable_ast_surfaces_visitor_resource_failure(self):
        source = "x = " + "+".join(["1"] * 1500)
        self.assertTrue(any("coverage is incomplete" in error for error in analyze_file_errors("deep.py", source)))
        with self.assertRaises(RecursionError):
            analyze_file("deep.py", source)

    def test_visitor_resource_failures_mark_scan_incomplete(self):
        from ai_security_scan.scanner import scan

        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "deep.py").write_text("x = " + "+".join(["1"] * 1500), encoding="utf-8")
            report = scan(directory)
            self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])
            self.assertTrue(any(error["kind"] == "analysis_error" for error in report["coverage"]["errors"]))
        with patch("ai_security_scan.analyzer._PythonAnalyzer.visit", side_effect=MemoryError):
            with self.assertRaisesRegex(ValueError, "exceeded available memory"):
                analyze_file("small.py", "x = 1")

    def test_surprising_but_valid_ast_does_not_crash(self):
        for source in ("jwt.decode(x, algorithms=True)", "x = {**other}", "x = {[1]: 2}", "x = None", "f(**kwargs)"):
            with self.subTest(source=source):
                analyze_file("edge.py", source)


class JavaScriptRuleTests(unittest.TestCase):
    def test_javascript_rule_examples(self):
        cases = [
            ("AI012", "import {exec} from 'node:child_process';\nexec(userInput);"),
            ("AI013", "const result = eval(userInput);"),
            ("AI006", "const client = new Agent({rejectUnauthorized: false});"),
            ("AI007", "app.use(cors({origin: '*'}));"),
            ("AI008", "app.listen(8000, '0.0.0.0');"),
            ("AI010", "const apiKey = 'real-looking-secret-123456789';"),
            ("AI014", "const result = await fetch(req.body.url);"),
            ("AI015", "const result = fs.readFileSync(req.query.path);"),
            ("AI017", "jwt.verify(token, key, {algorithms: ['none']});"),
            ("AI026", "const config = {auth: false};"),
            ("AI027", "const config = {allowedTools: ['*']};"),
            ("AI028", "const config = {tokenPassthrough: true};"),
            ("AI030", "new Client({dangerouslyAllowBrowser: true});"),
            ("AI031", "const config = {bypassPermissions: true};"),
            ("AI032", "const messages = [{role: 'system', content: toolOutput}];"),
            ("AI033", "console.log('API credential', apiKey);"),
            ("AI036", "database.query(`SELECT * FROM users WHERE id=${userInput}`);"),
            ("AI040", "element.innerHTML = toolOutput;"),
        ]
        for rule, source in cases:
            with self.subTest(rule=rule):
                self.assertIn(rule, ids(source, "agent.ts"))

    def test_shell_exec_alias_and_namespace(self):
        examples = [
            "const {exec: run} = require('child_process');\nrun(userInput);",
            "import {execSync as run} from 'node:child_process';\nrun(userInput);",
            "import * as cp from 'node:child_process';\ncp.execSync(`echo ${userInput}`);",
            "const cp = require('node:child_process');\ncp.exec(\nuserInput\n);",
        ]
        for source in examples:
            self.assertIn("AI012", ids(source, "agent.js"))

    def test_regex_exec_and_execfile_not_shell_exec(self):
        source = "import {execFile} from 'child_process';\nregex.exec(userInput);\nexecFile('echo', [userInput]);"
        self.assertNotIn("AI012", ids(source, "agent.js"))

    def test_fixed_shell_command_not_reported_as_dynamic(self):
        self.assertNotIn("AI012", ids("import {exec} from 'child_process';\nexec('echo fixed');", "agent.js"))
        self.assertNotIn("AI012", ids("import {exec} from 'child_process';\nexec(`echo fixed`);", "agent.js"))

    def test_comments_are_masked_and_urls_preserved(self):
        source = "// eval(userInput)\n/* client = {rejectUnauthorized: false}; */\nconst url = 'https://example.com';\nfetch(url);"
        self.assertEqual(set(), ids(source, "agent.js"))


class ConfigurationRuleTests(unittest.TestCase):
    def test_all_config_rules(self):
        cases = [
            ("AI011", "secret.pem", "-----BEGIN PRIVATE KEY-----\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"),
            ("AI018", ".mcp.json", json.dumps({"mcpServers": {"demo": {"command": "npx", "args": ["-y", "@vendor/mcp-server"]}}})),
            ("AI019", "install.sh", "curl https://example.com/install.sh | bash"),
            ("AI020", ".github/workflows/test.yml", "steps:\n  - uses: actions/checkout@v4"),
            ("AI021", "Dockerfile", "FROM python:3.12\nUSER root"),
            ("AI022", "compose.yaml", "services:\n  agent:\n    privileged: true"),
            ("AI023", "compose.yaml", "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock"),
            ("AI024", "Dockerfile", "FROM python:3.12"),
            ("AI025", "requirements.txt", "fastmcp>=2.0"),
            ("AI026", "mcp.json", '{"authentication": false}'),
            ("AI027", "mcp.json", '{"permissions": ["*"]}'),
            ("AI028", "mcp.json", '{"token_passthrough": true}'),
            ("AI029", "mcp.json", '{"mcpServers": {"demo": {"url": "http://example.com/mcp"}}}'),
            ("AI030", "config.json", '{"dangerouslyAllowBrowser": true}'),
            ("AI031", "agent.json", '{"sandbox_mode": "danger-full-access"}'),
            ("AI034", "settings.env", "URL=https://example.com/mcp?access_token=liveToken0123456789"),
            ("AI041", "mcp.json", '{"DANGEROUSLY_OMIT_AUTH": "true"}'),
            ("AI042", "compose.yml", "network_mode: host"),
        ]
        for rule, path, source in cases:
            with self.subTest(rule=rule):
                self.assertIn(rule, ids(source, path))

    def test_exact_mcp_runner_versions(self):
        for command, args in [("npx", ["-y", "@vendor/server@1.2.3"]), ("uvx", ["server==1.2.3"]), ("uvx", ["--from", "server==1.2.3", "server"])]:
            source = json.dumps({"mcpServers": {"demo": {"command": command, "args": args}}})
            self.assertNotIn("AI018", ids(source, "mcp.json"))

    def test_unrestricted_auto_approval(self):
        for value in [True, ["*"], ["read_resource", "*"]]:
            source = json.dumps({"mcpServers": {"demo": {"autoApprove": value}}})
            with self.subTest(value=value):
                self.assertIn("AI031", ids(source, "mcp.json"))
        for value in [False, [], ["read_resource"], ["all"], "*"]:
            source = json.dumps({"mcpServers": {"demo": {"autoApprove": value}}})
            with self.subTest(value=value):
                self.assertNotIn("AI031", ids(source, "mcp.json"))

    def test_auto_approval_javascript_yaml_and_python(self):
        cases = [
            ("agent.ts", "const config = {autoApprove: true};"),
            ("agent.ts", "const config = {autoApprove: ['read_resource', '*']};"),
            ("agent.ts", "const config = {autoApprove: [\n'read_resource',\n'*'\n]};"),
            ("mcp.yml", "autoApprove: true"),
            ("mcp.yml", "auto_approve: ['read_resource', '*']"),
            ("mcp.yml", "server:\n  autoApprove:\n    - read_resource\n    - '*'\n  auth: true\n"),
            ("agent.py", "Agent(auto_approve=['*'])"),
            ("agent.py", "config = {'autoApprove': True}"),
        ]
        for path, source in cases:
            with self.subTest(path=path, source=source):
                self.assertIn("AI031", ids(source, path))
        secure = [
            ("agent.ts", "const config = {autoApprove: ['read_resource']};"),
            ("agent.ts", "const config = {autoApprove: false};"),
            ("mcp.yml", "autoApprove: ['read_resource']"),
            ("mcp.yml", "autoApprove:\n  - read_resource\nother:\n  - '*'\n"),
            ("agent.py", "Agent(auto_approve=['read_resource'])"),
        ]
        for path, source in secure:
            with self.subTest(path=path, source=source):
                self.assertNotIn("AI031", ids(source, path))

    def test_mcp_mutable_runner_versions(self):
        for command, args in [("npx", ["-y", "@vendor/server@latest"]), ("uvx", ["--from", "server>=1.0", "server"]), ("uvx", ["--python", "3.12", "server"])]:
            source = json.dumps({"mcpServers": {"demo": {"command": command, "args": args}}})
            self.assertIn("AI018", ids(source, "mcp.json"))

    def test_jsonc_comments_and_multiline_configuration(self):
        source = '''{
  // local tool declaration
  "mcpServers": {
    "demo": {
      "url": "https://example.com/mcp",
      "allowed_tools": ["*"]
    }
  }
}'''
        self.assertEqual([], analyze_file_errors("mcp.jsonc", source))
        finding = next(item for item in analyze_file("mcp.jsonc", source) if item["rule_id"] == "AI027")
        self.assertEqual(6, finding["line"])
        self.assertNotIn("AI029", ids(source, "mcp.jsonc"))

    def test_malformed_json_surfaces_coverage_gap(self):
        source = '{"mcpServers": {"demo": {"auth": false},'
        self.assertNotIn("AI026", ids(source, "mcp.json"))
        self.assertIn("structured configuration checks were skipped", analyze_file_errors("mcp.json", source)[0])

    def test_absence_of_auth_is_not_a_vulnerability(self):
        self.assertNotIn("AI026", ids('{"mcpServers": {"demo": {"url": "https://example.com/public"}}}', "mcp.json"))
        self.assertNotIn("AI026", ids("from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('public')"))

    def test_plain_http_is_allowed_on_loopback_only(self):
        for host in ["localhost", "127.0.0.1", "127.9.3.2", "[::1]"]:
            source = json.dumps({"mcpServers": {"demo": {"url": "http://" + host + ":3000/mcp"}}})
            self.assertNotIn("AI029", ids(source, "mcp.json"))
        self.assertIn("AI029", ids('{"mcpServers": {"demo": {"url": "http://localhost.evil.test/mcp"}}}', "mcp.json"))

    def test_environment_references_are_not_secrets(self):
        for value in ["${OPENAI_API_KEY}", "$OPENAI_API_KEY", "<api-key-here>", "your_api_key_here", "test-secret"]:
            source = json.dumps({"api_key": value})
            self.assertNotIn("AI010", ids(source, "settings.json"))

    def test_credentials_in_env_and_authorization_header(self):
        self.assertIn("AI010", ids("OPENAI_API_KEY=notARealKeyButRealistic0123456789", ".env"))
        self.assertIn("AI010", ids('{"headers":{"Authorization":"Bearer realisticToken1234567890"}}', "mcp.json"))

    def test_exact_requirements_and_hashed_actions(self):
        self.assertNotIn("AI025", ids("mcp==1.2.3\nrequests==2.32.4 --hash=sha256:abcd\n# example\n", "requirements.txt"))
        self.assertNotIn("AI020", ids("steps:\n  - uses: actions/checkout@" + "a" * 40, ".github/workflows/check.yml"))
        self.assertNotIn("AI020", ids("steps:\n  - uses: ./local-action", ".github/workflows/check.yml"))

    def test_docker_multistage_internal_references(self):
        source = "FROM python@sha256:" + "a" * 64 + " AS base\nFROM base AS build\nUSER app\n"
        self.assertEqual(set(), ids(source, "Dockerfile"))
        self.assertNotIn("AI024", ids("FROM scratch", "Dockerfile"))

    def test_package_json_lockfile_caveat(self):
        results = analyze_file("package.json", '{"dependencies": {"mcp-sdk": "^1.0.0", "fixed": "2.0.1"}}')
        deps = [item for item in results if item["rule_id"] == "AI025"]
        self.assertEqual(1, len(deps))
        self.assertIn("lockfile", deps[0]["description"])


class ContractTests(unittest.TestCase):
    def test_unique_and_complete_rule_metadata(self):
        self.assertEqual(47, len(RULES))
        self.assertEqual(len(RULES), len({item["id"] for item in RULES}))
        for rule in RULES:
            self.assertTrue({"id", "title", "severity", "description", "remediation", "category", "cwe", "references"}.issubset(rule))
            self.assertTrue(rule["references"])

    def test_finding_contract_and_stability(self):
        source = "eval(user_input)\neval(tool_result)\n"
        first = analyze_file("agent.py", source)
        self.assertEqual(first, analyze_file("agent.py", source))
        required = {"rule_id", "title", "severity", "confidence", "path", "line", "end_line", "evidence", "description", "remediation", "category", "cwe", "references"}
        for finding in first:
            self.assertTrue(required.issubset(finding))
            self.assertIsInstance(finding["line"], int)
            self.assertLessEqual(len(finding["evidence"]), 1000)

    def test_empty_files(self):
        for path in ("empty.py", "empty.ts", "empty.yaml", "empty.txt"):
            self.assertEqual([], analyze_file(path, ""))


if __name__ == "__main__":
    unittest.main()
