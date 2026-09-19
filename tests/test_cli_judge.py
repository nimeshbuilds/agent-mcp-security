"""Process, protocol, configuration and disclosure boundaries for CLI judges."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from ai_security_scan import cli_judge as cj


class CLIConfigurationTests(unittest.TestCase):
    def test_defaults_for_all_providers_and_no_mutation(self):
        for provider in sorted(cj.CLI_PROVIDERS):
            original = {"provider": provider}
            validated = cj.validate_cli_config(original)
            self.assertEqual(original, {"provider": provider})
            self.assertEqual(validated["model"], cj.DEFAULT_CLI_MODELS[provider])
            self.assertEqual(validated["timeout_seconds"], 60)
            self.assertEqual(validated["executable"], provider[:-4])

    def test_reject_unsupported_configuration_and_bad_limits(self):
        for extra in ({"args": ["--dangerously-skip-permissions"]}, {"endpoint": "https://example.com"},
                      {"api_key": "secret"}, {"max_output_tokens": 10}, {"model": "--debug"},
                      {"model": "name\nsecret"}, {"executable": "../fake"}, {"executable": "fake.cmd"},
                      {"timeout_seconds": True}, {"timeout_seconds": float("nan")},
                      {"timeout_seconds": 0}, {"max_request_bytes": 100}, {"max_response_bytes": 6 * 1024 * 1024},
                      {"max_request_bytes": 2048.0}, {"model": "\ud800"}, {"cli_home": "/tmp"}):
            with self.subTest(extra=list(extra)), self.assertRaises(cj.CLIJudgeError):
                cj.validate_cli_config({"provider": "codex_cli", **extra})
        for value in (None, [], {}, {"provider": "community-grok"}):
            with self.assertRaises(cj.CLIJudgeError):
                cj.validate_cli_config(value)

    def test_grok_home_is_optional_and_absolute(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = cj.validate_cli_config({"provider": "grok_cli", "cli_home": directory})
            before = dict(os.environ)
            environment = cj._environment(cfg)
            self.assertEqual(environment["GROK_HOME"], directory)
            self.assertEqual(dict(os.environ), before)
        with self.assertRaises(cj.CLIJudgeError):
            cj.validate_cli_config({"provider": "grok_cli", "cli_home": "relative"})
        with self.assertRaises(cj.CLIJudgeError):
            cj._environment(cfg)

    def test_child_environment_excludes_unrelated_secrets_and_injection(self):
        with patch.dict(os.environ, {"API_SECRET": "secret", "OPENAI_API_KEY": "secret",
                                    "ANTHROPIC_API_KEY": "secret", "XAI_API_KEY": "secret",
                                    "NODE_OPTIONS": "--require=/malicious.js", "PYTHONPATH": "/bad",
                                    "HOME": "/identity", "CODEX_HOME": "/identity/.codex"}, clear=True):
            env = cj._environment({"provider": "codex_cli"})
        for key in ("API_SECRET", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY", "NODE_OPTIONS", "PYTHONPATH"):
            self.assertNotIn(key, env)
        self.assertEqual(env["HOME"], "/identity")
        self.assertEqual(env["CODEX_HOME"], "/identity/.codex")

    def test_bare_executable_drops_relative_and_current_path(self):
        absolute_bin = str(Path(sys.executable).resolve().parent)
        with patch.dict(os.environ, {"PATH": os.pathsep.join([".", "relative", str(Path.cwd()), absolute_bin])}), \
                patch.object(cj.shutil, "which", return_value=sys.executable) as which:
            cj._executable({"executable": "codex"})
            self.assertEqual(which.call_args.kwargs["path"], absolute_bin)
        with patch.object(cj.shutil, "which", return_value=None), self.assertRaises(cj.CLIJudgeError):
            cj._executable({"executable": "nonexistent"})


class CLIProtocolTests(unittest.TestCase):
    def test_valid_codex_and_all_terminal_failures(self):
        events = [{"type": "thread.started"}, {"type": "turn.started"},
                  {"type": "item.completed", "item": {"type": "reasoning", "text": "private reasoning"}},
                  {"type": "item.completed", "item": {"type": "agent_message", "text": '{"assessments":[]}'}},
                  {"type": "turn.completed"}]
        def encoded(rows):
            return b"\n".join(json.dumps(e).encode() for e in rows)
        self.assertEqual(cj._extract("codex_cli", encoded(events)), {"assessments": []})
        for addition in ({"type": "error", "message": "secret"}, {"type": "turn.failed"},
                         {"type": "item.completed", "item": {"type": "command_execution"}},
                         {"type": "item.started", "item": {"type": "mcp_tool_call"}},
                         {"type": "item.started", "item": []}, {"type": "new_unknown_event"}, []):
            with self.subTest(addition=addition), self.assertRaises(cj.CLIJudgeError):
                cj._extract("codex_cli", encoded(events + [addition]))
        with self.assertRaises(cj.CLIJudgeError):
            cj._extract("codex_cli", encoded(events[:-1]))
        with self.assertRaises(cj.CLIJudgeError):
            cj._extract("codex_cli", encoded([{"type": "turn.completed"}]))

    def test_claude_success_structured_output_and_failure(self):
        valid = {"type": "result", "subtype": "success", "is_error": False, "result": '{"assessments":[]}'}
        self.assertEqual(cj._extract("claude_cli", json.dumps(valid)), {"assessments": []})
        self.assertEqual(cj._extract("claude_cli", json.dumps({**valid, "structured_output": {"a": 1}})), {"a": 1})
        for update in ({"subtype": "error_max_turns"}, {"is_error": True}, {"type": "assistant"},
                       {"permission_denials": [{"tool": "Bash"}]}, {"tool_calls": [{}]}, {"result": []}):
            with self.subTest(update=update), self.assertRaises(cj.CLIJudgeError):
                cj._extract("claude_cli", json.dumps({**valid, **update}))

    def test_grok_output_and_incomplete_stop_reasons(self):
        valid = {"text": '{"assessments":[]}', "stopReason": "end_turn"}
        self.assertEqual(cj._extract("grok_cli", json.dumps(valid)), {"assessments": []})
        for reason in ("max_tokens", "max_turn_requests", "cancelled", "refusal", None):
            with self.assertRaises(cj.CLIJudgeError):
                cj._extract("grok_cli", json.dumps({**valid, "stopReason": reason}))

    def test_json_must_be_unambiguous(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', '{"a":"\\ud800"}',
                    '```json\n{}\n```', b'\xff', '{"nested":' + '[' * 3000):
            with self.subTest(raw=str(raw)[:40]), self.assertRaises(cj.CLIJudgeError):
                cj._loads(raw)

    def test_grok_extensions_fail_closed_and_do_not_leak_values(self):
        fields = ("hooks", "mcpServers", "lspServers", "plugins", "skills", "projectInstructions", "agents", "marketplaces")
        empty = {key: [] for key in fields}
        with patch.object(cj, "_run", return_value=json.dumps(empty).encode()):
            cj._grok_preflight("grok", Path("/tmp"), {}, time.monotonic() + 5)
        for key in fields:
            with patch.object(cj, "_run", return_value=json.dumps({**empty, key: [{"target": "secret_value"}]}).encode()):
                with self.assertRaises(cj.CLIJudgeError) as raised:
                    cj._grok_preflight("grok", Path("/tmp"), {}, time.monotonic() + 5)
                self.assertIn(key, str(raised.exception))
                self.assertNotIn("secret_value", str(raised.exception))
        with patch.object(cj, "_run", return_value=b'{}'), self.assertRaises(cj.CLIJudgeError):
            cj._grok_preflight("grok", Path("/tmp"), {}, time.monotonic() + 5)

    def test_command_capability_contract_and_prompt_privacy(self):
        prompt = b"highly private evidence"
        with tempfile.TemporaryDirectory() as directory:
            for provider in sorted(cj.CLI_PROVIDERS):
                argv, stdin = cj._command("official", provider, Path(directory), "default", prompt)
                self.assertNotIn(prompt.decode(), " ".join(argv))
                self.assertNotIn("--model", argv)
                self.assertNotIn("--dangerously-skip-permissions", argv)
                if provider == "grok_cli":
                    self.assertEqual(argv[argv.index("--tools") + 1], "Bash")
                    self.assertEqual(argv[argv.index("--disallowed-tools") + 1], "run_terminal_cmd,bash,search_tool,use_tool")
                    self.assertEqual(stdin, b"")
                    self.assertEqual((Path(directory) / "request.txt").read_bytes(), prompt)
                    if os.name == "posix":
                        self.assertEqual((Path(directory) / "request.txt").stat().st_mode & 0o777, 0o600)
                else:
                    self.assertEqual(stdin, prompt)
                if provider == "claude_cli":
                    self.assertIn("--safe-mode", argv)
                    self.assertNotIn("--bare", argv)
                    self.assertEqual(argv[argv.index("--tools") + 1], "")
                if provider == "codex_cli":
                    self.assertIn("--ignore-user-config", argv)
                    self.assertIn("shell_tool", argv)

    def test_probe_minimum_version_required_flags(self):
        for provider, version in (("codex_cli", b"codex-cli 0.154.0"),
                                  ("claude_cli", b"2.1.214 (Claude Code)"), ("grok_cli", b"grok 0.2.60 (hash)")):
            with patch.object(cj, "_run", side_effect=[version, b"--nothing"]), self.assertRaises(cj.CLIJudgeError):
                cj._probe("tool", provider, Path("/tmp"), {}, time.monotonic() + 5)

    def test_only_exact_expected_codex_startup_warning_is_accepted(self):
        warning = {"type": "item.completed", "item": {"type": "error", "message": cj._CODEX_DISABLED_WARNING}}
        final = [{"type": "turn.started"}, {"type": "item.completed", "item": {"type": "agent_message", "text": '{}'}}, {"type": "turn.completed"}]
        data = lambda rows: b"\n".join(json.dumps(x).encode() for x in rows)
        warnings = []
        self.assertEqual(cj._extract("codex_cli", data([warning] + final), warnings), {})
        self.assertEqual(warnings, ["codex_code_mode_intentionally_disabled"])
        with self.assertRaises(cj.CLIJudgeError):
            cj._extract("codex_cli", data(final + [warning]))
        warning["item"]["message"] += " injected text"
        with self.assertRaises(cj.CLIJudgeError):
            cj._extract("codex_cli", data([warning] + final))

    def test_run_cli_minimized_private_request_and_audit(self):
        seen = []
        def run(argv, **kwargs):
            seen.append((argv, kwargs))
            self.assertNotEqual(kwargs["cwd"], Path.cwd())
            return b'{"type":"result","subtype":"success","is_error":false,"result":"{\\"assessments\\":[]}"}'
        with patch.object(cj, "_executable", return_value="/trusted/claude"), \
                patch.object(cj, "_probe", return_value="2.1.214"), patch.object(cj, "_run", side_effect=run):
            result, audit = cj.run_cli({"provider": "claude_cli"}, {"evidence": "PRIVATE"}, "Review only supplied data")
        self.assertEqual(result, {"assessments": []})
        self.assertIn(b"PRIVATE", seen[0][1]["stdin"])
        self.assertNotIn("PRIVATE", json.dumps(audit))
        self.assertEqual(audit["auth_mode"], "cli_managed")
        self.assertFalse(audit["repository_working_directory"])
        self.assertFalse(Path(seen[0][1]["cwd"]).exists())
        with patch.object(cj, "_executable") as start, self.assertRaises(cj.CLIJudgeError):
            cj.run_cli({"provider": "claude_cli", "max_request_bytes": 1024}, {"large": "x" * 1024}, "instructions")
        start.assert_not_called()


class CLISubprocessTests(unittest.TestCase):
    def run_script(self, code, *, stdin=b"", timeout=3, limit=1024):
        with tempfile.TemporaryDirectory() as directory:
            return cj._run([sys.executable, "-c", code], cwd=directory,
                           environment=dict(os.environ), stdin=stdin,
                           deadline=time.monotonic() + timeout, limit=limit)

    def test_real_subprocess_stdin_stdout_and_stderr(self):
        result = self.run_script("import sys; sys.stderr.write('diagnostic'); sys.stdout.buffer.write(sys.stdin.buffer.read())", stdin=b"known\x00value")
        self.assertEqual(result, b"known\x00value")

    def test_real_output_stderr_nonzero_and_timeout_caps(self):
        scenarios = [("import sys;sys.stdout.write('x'*100000)", "byte limit"),
                     ("import sys;sys.stderr.write('SECRET'*20000)", "byte limit"),
                     ("import sys;sys.stderr.write('SECRET');sys.exit(3)", "failed"),
                     ("import time;time.sleep(5)", "timeout")]
        for code, expected in scenarios:
            start = time.monotonic()
            with self.subTest(expected=expected), self.assertRaises(cj.CLIJudgeError) as raised:
                self.run_script(code, timeout=0.3)
            self.assertIn(expected, str(raised.exception))
            self.assertNotIn("SECRET", str(raised.exception))
            self.assertLess(time.monotonic() - start, 2)

    def test_blocked_stdin_is_bounded(self):
        with self.assertRaises(cj.CLIJudgeError):
            self.run_script("import time;time.sleep(5)", stdin=b"x" * 1024 * 1024, timeout=0.2)

    @unittest.skipUnless(os.name == "posix", "Process group lifecycle is POSIX specific")
    def test_descendant_cannot_hold_pipes_past_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "escaped.txt")
            child = "import time,pathlib;time.sleep(0.7);pathlib.Path(" + repr(marker) + ").write_text('escaped')"
            code = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child) + "])"
            with self.assertRaises(cj.CLIJudgeError):
                self.run_script(code, timeout=0.2)
            time.sleep(0.8)
            self.assertFalse(Path(marker).exists())

    def test_nonexistent_executable_error_is_sanitized(self):
        with self.assertRaises(cj.CLIJudgeError) as raised:
            cj._run(["/nonexistent/SECRET"], cwd=Path.cwd(), environment={}, deadline=time.monotonic() + 1, limit=1024)
        self.assertNotIn("SECRET", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
