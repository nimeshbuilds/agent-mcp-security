"""Official interactive login, auto-resume and unattended failure boundaries."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from ai_security_scan import cli_judge as cj
from ai_security_scan.cli import main
from tests.test_cli_judge_integration import response


class Terminal(io.StringIO):
    def isatty(self):
        return True


class LoginTests(unittest.TestCase):
    def test_probe_claude_status_ignores_identity_fields(self):
        for state in (True, False):
            raw = json.dumps({"loggedIn": state, "email": "private@example.com", "token": "SECRET"}).encode()
            with patch.object(cj, "_executable", return_value="claude"), patch.object(cj, "_probe"), patch.object(cj, "_run", return_value=raw):
                result = cj.probe_auth({"provider": "claude_cli"})
            self.assertIs(result["logged_in"], state)
            self.assertNotIn("SECRET", json.dumps(result))
            self.assertNotIn("private", json.dumps(result))

    def test_probe_codex_exact_states_and_incompatible_output(self):
        for raw, expected in ((b"Logged in using ChatGPT\n", True), (b"Not logged in\n", False), (b"Logged in using an API key - SECRET", True)):
            with patch.object(cj, "_executable", return_value="codex"), patch.object(cj, "_probe"), patch.object(cj, "_run", return_value=raw):
                self.assertIs(cj.probe_auth({"provider": "codex_cli"})["logged_in"], expected)
        with patch.object(cj, "_executable", return_value="codex"), patch.object(cj, "_probe"), patch.object(cj, "_run", return_value=b"unexpected SECRET"), self.assertRaises(cj.CLIJudgeError):
            cj.probe_auth({"provider": "codex_cli"})

    def test_grok_status_is_unknown_and_checks_extensions_first(self):
        with patch.object(cj, "_executable", return_value="grok"), patch.object(cj, "_probe"), patch.object(cj, "_grok_preflight") as preflight:
            self.assertIsNone(cj.probe_auth({"provider": "grok_cli"})["logged_in"])
            preflight.assert_called_once()

    def test_noninteractive_login_never_starts_process_or_browser(self):
        with patch.object(cj.sys, "stdin", io.StringIO()), patch.object(cj, "_executable") as executable:
            with self.assertRaisesRegex(cj.CLIJudgeError, "interactive terminal"):
                cj.login_cli({"provider": "claude_cli"})
            executable.assert_not_called()

    def test_official_login_commands_inherit_terminal_not_source_or_shell(self):
        expected = {"codex_cli": ["login"], "claude_cli": ["auth", "login", "--claudeai"], "grok_cli": ["login", "--oauth"]}
        for provider, args in expected.items():
            process = MagicMock()
            process.wait.return_value = 0
            process.poll.return_value = 0
            with self.subTest(provider=provider), patch.object(cj.sys, "stdin", Terminal()) as terminal, \
                 patch.object(cj.sys, "stderr", Terminal()) as display, patch.object(cj, "_executable", return_value="/official/tool"), \
                 patch.object(cj, "_probe"), patch.object(cj, "_grok_preflight"), \
                 patch.object(cj, "probe_auth", return_value={"logged_in": True}), patch.object(cj.subprocess, "Popen", return_value=process) as start:
                self.assertTrue(cj.login_cli({"provider": provider})["logged_in"])
                self.assertEqual(start.call_args.args[0], ["/official/tool", *args])
                self.assertFalse(start.call_args.kwargs["shell"])
                self.assertIs(start.call_args.kwargs["stdin"], terminal)
                self.assertIs(start.call_args.kwargs["stdout"], display)
                self.assertNotEqual(start.call_args.kwargs["cwd"], Path.cwd())
                self.assertFalse(start.call_args.kwargs["cwd"].exists())

    def test_login_timeout_cancel_and_unsuccessful_status_stop(self):
        for effect in (subprocess.TimeoutExpired("tool", 1), KeyboardInterrupt(), 1):
            process = MagicMock()
            process.poll.return_value = None
            process.wait.side_effect = [effect, 0]
            with self.subTest(effect=type(effect).__name__), patch.object(cj.sys, "stdin", Terminal()), \
                 patch.object(cj.sys, "stderr", Terminal()), patch.object(cj, "_executable", return_value="/official/tool"), \
                 patch.object(cj, "_probe"), patch.object(cj.subprocess, "Popen", return_value=process):
                with self.assertRaises(cj.CLIJudgeAuthError):
                    cj.login_cli({"provider": "claude_cli"})
                process.kill.assert_called_once()


class LoginRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n")
        self.output = Path(self.temp.name) / "report"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args, terminal=True, standalone=False):
        stdout, stderr = io.StringIO(), Terminal() if terminal else io.StringIO()
        with patch("sys.stdin", Terminal() if terminal else io.StringIO()), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = main([*([] if standalone else [str(self.root), "--output", str(self.output)]), *args])
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_signed_out_interactive_scan_logs_in_and_resumes(self):
        with patch.object(cj, "probe_auth", return_value={"logged_in": False}), patch.object(cj, "login_cli") as login, patch.object(cj, "run_cli", side_effect=response) as run:
            self.assertEqual(self.invoke("--judge-cli", "claude", "--judge-mode", "findings")[0], 1)
            login.assert_called_once()
            run.assert_called_once()
        report = json.loads((self.output / "report.json").read_text())
        self.assertEqual(report["judge"]["status"], "completed")

    def test_expired_login_retries_once_after_official_login(self):
        calls = []
        def run(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise cj.CLIJudgeAuthError("CLI authentication required.")
            return response(*args, **kwargs)
        with patch.object(cj, "probe_auth", return_value={"logged_in": True}), patch.object(cj, "login_cli") as login, patch.object(cj, "run_cli", side_effect=run):
            self.assertEqual(self.invoke("--judge-cli", "claude", "--judge-mode", "findings")[0], 1)
            login.assert_called_once()
            self.assertEqual(len(calls), 2)

    def test_no_retry_loop_on_repeated_auth_failure(self):
        with patch.object(cj, "probe_auth", return_value={"logged_in": True}), patch.object(cj, "login_cli") as login, patch.object(cj, "run_cli", side_effect=cj.CLIJudgeAuthError("Sign in required")) as run:
            self.assertEqual(self.invoke("--judge-cli", "codex")[0], 2)
            self.assertEqual(run.call_count, 2)
            login.assert_called_once()

    def test_expiry_during_control_batch_resumes_and_counts_retry(self):
        failed = []
        def run(config, payload, instructions, stage="findings"):
            if stage == "controls" and not failed:
                failed.append(True)
                raise cj.CLIJudgeAuthError("Expired credentials")
            return response(config, payload, instructions, stage)
        with patch.object(cj, "probe_auth", return_value={"logged_in": True}), patch.object(cj, "login_cli") as login, patch.object(cj, "run_cli", side_effect=run):
            self.assertEqual(self.invoke("--judge-cli", "codex")[0], 1)
            login.assert_called_once()
        report = json.loads((self.output / "report.json").read_text())
        self.assertEqual(report["analyst"]["coverage"]["calls_made"], 12)
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 0)
        self.assertTrue(report["analyst"]["requests"][0]["authentication_retry"])

    def test_control_auth_retry_cannot_exceed_call_budget(self):
        def run(config, payload, instructions, stage="findings"):
            if stage == "controls":
                raise cj.CLIJudgeAuthError("Expired credentials")
            return response(config, payload, instructions, stage)
        with patch.object(cj, "probe_auth", return_value={"logged_in": True}), patch.object(cj, "login_cli") as login, patch.object(cj, "run_cli", side_effect=run):
            self.assertEqual(self.invoke("--judge-cli", "codex", "--analyst-max-calls", "1")[0], 2)
            login.assert_not_called()
        report = json.loads((self.output / "report.json").read_text())
        self.assertEqual(report["analyst"]["coverage"]["calls_made"], 1)

    def test_signed_out_login_cannot_repeat_during_control_review(self):
        def run(config, payload, instructions, stage="findings"):
            if stage == "controls":
                raise cj.CLIJudgeAuthError("Expired credentials")
            return response(config, payload, instructions, stage)
        with patch.object(cj, "probe_auth", return_value={"logged_in": False}), patch.object(cj, "login_cli") as login, patch.object(cj, "run_cli", side_effect=run):
            self.assertEqual(self.invoke("--judge-cli", "codex")[0], 2)
            login.assert_called_once()

    def test_quiet_json_noninteractive_and_never_modes_do_not_login(self):
        for flags, tty in ((["--quiet"], True), (["--summary-json"], True), ([], False), (["--judge-login", "never"], True)):
            with self.subTest(flags=flags, tty=tty), patch.object(cj, "probe_auth", side_effect=AssertionError("No login probe")), \
                 patch.object(cj, "login_cli", side_effect=AssertionError("No login")), patch.object(cj, "run_cli", side_effect=cj.CLIJudgeAuthError("Sign in required")):
                self.assertEqual(self.invoke("--judge-cli", "claude", *flags, terminal=tty)[0], 2)

    def test_cancelled_login_preserves_static_reports(self):
        with patch.object(cj, "probe_auth", return_value={"logged_in": False}), patch.object(cj, "login_cli", side_effect=cj.CLIJudgeAuthError("Login cancelled")), patch.object(cj, "run_cli") as run:
            self.assertEqual(self.invoke("--judge-cli", "claude")[0], 2)
            run.assert_not_called()
        report = json.loads((self.output / "report.json").read_text())
        self.assertGreater(report["summary"]["open_findings"], 0)
        self.assertEqual(report["judge"]["status"], "error")

    def test_standalone_login_never_scans_and_validates_combination(self):
        with patch.object(cj, "login_cli") as login, patch("ai_security_scan.cli.scan", side_effect=AssertionError("No scan")):
            self.assertEqual(self.invoke("--login", "claude", standalone=True)[0], 0)
            login.assert_called_once()
            self.assertEqual(self.invoke("--login", "codex", "--summary-json", standalone=True)[0], 2)
            self.assertEqual(self.invoke("--login", "claude")[0], 2)
            self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
