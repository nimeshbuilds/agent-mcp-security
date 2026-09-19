"""CLI-backed advice crosses the same deterministic gates as HTTP advice.

Runner subprocess/security tests live in test_cli_judge; these exercise public
scan routing, strict evidence checks, policy, image scope and failure behavior.
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.cli import main
from ai_security_scan.cli_judge import CLIJudgeError
from ai_security_scan.judge import JudgeError, load_config, review, review_controls
from tests.image_fixtures import docker_archive


def response(config, payload, instructions, stage="findings"):
    if stage == "findings":
        value = {"assessments": [{"finding_id": f.get("finding_id", f.get("id")),
                  "verdict": "likely_false_positive", "reason": "Synthetic advisory opinion; verify input provenance."}
                 for f in payload["findings"]], "additional_concerns": []}
    else:
        value = {"control_assessments": [{"control_id": c["id"], "check_assessments": [
                 {"check_index": i, "status": "insufficient_evidence", "reason": "Runtime evidence is absent.",
                  "citations": [], "verification_steps": ["Review authorized deployment evidence with the owner."]}
                 for i in range(1, len(c["checks"]) + 1)]} for c in payload["controls"]]}
    return value, {"transport": "official_cli", "cli_version": "test-fixture", "provider": config["provider"],
                   "auth_mode": "cli_managed", "stage": stage, "request_sha256": "a" * 64}


class CliJudgeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "target"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        self.output = self.base / "report"
        self.config = self.base / "judge.json"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *arguments, image=False):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main([*([] if image else [str(self.root)]), "--output", str(self.output), *arguments])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def report(self):
        return json.loads((self.output / "report.json").read_text(encoding="utf-8"))

    def test_default_scan_and_help_never_probe_or_launch_clis(self):
        with mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=AssertionError("No opt-in")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("No subprocess")):
            self.assertEqual(self.invoke()[0], 1)
            self.assertFalse(self.report()["judge"]["enabled"])
            self.assertEqual(self.invoke("--judge-cli", "codex", "--help")[0], 0)

    def test_all_cli_providers_preserve_static_findings_and_gate(self):
        self.assertEqual(self.invoke()[0], 1)
        baseline = self.report()
        for provider in ("codex", "claude", "grok"):
            with self.subTest(provider=provider), mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=response) as runner, \
                 mock.patch("ai_security_scan.judge._post_json", side_effect=AssertionError("No HTTP adapter")):
                code, stdout, _ = self.invoke("--judge-cli", provider, "--judge-mode", "findings", "--summary-json")
                report = self.report()
                self.assertEqual(code, 1)
                for key in ("scan_id", "findings", "summary", "controls", "assessment"):
                    self.assertEqual(report[key], baseline[key], key)
                self.assertEqual(runner.call_count, 1)
                self.assertEqual(report["judge"]["provider"], provider + "_cli")
                self.assertEqual(report["judge"]["assessments"][0]["verdict"], "likely_false_positive")
                self.assertFalse(report["analyst"]["enabled"])
                self.assertEqual(json.loads(stdout)["optional_review"]["judge"]["cli"]["auth_mode"], "cli_managed")

    def test_all_cli_providers_review_every_check_on_clean_scan(self):
        (self.root / "agent.py").write_text("agent_name = 'example'\n", encoding="utf-8")
        for provider in ("codex", "claude", "grok"):
            with self.subTest(provider=provider), mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=response) as runner:
                self.assertEqual(self.invoke("--judge-cli", provider, "--quiet")[0], 0)
                report = self.report()
                self.assertEqual(runner.call_count, 12)
                self.assertEqual(report["analyst"]["coverage"]["total_checks"], 132)
                self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 0)
                self.assertTrue(all(r["cli"]["stage"] == "controls" for r in report["analyst"]["requests"]))
                self.assertFalse(report["analyst"]["provenance"]["static_results_modified"])

    def test_cli_json_and_shortcut_produce_equivalent_advice(self):
        self.config.write_text(json.dumps({"provider": "codex_cli", "model": "explicit-test-model",
                              "executable": "trusted-codex", "timeout_seconds": 120}), encoding="utf-8")
        with mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=response) as runner:
            self.invoke("--judge-cli", "codex", "--judge-model", "explicit-test-model", "--judge-executable", "trusted-codex",
                        "--judge-timeout", "120", "--judge-mode", "findings")
            shortcut = runner.call_args.args[0]
            self.invoke("--judge-config", str(self.config), "--judge-mode", "findings")
            self.assertEqual(shortcut, runner.call_args.args[0])

    def test_invalid_shortcut_combinations_stop_before_scan(self):
        cases = [("--judge-cli", "codex", "--judge-config", "x"), ("--judge-model", "m"),
                 ("--judge-timeout", "10"), ("--judge-executable", "codex"),
                 ("--judge-cli", "claude", "--judge-cli-home", "/profile"),
                 ("--judge-cli", "codex", "--judge-timeout", "nan"),
                 ("--judge-cli", "codex", "--judge-timeout", "0"),
                 ("--judge-config", "x", "--judge-model", "m")]
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Invalid arguments")):
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    self.assertEqual(self.invoke(*arguments)[0], 2)

    def test_cli_failure_preserves_all_reports_and_unreviewed_checks(self):
        for message in ("CLI judge exceeded its timeout.", "The selected CLI judge executable is not installed or executable.",
                        "Grok CLI has active extensions."):
            with self.subTest(message=message), mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=CLIJudgeError(message)):
                self.assertEqual(self.invoke("--judge-cli", "codex", "--fail-on", "none")[0], 2)
                report = self.report()
                self.assertGreater(report["summary"]["open_findings"], 0)
                self.assertIn("Deterministic results are preserved", report["judge"]["error"])
                self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 132)
                self.assertEqual({p.name for p in self.output.iterdir()}, {"report.html", "report.json", "report.md", "report.sarif"})

    def test_unknown_cli_config_fields_preserve_static_report(self):
        for field, value in (("endpoint", "https://example.com"), ("max_output_tokens", 1000), ("arguments", ["--dangerous"])):
            self.config.write_text(json.dumps({"provider": "codex_cli", field: value}), encoding="utf-8")
            with self.subTest(field=field), mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=AssertionError("Invalid config")):
                self.assertEqual(self.invoke("--judge-config", str(self.config))[0], 2)
                self.assertEqual(self.report()["judge"]["status"], "error")

    def test_policy_excludes_checks_before_cli_evidence_routing(self):
        policy = self.base / "policy.json"
        policy.write_text(json.dumps({"schema_version": "1.0", "controls": {"GOV-01": {"status": "justified", "reason": "Owner review elsewhere."}},
                                    "checks": {"AUTH-01:2": {"status": "disabled"}}}), encoding="utf-8")
        with mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=response) as runner:
            self.assertEqual(self.invoke("--judge-cli", "claude", "--review-config", str(policy))[0], 1)
            routed = [c for call in runner.call_args_list if call.kwargs["stage"] == "controls" for c in call.args[1]["controls"]]
            self.assertNotIn("GOV-01", {c["id"] for c in routed})
            self.assertEqual(len(next(c for c in routed if c["id"] == "AUTH-01")["checks"]), 1)
            self.assertEqual(self.report()["analyst"]["coverage"]["total_checks"], 129)

    def test_image_evidence_uses_same_cli_and_retains_container_provenance(self):
        archive = self.base / "agent.tar"
        docker_archive(archive, [[("app/agent.py", "import os\nos.system(user_input)\n")]], config={"config": {"User": "1000"}})
        with mock.patch("ai_security_scan.cli_judge.run_cli", side_effect=response) as runner:
            self.assertEqual(self.invoke("--image-archive", str(archive), "--judge-cli", "codex", "--judge-include-source",
                                        "--judge-mode", "findings", image=True)[0], 1)
            self.assertFalse(self.report()["image"]["container_started"])
            context = runner.call_args.args[1]["source_context"][0]
            self.assertEqual(context["image_context"], "final_filesystem")

    def test_cli_outputs_cannot_invent_ids_or_invoke_tools(self):
        payload = {"findings": [{"finding_id": "F1"}]}
        bad = [{"assessments": [{"finding_id": "UNKNOWN", "verdict": "needs_review", "reason": "Check."}], "additional_concerns": []},
               {"assessments": [], "additional_concerns": [], "tool_calls": [{"name": "shell"}]}]
        for value in bad:
            with self.subTest(value=value), mock.patch("ai_security_scan.cli_judge.run_cli", return_value=(value, {})):
                with self.assertRaises(JudgeError):
                    review({"provider": "codex_cli"}, payload)

    def test_cli_control_quotes_are_verified_and_manual_support_downgraded(self):
        payload = {"controls": [{"id": "C1", "checks": ["Owner reviews the control."], "validation": "manual", "evidence_ids": ["E1"]}],
                   "evidence": [{"evidence_id": "E1", "path": "agent.py", "start_line": 1, "end_line": 1, "source_sha256": "0" * 64,
                                 "text": "auth_required = True"}]}
        check = {"check_index": 1, "status": "supported_by_code", "reason": "Configuration is explicit.",
                 "citations": [{"evidence_id": "E1", "quote": "auth_required = True"}], "verification_steps": ["Verify deployment evidence."]}
        output = {"control_assessments": [{"control_id": "C1", "check_assessments": [check]}]}
        with mock.patch("ai_security_scan.cli_judge.run_cli", return_value=(output, {})):
            answer = review_controls({"provider": "grok_cli"}, payload)
            self.assertEqual(answer["control_assessments"][0]["check_assessments"][0]["status"], "needs_human_review")
            check["citations"][0]["quote"] = "invented source"
            with self.assertRaises(JudgeError):
                review_controls({"provider": "grok_cli"}, payload)

    def test_cli_configuration_duplicate_keys_rejected(self):
        self.config.write_text('{"provider":"codex_cli","provider":"claude_cli"}', encoding="utf-8")
        with self.assertRaises(JudgeError):
            load_config(self.config)
