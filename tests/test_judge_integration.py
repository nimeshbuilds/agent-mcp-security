"""Exercise the public CLI's advisory-only and outbound-data boundaries."""

import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from ai_security_scan.cli import judge_payload, main
from ai_security_scan.scanner import scan


MARKER = "UNTRUSTED_REPOSITORY_DATA_JSON:\n"


def assessments_for(payload):
    return {
        "assessments": [
            {"finding_id": finding["finding_id"], "verdict": "likely_false_positive", "reason": "Unverified fixture assessment; review remains necessary."}
            for finding in payload["findings"]
        ],
        "additional_concerns": [],
    }


class JudgeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repository"
        self.repo.mkdir()
        self.config = self.base / "trusted-judge.json"
        self.config.write_text(json.dumps({"provider": "openai_chat", "model": "test-only-model"}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def cli(self, output_name, *args):
        output = self.base / output_name
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([str(self.repo), "--output", str(output), "--judge-mode", "findings", *args])
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        return code, report, output, stdout.getvalue() + stderr.getvalue()

    def mock_post(self, captured):
        def post(config, headers, body):
            request_body = json.loads(body)
            payload = json.loads(request_body["messages"][1]["content"].split(MARKER, 1)[1])
            captured.append(payload)
            return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(assessments_for(payload))}}]}
        return post

    def test_cli_false_positive_advice_preserves_findings_severity_and_gate(self):
        self.write("agent.py", "import os\nos.system(user_input)\neval(model_output)\n")
        baseline_code, baseline, baseline_output, _ = self.cli("baseline-report")
        sent = []
        with mock.patch("ai_security_scan.judge._post_json", side_effect=self.mock_post(sent)):
            code, report, output, _ = self.cli("judge-report", "--judge-config", str(self.config))
        self.assertEqual(baseline_code, 1)
        self.assertEqual(code, 1)
        self.assertEqual(report["findings"], baseline["findings"])
        self.assertEqual(report["summary"], baseline["summary"])
        self.assertEqual(report["controls"], baseline["controls"])
        self.assertEqual((output / "report.sarif").read_bytes(), (baseline_output / "report.sarif").read_bytes())
        self.assertTrue(report["judge"]["advisory_only"])
        self.assertEqual(report["judge"]["status"], "completed")
        self.assertTrue(all(item["verdict"] == "likely_false_positive" for item in report["judge"]["assessments"]))
        self.assertEqual(len(sent), 1)

    def test_cli_default_payload_redacts_evidence_without_neighboring_source(self):
        secret = "LOCAL_CANARY_OPENAI_SECRET_123456"
        source_marker = "NEIGHBOR_SOURCE_OPT_IN_REQUIRED"
        self.write("agent.py", 'import os\nAPI_KEY = "' + secret + '"\n# ' + source_marker + '\nos.system(user_input)\n')
        sent = []
        with mock.patch("ai_security_scan.judge._post_json", side_effect=self.mock_post(sent)):
            code, report, output, console = self.cli("redacted-report", "--judge-config", str(self.config))
        self.assertEqual(code, 1)
        self.assertNotIn("source_context", sent[0])
        self.assertFalse(sent[0]["source_context_included"])
        self.assertNotIn(source_marker, json.dumps(sent))
        self.assertNotIn(secret, json.dumps(sent))
        self.assertTrue(any("[REDACTED" in f["evidence"] for f in sent[0]["findings"]))
        self.assertEqual(report["judge"]["source_context_sent_count"], 0)
        for path in output.iterdir():
            self.assertNotIn(secret, path.read_text(encoding="utf-8"))
        self.assertNotIn(secret, console)

    def test_cli_clipping_records_unreviewed_findings(self):
        self.write("agent.py", "import os\nos.system(first_input)\nos.system(second_input)\nos.system(third_input)\n")
        sent = []
        with mock.patch("ai_security_scan.judge._post_json", side_effect=self.mock_post(sent)):
            code, report, output, _ = self.cli("clipped-report", "--judge-config", str(self.config), "--judge-max-findings", "1")
        self.assertEqual(code, 1)
        self.assertEqual(len(sent[0]["findings"]), 1)
        self.assertGreater(report["summary"]["open_findings"], 1)
        omitted = report["summary"]["open_findings"] - 1
        self.assertEqual(sent[0]["omitted_open_findings"], omitted)
        self.assertEqual(report["judge"]["omitted_open_findings"], omitted)
        self.assertEqual(report["judge"]["findings_submitted"], 1)
        self.assertEqual(report["judge"]["omitted_assessments"], 0)
        self.assertIn('"omitted_open_findings": ' + str(omitted), (output / "report.md").read_text())
        self.assertEqual(len(report["findings"]), report["summary"]["open_findings"])

    def test_cli_source_opt_in_is_bounded_redacted_and_counted(self):
        secret = "LOCAL_SOURCE_CONTEXT_SECRET_918274"
        marker = "NEIGHBOR_SOURCE_NOW_AUTHORIZED"
        self.write("agent.py", 'import os\nAPI_KEY = "' + secret + '"\n# ' + marker + '\nos.system(user_input)\n')
        self.write(".env", "API_KEY=" + secret + "\n")
        sent = []
        with mock.patch("ai_security_scan.judge._post_json", side_effect=self.mock_post(sent)):
            code, report, _, _ = self.cli("context-report", "--judge-config", str(self.config), "--judge-include-source")
        self.assertEqual(code, 1)
        self.assertTrue(sent[0]["source_context_included"])
        contexts = sent[0]["source_context"]
        self.assertTrue(contexts)
        self.assertIn(marker, json.dumps(contexts))
        self.assertNotIn(secret, json.dumps(sent))
        self.assertFalse(any(c["path"] == ".env" for c in contexts))
        self.assertLessEqual(sum(len(c["text"]) for c in contexts), 30000)
        self.assertTrue(all(len(c["text"]) <= 3000 for c in contexts))
        self.assertEqual(report["judge"]["source_context_sent_count"], len(contexts))

    def test_invalid_judge_response_keeps_baseline_and_error_exit(self):
        self.write("agent.py", "import os\nos.system(user_input)\n")
        _, baseline, _, _ = self.cli("error-baseline")
        with mock.patch("ai_security_scan.judge._post_json", return_value={"choices": [{"message": {"content": "provider echoed INTERNAL_CANARY_SECRET_INVALID_JSON"}}]}):
            code, report, output, console = self.cli("invalid-judge-report", "--judge-config", str(self.config), "--fail-on", "none")
        self.assertEqual(code, 2)
        self.assertEqual(report["findings"], baseline["findings"])
        self.assertEqual(report["judge"]["status"], "error")
        self.assertNotIn("INTERNAL_CANARY_SECRET", json.dumps(report) + console)
        self.assertTrue((output / "report.sarif").exists())

    def test_suppressed_findings_are_not_sent_for_judging(self):
        self.write("agent.py", "import os\nos.system(user_input)\neval(model_output)\n")
        first = scan(self.repo)
        finding_id = first["findings"][0]["id"]
        report = scan(self.repo, baseline={finding_id: "Explicitly accepted fixture"})
        payload = judge_payload(report, self.repo, max_findings=1)
        self.assertNotIn(finding_id, [f["id"] for f in payload["findings"]])
        self.assertEqual(payload["omitted_open_findings"], report["summary"]["open_findings"] - len(payload["findings"]))

    def test_scan_script_custom_local_gateway_end_to_end(self):
        self.write("agent.py", "import os\nos.system(user_input)\n")
        requests_seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                payload = json.loads(body["review_prompt"].split(MARKER, 1)[1])
                requests_seen.append({"path": self.path, "authorization": self.headers.get("Authorization"), "payload": payload})
                response = json.dumps({"data": {"review": assessments_for(payload)}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.config.write_text(json.dumps({
                "provider": "custom", "model": "loopback-test-model",
                "endpoint": "http://127.0.0.1:%d/internal/review" % server.server_port,
                "headers": {"Authorization": "Bearer ${ENV:LOCAL_JUDGE_TEST_KEY}"},
                "request_template": {"deployment": "${MODEL}", "review_prompt": "${PROMPT}"},
                "response_path": "data.review", "timeout_seconds": 3,
            }), encoding="utf-8")
            output = self.base / "subprocess-report"
            environment = dict(os.environ, LOCAL_JUDGE_TEST_KEY="LOCAL_GATEWAY_TRANSPORT_SECRET_123456")
            process = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1] / "scan.py"), str(self.repo),
                 "--output", str(output), "--judge-config", str(self.config), "--judge-mode", "findings"],
                capture_output=True, text=True, timeout=15, env=environment,
            )
            self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["judge"]["provider"], "custom")
            self.assertEqual(report["judge"]["status"], "completed")
            self.assertTrue(report["findings"])
            self.assertEqual(len(requests_seen), 1)
            self.assertEqual(requests_seen[0]["path"], "/internal/review")
            self.assertEqual(requests_seen[0]["authorization"], "Bearer LOCAL_GATEWAY_TRANSPORT_SECRET_123456")
            self.assertNotIn("LOCAL_GATEWAY_TRANSPORT_SECRET_123456", json.dumps(report) + process.stdout + process.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


if __name__ == "__main__":
    unittest.main()
