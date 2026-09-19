"""Adversarial provider/transport scenarios; only mocked or loopback networking.

These tests exercise public review entry points through protocol envelopes and
real HTTP for every adapter, rather than treating a model answer as trusted.
"""

import copy
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from ai_security_scan import judge


MARKER = "UNTRUSTED_REPOSITORY_DATA_JSON:\n"
PROVIDERS = ("openai_chat", "openai_responses", "anthropic", "gemini", "ollama", "custom")
CONTROL_INPUT = {
    "controls": [{"id": "AUTH-01", "title": "Authorize execution", "validation": "hybrid",
                  "checks": ["Require an authorized identity.", "Verify denied execution."],
                  "evidence_ids": ["EV-1"]}],
    "evidence": [{"evidence_id": "EV-1", "path": "agent.py", "start_line": 20, "end_line": 21,
                  "text": "require_permission(user)\nexecute_tool(user)\n", "source_sha256": "a" * 64}],
}
FINDING_INPUT = {"findings": [{"finding_id": "finding-1", "title": "Review authorization"}]}


def control_answer():
    return {"control_assessments": [{"control_id": "AUTH-01", "check_assessments": [
        {"check_index": 1, "status": "supported_by_code", "reason": "A permission check precedes execution.",
         "citations": [{"evidence_id": "EV-1", "quote": "require_permission(user)"}],
         "verification_steps": ["Obtain the authorization policy and approved denial test results."]},
        {"check_index": 2, "status": "needs_runtime_validation", "reason": "The excerpt has no runtime observations.",
         "citations": [], "verification_steps": ["Review traces from authorized negative tests."]},
    ]}]}


def finding_answer():
    return {"assessments": [{"finding_id": "finding-1", "verdict": "needs_review",
                             "reason": "Verify that authorization rejects unauthorized identities."}],
            "additional_concerns": []}


def envelope(provider, answer):
    raw = json.dumps(answer)
    return {
        "openai_chat": {"choices": [{"finish_reason": "stop", "message": {"content": raw}}]},
        "openai_responses": {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": raw}]}]},
        "anthropic": {"stop_reason": "end_turn", "content": [{"type": "text", "text": raw}]},
        "gemini": {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": raw}]}}]},
        "ollama": {"done": True, "done_reason": "stop", "message": {"content": raw}},
        "custom": {"data": [{"review": answer}]},
    }[provider]


def config(provider="openai_chat", **options):
    value = {"provider": provider, "model": "protocol-test-model", **options}
    if provider == "custom":
        value.setdefault("endpoint", "https://gateway.example.invalid/internal/review")
        value.setdefault("request_template", {"deployment": "${MODEL}", "review_prompt": "${PROMPT}"})
        value.setdefault("response_path", "data.0.review")
    return value


class Response:
    def __init__(self, raw, headers=None):
        self.status = 200
        self.headers = headers or {}
        self.raw = io.BytesIO(raw)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read1(self, count):
        return self.raw.read(count)


class ProtocolAdversarialTests(unittest.TestCase):
    def invoke(self, provider, response, controls=True, options=None):
        callback = judge.review_controls if controls else judge.review
        payload = CONTROL_INPUT if controls else FINDING_INPUT
        with mock.patch.object(judge, "_post_json", return_value=response) as post:
            result = callback(config(provider, **(options or {})), copy.deepcopy(payload))
        self.assertEqual(post.call_count, 1)
        return result

    def test_control_character_cleanup_cannot_reconstruct_credentials(self):
        secret = "CANARY_SECRET_123456"
        disguised = "CANARY_SECRET_\x01123456"
        for controls in (False, True):
            with self.subTest(controls=controls):
                value = control_answer() if controls else finding_answer()
                if controls:
                    check = value["control_assessments"][0]["check_assessments"][0]
                    check["reason"] = disguised
                    check["verification_steps"] = [disguised]
                else:
                    value["assessments"][0]["reason"] = disguised
                    value["additional_concerns"] = [disguised]
                response = envelope("openai_chat", value)
                response["model"] = disguised
                with mock.patch.dict(os.environ, {"ADVERSARIAL_JUDGE_KEY": secret}):
                    result = self.invoke("openai_chat", response, controls, {"api_key_env": "ADVERSARIAL_JUDGE_KEY"})
                self.assertNotIn(secret, json.dumps(result))
                self.assertIn("[REDACTED]", json.dumps(result))

    def test_finding_triage_rejects_tool_invocation_even_with_valid_text(self):
        for provider in PROVIDERS:
            response = envelope(provider, finding_answer())
            if provider == "openai_chat":
                response["choices"][0]["message"]["tool_calls"] = [{"function": {"name": "shell"}}]
            elif provider == "openai_responses":
                response["output"].append({"type": "function_call", "name": "shell", "arguments": "{}"})
            elif provider == "anthropic":
                response["content"].append({"type": "tool_use", "name": "shell", "input": {}})
            elif provider == "gemini":
                response["candidates"][0]["content"]["parts"].append({"functionCall": {"name": "shell"}})
            elif provider == "ollama":
                response["message"]["tool_calls"] = [{"function": {"name": "shell"}}]
            else:
                response["tool_calls"] = [{"function": {"name": "shell"}}]
            with self.subTest(provider=provider), self.assertRaises(judge.JudgeError):
                self.invoke(provider, response, controls=False)

    def test_finding_triage_cannot_enable_legacy_or_custom_tool_fields(self):
        for provider, options in (
            ("openai_chat", {"extra_body": {"functions": [{"name": "shell"}]}}),
            ("gemini", {"extra_body": {"toolConfig": {"functionCallingConfig": {"mode": "AUTO"}}}}),
            ("custom", {"request_template": {"review_prompt": "${PROMPT}", "tools": [{"name": "shell"}]}}),
        ):
            with self.subTest(provider=provider), mock.patch.object(judge, "_post_json") as post:
                with self.assertRaises(judge.JudgeError):
                    judge.review(config(provider, **options), FINDING_INPUT)
                post.assert_not_called()

    def test_invalid_unicode_model_fails_with_sanitized_judge_error(self):
        for model in (None, True, 123, [], {}, "", "\ud800", "test-\udfff"):
            with self.subTest(model=repr(model)), mock.patch.object(judge, "_post_json") as post:
                with self.assertRaises(judge.JudgeError):
                    judge.review(config(model=model), FINDING_INPUT)
                post.assert_not_called()

    def test_invalid_unicode_endpoint_is_rejected_during_preflight(self):
        for endpoint in ("https://\ud800.example/review", "https://gateway.example/\ud800",
                         "https://gateway.example/?opaque=\ud800"):
            with self.subTest(endpoint=repr(endpoint)), mock.patch.object(judge, "_post_json") as post:
                with self.assertRaises(judge.JudgeError):
                    judge.review(config(endpoint=endpoint), FINDING_INPUT)
                post.assert_not_called()

    def test_provider_unicode_output_can_be_rendered_as_utf8(self):
        text = "Untrusted provider text with an unpaired surrogate: \ud800."
        for controls in (False, True):
            value = control_answer() if controls else finding_answer()
            if controls:
                check = value["control_assessments"][0]["check_assessments"][0]
                check["reason"] = text
                check["verification_steps"] = [text]
            else:
                value["assessments"][0]["reason"] = text
                value["additional_concerns"] = [text]
            response = envelope("openai_chat", value)
            response["model"] = text
            with self.subTest(controls=controls):
                result = self.invoke("openai_chat", response, controls)
                rendered = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self.assertTrue(rendered)

    def test_end_of_stream_after_deadline_is_not_a_successful_review(self):
        clock = [0.0]

        class LateEOF(Response):
            def read1(self, count):
                data = super().read1(count)
                clock[0] = 0.9 if data else 1.1
                return data

        opener = mock.Mock()
        opener.open.return_value = LateEOF(b'{"result":"complete"}')
        with mock.patch.object(judge.request, "build_opener", return_value=opener), \
                mock.patch.object(judge.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(judge.JudgeError):
                judge._post_json(judge._validate_config(config(timeout_seconds=1)), {}, b"{}")
        self.assertEqual(opener.open.call_count, 1)

    def test_every_adapter_roundtrips_both_review_modes_over_real_loopback_http(self):
        received = []
        failures = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    provider = self.path.split("?", 1)[0].rsplit("/", 1)[-1]
                    if provider in ("openai_chat", "ollama", "anthropic"):
                        prompt = body["messages"][-1]["content"]
                    elif provider == "openai_responses":
                        prompt = body["input"]
                    elif provider == "gemini":
                        prompt = body["contents"][0]["parts"][0]["text"]
                    else:
                        prompt = body["review_prompt"]
                    payload = json.loads(prompt.split(MARKER, 1)[1])
                    is_controls = "controls" in payload
                    received.append({"path": self.path, "provider": provider, "payload": payload,
                                     "headers": dict(self.headers), "body": body})
                    raw = json.dumps(envelope(provider, control_answer() if is_controls else finding_answer())).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except Exception as exc:
                    failures.append(type(exc).__name__)
                    self.send_error(500)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.dict(os.environ, {"ADVERSARIAL_JUDGE_KEY": "LOOPBACK_ONLY_SECRET_123456"}):
                for provider in PROVIDERS:
                    for controls in (False, True):
                        with self.subTest(provider=provider, controls=controls):
                            endpoint = "http://127.0.0.1:%d/custom/base/%s?api-version=test" % (server.server_port, provider)
                            options = config(provider, endpoint=endpoint, api_key_env="ADVERSARIAL_JUDGE_KEY", timeout_seconds=3)
                            callback = judge.review_controls if controls else judge.review
                            result = callback(options, copy.deepcopy(CONTROL_INPUT if controls else FINDING_INPUT))
                            self.assertEqual(result["status"], "completed")
                            self.assertTrue(result["advisory_only"])
                            self.assertEqual(result["omitted_checks"] if controls else result["omitted_assessments"], 0)
                            self.assertNotIn("LOOPBACK_ONLY_SECRET_123456", json.dumps(result))
                            request = received[-1]
                            self.assertEqual(request["path"], "/custom/base/" + provider + "?api-version=test")
                            headers = {name.lower(): value for name, value in request["headers"].items()}
                            expected_header = {"anthropic": "x-api-key", "gemini": "x-goog-api-key"}.get(provider, "authorization")
                            expected_prefix = "Bearer " if expected_header == "authorization" else ""
                            self.assertEqual(headers[expected_header], expected_prefix + "LOOPBACK_ONLY_SECRET_123456")
                            self.assertNotIn("tools", request["body"])
                            self.assertEqual(request["payload"], CONTROL_INPUT if controls else FINDING_INPUT)
            self.assertEqual(len(received), 12)
            self.assertEqual(failures, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required to create an ephemeral local TLS test certificate")
    def test_https_custom_ca_and_hostname_verification_use_real_tls(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                received.append(self.headers.get("Authorization"))
                raw = json.dumps(envelope("openai_chat", control_answer())).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            certificate, private_key = path / "server.pem", path / "server.key"
            certificate_config = path / "certificate.cnf"
            certificate_config.write_text(
                "[req]\nprompt=no\ndistinguished_name=subject\nx509_extensions=extensions\n"
                "[subject]\nCN=127.0.0.1\n[extensions]\nsubjectAltName=IP:127.0.0.1\n"
                "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n",
                encoding="utf-8",
            )
            generated = subprocess.run(
                [shutil.which("openssl"), "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
                 "-days", "1", "-keyout", str(private_key), "-out", str(certificate), "-config", str(certificate_config)],
                capture_output=True, timeout=20,
            )
            self.assertEqual(generated.returncode, 0, "Could not generate local TLS test certificate.")
            server = HTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certificate), str(private_key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                endpoint = "https://127.0.0.1:%d/review" % server.server_port
                with mock.patch.dict(os.environ, {"ADVERSARIAL_JUDGE_KEY": "EPHEMERAL_TLS_TEST_SECRET_123456"}):
                    with self.assertRaisesRegex(judge.JudgeError, "TLS verification failed"):
                        judge.review_controls(config(endpoint=endpoint, timeout_seconds=3, api_key_env="ADVERSARIAL_JUDGE_KEY"), CONTROL_INPUT)
                    self.assertEqual(received, [])
                    result = judge.review_controls(config(endpoint=endpoint, timeout_seconds=3, ca_file=str(certificate),
                                                          api_key_env="ADVERSARIAL_JUDGE_KEY"), CONTROL_INPUT)
                    self.assertEqual(result["status"], "completed")
                    self.assertEqual(received, ["Bearer EPHEMERAL_TLS_TEST_SECRET_123456"])
                    with self.assertRaisesRegex(judge.JudgeError, "TLS verification failed"):
                        judge.review_controls(config(endpoint=endpoint.replace("127.0.0.1", "localhost"), timeout_seconds=3,
                                                     ca_file=str(certificate), api_key_env="ADVERSARIAL_JUDGE_KEY"), CONTROL_INPUT)
                    self.assertEqual(len(received), 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)

    def test_noncompletion_envelopes_are_rejected_in_both_modes(self):
        cases = [("openai_chat", "finish_reason", reason) for reason in ("length", "content_filter", "tool_calls")]
        cases += [("openai_responses", "status", reason) for reason in ("failed", "incomplete", "cancelled", "in_progress", "queued")]
        cases += [("anthropic", "stop_reason", reason) for reason in ("max_tokens", "tool_use", "refusal", "pause_turn")]
        cases += [("gemini", "finishReason", reason) for reason in ("MAX_TOKENS", "SAFETY", "RECITATION", "OTHER")]
        cases += [("ollama", "done", False), ("ollama", "done_reason", "length")]
        for provider, field, value in cases:
            for controls in (False, True):
                response = envelope(provider, control_answer() if controls else finding_answer())
                destination = response["choices"][0] if provider == "openai_chat" else response["candidates"][0] if provider == "gemini" else response
                destination[field] = value
                with self.subTest(provider=provider, status=value, controls=controls), self.assertRaises(judge.JudgeError):
                    self.invoke(provider, response, controls)

    def test_missing_or_wrong_type_native_envelopes_fail_closed(self):
        malformed = {
            "openai_chat": [{"choices": []}, {"choices": [False]}, {"choices": [{"message": {"content": None}}]}],
            "openai_responses": [{"output": None}, {"output": [False]}, {"output": [{"type": "message", "content": [False]}]}],
            "anthropic": [{"content": None}, {"content": [False]}, {"content": [{"type": "text", "text": None}]}],
            "gemini": [{"candidates": []}, {"candidates": [False]}, {"candidates": [{"content": {"parts": [False]}}]}],
            "ollama": [{"message": None}, {"message": {}}, {"message": {"content": []}}],
            "custom": [{"data": []}, {"data": [False]}, {"data": [{"review": None}]}],
        }
        for provider, responses in malformed.items():
            for index, response in enumerate(responses):
                with self.subTest(provider=provider, case=index), self.assertRaises(judge.JudgeError):
                    self.invoke(provider, response)

    def test_transport_byte_limit_is_inclusive_and_enforced_before_json_parse(self):
        raw = json.dumps({"padding": "x" * 1009}).encode()
        self.assertEqual(len(raw), 1024)
        for extra in (b"", b" "):
            opener = mock.Mock()
            opener.open.return_value = Response(raw + extra)
            with self.subTest(extra=len(extra)), mock.patch.object(judge.request, "build_opener", return_value=opener):
                if extra:
                    with self.assertRaisesRegex(judge.JudgeError, "max_response_bytes"):
                        judge._post_json(judge._validate_config(config(max_response_bytes=1024)), {}, b"{}")
                else:
                    self.assertEqual(judge._post_json(judge._validate_config(config(max_response_bytes=1024)), {}, b"{}")["padding"], "x" * 1009)
            self.assertEqual(opener.open.call_count, 1)

    def test_transport_rejects_bad_utf8_nested_duplicate_keys_and_nonfinite_numbers(self):
        bodies = (b'{"private":"\xff"}', b'{"nested":{"key":1,"key":2}}',
                  b'{"nested":{"value":Infinity}}', b'{"nested":{"value":-Infinity}}',
                  b'[{"control_assessments":[]}]', b'{"ok":true}TRAILING_PRIVATE_CANARY')
        for raw in bodies:
            opener = mock.Mock()
            opener.open.return_value = Response(raw)
            with self.subTest(raw=repr(raw)), mock.patch.object(judge.request, "build_opener", return_value=opener), self.assertRaises(judge.JudgeError) as ctx:
                judge._post_json(judge._validate_config(config()), {}, b"{}")
            self.assertNotIn("PRIVATE_CANARY", str(ctx.exception))
            self.assertEqual(opener.open.call_count, 1)

    def test_custom_extraction_path_cannot_execute_attributes_or_code(self):
        for path in ("__class__", "data.__dict__", "data.0.review.__class__", "data[-1].review", "data.999999.review"):
            with self.subTest(path=path), self.assertRaises(judge.JudgeError):
                self.invoke("custom", envelope("custom", control_answer()), options={"response_path": path})

    def test_model_order_does_not_change_control_check_order_or_omission_accounting(self):
        payload = copy.deepcopy(CONTROL_INPUT)
        payload["controls"].append(dict(payload["controls"][0], id="AUTH-02"))
        output = control_answer()
        output["control_assessments"][0]["check_assessments"].reverse()
        output["control_assessments"].insert(0, {"control_id": "AUTH-02", "check_assessments": [
            {"check_index": 2, "status": "insufficient_evidence", "reason": "The excerpt cannot establish the second check.",
             "citations": [], "verification_steps": ["Obtain the missing verification evidence."]}]})
        with mock.patch.object(judge, "_post_json", return_value=envelope("openai_chat", output)):
            result = judge.review_controls(config(), payload)
        self.assertEqual([entry["control_id"] for entry in result["control_assessments"]], ["AUTH-01", "AUTH-02"])
        self.assertEqual(result["omitted_controls"], 0)
        self.assertEqual(result["omitted_checks"], 1)
        for control in result["control_assessments"]:
            self.assertEqual([check["check_index"] for check in control["check_assessments"]], [1, 2])
        missing, model = result["control_assessments"][1]["check_assessments"]
        self.assertEqual(missing["status"], model["status"])
        self.assertFalse(missing["model_supplied"])
        self.assertTrue(model["model_supplied"])


if __name__ == "__main__":
    unittest.main()
