#!/usr/bin/env python3
"""Loopback-only documentation fixture. It supplies scripted answers, never AI judgment.

Run in a second terminal, leave open during scenario 9, and stop with Ctrl+C.
Only 127.0.0.1 is bound. Configs contain no credentials. No target code runs.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

PROVIDERS = ("custom", "openai_chat", "openai_responses", "anthropic", "gemini", "ollama")
MARKER = "UNTRUSTED_REPOSITORY_DATA_JSON:\n"


def request_payload(provider, body):
    if provider == "custom":
        prompt = body["review_prompt"]
    elif provider == "openai_responses":
        prompt = body["input"]
    elif provider == "gemini":
        prompt = body["contents"][0]["parts"][0]["text"]
    else:
        prompt = body["messages"][-1]["content"]
    return json.loads(prompt.split(MARKER, 1)[1])


def envelope(provider, answer):
    text = json.dumps(answer)
    if provider == "custom":
        return {"data": {"review": answer}}
    if provider == "openai_chat":
        return {"choices": [{"finish_reason": "stop", "message": {"content": text}}]}
    if provider == "openai_responses":
        return {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}]}
    if provider == "anthropic":
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}
    if provider == "gemini":
        return {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": text}]}}]}
    return {"done": True, "done_reason": "stop", "message": {"content": text}}


def answer(payload, investigate=False):
    reason = "SCRIPTED DOCUMENTATION FIXTURE: no real model or runtime validation occurred."
    if "controls" not in payload:
        return {"assessments": [{"finding_id": f.get("finding_id", f.get("id")), "verdict": "needs_review", "reason": reason}
                                for f in payload["findings"]], "additional_concerns": []}
    investigation = payload.get("investigation", {})
    if investigate and investigation.get("requests_allowed"):
        entry = next((item for item in investigation["inventory"] if item["path"] == "delivery.py"), None)
        if entry:
            return {"control_assessments": [], "evidence_requests": [{
                "control_id": payload["controls"][0]["id"], "check_index": 1,
                "file_id": entry["file_id"], "start_line": 13, "end_line": min(41, entry["line_count"]),
                "purpose": "counterevidence", "reason": "Inspect the fixture admission predicate before delivery.",
                "counterevidence": "A destination guard might constrain this path."}]}
    results = []
    for control in payload["controls"]:
        results.append({"control_id": control["id"], "check_assessments": [
            {"check_index": index, "status": "insufficient_evidence", "reason": reason, "citations": [],
             "verification_steps": ["Replace this scripted fixture with an authorized provider and validate deployed boundaries."]}
            for index, _ in enumerate(control["checks"], 1)]})
    value = {"control_assessments": results}
    if investigation:
        value["evidence_requests"] = []
    return value


def create_server(output):
    output.mkdir(parents=True, exist_ok=True)
    records = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                provider, mode = self.path.strip("/").split("/", 1)
                if provider not in PROVIDERS:
                    raise ValueError("Unknown fixture protocol")
                size = int(self.headers.get("Content-Length", "0"))
                if size <= 0 or size > 2000000:
                    raise ValueError("Fixture request outside size bound")
                body = json.loads(self.rfile.read(size))
                payload = request_payload(provider, body)
                response = answer(payload, mode == "investigate")
                records.append({"provider": provider, "mode": mode, "stage": "controls" if "controls" in payload else "findings",
                                "payload_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
                                "requested_ranges": len(response.get("evidence_requests", [])),
                                "source": "scripted local HTTP fixture, no real model"})
                (output / "requests.json").write_text(json.dumps(records, indent=2) + "\n")
                raw = json.dumps(envelope(provider, response)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (ValueError, KeyError, IndexError, TypeError):
                self.send_error(400, "Invalid documentation fixture request")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    for provider in PROVIDERS:
        config = {"provider": provider, "model": "scripted-local-fixture", "endpoint": "http://127.0.0.1:%d/%s/review" % (server.server_port, provider),
                  "timeout_seconds": 10}
        if provider == "custom":
            config.update(request_template={"review_prompt": "${PROMPT}", "deployment": "${MODEL}"}, response_path="data.review")
        (output / (provider + ".json")).write_text(json.dumps(config, indent=2) + "\n")
        if provider == "custom":
            config["endpoint"] = config["endpoint"].replace("/review", "/investigate")
            (output / "investigation.json").write_text(json.dumps(config, indent=2) + "\n")
    (output / "ready.json").write_text(json.dumps({"protocols": list(PROVIDERS), "real_model_calls": 0}) + "\n")
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Directory for loopback configs and sanitized request receipts")
    args = parser.parse_args()
    server = create_server(args.output)
    print("Scripted loopback gateway ready; leave this terminal open during scenario 9. Ctrl+C stops it.", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
