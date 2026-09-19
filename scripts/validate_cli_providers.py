#!/usr/bin/env python3
"""Opt-in live smoke validation of official CLI security-review transports.

Only the fixed synthetic payloads below are submitted. No scanned repository,
credential file, account identity, raw stderr or login URL is collected.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_security_scan import __version__
from ai_security_scan.cli_judge import CLIJudgeError, validate_cli_config
from ai_security_scan.judge import JudgeError, review, review_controls
from ai_security_scan.report import atomic_write
from ai_security_scan.security import redact_object


SOURCE = "import os\ndef run(user_input):\n    os.system(user_input)"
FINDINGS = {
    "findings": [{"finding_id": "LIVE-F1", "rule_id": "AI002", "path": "synthetic.py", "line": 2,
                  "evidence": "os.system(user_input)",
                  "note": "Synthetic untrusted-input fixture; no source execution."}],
    "limitations": ["Only a synthetic single-line fixture is supplied."],
}
CONTROLS = {
    "controls": [{"id": "LIVE-C1", "checks": ["Check whether this function passes untrusted input to shell execution."],
                  "validation": "hybrid", "evidence_ids": ["LIVE-E1"]}],
    "evidence": [{"evidence_id": "LIVE-E1", "path": "synthetic.py", "start_line": 1, "end_line": 3,
                  "source_sha256": hashlib.sha256(SOURCE.encode("utf-8")).hexdigest(), "text": SOURCE}],
}


def parser():
    p = argparse.ArgumentParser(
        description="Run fixed synthetic findings/control payloads through Invarune's real CLI adapters and deterministic response validators. Explicit opt-in is required; calls consume the selected provider's account usage.",
        epilog="Example: python3 scripts/validate_cli_providers.py --provider codex --allow-live-requests\n"
               "Reproduce the recorded Grok preflight attempt: --provider grok --stage findings --allow-live-requests\n"
               "Use invarune --login PROVIDER separately if sign-in is needed. This harness never opens a login flow, executes fixture code or publishes files remotely.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--provider", choices=("codex", "claude", "grok"), required=True, help="One installed official CLI to validate")
    p.add_argument("--stage", choices=("findings", "controls", "both"), default="both", help="Fixed synthetic review stages (default: both; at most two advisory requests)")
    p.add_argument("--allow-live-requests", action="store_true", help="Explicitly permit these live synthetic model requests and account usage; required even for an expected preflight failure")
    p.add_argument("--model", help="Optional model override; omitted uses Invarune's provider default")
    p.add_argument("--executable", help="Trusted absolute executable path or bare official command name")
    p.add_argument("--cli-home", help="Existing clean Grok profile directory; Grok-only; no credentials are copied")
    p.add_argument("--timeout", type=float, default=120, help="Per-stage timeout in seconds, including provider preflight (0.1–300; default: 120)")
    p.add_argument("--output", type=Path, default=ROOT / "test-output" / "cli-providers", help="Local receipt directory (default: ignored test-output/cli-providers); nothing is uploaded")
    return p


def safe_receipt(value):
    """Keep already minimized output free of URLs and machine-specific paths."""
    value = redact_object(value)
    if isinstance(value, dict):
        return {key: safe_receipt(item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_receipt(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"https?://[^\s\"'<>]+", "<URL omitted>", value)
        value = re.sub(r"/(?:Users|home|private|var|tmp|etc|opt|usr|Applications|Volumes)/[^\s\"'<>]+", "<local path omitted>", value)
        value = re.sub(r"[A-Za-z]:[\\/][^\s\"'<>]+", "<local path omitted>", value)
    return value


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not args.allow_live_requests:
        p.error("--allow-live-requests is required; no provider was called")
    config = {"provider": args.provider + "_cli", "timeout_seconds": args.timeout}
    for key, value in (("model", args.model), ("executable", args.executable), ("cli_home", args.cli_home)):
        if value is not None:
            config[key] = value
    try:
        config = validate_cli_config(config)
    except CLIJudgeError as exc:
        p.error(str(exc))
    stages = [("findings", review, FINDINGS), ("controls", review_controls, CONTROLS)]
    if args.stage != "both":
        stages = [item for item in stages if item[0] == args.stage]
    receipt = {"schema_version": "1.0", "provider": config["provider"],
               "input_kind": "synthetic, no target execution", "scanner_version": __version__,
               "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
               "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "requested_model": config["model"], "timeout_seconds_per_stage": config["timeout_seconds"],
               "results": []}
    path = args.output / (config["provider"] + ".json")
    try:
        # Establish a writable receipt before any paid operation.
        atomic_write(path, json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        for stage, method, payload in stages:
            started = time.monotonic()
            try:
                response = method(config, payload)
                result = {"stage": stage, "status": "completed", "response": response}
            except JudgeError as exc:
                result = {"stage": stage, "status": "error", "error": str(exc)}
            result["seconds"] = round(time.monotonic() - started, 3)
            receipt["results"].append(safe_receipt(result))
            atomic_write(path, json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            print(json.dumps({"provider": config["provider"], "stage": stage,
                              "status": result["status"], "seconds": result["seconds"]}), flush=True)
    except (OSError, ValueError):
        print("Cannot write local CLI validation receipt.", file=sys.stderr)
        return 2
    return 0 if all(item["status"] == "completed" for item in receipt["results"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
