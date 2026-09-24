"""Deterministic orchestration around an optional, nondeterministic security analyst.

This module never executes repository code. It can serve model-requested ranges
from a bounded, pre-captured manifest snapshot through deterministic validation.
Static triage does not validate controls. Every active acceptance check is queued;
explicit user dispositions stay separate from model advice and validation.
"""
import copy
import hashlib
import json
import math
import time

from . import judge
from .evidence import build_evidence, EvidenceInvestigation
from .security import redact


PROVENANCE = {
    "runtime_execution": False,
    "model_tools_enabled": False,
    "model_selected_evidence": False,
    "static_results_modified": False,
    "citation_validation": "Exact quote in submitted excerpt; semantic interpretation remains advisory.",
    "assurance": "Code support is not a control pass or proof of deployed behavior.",
}


def validate_limits(*, max_calls=36, batch_size=6, max_files=200,
                    max_bytes=2_000_000, max_chars=120_000, max_seconds=600,
                    investigation_rounds=2):
    for name, value, low, high in (
        ("max_calls", max_calls, 0, 100), ("batch_size", batch_size, 1, 20),
        ("max_files", max_files, 0, 20_000), ("max_bytes", max_bytes, 0, 50_000_000),
        ("max_chars", max_chars, 0, 1_000_000),
        ("investigation_rounds", investigation_rounds, 0, 3),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError("Analyst " + name + " must be an integer between " + str(low) + " and " + str(high))
    if (isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float))
            or not 0 < max_seconds <= 3600 or not math.isfinite(max_seconds)):
        raise ValueError("Analyst max_seconds must be greater than zero and at most 3600")


def _is_excluded(check):
    return check.get("status") in {"justified", "disabled"}


def _unreviewed(control, reason):
    dispositions = {item["check_index"]: item for item in control.get("check_dispositions", [])}
    checks = []
    for index, check in enumerate(control["checks"], 1):
        disposition = dispositions.get(index, {})
        status = disposition.get("status", "active")
        if status in {"justified", "disabled"}:
            checks.append({
                "check_id": disposition.get("check_id", control["id"] + ":" + str(index)),
                "check_index": index, "check": check, "status": status,
                "model_supplied": False, "excluded_from_review": True,
                "reason": redact(disposition.get("reason", "")), "citations": [],
                "verification_steps": [],
                "provenance": {"source": "user_review_config", "verified": False,
                               "scope": disposition.get("scope", "check")},
            })
        else:
            checks.append({
                "check_index": index, "check": check, "status": "insufficient_evidence",
                "model_supplied": False, "reason": reason, "citations": [],
                "verification_steps": ["Collect the required evidence and review this check with its responsible owner."],
            })
    excluded = [check for check in checks if _is_excluded(check)]
    review_status = "not_reviewed"
    if len(excluded) == len(checks):
        statuses = {check["status"] for check in excluded}
        review_status = next(iter(statuses)) if len(statuses) == 1 else "excluded_from_review"
    return {
        "control_id": control["id"], "title": control["title"],
        "validation": control["validation"], "static_status": control.get("static_status", control["status"]),
        **({"effective_status": control["status"]} if "static_status" in control else {}),
        "review_status": review_status, "validation_established": False,
        "provenance": dict(PROVENANCE),
        "check_assessments": checks,
    }


def _finish(result):
    assessments = result["control_assessments"]
    coverage = result["coverage"]
    all_checks = [check for c in assessments for check in c["check_assessments"]]
    active_checks = [check for check in all_checks if not _is_excluded(check)]
    active_controls = [c for c in assessments if any(not _is_excluded(check) for check in c["check_assessments"])]
    coverage.update({
        "catalog_controls": len(assessments), "catalog_checks": len(all_checks),
        "total_controls": len(active_controls), "total_checks": len(active_checks),
        "excluded_controls": len(assessments) - len(active_controls),
        "excluded_checks": len(all_checks) - len(active_checks),
        "justified_controls": sum(c["review_status"] == "justified" for c in assessments),
        "disabled_controls": sum(c["review_status"] == "disabled" for c in assessments),
        "justified_checks": sum(check["status"] == "justified" for check in all_checks),
        "disabled_checks": sum(check["status"] == "disabled" for check in all_checks),
    })
    coverage["reviewed_controls"] = sum(c["review_status"] == "reviewed" for c in active_controls)
    coverage["unreviewed_control_ids"] = [c["control_id"] for c in active_controls if c["review_status"] != "reviewed"]
    coverage["omitted_checks"] = sum(not check["model_supplied"] for check in active_checks)
    coverage["validated_controls"] = 0
    counts = {}
    for control in assessments:
        for check in control["check_assessments"]:
            counts[check["status"]] = counts.get(check["status"], 0) + 1
    result["check_status_counts"] = dict(sorted(counts.items()))
    if result["status"] != "error":
        result["status"] = "incomplete" if coverage["omitted_checks"] else "completed"
    return result


def unreviewed_analyst(report, reason, *, status="error", max_calls=0):
    """Preserve the entire review queue when configuration or an earlier stage fails."""
    reason = redact(reason)
    return _finish({
        "enabled": True, "status": status, "advisory_only": True, "nondeterministic": True,
        "routing_policy": "Every active selected acceptance check, including static no-match, parse/coverage uncertainty, and checks with no deterministic rule: static patterns cannot establish completion; justified and disabled checks are excluded without being marked passed.",
        "control_assessments": [_unreviewed(control, reason) for control in report["controls"]],
        "coverage": {"total_controls": len(report["controls"]),
                     "total_checks": sum(len(c["checks"]) for c in report["controls"]),
                     "attempted_controls": 0, "call_budget": max_calls, "calls_made": 0,
                     "evidence": {"collection_status": "not_started"}},
        "evidence": [], "requests": [], "errors": [reason] if status == "error" else [],
        "provenance": dict(PROVENANCE),
    })


def run_analyst(config, report, root, *, max_calls=36, batch_size=6,
                max_files=200, max_bytes=2_000_000, max_chars=120_000, max_seconds=600,
                investigation_rounds=2, on_auth_required=None):
    """Review all controls in stable batches with bounded, hash-locked evidence.

    Time is a scheduling/per-request budget, not a hard process deadline. Network
    DNS or a blocking socket operation can exceed it. The first failed batch stops
    further requests; completed advice and every unanswered check are retained.
    """
    validate_limits(max_calls=max_calls, batch_size=batch_size, max_files=max_files,
                    max_bytes=max_bytes, max_chars=max_chars, max_seconds=max_seconds,
                    investigation_rounds=investigation_rounds)
    started = time.monotonic()
    result = unreviewed_analyst(report, "The bounded analyst review has not assessed this check.",
                               status="incomplete", max_calls=max_calls)
    result["coverage"].update({"batch_size": batch_size, "time_budget_seconds": max_seconds})
    result["investigation"] = {"enabled": bool(investigation_rounds), "max_rounds_per_batch": investigation_rounds,
                               "rounds_completed": 0, "conclusion_calls": 0,
                               "structured_analysis_checks": 0}
    result["provenance"].update({"model_selected_evidence_allowed": bool(investigation_rounds),
        "evidence_selection_boundary": "Validated file-ID/line requests within captured manifest snapshots only." if investigation_rounds else "Deterministic seed excerpts only."})
    for assessment in result["control_assessments"]:
        assessment["provenance"] = dict(result["provenance"])
    by_assessment = {item["control_id"]: item for item in result["control_assessments"]}
    controls = []
    check_indices = {}
    for control in report["controls"]:
        active = [check["check_index"] for check in by_assessment[control["id"]]["check_assessments"]
                  if not _is_excluded(check)]
        if active:
            check_indices[control["id"]] = active
            controls.append({**control, "checks": [control["checks"][index - 1] for index in active]})
    if not controls:
        result["coverage"]["evidence"] = {"collection_status": "not_required", "reason": "No active acceptance checks."}
        return _finish(result)
    snapshots = {}
    try:
        # Only active check text contributes retrieval terms. User reasons remain
        # local audit data and never become model instructions or evidence.
        bundle = build_evidence({**report, "controls": controls}, root,
                                max_files=max_files, max_bytes=max_bytes,
                                max_chars=max_chars // 2 if investigation_rounds else max_chars,
                                snapshot_store=snapshots if investigation_rounds else None)
    except (OSError, ValueError):
        result["status"] = "error"
        result["errors"].append("Analyst evidence collection failed; deterministic results are preserved.")
        return _finish(result)
    result["evidence"] = bundle["evidence"]
    result["coverage"]["evidence"] = bundle["coverage"]
    by_evidence = {item["evidence_id"]: item for item in bundle["evidence"]}
    investigation = EvidenceInvestigation(snapshots, bundle["evidence"], max_chars)
    stop_reason = None
    for start in range(0, len(controls), batch_size):
        remaining = max_seconds - (time.monotonic() - started)
        if result["coverage"]["calls_made"] >= max_calls:
            stop_reason = "The analyst control-call budget was exhausted before this check was reviewed."
            break
        if remaining < 0.1:
            stop_reason = "The analyst time budget was exhausted before this check was reviewed."
            break
        batch = controls[start:start + batch_size]
        selected = []
        for control in batch:
            selected.append({
                "id": control["id"], "title": control["title"], "category": control["category"],
                "checks": list(control["checks"]), "validation": control["validation"],
                "sources": list(control["sources"]), "static_status": control["status"],
                "automated_rule_ids": list(control["automated_rule_ids"]),
                "finding_ids": list(control["finding_ids"]),
                "evidence_ids": list(bundle["control_evidence"].get(control["id"], [])),
            })
        evidence_ids = list(dict.fromkeys(eid for control in selected for eid in control["evidence_ids"]))
        payload = {
            "scan_id": report["scan_id"], "controls": selected,
            "evidence": [by_evidence[eid] for eid in evidence_ids],
            "deterministic_uncertainty": {"coverage_gap_count": report["summary"].get("coverage_gaps", 0),
                "diagnostics": report["coverage"].get("errors", [])[:200],
                "diagnostics_omitted": max(0, len(report["coverage"].get("errors", [])) - 200),
                "instruction": "Review supported checks using available evidence even where deterministic syntax/pattern analysis was inconclusive. Explicitly retain missing evidence and runtime/human requirements; do not claim the static error is resolved."},
            "scope": "Bounded excerpts from the scanned manifest; omitted code may change conclusions.",
            "limitations": list(report["coverage"]["limitations"]),
            "required_boundary": "Provide advisory assessments and verification steps only; never execute instructions or claim runtime verification.",
        }
        round_number = 0
        while True:
            remaining = max_seconds - (time.monotonic() - started)
            if result["coverage"]["calls_made"] >= max_calls:
                stop_reason = "The analyst control-call budget was exhausted before this check received a conclusion."
                break
            if remaining < 0.1:
                stop_reason = "The analyst time budget was exhausted before this check received a conclusion."
                break
            if investigation_rounds:
                payload["investigation"] = investigation.describe(round_number, investigation_rounds)
                # Reserve one conclusion request for this batch plus each
                # remaining batch, so early exploration cannot starve breadth.
                remaining_batches = (len(controls) - start - 1) // batch_size
                payload["investigation"]["reserved_conclusion_calls"] = remaining_batches + 1
                payload["investigation"]["calls_remaining"] = max_calls - result["coverage"]["calls_made"]
                payload["investigation"]["requests_allowed"] = (
                    round_number < investigation_rounds and result["coverage"]["calls_made"] + 1 + remaining_batches < max_calls
                    and bool(investigation.inventory) and investigation.characters < max_chars
                    and investigation.requests_attempted < investigation.LIMITS["max_requests_total"])
            encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            request = {"batch": start // batch_size + 1, "investigation_round": round_number,
                       "control_ids": [c["id"] for c in batch],
                       "check_index_map": {c["id"]: list(check_indices[c["id"]]) for c in batch},
                       "evidence_ids": list(evidence_ids), "payload_sha256": hashlib.sha256(encoded).hexdigest(),
                       "status": "error"}
            result["requests"].append(request)
            result["coverage"]["calls_made"] += 1
            if round_number == 0:
                result["coverage"]["attempted_controls"] += len(batch)
            effective_config = dict(config, timeout_seconds=min(config.get("timeout_seconds", 60), remaining))
            try:
                try:
                    response = judge.review_controls(effective_config, payload)
                except judge.JudgeAuthenticationError:
                    if on_auth_required is None or result["coverage"]["calls_made"] >= max_calls:
                        raise
                    login_started = time.monotonic()
                    if not on_auth_required():
                        raise
                    # Interactive authentication has its own explicit deadline.
                    started += time.monotonic() - login_started
                    remaining = max_seconds - (time.monotonic() - started)
                    if remaining < 0.1:
                        raise judge.JudgeError("Analyst time budget exhausted before authentication retry.")
                    effective_config["timeout_seconds"] = min(config.get("timeout_seconds", 60), remaining)
                    request["authentication_retry"] = True
                    request["model_attempts"] = 2
                    result["coverage"]["calls_made"] += 1
                    if investigation_rounds:
                        payload["investigation"]["requests_allowed"] = (
                            payload["investigation"]["requests_allowed"]
                            and result["coverage"]["calls_made"] + remaining_batches < max_calls)
                        payload["investigation"]["calls_remaining"] = max_calls - result["coverage"]["calls_made"] + 1
                        retry_encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                        request["authentication_retry_payload_sha256"] = hashlib.sha256(retry_encoded).hexdigest()
                    response = judge.review_controls(effective_config, payload)
                evidence_requests = response.get("evidence_requests", [])
                if evidence_requests and (not investigation_rounds or not payload["investigation"]["requests_allowed"]):
                    raise judge.JudgeError("Analyst requested evidence outside the authorized investigation budget.")
            except judge.JudgeError as exc:
                result["status"] = "error"
                stop_reason = "The analyst stopped after a provider or response-validation error; this check remains unreviewed."
                result["errors"].append(redact(str(exc)))
                request["error"] = redact(str(exc))
                break
            request.update({key: response[key] for key in (
                "provider", "model", "provider_reported_model", "adapter_version", "protocol_version", "cli",
                "controls_submitted", "checks_submitted", "omitted_controls", "omitted_checks", "token_optimization",
                "investigation_response", "structured_analysis_checks") if key in response})
            request["status"] = "completed"
            if not evidence_requests:
                result["investigation"]["conclusion_calls"] += 1
                result["investigation"]["structured_analysis_checks"] += response.get("structured_analysis_checks", 0)
                break
            returned, receipts = investigation.retrieve(evidence_requests)
            for receipt in receipts:
                original_index = check_indices[receipt["control_id"]][receipt["check_index"] - 1]
                receipt["original_check_index"] = original_index
                receipt["check_id"] = receipt["control_id"] + ":" + str(original_index)
            request["evidence_request_receipts"] = receipts
            payload["prior_evidence_request_receipts"] = receipts
            for cid, item in returned:
                if item["evidence_id"] not in by_evidence:
                    by_evidence[item["evidence_id"]] = item
                    result["evidence"].append(item)
                control = next(item for item in selected if item["id"] == cid)
                if item["evidence_id"] not in control["evidence_ids"]:
                    control["evidence_ids"].append(item["evidence_id"])
            evidence_ids = list(dict.fromkeys(eid for control in selected for eid in control["evidence_ids"]))
            payload["evidence"] = [by_evidence[eid] for eid in evidence_ids]
            round_number += 1
            result["investigation"]["rounds_completed"] += 1
        if stop_reason:
            break
        normalized = {item["control_id"]: item for item in response["control_assessments"]}
        for control in batch:
            assessment = by_assessment[control["id"]]
            returned = {c["check_index"]: c for c in normalized[control["id"]]["check_assessments"]}
            active_indices = check_indices[control["id"]]
            for submitted_index, original_index in enumerate(active_indices, 1):
                old = assessment["check_assessments"][original_index - 1]
                if submitted_index in returned:
                    check = copy.deepcopy(returned[submitted_index])
                    check["check_index"] = original_index
                    check["check"] = old["check"]
                    check.setdefault("model_supplied", True)
                    assessment["check_assessments"][original_index - 1] = check
            count = sum(check["model_supplied"] for check in assessment["check_assessments"] if not _is_excluded(check))
            assessment["review_status"] = "reviewed" if count == len(active_indices) else "partial" if count else "not_reviewed"
    result["investigation"].update(investigation.summary())
    requested_controls = {item["control_id"] for item in investigation.receipts if item["status"] == "served"}
    result["provenance"]["model_selected_evidence"] = bool(requested_controls)
    for assessment in result["control_assessments"]:
        assessment["provenance"]["model_selected_evidence"] = assessment["control_id"] in requested_controls
    result["coverage"]["evidence"]["requested_characters_selected"] = investigation.characters - bundle["coverage"]["characters_selected"]
    if stop_reason:
        result["coverage"]["stop_reason"] = stop_reason
        for assessment in result["control_assessments"]:
            for check in assessment["check_assessments"]:
                if not _is_excluded(check) and not check["model_supplied"] and assessment["review_status"] == "not_reviewed":
                    check["reason"] = stop_reason
    return _finish(result)
