"""Explicit, deterministic user dispositions with retained evidence and audit counts.

Policies are never discovered in the scan target. A caller must deliberately load
one and apply it after collecting source or image evidence. A user disposition is
an assessment exception, not a validated pass or evidence of remediation.
"""
import copy
import json
from pathlib import Path

from .fs import read_confined
from .rules import RULES
from .scanner import SEVERITIES, _digest, load_controls
from .security import redact


MAX_CONFIG_BYTES = 1_000_000
MAX_REASON_CHARS = 8_000
DEFAULT_DISABLED_REASON = "Disabled by explicit user configuration."
ASSURANCE = (
    "User dispositions are not validated passes and are excluded from actionable "
    "finding and active review counts. Rule dispositions affect their findings; "
    "control and check dispositions affect review scope only and never waive "
    "static rule findings. Observed evidence and operational coverage gaps remain "
    "in the report. Shared static analysis may still collect evidence for disabled rules."
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Review configuration contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Review configuration must contain standard JSON values")


def _valid_text(value):
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return all(ord(character) >= 32 or character in "\n\r\t" for character in value)


def validate_review_config(value):
    """Return a canonical, independently owned policy; reject ambiguous input."""
    if not isinstance(value, dict) or set(value) - {"schema_version", "rules", "controls", "checks"}:
        raise ValueError("Review configuration must be an object with only schema_version, rules, controls, and checks")
    if value.get("schema_version") != "1.0":
        raise ValueError("Review configuration requires schema_version '1.0'")
    controls = {control["id"]: control for control in load_controls()}
    known = {
        "rules": {rule["id"] for rule in RULES},
        "controls": set(controls),
        "checks": {"{}:{}".format(identifier, index) for identifier, control in controls.items()
                   for index in range(1, len(control["checks"]) + 1)},
    }
    result = {"schema_version": "1.0"}
    for scope in ("rules", "controls", "checks"):
        entries = value.get(scope, {})
        if not isinstance(entries, dict):
            raise ValueError("Review configuration {} must be an object".format(scope))
        normalized = {}
        # Reject unknown/nonstring keys before sorting, including programmatic
        # callers passing mixed types or an invalid Unicode key.
        if any(not _valid_text(identifier) or identifier not in known[scope] for identifier in entries):
            raise ValueError("Review configuration contains an unknown {} identifier".format(scope))
        for identifier in sorted(entries):
            item = entries[identifier]
            if not isinstance(item, dict) or set(item) - {"status", "reason"}:
                raise ValueError("Every review disposition must contain only status and optional reason")
            status = item.get("status")
            if not isinstance(status, str) or status not in {"disabled", "justified"}:
                raise ValueError("Review disposition status must be disabled or justified")
            reason = item.get("reason", DEFAULT_DISABLED_REASON if status == "disabled" else None)
            if not _valid_text(reason) or not reason.strip() or len(reason) > MAX_REASON_CHARS:
                raise ValueError("Review dispositions require a nonblank Unicode reason of at most 8000 characters; only disabled may omit it")
            normalized[identifier] = {"status": status, "reason": reason}
        result[scope] = normalized
    if any(identifier.rsplit(":", 1)[0] in result["controls"] for identifier in result["checks"]):
        raise ValueError("A review configuration cannot specify both a whole control and its individual checks")
    # The file reader enforces the byte bound before parsing; enforce the same
    # limit for callers constructing dictionaries directly.
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("Review configuration exceeds the 1000000-byte limit")
    return result


def load_review_config(path):
    """Read an explicit bounded UTF-8 JSON regular file without following it."""
    try:
        path = Path(path).expanduser().absolute()
        if path.is_symlink():
            raise ValueError("Review configuration must not be a symbolic link")
        # Resolve the parent so macOS /tmp aliases are harmless while retaining
        # a no-follow open for the file itself. Parent loops raise RuntimeError
        # on older Python versions and must remain ordinary config errors.
        parent = path.parent.resolve(strict=True)
        data, _ = read_confined(parent, path.name, MAX_CONFIG_BYTES)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ValueError("Review configuration must be a readable regular file of at most 1000000 bytes, not a symbolic link") from exc
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Review configuration must be valid UTF-8 JSON") from exc
    return validate_review_config(value)


def _disposition(item, scope, identifier):
    return {"status": item["status"], "reason": redact(item["reason"]), "scope": scope, "id": identifier}


def _mapped_status(control, groups):
    if control.get("automated_rule_ids"):
        if groups["open"]:
            return "findings_detected"
        if groups["suppressed"]:
            return "findings_suppressed"
        if groups["justified"] and groups["disabled"]:
            return "findings_exempted"
        if groups["justified"]:
            return "findings_justified"
        if groups["disabled"]:
            return "findings_disabled"
        return "no_pattern_detected"
    if control.get("validation") == "dynamic":
        return "runtime_validation_required"
    if control.get("validation") == "manual":
        return "manual_review_required"
    return "review_required"


def apply_review_config(report, policy):
    """Return a copy with explicit exclusions; never discard findings or gaps.

    Rule exceptions take precedence over a matching legacy finding baseline but
    retain its original status and suppression reason. Acceptance check/control
    exceptions never affect the findings gate. Applying the same policy twice is
    idempotent; to replace a policy, apply it to the original static report.
    """
    if policy is None:
        return copy.deepcopy(report)
    policy = validate_review_config(policy)
    digest = _digest(policy)
    existing = report.get("review_policy")
    if existing:
        if existing.get("sha256") == digest:
            return copy.deepcopy(report)
        raise ValueError("Apply a different review configuration to the original static report")
    result = copy.deepcopy(report)
    # Executive summaries are derived from the final finding/control states.
    result.pop("assessment", None)
    findings = result.get("findings", [])
    for finding in findings:
        item = policy["rules"].get(finding["rule_id"])
        if item:
            finding["original_status"] = finding["status"]
            finding["status"] = item["status"]
            finding["disposition"] = _disposition(item, "rule", finding["rule_id"])

    rule_ids = sorted(rule["id"] for rule in RULES)
    controls = result.get("controls", [])
    counts = {"catalog_rules": len(rule_ids), "catalog_controls": len(controls),
              "catalog_checks": sum(len(control.get("checks", [])) for control in controls)}
    for status in ("active", "justified", "disabled"):
        counts[status + "_rules"] = sum(policy["rules"].get(identifier, {}).get("status", "active") == status for identifier in rule_ids)
        counts[status + "_controls"] = 0
        counts[status + "_checks"] = 0
    counts["mixed_excluded_controls"] = 0
    for control in controls:
        identifier = control["id"]
        control["static_status"] = control["status"]
        mapped = set(control.get("automated_rule_ids", []))
        groups = {status: [finding["id"] for finding in findings
                          if finding["rule_id"] in mapped and finding["status"] == status]
                  for status in ("open", "suppressed", "justified", "disabled")}
        for status, ids in groups.items():
            control[("" if status == "open" else status + "_") + "finding_ids"] = ids
        control["status"] = _mapped_status(control, groups)
        whole = policy["controls"].get(identifier)
        if whole:
            control["disposition"] = _disposition(whole, "control", identifier)
        check_dispositions = []
        for index, _ in enumerate(control.get("checks", []), 1):
            check_id = "{}:{}".format(identifier, index)
            item = whole or policy["checks"].get(check_id)
            entry = {"check_id": check_id, "check_index": index, "status": "active", "reason": ""}
            if item:
                entry.update(_disposition(item, "control" if whole else "check", identifier if whole else check_id))
            check_dispositions.append(entry)
            counts[entry["status"] + "_checks"] += 1
        control["check_dispositions"] = check_dispositions
        states = {entry["status"] for entry in check_dispositions}
        if "active" in states:
            counts["active_controls"] += 1
        elif states == {"justified"}:
            control["status"] = "justified"
            counts["justified_controls"] += 1
        elif states == {"disabled"}:
            control["status"] = "disabled"
            counts["disabled_controls"] += 1
        else:
            control["status"] = "excluded_from_review"
            counts["mixed_excluded_controls"] += 1
    counts["excluded_controls"] = len(controls) - counts["active_controls"]

    summary = result["summary"]
    for status in ("open", "suppressed", "justified", "disabled"):
        summary[status + "_findings"] = sum(finding["status"] == status for finding in findings)
    summary["severity_counts"] = {severity: sum(finding["status"] == "open" and finding["severity"] == severity for finding in findings)
                                  for severity in SEVERITIES}
    coverage = result["coverage"]
    for status, field in (("active", "rules_enabled"), ("justified", "rules_justified"), ("disabled", "rules_disabled")):
        coverage[field] = [identifier for identifier in rule_ids if policy["rules"].get(identifier, {}).get("status", "active") == status]
    entries = {scope: {identifier: {"status": item["status"], "reason": redact(item["reason"])}
                       for identifier, item in policy[scope].items()}
               for scope in ("rules", "controls", "checks")}
    result["review_policy"] = {"enabled": True, "schema_version": "1.0", "sha256": digest,
                               "entries": entries, "counts": counts, "assurance": ASSURANCE}
    result["configuration"]["review_config_sha256"] = digest
    result["scan_id"] = _digest({"static_scan_id": report["scan_id"], "review_config_sha256": digest})
    return result
