"""Bounded, editable human-review capsules bound to a fresh deterministic scan.

Only explicit user decision fields are imported. Report prose, severity edits,
model advice, URLs, and commands never become scanner configuration or evidence.
The capsule is a review record, not a signature, authentication, or a control pass.
"""
import copy
import datetime
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re

from .fs import read_confined
from .review_policy import apply_review_config
from .rules import RULES
from .scanner import _digest, load_controls
from .security import redact


MAX_REPORT_BYTES = 50_000_000
MAX_WORKSPACE_BYTES = 4_000_000
MAX_ITEMS = 10_000
EDITABLE_FIELDS = ("decision", "reason", "reviewer", "reviewed_at", "evidence_ref")
FIELD_LIMITS = {"decision": 32, "reason": 8000, "reviewer": 200, "reviewed_at": 64, "evidence_ref": 2000}
DECISIONS = ("", "justified", "disabled", "note", "needs_runtime_validation", "needs_human_review")
GAP_DECISIONS = ("", "note", "needs_runtime_validation", "needs_human_review")
MD_BEGIN = "<!-- INVARUNE_REVIEW_BEGIN -->"
MD_END = "<!-- INVARUNE_REVIEW_END -->"
HTML_CAPSULE_ID = "invarune-review"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_FINDING_ID = re.compile(r"finding:[0-9a-f]{24}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)?\Z")
_CONFIG_KEYS = {"max_file_bytes", "max_total_bytes", "max_files", "max_entries", "exclude",
                "default_excluded_directories", "generated_outputs_and_judge_config_excluded"}
_IMAGE_LIMIT_KEYS = {"max_archive_bytes", "max_unpacked_bytes", "max_layer_entries", "max_layers"}
_ORIGIN_KEYS = {"scan_id", "tool", "target", "configuration", "image_limits", "manifest_sha256",
                "catalog_sha256", "evidence_sha256", "scope_sha256"}
_ITEM_KEYS = {"id", "kind", "subject", "binding_sha256", *EDITABLE_FIELDS}


class ReviewWorkspace(dict):
    """A dict-compatible capsule with local loader provenance outside its JSON."""
    source_sha256 = None


class ReviewWorkspaceLimitError(ValueError):
    """A complete capsule cannot fit; static findings must still be preserved."""


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Review report contains duplicate JSON keys")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Review report must contain standard JSON values")


def _parse_json(text):
    try:
        return json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Review capsule must contain valid UTF-8 JSON") from exc


def _text(value, limit, *, multiline=False, required=False):
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError("Review field has an invalid type, length, or missing required text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("Review fields must contain valid Unicode") from exc
    # Reasons preserve the existing review-config Unicode contract, including
    # C1 Unicode characters. Single-line identity/reference fields stay stricter.
    if any((ord(character) < 32 or (not multiline and 127 <= ord(character) <= 159))
           and not (multiline and character in "\r\n\t") for character in value):
        raise ValueError("Review field contains unsupported control characters")
    return value


def _safe_text(value, limit):
    # POSIX paths can contain surrogate-escaped bytes and control characters.
    # Represent those bytes visibly rather than creating an invalid capsule.
    value = redact(str(value)).encode("utf-8", errors="backslashreplace").decode("utf-8")
    value = "".join(character if ord(character) >= 32 and not 127 <= ord(character) <= 159
                    else "\\u{:04x}".format(ord(character)) for character in value)
    return value[:limit]


def _object(value, keys, description):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("Invalid or unknown fields in review " + description)


def _digest_field(value):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ValueError("Review binding and origin digests must be lowercase SHA-256 values")


def _validate_configuration(value):
    if not isinstance(value, dict) or set(value) - _CONFIG_KEYS:
        raise ValueError("Invalid selected configuration in review origin")
    for key, item in value.items():
        if key in {"exclude", "default_excluded_directories"}:
            if not isinstance(item, list) or len(item) > 10000:
                raise ValueError("Invalid review origin exclusion list")
            for entry in item:
                _text(entry, 4000, required=True)
        elif key == "generated_outputs_and_judge_config_excluded":
            if not isinstance(item, bool):
                raise ValueError("Invalid review origin configuration flag")
        elif isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise ValueError("Invalid review origin scan limit")


def validate_workspace(value):
    """Strictly validate a capsule, retaining editable text without trusting it."""
    _object(value, {"schema_version", "kind", "origin", "items"}, "workspace")
    if value["schema_version"] != "1.0" or value["kind"] != "invarune_review":
        raise ValueError("Unsupported review workspace kind or schema version")
    origin = value["origin"]
    _object(origin, _ORIGIN_KEYS, "origin")
    for name in ("scan_id", "manifest_sha256", "catalog_sha256", "evidence_sha256", "scope_sha256"):
        _digest_field(origin[name])
    _object(origin["tool"], {"name", "version", "implementation_sha256"}, "tool identity")
    _text(origin["tool"]["name"], 200, required=True)
    _text(origin["tool"]["version"], 100, required=True)
    _digest_field(origin["tool"]["implementation_sha256"])
    _object(origin["target"], {"kind", "description", "platform"}, "target description")
    if not isinstance(origin["target"]["kind"], str) or origin["target"]["kind"] not in {"source", "image"}:
        raise ValueError("Invalid review target kind")
    _text(origin["target"]["description"], 1000, required=True)
    _text(origin["target"]["platform"], 100)
    _validate_configuration(origin["configuration"])
    limits = origin["image_limits"]
    if not isinstance(limits, dict) or set(limits) - _IMAGE_LIMIT_KEYS or any(
            isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in limits.values()):
        raise ValueError("Invalid review image limits")
    expected_scope = _digest({"kind": origin["target"]["kind"], "platform": origin["target"]["platform"],
                              "configuration": origin["configuration"], "image_limits": limits})
    if origin["scope_sha256"] != expected_scope:
        raise ValueError("Review origin selected-scope digest does not match its recorded configuration")
    if not isinstance(value["items"], list):
        raise ValueError("Review workspace items must be a list")
    if len(value["items"]) > MAX_ITEMS:
        raise ReviewWorkspaceLimitError("Review workspace exceeds the 10000-item limit")
    checks = {"check:{}:{}".format(control["id"], index) for control in load_controls()
              for index in range(1, len(control["checks"]) + 1)}
    seen = set()
    for item in value["items"]:
        _object(item, _ITEM_KEYS, "item")
        identifier, kind = item["id"], item["kind"]
        _text(identifier, 150, required=True)
        if identifier in seen:
            raise ValueError("Review workspace contains duplicate item IDs")
        seen.add(identifier)
        if (not isinstance(kind, str) or kind not in {"finding", "check", "gap"}
                or (kind == "finding" and not _FINDING_ID.fullmatch(identifier))
                or (kind == "check" and identifier not in checks)
                or (kind == "gap" and (not identifier.startswith("gap:") or not _HEX.fullmatch(identifier[4:])))):
            raise ValueError("Review workspace contains an unknown item identifier or kind")
        _text(item["subject"], 2000, required=True)
        _digest_field(item["binding_sha256"])
        for field in EDITABLE_FIELDS:
            _text(item[field], FIELD_LIMITS[field], multiline=field == "reason")
        if item["decision"] not in (GAP_DECISIONS if kind == "gap" else DECISIONS):
            raise ValueError("Invalid review decision; gaps cannot be justified or disabled and manual passes are unsupported")
        if item["decision"] and not item["reason"].strip():
            raise ValueError("Every nonblank review decision requires a reason")
        if item["decision"] in {"justified", "disabled"} and not item["reviewer"].strip():
            raise ValueError("Justified and disabled decisions require a reviewer")
        if not item["decision"] and any(item[field].strip() for field in EDITABLE_FIELDS[1:]):
            raise ValueError("Review text requires an explicit decision; use note for commentary")
        if item["reviewed_at"]:
            try:
                if not _DATE.fullmatch(item["reviewed_at"]):
                    raise ValueError("Unsupported date format")
                if "T" in item["reviewed_at"]:
                    datetime.datetime.fromisoformat(item["reviewed_at"].replace("Z", "+00:00"))
                else:
                    datetime.date.fromisoformat(item["reviewed_at"])
            except ValueError as exc:
                raise ValueError("reviewed_at must be an ISO date or timestamp") from exc
    try:
        size = len(_json(value).encode("utf-8"))
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Review workspace is not valid bounded JSON") from exc
    if size > MAX_WORKSPACE_BYTES:
        raise ReviewWorkspaceLimitError("Review workspace exceeds the 4000000-byte capsule limit")
    return copy.deepcopy(dict(value))


def _configuration(report):
    selected = {key: copy.deepcopy(value) for key, value in report.get("configuration", {}).items() if key in _CONFIG_KEYS}
    for key in ("exclude", "default_excluded_directories"):
        if key in selected:
            selected[key] = [_safe_text(item, 4000) for item in selected[key]]
    return selected


def _finding_binding(finding, manifest, origin, image_identity):
    immutable = {key: finding.get(key) for key in (
        "id", "rule_id", "path", "line", "end_line", "title", "description", "severity",
        "confidence", "evidence", "image_context", "image_provenance")}
    # Baseline changes are context changes. Preserve original_status when a
    # previous user rule/finding decision is already reflected in this report.
    immutable["baseline_status"] = finding.get("original_status", finding.get("status", "open"))
    immutable["baseline_reason"] = finding.get("suppression_reason", "")
    return _digest({"finding": immutable, "file": manifest.get(finding["path"]),
                    "scope": origin["scope_sha256"], "tool": origin["tool"],
                    "catalog": origin["catalog_sha256"], "image_identity": image_identity})


def _new_item(kind, identifier, subject, binding):
    return {"id": kind + ":" + identifier, "kind": kind, "subject": _safe_text(subject, 2000),
            "binding_sha256": binding, **{field: "" for field in EDITABLE_FIELDS}}


def build_workspace(report):
    """Create deterministic editable records from static data, never model advice."""
    if len(report.get("findings", [])) + sum(len(control.get("checks", [])) for control in report.get("controls", [])) > MAX_ITEMS:
        raise ReviewWorkspaceLimitError("Review workspace exceeds the 10000-item limit")
    image = report.get("image", {})
    tool = report["tool"]
    target = {"kind": "image" if image else "source",
              "description": _safe_text(image.get("display_target", "Selected source directory; paths are relative."), 1000),
              "platform": _safe_text(image.get("identity", {}).get("platform", ""), 100)}
    origin = {"scan_id": report["scan_id"],
              "tool": {"name": tool["name"], "version": tool["version"], "implementation_sha256": tool["implementation_sha256"]},
              "target": target, "configuration": _configuration(report),
              "image_limits": {key: value for key, value in image.get("limits", {}).items() if key in _IMAGE_LIMIT_KEYS},
              "manifest_sha256": _digest(report.get("files", [])),
              "catalog_sha256": _digest({"rules": RULES, "controls": load_controls()}),
              "evidence_sha256": _digest([{key: finding.get(key) for key in (
                  "id", "rule_id", "path", "line", "evidence", "severity", "image_context", "image_provenance")}
                  for finding in report.get("findings", [])])}
    origin["scope_sha256"] = _digest({"kind": target["kind"], "platform": target["platform"],
                                       "configuration": origin["configuration"], "image_limits": origin["image_limits"]})
    manifest = {item["path"]: item for item in report.get("files", [])}
    image_identity = image.get("identity", {})
    items = []
    for finding in report.get("findings", []):
        binding = _finding_binding(finding, manifest, origin, image_identity)
        item = _new_item("finding", finding["id"], "{} {} — {}:{}".format(
            finding["rule_id"], finding["title"], finding["path"], finding["line"]), binding)
        disposition = finding.get("disposition", {})
        if disposition.get("status") in {"justified", "disabled"}:
            item.update(decision=disposition["status"], reason=disposition.get("reason", ""), reviewer="Explicit review configuration")
        items.append(item)
    check_context = {"manifest": origin["manifest_sha256"], "catalog": origin["catalog_sha256"],
                     "scope": origin["scope_sha256"], "tool": origin["tool"], "image_identity": image_identity,
                     "coverage_errors": report.get("coverage", {}).get("errors", []),
                     "coverage_skipped": report.get("coverage", {}).get("skipped", [])}
    for control in report.get("controls", []):
        dispositions = {item["check_index"]: item for item in control.get("check_dispositions", [])}
        for index, check in enumerate(control.get("checks", []), 1):
            identifier = "{}:{}".format(control["id"], index)
            binding = _digest({"context": check_context, "control_id": control["id"], "check_index": index,
                               "check": check, "validation": control.get("validation"),
                               "mapped_rules": control.get("automated_rule_ids", [])})
            item = _new_item("check", identifier, identifier + " " + check, binding)
            disposition = dispositions.get(index, {})
            if disposition.get("status") in {"justified", "disabled"}:
                item.update(decision=disposition["status"], reason=disposition.get("reason", ""), reviewer="Explicit review configuration")
            items.append(item)
    gaps = [{"type": "error", **item} for item in report.get("coverage", {}).get("errors", [])]
    gaps += [{"type": "skipped", **item} for item in report.get("coverage", {}).get("skipped", []) if item.get("coverage_gap")]
    seen = set()
    for gap in gaps:
        identifier = _digest(gap)
        if identifier in seen:
            continue
        seen.add(identifier)
        binding = _digest({"gap": gap, "context": check_context})
        items.append(_new_item("gap", identifier, "{}: {}".format(gap.get("path", "."), gap.get("error", gap.get("reason", "Coverage gap"))), binding))
    # Only matching bindings may inherit a prior editable record. Stale decisions
    # remain in review_import, not silently reattached to new source evidence.
    prior = {item["id"]: item for item in report.get("review_workspace", {}).get("items", [])}
    for item in items:
        old = prior.get(item["id"], {})
        if old.get("binding_sha256") == item["binding_sha256"] and old.get("subject") == item["subject"]:
            for field in EDITABLE_FIELDS:
                item[field] = old.get(field, "")
    return validate_workspace({"schema_version": "1.0", "kind": "invarune_review", "origin": origin, "items": items})


class _CapsuleHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.matches = 0
        self.active = False
        self.complete = False
        self.data = []

    def handle_starttag(self, tag, attrs):
        matching = [value for key, value in attrs if key == "id" and value == HTML_CAPSULE_ID]
        if matching:
            if len({key for key, _ in attrs}) != len(attrs):
                raise ValueError("Duplicate attributes in review capsule element")
            self.matches += 1
            if self.matches > 1 or tag != "script" or dict(attrs).get("type") != "application/json":
                raise ValueError("Review HTML must contain exactly one application/json capsule script")
            self.active = True

    def handle_endtag(self, tag):
        if self.active and tag == "script":
            self.active = False
            self.complete = True

    def handle_data(self, data):
        if self.active:
            self.data.append(data)

    def capsule(self):
        if self.matches != 1 or not self.complete or self.active:
            raise ValueError("Review HTML is missing its unique complete capsule")
        return _parse_json("".join(self.data))


def _parse_html(text):
    parser = _CapsuleHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except (RecursionError, AssertionError) as exc:
        raise ValueError("Review HTML capsule could not be parsed") from exc
    return parser.capsule()


def load_review_report(path):
    """Import only the designated capsule from JSON, MD, HTML, SARIF, or PDF."""
    try:
        path = Path(path).expanduser().absolute()
        if path.is_symlink():
            raise ValueError("Symbolic link")
        data, _ = read_confined(path.parent.resolve(strict=True), path.name, MAX_REPORT_BYTES)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ValueError("Review report must be a regular non-symlink file of at most 50000000 bytes") from exc
    if data.startswith(b"%PDF-"):
        from .report_pdf import extract_review_workspace
        value = extract_review_workspace(data)
    else:
        try:
            text = data.decode("utf-8-sig", errors="strict")
        except UnicodeError as exc:
            raise ValueError("Non-PDF review reports must be valid UTF-8") from exc
        stripped = text.lstrip()
        if stripped.startswith("{"):
            document = _parse_json(text)
            if not isinstance(document, dict):
                raise ValueError("Review JSON must be an object")
            if document.get("kind") == "invarune_review":
                value = document
            elif "review_workspace" in document:
                value = document["review_workspace"]
            elif document.get("version") == "2.1.0" and isinstance(document.get("runs"), list) and len(document["runs"]) == 1:
                run = document["runs"][0]
                properties = run.get("properties", {}) if isinstance(run, dict) else None
                value = properties.get("invarune_review") if isinstance(properties, dict) else None
            else:
                raise ValueError("Review JSON/SARIF is missing its designated capsule")
        elif path.suffix.lower() in {".html", ".htm"} or re.match(r"(?is)<(?:!doctype\s+html|html\b)", stripped):
            value = _parse_html(text)
        elif MD_BEGIN in text or MD_END in text:
            if text.count(MD_BEGIN) != 1 or text.count(MD_END) != 1:
                raise ValueError("Review Markdown requires exactly one capsule marker pair")
            start, end = text.index(MD_BEGIN) + len(MD_BEGIN), text.index(MD_END)
            block = text[start:end].strip() if start < end else ""
            match = re.fullmatch(r"(`{3,})json\r?\n([\s\S]*)\r?\n\1", block)
            if not match:
                raise ValueError("Review Markdown capsule must be a single fenced JSON block")
            value = _parse_json(match.group(2))
        elif "<" in stripped[:100]:
            value = _parse_html(text)
        else:
            raise ValueError("Unrecognized review report format or missing capsule")
    workspace = ReviewWorkspace(validate_workspace(value))
    workspace.source_sha256 = hashlib.sha256(data).hexdigest()
    return workspace


def apply_review_workspace(report, workspace):
    """Bind explicit human decisions to freshly scanned evidence; retain drift."""
    source_sha256 = getattr(workspace, "source_sha256", None)
    workspace = validate_workspace(workspace)
    source_sha256 = source_sha256 or _digest(workspace)
    if report.get("review_policy") or report.get("review_import"):
        raise ValueError("Apply an imported review to the original fresh static report without review configuration")
    current = build_workspace(report)
    by_id = {item["id"]: item for item in current["items"]}
    audit = {"enabled": True, "status": "completed", "incomplete": False,
             "source_sha256": source_sha256, "origin_scan_id": workspace["origin"]["scan_id"],
             "applied": [], "stale": [], "not_redetected": [], "out_of_scope": [], "unresolved": [],
             "assurance": "Only explicit user fields bound to fresh evidence were imported. User decisions are not validated passes; not redetected does not mean fixed. Report prose and model advice cannot change findings or configuration."}
    policy = {"schema_version": "1.0", "checks": {}}
    findings = {}
    same_scope = (workspace["origin"]["scope_sha256"] == current["origin"]["scope_sha256"]
                  and workspace["origin"]["tool"] == current["origin"]["tool"]
                  and workspace["origin"]["catalog_sha256"] == current["origin"]["catalog_sha256"])
    complete = bool(report["summary"].get("scan_complete_within_selected_scope"))
    for previous in workspace["items"]:
        if not previous["decision"]:
            continue
        old = {key: redact(value) if key in EDITABLE_FIELDS or key == "subject" else value for key, value in previous.items()}
        fresh = by_id.get(old["id"])
        if fresh is None:
            category = "not_redetected" if old["kind"] != "check" and complete and same_scope else "out_of_scope"
            old["reason_for_status"] = ("This item was not redetected in the complete compatible selected scope; no remediation or fix is established."
                                        if category == "not_redetected" else "The item is absent and the current scope or scanner context cannot establish comparable coverage.")
            audit[category].append(old)
            continue
        if previous["binding_sha256"] != fresh["binding_sha256"] or previous["subject"] != fresh["subject"]:
            old["reason_for_status"] = "Source, selected configuration, scanner/catalog, or immutable review context changed; the decision was not applied."
            audit["stale"].append(old)
            continue
        audit["applied"].append(old)
        for field in EDITABLE_FIELDS:
            fresh[field] = old[field]
        if old["decision"] in {"needs_runtime_validation", "needs_human_review"}:
            audit["unresolved"].append(old)
        if old["decision"] in {"justified", "disabled"}:
            item = {"status": old["decision"], "reason": previous["reason"]}
            if old["kind"] == "finding":
                findings[old["id"][len("finding:"):]] = item
            elif old["kind"] == "check":
                policy["checks"][old["id"][len("check:"):]] = item
    result = apply_review_config(report, policy, finding_dispositions=findings)
    # Attach complete editable provenance to granular dispositions, independently
    # of model records. All displayed metadata is redacted before export.
    decisions = {item["id"]: item for item in audit["applied"]}
    for finding in result["findings"]:
        item = decisions.get("finding:" + finding["id"])
        if item:
            finding["human_review"] = {field: item[field] for field in EDITABLE_FIELDS}
    for control in result["controls"]:
        for item in control.get("check_dispositions", []):
            decision = decisions.get("check:" + item["check_id"])
            if decision:
                item["human_review"] = {field: decision[field] for field in EDITABLE_FIELDS}
    audit["counts"] = {name: len(audit[name]) for name in ("applied", "stale", "not_redetected", "out_of_scope", "unresolved")}
    audit["counts"]["imported_items"] = len(workspace["items"])
    audit["counts"]["decisions"] = sum(bool(item["decision"]) for item in workspace["items"])
    audit["incomplete"] = bool(audit["stale"] or audit["out_of_scope"] or audit["unresolved"])
    audit["status"] = "incomplete" if audit["incomplete"] else "completed"
    result["review_import"] = audit
    # Include all original editable text in provenance identity, even if redacted
    # strings look the same. Imported artifact rendering/format is not replayed.
    result["scan_id"] = _digest({"disposition_scan_id": result["scan_id"], "review_workspace_sha256": _digest(workspace)})
    result["review_workspace"] = current
    result["review_workspace"] = build_workspace(result)
    return result
