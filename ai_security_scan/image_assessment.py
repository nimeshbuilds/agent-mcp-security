"""Bounded, offline assessment of a materialized container image.

Image metadata is evidence about the artifact, not proof of runtime deployment
settings. Old layer contents are checked only for retained credential exposure;
source vulnerabilities in deleted files are not reported as live application bugs.
"""
from __future__ import annotations

import json
import re
import shlex
import stat
from pathlib import Path, PurePosixPath

from .analyzer import analyze_file
from .evidence import model_source_exclusion, source_scope_exclusion
from .fs import read_confined
from .rules import RULE_BY_ID
from .security import redact, redact_object

_SECRET_RULES = {"AI010", "AI011", "AI034"}
_RUNTIME_RULES = _SECRET_RULES | {"AI031", "AI041", "AI006"}
_REDACTED = "[REDACTED: credential-related image evidence; inspect this location locally]"
_PREFIX = ".image-metadata/"
_MAX_METADATA_RECORDS = 10_000
_TEXT_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".txt", ".pem", ".key", ".conf", ".sh", ".bash", ".zsh", ".md"}


def _json(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("utf-8")


def _safe(value):
    """Normalize controls/surrogates before redaction, including paths."""
    value = str(value).encode("utf-8", "backslashreplace").decode("utf-8")
    value = "".join(char if char in "\t\n" or ord(char) >= 32 else " " for char in value)
    return redact(value)


def _integer(value, default=0):
    return value if isinstance(value, int) and not isinstance(value, bool) else default


class _Assessment:
    def __init__(self, materialized, max_file_bytes, max_total_bytes, exclude=(), excluded_directories=()):
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
               for value in (max_file_bytes, max_total_bytes)):
            raise ValueError("Image assessment byte limits must be positive integers")
        self.materialized = materialized
        self.root = Path(materialized["root"])
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.bytes_charged = 0
        self.bytes_read = 0
        self.findings = []
        self.evidence = {}
        self.evidence_metadata = {}
        self.exclude = tuple(exclude)
        self.excluded_directories = set(excluded_directories)
        self.skipped = []
        self.errors = []
        self.cache = {}
        self.layers_checked = 0
        self.record_count = 0
        self.record_limit_reported = False
        self.evidence_limit_reported = False
        self.package_limit_reported = False
        self.entries = materialized.get("entries", [])
        self.inventory = {"identity": redact_object(materialized.get("identity", {})),
                          "runtime": {}, "os_release": {}, "packages": [],
                          "permission_review_signals": [],
                          "package_inventory_is_cve_scan": False,
                          "binary_logic_analyzed": False, "binary_secret_engine_enabled": False}

    def skip(self, path, reason, gap=True):
        self.skipped.append({"path": _safe(path), "reason": reason, "coverage_gap": gap})

    def record(self, path):
        if self.record_count >= _MAX_METADATA_RECORDS:
            if not self.record_limit_reported:
                self.skip(path, "image_metadata_record_limit")
                self.record_limit_reported = True
            return False
        self.record_count += 1
        return True

    def error(self, path, message):
        self.errors.append({"path": _safe(path), "error": message, "kind": "image_assessment_error"})

    def read(self, root, relative):
        key = (str(root), relative)
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = None
        try:
            path = root / relative
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                self.skip(relative, "image_metadata_non_regular_file")
                return None
            if info.st_size > self.max_file_bytes:
                self.skip(relative, "image_metadata_file_size_limit")
                return None
            charged = info.st_size + 1
            if self.bytes_charged + charged > self.max_total_bytes:
                self.skip(relative, "image_metadata_total_byte_limit")
                return None
            self.bytes_charged += charged
            root_info = root.stat()
            data, opened = read_confined(root, relative, info.st_size,
                                        (root_info.st_dev, root_info.st_ino))
            self.bytes_read += len(data)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                self.skip(relative, "image_metadata_file_changed_during_open")
                return None
            self.cache[key] = data
            return data
        except (OSError, ValueError, RuntimeError):
            self.error(relative, "Image metadata file could not be read safely")
            return None

    def text(self, root, relative, expected_text=True):
        raw = self.read(root, relative)
        if raw is None:
            return None
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            self.skip(relative, "image_metadata_non_utf8_content", expected_text)
            return None
        if "\x00" in text:
            self.skip(relative, "image_metadata_binary_content", expected_text)
            return None
        return text

    def emit(self, path, data, allowed, context, provenance, source_path=None):
        """Record bounded local evidence and selected rules, never execute it."""
        if len(self.evidence) >= _MAX_METADATA_RECORDS:
            if not self.evidence_limit_reported:
                self.skip(path, "image_metadata_evidence_file_limit")
                self.evidence_limit_reported = True
            return
        if len(data) > self.max_file_bytes:
            self.skip(path, "image_metadata_file_size_limit")
            return
        if self.bytes_charged + len(data) > self.max_total_bytes:
            self.skip(path, "image_metadata_total_byte_limit")
            return
        self.bytes_charged += len(data)
        self.evidence[path] = data
        self.evidence_metadata[path] = {"image_context": context, "image_provenance": redact_object(provenance)}
        if source_path is not None:
            exclusion = model_source_exclusion(source_path, exclude=self.exclude,
                                               default_excluded_directories=self.excluded_directories)
            if exclusion:
                self.evidence_metadata[path]["model_evidence_exclusion"] = exclusion
        try:
            text = data.decode("utf-8-sig")
            candidates = analyze_file(path, text)
        except (UnicodeError, ValueError, RuntimeError, RecursionError):
            self.error(path, "Image evidence could not be analyzed")
            return
        for item in candidates:
            if item["rule_id"] not in allowed:
                continue
            item["evidence"] = _REDACTED if item["rule_id"] in _SECRET_RULES else _safe(item["evidence"])
            item["path"] = _safe(path)
            item["image_context"] = context
            item["image_provenance"] = redact_object(provenance)
            if context == "retained_layer":
                item["description"] += " This credential-like content remains in a retained image layer even though the file revision is absent from the final filesystem; this is artifact exposure, not a live source-code finding."
            elif context == "build_history":
                item["description"] += " The evidence is a recorded build-history instruction, not a statement about current runtime behavior."
            self.findings.append(item)

    def config(self):
        document = self.materialized.get("config", {})
        config = document.get("config", {}) if isinstance(document, dict) else {}
        if not isinstance(config, dict):
            self.error(_PREFIX + "config.json", "Image runtime configuration is not an object")
            config = {}
        fields = {key: config[key] for key in ("User", "Entrypoint", "Cmd", "WorkingDir", "ExposedPorts", "Volumes", "StopSignal") if key in config}
        # These values can contain credentials, so only name/count information is
        # placed in ordinary inventory. Raw evidence stays in the temp workspace.
        user = config.get("User", "")
        self.inventory["runtime"] = {"configured_user": _safe(user),
                                     "entrypoint_present": bool(config.get("Entrypoint")),
                                     "command_present": bool(config.get("Cmd")),
                                     "working_directory": _safe(config.get("WorkingDir", ""))}
        path = _PREFIX + "config.json"
        self.emit(path, _json(fields), _SECRET_RULES, "runtime_configuration", {"field": "config"})
        self.user(user, path)
        for field, allowed in (("Env", _RUNTIME_RULES), ("Labels", _SECRET_RULES)):
            values = config.get(field) or ([] if field == "Env" else {})
            if field == "Env":
                if not isinstance(values, list):
                    self.error(_PREFIX + "environment.json", "Image Env configuration is not an array")
                    continue
                pairs = []
                for index, value in enumerate(values):
                    if not self.record(_PREFIX + "environment"):
                        break
                    if not isinstance(value, str) or "=" not in value:
                        self.skip(_PREFIX + "environment/%06d.json" % index, "image_environment_invalid_entry")
                        continue
                    key, value = value.split("=", 1)
                    pairs.append((index, key, value))
                self.inventory["runtime"]["environment_names"] = [_safe(key) for _, key, _ in pairs]
            else:
                if not isinstance(values, dict):
                    self.error(_PREFIX + "labels.json", "Image Labels configuration is not an object")
                    continue
                pairs = []
                for index, (key, value) in enumerate(sorted(values.items())):
                    if not self.record(_PREFIX + "labels"):
                        break
                    pairs.append((index, str(key), value))
                self.inventory["runtime"]["label_names"] = [_safe(key) for _, key, _ in pairs]
            for index, key, value in pairs:
                location = _PREFIX + ("environment" if field == "Env" else "labels") + "/%06d.json" % index
                self.emit(location, _json({key: value}), allowed, "runtime_configuration", {"field": field, "index": index, "key": _safe(key)})
        for field in ("Entrypoint", "Cmd"):
            values = config.get(field) or []
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                self.error(_PREFIX + field.lower() + ".sh", "Image command configuration is not a string array")
                continue
            if values:
                self.emit(_PREFIX + field.lower() + ".sh", (" ".join(values) + "\n").encode("utf-8", "backslashreplace"), _RUNTIME_RULES, "runtime_configuration", {"field": field})
        history = (document.get("history") or []) if isinstance(document, dict) else []
        if not isinstance(history, list):
            self.error(_PREFIX + "history", "Image history is not an array")
            return
        layer_index = 0
        for index, item in enumerate(history):
            if not self.record(_PREFIX + "history"):
                break
            if not isinstance(item, dict):
                self.skip(_PREFIX + "history/%06d.sh" % index, "image_history_invalid_entry")
                continue
            empty = item.get("empty_layer", False) is True
            provenance = {"history_index": index, "empty_layer": empty}
            if not empty:
                provenance["layer_index"] = layer_index
                layer_index += 1
            instruction = item.get("created_by", "")
            if isinstance(instruction, str):
                findings_before = len(self.findings)
                self.emit(_PREFIX + "history/%06d.sh" % index, (instruction + "\n").encode("utf-8", "backslashreplace"), _SECRET_RULES | {"AI019", "AI031"}, "build_history", provenance)
                # Docker ENV/ARG history is commonly unquoted and wrapped by
                # /bin/sh -c #(nop). Preserve the original instruction as evidence
                # and expose key/value fields to the existing secret detector.
                match = re.search(r"(?:^|#\(nop\)\s+)(?:ENV|ARG)\s+(.+)$", instruction, re.S)
                if match:
                    try:
                        tokens = shlex.split(match.group(1))
                    except ValueError:
                        self.skip(_PREFIX + "history/%06d.sh" % index, "image_history_assignment_parse_error")
                        continue
                    assignments = []
                    for token in tokens:
                        key, equal, value = token.partition("=")
                        if equal and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                            assignments.append({key: value})
                    if not assignments and len(tokens) >= 2 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]):
                        assignments = [{tokens[0]: " ".join(tokens[1:])}]
                    if assignments:
                        already_reported = {item["rule_id"] for item in self.findings[findings_before:]}
                        self.emit(_PREFIX + "history/%06d-assignments.json" % index, _json(assignments), _SECRET_RULES - already_reported, "build_history", provenance)

    def user(self, user, path):
        if not isinstance(user, str):
            self.error(path, "Image User configuration is not a string")
            return
        name = user.split(":", 1)[0]
        root = name in {"", "root"} or bool(re.fullmatch(r"0+", name))
        numeric = bool(re.fullmatch(r"[0-9]+", name))
        reason = "default_root" if not name else "explicit_root" if root else "nonroot_numeric" if numeric else "named_user_unresolved"
        if name and not numeric:
            passwd = next((entry for entry in self.entries if entry.get("path") == "etc/passwd"), None)
            if passwd is not None:
                text = self.text(self.root, "etc/passwd")
                if text is not None:
                    for line in text.splitlines():
                        parts = line.split(":")
                        if len(parts) >= 4 and parts[0] == name and re.fullmatch(r"[0-9]+", parts[2]):
                            root = bool(re.fullmatch(r"0+", parts[2]))
                            reason = "named_user_uid_zero" if root else "named_user_nonzero_uid"
                            break
        self.inventory["runtime"]["user_assessment"] = reason
        self.inventory["runtime"]["deployment_user_override_checked"] = False
        if root:
            rule = RULE_BY_ID["AI021"]
            finding = {key: rule[key] for key in ("title", "severity", "description", "remediation", "category", "cwe", "references")}
            finding.update(rule_id="AI021", title="Container image defaults to root", path=path, line=1, end_line=1, confidence="high", evidence="Image configured user resolves to UID 0 (%s)." % reason,
                           image_context="runtime_configuration", image_provenance={"field": "User", "resolution": reason})
            finding["description"] = "The image's default runtime user is UID 0. Deployment settings can override this; deployment privilege, Linux capabilities, and runtime isolation are not established by image analysis."
            self.findings.append(finding)

    def file_inventory(self):
        for entry in sorted(self.entries, key=lambda item: item.get("path", "")):
            relative = entry.get("path", "")
            if not isinstance(relative, str):
                continue
            kind, mode = entry.get("kind"), _integer(entry.get("mode"))
            signals = []
            if mode & stat.S_ISUID:
                signals.append("setuid")
            if mode & stat.S_ISGID:
                signals.append("setgid")
            if mode & stat.S_IWOTH:
                signals.append("world_writable")
            if signals:
                if not self.record(relative):
                    break
                self.inventory["permission_review_signals"].append({"path": _safe(relative), "kind": kind, "mode": format(mode & 0o7777, "04o"), "uid": _integer(entry.get("uid")), "gid": _integer(entry.get("gid")), "signals": signals, "assessment": "review_required; deployment mount options, capabilities, and intended permissions are unknown"})
            if kind not in {"file", "regular"}:
                continue
            pure = PurePosixPath(relative)
            package_kind = "dpkg" if relative == "var/lib/dpkg/status" else "apk" if relative == "lib/apk/db/installed" else "python" if pure.name == "METADATA" and pure.parent.name.endswith(".dist-info") else "npm" if pure.name == "package.json" else None
            if relative not in {"etc/os-release", "usr/lib/os-release"} and package_kind is None:
                continue
            if not self.record(relative):
                break
            text = self.text(self.root, relative)
            if text is None:
                continue
            if relative in {"etc/os-release", "usr/lib/os-release"}:
                values = {}
                for line in text.splitlines():
                    key, equal, value = line.partition("=")
                    if equal and re.fullmatch(r"[A-Z_]+", key):
                        values[key] = _safe(value.strip().strip("\"'"))
                # /etc overrides the vendor default regardless of traversal order.
                if relative == "etc/os-release" or not self.inventory["os_release"]:
                    self.inventory["os_release"] = {"path": _safe(relative), "fields": values}
            else:
                self.packages(relative, package_kind, text)

    def packages(self, relative, kind, text):
        def add(name, version, extra=None):
            if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
                return
            if len(self.inventory["packages"]) >= _MAX_METADATA_RECORDS:
                if not self.package_limit_reported:
                    self.skip(relative, "image_package_inventory_record_limit")
                    self.package_limit_reported = True
                return
            record = {"ecosystem": kind, "name": _safe(name), "version": _safe(version), "path": _safe(relative), "assessment": "version observed; vulnerability status not assessed"}
            if extra:
                record.update(extra)
            self.inventory["packages"].append(record)
        if kind == "npm":
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                self.error(relative, "Package metadata JSON could not be parsed")
                return
            if isinstance(data, dict):
                add(data.get("name"), data.get("version"))
            return
        blocks = re.split(r"\r?\n\s*\r?\n", text) if kind in {"dpkg", "apk"} else [text]
        for block in blocks:
            fields = {}
            for line in block.splitlines():
                key, equal, value = line.partition(":")
                if equal and key not in fields:
                    fields[key] = value.strip()
            if kind == "dpkg" and fields.get("Status") == "install ok installed":
                add(fields.get("Package"), fields.get("Version"), {"architecture": _safe(fields.get("Architecture", ""))})
            elif kind == "apk":
                add(fields.get("P"), fields.get("V"), {"architecture": _safe(fields.get("A", ""))})
            elif kind == "python":
                add(fields.get("Name"), fields.get("Version"))

    def retained_layers(self):
        live = {(entry.get("path"), entry.get("layer"), entry.get("sha256")) for entry in self.entries if entry.get("kind") in {"file", "regular"}}
        revisions = self.materialized.get("layer_files", [])
        for index, item in enumerate(revisions):
            relative = item.get("path", "")
            if (relative, item.get("layer"), item.get("sha256")) in live:
                continue
            exclusion = source_scope_exclusion(relative, exclude=self.exclude,
                                                default_excluded_directories=self.excluded_directories)
            if exclusion:
                self.skip(relative, "retained_layer_" + exclusion, False)
                self.skipped[-1]["layer"] = item.get("layer")
                continue
            if not self.record(_PREFIX + "retained-layer"):
                break
            blob = item.get("blob_path")
            if not blob:
                self.skip(relative, "retained_layer_content_unavailable")
                continue
            blob = Path(blob)
            suffix = PurePosixPath(str(relative)).suffix.lower()
            expected_text = suffix in _TEXT_SUFFIXES or PurePosixPath(str(relative)).name.startswith(".env")
            previous = len(self.skipped)
            previous_errors = len(self.errors)
            text = self.text(blob.parent, blob.name, expected_text)
            # Report artifact locations, never temporary blob filenames.
            for problem in self.skipped[previous:] + self.errors[previous_errors:]:
                problem["path"] = _safe(relative)
                problem["layer"] = item.get("layer")
            if text is None:
                continue
            self.layers_checked += 1
            # Keep a useful syntax suffix for literal checks but discard the
            # untrusted original filename from the synthetic namespace.
            suffix = PurePosixPath(str(relative)).suffix.lower()
            suffix = suffix if suffix in {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"} else ".env"
            location = _PREFIX + "retained-layer/%06d%s" % (index, suffix)
            self.emit(location, text.encode("utf-8"), _SECRET_RULES, "retained_layer", {"original_path": _safe(relative), "layer": item.get("layer"), "sha256": item.get("sha256"), "present_in_final_filesystem": False}, source_path=relative)

    def result(self):
        self.config()
        self.file_inventory()
        self.retained_layers()
        self.findings.sort(key=lambda item: (item["path"], item["line"], item["rule_id"]))
        self.inventory["packages"].sort(key=lambda item: (item["ecosystem"], item["name"], item["version"], item["path"]))
        return {"findings": self.findings, "evidence_files": self.evidence, "evidence_metadata": self.evidence_metadata,
                "inventory": self.inventory,
                "coverage": {"errors": self.errors, "skipped": self.skipped,
                             "counters": {"bytes_read": self.bytes_read, "bytes_charged": self.bytes_charged,
                                          "retained_layer_revisions_checked": self.layers_checked,
                                          "metadata_evidence_files": len(self.evidence),
                                          "metadata_records_considered": self.record_count,
                                          "max_metadata_records": _MAX_METADATA_RECORDS},
                             "limitations": ["Image metadata and retained layers are assessed offline; the image is never started and binaries are not decompiled.",
                                             "Installed-package metadata is inventory only; no CVE database, vendor advisory, signature, or exploitability lookup is performed.",
                                             "Deleted and overwritten layers are checked for credential exposure only; other historic source patterns are not live-runtime findings.",
                                             "Default image user, stored permissions, and command configuration can be overridden at deployment; runtime isolation and authorization require separate validation.",
                                             "Compiled code, obfuscated data, encrypted secrets, unsupported package databases, and unavailable source cannot receive source-level rule coverage."]}}


def assess_image(materialized, *, max_file_bytes=1_000_000, max_total_bytes=50_000_000,
                 exclude=(), excluded_directories=()):
    """Return rule-shaped findings, raw temporary evidence, inventory and gaps.

    ``evidence_files`` contains sensitive, local-only bytes; callers must not put
    it verbatim in reports. Findings have no ids: the report orchestrator assigns
    deterministic identifiers and applies baselines consistently with source files.
    ``evidence_metadata`` retains redacted origins and model-excerpt exclusions
    independently of findings. Path exclusions apply to retained file revisions;
    image configuration/history and inventory remain separately assessed.
    """
    return _Assessment(materialized, max_file_bytes, max_total_bytes, exclude, excluded_directories).result()
