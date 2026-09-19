"""Deterministic, bounded source retrieval for an advisory security analyst.

Only files in a completed scanner manifest are eligible. Repository text is data:
it never supplies retrieval instructions, paths to open, or commands to execute.
Keyword matches select context; they do not establish control compliance.
"""

from bisect import insort
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import stat

from .fs import read_confined
from .security import redact, redact_object


_LINES_PER_EXCERPT = 12
_CHARS_PER_EXCERPT = 2000
_MAX_FILE_BYTES = 1_000_000
_MAX_PER_CONTROL = 4
_MAX_CANDIDATES_PER_CONTROL = 64
_SECRET_RULES = {"AI010", "AI011", "AI034"}
_SECRET_LINE = "[REDACTED: credential-related source line; inspect locally]"
_PRIVATE_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S
)
_WORDS = re.compile(r"[a-z][a-z0-9]{2,}")
_CAMEL = re.compile(r"([a-z])([A-Z])")
_STOPWORDS = set("""
    the and for with from that this every across through into only other each
    where when what which their them they require required ensure verify validate
    prevent protect enforce secure security control checks test tests testing
    use used using model models agent agents server servers tool tools mcp
    data code source configuration configured configurations provide maintain
    record define apply allow must should can may need needs review include
    including support supported request requests response responses result
    results change changes action actions operation operations new any all not
""".split())

# These terms are maintained with the packaged control IDs, supplementing the
# control titles/checks. They are retrieval hints, never executable policy.
_CONTROL_TERMS = {
    "GOV-01": "inventory owner deployment registry endpoints assets catalog",
    "GOV-02": "threat boundary boundaries diagram architecture attacker trust",
    "GOV-03": "owner accountability acceptable permitted prohibited policy purpose",
    "GOV-04": "exception waiver evidence risk acceptance register compensating",
    "GOV-05": "reassessment impact autonomy integration change approval",
    "GOV-06": "responsibility responsibilities provider contract vendor shared raci",
    "AUTH-01": "auth authentication authenticate middleware bearer principal login",
    "AUTH-02": "authorization authorize permission permissions tenant rbac abac acl scope",
    "AUTH-03": "jwt jwks issuer audience signature claims expiry algorithms token",
    "AUTH-04": "passthrough deputy audience resource bearer token exchange",
    "AUTH-05": "credential credentials token secret vault expiry rotation lifetime",
    "AUTH-06": "oauth pkce redirect callback nonce state verifier challenge",
    "AUTH-07": "oauth discovery registration metadata issuer ssrf consent",
    "AUTH-08": "delegation delegated identity principal scope expiry impersonation",
    "AUTH-09": "identity enrollment revocation retirement lifecycle deprovisioning",
    "MCP-01": "transport origin cors localhost host http sse websocket dns",
    "MCP-02": "schema input output arguments properties additionalproperties pydantic zod",
    "MCP-03": "description annotations readonlyhint destructivehint instructions untrusted",
    "MCP-04": "tools listchanged hash digest metadata substitution manifest pinning",
    "MCP-05": "session handle cookie tenant binding state replay",
    "MCP-06": "sampling createmessage context permission approval includecontext",
    "MCP-07": "elicitation url consent sensitive phishing browser redirect",
    "MCP-08": "roots filesystem path symlink traversal sandbox realpath resolve",
    "MCP-09": "stdio subprocess spawn command args env inherit launch",
    "MCP-10": "protocolversion capabilities cancellation cancelled cache invalidation version",
    "AGT-01": "policy authorize permission allowlist deny approval gate enforcement",
    "AGT-02": "approval confirmation digest argument binding transaction toctou",
    "AGT-03": "prompt injection untrusted instruction system delimiter role provenance",
    "AGT-04": "retrieval memory vector embedding rag poisoning provenance tenant",
    "AGT-05": "delegation handoff multiagent objective scope budget escalation",
    "AGT-06": "skills prompt config instructions permission signature integrity",
    "AGT-07": "exfiltration egress dlp destination sensitive redaction outbound",
    "EXEC-01": "subprocess shell system exec command spawn shlex injection",
    "EXEC-02": "sandbox eval exec generated interpreter isolation container",
    "EXEC-03": "sql query execute parameter parameterized prepared database injection",
    "EXEC-04": "path traversal symlink archive zip tar extract resolve realpath",
    "EXEC-05": "ssrf fetch requests url address redirect dns allowlist egress",
    "EXEC-06": "pickle yaml deserialize deserialization loads load unsafe parser",
    "EXEC-07": "html escape sanitize innerhtml dangerouslysetinnerhtml render xss markdown",
    "DATA-01": "secret password credential token key vault redacted",
    "DATA-02": "privacy minimization retention gateway consent pii redact sensitive",
    "DATA-03": "log logging trace traceback redact telemetry exception sensitive",
    "DATA-04": "provenance lineage dataset integrity ingestion origin signature",
    "DATA-05": "retention delete deletion expiry backup memory cache purge",
    "DATA-06": "encrypt encryption kms key vault cipher storage tls",
    "SUP-01": "requirements lock dependency dependencies versions sbom package pyproject",
    "SUP-02": "cve vulnerability vulnerable advisory audit dependency maintenance patch",
    "SUP-03": "provenance signature digest attestation sigstore slsa artifact verify",
    "SUP-04": "workflow ci release branch approval permissions build pull_request",
    "SUP-05": "dockerfile container privileged capabilities readonly root namespace seccomp",
    "SUP-06": "training development dataset isolation production access environment",
    "OPS-01": "audit actor principal correlation trace log event attribution",
    "OPS-02": "rate quota budget timeout concurrency semaphore limit tokens",
    "OPS-03": "cancel cancellation shutdown kill abort terminate stop interrupt",
    "OPS-04": "idempotency retry rollback transaction recovery failure atomic",
    "OPS-05": "monitor alert telemetry anomaly rollback canary metric drift",
    "OPS-06": "incident response disclosure contact playbook recovery notification",
    "TEST-01": "benchmark prompt injection adversarial utility attack success asr",
    "TEST-02": "adaptive adversarial repeat seed trials distribution benchmark regression",
    "TEST-03": "oauth auth protocol malformed replay session origin fuzz",
    "TEST-04": "tenant isolation crossagent cross-tenant principal authorization",
    "TEST-05": "bypass approval policy sandbox escape escalation adversarial",
    "TEST-06": "sast dast injection xss ssrf application penetration fuzz",
    "TEST-07": "exhaustion load stress denial dos observability logging timeout",
    "TEST-08": "judge analyst hallucination injection calibration citation evaluation",
    "TEST-09": "backdoor poisoning extraction evasion membership inversion model",
}
_CATEGORY_TERMS = {
    "GOV": "policy governance ownership architecture threat risk",
    "AUTH": "auth authorization authentication identity permission oauth",
    "MCP": "mcp fastmcp modelcontextprotocol protocol transport tool",
    "AGT": "agent prompt context policy memory orchestration",
    "EXEC": "execute execution command input request parser",
    "DATA": "privacy data secret retention sensitive storage",
    "SUP": "dependency dependencies supply build artifact deployment",
    "OPS": "operations logging monitoring resilience timeout lifecycle",
    "TEST": "test tests security adversarial benchmark evaluation",
}
_PATH_PRIORITY = set("security policy threat architecture auth agent mcp tool server sandbox test tests requirements pyproject dockerfile readme".split())


def _tokens(text):
    return set(_WORDS.findall(_CAMEL.sub(r"\1 \2", str(text)).lower()))


def _sensitive_path(path):
    parts = [part.lower() for part in Path(path).parts]
    name = parts[-1]
    return (
        any(part in {".ssh", ".aws", ".gnupg", ".kube"} for part in parts[:-1])
        or name.startswith(".env") or name.endswith(".env") or ".env." in name
        or Path(name).suffix in {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
        or name in {".npmrc", ".netrc", "_netrc", ".pypirc", "credentials", "credentials.json", "credentials.yaml", "credentials.yml", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
    )


def source_scope_exclusion(path, *, exclude=(), default_excluded_directories=()):
    """Evaluate an original artifact path before a synthetic name or redaction.

    Parent matches reproduce directory-pruning exclusions for historical files
    that are no longer present in the final image filesystem.
    """
    from .scanner import _excluded
    relative = Path(path)
    paths = [relative.as_posix()] + [parent.as_posix() for parent in relative.parents if parent != Path(".")]
    if any(_excluded(candidate, exclude) for candidate in paths):
        return "user_exclusion"
    if any(part in default_excluded_directories for part in relative.parts[:-1]):
        return "default_excluded_directory"
    return None


def model_source_exclusion(path, *, exclude=(), default_excluded_directories=()):
    if _sensitive_path(path):
        return "sensitive_file_excluded"
    return source_scope_exclusion(path, exclude=exclude, default_excluded_directories=default_excluded_directories)


def model_evidence_exclusion(item):
    """Honor image-origin policy as well as the manifest's visible filename."""
    return item.get("model_evidence_exclusion") or model_source_exclusion(item["path"])


def image_evidence_context(item):
    """Keep historical image evidence distinguishable from packaged live files."""
    return redact_object({key: item[key] for key in ("image_context", "image_provenance") if key in item})


def _valid_entry(item):
    if not isinstance(item, dict):
        return False
    path, digest, size = item.get("path"), item.get("sha256"), item.get("bytes")
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        return False
    relative = Path(path)
    return (
        not relative.is_absolute() and ".." not in relative.parts
        and bool(relative.parts) and relative.as_posix() == path
        and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        and isinstance(size, int) and not isinstance(size, bool) and size >= 0
    )


def _redacted_lines(source, findings):
    # Preserve original line positions even when a PEM block spans many lines.
    # Redacting each full line afterwards avoids truncating quoted credentials
    # before the redactor can see their closing delimiter.
    source = _PRIVATE_BLOCK.sub(
        lambda match: "[REDACTED PRIVATE KEY]" + "\n" * match.group(0).count("\n"), source
    )
    lines = [redact(line) for line in source.splitlines()]
    for finding in findings:
        if finding.get("rule_id") not in _SECRET_RULES:
            continue
        start = finding.get("line", 1)
        end = finding.get("end_line", start)
        if isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int):
            for index in range(max(0, start - 1), min(len(lines), max(start, end))):
                lines[index] = _SECRET_LINE
    return lines


def _keyword_index(controls):
    inverse = defaultdict(dict)
    for control in controls:
        cid = control["id"]
        terms = {}
        for text, weight in (
            (" ".join(control.get("checks", [])), 1),
            (control.get("title", ""), 2),
            (_CATEGORY_TERMS.get(cid.split("-", 1)[0], ""), 1),
            (_CONTROL_TERMS.get(cid, ""), 4),
        ):
            for token in _tokens(text):
                if weight == 1 and token in _STOPWORDS and text != _CATEGORY_TERMS.get(cid.split("-", 1)[0], ""):
                    continue
                if weight == 2 and token in _STOPWORDS:
                    continue
                terms[token] = max(weight, terms.get(token, 0))
        for token, weight in terms.items():
            inverse[token][cid] = weight
    return inverse


def _scores(tokens, inverse):
    scores = defaultdict(int)
    for token in tokens:
        for cid, weight in inverse.get(token, {}).items():
            scores[cid] += weight
    return scores


def _excerpt(path, digest, lines, start, max_chars):
    """Select complete lines, or explicitly identify a partial single long line."""
    text_lines = []
    used = 0
    complete = True
    for line in lines[start:start + _LINES_PER_EXCERPT]:
        extra = len(line) + (1 if text_lines else 0)
        if used + extra <= max_chars:
            text_lines.append(line)
            used += extra
        elif not text_lines and max_chars > 0:
            text_lines.append(line[:max_chars])
            complete = False
            break
        else:
            break
    if not text_lines or not any(text_lines):
        return None
    end = start + len(text_lines)
    text = "\n".join(text_lines)
    identity = json.dumps([path, start + 1, end, text, digest], ensure_ascii=True, separators=(",", ":"))
    item = {
        "evidence_id": "src-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
        "kind": "source_excerpt", "path": path,
        "start_line": start + 1, "end_line": end,
        "text": text, "source_sha256": digest, "end_line_complete": complete,
    }
    if not complete:
        item["end_line_retained_chars"] = len(text_lines[-1])
        item["column_basis"] = "redacted_text"
    return item


def build_evidence(report, root, *, max_files=200, max_bytes=2_000_000,
                   max_snippets=240, max_chars=120_000):
    """Return bounded excerpts plus a mapping for every reported control.

    All limits are nonnegative integers; zero produces explicitly empty or
    constrained evidence. ``max_bytes`` bounds source I/O conservatively: a
    failed read is charged its maximum possible size, including one sentinel
    byte. ``bytes_read`` separately counts successfully returned raw bytes,
    including changed files rejected after reading. ``max_chars`` counts unique
    excerpt text characters, excluding metadata. At most four excerpts are
    attached to a control. Empty retrieval is insufficient evidence, not a pass.
    """
    limits = {"max_files": max_files, "max_bytes": max_bytes,
              "max_snippets": max_snippets, "max_chars": max_chars}
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in limits.values()):
        raise ValueError("Evidence limits must be nonnegative integers")
    controls = sorted(report.get("controls", []), key=lambda control: control["id"])
    control_evidence = {control["id"]: [] for control in controls}
    manifest = report.get("files", [])
    coverage = {
        "scope": "bounded_excerpts_from_unchanged_scanner_manifest_files",
        "selection_method": "deterministic_control_keywords_and_findings",
        "full_repository_review": False, "limits": {**limits, "max_file_bytes": _MAX_FILE_BYTES,
            "max_excerpts_per_control": _MAX_PER_CONTROL, "max_lines_per_excerpt": _LINES_PER_EXCERPT,
            "max_chars_per_excerpt": _CHARS_PER_EXCERPT, "max_candidates_per_control": _MAX_CANDIDATES_PER_CONTROL},
        "manifest_files": len(manifest), "file_read_attempts": 0, "files_read": 0,
        "files_verified": 0, "bytes_read": 0, "bytes_charged": 0,
        "failed_read_bytes_charged": 0, "snippets_selected": 0,
        "characters_selected": 0, "controls_total": len(controls),
        "skipped_files": [], "budget_exhausted": [],
        "limitations": [
            "Keyword-selected excerpts are partial context and do not prove implementation, absence, effectiveness, or compliance.",
            "Only unchanged manifest files are eligible; scanner exclusions and unsupported files remain outside this review.",
            "Credentials and environment files are excluded; other redaction is best-effort and source can contain sensitive data.",
            "Read budgets reserve one sentinel byte and conservatively charge failed read attempts, even if failure happened before any source bytes were read.",
            "No target code is executed, imported, installed, or contacted; repository instructions cannot change retrieval.",
            "Runtime behavior and missing evidence require additional validation; an empty control mapping is not a pass.",
        ],
    }
    skipped = coverage["skipped_files"]
    exhausted = set()

    def skip(path, reason):
        skipped.append({"path": redact(path), "reason": reason})

    findings_by_path = defaultdict(list)
    finding_controls = defaultdict(set)
    for control in controls:
        for fid in control.get("finding_ids", []) + control.get("suppressed_finding_ids", []):
            finding_controls[fid].add(control["id"])
    rules_to_controls = defaultdict(set)
    for control in controls:
        for rule in control.get("automated_rule_ids", []):
            rules_to_controls[rule].add(control["id"])
    for finding in report.get("findings", []):
        findings_by_path[finding["path"]].append(finding)
    inverse = _keyword_index(controls)
    candidates = defaultdict(list)
    sources = {}
    candidate_keys = set()
    candidates_dropped = 0

    # Resolve a caller-supplied root once, then pin its device/inode throughout
    # confined file opens. The scanner's manifest hashes pin file contents.
    source_root = Path(root).expanduser()
    root_error = None
    root_identity = None
    try:
        if source_root.is_symlink():
            raise OSError("Symbolic link root")
        source_root = source_root.resolve(strict=True)
        root_info = source_root.stat()
        if not stat.S_ISDIR(root_info.st_mode):
            raise OSError("Non-directory root")
        root_identity = (root_info.st_dev, root_info.st_ino)
    except (OSError, ValueError, RuntimeError):
        root_error = "source_root_unavailable_or_symlink"

    valid = []
    seen = set()
    for item in manifest:
        if not _valid_entry(item):
            skip(item.get("path", "[invalid manifest entry]") if isinstance(item, dict) else "[invalid manifest entry]", "invalid_manifest_entry")
            continue
        path = item["path"]
        if path in seen:
            skip(path, "duplicate_manifest_path")
            continue
        seen.add(path)
        exclusion = model_evidence_exclusion(item)
        if exclusion:
            skip(path, exclusion)
            continue
        valid.append(item)
    valid.sort(key=lambda item: (
        -int(bool(findings_by_path.get(item["path"]))),
        -len(_tokens(item["path"]) & _PATH_PRIORITY), item["path"], item["sha256"]
    ))
    scanner_file_limit = report.get("configuration", {}).get("max_file_bytes", _MAX_FILE_BYTES)
    file_limit = min(_MAX_FILE_BYTES, scanner_file_limit) if isinstance(scanner_file_limit, int) and scanner_file_limit > 0 else _MAX_FILE_BYTES
    coverage["limits"]["max_file_bytes"] = file_limit

    for item in valid:
        path = item["path"]
        if root_error:
            skip(path, root_error)
            continue
        if coverage["file_read_attempts"] >= max_files:
            skip(path, "file_count_limit")
            exhausted.add("max_files")
            continue
        if item["bytes"] > file_limit:
            skip(path, "file_byte_limit")
            continue
        remaining_bytes = max_bytes - coverage["bytes_charged"]
        # read_confined can read one sentinel byte to detect concurrent growth.
        # Reserve that byte and never request more than the manifest file size.
        if remaining_bytes <= 0 or item["bytes"] + 1 > remaining_bytes:
            skip(path, "total_byte_limit")
            exhausted.add("max_bytes")
            continue
        coverage["file_read_attempts"] += 1
        try:
            data, _ = read_confined(source_root, path, item["bytes"], root_identity)
        except (OSError, ValueError, RuntimeError):
            coverage["bytes_charged"] += item["bytes"] + 1
            coverage["failed_read_bytes_charged"] += item["bytes"] + 1
            skip(path, "confined_read_failed_or_size_changed")
            continue
        coverage["files_read"] += 1
        coverage["bytes_read"] += len(data)
        coverage["bytes_charged"] += len(data)
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            skip(path, "source_hash_changed")
            continue
        if b"\x00" in data:
            skip(path, "binary_content")
            continue
        try:
            source = data.decode("utf-8-sig")
        except UnicodeError:
            skip(path, "non_utf8_content")
            continue
        coverage["files_verified"] += 1
        lines = _redacted_lines(source, findings_by_path[path])
        sources[path] = (item["sha256"], lines, image_evidence_context(item))
        boosts = defaultdict(set)
        for finding in findings_by_path[path]:
            line = finding.get("line", 0)
            if isinstance(line, int) and 1 <= line <= len(lines):
                ids = finding_controls.get(finding.get("id", finding.get("finding_id")), set()) | rules_to_controls.get(finding.get("rule_id"), set())
                boosts[((line - 1) // _LINES_PER_EXCERPT) * _LINES_PER_EXCERPT].update(ids)
        path_scores = _scores(_tokens(path), inverse)
        for start in range(0, len(lines), _LINES_PER_EXCERPT):
            # Score only text that can actually be included in this excerpt.
            # Otherwise a long line could hide the sole relevant term beyond
            # the truncation point and produce a misleading citation.
            preview = _excerpt(path, item["sha256"], lines, start, _CHARS_PER_EXCERPT)
            if preview is None:
                continue
            scores = _scores(_tokens(preview["text"]), inverse)
            for cid, score in path_scores.items():
                if start == 0 or cid in scores:
                    scores[cid] += min(score, 8)
            for cid in boosts.get(start, set()):
                # Findings are a location hint; the finding itself is supplied
                # separately. A excerpt does not imply reproduction of it.
                scores[cid] += 1000
            if scores:
                candidate_keys.add((path, start))
            for cid, score in scores.items():
                entry = (-score, path, start)
                insort(candidates[cid], entry)
                if len(candidates[cid]) > _MAX_CANDIDATES_PER_CONTROL:
                    candidates[cid].pop()
                    candidates_dropped += 1

    selected = {}
    evidence = []
    # Round robin gives all controls an opportunity before adding second,
    # third and fourth excerpts. Shared snippets consume the global budget once.
    for _ in range(_MAX_PER_CONTROL):
        for cid in control_evidence:
            mapped = control_evidence[cid]
            for _, path, start in candidates[cid]:
                key = (path, start)
                if key in selected:
                    eid = selected[key]["evidence_id"]
                    if eid not in mapped:
                        mapped.append(eid)
                        break
                    continue
                if len(evidence) >= max_snippets:
                    exhausted.add("max_snippets")
                    continue
                remaining_chars = max_chars - coverage["characters_selected"]
                if remaining_chars <= 0:
                    exhausted.add("max_chars")
                    continue
                digest, lines, image_context = sources[path]
                excerpt = _excerpt(path, digest, lines, start, min(_CHARS_PER_EXCERPT, remaining_chars))
                if excerpt is None:
                    continue
                if remaining_chars < _CHARS_PER_EXCERPT and len(excerpt["text"]) < len(_excerpt(path, digest, lines, start, _CHARS_PER_EXCERPT)["text"]):
                    exhausted.add("max_chars")
                excerpt.update(image_context)
                selected[key] = excerpt
                evidence.append(excerpt)
                coverage["characters_selected"] += len(excerpt["text"])
                mapped.append(excerpt["evidence_id"])
                break

    evidence.sort(key=lambda item: (item["path"], item["start_line"], item["evidence_id"]))
    skipped.sort(key=lambda item: (item["path"], item["reason"]))
    coverage.update({
        "snippets_selected": len(evidence),
        "evidence_files": len({item["path"] for item in evidence}),
        "candidate_snippets": len(candidate_keys),
        "candidate_rankings_dropped": candidates_dropped,
        "controls_with_evidence": sum(bool(ids) for ids in control_evidence.values()),
        "controls_without_evidence": [cid for cid, ids in control_evidence.items() if not ids],
        "skipped_counts": dict(sorted(Counter(item["reason"] for item in skipped).items())),
        "budget_exhausted": sorted(exhausted),
    })
    if candidates_dropped:
        coverage["budget_exhausted"].append("max_candidates_per_control")
        coverage["budget_exhausted"].sort()
    return {"evidence": evidence, "control_evidence": control_evidence, "coverage": coverage}
