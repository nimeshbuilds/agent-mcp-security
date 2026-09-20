"""Lossless evidence-JSON compaction, independent of model/provider protocols.

Only the pinned Headroom JSON minifier is used. Its general compression pipeline
is intentionally not invoked: removing source data or adding retrieval tools is
incompatible with the analyst's bounded, exact-citation evidence contract.
"""
import hashlib
from importlib import metadata
import json


MODES = ("headroom", "compact", "off")
HEADROOM_VERSION = "0.37.0"


def validate_mode(value):
    if not isinstance(value, str) or value not in MODES:
        raise ValueError("token_optimizer must be headroom, compact or off.")
    return value


def _loads(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("Non-finite JSON value")

    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    # Also rejects numeric overflow such as 1e999, and preserves JSON types.
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True,
                           allow_nan=False, separators=(",", ":"))
    return canonical


def _headroom_minify(text):
    # Lazy import: deterministic scans and help never import Headroom. Pin this
    # private upstream API and independently validate every returned character.
    from headroom.transforms.content_router import ContentRouter
    return ContentRouter._minify_json_data_lossless(text)


def optimize_payload(payload, mode="headroom", ensure_ascii=True, max_bytes=5 * 1024 * 1024):
    """Return serialized JSON and an audit receipt; never mutate the payload.

    Compaction preserves every parsed value, array order and source string. A
    Headroom failure or unsafe transformation falls back to local JSON encoding.
    Byte counts measure evidence JSON only, not tokenizer counts or billed cost.
    The pre-optimization byte bound cannot be bypassed by successful compaction.
    """
    validate_mode(mode)
    original = json.dumps(payload, sort_keys=True, ensure_ascii=ensure_ascii, allow_nan=False)
    original_bytes = original.encode("utf-8")
    if len(original_bytes) > max_bytes:
        raise ValueError("Judge payload exceeds max_request_bytes before optimization; reduce findings or excerpts.")
    canonical = _loads(original)
    encoded, engine, status = original, "none", "disabled"
    version, reason = None, None
    if mode != "off":
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=ensure_ascii,
                             allow_nan=False, separators=(",", ":"))
        engine, status = "builtin_compact", "optimized" if encoded != original else "unchanged"
    if mode == "headroom":
        try:
            version = metadata.version("headroom-ai")
            if version != HEADROOM_VERSION:
                reason = "unsupported_headroom_version"
            else:
                candidate = _headroom_minify(original)
                if candidate is None:
                    candidate = original
                if not isinstance(candidate, str):
                    reason = "invalid_optimizer_output"
                elif len(candidate.encode("utf-8")) > len(original_bytes):
                    reason = "optimizer_expanded_payload"
                elif _loads(candidate) != canonical:
                    reason = "optimizer_changed_evidence"
                else:
                    encoded, engine = candidate, "headroom"
                    status = "optimized" if encoded != original else "unchanged"
        except metadata.PackageNotFoundError:
            reason = "headroom_not_installed"
        except Exception:
            # Never print third-party exception text: it may contain evidence.
            reason = "optimizer_unavailable_or_invalid"
        if reason:
            status = "fallback"
    sent = encoded.encode("utf-8")
    if len(sent) > len(original_bytes) or _loads(encoded) != canonical:
        raise ValueError("Lossless evidence optimization could not preserve the payload.")
    return encoded, {
        "schema_version": "1.0", "requested": mode, "engine": engine,
        "status": status, "headroom_version": version, "fallback_reason": reason,
        "payload_bytes_before": len(original_bytes), "payload_bytes_after": len(sent),
        "bytes_saved": len(original_bytes) - len(sent),
        "original_payload_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "sent_payload_sha256": hashlib.sha256(sent).hexdigest(),
        "evidence_preserved": True, "token_savings_measured": False,
        "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
    }
