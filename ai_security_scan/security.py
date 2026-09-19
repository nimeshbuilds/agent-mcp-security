"""Best-effort evidence redaction; never a guarantee of anonymization."""
import re

_KEY = r"(?:[A-Za-z_][A-Za-z0-9_-]{0,127}?)?(?:api[_-]?key|apikey|private[_-]?key|signing[_-]?key|secret(?:[_-]?(?:key|access[_-]?key))?|password|passwd|pwd|(?:(?:access|refresh|auth|bearer)[_-]?)?token|authorization|client[_-]?secret|credentials?)"
_ASSIGN = re.compile(r"(?i)(?<![A-Za-z0-9_-])([\"']?" + _KEY + r"[\"']?\s*[:=]\s*)([\"'])(?:\\.|(?!\2)[^\\\r\n])*(?:\2|(?=\r?\n|\Z))")
_BARE = re.compile(r"(?im)(\b" + _KEY + r"\b\s*[:=]\s*)(?![\"'])([^\s,;}]+)")
_KNOWN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)
_URL_AUTH = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]{0,31}://)[^/@\s]+:[^/@\s]+@")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_./+=-]{6,}")
_QUERY = re.compile(r"(?i)([?&](?:" + _KEY + r")=)[^&#\s\"']+")


def redact(text):
    text = _PEM.sub("[REDACTED PRIVATE KEY]", str(text))
    text = _BEARER.sub(lambda m: m.group(1) + " [REDACTED]", text)
    text = _ASSIGN.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]" + m.group(2), text)
    text = _BARE.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = _KNOWN.sub("[REDACTED TOKEN]", text)
    text = _JWT.sub("[REDACTED JWT]", text)
    text = _URL_AUTH.sub(r"\1[REDACTED]@", text)
    return _QUERY.sub(lambda m: m.group(1) + "[REDACTED]", text)


def redact_object(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_object(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_object(v) for k, v in value.items()}
    return value
