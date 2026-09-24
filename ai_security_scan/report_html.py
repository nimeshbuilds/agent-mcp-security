"""Self-contained HTML reports with escaped evidence and a CSP-pinned review editor.

Report content, including model advice and repository filenames, is untrusted.
The renderer uses fixed markup, hashed anchors, allowlisted HTTPS links, and one
immutable local-only editor script. Report data never enters executable code.
"""
import base64
import hashlib
import html
import ipaddress
import json
import re
from urllib.parse import unquote, urlsplit

from . import DISPLAY_NAME
from .security import redact


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _text(value):
    return str(value).encode("utf-8", "backslashreplace").decode("utf-8")


def _escape(value):
    return html.escape(_text(value), quote=True)


def _anchor(kind, value):
    return kind + "-" + hashlib.sha256(_text(value).encode("utf-8")).hexdigest()[:16]


def _safe_url(value):
    """Only produce navigation links for unambiguous, credential-free HTTPS URLs."""
    if not isinstance(value, str) or not value.startswith("https://"):
        return None
    decoded = unquote(value)
    if any(c.isspace() or ord(c) < 32 or 127 <= ord(c) <= 159 for c in decoded):
        return None
    if "\\" in decoded:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.netloc or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        # Reading the port rejects invalid or out-of-range port text.
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return None
        host = parsed.hostname
        if "[" in parsed.netloc or "]" in parsed.netloc:
            if not re.fullmatch(r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?", parsed.netloc):
                return None
            ipaddress.IPv6Address(host)
        else:
            if not re.fullmatch(re.escape(host) + r"(?::[0-9]+)?", parsed.netloc, re.IGNORECASE):
                return None
            ascii_host = host.encode("idna").decode("ascii")
            if len(ascii_host) > 253 or any(
                not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in ascii_host.split(".")
            ):
                return None
            if re.fullmatch(r"[0-9.]+", ascii_host):
                ipaddress.IPv4Address(ascii_host)
    except (ValueError, UnicodeError):
        return None
    return value


def _link(url, label=None):
    label = url if label is None else label
    safe = _safe_url(url)
    if safe is None:
        return '<span class="unlinked">' + _escape(label) + " (unlinked reference)</span>"
    return '<a href="' + _escape(safe) + '" rel="noopener noreferrer">' + _escape(label) + "</a>"


def _list(items, css="", ordered=False):
    tag = "ol" if ordered else "ul"
    attr = ' class="' + css + '"' if css else ""
    return "<" + tag + attr + ">" + "".join("<li>" + _escape(item) + "</li>" for item in items) + "</" + tag + ">"


def _json(value):
    # Scanner evidence is already redacted. Reapply the shared best-effort
    # redactor before rendering diagnostic/provider objects supplied by callers.
    return '<pre class="audit"><code>' + _escape(redact(json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True))) + "</code></pre>"


def _details(title, content, opened=False, css=""):
    return ('<details class="' + css + '"' + (" open" if opened else "") + "><summary>"
            + _escape(title) + "</summary><div class=\"details-body\">" + content + "</div></details>")


def _pill(value, severity=False):
    css = "pill"
    if severity and value in _SEVERITIES:
        css += " " + value
    elif not severity and value in ("justified", "disabled", "excluded_from_review"):
        css += " " + value
    return '<span class="' + css + '">' + _escape(value) + "</span>"


def _checklist(control, review_items=None):
    review_items = review_items or {}
    dispositions = {entry["check_index"]: entry for entry in control.get("check_dispositions", [])}
    items = []
    for index, check in enumerate(control.get("checks", []), 1):
        disposition = dispositions.get(index, {})
        entry = '<li>' + _escape(check)
        if disposition.get("status") in ("justified", "disabled"):
            entry += ('<div class="spacer">' + _pill(disposition["status"])
                      + ' <code>' + _escape(disposition.get("check_id", control["id"] + ":" + str(index)))
                      + '</code><p><strong>User reason:</strong> ' + _escape(disposition.get("reason", "No reason supplied."))
                      + '</p><p class="small">Excluded from active review totals without positive or negative credit.</p></div>')
        entry += _editor(review_items.get('check:' + control['id'] + ':' + str(index)))
        items.append(entry + '</li>')
    return '<ol class="checklist">' + "".join(items) + '</ol>'


def _review_policy(report):
    policy = report.get("review_policy", {})
    if not policy.get("enabled"):
        return ""
    counts = policy.get("counts", {})
    parts = ['<section id="review-policy"><p class="eyebrow">Explicit user configuration</p><h2>User review decisions</h2>',
             '<p class="note warning"><strong>Justified is a user decision, not a validated pass.</strong> Justified and disabled items earn no positive credit and do not count against active totals. Rule decisions and imported individual-finding decisions exclude their matching findings from the severity gate. Control and individual-check decisions affect checklist review only. Scan errors and coverage gaps remain unresolved.</p>',
             '<div class="table-wrap"><table><thead><tr><th>Scope</th><th>Active</th><th>Justified</th><th>Disabled</th><th>Excluded with mixed check decisions</th><th>Catalog total</th></tr></thead><tbody>']
    for scope in ("rules", "controls", "checks"):
        parts.append('<tr><td>' + scope.capitalize() + '</td><td>' + _escape(counts.get("active_" + scope, 0))
                     + '</td><td>' + _escape(counts.get("justified_" + scope, 0)) + '</td><td>' + _escape(counts.get("disabled_" + scope, 0))
                     + '</td><td>' + _escape(counts.get("mixed_excluded_controls", 0) if scope == "controls" else 0)
                     + '</td><td>' + _escape(counts.get("catalog_" + scope, 0)) + '</td></tr>')
    parts += ['</tbody></table></div><h3>Configured decisions and reasons</h3>',
              '<div class="table-wrap"><table><thead><tr><th>Scope</th><th>Identifier</th><th>Decision</th><th>User reason</th></tr></thead><tbody>']
    for scope in ("rules", "findings", "controls", "checks"):
        for identifier, entry in sorted(policy.get("entries", {}).get(scope, {}).items()):
            parts.append('<tr><td>' + scope + '</td><td><code>' + _escape(identifier) + '</code></td><td>'
                         + _pill(entry["status"]) + '</td><td>' + _escape(entry.get("reason") or "No reason supplied.") + '</td></tr>')
    parts += ['</tbody></table></div><p class="small"><strong>Review configuration SHA-256:</strong> <code>'
              + _escape(policy.get("sha256", "")) + '</code></p>',
              '<p class="small">' + _escape(policy.get("assurance", "User decisions do not verify the stated safeguards.")) + '</p>',
              _details("Complete user review configuration audit", _json(policy)), '</section>']
    return "\n".join(parts)


def _scoring(report):
    from .scoring import build_scoring, format_ratio
    result = report.get("scoring") or build_scoring(report)
    static, ai = result["deterministic"], result["optional_ai"]
    rows = [
        ("Open deterministic findings", str(static["open_findings"]) + " (" + str(static["urgent_findings"]) + " critical/high)",
         "Exact observed counts. No severity weights or estimated probability of compromise are assigned."),
        ("Partial deterministic mapping reach", format_ratio(static["mapping_reach"]),
         "Active selected controls with at least one active selected mapped rule. Partial availability, not a pass rate."),
        ("Optional AI answer coverage", format_ratio(ai["answer_coverage"]),
         "Active selected checks with an actual model answer, including concerns or explicit unknowns. Review completion, not a pass rate."),
    ]
    parts = ['<section id="scoring"><p class="eyebrow">Transparent measures</p><h2>Metrics and how they are calculated</h2>',
             '<p class="note">' + _escape(result["overall_security_score_reason"]) + '</p>',
             '<div class="table-wrap"><table><thead><tr><th>Measure</th><th>Result</th><th>Meaning</th></tr></thead><tbody>']
    for label, value, explanation in rows:
        parts.append('<tr><td>' + _escape(label) + '</td><td><strong>' + _escape(value) + '</strong></td><td>' + _escape(explanation) + '</td></tr>')
    parts += ['</tbody></table></div><p><strong>Selected scope:</strong> ' + _escape(static["selected_rules"])
              + ' rules (' + _escape(static["active_rules"]) + ' active), ' + _escape(static["selected_controls"])
              + ' controls (' + _escape(static["active_controls"]) + ' active), ' + _escape(static["active_checks"]) + ' active acceptance checks.</p>',
              '<p><strong>Static execution:</strong> ' + ('Selected scope completed' if static["selected_scope_complete"] else 'Selected scope incomplete')
              + '; ' + _escape(static["coverage_gaps"]) + ' recorded coverage gaps.</p>',
              '<h3>Optional AI outcomes</h3><p>Finding stage: ' + _escape(ai["finding_review_status"])
              + '. Control stage: ' + _escape(ai["control_review_status"]) + '.</p>',
              '<div class="table-wrap"><table><thead><tr><th>Advisory check outcome</th><th>Count</th></tr></thead><tbody>']
    for status, count in ai["check_outcomes"].items():
        parts.append('<tr><td>' + _escape(status) + '</td><td>' + _escape(count) + '</td></tr>')
    parts += ['</tbody></table></div><p>' + _escape(ai["interpretation"]) + '</p>',
              _details("Exact formulas, exclusions, and CI gate", '<p><strong>Mapping formula:</strong> ' + _escape(static["mapping_reach_formula"])
                       + '</p><p><strong>AI answer formula:</strong> ' + _escape(ai["answer_coverage_formula"])
                       + '</p><p>' + _escape(result["exclusions"]) + '</p><p>' + _escape(result["gate"]) + '</p>', opened=True), '</section>']
    return "\n".join(parts)


def _sources(sources, title="Guidance sources"):
    if not sources:
        return ""
    links = []
    for source in sources:
        if isinstance(source, dict):
            label = source.get("id", "") + (" / " if source.get("id") else "") + source.get("title", source.get("url", "Reference"))
            links.append(_link(source.get("url", ""), label))
        else:
            links.append(_link(source))
    return '<div class="sources"><strong>' + _escape(title) + "</strong><ul>" + "".join("<li>" + link + "</li>" for link in links) + "</ul></div>"


def _finding_links(ids, known, label="Evidence"):
    links = []
    for identifier in ids:
        if identifier in known:
            links.append('<a href="#' + _anchor("finding", identifier) + '"><code>' + _escape(identifier) + "</code></a>")
        else:
            links.append("<code>" + _escape(identifier) + "</code>")
    return '<p class="small"><strong>' + _escape(label) + ":</strong> " + ", ".join(links) + "</p>" if links else ""


def _control_links(ids, known):
    links = []
    for identifier in ids:
        if identifier in known:
            links.append('<a href="#' + _anchor("control", identifier) + '">' + _escape(identifier) + "</a>")
        else:
            links.append(_escape(identifier))
    return '<p class="small"><strong>Related controls:</strong> ' + ", ".join(links) + "</p>" if links else ""


_CSS = """
:root{color-scheme:light;--ink:#142338;--navy:#0b1220;--mint:#35e3b1;--paper:#f2f6fa;--muted:#516279;--line:#dbe3ec;--white:#fff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:#12674f;text-underline-offset:3px;overflow-wrap:anywhere}a:hover{color:#064331}a:focus-visible,summary:focus-visible{outline:3px solid #178268;outline-offset:4px}h1,h2,h3,h4,p{margin-top:0}h1{font-size:clamp(1.65rem,3vw,2rem);line-height:1.2;letter-spacing:-.035em;margin-bottom:10px}h2{font-size:1.8rem;line-height:1.25;letter-spacing:-.025em;margin-bottom:12px}h3{font-size:1.14rem;line-height:1.4;margin-bottom:12px}h4{font-size:1rem;margin-bottom:6px}p{margin-bottom:14px}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}code{font-size:.85em;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#eef2f6;border:1px solid var(--line);padding:18px;border-radius:10px;line-height:1.5;font-size:.82rem;margin:12px 0 20px}pre code{font-size:inherit}ul,ol{padding-left:24px}li+li{margin-top:7px}strong{font-weight:650}.wrap{max-width:1220px;margin:auto;padding:0 40px}.masthead{background:var(--navy);color:#f2f6fa}.brandrow{display:flex;justify-content:space-between;align-items:center;gap:24px;padding-top:16px;padding-bottom:16px;border-bottom:1px solid #2b3648}.brand{display:flex;align-items:center;gap:13px}.brand svg{width:40px;height:40px;flex:none}.brand-name{font-size:1.45rem;font-weight:750;letter-spacing:-.035em;line-height:1.15}.brand-by{font-size:.71rem;letter-spacing:.11em;text-transform:uppercase;color:#adbbc9;margin-top:4px}.edition{color:#adbbc9;font-size:.8rem;text-align:right}.hero{padding-top:23px;padding-bottom:23px}.eyebrow{font-size:.72rem;font-weight:750;text-transform:uppercase;letter-spacing:.16em;color:#238266;margin-bottom:13px}.hero .eyebrow{color:var(--mint)}.hero p{max-width:800px;color:#c3cfdd;font-size:.9rem;margin-bottom:0}.hero-meta{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px;font-size:.72rem;color:#bcc9d8}.hero-meta code{font-size:inherit}.hero-meta span{padding:7px 12px;border:1px solid #334055;border-radius:7px;overflow-wrap:anywhere;min-width:0;max-width:100%}.nav{background:#fff;border-bottom:1px solid var(--line)}.nav .wrap{display:flex;flex-wrap:wrap;gap:8px 25px;padding-top:17px;padding-bottom:17px}.nav a{color:#40516b;text-decoration:none;font-size:.84rem;font-weight:600}.nav a:hover{text-decoration:underline}main{padding-top:32px;padding-bottom:64px}section{scroll-margin-top:24px;margin-bottom:44px}.panel{background:var(--white);border:1px solid var(--line);border-radius:16px;padding:28px}.posture{display:grid;grid-template-columns:8px 1fr;gap:24px;padding:28px;background:#fff;border:1px solid var(--line);border-radius:16px;margin-bottom:20px}.posture:before{content:"";background:#1c8065;border-radius:6px}.posture h2{font-size:1.45rem}.posture p:last-child{margin-bottom:0}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px;margin:20px 0}.metric{padding:20px 22px;background:#fff;border:1px solid var(--line);border-radius:13px}.metric strong{display:block;font-size:2rem;line-height:1.1;letter-spacing:-.04em;margin-bottom:7px}.metric span{font-size:.8rem;color:var(--muted)}.severity-row{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);border-radius:13px;overflow:hidden;background:#fff;margin:20px 0}.severity-cell{padding:15px 20px;border-right:1px solid var(--line);display:flex;justify-content:space-between;gap:10px;align-items:center}.severity-cell:last-child{border:0}.severity-cell strong{font-size:1.2rem}.pill{display:inline-block;border:1px solid #ccd7e4;background:#f1f5f9;color:#3b4e66;border-radius:5px;padding:2px 8px;font-size:.69rem;font-weight:700;letter-spacing:.02em;line-height:1.6;overflow-wrap:anywhere;max-width:100%}.pill.justified{background:#f2ecff;border-color:#c7b3e9;color:#60408e}.pill.disabled,.pill.excluded_from_review{background:#eef0f3;border-color:#c4ccd5;color:#4c5969}.pill.critical{background:#fde9ec;border-color:#f2b1bd;color:#961331}.pill.high{background:#fff0e6;border-color:#f4c8a7;color:#913f0d}.pill.medium{background:#fff9dc;border-color:#e4d280;color:#745707}.pill.low{background:#e8f1ff;border-color:#bdd3f3;color:#285286}.pill.info{background:#edf3f5;border-color:#c6d7dc;color:#375866}.muted,.small{color:var(--muted)}.small{font-size:.84rem}.note{border-left:3px solid #65aa98;padding:12px 18px;background:#edf7f3;border-radius:0 8px 8px 0;font-size:.88rem}.note.warning{border-color:#c9a351;background:#fff9e8}.section-heading{display:flex;justify-content:space-between;gap:20px;align-items:baseline;margin-bottom:18px}.section-heading p{margin-bottom:0}.action-preview{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:22px 0}.preview{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px}.preview h3{font-size:1rem;margin-top:10px}.preview p:last-child{margin-bottom:0}.badge-line{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px}.priority{background:#0f2d29;color:#dcfff2;border-color:#0f2d29}.action-card,.finding{background:#fff;border:1px solid var(--line);border-radius:14px;padding:25px;margin-bottom:17px;scroll-margin-top:24px}.action-card h3{font-size:1.25rem}.rule-label{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.76rem;color:var(--muted)}.action-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}.action-grid>div{background:#f6f8fb;padding:18px;border-radius:10px}.action-grid p{margin-bottom:0;font-size:.9rem}.locations{margin-top:15px}.sources{font-size:.79rem;color:var(--muted);margin-top:17px}.sources ul{margin-top:7px}.sources li+li{margin-top:4px}.layer{border-left:3px solid #35aa88;padding:0 0 0 17px;margin:23px 0}.layer h4{font-size:1rem}.layer p{font-size:.87rem;margin-bottom:9px}.layer .residual{color:#6d541b;background:#fff9e9;padding:10px 13px;border-radius:6px}.layer:first-child{margin-top:4px}.layer:last-child{margin-bottom:4px}details{border:1px solid var(--line);border-radius:10px;background:#fff;margin-top:15px}summary{padding:16px 18px;cursor:pointer;font-weight:650;line-height:1.45;overflow-wrap:anywhere}summary:hover{background:#f5f8fa;border-radius:10px}details[open]>summary{border-bottom:1px solid var(--line);border-radius:10px 10px 0 0}.details-body{padding:20px}.details-body>:last-child{margin-bottom:0}.control{margin-top:12px;scroll-margin-top:24px}.control>summary{display:flex;justify-content:space-between;gap:15px;align-items:center}.control-title{max-width:75%}.control-code{display:block;font-size:.72rem;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em}.control>summary:before{content:"+";font-size:1.3rem;color:#397763;margin-right:3px}.control[open]>summary:before{content:"−"}.control>summary .control-title{flex:1}.checklist{list-style:none;padding:0;counter-reset:checks}.checklist li{position:relative;padding:10px 12px 10px 40px;background:#f4f7fa;border-radius:7px;counter-increment:checks;font-size:.88rem}.checklist li:before{content:counter(checks);position:absolute;left:13px;color:#397763;font-weight:700}.analyst-panel{border:1px solid #c7cce9;background:#f7f6fe;border-radius:11px;padding:20px;margin-top:18px}.analyst-panel h4{color:#4e4481}.analyst-check{border-top:1px solid #dcdcf0;padding-top:16px;margin-top:16px}.analyst-check p{font-size:.88rem}.evidence-location{display:block;color:#516279;font-size:.8rem;overflow-wrap:anywhere;margin-bottom:12px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;margin:16px 0}table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{background:#f1f5f9;color:#485b73;font-weight:650}tr:last-child td{border-bottom:0}.empty{padding:26px;background:#fff;border:1px dashed #a4bfb5;border-radius:12px;color:#3d6657}.coverage-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.coverage-grid>div{min-width:0}.audit{font-size:.75rem;max-height:36rem;overflow:auto}.footer{background:#0b1220;color:#aab9ca;padding:28px 0;font-size:.78rem}.footer p:last-child{margin-bottom:0}.footer strong{color:#f2f6fa}.unlinked{overflow-wrap:anywhere}.inline-code{padding:2px 5px;border:1px solid var(--line);border-radius:4px;background:#f1f5f9}.back{font-size:.78rem;float:right}.verification{padding-left:21px;font-size:.88rem}.check-note{font-size:.8rem;color:#695687}.spacer{margin-top:22px}
.posture.urgent:before{background:#c34b42}.posture.attention:before{background:#b18832}.posture.neutral:before{background:#597693}
@media(max-width:850px){.wrap{padding-left:22px;padding-right:22px}.severity-cell{padding:13px 12px;display:block}.severity-cell strong{display:block;margin-top:7px}.coverage-grid{grid-template-columns:1fr}.hero{padding-top:22px;padding-bottom:22px}.hero-meta{display:block}.hero-meta span{display:block;margin-top:8px}.action-grid{grid-template-columns:1fr}.section-heading{display:block}}
@media(max-width:560px){.wrap{padding-left:16px;padding-right:16px}.edition{max-width:120px}.metrics,.action-preview{grid-template-columns:1fr 1fr;gap:9px}.metric{padding:17px 14px}.metric strong{font-size:1.65rem}.severity-row{grid-template-columns:repeat(3,minmax(0,1fr))}.severity-cell{border-bottom:1px solid var(--line)}.action-preview{grid-template-columns:1fr}.panel,.action-card,.finding{padding:20px}.posture{padding:22px;gap:15px}.control>summary{flex-wrap:wrap}.control-title{max-width:85%}.details-body{padding:16px}.nav .wrap{gap:9px 18px}.brand-name{font-size:1.4rem}.brand svg{width:39px;height:39px}.back{float:none;display:block;margin-bottom:10px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:#fff;font-size:10pt}.wrap{max-width:none;padding:0}.masthead{background:#fff;color:#142338;border-bottom:2px solid #1c8065}.brand-name{color:#142338}.brand-by,.edition,.hero p,.hero-meta{color:#516279}.brand svg{background:#0b1220;border-radius:7px}.brandrow{padding:0 0 14px;border:0}.hero{padding:18px 0}.hero .eyebrow{color:#12674f}h1{font-size:27pt}h2{font-size:19pt}.hero-meta span{border-color:#b8c6d6}.nav,.back{display:none}main{padding:20px 0}.panel,.posture,.action-card,.finding,.metric,details,.preview{box-shadow:none;border-color:#c2cbd4;border-radius:5px}.metrics{grid-template-columns:repeat(4,1fr)}.action-preview{grid-template-columns:1fr 1fr}.action-grid{grid-template-columns:1fr 1fr}.metric strong{font-size:22pt}.severity-row{grid-template-columns:repeat(5,1fr)}.severity-cell{display:flex}.action-card,.finding,.control{break-inside:auto}h2,h3,h4,summary{break-after:avoid}pre,.layer{break-inside:auto}.audit{max-height:none;overflow:visible}details>summary{list-style:none}details>.details-body{display:block!important}details::details-content{display:block!important;content-visibility:visible!important}details{content-visibility:visible}a{color:#12674f;text-decoration:underline}.footer{background:#fff;color:#516279;border-top:1px solid #c2cbd4}.footer strong{color:#142338}section{margin-bottom:28px}.hero-meta{display:block}.hero-meta span{display:block;margin-top:5px}.coverage-grid{grid-template-columns:1fr}.table-wrap{overflow:visible}thead{display:table-header-group}.checklist li,.note,.action-grid>div{background:#f6f8fa}@page{margin:16mm 14mm}}
"""



_CSS += """
.status-strip{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:18px 0}.status-strip>div{padding:15px 18px;border:1px solid var(--line);border-left:4px solid #238266;border-radius:9px;background:#fff}.status-strip>div:last-child{border-left-color:#8061a6}.status-strip span{display:block;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}.status-strip strong{display:block;font-size:.95rem;margin:5px 0}.status-strip p{font-size:.8rem;margin:0}.priority-table th:first-child{width:12%}.priority-table th:nth-child(2){width:22%}.priority-table td{vertical-align:top}.priority-table td:last-child{min-width:230px}.priority-table .pill{margin-bottom:6px}.priority-table p{margin:7px 0 0}.priority-table a{font-weight:600}.priority-table .small{font-size:.8rem}
@media(max-width:760px){.status-strip{grid-template-columns:1fr}.priority-table td:last-child{min-width:190px}}
.chart{background:#fff;border:1px solid var(--line);border-radius:14px;padding:22px;min-width:0}.chart svg{display:block;width:100%;height:auto}.chart h3{font-size:1rem}.chart-label{font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;fill:#40516b}.chart-number{font:600 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;fill:#142338}.visual-summary{margin:22px 0 14px}.review-flow{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;list-style:none;padding:0;margin:22px 0}.review-flow li{margin:0;padding:22px;background:#fff;border:1px solid var(--line);border-top:4px solid #238266;border-radius:10px}.review-flow li:nth-child(2){border-top-color:#8061a6}.review-flow li:nth-child(3){border-top-color:#c19b4d}.review-flow span{display:block;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:9px}.review-flow h3{font-size:1.05rem}.review-flow p{font-size:.86rem;margin-bottom:0}.review-steps li{padding-left:5px}.review-toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:22px 0 14px}.review-toolbar button{border:1px solid #12674f;border-radius:8px;padding:12px 18px;background:#12674f;color:#fff;font:600 .86rem -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}.review-toolbar button:hover{background:#09533e}.review-toolbar button.secondary{background:#fff;color:#12674f}.review-toolbar button.secondary:hover{background:#edf7f3}.review-toolbar button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #8061a6;outline-offset:3px}.review-toolbar span{font-size:.8rem;color:var(--muted)}.review-editor{border-color:#c7cce9;background:#fcfbff}.review-editor summary{display:flex;justify-content:space-between;gap:10px;color:#584282;font-size:.86rem}.review-editor fieldset{border:0;padding:0;margin:0;min-width:0}.review-editor legend{font-weight:650;font-size:.9rem;margin-bottom:12px;overflow-wrap:anywhere;max-width:100%}.review-editor label{display:block;font-size:.8rem;font-weight:650;margin:13px 0 5px}.review-editor input,.review-editor select,.review-editor textarea{width:100%;min-width:0;max-width:100%;padding:10px 12px;border:1px solid #bac5d3;border-radius:6px;background:#fff;color:#243750;font:inherit;font-size:.85rem;line-height:1.5}.review-editor textarea{resize:vertical}.review-fields{display:grid;grid-template-columns:1fr 1fr;gap:14px}.review-fields>div:last-child{grid-column:1/-1}.review-editor .small:last-child{margin:15px 0 0}.checklist .review-editor{counter-reset:none}.checklist .review-editor li{counter-increment:none}.review-editor .spacer{margin-top:10px}#review-save-status{overflow-wrap:anywhere}#configuration td:nth-child(2){min-width:150px}#method th:first-child{width:30%}#method th:nth-child(2){width:38%}
@media(max-width:760px){.review-flow{grid-template-columns:1fr}.review-fields{grid-template-columns:1fr}.review-fields>div:last-child{grid-column:auto}.review-toolbar{align-items:stretch}.review-toolbar button{width:100%}.review-editor .details-body{padding:15px}.chart{padding:17px}.review-flow li{padding:18px}#configuration td:nth-child(2){min-width:90px}}
@media print{.review-toolbar button,noscript{display:none}.review-flow{grid-template-columns:repeat(3,1fr)}.review-editor summary{color:#243750}.review-editor input,.review-editor select,.review-editor textarea{border-color:#c2cbd4}.chart,.review-flow li{break-inside:avoid}.review-editor{break-inside:auto}.review-editor textarea{min-height:60px}}
"""

_MARK = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Invarune evidence mark">'
         '<polygon fill="#F2F6FA" points="26,4 8,14 8,50 26,60 26,47 19,43 19,21 26,17"/>'
         '<polygon fill="#35E3B1" points="38,4 56,14 56,50 38,60 38,47 45,43 45,21 38,17"/>'
         '<polygon fill="#35E3B1" points="32,22 42,32 32,42 22,32"/></svg>')


def _action(group, finding_ids, control_ids):
    parts = ['<article class="action-card" id="' + _anchor("group", group.get("id", "")) + '">',
             '<div class="badge-line"><span class="pill priority">' + _escape(group.get("priority", "Review")) + '</span>',
             _pill(group.get("severity", "info"), True), _pill(group.get("status", "open")),
             '<span class="rule-label">' + _escape(group.get("rule_id", "")) + '</span></div>',
             '<h3>' + _escape(group.get("title", "Finding group")) + '</h3>',
             '<p class="small">' + _escape(group.get("count", len(group.get("finding_ids", []))))
             + ' occurrence(s) · Suggested owner: <strong>' + _escape(group.get("suggested_owner", "Security and engineering")) + '</strong></p>',
             '<div class="action-grid"><div><h4>Why this matters</h4><p>' + _escape(group.get("plausible_impact", "Investigate the evidence and validate the reachable impact."))
             + '</p></div><div><h4>Immediate action</h4><p>' + _escape(group.get("immediate_action", "Review the linked finding evidence.")) + '</p></div></div>']
    if group.get("image_context"):
        label = "Evidence context" if group["image_context"] == "source" else "Image evidence context"
        parts.append('<p class="small spacer"><strong>' + label + ':</strong> ' + _escape(group["image_context"]) + '</p>')
    if group.get("context_note"):
        parts.append('<p class="note spacer">' + _escape(group["context_note"]) + '</p>')
    locations = []
    for location in group.get("locations", []):
        label = _text(location.get("path", "")) + ":" + _text(location.get("line", "?"))
        if location.get("end_line") != location.get("line"):
            label += "–" + _text(location.get("end_line", "?"))
        identifier = location.get("finding_id", "")
        locations.append('<li>' + ('<a href="#' + _anchor("finding", identifier) + '">' + _escape(label) + '</a>' if identifier in finding_ids else _escape(label)) + '</li>')
    if locations:
        parts.append(_details("Affected locations (" + _text(len(locations)) + ")", '<ul class="locations">' + "".join(locations) + '</ul>'))
    parts.append(_finding_links(group.get("finding_ids", []), finding_ids))
    parts.append(_control_links(group.get("control_ids", []), control_ids))
    layers = []
    for layer in group.get("defense_layers", []):
        layer_parts = ['<article class="layer"><h4>' + _escape(layer.get("title", "Mitigation layer")) + '</h4>',
                       '<p><strong>How it lowers risk:</strong> ' + _escape(layer.get("how_it_helps", "")) + '</p>',
                       '<p><strong>Evidence to verify:</strong> ' + _escape(layer.get("verification", "")) + '</p>',
                       '<p class="residual"><strong>Residual limitation:</strong> ' + _escape(layer.get("residual_limit", "")) + '</p>',
                       '<p class="small"><strong>Verification status:</strong> ' + _escape(layer.get("status", "proposed_not_verified")) + '</p>',
                       _control_links(layer.get("control_ids", []), control_ids),
                       _sources(layer.get("sources", [])), '</article>']
        layers.append("".join(layer_parts))
    if layers:
        parts.append('<p class="small spacer"><strong>Additional defenses to verify:</strong> '
                     + _escape(" • ".join(_text(layer.get("title", "Mitigation layer")) for layer in group.get("defense_layers", []))) + '</p>')
        parts.append(_details("Additional layers that can lower risk (" + _text(len(layers)) + ")", "".join(layers)))
    if group.get("sources"):
        parts.append(_details("Guidance sources (" + _text(len(group["sources"])) + ")", _sources(group["sources"])))
    parts.append('</article>')
    return "\n".join(parts)


def _recommended_actions(actions):
    if not actions:
        return ""
    return ('<div class="panel"><h4>Model-proposed fix guidance (unverified)</h4><p><strong>Agent/MCP relevance:</strong> '
            + _escape(actions["agent_mcp_relevance"]) + '</p><p><strong>When this applies:</strong> '
            + _escape(actions["applicability"]) + '</p>' + _list(actions["steps"], ordered=True)
            + '<p><strong>How to verify</strong></p>' + _list(actions["verification"]) + '</div>')


def _remediation(advice):
    if not advice:
        return ""
    parts = ['<h4>Fix plan and agent/MCP relevance</h4><p>' + _escape(advice["summary"]) + '</p>',
             '<p><strong>Why this matters for agents/MCP:</strong> ' + _escape(advice["agent_mcp_relevance"]) + '</p>',
             '<p class="note">' + _escape(advice["scope_note"]) + '</p><p><strong>Confirm applicability</strong></p>',
             _list(advice["applicability"]), '<ol>']
    for step in advice["steps"]:
        parts += ['<li><strong>' + _escape(step["title"]) + '</strong><p>' + _escape(step["action"])
                  + '</p><p class="small"><strong>Verify:</strong> ' + _escape(step["verification"]) + '</p></li>']
    parts += ['</ol><p><strong>Remaining validation</strong></p>', _list(advice["residual_risk"]),
              '<p class="small">Related controls: ' + _escape(", ".join(advice["control_ids"])) + '</p>',
              _sources(advice["sources"], "Fix guidance sources")]
    return "\n".join(parts)


def _finding(finding, review_item=None, remediation=None, advisory=None):
    identifier = finding.get("id", finding.get("finding_id", ""))
    parts = ['<article class="finding" id="' + _anchor("finding", identifier) + '">',
             '<div class="badge-line">' + _pill(finding.get("severity", "info"), True)
             + _pill(finding.get("status", "open")) + '<span class="rule-label">' + _escape(finding.get("rule_id", "")) + '</span></div>',
             '<h3>' + _escape(finding.get("title", "Finding")) + '</h3>',
             '<span class="evidence-location">' + _escape(finding.get("path", "")) + ":" + _escape(finding.get("line", "?"))
             + "–" + _escape(finding.get("end_line", finding.get("line", "?"))) + '</span>',
             '<p class="small"><strong>Finding ID:</strong> <code>' + _escape(identifier) + '</code><br><strong>Confidence:</strong> '
             + _escape(finding.get("confidence", "unknown")) + ' · <strong>Category:</strong> ' + _escape(finding.get("category", "unknown")) + '</p>',
             '<p>' + _escape(finding.get("description", "")) + '</p>',
             '<h4>Observed evidence</h4><pre><code>' + _escape(finding.get("evidence", "")) + '</code></pre>',
             '<p><strong>Remediation:</strong> ' + _escape(finding.get("remediation", "")) + '</p>']
    parts.append(_remediation(remediation))
    if advisory:
        parts += ['<h4>Optional finding review</h4><p>' + _escape(advisory.get("verdict", "needs_review"))
                  + ': ' + _escape(advisory.get("reason", "")) + '</p>', _recommended_actions(advisory.get("recommended_actions"))]
    if finding.get("suppression_reason"):
        parts.append('<p class="note warning"><strong>Suppression reason:</strong> ' + _escape(finding["suppression_reason"]) + ' A baseline records an accepted exception; it does not remediate this finding.</p>')
    if finding.get("disposition"):
        disposition = finding["disposition"]
        parts.append('<p class="note warning"><strong>User decision:</strong> ' + _escape(disposition["status"])
                     + ' (' + _escape(disposition.get("scope", "rule")) + ' ' + _escape(disposition.get("id", finding.get("rule_id", "")))
                     + '). <strong>User reason:</strong> ' + _escape(disposition.get("reason", "No reason supplied."))
                     + '<br>This observed pattern is retained for audit and excluded from active findings and the severity gate. Its severity and evidence remain unchanged; this decision does not prove remediation.</p>')
    if finding.get("image_context"):
        parts.append('<p><strong>Image evidence context:</strong> ' + _escape(finding["image_context"]) + '</p>')
    if finding.get("image_provenance"):
        parts.append(_details("Image evidence provenance", _json(finding["image_provenance"])))
    if finding.get("cwe"):
        parts.append('<p class="small"><strong>Weakness mappings:</strong> ' + _escape(", ".join(finding["cwe"])) + '</p>')
    parts.append(_sources(finding.get("references", []), "Finding references"))
    parts.append(_editor(review_item))
    parts.append('</article>')
    return "\n".join(parts)


def _advisory_check(check):
    parts = ['<div class="analyst-check"><h4>Check ' + _escape(check.get("check_index", "?")) + ": "
             + _escape(check.get("status", "insufficient_evidence")) + '</h4>',
             '<p>' + _escape(check.get("reason", "No assessment reason was provided.")) + '</p>']
    parts.append(_recommended_actions(check.get("recommended_actions")))
    for key, label in (("risk_hypothesis", "Risk hypothesis"), ("boundary", "Trust boundary"),
                       ("counterevidence", "Counterevidence considered"), ("conclusion_limits", "Conclusion limits")):
        value = check.get("analysis", {}).get(key)
        if value:
            parts.append('<p><strong>' + label + ':</strong> ' + _escape(value) + '</p>')
    if check.get("status") in ("justified", "disabled"):
        parts.append('<p class="check-note">User decision; excluded from optional review and active check totals.</p>')
    elif not check.get("model_supplied", False):
        parts.append('<p class="check-note">No model assessment was received for this check.</p>')
    for citation in check.get("citations", []):
        parts += ['<p class="small"><strong>Evidence ' + _escape(citation.get("evidence_id", "")) + ':</strong> '
                  + _escape(citation.get("path", "")) + ":" + _escape(citation.get("start_line", "?")) + "–" + _escape(citation.get("end_line", "?"))
                  + ' · exact quote verified in submitted excerpt</p>', '<pre><code>' + _escape(citation.get("quote", "")) + '</code></pre>']
    if check.get("verification_steps"):
        parts += ['<p><strong>Verification still required</strong></p>', _list(check["verification_steps"], "verification")]
    parts.append('</div>')
    return "\n".join(parts)


def _control(control, advisory, finding_ids, review_items=None):
    identifier = control.get("id", "")
    parts = ['<details class="control" id="' + _anchor("control", identifier) + '"><summary><span class="control-title"><span class="control-code">'
             + _escape(identifier) + '</span>' + _escape(control.get("title", "Control")) + '</span>' + _pill(control.get("status", "review_required"))
             + '</summary><div class="details-body">',
             '<p class="small"><strong>Category:</strong> ' + _escape(control.get("category", "")) + ' · <strong>Validation:</strong> '
             + _escape(control.get("validation", "")) + '</p>',
             '<p class="note">' + _escape(control.get("assurance", "Not established by this static scan")) + '</p>',
             '<h4>Acceptance checks</h4>', _checklist(control, review_items)]
    if control.get("static_status") and control["static_status"] != control["status"]:
        parts.append('<p class="small"><strong>Underlying static status:</strong> ' + _escape(control["static_status"])
                     + '. The user decision does not change detector evidence.</p>')
    if control.get("automated_rule_ids"):
        parts.append('<p class="small spacer"><strong>Partial static rules:</strong> ' + _escape(", ".join(control["automated_rule_ids"])) + '</p>')
    parts.append(_finding_links(control.get("finding_ids", []), finding_ids, "Open finding IDs"))
    parts.append(_finding_links(control.get("suppressed_finding_ids", []), finding_ids, "Suppressed finding IDs"))
    parts.append(_finding_links(control.get("justified_finding_ids", []), finding_ids, "Justified finding IDs"))
    parts.append(_finding_links(control.get("disabled_finding_ids", []), finding_ids, "Disabled finding IDs"))
    if advisory:
        parts += ['<div class="analyst-panel"><h4>Optional advisory analyst</h4>',
                  '<p class="small"><strong>Review status:</strong> ' + _escape(advisory.get("review_status", "not_reviewed"))
                  + '. Deterministic control status remains <strong>' + _escape(control.get("status", "review_required")) + '</strong>.</p>',
                  '<p class="check-note">Exact-quote validation confirms text appeared in a submitted excerpt. It does not verify the interpretation or deployed behavior.</p>']
        parts.extend(_advisory_check(check) for check in advisory.get("check_assessments", []))
        if advisory.get("provenance"):
            parts.append(_details("Advisory provenance", _json(advisory["provenance"])))
        parts.append('</div>')
    if control.get("source_ids"):
        parts.append('<p class="small spacer"><strong>Source mappings:</strong> ' + _escape(", ".join(control["source_ids"])) + '</p>')
    if control.get("alignment_source_ids"):
        parts.append('<p class="small"><strong>Additional alignment:</strong> ' + _escape(", ".join(control["alignment_source_ids"])) + '</p>')
    parts.append(_sources(control.get("sources", []), "Published control guidance"))
    parts.append('</div></details>')
    return "\n".join(parts)


def _coverage(report, assessment, review_items=None):
    coverage = report.get("coverage", {})
    summary = report.get("summary", {})
    parts = ['<section id="coverage"><div class="section-heading"><div><p class="eyebrow">Scope and assurance</p><h2>What this scan could establish</h2></div></div>',
             '<div class="coverage-grid"><div class="panel"><h3>Coverage requiring attention</h3>']
    attention = assessment.get("coverage_attention", [])
    if attention:
        for item in attention:
            parts += ['<h4>' + _escape(item.get("reason", "Coverage gap")) + ' (' + _escape(item.get("count", 0)) + ')</h4>', _list(item.get("examples", []), "small")]
    else:
        parts.append('<p>No traversal, parsing, or resource-limit gaps were recorded inside the selected scope.</p>')
    parts += ['<p class="small">Excluded directories, unsupported languages, deployment configuration, and runtime behavior may remain outside that scope.</p></div>',
              '<div class="panel"><h3>Unknowns and follow-up validation</h3>', _list(assessment.get("unknowns", coverage.get("limitations", [])), "small"), '</div></div>']
    profiles = coverage.get("analysis_profiles", {})
    rows = []
    for name, profile in sorted(profiles.items()):
        if profile.get("files"):
            rows.append('<tr><td>' + _escape(name) + '</td><td>' + _escape(profile.get("files", 0)) + '</td><td>' + _escape(profile.get("scope", "")) + '</td></tr>')
    if rows:
        parts.append('<h3 class="spacer">Analysis depth</h3><p class="small">File counts describe inspected inputs; they do not imply complete semantic coverage.</p><div class="table-wrap"><table><thead><tr><th>Profile</th><th>Files</th><th>Analysis scope</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>')
    if "bytes_charged" in summary:
        parts.append('<p class="small">Source I/O: <strong>' + _escape(summary.get("bytes_read", 0)) + ' bytes read</strong>; '
                     + _escape(summary.get("bytes_charged", 0)) + ' bytes charged against the budget, including '
                     + _escape(summary.get("failed_read_bytes_charged", 0)) + ' conservatively charged bytes for failed reads. Reads reserve a sentinel byte to detect growth.</p>')
    parts.append(_details("All scanner limitations", _list(coverage.get("limitations", []))))
    gaps = [item for item in (review_items or {}).values() if item.get("kind") == "gap"]
    if gaps:
        parts.append('<div id="gap-review" class="spacer"><h3>Review coverage gaps</h3><p>Record context and remaining work. A note cannot remove an operational gap.</p>')
        parts.extend(_editor(item) for item in gaps)
        parts.append('</div>')
    errors = coverage.get("errors", [])
    error_body = _list([_text(item.get("path", ".")) + ": " + _text(item.get("error", "")) for item in errors]) if errors else '<p>No scan errors recorded.</p>'
    parts.append(_details("Scan errors (" + _text(len(errors)) + ")", error_body, bool(errors)))
    skipped = coverage.get("skipped", [])
    rows = ['<tr><td>' + _escape(item.get("path", "")) + '</td><td>' + _escape(item.get("reason", "")) + '</td><td>'
            + ('yes' if item.get("coverage_gap") else 'outside scope') + '</td></tr>' for item in skipped]
    skipped_body = '<div class="table-wrap"><table><thead><tr><th>Path</th><th>Reason</th><th>Coverage gap</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>' if rows else '<p>No skipped paths recorded.</p>'
    parts.append(_details("Excluded or skipped paths (" + _text(len(skipped)) + ")", skipped_body))
    if coverage.get("unmatched_baseline_ids"):
        parts.append(_details("Unused baseline IDs", _list(coverage["unmatched_baseline_ids"])))
    inventory = report.get("inventory", {})
    inventory_intro = '<p>Dependency manifests: <strong>' + _escape(len(inventory.get("dependency_manifests", []))) + '</strong>; agent/MCP signal files: <strong>' + _escape(len(inventory.get("agent_mcp_signals", []))) + '</strong>.</p><p class="small">Dependency manifests are inventoried; they are not checked against a vulnerability database.</p>'
    parts.append(_details("Source and dependency inventory", inventory_intro + _json(inventory)))
    parts.append(_details("Inspected file manifest and content hashes", _json(report.get("files", []))))
    parts.append(_details("Scan configuration and selected rules", _json({"configuration": report.get("configuration", {}), "rules_enabled": coverage.get("rules_enabled", [])})))
    parts.append('</section>')
    return "\n".join(parts)


def _image(container):
    identity = container.get("identity", {})
    parts = ['<section id="image"><p class="eyebrow">Built-image analysis</p><h2>Image scope and provenance</h2><div class="panel">',
             '<p><strong>Input:</strong> ' + _escape(container.get("display_target", "")) + '<br><strong>Format:</strong> ' + _escape(identity.get("format", "unknown"))
             + ' · <strong>Platform:</strong> ' + _escape(identity.get("platform", "unknown")) + '</p>',
             '<p class="small"><strong>Image config digest:</strong> <code>' + _escape(identity.get("config_digest", "unknown")) + '</code></p>',
             '<p><strong>Analysis scope:</strong> ' + _escape(container.get("analysis_scope", "unknown")) + '<br><strong>Packaged source files inspected:</strong> '
             + _escape(container.get("packaged_source_files_inspected", 0)) + '</p>',
             '<p class="note">The container was not started. Supported packaged code and stored image metadata are inspected offline. Native binary logic is not decompiled, and package inventory is not a CVE scan.</p>',
             '<p class="small">Paths under <code>rootfs/</code> refer to the final image filesystem. <code>.image-metadata/</code> contains generated evidence from configuration, build history, permissions, and retained layers. Deployment overrides and runtime enforcement require separate validation.</p>',
             '<p class="small">' + _escape(container.get("exclusion_scope", "")) + '</p>',
             _details("Image identity, digests, and acquisition", _json({"identity": identity, "input_kind": container.get("input_kind"), "acquisition": container.get("acquisition")})),
             _details("Image package, operating-system, permission, and runtime inventory", _json(container.get("inventory", {}))),
             _details("Image extraction and assessment coverage", _json({"extraction_coverage": container.get("extraction_coverage", {}), "assessment_coverage": container.get("assessment_coverage", {}), "limits": container.get("limits", {})})),
             '</div></section>']
    return "\n".join(parts)


def _advisory(report):
    judge = report.get("judge", {})
    analyst = report.get("analyst", {})
    parts = ['<section id="advisory"><p class="eyebrow">Separate advisory layer</p><h2>Optional security review</h2><div class="panel">',
             '<p class="note">Model output is nondeterministic and advisory. It cannot dismiss deterministic findings, change their severity, establish compliance, or change the deterministic CI gate.</p>']
    if not judge.get("enabled") and not analyst.get("enabled"):
        parts.append('<p><strong>Disabled.</strong> No optional LLM request was made. The deterministic scan and this report run independently.</p>')
    if (judge.get("enabled") or analyst.get("enabled")) and report.get("advice_coverage"):
        parts.append(_details("Fix guidance coverage and omissions", _json(report["advice_coverage"]), opened=True))
    if judge.get("enabled"):
        parts += ['<h3>Finding judge</h3><p class="small">Status and request metadata below are advisory. Source strings and returned advice are rendered as text.</p>', _details("Finding judge result and request audit", _json(judge))]
        actions = {entry["concern_index"]: entry["recommended_actions"] for entry in judge.get("additional_concern_actions", [])}
        for index, concern in enumerate(judge.get("additional_concerns", []), 1):
            parts += ['<h4>Additional model concern ' + str(index) + ' (unverified)</h4><p>' + _escape(concern) + '</p>',
                      _recommended_actions(actions.get(index))]
    elif analyst.get("enabled"):
        parts.append('<p class="small"><strong>Finding judge:</strong> disabled.</p>')
    if analyst.get("enabled"):
        coverage = analyst.get("coverage", {})
        investigation = analyst.get("investigation", {})
        if investigation:
            parts += ['<div class="analyst-panel"><h3>Bounded evidence investigation</h3><p>Follow-up rounds: '
                      + _escape(investigation.get("rounds_completed", 0)) + ' · evidence requests served / denied: '
                      + _escape(investigation.get("requests_served", 0)) + ' / ' + _escape(investigation.get("requests_denied", 0))
                      + ' · captured files offered: ' + _escape(investigation.get("snapshot_files_offered", 0))
                      + '.</p><p>The model can request exact ranges from verified, redacted snapshots. The controller enforces file IDs, scope, shared budgets and quote validation. Requests do not execute target tools or resolve runtime uncertainty.</p>'
                      + _details("Evidence requests, counterevidence and budget receipts", _json(investigation)) + '</div>']
        parts += ['<div class="analyst-panel"><h3>Control analyst</h3><p><strong>Review status:</strong> ' + _escape(analyst.get("status", "unknown"))
                  + ' · <strong>Controls reviewed:</strong> ' + _escape(coverage.get("reviewed_controls", 0)) + '/' + _escape(coverage.get("total_controls", 0))
                  + '<br><strong>Unanswered checks:</strong> ' + _escape(coverage.get("omitted_checks", 0))
                  + ' · <strong>Control requests:</strong> ' + _escape(coverage.get("calls_made", 0)) + '/' + _escape(coverage.get("call_budget", 0)) + '</p>',
                  '<p class="small">Every active control is routed for review because static patterns cannot establish completion. Review completion means an answer was received for every active check; it does not mean the checks passed. User-justified and disabled checks are excluded from review counts. Model tools and runtime execution are disabled.</p>',
                  '<p class="small">Per-check status, reasons, verified quotes, and proposed verification steps appear beside each control in the <a href="#controls">complete control checklist</a>.</p>']
        counts = analyst.get("check_status_counts", {})
        if counts:
            parts.append('<div class="table-wrap"><table><thead><tr><th>Advisory check status</th><th>Count</th></tr></thead><tbody>'
                         + "".join('<tr><td>' + _escape(status) + '</td><td>' + _escape(count) + '</td></tr>' for status, count in sorted(counts.items())) + '</tbody></table></div>')
        parts += ['<p class="check-note">Only bounded excerpts were submitted. Missing evidence may reflect collection limits, exclusions, or retrieval misses. A verified quote establishes its presence in an excerpt, not the truth of the interpretation. Proposed verification steps have not been executed.</p>',
                  _details("Evidence selection and analyst review coverage", _json(coverage)),
                  _details("Analyst request receipts and provenance", _json({"requests": analyst.get("requests", []), "provenance": analyst.get("provenance", {})})),
                  _details("Redacted analyst evidence and original file hashes", _json(analyst.get("evidence", [])))]
        if analyst.get("errors"):
            parts.append(_details("Analyst errors", _list(analyst["errors"]), True))
        parts.append('</div>')
    elif judge.get("enabled"):
        parts.append('<p class="small"><strong>Control analyst:</strong> disabled.</p>')
    parts.append('</div>' + _token_optimization(report) + '</section>')
    return "\n".join(parts)


def _advisory_summary(report):
    judge = report.get("judge", {})
    analyst = report.get("analyst", {})
    if not judge.get("enabled") and not analyst.get("enabled"):
        return ('<p class="small spacer"><strong>Optional review:</strong> disabled. '
                'The deterministic analysis ran offline; no LLM request was made.</p>')
    coverage = analyst.get("coverage", {})
    incomplete = any(item.get("enabled") and item.get("status") != "completed" for item in (judge, analyst))
    incomplete = incomplete or bool(analyst.get("enabled") and coverage.get("omitted_checks", 0))
    parts = ['<div class="note' + (' warning' if incomplete else '') + ' spacer">']
    if incomplete:
        parts.append('<p><strong>Requested optional review is incomplete; static findings are preserved.</strong></p>')
    parts.append('<p><strong>Optional review:</strong> finding judge '
                 + _escape(judge.get("status", "unknown") if judge.get("enabled") else "disabled")
                 + '; control analyst ' + _escape(analyst.get("status", "unknown") if analyst.get("enabled") else "disabled") + '.</p>')
    if analyst.get("enabled"):
        parts.append('<p><strong>Controls reviewed:</strong> ' + _escape(coverage.get("reviewed_controls", 0)) + '/'
                     + _escape(coverage.get("total_controls", 0)) + ' · <strong>Unanswered checks:</strong> '
                     + _escape(coverage.get("omitted_checks", 0)) + '. Review completion does not mean the checks passed.</p>')
    if judge.get("enabled") and "omitted_open_findings" in judge:
        parts.append('<p><strong>Open findings outside the bounded judge review:</strong> '
                     + _escape(judge["omitted_open_findings"]) + '.</p>')
    parts.append('<p>Advisory output cannot lower deterministic finding severity or establish control completion. '
                 '<a href="#advisory">Review optional-review coverage, errors, and request audit</a>.</p></div>')
    return "\n".join(parts)


def _status_strip(report):
    summary = report.get("summary", {})
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    static = "Incomplete selected scope" if summary.get("coverage_gaps", 0) else "Selected scope completed"
    optional = "Disabled - no model review requested"
    if judge.get("enabled") or analyst.get("enabled"):
        optional = "Findings: " + str(judge.get("status", "unknown") if judge.get("enabled") else "disabled")
        optional += " / Controls: " + str(analyst.get("status", "unknown") if analyst.get("enabled") else "disabled")
        counts = analyst.get("check_status_counts", {})
        if analyst.get("enabled"):
            optional += "; {} potential gaps; {} checks need runtime, human or additional evidence; {} unanswered".format(
                _count(counts.get("potential_gap", 0)),
                sum(_count(counts.get(key, 0)) for key in ("needs_runtime_validation", "needs_human_review", "insufficient_evidence")),
                _count(analyst.get("coverage", {}).get("omitted_checks", 0)))
        if judge.get("additional_concerns"):
            optional += "; {} additional advisory concerns".format(len(judge["additional_concerns"]))
    return ('<div class="status-strip" aria-label="Independent scan and review outcomes"><div><span>Deterministic layer</span><strong>'
            + _escape(static) + '</strong><p>Observed evidence and fixes. <a href="#coverage">Inspect scope and limits</a>.</p></div>'
            + '<div><span>Optional model layer</span><strong>' + _escape(optional)
            + '</strong><p>Advisory interpretations remain separate. <a href="#advisory">Inspect actual review coverage</a>.</p></div></div>')


def _priority_preview(actions, known_findings):
    rows = []
    for group in actions[:5]:
        locations = []
        for location in group.get("locations", [])[:2]:
            label = str(location.get("path", "")) + ":" + str(location.get("line", ""))
            if location.get("finding_id") in known_findings:
                locations.append('<a href="#' + _anchor("finding", location["finding_id"]) + '">' + _escape(label) + '</a>')
            else:
                locations.append(_escape(label))
        extra = len(group.get("locations", [])) - len(locations)
        if extra > 0:
            locations.append(_escape("+" + str(extra) + " more locations"))
        rows.append('<tr><td>' + _pill(group.get("priority", "Review")) + '<br>' + _escape(group.get("count", 0)) + ' open</td><td>'
                    + ('<br>'.join(locations) or 'See finding evidence') + '</td><td><a href="#' + _anchor("group", group.get("id", "")) + '">'
                    + _escape(str(group.get("rule_id", "")) + " / " + str(group.get("title", "Finding group"))) + '</a><p class="small">'
                    + _escape(group.get("immediate_action", "Review the linked evidence.")) + '</p></td></tr>')
    return ('<div class="table-wrap"><table class="priority-table"><thead><tr><th>Priority / count</th><th>Observed locations</th>'
            + '<th>Immediate concern and first action</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>')


def _token_optimization(report):
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    records = []
    if isinstance(judge.get("token_optimization"), dict):
        records.append(("Finding request", judge["token_optimization"]))
    for index, request in enumerate(analyst.get("requests", []), 1):
        if isinstance(request.get("token_optimization"), dict):
            records.append(("Control request " + str(index), request["token_optimization"]))
    if not records:
        return ""
    rows = []
    for label, record in records:
        rows.append('<tr><td>' + _escape(label) + '</td><td>' + _escape(record.get("requested", "unknown")) + ' / '
                    + _escape(record.get("engine", "unknown")) + '</td><td>' + _escape(record.get("status", "unknown"))
                    + ('<br>' + _escape(record["fallback_reason"]) if record.get("fallback_reason") else '')
                    + '</td><td>' + _escape(record.get("payload_bytes_before", 0)) + ' → ' + _escape(record.get("payload_bytes_after", 0))
                    + '<br>' + _escape(record.get("bytes_saved", 0)) + ' bytes saved</td></tr>')
    return ('<div class="panel spacer"><h3>Optional request payload optimization</h3><div class="table-wrap"><table><thead><tr>'
            + '<th>Request</th><th>Requested / actual engine</th><th>Outcome</th><th>Evidence payload bytes</th></tr></thead><tbody>'
            + ''.join(rows) + '</tbody></table></div><p class="small">These are measured evidence-JSON bytes, excluding instructions, response schemas and provider wrappers. '
            + 'Token and cost savings were not measured. Evidence-preserving formatting does not validate a model interpretation.</p></div>')


# Deterministic SVGs use numeric measurements from this report, never a risk score.
def _count(value):
    try:
        return max(0, int(value))
    except (ValueError, TypeError, OverflowError):
        return 0


def _bars(title, rows):
    """Accessible, noninteractive count chart with visible numeric labels."""
    maximum = max([_count(row[1]) for row in rows] + [1])
    height = 34 * len(rows) + 10
    parts = ['<div class="chart"><h3>' + _escape(title) + '</h3>',
             '<svg viewBox="0 0 560 ' + str(height) + '" role="img" aria-label="' + _escape(title) + '">',
             '<title>' + _escape(title) + '; ' + _escape('; '.join(str(label) + ': ' + str(_count(value)) for label, value, _ in rows)) + '</title>']
    for index, (label, value, color) in enumerate(rows):
        value = _count(value)
        y = 34 * index + 5
        width = value * 290 / maximum
        parts += ['<text x="0" y="' + str(y + 17) + '" class="chart-label">' + _escape(label) + '</text>',
                  '<rect x="190" y="' + str(y) + '" width="290" height="23" rx="4" fill="#edf1f5"/>',
                  '<rect x="190" y="' + str(y) + '" width="' + format(width, '.2f') + '" height="23" rx="4" fill="' + color + '"/>',
                  '<text x="492" y="' + str(y + 17) + '" class="chart-number">' + str(value) + '</text>']
    parts.append('</svg></div>')
    return ''.join(parts)


def _visual_summary(report, assessment):
    from .scoring import build_scoring
    scoring = report.get("scoring") or build_scoring(report)
    mapped = scoring["deterministic"]["mapping_reach"]["numerator"]
    active_controls = scoring["deterministic"]["active_controls"]
    active_checks = scoring["deterministic"]["active_checks"]
    answered = scoring["optional_ai"]["answer_coverage"]["numerator"]
    findings = report.get("findings", [])
    rows = [(label, sum(finding.get("status") == state for finding in findings), color)
            for state, label, color in (("open", "Open findings", "#c26024"), ("suppressed", "Baseline suppressed", "#7a8595"),
                                       ("justified", "User justified", "#8061a6"), ("disabled", "User disabled", "#99a4b2"))]
    return ('<div class="coverage-grid visual-summary">' + _bars("Finding dispositions", rows)
            + _bars("Static control mapping", [("Partial static mapping", mapped, "#238266"),
                                                  ("No mapped detector", active_controls - mapped, "#99a4b2")])
            + '</div><p class="small">The mapping chart counts active selected controls with at least one active selected partial detector: '
            + str(mapped) + '/' + str(active_controls) + '. It is not a control pass rate or vulnerability-detection rate. '
            + str(answered) + '/' + str(active_checks) + ' active acceptance checks received an optional model answer; an answer does not establish effectiveness.</p>')


def _method_and_configuration(report, assessment):
    configuration = report.get("configuration", {})
    judge = report.get("judge", {})
    analyst = report.get("analyst", {})
    coverage = analyst.get("coverage", {})
    run = report.get("run_configuration", {})
    requested_review = run.get("optional_review", {})
    parts = ['<section id="method"><p class="eyebrow">Understand the evidence</p><h2>How the review layers work</h2>',
             '<ol class="review-flow"><li><span>01 / Deterministic</span><h3>Inspect selected artifacts</h3><p>Bounded parsers and static rules collect reproducible file, configuration and image observations. Scope limits and read or parse failures remain visible.</p></li>',
             '<li><span>02 / Optional model</span><h3>Review bounded evidence</h3><p>An explicitly enabled model can identify contextual concerns. Deterministic selection, budgets, schema checks and exact-quote checks constrain its input and output. Its judgment remains advisory.</p></li>',
             '<li><span>03 / Human and runtime</span><h3>Verify deployed controls</h3><p>Owners validate access boundaries, approvals, isolation and recovery in the deployed system. Record your evidence and unresolved work in this report.</p></li></ol>',
             '<div class="table-wrap"><table><thead><tr><th>Scenario a scan can miss</th><th>What each review layer can establish</th><th>What still needs evidence</th></tr></thead><tbody>']
    methodology = report.get("methodology")
    if not methodology:
        from .methodology import build_methodology
        methodology = build_methodology(report)
    for area in methodology.get("areas", []):
        parts.append('<tr><td><strong>' + _escape(area["area"]) + '</strong><br>' + _escape(area["can_miss_or_misclassify"])
                     + '</td><td><strong>Deterministic:</strong> ' + _escape(area["deterministic"])
                     + '<br><strong>Optional model:</strong> ' + _escape(area["optional_review"])
                     + '</td><td>' + _escape(area["runtime_or_human_validation"]) + '</td></tr>')
    parts += ['</tbody></table></div>', _details("Complete scan and review workflow", _list(methodology.get("workflow", []), ordered=True))]
    parts += ['<p class="note">Neither layer provides a numerical security score, complete attack coverage, or compliance certification. Human notes and proposed verification are not proof that a check passed.</p></section>',
              '<section id="configuration"><p class="eyebrow">Reproduce the selected run</p><h2>Scan configuration</h2>',
              '<div class="table-wrap"><table><thead><tr><th>Setting</th><th>Recorded value</th><th>Effect on this report</th></tr></thead><tbody>']
    rows = [
        ("Input mode", "built image" if report.get("image") else "source directory", "Only the selected artifact is inspected; no target application is executed."),
        ("Severity gate", report.get("execution", {}).get("failure_threshold", "not recorded by caller"), "Only open findings at this threshold or higher affect the finding gate; operational gaps remain separate."),
        ("Active static rules", assessment.get("metrics", {}).get("active_rules", len(report.get("coverage", {}).get("rules_enabled", []))), "Justified/disabled rule matches remain audit observations and receive no positive or negative count."),
        ("Maximum source file bytes", configuration.get("max_file_bytes", "not recorded"), "A larger selected file creates a visible coverage gap."),
        ("Total source read budget", configuration.get("max_total_bytes", "not recorded"), "The bounded read budget includes conservative charging for failed reads."),
        ("Maximum source files / traversal entries", str(configuration.get("max_files", "not recorded")) + " / " + str(configuration.get("max_entries", "not recorded")), "A reached limit leaves work incomplete, rather than silently treating omitted content as safe."),
        ("Finding judge", judge.get("status", "enabled" if judge.get("enabled") else "disabled"), "Only explicitly enabled review sends a bounded payload. The model cannot change recorded static severity."),
        ("Control analyst", analyst.get("status", "enabled" if analyst.get("enabled") else "disabled"), "Only active acceptance checks enter the optional queue."),
        ("Control requests used / allowed", str(coverage.get("calls_made", 0)) + " / " + str(coverage.get("call_budget", "not enabled")), "The finding-triage request is a separate request; budgets do not guarantee completed validation."),
    ]
    if requested_review:
        rows.extend([
            ("Configured optional review provider / mode", str(requested_review.get("provider", "not selected")) + " / " + str(requested_review.get("mode", "not selected")), "Configured request settings; the actual stage results above show whether the requested work completed."),
            ("Configured finding limit / extra source", str(requested_review.get("findings_limit", "not recorded")) + " / " + str(bool(requested_review.get("include_finding_source"))), "Controls finding-triage scope; full-mode source selection has separate evidence budgets."),
        ])
    for label, value, effect in rows:
        parts.append('<tr><td>' + _escape(label) + '</td><td>' + _escape(value) + '</td><td>' + _escape(effect) + '</td></tr>')
    parts += ['</tbody></table></div>',
              _details("Selected source configuration, exclusions and limits", _json(configuration)),
              _details("Optional review request and evidence coverage", _json({"judge": judge, "analyst_coverage": coverage})),
              _details("Configured run options (budgets are limits, not work completed)", _json(report.get("run_configuration", report.get("scan_configuration", {})))), '</section>']
    return '\n'.join(parts)


_REVIEW_DECISIONS = (("", "Unreviewed"), ("justified", "Justified by reviewer"), ("disabled", "Disabled by reviewer"),
                     ("note", "Review note"), ("needs_runtime_validation", "Needs runtime validation"),
                     ("needs_human_review", "Needs human review"))


def _editor(item):
    if not item:
        return ""
    identifier = _anchor("review", item["id"])
    allowed = [pair for pair in _REVIEW_DECISIONS if item.get("kind") != "gap" or pair[0] not in ("justified", "disabled")]
    parts = ['<details class="review-editor" id="' + identifier + '"><summary>Record your review <span class="pill">'
             + _escape(item.get("decision") or "unreviewed") + '</span></summary><div class="details-body">',
             '<fieldset data-review-id="' + _escape(item["id"]) + '"><legend>' + _escape(item.get("subject", item["id"])) + '</legend>',
             '<p class="small">' + ('A gap cannot be justified away or disabled. Record context and the validation still required.' if item.get("kind") == "gap"
                                    else 'Justified or disabled requires a reason and reviewer. Notes and runtime/human validation requests do not remove an open finding or establish a pass.') + '</p>',
             '<label for="' + identifier + '-decision">Review decision</label><select id="' + identifier + '-decision" data-field="decision">']
    for value, label in allowed:
        parts.append('<option value="' + value + '"' + (' selected' if item.get("decision", "") == value else '') + '>' + label + '</option>')
    parts += ['</select><label for="' + identifier + '-reason">Reason / evidence summary</label><textarea id="' + identifier
              + '-reason" data-field="reason" rows="3" maxlength="8000">' + _escape(item.get("reason", "")) + '</textarea><div class="review-fields">']
    for field, label, maximum, hint in (("reviewer", "Reviewer", 200, "Name or accountable team"),
                                        ("reviewed_at", "Review date (optional)", 64, "YYYY-MM-DD or ISO timestamp"),
                                        ("evidence_ref", "Evidence reference (optional)", 2000, "Ticket, document, or test-run reference; stored as plain text")):
        parts.append('<div><label for="' + identifier + '-' + field + '">' + label + '</label><input type="text" id="' + identifier
                     + '-' + field + '" data-field="' + field + '" maxlength="' + str(maximum) + '" value="' + _escape(item.get(field, ""))
                     + '" placeholder="' + hint + '"></div>')
    parts += ['</div><p class="small">Edits are pending review records. Use <strong>Download reviewed HTML</strong> to save them, then rerun the CLI with that file. This page’s scan totals remain the original snapshot.</p></fieldset></div></details>']
    return '\n'.join(parts)


def _review_area(report, workspace):
    if workspace is None:
        unavailable = report.get("review_workspace_unavailable", {})
        return ('<section id="review-workspace"><p class="eyebrow">Review export limit</p><h2>Review editing unavailable for this run</h2>'
                + '<p class="note warning">' + _escape(unavailable.get("reason", "The review workspace exceeded its supported limits."))
                + '</p><p>Static findings, controls, and scope evidence remain available in this report. No editable fields or importable review capsule were created. '
                + 'Adjust the selected scan scope or review text size and rerun, or use an explicit <code>--review-config</code> for scoped review decisions.</p>'
                + _details("Review workspace limits and export status", _json(unavailable)) + '</section>')
    items = workspace.get("items", [])
    parts = ['<section id="review-workspace"><p class="eyebrow">Your review record</p><h2>Review, save, and rescan</h2>',
             '<div class="panel"><p>Use <strong>Record your review</strong> beside a finding, acceptance check, or coverage gap. Keep the observed result and your rationale together. Justifications are user decisions, never automatic passes.</p>',
             '<ol class="review-steps"><li><a href="#findings">Review findings</a> and <a href="#controls">acceptance checks</a>; add an owner, reason and supporting reference.</li><li>Choose <strong>Download reviewed HTML</strong> below. Use this button instead of the browser’s Save As command so form edits and import metadata are preserved.</li><li>Scan the current source/image again using the saved file: <code>invarune ./repository --review-report ./invarune-reviewed.html --output ./new-report</code>.</li></ol>',
             '<p class="note warning">Rescanning checks the current evidence before reusing decisions. Changed or out-of-scope records remain visible for review; a missing detection is not proof of remediation. Runtime and human validation notes do not waive coverage gaps.</p>',
             '<div class="review-toolbar"><button type="button" id="download-reviewed-html">Download reviewed HTML</button><button type="button" id="download-review-json" class="secondary">Download review JSON</button><span id="review-progress" role="status" aria-live="polite">'
             + str(sum(bool(item.get("decision")) for item in items)) + ' of ' + str(len(items)) + ' items have a review decision.</span></div>',
             '<p id="review-save-status" class="small" role="status" aria-live="polite">Edits stay in this browser tab until you download a reviewed file. No network request is made.</p>',
             '<noscript><p class="note warning">The report remains readable without JavaScript. Local review editing and the download buttons require the bundled editor script. No external scripts are loaded.</p></noscript>',
             '</div>']
    imported = report.get("review_import", {})
    if imported.get("enabled"):
        parts += ['<div class="panel spacer"><h3>Imported review audit</h3><p><strong>Status:</strong> ' + _escape(imported.get("status", "unknown"))
                  + ' · Previous scan: <code>' + _escape(imported.get("origin_scan_id", "unknown")) + '</code></p>',
                  '<p class="small">Prior reasons are kept as review records. Only matching current evidence can receive an applied disposition. Fresh scan evidence and active findings remain in the main report.</p>']
        for key, label in (("applied", "Applied to matching evidence"), ("stale", "Stale: evidence or catalog changed"),
                           ("not_redetected", "Not redetected: remediation is not established"), ("out_of_scope", "Outside this scan’s scope"),
                           ("unresolved", "Unresolved review notes")):
            records = imported.get(key, [])
            body = '<p>No records in this category.</p>'
            if records:
                body = '<div class="table-wrap"><table><thead><tr><th>Item</th><th>Decision</th><th>Prior reason / current review status</th></tr></thead><tbody>'
                for item in records:
                    body += ('<tr><td>' + _escape(item.get("subject", item.get("id", ""))) + '</td><td>' + _pill(item.get("decision", "unreviewed"))
                             + '</td><td>' + _escape(item.get("reason", "")) + '<br>' + _escape(item.get("reason_for_status", "")) + '</td></tr>')
                body += '</tbody></table></div>'
            parts.append(_details(label + ' (' + str(len(records)) + ')', body, key in ("stale", "out_of_scope") and bool(records)))
        parts += [_details("Complete imported review provenance", _json(imported)), '</div>']
    parts.append('</section>')
    return '\n'.join(parts)


def _review_json(workspace):
    # A JSON data block still follows HTML raw-text parsing. Escaping '<' prevents
    # a repository/reviewer string from closing its script element.
    return json.dumps(workspace, sort_keys=True, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


# This immutable editor is the only executable script. CSP authorizes its exact
# bytes by SHA-256; repository/reviewer/model text never enters executable code.
_REVIEW_SCRIPT = r'''(() => {
  "use strict";
  const capsule = document.getElementById("invarune-review");
  const progress = document.getElementById("review-progress");
  const status = document.getElementById("review-save-status");
  const fields = ["decision", "reason", "reviewer", "reviewed_at", "evidence_ref"];
  const limits = {reason: 8000, reviewer: 200, reviewed_at: 64, evidence_ref: 2000};
  const allowed = ["", "justified", "disabled", "note", "needs_runtime_validation", "needs_human_review"];
  let workspace;
  try { workspace = JSON.parse(capsule.textContent); }
  catch (_) { status.textContent = "Review metadata is invalid. Generate a fresh report before editing."; return; }
  const byId = new Map(workspace.items.map(item => [item.id, item]));
  const editors = Array.from(document.querySelectorAll("fieldset[data-review-id]"));
  function dateValid(value) {
    if (!value) return true;
    if (!/^\d{4}-\d{2}-\d{2}(?:T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?)?$/.test(value)) return false;
    const day = new Date(value.slice(0, 10) + "T00:00:00Z");
    return !Number.isNaN(day.getTime()) && day.toISOString().slice(0, 10) === value.slice(0, 10) && !value.startsWith("0000-");
  }
  function readEditors(validate) {
    for (const editor of editors) {
      const item = byId.get(editor.dataset.reviewId);
      if (!item) throw new Error("An editor no longer matches the review metadata. Generate a fresh report.");
      for (const field of fields) {
        const input = editor.querySelector('[data-field="' + field + '"]');
        item[field] = input.value;
        input.setCustomValidity("");
      }
      let error = "";
      if (!allowed.includes(item.decision) || (item.kind === "gap" && ["justified", "disabled"].includes(item.decision))) error = "Choose an allowed review decision.";
      if (item.decision && !item.reason.trim()) error = "Add a reason for this review decision.";
      if (!item.decision && fields.slice(1).some(field => item[field].trim())) error = "Choose a decision for this text; use Review note for commentary.";
      if (["justified", "disabled"].includes(item.decision) && !item.reviewer.trim()) error = "Add a reviewer for a justified or disabled decision.";
      if (!dateValid(item.reviewed_at)) error = "Use a valid ISO date or timestamp for the review date.";
      for (const field of fields.slice(1)) {
        const value = item[field];
        if (Array.from(value).length > limits[field]) error = "A review field exceeds its documented character limit.";
        if (Array.from(value).some(character => { const code = character.codePointAt(0); return code >= 0xD800 && code <= 0xDFFF; })) error = "Review text contains invalid Unicode.";
        if ((field === "reason" ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/ : /[\u0000-\u001F\u007F-\u009F]/).test(value)) error = "Review fields contain an unsupported control character.";
      }
      if (validate && error) {
        editor.closest("details").open = true;
        let parent = editor.parentElement;
        while (parent) { if (parent.tagName === "DETAILS") parent.open = true; parent = parent.parentElement; }
        const input = editor.querySelector('[data-field="reason"]');
        input.setCustomValidity(error); input.reportValidity(); input.focus();
        throw new Error(error);
      }
    }
    progress.textContent = workspace.items.filter(item => item.decision).length + " of " + workspace.items.length + " items have a review decision.";
  }
  function safeJSON(value) {
    return JSON.stringify(value).replace(/[^\x00-\x7F]/g, character => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0")).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  }
  function download(kind) {
    try {
      readEditors(true);
      const encoded = safeJSON(workspace);
      if (encoded.length > 4000000) throw new Error("Review metadata exceeds the 4,000,000-byte import limit. Shorten review text before saving.");
      let content;
      if (kind === "html") {
        const clone = document.documentElement.cloneNode(true);
        clone.querySelector("#invarune-review").textContent = encoded;
        for (const editor of clone.querySelectorAll("fieldset[data-review-id]")) {
          const item = byId.get(editor.dataset.reviewId);
          for (const field of fields) {
            const input = editor.querySelector('[data-field="' + field + '"]');
            if (field === "decision") {
              for (const option of input.options) {
                if (option.value === item[field]) option.setAttribute("selected", "selected");
                else option.removeAttribute("selected");
              }
            } else if (field === "reason") input.textContent = item[field];
            else input.setAttribute("value", item[field]);
          }
          const badge = editor.closest("details").querySelector("summary .pill");
          if (badge) badge.textContent = item.decision || "unreviewed";
        }
        clone.querySelector("#review-save-status").textContent = "Saved review snapshot. Import this file with --review-report when rescanning the current artifact.";
        content = "<!doctype html>\n" + clone.outerHTML;
      } else content = encoded + "\n";
      const blob = new Blob([content], {type: kind === "html" ? "text/html;charset=utf-8" : "application/json;charset=utf-8"});
      if (blob.size > 50000000) throw new Error("Reviewed report exceeds the 50,000,000-byte import limit; download the review JSON instead.");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = kind === "html" ? "invarune-reviewed.html" : "invarune-review.json";
      document.body.appendChild(link); link.click(); link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      status.textContent = "Reviewed " + kind.toUpperCase() + " downloaded. Rescan with --review-report to apply eligible decisions; displayed scan totals remain unchanged.";
    } catch (error) { status.textContent = "Review not downloaded: " + error.message; }
  }
  document.getElementById("download-reviewed-html").addEventListener("click", () => download("html"));
  document.getElementById("download-review-json").addEventListener("click", () => download("json"));
  for (const editor of editors) {
    editor.addEventListener("input", () => { readEditors(false); status.textContent = "Unsaved review edits. Use Download reviewed HTML to preserve them."; });
    editor.addEventListener("change", () => { readEditors(false); });
  }
})();'''


def html_report(report):
    """Render a deterministic scan snapshot plus a local, explicitly saved editor."""
    workspace = report.get("review_workspace")
    if report.get("review_workspace_unavailable"):
        workspace = None
    elif workspace is None:
        from .review_workspace import build_workspace
        workspace = build_workspace(report)
    review_items = {item["id"]: item for item in workspace.get("items", [])} if workspace is not None else {}
    script_hash = base64.b64encode(hashlib.sha256(_REVIEW_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    script_source = "'sha256-" + script_hash + "'" if workspace is not None else "'none'"
    assessment = report.get("assessment")
    if not assessment:
        from .assessment import build_assessment
        assessment = build_assessment(report)
    metrics = assessment.get("metrics", {})
    summary = report.get("summary", {})
    tool = report.get("tool", {})
    posture = assessment.get("posture", {})
    posture_class = {"urgent_review": "urgent", "incomplete_scope": "attention",
                     "open_findings_review": "attention", "configured_exceptions": "attention", "review_followup_required": "attention"}.get(posture.get("code"), "neutral")
    findings = report.get("findings", [])
    controls = report.get("controls", [])
    known_findings = {item.get("id", item.get("finding_id", "")) for item in findings}
    known_controls = {item.get("id", "") for item in controls}
    groups = assessment.get("finding_groups", [])
    actions = assessment.get("immediate_actions", [])
    analyst = report.get("analyst", {})
    advisory_controls = {item.get("control_id"): item for item in analyst.get("control_assessments", [])} if analyst.get("enabled") else {}
    title = tool.get("display_name", DISPLAY_NAME) + " | Security report"
    target = report.get("image", {}).get("display_target", report.get("target", "."))
    scope_label = "Target: " + _text(target)
    if not report.get("image") and target == ".":
        scope_label = "Source scope: selected directory (relative paths)"
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src ' + script_source + '; script-src-attr \'none\'; connect-src \'none\'; style-src \'unsafe-inline\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">',
             '<meta name="referrer" content="no-referrer">', '<title>' + _escape(title) + '</title><style>' + _CSS + '</style></head><body>',
             '<header class="masthead" id="top"><div class="wrap"><div class="brandrow"><div class="brand">' + _MARK
             + '<div><div class="brand-name">Invarune</div><div class="brand-by">by NimeshBuild</div></div></div>',
             '<div class="edition">Evidence for agent security<br>Scanner ' + _escape(tool.get("version", "")) + '</div></div>',
             '<div class="hero"><h1>AI agent, MCP &amp; skill security report</h1>',
             '<p>Findings, priorities, and evidence needed to verify safeguards.</p>',
             '<div class="hero-meta"><span>' + _escape(scope_label) + '</span><span>Scan ID: <code>' + _escape(report.get("scan_id", "")) + '</code></span></div></div></div></header>',
             '<nav class="nav" aria-label="Report navigation"><div class="wrap"><a href="#summary">Executive summary</a><a href="#scoring">Metrics and calculation</a><a href="#actions">Priority actions</a><a href="#findings">Finding evidence</a><a href="#review-workspace">Review and save</a><a href="#method">Methods and blind spots</a><a href="#configuration">Scan configuration</a><a href="#coverage">Coverage</a>'
             + ('<a href="#review-policy">User decisions</a>' if report.get("review_policy", {}).get("enabled") else '')
             + ('<a href="#image">Image scope</a>' if report.get("image") else '') + '<a href="#advisory">Optional review</a><a href="#controls">All controls</a></div></nav>',
             '<main class="wrap"><section id="summary"><p class="eyebrow">Start here</p><h2>Executive summary</h2>',
             '<div class="posture ' + posture_class + '"><div><h2>' + _escape(posture.get("title", "Static security triage")) + '</h2><p>'
             + _escape(posture.get("explanation", "Review the findings and coverage boundaries below.")) + '</p></div></div>',
             '<div class="metrics">']
    for number, label in ((metrics.get("open_findings", summary.get("open_findings", 0)), "Open findings"),
                          (metrics.get("urgent_findings", 0), "Critical / high findings"),
                          (metrics.get("affected_files", 0), "Files with open findings"),
                          (metrics.get("coverage_gaps", summary.get("coverage_gaps", 0)), "Recorded coverage gaps")):
        parts.append('<div class="metric"><strong>' + _escape(number) + '</strong><span>' + label + '</span></div>')
    parts.append('</div>' + _status_strip(report) + '<div class="severity-row" aria-label="Open findings by severity">')
    for severity in _SEVERITIES:
        parts.append('<div class="severity-cell">' + _pill(severity, True) + '<strong>' + _escape(summary.get("severity_counts", {}).get(severity, 0)) + '</strong></div>')
    parts += ['</div><p class="small">Inspected <strong>' + _escape(metrics.get("files_scanned", summary.get("files_scanned", 0)))
              + ' files</strong>; <strong>' + _escape(metrics.get("suppressed_findings", summary.get("suppressed_findings", 0)))
              + ' suppressed findings</strong> are retained below. <strong>' + _escape(metrics.get("controls_requiring_validation", len(controls)))
              + ' active controls require validation</strong> out of ' + _escape(metrics.get("controls_total", len(controls))) + ' selected controls'
              + '; static pattern results do not establish control completion.</p>']
    if report.get("review_policy", {}).get("enabled"):
        parts.append('<p class="note warning"><strong>User review decisions:</strong> ' + _escape(metrics.get("active_rules", 0))
                     + ' active rules; ' + _escape(metrics.get("active_checks", 0)) + ' active acceptance checks.<br>Separately recorded: '
                     + _escape(metrics.get("justified_rules", 0)) + ' justified / ' + _escape(metrics.get("disabled_rules", 0)) + ' disabled rules; '
                     + _escape(metrics.get("justified_checks", 0)) + ' justified / ' + _escape(metrics.get("disabled_checks", 0)) + ' disabled checks; '
                     + _escape(metrics.get("justified_findings", 0)) + ' justified / ' + _escape(metrics.get("disabled_findings", 0)) + ' disabled observed findings.'
                     + '<br>These items are excluded from active totals without positive or negative credit. They are user decisions, not validated passes. <a href="#review-policy">Read every reason and scope decision</a>.</p>')
    if report.get("image"):
        container = report["image"]
        packaged_count = container.get("packaged_source_files_inspected", 0)
        image_note = ('<strong>Image analysis scope:</strong> ' + _escape(container.get("analysis_scope", "unknown"))
                      + ' · <strong>Packaged source files inspected:</strong> ' + _escape(packaged_count)
                      + '. The container was not started; native binary logic was not analyzed, and package inventory is not a CVE scan.')
        if not packaged_count:
            image_note += ' <strong>No packaged source was inspected. Agent and MCP implementation behavior remains unknown.</strong>'
        parts.append('<p class="note warning">' + image_note + '</p>')
    execution = report.get("execution", {})
    if execution:
        parts.append('<p class="small"><strong>Configured severity gate:</strong> ' + _escape(execution.get("failure_threshold", "unknown"))
                     + ' · <strong>Process exit code:</strong> ' + _escape(execution.get("exit_code", "unknown")) + '. The exit code follows configured scan policy; it is not a security rating.</p>')
    parts.append('<p class="note">This is static security triage, not certification or proof that a system is secure. Finding severity describes a detected risk pattern; reachability, exploitability, exposure, and deployed safeguards still require verification.</p>')
    for error in report.get("export_errors", []):
        parts.append('<p class="note warning"><strong>Report export incomplete:</strong> ' + _escape(error.get("format", "requested format"))
                     + ' — ' + _escape(error.get("error", "Export failed")) + '. Existing scan evidence is retained; the requested export must be resolved.</p>')
    if report.get("review_workspace_unavailable"):
        parts.append('<p class="note warning"><strong>Review editing unavailable:</strong> '
                     + _escape(report["review_workspace_unavailable"].get("reason", "Review export limit reached."))
                     + ' Static scan evidence is retained. <a href="#review-workspace">See the export limit and next steps</a>.</p>')
    parts.append(_advisory_summary(report))
    if report.get("advice_coverage"):
        advice = report["advice_coverage"]
        parts.append('<p class="note"><strong>Actionable fix guidance:</strong> ' + str(advice["static_fix_plans"]) + '/' + str(advice["static_findings"])
                     + ' observed findings have a deterministic fix plan, verification steps and agent/MCP context. Proposed changes still require validation.</p>')
    parts.append(_visual_summary(report, assessment))
    if assessment.get("themes"):
        parts.append('<h3 class="spacer">What the scanner found</h3><p class="small">Detected categories describe observed patterns, not confirmed attack paths.</p><div class="badge-line">')
        for theme in assessment["themes"]:
            parts.append('<span class="pill">' + _escape(theme.get("name", theme.get("category", "Other")))
                         + ': ' + _escape(theme.get("open_findings", 0)) + '</span>')
        parts.append('</div>')
    if actions:
        parts.append('<h3 class="spacer">Immediate concerns</h3><p class="small">' + _escape(assessment.get("priority_basis", "Prioritized from deterministic finding severity and status.")) + '</p>')
        parts.append(_priority_preview(actions, known_findings))
        parts.append('<p class="small">Showing ' + _escape(min(5, len(actions))) + ' of ' + _escape(len(actions))
                     + ' open finding groups. <a href="#actions">Review every priority action and mitigation layer</a>.</p>')
    else:
        parts.append('<div class="empty"><strong>No open finding groups.</strong> Review any baseline or user-configured exceptions and complete the active coverage and control validation work below. An empty finding list does not demonstrate that a deployment is secure.</div>')
    parts += ['</section>', _scoring(report), _review_area(report, workspace), '<section id="actions"><div class="section-heading"><div><p class="eyebrow">Action plan</p><h2>Priority actions and defense layers</h2></div><a class="back" href="#top">Back to top</a></div>',
              '<p>Each group connects observed evidence to a practical first action, an accountable team, and additional safeguards. These layers are <strong>proposed, not verified</strong>; they do not automatically reduce finding severity or remove the need to fix the underlying condition.</p>']
    if groups:
        parts.extend(_action(group, known_findings, known_controls) for group in groups)
    else:
        parts.append('<p class="empty">No finding groups were generated. Use the complete control checklist to plan runtime, deployment, and manual validation.</p>')
    parts += ['</section><section id="findings"><div class="section-heading"><div><p class="eyebrow">Scanner observations</p><h2>Complete finding evidence</h2></div><a class="back" href="#top">Back to top</a></div>',
              '<p class="small">All ' + _escape(len(findings)) + ' findings are retained with locations, stable IDs, confidence, remediation, and references. Suppressed, justified, and disabled findings remain visible as distinct exceptions.</p>']
    if findings:
        advice = {item.get("finding_id"): item for item in report.get("judge", {}).get("assessments", [])}
        parts.extend(_finding(finding, review_items.get("finding:" + finding.get("id", finding.get("finding_id", ""))),
                              report.get("remediation", {}).get(finding.get("id")), advice.get(finding.get("id"))) for finding in findings)
    else:
        parts.append('<p class="empty">No configured risk patterns were detected in the selected files.</p>')
    parts += ['</section>', _review_policy(report), _method_and_configuration(report, assessment), _coverage(report, assessment, review_items)]
    if report.get("image"):
        parts.append(_image(report["image"]))
    parts += [_advisory(report), '<section id="controls"><div class="section-heading"><div><p class="eyebrow">Complete control checklist</p><h2>Controls and acceptance checks</h2></div><a class="back" href="#top">Back to top</a></div>',
              '<p>All ' + _escape(len(controls)) + ' selected controls appear below. Expand a control for acceptance checks, source guidance, mapped findings, and any optional analyst review.</p>',
              '<p class="note">These are project-defined checks mapped to published guidance, not official benchmark scores. <code>no_pattern_detected</code> means only that the mapped detector did not fire. <code>findings_detected</code> requires investigation; it is not an automatic compliance failure.</p>']
    parts.extend(_control(control, advisory_controls.get(control.get("id")), known_findings, review_items) for control in controls)
    parts += ['</section><section id="provenance"><h2>Report provenance</h2><div class="panel"><p class="small">The executive assessment is derived deterministically from scan findings, scope, and the versioned mitigation guidance catalog. Optional model advice is shown separately.</p>',
              _details("Assessment method and guidance provenance", _json({"schema_version": assessment.get("schema_version"), "method": assessment.get("method"), "guidance": assessment.get("guidance", {}), "priority_basis": assessment.get("priority_basis")})),
              _details("Scanner identity and implementation digest", _json({"tool": tool, "scan_id": report.get("scan_id"), "schema_version": report.get("schema_version"), "mode": report.get("mode")})),
              '<p class="small spacer">This standalone report loads no external resources. '
              + ('Its fixed local editor only records and downloads review decisions; it never executes evidence or contacts a service. ' if workspace is not None else 'Review editing is unavailable; this artifact contains no scripts or importable review capsule. ')
              + 'Evidence and advice are rendered as text. Redaction is best-effort; treat the report as potentially sensitive.</p></div></section></main>',
              '<footer class="footer"><div class="wrap"><p><strong>Invarune by NimeshBuild</strong> / Evidence for agent security.</p><p>Preserve the scan ID and evidence when assigning remediation. Verify controls in the deployed system before accepting residual risk.</p></div></footer>',
              ('<script type="application/json" id="invarune-review">' + _review_json(workspace) + '</script>' if workspace is not None else ''),
              ('<script id="invarune-review-editor">' + _REVIEW_SCRIPT + '</script>' if workspace is not None else ''), '</body></html>']
    return "\n".join(parts) + "\n"
