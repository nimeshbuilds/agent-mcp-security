"""Self-contained, script-free HTML security reports with escaped evidence.

Report content, including model advice and repository filenames, is untrusted.
The renderer uses fixed markup, hashed anchors, and allowlisted HTTPS links.
"""
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
    return '<span class="' + css + '">' + _escape(value) + "</span>"


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
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:#12674f;text-underline-offset:3px;overflow-wrap:anywhere}a:hover{color:#064331}a:focus-visible,summary:focus-visible{outline:3px solid #178268;outline-offset:4px}h1,h2,h3,h4,p{margin-top:0}h1{font-size:clamp(1.65rem,3vw,2rem);line-height:1.2;letter-spacing:-.035em;margin-bottom:10px}h2{font-size:1.8rem;line-height:1.25;letter-spacing:-.025em;margin-bottom:12px}h3{font-size:1.14rem;line-height:1.4;margin-bottom:12px}h4{font-size:1rem;margin-bottom:6px}p{margin-bottom:14px}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}code{font-size:.85em;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#eef2f6;border:1px solid var(--line);padding:18px;border-radius:10px;line-height:1.5;font-size:.82rem;margin:12px 0 20px}pre code{font-size:inherit}ul,ol{padding-left:24px}li+li{margin-top:7px}strong{font-weight:650}.wrap{max-width:1220px;margin:auto;padding:0 40px}.masthead{background:var(--navy);color:#f2f6fa}.brandrow{display:flex;justify-content:space-between;align-items:center;gap:24px;padding-top:16px;padding-bottom:16px;border-bottom:1px solid #2b3648}.brand{display:flex;align-items:center;gap:13px}.brand svg{width:40px;height:40px;flex:none}.brand-name{font-size:1.45rem;font-weight:750;letter-spacing:-.035em;line-height:1.15}.brand-by{font-size:.71rem;letter-spacing:.11em;text-transform:uppercase;color:#adbbc9;margin-top:4px}.edition{color:#adbbc9;font-size:.8rem;text-align:right}.hero{padding-top:23px;padding-bottom:23px}.eyebrow{font-size:.72rem;font-weight:750;text-transform:uppercase;letter-spacing:.16em;color:#238266;margin-bottom:13px}.hero .eyebrow{color:var(--mint)}.hero p{max-width:800px;color:#c3cfdd;font-size:.9rem;margin-bottom:0}.hero-meta{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px;font-size:.72rem;color:#bcc9d8}.hero-meta code{font-size:inherit}.hero-meta span{padding:7px 12px;border:1px solid #334055;border-radius:7px;overflow-wrap:anywhere;min-width:0;max-width:100%}.nav{background:#fff;border-bottom:1px solid var(--line)}.nav .wrap{display:flex;flex-wrap:wrap;gap:8px 25px;padding-top:17px;padding-bottom:17px}.nav a{color:#40516b;text-decoration:none;font-size:.84rem;font-weight:600}.nav a:hover{text-decoration:underline}main{padding-top:32px;padding-bottom:64px}section{scroll-margin-top:24px;margin-bottom:44px}.panel{background:var(--white);border:1px solid var(--line);border-radius:16px;padding:28px}.posture{display:grid;grid-template-columns:8px 1fr;gap:24px;padding:28px;background:#fff;border:1px solid var(--line);border-radius:16px;margin-bottom:20px}.posture:before{content:"";background:#1c8065;border-radius:6px}.posture h2{font-size:1.45rem}.posture p:last-child{margin-bottom:0}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px;margin:20px 0}.metric{padding:20px 22px;background:#fff;border:1px solid var(--line);border-radius:13px}.metric strong{display:block;font-size:2rem;line-height:1.1;letter-spacing:-.04em;margin-bottom:7px}.metric span{font-size:.8rem;color:var(--muted)}.severity-row{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);border-radius:13px;overflow:hidden;background:#fff;margin:20px 0}.severity-cell{padding:15px 20px;border-right:1px solid var(--line);display:flex;justify-content:space-between;gap:10px;align-items:center}.severity-cell:last-child{border:0}.severity-cell strong{font-size:1.2rem}.pill{display:inline-block;border:1px solid #ccd7e4;background:#f1f5f9;color:#3b4e66;border-radius:5px;padding:2px 8px;font-size:.69rem;font-weight:700;letter-spacing:.02em;line-height:1.6;overflow-wrap:anywhere;max-width:100%}.pill.critical{background:#fde9ec;border-color:#f2b1bd;color:#961331}.pill.high{background:#fff0e6;border-color:#f4c8a7;color:#913f0d}.pill.medium{background:#fff9dc;border-color:#e4d280;color:#745707}.pill.low{background:#e8f1ff;border-color:#bdd3f3;color:#285286}.pill.info{background:#edf3f5;border-color:#c6d7dc;color:#375866}.muted,.small{color:var(--muted)}.small{font-size:.84rem}.note{border-left:3px solid #65aa98;padding:12px 18px;background:#edf7f3;border-radius:0 8px 8px 0;font-size:.88rem}.note.warning{border-color:#c9a351;background:#fff9e8}.section-heading{display:flex;justify-content:space-between;gap:20px;align-items:baseline;margin-bottom:18px}.section-heading p{margin-bottom:0}.action-preview{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:22px 0}.preview{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px}.preview h3{font-size:1rem;margin-top:10px}.preview p:last-child{margin-bottom:0}.badge-line{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px}.priority{background:#0f2d29;color:#dcfff2;border-color:#0f2d29}.action-card,.finding{background:#fff;border:1px solid var(--line);border-radius:14px;padding:25px;margin-bottom:17px;scroll-margin-top:24px}.action-card h3{font-size:1.25rem}.rule-label{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.76rem;color:var(--muted)}.action-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}.action-grid>div{background:#f6f8fb;padding:18px;border-radius:10px}.action-grid p{margin-bottom:0;font-size:.9rem}.locations{margin-top:15px}.sources{font-size:.79rem;color:var(--muted);margin-top:17px}.sources ul{margin-top:7px}.sources li+li{margin-top:4px}.layer{border-left:3px solid #35aa88;padding:0 0 0 17px;margin:23px 0}.layer h4{font-size:1rem}.layer p{font-size:.87rem;margin-bottom:9px}.layer .residual{color:#6d541b;background:#fff9e9;padding:10px 13px;border-radius:6px}.layer:first-child{margin-top:4px}.layer:last-child{margin-bottom:4px}details{border:1px solid var(--line);border-radius:10px;background:#fff;margin-top:15px}summary{padding:16px 18px;cursor:pointer;font-weight:650;line-height:1.45;overflow-wrap:anywhere}summary:hover{background:#f5f8fa;border-radius:10px}details[open]>summary{border-bottom:1px solid var(--line);border-radius:10px 10px 0 0}.details-body{padding:20px}.details-body>:last-child{margin-bottom:0}.control{margin-top:12px;scroll-margin-top:24px}.control>summary{display:flex;justify-content:space-between;gap:15px;align-items:center}.control-title{max-width:75%}.control-code{display:block;font-size:.72rem;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em}.control>summary:before{content:"+";font-size:1.3rem;color:#397763;margin-right:3px}.control[open]>summary:before{content:"−"}.control>summary .control-title{flex:1}.checklist{list-style:none;padding:0;counter-reset:checks}.checklist li{position:relative;padding:10px 12px 10px 40px;background:#f4f7fa;border-radius:7px;counter-increment:checks;font-size:.88rem}.checklist li:before{content:counter(checks);position:absolute;left:13px;color:#397763;font-weight:700}.analyst-panel{border:1px solid #c7cce9;background:#f7f6fe;border-radius:11px;padding:20px;margin-top:18px}.analyst-panel h4{color:#4e4481}.analyst-check{border-top:1px solid #dcdcf0;padding-top:16px;margin-top:16px}.analyst-check p{font-size:.88rem}.evidence-location{display:block;color:#516279;font-size:.8rem;overflow-wrap:anywhere;margin-bottom:12px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;margin:16px 0}table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{background:#f1f5f9;color:#485b73;font-weight:650}tr:last-child td{border-bottom:0}.empty{padding:26px;background:#fff;border:1px dashed #a4bfb5;border-radius:12px;color:#3d6657}.coverage-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.coverage-grid>div{min-width:0}.audit{font-size:.75rem;max-height:36rem;overflow:auto}.footer{background:#0b1220;color:#aab9ca;padding:28px 0;font-size:.78rem}.footer p:last-child{margin-bottom:0}.footer strong{color:#f2f6fa}.unlinked{overflow-wrap:anywhere}.inline-code{padding:2px 5px;border:1px solid var(--line);border-radius:4px;background:#f1f5f9}.back{font-size:.78rem;float:right}.verification{padding-left:21px;font-size:.88rem}.check-note{font-size:.8rem;color:#695687}.spacer{margin-top:22px}
.posture.urgent:before{background:#c34b42}.posture.attention:before{background:#b18832}.posture.neutral:before{background:#597693}
@media(max-width:850px){.wrap{padding-left:22px;padding-right:22px}.severity-cell{padding:13px 12px;display:block}.severity-cell strong{display:block;margin-top:7px}.coverage-grid{grid-template-columns:1fr}.hero{padding-top:22px;padding-bottom:22px}.hero-meta{display:block}.hero-meta span{display:block;margin-top:8px}.action-grid{grid-template-columns:1fr}.section-heading{display:block}}
@media(max-width:560px){.wrap{padding-left:16px;padding-right:16px}.edition{max-width:120px}.metrics,.action-preview{grid-template-columns:1fr 1fr;gap:9px}.metric{padding:17px 14px}.metric strong{font-size:1.65rem}.severity-row{grid-template-columns:repeat(3,minmax(0,1fr))}.severity-cell{border-bottom:1px solid var(--line)}.action-preview{grid-template-columns:1fr}.panel,.action-card,.finding{padding:20px}.posture{padding:22px;gap:15px}.control>summary{flex-wrap:wrap}.control-title{max-width:85%}.details-body{padding:16px}.nav .wrap{gap:9px 18px}.brand-name{font-size:1.4rem}.brand svg{width:39px;height:39px}.back{float:none;display:block;margin-bottom:10px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:#fff;font-size:10pt}.wrap{max-width:none;padding:0}.masthead{background:#fff;color:#142338;border-bottom:2px solid #1c8065}.brand-name{color:#142338}.brand-by,.edition,.hero p,.hero-meta{color:#516279}.brand svg{background:#0b1220;border-radius:7px}.brandrow{padding:0 0 14px;border:0}.hero{padding:18px 0}.hero .eyebrow{color:#12674f}h1{font-size:27pt}h2{font-size:19pt}.hero-meta span{border-color:#b8c6d6}.nav,.back{display:none}main{padding:20px 0}.panel,.posture,.action-card,.finding,.metric,details,.preview{box-shadow:none;border-color:#c2cbd4;border-radius:5px}.metrics{grid-template-columns:repeat(4,1fr)}.action-preview{grid-template-columns:1fr 1fr}.action-grid{grid-template-columns:1fr 1fr}.metric strong{font-size:22pt}.severity-row{grid-template-columns:repeat(5,1fr)}.severity-cell{display:flex}.action-card,.finding,.control{break-inside:auto}h2,h3,h4,summary{break-after:avoid}pre,.layer{break-inside:auto}.audit{max-height:none;overflow:visible}details>summary{list-style:none}details>.details-body{display:block!important}details::details-content{display:block!important;content-visibility:visible!important}details{content-visibility:visible}a{color:#12674f;text-decoration:underline}.footer{background:#fff;color:#516279;border-top:1px solid #c2cbd4}.footer strong{color:#142338}section{margin-bottom:28px}.hero-meta{display:block}.hero-meta span{display:block;margin-top:5px}.coverage-grid{grid-template-columns:1fr}.table-wrap{overflow:visible}thead{display:table-header-group}.checklist li,.note,.action-grid>div{background:#f6f8fa}@page{margin:16mm 14mm}}
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


def _finding(finding):
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
    if finding.get("suppression_reason"):
        parts.append('<p class="note warning"><strong>Suppression reason:</strong> ' + _escape(finding["suppression_reason"]) + ' A baseline records an accepted exception; it does not remediate this finding.</p>')
    if finding.get("image_context"):
        parts.append('<p><strong>Image evidence context:</strong> ' + _escape(finding["image_context"]) + '</p>')
    if finding.get("image_provenance"):
        parts.append(_details("Image evidence provenance", _json(finding["image_provenance"])))
    if finding.get("cwe"):
        parts.append('<p class="small"><strong>Weakness mappings:</strong> ' + _escape(", ".join(finding["cwe"])) + '</p>')
    parts.append(_sources(finding.get("references", []), "Finding references"))
    parts.append('</article>')
    return "\n".join(parts)


def _advisory_check(check):
    parts = ['<div class="analyst-check"><h4>Check ' + _escape(check.get("check_index", "?")) + ": "
             + _escape(check.get("status", "insufficient_evidence")) + '</h4>',
             '<p>' + _escape(check.get("reason", "No assessment reason was provided.")) + '</p>']
    if not check.get("model_supplied", False):
        parts.append('<p class="check-note">No model assessment was received for this check.</p>')
    for citation in check.get("citations", []):
        parts += ['<p class="small"><strong>Evidence ' + _escape(citation.get("evidence_id", "")) + ':</strong> '
                  + _escape(citation.get("path", "")) + ":" + _escape(citation.get("start_line", "?")) + "–" + _escape(citation.get("end_line", "?"))
                  + ' · exact quote verified in submitted excerpt</p>', '<pre><code>' + _escape(citation.get("quote", "")) + '</code></pre>']
    if check.get("verification_steps"):
        parts += ['<p><strong>Verification still required</strong></p>', _list(check["verification_steps"], "verification")]
    parts.append('</div>')
    return "\n".join(parts)


def _control(control, advisory, finding_ids):
    identifier = control.get("id", "")
    parts = ['<details class="control" id="' + _anchor("control", identifier) + '"><summary><span class="control-title"><span class="control-code">'
             + _escape(identifier) + '</span>' + _escape(control.get("title", "Control")) + '</span>' + _pill(control.get("status", "review_required"))
             + '</summary><div class="details-body">',
             '<p class="small"><strong>Category:</strong> ' + _escape(control.get("category", "")) + ' · <strong>Validation:</strong> '
             + _escape(control.get("validation", "")) + '</p>',
             '<p class="note">' + _escape(control.get("assurance", "Not established by this static scan")) + '</p>',
             '<h4>Acceptance checks</h4>', _list(control.get("checks", []), "checklist", True)]
    if control.get("automated_rule_ids"):
        parts.append('<p class="small spacer"><strong>Partial static rules:</strong> ' + _escape(", ".join(control["automated_rule_ids"])) + '</p>')
    parts.append(_finding_links(control.get("finding_ids", []), finding_ids, "Open finding IDs"))
    parts.append(_finding_links(control.get("suppressed_finding_ids", []), finding_ids, "Suppressed finding IDs"))
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


def _coverage(report, assessment):
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
    if judge.get("enabled"):
        parts += ['<h3>Finding judge</h3><p class="small">Status and request metadata below are advisory. Source strings and returned advice are rendered as text.</p>', _details("Finding judge result and request audit", _json(judge))]
    elif analyst.get("enabled"):
        parts.append('<p class="small"><strong>Finding judge:</strong> disabled.</p>')
    if analyst.get("enabled"):
        coverage = analyst.get("coverage", {})
        parts += ['<div class="analyst-panel"><h3>Control analyst</h3><p><strong>Review status:</strong> ' + _escape(analyst.get("status", "unknown"))
                  + ' · <strong>Controls reviewed:</strong> ' + _escape(coverage.get("reviewed_controls", 0)) + '/' + _escape(coverage.get("total_controls", 0))
                  + '<br><strong>Unanswered checks:</strong> ' + _escape(coverage.get("omitted_checks", 0))
                  + ' · <strong>Control requests:</strong> ' + _escape(coverage.get("calls_made", 0)) + '/' + _escape(coverage.get("call_budget", 0)) + '</p>',
                  '<p class="small">Every catalog control is routed for review because static patterns cannot establish completion. Review completion means an answer was received for every check; it does not mean the checks passed. Model tools and runtime execution are disabled.</p>',
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
    parts.append('</div></section>')
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


def html_report(report):
    """Render the complete report as deterministic, portable HTML without scripts."""
    assessment = report.get("assessment")
    if not assessment:
        from .assessment import build_assessment
        assessment = build_assessment(report)
    metrics = assessment.get("metrics", {})
    summary = report.get("summary", {})
    tool = report.get("tool", {})
    posture = assessment.get("posture", {})
    posture_class = {"urgent_review": "urgent", "incomplete_scope": "attention",
                     "open_findings_review": "attention"}.get(posture.get("code"), "neutral")
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
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'none\'; style-src \'unsafe-inline\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">',
             '<meta name="referrer" content="no-referrer">', '<title>' + _escape(title) + '</title><style>' + _CSS + '</style></head><body>',
             '<header class="masthead" id="top"><div class="wrap"><div class="brandrow"><div class="brand">' + _MARK
             + '<div><div class="brand-name">Invarune</div><div class="brand-by">by NimeshBuild</div></div></div>',
             '<div class="edition">Evidence for agent security<br>Scanner ' + _escape(tool.get("version", "")) + '</div></div>',
             '<div class="hero"><h1>AI agent &amp; MCP security report</h1>',
             '<p>Findings, priorities, and evidence needed to verify safeguards.</p>',
             '<div class="hero-meta"><span>' + _escape(scope_label) + '</span><span>Scan ID: <code>' + _escape(report.get("scan_id", "")) + '</code></span></div></div></div></header>',
             '<nav class="nav" aria-label="Report navigation"><div class="wrap"><a href="#summary">Executive summary</a><a href="#actions">Priority actions</a><a href="#findings">Finding evidence</a><a href="#coverage">Coverage</a>'
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
    parts.append('</div><div class="severity-row" aria-label="Open findings by severity">')
    for severity in _SEVERITIES:
        parts.append('<div class="severity-cell">' + _pill(severity, True) + '<strong>' + _escape(summary.get("severity_counts", {}).get(severity, 0)) + '</strong></div>')
    parts += ['</div><p class="small">Inspected <strong>' + _escape(metrics.get("files_scanned", summary.get("files_scanned", 0)))
              + ' files</strong>; <strong>' + _escape(metrics.get("suppressed_findings", summary.get("suppressed_findings", 0)))
              + ' suppressed findings</strong> are retained below. <strong>' + _escape(metrics.get("controls_requiring_validation", len(controls)))
              + '/' + _escape(metrics.get("controls_total", len(controls))) + ' controls require validation</strong>; static pattern results do not establish control completion.</p>']
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
    parts.append(_advisory_summary(report))
    if assessment.get("themes"):
        parts.append('<h3 class="spacer">What the scanner found</h3><p class="small">Detected categories describe observed patterns, not confirmed attack paths.</p><div class="badge-line">')
        for theme in assessment["themes"]:
            parts.append('<span class="pill">' + _escape(theme.get("name", theme.get("category", "Other")))
                         + ': ' + _escape(theme.get("open_findings", 0)) + '</span>')
        parts.append('</div>')
    if actions:
        parts.append('<h3 class="spacer">Immediate concerns</h3><p class="small">' + _escape(assessment.get("priority_basis", "Prioritized from deterministic finding severity and status.")) + '</p><div class="action-preview">')
        for group in actions[:5]:
            parts.append('<article class="preview"><div class="badge-line"><span class="pill priority">' + _escape(group.get("priority", "Review")) + '</span>'
                         + _pill(group.get("severity", "info"), True) + '</div><h3><a href="#' + _anchor("group", group.get("id", "")) + '">'
                         + _escape(group.get("title", "Finding group")) + '</a></h3><p class="small">' + _escape(group.get("immediate_action", "Review the linked evidence.")) + '</p></article>')
        parts.append('</div><p class="small">Showing ' + _escape(min(5, len(actions))) + ' of ' + _escape(len(actions))
                     + ' open finding groups. <a href="#actions">Review every priority action and mitigation layer</a>.</p>')
    else:
        parts.append('<div class="empty"><strong>No open finding groups.</strong> Review any accepted baseline findings and complete the coverage and control validation work below. An empty finding list does not demonstrate that a deployment is secure.</div>')
    parts += ['</section><section id="actions"><div class="section-heading"><div><p class="eyebrow">Action plan</p><h2>Priority actions and defense layers</h2></div><a class="back" href="#top">Back to top</a></div>',
              '<p>Each group connects observed evidence to a practical first action, an accountable team, and additional safeguards. These layers are <strong>proposed, not verified</strong>; they do not automatically reduce finding severity or remove the need to fix the underlying condition.</p>']
    if groups:
        parts.extend(_action(group, known_findings, known_controls) for group in groups)
    else:
        parts.append('<p class="empty">No finding groups were generated. Use the complete control checklist to plan runtime, deployment, and manual validation.</p>')
    parts += ['</section><section id="findings"><div class="section-heading"><div><p class="eyebrow">Scanner observations</p><h2>Complete finding evidence</h2></div><a class="back" href="#top">Back to top</a></div>',
              '<p class="small">All ' + _escape(len(findings)) + ' findings are retained with locations, stable IDs, confidence, remediation, and references. Suppressed findings remain visible as accepted exceptions.</p>']
    if findings:
        parts.extend(_finding(finding) for finding in findings)
    else:
        parts.append('<p class="empty">No configured risk patterns were detected in the selected files.</p>')
    parts += ['</section>', _coverage(report, assessment)]
    if report.get("image"):
        parts.append(_image(report["image"]))
    parts += [_advisory(report), '<section id="controls"><div class="section-heading"><div><p class="eyebrow">Complete control checklist</p><h2>Controls and acceptance checks</h2></div><a class="back" href="#top">Back to top</a></div>',
              '<p>All ' + _escape(len(controls)) + ' catalog controls appear below. Expand a control for acceptance checks, source guidance, mapped findings, and any optional analyst review.</p>',
              '<p class="note">These are project-defined checks mapped to published guidance, not official benchmark scores. <code>no_pattern_detected</code> means only that the mapped detector did not fire. <code>findings_detected</code> requires investigation; it is not an automatic compliance failure.</p>']
    parts.extend(_control(control, advisory_controls.get(control.get("id")), known_findings) for control in controls)
    parts += ['</section><section id="provenance"><h2>Report provenance</h2><div class="panel"><p class="small">The executive assessment is derived deterministically from scan findings, scope, and the versioned mitigation guidance catalog. Optional model advice is shown separately.</p>',
              _details("Assessment method and guidance provenance", _json({"schema_version": assessment.get("schema_version"), "method": assessment.get("method"), "guidance": assessment.get("guidance", {}), "priority_basis": assessment.get("priority_basis")})),
              _details("Scanner identity and implementation digest", _json({"tool": tool, "scan_id": report.get("scan_id"), "schema_version": report.get("schema_version"), "mode": report.get("mode")})),
              '<p class="small spacer">This standalone report loads no external resources and runs no scripts. Evidence and advice are rendered as text. Redaction is best-effort; treat the report as potentially sensitive.</p></div></section></main>',
              '<footer class="footer"><div class="wrap"><p><strong>Invarune by NimeshBuild</strong> / Evidence for agent security.</p><p>Preserve the scan ID and evidence when assigning remediation. Verify controls in the deployed system before accepting residual risk.</p></div></footer></body></html>']
    return "\n".join(parts) + "\n"
