"""Optional, bounded PDF review documents. No PDF library is imported by default.

The embedded review workspace binds form edits to their original evidence. PDF
appearance and canonical values must agree; ambiguous or damaged forms are not
silently repaired. The caller validates evidence bindings and review policy.
"""
import copy
import hashlib
import html
import io
import json
import math
import os
from pathlib import Path
import re
import tempfile
import zlib
from urllib.parse import urlsplit

CAPSULE_NAME = "invarune-review.json"
MAX_PDF_BYTES = 50_000_000
MAX_CAPSULE_BYTES = 4_000_000
MAX_ITEMS = 2000
FIELDS = ("decision", "reason", "reviewer", "reviewed_at", "evidence_ref")
LIMITS = {"decision": 40, "reason": 8000, "reviewer": 200, "reviewed_at": 64, "evidence_ref": 2000}
DECISIONS = ("", "justified", "disabled", "note", "needs_runtime_validation", "needs_human_review")


def _choices(item):
    return [value or "Unreviewed" for value in DECISIONS
            if item.get("kind") != "gap" or value not in {"justified", "disabled"}]


def _rectangle(value):
    try:
        values = [float(number) for number in value]
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid PDF review widget geometry") from exc
    if len(values) != 4 or not all(math.isfinite(number) for number in values) or values[2] - values[0] < 1 or values[3] - values[1] < 1:
        raise ValueError("Invisible or invalid PDF review widget geometry")
    return values


def _matrix(value):
    try:
        numbers = [float(number) for number in value]
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid PDF appearance transform") from exc
    if len(numbers) != 6 or not all(math.isfinite(number) for number in numbers) or abs(numbers[0] * numbers[3] - numbers[1] * numbers[2]) < .01:
        raise ValueError("Invisible or unsupported PDF appearance transform")


def _dependencies():
    try:
        import pypdf
        import reportlab
    except ImportError as exc:
        raise ValueError("PDF support requires the optional packages: from the repository checkout run pip install '.[pdf]'") from exc
    return pypdf, reportlab


def _json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate key in PDF review capsule")
            value[key] = item
        return value

    def invalid(_):
        raise ValueError("Nonstandard JSON in PDF review capsule")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("PDF review capsule must be bounded UTF-8 JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("items"), list) or len(value["items"]) > MAX_ITEMS:
        raise ValueError("PDF review capsule has an invalid or oversized item list")
    for item in value["items"]:
        if not isinstance(item, dict):
            raise ValueError("PDF review capsule item must be an object")
    return value


def _obj(value):
    return value.get_object() if hasattr(value, "get_object") else value


def _identity(value):
    ref = value if hasattr(value, "idnum") else getattr(value, "indirect_reference", None)
    return (ref.idnum, ref.generation) if ref is not None else ("direct", id(value))


def _stream_bytes(stream, limit):
    """Decode only the filters emitted by this exporter, with an output bound."""
    stream = _obj(stream)
    raw = getattr(stream, "_data", None)
    if not isinstance(raw, bytes) or len(raw) > MAX_PDF_BYTES:
        raise ValueError("Invalid or oversized PDF stream")
    filters = stream.get("/Filter", [])
    filters = [filters] if isinstance(filters, str) else list(filters)
    if filters not in ([], ["/FlateDecode"]):
        raise ValueError("Unsupported PDF stream filter; export the review as JSON instead")
    if filters:
        if stream.get("/DecodeParms"):
            raise ValueError("Unsupported PDF stream predictor")
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(raw, limit + 1)
            if len(raw) > limit or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
                raise ValueError("PDF stream exceeds its bound or is truncated")
        except zlib.error as exc:
            raise ValueError("Invalid compressed PDF stream") from exc
    if len(raw) > limit:
        raise ValueError("PDF stream exceeds its decoded byte limit")
    return raw


def _capsule(reader):
    root = reader.trailer["/Root"]
    if root.get("/OpenAction") or root.get("/AA"):
        raise ValueError("Active PDF document actions are not supported for review import")
    names = _obj(root.get("/Names", {}))
    if names.get("/JavaScript"):
        raise ValueError("PDF JavaScript is not supported for review import")
    embedded = names.get("/EmbeddedFiles")
    if embedded is None:
        raise ValueError("PDF has no embedded Invarune review capsule")
    attachments, seen = {}, set()

    def walk(reference, depth=0):
        key = _identity(reference)
        if key in seen or depth > 16 or len(seen) >= 128:
            raise ValueError("Ambiguous or oversized PDF attachment tree")
        seen.add(key)
        node = _obj(reference)
        if node.get("/Kids") and node.get("/Names"):
            raise ValueError("Ambiguous PDF attachment tree")
        pairs = node.get("/Names", [])
        if len(pairs) % 2 or len(pairs) > 32:
            raise ValueError("Invalid PDF attachment names")
        for index in range(0, len(pairs), 2):
            name, spec = str(pairs[index]), _obj(pairs[index + 1])
            if name in attachments or name not in {CAPSULE_NAME, "invarune-report.json"}:
                raise ValueError("Duplicate or unexpected PDF attachment")
            if str(spec.get("/UF", spec.get("/F", ""))) != name:
                raise ValueError("PDF attachment filename mismatch")
            attachments[name] = spec
        for child in node.get("/Kids", []):
            walk(child, depth + 1)

    walk(embedded)
    if CAPSULE_NAME not in attachments:
        raise ValueError("PDF has no embedded Invarune review capsule")
    spec = attachments[CAPSULE_NAME]
    streams = _obj(spec.get("/EF", {}))
    if "/F" not in streams or ("/UF" in streams and _identity(streams["/F"]) != _identity(streams["/UF"])):
        raise ValueError("Ambiguous PDF review capsule stream")
    return _json(_stream_bytes(streams["/F"], MAX_CAPSULE_BYTES))


def _canonical_fields(reader, expected):
    form = _obj(reader.trailer["/Root"].get("/AcroForm", {}))
    flag = _obj(form.get("/NeedAppearances", False))
    if form.get("/XFA") or getattr(flag, "value", flag) is not False:
        raise ValueError("PDF needs regenerated appearances or uses unsupported XFA forms")
    fields, visited = {}, set()

    def walk(reference, prefix="", inherited_type=None, depth=0):
        key = _identity(reference)
        if key in visited or depth > 24 or len(visited) > MAX_ITEMS * 10 + 100:
            raise ValueError("Cyclic, duplicate or oversized PDF form tree")
        visited.add(key)
        node = _obj(reference)
        if node.get("/A") or node.get("/AA"):
            raise ValueError("Active PDF form actions are not supported")
        name = str(node.get("/T", ""))
        full = (prefix + "." + name) if prefix and name else (name or prefix)
        field_type = node.get("/FT", inherited_type)
        kids = list(node.get("/Kids", []))
        field_kids = [child for child in kids if _obj(child).get("/T") is not None]
        if field_kids:
            if len(field_kids) != len(kids):
                raise ValueError("Ambiguous mixed PDF field and widget tree")
            for child in field_kids:
                walk(child, full, field_type, depth + 1)
            return
        if full not in expected or full in fields or field_type not in {"/Tx", "/Ch"}:
            raise ValueError("Unknown, duplicate or unsupported PDF review field")
        wanted_type = "/Ch" if full.endswith(".decision") else "/Tx"
        if field_type != wanted_type or "/V" not in node or not isinstance(node["/V"], str):
            raise ValueError("Invalid canonical PDF review field value/type")
        if field_type == "/Ch":
            options = [(str(option[0]), str(option[1])) if isinstance(option, list) and len(option) == 2 else (str(option), str(option))
                       for option in node.get("/Opt", [])]
            if options != [(value, value) for value in expected[full]]:
                raise ValueError("PDF decision choices or labels differ from the canonical review options")
        widgets = kids or ([reference] if node.get("/Subtype") == "/Widget" else [])
        if len(widgets) != 1:
            raise ValueError("Each canonical review field must have exactly one widget")
        widget = _obj(widgets[0])
        if widget.get("/Subtype") != "/Widget":
            raise ValueError("Canonical review field has an invalid widget")
        if _identity(widgets[0]) != key and _identity(widget.get("/Parent")) != key:
            raise ValueError("PDF widget is not connected to its canonical field")
        fields[full] = (node, widget, _identity(widgets[0]))

    for reference in form.get("/Fields", []):
        walk(reference)
    if set(fields) != set(expected):
        raise ValueError("PDF is missing required canonical review fields")
    page_widgets = set()
    if len(reader.pages) > 2000:
        raise ValueError("PDF page count exceeds the review limit")
    for page in reader.pages:
        if page.get("/AA"):
            raise ValueError("Active PDF page actions are not supported")
        annotations = page.get("/Annots", [])
        if len(annotations) > MAX_ITEMS * 5 + 200:
            raise ValueError("PDF annotation limit exceeded")
        for reference in annotations:
            annotation = _obj(reference)
            if annotation.get("/Subtype") != "/Widget":
                continue
            if int(annotation.get("/F", 0)) & (1 | 2 | 32):
                raise ValueError("Hidden or invisible PDF review widgets are unsupported")
            rectangle = _rectangle(annotation.get("/Rect"))
            box = [float(number) for number in page.mediabox]
            if rectangle[0] < box[0] or rectangle[1] < box[1] or rectangle[2] > box[2] or rectangle[3] > box[3] or annotation.get("/OC"):
                raise ValueError("PDF review widget is outside the visible page or uses an optional-content layer")
            key = _identity(reference)
            if key in page_widgets:
                raise ValueError("Duplicate PDF widget annotation")
            page_widgets.add(key)
    if page_widgets != {entry[2] for entry in fields.values()}:
        raise ValueError("Orphan or missing PDF widget; no automatic form repair is performed")
    return fields, form


def _appearance_text(widget, form, pypdf):
    appearance = _obj(widget.get("/AP", {})).get("/N")
    if appearance is None or not hasattr(_obj(appearance), "get_data"):
        raise ValueError("Missing or unsupported PDF widget appearance")
    stream = _obj(appearance)
    _rectangle(stream.get("/BBox"))
    if stream.get("/Matrix") is not None:
        _matrix(stream["/Matrix"])
    raw = _stream_bytes(stream, 65536)
    if not raw.strip():
        raise ValueError("Empty PDF widget appearance")
    # Extract only the bounded appearance stream, using its own font resources.
    from pypdf.generic import ContentStream, DecodedStreamObject, NameObject
    contents = DecodedStreamObject()
    contents.set_data(raw)
    fill = (0, 0, 0)
    fill_stack = []
    for operands, operator in ContentStream(contents, None).operations:
        if operator == b"q":
            fill_stack.append(fill)
        elif operator == b"Q" and fill_stack:
            fill = fill_stack.pop()
        elif operator == b"Tr" and (len(operands) != 1 or float(operands[0]) != 0):
            raise ValueError("Invisible or unsupported PDF appearance text rendering mode")
        elif operator in {b"cm", b"Tm"}:
            _matrix(operands)
        elif operator == b"Tf" and (len(operands) != 2 or not math.isfinite(float(operands[1])) or float(operands[1]) < 1):
            raise ValueError("Invisible PDF appearance text size")
        elif operator in {b"gs", b"Do", b"BDC"}:
            raise ValueError("Unsupported PDF appearance graphics state or optional content")
        elif operator == b"rg" and len(operands) == 3:
            fill = tuple(float(value) for value in operands)
        elif operator == b"g" and len(operands) == 1:
            fill = (float(operands[0]),) * 3
        elif operator == b"k" and len(operands) == 4:
            cyan, magenta, yellow, black = (float(value) for value in operands)
            fill = (1 - min(1, cyan + black), 1 - min(1, magenta + black), 1 - min(1, yellow + black))
        elif operator in {b"Tj", b"TJ", b"'", b'"'} and min(fill) > .8:
            raise ValueError("PDF appearance text has insufficient visible contrast")
    page = pypdf.PageObject.create_blank_page(width=600, height=850)
    page[NameObject("/Contents")] = contents
    page[NameObject("/Resources")] = _obj(stream.get("/Resources", form.get("/DR", {})))
    if page["/Resources"].get("/XObject"):
        raise ValueError("Nested PDF widget appearances are unsupported; use JSON review")
    font_map = _obj(page["/Resources"].get("/Font", {}))
    if len(font_map) > 8:
        raise ValueError("PDF appearance font limit exceeded")
    for font_ref in font_map.values():
        font = _obj(font_ref)
        if font.get("/Subtype") != "/Type1" or font.get("/ToUnicode") or font.get("/DescendantFonts"):
            raise ValueError("Unsupported PDF form font; use the JSON review for this editor")
        descriptor = _obj(font.get("/FontDescriptor", {}))
        if any(key in descriptor for key in ("/FontFile", "/FontFile2", "/FontFile3")):
            raise ValueError("Embedded PDF form fonts are unsupported for bounded import")
    try:
        return page.extract_text()
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError("Cannot verify PDF widget appearance text") from exc


def extract_review_workspace(data):
    """Return a capsule with validated editable field values; never execute PDF actions."""
    pypdf, _ = _dependencies()
    if not isinstance(data, bytes) or not data or len(data) > MAX_PDF_BYTES:
        raise ValueError("PDF review input must contain at most 50 MB")
    try:
        reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are not supported for review import")
        workspace = _capsule(reader)
        expected = {"ivr.{}.{}".format(index, field): _choices(item) if field == "decision" else None
                    for index, item in enumerate(workspace["items"]) for field in FIELDS}
        fields, form = _canonical_fields(reader, expected)
        for index, item in enumerate(workspace["items"]):
            for field in FIELDS:
                name = "ivr.{}.{}".format(index, field)
                canonical, widget, _ = fields[name]
                value = str(canonical["/V"])
                if len(value) > LIMITS[field] or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
                    raise ValueError("PDF review field exceeds its text limit or has invalid Unicode")
                if widget.get("/A") or widget.get("/AA") or ("/V" in widget and str(widget["/V"]) != value):
                    raise ValueError("PDF widget and canonical field disagree")
                if field == "decision" and value not in expected[name] + [""]:
                    raise ValueError("Unknown PDF review decision")
                display = value
                if field == "decision":
                    for option in canonical.get("/Opt", []):
                        if isinstance(option, list) and len(option) == 2 and str(option[0]) == value:
                            display = str(option[1])
                            break
                actual = _appearance_text(widget, form, pypdf)
                if " ".join(actual.split()) != " ".join(display.split()):
                    raise ValueError("PDF appearance is stale or differs from the canonical field value; save with regenerated appearances or use JSON")
                item[field] = "" if field == "decision" and value == "Unreviewed" else value
        return workspace
    except ValueError:
        raise
    except Exception as exc:
        # pypdf exposes several malformed-object exception classes. The public
        # boundary reports a safe operational error rather than trusting a form.
        raise ValueError("Invalid or unsupported Invarune review PDF") from exc


def _display(value):
    value = str(value).translate(str.maketrans({"\u2011": "-", "\u2013": "-", "\u2014": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"'}))
    # Base PDF fonts are portable. Explicit escapes preserve uncommon characters
    # in static labels rather than silently dropping them or drawing tofu.
    return value.encode("cp1252", "backslashreplace").decode("cp1252")


def _render_pdf(report, path):
    """Create a branded report with editable review fields and an attached capsule."""
    pypdf, _ = _dependencies()
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfgen import canvas
    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Flowable, KeepTogether
    from reportlab.platypus.tableofcontents import TableOfContents

    if report.get("workspace_unavailable") or report.get("review_workspace_unavailable"):
        raise ValueError("PDF review export is unavailable because the bound review workspace could not be created")
    workspace = report.get("review_workspace")
    if not isinstance(workspace, dict):
        raise ValueError("PDF export requires the report's bound review_workspace")
    capsule = json.dumps(workspace, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(capsule) > MAX_CAPSULE_BYTES:
        raise ValueError("PDF review workspace exceeds its 4 MB capsule limit")
    _json(capsule)
    for item in workspace["items"]:
        for field in FIELDS:
            value = item.get(field, "")
            if not isinstance(value, str) or len(value) > LIMITS[field]:
                raise ValueError("Invalid PDF review field value")
            try:
                value.encode("cp1252")
            except UnicodeError as exc:
                raise ValueError("Prefilled PDF fields require Western text; preserve other Unicode review text using JSON") from exc
    navy, teal, pale, grey = [colors.HexColor(x) for x in ("#0b1220", "#087e78", "#f2f6fa", "#526276")]
    styles = {
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=12, textColor=navy, spaceAfter=7),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=7.5, leading=10, textColor=grey, spaceAfter=5),
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=28, leading=32, textColor=navy, spaceAfter=15),
        "heading": ParagraphStyle("heading", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=navy, spaceAfter=12),
        "sub": ParagraphStyle("sub", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=teal, spaceAfter=7, keepWithNext=True),
    }

    def bookmark_key(kind, value):
        return kind + "-" + hashlib.sha256(str(value).encode("utf-8", "backslashreplace")).hexdigest()[:20]

    def para(value, style="body", anchor=None):
        markup = html.escape(_display(value)).replace("\n", "<br/>")
        if anchor:
            markup = '<a name="' + anchor + '"/>' + markup
        return Paragraph(markup, styles[style])

    def internal_link(destination, label):
        return Paragraph('<link color="#087e78" href="#' + destination + '">' + html.escape(_display(label)) + '</link>', styles["small"])

    def data_table(headers, rows, widths):
        cells = [[para(item, "small") for item in headers]]
        cells += [[item if isinstance(item, Flowable) else para(item, "small") for item in row] for row in rows]
        result = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), pale),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, 0), .7, teal),
            ("LINEBELOW", (0, 1), (-1, -1), .3, colors.HexColor("#dbe3ec"))]))
        return result

    def readable(value):
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if value is None:
            return "Not configured"
        if isinstance(value, list) and all(not isinstance(item, (list, dict)) for item in value):
            return ", ".join(str(item) for item in value) or "None"
        return str(value)

    def configuration_rows(value, prefix=""):
        rows = []
        for field, content in sorted(value.items()):
            name = (prefix + " / " if prefix else "") + field.replace("_", " ").capitalize()
            if isinstance(content, dict):
                rows.extend(configuration_rows(content, name))
            else:
                rows.append((name, readable(content)))
        return rows

    def source_link(url, label=None):
        try:
            parsed = urlsplit(url)
        except (TypeError, ValueError):
            return None
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or any(ord(c) < 33 for c in url):
            return None
        label = _display(label or (url if len(url) < 105 else url[:101] + "..."))
        return Paragraph('<link color="#087e78" href="' + html.escape(url, quote=True) + '">' + html.escape(label) + '</link>', styles["small"])

    def proposed_actions(actions):
        if not actions:
            return []
        result = [para("Model-proposed fix guidance (unverified)", "sub"),
                  para("Agent/MCP relevance: " + actions["agent_mcp_relevance"], "small"),
                  para("When this applies: " + actions["applicability"], "small")]
        result += [para(str(index) + ". " + step, "small") for index, step in enumerate(actions["steps"], 1)]
        result += [para("Verify: " + step, "small") for step in actions["verification"]]
        return result

    class ReviewCard(Flowable):
        def __init__(self, index, item):
            Flowable.__init__(self)
            self.index, self.item = index, item
            self.width, self.height = 507, 288

        def draw(self):
            c, item = self.canv, self.item
            c.bookmarkHorizontal(bookmark_key("review", item["id"]), 0, self.height)
            c.setFillColor(pale)
            c.roundRect(0, 0, 507, self.height, 6, fill=1, stroke=0)
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(teal)
            label = "Finding review" if item.get("kind") == "finding" else ("Acceptance check review" if item.get("kind") == "check" else "Coverage gap review")
            c.drawString(12, 270, label)
            c.setFont("Helvetica", 7)
            c.setFillColor(grey)
            destination = "gaps"
            if item.get("kind") == "finding":
                destination = bookmark_key("finding", item["id"].split(":", 1)[1])
            elif item.get("kind") == "check":
                destination = bookmark_key("control", item["id"].split(":", 2)[1])
            c.drawRightString(495, 270, "Back to evidence")
            c.linkRect("Back to evidence", destination, (401, 267, 495, 280), relative=1, thickness=0)
            text = str(item.get("subject", ""))
            paragraph = para(text[:450] + (" [Full subject in capsule]" if len(text) > 450 else ""), "small")
            _, height = paragraph.wrap(483, 55)
            if height > 55:
                paragraph = para(text[:230] + " [Full subject in capsule]", "small")
                _, height = paragraph.wrap(483, 55)
            paragraph.drawOn(c, 12, 255 - height)
            c.setFont("Helvetica", 6)
            c.drawString(12, 194, "Evidence binding: " + str(item.get("binding_sha256", ""))[:64])
            prefix = "ivr.{}.".format(self.index)
            c.setFont("Helvetica-Bold", 7)
            for label, x, y in [("DECISION", 12, 177), ("REVIEWER", 263, 177), ("REASON / JUSTIFICATION", 12, 128), ("REVIEWED AT (YOUR DATE)", 12, 49), ("EVIDENCE REFERENCE", 203, 49)]:
                c.drawString(x, y, label)
            common = dict(borderWidth=.6, borderColor=colors.HexColor("#bed0dd"), fillColor=colors.white,
                          textColor=navy, fontName="Helvetica", fontSize=8, forceBorder=True, relative=True)
            c.acroForm.choice(name=prefix + "decision", tooltip="Review decision; blank retains existing scanner status", x=12, y=144, width=239, height=27,
                              options=_choices(item), value=item.get("decision", "") or "Unreviewed", fieldFlags="combo", **common)
            for field, x, y, width, height, multiline in [("reviewer", 263, 144, 232, 27, False),
                    ("reason", 12, 66, 483, 55, True), ("reviewed_at", 12, 16, 179, 27, False),
                    ("evidence_ref", 203, 16, 292, 27, False)]:
                c.acroForm.textfield(name=prefix + field, tooltip=field.replace("_", " "),
                    value="", x=x, y=y, width=width, height=height, maxlen=LIMITS[field],
                    fieldFlags="multiline" if multiline else "", **common)

    class Bars(Flowable):
        def __init__(self, rows, caption):
            Flowable.__init__(self)
            self.rows, self.caption = rows, caption
            self.width, self.height = 507, 37 + 24 * len(rows)

        def draw(self):
            c, maximum = self.canv, max([n for _, n in self.rows] + [1])
            for index, (label, number) in enumerate(self.rows):
                y = self.height - 20 - 24 * index
                c.setFont("Helvetica", 8)
                c.setFillColor(navy)
                c.drawString(0, y, _display(label))
                c.setFillColor(pale)
                c.rect(145, y - 3, 320, 12, fill=1, stroke=0)
                c.setFillColor(teal)
                c.rect(145, y - 3, 320 * number / maximum, 12, fill=1, stroke=0)
                c.setFillColor(navy)
                c.drawRightString(505, y, str(number))
            c.setFont("Helvetica", 7)
            c.setFillColor(grey)
            c.drawString(0, 3, self.caption)

    class Metrics(Flowable):
        def __init__(self, rows):
            Flowable.__init__(self)
            self.rows, self.width, self.height = rows, 507, 80

        def draw(self):
            for index, (label, value) in enumerate(self.rows):
                x = index * 174
                self.canv.setFillColor(pale)
                self.canv.roundRect(x, 0, 159, 73, 6, fill=1, stroke=0)
                self.canv.setFillColor(teal)
                self.canv.setFont("Helvetica-Bold", 26)
                self.canv.drawString(x + 12, 34, str(value))
                self.canv.setFillColor(navy)
                self.canv.setFont("Helvetica", 8)
                self.canv.drawString(x + 12, 14, label)

    class Workflow(Flowable):
        def __init__(self):
            Flowable.__init__(self)
            self.width, self.height = 507, 136

        def draw(self):
            labels = [("1 / SELECT", "Source or built image"), ("2 / INSPECT", "Deterministic evidence"),
                      ("3 / OPTIONAL", "Bounded analyst review"), ("4 / VALIDATE", "Runtime / human tests"),
                      ("5 / RECORD", "Decision + reason + owner"), ("6 / RECHECK", "Fresh scan + bound import")]
            for index, (title, body) in enumerate(labels):
                x, y = (index % 3) * 173, 72 - (index // 3) * 68
                self.canv.setFillColor(navy if index == 2 else pale)
                self.canv.roundRect(x, y, 160, 56, 5, fill=1, stroke=0)
                self.canv.setFont("Helvetica-Bold", 8)
                self.canv.setFillColor(colors.white if index == 2 else teal)
                self.canv.drawString(x + 10, y + 35, title)
                self.canv.setFont("Helvetica", 7.5)
                self.canv.drawString(x + 10, y + 16, body)

    class Document(BaseDocTemplate):
        def afterFlowable(self, flowable):
            if hasattr(flowable, "bookmark"):
                self.canv.bookmarkPage(flowable.bookmark)
                self.canv.addOutlineEntry(flowable.getPlainText(), flowable.bookmark, level=0)
                self.notify("TOCEntry", (0, flowable.getPlainText(), self.page, flowable.bookmark))

    def frame(c, doc):
        c.saveState()
        c.setFillColor(navy)
        c.rect(0, 800, 595.276, 42, fill=1, stroke=0)
        for points, fill in [([(1, 2), (7, 0), (7, 5), (5, 6), (5, 15), (7, 16), (7, 21), (1, 19)], colors.white),
                             ([(11, 0), (17, 2), (17, 19), (11, 21), (11, 16), (13, 15), (13, 6), (11, 5)], colors.HexColor("#35e3b1"))]:
            c.setFillColor(fill)
            shape = c.beginPath()
            shape.moveTo(44 + points[0][0], 809 + points[0][1])
            for x, y in points[1:]:
                shape.lineTo(44 + x, 809 + y)
            shape.close()
            c.drawPath(shape, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(colors.white)
        c.drawString(73, 817, "INVARUNE  /  NIMESHBUILD")
        c.setFont("Helvetica", 7)
        c.setFillColor(grey)
        c.drawString(44, 28, "Evidence-bound security review | Findings are unverified patterns")
        c.drawRightString(550, 28, str(doc.page))
        c.restoreState()

    def heading(title, key):
        value = para(title, "heading")
        value.bookmark = key
        return value

    summary = report.get("summary", {})
    assessment = report.get("assessment", {})
    if not assessment:
        from .assessment import build_assessment
        assessment = build_assessment(report)
    findings_by_id = {item["id"]: item for item in report.get("findings", [])}
    review_by_id = {item["id"]: item for item in workspace["items"]}
    actions = assessment.get("immediate_actions", [])

    def action_table(limit=5):
        rows = []
        for action in actions[:limit]:
            locations = action.get("locations", [])
            location = locations[0] if locations else {}
            label = str(location.get("path", "See evidence")) + (":" + str(location["line"]) if location.get("line") else "")
            if len(locations) > 1:
                label += " (+{} locations)".format(len(locations) - 1)
            finding_id = location.get("finding_id") or next((item for item in action.get("finding_ids", []) if item in findings_by_id), None)
            evidence = internal_link(bookmark_key("finding", finding_id), label) if finding_id in findings_by_id else para(label, "small")
            rows.append((str(action.get("priority", "Review")) + " / " + str(action.get("rule_id", "")) + "\n" + str(action.get("count", 0)) + " open",
                         evidence, str(action.get("title", "Review finding")) + "\n" + str(action.get("immediate_action", "Review the linked evidence."))))
        return data_table(["Priority / count", "Observed location", "Immediate concern and first action"], rows, [76, 126, 305])
    posture = assessment.get("posture", {})
    posture_explanation = posture.get("explanation", "") if isinstance(posture, dict) else ""
    if isinstance(posture, dict):
        posture = posture.get("title", posture.get("summary", posture.get("label", posture.get("status", "Static review required"))))
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    review_notice = "Optional model review: disabled. Deterministic findings and fix guidance run independently."
    if judge.get("enabled") or analyst.get("enabled"):
        review_notice = "Optional model review: finding stage {}; control stage {}.".format(
            judge.get("status", "unknown") if judge.get("enabled") else "disabled",
            analyst.get("status", "unknown") if analyst.get("enabled") else "disabled")
        if judge.get("enabled"):
            answered = report.get("advice_coverage", {}).get("finding_assessments")
            review_notice += " " + (str(answered) + " model answers from " if answered is not None else "Finding scope: ")
            review_notice += str(judge.get("selected_findings", 0)) + " selected findings; " + str(judge.get("omitted_open_findings", 0)) + " open findings outside the cap."
        if analyst.get("enabled"):
            review_notice += " {} acceptance checks remain unanswered.".format(analyst.get("coverage", {}).get("omitted_checks", 0))
        if report.get("execution", {}).get("exit_code") == 2:
            review_notice += " Requested work is incomplete. Inspect the recorded errors; no model judgment resolves the static findings."
    target = report.get("image", {}).get("display_target", report.get("target", "."))
    if target == ".":
        target = "Selected source directory; paths below are relative"
    static_status = "Incomplete selected scope" if summary.get("coverage_gaps", 0) else "Selected static scope completed"
    story = [Spacer(1, 8), heading("Executive summary", "summary"),
             para("AI AGENT + MCP SECURITY REVIEW", "sub"),
             para("Scope: " + str(target) + " | Invarune " + str(report.get("tool", {}).get("version", "")), "small"),
             para(str(posture), "sub"), para(str(posture_explanation)),
             Metrics([("OPEN FINDINGS", int(summary.get("open_findings", 0))), ("COVERAGE GAPS", int(summary.get("coverage_gaps", 0))),
                      ("FILES EXAMINED", int(summary.get("files_scanned", 0)))]),
             para("Observed counts only. This is not an accuracy score or a security grade.", "small"),
             para("Deterministic layer: " + static_status + ".", "small"), para(review_notice, "small")]
    if any(summary.get(name, 0) for name in ("suppressed_findings", "justified_findings", "disabled_findings")) or report.get("review_policy", {}).get("enabled"):
        story.append(para("Accepted baseline: {} | Justified: {} | Disabled: {} findings. User exceptions receive no pass credit and remain visible in the decision audit.".format(
            summary.get("suppressed_findings", 0), summary.get("justified_findings", 0), summary.get("disabled_findings", 0)), "small"))
    if actions:
        story += [para("Immediate concerns", "sub"), action_table(),
                  para("Showing {} of {} open finding groups. Locations link to evidence; every proposed fix needs verification.".format(min(5, len(actions)), len(actions)), "small")]
    else:
        story.append(para("No priority groups were supplied; review the observed findings below." if summary.get("open_findings", 0)
                          else "No open finding groups. Review accepted exceptions, coverage limits and active controls before drawing a deployment conclusion."))
    story += [internal_link("review", "Record a review decision and rescan"),
              para("Justified and disabled are human decisions, not passes. The full review forms and all evidence remain in this report.", "small"),
              para("Scan ID: " + str(report.get("scan_id", "")), "small"), PageBreak(), heading("Contents", "contents")]
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("TOC", fontName="Helvetica", fontSize=10, leading=19, textColor=teal)]
    story += [toc, PageBreak(), heading("Priorities and first actions", "actions"),
              para(review_notice),
              para("Severity counts describe observed open patterns. They do not establish exploitability or an estimated probability of compromise."),
              Bars([(name.title(), int(summary.get("severity_counts", {}).get(name, 0))) for name in ("critical", "high", "medium", "low", "info")], "Severity counts use the existing scanner rules; no model or reviewer score is added.")]
    if report.get("advice_coverage"):
        advice = report["advice_coverage"]
        story.append(para("Fix guidance: {}/{} findings have deterministic fix plans and agent/MCP context. Model fix plans: {}/{} finding assessments; {}/{} answered checks. Proposals require verification.".format(
            advice["static_fix_plans"], advice["static_findings"], advice["finding_fix_plans"], advice["finding_assessments"],
            advice["model_check_fix_plans"], advice["model_check_assessments"]), "small"))
    if actions:
        story += [action_table(8), para("Showing {} of {} open finding groups in priority order. The complete findings follow.".format(min(8, len(actions)), len(actions)), "small")]
    story += [para("Review every detailed finding and gap below. Additional concerns can exist outside this bounded scan's supported syntax, files, budgets and execution context.")]
    configuration_start = len(story)
    story += [PageBreak(), heading("Scan configuration and scope", "configuration")]
    for title, config in [("Source scope and limits", report.get("configuration", {})),
                          ("Invocation and optional-review budgets", report.get("run_configuration", {})),
                          ("Image limits", report.get("image", {}).get("limits", {}))]:
        story.append(para(title, "sub"))
        if not config:
            story.append(para("Not present for this scan.", "small"))
        if config:
            story += [data_table(["Setting", "Configured value"], configuration_rows(config), [194, 313]), Spacer(1, 12)]
    story += [para("Source and image evidence are static. Image metadata, retained layers and packaged files do not reveal every runtime override or compiled program behavior."),
              para("Scanner provenance", "sub"), data_table(["Identity", "Recorded value"], configuration_rows(report.get("tool", {})), [194, 313]), PageBreak(),
              heading("Deterministic checks and optional review", "layers"),
              para("42 static source/configuration patterns", "sub"),
              para("Deterministic checks inspect bounded Python syntax and local value flow, JavaScript/TypeScript lexical structure, structured JSON, configuration settings, selected secret patterns and image metadata. Repeated stable input produces repeatable evidence; it does not guarantee zero false positives or negatives."),
              para("Optional security analyst", "sub"),
              para("If enabled, a model reviews selected findings and acceptance checks using bounded supplied evidence. Strict IDs, citations, response validation and tool restrictions constrain the protocol. Partial budgets, omitted answers and unavailable source/runtime evidence remain visible. Advice does not independently prove safety or erase static findings."),
              data_table(["Review layer", "Actual outcome / coverage"], [
                  ("Finding review", readable(judge.get("status", "Disabled")) + "; " + str(judge.get("selected_findings", 0)) + " selected; " + str(judge.get("omitted_open_findings", 0)) + " outside cap"),
                  ("Control review", readable(analyst.get("status", "Disabled")) + "; " + str(analyst.get("coverage", {}).get("reviewed_controls", 0)) + "/" + str(analyst.get("coverage", {}).get("total_controls", 0)) + " active controls answered"),
                  ("Unanswered acceptance checks", str(analyst.get("coverage", {}).get("omitted_checks", 0)) + "/" + str(analyst.get("coverage", {}).get("total_checks", 0)) + " requested checks"),
                  ("Control requests", str(analyst.get("coverage", {}).get("calls_made", 0)) + "/" + str(analyst.get("coverage", {}).get("call_budget", 0)) + " configured calls"),
                  ("Finding-stage error", judge.get("error", "None recorded")),
                  ("Control-stage errors", readable(analyst.get("errors", [])))], [160, 347]), Spacer(1, 12),
              para("What can be missed", "sub"),
              para("Cross-module/interprocedural flow, reflection, dynamic loaders, complex language syntax, templates before rendering, unsupported languages, compiled image behavior, runtime authentication/authorization, tenant isolation, egress policy, dependency CVEs and adaptive prompt injection require additional validation. A source declaration or proposed mitigation is not deployment evidence."),
              para("Human/runtime review workflow", "sub"), Workflow(),
              para("1. Review evidence and the immediate concern. 2. Record a decision, reason, reviewer, date and evidence reference. 3. Validate runtime or human-dependent controls in the applicable environment. 4. Save and import the edited PDF or equivalent JSON. 5. Resolve rejected/stale edits, then rescan. Gaps remain operationally incomplete; blank decisions retain existing scanner semantics."), PageBreak(),
              heading("Coverage, misses and validation by area", "methodology")]
    review_audit = {"judge": {k: v for k, v in judge.items() if k in {"enabled", "status", "provider", "model", "cli", "selected_findings", "omitted_open_findings", "source_context_requested", "source_context_sent_count", "source_context_skipped", "error"}},
                    "analyst": {k: v for k, v in analyst.items() if k in {"enabled", "status", "summary", "coverage", "check_status_counts", "errors"}}}
    optimization = []
    if isinstance(judge.get("token_optimization"), dict):
        optimization.append(("Finding request", judge["token_optimization"]))
    for index, request in enumerate(analyst.get("requests", []), 1):
        if isinstance(request.get("token_optimization"), dict):
            optimization.append(("Control request " + str(index), request["token_optimization"]))
    if optimization:
        optimization_rows = []
        for label, record in optimization:
            optimization_rows.append((label, str(record.get("requested", "unknown")) + " / " + str(record.get("engine", "unknown")),
                str(record.get("status", "unknown")) + (" / " + str(record["fallback_reason"]) if record.get("fallback_reason") else ""),
                str(record.get("payload_bytes_before", 0)) + " -> " + str(record.get("payload_bytes_after", 0)) + "\n" + str(record.get("bytes_saved", 0)) + " bytes saved"))
        configuration_story_extra = [para("Optional request payload optimization", "sub"),
            data_table(["Request", "Requested / actual engine", "Outcome", "Evidence payload bytes"], optimization_rows, [82, 129, 125, 171]),
            para("These are measured evidence-JSON bytes, excluding instructions, response schemas and provider wrappers. Token and cost savings were not measured. Evidence-preserving formatting does not validate the model's interpretation.", "small")]
    else:
        configuration_story_extra = []
    from .methodology import build_methodology
    methodology = report.get("methodology") or build_methodology(report)
    catalog = methodology["catalog"]
    story += [Bars([("Controls with rule mapping", catalog["statically_mapped_controls"]),
                    ("Controls without rule mapping", catalog["controls_without_static_mapping"])],
                   "Catalog mapping counts are not passed controls or percent secure."), para(methodology["interpretation"], "small")]
    for area in methodology["areas"]:
        block = [para(area["area"], "sub")]
        for label, key in [("Deterministic", "deterministic"), ("Optional analyst", "optional_review"),
                           ("Can miss or misclassify", "can_miss_or_misclassify"), ("Validate elsewhere", "runtime_or_human_validation")]:
            block.append(para(label + ": " + area[key], "small"))
        story.append(KeepTogether(block))
    configuration_story = story[configuration_start:]
    configuration_story += configuration_story_extra
    configuration_story += [para("Optional-review audit details", "sub"), data_table(["Recorded field", "Recorded value"], configuration_rows(review_audit), [194, 313])]
    del story[configuration_start:]
    rule_inventory = [PageBreak(), heading("Appendix / Deterministic rule inventory", "rules")]
    from .rules import RULES
    for rule in RULES:
        rule_inventory += [para(rule["id"] + " / " + rule["title"], "sub"), para(rule["description"], "small")]
    story += [PageBreak(), heading("Observed findings and mitigating layers", "findings")]
    if not report.get("findings"):
        story.append(para("No selected static pattern was emitted. Review coverage gaps and control evidence before drawing a conclusion."))
    severity_order = {name: index for index, name in enumerate(("critical", "high", "medium", "low", "info"))}
    display_findings = sorted(report.get("findings", []), key=lambda item: (item.get("status") != "open", severity_order.get(item.get("severity"), 5), item["rule_id"], item.get("path", ""), item.get("line", 0), item["id"]))
    for finding in display_findings:
        story += [para("{} / {} / {}".format(finding["rule_id"], finding.get("severity", ""), finding.get("status", "")), "sub", bookmark_key("finding", finding["id"])),
                  para(finding.get("title", "")), para("{}:{}".format(finding.get("path", ""), finding.get("line", "")), "small"),
                  para(finding.get("evidence", ""), "small"), para(finding.get("remediation", ""), "small")]
        if finding.get("suppression_reason"):
            story.append(para("Accepted baseline reason: " + finding["suppression_reason"], "small"))
        if finding.get("disposition"):
            decision = finding["disposition"]
            story.append(para("Human disposition: " + str(decision.get("status", "")) + " | Scope: " + str(decision.get("scope", ""))
                              + " | Reason: " + str(decision.get("reason", "")) + ". This is an accepted exception, not a verified pass.", "small"))
        if "finding:" + finding["id"] in review_by_id:
            story.append(internal_link(bookmark_key("review", "finding:" + finding["id"]), "Record a decision, reason and reviewer for this finding"))
        for group in assessment.get("finding_groups", []):
            if finding["id"] in group.get("finding_ids", []) and group.get("defense_layers"):
                story.append(internal_link(bookmark_key("layers", group["id"]), "Additional defenses: " + "; ".join(layer.get("title", layer.get("name", "Review layer")) for layer in group["defense_layers"])))
        advice = report.get("remediation", {}).get(finding.get("id"))
        if advice:
            story += [para("Fix plan and agent/MCP relevance", "sub"), para(advice["summary"], "small"),
                      para("Why this matters for agents/MCP: " + advice["agent_mcp_relevance"], "small"),
                      para(advice["scope_note"], "small")]
            story += [para("Confirm applicability: " + item, "small") for item in advice["applicability"]]
            for index, step in enumerate(advice["steps"], 1):
                story.append(KeepTogether([para(str(index) + ". " + step["title"], "sub"),
                                           para(step["action"], "small"), para("Verify: " + step["verification"], "small")]))
            story += [para("Remaining validation: " + item, "small") for item in advice["residual_risk"]]
            story.append(para("Related controls: " + ", ".join(advice["control_ids"]), "small"))
            for source in advice["sources"]:
                link = source_link(source["url"], source["id"] + " / " + source["title"])
                if link is not None:
                    story.append(link)
    for group in assessment.get("finding_groups", []):
        for layer_index, layer in enumerate(group.get("defense_layers", [])):
            block = [para(str(group.get("rule_id", "")) + " / " + str(layer.get("name", layer.get("title", "Proposed mitigating layer"))), "sub", bookmark_key("layers", group["id"]) if layer_index == 0 else None),
                     para("Proposed control; effectiveness has not been verified.", "small")]
            for label, key in [("How it helps", "how_it_helps"), ("Evidence to obtain", "verification"), ("Remaining limit", "residual_limit")]:
                if layer.get(key):
                    block.append(para(label + ": " + str(layer[key]), "small"))
            if layer.get("control_ids"):
                block.append(para("Related controls: " + ", ".join(layer["control_ids"]), "small"))
            for source in layer.get("sources", []):
                link = source_link(source.get("url", ""), str(source.get("id", "Source")) + " / " + str(source.get("title", "")))
                if link is not None:
                    block.append(link)
            story.append(KeepTogether(block))
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    if judge.get("enabled") or analyst.get("enabled"):
        story += [PageBreak(), heading("Optional advisory review and evidence", "advisory"),
                  para("Model interpretations are advisory. They do not dismiss static findings, prove control effectiveness or change deterministic evidence. A verified quotation proves its presence in the supplied excerpt, not the correctness of the interpretation."),
                  para("Omissions, evidence collection limits, errors and budgets are recorded in the optional-review summary above. Proposed verification steps have not been executed by this scanner.")]
        for item in judge.get("assessments", []):
            story.append(para("Finding review: " + str(item.get("finding_id", item.get("id", ""))), "sub"))
            for key, value in item.items():
                if key not in {"finding_id", "id", "recommended_actions"}:
                    story.append(para(key.replace("_", " ").capitalize() + ": " + (value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)), "small"))
            story += proposed_actions(item.get("recommended_actions"))
        concern_actions = {item["concern_index"]: item["recommended_actions"] for item in judge.get("additional_concern_actions", [])}
        for index, item in enumerate(judge.get("additional_concerns", []), 1):
            story.append(para("Additional model concern - unverified", "sub"))
            if isinstance(item, dict):
                for key, value in item.items():
                    story.append(para(key.replace("_", " ").capitalize() + ": " + (value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)), "small"))
            else:
                story.append(para(str(item), "small"))
            story += proposed_actions(concern_actions.get(index))
        for control in analyst.get("control_assessments", []):
            story += [para(str(control.get("control_id", "")) + " / Advisory check review: " + str(control.get("review_status", "unknown")), "sub")]
            for check in control.get("check_assessments", []):
                block = [para("Check {} / {}".format(check.get("check_index", ""), check.get("status", "unknown")), "sub"),
                         para(check.get("reason", "No reason supplied."), "small")]
                if check.get("status") in {"justified", "disabled"}:
                    block.append(para("Human disposition; excluded from optional review, not a model-verified pass.", "small"))
                elif not check.get("model_supplied", False):
                    block.append(para("No model assessment was received for this check.", "small"))
                else:
                    block.append(para("Model supplied this advisory interpretation.", "small"))
                for citation in check.get("citations", []):
                    block += [para("Evidence {} / {}:{}-{}".format(citation.get("evidence_id", ""), citation.get("path", ""), citation.get("start_line", ""), citation.get("end_line", "")), "small"),
                              para("Quoted excerpt: " + str(citation.get("quote", "")), "small")]
                for step in check.get("verification_steps", []):
                    block.append(para("Verification still required: " + str(step), "small"))
                story.append(KeepTogether(block))
                story += proposed_actions(check.get("recommended_actions"))
    story += [PageBreak(), heading("Coverage gaps and required validation", "gaps")]
    gaps = list(report.get("coverage", {}).get("errors", [])) + [item for item in report.get("coverage", {}).get("skipped", []) if item.get("coverage_gap")]
    if not gaps:
        story.append(para("No operational gap was recorded within the selected scope. Unsupported runtime properties still require their own checks."))
    for gap in gaps:
        story.append(para(json.dumps(gap, ensure_ascii=True, sort_keys=True), "small"))
    review_start = len(story)
    story += [PageBreak(), heading("Interactive review workspace", "review"),
              para("Every bound item below remains tied to its original evidence. Blank means unreviewed. Any nonblank decision requires a reason; justified/disabled also require a reviewer. Coverage gaps cannot be justified or disabled. Runtime/human decisions identify outstanding validation and are not passes."),
              para("Long fields scroll in compatible PDF viewers. Save with regenerated appearances. If your editor flattens the form or cannot preserve it, use the JSON review workspace instead.", "small")]
    for index, item in enumerate(workspace["items"]):
        story += [ReviewCard(index, item), Spacer(1, 12)]
    review_story = story[review_start:]
    del story[review_start:]
    story += [PageBreak(), heading("Control checklist and evidence requirements", "controls")]
    for control in report.get("controls", []):
        block = [para(control["id"] + " / " + control["title"], "sub", bookmark_key("control", control["id"])),
                  para("Scanner status: " + str(control.get("status", "unknown")) + " | validation: " + str(control.get("validation", "")), "small")]
        dispositions = {item["check_index"]: item for item in control.get("check_dispositions", [])}
        for number, check in enumerate(control.get("checks", []), 1):
            block.append(para(str(number) + ". " + str(check), "small"))
            review_id = "check:" + control["id"] + ":" + str(number)
            if review_id in review_by_id:
                block.append(internal_link(bookmark_key("review", review_id), "Record review for " + control["id"] + ":" + str(number)))
            disposition = dispositions.get(number, {})
            if disposition.get("status") in {"justified", "disabled"}:
                block.append(para("Human disposition: " + disposition["status"] + " | Reason: " + disposition.get("reason", ""), "small"))
        for url in control.get("sources", []):
            link = source_link(url)
            if link is not None:
                block.append(link)
        story.append(KeepTogether(block))
    policy = report.get("review_policy", {})
    imported = report.get("review_import", {})
    if policy.get("enabled") or imported.get("enabled"):
        story += [PageBreak(), heading("User decisions and imported review audit", "decisions"),
                  para("Justified and disabled items are human exceptions, not passes. Rule and individual-finding decisions may waive the corresponding finding gate; control/check decisions only change checklist review scope. Scan errors and coverage gaps remain unresolved.")]
        if policy.get("enabled"):
            counts = policy.get("counts", {})
            rows = [(label, str(counts.get("active_" + name, 0)), str(counts.get("justified_" + name, 0)), str(counts.get("disabled_" + name, 0)))
                    for label, name in (("Rules", "rules"), ("Controls", "controls"), ("Acceptance checks", "checks"))]
            story += [data_table(["Scope", "Active", "Justified", "Disabled"], rows, [174, 111, 111, 111]),
                      para("Mixed fully excepted controls and exact catalog counts remain in the complete accounting below. Exceptions contribute neither positive nor negative credit.", "small"),
                      para("Policy SHA-256: " + str(policy.get("sha256", "not recorded")), "small")]
            for scope, entries in sorted(policy.get("entries", {}).items()):
                for identifier, entry in sorted(entries.items()):
                    story += [para(str(scope) + " / " + str(identifier) + " / " + str(entry.get("status", "unknown")), "sub"),
                              para("Reason: " + str(entry.get("reason", "No reason recorded.")), "small")]
                    for field, value in sorted(entry.items()):
                        if field not in {"status", "reason"}:
                            story.append(para(field.replace("_", " ").capitalize() + ": " + readable(value), "small"))
            story += [para("Complete policy accounting", "sub"), data_table(["Count", "Recorded value"], configuration_rows(counts), [310, 197])]
        if imported.get("enabled"):
            story += [para("Imported review / " + str(imported.get("status", "unknown")), "sub"),
                      para("Previous scan: " + str(imported.get("origin_scan_id", "not recorded")) + " | Input SHA-256: " + str(imported.get("source_sha256", "not recorded")), "small"),
                      para("Only matching current evidence receives an eligible disposition. Missing detections are not proof of a fix; stale, out-of-scope and pending validation records remain explicit.", "small")]
            for field, title in (("applied", "Applied to matching evidence"), ("stale", "Stale evidence or catalog"),
                                 ("not_redetected", "Not redetected; remediation not established"), ("out_of_scope", "Outside current scope"),
                                 ("unresolved", "Pending review or validation")):
                entries = imported.get(field, [])
                story.append(para(title + " / " + str(len(entries)) + " records", "sub"))
                if not entries:
                    story.append(para("No records in this category.", "small"))
                for entry in entries:
                    story += [para(str(entry.get("subject", entry.get("id", "Review record"))), "sub"),
                              para("Decision: " + str(entry.get("decision", "unreviewed")) + " | Item: " + str(entry.get("id", "")), "small"),
                              para("Prior reason: " + str(entry.get("reason", "No reason recorded.")), "small")]
                    for name, value in sorted(entry.items()):
                        if name not in {"id", "subject", "decision", "reason"}:
                            story.append(para(name.replace("_", " ").capitalize() + ": " + readable(value), "small"))
            if imported.get("counts"):
                story += [para("Import accounting", "sub"), data_table(["Count", "Recorded value"], configuration_rows(imported["counts"]), [310, 197])]
    story += configuration_story + rule_inventory + review_story
    raw = io.BytesIO()
    document = Document(raw, pagesize=(595.276, 841.89), leftMargin=44, rightMargin=44, topMargin=66, bottomMargin=50,
                        title="Invarune | Evidence-bound agent and MCP security review", author="NimeshBuild")
    document.addPageTemplates(PageTemplate(id="report", frames=[Frame(44, 50, 507, 726, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=frame))
    document.multiBuild(story, canvasmaker=lambda *a, **kw: canvas.Canvas(*a, **{**kw, "invariant": 1}))
    writer = pypdf.PdfWriter()
    writer.clone_document_from_reader(pypdf.PdfReader(io.BytesIO(raw.getvalue())))
    # ReportLab's appearance escaper assumes Latin-1; generate Western Unicode
    # prefills and their canonical appearances through pypdf instead.
    prefills = {"ivr.{}.{}".format(index, field): item[field]
                for index, item in enumerate(workspace["items"])
                for field in FIELDS if field != "decision" and item.get(field)}
    if prefills:
        writer.update_page_form_field_values(None, prefills, auto_regenerate=False)
    writer.add_attachment(CAPSULE_NAME, capsule)
    serialized_report = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    if len(serialized_report) <= MAX_CAPSULE_BYTES:
        writer.add_attachment("invarune-report.json", serialized_report)
    result = io.BytesIO()
    writer.write(result)
    data = result.getvalue()
    # Reopen before publishing: field completeness and visible/logical agreement
    # are part of export validation, not just an import-time assumption.
    extracted = extract_review_workspace(data)
    if extracted != workspace:
        raise ValueError("Rendered PDF review fields differ from the embedded workspace")
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in [path.parent, *path.parent.parents]):
        raise ValueError("PDF output must not traverse symbolic links")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".invarune-pdf-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def render_pdf(report, path):
    """Export safely; optional library/layout failures use the CLI error boundary."""
    try:
        return _render_pdf(report, path)
    except (ValueError, OSError):
        raise
    except Exception as exc:
        raise ValueError("PDF export could not be completed ({})".format(type(exc).__name__)) from exc
