"""Interactive PDF truth comes from canonical fields plus verified appearances."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zlib

from ai_security_scan import report_pdf

HAS_PDF = all(importlib.util.find_spec(name) is not None for name in ("reportlab", "pypdf"))


class OptionalPDFDependencyTests(unittest.TestCase):
    def test_dependency_failure_is_a_clear_operational_error(self):
        real_import = __import__

        def imported(name, *args, **kwargs):
            if name == "pypdf":
                raise ImportError("fixture")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=imported):
            with self.assertRaisesRegex(ValueError, r"\[pdf\]"):
                report_pdf.extract_review_workspace(b"%PDF-1.7")


@unittest.skipUnless(HAS_PDF, "Optional PDF extra is not installed")
class PDFReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pypdf
        from ai_security_scan.scanner import scan
        from ai_security_scan.review_workspace import build_workspace
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name).resolve()
        source = cls.root / "source"
        source.mkdir()
        (source / "agent.py").write_text("eval(user_input)\n", encoding="utf-8")
        cls.report = scan(source)
        cls.report["controls"] = cls.report["controls"][:1]
        cls.report["review_workspace"] = build_workspace(cls.report)
        cls.path = cls.root / "review.pdf"
        report_pdf.render_pdf(cls.report, cls.path)
        cls.data = cls.path.read_bytes()
        cls.pypdf = pypdf

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def rewrite(self, edit):
        writer = self.pypdf.PdfWriter()
        writer.clone_document_from_reader(self.pypdf.PdfReader(io.BytesIO(self.data)))
        edit(writer)
        output = io.BytesIO()
        writer.write(output)
        return output.getvalue()

    def first_field(self, writer, suffix="reason"):
        return next(ref.get_object() for ref in writer.root_object["/AcroForm"]["/Fields"]
                    if str(ref.get_object().get("/T", "")) == "ivr.0." + suffix)

    def test_render_roundtrip_keeps_origin_bindings_and_all_editable_fields(self):
        workspace = report_pdf.extract_review_workspace(self.data)
        self.assertEqual(workspace, self.report["review_workspace"])
        reader = self.pypdf.PdfReader(io.BytesIO(self.data))
        self.assertEqual(len(reader.get_fields()), len(workspace["items"]) * 5)
        self.assertEqual(sum(1 for page in reader.pages for ref in page.get("/Annots", [])
                             if ref.get_object().get("/Subtype") == "/Widget"), len(workspace["items"]) * 5)
        self.assertGreater(len(reader.outline), 5)
        self.assertIn(report_pdf.CAPSULE_NAME, reader.attachments)

    def test_user_edits_roundtrip_with_regenerated_appearances(self):
        values = {"ivr.0.decision": "justified", "ivr.0.reason": "Reviewed fixture.\nTrusted input is isolated.",
                  "ivr.0.reviewer": "Security reviewer", "ivr.0.reviewed_at": "2026-09-19", "ivr.0.evidence_ref": "TICKET-42"}
        changed = self.rewrite(lambda writer: writer.update_page_form_field_values(None, values, auto_regenerate=False))
        workspace = report_pdf.extract_review_workspace(changed)
        for field in report_pdf.FIELDS:
            self.assertEqual(workspace["items"][0][field], values["ivr.0." + field])
        self.assertEqual(workspace["origin"], self.report["review_workspace"]["origin"])

    def test_repeated_exports_are_byte_identical(self):
        other = self.root / "repeated.pdf"
        report_pdf.render_pdf(self.report, other)
        self.assertEqual(self.data, other.read_bytes())

    def test_western_unicode_field_roundtrip_and_nonwestern_prefill_limit(self):
        values = {"ivr.0.decision": "note", "ivr.0.reason": "Données vérifiées - coût €12", "ivr.0.reviewer": "Anaïs"}
        changed = self.rewrite(lambda writer: writer.update_page_form_field_values(None, values, auto_regenerate=False))
        result = report_pdf.extract_review_workspace(changed)
        self.assertEqual(result["items"][0]["reason"], values["ivr.0.reason"])
        self.assertEqual(result["items"][0]["reviewer"], "Anaïs")
        reviewed = copy.deepcopy(self.report)
        reviewed["review_workspace"] = result
        target = self.root / "western-prefill.pdf"
        report_pdf.render_pdf(reviewed, target)
        self.assertEqual(report_pdf.extract_review_workspace(target.read_bytes()), result)
        bad = copy.deepcopy(self.report)
        bad["review_workspace"]["items"][0]["reason"] = "確認"
        with self.assertRaisesRegex(ValueError, "Unicode review text using JSON"):
            report_pdf.render_pdf(bad, self.root / "unsupported-prefill.pdf")

    def test_canonical_value_change_without_appearance_update_is_rejected(self):
        from pypdf.generic import NameObject, TextStringObject
        changed = self.rewrite(lambda writer: self.first_field(writer).__setitem__(NameObject("/V"), TextStringObject("Hidden edit")))
        with self.assertRaisesRegex(ValueError, "appearance is stale"):
            report_pdf.extract_review_workspace(changed)

    def test_appearance_change_without_canonical_update_is_rejected(self):
        from pypdf.generic import NameObject, DecodedStreamObject

        def edit(writer):
            field = self.first_field(writer)
            old = field["/AP"]["/N"].get_object()
            stream = DecodedStreamObject()
            stream.set_data(b"BT /Helv 10 Tf (Hidden edit) Tj ET")
            stream[NameObject("/Resources")] = old["/Resources"]
            stream[NameObject("/BBox")] = old["/BBox"]
            field["/AP"][NameObject("/N")] = writer._add_object(stream)

        with self.assertRaisesRegex(ValueError, "appearance is stale"):
            report_pdf.extract_review_workspace(self.rewrite(edit))

    def test_invisible_appearance_text_and_degenerate_geometry_are_rejected(self):
        from pypdf.generic import ArrayObject, DecodedStreamObject, NameObject, NumberObject

        def appearance(writer, operator):
            writer.update_page_form_field_values(None, {"ivr.0.reason": "Visible decision evidence"}, auto_regenerate=False)
            field = self.first_field(writer)
            old = field["/AP"]["/N"].get_object()
            stream = DecodedStreamObject()
            for key, value in old.items():
                if key not in {"/Filter", "/Length", "/DecodeParms"}:
                    stream[key] = value
            stream.set_data(old.get_data().replace(b"BT", b"BT\n" + operator, 1))
            field["/AP"][NameObject("/N")] = writer._add_object(stream)

        for operator in (b"3 Tr", b"0 0 0 0 0 0 Tm", b"0.01 0 0 .01 0 0 cm", b"/Helv 0 Tf"):
            with self.subTest(operator=operator), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(lambda writer: appearance(writer, operator)))
        for coordinates in ([0, 0, 0, 0], [900, 900, 950, 950]):
            with self.subTest(rectangle=coordinates), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(lambda writer: self.first_field(writer).__setitem__(NameObject("/Rect"), ArrayObject([NumberObject(x) for x in coordinates]))))

    def test_gap_dropdown_cannot_offer_exemptions(self):
        from ai_security_scan.review_workspace import build_workspace
        report = copy.deepcopy(self.report)
        report["coverage"]["errors"].append({"error": "fixture runtime evidence gap", "path": "agent.py"})
        report["review_workspace"] = build_workspace(report)
        target = self.root / "gap.pdf"
        report_pdf.render_pdf(report, target)
        fields = self.pypdf.PdfReader(target).get_fields()
        indexes = [index for index, item in enumerate(report["review_workspace"]["items"]) if item["kind"] == "gap"]
        self.assertTrue(indexes)
        for index in indexes:
            options = fields["ivr.{}.decision".format(index)]["/Opt"]
            self.assertNotIn("justified", options)
            self.assertNotIn("disabled", options)

    def test_generator_layout_errors_and_unavailable_capsules_are_operational(self):
        from reportlab.platypus.doctemplate import LayoutError
        with mock.patch.object(report_pdf, "_render_pdf", side_effect=LayoutError("fixture")):
            with self.assertRaisesRegex(ValueError, "LayoutError"):
                report_pdf.render_pdf(self.report, self.root / "layout.pdf")
        bad = copy.deepcopy(self.report)
        bad["workspace_unavailable"] = {"reason": "fixture item bound"}
        with self.assertRaisesRegex(ValueError, "workspace"):
            report_pdf.render_pdf(bad, self.root / "unavailable.pdf")

    def test_report_configuration_posture_and_optional_coverage_use_actual_schema(self):
        report = copy.deepcopy(self.report)
        report["configuration"] = {"max_file_bytes": 98765, "exclude": ["scope-fixture"]}
        report["run_configuration"] = {"judge_max_findings": 7}
        report["image"] = {"limits": {"max_layers": 23}}
        report["assessment"] = {"posture": {"code": "review_followup_required", "title": "Fixture needs validation", "explanation": "Fixture validation explanation"}}
        report["judge"] = {"status": "completed", "selected_findings": 2, "omitted_open_findings": 9, "source_context_sent_count": 1}
        report["analyst"] = {"status": "incomplete", "coverage": {"total_checks": 132, "omitted_checks": 130}}
        target = self.root / "schema.pdf"
        report_pdf.render_pdf(report, target)
        text = " ".join(" ".join(page.extract_text().split()) for page in self.pypdf.PdfReader(target).pages)
        for term in ("Fixture needs validation", "Fixture validation explanation", "max_file_bytes: 98765", "scope-fixture", "judge_max_findings: 7", "max_layers: 23", '"selected_findings": 2', '"omitted_open_findings": 9', '"omitted_checks": 130', '"total_checks": 132'):
            self.assertIn(term, text)

    def test_missing_appearance_and_need_appearances_are_rejected(self):
        from pypdf.generic import BooleanObject, NameObject
        for edit in [lambda writer: self.first_field(writer).pop("/AP"),
                     lambda writer: writer.root_object["/AcroForm"].__setitem__(NameObject("/NeedAppearances"), BooleanObject(True))]:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(edit))

    def test_missing_duplicate_unknown_and_wrong_type_canonical_fields_are_rejected(self):
        from pypdf.generic import NameObject, TextStringObject
        edits = [lambda writer: writer.root_object["/AcroForm"]["/Fields"].pop(),
                 lambda writer: writer.root_object["/AcroForm"]["/Fields"].append(writer.root_object["/AcroForm"]["/Fields"][0]),
                 lambda writer: self.first_field(writer).__setitem__(NameObject("/T"), TextStringObject("ivr.999.reason")),
                 lambda writer: self.first_field(writer).__setitem__(NameObject("/FT"), NameObject("/Btn"))]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(edit))

    def test_orphan_and_duplicate_page_widgets_are_rejected(self):
        from pypdf.generic import DictionaryObject

        def edit(writer, duplicate):
            page = next(page for page in writer.pages if any(ref.get_object().get("/Subtype") == "/Widget" for ref in page.get("/Annots", [])))
            ref = next(ref for ref in page["/Annots"] if ref.get_object().get("/Subtype") == "/Widget")
            page["/Annots"].append(ref if duplicate else writer._add_object(DictionaryObject(ref.get_object())))

        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(lambda writer: edit(writer, duplicate)))

    def test_changed_decision_labels_are_rejected(self):
        from pypdf.generic import ArrayObject, TextStringObject

        def edit(writer):
            self.first_field(writer, "decision")["/Opt"][1] = ArrayObject([TextStringObject("justified"), TextStringObject("Needs runtime validation")])

        with self.assertRaisesRegex(ValueError, "choices or labels"):
            report_pdf.extract_review_workspace(self.rewrite(edit))

    def test_hidden_widget_and_active_form_actions_are_rejected(self):
        from pypdf.generic import DictionaryObject, NameObject, NumberObject
        edits = [lambda writer: self.first_field(writer).__setitem__(NameObject("/F"), NumberObject(2)),
                 lambda writer: self.first_field(writer).__setitem__(NameObject("/AA"), DictionaryObject({NameObject("/K"): DictionaryObject()})),
                 lambda writer: writer.root_object.__setitem__(NameObject("/OpenAction"), DictionaryObject({NameObject("/S"): NameObject("/JavaScript")}))]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(edit))

    def test_duplicate_missing_and_unexpected_capsules_are_rejected(self):
        edits = [lambda writer: writer.add_attachment(report_pdf.CAPSULE_NAME, b"{}"),
                 lambda writer: writer.root_object.pop("/Names"),
                 lambda writer: writer.add_attachment("unexpected.json", b"{}")]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(self.rewrite(edit))

    def test_capsule_json_limits_and_duplicate_keys_are_rejected(self):
        for data in [b'{"items":[],"items":[]}', b'{"items":NaN}', b'{"items":{}}', b'\xff', b'{bad']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                report_pdf._json(data)

    def test_stream_decompression_is_bounded_and_truncation_rejected(self):
        from pypdf.generic import EncodedStreamObject, NameObject
        stream = EncodedStreamObject()
        stream[NameObject("/Filter")] = NameObject("/FlateDecode")
        stream._data = zlib.compress(b"A" * 10000)
        with self.assertRaises(ValueError):
            report_pdf._stream_bytes(stream, 500)
        self.assertEqual(report_pdf._stream_bytes(stream, 10000), b"A" * 10000)
        stream._data = stream._data[:-2]
        with self.assertRaises(ValueError):
            report_pdf._stream_bytes(stream, 10000)

    def test_encrypted_malformed_and_nonbytes_inputs_are_rejected(self):
        encrypted = self.rewrite(lambda writer: writer.encrypt("fixture-password"))
        for data in [encrypted, b"not a PDF", "not bytes", b""]:
            with self.subTest(data=type(data)), self.assertRaises(ValueError):
                report_pdf.extract_review_workspace(data)

    def test_renderer_rejects_missing_workspace_and_excessive_form_values(self):
        bad = copy.deepcopy(self.report)
        bad.pop("review_workspace")
        with self.assertRaisesRegex(ValueError, "review_workspace"):
            report_pdf.render_pdf(bad, self.root / "bad.pdf")
        bad = copy.deepcopy(self.report)
        bad["review_workspace"]["items"][0]["reason"] = "x" * 8001
        with self.assertRaises(ValueError):
            report_pdf.render_pdf(bad, self.root / "bad.pdf")

    def test_pdf_contains_configuration_methodology_inventory_and_full_check_text(self):
        text = "\n".join(page.extract_text() for page in self.pypdf.PdfReader(io.BytesIO(self.data)).pages)
        for term in ["Scan configuration and scope", "Deterministic checks and optional review", "Coverage, misses and validation by area", "AI001", "AI042", "Runtime / human", "Control checklist"]:
            self.assertIn(term, text)
        for check in self.report["controls"][0]["checks"]:
            self.assertIn(" ".join(report_pdf._display(check).split()), " ".join(text.split()))

    def test_pdf_retains_advisory_findings_checks_citations_and_human_dispositions(self):
        report = copy.deepcopy(self.report)
        report["judge"] = {"enabled": True, "status": "completed", "assessments": [{"finding_id": "fixture-find", "verdict": "needs_review", "reason": "Fixture model reasoning"}], "additional_concerns": ["Fixture extra concern. Fixture concern explanation"]}
        report["analyst"] = {"enabled": True, "status": "incomplete", "coverage": {"omitted_checks": 1}, "control_assessments": [{"control_id": "GOV-01", "review_status": "not_reviewed", "check_assessments": [{"check_index": 1, "status": "partial_support", "reason": "Fixture partial evidence", "model_supplied": True, "citations": [{"evidence_id": "EV-fixture", "path": "agent.py", "start_line": 1, "end_line": 1, "quote": "fixture quoted evidence"}], "verification_steps": ["Fixture runtime experiment"]}, {"check_index": 2, "status": "insufficient_evidence", "reason": "Fixture omitted check", "model_supplied": False}]}]}
        report["controls"][0]["check_dispositions"] = [{"check_index": 1, "status": "justified", "reason": "Fixture explicit human exception"}]
        target = self.root / "advisory.pdf"
        report_pdf.render_pdf(report, target)
        text = " ".join(" ".join(page.extract_text().split()) for page in self.pypdf.PdfReader(target).pages)
        for term in ("Optional advisory review and evidence", "Fixture model reasoning", "Fixture extra concern", "Fixture concern explanation", "Fixture partial evidence", "fixture quoted evidence", "EV-fixture", "Fixture runtime experiment", "No model assessment was received", "Human disposition: justified", "Fixture explicit human exception"):
            self.assertIn(term, text)


if __name__ == "__main__":
    unittest.main()
