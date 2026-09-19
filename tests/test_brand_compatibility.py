"""Product display branding must preserve machine identities and old baselines."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan import DISPLAY_NAME, __version__
from ai_security_scan.cli import main
from ai_security_scan.image_scan import scan_image
from ai_security_scan.report import markdown, sarif
from ai_security_scan.scanner import scan
from tests.image_fixtures import docker_archive


class BrandCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def assert_branded_report(self, report, expected_id):
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["tool"]["name"], "agent-mcp-security-scan")
        self.assertEqual(report["tool"]["display_name"], "Invarune by NimeshBuild")
        self.assertEqual(report["tool"]["version"], __version__)
        self.assertTrue(markdown(report).startswith("# Invarune by NimeshBuild\n"))
        self.assertEqual([(item["rule_id"], item["id"]) for item in report["findings"]], [("AI003", expected_id)])
        self.assertEqual(report["findings"][0]["status"], "suppressed")
        self.assertEqual(report["summary"]["open_findings"], 0)
        self.assertEqual(report["coverage"]["unmatched_baseline_ids"], [])
        run = sarif(report)["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "agent-mcp-security-scan")
        self.assertEqual(run["tool"]["driver"]["fullName"], DISPLAY_NAME)
        self.assertEqual(run["results"][0]["partialFingerprints"], {"agentMcpScan/v1": expected_id})
        self.assertEqual(run["results"][0]["suppressions"][0]["status"], "accepted")

    def test_source_brand_preserves_pre_brand_finding_and_baseline(self):
        # Recorded with v0.4.1, before display branding was introduced. This
        # compatibility check intentionally does not derive its expected hash
        # from the current implementation.
        identifier = "f71579e9e11dbdd58ed0a80c"
        report = scan(self.source, baseline={identifier: "Previously reviewed source fixture"})
        self.assert_branded_report(report, identifier)

    def test_image_brand_preserves_pre_brand_finding_and_baseline(self):
        identifier = "e0b70ef00c9b88425b594985"  # Recorded with v0.4.1.
        archive = self.base / "image.tar"
        docker_archive(archive, [[("app/agent.py", "import os\nos.system(user_input)\n")]],
                       config={"config": {"User": "1000"}})
        with scan_image(archive=archive, baseline={identifier: "Previously reviewed image fixture"}) as (report, _):
            self.assert_branded_report(report, identifier)

    def test_reports_without_additive_display_metadata_still_render(self):
        report = scan(self.source)
        del report["tool"]["display_name"]
        self.assertTrue(markdown(report).startswith("# Invarune by NimeshBuild\n"))
        driver = sarif(report)["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "agent-mcp-security-scan")
        self.assertEqual(driver["fullName"], DISPLAY_NAME)

    def test_primary_and_legacy_invocations_have_equivalent_reference_and_bare_version(self):
        references = []
        for command in ("invarune", "ai-security-scan"):
            for flag in ("-h", "--help", "--version"):
                stdout, stderr = io.StringIO(), io.StringIO()
                with self.subTest(command=command, flag=flag), \
                     mock.patch("sys.argv", [command, flag]), \
                     mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("No scan")), \
                     mock.patch("subprocess.Popen", side_effect=AssertionError("No subprocess")), \
                     mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("No network")), \
                     contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as exit_state:
                        main()
                    self.assertEqual(exit_state.exception.code, 0)
                self.assertEqual(stderr.getvalue(), "")
                if flag == "--version":
                    self.assertEqual(stdout.getvalue(), __version__ + "\n")
                else:
                    self.assertIn("usage: " + command + " ", stdout.getvalue())
                    self.assertIn("compatible legacy alias", stdout.getvalue())
                    self.assertIn("invarune --image-archive", stdout.getvalue())
                    self.assertIn("Custom JSON gateway configuration:", stdout.getvalue())
                    references.append(stdout.getvalue().split(DISPLAY_NAME, 1)[1])
        self.assertTrue(all(value == references[0] for value in references))
