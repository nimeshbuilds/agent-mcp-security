"""Image configuration, retained-layer exposure, and metadata inventory tests."""
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_security_scan.image_assessment import assess_image


class ImageAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Match scan_image's canonical private workspace. Windows TEMP may use
        # an 8.3 alias; the portable confined reader rejects unresolved aliases.
        self.work = Path(self.tmp.name).resolve()
        self.root = self.work / "rootfs"
        self.root.mkdir()
        self.materialized = {"root": self.root, "config": {"config": {"User": "1001:1001"}},
                             "identity": {"format": "oci", "config_digest": "sha256:" + "a" * 64,
                                          "platform": "linux/amd64", "layers": ["sha256:" + "b" * 64]},
                             "entries": [], "layer_files": [], "coverage": {}}

    def add_file(self, path, data, mode=0o644, layer=0):
        if isinstance(data, str):
            data = data.encode("utf-8")
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entry = {"path": path, "kind": "file", "mode": mode, "uid": 0, "gid": 0,
                 "size": len(data), "layer": layer, "sha256": hashlib.sha256(data).hexdigest()}
        self.materialized["entries"].append(entry)
        return entry

    def add_layer(self, path, data, layer=0):
        if isinstance(data, str):
            data = data.encode("utf-8")
        blob = self.work / ("layer-%s-%s" % (layer, len(self.materialized["layer_files"])))
        blob.write_bytes(data)
        entry = {"path": path, "layer": layer, "sha256": hashlib.sha256(data).hexdigest(),
                 "blob_path": blob, "size": len(data)}
        self.materialized["layer_files"].append(entry)
        return entry

    def run_scan(self, **kwargs):
        return assess_image(self.materialized, **kwargs)

    def test_metadata_only_image_is_valid_without_source(self):
        result = self.run_scan()
        self.assertFalse(result["coverage"]["errors"])
        self.assertFalse(result["findings"])
        self.assertIn(".image-metadata/config.json", result["evidence_files"])
        self.assertFalse(result["inventory"]["package_inventory_is_cve_scan"])

    def test_portable_read_fallback_inspects_metadata_and_retained_revisions(self):
        self.add_file("etc/passwd", "service:x:0:1000:service:/app:/bin/false\n")
        self.materialized["config"]["config"]["User"] = "service"
        self.add_layer("app/old.py", 'API_KEY = "syntheticPortableRetainedCredential012345"\n')
        with patch("ai_security_scan.fs.os.supports_dir_fd", set()):
            result = self.run_scan()
        self.assertFalse(result["coverage"]["errors"])
        self.assertEqual({item["rule_id"] for item in result["findings"]}, {"AI021", "AI010"})
        self.assertEqual(result["coverage"]["counters"]["retained_layer_revisions_checked"], 1)

    def test_default_and_explicit_root_variants_are_identified(self):
        for value in ("", "root", "root:root", "0", "0:1000", "0000:group"):
            with self.subTest(user=value):
                self.materialized["config"]["config"]["User"] = value
                result = self.run_scan()
                findings = result["findings"]
                self.assertEqual([item["rule_id"] for item in findings], ["AI021"])
                self.assertEqual(findings[0]["image_context"], "runtime_configuration")
                self.assertIn("override", findings[0]["description"])

    def test_named_user_resolves_uid_from_image_passwd(self):
        self.add_file("etc/passwd", "service:x:0:1000:service:/app:/bin/false\napp:x:1000:1000:app:/app:/bin/false\n")
        self.materialized["config"]["config"]["User"] = "service"
        self.assertEqual(self.run_scan()["findings"][0]["image_provenance"]["resolution"], "named_user_uid_zero")
        self.materialized["config"]["config"]["User"] = "app"
        self.assertFalse(self.run_scan()["findings"])
        self.materialized["config"]["config"]["User"] = "missing"
        self.assertEqual(self.run_scan()["inventory"]["runtime"]["user_assessment"], "named_user_unresolved")

    def test_root_name_with_explicit_nonzero_passwd_uid_is_respected(self):
        self.add_file("etc/passwd", "root:x:1001:1001:renamed user:/app:/bin/false\n")
        self.materialized["config"]["config"]["User"] = "root"
        result = self.run_scan()
        self.assertFalse(result["findings"])
        self.assertEqual(result["inventory"]["runtime"]["user_assessment"], "named_user_nonzero_uid")

    def test_config_secrets_are_detected_and_reports_redacted(self):
        secret = "local-image-test-secret-4827"
        self.materialized["config"]["config"].update(Env=["API_KEY=" + secret], Labels={"client_secret": secret})
        result = self.run_scan()
        self.assertEqual(sum(item["rule_id"] == "AI010" for item in result["findings"]), 2)
        self.assertNotIn(secret, json.dumps({key: value for key, value in result.items() if key != "evidence_files"}))
        self.assertIn(secret.encode(), result["evidence_files"][".image-metadata/environment/000000.json"])

    def test_placeholder_secret_and_duplicate_env_entries(self):
        self.materialized["config"]["config"]["Env"] = ["API_KEY=placeholder", "API_KEY=local-image-realistic-5678", "API_KEY=${SECRET}"]
        result = self.run_scan()
        self.assertEqual([item["path"] for item in result["findings"]], [".image-metadata/environment/000001.json"])
        self.assertEqual(len(result["inventory"]["runtime"]["environment_names"]), 3)

    def test_command_bypass_and_dangerous_env_detected(self):
        self.materialized["config"]["config"].update(Entrypoint=["agent", "--dangerously-skip-permissions"],
                                                    Env=["DANGEROUSLY_OMIT_AUTH=true", "NODE_TLS_REJECT_UNAUTHORIZED=0"])
        result = self.run_scan()
        self.assertEqual({item["rule_id"] for item in result["findings"]}, {"AI031", "AI041", "AI006"})
        self.assertTrue(all(item["image_context"] == "runtime_configuration" for item in result["findings"]))

    def test_labels_do_not_turn_text_configuration_into_runtime_findings(self):
        self.materialized["config"]["config"]["Labels"] = {"documentation": "agent --yolo", "auth": False, "privileged": True}
        self.assertFalse(self.run_scan()["findings"])

    def test_build_history_preserves_historical_provenance(self):
        self.materialized["config"]["history"] = [
            {"created_by": "/bin/sh -c curl https://example.test/install | sh"},
            {"created_by": "/bin/sh -c #(nop) ENV API_KEY=history-secret-482927", "empty_layer": True},
            {"created_by": "agent --yolo"}]
        result = self.run_scan()
        self.assertEqual({item["rule_id"] for item in result["findings"]}, {"AI019", "AI010", "AI031"})
        for item in result["findings"]:
            self.assertEqual(item["image_context"], "build_history")
            self.assertIn("not a statement about current runtime", item["description"])
        secret = next(item for item in result["findings"] if item["rule_id"] == "AI010")
        self.assertTrue(secret["image_provenance"]["empty_layer"])
        self.assertNotIn("layer_index", secret["image_provenance"])
        self.assertNotIn("history-secret-482927", json.dumps(result["findings"]))

    def test_history_legacy_env_and_quoted_values(self):
        self.materialized["config"]["history"] = [{"created_by": "ENV API_KEY quoted-long-secret"},
                                                  {"created_by": 'ARG PASSWORD="quoted password value"'}]
        self.assertEqual([item["rule_id"] for item in self.run_scan()["findings"]].count("AI010"), 2)

    def test_retained_layer_secrets_have_exposure_provenance(self):
        self.add_layer("app/deleted.py", 'API_KEY = "deleted-secret-4827"\neval(user_input)\n', layer=0)
        result = self.run_scan()
        self.assertEqual([item["rule_id"] for item in result["findings"]], ["AI010"])
        item = result["findings"][0]
        self.assertEqual(item["image_context"], "retained_layer")
        self.assertEqual(item["image_provenance"]["original_path"], "app/deleted.py")
        self.assertFalse(item["image_provenance"]["present_in_final_filesystem"])
        self.assertNotIn(str(self.work), json.dumps({key: value for key, value in result.items() if key != "evidence_files"}))

    def test_current_layer_revision_is_left_to_source_scanner(self):
        text = 'API_KEY = "current-secret-4827"\n'
        self.add_file("app/main.py", text, layer=1)
        self.add_layer("app/main.py", text, layer=1)
        result = self.run_scan()
        self.assertFalse(result["findings"])
        self.assertEqual(result["coverage"]["counters"]["retained_layer_revisions_checked"], 0)

    def test_overwritten_revision_not_only_deleted_file_is_assessed(self):
        self.add_file("app/.env", "API_KEY=${LIVE_SECRET}\n", layer=2)
        self.add_layer("app/.env", "API_KEY=overwritten-secret-4827\n", layer=1)
        self.assertEqual(self.run_scan()["findings"][0]["rule_id"], "AI010")

    def test_deleted_non_secret_unsafe_source_has_no_live_finding(self):
        self.add_layer("app/unsafe.py", "import os\nos.system(user_input)\n")
        self.add_layer("app/config.json", '{"privileged": true, "auth": false}')
        self.assertFalse(self.run_scan()["findings"])

    def test_private_key_and_url_credential_retained_exposure(self):
        self.add_layer("gone.pem", "-----BEGIN PRIVATE KEY-----\nsample-test-data\n-----END PRIVATE KEY-----")
        self.add_layer("gone.txt", "https://example.test/?access_token=retained-secret-4827")
        self.assertEqual({item["rule_id"] for item in self.run_scan()["findings"]}, {"AI011", "AI034"})

    def test_binary_non_utf8_and_large_retained_files_are_gaps(self):
        self.add_layer("binary", b"\x00data")
        self.add_layer("badencoding", b"\xffdata")
        self.add_layer("large", b"x" * 600)
        result = self.run_scan(max_file_bytes=500)
        self.assertEqual({item["reason"] for item in result["coverage"]["skipped"]},
                         {"image_metadata_binary_content", "image_metadata_non_utf8_content", "image_metadata_file_size_limit"})
        self.assertFalse(result["coverage"]["errors"])

    def test_opaque_binary_scope_and_corrupt_text_are_distinguished(self):
        self.add_layer("bin/helper", b"\x00compiled")
        self.add_layer("app/secret.env", b"\xffinvalid")
        result = self.run_scan()
        skips = {item["path"]: item for item in result["coverage"]["skipped"]}
        self.assertFalse(skips["bin/helper"]["coverage_gap"])
        self.assertTrue(skips["app/secret.env"]["coverage_gap"])
        self.assertFalse(result["inventory"]["binary_logic_analyzed"])
        self.assertFalse(result["inventory"]["binary_secret_engine_enabled"])

    def test_metadata_record_limit_is_explicit(self):
        self.materialized["config"]["config"]["Env"] = ["ITEM_%s=value" % index for index in range(10)]
        with patch("ai_security_scan.image_assessment._MAX_METADATA_RECORDS", 3):
            result = self.run_scan()
        self.assertLessEqual(result["coverage"]["counters"]["metadata_records_considered"], 3)
        self.assertLessEqual(len(result["evidence_files"]), 3)
        self.assertIn("image_metadata_record_limit", {item["reason"] for item in result["coverage"]["skipped"]})

    def test_package_inventory_count_is_bounded(self):
        self.add_file("lib/apk/db/installed", "\n\n".join("P:package%s\nV:1.0" % index for index in range(5)))
        with patch("ai_security_scan.image_assessment._MAX_METADATA_RECORDS", 2):
            result = self.run_scan()
        self.assertEqual(len(result["inventory"]["packages"]), 2)
        self.assertIn("image_package_inventory_record_limit", {item["reason"] for item in result["coverage"]["skipped"]})

    def test_total_byte_budget_is_enforced(self):
        self.add_layer("a.env", "API_KEY=budget-secret-4827")
        self.add_layer("b.env", "API_KEY=budget-secret-9482")
        result = self.run_scan(max_total_bytes=60)
        self.assertLessEqual(result["coverage"]["counters"]["bytes_charged"], 60)
        self.assertIn("image_metadata_total_byte_limit", {item["reason"] for item in result["coverage"]["skipped"]})

    def test_read_failure_is_bounded_and_reported(self):
        self.add_layer("a.env", "API_KEY=budget-secret-4827")
        with patch("ai_security_scan.image_assessment.read_confined", side_effect=OSError):
            result = self.run_scan()
        self.assertTrue(result["coverage"]["errors"])
        self.assertGreater(result["coverage"]["counters"]["bytes_charged"], 20)
        self.assertFalse(result["findings"])

    def test_retained_symlink_cannot_read_host_file(self):
        host = self.work / "host-secret"
        host.write_text("API_KEY=host-secret-4827")
        link = self.work / "blob-link"
        try:
            link.symlink_to(host)
        except OSError:
            self.skipTest("Symlink creation unavailable")
        self.materialized["layer_files"].append({"path": "old.env", "layer": 0, "sha256": "a" * 64, "blob_path": link})
        result = self.run_scan()
        self.assertFalse(result["findings"])
        self.assertEqual(result["coverage"]["skipped"][0]["reason"], "image_metadata_non_regular_file")

    def test_permission_signals_are_not_new_vulnerability_rules(self):
        self.add_file("bin/helper", b"\x00compiled", mode=0o4755)
        self.add_file("app/state", "", mode=0o2666)
        result = self.run_scan()
        self.assertFalse(result["findings"])
        self.assertEqual([item["signals"] for item in result["inventory"]["permission_review_signals"]],
                         [["setgid", "world_writable"], ["setuid"]])

    def test_os_release_is_text_not_executable_shell(self):
        sentinel = self.work / "must-not-exist"
        self.add_file("etc/os-release", 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="$(touch %s)"\n' % sentinel)
        self.add_file("usr/lib/os-release", "ID=vendor\n")
        result = self.run_scan()
        self.assertEqual(result["inventory"]["os_release"]["fields"]["ID"], "debian")
        self.assertFalse(sentinel.exists())

    def test_package_inventory_is_observed_installed_metadata(self):
        self.add_file("var/lib/dpkg/status", "Package: curl\nVersion: 8.0-1\nArchitecture: amd64\nStatus: install ok installed\n\nPackage: removed\nVersion: 1.0\nStatus: deinstall ok config-files\n")
        self.add_file("lib/apk/db/installed", "P:busybox\nV:1.36.1-r1\nA:x86_64\n")
        self.add_file("usr/lib/python3.12/site-packages/mcp-1.0.dist-info/METADATA", "Metadata-Version: 2.3\nName: mcp\nVersion: 1.0\n")
        self.add_file("app/node_modules/@sdk/mcp/package.json", '{"name":"@sdk/mcp","version":"2.0.0","dependencies":{"foo":"*"}}')
        result = self.run_scan()
        self.assertEqual({item["ecosystem"] for item in result["inventory"]["packages"]}, {"dpkg", "apk", "python", "npm"})
        self.assertEqual(len(result["inventory"]["packages"]), 4)
        self.assertFalse(result["findings"])
        self.assertTrue(all("not assessed" in item["assessment"] for item in result["inventory"]["packages"]))

    def test_invalid_package_metadata_does_not_crash(self):
        self.add_file("app/package.json", '{"name":')
        result = self.run_scan()
        self.assertEqual(result["coverage"]["errors"][0]["path"], "app/package.json")

    def test_nullable_config_fields_are_valid(self):
        self.materialized["config"]["config"].update(Env=None, Labels=None, Entrypoint=None, Cmd=None)
        self.materialized["config"]["history"] = None
        self.assertFalse(self.run_scan()["coverage"]["errors"])

    def test_malformed_metadata_is_explicitly_unassessed(self):
        self.materialized["config"]["config"].update(Env=[None, "NOT_AN_ASSIGNMENT"], Labels=[], Entrypoint=[3], User=42)
        self.materialized["config"]["history"] = [None]
        result = self.run_scan()
        self.assertTrue(result["coverage"]["errors"])
        self.assertGreaterEqual(len(result["coverage"]["skipped"]), 3)

    def test_repeated_assessment_is_deterministic(self):
        self.add_file("app/package.json", '{"name":"test","version":"1.0.0"}')
        self.add_layer("secret.env", "API_KEY=deterministic-secret-4827")
        self.assertEqual(self.run_scan(), self.run_scan())

    def test_limits_are_positive_integers(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_scan(max_file_bytes=value)


if __name__ == "__main__":
    unittest.main()
