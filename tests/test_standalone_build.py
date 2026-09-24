"""Release integrity contracts that do not require PyInstaller during unit tests."""
import importlib.util
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load_module("standalone_build", ROOT / "scripts" / "build_standalone.py")
external = load_module("standalone_external", ROOT / "packaging" / "external_process.py")
bundled_tls = load_module("standalone_tls", ROOT / "packaging" / "bundled_tls.py")


class StandaloneBuildTests(unittest.TestCase):
    def test_inventory_order_is_identical_on_windows_and_posix(self):
        for kind, root_value in ((PurePosixPath, "/repo"), (PureWindowsPath, "C:/repo")):
            root = kind(root_value)
            paths = [root / name for name in ("a.txt", "Z.txt", "B.txt")]
            self.assertEqual([path.relative_to(root).as_posix() for path in build.portable_sorted(paths, root)],
                             ["B.txt", "Z.txt", "a.txt"])
        inventory = build.source_inventory()
        self.assertEqual([entry["path"] for entry in inventory], sorted(entry["path"] for entry in inventory))

    def test_five_native_targets_and_reject_unsupported(self):
        for system, machine, expected in [
            ("Linux", "x86_64", ("linux", "x86_64")),
            ("Linux", "aarch64", ("linux", "arm64")),
            ("Darwin", "arm64", ("macos", "arm64")),
            ("Darwin", "x86_64", ("macos", "x86_64")),
            ("Windows", "AMD64", ("windows", "x86_64")),
        ]:
            self.assertEqual(build.platform_tag(system, machine), expected)
        for system, machine in [("Windows", "ARM64"), ("Linux", "i386"), ("Plan9", "x86_64")]:
            with self.assertRaises(ValueError):
                build.platform_tag(system, machine)

    def test_archive_names_cannot_escape_output(self):
        self.assertEqual(build.archive_name("0.15.0", "linux", "arm64"), "invscan-0.15.0-linux-arm64.tar.gz")
        self.assertEqual(build.archive_name("0.15.0", "windows", "x86_64"), "invscan-0.15.0-windows-x86_64.zip")
        with self.assertRaises(ValueError):
            build.archive_name("../../escape", "linux", "arm64")

    def test_archives_preserve_root_runtime_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            distribution = directory / "invscan-0.15.0-test"
            (distribution / "_internal").mkdir(parents=True)
            (distribution / "invscan").write_bytes(b"native")
            (distribution / "_internal" / "catalog.json").write_bytes(b"{}")
            for os_name, suffix in [("linux", ".tar.gz"), ("windows", ".zip")]:
                artifact = directory / (os_name + suffix)
                build.create_archive(distribution, artifact, os_name)
                if os_name == "windows":
                    with zipfile.ZipFile(artifact) as archive:
                        names = archive.namelist()
                else:
                    with tarfile.open(artifact) as archive:
                        names = archive.getnames()
                        for member in archive.getmembers():
                            self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime),
                                             (0, 0, "", "", 0))
                self.assertIn(distribution.name + "/invscan", names)
                self.assertIn(distribution.name + "/_internal/catalog.json", names)
                with self.assertRaises(FileExistsError):
                    build.create_archive(distribution, artifact, os_name)

    def test_inventory_hashes_change_and_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "input").write_bytes(b"first")
            before = build.file_inventory(directory)
            (directory / "input").write_bytes(b"second")
            self.assertNotEqual(before[0]["sha256"], build.file_inventory(directory)[0]["sha256"])
            try:
                (directory / "escape").symlink_to(directory.parent, target_is_directory=True)
            except OSError:
                return  # Windows runners may not grant symlink creation rights.
            with self.assertRaisesRegex(ValueError, "escapes"):
                build.file_inventory(directory)

    def test_provenance_includes_source_catalog_bootstrap_lock_and_examples(self):
        inventory = {entry["path"]: entry["sha256"] for entry in build.source_inventory()}
        for required in ("ai_security_scan/scanner.py", "ai_security_scan/data/controls.json",
                         "packaging/entry.py", "packaging/external_process.py", "packaging/invscan.spec",
                         "requirements-release.txt", "examples/images/demo-agent.tar"):
            self.assertIn(required, inventory)
            self.assertEqual(len(inventory[required]), 64)
        self.assertFalse(any(path.startswith(("tmp/", ".git/")) for path in inventory))


class ExternalProcessTests(unittest.TestCase):
    def test_child_loader_paths_sanitized_without_mutating_parent_or_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            environment = {"PATH": os.pathsep.join([str(root / "bin"), str(root.parent / "tools")]),
                           "LD_LIBRARY_PATH": str(root), "LD_LIBRARY_PATH_ORIG": "/external/lib",
                           "DYLD_LIBRARY_PATH": str(root / "nested"), "SAFE": "retained"}
            original = dict(environment)
            with patch.dict(os.environ, {"SECRET_SHOULD_NOT_LEAK": "sentinel"}):
                child = external.clean_child_environment(environment, root)
            self.assertEqual(environment, original)
            self.assertEqual(child["PATH"], str(root.parent / "tools"))
            self.assertEqual(child["LD_LIBRARY_PATH"], "/external/lib")
            self.assertNotIn("DYLD_LIBRARY_PATH", child)
            self.assertNotIn("LD_LIBRARY_PATH_ORIG", child)
            self.assertNotIn("SECRET_SHOULD_NOT_LEAK", child)
            self.assertEqual(child["SAFE"], "retained")

    def test_empty_original_library_path_removed(self):
        env = {"LD_LIBRARY_PATH_ORIG": "", "LD_LIBRARY_PATH": "/bundle"}
        self.assertEqual(external.clean_child_environment(env, "/bundle"), {})

    def test_only_bootstrap_injected_ca_is_removed_from_child_environment(self):
        injected = "/bundle/cacert.pem"
        environment = {"SSL_CERT_FILE": injected, "SSL_CERT_DIR": "/enterprise/certs", "SAFE": "yes"}
        original = dict(environment)
        self.assertEqual(external.clean_child_environment(environment, "/bundle", injected),
                         {"SSL_CERT_DIR": "/enterprise/certs", "SAFE": "yes"})
        self.assertEqual(environment, original)
        # No recorded injection means a user-supplied setting, even if its path
        # happens to be inside the bundle. A changed value also remains intact.
        self.assertEqual(external.clean_child_environment(environment, "/bundle"), environment)
        environment["SSL_CERT_FILE"] = "/enterprise/roots.pem"
        self.assertEqual(external.clean_child_environment(environment, "/bundle", injected), environment)
        environment["SSL_CERT_FILE"] = ""
        self.assertEqual(external.clean_child_environment(environment, "/bundle", injected), environment)

    def test_external_process_drops_injected_ca_without_mutating_scanner(self):
        captured = []
        module = types.SimpleNamespace(Popen=lambda *args, **kwargs: captured.append(kwargs["env"]))
        facade = external.ExternalSubprocess("/bundle", module=module, injected_ca_file="/bundle/cacert.pem")
        with patch.dict(os.environ, {"SSL_CERT_FILE": "/bundle/cacert.pem"}, clear=True):
            facade.Popen(["vendor"])
            self.assertEqual(os.environ["SSL_CERT_FILE"], "/bundle/cacert.pem")
        facade.Popen(["vendor"], env={"SSL_CERT_FILE": "/enterprise/roots.pem"})
        self.assertEqual(captured, [{}, {"SSL_CERT_FILE": "/enterprise/roots.pem"}])

    def test_windows_dll_search_restored_on_success_and_failure(self):
        for fail in (False, True):
            events = []

            def dll(path):
                events.append(("dll", path))
                return 1

            def popen(*args, **kwargs):
                events.append(("spawn", kwargs["env"]))
                if fail:
                    raise OSError("spawn failed")
                return "process"

            module = types.SimpleNamespace(Popen=popen, PIPE=subprocess.PIPE)
            facade = external.ExternalSubprocess("/bundle", module=module, windows_dll=dll)
            self.assertEqual(facade.PIPE, subprocess.PIPE)
            if fail:
                with self.assertRaisesRegex(OSError, "spawn failed"):
                    facade.Popen(["vendor"], env={"SAFE": "yes"})
            else:
                self.assertEqual(facade.Popen(["vendor"], env={"SAFE": "yes"}), "process")
            self.assertEqual(events, [("dll", None), ("spawn", {"SAFE": "yes"}), ("dll", "/bundle")])

    def test_failed_dll_reset_never_spawns(self):
        def popen(*args, **kwargs):
            self.fail("Must not launch with unsafe DLL search state")
        facade = external.ExternalSubprocess("/bundle", module=types.SimpleNamespace(Popen=popen), windows_dll=lambda _: 0)
        with self.assertRaisesRegex(OSError, "reset"):
            facade.Popen(["vendor"], env={})

    def test_source_execution_does_not_replace_subprocess(self):
        from ai_security_scan import cli_judge, image_runtime
        with patch.object(external.sys, "frozen", False, create=True):
            external.install_external_process_boundary()
        self.assertIs(cli_judge.subprocess, subprocess)
        self.assertIs(image_runtime.subprocess, subprocess)

    def test_frozen_boundary_attaches_only_to_both_external_launch_modules(self):
        from ai_security_scan import cli_judge, image_runtime
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(external.sys, "frozen", True, create=True), \
                    patch.object(external.sys, "_MEIPASS", temporary, create=True), \
                    patch.object(cli_judge, "subprocess", subprocess), \
                    patch.object(image_runtime, "subprocess", subprocess):
                external.install_external_process_boundary(injected_ca_file="/bundle/cacert.pem")
                self.assertIsInstance(cli_judge.subprocess, external.ExternalSubprocess)
                self.assertIs(cli_judge.subprocess, image_runtime.subprocess)
                self.assertEqual(cli_judge.subprocess._injected_ca_file, "/bundle/cacert.pem")
                self.assertIs(subprocess.Popen, real_popen)
        self.assertIs(cli_judge.subprocess, subprocess)
        self.assertIs(image_runtime.subprocess, subprocess)


class BundledTrustTests(unittest.TestCase):
    def test_existing_system_trust_and_explicit_overrides_are_preserved(self):
        context = types.SimpleNamespace(cert_store_stats=lambda: {"x509_ca": 100})
        for environment in ({}, {"SSL_CERT_FILE": ""}, {"SSL_CERT_DIR": "/enterprise"}):
            with patch.object(bundled_tls.sys, "frozen", True, create=True), \
                    patch.dict(os.environ, environment, clear=True), \
                    patch.object(bundled_tls.ssl, "create_default_context", return_value=context) as create:
                self.assertFalse(bundled_tls.configure_bundled_tls())
                self.assertEqual(dict(os.environ), environment)
                self.assertEqual(create.call_count, 0 if environment else 1)

    def test_empty_trust_uses_validated_bundled_roots(self):
        empty = types.SimpleNamespace(cert_store_stats=lambda: {"x509_ca": 0})
        trusted = types.SimpleNamespace(cert_store_stats=lambda: {"x509_ca": 100})
        certifi = types.SimpleNamespace(where=lambda: "/bundle/cacert.pem")
        with patch.object(bundled_tls.sys, "frozen", True, create=True), \
                patch.dict(os.environ, {}, clear=True), \
                patch.dict(bundled_tls.sys.modules, {"certifi": certifi}), \
                patch.object(bundled_tls.ssl, "create_default_context", side_effect=[empty, trusted]) as create:
            self.assertEqual(bundled_tls.configure_bundled_tls(), "/bundle/cacert.pem")
            self.assertEqual(dict(os.environ), {"SSL_CERT_FILE": "/bundle/cacert.pem"})
            self.assertEqual(create.call_args.kwargs, {"cafile": "/bundle/cacert.pem"})

    def test_broken_trust_does_not_disable_verification_or_block_offline_work(self):
        with patch.object(bundled_tls.sys, "frozen", True, create=True), \
                patch.dict(os.environ, {}, clear=True), \
                patch.object(bundled_tls.ssl, "create_default_context", side_effect=OSError("unreadable trust")):
            self.assertFalse(bundled_tls.configure_bundled_tls())
            self.assertEqual(dict(os.environ), {})

    def test_nonfrozen_source_does_not_change_ssl_behavior(self):
        with patch.object(bundled_tls.sys, "frozen", False, create=True), \
                patch.object(bundled_tls.ssl, "create_default_context") as create:
            self.assertFalse(bundled_tls.configure_bundled_tls())
            create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
