"""Real child-process acquisition tests, without an installed image daemon.

The process-launch boundary substitutes a tiny Python runtime fixture; argument
construction and all production streaming/timeout/cleanup logic remain real.
"""

from contextlib import ExitStack
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from ai_security_scan import image_runtime


class ImageRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.destination = self.root / "image.tar"
        self.calls = []
        self.processes = []

    def fixture(self, script):
        real_popen = subprocess.Popen

        def launch(command, **kwargs):
            self.calls.append((list(command), dict(kwargs)))
            process = real_popen([sys.executable, "-c", script] + command[1:], **kwargs)
            self.processes.append(process)
            return process

        stack = ExitStack()
        stack.enter_context(mock.patch.object(image_runtime.shutil, "which", return_value=sys.executable))
        stack.enter_context(mock.patch.object(image_runtime.subprocess, "Popen", side_effect=launch))
        return stack

    def assert_clean_failure(self):
        self.assertEqual(list(self.root.glob(".ai-image-*")), [])
        for process in self.processes:
            self.assertIsNotNone(process.poll(), "runtime remained alive after acquisition failed")

    def test_local_docker_export_never_pulls_or_starts_a_container(self):
        with self.fixture("import sys; sys.stdout.buffer.write(b'archive-bytes')"):
            result = image_runtime.export_image("registry.example/team/agent:v1", self.destination)
        self.assertEqual(self.destination.read_bytes(), b"archive-bytes")
        self.assertEqual(result, {"reference": "registry.example/team/agent:v1", "runtime": "docker",
                                  "pulled": False, "platform": None})
        self.assertEqual(len(self.calls), 1)
        command, options = self.calls[0]
        self.assertEqual(command[1:], ["image", "save", "--", "registry.example/team/agent:v1"])
        self.assertIs(options["shell"], False)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["bufsize"], 0)
        self.assert_clean_failure()

    def test_explicit_pull_precedes_export_and_forwards_docker_platform(self):
        script = "import sys; sys.stdout.buffer.write(b'pulled' if sys.argv[2] == 'pull' else b'archive')"
        with self.fixture(script):
            result = image_runtime.export_image("agent:v1", self.destination, pull=True, platform="linux/arm64/v8")
        self.assertTrue(result["pulled"])
        self.assertEqual(result["platform"], "linux/arm64/v8")
        self.assertEqual([call[0][1:] for call in self.calls], [
            ["image", "pull", "--quiet", "--platform", "linux/arm64/v8", "--", "agent:v1"],
            ["image", "save", "--platform", "linux/arm64/v8", "--", "agent:v1"],
        ])
        self.assertEqual(self.destination.read_bytes(), b"archive")

    def test_podman_uses_docker_archive_and_platform_only_during_pull(self):
        with self.fixture("import sys; sys.stdout.buffer.write(b'archive')"):
            result = image_runtime.export_image("agent:v1", self.destination, runtime="podman",
                                                pull=True, platform="linux/amd64")
        self.assertEqual(result["runtime"], "podman")
        self.assertEqual([call[0][1:] for call in self.calls], [
            ["image", "pull", "--quiet", "--platform", "linux/amd64", "--", "agent:v1"],
            ["image", "save", "--format", "docker-archive", "--quiet", "--", "agent:v1"],
        ])

    def test_podman_local_mode_also_never_pulls(self):
        with self.fixture("import sys; sys.stdout.buffer.write(b'archive')"):
            image_runtime.export_image("agent:v1", self.destination, runtime="podman")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0][1:], ["image", "save", "--format", "docker-archive", "--quiet", "--", "agent:v1"])

    def test_shell_metacharacters_remain_one_literal_argument(self):
        reference = "agent:v1;$(touch${IFS}SHOULD_NOT_EXIST)"
        with self.fixture("import sys; sys.stdout.buffer.write(sys.argv[-1].encode())"):
            image_runtime.export_image(reference, self.destination)
        self.assertEqual(self.destination.read_text(), reference)
        self.assertEqual(self.calls[0][0][-2:], ["--", reference])
        self.assertIs(self.calls[0][1]["shell"], False)

    def test_invalid_references_are_rejected_before_runtime_lookup(self):
        invalid = [None, 1, "", "--output=/tmp/foo", " agent:v1", "agent v1", "agent\nsecret",
                   "agent\x00secret", "agent\x7fsecret", "agent\u0085secret", "agent\u202esecret",
                   "agent\udfffsecret", "a" * 4097]
        with mock.patch.object(image_runtime.shutil, "which") as lookup:
            for reference in invalid:
                with self.subTest(reference=repr(reference)), self.assertRaises(image_runtime.ImageRuntimeError):
                    image_runtime.export_image(reference, self.destination)
            lookup.assert_not_called()

    def test_invalid_runtimes_and_limits_are_rejected(self):
        variants = [{"runtime": "bash"}, {"runtime": "/usr/bin/docker"}, {"runtime": None},
                    {"platform": "--flag"}, {"platform": "linux/amd64\nsecret"},
                    {"platform": "linux/amd64/v1/extra"}, {"platform": 4}, {"platform": ""},
                    {"pull": "true"}, {"pull": 1},
                    {"max_archive_bytes": 0}, {"max_archive_bytes": -1},
                    {"max_archive_bytes": True}, {"max_archive_bytes": 3.5},
                    {"timeout_seconds": 0}, {"timeout_seconds": -1},
                    {"timeout_seconds": float("inf")}, {"timeout_seconds": float("nan")},
                    {"timeout_seconds": True}, {"timeout_seconds": "1"}]
        with mock.patch.object(image_runtime.shutil, "which") as lookup:
            for options in variants:
                with self.subTest(options=options), self.assertRaises(image_runtime.ImageRuntimeError):
                    image_runtime.export_image("agent:v1", self.destination, **options)
            lookup.assert_not_called()

    def test_missing_runtime_and_command_files_are_safe_errors(self):
        for resolved, expected in [(None, "not installed"), ("C:/tools/docker.cmd", "native executable"),
                                   ("C:/tools/docker.BAT", "native executable")]:
            with self.subTest(resolved=resolved), mock.patch.object(image_runtime.shutil, "which", return_value=resolved):
                with mock.patch.object(image_runtime.subprocess, "Popen") as launch:
                    with self.assertRaisesRegex(image_runtime.ImageRuntimeError, expected):
                        image_runtime.export_image("agent:v1", self.destination)
                    launch.assert_not_called()

    def test_runtime_launch_failure_does_not_leak_credentials(self):
        with mock.patch.object(image_runtime.shutil, "which", return_value="docker"):
            with mock.patch.object(image_runtime.subprocess, "Popen", side_effect=OSError("CANARY_PRIVATE_TOKEN")):
                with self.assertRaises(image_runtime.ImageRuntimeError) as context:
                    image_runtime.export_image("agent:v1", self.destination)
        self.assertNotIn("CANARY_PRIVATE_TOKEN", str(context.exception))
        self.assert_clean_failure()

    def test_nonzero_runtime_and_registry_failures_omit_all_diagnostics(self):
        script = "import sys; sys.stdout.write('CANARY_STDOUT_SECRET'); sys.stderr.write('CANARY_STDERR_SECRET'); sys.exit(3)"
        for pull in (False, True):
            with self.subTest(pull=pull), self.fixture(script):
                with self.assertRaises(image_runtime.ImageRuntimeError) as context:
                    image_runtime.export_image("agent:v1", self.destination, pull=pull)
                self.assertNotIn("CANARY", str(context.exception))
                self.assertIn("pull failed" if pull else "export failed", str(context.exception))
                self.assertFalse(self.destination.exists())
                self.assert_clean_failure()
        self.assertEqual(len(self.calls), 2, "a failed pull must not proceed to export")

    def test_exact_archive_limit_succeeds_and_one_extra_byte_fails(self):
        for count in (65536, 65537):
            self.destination.write_bytes(b"prior-destination")
            script = "import sys; sys.stdout.buffer.write(b'x' * {})".format(count)
            with self.subTest(count=count), self.fixture(script):
                if count == 65536:
                    image_runtime.export_image("agent:v1", self.destination, max_archive_bytes=65536)
                    self.assertEqual(self.destination.stat().st_size, 65536)
                else:
                    with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "archive exceeded"):
                        image_runtime.export_image("agent:v1", self.destination, max_archive_bytes=65536)
                    self.assertEqual(self.destination.read_bytes(), b"prior-destination")
                self.assert_clean_failure()

    def test_over_limit_process_never_writes_beyond_archive_budget(self):
        output = io.BytesIO()
        with self.fixture("import sys; sys.stdout.buffer.write(b'x' * 1000000)"):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "archive exceeded"):
                image_runtime._run([sys.executable, "image", "save", "--", "agent:v1"], output,
                                   max_stdout_bytes=100000, deadline=time.monotonic() + 5,
                                   operation="export", runtime="docker")
        self.assertLessEqual(len(output.getvalue()), 100000)
        self.assert_clean_failure()

    def test_stderr_at_limit_is_drained_without_deadlock_or_disclosure(self):
        script = "import sys; sys.stderr.buffer.write(b's' * 65536); sys.stderr.flush(); sys.stdout.buffer.write(b'archive')"
        with self.fixture(script):
            image_runtime.export_image("agent:v1", self.destination, timeout_seconds=5)
        self.assertEqual(self.destination.read_bytes(), b"archive")

    def test_simultaneous_large_stdout_and_stderr_are_drained(self):
        script = ("import sys,threading\n"
                  "def diagnostic():\n"
                  "    sys.stderr.buffer.write(b's' * 64000)\n"
                  "    sys.stderr.flush()\n"
                  "worker = threading.Thread(target=diagnostic)\n"
                  "worker.start()\n"
                  "sys.stdout.buffer.write(b'x' * 1000000)\n"
                  "sys.stdout.flush()\n"
                  "worker.join()\n")
        with self.fixture(script):
            image_runtime.export_image("agent:v1", self.destination, max_archive_bytes=1000000, timeout_seconds=5)
        self.assertEqual(self.destination.stat().st_size, 1000000)
        self.assert_clean_failure()

    def test_stderr_over_limit_aborts_with_bounded_cleanup(self):
        script = "import sys,time; sys.stderr.buffer.write(b's' * 65537); sys.stderr.flush(); time.sleep(20)"
        with self.fixture(script):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "diagnostic output exceeded"):
                image_runtime.export_image("agent:v1", self.destination, timeout_seconds=5)
        self.assertFalse(self.destination.exists())
        self.assert_clean_failure()

    def test_pull_informational_stdout_has_an_independent_limit(self):
        script = "import sys; sys.stdout.buffer.write(b's' * 65537)"
        with self.fixture(script):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "informational output exceeded"):
                image_runtime.export_image("agent:v1", self.destination, pull=True)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.destination.exists())
        self.assert_clean_failure()

    def test_silent_and_partial_output_timeouts_kill_and_remove_temporary_archive(self):
        for script in ["import time; time.sleep(20)",
                       "import sys,time; sys.stdout.buffer.write(b'partial'); sys.stdout.flush(); time.sleep(20)"]:
            self.destination.write_bytes(b"preserve")
            started = time.monotonic()
            with self.subTest(script=script), self.fixture(script):
                with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "timeout"):
                    image_runtime.export_image("agent:v1", self.destination, timeout_seconds=0.25)
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(self.destination.read_bytes(), b"preserve")
            self.assert_clean_failure()

    def test_timeout_covers_pull_and_export_together(self):
        script = "import sys,time; time.sleep(0.20); sys.stdout.buffer.write(b'archive')"
        with self.fixture(script):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "timeout"):
                image_runtime.export_image("agent:v1", self.destination, pull=True, timeout_seconds=0.35)
        self.assertFalse(self.destination.exists())
        self.assert_clean_failure()

    def test_empty_archive_is_rejected(self):
        with self.fixture("pass"):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "empty archive"):
                image_runtime.export_image("agent:v1", self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_clean_failure()

    def test_already_expired_deadline_never_starts_runtime(self):
        with self.fixture("raise SystemExit('must not run')"):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "timeout"):
                image_runtime._run([sys.executable, "image", "save", "--", "agent:v1"], io.BytesIO(),
                                   max_stdout_bytes=1000, deadline=time.monotonic() - 1,
                                   operation="export", runtime="docker")
        self.assertEqual(self.calls, [])

    def test_destination_errors_are_generic_and_do_not_leave_temp_files(self):
        with self.fixture("import sys; sys.stdout.buffer.write(b'archive')"):
            with mock.patch.object(image_runtime.os, "replace", side_effect=OSError("CANARY_PATH_SECRET")):
                with self.assertRaises(image_runtime.ImageRuntimeError) as context:
                    image_runtime.export_image("agent:v1", self.destination)
        self.assertNotIn("CANARY_PATH_SECRET", str(context.exception))
        self.assertFalse(self.destination.exists())
        self.assert_clean_failure()

    def test_missing_destination_directory_fails_without_export(self):
        with self.fixture("import sys; sys.stdout.buffer.write(b'archive')"):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "could not be written"):
                image_runtime.export_image("agent:v1", self.root / "missing" / "archive.tar")
        self.assertEqual(self.calls, [])
        self.assert_clean_failure()

    def test_destination_symlink_is_rejected_without_following_it(self):
        prior = self.root / "prior.tar"
        prior.write_bytes(b"untouched")
        try:
            self.destination.symlink_to(prior)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        with self.fixture("import sys; sys.stdout.buffer.write(b'archive')"):
            with self.assertRaisesRegex(image_runtime.ImageRuntimeError, "symbolic link"):
                image_runtime.export_image("agent:v1", self.destination)
        self.assertEqual(prior.read_bytes(), b"untouched")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
