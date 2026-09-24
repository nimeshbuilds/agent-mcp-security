"""Boundaries of the native-release validation harness (no builds required)."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('standalone_validator', ROOT / 'scripts/validate_standalone.py')
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class StandaloneValidationTests(unittest.TestCase):
    def test_openssl_discovery_prefers_path_and_finds_git_for_windows_installation(self):
        with patch.object(validator.shutil, 'which', return_value='/tools/openssl'):
            self.assertEqual(validator.find_openssl(), Path('/tools/openssl').absolute())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / 'Git/usr/bin/openssl.exe'
            expected.parent.mkdir(parents=True)
            expected.write_bytes(b'fixture')
            with patch.object(validator, 'os', SimpleNamespace(name='nt')), \
                 patch.object(validator.shutil, 'which', side_effect=lambda command: str(root / 'Git/cmd/git.exe') if command == 'git' else None):
                self.assertEqual(validator.find_openssl(), expected)
        with patch.object(validator.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Controller OpenSSL'):
                validator.find_openssl()

    def test_archive_member_paths_reject_absolute_traversal_and_windows_escape(self):
        for name in ('../outside', '/absolute', 'C:/escape', 'invscan-test/../../escape',
                     'invscan-test/..\\escape', 'unbranded/file', ''):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                validator.archive_path(name)
        self.assertEqual(str(validator.archive_path('invscan-test/_internal/data.json')),
                         'invscan-test/_internal/data.json')

    def test_zip_release_extracts_native_binary_and_rejects_link_or_multiple_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'release.zip'
            executable = 'invscan.exe' if os.name == 'nt' else 'invscan'
            def make_zip():
                with zipfile.ZipFile(archive, 'w') as stream:
                    stream.writestr('invscan-test/' + executable, b'MZ\x00\x00fixture')
                    stream.writestr('invscan-test/_internal/data.json', '{}')
            make_zip()
            extracted = validator.extract_archive(archive, root / 'good')
            self.assertEqual(extracted.name, executable)
            for name, mode in [('invscan-other/file', 0), ('invscan-test/link', 0o120777)]:
                make_zip()
                with zipfile.ZipFile(archive, 'a') as stream:
                    entry = zipfile.ZipInfo(name)
                    entry.external_attr = mode << 16
                    stream.writestr(entry, '../outside')
                with self.assertRaises(RuntimeError):
                    validator.extract_archive(archive, root / 'bad')
                self.assertFalse((root / 'bad').exists())

    @unittest.skipUnless(hasattr(tarfile, 'data_filter'), 'Safe tar extraction requires the data filter')
    def test_tar_allows_internal_framework_symlink_but_rejects_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = 'invscan.exe' if os.name == 'nt' else 'invscan'
            def make_archive(destination, target):
                with tarfile.open(destination, 'w') as stream:
                    for name, body in [('invscan-test/' + executable, b'MZ\x00\x00fixture'),
                                       ('invscan-test/_internal/Python.framework/Versions/3.12/Python', b'runtime')]:
                        entry = tarfile.TarInfo(name)
                        entry.size = len(body)
                        entry.mode = 0o755
                        stream.addfile(entry, io.BytesIO(body))
                    link = tarfile.TarInfo('invscan-test/_internal/Python.framework/Python')
                    link.type = tarfile.SYMTYPE
                    link.linkname = target
                    stream.addfile(link)
            good = root / 'good.tar'
            make_archive(good, 'Versions/3.12/Python')
            # Symlink creation may be unavailable on a developer Windows host.
            if os.name != 'nt':
                validator.extract_archive(good, root / 'good')
                self.assertEqual((root / 'good/invscan-test/_internal/Python.framework/Python').read_bytes(), b'runtime')
            bad = root / 'bad.tar'
            make_archive(bad, '../../../../outside')
            with self.assertRaisesRegex(RuntimeError, 'escapes'):
                validator.extract_archive(bad, root / 'bad')
            self.assertFalse((root / 'bad').exists())

    def test_native_gate_rejects_interpreter_wrappers_and_missing_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'invscan'
            binary.write_bytes(b'#!/usr/bin/env python3\n')
            (root / '_internal').mkdir()
            with self.assertRaisesRegex(RuntimeError, 'native executable'):
                validator.verify_native_command(binary)
            for magic in (*validator.NATIVE_MAGICS, b'MZ\x00\x00'):
                binary.write_bytes(magic + b'fixture')
                validator.verify_native_command(binary)
            (root / '_internal').rmdir()
            with self.assertRaisesRegex(RuntimeError, '_internal'):
                validator.verify_native_command(binary)

    def test_child_environment_excludes_credentials_python_paths_and_user_home(self):
        original = {'PATH': '/a/python/bin', 'HOME': '/a/user', 'PYTHONPATH': '/checkout',
                    'OPENAI_API_KEY': 'test-only-placeholder', 'ANTHROPIC_API_KEY': 'test-only-placeholder',
                    'HTTPS_PROXY': 'http://external.invalid', 'CODEX_HOME': '/a/config',
                    'SystemRoot': 'C:\\Windows', 'LANG': 'en_US.UTF-8'}
        before = dict(original)
        with tempfile.TemporaryDirectory() as temporary:
            environment = validator.isolated_environment(original, Path(temporary))
            self.assertEqual(original, before)
            for key in ('PYTHONPATH', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'HTTPS_PROXY', 'CODEX_HOME'):
                self.assertNotIn(key, environment)
            self.assertEqual(environment['SystemRoot'], 'C:\\Windows')
            self.assertNotEqual(environment['HOME'], original['HOME'])
            self.assertEqual(environment['NO_PROXY'], '127.0.0.1,localhost')
            self.assertEqual(list(Path(environment['PATH']).iterdir()), [])
            self.assertIsNone(shutil.which('python', path=environment['PATH']))

    def test_receipt_path_redaction_handles_windows_and_specific_paths_first(self):
        paths = [('C:\\users\\test', '<HOME>'), ('C:\\users\\test\\work', '<WORK>')]
        text = validator.portable('C:/users/test/work/report.json C:\\users\\test\\config', paths)
        self.assertEqual(text, '<WORK>/report.json <HOME>\\config')

    def test_existing_validation_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'evidence'
            output.mkdir()
            marker = output / 'receipt.json'
            marker.write_text('keep')
            with self.assertRaises(SystemExit) as result, patch.object(validator, 'validate') as execute:
                validator.main(['--command', 'invscan', '--output', str(output)])
            self.assertEqual(result.exception.code, 2)
            execute.assert_not_called()
            self.assertEqual(marker.read_text(), 'keep')

    def test_failed_validation_writes_failure_receipt_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'evidence'
            with patch.object(validator, 'validate', side_effect=RuntimeError('native validation rejected')):
                code = validator.main(['--command', 'invscan', '--output', str(output)])
            receipt = json.loads((output / 'receipt.json').read_text())
            self.assertEqual(code, 1)
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(receipt['steps_executed'], 0)
            self.assertEqual(receipt['error'], 'native validation rejected')
            self.assertFalse(receipt['scope']['target_execution'])


if __name__ == '__main__':
    unittest.main()
