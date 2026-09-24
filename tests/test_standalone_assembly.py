"""Prevent publishing mixed, altered or unvalidated native artifacts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('standalone_assembly', ROOT / 'scripts/assemble_standalone_release.py')
assembly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembly)
COMMIT = 'a' * 40


class StandaloneAssemblyTests(unittest.TestCase):
    def prepare(self, root):
        for target in assembly.TARGETS:
            folder = root / ('standalone-' + target)
            folder.mkdir()
            stem = 'invscan-0.15.0-' + target
            archive = folder / (stem + ('.zip' if target.startswith('windows-') else '.tar.gz'))
            archive.write_bytes(('synthetic-artifact:' + target).encode())
            platform, architecture = target.split('-', 1)
            manifest = {'version': '0.15.0', 'platform': platform, 'architecture': architecture,
                        'git': {'commit': COMMIT, 'dirty': False}, 'archive': archive.name,
                        'archive_sha256': assembly.digest(archive), 'archive_size': archive.stat().st_size,
                        'source_inputs_sha256': 'b' * 64}
            validation = {'status': 'passed', 'archive': {'name': archive.name, 'sha256': assembly.digest(archive)}}
            (folder / (stem + '.build-manifest.json')).write_text(json.dumps(manifest))
            (folder / (stem + '.validation.json')).write_text(json.dumps(validation))

    def test_complete_set_and_checksum_assembly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            files, records, snapshot = assembly.collect(root, '0.15.0', COMMIT)
            self.assertEqual((len(files), len(records), snapshot), (15, 5, 'b' * 64))
            output = root / 'release'
            assembly.main(['--input', str(root), '--output', str(output), '--version', '0.15.0',
                           '--commit', COMMIT, '--run-url', 'https://github.com/nimeshbuilds/invarune/actions/runs/123'])
            sums = (output / 'SHA256SUMS-standalone.txt').read_text().splitlines()
            self.assertEqual(len(sums), 16)
            for line in sums:
                value, name = line.split('  ', 1)
                self.assertEqual(value, assembly.digest(output / name))

    def test_changed_archive_and_wrong_tested_bytes_are_rejected(self):
        for change in ('archive', 'receipt'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare(root)
                folder = root / 'standalone-linux-arm64'
                if change == 'archive':
                    next(folder.glob('*.tar.gz')).write_bytes(b'altered-after-validation')
                else:
                    path = next(folder.glob('*.validation.json'))
                    value = json.loads(path.read_text())
                    value['archive']['sha256'] = 'c' * 64
                    path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    assembly.collect(root, '0.15.0', COMMIT)

    def test_missing_or_failed_platform_blocks_release(self):
        for change in ('missing', 'failed'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare(root)
                path = next((root / 'standalone-windows-x86_64').glob('*.validation.json'))
                if change == 'missing':
                    path.unlink()
                else:
                    value = json.loads(path.read_text())
                    value['status'] = 'failed'
                    path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    assembly.collect(root, '0.15.0', COMMIT)

    def test_dirty_mixed_commit_and_different_snapshot_block_release(self):
        for change in ('dirty', 'commit', 'snapshot'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare(root)
                path = next((root / 'standalone-macos-arm64').glob('*.build-manifest.json'))
                value = json.loads(path.read_text())
                if change == 'dirty':
                    value['git']['dirty'] = True
                elif change == 'commit':
                    value['git']['commit'] = 'c' * 40
                else:
                    value['source_inputs_sha256'] = 'c' * 64
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    assembly.collect(root, '0.15.0', COMMIT)


if __name__ == '__main__':
    unittest.main()
