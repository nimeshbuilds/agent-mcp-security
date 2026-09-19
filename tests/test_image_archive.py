import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.image_archive import ImageArchiveError, materialize_image
from tests.image_fixtures import docker_archive, oci_archive, rewrite_archive, tar_bytes, json_bytes


class ImageArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.archive = self.base / "image.tar"
        self.out = self.base / "out"
        self.out.mkdir()

    def scan(self, layers, *, maker=docker_archive, config=None, options=None, **kwargs):
        maker(self.archive, layers, config, **kwargs)
        return materialize_image(self.archive, self.out, **(options or {}))

    def test_docker_save_roundtrip_source_and_binary(self):
        result = self.scan([[('app/main.py', 'eval(input())'), ('app/program', b'\x7fELF\x00\xff')]])
        self.assertEqual((result['root'] / 'app/main.py').read_text(), 'eval(input())')
        self.assertEqual((result['root'] / 'app/program').read_bytes(), b'\x7fELF\x00\xff')
        self.assertEqual(result['identity']['format'], 'docker-save')
        self.assertEqual(result['identity']['platform'], 'linux/amd64')
        self.assertEqual(result['coverage']['errors'], [])
        self.assertEqual(len(result['layer_files']), 2)

    def test_empty_scratch_image_is_supported(self):
        result = self.scan([], config={'config': {'User': '1000'}})
        self.assertEqual(result['entries'], [])
        self.assertEqual(result['coverage']['layers'], 0)
        self.assertTrue(result['root'].is_dir())

    def test_binary_only_image_never_executes_entrypoint(self):
        marker = self.base / 'MUST_NOT_EXIST'
        result = self.scan([[('app/program', '#!/bin/sh\ntouch ' + str(marker))]],
                           config={'config': {'Entrypoint': ['/app/program']}})
        self.assertFalse(marker.exists())
        self.assertEqual(result['config']['config']['Entrypoint'], ['/app/program'])

    def test_gzip_outer_archive(self):
        result = self.scan([[('x', 'contents')]], gzip_outer=True)
        self.assertEqual((result['root'] / 'x').read_text(), 'contents')

    def test_oci_plain_and_gzip_layers(self):
        for compressed in (False, True):
            with self.subTest(gzip=compressed):
                output = self.base / ('out-' + str(compressed)); output.mkdir()
                oci_archive(self.archive, [[('app/x.py', 'print(1)')]], gzip_layers=compressed)
                result = materialize_image(self.archive, output)
                self.assertEqual(result['identity']['format'], 'oci')
                self.assertEqual((result['root'] / 'app/x.py').read_text(), 'print(1)')
                self.assertEqual(result['coverage']['errors'], [])

    def test_whiteout_applies_to_lower_layer_only_regardless_order(self):
        result = self.scan([[('app/old', 'secret'), ('app/keep', 'lower')],
                            [('app/old', 'new'), ('app/.wh.old', b'')]])
        self.assertEqual((result['root'] / 'app/old').read_text(), 'new')
        self.assertEqual((result['root'] / 'app/keep').read_text(), 'lower')
        revisions = [r for r in result['layer_files'] if r['path'] == 'app/old']
        self.assertEqual([r['blob_path'].read_text() for r in revisions], ['secret', 'new'])
        self.assertFalse((result['root'] / 'app/.wh.old').exists())

    def test_opaque_whiteout_preserves_current_layer_entries(self):
        result = self.scan([[('a/old', 'old'), ('a/sub/old', 'old'), ('outside', 'keep')],
                            [('a/new', 'new'), ('a/.wh..wh..opq', b'')]])
        self.assertFalse((result['root'] / 'a/old').exists())
        self.assertFalse((result['root'] / 'a/sub').exists())
        self.assertEqual((result['root'] / 'a/new').read_text(), 'new')
        self.assertEqual((result['root'] / 'outside').read_text(), 'keep')

    def test_root_opaque_whiteout(self):
        result = self.scan([[('a/old', 'old')], [('new', 'new'), ('.wh..wh..opq', b'')]])
        self.assertEqual([x.name for x in result['root'].iterdir()], ['new'])

    def test_whiteout_removes_implicit_directory(self):
        result = self.scan([[('a/b/c', 'old')], [('.wh.a', b'')]])
        self.assertEqual(result['entries'], [])
        self.assertEqual(result['layer_files'][0]['blob_path'].read_text(), 'old')

    def test_directory_to_file_replacement_removes_children(self):
        result = self.scan([[('a/b/c', 'old')], [('a', 'new')]])
        self.assertEqual((result['root'] / 'a').read_text(), 'new')
        self.assertEqual([e['path'] for e in result['entries']], ['a'])

    def test_file_to_directory_replacement(self):
        result = self.scan([[('a', 'old')], [{'path': 'a', 'kind': 'directory'}, ('a/new', 'new')]])
        self.assertEqual((result['root'] / 'a/new').read_text(), 'new')

    def test_directory_metadata_replacement_keeps_children(self):
        result = self.scan([[('a/child', 'old')], [{'path': 'a', 'kind': 'directory', 'mode': 0o777, 'uid': 501}]])
        item = next(e for e in result['entries'] if e['path'] == 'a')
        self.assertEqual((item['mode'], item['uid']), (0o777, 501))
        self.assertTrue((result['root'] / 'a/child').exists())

    def test_metadata_preserved_without_installing_privileged_modes(self):
        result = self.scan([[{'path': 'bin/program', 'data': 'binary', 'mode': 0o4755, 'uid': 0, 'gid': 25}]])
        item = next(e for e in result['entries'] if e['kind'] == 'file')
        self.assertEqual((item['mode'], item['uid'], item['gid']), (0o4755, 0, 25))
        if os.name != 'nt':
            self.assertEqual((result['root'] / 'bin/program').stat().st_mode & 0o7777, 0o600)

    def test_symlinks_are_virtual_and_safe_file_aliases_are_copied(self):
        result = self.scan([[('usr/bin/tool', 'code'),
                            {'path': 'bin', 'kind': 'symlink', 'target': 'usr/bin'},
                            {'path': 'tool', 'kind': 'symlink', 'target': '/bin/tool'}]])
        self.assertFalse((result['root'] / 'bin').exists())
        self.assertFalse((result['root'] / 'tool').is_symlink())
        self.assertEqual((result['root'] / 'tool').read_text(), 'code')
        self.assertEqual(result['coverage']['errors'], [])
        self.assertTrue(any(not s['coverage_gap'] for s in result['coverage']['skipped']))

    def test_root_directory_symlink_is_nongap_alias(self):
        result = self.scan([[{'path': 'root-alias', 'kind': 'symlink', 'target': '/'}, ('file', 'x')]])
        self.assertEqual(result['coverage']['errors'], [])
        self.assertEqual(result['coverage']['skipped'][0]['coverage_gap'], False)

    def test_cyclic_missing_and_escaping_symlinks_report_gaps(self):
        result = self.scan([[{'path': 'a', 'kind': 'symlink', 'target': 'b'},
                            {'path': 'b', 'kind': 'symlink', 'target': 'a'},
                            {'path': 'missing', 'kind': 'symlink', 'target': 'not-there'},
                            {'path': 'escape', 'kind': 'symlink', 'target': '../outside'}]])
        self.assertEqual(len(result['coverage']['errors']), 4)
        self.assertFalse(any(result['root'].iterdir()))

    def test_layer_write_through_directory_link_reports_gap(self):
        result = self.scan([[('usr/bin/original', 'code'), {'path': 'bin', 'kind': 'symlink', 'target': 'usr/bin'}],
                            [('bin/new', 'not silently accepted')]])
        self.assertTrue(any(e['kind'] == 'unsupported_path_semantics' for e in result['coverage']['errors']))
        self.assertEqual(result['layer_files'][-1]['blob_path'].read_text(), 'not silently accepted')

    def test_whiteout_through_directory_link_reports_gap(self):
        result = self.scan([[('usr/bin/tool', 'code'), {'path': 'bin', 'kind': 'symlink', 'target': 'usr/bin'}],
                            [('bin/.wh.tool', b'')]])
        self.assertTrue(any(e['kind'] == 'unsupported_path_semantics' for e in result['coverage']['errors']))
        self.assertEqual((result['root'] / 'usr/bin/tool').read_text(), 'code')

    def test_implicit_directories_are_bounded(self):
        with self.assertRaisesRegex(ImageArchiveError, 'filesystem exceeds entry limit'):
            self.scan([[('a/b/c/d/e/f/g/h/file', 'x')]], options={'max_entries': 6})

    def test_sparse_pax_rejected_before_sparse_decoder(self):
        with self.assertRaisesRegex(ImageArchiveError, 'Sparse tar entries are unsupported'):
            self.scan([[{'path': 'file', 'data': 'x', 'pax_headers': {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'}}]])

    def test_hardlink_binds_before_future_target_overwrite(self):
        result = self.scan([[('original', 'old'), {'path': 'alias', 'kind': 'hardlink', 'target': 'original'}],
                            [('original', 'new')]])
        self.assertEqual((result['root'] / 'original').read_text(), 'new')
        self.assertEqual((result['root'] / 'alias').read_text(), 'old')
        self.assertNotEqual((result['root'] / 'original').stat().st_ino, (result['root'] / 'alias').stat().st_ino)

    def test_forward_hardlink_and_chain(self):
        result = self.scan([[{'path': 'a', 'kind': 'hardlink', 'target': 'b'},
                            {'path': 'b', 'kind': 'hardlink', 'target': 'c'}, ('c', 'content')]])
        self.assertEqual((result['root'] / 'a').read_text(), 'content')
        self.assertEqual(result['coverage']['errors'], [])

    def test_bad_hardlinks_are_reported_not_followed_on_host(self):
        result = self.scan([[{'path': 'a', 'kind': 'hardlink', 'target': 'b'},
                            {'path': 'b', 'kind': 'hardlink', 'target': 'a'},
                            {'path': 'missing', 'kind': 'hardlink', 'target': 'not-there'}]])
        self.assertEqual(len(result['coverage']['errors']), 3)
        self.assertFalse(any(result['root'].iterdir()))

    def test_special_files_are_metadata_only_with_coverage_gap(self):
        result = self.scan([[{'path': 'fifo', 'kind': 'fifo'}, {'path': 'device', 'kind': 'device'}]])
        self.assertEqual(len(result['coverage']['skipped']), 2)
        self.assertTrue(all(s['coverage_gap'] for s in result['coverage']['skipped']))
        self.assertFalse(any(result['root'].iterdir()))

    def test_extended_security_attributes_report_gap(self):
        result = self.scan([[{'path': 'file', 'data': 'data', 'pax_headers': {'SCHILY.xattr.security.capability': 'abc'}}]])
        self.assertTrue(any('extended permissions' in e['reason'] for e in result['coverage']['skipped']))

    def test_hostile_layer_paths_are_rejected(self):
        for name in ('../escape', '/absolute', 'a/../../escape', 'C:/windows', 'a\\b', 'CON', 'a./x', 'a/../b', 'a//b', 'a\nline', 'a:stream'):
            with self.subTest(path=name):
                output = self.base / ('case-' + str(len(list(self.base.iterdir())))); output.mkdir()
                docker_archive(self.archive, [[(name, 'x')]])
                with self.assertRaises(ImageArchiveError):
                    materialize_image(self.archive, output)
        self.assertFalse((self.base.parent / 'escape').exists())

    def test_outer_hostile_path_is_rejected(self):
        docker_archive(self.archive, [[('safe', 'x')]], extra_entries=[('../outside', 'x')])
        with self.assertRaisesRegex(ImageArchiveError, 'Unsafe archive path'):
            materialize_image(self.archive, self.out)

    def test_outer_symlink_rejected(self):
        docker_archive(self.archive, [], extra_entries=[{'path': 'alias', 'kind': 'symlink', 'target': '/etc/passwd'}])
        with self.assertRaisesRegex(ImageArchiveError, 'unsupported link'):
            materialize_image(self.archive, self.out)

    def test_duplicate_layer_paths_rejected(self):
        with self.assertRaisesRegex(ImageArchiveError, 'Duplicate layer entry'):
            self.scan([[('same', 'a'), ('./same', 'b')]])

    def test_duplicate_outer_paths_rejected(self):
        docker_archive(self.archive, [], extra_entries=[('manifest.json', '[]')])
        with self.assertRaisesRegex(ImageArchiveError, 'Duplicate archive entry'):
            materialize_image(self.archive, self.out)

    def test_case_and_unicode_collisions_rejected(self):
        for layers in ([[('A/x', 'a'), ('a/y', 'b')]], [[('A/x', 'a')], [('a/y', 'b')]], [[('caf\u00e9', 'a'), ('cafe\u0301', 'b')]]):
            with self.subTest(layers=layers):
                output = self.base / ('case-' + str(len(list(self.base.iterdir())))); output.mkdir()
                docker_archive(self.archive, layers)
                with self.assertRaisesRegex(ImageArchiveError, 'colliding'):
                    materialize_image(self.archive, output)

    def test_invalid_whiteouts_rejected(self):
        for entry in (('.wh.', b''), ('.wh.x', b'not empty'), {'path': '.wh.x', 'kind': 'directory'}, ('.wh...', b'')):
            with self.subTest(entry=entry):
                output = self.base / ('case-' + str(len(list(self.base.iterdir())))); output.mkdir()
                docker_archive(self.archive, [[entry]])
                with self.assertRaises(ImageArchiveError):
                    materialize_image(self.archive, output)

    def test_platform_selection_is_explicit_for_multiarch(self):
        oci_archive(self.archive, [[('file', 'x')]], platforms=['linux/amd64', 'linux/arm64/v8'])
        with self.assertRaisesRegex(ImageArchiveError, 'multiple images'):
            materialize_image(self.archive, self.out)
        another = self.base / 'selected'; another.mkdir()
        result = materialize_image(self.archive, another, platform='linux/arm64')
        self.assertEqual(result['identity']['platform'], 'linux/arm64/v8')

    def test_unmatched_or_invalid_platform_rejected(self):
        for platform in ('windows/amd64', 'amd64', '../linux/amd64'):
            with self.subTest(platform=platform):
                output = self.base / ('case-' + str(len(list(self.base.iterdir())))); output.mkdir()
                docker_archive(self.archive, [])
                with self.assertRaises(ImageArchiveError):
                    materialize_image(self.archive, output, platform=platform)

    def test_manifest_descriptor_digest_mismatch_rejected(self):
        oci_archive(self.archive, [])
        def corrupt(entries):
            result = []
            for name, data in entries:
                if name.startswith('blobs/') and b'"schemaVersion"' in data:
                    data += b' '
                result.append((name, data))
            return result
        rewrite_archive(self.archive, corrupt)
        with self.assertRaisesRegex(ImageArchiveError, 'digest or size mismatch'):
            materialize_image(self.archive, self.out)

    def test_descriptor_size_mismatch_rejected(self):
        oci_archive(self.archive, [])
        def corrupt(entries):
            result = []
            for name, data in entries:
                if name == 'index.json':
                    value = json.loads(data); value['manifests'][0]['size'] += 1
                    data = json_bytes(value)
                result.append((name, data))
            return result
        rewrite_archive(self.archive, corrupt)
        with self.assertRaisesRegex(ImageArchiveError, 'digest or size mismatch'):
            materialize_image(self.archive, self.out)

    def test_layer_diffid_mismatch_rejected(self):
        with self.assertRaisesRegex(ImageArchiveError, 'diff_id mismatch'):
            self.scan([[('file', 'x')]], config={'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + '0' * 64]}})

    def test_layer_diffid_count_mismatch_rejected(self):
        with self.assertRaisesRegex(ImageArchiveError, 'count/digest'):
            self.scan([[('file', 'x')]], config={'rootfs': {'type': 'layers', 'diff_ids': []}})

    def test_absent_diffids_report_gap(self):
        result = self.scan([[('file', 'x')]], diff_ids=False)
        self.assertTrue(any('diff_ids absent' in e['reason'] for e in result['coverage']['skipped']))

    def test_docker_config_digest_mismatch_rejected(self):
        docker_archive(self.archive, [])
        rewrite_archive(self.archive, lambda entries: [(n, d + b' ' if n.endswith('.json') and n != 'manifest.json' else d) for n, d in entries])
        with self.assertRaisesRegex(ImageArchiveError, 'config filename digest mismatch'):
            materialize_image(self.archive, self.out)

    def test_unsupported_oci_layer_compression_rejected(self):
        with self.assertRaisesRegex(ImageArchiveError, 'Unsupported OCI layer media type'):
            self.scan([[('file', 'x')]], maker=oci_archive, media_type='application/vnd.oci.image.layer.v1.tar+zstd')

    def test_gzip_media_type_mismatch_rejected(self):
        with self.assertRaisesRegex(ImageArchiveError, 'compression does not match'):
            self.scan([[('file', 'x')]], maker=oci_archive, media_type='application/vnd.oci.image.layer.v1.tar+gzip')

    def test_truncated_layer_rejected(self):
        layer = tar_bytes([('file', 'x')])[:1024]
        with self.assertRaisesRegex(ImageArchiveError, 'Truncated tar end markers'):
            self.scan([layer])

    def test_truncated_outer_archive_rejected(self):
        docker_archive(self.archive, [])
        self.archive.write_bytes(self.archive.read_bytes()[:512])
        with self.assertRaises(ImageArchiveError):
            materialize_image(self.archive, self.out)

    def test_trailing_nonzero_tar_payload_rejected(self):
        docker_archive(self.archive, [])
        self.archive.write_bytes(self.archive.read_bytes() + b'malicious'.ljust(1024, b'\0'))
        with self.assertRaisesRegex(ImageArchiveError, 'trailing tar data'):
            materialize_image(self.archive, self.out)

    def test_corrupt_gzip_crc_rejected(self):
        docker_archive(self.archive, [], gzip_outer=True)
        data = bytearray(self.archive.read_bytes()); data[-5] ^= 0xff
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(ImageArchiveError, 'Invalid or truncated gzip'):
            materialize_image(self.archive, self.out)

    def test_archive_size_limit(self):
        docker_archive(self.archive, [])
        with self.assertRaisesRegex(ImageArchiveError, 'archive exceeds byte limit'):
            materialize_image(self.archive, self.out, max_archive_bytes=10)

    def test_outer_decompression_bomb_limit(self):
        docker_archive(self.archive, [[('large', b'0' * 100000)]], gzip_outer=True)
        self.assertLess(self.archive.stat().st_size, 2000)
        with self.assertRaisesRegex(ImageArchiveError, 'expanded image archive exceeds byte limit'):
            materialize_image(self.archive, self.out, max_archive_bytes=2000)

    def test_layer_decompression_limit(self):
        oci_archive(self.archive, [[('large', b'0' * 100000)]], gzip_layers=True)
        with self.assertRaisesRegex(ImageArchiveError, 'expanded layer 0 exceeds byte limit'):
            materialize_image(self.archive, self.out, max_unpacked_bytes=2000)

    def test_layer_count_limit(self):
        with self.assertRaisesRegex(ImageArchiveError, 'layer count limit'):
            self.scan([[], []], options={'max_layers': 1})

    def test_entry_count_limit_includes_outer_and_layer_headers(self):
        with self.assertRaisesRegex(ImageArchiveError, 'entry limit'):
            self.scan([[('a', 'x'), ('b', 'x')]], options={'max_entries': 4})

    def test_final_copied_link_bytes_are_bounded(self):
        contents = b'x' * 20000
        entries = [('file', contents)] + [{'path': 'alias%d' % i, 'kind': 'symlink', 'target': 'file'} for i in range(4)]
        with self.assertRaisesRegex(ImageArchiveError, 'Final image filesystem exceeds byte limit'):
            self.scan([entries], options={'max_unpacked_bytes': 40000})

    def test_invalid_budgets_rejected(self):
        for value in (0, -1, True, '100'):
            with self.subTest(value=value), self.assertRaisesRegex(ImageArchiveError, 'positive integer'):
                materialize_image(self.archive, self.out, max_entries=value)

    def test_nonempty_destination_rejected_without_overwrite(self):
        (self.out / 'valuable').write_text('keep')
        with self.assertRaisesRegex(ImageArchiveError, 'empty private directory'):
            materialize_image(self.archive, self.out)
        self.assertEqual((self.out / 'valuable').read_text(), 'keep')

    def test_symlink_archive_input_rejected(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('symlink primitive unavailable')
        docker_archive(self.archive, [])
        link = self.base / 'link'
        try:
            link.symlink_to(self.archive)
        except OSError:
            self.skipTest('host disallows symlink creation')
        with self.assertRaisesRegex(ImageArchiveError, 'regular Docker-save or OCI archive'):
            materialize_image(link, self.out)

    def test_exported_rootfs_is_not_misidentified_as_image(self):
        self.archive.write_bytes(tar_bytes([('etc/file', 'x')]))
        with self.assertRaisesRegex(ImageArchiveError, 'docker export/rootfs tar is unsupported'):
            materialize_image(self.archive, self.out)

    def test_missing_layer_member_rejected(self):
        docker_archive(self.archive, [[('file', 'x')]])
        rewrite_archive(self.archive, lambda entries: [(n, d) for n, d in entries if not n.endswith('layer.tar')])
        with self.assertRaisesRegex(ImageArchiveError, 'Required image archive member is missing'):
            materialize_image(self.archive, self.out)

    def test_duplicate_metadata_json_keys_rejected(self):
        docker_archive(self.archive, [])
        rewrite_archive(self.archive, lambda entries: [(n, b'[{"Config":"a","Config":"b","Layers":[]}]' if n == 'manifest.json' else d) for n, d in entries])
        with self.assertRaisesRegex(ImageArchiveError, 'Invalid JSON'):
            materialize_image(self.archive, self.out)

    def test_huge_pax_extension_is_bounded_before_payload_read(self):
        # A handcrafted header advertises a huge extension; no huge allocation is needed.
        header = tarfile.TarInfo('pax'); header.type = tarfile.XHDTYPE; header.size = 5_000_000
        self.archive.write_bytes(header.tobuf() + b'\0' * 1024)
        with self.assertRaisesRegex(ImageArchiveError, 'extended header exceeds metadata limit'):
            materialize_image(self.archive, self.out)

    def test_identity_and_metadata_are_reproducible(self):
        result = self.scan([[('file', 'x')]])
        output = self.base / 'second'; output.mkdir()
        again = materialize_image(self.archive, output)
        self.assertEqual(result['identity'], again['identity'])
        self.assertEqual(result['entries'], again['entries'])
        self.assertEqual(result['coverage'], again['coverage'])

    def test_extraction_and_process_apis_are_never_used(self):
        with patch('tarfile.TarFile.extractall', side_effect=AssertionError('unsafe extractall')), \
             patch('tarfile.TarFile.extract', side_effect=AssertionError('unsafe extract')), \
             patch('os.symlink', side_effect=AssertionError('host symlink')), \
             patch('os.link', side_effect=AssertionError('host hardlink')), \
             patch('subprocess.run', side_effect=AssertionError('target execution')):
            result = self.scan([[('file', 'x'), {'path': 'alias', 'kind': 'symlink', 'target': 'file'}]])
        self.assertEqual((result['root'] / 'alias').read_text(), 'x')


if __name__ == '__main__':
    unittest.main()
