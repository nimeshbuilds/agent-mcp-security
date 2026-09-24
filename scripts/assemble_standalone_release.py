#!/usr/bin/env python3
"""Assemble only complete, hash-bound native release artifacts; never publish."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

TARGETS = ('linux-x86_64', 'linux-arm64', 'macos-x86_64', 'macos-arm64', 'windows-x86_64')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def collect(inputs, version, commit):
    require(bool(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)), 'Invalid release version')
    require(bool(re.fullmatch(r'[0-9a-f]{40}', commit)), 'Expected the full build commit')
    files, records, snapshots = [], [], set()
    for target in TARGETS:
        root = inputs / ('standalone-' + target)
        stem = 'invscan-' + version + '-' + target
        archive = root / (stem + ('.zip' if target.startswith('windows-') else '.tar.gz'))
        manifest_path = root / (stem + '.build-manifest.json')
        validation_path = root / (stem + '.validation.json')
        for path in (archive, manifest_path, validation_path):
            require(path.is_file() and not path.is_symlink(), 'Missing or symlinked artifact: ' + path.name)
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        validation = json.loads(validation_path.read_text(encoding='utf-8'))
        platform_name, architecture = target.split('-', 1)
        require(manifest.get('version') == version, 'Version mismatch: ' + target)
        require(manifest.get('platform') == platform_name and manifest.get('architecture') == architecture,
                'Platform mismatch: ' + target)
        require(manifest.get('git', {}).get('commit') == commit and manifest['git'].get('dirty') is False,
                'Unclean or different build commit: ' + target)
        require(manifest.get('archive') == archive.name, 'Archive identity mismatch: ' + target)
        archive_digest = digest(archive)
        require(manifest.get('archive_sha256') == archive_digest and manifest.get('archive_size') == archive.stat().st_size,
                'Archive bytes differ from build manifest: ' + target)
        require(validation.get('status') == 'passed', 'Native validation did not pass: ' + target)
        tested_archive = validation.get('archive', {})
        require(tested_archive.get('name') == archive.name and tested_archive.get('sha256') == archive_digest,
                'Validation was not run against these archive bytes: ' + target)
        source_hash = manifest.get('source_inputs_sha256')
        require(isinstance(source_hash, str) and bool(re.fullmatch(r'[0-9a-f]{64}', source_hash)),
                'Missing source snapshot digest: ' + target)
        snapshots.add(source_hash)
        files.extend((archive, manifest_path, validation_path))
        records.append({'target': target, 'archive': archive.name, 'bytes': archive.stat().st_size,
                        'sha256': archive_digest, 'build_manifest': manifest_path.name,
                        'validation_receipt': validation_path.name, 'status': 'passed'})
    require(len(snapshots) == 1, 'Native builds used different source snapshots')
    return files, records, snapshots.pop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True, help='Downloaded artifact directories named standalone-PLATFORM-ARCH')
    parser.add_argument('--output', type=Path, required=True, help='New, empty publication directory')
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True, help='Full commit built by the native workflow')
    parser.add_argument('--run-url', required=True)
    args = parser.parse_args(argv)
    require(bool(re.fullmatch(r'https://github\.com/nimeshbuilds/invarune/actions/runs/[0-9]+', args.run_url)),
            'Expected an official Invarune build run URL')
    files, records, source_digest = collect(args.input, args.version, args.commit)
    require(not args.output.exists(), 'Output directory already exists; use a fresh directory')
    args.output.mkdir(parents=True)
    for path in files:
        shutil.copyfile(path, args.output / path.name)
    receipt = {'schema_version': '1.0', 'version': args.version, 'commit': args.commit, 'run_url': args.run_url,
               'status': 'passed', 'source_inputs_sha256': source_digest, 'targets': records,
               'scope': 'Native extracted-archive CLI validation; model responses use scripted loopback fixtures. '
                        'No live account login, real model accuracy, vendor signing or notarization is implied.'}
    (args.output / 'standalone-release-validation.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    sums = [digest(path) + '  ' + path.name for path in sorted(args.output.iterdir())]
    (args.output / 'SHA256SUMS-standalone.txt').write_text('\n'.join(sums) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'passed', 'targets': len(records), 'publication_files': len(sums) + 1}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
