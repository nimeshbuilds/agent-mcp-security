#!/usr/bin/env python3
"""Exercise actual Docker-built artifacts without running the fixture container."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

PROJECT = Path(__file__).resolve().parents[1]


def command(arguments, *, timeout=120, expected=0):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode != expected:
        raise RuntimeError('Validation command failed: ' + arguments[0] + ' (exit %s)' % result.returncode)
    return result


def main():
    docker = shutil.which('docker')
    if not docker:
        raise RuntimeError('Docker is required for this integration validation')
    tag = 'nimeshbuild-image-scan-test:' + uuid.uuid4().hex
    built = False
    with tempfile.TemporaryDirectory(prefix='image-cli-validation-') as temporary:
        root = Path(temporary)
        context = root / 'context'
        context.mkdir()
        (context / 'Dockerfile').write_text('''FROM scratch
COPY worker.py /app/dist/worker.py
COPY old.env /app/.env
COPY replacement.env /app/.env
COPY worker-binary /app/worker-binary
ENV SERVICE_API_KEY=syntheticImageConfigCredential0123456789
USER 1000
ENTRYPOINT ["/app/worker-binary"]
''', encoding='utf-8')
        (context / 'worker.py').write_text('import os\nos.system(user_input)\n', encoding='utf-8')
        (context / 'old.env').write_text('API_KEY=syntheticRetainedLayerCredential987654321\n', encoding='utf-8')
        (context / 'replacement.env').write_text('LOG_LEVEL=info\n', encoding='utf-8')
        # A real native executable is packaged, but never executed by this test.
        shutil.copyfile('/bin/true', context / 'worker-binary')
        try:
            command([docker, 'build', '--network=none', '--pull=false', '--tag', tag, str(context)], timeout=180)
            built = True
            output = root / 'reference-report'
            invocation = [sys.executable, str(PROJECT / 'scan.py'), '--image', tag, '--output', str(output), '--summary-json']
            result = command(invocation, expected=1)
            summary = json.loads(result.stdout)
            report = json.loads((output / 'report.json').read_text(encoding='utf-8'))
            assert summary['image']['container_started'] is False
            assert report['summary']['coverage_gaps'] == 0, report['coverage']['errors']
            assert any(item['rule_id'] == 'AI003' and item['path'] == 'rootfs/app/dist/worker.py' for item in report['findings'])
            assert any(item['rule_id'] == 'AI010' and item['image_context'] == 'runtime_configuration' for item in report['findings'])
            assert any(item['rule_id'] == 'AI010' and item['image_context'] == 'retained_layer' for item in report['findings'])
            assert report['image']['binary_logic_analyzed'] is False
            archive = root / 'built-image.tar'
            command([docker, 'image', 'save', '--output', str(archive), tag])
            archive_output = root / 'archive-report'
            command([sys.executable, str(PROJECT / 'scan.py'), '--image-archive', str(archive), '--output', str(archive_output)], expected=1)
            archive_report = json.loads((archive_output / 'report.json').read_text(encoding='utf-8'))
            assert report['image']['identity']['config_digest'] == archive_report['image']['identity']['config_digest']
            assert report['findings'] == archive_report['findings']
            # Apply user policy after the same actual runtime image has been read.
            review_config = root / 'trusted-review.json'
            review_config.write_text(json.dumps({'schema_version': '1.0', 'rules': {
                item['rule_id']: {'status': 'justified', 'reason': 'Synthetic built-image review fixture only.'}
                for item in report['findings']}}), encoding='utf-8')
            reviewed_output = root / 'reviewed-reference-report'
            command([sys.executable, str(PROJECT / 'scan.py'), '--image', tag, '--output', str(reviewed_output),
                     '--review-config', str(review_config)])
            reviewed = json.loads((reviewed_output / 'report.json').read_text(encoding='utf-8'))
            assert reviewed['summary']['open_findings'] == 0
            assert reviewed['summary']['justified_findings'] == len(report['findings'])
            assert {f['id'] for f in reviewed['findings']} == {f['id'] for f in report['findings']}
            assert reviewed['image']['container_started'] is False
            for directory in (output, archive_output, reviewed_output):
                for path in directory.glob('report.*'):
                    content = path.read_text(encoding='utf-8')
                    assert 'syntheticImageConfigCredential0123456789' not in content
                    assert 'syntheticRetainedLayerCredential987654321' not in content
            # Verify the source-free, metadata-only path on an actual built image.
            (context / 'Dockerfile').write_text('FROM scratch\nCOPY worker-binary /app/worker\nUSER 1000\nENTRYPOINT ["/app/worker"]\n', encoding='utf-8')
            command([docker, 'build', '--network=none', '--pull=false', '--tag', tag, str(context)], timeout=180)
            result = command([sys.executable, str(PROJECT / 'scan.py'), '--image', tag, '--output', str(root / 'binary-report'), '--summary-json'])
            binary = json.loads(result.stdout)
            assert binary['image']['analysis_scope'] == 'metadata_only'
            assert binary['summary']['packaged_source_files_inspected'] == 0
            assert binary['image']['binary_logic_analyzed'] is False
            print('Actual Docker validation passed: local reference, saved archive, retained secrets, packaged source, review dispositions, binary-only scope, no container execution.')
        finally:
            if built:
                subprocess.run([docker, 'image', 'rm', '--force', tag], capture_output=True, timeout=30)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
