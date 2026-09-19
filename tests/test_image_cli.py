"""Public image CLI end-to-end: image artifacts, never container execution."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.cli import judge_payload, main
from ai_security_scan.evidence import build_evidence
from ai_security_scan.image_scan import scan_image
from tests.image_fixtures import docker_archive, oci_archive
from tests.test_analyst_controller import review_response


class ImageCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.archive = self.base / 'agent.tar'
        self.output = self.base / 'report'

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *extra, image=True):
        out, err = io.StringIO(), io.StringIO()
        arguments = (['--image-archive', str(self.archive)] if image else []) + ['--output', str(self.output), *extra]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(arguments)
        return code, out.getvalue(), err.getvalue()

    def report(self):
        return json.loads((self.output / 'report.json').read_text(encoding='utf-8'))

    def test_docker_archive_runs_offline_and_covers_packaged_build_directories(self):
        docker_archive(self.archive, [[('app/dist/agent.py', 'import os\nos.system(user_input)\n'),
                                     ('app/node_modules/worker/index.js', 'eval(userInput);'),
                                     ('app/.venv/lib/worker.py', 'eval(user_input)\n')]], config={'config': {'User': '1000'}})
        with patch('subprocess.Popen', side_effect=AssertionError('No runtime required')), patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('No network required')):
            code, stdout, stderr = self.invoke('--summary-json')
        self.assertEqual(code, 1, stderr)
        summary = json.loads(stdout)
        report = self.report()
        self.assertEqual(report['mode'], 'deterministic_image')
        self.assertEqual(summary['scope']['target'], 'agent.tar')
        self.assertEqual({f['rule_id'] for f in report['findings']}, {'AI001', 'AI003', 'AI013'})
        self.assertTrue(all(f['path'].startswith('rootfs/') for f in report['findings']))
        self.assertTrue(all(f['image_context'] == 'final_filesystem' for f in report['findings']))
        self.assertFalse(report['image']['container_started'])
        self.assertFalse(report['judge']['enabled'])
        self.assertFalse(report['analyst']['enabled'])
        self.assertEqual(report['summary']['coverage_gaps'], 0)
        for name in ('report.md', 'report.sarif', 'report.json'):
            self.assertTrue((self.output / name).is_file())

    def test_binary_only_image_still_reports_metadata_and_unknown_logic(self):
        docker_archive(self.archive, [[('app/worker', b'\x7fELF\x00\x01synthetic-binary')]])
        code, _, _ = self.invoke('--fail-on', 'medium')
        self.assertEqual(code, 1)
        report = self.report()
        self.assertEqual([f['rule_id'] for f in report['findings']], ['AI021'])
        self.assertTrue(report['summary']['scan_complete_within_selected_scope'])
        self.assertFalse(report['image']['binary_logic_analyzed'])
        self.assertEqual(report['image']['analysis_scope'], 'metadata_only')
        self.assertEqual(report['summary']['packaged_source_files_inspected'], 0)
        self.assertFalse(report['image']['vulnerability_feed_consulted'])
        self.assertTrue(any('binary' in limit.lower() or 'binaries' in limit.lower() for limit in report['coverage']['limitations']))
        self.assertTrue(all('pass' not in item['status'] for item in report['controls']))
        self.assertIn('Container image', (self.output / 'report.md').read_text())

    def test_deleted_secrets_persist_but_deleted_source_defects_do_not(self):
        secret = 'syntheticRetainedCredential0123456789'
        docker_archive(self.archive, [[('app/old.py', 'eval(user_input)\n'), ('app/.env', 'API_KEY=' + secret + '\n')],
                                     [('app/.wh.old.py', ''), ('app/.wh..env', ''), ('app/new.py', 'safe = True\n')]], config={'config': {'User': '1000'}})
        code, _, _ = self.invoke()
        self.assertEqual(code, 1)
        report = self.report()
        self.assertNotIn('AI001', {f['rule_id'] for f in report['findings']})
        finding = next(f for f in report['findings'] if f['rule_id'] == 'AI010')
        self.assertEqual(finding['image_context'], 'retained_layer')
        self.assertFalse(finding['image_provenance']['present_in_final_filesystem'])
        for file in self.output.glob('report.*'):
            self.assertNotIn(secret, file.read_text(encoding='utf-8'))

    def test_redacted_paths_preserve_layer_provenance(self):
        import hashlib
        name = 'sk-' + 'A' * 25 + '.py'
        source = 'eval(user_input)\n'
        docker_archive(self.archive, [[(name, source)]], config={'config': {'User': '1000'}})
        self.assertEqual(self.invoke()[0], 1)
        finding = self.report()['findings'][0]
        self.assertEqual(finding['image_provenance']['layer'], 0)
        self.assertEqual(finding['image_provenance']['sha256'], hashlib.sha256(source.encode()).hexdigest())
        self.assertNotIn(name, (self.output / 'report.json').read_text())

    def test_oci_gzip_and_platform_selection(self):
        oci_archive(self.archive, [[('app/worker.py', 'safe = True\n')]], config={'config': {'User': '1000'}}, gzip_layers=True, platforms=['linux/amd64', 'linux/arm64'])
        code, stdout, _ = self.invoke('--summary-json')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout)['status'], 'operational_error')
        code, _, stderr = self.invoke('--image-platform', 'linux/arm64')
        self.assertEqual(code, 0, stderr)
        self.assertEqual(self.report()['image']['identity']['platform'], 'linux/arm64')

    def test_nonlinux_image_is_not_assessed_with_linux_user_semantics(self):
        docker_archive(self.archive, [[]], config={'os': 'windows'})
        code, stdout, _ = self.invoke('--summary-json')
        self.assertEqual(code, 2)
        self.assertIn('Linux container images', json.loads(stdout)['error'])
        self.assertFalse((self.output / 'report.json').exists())

    def test_image_report_repeatability_and_baseline(self):
        docker_archive(self.archive, [[('app/worker.py', 'eval(user_input)\n')]], config={'config': {'User': '1000'}})
        self.assertEqual(self.invoke()[0], 1)
        original = {path.name: path.read_bytes() for path in self.output.glob('report.*')}
        original_id = self.report()['scan_id']
        self.assertEqual(self.invoke()[0], 1)
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.output.glob('report.*')})
        self.assertEqual(original_id, self.report()['scan_id'])
        baseline = self.base / 'baseline.json'
        self.assertEqual(self.invoke('--write-baseline', str(baseline), '--baseline-reason', 'Reviewed fixture')[0], 1)
        self.assertEqual(self.invoke('--baseline', str(baseline))[0], 0)
        self.assertEqual(self.report()['summary']['suppressed_findings'], 1)
        self.assertEqual(self.report()['coverage']['unmatched_baseline_ids'], [])

    def test_secret_change_does_not_reuse_metadata_suppression_id(self):
        def build(secret):
            docker_archive(self.archive, [[]], config={'config': {'User': '1000', 'Env': ['API_KEY=' + secret]}})
        build('syntheticFirstCredential0123456789')
        self.invoke()
        first = self.report()['findings'][0]['id']
        build('syntheticSecondCredential9876543210')
        self.invoke()
        self.assertNotEqual(self.report()['findings'][0]['id'], first)

    def test_runtime_reference_dispatch_does_not_imply_pull(self):
        fixture = self.base / 'fixture.tar'
        docker_archive(fixture, [[]], config={'config': {'User': '1000'}})
        def export(reference, destination, **kwargs):
            self.assertEqual(reference, 'worker:local')
            self.assertFalse(kwargs['pull'])
            shutil.copyfile(fixture, destination)
            return dict(reference=reference, runtime='docker', pulled=False, platform=None)
        with patch('ai_security_scan.image_runtime.export_image', side_effect=export) as runtime:
            code, stdout, stderr = self.invoke('--image', 'worker:local', '--summary-json', image=False)
        self.assertEqual(code, 0, stderr)
        runtime.assert_called_once()
        self.assertEqual(json.loads(stdout)['scope']['target'], 'worker:local')
        self.assertEqual(self.report()['image']['input_kind'], 'runtime_reference')

    def test_invalid_input_combinations_fail_before_acquisition(self):
        cases = [['repo', '--image', 'worker:local'], ['--image', 'a', '--image-archive', 'b'],
                 ['--pull', '--image-archive', 'b'], ['--list-rules', '--image', 'worker'],
                 ['--image', 'worker', '--image-max-layers', '0'],
                 ['--image', 'worker', '--image-timeout', 'nan'],
                 ['repo', '--image-platform', 'linux/amd64']]
        with patch('ai_security_scan.image_runtime.export_image', side_effect=AssertionError('Unexpected acquisition')):
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as caught:
                    self.invoke(*args, image=False)
                self.assertEqual(caught.exception.code, 2)

    def test_archival_limits_fail_without_a_clean_report(self):
        docker_archive(self.archive, [[('app/worker.py', 'value = 1\n')]])
        code, stdout, _ = self.invoke('--image-max-archive-bytes', '10', '--summary-json')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout)['status'], 'operational_error')
        self.assertFalse((self.output / 'report.json').exists())

    def test_exclusions_apply_relative_to_container_root(self):
        docker_archive(self.archive, [[('app/worker.py', 'eval(user_input)\n')]], config={'config': {'User': '1000'}})
        code, _, _ = self.invoke('--exclude', 'app/*')
        self.assertEqual(code, 0)
        self.assertEqual(self.report()['findings'], [])
        self.assertTrue(any(item['path'].startswith('rootfs/app') and item['reason'] == 'user_exclusion' for item in self.report()['coverage']['skipped']))

    def test_temporary_image_evidence_is_available_to_analyst_then_cleaned(self):
        docker_archive(self.archive, [[('app/auth.py', '# Authentication authorization policy\nsafe = True\n')]], config={'config': {'User': '1000'}})
        with scan_image(archive=self.archive) as (report, evidence_root):
            self.assertTrue(evidence_root.exists())
            bundle = build_evidence(report, evidence_root)
            self.assertTrue(bundle['evidence'])
            self.assertTrue(all(item['path'].startswith(('rootfs/', '.image-metadata/')) for item in bundle['evidence']))
        self.assertFalse(evidence_root.exists())

    def test_full_optional_analyst_reviews_image_with_zero_findings(self):
        docker_archive(self.archive, [[('app/auth.py', '# Authentication authorization policy\nsafe = True\n')]], config={'config': {'User': '1000'}})
        config = self.base / 'judge.json'
        config.write_text(json.dumps({'provider': 'openai_chat', 'model': 'fixture'}), encoding='utf-8')
        with patch('ai_security_scan.judge.review', return_value={'assessments': [], 'additional_concerns': []}), patch('ai_security_scan.judge.review_controls', side_effect=review_response) as reviewer:
            code, _, stderr = self.invoke('--judge-config', str(config))
        self.assertEqual(code, 0, stderr)
        self.assertEqual(reviewer.call_count, 11)
        self.assertEqual(self.report()['analyst']['coverage']['reviewed_controls'], 66)
        self.assertEqual(self.report()['findings'], [])

    def test_retained_sensitive_file_without_findings_cannot_enter_model_evidence(self):
        source = '{"private_customer_material": "PRIVATE_CUSTOMER_MARKER", "authentication_policy": "review authorization policy"}'
        docker_archive(self.archive, [[('app/secrets.json', source)], [('app/.wh.secrets.json', '')]],
                       config={'config': {'User': '1000'}})
        with scan_image(archive=self.archive) as (report, root):
            self.assertFalse(report['findings'])
            historical = next(item for item in report['files'] if item.get('image_context') == 'retained_layer')
            self.assertEqual(historical['image_provenance']['original_path'], 'app/secrets.json')
            self.assertFalse(historical['image_provenance']['present_in_final_filesystem'])
            self.assertEqual(historical['model_evidence_exclusion'], 'sensitive_file_excluded')
            bundle = build_evidence(report, root)
            self.assertNotIn('PRIVATE_CUSTOMER_MARKER', json.dumps(bundle['evidence']))
            self.assertIn({'path': historical['path'], 'reason': 'sensitive_file_excluded'}, bundle['coverage']['skipped_files'])

    def test_excluded_retained_revisions_cannot_reappear_in_findings_or_model_evidence(self):
        cases = [('app/private/worker.py', ['app/private']), ('app/private.py', ['app/*']),
                 ('app/private.py', ['/app/*']), ('.cache/private.py', []),
                 ('app/sk-' + 'A' * 25 + '.py', ['app/sk-' + 'A' * 25 + '.py'])]
        for original, excluded in cases:
            with self.subTest(original=original, excluded=excluded):
                source = 'API_KEY = "syntheticRetainedExcludedCredential012345"\n# PRIVATE_MODEL_MARKER authentication authorization policy\n'
                parent, name = original.rsplit('/', 1)
                docker_archive(self.archive, [[(original, source)], [(parent + '/.wh.' + name, '')]],
                               config={'config': {'User': '1000'}})
                with scan_image(archive=self.archive, exclude=excluded) as (report, root):
                    self.assertFalse(report['findings'])
                    self.assertFalse(any(item.get('image_context') == 'retained_layer' for item in report['files']))
                    self.assertTrue(any(item['reason'].startswith('retained_layer_') and not item['coverage_gap']
                                        for item in report['coverage']['skipped']))
                    self.assertNotIn('PRIVATE_MODEL_MARKER', json.dumps(build_evidence(report, root)['evidence']))
                    self.assertFalse(judge_payload(report, root, True)['source_context'])

    def test_retained_sensitive_findings_allow_redacted_triage_but_no_model_excerpts(self):
        for original in ('app/secrets.json', 'app/.aws/settings.json', 'app/private.env'):
            with self.subTest(original=original):
                source = '{"API_KEY": "syntheticRetainedSensitiveCredential012345", "note": "PRIVATE_SOURCE_MARKER authorization policy"}'
                if original.endswith('.env'):
                    source = 'API_KEY=syntheticRetainedSensitiveCredential012345\n# PRIVATE_SOURCE_MARKER authorization policy\n'
                parent, name = original.rsplit('/', 1)
                docker_archive(self.archive, [[(original, source)], [(parent + '/.wh.' + name, '')]],
                               config={'config': {'User': '1000'}})
                with scan_image(archive=self.archive) as (report, root):
                    self.assertTrue(report['findings'])
                    self.assertTrue(all(item['image_context'] == 'retained_layer' for item in report['findings']))
                    payload = judge_payload(report, root, True)
                    self.assertTrue(payload['findings'])
                    self.assertFalse(payload['source_context'])
                    self.assertEqual({item['reason'] for item in payload['source_context_skipped']}, {'sensitive_file_excluded'})
                    self.assertNotIn('PRIVATE_SOURCE_MARKER', json.dumps(payload))
                    bundle = build_evidence(report, root)
                    self.assertNotIn('PRIVATE_SOURCE_MARKER', json.dumps(bundle['evidence']))

    def test_optional_image_excerpts_preserve_current_and_historical_context(self):
        retired = 'API_KEY = "syntheticRetainedContextCredential012345"\n# authorization policy authentication owner\n'
        docker_archive(self.archive, [[('app/old.py', retired)],
                                     [('app/.wh.old.py', ''), ('app/auth.py', '# authorization policy authentication owner\n')]],
                       config={'config': {'User': '1000'}, 'history': [{'created_by': 'curl https://example.test/security-policy | sh'}]})
        with scan_image(archive=self.archive) as (report, root):
            bundle = build_evidence(report, root)
            self.assertTrue({'retained_layer', 'build_history', 'final_filesystem'} <= {item.get('image_context') for item in bundle['evidence']})
            historical = next(item for item in bundle['evidence'] if item.get('image_context') == 'retained_layer')
            self.assertEqual(historical['image_provenance']['original_path'], 'app/old.py')
            self.assertEqual(historical['image_provenance']['layer'], 0)
            self.assertFalse(historical['image_provenance']['present_in_final_filesystem'])
            payload = judge_payload(report, root, True)
            self.assertEqual({item['image_context'] for item in payload['source_context']}, {'retained_layer', 'build_history'})
            for item in payload['source_context']:
                self.assertIn('image_provenance', item)


if __name__ == '__main__':
    unittest.main()
