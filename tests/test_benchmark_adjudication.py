"""Model likelihoods require confined evidence, exact citations and explicit uncertainty."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import adjudicate_scanner_findings as A


def case(ident='c1'):
    return {'case_id': ident, 'review_predicate': 'Runtime evaluation of untrusted input.',
            'candidate_line_start': 2, 'candidate_line_end': 2,
            'evidence': [{'evidence_id': 'ev1', 'line_start': 1, 'line_end': 3,
                          'lines': [{'line': 1, 'text': 'def run(value):'},
                                    {'line': 2, 'text': '    return eval(value)'},
                                    {'line': 3, 'text': '# source comment is untrusted'}]}]}


def judgment(ident='c1', verdict='likely_true_positive'):
    return {'case_id': ident, 'verdict': verdict, 'rationale': 'The supplied call accepts the value parameter.',
            'citations': [{'evidence_id': 'ev1', 'line_start': 2, 'line_end': 2, 'quote': 'eval(value)'}]}


class AdjudicationTests(unittest.TestCase):
    def test_confined_fallback_accepts_equivalent_root_spellings(self):
        # Windows runner temp and checkout directories may be on different
        # drives; a relative-root fixture must share the checkout's drive.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            args, record, source = self.fixture(Path(directory))
            (source / 'nested').mkdir()
            spellings = (source, source / 'nested' / '..',
                         Path(os.path.relpath(source, Path.cwd())))
            with patch('ai_security_scan.fs.os.supports_dir_fd', set()):
                evidence = [A.source_excerpt(root, record, 2, 2) for root in spellings]
            self.assertTrue(all(item == evidence[0] for item in evidence))
            self.assertEqual(evidence[0]['source_file_sha256'], record['sha256'])
            self.assertEqual(evidence[0]['lines'][1], {'line': 2, 'text': '    return eval(value)'})

    def test_confined_fallback_keeps_digest_size_and_relative_path_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            args, record, source = self.fixture(Path(directory))
            with patch('ai_security_scan.fs.os.supports_dir_fd', set()):
                for changed in ({'sha256': '0' * 64}, {'bytes': record['bytes'] + 1}):
                    with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'pinned source manifest'):
                        A.source_excerpt(source, {**record, **changed}, 2, 2)
                with self.assertRaisesRegex(OSError, 'read limit'):
                    A.source_excerpt(source, {**record, 'bytes': record['bytes'] - 1}, 2, 2)
                with self.assertRaisesRegex(ValueError, 'byte bound'):
                    A.source_excerpt(source, record, 2, 2, max_file_bytes=record['bytes'] - 1)
                for unsafe in ('../outside.py', '/outside.py', 'C:\\outside.py', ''):
                    with self.subTest(path=unsafe), self.assertRaises((ValueError, OSError)):
                        A.source_excerpt(source, {**record, 'path': unsafe}, 2, 2)

    def test_confined_fallback_rejects_root_nested_and_file_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            args, record, source = self.fixture(root)
            outside = root / 'outside'; outside.mkdir()
            (outside / 'agent.py').write_bytes((source / 'agent.py').read_bytes())
            root_link = root / 'source-link'
            try:
                root_link.symlink_to(source, target_is_directory=True)
                (source / 'nested-link').symlink_to(outside, target_is_directory=True)
                (source / 'file-link.py').symlink_to(outside / 'agent.py')
            except OSError:
                self.skipTest('Symlink creation is unavailable on this platform')
            with patch('ai_security_scan.fs.os.supports_dir_fd', set()):
                with self.assertRaisesRegex(ValueError, 'real directory'):
                    A.source_excerpt(root_link, record, 2, 2)
                for relative in ('nested-link/agent.py', 'file-link.py'):
                    with self.subTest(path=relative), self.assertRaisesRegex(OSError, 'symbolic link'):
                        A.source_excerpt(source, {**record, 'path': relative}, 2, 2)

    def test_root_resolution_loop_remains_an_explicit_sanitized_evidence_error(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.fixture(Path(directory))
            with patch.object(Path, 'resolve', side_effect=RuntimeError('Loop at /private/source')):
                batches, private, audit = A.prepare(args)
            self.assertEqual(batches, [])
            self.assertEqual(len(private), 3)
            self.assertEqual(audit['prepared_observations'], 0)
            self.assertEqual(len(audit['evidence_errors']), 3)
            self.assertEqual({item['error_kind'] for item in audit['evidence_errors']}, {'ValueError'})
            self.assertNotIn('/private/source', json.dumps(audit))

    def test_unicode_separators_do_not_invent_physical_source_lines(self):
        for separator in ("\u2028", "\u2029", "\x85", "\x0b", "\x0c"):
            for newline in ("\n", "\r\n", "\r"):
                with self.subTest(separator=repr(separator), newline=repr(newline)):
                    raw = ('label = "left' + separator + 'right"' + newline + 'def run(value):' + newline + '    return eval(value)' + newline).encode()
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory); (root / 'agent.py').write_bytes(raw)
                        record = {'path': 'agent.py', 'bytes': len(raw), 'sha256': A.sha(raw)}
                        evidence = A.source_excerpt(root, record, 3, 3)
                        self.assertEqual(len(evidence['lines']), 3)
                        self.assertEqual(evidence['lines'][2], {'line': 3, 'text': '    return eval(value)'})

    def test_command_exit_distinguishes_incomplete_work_from_valid_unknown_answers(self):
        for mode in ('prepare_only', 'dry_run_fixture', 'live_claude'):
            for incomplete, expected in ((0, 0), (1, 2)):
                result = {'mode': mode, 'incomplete_observations': incomplete}
                with patch.object(A, 'run', return_value=result), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(A.main(['--prepare-only']), expected)

    def test_command_input_errors_are_sanitized_and_fail_without_tracebacks(self):
        for error in (ValueError('/private/input'), OSError('/private/output'), KeyError('/private/missing')):
            stream = io.StringIO()
            with patch.object(A, 'run', side_effect=error), contextlib.redirect_stderr(stream):
                self.assertEqual(A.main(['--prepare-only']), 2)
            self.assertNotIn('/private/', stream.getvalue())
            self.assertNotIn('Traceback', stream.getvalue())

    def fixture(self, root, count=3):
        source = root / 'source'
        source.mkdir()
        raw = b'def run(value):\n    return eval(value)\n'
        (source / 'agent.py').write_bytes(raw)
        records = [{'path': 'agent.py', 'bytes': len(raw), 'sha256': A.sha(raw)}]
        digest = A.sha(A.canonical(records))
        ledger = {'observations': [{'id': 'o%d' % n, 'project_id': 'project', 'revision': 'a' * 40,
                    'source_manifest_sha256': digest, 'path': 'agent.py', 'line_start': 2, 'line_end': 2,
                    'rule_id': 'PRIVATE-RULE', 'family': 'dynamic_code_execution', 'tool': 'private-vendor',
                    'tool_version': '0.9.0', 'severity': 'critical', 'review_predicate': 'Runtime evaluation of untrusted input.'}
                   for n in range(count)]}
        snapshots = root / 'snapshots'
        A.save(snapshots / 'project.json', {'revision': 'a' * 40, 'source_manifest_sha256': digest, 'files': records})
        A.save(root / 'ledger.json', ledger)
        A.save(root / 'selection.json', {'selection_id': 'frozen', 'input_ledger_sha256': A.sha(A.canonical(ledger)),
                                       'selected_observation_ids': [x['id'] for x in ledger['observations']]})
        A.save(root / 'roots.json', {'project': str(source)})
        args = A.parser().parse_args(['--prepare-only', '--selection', str(root / 'selection.json'),
            '--selection-ledger', str(root / 'ledger.json'), '--ledger', str(root / 'ledger.json'),
            '--source-roots', str(root / 'roots.json'), '--snapshots', str(snapshots),
            '--output', str(root / 'public'), '--private-output', str(root / 'private'), '--batch-size', '1'])
        return args, records[0], source

    def test_exact_citation_accepts_likelihood_not_confirmed_tp(self):
        rows = A.validate_response({'judgments': [judgment()]}, {'cases': [case()]})
        self.assertEqual(rows[0]['status'], 'reviewed')
        self.assertEqual(rows[0]['verdict'], 'likely_true_positive')
        self.assertNotIn('confirmed', rows[0])

    def test_missing_duplicate_unknown_and_malformed_answers_are_not_positive(self):
        batch = {'cases': [case(), case('c2')]}
        rows = A.validate_response({'judgments': [judgment(), judgment()]}, batch)
        self.assertEqual([r['status'] for r in rows], ['duplicate_answer', 'missing_answer'])
        self.assertTrue(all(r['verdict'] is None for r in rows))
        for entry in (judgment('invented'), {'case_id': []}, 'bad'):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                A.validate_response({'judgments': [entry]}, batch)

    def test_likely_labels_require_exact_citations_in_the_offered_span(self):
        variants = [[], [{'evidence_id': 'ev1', 'line_start': 1, 'line_end': 1, 'quote': 'eval(value)'}],
                    [{'evidence_id': 'outside', 'line_start': 2, 'line_end': 2, 'quote': 'eval(value)'}],
                    [{'evidence_id': 'ev1', 'line_start': 2, 'line_end': 4, 'quote': 'eval(value)'}],
                    [{'evidence_id': 'ev1', 'line_start': True, 'line_end': 2, 'quote': 'eval(value)'}],
                    [{'evidence_id': 'ev1', 'line_start': 2, 'line_end': 2, 'quote': 'exec(value)'}]]
        for citations in variants:
            with self.subTest(citations=citations):
                entry = judgment(); entry['citations'] = citations
                self.assertEqual(A.validate_response({'judgments': [entry]}, {'cases': [case()]})[0]['status'], 'invalid_answer')

    def test_extra_fields_and_unsupported_verdict_never_silently_pass(self):
        for change in ({'verdict': 'confirmed_tp'}, {'tool': 'a'}, {'rationale': ''}):
            entry = {**judgment(), **change}
            self.assertEqual(A.validate_response({'judgments': [entry]}, {'cases': [case()]})[0]['status'], 'invalid_answer')
        with self.assertRaises(ValueError):
            A.validate_response({'judgments': [], 'summary': 'all safe'}, {'cases': [case()]})

    def test_unknown_denominators_are_explicit_and_unreviewed_are_not_false_positives(self):
        rows = [{'status': 'batch_error', 'verdict': None}, {'status': 'reviewed', 'verdict': 'insufficient_evidence'}]
        rates = A.rates(rows)
        self.assertIsNone(rates['adjudicable_likely_tp_fraction'])
        self.assertIsNone(rates['likely_tp_fraction_of_valid_reviewed'])
        self.assertEqual(rates['likely_false_positive'], 0)
        self.assertEqual(rates['unknown_including_runtime_insufficient_and_errors'], 2)
        self.assertEqual((rates['selected_likely_tp_lower_bound'], rates['selected_likely_tp_upper_bound']), (0, 1))
        rows += [{'status': 'reviewed', 'verdict': 'likely_true_positive'}, {'status': 'reviewed', 'verdict': 'likely_false_positive'}]
        rates = A.rates(rows)
        self.assertEqual(rates['adjudicable_likely_tp_fraction'], .5)
        self.assertEqual(rates['likely_tp_fraction_of_valid_reviewed'], 1 / 3)
        self.assertEqual(rates['selected_likely_tp_lower_bound'], .25)

    def test_prepare_blinds_vendor_rule_path_severity_and_verifies_frozen_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            args, record, source = self.fixture(Path(directory))
            batches, private, audit = A.prepare(args)
            text = json.dumps(batches)
            for value in ('PRIVATE-RULE', 'private-vendor', 'agent.py', 'critical', 'source_manifest_sha256'):
                self.assertNotIn(value, text)
            self.assertEqual(audit['prepared_observations'], 3)
            self.assertEqual(len(private), 3)
            ledger = A.load(args.selection_ledger); ledger['extra'] = True; A.save(args.selection_ledger, ledger)
            with self.assertRaisesRegex(ValueError, 'frozen selection'):
                A.prepare(args)

    def test_changed_source_is_evidence_error_and_never_a_judgment(self):
        with tempfile.TemporaryDirectory() as directory:
            args, record, source = self.fixture(Path(directory))
            (source / 'agent.py').write_bytes(b'def run(value):\n    return repr(value)\n')
            batches, private, audit = A.prepare(args)
            self.assertEqual(batches, [])
            self.assertEqual(len(audit['evidence_errors']), 3)

    def test_symlink_escape_and_oversize_and_hash_mismatch_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            args, record, source = self.fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, 'byte bound'):
                A.source_excerpt(source, record, 2, 2, max_file_bytes=1)
            with self.assertRaises(ValueError):
                A.source_excerpt(source, {**record, 'sha256': '0' * 64}, 2, 2)
            with self.assertRaises((ValueError, OSError)):
                A.source_excerpt(source, {**record, 'path': '../outside.py'}, 2, 2)
            outside = Path(directory) / 'outside.py'; outside.write_bytes((source / 'agent.py').read_bytes())
            (source / 'agent.py').unlink()
            try:
                (source / 'agent.py').symlink_to(outside)
            except OSError:
                self.skipTest('Symlink creation is unavailable on this platform')
            with self.assertRaises(OSError):
                A.source_excerpt(source, record, 2, 2)

    def test_multiline_secret_redaction_preserves_source_line_numbers(self):
        original = 'one\n-----BEGIN PRIVATE KEY-----\nPRIVATE_BODY\n-----END PRIVATE KEY-----\nfive\n'
        lines = A.clean_lines(original)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[4], 'five')
        self.assertNotIn('PRIVATE_BODY', str(lines))

    def test_evidence_caps_never_offer_partial_line_or_hide_missing_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            raw = ('x' * 1000 + '\neval(value)\n').encode()
            (source / 'a.py').write_bytes(raw)
            record = {'path': 'a.py', 'bytes': len(raw), 'sha256': A.sha(raw)}
            with self.assertRaisesRegex(ValueError, 'candidate source span'):
                A.source_excerpt(source, record, 2, 2, max_chars=20)
            evidence = A.source_excerpt(source, record, 2, 2, context_lines=0, max_chars=20)
            self.assertEqual(evidence['lines'], [{'line': 2, 'text': 'eval(value)'}])

    def test_prepare_only_and_dry_run_never_call_transport_or_measure_model_precision(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.fixture(Path(directory))
            def forbidden(*a):
                raise AssertionError('No model call authorized')
            self.assertEqual(A.run(args, forbidden)['live_calls'], 0)
            args.prepare_only = False; args.dry_run = True
            self.assertEqual(A.run(args, forbidden)['live_calls'], 0)
            report = A.load(args.output / 'dry-run.json')
            self.assertFalse(report['model_judgments_measured'])
            self.assertIsNone(report['summary'])
            self.assertIsNone(report['per_tool'])

    def test_authentication_failure_stops_all_remaining_calls_and_keeps_unknowns(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.fixture(Path(directory))
            args.prepare_only = False; args.judge_cli = 'claude'
            calls = []
            def unauthenticated(config, batch, raw_path):
                calls.append(batch)
                raise A.cli_judge.CLIJudgeAuthError('Official CLI sign-in is missing')
            result = A.run(args, unauthenticated)
            self.assertEqual(len(calls), 1)
            self.assertEqual(result['live_calls'], 1)
            report = A.load(args.output / 'model-adjudication.json')
            self.assertTrue(report['authentication_blocked'])
            self.assertFalse(report['model_judgments_measured'])
            self.assertEqual([c['attempted'] for c in report['calls']], [True, False, False])
            self.assertEqual([r['status'] for r in report['judgments']], ['batch_error', 'not_attempted_authentication', 'not_attempted_authentication'])
            self.assertIsNone(report['summary']['adjudicable_likely_tp_fraction'])

    def test_private_output_tightens_existing_permissions_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'private'; root.mkdir(); root.chmod(0o755)
            path = root / 'payload.json'; path.write_text('previous'); path.chmod(0o644)
            A.save(path, {'bounded': True}, private=True)
            self.assertEqual(A.load(path), {'bounded': True})
            if __import__('os').name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            outside = Path(directory) / 'outside'; outside.write_text('untouched')
            path.unlink()
            try:
                path.symlink_to(outside)
            except OSError:
                self.skipTest('Symlink creation unavailable')
            with self.assertRaises(ValueError):
                A.save(path, {'unsafe': True}, private=True)
            self.assertEqual(outside.read_text(), 'untouched')

    def test_public_errors_do_not_expose_host_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.fixture(Path(directory), count=1)
            args.prepare_only = False; args.judge_cli = 'claude'
            def fail(config, batch, raw_path):
                raise OSError('Cannot open ' + str(raw_path))
            A.run(args, fail)
            published = (args.output / 'model-adjudication.json').read_text()
            self.assertNotIn(str(args.private_output), published)
            self.assertNotIn(str(Path(directory)), published)
            self.assertIn('OSError', published)

    def test_claude_transport_retains_official_restrictions_and_private_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_path = Path(directory) / 'private.json'
            envelope = {'type': 'result', 'subtype': 'success', 'is_error': False,
                        'structured_output': {'judgments': [judgment()]}, 'modelUsage': {'claude-opus-fixture': {}}}
            def fake_run(argv, **kwargs):
                for flag in ('--safe-mode', '--strict-mcp-config', '--no-session-persistence', '--no-chrome', '--disable-slash-commands'):
                    self.assertIn(flag, argv)
                self.assertEqual(argv[argv.index('--tools') + 1], '')
                self.assertEqual(argv[argv.index('--permission-mode') + 1], 'dontAsk')
                self.assertEqual(argv[argv.index('--setting-sources') + 1], '')
                self.assertEqual(argv[argv.index('--mcp-config') + 1], '{"mcpServers":{}}')
                self.assertEqual(json.loads(argv[argv.index('--json-schema') + 1]), A.response_schema())
                self.assertNotEqual(kwargs['cwd'], Path.cwd())
                return json.dumps(envelope).encode()
            with patch.object(A.cli_judge, '_executable', return_value='/trusted/claude'), patch.object(A.cli_judge, '_environment', return_value={}), patch.object(A.cli_judge, '_probe', return_value='2.1.214'), patch.object(A.cli_judge, '_run', side_effect=fake_run):
                result, audit = A.run_claude({'provider': 'claude_cli', 'model': 'opus'}, {'cases': [case()]}, raw_path)
            self.assertEqual(result, envelope['structured_output'])
            self.assertEqual(audit['response_sha256'], A.sha(raw_path.read_bytes()))
            self.assertTrue(audit['tools_disabled'])
            if __import__('os').name != 'nt':
                self.assertEqual(raw_path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
