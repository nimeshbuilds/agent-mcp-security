#!/usr/bin/env python3
"""Execute the ten published journeys using an installed CLI outside a fresh clone.

The manifest and tagged documentation fences must match. Installs optional AI/PDF
packages, starts only a scripted loopback HTTP fixture, and never invokes an
actual provider login, model, target program, or container. External prerequisites
are recorded separately; a fixture protocol success is not live inference.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path('examples/scenarios/scenarios.json')
DOC = Path('docs/SCENARIOS.md')
SETUP_DOC = Path('docs/walkthroughs/setup.md')
GUIDE_PAGES = {
    '01': Path('docs/walkthroughs/01-explore.md'),
    '02': Path('docs/walkthroughs/02-source.md'),
    '03': Path('docs/walkthroughs/03-skills.md'),
    '04': Path('docs/walkthroughs/04-scope.md'),
    '05': Path('docs/walkthroughs/05-images.md'),
    '06': Path('docs/walkthroughs/06-ci.md'),
    '07': Path('docs/walkthroughs/07-exceptions.md'),
    '08': Path('docs/walkthroughs/08-review.md'),
    '09': Path('docs/walkthroughs/09-gateways.md'),
    '10': Path('docs/walkthroughs/10-provider-cli.md'),
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path):
    manifest = json.loads(path.read_text(encoding='utf-8'))
    require(manifest.get('schema_version') == '1.0', 'Unknown scenario manifest schema')
    require([g['id'] for g in manifest['scenarios']] == ['%02d' % n for n in range(1, 11)], 'Manifest must contain exactly ten ordered journeys')
    seen = set()
    for group in manifest['scenarios']:
        for step in group['steps']:
            identity = group['id'] + ':' + step['id']
            require(identity not in seen, 'Duplicate scenario step ' + identity)
            seen.add(identity)
            require(isinstance(step['argv'], list) and bool(step['argv']) and all(isinstance(a, str) for a in step['argv']), 'Invalid argv')
            require(step['argv'][0] in ('{cli}', '{python}', '{invarune}', '{ai-security-scan}'), 'Unrecognized command entry point')
            require(step.get('expected_exit') in (0, 1, 2), 'Missing explicit expected exit')
    return manifest


def render_argument(arg):
    value = arg.replace('{repo}/', '').replace('{work}', 'scan-report/scenarios').replace('{cwd}/', '')
    value = {'{cli}': 'invscan', '{python}': 'python', '{invarune}': 'invarune', '{ai-security-scan}': 'ai-security-scan'}.get(value, value)
    # POSIX single quotes also work for these literal strings in PowerShell.
    return shlex.quote(value)


def command_text(step):
    command = ' '.join(render_argument(arg) for arg in step['argv'])
    if step.get('background'):
        return '# Run in a second terminal; leave it open until scenario 9 finishes.\n' + command
    return command + ('  # Expected exit ' + str(step['expected_exit']) if step['expected_exit'] else '')


def documentation_blocks(manifest):
    blocks = {}
    for group in manifest['scenarios']:
        commands = []
        for step in group['steps']:
            if step.get('background'):
                blocks[group['id'] + '-server'] = command_text(step)
            else:
                commands.append(command_text(step))
        blocks[group['id']] = '\n'.join(commands)
    return blocks


def verify_documentation(manifest, text):
    found = re.findall(r'<!-- invscan-scenario:([0-9]{2}(?:-server)?) -->\s*```(?:sh|bash|shell)\n(.*?)\n```', text, re.S)
    require(len(found) == len(dict(found)), 'Duplicate tagged scenario documentation block')
    actual = dict(found)
    expected = documentation_blocks(manifest)
    require(set(actual) == set(expected), 'Documentation is missing or adds a tagged scenario block')
    for key, value in expected.items():
        require(actual[key] == value, 'Documentation command drift in scenario ' + key)
    return len(expected)


def documentation_steps(manifest):
    """One exact, independently copyable command fence per manifest step."""
    return {group['id'] + ':' + step['id']: command_text(step)
            for group in manifest['scenarios'] for step in group['steps']}


def load_documentation(source):
    """Require every published walkthrough, including the scenario hub."""
    documents = {}
    for path in (DOC, SETUP_DOC, *GUIDE_PAGES.values()):
        require((source / path).is_file(), 'Missing scenario documentation file ' + path.as_posix())
        documents[path.as_posix()] = (source / path).read_bytes().decode('utf-8')
    return documents


def verify_walkthrough_documentation(manifest, documents):
    """Bind every step to its scenario page; reject omitted or orphan markers."""
    expected_paths = {path.as_posix() for path in (DOC, SETUP_DOC, *GUIDE_PAGES.values())}
    require(set(documents) == expected_paths, 'Scenario documentation file set differs from the published guides')
    expected = documentation_steps(manifest)
    actual = {}
    # Match markers separately as well: a misspelled fence or a marker with no
    # adjacent command must fail, even when all legitimate steps are present.
    marker_pattern = re.compile(r'<!--\s*invscan-step:([^>]*?)\s*-->')
    fence_pattern = re.compile(r'<!-- invscan-step:([^\r\n]*?) -->[ \t]*\r?\n```(?:sh|bash|shell)\r?\n(.*?)\r?\n```(?=\r?\n|$)', re.S)
    for path, text in documents.items():
        markers = marker_pattern.findall(text)
        fences = fence_pattern.findall(text)
        require(len(markers) == len(fences), 'Malformed or unattached scenario step marker in ' + path)
        require('invscan-scenario:' not in text, 'Legacy grouped scenario commands remain in ' + path)
        for identity, command in fences:
            require(identity not in actual, 'Duplicate tagged scenario step ' + identity)
            require(identity in expected, 'Unknown tagged scenario step ' + identity)
            group = identity.split(':', 1)[0]
            require(path == GUIDE_PAGES[group].as_posix(), 'Scenario step ' + identity + ' is in the wrong guide ' + path)
            require(command == expected[identity], 'Documentation command drift in scenario step ' + identity)
            actual[identity] = command
    missing = set(expected) - set(actual)
    require(not missing, 'Documentation is missing scenario steps: ' + ', '.join(sorted(missing)))
    return len(actual)


def documentation_contract(source, manifest, documents):
    return {'tagged_blocks_verified': verify_walkthrough_documentation(manifest, documents),
            'guide_files_verified': len(documents),
            'format': 'individual_step_walkthroughs',
            **verify_feature_map(manifest, (source / 'ai_security_scan/cli.py').read_text(encoding='utf-8'), '\n'.join(documents.values()))}


def documentation_hashes(documents):
    """Hash file bytes, preserving the exact documentation tested on this host."""
    files = {path: hashlib.sha256(documents[path].encode('utf-8')).hexdigest() for path in sorted(documents)}
    aggregate = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    return {'files': files, 'sha256': aggregate}


def verify_documentation_snapshot(documentation_inputs, snapshot):
    snapshot_files = {item['path']: item['sha256'] for item in snapshot['files']}
    require(all(snapshot_files.get(path) == sha256 for path, sha256 in documentation_inputs['files'].items()),
            'Scenario documentation changed between contract validation and execution snapshot')


def verify_feature_map(manifest, cli_source, guide):
    inventory = set()
    for node in ast.walk(ast.parse(cli_source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument':
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    inventory.add(arg.value)
    mapped = manifest.get('feature_scenarios', {})
    require(set(mapped) == inventory, 'Scenario feature map differs from the CLI parser inventory')
    require(all(value in {g['id'] for g in manifest['scenarios']} for value in mapped.values()), 'Feature map references an unknown scenario')
    missing = [flag for flag in inventory if flag != 'target' and not re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', guide)]
    require(not missing, 'Guide omits CLI flags: ' + ', '.join(sorted(missing)))
    return {'option_spellings': len(inventory - {'target'}), 'positional_target': 'target' in inventory}


def lookup(value, path):
    for key in path.split('.'):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def assert_values(value, expected, context):
    for key, wanted in expected.items():
        try:
            actual = lookup(value, key)
        except (KeyError, IndexError, TypeError, ValueError):
            raise RuntimeError(context + ': missing field ' + key) from None
        require(type(actual) is type(wanted) and actual == wanted, context + ': unexpected value for ' + key)


def validate(args, receipt):
    source = args.source.resolve(strict=True)
    manifest = load_manifest(source / MANIFEST)
    receipt['manifest_sha256'] = digest(source / MANIFEST)
    receipt['document_sha256'] = digest(source / DOC) if (source / DOC).is_file() else None
    documents = load_documentation(source)
    receipt['documentation_inputs'] = documentation_hashes(documents)
    if args.skip_doc_check:
        receipt['documentation_contract'] = 'skipped_by_explicit_development_flag'
    else:
        receipt['documentation_contract'] = documentation_contract(source, manifest, documents)
    quickstart = load_module('invarune_scenario_quickstart', source / 'scripts/validate_quickstart.py')
    security = load_module('invarune_scenario_redaction', source / 'ai_security_scan/security.py')
    interpreter = str(Path(args.python).resolve()) if Path(args.python).is_file() else args.python
    with tempfile.TemporaryDirectory(prefix='invarune-scenarios-') as temporary:
        work = Path(temporary).resolve()
        checkout, environment, outside = work / 'checkout', work / 'venv', work / 'outside-checkout'
        outside.mkdir()
        replacements = [(interpreter, '<DIRECT_PYTHON>'), (str(source), '<SOURCE>'), (str(environment), '<VENV>'),
                        (str(checkout), '<CHECKOUT>'), (str(outside), '<SCENARIO_WORKSPACE>'), (str(work), '<WORK>'),
                        (str(Path(tempfile.gettempdir()).resolve()), '<HOST_TEMP>'), (tempfile.gettempdir(), '<HOST_TEMP>'), (str(Path.home()), '<USER_HOME>')]
        def clean(value):
            return quickstart.replace_paths(security.redact(str(value)), replacements)
        child_env = dict(os.environ, PYTHONNOUSERSITE='1', PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1', PIP_NO_INPUT='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
        child_env.pop('PYTHONPATH', None)
        def setup(id, argv, cwd=outside, timeout=180):
            process = subprocess.run([str(v) for v in argv], cwd=cwd, env=child_env, text=True, capture_output=True, timeout=timeout)
            receipt['setup'].append({'id': id, 'command': [clean(v) for v in argv], 'exit_code': process.returncode, 'status': 'passed' if process.returncode == 0 else 'failed'})
            require(process.returncode == 0, id + ': ' + clean(process.stderr[-1500:]))
            return process
        receipt['source_commit'] = setup('source_revision', ['git', 'rev-parse', 'HEAD'], source).stdout.strip()
        setup('fresh_clone', ['git', 'clone', '--quiet', '--no-hardlinks', '--no-local', str(source), str(checkout)])
        quickstart.SNAPSHOT_PATHS += ('examples/scenarios',)
        receipt['snapshot'] = quickstart.snapshot(source, checkout)
        verify_documentation_snapshot(receipt['documentation_inputs'], receipt['snapshot'])
        setup('create_venv', [interpreter, '-m', 'venv', str(environment)])
        bindir = environment / ('Scripts' if os.name == 'nt' else 'bin')
        python = bindir / ('python.exe' if os.name == 'nt' else 'python')
        setup('install_ai_pdf_extras', [python, '-m', 'pip', 'install', '.[ai,pdf]'], checkout, 900)
        result = setup('installed_metadata', [python, '-c', "import ai_security_scan,importlib.metadata as m,json,platform;print(json.dumps({'version':ai_security_scan.__version__,'module':ai_security_scan.__file__,'python':platform.python_version(),'headroom':m.version('headroom-ai'),'reportlab':m.version('reportlab'),'pypdf':m.version('pypdf')}))"])
        receipt['installed'] = json.loads(clean(result.stdout))
        require(receipt['installed']['module'].startswith('<VENV>'), 'Scanner was not imported from the installed environment')
        # Only inert examples and a report-editing utility enter the execution
        # directory. There is no importable scanner source package here.
        for name in ('safer', 'vulnerable', 'skills', 'images', 'investigation', 'scenarios', 'review-config.json'):
            src, dst = checkout / 'examples' / name, outside / 'examples' / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            else:
                shutil.copy2(src, dst)
        (outside / 'scripts').mkdir()
        shutil.copy2(checkout / 'scripts/validate_report_review.py', outside / 'scripts/validate_report_review.py')
        destination = outside / 'scan-report/scenarios'
        destination.mkdir(parents=True)
        substitutions = {'repo': str(outside), 'cwd': str(outside), 'work': str(destination), 'python': str(python),
                         'cli': str(bindir / ('invscan.exe' if os.name == 'nt' else 'invscan')),
                         'invarune': str(bindir / ('invarune.exe' if os.name == 'nt' else 'invarune')),
                         'ai-security-scan': str(bindir / ('ai-security-scan.exe' if os.name == 'nt' else 'ai-security-scan'))}
        def expand(text):
            for key, value in substitutions.items():
                text = text.replace('{' + key + '}', value)
            return text
        processes = []
        try:
            for group in manifest['scenarios']:
                record = {'id': group['id'], 'title': group['title'], 'status': 'running', 'steps': []}
                receipt['scenarios'].append(record)
                for step in group['steps']:
                    command = [expand(v) for v in step['argv']]
                    item = {'id': step['id'], 'documented_command': command_text(step), 'command': [clean(v) for v in command],
                            'expected_exit': step['expected_exit'], 'status': 'running', 'cwd': '<SCENARIO_WORKSPACE>'}
                    record['steps'].append(item)
                    if step.get('background'):
                        proc = subprocess.Popen(command, cwd=outside, env=child_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        processes.append(proc)
                        deadline = time.monotonic() + 10
                        ready = Path(expand(step['ready_file']))
                        while not ready.is_file() and proc.poll() is None and time.monotonic() < deadline:
                            time.sleep(0.05)
                        require(ready.is_file() and proc.poll() is None, 'Scripted loopback server did not become ready')
                        item.update(status='passed', readiness_verified=True, real_model=False)
                        continue
                    prior_files = set(outside.rglob('report.*')) if step.get('no_reports_created') else None
                    process = subprocess.run(command, cwd=outside, env=child_env, capture_output=True, text=True, timeout=180)
                    if prior_files is not None:
                        require(set(outside.rglob('report.*')) == prior_files, step['id'] + ': terminal-only command wrote reports')
                        item['no_reports_created'] = True
                    item.update(exit_code=process.returncode, stdout_sha256=hashlib.sha256(process.stdout.encode()).hexdigest(), stderr=clean(process.stderr[-3000:]))
                    require(process.returncode == step['expected_exit'], group['id'] + ':' + step['id'] + ': unexpected exit ' + str(process.returncode) + '; ' + clean(process.stderr[-1200:]))
                    for substring in step.get('stdout_contains', []):
                        require(substring in process.stdout, step['id'] + ': expected stdout text absent: ' + substring)
                    if step.get('stdout_empty'):
                        require(not process.stdout.strip(), step['id'] + ': quiet stdout was not empty')
                    if 'stdout_json_equals' in step:
                        assert_values(json.loads(process.stdout), step['stdout_json_equals'], step['id'])
                    if step.get('report'):
                        path = Path(expand(step['report']))
                        report = json.loads(path.read_text())
                        assert_values(report, step.get('report_equals', {}), step['id'])
                        require(report['execution']['exit_code'] == process.returncode, step['id'] + ': report exit differs from CLI')
                        for suffix in step.get('report_formats', ('html', 'md', 'json', 'sarif')):
                            require(path.with_suffix('.' + suffix).is_file(), step['id'] + ': missing report.' + suffix)
                        item['report_sha256'] = {p.name: digest(p) for p in sorted(path.parent.glob('report.*'))}
                        item['asserted_report_fields'] = step.get('report_equals', {})
                        if step.get('optimizer'):
                            requests = [report['judge'], *report['analyst']['requests']]
                            require(all(v['token_optimization']['engine'] == step['optimizer'] and v['token_optimization']['evidence_preserved'] for v in requests), step['id'] + ': optimizer engine/evidence mismatch')
                            item['optimizer_requests_verified'] = len(requests)
                        if step['id'].startswith('replay_'):
                            initial = json.loads((destination / '02-source/report.json').read_text())
                            extract = lambda r: [(f['id'], f['severity'], f['evidence']) for f in r['findings']]
                            require(extract(initial) == extract(report), 'Review import changed finding evidence or severity')
                            require(not any(f['status'] == 'pass' for f in report['findings']), 'Justification incorrectly became a pass')
                            item['finding_evidence_unchanged'] = True
                    item['status'] = 'passed'
                record['status'] = 'passed'
            calls = json.loads((destination / '09-gateway/requests.json').read_text())
            receipt['loopback'] = {'request_count': len(calls), 'protocols': sorted({r['provider'] for r in calls}), 'evidence_requests': sum(r['requested_ranges'] for r in calls), 'real_model_calls': 0, 'requests': calls}
            receipt['assertions'] = {'fresh_clone': True, 'fresh_venv': True, 'installed_outside_checkout': True, 'target_execution': False, 'container_execution': False, 'real_model_calls': 0, 'automatic_login_calls': 0}
        finally:
            for process in processes:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--output', type=Path, help='Local sanitized receipt directory; existing receipt files are replaced')
    parser.add_argument('--print-doc-blocks', action='store_true', help='Render the exact tested command fences for the guide; no commands execute')
    parser.add_argument('--check-docs-only', action='store_true', help='Check all tagged guide commands against the manifest; no commands execute')
    parser.add_argument('--skip-doc-check', action='store_true', help='Development only: explicitly mark documentation drift checking as skipped')
    args = parser.parse_args(argv)
    if args.print_doc_blocks:
        for key, content in documentation_steps(load_manifest(args.source / MANIFEST)).items():
            print('<!-- invscan-step:' + key + ' -->\n```sh\n' + content + '\n```\n')
        return 0
    if args.check_docs_only:
        manifest = load_manifest(args.source / MANIFEST)
        documents = load_documentation(args.source)
        print(json.dumps({**documentation_contract(args.source, manifest, documents),
                          'documentation_inputs': documentation_hashes(documents)})); return 0
    if args.output is None:
        parser.error('--output is required unless checking or printing documentation')
    receipt = {'schema_version': '1.0', 'recorded_at_utc': datetime.now(timezone.utc).isoformat(), 'status': 'running',
               'purpose': 'Executed documentation journeys on inert fixtures, not detector accuracy or production assurance.',
               'host': {'platform': platform.system(), 'machine': platform.machine(), 'python': platform.python_version()},
               'external_scope': {'live_provider_authentication': 'Separate opt-in validation receipt; not attempted by this harness.', 'runtime_images': 'Archives exercised; Docker/Podman daemon export and pull require separate evidence.', 'interactive_html_editing': 'Scripted form/capsule edits tested; no actual browser interaction claimed.'},
               'setup': [], 'scenarios': []}
    try:
        validate(args, receipt)
        receipt['status'] = 'passed'
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        receipt['status'] = 'failed'
        receipt['error'] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__ + ': validation did not finish; inspect the last step.'
        if receipt['scenarios']:
            last = receipt['scenarios'][-1]
            last['status'] = 'failed'
            if last['steps'] and last['steps'][-1]['status'] == 'running':
                last['steps'][-1]['status'] = 'failed'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    steps = sum(len(group['steps']) for group in receipt['scenarios'])
    lines = ['# Ten executed product scenarios', '', 'Status: **' + receipt['status'] + '**. Executed manifest steps: **' + str(steps) + '**.', '',
             '[Machine-readable receipt](receipt.json) records exact commands, expected exits, assertions, source snapshot, report hashes, and limits.', '',
             'The installed scanner runs outside a new clone in a fresh environment. API replies are scripted loopback fixtures; real-provider authentication and Docker/Podman runtime behavior are separate evidence. Deliberate findings and incomplete scans are expected outcomes, not harness failures.', '',
             '| Scenario | Result | Steps |', '|---|---|---:|']
    lines += ['| ' + group['id'] + ' ' + group['title'] + ' | ' + group['status'] + ' | ' + str(len(group['steps'])) + ' |' for group in receipt['scenarios']]
    lines += ['', 'Rerun with `python scripts/validate_scenarios.py --output test-output/scenarios` after installing Python 3.10+ and Git. This installs optional PDF/AI packages from the configured package index. No provider login or target/container execution occurs.', '']
    (output / 'README.md').write_text('\n'.join(lines))
    print(json.dumps({'status': receipt['status'], 'scenarios': len(receipt['scenarios']), 'steps': steps, 'receipt': str(output / 'receipt.json')}))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
