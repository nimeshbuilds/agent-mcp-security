#!/usr/bin/env python3
"""Validate an extracted native release with no external Python on its PATH.

The controller requires Python, pypdf for test PDF edits, and OpenSSL to generate
temporary HTTPS test certificates. The scanner needs none of these externally:
every scanner process uses the copied native distribution, an isolated home, and
a PATH containing only an empty directory. The two fixture utilities explicitly
use the controller interpreter; they are never invoked by the scanner. API
answers are scripted loopback fixtures, not live model or login validation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import platform
import posixpath
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NATIVE_MAGICS = (b'\x7fELF', b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                 b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                 b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                 b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
SOURCE_ONLY_ALIASES = ('{invarune}', '{ai-security-scan}')
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 50000


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def verify_native_command(command):
    require(command.is_file(), 'Standalone command must be an existing file')
    with command.open('rb') as stream:
        magic = stream.read(4)
    require(magic in NATIVE_MAGICS or magic[:2] == b'MZ',
            'Standalone command must be a native executable, not a Python/shell wrapper')
    require((command.parent / '_internal').is_dir(),
            'Extract the complete release directory: the _internal runtime is required')


def archive_path(name):
    path = PurePosixPath(name)
    require(bool(name) and not path.is_absolute() and '\\' not in name and ':' not in name
            and '..' not in path.parts and bool(path.parts), 'Unsafe archive member path')
    require(path.parts[0].startswith('invscan-') and path.parts[0] != 'invscan-',
            'Archive must contain a named invscan release directory')
    return path


def extract_archive(archive, output):
    """Extract only bounded, single-root release archives into a new directory."""
    require(archive.is_file() and archive.stat().st_size <= MAX_ARCHIVE_BYTES, 'Archive missing or above size limit')
    require(not output.exists(), 'Archive extraction directory must not already exist')
    roots, total = set(), 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as stream:
            members = stream.infolist()
            require(0 < len(members) <= MAX_ARCHIVE_ENTRIES, 'Archive entry count outside limit')
            for member in members:
                path = archive_path(member.filename)
                roots.add(path.parts[0])
                mode = member.external_attr >> 16
                require(not stat.S_ISLNK(mode), 'Zip symlinks are not accepted')
                require(not stat.S_IFMT(mode) or stat.S_ISREG(mode) or stat.S_ISDIR(mode), 'Unsupported zip member type')
                total += member.file_size
            require(len(roots) == 1 and total <= MAX_UNPACKED_BYTES, 'Archive root or unpacked size is invalid')
            output.mkdir()
            stream.extractall(output)
    else:
        require(hasattr(tarfile, 'data_filter'), 'Tar release validation requires Python with tarfile data_filter (3.12+)')
        with tarfile.open(archive, 'r:*') as stream:
            members = stream.getmembers()
            require(0 < len(members) <= MAX_ARCHIVE_ENTRIES, 'Archive entry count outside limit')
            for member in members:
                path = archive_path(member.name)
                root = path.parts[0]
                roots.add(root)
                require(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'Unsupported tar member type')
                if member.issym() or member.islnk():
                    link = member.linkname
                    require(bool(link) and not PurePosixPath(link).is_absolute() and '\\' not in link and ':' not in link,
                            'Unsafe archive link target')
                    target = posixpath.normpath(posixpath.join(str(path.parent), link) if member.issym() else link)
                    require(target == root or target.startswith(root + '/'), 'Archive link escapes release directory')
                total += member.size
            require(len(roots) == 1 and total <= MAX_UNPACKED_BYTES, 'Archive root or unpacked size is invalid')
            output.mkdir()
            stream.extractall(output, members=members, filter='data')
    root = output / next(iter(roots))
    command = root / ('invscan.exe' if os.name == 'nt' else 'invscan')
    verify_native_command(command)
    return command


def isolated_environment(environ, work):
    """Allow only OS essentials; exclude provider credentials and Python paths."""
    permitted = {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ'}
    result = {key: value for key, value in environ.items() if key.upper() in permitted}
    home, temporary, empty_path = work / 'home', work / 'temporary', work / 'empty-path'
    for folder in (home, temporary, empty_path):
        folder.mkdir(parents=True, exist_ok=True)
    result.update(PATH=str(empty_path), HOME=str(home), USERPROFILE=str(home),
                  APPDATA=str(home / 'AppData/Roaming'), LOCALAPPDATA=str(home / 'AppData/Local'),
                  TMPDIR=str(temporary), TEMP=str(temporary), TMP=str(temporary),
                  PYTHONNOUSERSITE='1', PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1',
                  NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
    return result


def portable(value, replacements):
    value = str(value)
    for source, replacement in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        value = value.replace(source, replacement).replace(source.replace('\\', '/'), replacement)
    return value


def find_openssl():
    """Use controller OpenSSL, including Git for Windows' private installation."""
    found = shutil.which('openssl')
    if found:
        return Path(found).absolute()
    git = shutil.which('git')
    if git and os.name == 'nt':
        base = Path(git).absolute().parent.parent
        for relative in ('usr/bin/openssl.exe', 'mingw64/bin/openssl.exe'):
            candidate = base / relative
            if candidate.is_file():
                return candidate
    raise RuntimeError('Controller OpenSSL is required for the isolated HTTPS certificate fixture')


def tls_validation(source, executable, outside, destination, environment, receipt, validator, clean):
    """Require trusted custom CA success and untrusted CA failure over real TLS."""
    folder = destination / 'tls-fixture'
    folder.mkdir()
    openssl = find_openssl()
    ca_config, leaf_config = folder / 'ca.cnf', folder / 'leaf.cnf'
    ca_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n'
                         '[dn]\nCN=Invarune temporary validation CA\n[ca]\n'
                         'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n'
                         'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n', encoding='utf-8')
    leaf_config.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                           'extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n'
                           'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n', encoding='utf-8')
    for arguments in (
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
         '-days', '1', '-sha256', '-config', str(ca_config)],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr',
         '-subj', '/CN=localhost', '-config', str(ca_config)],
        ['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
         '-out', 'server.pem', '-days', '1', '-sha256', '-extfile', str(leaf_config)],
    ):
        result = subprocess.run([str(openssl), *arguments], cwd=folder, capture_output=True, timeout=30)
        require(result.returncode == 0, 'Temporary HTTPS fixture certificate generation failed')
    gateway = load_module('standalone_tls_fixture', source / 'examples/scenarios/local_gateway.py')
    server = gateway.create_server(folder / 'gateway')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(folder / 'server.pem'), str(folder / 'server.key'))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    record = {'status': 'running', 'transport': 'Actual HTTPS to loopback scripted fixture',
              'private_keys': 'Generated temporarily by controller OpenSSL; deleted with test workspace',
              'real_model_calls': 0, 'public_network_requests': 0, 'checks': []}
    receipt['tls_validation'] = record
    reports = []
    try:
        original = json.loads((folder / 'gateway/custom.json').read_text(encoding='utf-8'))
        original['endpoint'] = original['endpoint'].replace('http://', 'https://')
        for trusted, expected_exit in ((True, 1), (False, 2)):
            name = 'custom-ca-trusted' if trusted else 'untrusted-ca-rejected'
            config = dict(original)
            if trusted:
                config['ca_file'] = str(folder / 'ca.pem')
            path = folder / (name + '.json')
            path.write_text(json.dumps(config), encoding='utf-8')
            target = destination / name
            invocation = [str(executable), str(outside / 'examples/vulnerable'), '--scans', 'AI002',
                          '--judge-config', str(path), '--judge-mode', 'findings',
                          '--report', str(target), '--summary-json']
            item = {'id': name, 'command': [clean(value) for value in invocation],
                    'expected_exit': expected_exit, 'status': 'running'}
            record['checks'].append(item)
            process = subprocess.run(invocation, cwd=outside, env=environment, capture_output=True,
                                     text=True, encoding='utf-8', errors='replace', timeout=180)
            item['exit_code'] = process.returncode
            require(process.returncode == expected_exit, name + ': unexpected exit; ' + clean(process.stderr[-1000:]))
            report = json.loads((target / 'report.json').read_text(encoding='utf-8'))
            validator.assert_values(report, {'summary.open_findings': 1, 'analyst.enabled': False,
                                            'judge.status': 'completed' if trusted else 'error'}, name)
            if not trusted:
                require('TLS verification failed' in report['judge']['error'], 'Untrusted certificate was not rejected as TLS failure')
            require(all((target / ('report.' + suffix)).is_file() for suffix in ('html', 'md', 'json', 'sarif')),
                    name + ': deterministic reports were not preserved')
            reports.append(report)
            item.update(status='passed', deterministic_findings_preserved=True)
        require(reports[0]['findings'] == reports[1]['findings'] and reports[0]['summary'] == reports[1]['summary'],
                'TLS trust failure modified deterministic evidence or summary')
        calls = json.loads((folder / 'gateway/requests.json').read_text(encoding='utf-8'))
        require(len(calls) == 1, 'Untrusted TLS attempt reached the HTTP payload handler')
        record.update(status='passed', https_payload_requests=1, rejected_before_http_payload=True,
                      deterministic_evidence_unchanged=True, native_invocations=2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def validate(args, receipt):
    source = args.source.resolve(strict=True)
    command = args.command.resolve(strict=True)
    verify_native_command(command)
    validator = load_module('standalone_scenario_contract', source / 'scripts/validate_scenarios.py')
    security = load_module('standalone_receipt_redaction', source / 'ai_security_scan/security.py')
    manifest = validator.load_manifest(source / validator.MANIFEST)
    receipt['manifest_sha256'] = digest(source / validator.MANIFEST)
    receipt['binary_sha256'] = digest(command)
    receipt['source_only_aliases_omitted'] = ['invarune --version', 'ai-security-scan --version']
    with tempfile.TemporaryDirectory(prefix='invarune-native-validation-') as temporary:
        work = Path(temporary).resolve()
        distribution, outside = work / 'distribution', work / 'outside-checkout'
        shutil.copytree(command.parent, distribution, symlinks=True)
        executable = distribution / command.name
        outside.mkdir()
        environment = isolated_environment(os.environ, work)
        receipt['isolation'] = {
            'native_header_verified': True, 'complete_distribution_copied': True,
            'scanner_cwd_outside_checkout': True, 'isolated_home': True,
            'provider_credentials_inherited': False,
            'python_on_scanner_path': any(shutil.which(name, path=environment['PATH'])
                                          for name in ('python', 'python3', 'py', 'python.exe')),
            'scanner_path_entries': ['<EMPTY_PATH>'],
            'controller_python_used_only_for_fixture_utilities': True,
        }
        require(not receipt['isolation']['python_on_scanner_path'], 'Python unexpectedly available on restricted scanner PATH')
        replacements = [(str(command), '<ORIGINAL_NATIVE_COMMAND>'), (str(source), '<SOURCE>'),
                        (str(Path(sys.executable).absolute()), '<CONTROLLER_PYTHON>'),
                        (str(distribution), '<DISTRIBUTION>'), (str(outside), '<SCENARIO_WORKSPACE>'),
                        (str(work), '<WORK>'), (str(Path.home()), '<USER_HOME>'),
                        (str(Path(tempfile.gettempdir()).resolve()), '<HOST_TEMP>')]
        def clean(value):
            return portable(security.redact(str(value)), replacements)

        # The scanner never receives checkout source as its target or cwd. These
        # examples are inert input data, not imported modules or executable tests.
        for name in ('safer', 'vulnerable', 'skills', 'images', 'investigation', 'scenarios', 'review-config.json'):
            # Validate the examples actually downloaded by users. Only the
            # controller fixture utilities are supplied by the source checkout.
            src = (source if name == 'scenarios' else distribution) / 'examples' / name
            dst = outside / 'examples' / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            else:
                shutil.copy2(src, dst)
        (outside / 'scripts').mkdir()
        shutil.copy2(source / 'scripts/validate_report_review.py', outside / 'scripts/validate_report_review.py')
        destination = outside / 'scan-report/scenarios'
        destination.mkdir(parents=True)
        substitutions = {'repo': str(outside), 'cwd': str(outside), 'work': str(destination),
                         'python': str(Path(sys.executable).absolute()), 'cli': str(executable)}
        def expand(value):
            for key, replacement in substitutions.items():
                value = value.replace('{' + key + '}', replacement)
            return value

        processes = []
        try:
            for group in manifest['scenarios']:
                record = {'id': group['id'], 'title': group['title'], 'status': 'running', 'steps': []}
                receipt['scenarios'].append(record)
                for step in group['steps']:
                    if step['argv'][0] in SOURCE_ONLY_ALIASES:
                        continue
                    invocation = [expand(value) for value in step['argv']]
                    item = {'id': step['id'], 'command': [clean(value) for value in invocation],
                            'execution_kind': 'controller_fixture_utility' if step['argv'][0] == '{python}' else 'native_scanner',
                            'expected_exit': step['expected_exit'], 'status': 'running'}
                    record['steps'].append(item)
                    if step.get('background'):
                        started = time.monotonic()
                        with tempfile.TemporaryFile() as startup_log:
                            process = subprocess.Popen(invocation, cwd=outside, env=environment,
                                                       stdout=startup_log, stderr=startup_log)
                            processes.append(process)
                            deadline = started + 30
                            ready = Path(expand(step['ready_file']))
                            while not ready.is_file() and process.poll() is None and time.monotonic() < deadline:
                                time.sleep(0.05)
                            startup_log.seek(0)
                            detail = clean(startup_log.read(3000).decode('utf-8', errors='replace'))
                            item['startup_seconds'] = round(time.monotonic() - started, 3)
                            item['startup_output'] = detail
                            require(ready.is_file() and process.poll() is None,
                                    'Scripted loopback fixture did not become ready; process exit=' +
                                    str(process.poll()) + '; ' + detail)
                        item.update(status='passed', readiness_verified=True, real_model=False)
                        continue
                    before = set(outside.rglob('*')) if step.get('no_reports_created') else None
                    process = subprocess.run(invocation, cwd=outside, env=environment, capture_output=True,
                                             text=True, encoding='utf-8', errors='replace', timeout=180)
                    item.update(exit_code=process.returncode,
                                stdout_sha256=hashlib.sha256(process.stdout.encode()).hexdigest(),
                                stderr=clean(process.stderr[-3000:]))
                    require(process.returncode == step['expected_exit'], group['id'] + ':' + step['id'] +
                            ': unexpected exit ' + str(process.returncode) + '; ' + clean(process.stderr[-1500:]))
                    if before is not None:
                        require(set(outside.rglob('*')) == before, step['id'] + ': terminal command wrote files')
                        item['no_files_created'] = True
                    for substring in step.get('stdout_contains', []):
                        require(substring in process.stdout, step['id'] + ': expected stdout text absent: ' + substring)
                    if group['id'] == '01' and step['id'] == 'version':
                        receipt['version'] = process.stdout.strip()
                    if step.get('stdout_empty'):
                        require(not process.stdout.strip(), step['id'] + ': quiet stdout was not empty')
                    if 'stdout_json_equals' in step:
                        validator.assert_values(json.loads(process.stdout), step['stdout_json_equals'], step['id'])
                    if step.get('report'):
                        path = Path(expand(step['report']))
                        report = json.loads(path.read_text(encoding='utf-8'))
                        validator.assert_values(report, step.get('report_equals', {}), step['id'])
                        require(report['execution']['exit_code'] == process.returncode, step['id'] + ': report exit differs')
                        for suffix in step.get('report_formats', ('html', 'md', 'json', 'sarif')):
                            require(path.with_suffix('.' + suffix).is_file(), step['id'] + ': missing report.' + suffix)
                        item['report_sha256'] = {p.name: digest(p) for p in sorted(path.parent.glob('report.*'))}
                        item['asserted_report_fields'] = step.get('report_equals', {})
                        if step.get('optimizer'):
                            requests = [report['judge'], *report['analyst']['requests']]
                            require(bool(requests) and all(
                                value['token_optimization']['engine'] == step['optimizer'] and
                                value['token_optimization']['evidence_preserved'] for value in requests),
                                step['id'] + ': optimizer engine or preserved evidence mismatch')
                            item['optimizer'] = step['optimizer']
                            item['optimizer_requests_verified'] = len(requests)
                        if step['id'].startswith('replay_'):
                            initial = json.loads((destination / '02-source/report.json').read_text(encoding='utf-8'))
                            evidence = lambda result: [(f['id'], f['severity'], f['evidence']) for f in result['findings']]
                            require(evidence(initial) == evidence(report), 'Review changed finding evidence or severity')
                            require(not any(f['status'] == 'pass' for f in report['findings']), 'Justification became pass')
                            item['finding_evidence_unchanged'] = True
                    item['status'] = 'passed'
                record['status'] = 'passed'
            calls = json.loads((destination / '09-gateway/requests.json').read_text(encoding='utf-8'))
            receipt['loopback'] = {'request_count': len(calls), 'protocols': sorted({r['provider'] for r in calls}),
                                   'evidence_requests': sum(r['requested_ranges'] for r in calls),
                                   'real_model_calls': 0, 'requests': calls}
            require(len(receipt['loopback']['protocols']) == 6, 'Not all six API protocols were exercised')
            require(receipt['loopback']['evidence_requests'] == 1, 'Bounded investigation request was not exercised')
            # Git is a real external native program available on release CI.
            # The precise version rejection establishes that its --version
            # subprocess started and returned output successfully. It is not a
            # vendor CLI and this test makes no authentication/inference claim.
            git = shutil.which('git')
            require(bool(git), 'Host Git is required for the external native process compatibility probe')
            invocation = [str(executable), str(outside / 'examples/vulnerable'), '--scans', 'AI002',
                          '--judge-cli', 'codex', '--judge-executable', str(Path(git).absolute()),
                          '--judge-login', 'never', '--judge-mode', 'findings',
                          '--report', str(destination / 'external-native-probe'), '--summary-json']
            process = subprocess.run(invocation, cwd=outside, env=environment, capture_output=True,
                                     text=True, encoding='utf-8', errors='replace', timeout=180)
            receipt['external_native_process'] = {
                'program': 'git', 'purpose': 'Actual external native version-probe compatibility; not vendor authentication or inference',
                'command': [clean(value).replace(str(Path(git).absolute()), '<HOST_GIT>') for value in invocation],
                'expected_exit': 2, 'exit_code': process.returncode, 'status': 'running'}
            require(process.returncode == 2, 'External native compatibility probe did not fail closed')
            report = json.loads((destination / 'external-native-probe/report.json').read_text(encoding='utf-8'))
            validator.assert_values(report, {'summary.open_findings': 1, 'analyst.enabled': False, 'judge.status': 'error'}, 'external-native-probe')
            require('CLI judge version is unsupported' in report['judge']['error'],
                    'External Git process did not return successfully to the provider version check')
            receipt['external_native_process'].update(status='passed', deterministic_findings_preserved=True,
                                                       native_subprocess_returned_version=True)
            tls_validation(source, executable, outside, destination, environment, receipt, validator, clean)
            # Frozen Python ignores PYTHONUTF8. Exercise the actual interpreter
            # option using a non-ASCII file name in piped human-readable output.
            unicode_target = outside / 'unicode-安全-Δ'
            shutil.copytree(outside / 'examples/vulnerable', unicode_target)
            (unicode_target / 'agent.py').rename(unicode_target / '安全_Δ.py')
            invocation = [str(executable), str(unicode_target), '--scans', 'AI002']
            process = subprocess.run(invocation, cwd=outside, env=environment, capture_output=True,
                                     text=True, encoding='utf-8', errors='strict', timeout=180)
            require(process.returncode == 1 and '安全_Δ.py' in process.stdout,
                    'Native Unicode file path or UTF-8 terminal output failed')
            receipt['unicode_validation'] = {'status': 'passed', 'native_invocations': 1,
                                            'expected_exit': 1, 'exit_code': process.returncode,
                                            'non_ascii_file_path_preserved': True,
                                            'piped_stdout_utf8_decoded_strictly': True}
        finally:
            for process in processes:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selected = parser.add_mutually_exclusive_group(required=True)
    selected.add_argument('--command', type=Path, help='Native invscan executable in the fully extracted release directory')
    selected.add_argument('--archive', type=Path, help='Native release .tar.gz/.zip to safely extract and validate (recommended release gate)')
    parser.add_argument('--output', required=True, type=Path, help='New or empty directory for the portable receipt')
    parser.add_argument('--source', type=Path, default=ROOT, help='Checkout containing inert fixtures and the scenario contract')
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error('Output must be a new or empty directory')
    receipt = {'schema_version': '1.0', 'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
               'status': 'running', 'host': {'platform': platform.system(), 'machine': platform.machine()},
               'purpose': 'Extracted native distribution validation; scanner runs without external Python on PATH.',
               'scope': {'real_model_calls': 0, 'provider_logins': 0, 'target_execution': False,
                         'container_execution': False, 'pdf_form_edits': 'Scripted controller edits; no browser interaction claimed.',
                         'controller_python': 'Used by this validation harness and two fixture utilities, never to launch the scanner.'},
               'scenarios': []}
    try:
        with tempfile.TemporaryDirectory(prefix='invarune-native-archive-') as temporary:
            if args.archive:
                archive = args.archive.resolve(strict=True)
                receipt['archive'] = {'name': archive.name, 'sha256': digest(archive), 'bytes': archive.stat().st_size,
                                      'extracted_before_validation': True}
                args.command = extract_archive(archive, Path(temporary) / 'extracted')
            validate(args, receipt)
        receipt['status'] = 'passed'
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        receipt['status'] = 'failed'
        receipt['error'] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__ + ': inspect the final recorded step'
        if receipt['scenarios']:
            last = receipt['scenarios'][-1]
            last['status'] = 'failed'
            if last['steps'] and last['steps'][-1]['status'] == 'running':
                last['steps'][-1]['status'] = 'failed'
    steps = [step for group in receipt['scenarios'] for step in group['steps']]
    receipt['steps_executed'] = len(steps)
    receipt['native_scanner_invocations'] = sum(step['execution_kind'] == 'native_scanner' for step in steps)
    if receipt.get('external_native_process'):
        receipt['native_scanner_invocations'] += 1
    if receipt.get('tls_validation'):
        receipt['native_scanner_invocations'] += len(receipt['tls_validation']['checks'])
    if receipt.get('unicode_validation'):
        receipt['native_scanner_invocations'] += 1
    output.mkdir(parents=True, exist_ok=True)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'status': receipt['status'], 'steps': len(steps), 'receipt': str(output / 'receipt.json')}))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
