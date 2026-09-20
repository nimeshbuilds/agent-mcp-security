"""Image assessment orchestration; the inspected container is never started."""
from contextlib import contextmanager
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import tempfile

from .scanner import SEVERITIES, _digest, scan
from .security import redact, redact_object

IMAGE_EXCLUDED_DIRS = {'.git', '.hg', '.svn', '__pycache__', '.mypy_cache', '.pytest_cache', '.cache'}
IMAGE_LIMITATIONS = [
    'The container was not started. Image configuration can be overridden at deployment; runtime authorization, network policy, mounts, privileges and effective user are not established.',
    'Packaged supported source/configuration is analyzed directly. Native binaries, bytecode-only applications and stripped/minified artifacts do not receive decompilation or complete application-logic analysis.',
    'Image dependency inventory is not a CVE assessment. No vulnerability feed, signature trust policy, registry provenance, or malware engine is consulted.',
    'Build history and retained-layer credentials are image-artifact evidence; removed source-code defects are not reported as live application defects.',
]


def _image_path(path):
    return 'rootfs/' + path if path != '.' else 'rootfs'


def _merge_assessment(report, assessment, materialized, evidence_root, baseline):
    image_entries = {}
    for entry in materialized.get('entries', []):
        image_entries.setdefault(redact(entry['path']), []).append(entry)
    packaged_files = len(report['files'])
    packaged_source_files = sum(item['analysis_profile'] in {'python_ast', 'javascript_lexical'} for item in report['files'])
    report['summary']['packaged_files_inspected'] = packaged_files
    report['summary']['packaged_source_files_inspected'] = packaged_source_files
    report['summary']['image_analysis_scope'] = 'packaged_source_and_metadata' if packaged_source_files else 'metadata_and_text_only' if packaged_files else 'metadata_only'
    for item in report['files'] + report['findings']:
        candidates = image_entries.get(item['path'], [])
        entry = candidates[0] if len(candidates) == 1 else {}
        if len(candidates) > 1:
            report['coverage']['errors'].append({'path': item['path'], 'kind': 'image_provenance_error',
                'error': 'Redacted image paths collide; exact layer provenance cannot be attached unambiguously'})
        item['image_provenance'] = {'container_path': '/' + item['path'],
                                    'layer': entry.get('layer'), 'sha256': entry.get('sha256')}
        item['image_context'] = 'final_filesystem'
        if 'rule_id' in item:
            item['_source_fingerprint'] = item['id']
    for collection in (report['files'], report['findings'], report['coverage']['errors'], report['coverage']['skipped']):
        for item in collection:
            item['path'] = _image_path(item['path'])
    report['inventory']['dependency_manifests'] = [_image_path(path) for path in report['inventory']['dependency_manifests']]
    for item in report['inventory']['agent_mcp_signals']:
        item['path'] = _image_path(item['path'])
    for key in ('skill_manifests', 'skill_instruction_files'):
        report['inventory'][key] = [_image_path(path) for path in report['inventory'].get(key, [])]
    metadata_bytes = 0
    for relative, content in sorted(assessment.get('evidence_files', {}).items()):
        rel = PurePosixPath(relative)
        if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] != '.image-metadata' or '\\' in relative:
            raise ValueError('Image assessor returned an invalid evidence path')
        if not isinstance(content, bytes):
            raise ValueError('Image evidence must contain bytes')
        path = evidence_root.joinpath(*rel.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        metadata = assessment.get('evidence_metadata', {}).get(relative, {})
        report['files'].append({'path': relative, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'analysis_profile': 'image_metadata',
                                **redact_object(metadata)})
        metadata_bytes += len(content)
    report['files'].sort(key=lambda item: item['path'])
    selected_rules = set(report['configuration']['selected_rule_ids'])
    report['findings'].extend(item for item in assessment.get('findings', []) if item['rule_id'] in selected_rules)
    file_hashes = {item['path']: item['sha256'] for item in report['files']}
    unique = {}
    for finding in report['findings']:
        fingerprint = finding.pop('_source_fingerprint', file_hashes.get(finding['path']))
        identifier = _digest([finding['rule_id'], finding['path'], finding['line'], fingerprint, finding.get('evidence', '')])[:24]
        finding.update(id=identifier, finding_id=identifier, status='suppressed' if identifier in baseline else 'open')
        finding.pop('suppression_reason', None)
        if identifier in baseline:
            finding['suppression_reason'] = redact(baseline[identifier])
        # Image metadata and source excerpts are both untrusted report content.
        finding['evidence'] = redact(finding.get('evidence', ''))[:2000]
        unique[identifier] = finding
    report['findings'] = sorted(unique.values(), key=lambda item: (SEVERITIES.index(item['severity']), item['path'], item['line'], item['rule_id'], item['id']))
    for source in (materialized.get('coverage', {}), assessment.get('coverage', {})):
        report['coverage']['errors'].extend(redact_object(source.get('errors', [])))
        report['coverage']['skipped'].extend(redact_object(source.get('skipped', [])))
    if assessment.get('evidence_files'):
        report['coverage']['errors'] = [item for item in report['coverage']['errors'] if item.get('kind') != 'empty_scope']
    report['coverage']['errors'].sort(key=lambda item: (item.get('path', ''), item.get('error', '')))
    report['coverage']['skipped'].sort(key=lambda item: (item.get('path', ''), item.get('reason', '')))
    report['coverage']['limitations'] = IMAGE_LIMITATIONS + report['coverage']['limitations']
    report['coverage']['unmatched_baseline_ids'] = sorted(set(baseline) - set(unique))
    report['coverage']['analysis_profiles']['image_metadata'] = {'files': len(assessment.get('evidence_files', {})), 'scope': 'Selected image configuration/history/layer security checks; package inventory and file metadata are not application logic or CVE validation.'}
    for control in report['controls']:
        mapped = set(control['automated_rule_ids'])
        control['finding_ids'] = [item['id'] for item in report['findings'] if item['rule_id'] in mapped and item['status'] == 'open']
        control['suppressed_finding_ids'] = [item['id'] for item in report['findings'] if item['rule_id'] in mapped and item['status'] == 'suppressed']
        if mapped:
            control['status'] = 'findings_detected' if control['finding_ids'] else 'findings_suppressed' if control['suppressed_finding_ids'] else 'no_pattern_detected'
    active = [item for item in report['findings'] if item['status'] == 'open']
    summary = report['summary']
    summary.update(open_findings=len(active), suppressed_findings=len(report['findings'])-len(active), files_scanned=len(report['files']),
                   severity_counts={severity: sum(item['severity'] == severity for item in active) for severity in SEVERITIES}, assessment='static_image_triage_only')
    summary['metadata_evidence_bytes'] = metadata_bytes
    summary['coverage_gaps'] = len(report['coverage']['errors']) + sum(bool(item.get('coverage_gap')) for item in report['coverage']['skipped'])
    summary['scan_complete_within_selected_scope'] = summary['coverage_gaps'] == 0


@contextmanager
def scan_image(*, archive=None, reference=None, runtime='docker', pull=False, platform=None,
               max_archive_bytes=2_000_000_000, max_unpacked_bytes=4_000_000_000,
               max_layer_entries=500_000, max_layers=200, timeout_seconds=300,
               **scan_options):
    """Yield (report, evidence_root) until optional analyst/report work is done."""
    from .image_archive import materialize_image
    from .image_assessment import assess_image
    if bool(archive) == bool(reference):
        raise ValueError('Choose exactly one image reference or image archive')
    for value in (max_archive_bytes, max_unpacked_bytes, max_layer_entries, max_layers):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError('Image limits must be positive integers')
    baseline = scan_options.pop('baseline', None) or {}
    # Source output/baseline paths cannot exist inside our private reconstructed image.
    scan_options.pop('output_paths', None)
    with tempfile.TemporaryDirectory(prefix='nimeshbuild-image-') as temporary:
        workspace = Path(temporary).resolve()
        acquisition = None
        if reference:
            from .image_runtime import export_image
            archive_path = workspace / 'export.tar'
            acquisition = export_image(reference, archive_path, runtime=runtime, pull=pull, platform=platform,
                                       max_archive_bytes=max_archive_bytes, timeout_seconds=timeout_seconds)
            display_target = reference
        else:
            archive_path = Path(archive).expanduser()
            display_target = archive_path.name
        image_workspace = workspace / 'image'
        image_workspace.mkdir(mode=0o700)
        materialized = materialize_image(archive_path, image_workspace, platform=platform,
                                         max_archive_bytes=max_archive_bytes, max_unpacked_bytes=max_unpacked_bytes,
                                         max_entries=max_layer_entries, max_layers=max_layers)
        if materialized['identity'].get('platform', '').split('/', 1)[0] != 'linux':
            raise ValueError('Image assessment currently supports Linux container images; Windows container filesystem and user semantics are not implemented')
        evidence_root = workspace / 'review'
        evidence_root.mkdir()
        rootfs = evidence_root / 'rootfs'
        shutil.move(str(materialized['root']), str(rootfs))
        materialized['root'] = rootfs
        report = scan(rootfs, default_excluded_directories=IMAGE_EXCLUDED_DIRS, **scan_options)
        assessment = assess_image(materialized, max_file_bytes=scan_options.get('max_file_bytes', 1_000_000),
                                  max_total_bytes=scan_options.get('max_total_bytes', 50_000_000),
                                  exclude=scan_options.get('exclude', ()), excluded_directories=IMAGE_EXCLUDED_DIRS)
        _merge_assessment(report, assessment, materialized, evidence_root, baseline)
        report['mode'] = 'deterministic_image'
        report['target'] = 'container-image'
        report['image'] = redact_object({'input_kind': 'runtime_reference' if reference else 'archive',
            'display_target': display_target, 'identity': materialized['identity'], 'acquisition': acquisition,
            'inventory': assessment.get('inventory', {}),
            'extraction_coverage': materialized.get('coverage', {}), 'assessment_coverage': assessment.get('coverage', {}),
            'limits': {'max_archive_bytes': max_archive_bytes, 'max_unpacked_bytes': max_unpacked_bytes,
                       'max_layer_entries': max_layer_entries, 'max_layers': max_layers},
            'analysis_scope': report['summary']['image_analysis_scope'],
            'exclusion_scope': 'Container-relative exclusions apply to final packaged files and retained file revisions. Image configuration, build history, OS/package inventory and stored permission review remain independently assessed.',
            'packaged_source_files_inspected': report['summary']['packaged_source_files_inspected'],
            'packaged_files_inspected': report['summary']['packaged_files_inspected'],
            'container_started': False, 'binary_logic_analyzed': False, 'vulnerability_feed_consulted': False})
        report['scan_id'] = _digest({'source_scan_id': report['scan_id'], 'image': report['image'],
                                    'files': report['files'], 'findings': report['findings'], 'coverage': report['coverage'], 'baseline': baseline})
        yield report, evidence_root
