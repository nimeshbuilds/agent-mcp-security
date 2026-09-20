#!/usr/bin/env python3
"""Measure lossless evidence JSON formatting; no LLM or target program is run.

Run with the pinned Headroom optional dependency already installed. No tokenizer
asset is fetched: cl100k_base counts are produced only if its verified file was
already cached. Use an OS network sandbox as an additional proof boundary.
"""
import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frozen(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload-root', type=Path, default=ROOT / 'tmp/comparison-v010/adjudication-prepared')
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/token-optimization-v011/payload-wire-proof.json')
    args = parser.parse_args()
    assert metadata.version('headroom-ai') == '0.37.0'
    attempts = {'network': [], 'child_process': []}

    def audit(event, values):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind'):
            attempts['network'].append(event)
            raise RuntimeError('Network access prohibited in this proof')
        if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn'):
            attempts['child_process'].append(event)
            raise RuntimeError('Child process access prohibited in this proof')

    sys.addaudithook(audit)
    from headroom.transforms.content_router import ContentRouter
    from ai_security_scan.token_optimizer import optimize_payload
    from ai_security_scan import __version__

    # Only a pre-existing, hash-verified tiktoken asset may be used. No fetch.
    url = 'https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken'
    expected_hash = '223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7'
    cache = Path(os.environ.get('TIKTOKEN_CACHE_DIR', os.environ.get('DATA_GYM_CACHE_DIR',
                 str(Path(tempfile.gettempdir()) / 'data-gym-cache'))))
    asset = cache / hashlib.sha1(url.encode()).hexdigest()
    encoding = None
    if asset.is_file() and asset.stat().st_size < 10_000_000 and sha(asset.read_bytes()) == expected_hash:
        import tiktoken
        encoding = tiktoken.get_encoding('cl100k_base')

    payloads = []
    for path in sorted(args.payload_root.glob('*-payload.json')):
        if path.is_symlink() or path.stat().st_size > 500_000:
            raise ValueError('Unsupported evidence file')
        raw = path.read_bytes()
        payload = json.loads(raw)
        payloads.append((path.name, raw, payload))
    if not payloads:
        raise ValueError('No frozen payload files available')
    profiles = {}
    for profile, ensure_ascii in (('http_evidence_json', True), ('cli_evidence_json', False)):
        rows = []
        for name, raw, payload in payloads:
            original = json.dumps(payload, sort_keys=True, ensure_ascii=ensure_ascii, allow_nan=False)
            direct = ContentRouter._minify_json_data_lossless(original) or original
            output, receipt = optimize_payload(payload, 'headroom', ensure_ascii=ensure_ascii)
            compact, compact_receipt = optimize_payload(payload, 'compact', ensure_ascii=ensure_ascii)
            off, off_receipt = optimize_payload(payload, 'off', ensure_ascii=ensure_ascii)
            assert output == direct and off == original
            assert frozen(json.loads(output)) == frozen(payload)
            assert frozen(json.loads(compact)) == frozen(payload)
            assert receipt['engine'] == 'headroom' and receipt['fallback_reason'] is None
            assert compact_receipt['engine'] == 'builtin_compact' and off_receipt['engine'] == 'none'
            assert len(output.encode()) <= len(original.encode())
            assert frozen(payload) == frozen(json.loads(raw)), 'Caller-owned payload mutated'
            row = {'payload_file': name, 'stored_payload_sha256': sha(raw),
                   'before_bytes': len(original.encode()), 'headroom_after_bytes': len(output.encode()),
                   'builtin_after_bytes': len(compact.encode()), 'off_after_bytes': len(off.encode()),
                   'before_sha256': sha(original.encode()), 'headroom_after_sha256': sha(output.encode()),
                   'strict_typed_json_equal': True, 'optimizer_receipt': receipt}
            if encoding is not None:
                row.update(cl100k_before=len(encoding.encode(original, disallowed_special=())),
                           cl100k_after=len(encoding.encode(output, disallowed_special=())))
            rows.append(row)
        before = sum(r['before_bytes'] for r in rows)
        after = sum(r['headroom_after_bytes'] for r in rows)
        profiles[profile] = {'baseline': 'json.dumps(payload, sort_keys=True, ensure_ascii=%s, allow_nan=False), default one-space separators' % ensure_ascii,
                            'payloads': len(rows), 'bytes_before': before, 'bytes_after': after,
                            'bytes_saved': before - after, 'byte_reduction_fraction': (before - after) / before,
                            'builtin_bytes_after': sum(r['builtin_after_bytes'] for r in rows), 'rows': rows}
        if encoding is not None:
            profiles[profile].update(cl100k_before=sum(r['cl100k_before'] for r in rows),
                                     cl100k_after=sum(r['cl100k_after'] for r in rows))
    result = {'schema_version': '1.0', 'invarune_version': __version__, 'headroom_version': metadata.version('headroom-ai'),
              'optimizer_source_sha256': sha((ROOT / 'ai_security_scan/token_optimizer.py').read_bytes()),
              'baseline_scope': 'Legacy one-space serialized evidence JSON actually embedded in requests; excludes security instructions, schemas and provider/CLI wrappers.',
              'profiles': profiles, 'network_attempts': len(attempts['network']), 'child_process_attempts': len(attempts['child_process']),
              'headroom_native_core_loaded': 'headroom._core' in sys.modules,
              'tokenizer': {'measured': encoding is not None, 'encoding': 'cl100k_base' if encoding else None,
                            'status': 'verified_existing_cache' if encoding else 'unavailable_no_verified_cached_asset_no_download_attempted',
                            'caveat': 'Optional encoding counts are not provider billing or a tokenizer guarantee for Claude/Codex/Grok.'},
              'model_calls': 0, 'interpretation': 'No claim of changed LLM accuracy, billed token savings or monetary cost savings. All payload values preserved.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(result, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({k: {m: v for m, v in value.items() if m != 'rows'} for k, value in profiles.items()}, indent=2))


if __name__ == '__main__':
    main()
