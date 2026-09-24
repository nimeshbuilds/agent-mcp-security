"""Validate the separate v0.15 evaluation tracks before visual publication."""
from collections import Counter
import hashlib
import json
from pathlib import Path
from scripts.benchmark_agent_challenge import metrics, outcome, validate_corpus

ROOT=Path(__file__).resolve().parents[1]


def sha(raw):return hashlib.sha256(raw).hexdigest()


def validate_challenge(report, corpus, corpus_hash, commitment_hash, phase, implementation=None):
    if report['phase']!=phase or report['corpus_sha256']!=corpus_hash or report['commitment_sha256']!=commitment_hash or report['case_count']!=len(corpus['cases']):
        raise ValueError('Challenge identity or phase mismatch')
    own=report['invarune']
    if implementation and own['implementation_sha256']!=implementation:
        raise ValueError('Challenge does not bind the expected frozen implementation')
    labels={c['id']:c for c in corpus['cases']}
    if len(own['cases'])!=len(labels) or {c['id'] for c in own['cases']}!=set(labels):
        raise ValueError('Challenge omitted or duplicated cases')
    for row in own['cases']:
        case=labels[row['id']];rule,expected=next(iter(case['expect'].items()))
        actual=bool(set(row['detected_rule_ids'])&{'AI043','AI044','AI045'}) if case['suite']=='heldout-metadata' else rule in row['detected_rule_ids']
        if (row['expected']!=expected or row['predicate_rule_id']!=rule or row['track']!=case['suite']
                or row['detected']!=actual or row['outcome']!=outcome(expected,actual,row['analysis_errors'])):
            raise ValueError('Challenge label, detection or outcome was modified')
    if own['overall']!=metrics(own['cases']):raise ValueError('Challenge totals omit outcomes')
    for track in ('heldout-source','heldout-metadata'):
        if own['tracks'][track]!=metrics([x for x in own['cases'] if x['track']==track]):
            raise ValueError('Challenge track totals disagree')
    if 'cisco_metadata' in report:
        peer=report['cisco_metadata'];expected_ids={c['id'] for c in corpus['cases'] if c['suite']=='heldout-metadata'}
        if len(peer['cases'])!=len(expected_ids) or {c['id'] for c in peer['cases']}!=expected_ids:
            raise ValueError('Cisco omitted or duplicated metadata cases')
        for row in peer['cases']:
            expected=next(iter(labels[row['id']]['expect'].values()))
            if row['expected']!=expected or row['outcome']!=outcome(expected,row['detected'],row['analysis_error']):
                raise ValueError('Cisco challenge outcome or label mismatch')
            if not row['analysis_error'] and row['detected']!=(row['finding_count']>0):
                raise ValueError('Cisco detection disagrees with native count')
        if peer['overall']!=metrics(peer['cases']):raise ValueError('Cisco totals disagree')


def load_extensions(directory, version, implementation, read_json, check_accuracy):
    """read_json records each loaded input hash in its caller's publication receipt."""
    if not version.startswith('0.15.'):
        return None
    commitment=read_json(directory/'challenge-commitment.json')
    corpus=read_json(directory/'heldout-challenge.json');raw=(directory/'heldout-challenge.json').read_bytes()
    validate_corpus(raw)
    if sha(raw)!=commitment['sha256']:raise ValueError('Sealed challenge corpus differs from commitment')
    commit_hash=sha((directory/'challenge-commitment.json').read_bytes())
    freeze=read_json(directory/'initial-freeze.json')
    challenge={}
    for key,phase,expected in [('baseline','baseline',None),('initial','initial-heldout',freeze['implementation_sha256']),('final','post-disclosure-development',implementation)]:
        challenge[key]=read_json(directory/('challenge-'+key+'.json'))
        validate_challenge(challenge[key],corpus,sha(raw),commit_hash,phase,expected)
    confirm_commit=read_json(directory/'confirmation-commitment.json')
    confirm_corpus=read_json(directory/'sealed-confirmation.json');raw_confirm=(directory/'sealed-confirmation.json').read_bytes()
    validate_corpus(raw_confirm)
    if sha(raw_confirm)!=confirm_commit['sha256']:raise ValueError('Confirmation corpus differs from sealed commitment')
    confirmation_freeze=read_json(directory/'confirmation-first-freeze.json')
    confirmation=read_json(directory/'confirmation-first.json')
    confirm_hash=sha((directory/'confirmation-commitment.json').read_bytes())
    validate_challenge(confirmation,confirm_corpus,sha(raw_confirm),confirm_hash,'initial-heldout',confirmation_freeze['implementation_sha256'])
    confirmation_repeat=read_json(directory/'confirmation-final.json')
    validate_challenge(confirmation_repeat,confirm_corpus,sha(raw_confirm),confirm_hash,'presentation-only-repeat',implementation)
    if confirmation['invarune']['cases']!=confirmation_repeat['invarune']['cases']:
        raise ValueError('Presentation-only confirmation repeat changed detector outcomes')
    presentation=read_json(directory/'presentation-only-change.json')
    if presentation['before_implementation_sha256']!=confirmation_freeze['implementation_sha256'] or presentation['after_implementation_sha256']!=implementation:
        raise ValueError('Presentation change does not bind both confirmation implementations')
    if set(presentation['changed_modules'])!={'report_pdf.py','report_html.py'}:
        raise ValueError('More than report presentation changed after sealed confirmation')
    extra={}
    for label,name,corpus_path in [('corrected_before','skills-corrected-before.json','benchmarks/skills_tools_accuracy-v110.json'),
                                    ('corrected_after','skills-corrected-after.json','benchmarks/skills_tools_accuracy-v110.json'),
                                    ('callflow','callflow-permissions-accuracy.json','benchmarks/callflow_permissions_accuracy.json'),
                                    ('instructions','instruction-extensions-accuracy.json','benchmarks/instruction_extensions-v015.json')]:
        data=read_json(directory/name);cp=ROOT/corpus_path;c=read_json(cp)
        check_accuracy(data,c,sha(cp.read_bytes()))
        if label!='corrected_before' and data['tool_version']!=version:raise ValueError('Development track version mismatch')
        extra[label]=data
    audit=read_json(directory/'source-review.json')
    return dict(challenge=challenge,confirmation=confirmation,confirmation_repeat=confirmation_repeat,source_review=audit,**extra)
