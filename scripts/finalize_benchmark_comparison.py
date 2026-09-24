#!/usr/bin/env python3
"""Bind paired benchmark reports to real repeated executions and publish receipts.

This script does not run or relabel scans. It rejects mismatched source snapshots,
implementation hashes, report bytes and changed original-corpus labels.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf-8')


def portable(value, replacements):
    if isinstance(value, str):
        for old, new in sorted(replacements.items(), key=lambda x: -len(x[0])):
            value=value.replace(old,new)
        return value
    if isinstance(value, list):return [portable(x,replacements) for x in value]
    if isinstance(value, dict):return {k:portable(v,replacements) for k,v in value.items()}
    return value


def labels(report):
    return {(c['id'],a['rule_id']):a for c in report['cases'] for a in c['assertions']}


def pair_accuracy(directory, before_name, after_name, corpus_path, implementations):
    before,after=read(directory/before_name),read(directory/after_name)
    corpus=read(corpus_path)
    a,b=labels(before),labels(after)
    if (before['corpus_sha256']!=after['corpus_sha256'] or before['corpus_sha256']!=sha(corpus_path.read_bytes())
        or set(a)!=set(b) or any(a[k]['expected']!=b[k]['expected'] for k in a)):
        raise ValueError('Paired corpus labels or source bytes changed')
    expected={(c['id'],r):e for c in corpus['cases'] for r,e in c['expect'].items()}
    if set(a)!=set(expected) or any(a[k]['expected']!=expected[k] for k in expected):
        raise ValueError('Paired evaluation omitted or changed corpus labels')
    changes=[dict(case_id=k[0],rule_id=k[1],expected=a[k]['expected'],before_detected=a[k]['detected'],after_detected=b[k]['detected'],
                  before_outcome=a[k]['outcome'],after_outcome=b[k]['outcome']) for k in sorted(a) if a[k]!=b[k]]
    remaining=[dict(case_id=k[0],**b[k]) for k in sorted(b) if b[k]['outcome'] in ('false_positive','false_negative')]
    phases={}
    for phase,name,report in [('before',before_name,before),('after',after_name,after)]:
        phases[phase]={key:report[key] for key in ('tool_version','overall','by_suite','failed_case_ids','analysis_error_cases')}
        phases[phase].update(accuracy_report=name,accuracy_report_sha256=sha((directory/name).read_bytes()),implementation_sha256=implementations[phase])
    return dict(schema_version='1.0',experiment=directory.name,scope='Paired unchanged project-authored rule-presence assertions; not production vulnerability accuracy.',
                corpus=dict(path=corpus_path.relative_to(ROOT).as_posix(),sha256=sha(corpus_path.read_bytes()),version=corpus['version'],case_count=len(corpus['cases'])),
                label_policy='No assertion removed or relabeled within this paired denominator; other tracks remain separate.',
                input_invariants=dict(identical_corpus_sha256=True,identical_case_ids_and_labels=True),changes=changes,remaining_mismatches=remaining,**phases)


def finding_key(row):
    return row['rule_id'],row['path'],row['line']


def verify_reports(project, receipt, directory):
    runs=receipt.get('repeated_runs',[])
    if len(runs)<2 or not receipt.get('byte_identical_reports'):
        raise ValueError('Two byte-identical executions are required')
    records=[]
    for name in ('report.html','report.json','report.md','report.sarif'):
        path=directory/project['id']/name;raw=path.read_bytes();digest=sha(raw)
        if any(r['report_sha256'][name]!=digest for r in runs):
            raise ValueError('Published bytes do not match every execution: '+project['id']+'/'+name)
        records.append(dict(path='invarune-reports/'+project['id']+'/'+name,project_id=project['id'],bytes=len(raw),sha256=digest,matches_both_execution_receipts=True))
    report=read(directory/project['id']/'report.json')
    if report['tool']['implementation_sha256']!=receipt['tool']['implementation_sha256']:
        raise ValueError('Report/receipt implementation identity differs')
    return report,records


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    p.add_argument('--input-dir',type=Path,required=True)
    for phase in ('before','after'):
        p.add_argument('--'+phase+'-reports',type=Path,required=True)
        p.add_argument('--'+phase+'-records',type=Path,required=True)
    args=p.parse_args(argv)
    for key,value in vars(args).items():setattr(args,key,value.resolve())
    directory=args.input_dir;manifest=read(ROOT/'benchmarks/real-world/manifest.json')
    replacements={str(ROOT):'{workspace}',str(Path.home()):'{home}'}
    reports,receipts,implementations,coverage,publication={},{},{},{},[]
    for phase in ('before','after'):
        reports[phase]={};receipts[phase]={};coverage[phase]=[];impl=set();runs=[]
        source_dir=getattr(args,phase+'_reports'); records_dir=getattr(args,phase+'_records')/'receipts'
        for project in manifest['projects']:
            ident=project['id'];r=read(records_dir/(ident+'.json'))
            if r['revision']!=project['revision'] or r['repository']!=project['repository']:
                raise ValueError('Run differs from frozen source revision')
            report,files=verify_reports(project,r,source_dir);reports[phase][ident]=report;receipts[phase][ident]=r;impl.add(report['tool']['implementation_sha256'])
            save(directory/('invarune-receipts-'+phase)/(ident+'.json'),portable(r,replacements))
            coverage[phase].append(dict(project_id=ident,exported_files=r['source_files'],files_examined=report['summary']['files_scanned'],
                coverage_gaps=report['summary']['coverage_gaps'],errors=report['coverage']['errors'],skipped=report['coverage']['skipped'],
                implementation_sha256=report['tool']['implementation_sha256'],report_sha256=sha((source_dir/ident/'report.json').read_bytes())))
            runs.append(dict(project_id=ident,source_manifest_sha256=r['source_manifest_sha256'],tool=r['tool'],command=portable(r['command'],replacements),
                byte_identical_reports=r['byte_identical_reports'],executions=portable(r['repeated_runs'],replacements)))
            if phase=='after':
                for item in files:
                    target=directory/item['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source_dir/ident/Path(item['path']).name,target)
                publication.extend(files)
        if len(impl)!=1:raise ValueError('Multiple implementations within a benchmark phase')
        implementations[phase]=next(iter(impl))
        accuracy_name='accuracy-'+phase+'.json';accuracy=read(directory/accuracy_name)
        save(directory/(phase+'-executions.json'),dict(schema_version='1.0',phase=phase,
            scope='Frozen implementation, static scan only; no target execution or LLM review.',actual_source_cli_executions=sum(len(r['executions']) for r in runs),
            source_bytes_verified_before_and_after=True,implementation_hash_verified_against_frozen_snapshot=True,source_runs=runs,
            accuracy=dict(path=accuracy_name,sha256=sha((directory/accuracy_name).read_bytes()),corpus_sha256=accuracy['corpus_sha256'],case_count=accuracy['case_count'],
                          overall=accuracy['overall'],analysis_error_cases=accuracy['analysis_error_cases'])))
        save(directory/('source-coverage-'+phase+'.json'),dict(schema_version='1.0',scanner_version=accuracy['tool_version'],
            assessment='Static input coverage; parser gaps and benign exclusions remain separate. Not a security completeness score.',projects=coverage[phase]))
    base=read(directory/'baseline-identity.json')
    if base['implementation_sha256']!=implementations['before']:raise ValueError('Baseline identity mismatch')
    pair=pair_accuracy(directory,'accuracy-before.json','accuracy-after.json',ROOT/'benchmarks/static_accuracy.json',implementations)
    save(directory/'before-after-accuracy.json',pair)
    if (directory/'skills-tools-before.json').exists() and (directory/'skills-tools-accuracy.json').exists():
        save(directory/'before-after-skills-legacy.json',pair_accuracy(directory,'skills-tools-before.json','skills-tools-accuracy.json',ROOT/'benchmarks/skills_tools_accuracy.json',implementations))
        skills=read(directory/'skills-tools-accuracy.json');corpus=ROOT/'benchmarks/skills_tools_accuracy.json'
        save(directory/'skills-tools-evaluation-receipt.json',dict(schema_version='1.0',experiment=directory.name,tool_version=skills['tool_version'],
            implementation_sha256=implementations['after'],separate_denominator=True,
            corpus=dict(path=corpus.relative_to(ROOT).as_posix(),sha256=sha(corpus.read_bytes()),version=read(corpus)['version']),
            report=dict(path='skills-tools-accuracy.json',sha256=sha((directory/'skills-tools-accuracy.json').read_bytes())),
            case_count=skills['case_count'],overall=skills['overall'],by_suite=skills['by_suite'],analysis_error_cases=skills['analysis_error_cases'],
            failed_case_ids=skills['failed_case_ids'],scope='Original 331 skill/tool assertions unchanged, including old scope-exclusion labels; explicit revised-label track is separate.'))
    projects=[]
    for project in manifest['projects']:
        ident=project['id'];before,after=reports['before'][ident],reports['after'][ident]
        br,ar=receipts['before'][ident],receipts['after'][ident]
        if br['source_manifest_sha256']!=ar['source_manifest_sha256'] or {(x['path'], x['sha256'], x['bytes']) for x in before['files']}!={(x['path'], x['sha256'], x['bytes']) for x in after['files']}:
            raise ValueError('Source or examined file bytes changed across phases')
        b={finding_key(x):x for x in before['findings']};a={finding_key(x):x for x in after['findings']}
        changed=[dict(rule_id=k[0],path=k[1],line=k[2],before_end_line=b[k]['end_line'],after_end_line=a[k]['end_line']) for k in a.keys()&b.keys() if a[k]['end_line']!=b[k]['end_line']]
        row={key:project[key] for key in ('repository','revision')};row.update(project_id=ident,source_manifest_sha256=br['source_manifest_sha256'],
            source_and_scope_equal=True,examined_file_bytes_equal=True,
            added=[a[k] for k in sorted(a.keys()-b.keys())],removed=[b[k] for k in sorted(b.keys()-a.keys())],
            identity_added=len(a.keys()-b.keys()),identity_removed=len(b.keys()-a.keys()),unchanged_pattern_identities=len(a.keys()&b.keys()),span_changes=changed,
            coverage_errors_added=[x for x in after['coverage']['errors'] if x not in before['coverage']['errors']],
            coverage_errors_removed=[x for x in before['coverage']['errors'] if x not in after['coverage']['errors']])
        for phase,report,source in [('before',before,args.before_reports),('after',after,args.after_reports)]:
            row[phase]=dict(tool=report['tool'],summary=report['summary'],report_sha256=sha((source/ident/'report.json').read_bytes()))
        projects.append(row)
    delta=dict(schema_version='1.0',experiment=directory.name,before_version=pair['before']['tool_version'],after_version=pair['after']['tool_version'],
        measurement='Same pinned exported source bytes. Identity uses rule, path and start line; span changes kept separately. Counts are observations, not vulnerabilities.',projects=projects,
        before_total=sum(p['before']['summary']['open_findings'] for p in projects),after_total=sum(p['after']['summary']['open_findings'] for p in projects),
        before_gaps=sum(p['before']['summary']['coverage_gaps'] for p in projects),after_gaps=sum(p['after']['summary']['coverage_gaps'] for p in projects),
        added_total=sum(len(p['added']) for p in projects),removed_total=sum(len(p['removed']) for p in projects),
        identity_added_total=sum(p['identity_added'] for p in projects),identity_removed_total=sum(p['identity_removed'] for p in projects),span_changes_total=sum(len(p['span_changes']) for p in projects))
    save(directory/'source-delta.json',delta)
    save(directory/'published-report-manifest.json',dict(schema_version='1.0',experiment=directory.name,file_count=len(publication),total_bytes=sum(x['bytes'] for x in publication),files=publication))
    lock=read(directory/'tool-lock.json');external=[]
    for project in manifest['projects']:
        for tool in ('semgrep','bandit','gitleaks'):
            path=directory/'external-results'/project['id']/(tool+'.json');r=read(path)
            external.append(dict(project_id=project['id'],tool=tool,version=lock[tool]['version'],status=r['status'],finding_count=r['finding_count'],
                analysis_error_count=len(r['errors']),started_at_utc=r['started_at_utc'],wall_seconds=r['wall_seconds'],raw_report_sha256=r['raw_report_sha256'],normalized_receipt_sha256=sha(path.read_bytes())))
    save(directory/'external-executions.json',dict(schema_version='1.0',experiment=directory.name,actual_source_executions=len(external),runs=external,
         recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),confirmed_vulnerabilities=None,
         interpretation='Fresh executions; native observations and parser failures are not vulnerability accuracy.',tool_lock='tool-lock.json',tool_lock_sha256=sha((directory/'tool-lock.json').read_bytes()),
         tools={t:lock[t]['version'] for t in ('semgrep','bandit','gitleaks')},version_policy='Frozen peer versions and rule bytes retained for comparability, not claimed latest.'))
    print(json.dumps(dict(implementations=implementations,source_findings=delta['after_total'],source_gaps=delta['after_gaps'],report_count=len(publication),changes=len(pair['changes'])),sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
