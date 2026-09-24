#!/usr/bin/env python3
"""Run the sealed agent/MCP challenge without executing any target program.

Source-flow assertions measure Invarune alone. The metadata track supplies the
same descriptors to Invarune and Cisco YARA and scores tool-level risk presence.
Native peer source observations are preserved but not mislabeled as an equivalent
interprocedural analysis benchmark. Label provenance and initial freeze matter.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def metrics(rows):
    counts = Counter(row['outcome'] for row in rows)
    out = {key: counts[key] for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative', 'analysis_error')}
    tp, tn, fp, fn = (out[key] for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative'))
    out.update(labeled_assertions=len(rows), scored_assertions=tp+tn+fp+fn,
               precision=round(tp/(tp+fp), 6) if tp+fp else None,
               recall=round(tp/(tp+fn), 6) if tp+fn else None)
    return out


def outcome(expected, detected, errors=None):
    if errors:
        return 'analysis_error'
    return ('true_positive' if expected else 'false_positive') if detected else ('false_negative' if expected else 'true_negative')


def validate_corpus(raw):
    data = json.loads(raw)
    if data.get('schema_version') != '1.0' or not isinstance(data.get('cases'), list) or not 1 <= len(data['cases']) <= 1000:
        raise ValueError('Invalid challenge corpus')
    names = set()
    for case in data['cases']:
        if (not isinstance(case.get('id'), str) or case['id'] in names
                or not case['id'] or not all(c.isalnum() or c == '-' for c in case['id'])):
            raise ValueError('Invalid or duplicate case id')
        names.add(case['id'])
        if case.get('suite') not in ('heldout-source', 'heldout-metadata'):
            raise ValueError('Unknown challenge track')
        if not isinstance(case.get('source'), str) or len(case['source']) > 100000:
            raise ValueError('Invalid challenge content')
        p = Path(case.get('path', ''))
        if p.is_absolute() or len(p.parts) != 1 or p.name in ('', '.', '..'):
            raise ValueError('Challenge paths must be simple filenames')
        if len(case.get('expect', {})) != 1 or any(type(x) is not bool for x in case['expect'].values()):
            raise ValueError('Exactly one boolean risk predicate per case is required')
        if case['suite'] == 'heldout-metadata':
            tools = json.loads(case['source'])['tools']
            if len(tools) != 1 or tools[0]['name'] != case['id'].replace('-', '_'):
                raise ValueError('Metadata identity is not bound to case id')
    return data


WORKER = r'''
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
from ai_security_scan import __version__
from ai_security_scan.analyzer import analyze_file,analyze_file_errors
h=hashlib.sha256()
for m in sorted((root/'ai_security_scan').glob('*.py')):h.update(m.name.encode());h.update(m.read_bytes())
cases=json.loads(Path(sys.argv[2]).read_bytes())['cases']
rows=[]
for case in cases:
 errors=analyze_file_errors(case['path'],case['source'])
 findings=analyze_file(case['path'],case['source']) if not errors else []
 rows.append({'id':case['id'],'analysis_errors':errors,'findings':findings})
final=hashlib.sha256()
for m in sorted((root/'ai_security_scan').glob('*.py')):final.update(m.name.encode());final.update(m.read_bytes())
if final.hexdigest()!=h.hexdigest():raise RuntimeError('Implementation changed during challenge run')
Path(sys.argv[3]).write_text(json.dumps({'tool_version':__version__,'implementation_sha256':h.hexdigest(),'cases':rows},sort_keys=True)+'\n')
'''


def run_invarune(args, corpus):
    result_path = args.raw_output / 'invarune.json'
    started, timer = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), time.monotonic()
    proc = subprocess.run([sys.executable, '-c', WORKER, str(args.implementation_root), str(args.corpus), str(result_path)],
                          cwd=str(args.raw_output), check=True, capture_output=True, timeout=180)
    raw = result_path.read_bytes()
    result = json.loads(raw)
    observed = {x['id']: x for x in result['cases']}
    rows = []
    for case in corpus['cases']:
        rule, expected = next(iter(case['expect'].items()))
        actual = observed[case['id']]
        detected_rules = sorted({x['rule_id'] for x in actual['findings']})
        # Metadata peer comparison asks whether the descriptor contains any
        # operative malicious-instruction indicator, not native taxonomy equality.
        detected = bool(set(detected_rules) & {'AI043','AI044','AI045'}) if case['suite'] == 'heldout-metadata' else rule in detected_rules
        rows.append({'id':case['id'],'track':case['suite'],'predicate_rule_id':rule,
                     'expected':expected,'detected':detected,'detected_rule_ids':detected_rules,
                     'outcome':outcome(expected,detected,actual['analysis_errors']),
                     'analysis_errors':actual['analysis_errors'],'rationale':case['rationale'],
                     'finding_count':len(actual['findings'])})
    return {'tool':'invarune','tool_version':result['tool_version'],'implementation_sha256':result['implementation_sha256'],
            'started_at_utc':started,'wall_seconds':round(time.monotonic()-timer,6),'process_exit_code':proc.returncode,
            'raw_report_sha256':sha(raw),'overall':metrics(rows),
            'tracks':{track:metrics([x for x in rows if x['track']==track]) for track in ('heldout-source','heldout-metadata')},'cases':rows}


def cisco_identity(executable, expected):
    interpreter = executable.parent / 'python'
    code = "from importlib.metadata import version; print(version('cisco-ai-mcp-scanner'))"
    actual = subprocess.check_output([str(interpreter), '-c', code], timeout=30).decode().strip()
    if actual != expected:
        raise ValueError('Cisco installed distribution differs from expected version')
    return {'distribution_version':actual, 'executable_sha256':sha(executable.read_bytes())}


def run_cisco(args, corpus):
    identity = cisco_identity(args.cisco, args.cisco_version)
    cases = [x for x in corpus['cases'] if x['suite']=='heldout-metadata']
    input_path, output_path = args.raw_output/'cisco-tools.json', args.raw_output/'cisco-result.json'
    tools = [json.loads(x['source'])['tools'][0] for x in cases]
    save(input_path, {'tools':tools})
    command = [str(args.cisco), '--analyzers','yara','--format','raw','--output',str(output_path),'static','--tools',str(input_path)]
    env={'PATH':'/usr/bin:/bin','HOME':os.environ.get('HOME',''),'LANG':'en_US.UTF-8','NO_COLOR':'1','LITELLM_LOCAL_MODEL_COST_MAP':'True','HF_HUB_OFFLINE':'1'}
    started,timer=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),time.monotonic()
    proc=subprocess.run(command,cwd=str(args.raw_output),capture_output=True,timeout=300,env=env)
    (args.raw_output/'cisco-stderr.log').write_bytes(proc.stderr)
    raw=output_path.read_bytes() if output_path.exists() else proc.stdout
    (args.raw_output/'cisco-raw.json').write_bytes(raw)
    (args.raw_output/'cisco-stdout.log').write_bytes(proc.stdout)
    result=json.loads(raw)
    records=result['scan_results']; index={x['tool_name']:x for x in records}
    if len(records)!=len(tools) or set(index)!={x['name'] for x in tools}:
        raise ValueError('Cisco response omitted or duplicated metadata items')
    valid=(proc.returncode==0 and result['requested_analyzers']==['yara'])
    rows=[]
    for case in cases:
        record=index[case['id'].replace('-','_')]
        rule,expected=next(iter(case['expect'].items()))
        findings=record.get('findings',{}).get('yara_analyzer',{})
        error=not valid or record.get('status')!='completed' or type(findings.get('total_findings')) is not int
        detected=findings.get('total_findings',0)>0
        rows.append({'id':case['id'],'expected':expected,'detected':detected,'outcome':outcome(expected,detected,error),
                     'analysis_error':error,'finding_count':findings.get('total_findings'),'threat_names':findings.get('threat_names',[]),
                     'predicate_rule_id':rule,'rationale':case['rationale']})
    return {'tool':'cisco-mcp-scanner','version':args.cisco_version,'analyzer':'yara','installed_identity':identity,'started_at_utc':started,
            'wall_seconds':round(time.monotonic()-timer,6),'process_exit_code':proc.returncode,'input_sha256':sha(input_path.read_bytes()),
            'raw_report_sha256':sha(raw),'scope':f'The same {len(cases)} offline literal tool descriptors; tool-level instruction-risk presence. Other analyzers disabled.',
            'command':['mcp-scanner','--analyzers','yara','--format','raw','--output','{output}','static','--tools','{input}'],
            'overall':metrics(rows),'cases':rows}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--commitment',type=Path,required=True)
    parser.add_argument('--implementation-root',type=Path,default=ROOT)
    parser.add_argument('--phase',choices=['baseline','initial-heldout','post-disclosure-development','presentation-only-repeat'],required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--raw-output',type=Path,required=True)
    parser.add_argument('--cisco',type=Path)
    parser.add_argument('--cisco-version',default='4.8.4')
    args=parser.parse_args(argv)
    for key in ('corpus','commitment','implementation_root','output','raw_output','cisco'):
        val=getattr(args,key)
        if val is not None:setattr(args,key,val.resolve())
    raw=args.corpus.read_bytes();corpus=validate_corpus(raw)
    commitment=json.loads(args.commitment.read_bytes())
    if sha(raw)!=commitment['sha256'] or len(corpus['cases'])!=commitment['case_count']:
        raise ValueError('Sealed challenge bytes changed')
    if args.output.exists():
        raise ValueError('Refusing to overwrite a recorded challenge execution')
    args.raw_output.mkdir(parents=True,exist_ok=True)
    result={'schema_version':'1.0','phase':args.phase,'corpus_sha256':sha(raw),'commitment_sha256':sha(args.commitment.read_bytes()),
            'provenance':corpus['provenance'],'case_count':len(corpus['cases']),
            'metric_unit':corpus['metric_unit'],'invarune':run_invarune(args,corpus),
            'not_scored':{'semgrep':'The frozen generic security-audit pack has no equivalent MCP parameter-to-sink or instruction semantic guarantee.',
                          'bandit':'Python API audit findings do not implement equivalent MCP source-to-sink or instruction predicates.',
                          'gitleaks':'No live credential patterns supplied; unsupported scope does not earn true negatives.',
                          'snyk-agent-scan':'Authenticated service not executed.'}}
    if args.cisco:result['cisco_metadata']=run_cisco(args,corpus)
    save(args.output,result)
    print(json.dumps({'phase':args.phase,'invarune':result['invarune']['overall'],
                      'cisco_metadata':result.get('cisco_metadata',{}).get('overall')},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
