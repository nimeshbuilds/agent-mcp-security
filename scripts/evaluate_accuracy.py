#!/usr/bin/env python3
"""Score explicit rule-presence labels without executing any fixture source."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from ai_security_scan import __version__
from ai_security_scan.analyzer import analyze_file, analyze_file_errors
from ai_security_scan.report import atomic_write, md
from ai_security_scan.rules import RULE_BY_ID


def load_corpus(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(10_000_001)
    if len(raw) > 10_000_000:
        raise ValueError('Corpus exceeds the 10 MB limit')
    corpus = json.loads(raw)
    if not isinstance(corpus, dict) or corpus.get('schema_version') != '1.0' or not isinstance(corpus.get('cases'), list):
        raise ValueError('Corpus requires schema_version 1.0 and a cases list')
    cases = corpus['cases']
    if not cases or len(cases) > 10_000:
        raise ValueError('Corpus must contain 1–10,000 cases')
    seen = set()
    for item in cases:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or item['id'] in seen:
            raise ValueError('Each case requires a unique nonempty string id')
        seen.add(item['id'])
        if item.get('suite') not in {'regression', 'challenge'}:
            raise ValueError('Case suite must be regression or challenge')
        if not isinstance(item.get('path'), str) or not item['path'] or not isinstance(item.get('source'), str) or len(item['source']) > 100_000:
            raise ValueError('Each case requires a path label and at most 100,000 source characters')
        expected = item.get('expect')
        if not isinstance(expected, dict) or not expected or any(rule not in RULE_BY_ID or type(value) is not bool for rule, value in expected.items()):
            raise ValueError('Case expect must map known rule IDs to boolean presence labels')
    return corpus, hashlib.sha256(raw).hexdigest()


def metrics(counts):
    out = {key: counts.get(key, 0) for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative')}
    tp, tn, fp, fn = (out[key] for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative'))
    out.update(assertions=tp + tn + fp + fn,
               precision=round(tp / (tp + fp), 6) if tp + fp else None,
               recall=round(tp / (tp + fn), 6) if tp + fn else None,
               false_positive_rate=round(fp / (fp + tn), 6) if fp + tn else None,
               false_negative_rate=round(fn / (fn + tp), 6) if fn + tp else None)
    return out


def evaluate(corpus, corpus_hash, analyzer=analyze_file, error_checker=analyze_file_errors):
    totals = Counter()
    by_suite = {name: Counter() for name in ('regression', 'challenge')}
    by_rule = {rule: Counter() for rule in RULE_BY_ID}
    results = []
    for case in corpus['cases']:
        errors = error_checker(case['path'], case['source'])
        findings = analyzer(case['path'], case['source']) if not errors else []
        detected = sorted({finding['rule_id'] for finding in findings})
        assertions = []
        if not errors:
            for rule, expected in sorted(case['expect'].items()):
                actual = rule in detected
                outcome = ('true_positive' if expected else 'false_positive') if actual else ('false_negative' if expected else 'true_negative')
                totals[outcome] += 1
                by_suite[case['suite']][outcome] += 1
                by_rule[rule][outcome] += 1
                assertions.append(dict(rule_id=rule, expected=expected, detected=actual, outcome=outcome))
        results.append(dict(id=case['id'], suite=case['suite'], path=case['path'],
                            rationale=case.get('rationale', ''), assertions=assertions,
                            detected_rule_ids=detected, unscored_rule_ids=sorted(set(detected) - set(case['expect'])),
                            analysis_errors=errors, matched_labels=not errors and all(a['expected'] == a['detected'] for a in assertions)))
    failures = [case['id'] for case in results if not case['matched_labels']]
    regression_failures = [case['id'] for case in results if case['suite'] == 'regression' and not case['matched_labels']]
    return dict(schema_version='1.0', tool_version=__version__, corpus_sha256=corpus_hash,
                corpus_name=corpus.get('name', ''), corpus_version=corpus.get('version', ''),
                provenance=corpus.get('provenance', ''), metric_unit=corpus.get('metric_unit', ''),
                scope='Synthetic, project-authored rule-presence fixtures. These are not production accuracy estimates or proof of security. Challenge cases are included in overall metrics even when the regression gate passes.',
                case_count=len(results), failed_case_ids=failures, regression_failure_ids=regression_failures,
                analysis_error_cases=sum(bool(case['analysis_errors']) for case in results),
                overall=metrics(totals), by_suite={name: metrics(counts) for name, counts in by_suite.items()},
                by_rule={name: metrics(counts) for name, counts in by_rule.items()}, cases=results)


def render_markdown(report):
    lines = ['# Invarune static rule accuracy', '', report['scope'], '',
             'Scanner: **' + md(report['tool_version']) + '** · Corpus: `' + report['corpus_sha256'] + '`', '',
             md(report['provenance']), '', md(report['metric_unit']), '',
             '| Suite | TP | TN | FP | FN | Precision | Recall |', '|---|---:|---:|---:|---:|---:|---:|']
    for name, result in [('Overall', report['overall']), *report['by_suite'].items()]:
        values = [str(result[key]) for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative')]
        rates = ['n/a' if result[key] is None else '%.2f%%' % (result[key] * 100) for key in ('precision', 'recall')]
        lines.append('| ' + ' | '.join([name, *values, *rates]) + ' |')
    lines += ['', '## Mismatches and analysis errors', '', '| Case | Suite | Expected → detected | Rationale |', '|---|---|---|---|']
    for case in report['cases']:
        if case['matched_labels']:
            continue
        result = '; '.join(a['rule_id'] + ': ' + str(a['expected']) + ' → ' + str(a['detected']) for a in case['assertions'] if a['expected'] != a['detected'])
        if case['analysis_errors']:
            result = '; '.join(case['analysis_errors'])
        lines.append('| ' + ' | '.join(md(value) for value in (case['id'], case['suite'], result, case['rationale'])) + ' |')
    lines += ['', 'Unlabeled detections are recorded in the JSON report but are not scored. A matched negative means this rule should not fire on this fixture; it is not a declaration that the application is safe.', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--corpus', type=Path, default=PROJECT / 'benchmarks/static_accuracy.json')
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--output', type=Path, help='Write the report here; otherwise use stdout')
    parser.add_argument('--fail-on', choices=('regression', 'any', 'none'), default='regression', help='Default gates supported regression cases; challenge failures remain visible in every report')
    args = parser.parse_args(argv)
    try:
        corpus, digest = load_corpus(args.corpus)
        report = evaluate(corpus, digest)
        content = json.dumps(report, indent=2, sort_keys=True) + '\n' if args.format == 'json' else render_markdown(report)
        if args.output:
            atomic_write(args.output.expanduser().resolve(), content)
        else:
            print(content, end='')
    except (OSError, ValueError, RecursionError) as exc:
        print('Accuracy evaluation failed: ' + str(exc), file=sys.stderr)
        return 2
    if report['analysis_error_cases']:
        return 2
    failed = report['regression_failure_ids'] if args.fail_on == 'regression' else report['failed_case_ids'] if args.fail_on == 'any' else []
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
