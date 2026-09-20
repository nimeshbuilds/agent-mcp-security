"""Readable complete terminal results; no file output and no ANSI from evidence."""
import unicodedata
from .scoring import format_ratio


def _safe(value):
    return ''.join(c if c in '\n\t' or not unicodedata.category(c).startswith('C') else '?' for c in str(value))


def _escape_fields(value):
    """Preserve trusted layout; evidence must never inject a new output line."""
    if isinstance(value, str):
        return _safe(value).replace('\n', '\\n').replace('\t', '\\t')
    if isinstance(value, dict):
        return {key: _escape_fields(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_escape_fields(item) for item in value]
    return value


def render_terminal(report, report_paths=None):
    report, report_paths = _escape_fields(report), _escape_fields(report_paths)
    summary, scoring = report['summary'], report['scoring']
    static, ai = scoring['deterministic'], scoring['optional_ai']
    lines = ['INVARUNE | NimeshBuild', report['assessment']['posture']['title'],
             'Scanned {} files; {} open findings; {} coverage gaps; exit {}'.format(
                 summary['files_scanned'], summary['open_findings'], summary['coverage_gaps'], report['execution']['exit_code']),
             'Selected scope: {} rules / {} controls / {} active checks'.format(
                 static['selected_rules'], static['selected_controls'], static['active_checks']),
             'Immediate attention: {} critical/high findings.'.format(static['urgent_findings']),
             'Partial deterministic mapping reach: ' + format_ratio(static['mapping_reach']),
             'Security score: not assigned. Coverage is not a safety or compliance percentage.']
    groups = {group['rule_id']: group for group in report['assessment'].get('finding_groups', [])}
    lines.append('\nFINDINGS')
    if not report['findings']:
        lines.append('No selected patterns detected. This does not establish security.')
    for item in report['findings']:
        lines.append('[{} / {}] {} {}:{} — {}'.format(item['severity'].upper(), item['status'], item['rule_id'], item['path'], item['line'], item['title']))
        if item.get('evidence'):
            lines.append('  Evidence: ' + item['evidence'])
        group = groups.get(item['rule_id'], {})
        if group.get('immediate_action'):
            lines.append('  Fix: ' + group['immediate_action'])
        if item.get('disposition', {}).get('reason') or item.get('suppression_reason'):
            lines.append('  Justification: ' + (item.get('disposition', {}).get('reason') or item['suppression_reason']))
        lines.append('  Details: invscan --explain-scan ' + item['rule_id'])
    lines.append('\nSELECTED CONTROL RESULTS')
    for control in report['controls']:
        lines.append('{} [{}] {} (rules: {})'.format(control['id'], control['status'], control['title'], ', '.join(control['automated_rule_ids']) or 'none; review required'))
    if summary['coverage_gaps']:
        lines.append('\nCOVERAGE GAPS — not cleared by AI or user exceptions')
        for gap in report['coverage']['errors']:
            lines.append('{}: {}'.format(gap['path'], gap['error']))
        for gap in report['coverage']['skipped']:
            if gap.get('coverage_gap'):
                lines.append('{}: {}'.format(gap['path'], gap['reason']))
    lines.append('\nOPTIONAL AI REVIEW: ' + ('enabled (advisory)' if ai['enabled'] else 'disabled'))
    if ai['enabled']:
        lines.append('Valid answers: ' + format_ratio(ai['answer_coverage']) + '; deterministic findings and gate unchanged.')
        for answer in report.get('judge', {}).get('assessments', []):
            lines.append('Finding {} [{}] {}'.format(answer['finding_id'], answer['verdict'], answer.get('reason', '')))
            for step in answer.get('recommended_actions', {}).get('steps', []):
                lines.append('  Proposed fix: ' + step)
        for control in report.get('analyst', {}).get('control_assessments', []):
            for check in control['check_assessments']:
                lines.append('{}:{} [{}] {}'.format(control['control_id'], check['check_index'], check['status'], check.get('reason', '')))
                for step in check.get('verification_steps', []):
                    lines.append('  Next: ' + str(step))
        for concern in report.get('judge', {}).get('additional_concerns', []):
            lines.append('Additional advisory concern: ' + str(concern))
        if report.get('judge', {}).get('error'):
            lines.append(report['judge']['error'])
    lines.append('\nJustified/disabled items receive no pass credit. Runtime authorization, tool behavior, isolation and injection resistance need separate validation.')
    if report_paths:
        lines.append('Reports: ' + ', '.join('{}={}'.format(key, value) for key, value in report_paths.items()))
    else:
        lines.append('Terminal output only. Use --report [DIR] or --output DIR to save editable reports; add --pdf for PDF.')
    return _safe('\n'.join(lines))
