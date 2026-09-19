#!/usr/bin/env python3
"""Build the branded finding-comparison research PDF from frozen local receipts.

No scanners, model calls, target code, network requests or executable PDF forms.
ReportLab is needed only when rendering; --validate-only checks source accounting.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / 'benchmarks/comparison-v010'
DEFAULT_OUTPUT = ROOT / 'output/pdf/invarune-finding-comparison-v010.pdf'
REPO = 'https://github.com/nimeshbuilds/agent-mcp-security'
ONLINE = REPO + '/blob/main/benchmarks/comparison-v010/'
TOOLS = ('invarune', 'semgrep', 'bandit', 'gitleaks')
NAMES = {'invarune': 'Invarune', 'semgrep': 'Semgrep CE', 'bandit': 'Bandit', 'gitleaks': 'Gitleaks'}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_inputs(directory=DEFAULT_INPUT, adjudication=None):
    """Validate ledgers before presenting any comparison counts or selections."""
    directory = Path(directory)
    names = ('observations.json', 'overlaps.json', 'run-status.json', 'adjudication-selection.json',
             'observations-selection-v1.json', 'observations-v090.json', 'run-status-v090.json',
             'tool-lock.json', 'external-results/shared-pattern-fixtures.json', 'external-results/cisco-metadata.json')
    files = {}
    hashes = {}
    for name in names:
        raw = (directory / name).read_bytes()
        files[name] = json.loads(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    ledger, overlaps, selection = (files[name] for name in ('observations.json', 'overlaps.json', 'adjudication-selection.json'))
    observations = ledger['observations']
    by_id = {item['id']: item for item in observations}
    counts = dict(Counter(item['tool'] for item in observations))
    if len(by_id) != len(observations) or ledger['observation_count'] != len(observations) or ledger['counts_by_tool'] != counts:
        raise ValueError('Observation count, tool totals or unique identifiers do not agree')
    if overlaps['observation_ledger_sha256'] != digest(ledger):
        raise ValueError('Overlap receipt does not bind the current observation ledger')
    for pair in overlaps['pairs']:
        left, right, c = pair['left_tool'], pair['right_tool'], pair['counts']
        if c['left_observations'] != counts.get(left, 0) or c['right_observations'] != counts.get(right, 0):
            raise ValueError('Pairwise overlap denominator differs from the observation ledger')
        for key, count_key in [('one_to_one_matches', 'one_to_one_pairs'), ('ambiguous_family_location_edges', 'ambiguous_edges'), ('location_only_edges', 'location_only_edges')]:
            if len(pair[key]) != c[count_key]:
                raise ValueError('Pairwise edge count differs from its receipt')
            for edge in pair[key]:
                if edge['left_id'] not in by_id or edge['right_id'] not in by_id:
                    raise ValueError('Overlap edge references an absent observation')
                if by_id[edge['left_id']]['tool'] != left or by_id[edge['right_id']]['tool'] != right:
                    raise ValueError('Overlap edge belongs to the wrong tool')
        for side in ('left', 'right'):
            unmatched = pair[side + '_without_family_match']
            matched = {edge[side + '_id'] for key in ('one_to_one_matches', 'ambiguous_family_location_edges') for edge in pair[key]}
            expected = {item['id'] for item in observations if item['tool'] == pair[side + '_tool']}
            if len(unmatched) != c[side + '_without_family_match'] or len(unmatched) != len(set(unmatched)) or matched & set(unmatched) or matched | set(unmatched) != expected:
                raise ValueError('Matched/unmatched observation accounting is not exhaustive and disjoint')
    frozen = files['observations-selection-v1.json']
    frozen_by_id = {item['id']: item for item in frozen['observations']}
    selected = selection['selected_observation_ids']
    if selection['input_ledger_sha256'] != digest(frozen):
        raise ValueError('Frozen selection does not bind its preserved input ledger')
    if len(selected) != selection['selected_observations'] or len(set(selected)) != len(selected) or not set(selected) <= set(frozen_by_id):
        raise ValueError('Frozen selection identifiers or denominator are invalid')
    if dict(Counter(frozen_by_id[identifier]['tool'] for identifier in selected)) != selection['selected_counts_by_tool']:
        raise ValueError('Frozen selection tool counts differ from selected observations')
    if len(selection['locations']) != selection['selected_locations'] or {identifier for loc in selection['locations'] for identifier in loc['observation_ids']} != set(selected):
        raise ValueError('Frozen source spans do not account for the selected observation set')
    runs = files['run-status.json']['runs']
    if len({(run['project_id'], run['tool']) for run in runs}) != len(runs):
        raise ValueError('Duplicate normalized tool/project run receipt')
    for tool, count in counts.items():
        if sum(run.get('finding_count') or 0 for run in runs if run['tool'] == tool) != count:
            raise ValueError('Run receipt finding counts disagree with normalized observations')
    shared = files['external-results/shared-pattern-fixtures.json']
    for tool, result in shared['results'].items():
        measured = result['counts']
        if sum(measured[key] for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative')) != shared['case_count']:
            raise ValueError('Shared fixture outcome denominator is inconsistent')
    receipts = [json.loads(path.read_text(encoding='utf-8')) for path in sorted((directory / 'invarune-receipts').glob('*.json'))]
    data = {'directory': directory, 'files': files, 'hashes': hashes, 'ledger': ledger, 'by_id': by_id,
            'overlaps': overlaps, 'selection': selection, 'frozen': frozen, 'runs': runs,
            'shared': shared, 'receipts': receipts, 'adjudication': None, 'source_audit': None, 'preparation': None}
    for name, key in [('source-audit.json', 'source_audit'), ('adjudication-prepared/preparation.json', 'preparation')]:
        path = directory / name
        if path.is_file():
            raw = path.read_bytes()
            data[key] = json.loads(raw)
            hashes[name] = hashlib.sha256(raw).hexdigest()
    if data['source_audit'] is not None:
        audit = data['source_audit']
        audit_selection = audit['selection']
        if audit_selection.get('input_ledger_path') != 'observations-v090.json' or audit_selection['input_ledger_sha256'] != hashes['observations-v090.json']:
            raise ValueError('Source audit does not bind the preserved observation ledger')
        if audit_selection['input_selection_sha256'] != hashes['adjudication-selection.json']:
            raise ValueError('Source audit does not bind the frozen selection')
        if (audit_selection.get('parent_selection_input_ledger_path') != 'observations-selection-v1.json'
                or audit_selection.get('parent_selection_input_raw_sha256') != hashes['observations-selection-v1.json']
                or audit_selection.get('parent_selection_declared_canonical_sha256') != digest(frozen)):
            raise ValueError('Source audit parent selection provenance is inconsistent')
        correspondence = audit['current_ledger_correspondence']
        if correspondence.get('path') != 'observations.json' or correspondence.get('raw_sha256') != hashes['observations.json']:
            raise ValueError('Source audit current ledger correspondence digest is inconsistent')
        historical_by_id = {row['id']: row for row in files['observations-v090.json']['observations']}
        audit_selected = audit_selection['selected_observation_ids']
        if len(audit_selected) != len(set(audit_selected)) or not set(audit_selected) <= set(selected):
            raise ValueError('Source audit selection must be a unique subset of the frozen parent selection')
        invariants = ('tool', 'rule_id', 'project_id', 'path', 'line_start', 'line_end', 'family', 'review_predicate', 'revision', 'source_manifest_sha256')
        for identifier in audit_selected:
            if identifier not in by_id or identifier not in historical_by_id or any(by_id[identifier][key] != historical_by_id[identifier][key] for key in invariants):
                raise ValueError('Source audit current and preserved observation identities differ')
        if correspondence.get('all_selected_invariants_match') is not True or correspondence.get('selected_observations_compared') != len(audit_selected):
            raise ValueError('Source audit current correspondence count or claim is inconsistent')
        audit_ids = [row['observation_id'] for row in audit['observations']]
        if len(set(audit_ids)) != len(audit_ids) or not set(audit_ids) <= set(audit_selected):
            raise ValueError('Source audit contains duplicate or unselected observations')
        if audit.get('status') == 'completed' and set(audit_ids) != set(audit_selected):
            raise ValueError('Completed source audit must retain every selected observation')
        allowed = {'supported_source_pattern', 'conditional_rule_mismatch', 'insufficient_evidence'}
        if any(row['source_pattern_status'] not in allowed for row in audit['observations']):
            raise ValueError('Source audit contains an unsupported label')
        for row in audit['observations']:
            original = historical_by_id.get(row['observation_id'])
            if original is None or any(row[key] != original[key] for key in invariants if key not in ('line_start', 'line_end')) or row['tool_version'] != original['tool_version'] or row['reported_line_start'] != original['line_start'] or row['reported_line_end'] != original['line_end']:
                raise ValueError('Source audit changed the selected observation identity')
        if 'summary' in audit:
            summary = audit['summary']
            patterns = Counter(row['source_pattern_status'] for row in audit['observations'])
            if summary.get('selected_observations') != len(audit_ids) or any(summary['source_pattern_counts'].get(key) != patterns[key] for key in allowed):
                raise ValueError('Source audit summary disagrees with the detailed source labels')
    if adjudication is None:
        default = directory / 'adjudication-live/model-adjudication.json'
        if default.is_file():
            adjudication = default
    if adjudication is not None:
        path = Path(adjudication)
        raw = path.read_bytes()
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError('Optional adjudication must be a JSON object')
        data['adjudication'] = {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'data': result}
        if result.get('mode') == 'live_claude':
            # Selection identity binds its historical input; evidence preparation
            # separately binds the actual review ledger. Those are different
            # artifacts, and both digests use canonical JSON (not raw bytes).
            review_name = next((name for name in ('observations.json', 'observations-v090.json')
                                if digest(files[name]) == result.get('review_ledger_sha256')), None)
            if result.get('selection_id') != selection['selection_id'] or result.get('original_selection_ledger_sha256') != digest(frozen) or review_name is None:
                raise ValueError('Model adjudication does not bind the frozen selection and a known review ledger')
            preparation_path = path.parent / 'preparation.json'
            if not preparation_path.is_file():
                raise ValueError('Model adjudication requires its adjacent preparation receipt')
            preparation_raw = preparation_path.read_bytes()
            preparation = json.loads(preparation_raw)
            if result.get('preparation_sha256') != digest(preparation):
                raise ValueError('Model adjudication preparation digest does not match its receipt')
            for key in ('selection_id', 'original_selection_ledger_sha256', 'review_ledger_sha256'):
                if preparation.get(key) != result[key]:
                    raise ValueError('Model adjudication and preparation provenance do not agree')
            if preparation.get('selection_file_sha256') != hashes['adjudication-selection.json'] or preparation.get('selected_observations') != len(selected):
                raise ValueError('Model preparation does not bind the frozen selection file and count')
            review_by_id = {row['id']: row for row in files[review_name]['observations']}
            invariants = ('project_id', 'revision', 'source_manifest_sha256', 'path', 'line_start', 'line_end', 'rule_id', 'family', 'tool')
            for identifier in selected:
                if identifier not in review_by_id or any(review_by_id[identifier][key] != frozen_by_id[identifier][key] for key in invariants):
                    raise ValueError('Model review ledger changed a selected observation identity')
            actual_versions = sorted({review_by_id[identifier]['tool_version'] for identifier in selected if review_by_id[identifier]['tool'] == 'invarune'})
            if preparation.get('engine_versions') != actual_versions:
                raise ValueError('Model preparation engine versions differ from the reviewed observations')
            data['adjudication']['review_ledger'] = review_name
            data['adjudication']['review_invarune_versions'] = ', '.join(actual_versions)
            data['adjudication']['preparation'] = preparation
            hashes['adjudication-live/preparation.json'] = hashlib.sha256(preparation_raw).hexdigest()
            judgments = result['judgments']
            ids = [row['observation_id'] for row in judgments]
            if len(set(ids)) != len(ids) or set(ids) != set(selected):
                raise ValueError('Model adjudication must retain every selected observation exactly once')
            for row in judgments:
                if any(row[key] != review_by_id[row['observation_id']][key] for key in ('tool', 'project_id', 'path', 'rule_id', 'tool_version')):
                    raise ValueError('Model adjudication identity differs from its reviewed observation')
            actual = likelihood_counts(judgments)
            if any(result['summary'].get(key) != number for key, number in actual.items()):
                raise ValueError('Model adjudication summary counts disagree with its judgments')
            if result.get('model_judgments_measured') is not bool(actual['valid_model_answers']):
                raise ValueError('Model adjudication measurement flag disagrees with accepted answers')
    return data


def likelihood_counts(rows):
    verdicts = ('likely_true_positive', 'likely_false_positive', 'needs_runtime_validation', 'insufficient_evidence')
    if any(row.get('status') == 'reviewed' and row.get('verdict') not in verdicts for row in rows):
        raise ValueError('Unknown model likelihood label')
    counts = Counter(row['verdict'] for row in rows if row.get('status') == 'reviewed')
    reviewed = sum(counts.values())
    decided = counts['likely_true_positive'] + counts['likely_false_positive']
    return {'selected_observations': len(rows), 'valid_model_answers': reviewed, 'adjudicable_answers': decided,
            **{label: counts[label] for label in verdicts}, 'answer_or_execution_errors': len(rows) - reviewed,
            'unknown_including_runtime_insufficient_and_errors': len(rows) - decided}


def versions(ledger, tool):
    return ', '.join(sorted({item['tool_version'] for item in ledger['observations'] if item['tool'] == tool})) or 'not recorded'


def illustrative_observations(data):
    """A small deterministic sample of relations; model outcomes are not inputs."""
    chosen, seen = [], set()
    pairs = data['overlaps']['pairs']
    for relationship, key in [('One-to-one family/location agreement', 'one_to_one_matches'), ('Ambiguous family/location relation', 'ambiguous_family_location_edges')]:
        pair = next((pair for pair in pairs if pair['left_tool'] == 'invarune' and pair[key]), None)
        if pair:
            edge = sorted(pair[key], key=lambda row: (row['left_id'], row['right_id']))[0]
            chosen.append((data['by_id'][edge['left_id']], relationship, [data['by_id'][edge['right_id']]]))
            seen.add(edge['left_id'])
    preferences = [('invarune', 'dependency_version_range'), ('bandit', 'assert_statement'),
                   ('semgrep', 'pickle_family_api'), ('gitleaks', 'credential_literal')]
    for tool, preferred in preferences:
        opposite = next((pair for pair in pairs if {pair['left_tool'], pair['right_tool']} == {tool, 'invarune'}), None)
        if tool == 'invarune':
            opposite = next(pair for pair in pairs if pair['left_tool'] == 'invarune' and pair['right_tool'] == 'semgrep')
        side = 'left' if opposite['left_tool'] == tool else 'right'
        candidates = [data['by_id'][identifier] for identifier in opposite[side + '_without_family_match'] if identifier not in seen]
        candidates.sort(key=lambda item: (item['family'] != preferred, item['project_id'], item['path'], item['line_start'], item['id']))
        if candidates:
            item = candidates[0]
            other = opposite['right_tool'] if side == 'left' else opposite['left_tool']
            chosen.append((item, 'No family/location match with ' + NAMES[other], []))
            seen.add(item['id'])
    return chosen


def build_pdf(data, output=DEFAULT_OUTPUT):
    # Reuse the established NimeshBuild fonts, colors, tables and navigation.
    sys.path.insert(0, str(ROOT / 'scripts'))
    from build_benchmark_report import (FONT, TEAL, NavigationDocument, CountChart, frame,
                                        p as base_p, table, link as base_link)
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Frame, PageTemplate, Spacer, PageBreak, Image, Table, Paragraph
    from reportlab.platypus.tableofcontents import TableOfContents
    from reportlab.pdfgen import canvas

    def p(value, kind='body'):
        text = str(value).encode('utf-8', 'backslashreplace').decode('utf-8')
        return base_p(text, kind)

    def link(label, url):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or any(ord(c) < 33 for c in url):
            raise ValueError('Comparison source links must be ordinary HTTPS URLs')
        return base_link(label, url)

    def section(title):
        return [PageBreak(), p(title, 'heading')]

    ledger, by_id, overlaps, selection = data['ledger'], data['by_id'], data['overlaps'], data['selection']
    runs, shared, files = data['runs'], data['shared'], data['files']
    count = ledger['observation_count']
    current_version = versions(ledger, 'invarune')
    initial = files['observations-v090.json']
    projects = sorted({item['project_id'] for item in ledger['inputs']})
    file_total = sum(item['files'] for item in ledger['inputs'])
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle('comparison-contents', fontName=FONT, fontSize=10.5, leading=24, textColor=TEAL)]
    story = [Spacer(1, 20), Image(str(ROOT / 'docs/assets/brand/invarune-mark.png'), width=76, height=76, hAlign='LEFT'),
             Spacer(1, 20), p('Findings compared.\nClaims kept separate.', 'heading'),
             p('Agent and MCP security / source-scanner research', 'sub'),
             p('Comparison v0.10 series | Recorded Invarune engine: ' + current_version + ' | 19 September 2026', 'small'),
             Spacer(1, 18), table([['PINNED PROJECTS', 'SOURCE OBSERVATIONS', 'FROZEN REVIEW SPANS'],
                                  [str(len(projects)), format(count, ','), str(selection['selected_locations'])]], [169, 169, 169]),
             Spacer(1, 16), p('The useful result', 'sub'),
             p('Different scanners expose different review work. This comparison retains every observation and analysis gap, links exact source locations and identifies conservative overlap. It does not turn agreement, severity or model judgments into confirmed vulnerabilities.'),
             p('Immediate priorities: inspect executable/deserialization and credential boundaries in context; close analysis gaps; validate agent reachability, tenant permissions and deployed safeguards before accepting or dismissing a concern.'),
             p('The complete online ledger contains ' + format(count, ',') + ' source observations. This PDF shows representative cases and explicit denominators instead of repeating the entire ledger.'),
             link('Open the complete finding-by-finding ledger', ONLINE + 'FINDINGS.md'),
             link('Machine-readable evidence, receipts and reproducible methods', ONLINE + 'README.md'),
             PageBreak(), p('Contents', 'sub'), p('Click an entry or use PDF bookmarks. This is a research report, not an editable scan-review capsule.'), toc]

    story += section('01 / What ran and what the counts mean')
    story += [p(str(len(runs)) + ' normalized project/tool run records cover ' + str(len(projects)) + ' pinned public source exports (' + format(file_total, ',') + ' exported files). The same exported bytes were offered to each source scanner; supported languages, parser outcomes and active rules differ.'),
              p('One observation is one scanner-reported source record. It is not necessarily one distinct vulnerability. Repeated Invarune executions are repeatability checks and do not multiply the observation denominator.'),
              CountChart([(NAMES[tool], ledger['counts_by_tool'].get(tool, 0)) for tool in TOOLS], 'Observation volume only; different rule scopes. No quality ranking.'), Spacer(1, 12)]
    rows = [['Source tool', 'Recorded version', 'Observations', 'Relevant scope']]
    boundaries = {'invarune': 'Agent/MCP and shared source/configuration patterns', 'semgrep': 'CE engine; frozen 225-rule audit pack', 'bandit': 'Packaged Python plugins; includes imports/assertions', 'gitleaks': 'Directory secret patterns; no Git-history run'}
    for tool in TOOLS:
        rows.append([NAMES[tool], versions(ledger, tool), str(ledger['counts_by_tool'].get(tool, 0)), boundaries[tool]])
    story += [table(rows, [92, 82, 79, 254]), Spacer(1, 12),
              p('Do not compare a library import, a policy warning, a dangerous API call, an active attack success and a confirmed exploitable vulnerability as interchangeable units. A lower count can reflect narrower scope, different predicates or incomplete analysis.'),
              link('Tool configurations, versions and ruleset hashes', ONLINE + 'tool-lock.json')]

    story += section('02 / Analysis completeness and source scope')
    rows = [['Tool', 'Run records', 'Runs with errors/gaps', 'Unsupported inputs', 'Reported errors / gaps']]
    for tool in TOOLS:
        selected_runs = [run for run in runs if run['tool'] == tool]
        errors = sum(bool(run.get('errors') or run.get('coverage_gaps')) for run in selected_runs)
        unsupported = sum('unsupported' in run['status'] for run in selected_runs)
        rows.append([NAMES[tool], str(len(selected_runs)), str(errors) + '/' + str(len(selected_runs)), str(unsupported),
                     str(sum(len(run.get('errors', [])) for run in selected_runs)) + ' errors; ' + str(sum(run.get('coverage_gaps', 0) for run in selected_runs)) + ' gaps'])
    story += [table(rows, [84, 69, 110, 100, 144]), Spacer(1, 12),
              p('Error and gap counts describe each tool own receipt schema; they are not equivalent coverage units and must not be summed into an accuracy denominator. Unsupported Bandit exports are not clean Python scans. A successful process can still report parser warnings or partial analysis.'),
              p('Project-level recorded statuses', 'sub')]
    rows = [['Project', 'Invarune', 'Semgrep', 'Bandit', 'Gitleaks']]
    by_run = {(run['project_id'], run['tool']): run for run in runs}
    for project in projects:
        values = [project]
        for tool in TOOLS:
            run = by_run.get((project, tool))
            value = 'No receipt'
            if run is not None:
                value = 'N/A' if 'unsupported' in run['status'] else str(run.get('finding_count', '?'))
                if run.get('errors') or run.get('coverage_gaps'):
                    value += '; partial'
            values.append(value)
        rows.append(values)
    story += [table(rows, [123, 96, 96, 96, 96]), Spacer(1, 12),
              p('Cells show observation counts; partial means errors or gaps are recorded. N/A means unsupported input. Generated templates, unsupported syntax and parser limitations can hide relevant implementation paths; inspect the raw statuses before claiming another scanner missed an issue.', 'small'),
              link('Complete run statuses and error records', ONLINE + 'run-status.json'),
              link('Pinned source manifests, project commits and licenses', REPO + '/blob/main/benchmarks/real-world/manifest.json')]

    story += section('03 / Conservative finding-by-finding overlap')
    story += [p(overlaps['method']), p('A one-to-one pair requires each observation to have exactly one compatible counterpart. Many-to-many edges remain ambiguous. Location-only relations overlap a span but differ in family or mapping; none of these relations supplies a correctness label.')]
    rows = [['Pair (left / right)', '1:1 pairs', 'Ambiguous edges', 'Location-only', 'Left unmatched / all', 'Right unmatched / all']]
    for pair in overlaps['pairs']:
        c = pair['counts']
        rows.append([NAMES[pair['left_tool']] + ' / ' + NAMES[pair['right_tool']], str(c['one_to_one_pairs']), str(c['ambiguous_edges']), str(c['location_only_edges']),
                     str(c['left_without_family_match']) + '/' + str(c['left_observations']), str(c['right_without_family_match']) + '/' + str(c['right_observations'])])
    story += [table(rows, [127, 52, 68, 68, 96, 96]), Spacer(1, 12),
              p('The unmatched denominator is the relevant tool observation count in that pair. Ambiguous edges can share endpoints, so edge counts must not be interpreted as unique shared issues. Pairwise rows are not additive across tools.'),
              p('Tool-only is not a missed vulnerability. First establish compatible rule predicates, successful analysis of the affected language/file, a valid security use and the relevant trust boundary. Different source spans remain unmatched rather than being guessed into alignment.'),
              link('Every match, ambiguous edge and unmatched observation ID', ONLINE + 'overlaps.json'),
              link('Explicit compatible families and review predicates', ONLINE + 'rule-family-map.json')]

    story += section('04 / Frozen selection and unresolved accuracy')
    story += [p('Before reading any model outcomes, the recorded selection froze ' + str(selection['selected_locations']) + ' exact spans containing ' + str(selection['selected_observations']) + ' observations from a ' + str(selection['input_observation_count']) + '-observation ledger. It covers ' + str(selection['covered_strata']) + '/' + str(selection['total_observed_strata']) + ' observed tool/project/family strata.'),
              p(selection['strategy']), p(selection['sampling_limitations']),
              p('Selection coverage is a workload measure, not a confidence interval or accuracy estimate. Unreviewed observations remain unknown; they are not false positives. Labels for the frozen historical observations must not silently be reassigned to new detections.')]
    rows = [['Tool', 'Selected historical observations', 'Historical source observations', 'Selected share']]
    for tool in TOOLS:
        selected_count = selection['selected_counts_by_tool'].get(tool, 0)
        total = data['frozen']['counts_by_tool'].get(tool, 0)
        rows.append([NAMES[tool], str(selected_count), str(total), ('{:.1f}% ({}/{})'.format(100 * selected_count / total, selected_count, total) if total else 'N/A')])
    story += [table(rows, [90, 140, 142, 135]), Spacer(1, 12),
              p('Selected IDs still present in the current ledger: ' + str(len(set(selection['selected_observation_ids']) & set(by_id))) + '/' + str(selection['selected_observations']) + '. A changed detector version can create or remove observations; preserved selection provenance remains tied to its original input digest.', 'small'),
              link('Frozen algorithm, seed, selection ID and all selected spans', ONLINE + 'adjudication-selection.json')]
    story += adjudication_story(data, p, table, link)
    story += source_audit_story(data, p, table, link)

    story += section('05 / Representative observations and agent relevance')
    story += [p('These illustrations are selected deterministically from current match relations and named families, without consulting any model outcome. They are examples of review work, not a verdict on the upstream projects. Source links point to the pinned commit.')]
    relevance = {
        'dynamic_code_execution': 'If agent/user/tool content reaches this evaluator, text can become code under the tool identity. Trace the producer, callable path and execution isolation before judging exploitability.',
        'credential_literal': 'If this is a live credential used by a model gateway or downstream tool, copying it can bypass the normal agent session. Classify it without revealing the value; test/example strings are not automatically secrets.',
        'dependency_version_range': 'A movable dependency can change the agent or MCP runtime and its security behavior. Check the effective lockfile and installation command before treating a version range as uncontrolled installation.',
        'assert_statement': 'An assertion matters to agent security when it enforces authorization or input constraints that disappear under optimization. Many assertions express internal invariants; the source predicate alone does not establish an exploitable gap.',
        'pickle_family_api': 'Executable deserialization can cross an agent artifact/cache trust boundary. Serialization and imports are different operations; identify the exact call and whether input bytes can come from an untrusted producer.'}
    for index, (item, relationship, counterparts) in enumerate(illustrative_observations(data), 1):
        story += [p(str(index) + '. ' + NAMES[item['tool']] + ' / ' + item['rule_id'], 'sub'),
                  p(relationship + ' | ' + item['project_id'] + ' | ' + item['path'] + ':' + str(item['line_start']) + '-' + str(item['line_end']), 'small'),
                  p('Scanner claim: ' + item['rule_message']),
                  p('Review predicate: ' + item.get('review_predicate', 'Inspect the native rule predicate and actual source context before reaching a conclusion.'), 'small'),
                  p('Agent/MCP applicability: ' + relevance.get(item['family'], 'Determine whether this pattern is part of the agent/MCP data or execution path, who controls its inputs, and which identity/resources it can reach. Generic source presence does not establish that path.'), 'small'),
                  p('Observation ID: ' + item['id'] + ' | Recorded engine ' + item['tool_version'] + ' | Status: unverified observation', 'small'),
                  link('Inspect pinned source location', item['source_url'])]
        for other in counterparts:
            story += [p('Counterpart: ' + NAMES[other['tool']] + ' / ' + other['rule_id'] + ' / ' + other['id'] + '. Compatible location/family does not establish identical semantics or ground truth.', 'small'), link('Inspect counterpart pinned span', other['source_url'])]
        story.append(Spacer(1, 8))

    story += section('06 / Shared fixtures and the Inspector correction')
    story += [p('A separate development-visible fixture receipt tests five API patterns with a positive and negative example each: dynamic eval, shell subprocesses, unsafe YAML, pickle loading and disabled TLS verification. Only the mapped API-pattern assertion is scored; unrelated observations do not become errors for that assertion.'),
              p('Recorded fixture Invarune version: ' + shared.get('invarune_version', 'not recorded') + '. These results remain attached to that execution, even when this PDF summarizes a later source-scan engine.', 'small')]
    rows = [['Tool', 'Positive hits / positives', 'Correct negative labels / negatives', 'False positive / false negative']]
    for tool in ('invarune', 'semgrep', 'bandit'):
        c = shared['results'][tool]['counts']
        rows.append([NAMES[tool], str(c['true_positive']) + '/' + str(c['true_positive'] + c['false_negative']),
                     str(c['true_negative']) + '/' + str(c['true_negative'] + c['false_positive']), str(c['false_positive']) + ' / ' + str(c['false_negative'])])
    story += [table(rows, [90, 140, 145, 132]), Spacer(1, 12),
              p('Five hits out of five selected positive labels supports a 100% hit rate only for those five cases. This is not production recall, precision, exploitability or full agent/MCP coverage. Gitleaks and metadata tools are outside this fixture scope and receive no artificial true negatives.'),
              link('Exact fixture cases, labels, tool mappings and execution receipts', ONLINE + 'external-results/shared-pattern-fixtures.json'),
              p('AI041: an authentication-bypass configuration trap', 'sub'),
              p('Current official Inspector documentation says any nonempty DANGEROUSLY_OMIT_AUTH value disables authentication, including the strings false and 0. Remediation must unset the variable; setting it to false is not the safe counterexample. The detector and development-corpus labels were corrected, with the previous corpus preserved.'),
              p('This is a documented configuration-semantics correction, not proof of exploitation in the public projects. AI041 is outside the five-pattern fixture set above. Initial v0.9 observations remain historical; any v0.10 detection changes belong to a new recorded execution.'),
              link('Official Inspector environment-variable semantics', 'https://github.com/modelcontextprotocol/inspector/blob/main/docs/environment-variables.md'),
              link('Correction regressions and unsafe-value matrix', REPO + '/blob/main/tests/test_inspector_auth_values.py')]

    story += section('07 / Initial versus current engine evidence')
    rows = [['Evidence snapshot', 'Invarune version', 'Invarune observations', 'Total source observations']]
    rows.append(['Preserved initial source run', versions(initial, 'invarune'), str(initial['counts_by_tool'].get('invarune', 0)), str(initial['observation_count'])])
    rows.append(['Current normalized source ledger', current_version, str(ledger['counts_by_tool'].get('invarune', 0)), str(count)])
    story += [table(rows, [165, 105, 119, 118]), Spacer(1, 12)]
    old_ids = {item['id'] for item in initial['observations'] if item['tool'] == 'invarune'}
    new_ids = {item['id'] for item in ledger['observations'] if item['tool'] == 'invarune'}
    story += [p('Invarune observation identity comparison: ' + str(len(old_ids & new_ids)) + ' retained, ' + str(len(new_ids - old_ids)) + ' added, ' + str(len(old_ids - new_ids)) + ' absent from the current ledger. These are detection-set changes, not fixed vulnerabilities or newly proven defects.'),
              p('Observation IDs deliberately exclude engine version, while each row retains its actual tool version and raw-report digest. A missing observation may reflect a changed detector, rule mapping or scope. Consult the source and execution receipt before interpreting a change.')]
    if current_version == versions(initial, 'invarune'):
        story.append(p('No later Invarune engine is represented by the current ledger yet. The comparison series name does not relabel these measurements as a v0.10 engine run.', 'sub'))
    for version in sorted({receipt.get('tool', {}).get('version', 'unknown') for receipt in data['receipts']}):
        receipts = [receipt for receipt in data['receipts'] if receipt.get('tool', {}).get('version', 'unknown') == version]
        repeats = sum(len(receipt.get('repeated_runs', [])) for receipt in receipts)
        identical = sum(receipt.get('byte_identical_reports') is True for receipt in receipts)
        story.append(p('Archived Invarune ' + version + ' receipts: ' + str(repeats) + ' recorded executions across ' + str(len(receipts)) + ' projects; ' + str(identical) + '/' + str(len(receipts)) + ' projects report byte-identical repeated outputs. This measures repeatability under those recorded inputs, not correctness.', 'small'))
    story += [link('Preserved v0.9 observations', ONLINE + 'observations-v090.json'), link('Current source observations', ONLINE + 'observations.json')]

    story += section('08 / Other security layers and current tool research')
    cisco = files['external-results/cisco-metadata.json']
    story += [p('Cisco MCP Scanner ' + cisco['version'] + ' recorded ' + str(cisco['finding_count']) + ' findings over ' + str(len(cisco['declarations'])) + ' extracted literal tool descriptions using YARA only. This is partial offline metadata, not a live tools/list inventory, input-schema validation or runtime assessment.'),
              p('Researched but unexecuted in this experiment: Snyk Agent Scan 0.6.3, SPLX Agentic Radar 0.14.1 and Promptfoo MCP red teaming. Their inventory, cloud, workflow or runtime capabilities are different units; no score or clean-result credit is assigned.'),
              p('Source evidence still needs the deployment layers below', 'sub')]
    story += [table([['Boundary', 'What source observations can suggest', 'Additional evidence required'],
                     ['Tool execution', 'Dynamic code, shell, SQL or template sinks', 'Caller/resource policy, argument tests and actual worker isolation'],
                     ['MCP identity', 'Authentication flags, token forwarding and HTTP settings', 'Issuer/audience validation, tenant separation and direct-route denial tests'],
                     ['Agent decisions', 'Privileged prompt input and broad tool grants', 'Indirect-injection evaluation and approvals bound to actual effects'],
                     ['Data and artifacts', 'Secret patterns, unsafe loaders and mutable dependencies', 'Credential validity/rotation, provenance, access policy and separate CVE checks']], [94, 180, 233]), Spacer(1, 12),
              p('These are proposed verification layers. A model expert can help prioritize or interpret supplied evidence, but a deterministic protocol validator only constrains the response format and evidence links. It cannot convert model confidence into ground truth.'),
              link('Current primary-source tool research and scope distinctions', ONLINE + 'RESEARCH.md'),
              link('Invarune source-linked remediation catalog', REPO + '/blob/main/ai_security_scan/data/remediations.json'),
              link('Primary MCP security guidance', 'https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices')]

    story += section('09 / Sources, artifacts and reproducibility')
    story += [p('All metrics in this PDF are derived from the local checked-in ledgers and validated accounting at build time. Source URLs are clickable references, not instructions to fetch or execute anything. Raw tool messages and source snippets are not reproduced as the complete ledger; the normalized source records retain native rule identifiers for inspection.'),
              link('Complete online finding ledger (' + format(count, ',') + ' rows)', ONLINE + 'FINDINGS.md')]
    for name in ('README.md', 'RESEARCH.md', 'observations.json', 'overlaps.json', 'run-status.json', 'adjudication-selection.json', 'observations-selection-v1.json', 'tool-lock.json', 'external-results/shared-pattern-fixtures.json', 'external-results/cisco-metadata.json'):
        story.append(link(name, ONLINE + name))
    story += [p('Input artifact SHA-256 values', 'sub')]
    hash_style = ParagraphStyle('Digest', fontName=FONT, fontSize=7, leading=10)
    hash_table = Table([[p('Input artifact', 'headcell'), p('SHA-256', 'headcell')],
                        *[[p(name, 'small'), Paragraph(sha, hash_style)] for name, sha in sorted(data['hashes'].items())]],
                       colWidths=[200, 307], repeatRows=1, hAlign='LEFT')
    hash_table.setStyle([('BACKGROUND', (0, 0), (-1, 0), '#0b1220'), ('ROWBACKGROUNDS', (0, 1), (-1, -1), ['#ffffff', '#f2f6fa']),
                         ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                         ('LEFTPADDING', (0, 0), (-1, -1), 9), ('RIGHTPADDING', (0, 0), (-1, -1), 9)])
    story.append(hash_table)
    story += [p('Rebuild and validate', 'sub'),
              p('python3 scripts/build_finding_comparison_report.py --validate-only', 'small'),
              p('python3 scripts/build_finding_comparison_report.py --output output/pdf/invarune-finding-comparison-v010.pdf', 'small'),
              p('Rendering requires the authoring-only ReportLab dependency. The builder does not scan targets or call a model. Review the final PDF visually before distributing it; text extraction does not establish layout fidelity.', 'small')]
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    document = NavigationDocument(str(output), pagesize=(595.276, 841.89), leftMargin=44, rightMargin=44,
                                  topMargin=66, bottomMargin=50, title='Invarune | Finding-by-finding scanner comparison',
                                  author='NimeshBuild')
    document.addPageTemplates(PageTemplate(id='comparison', frames=[Frame(44, 50, 507, 726, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=frame))
    document.multiBuild(story, canvasmaker=lambda *args, **kwargs: canvas.Canvas(*args, **{**kwargs, 'invariant': 1}))
    return output


def adjudication_story(data, p, table, link):
    """Optional model results stay distinct; never invent labels or denominators."""
    record = data.get('adjudication')
    if record is None:
        return [p('Optional adjudication: no result attached', 'sub'),
                p('No real-project TP/FP percentage is calculated here. The frozen sample identifies work to review; the scanner observations remain unverified. A model-produced label would need its own provenance, answered/uncertain/excluded counts and independent validation before any stronger claim.')]
    result = record['data']
    if result.get('mode') == 'dry_run_fixture':
        return [p('Adjudication protocol fixture only', 'sub'),
                p('The attached artifact is a synthetic dry-run fixture, not a model execution or measured TP/FP result. It supplies no real-project likelihood labels. Artifact SHA-256: ' + record['sha256'])]
    if result.get('mode') == 'live_claude':
        rows = result['judgments']
        c = likelihood_counts(rows)
        story = [p('Optional Claude adjudication: actual attempt and coverage', 'sub'),
                 p(str(result.get('live_calls', 0)) + ' live request attempts are recorded. Authentication blocked remaining work: ' + str(bool(result.get('authentication_blocked')))
                   + '. Accepted model answers: ' + str(c['valid_model_answers']) + '/' + str(c['selected_observations']) + ' selected observations. Prepared evidence and an attempted request are not model answers.'),
                 p('The selection remains bound to its original historical ledger. Actual preparation separately binds ' + record['review_ledger'] + ' (Invarune ' + record['review_invarune_versions'] + '), with every selected observation identity checked across both inputs. Model artifact SHA-256: ' + record['sha256'], 'small')]
        chart = [['Tool', 'Accepted / selected', 'Likely TP / likely FP', 'Runtime / insufficient', 'No accepted answer']]
        for tool in TOOLS:
            value = likelihood_counts([row for row in rows if row['tool'] == tool])
            chart.append([NAMES[tool], str(value['valid_model_answers']) + '/' + str(value['selected_observations']),
                          str(value['likely_true_positive']) + ' / ' + str(value['likely_false_positive']),
                          str(value['needs_runtime_validation']) + ' / ' + str(value['insufficient_evidence']), str(value['answer_or_execution_errors'])])
        story += [table(chart, [88, 104, 105, 105, 105])]
        if c['adjudicable_answers']:
            fraction = c['likely_true_positive'] / c['adjudicable_answers']
            story.append(p('Within accepted, adjudicable model answers only: {:.1f}% ({}/{}) were labeled likely true positive. The denominator excludes runtime/insufficient answers and missing, failed or unattempted answers. This is model opinion on a purposive sample, not independently confirmed precision.'.format(100 * fraction, c['likely_true_positive'], c['adjudicable_answers'])))
        else:
            story.append(p('Model likely-TP point estimate: unavailable. There are zero accepted adjudicable answers, so no 0% TP claim is calculated. All selected observations remain unknown for that estimate.'))
        selected_count = c['selected_observations']
        if selected_count:
            low = c['likely_true_positive'] / selected_count
            high = (c['likely_true_positive'] + c['unknown_including_runtime_insufficient_and_errors']) / selected_count
            story.append(p('Selected-sample accounting bounds, treating every unresolved item as either negative or positive: {:.1f}% to {:.1f}% across all {} selected observations. These are missing-label bounds, not statistical confidence intervals or production accuracy.'.format(100 * low, 100 * high, selected_count), 'small'))
        story += [p('No independent human ground truth or confirmed exploitability is supplied by this model track. Unattempted or invalid answers are not false positives, and tool agreement is not used as a label.'),
                  link('Actual model attempt, status and exhaustive selected-row audit', ONLINE + 'adjudication-live/model-adjudication.json')]
        return story
    # An unknown optional schema is retained as a provenance reference only. It
    # must never be mined heuristically for numbers and promoted into accuracy.
    return [p('Optional adjudication artifact supplied', 'sub'),
            p('An optional result was supplied with SHA-256 ' + record['sha256'] + '. Its status is ' + str(result.get('status', 'not declared')) + '. No TP/FP percentage is inferred from an unrecognized label schema.'),
            p('Model judgments are nondeterministic opinions about supplied evidence. They do not relabel the static ledger or establish production precision, exploitability or runtime control effectiveness.')]


def source_audit_story(data, p, table, link):
    audit = data.get('source_audit')
    if audit is None:
        return []
    rows = audit['observations']
    selected = audit['selection']['selected_observation_ids']
    story = [p('Separate Codex-assisted source-predicate audit', 'sub'),
             p('Recorded status: ' + str(audit.get('status', 'not declared')) + '. Source-review rows present: ' + str(len(rows)) + '/' + str(len(selected)) + ' selected observations. This is agent-assisted source review, not independent human ground truth, Claude adjudication or runtime testing.'),
             p(audit.get('tool_blinding', 'The review is not asserted to be blind.'), 'small')]
    if rows:
        values = [['Tool', 'Reviewed / selected', 'Source predicate supported', 'Conditional mismatch', 'Insufficient evidence']]
        for tool in TOOLS:
            items = [row for row in rows if row['tool'] == tool]
            count = Counter(row['source_pattern_status'] for row in items)
            values.append([NAMES[tool], str(len(items)) + '/' + str(audit['selection']['counts_by_tool'].get(tool, 0)),
                           str(count['supported_source_pattern']), str(count['conditional_rule_mismatch']), str(count['insufficient_evidence'])])
        story += [table(values, [88, 104, 105, 105, 105])]
    story += [p('A supported source predicate means the cited syntax/configuration supports that narrow rule claim. It does not establish an exploitable vulnerability or deployment exposure. Conditional mismatches, such as an example/error string or non-security use, require interpretation of the actual rule predicate. No percentage from these labels is presented as production precision.'),
              p('For the three selected Gitleaks records, the audit distinguishes the benchmark claim of a private or usable secret from the native rule\'s broader lexical pattern. A public credential identifier or documented example can match that native pattern while failing the narrower benchmark predicate; these are not established Gitleaks detection errors.', 'small'),
              link('Complete source audit with pinned line evidence and rationale', ONLINE + 'source-audit.json'),
              link('Readable source-audit scope, selected findings and limits', ONLINE + 'SOURCE_AUDIT.md')]
    return story


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input-dir', type=Path, default=DEFAULT_INPUT, help='Directory containing current and preserved comparison ledgers (default: benchmarks/comparison-v010).')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT, help='Destination research PDF (default: output/pdf/invarune-finding-comparison-v010.pdf).')
    parser.add_argument('--adjudication', type=Path, help='Optional separately recorded adjudication JSON; defaults to adjudication-live/model-adjudication.json when present. Never selects illustrative findings or modifies static observations.')
    parser.add_argument('--validate-only', action='store_true', help='Validate ledger hashes, counts, match accounting and frozen selection, then print a compact summary without creating a PDF.')
    args = parser.parse_args(argv)
    try:
        data = load_inputs(args.input_dir, args.adjudication)
        if args.validate_only:
            print(json.dumps({'status': 'validated', 'observations': data['ledger']['observation_count'],
                              'selected_observations': data['selection']['selected_observations'],
                              'invarune_versions': versions(data['ledger'], 'invarune'),
                              'illustrative_observations': len(illustrative_observations(data))}, sort_keys=True))
        else:
            print(build_pdf(data, args.output))
    except (ValueError, OSError, ImportError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
