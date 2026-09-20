"""Explicit scan scope; selectors are data, never commands or target settings."""
from .rules import RULE_BY_ID


def resolve_scan_selection(values=None):
    from .scanner import load_controls
    controls = {item['id']: item for item in load_controls()}
    if values is None:
        return {'requested_scan_ids': [], 'selected_rule_ids': sorted(RULE_BY_ID),
                'selected_control_ids': sorted(controls)}
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError('Scan selection requires at least one rule or control ID')
    requested = set()
    for value in values:
        if not isinstance(value, str) or len(value) > 10000:
            raise ValueError('Scan selectors must be rule or control ID strings')
        for identifier in value.split(','):
            identifier = identifier.strip().upper()
            if identifier not in RULE_BY_ID and identifier not in controls:
                raise ValueError('Unknown or empty scan ID: ' + repr(identifier) + '; use invscan --list-scans')
            requested.add(identifier)
    explicit_rules = requested & set(RULE_BY_ID)
    rules = set(explicit_rules)
    selected_controls = requested & set(controls)
    for identifier in selected_controls:
        rules.update(set(controls[identifier].get('automated_rule_ids', [])) & set(RULE_BY_ID))
    # A control selected through a rule does not implicitly activate its other
    # mapped rules. Direct control selectors activate their mapped rule set.
    for identifier, control in controls.items():
        if set(control.get('automated_rule_ids', [])) & explicit_rules:
            selected_controls.add(identifier)
    return {'requested_scan_ids': sorted(requested), 'selected_rule_ids': sorted(rules),
            'selected_control_ids': sorted(selected_controls)}
