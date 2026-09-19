# Justified and disabled checks

Invarune accepts an optional **trusted user policy** through `--review-config PATH`. It works without a model for source directories, local image references and exported image archives. No policy is automatically loaded from a codebase, image or parent directory.

```sh
invarune ./repository --review-config ./trusted-review.json --output ./report
invarune --image-archive ./agent.tar --review-config ./trusted-review.json --output ./image-report
```

An exception records your decision; it does not establish that a control passed. **Justified** and **disabled** items are excluded from the active denominator and do not count positively or negatively. Full catalog totals and exception counts remain available for audit. Invarune does not calculate a numerical security score.

## Configuration

```json
{
  "schema_version": "1.0",
  "rules": {
    "AI008": {
      "status": "justified",
      "reason": "Intentional remote listener. Owner-reviewed ingress, authentication and TLS evidence is recorded in SEC-104."
    },
    "AI020": {
      "status": "disabled",
      "reason": "Action pinning is assessed by the separate pipeline control."
    }
  },
  "controls": {
    "GOV-01": {
      "status": "disabled",
      "reason": "Inventory governance is outside this selected engineering review."
    }
  },
  "checks": {
    "AUTH-01:2": {
      "status": "justified",
      "reason": "The owner reviewed the external authentication evidence in SEC-108."
    }
  }
}
```

These are illustrative reasons, not verified facts about your system. Replace them with your own scope and review record. The [shipped example](../examples/review-config.json) deliberately labels its reasons as examples. The [sample report](../examples/reports/reviewed/report.md) applies it to the vulnerable fixture, retaining 9 open, 1 justified and 1 disabled finding.

| Field | Meaning |
|---|---|
| `schema_version` | Required exact string `1.0`. |
| `rules` | Optional map of deterministic rule IDs, such as `AI008`, to dispositions. Applies to **all** matching findings for that rule in the selected scan. |
| `controls` | Optional map of control IDs, such as `GOV-01`, to dispositions. Applies to every acceptance check in that control. |
| `checks` | Optional map of individual check IDs to dispositions. `AUTH-01:2` means the second check of `AUTH-01`; indexes start at one. |
| `status` | Required `justified` or `disabled`. Values such as `pass`, `safe`, or `ignore` are rejected. |
| `reason` | Required nonblank string for `justified`. Optional for `disabled`; omission records a default user-disabled reason. Maximum 8,000 characters. |

Use `invarune --list-rules` to discover rules, `--explain-rule AI008` to inspect mappings, and `--list-controls` to see each control's text, sources and `check_ids`. IDs refer to the installed catalog; review your policy when upgrading. The entire schema is available offline in `--help`.

The loader accepts UTF-8 JSON up to 1,000,000 bytes. Unknown fields, unknown IDs, duplicate keys, invalid Unicode/types and overlapping whole-control plus child-check entries fail with exit 2 before scanning or model calls. There are no wildcard IDs, automatic expiry rules, environment interpolation, code evaluation or model-generated exceptions. Policy files cannot be overwritten by report or baseline output paths.

## Scope and precedence

**Rule exceptions affect finding counts and the severity gate.** Every matched finding remains in the report with the same finding ID, evidence, severity and original status. Its effective status becomes `justified` or `disabled`, and its user reason appears in `disposition`. A rule exception takes precedence over an existing baseline suppression; the original baseline reason remains visible. Use `--baseline` when you need an exception for one specific finding ID instead of every match of a rule. Baseline exceptions retain their existing `suppressed` label.

**Control and checklist exceptions affect review scope.** They exclude those acceptance checks from active checklist counts and optional analyst requests. They do not waive static findings mapped to the control: rules and controls have many-to-many mappings, and a partial pattern check is not equivalent to a full control assessment. Configure an explicit rule exception if that is your intended finding policy. A rule exception alone does not exempt related controls from review.

For example, disabling `EXEC-01` can remove its checklist items from analyst review while an `AI003` shell-command finding stays open and still triggers exit 1. Justifying `AI003` excludes its matching findings from the gate, but active `EXEC-01` checks still require their own evidence.

Disabled rules mean **excluded from active assessment**, not erased or skipped parsing. Shared static analysis still collects evidence, and the audit retains disabled matches. File exclusions are a different feature: use `--exclude` to omit selected paths from scanning.

## Reports and optional model review

HTML, Markdown and JSON show user dispositions separately, including configured rules with no matches. The summary counts only open findings as actionable and lists justified/disabled counts separately. `review_policy.counts.active_checks` and `active_controls` are the active denominators; `catalog_checks` and `catalog_controls` preserve the full inventory. The same active totals appear in `--summary-json` coverage. Fully exempt controls have no active denominator weight; a partially exempt control still has one active-control weight and only its remaining active checks count.

JSON includes a canonical policy SHA-256, redacted entries and a derived `scan_id`. The hash includes the original reason, so two reasons that redact identically still produce different policy identities. Formatting and JSON key order do not change the canonical policy. Finding IDs remain stable.

SARIF retains rule-excepted findings using accepted external suppressions, user reasons and a distinct disposition property. Checklist exceptions remain in HTML/Markdown/JSON rather than being fabricated as SARIF findings.

With `--judge-config`, finding triage receives open findings only. The control analyst receives active checklist items only. It cannot create or overturn user dispositions. Exempt items retain user provenance, never appear as model-supplied passes, and do not count as omitted responses. A control with one active check sends only that check; the controller maps its response back to the original index and records the mapping. All original catalog checks remain in the local report. Source excerpts relevant to active checks may still overlap the topics of exempt checks.

All-exempt control review needs zero control requests, including with `--analyst-max-calls 0`. The separately enabled finding-triage stage still makes its request. Omit `--judge-config` to keep both model stages off.

## Exit status and trust

Exit 0 means the selected scan completed without an **open** finding meeting the chosen threshold. It is not a control pass. Justifying or disabling rules can remove a finding-based exit 1. It cannot waive parse/read errors, coverage gaps, resource limits, invalid input, output errors, or a requested model failure: those still return exit 2.

Keep the policy under trusted review in CI; anyone allowed to change it can change the effective findings gate. The scanner excludes an explicitly selected policy inside the target from source scanning and analyst evidence. Keep credentials and sensitive text out of reasons. Reports redact known patterns best-effort, not universally, and retain the audit for reviewers.

Programmatic integrations can use `load_review_config(path)` and `apply_review_config(report, policy)` from `ai_security_scan.review_policy`. Apply it to the completed static source/image report **before** optional model review or writing reports. The original report is preserved. Reapplying the same policy is idempotent; apply a different policy to the original static report.
