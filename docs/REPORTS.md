# Reading an Invarune security report

Start with `report.html` for a navigable, branded review or `report.md` for a text-first review. Both start with an executive assessment and retain the finding evidence, full control checklist, and coverage details. `report.json` preserves the structured evidence and assessment; `report.sarif` retains static findings for CI consumers.

The HTML file is self-contained: it needs no server, account, model, JavaScript, CDN, font download, or internet connection. Its expandable sections and internal links use native browser behavior. External source links are opened only when you choose them. Print styles expand finding and control details for browser printing. Reports can contain sensitive paths and redacted source fragments; redaction is best-effort.

## The opening assessment

The first section answers these questions:

| Question | Report evidence |
|---|---|
| What did the scanner find? | Open finding count, critical/high count, affected files, and groups of matching rules |
| What needs attention first? | Severity-ordered actions tied to exact findings and proposed owner roles |
| Was the requested work completed? | Static coverage gaps and separate CLI/optional-review status |
| Were findings accepted as exceptions? | Suppressed count, preserved evidence, and the supplied baseline reasons |
| How could risk be reduced? | Underlying fixes plus additional defense layers, with verification steps and remaining limitations |
| What is still unknown? | Runtime exposure, control effectiveness, model behavior, unsupported inputs, and image-specific limitations |

An incomplete static scan is called out before any no-finding language. A complete selected-scope scan is not a whole-system security assessment. A metadata-only image can be completely inspected within its declared scope while application behavior remains unassessed.

The report does not assign a numerical risk score. Detector severity and confidence are not enough to estimate business impact or exploitability. The priority labels make the review order explicit:

| Priority | Detector severity | Interpretation |
|---|---|---|
| P0 | Critical | Review promptly and verify whether sensitive material or operations are exposed |
| P1 | High | Investigate the execution, credential, identity, or other flagged boundary |
| P2 | Medium | Validate applicability and address the identified pattern |
| P3 | Low or informational | Review deployment context and hardening needs |
| Accepted | Suppressed by an explicit baseline | Recheck the exception and its supporting evidence; it is not proven fixed |

These are review priorities, not contractual remediation deadlines or incident declarations. Within a severity, ordering is stable by rule and image context. Repeated occurrences are grouped by rule, open/suppressed status, and image provenance. Historical layer evidence is kept separate from current packaged files and image defaults.

## Immediate action and additional defenses

Each finding group distinguishes four things:

1. **Observed evidence:** the exact pattern, path, line, finding ID, and image context where applicable.
2. **Possible impact:** a conditional explanation of what could happen if the necessary exposure or attacker influence exists.
3. **Address the cause:** the proposed underlying fix and suggested responsible role.
4. **Additional defenses:** ways to constrain exposure or impact, with a concrete validation step and a residual limitation for every layer.

For example, a dynamic shell execution finding can lead to an action to remove shell interpretation and validate arguments. Additional layers can enforce tool authorization outside the model and isolate the execution environment. Those layers do not make the shell call safe by themselves. They need deployment evidence and negative tests showing that bypasses, extra arguments, privileged resources, and unintended network access are actually denied.

For credential-like literals, the first task is to establish whether the value is real without disclosing it. If a real credential was exposed, removal alone does not revoke it. Rotation, investigation of retained copies, restricted credential scope, and controlled injection address different parts of the exposure. A secret removed from the final container filesystem may still be present in a distributed layer.

The bundled [mitigation catalog](../ai_security_scan/data/mitigations.json) covers every static rule. [Guidance sources and limitations](MITIGATION_SOURCES.md) record the basis for the recommendations. These are project-authored engineering recommendations informed by the cited publications, not verbatim external control requirements or an official crosswalk.

## Evidence needed before claiming lower residual risk

Every suggested layer starts as `proposed_not_verified`. Invarune does not infer that it is deployed because similar code or a setting appears elsewhere. To accept a reduced risk, the reviewer should record:

- The effective deployment policy and where it is enforced, including alternate routes that might bypass it.
- A test that demonstrates the intended denial or containment using the actual identity and environment.
- The sensitive data and operations that remain reachable after the control is applied.
- An accountable owner, evidence link, verification date, expiry/review date, and remaining limitations.

Suggested layers never lower recorded severity, suppress findings, close controls, or change the CI finding gate. An explicit baseline is still required for an accepted finding, and its reason should reference the review record. Runtime tests and approvals described in the report are proposed work; the scanner has not performed them.

## Optional analyst and deterministic reporting

The entire overview and mitigation catalog work with the model disabled. The `assessment` field is derived from static findings, scope, and bundled guidance. It does not depend on the selected failure threshold, model verdict, or optional review completion. The report records the guidance catalog version and SHA-256 plus the source registry SHA-256 separately from the evidence scan ID.

If enabled, the model's finding triage and control review appear in explicitly advisory sections. The executive area shows optional-review completion separately. An answered check does not mean it passed, and a completed review can still require runtime or human evidence. A failed or partial review leaves the static findings intact and retains the existing exit-code-2 behavior.

`--summary-json` includes a compact assessment containing posture, metrics, and guidance provenance. The full finding groups, proposed layers, and their sources are in `report.json`. SARIF remains a static-findings format; it does not turn the proposed defenses into a risk reduction or compliance score.

## Output and compatibility

Version 0.6.0 adds `report.html` and the additive `assessment` JSON object. All four files are emitted by default; no new opt-in flag is needed. Existing commands, finding IDs, baseline semantics, and severity gates remain compatible. Deterministic output requires the same input, scanner/runtime, guidance catalog, settings, and filesystem availability. Optional model output remains outside that reproducibility guarantee.
