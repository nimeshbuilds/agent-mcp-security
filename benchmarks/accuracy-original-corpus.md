# Invarune static rule accuracy

Synthetic, project-authored rule-presence fixtures. These are not production accuracy estimates or proof of security. Challenge cases are included in overall metrics even when the regression gate passes.

Scanner: **0\.10\.0** · Corpus version: **1\.0\.0** · SHA-256: `00149f8a8c56fbf96b9c8b2c1ac2fd402982f6987f079b34b9c56b9932cba019`

Project\-authored synthetic cases; not an independent industry benchmark or production prevalence sample\. Expected labels were authored from API behavior, not inferred from scanner output\.

One explicitly labeled rule\-presence assertion per case, not confirmed vulnerabilities\. Other rule findings are recorded but are not scored without labels\.

| Suite | TP | TN | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 51 | 49 | 3 | 6 | 94.44% | 89.47% |
| regression | 51 | 48 | 1 | 1 | 98.08% | 98.08% |
| challenge | 0 | 1 | 2 | 5 | 0.00% | 0.00% |

## Mismatches and analysis errors

| Case | Suite | Expected → detected | Rationale |
|---|---|---|---|
| ai011\-risk | regression | AI011: True → False | Private versus public key marker; no actual key material\. |
| ai041\-comparison | regression | AI041: False → True | Explicit inspector authorization bypass\. |
| gap\-reflection\-python | challenge | AI003: True → False | Dynamic attribute reconstruction is beyond the bounded callable resolver\. |
| gap\-interprocedural\-url | challenge | AI014: True → False | Cross\-function argument flow needs interprocedural analysis\. |
| gap\-js\-wrapper\-taint | challenge | AI014: True → False | JS wrapper argument flow is not whole\-program taint analysis\. |
| gap\-yaml\-alias | challenge | AI027: True → False | Resolving YAML anchors requires a full YAML semantic model\. |
| gap\-yaml\-block\-string | challenge | AI026: False → True | Block scalar documentation is text, not an authentication field\. |
| gap\-shell\-wrapper | challenge | AI019: True → False | Nested shell expansion is beyond the direct download\-pipe pattern\. |
| gap\-validated\-user\-url | challenge | AI014: False → True | Constraint solving could prove this branch restricts the request to a fixed destination\. |

Unlabeled detections are recorded in the JSON report but are not scored. A matched negative means this rule should not fire on this fixture; it is not a declaration that the application is safe.
