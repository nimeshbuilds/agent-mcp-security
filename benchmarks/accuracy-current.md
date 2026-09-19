# Invarune static rule accuracy

Synthetic, project-authored rule-presence fixtures. These are not production accuracy estimates or proof of security. Challenge cases are included in overall metrics even when the regression gate passes.

Scanner: **0\.10\.0** · Corpus version: **1\.2\.0** · SHA-256: `eb7f1eba93f8e9842634cbd12687dde5bea879505d99d367621214583e54dde3`

Project\-authored synthetic cases; not an independent industry benchmark or production prevalence sample\. Expected labels were authored from API behavior, not inferred from scanner output\.

One explicitly labeled rule\-presence assertion per case, not confirmed vulnerabilities\. Other rule findings are recorded but are not scored without labels\.

| Suite | TP | TN | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 55 | 51 | 2 | 5 | 96.49% | 91.67% |
| regression | 55 | 50 | 0 | 0 | 100.00% | 100.00% |
| challenge | 0 | 1 | 2 | 5 | 0.00% | 0.00% |

## Mismatches and analysis errors

| Case | Suite | Expected → detected | Rationale |
|---|---|---|---|
| gap\-reflection\-python | challenge | AI003: True → False | Dynamic attribute reconstruction is beyond the bounded callable resolver\. |
| gap\-interprocedural\-url | challenge | AI014: True → False | Cross\-function argument flow needs interprocedural analysis\. |
| gap\-js\-wrapper\-taint | challenge | AI014: True → False | JS wrapper argument flow is not whole\-program taint analysis\. |
| gap\-yaml\-alias | challenge | AI027: True → False | Resolving YAML anchors requires a full YAML semantic model\. |
| gap\-yaml\-block\-string | challenge | AI026: False → True | Block scalar documentation is text, not an authentication field\. |
| gap\-shell\-wrapper | challenge | AI019: True → False | Nested shell expansion is beyond the direct download\-pipe pattern\. |
| gap\-validated\-user\-url | challenge | AI014: False → True | Constraint solving could prove this branch restricts the request to a fixed destination\. |

Unlabeled detections are recorded in the JSON report but are not scored. A matched negative means this rule should not fire on this fixture; it is not a declaration that the application is safe.
