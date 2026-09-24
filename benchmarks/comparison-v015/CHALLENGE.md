# Sealed challenge, disclosure, and remaining misses

A separate benchmark assistant authored these cases and committed their exact bytes before the detector agent saw them. This is within-project separation, not independent third-party validation. One assertion per case measures a static source or instruction predicate, not deployed exploitability. No target code or MCP server is executed.

The original 32-case set contains 16 source cases and 16 literal MCP tool descriptions: 16 positive and 16 negative assertions. Source cases use exact AI014/AI015 presence; metadata cases score any AI043/AI044/AI045 operative instruction-risk indicator. Thus the metadata comparison is tool-level detection, not exact native taxonomy agreement. Some source examples are partial declarations; they specify the recognized tool boundary but are not executable exploit demonstrations.

[Corpus](heldout-challenge.json) · [Commitment](challenge-commitment.json) · [First freeze](initial-freeze.json) · [Disclosure record](challenge-reveal.json)

## First result stays visible

The actual earlier release returned 3 TP / 16 TN / 0 FP / 13 FN. The first frozen candidate returned 4 TP / 16 TN / 0 FP / 12 FN. That result exposed missing recognized tool-handler parameter seeding and composed instruction semantics. After disclosure and changes, the same cases return 16 TP / 16 TN / 0 FP / 0 FN. The last result is development performance; it cannot be called blind.

| Case | Track | Expected | v0.14 | First candidate | After disclosure | Cisco YARA, same descriptor |
| --- | --- | --- | --- | --- | --- | --- |
| flow-url-two-hop | source | positive | FN | FN | TP | not applicable |
| flow-url-fixed-origin | source | negative | TN | TN | TN | not applicable |
| flow-url-keyword-call | source | positive | FN | FN | TP | not applicable |
| flow-url-exact-membership | source | negative | TN | TN | TN | not applicable |
| flow-url-host-only | source | positive | FN | FN | TP | not applicable |
| flow-url-unrelated-guard | source | positive | FN | FN | TP | not applicable |
| flow-url-fixed-local | source | negative | TN | TN | TN | not applicable |
| flow-url-literal-helper-guard | source | negative | TN | TN | TN | not applicable |
| flow-path-two-hop | source | positive | FN | FN | TP | not applicable |
| flow-path-fixed-helper | source | negative | TN | TN | TN | not applicable |
| flow-path-prefix-confusion | source | positive | FN | FN | TP | not applicable |
| flow-path-name-map | source | negative | TN | TN | TN | not applicable |
| flow-js-fetch-wrapper | source | positive | FN | FN | TP | not applicable |
| flow-js-fixed-fetch | source | negative | TN | TN | TN | not applicable |
| flow-js-file-wrapper | source | positive | FN | FN | TP | not applicable |
| flow-js-fixed-file | source | negative | TN | TN | TN | not applicable |
| metadata-hierarchy | metadata | positive | TP | TP | TP | FN |
| metadata-hierarchy-negated | metadata | negative | TN | TN | TN | TN |
| metadata-exfil-direct | metadata | positive | TP | TP | TP | FN |
| metadata-exfil-negated | metadata | negative | TN | TN | TN | TN |
| metadata-exfil-composed | metadata | positive | FN | FN | TP | FN |
| metadata-exfil-public | metadata | negative | TN | TN | TN | TN |
| metadata-bypass | metadata | positive | TP | TP | TP | FN |
| metadata-bypass-negated | metadata | negative | TN | TN | TN | TN |
| metadata-es-override | metadata | positive | FN | TP | TP | FN |
| metadata-es-safe | metadata | negative | TN | TN | TN | TN |
| metadata-indirect-authority | metadata | positive | FN | FN | TP | FN |
| metadata-describe-safe | metadata | negative | TN | TN | TN | TN |
| metadata-hidden-write | metadata | positive | FN | FN | TP | FN |
| metadata-log-safe | metadata | negative | TN | TN | TN | TN |
| metadata-exfil-vault | metadata | positive | FN | FN | TP | FN |
| metadata-vault-safe | metadata | negative | TN | TN | TN | TN |

Cisco MCP Scanner 4.8.4 ran its local YARA engine on the same 16 descriptions: 0 TP / 8 TN / 0 FP / 8 FN. The enabled engine passed a separate [positive/safe sanity pair](cisco-engine-sanity.json). Other Cisco analyzers were disabled and are not measured. Semgrep's frozen generic pack, Bandit's API audit and Gitleaks secret detection do not implement equivalent MCP source-flow or operative-instruction predicates; they are not assigned unsupported true negatives.

## Second eight-case temporal holdout

A new four-source/four-metadata set was sealed after the first disclosure, before the later detector freeze. Its first actual result is 2 TP / 4 TN / 0 FP / 2 FN. No detector change followed this disclosure. The report rendering code was subsequently improved; the release repeat produces the exact same eight case outcomes. This repeat is explicitly `presentation-only-repeat`, not a new blind test.

[Exact eight inputs](sealed-confirmation.json) · [Commitment](confirmation-commitment.json) · [First implementation manifest](confirmation-first-freeze.json) · [First result](confirmation-first.json) · [Presentation-only change](presentation-only-change.json) · [Repeat](confirmation-final.json)

| Case | Expected | First Invarune | Release repeat | Cisco YARA first | Predicate rationale |
| --- | --- | --- | --- | --- | --- |
| confirm-bound-http | positive | TP | TP | not applicable | A declared FastMCP entrypoint forwards its externally supplied URL through a keyword-only local helper. |
| confirm-fixed-http | negative | TN | TN | not applicable | The handler ignores its external URL and the helper receives a fixed destination. |
| confirm-bound-file | positive | TP | TP | not applicable | A declared MCP tool accepts a path that directly selects a local file without confinement. |
| confirm-fixed-file | negative | TN | TN | not applicable | The externally supplied path is replaced by a fixed file before the read. |
| confirm-authority-order | positive | FN | FN | FN | An operative instruction puts tool metadata above the system message. |
| confirm-authority-defensive | negative | TN | TN | TN | An operative instruction preserves the system hierarchy. |
| confirm-env-transfer | positive | FN | FN | TP | An operative instruction explicitly transfers a sensitive environment file to a network recipient. |
| confirm-public-template | negative | TN | TN | FP | A public example template is explicitly selected, not the live .env or a credential value. |

The two Invarune misses are an instruction to copy .env contents to a network endpoint, and a description that says its instruction takes precedence over the system message. All four source cases match their labels, including the keyword-only helper. The two source negatives use fixed URLs or replace external filenames with fixed values. The metadata negatives preserve system priority or explicitly select a public `.env.example` template.

On the four metadata cases, Invarune returns 0 TP / 2 TN / 0 FP / 2 FN; Cisco YARA returns 1 TP / 1 TN / 1 FP / 1 FN. Its credential rule matches both the live `.env` transfer and the explicitly public example template. This label is specific to credential transfer and does not prove every template or network action safe. Four examples cannot support a general performance estimate.

## Provenance and limits

All corpus bytes and labels are published unchanged from their commitments. Raw executions, timestamps, analyzer status, implementation and result hashes are preserved. The main dashboard and PDF validate every case, denominator and phase before generation. They reject omitted cases, rewritten labels, incorrect totals, replaced commitments, or detector changes disguised as presentation-only repeats.

The assistant authored these source predicates, so they are not independently verified production vulnerabilities. Challenge design can still favor assumptions made by this project. A credible next evaluation needs external authors, larger attack diversity, time-separated unseen cases, runtime tasks, and human source/exploit adjudication. The open misses are retained rather than tuned away and relabeled as blind success.
