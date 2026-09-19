# Limited live Codex review with concrete fix advice

An **actual Invarune 0.10.0 invocation** used installed Codex CLI 0.154.0 with the default `gpt-6-astra` model, through its existing CLI-managed authentication. It reviewed **two of eleven deterministic findings** in the inert vulnerable fixture; nine were outside the requested cap. This is a findings-only transport/advice validation, not a complete security review or a benchmark of model accuracy.

```sh
python3 scan.py examples/vulnerable --judge-cli codex --judge-login never --judge-mode findings --judge-max-findings 2 --judge-timeout 180 --judge-include-source --output examples/reports/cli-codex-v010 --summary-json
```

Both selected findings received `likely_true_positive` model opinions and structured actions. Three additional concerns received action/verification plans. Those are **unverified model proposals**, not independently confirmed vulnerabilities, and some concerns overlap deterministic findings outside the selected cap. The two selected opinions are not a production precision estimate.

Actual exit: **1**, from the unchanged deterministic findings gate. All 11 deterministic findings have static sourced fix plans. Findings, controls, file evidence, remediation, scan ID and SARIF bytes match a no-judge run under Python 3.12.14. The model was not allowed to execute tools, change source, apply fixes or lower severity. Its exact request/response digests, installed CLI version, model choice and process restrictions are recorded in the report.

- [Readable findings and fix plans](report.md)
- [Standalone HTML](report.html)
- [Structured report and actual request audit](report.json)
- [Unchanged deterministic SARIF](report.sarif)

Claude was separately requested and failed authentication; this successful Codex check is not a substitute claim of Claude validation. [Actual Claude-enabled result](../cli-claude-v010/README.md).
