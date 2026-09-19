# Claude-enabled scan: authentication incomplete

This is an **actual Invarune 0.10.0 invocation**, on the inert vulnerable fixture, requesting full Claude review. The installed official Claude Code CLI reported missing/expired authentication. A preceding official browser login initiated through Invarune timed out after 900 seconds without completed authorization. **No Claude security assessment succeeded.** These files must not be presented as a Claude-reviewed security report.

```sh
python3 scan.py examples/vulnerable --judge-cli claude --judge-login never --judge-timeout 120 --analyst-time-budget 600 --judge-include-source --pdf --output examples/reports/cli-claude-v010 --summary-json
```

Actual exit: **2**. All **11 deterministic findings** have sourced fix plans and conditional agent/MCP context. No scan coverage gaps were recorded; the requested optional layer failed. **Zero model answers and all 132 checks unreviewed** remain explicit. The request scope fields describe prepared evidence, not a claim of successful model delivery. Static findings, controls, file evidence, remediation, scan ID and SARIF bytes match a no-judge run under the same Python 3.12.14 installation.

- [Executive and detailed Markdown report](report.md)
- [Standalone HTML with editable review fields](report.html)
- [Structured report and failure audit](report.json)
- [Deterministic SARIF](report.sarif)
- [Fillable PDF with charts and clickable contents](report.pdf)

To complete the requested live review, run `python3 scan.py --login claude`, complete the official browser/device authorization, and rerun the command into a new output directory. Interactive scans can initiate this flow automatically. No API key is copied into Invarune; account access and usage limits remain managed by the official CLI.
