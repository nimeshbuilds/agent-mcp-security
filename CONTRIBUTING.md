# Contributing to Invarune

Invarune is the `invscan` CLI for bounded AI agent and MCP security triage. Start with the [developer guides](docs/developer/index.md) to find the code path and tests for your change. For normal scanning and installation, use the [quickstart](docs/QUICKSTART.md).

## Set up a development checkout

Use Python 3.9 or newer. Python 3.12 is a convenient choice when exercising the optional PDF and Headroom integrations. Run these commands from the repository root, using a new virtual environment or this project's existing environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
invscan --version
python -m unittest tests.test_rules tests.test_scanner tests.test_catalog -v
```

Windows PowerShell, without changing script execution policy:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
$env:Path = "$((Resolve-Path .venv\Scripts).Path);$env:Path"
invscan --version
python -m unittest tests.test_rules tests.test_scanner tests.test_catalog -v
```

Do not recreate an environment containing work you want to retain. Installation may download build tools. The base scanner has no third-party runtime dependencies. Optional integrations and their validation environments are described in [testing and release](docs/developer/testing-and-releasing.md).

## Make a reviewable change

1. Describe the concrete input and expected behavior. For a detector, distinguish the source pattern from a confirmed vulnerability.
2. Find the implementation boundary using the [architecture map](docs/developer/architecture.md).
3. Add a regression that demonstrates the problem and a meaningful counterexample. For a detector change, follow [adding checks and catalog content](docs/developer/adding-checks.md).
4. Preserve resource limits, source confinement, redaction and explicit incomplete outcomes. Do not turn failed analysis or unavailable evidence into a passing result.
5. Run the relevant tests, then the full suite and accuracy regression gate when changing scanner behavior.
6. Describe the final behavior, validation and remaining limitations in the pull request. Include fixture or artifact hashes when your claim depends on exact bytes.

Keep unrelated refactors, generated artifacts and historical benchmark changes out of a focused fix. Never execute an untrusted target repository to reproduce a source-pattern finding. Use inert source strings, controlled archives and local fixture servers instead.

## Contracts that must remain explicit

- A deterministic finding is a review signal. Absence of a finding is not a security or compliance pass.
- Model review is optional and advisory. It cannot change static severity, accepted exceptions or the finding gate.
- User dispositions remain `justified`, `disabled` or `suppressed`; they never become validated passes.
- Catalog search is an offline lookup, not an agent, scan or model conversation.
- Framework links are source context or thematic mappings unless a more specific relationship is actually substantiated.
- Historical results retain their original scanner, corpus, source and tool identities. Correct labels transparently; do not rewrite an old result as a new measurement.

The [current release evidence](benchmarks/validation-v012/README.md) records the tested 0.12.0 state. It is evidence for that revision, not an automatic guarantee for a proposed change.

## Choose a guide

- [Architecture and trust boundaries](docs/developer/architecture.md)
- [Add a detector, control, source or explanation](docs/developer/adding-checks.md)
- [Reports, exceptions and review imports](docs/developer/reports-and-reviews.md)
- [Optional AI adapters and evidence handling](docs/developer/ai-adapters.md)
- [Testing, packaging and release evidence](docs/developer/testing-and-releasing.md)

Use synthetic credentials in tests and redact issue/PR examples. For a security-sensitive report, follow the repository's published security guidance where available and avoid posting usable credentials or private target code in a public discussion.
