<div class="inv-hero" markdown>

<p class="inv-eyebrow">INVARUNE BY NIMESHBUILD · v0.13</p>

# Evidence for agent security.

Inspect an AI agent or MCP server from its source code or built Linux image. Understand each finding, trace it to a control, and carry the evidence into review.

**Deterministic scanning and `invscan --ask` work without agentic AI, model credentials or a subscription.** Enable the controlled AI analyst when you want additional advisory review.

[Start with invscan](docs/QUICKSTART.md){ .md-button .md-button--primary }
[Explore the benchmark dashboard](docs/BENCHMARK_DASHBOARD.md){ .md-button }

</div>

<div class="inv-stats">
<div class="inv-stat"><strong>66</strong><span>project-defined controls</span></div>
<div class="inv-stat"><strong>132</strong><span>acceptance checks</span></div>
<div class="inv-stat"><strong>42</strong><span>deterministic detection rules</span></div>
<div class="inv-stat"><strong>75</strong><span>source references</span></div>
</div>

## One CLI, three starting points

```sh
# Ask what the bundled security catalog covers, entirely offline.
invscan --ask 'How is MCP authentication covered?'

# Inspect a source checkout without running its code.
invscan ./my-agent --output ./scan-report/source

# Inspect a Docker-save or OCI archive without starting a container.
invscan --image-archive ./agent-image.tar --output ./scan-report/image

# Get every option and worked CLI examples.
invscan --help
invscan --help-topic all
```

[Install the CLI first](docs/QUICKSTART.md), or [download the v0.13 wheel](https://github.com/nimeshbuilds/invarune/releases/tag/v0.13.0). Core scanning uses Python 3.9+ and no runtime packages. PDF creation and AI integrations are optional extras.

## Improvements you can inspect

On the same 113 development fixtures, precision improved **96.49% → 98.31%** and recall **91.67% → 96.67%**. Four mismatches were corrected; three remain visible. The fresh public-project comparison preserves all inputs and coverage gaps. These percentages are fixture results, not production accuracy.

[See the charts, source reports and exact comparison](docs/BENCHMARK_DASHBOARD.md){ .md-button .md-button--primary }
[Download the updated benchmark PDF](output/pdf/invarune-benchmark-v013.pdf){ .md-button }

## Follow the path you need

<div class="grid cards" markdown>

- **Run your first assessment**

    Install, scan source or an image, interpret exit codes, and read immediate concerns and fixes.

    [Quick start](docs/QUICKSTART.md) · [CLI reference](docs/CLI.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)

- **Understand the controls**

    Explore what a check means, why it matters, which organizations discuss it, and what static evidence cannot prove.

    [Offline explorer](docs/SECURITY_EXPLORER.md) · [Checklist](docs/SECURITY_CHECKLIST.md) · [Source map](docs/SOURCE_MAP.md)

- **Review and justify**

    Edit supported reports, import a justification into a fresh scan, or configure reviewed exclusions. Justified items stay distinct from passes.

    [Review workflow](docs/REVIEW_WORKFLOW.md) · [Optional AI](docs/JUDGE.md) · [Analyst constraints](docs/ANALYST.md)

- **Inspect the benchmark evidence**

    Download branded PDFs, follow finding-level comparison ledgers, and reproduce pinned public-project measurements.

    [Visual dashboard](docs/BENCHMARK_DASHBOARD.md) · [Report library](docs/REPORT_LIBRARY.md) · [Benchmark guide](docs/BENCHMARK_GUIDE.md) · [Accuracy limits](docs/RULE_ACCURACY.md)

- **Build on Invarune**

    Learn the architecture, add controls and detectors, preserve report contracts, and reproduce tests and releases.

    [Developer architecture](docs/developer/architecture.md) · [Contributing](CONTRIBUTING.md)

- **Read the evidence behind this release**

    v0.13 passed 845 local tests, a 53-step installed-CLI quickstart and all eight CI jobs. Its release assets were downloaded back and hash-verified.

    [v0.13 validation](benchmarks/validation-v013/README.md) · [Quickstart receipt](benchmarks/quickstart-v013/README.md)

</div>

## Know what a result can establish

The 42 rules provide **partial static coverage of 26 of the 66 controls**. The other controls need operational, runtime or human evidence. A clean scan does not prove that an agent is secure, and catalog lookup does not assess your application.

The optional model review is nondeterministic and advisory. Its deterministic wrapper limits evidence, validates citations and responses, enforces budgets, and records incomplete work. A model answer cannot silently convert missing evidence into a verified pass. [Coverage and review design](docs/ANALYST.md).

The research draws on NSA/CISA and partners, CSA, MITRE ATLAS, NIST, OWASP, MCP, CIS, ISO and other primary publications. The controls are an original engineering synthesis with qualified mappings; they are not an official certification or publisher endorsement. [Sources and applicability](docs/RESEARCH.md).

The repository is public. Its original contents do not yet have an open-source license; see the [publication notice](NOTICE.md).
