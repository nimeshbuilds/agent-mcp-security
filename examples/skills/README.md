# Inert skill and tool scan fixture

The `risky` directory contains intentionally unsafe instruction text and a contradictory tool description. These are scan inputs, never instructions to execute. The reserved `.invalid` destination is a placeholder. No tool implementation, credential or executable skill command is provided.

```sh
invscan examples/skills/risky --scans AI043,AI044,AI045,AI046
invscan examples/skills/risky --scans AI043,AI044,AI045,AI046 --report ./skill-report
```

Expected: four selected findings and exit 1. The report names the exact patterns and fixes; this fixture does not establish real maliciousness or runtime exploitation. See the [complete scan matrix](../../docs/SCAN_COVERAGE.md).
