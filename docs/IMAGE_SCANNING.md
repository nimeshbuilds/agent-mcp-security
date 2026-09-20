# Scan built container images

Version 0.4.0 accepts a built **Linux container image** without a source checkout. It inspects a locally exported image filesystem and metadata; it never starts the container. Source-directory scanning and optional advisory LLM review remain available.

## Inputs and commands

```sh
# Existing local image; Docker must be installed and its daemon available.
invscan --image my-agent:latest --output ./image-report

# Podman uses its own local image store.
invscan --image my-mcp-server:latest --image-runtime podman

# Explicitly fetch an image from a registry before inspection.
invscan --image ghcr.io/example/agent:1.2.3 --pull

# Runtime-free, offline archive inspection.
docker image save --output agent-image.tar my-agent:latest
invscan --image-archive ./agent-image.tar --output ./image-report

# OCI archive with more than one platform.
invscan --image-archive ./agent.oci.tar --image-platform linux/arm64

# Optional model review adds the full control analyst to the image scan.
invscan --image-archive ./agent-image.tar --judge-config ./trusted-judge.json

# CI output and severity policy work for images too.
invscan --image my-agent:latest --summary-json --fail-on medium
```

Choose one source directory, `--image`, or `--image-archive`. The archive route needs only Python's standard library. Reference mode uses the trusted Docker or Podman executable and its configured daemon/connection; it performs **image save**, plus **image pull only when `--pull` is supplied**. A missing local image does not trigger an implicit pull. Registry authentication stays with the runtime's existing credential configuration; diagnostics are not echoed into reports. Runtime connections may themselves point to a remote daemon.

Docker platform-specific export requires a runtime version supporting `image save --platform`. Podman selection is applied during an explicit pull and verified against the exported archive. An ambiguous archive requires `--image-platform`; unsupported OS/filesystem semantics fail explicitly. The host running this Python tool may be Linux, macOS, or Windows; the supported target filesystem is a Linux container image.

Supported archives are Docker-save and OCI-layout **tar files**, optionally gzip-compressed, with plain-tar or gzip image layers. OCI descriptor sizes/SHA-256 digests and available uncompressed layer DiffIDs are verified. This verifies consistency with the supplied archive, not publisher identity or trust. Exported raw root filesystems (`docker export`), OCI layout directories, zstd/xz/bzip2 layers, sparse tar files, and Windows container filesystems are not supported in this version. Re-export unsupported images to an appropriate Docker-save/plain/gzip OCI archive; the tool will not silently report them as clean.

## What is assessed

| Evidence | Result |
|---|---|
| Final packaged Python/JS/TS and supported configuration | Existing deterministic rules, file/line evidence, image paths and layer/content provenance |
| Image runtime user | Root/default-root signal, including named UID resolution when `/etc/passwd` is available; deployment overrides remain unknown |
| Environment, labels, configured commands | Selected credential, explicit safeguard-bypass and transport/authentication signals |
| Build history | Credential and risky instruction evidence clearly labeled as historical, not current runtime behavior |
| Deleted/overwritten file revisions | Retained credential exposure; historical source-code defects are not treated as live code defects |
| OS and installed-package metadata | OS release plus bounded dpkg, apk, Python dist-info and npm name/version inventory |
| Stored file permissions | Setuid/setgid/world-writable review signals, without applying these permissions on the host |
| Native/bytecode-only application | Metadata assessment; binary logic is explicitly unassessed |

Image mode includes packaged `dist`, `build`, `node_modules`, `vendor`, and virtual-environment directories that source mode normally excludes. Common VCS/cache directories remain excluded. `--exclude` patterns apply relative to the **container filesystem root**, for example `--exclude 'usr/share/doc/*'`; report paths add a `rootfs/` prefix. These exclusions apply to final packaged-file rules and retained file revisions, including their optional model source evidence. Exclusions narrow the requested scope and remain visible. Image configuration, recorded build-history instructions, OS/package inventory and stored permission review are separate artifact assessments and remain enabled.

Package names/versions are **inventory, not a CVE scan**. The tool does not consult an advisory database, validate registry signatures, decompile binaries, execute malware, connect to the MCP service, or prove runtime authorization/isolation. An image can omit the original agent source; optional LLM review cannot reconstruct unavailable implementation facts reliably.

## Reports and coverage

The usual `report.html`, `report.json`, `report.md`, and `report.sarif` are produced. The [executive report](REPORTS.md) distinguishes final filesystem, image configuration, build history, and retained-layer findings and offers source-linked mitigation layers. `image.identity` includes archive, config, manifest, layer and DiffID provenance where available. Docker-save's manifest digest is explicitly labeled as the digest of its canonical selected entry, not a claimed registry manifest digest.

`rootfs/app/...` locations refer to image paths. `.image-metadata/...` locations identify generated evidence from the configuration, build history, or historical layers. These files live only in the scanner's private temporary workspace and are removed when scanning/optional review completes. Reports retain hashes, source location information, redacted evidence and provenance. They may still contain sensitive repository metadata; redaction is best-effort.

Generated evidence retains its image context and original layer/path provenance even when no deterministic finding exists. Both optional analyst excerpts and `--judge-include-source` excerpts carry this context. Sensitive source filenames (such as `secrets.json`, `.env` and files under `.aws`) remain excluded from model source excerpts after historical-file renaming; redacted deterministic findings can still be submitted for triage.

The report and human CLI summary distinguish:

- `packaged_source_and_metadata`: at least one supported Python/JS/TS file was inspected.
- `metadata_and_text_only`: supported text/configuration was inspected, but no supported Python/JS/TS source was found in the selected scope.
- `metadata_only`: no supported packaged file was inspected; generated image metadata was assessed.

Counts describe files inspected, not proof of application coverage. `binary_logic_analyzed` and `vulnerability_feed_consulted` remain false. A metadata-only run can complete successfully within its selected scope while application security remains unestablished. All 66 controls stay in the report; no control becomes a security pass merely because the image scan found nothing.

Exit codes retain the existing policy: **0** means selected inspection completed below the severity gate; **1** means open findings meet it; **2** means invalid input, unsafe/unsupported archive semantics, resource exhaustion, incomplete source analysis, or failed/incomplete requested analyst review. Malformed archives can fail before a report exists; `--summary-json` still emits an operational-error object for acquisition/inspection failures. Argument syntax errors use argparse stderr.

## Limits and extraction safety

| Option | Default | Scope |
|---|---:|---|
| `--image-max-archive-bytes` | 2,000,000,000 | Export/compressed archive and bounded outer-archive data |
| `--image-max-unpacked-bytes` | 4,000,000,000 | Cumulative expanded layer data; separately bounds final materialized bytes |
| `--image-max-entries` | 500,000 | Archive/layer headers and implicit-directory expansion |
| `--image-max-layers` | 200 | Selected image layers |
| `--image-timeout` | 300 seconds | Shared optional runtime pull + export deadline |

Existing `--max-file-bytes`, `--max-total-bytes`, `--max-files`, and `--max-entries` bound final-filesystem scanning. Image metadata/retained-layer analysis has a separate read/evidence budget using the configured per-file and total-byte values, plus a 10,000-record ceiling. Each phase reports its own counters; the final filesystem scan's `bytes_read` does not mean the entire archive was read only once. A large image may need explicit budget increases. Runtime pulls populate the runtime's own image store, which is outside the archive-file limit.

Temporary disk use for the archive snapshot, layer revision content, and final filesystem can reach the larger of twice the archive budget and the archive budget plus twice the unpacked budget; the defaults can therefore require approximately 10 GB for that content, plus generated evidence, reports, and filesystem overhead. Acquisition has a deadline; archive/source analysis has deterministic resource bounds, not a hard wall-clock process deadline.

Layer changes are applied in order. Whiteouts remove lower-layer paths; opaque whiteouts remove lower-layer directory contents regardless of their tar order relative to same-layer additions. Regular files are copied into a private workspace with safe host permissions. Original modes/owners are recorded, not applied. No host symlinks, hardlinks, devices or FIFOs are created. Safe in-image file links are copied; directory aliases are recorded without following host links. Unresolvable/escaping links and unsupported writes through directory aliases create explicit gaps.

The reader rejects traversal, absolute paths, duplicate/colliding or nonportable filenames, malformed tar/PAX data, sparse entries, mismatched descriptors, unsupported compression and budget exhaustion. Rejecting some legal Linux filenames is a deliberate portability boundary: the host filesystem must not silently merge different image paths.

The format behavior is grounded in the [OCI layer specification](https://github.com/opencontainers/image-spec/blob/main/layer.md), [OCI layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md), [OCI configuration](https://github.com/opencontainers/image-spec/blob/main/config.md), [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/) and [Podman save](https://docs.podman.io/en/latest/markdown/podman-save.1.html).

## Reproduce validation

```sh
python3 -m unittest tests.test_image_archive tests.test_image_assessment tests.test_image_runtime tests.test_image_cli -v

# Linux + Docker: builds controlled FROM-scratch fixtures with COPY only,
# scans reference/archive/binary-only forms, and never starts a container.
python3 scripts/validate_image_scan.py
```

Archive fixtures exercise layer order, whiteouts, opaque directories, overwritten secrets, hardlink snapshots, integrity, compression, malformed archives, path attacks and resource limits. Runtime tests invoke controlled subprocesses to exercise pipe pressure, byte caps, timeout cleanup and diagnostic redaction. The Docker integration job additionally checks an actual Docker-produced image and archive; synthetic fixtures alone are not treated as runtime compatibility evidence.
