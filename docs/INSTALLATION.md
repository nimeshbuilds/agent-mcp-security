# Install Invarune

**Download the built `invscan` CLI, or build it from source.** Both routes provide the same scanner, offline help and security catalog. AI review stays off until you enable it.

[Download a release](https://github.com/nimeshbuilds/invarune/releases/latest){ .md-button .md-button--primary }
[Build from source](#build-from-source){ .md-button }

| Route | What you need | What is included |
|---|---|---|
| **Standalone release** | A supported operating system and CPU; no separate Python installation | `invscan`, its private runtime, security catalogs, PDF export/import, Headroom and inert examples |
| **Python wheel** | Python 3.9+ and an isolated environment | Installed CLI and catalogs; optional `[ai,pdf]` packages |
| **Source checkout** | Git and Python 3.9+ | CLI, catalogs, all examples, tests, scripts and developer documentation |

Docker or Podman is needed only when scanning a local image reference. Exported image archives work without either runtime. Optional provider CLIs are installed separately; the bundle does not contain Codex, Claude Code or Grok Build, an account or API credentials.

## Download a standalone release

Choose your computer's operating system and CPU, not the architecture of the code or container you plan to scan. These links select **Invarune 0.15.0**; the [release page](https://github.com/nimeshbuilds/invarune/releases/latest) lists the current assets and their validation evidence.

| Computer | Download |
|---|---|
| Linux, Intel/AMD 64-bit (`x86_64`) | [invscan-0.15.0-linux-x86_64.tar.gz](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/invscan-0.15.0-linux-x86_64.tar.gz) |
| Linux, ARM 64-bit (`aarch64`) | [invscan-0.15.0-linux-arm64.tar.gz](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/invscan-0.15.0-linux-arm64.tar.gz) |
| macOS, Apple silicon (`arm64`) | [invscan-0.15.0-macos-arm64.tar.gz](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/invscan-0.15.0-macos-arm64.tar.gz) |
| macOS, Intel (`x86_64`) | [invscan-0.15.0-macos-x86_64.tar.gz](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/invscan-0.15.0-macos-x86_64.tar.gz) |
| Windows, Intel/AMD 64-bit (`x64`) | [invscan-0.15.0-windows-x86_64.zip](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/invscan-0.15.0-windows-x86_64.zip) |

The native build/test hosts are **Ubuntu 22.04** (both Linux architectures), **macOS 15** (both Mac architectures), and **Windows Server 2022** (x86-64). These are tested targets, not a promise of compatibility with every older OS. Each published manifest records the exact host and runtime versions.

[Read the native release validation](../benchmarks/standalone-v015/README.md): 57 scenario steps and 59 native CLI invocations passed on each of the five targets, with no Python on the scanner's PATH. Receipts distinguish scripted API tests from live model review and record public-download verification separately.

Linux bundles use glibc; Alpine/musl and Windows ARM64 do not have native bundles in this release. Each bundle's `build-manifest.json` records its build platform and dependency versions. Use the [wheel](#install-the-python-wheel) or [source route](#build-from-source) when your platform is outside the release's tested targets.

Keep the extracted directory intact: `invscan` (or `invscan.exe`) needs its neighboring `_internal` directory. Move the whole directory when installing elsewhere. Each archive also includes `README.txt`, dependency notices and example inputs.

### macOS and Linux

Run in a new directory where you want to keep Invarune. This selects the archive for the current machine; unsupported OS/CPU combinations stop before downloading:

```sh
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) INVSCAN_PLATFORM=macos-arm64 ;;
  Darwin-x86_64) INVSCAN_PLATFORM=macos-x86_64 ;;
  Linux-x86_64) INVSCAN_PLATFORM=linux-x86_64 ;;
  Linux-aarch64|Linux-arm64) INVSCAN_PLATFORM=linux-arm64 ;;
  *) echo "Use the Python wheel or source instructions for this platform."; exit 1 ;;
esac
INVSCAN_ARCHIVE="invscan-0.15.0-${INVSCAN_PLATFORM}.tar.gz"
INVSCAN_RELEASE="https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0"
curl --fail --location --output "$INVSCAN_ARCHIVE" "$INVSCAN_RELEASE/$INVSCAN_ARCHIVE"
curl --fail --location --output SHA256SUMS-standalone.txt "$INVSCAN_RELEASE/SHA256SUMS-standalone.txt"
```

Verify the downloaded archive before extracting it. The commands require exactly one matching checksum line and stop on a mismatch:

```sh
INVSCAN_EXPECTED=$(awk -v file="$INVSCAN_ARCHIVE" '$2 == file {print $1}' SHA256SUMS-standalone.txt)
if [ "${#INVSCAN_EXPECTED}" -ne 64 ]; then
  echo "Missing or ambiguous checksum entry."; exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  INVSCAN_ACTUAL=$(sha256sum "$INVSCAN_ARCHIVE" | awk '{print $1}')
else
  INVSCAN_ACTUAL=$(shasum -a 256 "$INVSCAN_ARCHIVE" | awk '{print $1}')
fi
if [ "$INVSCAN_ACTUAL" != "$INVSCAN_EXPECTED" ]; then
  echo "Checksum mismatch; download the release again."; exit 1
fi
tar -xzf "$INVSCAN_ARCHIVE"
cd "invscan-0.15.0-${INVSCAN_PLATFORM}"
./invscan --version
./invscan --help
```

Expect `0.15.0`. To use the shorter `invscan` command from any directory in this terminal:

```sh
export PATH="$PWD:$PATH"
invscan --version
```

This changes only the current terminal. In future terminals, use the full path to `invscan` or add the full extracted directory to your normal PATH configuration. Keep writable reports outside the bundle if you install it in a protected directory.

The macOS application is not Developer ID signed or notarized, and the Windows executable is unsigned. Operating-system policies may prevent it from opening. If your policy blocks the archive, use the reviewed [Python wheel](#install-the-python-wheel) or [source installation](#build-from-source); these instructions do not require disabling platform protections.

### Windows PowerShell

Run in a new directory where you want to keep Invarune:

```powershell
$InvscanArchive = 'invscan-0.15.0-windows-x86_64.zip'
$InvscanRelease = 'https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0'
Invoke-WebRequest "$InvscanRelease/$InvscanArchive" -OutFile $InvscanArchive
Invoke-WebRequest "$InvscanRelease/SHA256SUMS-standalone.txt" -OutFile SHA256SUMS-standalone.txt
$InvscanChecksum = @(Get-Content SHA256SUMS-standalone.txt | Where-Object { ($_ -split '\s+')[1] -eq $InvscanArchive })
if ($InvscanChecksum.Count -ne 1) { throw 'Missing or ambiguous checksum entry.' }
$InvscanExpected = ($InvscanChecksum[0] -split '\s+')[0]
$InvscanActual = (Get-FileHash $InvscanArchive -Algorithm SHA256).Hash
if ($InvscanActual -ne $InvscanExpected) { throw 'Checksum mismatch; download the release again.' }
Expand-Archive $InvscanArchive -DestinationPath .
Set-Location invscan-0.15.0-windows-x86_64
.\invscan.exe --version
.\invscan.exe --help
```

To use `invscan` from any directory in this terminal, add the entire extracted directory to the current PATH:

```powershell
$env:Path = "$((Get-Location).Path);$env:Path"
invscan --version
```

No PowerShell execution-policy change is needed. Future terminals can use the executable's full path or your normal user PATH configuration.

### Get your first report

From the extracted bundle directory, with PATH configured as above:

```sh
invscan examples/safer --pdf --report ./scan-report/first
invscan --ask 'How is MCP authentication covered?'
invscan --list-scans
```

The safer fixture yields **2 scanned files, 0 findings and exit 0**. Open `scan-report/first/report.html` or `report.pdf`. PDF support is already included. Then scan your own source, skill directory or saved container image:

```sh
invscan /path/to/agent-or-mcp-repo
invscan /path/to/skill --report ./skill-report
invscan --image-archive ./agent-image.tar --pdf --report ./image-report
```

Replace the paths with your inputs; quote paths containing spaces. With no report flag, the result stays in the terminal. See [Quick start](QUICKSTART.md) for report interpretation, optional AI and justifications.

The bundle's Headroom package becomes active only when AI review is enabled. Official provider CLIs and their login remain separate prerequisites. For example, with Codex already installed:

```sh
invscan /path/to/agent-or-mcp-repo --judge-cli codex --pdf --report ./ai-review
```

Interactive scans offer the supported provider's login when required. No provider is enabled by downloading or starting Invarune. [Provider requirements and tested behavior](CLI_PROVIDER_RESEARCH.md).

## Install the Python wheel

Use this route when you prefer a Python-managed CLI, need an unsupported native platform, or cannot run unsigned native applications. Deterministic scanning requires **Python 3.9+**. Use **Python 3.10+** for the Headroom extra; Python 3.9 can still run AI review with built-in compaction.

Download the [0.15.0 wheel](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/agent_mcp_security_scan-0.15.0-py3-none-any.whl) and [package checksums](https://github.com/nimeshbuilds/invarune/releases/download/v0.15.0/SHA256SUMS.txt) into one directory. Compare the wheel's SHA-256 with its exact filename in that checksum file: `shasum -a 256 FILENAME` on macOS, `sha256sum FILENAME` on Linux, or `Get-FileHash FILENAME -Algorithm SHA256` in PowerShell. These package checksums are separate from `SHA256SUMS-standalone.txt`.

macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install './agent_mcp_security_scan-0.15.0-py3-none-any.whl[ai,pdf]'
. .venv/bin/activate
invscan --version
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install './agent_mcp_security_scan-0.15.0-py3-none-any.whl[ai,pdf]'
$env:Path = "$((Resolve-Path .venv\Scripts).Path);$env:Path"
invscan --version
```

Remove `[ai,pdf]` for the dependency-free deterministic package. Extras can download dependencies from your configured Python package index. The wheel installs all three command aliases: `invscan`, `invarune` and `ai-security-scan`. The standalone archive provides `invscan`.

The wheel has catalogs, but no checkout examples or developer scripts. Point it at your own target, or obtain the repository for the [ten tested scenarios](SCENARIOS.md).

## Build from source

Use a source checkout to modify Invarune, reproduce all scenarios, or build your own packages. Start with **Git and Python 3.9+**, or **Python 3.10+** for Headroom. No GitHub login is required:

```sh
git clone https://github.com/nimeshbuilds/invarune.git
cd invarune
```

For the release source, run `git checkout v0.15.0` before installation. Leave it on the default branch for the latest documentation and development changes. Create a fresh environment; reuse an existing environment only if it belongs to this project.

macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[ai,pdf]'
. .venv/bin/activate
invscan --version
invscan examples/safer --pdf --report ./scan-report/first
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install '.[ai,pdf]'
$env:Path = "$((Resolve-Path .venv\Scripts).Path);$env:Path"
invscan --version
invscan examples/safer --pdf --report ./scan-report/first
```

Use `pip install .` instead of `pip install '.[ai,pdf]'` when you want only the base deterministic package. The detailed [source quickstart](QUICKSTART.md#1-install-the-cli-and-get-your-first-report) retains the same steps without requiring optional packages.

To produce the distributable wheel and source archive in `dist/`, from the activated environment:

```sh
python -m pip install build
python -m build
```

The [developer release guide](developer/testing-and-releasing.md) explains native bundle builds, validation and publishing. Build native bundles on each target platform; they are not cross-compiled. The [publication notice](../NOTICE.md) covers source and bundled third-party material.

## Update or remove an installation

For a standalone update, download and verify the new version, extract it to a new directory, run `invscan --version`, then point PATH at that directory. Retain earlier reports separately. Remove a standalone installation by removing its directory and any PATH entry you added; external provider accounts are managed by their respective CLIs.

For wheel or source installs, use the Python executable inside your chosen environment to install the next wheel or checkout. Remove a dedicated environment to uninstall it. Avoid mixing multiple versions on PATH: `command -v invscan` on macOS/Linux or `Get-Command invscan` on Windows identifies the executable being used.
