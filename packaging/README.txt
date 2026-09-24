INVARUNE by NimeshBuild — standalone invscan

This archive contains the native CLI and its private Python runtime. You do not
need to install Python or pip. Extract the entire archive and keep _internal
beside invscan (invscan.exe on Windows). Do not copy just the executable.

macOS / Linux (from the extracted directory):
  ./invscan --version
  ./invscan --help
  ./invscan --help-all
  ./invscan examples/vulnerable --report scan-report --pdf

Windows PowerShell (from the extracted directory):
  .\invscan.exe --version
  .\invscan.exe --help-all
  .\invscan.exe examples/vulnerable --report scan-report --pdf

The vulnerable examples intentionally produce findings and exit 1. Exit 0 means
the selected finding threshold was not met; exit 2 means an operational failure
or incomplete assessment. It does not prove a target is secure.

Included: offline security catalog, source/skills/image-archive scanning,
JSON/HTML/Markdown/SARIF/PDF reports and imports, HTTP model adapters, and the
pinned Headroom lossless JSON optimizer for optional model review.
No model API credentials, accounts, models, vendor CLIs, Docker, or Podman are
bundled. External-provider review needs your credentials or separately installed
official CLI; live image export needs Docker/Podman. Deterministic scanning and
saved image archive scanning need neither.

HTTPS keeps certificate and hostname verification enabled. Existing system
trust and SSL_CERT_FILE/SSL_CERT_DIR overrides are preserved. Only if the system
has no trusted CA certificates and neither override exists, the bundled Mozilla
CA roots from certifi are used. Judge ca_file remains available for a private CA.

Examples are inert scan inputs. Do not execute the vulnerable example programs.
The private runtime contains some original scanner sources to preserve report
implementation hashes. build-manifest.json records exact source and dependency
hashes. THIRD_PARTY_NOTICES.md and LICENSES contain third-party notices.

Download verification and platform guidance:
  https://nimeshbuilds.github.io/invarune/docs/INSTALLATION/
Quick start and tested scenarios:
  https://nimeshbuilds.github.io/invarune/docs/QUICKSTART/
  https://nimeshbuilds.github.io/invarune/docs/SCENARIOS/
Source and releases:
  https://github.com/nimeshbuilds/invarune
  https://github.com/nimeshbuilds/invarune/releases

See NOTICE.md for the original project's publication and source notice. Bundling
Python and dependencies does not change their respective license terms.
