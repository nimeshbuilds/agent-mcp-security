"""Native release entry point; scanner behavior remains in its normal CLI."""
from external_process import install_external_process_boundary
from bundled_tls import configure_bundled_tls

install_external_process_boundary(injected_ca_file=configure_bundled_tls())

from ai_security_scan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
