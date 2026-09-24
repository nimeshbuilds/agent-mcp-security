"""Supply bundled Mozilla roots only when no system or user trust exists."""
import os
import ssl
import sys


def configure_bundled_tls():
    """Return only the CA path injected by this bootstrap, or False.

    The external-process boundary uses this exact value to avoid imposing the
    scanner's fallback trust store on independently installed provider CLIs.
    """
    if not getattr(sys, "frozen", False):
        return False
    # Even an empty user setting is an explicit choice; do not override it.
    if "SSL_CERT_FILE" in os.environ or "SSL_CERT_DIR" in os.environ:
        return False
    try:
        if ssl.create_default_context().cert_store_stats().get("x509_ca", 0):
            return False
        import certifi
        ca_file = certifi.where()
        # Verify the shipped trust file loads before using it. Certificate and
        # hostname verification remain enabled by create_default_context.
        if not ssl.create_default_context(cafile=ca_file).cert_store_stats().get("x509_ca", 0):
            return False
    except (OSError, ValueError):
        # A broken trust store must not prevent offline deterministic scans.
        # HTTPS will retain its normal verified/fail-closed behavior.
        return False
    os.environ["SSL_CERT_FILE"] = ca_file
    return ca_file
