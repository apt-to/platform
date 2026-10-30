"""Helpers for reproducible, TLS-verified container build inputs.

The default trust input is the Linux runner's system CA bundle. A workflow may
set GETPATCHED_CA_BUNDLE only to an explicitly trusted runner-provisioned
bundle; its origin and SHA-256 are recorded in build evidence. The bundle is
passed through a BuildKit secret mount, never a build argument or log output.
"""
import hashlib
import os
from pathlib import Path
import re
import ssl


def runner_ca_bundle():
    explicit_override = os.environ.get("GETPATCHED_CA_BUNDLE")
    configured = explicit_override or "/etc/ssl/certs/ca-certificates.crt"
    path = Path(configured).expanduser().resolve()
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError("A readable non-empty Linux CA bundle is required (set GETPATCHED_CA_BUNDLE)")
    contents = path.read_bytes()
    if b"PRIVATE KEY" in contents:
        raise RuntimeError("CA bundle must not contain private key material")
    certificates = re.findall(
        rb"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
        contents,
        flags=re.DOTALL,
    )
    if not certificates:
        raise RuntimeError("CA bundle must contain PEM-encoded certificates")
    try:
        for certificate in certificates:
            ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("CA bundle contains an invalid PEM certificate") from error
    digest = hashlib.sha256(contents).hexdigest()
    source = "explicit-override" if explicit_override else "linux-system-default"
    return ["--secret", "id=runner-ca,src=" + str(path)], digest, source
