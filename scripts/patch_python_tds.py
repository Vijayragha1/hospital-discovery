#!/usr/bin/env python3
"""Apply the reviewed, version-locked python-tds TLS hostname compatibility fix.

This is a build/install step, never a runtime monkeypatch. Unknown input or output
is rejected. Certificate-chain verification and the TDS handshake are unchanged.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
from pathlib import Path


EXPECTED_VERSION = "1.17.1"
ORIGINAL_SHA256 = "a29e515b5a5754e66d70681b08e7111a83e980784d8d6aba48cb1a151974dde5"
PATCHED_SHA256 = "e7a0a1ef8ef72f86966ba605514354b61917ab8acaadf968be8cfb4a1db3033f"
ORIGINAL_INIT_SHA256 = "ea4bbf86dfa7a1e690e506742a67b56d8ed8db9a6dc0d01def2e725632738e4e"
PATCHED_INIT_SHA256 = "4903a27c3811c27d9b41925fc16a6799c6edc86942ddd7c4b08685d0b1b78b73"

HOSTNAME_MATCHER = '''def validate_host(cert, name: bytes) -> bool:
    """Validate DNS/IP SAN using cryptography and urllib3's hostname matcher.

    Hospital Discovery compatibility patch for python-tds 1.17.1. The existing
    OpenSSL VERIFY_PEER chain validation runs before this additional name check.
    Common-name-only certificates are deliberately rejected.
    """
    from urllib3.util.ssl_match_hostname import CertificateError, match_hostname
    from cryptography import x509

    try:
        certificate = cert.to_cryptography()
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        names = [("DNS", value) for value in san.get_values_for_type(x509.DNSName)]
        names.extend(
            ("IP Address", str(value))
            for value in san.get_values_for_type(x509.IPAddress)
        )
        if not names:
            return False
        match_hostname({"subjectAltName": names}, name.decode("ascii"),
                       hostname_checks_common_name=False)
    except (CertificateError, x509.ExtensionNotFound, ValueError,
            TypeError, AttributeError, UnicodeError):
        return False
    return True

'''


def patch_bytes(original: bytes, version: str) -> bytes:
    if version != EXPECTED_VERSION:
        raise RuntimeError("python_tds_patch_version_mismatch")
    digest = hashlib.sha256(original).hexdigest()
    if digest == PATCHED_SHA256:
        return original
    if digest != ORIGINAL_SHA256:
        raise RuntimeError("python_tds_patch_source_mismatch")
    text = original.decode("utf-8")
    start = text.index("def validate_host(")
    end = text.index("\ndef ", start + 1)
    patched = (text[:start] + HOSTNAME_MATCHER + text[end:]).encode("utf-8")
    if hashlib.sha256(patched).hexdigest() != PATCHED_SHA256:
        raise RuntimeError("python_tds_patch_result_mismatch")
    return patched


def patch_init_bytes(original: bytes, version: str) -> bytes:
    if version != EXPECTED_VERSION:
        raise RuntimeError("python_tds_patch_version_mismatch")
    digest = hashlib.sha256(original).hexdigest()
    if digest == PATCHED_INIT_SHA256:
        return original
    if digest != ORIGINAL_INIT_SHA256:
        raise RuntimeError("python_tds_patch_source_mismatch")
    text = original.decode("utf-8")
    start = text.index("        if route is not None:")
    end = text.index("        if not autocommit:", start)
    replacement = ('        if route is not None:\n'
                   '            sock.close()\n'
                   '            raise tds_base.Error("Server-directed routing is not supported")\n')
    patched = (text[:start] + replacement + text[end:]).encode("utf-8")
    if hashlib.sha256(patched).hexdigest() != PATCHED_INIT_SHA256:
        raise RuntimeError("python_tds_patch_result_mismatch")
    return patched


def main():
    version = importlib.metadata.version("python-tds")
    pending = []
    for name, patcher in (("pytds.tls", patch_bytes), ("pytds", patch_init_bytes)):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None:
            raise RuntimeError("python_tds_patch_module_missing")
        path = Path(spec.origin)
        before = path.read_bytes()
        pending.append((path, before, patcher(before, version)))
    # Validate every input/output before changing either installed file.
    for path, before, after in pending:
        if before != after:
            path.write_bytes(after)
    print("python-tds TLS compatibility patch verified")


if __name__ == "__main__":
    main()
