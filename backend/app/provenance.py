"""Version the processing runtime without recording source hosts or credentials."""
import hashlib
import importlib.metadata
import json
import os
import re


_IDENTITY = re.compile(r"[a-f0-9]{64}")
_KNOWN_SUFFIX = re.compile(r"/runtime-(?:bundle|local)-[a-f0-9]{64}$")


def processing_runtime_identity() -> str:
    """Packaged scans use image identity; local scans require no remote parser.

    The bundle stamps the API and Tika image IDs into Compose. This is release
    provenance, not remote attestation of an arbitrary TIKA_URL. Deployments must
    retain the supplied images/configuration. A standalone external parser with
    no recorded identity makes successive scans ineligible for source attribution.
    """
    configured = os.getenv("DISCOVERY_RUNTIME_ID", "").strip()
    if configured:
        return "runtime-bundle-" + configured if _IDENTITY.fullmatch(configured) else "runtime-unverified"
    if os.getenv("TIKA_URL", "").strip() or os.getenv("PAGE_OCR_URL", "").strip():
        return "runtime-unverified"
    try:
        packages = sorted({(str(distribution.metadata["Name"]).lower(), str(distribution.version))
                           for distribution in importlib.metadata.distributions()
                           if distribution.metadata["Name"] and distribution.version})
        if not packages:
            return "runtime-unverified"
        # The Detector separately includes the local pipeline code hash and the
        # chosen NLP model/version. Include all installed dependency versions so
        # native extraction/connector dependency changes cannot look like data edits.
        payload = json.dumps({"format": "native-runtime/v1", "packages": packages},
                             sort_keys=True, separators=(",", ":")).encode()
        return "runtime-local-" + hashlib.sha256(payload).hexdigest()
    except Exception:
        return "runtime-unverified"


def provenance_is_known(version: str) -> bool:
    return isinstance(version, str) and _KNOWN_SUFFIX.search(version) is not None
