#!/usr/bin/env python3
"""Generate fresh local secrets without printing them or overwriting existing files."""
import argparse
import base64
import os
from pathlib import Path
import secrets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("deploy/.env"))
    parser.add_argument("--source-mount", type=Path, required=True)
    args = parser.parse_args()
    mount = args.source_mount.resolve(strict=True)
    if not mount.is_dir() or any(c in str(mount) for c in "\n\r$\"'"):
        parser.error("Source mount must be an existing directory with a simple absolute path")
    content = "\n".join([
        "# Private deployment configuration. Back up keys separately from catalog data.",
        "APP_SECRET_KEY=" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "SESSION_SECRET=" + secrets.token_hex(32),
        "POSTGRES_PASSWORD=" + secrets.token_hex(32),
        'SOURCE_MOUNT="' + str(mount) + '"',
        "BIND_ADDRESS=127.0.0.1", "HTTPS_PORT=8443",
        "DATABASE_HOST_ALLOWLIST=", "SMB_HOST_ALLOWLIST=", "CLOUD_HOST_ALLOWLIST=",
        "# Optional source trust override: mount the CA directory with compose.trust.yaml.",
        "SOURCE_DATABASE_CA_FILE=", "SOURCE_CLOUD_CA_FILE=", "",
    ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(content)
    print("Created private deployment configuration; values were not printed.")


if __name__ == "__main__":
    main()
