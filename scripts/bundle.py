#!/usr/bin/env python3
"""Build online on a staging host, verify, or load a self-contained offline release."""
import argparse
import concurrent.futures
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGES = {
    "PYTHON_IMAGE": "python:3.12-slim-bookworm",
    "NODE_IMAGE": "node:22-alpine",
    "CADDY_IMAGE": "caddy:2-alpine",
    "JAVA_IMAGE": "eclipse-temurin:21-jre-jammy",
    "POSTGRES_IMAGE": "postgres:17-alpine",
}


def run(*args, capture=False, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=capture, **kwargs)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_image(image, platform=None):
    args = ["docker", "image", "inspect"]
    if platform:
        args.extend(["--platform", platform])
    data = json.loads(run(*args, image, capture=True).stdout)[0]
    record = {"name": image, "id": data["Id"], "repo_digests": data.get("RepoDigests", []),
              "architecture": data.get("Architecture", ""), "os": data.get("Os", "")}
    if platform:
        expected = platform.split("/")
        if len(expected) < 2 or (record["os"], record["architecture"]) != tuple(expected[:2]):
            raise ValueError("Docker did not return the requested platform's image configuration")
        record["platform"] = platform
    return record


def repository_name(reference):
    """Normalize Docker Hub shorthand without confusing a registry port with a tag."""
    name = reference.split("@", 1)[0]
    if ":" in name.rsplit("/", 1)[-1]:
        name = name.rsplit(":", 1)[0]
    components = name.split("/")
    if len(components) == 1 or not any(c in components[0] for c in ".:") and components[0] != "localhost":
        components.insert(0, "docker.io")
    if components[0] == "index.docker.io":
        components[0] = "docker.io"
    if components[0] == "docker.io" and len(components) == 2:
        components.insert(1, "library")
    return "/".join(components)


def registry_digest(requested, digests):
    # A supplied immutable reference was already successfully pulled; do not replace
    # it with a local retag alias that happens to be first in RepoDigests.
    if "@" in requested:
        return requested
    expected = repository_name(requested)
    for digest in digests:
        if "@" in digest and repository_name(digest) == expected:
            return digest
    raise ValueError("Registry did not supply an immutable digest for the requested repository")


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def runtime_identity(records):
    """Fingerprint immutable detector/parser runtimes, excluding UI/catalogue changes.

    Docker image IDs identify the complete image configuration and layers, which
    also covers packaged NLP weights, OCR language data and parser dependencies.
    Image tags and creation timestamps are intentionally not part of the payload.
    """
    runtimes = {}
    for component in ("api", "tika"):
        record = records.get(component) if isinstance(records, dict) else None
        image_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("Processing runtime identity requires immutable API and Tika image IDs.")
        runtimes[component] = image_id
    payload = {"format": "hospital-discovery-processing-runtime/v1", "images": runtimes}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def compose_image_overrides(records):
    """Generate pinned image overrides and an identical API/worker runtime stamp."""
    identity = runtime_identity(records)
    platform = None
    for component in ("api", "tika", "web", "postgres"):
        record = records.get(component)
        value = record.get("platform") if isinstance(record, dict) else None
        if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9_.-]+)?", value):
            raise ValueError("Image overrides require a fixed platform for every runtime component.")
        if platform is not None and value != platform:
            raise ValueError("All runtime component platforms must match.")
        platform = value
    services = {"postgres": "postgres", "api": "api", "worker": "api", "tika": "tika",
                "ingress_guard": "web", "web": "web"}
    lines = ["services:"]
    for service, component in services.items():
        record = records.get(component)
        name = record.get("name") if isinstance(record, dict) else None
        if not isinstance(name, str) or not name or any(char in name for char in "\n\r$"):
            raise ValueError("Image overrides require fixed image names for every runtime component.")
        lines.extend([f"  {service}:", "    image: " + json.dumps(name),
                      "    platform: " + json.dumps(platform), "    pull_policy: never"])
        if service in {"api", "worker"}:
            lines.extend(["    environment:", "      DISCOVERY_RUNTIME_ID: " + json.dumps(identity)])
    return "\n".join(lines) + "\n"


def checksum_manifest(directory):
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text("".join(
        f"{sha256(p)}  {p.relative_to(directory).as_posix()}\n" for p in files))


def verify(directory):
    directory = directory.resolve(strict=True)
    seen = set()
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        target = directory / name
        if target.is_symlink() or not target.resolve().is_relative_to(directory):
            raise ValueError("Unsafe path in checksum manifest")
        if name in seen or len(digest) != 64:
            raise ValueError("Invalid checksum manifest")
        seen.add(name)
        if not target.is_file() or sha256(target) != digest:
            raise ValueError(f"Checksum mismatch: {name}")
    for required in ("images.tar.gz", "images.lock.json", "release.json", "deploy/compose.yaml", "deploy/compose.images.yaml"):
        if required not in seen:
            raise ValueError(f"Missing required bundle artifact: {required}")
    print(f"Verified {len(seen)} bundle artifacts.")


def build(directory, platform, lock):
    run("docker", "info", capture=True)
    directory = directory.resolve()
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("Build output must be a new or empty directory")
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    desired = BASE_IMAGES.copy()
    if lock:
        prior = json.loads(lock.read_text())
        desired = {key: entry["resolved"] for key, entry in prior.items()}
        if set(desired) != set(BASE_IMAGES):
            raise ValueError("Base lock must cover all expected base images")
    base_lock = {}
    for key, tag in desired.items():
        run("docker", "pull", "--platform", platform, tag)
        record = inspect_image(tag, platform)
        record["requested"] = tag
        record["resolved"] = registry_digest(tag, record["repo_digests"])
        base_lock[key] = record
    write_json(directory / "base-images.lock.json", base_lock)
    images = {name: f"hospital-discovery-{name}:pilot-{stamp}" for name in ("api", "web", "tika")}
    images["postgres"] = f"hospital-discovery-postgres:pilot-{stamp}"

    def build_one(name):
        args = ["docker", "build", "--platform", platform, "--pull=false", "-f", str(ROOT / "deploy" / f"Dockerfile.{name}"), "-t", images[name]]
        for key, value in base_lock.items():
            args += ["--build-arg", f"{key}={value['resolved']}"]
        run(*args, str(ROOT))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(build_one, ("api", "web", "tika")))
    run("docker", "tag", base_lock["POSTGRES_IMAGE"]["resolved"], images["postgres"])
    records = {name: inspect_image(tag, platform) for name, tag in images.items()}
    write_json(directory / "images.lock.json", records)
    inventory = directory / "inventory"
    inventory.mkdir()
    for name, tag in images.items():
        # No source mounts, no networking, no runtime secrets during inventory.
        result = run("docker", "run", "--platform", platform, "--rm", "--network=none", "--entrypoint", "sh", tag, "-c",
                     "if command -v dpkg-query >/dev/null; then dpkg-query -W; elif command -v apk >/dev/null; then apk info -v; else exit 1; fi", capture=True)
        (inventory / f"{name}-os-packages.txt").write_text(result.stdout)
    result = run("docker", "run", "--platform", platform, "--rm", "--network=none", "--entrypoint", "python", images["api"], "-m", "pip", "freeze", capture=True)
    (inventory / "python-freeze.txt").write_text(result.stdout)
    result = run("docker", "run", "--platform", platform, "--rm", "--network=none", "--entrypoint", "python", images["api"], "-m", "pip", "inspect", capture=True)
    (inventory / "python-metadata.json").write_text(result.stdout)
    run("docker", "run", "--platform", platform, "--rm", "--network=none", "--entrypoint", "python", images["api"], "-c", "import spacy; spacy.load('en_core_web_lg'); print('Offline NLP model load passed')")
    result = run("docker", "run", "--platform", platform, "--rm", "--network=none", "--entrypoint", "tesseract", images["tika"], "--list-langs", capture=True)
    (inventory / "ocr-language-packs.txt").write_text(result.stdout)
    if "eng" not in result.stdout.split():
        raise ValueError("English OCR data missing")
    for name in ("deploy", "docs", "scripts", "fixtures"):
        shutil.copytree(ROOT / name, directory / name, ignore=shutil.ignore_patterns(".env", "*.key", "*.crt", "__pycache__"))
    shutil.copy2(ROOT / "README.md", directory / "README.md")
    shutil.copy2(ROOT / "frontend" / "package-lock.json", inventory / "npm-package-lock.json")
    (directory / "deploy" / "compose.images.yaml").write_text(compose_image_overrides(records))
    command = ["docker", "image", "save", "--platform", platform, *images.values()]
    with (directory / "images.tar.gz").open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            try:
                shutil.copyfileobj(process.stdout, compressed, 1024 * 1024)
            finally:
                process.stdout.close()
            if process.wait() != 0:
                raise RuntimeError("Docker image export failed")
    write_json(directory / "release.json", {"version": stamp, "platform": platform,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Hospital pilot; not hospital-validated accuracy", "tika_version": "3.3.2",
        "spacy_model": "en_core_web_lg-3.8.0", "network_required_at_runtime": False,
        "runtime_identity": runtime_identity(records),
        "reproducibility": "Exact release replay via images.tar.gz; transitive dependency versions are recorded in inventory. Rebuilding from source can change OS/package resolutions."})
    checksum_manifest(directory)
    verify(directory)
    print(f"Offline bundle assembled at {directory}")


def install(directory):
    verify(directory)
    records = json.loads((directory / "images.lock.json").read_text())
    platform = json.loads((directory / "release.json").read_text())["platform"]
    # Docker load accepts gzip and performs no registry fetch.
    run("docker", "image", "load", "--input", str(directory / "images.tar.gz"))
    for record in records.values():
        if inspect_image(record["name"], platform)["id"] != record["id"]:
            raise ValueError("Loaded image ID differs from the release manifest")
    print("Images loaded and checked. Configure deploy/.env and hospital TLS certificates before starting.")
    print("Start from deploy/: docker compose -f compose.yaml -f compose.images.yaml up -d --pull never --no-build")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify", "install"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("--base-lock", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "build":
            build(args.directory, args.platform, args.base_lock)
        elif args.action == "verify":
            verify(args.directory)
        else:
            install(args.directory.resolve())
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Bundle operation failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
