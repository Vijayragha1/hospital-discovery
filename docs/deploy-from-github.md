# Deploy from GitHub

Prefer the tested offline installation bundle attached to the repository **Releases**. It includes the runtime images, NLP/OCR resources, UI and installer. GitHub's automatic source ZIP/tar downloads contain source code; they are not an offline installation bundle.

Download on an approved online staging machine, then transfer through the hospital-approved channel. GitHub access is not required inside the hospital. Hosting remains a site decision: use a client-controlled Linux VM on premises or in an approved private cloud network. Review the [README](../README.md), [host and operating prerequisites](runbook.md#release-status-and-deployment-gate) and [hospital acceptance checklist](acceptance-checklist.md) before installation. The host needs Docker Engine/Compose v2, Python 3.10+, the documented Docker platform support, encrypted storage and approved source access. The supplied images target `linux/amd64`.

## Download, verify and install

Use an authenticated browser on staging to download these assets from the chosen repository release:

- `hospital-discovery-offline-linux-amd64.tar`
- `SHA256SUMS.txt`
- `hospital-discovery-install-validation.json`

Keep the validation report and release approval with the installation record. Verify the publisher and checksum through the approved release channel; checksums detect changed bytes but do not independently prove provenance.

Place the archive and checksum file together in a new approved receiving directory, such as `/secure/received`. On the Linux installation host, run:

```sh
cd /secure/received
sha256sum -c SHA256SUMS.txt
```

Continue only if verification succeeds. Extract into a directory that does not already contain an installation, then verify the bundle's internal manifest and load its images:

```sh
tar -xf hospital-discovery-offline-linux-amd64.tar
cd hospital-discovery-bundle
python3 scripts/bundle.py verify .
python3 scripts/bundle.py install .
```

Installation checks image identities against the release manifest and does not fetch images from a registry. It does not configure the hospital host or start services. Preserve the archive, manifests and generated `deploy/compose.images.yaml` for this exact release.

## Configure and start

Mount the approved file-share scope read-only at an existing host directory, using `/srv/hospital/discovery-input` below as an example. From the extracted bundle root:

```sh
python3 scripts/configure_deployment.py --source-mount /srv/hospital/discovery-input
```

This creates private `deploy/.env` with fresh secrets and refuses to overwrite an existing file. Escrow `APP_SECRET_KEY` and `SESSION_SECRET` separately from the catalog as described in the [offline installation steps](runbook.md#offline-install). Keep secrets, patient data and deployment certificates out of GitHub.

Install the hospital-issued certificate and private key at `deploy/certs/server.crt` and `deploy/certs/server.key`, readable by runtime UID/GID 10001 and authorized administrators. Set `BIND_ADDRESS` in `deploy/.env` to the approved intranet address; its default is loopback. The default HTTPS port is 8443. Caddy uses the supplied certificate and does not request an external one.

The base deployment below supports the mounted folder. Routed database, SMB and cloud access require the existing [source-network containment](runbook.md#network-containment-and-source-reachability) configuration before startup. Relational databases also require the [source CA trust](runbook.md#trust-for-source-connections) override. Follow those steps and retain the same approved override set on subsequent commands; always include `compose.images.yaml`.

```sh
cd deploy
docker compose -f compose.yaml -f compose.images.yaml config --quiet
docker compose -f compose.yaml -f compose.images.yaml up -d --pull never --no-build
docker compose -f compose.yaml -f compose.images.yaml exec api python -m app.cli init-admin --username hospital-admin
```

Enter the administrator password at the prompts. Open `https://<hospital-host>:8443`, verify the certificate and sign in. Record hospital-approved retention, then register the approved sources. Starting retention values are unapproved; a connection check does not approve workload or start a scan. Complete the [runbook](runbook.md) and site acceptance before hospital scanning. Installation and synthetic validation do not establish hospital accuracy or deployment acceptance.

## If building from source

Use an approved online staging machine and a reviewed repository revision. From the source checkout root, run the existing builder with a new or empty output directory:

```sh
python3 scripts/bundle.py build /secure/staging/hospital-discovery-bundle --platform linux/amd64
```

The builder downloads dependencies on staging and produces the offline bundle, checksums, image identities and dependency inventories. Review and validate that new bundle before transferring its complete directory to the hospital, then follow the same verify/install/configure steps above. A source rebuild can resolve different transitive dependencies; it is not automatically equivalent to the tested release asset. See [staging build details](runbook.md#build-on-an-approved-online-staging-machine).
