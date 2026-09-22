# Dependency and license inventory

The release contains open-source application dependencies. Exact installed versions are captured by `scripts/bundle.py` in `inventory/`; these inventories are supplied instead of claiming a complete SPDX/CycloneDX SBOM. Generate and review a full SBOM using the hospital's approved tool before production approval.

| Component | Project license / note |
|---|---|
| FastAPI, React, SQLAlchemy | MIT |
| PostgreSQL | PostgreSQL License |
| psycopg / psycopg-binary | LGPL-3.0; inspect packaged binary dependencies and corresponding-source obligations |
| PyMySQL 1.2.3, python-tds 1.17.1 | MIT; the SQL Server adapter uses the open-source TDS client, not a bundled Microsoft ODBC driver |
| pyOpenSSL 26.4.0 | Apache-2.0; cryptographic libraries retain separate notices |
| boto3 1.43.98, botocore 1.43.98, s3transfer 0.19.2 | Apache-2.0 |
| azure-core 1.41.0, azure-storage-blob 12.30.2, azure-data-tables 12.7.0 | MIT |
| Presidio analyzer | MIT; use package metadata from actual release |
| spaCy | MIT |
| en_core_web_lg 3.8.0 | MIT model package; review model-card training-data notices separately |
| Apache Tika | Apache-2.0; bundled parsers carry their own notices |
| Tesseract + English trained data | Apache-2.0; retain distribution notices |
| Caddy | Apache-2.0 |
| Python | PSF license and bundled notices |
| Temurin/OpenJDK | GPL-2.0 with Classpath Exception; OS image packages have separate licenses |
| smbprotocol | MIT |
| cryptography | Apache-2.0 / BSD dual license; dependencies have separate notices |

The connector entries above were checked against the installed Python package metadata; the release inventory remains the authority for bundled versions and transitive dependencies. Connecting to a commercial database or cloud service does not supply a license for that service. Local integration emulators are test infrastructure, not application runtime dependencies; review their separate terms if redistributing those test images.

The custom Tika image installs English Tesseract and DejaVu fonts. It avoids the Microsoft core-font installer present in some upstream full images. Inspect font and OS notices in the image; do not assume every package has the application's license.

Sources: [spaCy model card](https://spacy.io/models/en), [Tika distribution](https://tika.apache.org/download.html), [psycopg license](https://www.psycopg.org/docs/license.html), and package metadata in the generated release inventory. Upstream images retain installed license files; redistribution obligations must be checked for the actual approved release. No license for the hospital's patient data is implied.
