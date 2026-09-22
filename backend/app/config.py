import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


def secret(name: str) -> str:
    filename = os.getenv(name + "_FILE")
    return Path(filename).read_text().strip() if filename else os.getenv(name, "")


@dataclass(frozen=True)
class Settings:
    database_url: str
    encryption_key: str
    session_secret: str
    environment: str
    detector_mode: str
    spacy_model: str
    allowed_roots: tuple[str, ...]
    database_hosts: tuple[str, ...]
    smb_hosts: tuple[str, ...]
    cloud_hosts: tuple[str, ...]
    secure_cookies: bool
    frontend_dir: Path


@lru_cache
def settings() -> Settings:
    load_dotenv(os.getenv("APP_ENV_FILE", ".env"), override=False)
    environment = os.getenv("ENVIRONMENT", "production")
    key, session = secret("APP_SECRET_KEY"), secret("SESSION_SECRET")
    if not key or len(session) < 32:
        raise RuntimeError("Configure APP_SECRET_KEY and SESSION_SECRET before starting; use app.cli init-env.")
    url = os.getenv("DATABASE_URL", "")
    mode = os.getenv("DETECTOR_MODE", "presidio")
    if not url:
        raise RuntimeError("DATABASE_URL is required.")
    if environment == "production" and (not url.startswith("postgresql") or mode != "presidio"):
        raise RuntimeError("Production requires PostgreSQL and the Presidio detector.")
    secure = os.getenv("SECURE_COOKIES", "true").lower() == "true"
    if environment == "production" and not secure:
        raise RuntimeError("Production requires secure cookies and HTTPS.")
    return Settings(url, key, session, environment, mode, os.getenv("SPACY_MODEL", "en_core_web_lg"),
                    tuple(json.loads(os.getenv("SOURCE_ALLOWED_ROOTS", "[]"))),
                    tuple(x.strip().lower() for x in os.getenv("DATABASE_HOST_ALLOWLIST", "").split(",") if x.strip()),
                    tuple(x.strip().lower() for x in os.getenv("SMB_HOST_ALLOWLIST", "").split(",") if x.strip()),
                    tuple(x.strip().lower() for x in os.getenv("CLOUD_HOST_ALLOWLIST", "").split(",") if x.strip()),
                    secure, Path(os.getenv("FRONTEND_DIR", str(Path(__file__).resolve().parents[2] / "frontend/dist"))))
