import base64
import hashlib
import hmac
import json
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet

from .config import settings


@lru_cache
def cipher():
    return Fernet(settings().encryption_key.encode())


def encrypt(value) -> str:
    return cipher().encrypt(json.dumps(value, ensure_ascii=False).encode()).decode()


def decrypt(value: str):
    return json.loads(cipher().decrypt(value.encode()))


def stable_hash(value: str) -> str:
    return hmac.new(settings().session_secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Passwords require at least 12 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return base64.b64encode(salt + digest).decode()


def check_password(password: str, encoded: str) -> bool:
    try:
        raw = base64.b64decode(encoded)
        calculated = hashlib.scrypt(password.encode(), salt=raw[:16], n=16384, r=8, p=1)
        return hmac.compare_digest(raw[16:], calculated)
    except (ValueError, TypeError):
        return False


def audit(db, actor: str, action: str, detail: dict | None = None):
    from .models import Audit
    db.add(Audit(actor=actor, action=action, detail_encrypted=encrypt(detail or {})))
