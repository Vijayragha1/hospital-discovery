import csv
import io
import json
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import timedelta, timezone
from functools import lru_cache
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from . import models as m, schemas as s
from .comparison import compare_scans
from .config import settings
from .connectors import LIVE_KINDS, SECRET_FIELDS, validated_check
from .db import initialize, session
from .security import audit, check_password, decrypt, encrypt, hash_password, stable_hash
from .source_locks import SourceBusy, source_database_lock
from .sources import normalize_config, test_connection


@asynccontextmanager
async def lifespan(app):
    initialize()
    with session() as db:
        if db.get(m.Policy, 1) is None:
            db.add(m.Policy(id=1))
            db.commit()
    yield


app = FastAPI(title="Sentry Discovery", version="0.1.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        parsed = urlparse(origin or "")
        bad_origin = origin and (parsed.netloc != request.headers.get("host") or
                                (settings().environment == "production" and parsed.scheme != "https"))
        if bad_origin or request.headers.get("x-requested-with") != "SentryDiscovery":
            return JSONResponse({"detail": "Request origin could not be verified."}, status_code=403)
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return JSONResponse({"detail": "Invalid request size."}, status_code=400)
        if length > 65536:
            return JSONResponse({"detail": "Request too large."}, status_code=413)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 65536:
                return JSONResponse({"detail": "Request too large."}, status_code=413)
            body.extend(chunk)
        # Starlette's cached request replays this bounded body to the JSON decoder.
        request._body = bytes(body)
    response = await call_next(request)
    if request.method == "GET" and response.status_code == 200 and request.url.path in {
        "/api/findings", "/api/sources", "/api/source-setup", "/api/audit", "/api/overview"
    } or (request.method == "GET" and response.status_code == 200 and
          request.url.path.startswith("/api/scans/") and request.url.path.endswith("/objects")):
        # Record sensitive data access without logging search strings, source paths,
        # result content, cookies, or request headers.
        with session() as db:
            token = request.cookies.get("sentry_session", "")
            auth = db.get(m.LoginSession, stable_hash(token)) if token else None
            user = db.get(m.User, auth.user_id) if auth else None
            if user:
                route = request.scope.get("route")
                audit(db, user.username, "data_viewed", {"resource": getattr(route, "path", "/api")})
                db.commit()
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else "no-cache"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    return JSONResponse({"detail": "Invalid request fields or values."}, status_code=422)


def database():
    with session() as db:
        yield db


def current_user(request: Request, db=Depends(database)):
    token = request.cookies.get("sentry_session", "")
    auth = db.get(m.LoginSession, stable_hash(token)) if token else None
    expires = auth.expires_at.replace(tzinfo=timezone.utc) if auth and auth.expires_at.tzinfo is None else auth.expires_at if auth else None
    user = db.get(m.User, auth.user_id) if auth and expires > m.now() else None
    if not user or not user.active:
        raise HTTPException(401, "Sign in to continue.")
    return user


def roles(*allowed):
    def check(user=Depends(current_user)):
        if user.role not in allowed:
            raise HTTPException(403, "Your role cannot perform this action.")
        return user
    return check


def user_json(user):
    return {"id": user.id, "username": user.username, "role": user.role}


@lru_cache
def capabilities():
    from .detection import Detector
    from .extraction import extraction_capabilities
    try:
        detector = Detector(mode=settings().detector_mode, model=settings().spacy_model)
        return {**detector.capabilities, **extraction_capabilities(), "detector_available": True, "detector_mode": settings().detector_mode,
                "detector_version": detector.version, "accuracy_validated": False}
    except Exception:
        return {"detector_available": False, "detector_mode": settings().detector_mode,
                "accuracy_validated": False, "limitations": ["Required detector packages or local model are unavailable. Scanning is disabled."]}


attempts = {}
attempt_lock = threading.Lock()
dummy_password = hash_password(secrets.token_urlsafe(32))


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/api/auth/login")
def login(body: s.Login, request: Request, response: Response, db=Depends(database)):
    key = stable_hash((request.client.host if request.client else "unknown") + body.username.lower())
    with attempt_lock:
        recent = [x for x in attempts.get(key, []) if x > time.monotonic() - 900]
        if len(recent) >= 5:
            raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.")
        attempts[key] = recent + [time.monotonic()]
        if len(attempts) > 10000:
            for old in list(attempts)[:5000]:
                if old != key:
                    attempts.pop(old, None)
    user = db.scalar(select(m.User).where(m.User.username == body.username))
    valid = check_password(body.password, user.password_hash if user else dummy_password)
    if not user or not valid or not user.active:
        audit(db, "anonymous", "login_failed", {"account_ref": stable_hash(body.username)})
        db.commit()
        raise HTTPException(401, "Invalid username or password.")
    with attempt_lock:
        attempts.pop(key, None)
    token = secrets.token_urlsafe(48)
    db.add(m.LoginSession(token_hash=stable_hash(token), user_id=user.id, expires_at=m.now() + timedelta(hours=8)))
    audit(db, user.username, "login")
    db.commit()
    response.set_cookie("sentry_session", token, httponly=True, secure=settings().secure_cookies,
                        samesite="strict", max_age=8 * 3600, path="/")
    return user_json(user)


@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return user_json(user)


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user=Depends(current_user), db=Depends(database)):
    auth = db.get(m.LoginSession, stable_hash(request.cookies.get("sentry_session", "")))
    if auth:
        db.delete(auth)
    audit(db, user.username, "logout")
    db.commit()
    response.delete_cookie("sentry_session", path="/")
    return {"ok": True}


@app.post("/api/users", status_code=201)
def create_user(body: s.UserCreate, user=Depends(roles("admin")), db=Depends(database)):
    if db.scalar(select(m.User).where(m.User.username == body.username)):
        raise HTTPException(409, "Username already exists.")
    created = m.User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(created)
    audit(db, user.username, "user_created", {"username": body.username, "role": body.role})
    db.commit()
    return user_json(created)


def source_json(source, role):
    config = decrypt(source.config_encrypted) if role == "admin" else {}
    config = {k: "[redacted]" if k in SECRET_FIELDS else v for k, v in config.items()}
    return {"id": source.id, "name": decrypt(source.name_encrypted), "kind": source.kind,
            "config": config, "enabled": source.enabled, "safety_validated": source.safety_validated,
            "created_at": source.created_at}


@app.get("/api/sources")
def sources(user=Depends(current_user), db=Depends(database)):
    return [source_json(x, user.role) for x in db.scalars(select(m.Source).order_by(m.Source.created_at))]


@app.get("/api/source-setup")
def source_setup(user=Depends(roles("admin"))):
    configuration = settings()
    kinds = list(LIVE_KINDS)
    if configuration.environment == "development":
        kinds.append("sqlite")
    # Explicitly project setup fields: never serialize deployment credentials or DSNs.
    # This endpoint neither resolves hosts nor enumerates directories.
    return {"environment": configuration.environment, "allowed_roots": list(configuration.allowed_roots),
            "database_hosts": list(configuration.database_hosts), "smb_hosts": list(configuration.smb_hosts),
            "cloud_hosts": list(configuration.cloud_hosts),
            "supported_kinds": kinds}


_SOURCE_CONFIGURATION_HELP = {
    "filesystem": "Choose a folder inside an approved directory on the scanner host.",
    "smb": "Choose an approved file server and enter a share name and relative subfolder without parent traversal.",
    "postgresql": "Choose an approved database host and check the database name, username, port, schema and table names.",
    "sqlite": "Choose a fixture database inside an approved directory. SQLite sources are available only in development.",
}
_SOURCE_CONNECTION_HELP = {
    "filesystem": "The folder could not be checked. Confirm it exists on the scanner host and the scanner account can read it.",
    "smb": "The share could not be checked. Confirm the server, share, subfolder and credentials, encrypted SMB support, and read access.",
    "postgresql": "The database safety check did not pass. Confirm connectivity, TLS, the database and schema, a dedicated unprivileged read-only account, and server-side query cancellation.",
    "sqlite": "The fixture database could not be checked. Confirm the file exists inside an approved directory and can be opened read-only.",
}

for _kind in ("mysql", "mssql"):
    _SOURCE_CONFIGURATION_HELP[_kind] = "Choose an approved database server and check the database, schema, tables and read-only credentials."
    _SOURCE_CONNECTION_HELP[_kind] = "The database safety check did not pass. Check private connectivity, the deployment trust certificate, SELECT-only permissions and query cancellation."
for _kind in ("s3", "azure_blob", "azure_table"):
    _SOURCE_CONFIGURATION_HELP[_kind] = "Choose an approved HTTPS storage endpoint and enter the bucket, container or table, scope and read-only credentials."
    _SOURCE_CONNECTION_HELP[_kind] = "The storage connection check did not pass. Check private connectivity, TLS trust, the selected scope and read/list permissions."


def source_connect_failure(db, user, kind, message):
    try:
        audit(db, user.username, "source_test_failed", {"attempt_id": m.uid(), "kind": kind})
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(503, "The local catalogue is unavailable. Try connecting the source again shortly.") from None
    raise HTTPException(422, message) from None


@app.post("/api/sources/connect", status_code=201)
def connect_source(body: s.SourceCreate, user=Depends(roles("admin")), db=Depends(database)):
    try:
        config = normalize_config(body.kind, body.config)
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        source_connect_failure(db, user, body.kind, _SOURCE_CONFIGURATION_HELP[body.kind])
    try:
        with source_database_lock(body.kind, config):
            result = test_connection(body.kind, config)
            check = validated_check(body.kind, result)
    except SourceBusy as exc:
        raise HTTPException(409, str(exc)) from None
    except Exception:
        source_connect_failure(db, user, body.kind, _SOURCE_CONNECTION_HELP[body.kind])
    # A failed check creates no source. Success and its audit records commit together.
    try:
        source = m.Source(name_encrypted=encrypt(body.name), kind=body.kind,
                          config_encrypted=encrypt(config), safety_validated=check["safety_validated"])
        db.add(source)
        db.flush()
        detail = {"source_id": source.id, "kind": source.kind}
        audit(db, user.username, "source_created", detail)
        audit(db, user.username, "source_test_passed", detail)
        response = {"source": source_json(source, user.role), "check": check}
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(503, "The source could not be saved to the local catalogue. Try connecting it again shortly.") from None
    return response


@app.post("/api/sources", status_code=201)
def create_source(body: s.SourceCreate, user=Depends(roles("admin")), db=Depends(database)):
    try:
        config = normalize_config(body.kind, body.config)
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        raise HTTPException(422, "Invalid source configuration or source is outside the deployment allowlist.") from None
    source = m.Source(name_encrypted=encrypt(body.name), kind=body.kind,
                      config_encrypted=encrypt(config), safety_validated=False)
    db.add(source)
    db.flush()
    audit(db, user.username, "source_created", {"source_id": source.id, "kind": source.kind})
    db.commit()
    return source_json(source, user.role)


def get_source(db, source_id, *, for_update=False):
    source = (db.scalar(select(m.Source).where(m.Source.id == source_id).with_for_update())
              if for_update else db.get(m.Source, source_id))
    if not source:
        raise HTTPException(404, "Source not found.")
    return source


@app.patch("/api/sources/{source_id}")
def update_source(source_id: str, body: s.SourceUpdate, user=Depends(roles("admin")), db=Depends(database)):
    source = get_source(db, source_id, for_update=True)
    config = decrypt(source.config_encrypted)
    if body.enabled is not None:
        source.enabled = body.enabled
    if body.full_scan_allowed is not None:
        if body.full_scan_allowed and source.kind == "azure_table":
            raise HTTPException(422, "Azure Tables currently supports bounded sampling only.")
        if body.full_scan_allowed and not body.workload_validation_note:
            raise HTTPException(422, "Full scanning requires documented hospital workload validation.")
        config["full_scan_allowed"] = body.full_scan_allowed
        config["workload_validation_note"] = body.workload_validation_note or ""
    source.config_encrypted = encrypt(config)
    audit(db, user.username, "source_updated", {"source_id": source.id})
    db.commit()
    return source_json(source, user.role)


@app.post("/api/sources/{source_id}/credentials")
def source_credentials(source_id: str, body: s.SourceCredentials, user=Depends(roles("admin")), db=Depends(database)):
    # The same source row lock is used when queueing scans and updating settings.
    # Keep a failed replacement from disrupting a working stored credential.
    source = get_source(db, source_id, for_update=True)
    original = decrypt(source.config_encrypted)
    allowed = {
        "postgresql": {"username", "password"}, "mysql": {"username", "password"},
        "mssql": {"username", "password"}, "smb": {"username", "password", "domain"},
        "s3": {"access_key_id", "secret_access_key", "session_token"},
        "azure_blob": {"sas_token"}, "azure_table": {"sas_token"},
    }.get(source.kind, set())
    if source.kind == "s3" and original.get("auth_mode") == "iam_role":
        allowed = set()
    if (not set(body.credentials) <= allowed or not allowed
            or any(len(value) > 16384 for value in body.credentials.values())):
        raise HTTPException(422, "Only credential fields supported by this source can be updated.")
    if db.scalar(select(m.Scan.id).where(m.Scan.source_id == source.id,
                                        m.Scan.status.in_(["queued", "running", "paused"]))):
        raise HTTPException(409, "Finish or cancel the source's active scan before updating credentials.")
    try:
        config = normalize_config(source.kind, {**original, **body.credentials})
        with source_database_lock(source.kind, config):
            check = validated_check(source.kind, test_connection(source.kind, config))
        # Credential normalization must not discard existing workload approval.
        config.update({key: original[key] for key in ("full_scan_allowed", "workload_validation_note")
                       if key in original})
    except SourceBusy as exc:
        raise HTTPException(409, str(exc)) from None
    except Exception:
        audit(db, user.username, "source_credentials_update_failed", {"source_id": source.id})
        db.commit()
        raise HTTPException(422, "Replacement credentials failed the connection or read-only safety check. The saved credentials were kept.") from None
    source.config_encrypted = encrypt(config)
    source.safety_validated = check["safety_validated"]
    audit(db, user.username, "source_credentials_updated", {"source_id": source.id})
    response = {"source": source_json(source, user.role), "check": check}
    db.commit()
    return response


@app.post("/api/sources/{source_id}/test")
def source_test(source_id: str, user=Depends(roles("admin", "operator")), db=Depends(database)):
    source = get_source(db, source_id, for_update=True)
    try:
        config = normalize_config(source.kind, decrypt(source.config_encrypted))
        with source_database_lock(source.kind, config):
            result = validated_check(source.kind, test_connection(source.kind, config))
    except SourceBusy as exc:
        # Contention says nothing about source permissions or connectivity.
        # Preserve a previously passed safety gate, and issue no source queries.
        raise HTTPException(409, str(exc)) from None
    except Exception:
        source.safety_validated = False
        audit(db, user.username, "source_test_failed", {"source_id": source.id})
        db.commit()
        raise HTTPException(422, "Connection or read-only safety checks failed. Check the configured account, allowlist, TLS and source availability locally.") from None
    source.safety_validated = result["safety_validated"]
    audit(db, user.username, "source_test_passed", {"source_id": source.id})
    db.commit()
    return result


def scan_json(scan, db):
    source = db.get(m.Source, scan.source_id)
    return {"id": scan.id, "source_id": scan.source_id, "source_name": decrypt(source.name_encrypted),
            "status": scan.status, "created_at": scan.created_at, "started_at": scan.started_at,
            "finished_at": scan.finished_at, "detector_version": scan.detector_version,
            "coverage": scan.coverage, "object_count": sum(scan.coverage.values()),
            "finding_count": db.scalar(select(func.count()).select_from(m.Finding).where(m.Finding.scan_id == scan.id)),
            "error": scan.error, "options": scan.options}


@app.get("/api/scans")
def scans(user=Depends(current_user), db=Depends(database)):
    return [scan_json(x, db) for x in db.scalars(select(m.Scan).order_by(m.Scan.created_at.desc()).limit(100))]


@app.post("/api/scans", status_code=201)
def create_scan(body: s.ScanCreate, user=Depends(roles("admin", "operator")), db=Depends(database)):
    source = db.scalar(select(m.Source).where(m.Source.id == body.source_id).with_for_update())
    if not source:
        raise HTTPException(404, "Source not found.")
    if not source.enabled:
        raise HTTPException(409, "Source is disabled.")
    if source.kind == "azure_table" and body.options.full_scan:
        raise HTTPException(422, "Azure Tables currently supports bounded sampling only.")
    try:
        normalize_config(source.kind, decrypt(source.config_encrypted))
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        raise HTTPException(409, "Source is no longer permitted by the deployment allowlist.") from None
    if not source.safety_validated:
        raise HTTPException(409, "Run and pass the source connection and safety check first.")
    policy = db.get(m.Policy, 1)
    if not policy or not policy.retention_approved:
        raise HTTPException(409, "An administrator must approve retention settings before scanning.")
    if not capabilities()["detector_available"]:
        raise HTTPException(409, "Required detector model is unavailable; scanning is disabled.")
    if body.options.full_scan and not decrypt(source.config_encrypted).get("full_scan_allowed"):
        raise HTTPException(409, "Full scanning requires source-specific workload validation.")
    if db.scalar(select(m.Scan.id).where(m.Scan.source_id == source.id, m.Scan.status.in_(["queued", "running", "paused"]))):
        raise HTTPException(409, "This source already has an active scan.")
    scan = m.Scan(source_id=source.id, options=body.options.model_dump())
    db.add(scan)
    db.flush()
    audit(db, user.username, "scan_queued", {"scan_id": scan.id, "source_id": source.id,
                                           "capture_evidence": body.options.capture_evidence})
    db.commit()
    return scan_json(scan, db)


def get_scan(db, scan_id):
    scan = db.get(m.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str, user=Depends(current_user), db=Depends(database)):
    return scan_json(get_scan(db, scan_id), db)


@app.post("/api/scans/{scan_id}/{action}")
def scan_action(scan_id: str, action: str, user=Depends(roles("admin", "operator")), db=Depends(database)):
    scan = db.scalar(select(m.Scan).where(m.Scan.id == scan_id).with_for_update())
    if not scan:
        raise HTTPException(404, "Scan not found.")
    if action == "pause" and scan.status in {"queued", "running"}:
        scan.status = "paused"
    elif action == "resume" and scan.status in {"paused", "interrupted"}:
        # Serialize resumptions with credential replacement on the same source.
        get_source(db, scan.source_id, for_update=True)
        # A worker owns a paused scan while its heartbeat is fresh. Interrupted scans restart
        # with a complete coverage manifest, not a misleading partial continuation.
        hb = scan.heartbeat_at
        hb = hb.replace(tzinfo=timezone.utc) if hb and hb.tzinfo is None else hb
        scan.status = "running" if scan.status == "paused" and hb and hb > m.now() - timedelta(seconds=30) else "queued"
        if scan.status == "queued":
            scan.heartbeat_at = None
    elif action == "cancel" and scan.status in {"queued", "running", "paused", "interrupted"}:
        scan.status = "cancelled"
        scan.finished_at = m.now()
    else:
        raise HTTPException(409, "Action is not valid for this scan state.")
    audit(db, user.username, "scan_" + action, {"scan_id": scan.id})
    db.commit()
    return scan_json(scan, db)


@app.get("/api/scans/{scan_id}/objects")
def objects(scan_id: str, user=Depends(current_user), db=Depends(database)):
    get_scan(db, scan_id)
    return [{"id": o.id, "location": decrypt(o.location_encrypted), "status": o.status, "reason": o.reason,
             "examined": o.examined, "unit": o.unit,
             "metadata": decrypt(o.metadata_encrypted),
             "findings": db.scalar(select(func.count()).select_from(m.Finding).where(m.Finding.object_id == o.id))}
            for o in db.scalars(select(m.ScanObject).where(m.ScanObject.scan_id == scan_id))]


def finding_json(f, db):
    obj = db.get(m.ScanObject, f.object_id)
    scan = db.get(m.Scan, f.scan_id)
    source = db.get(m.Source, scan.source_id)
    return {"id": f.id, "scan_id": f.scan_id, "source_name": decrypt(source.name_encrypted),
            "location": decrypt(obj.location_encrypted), "entity_type": f.entity_type,
            "classification": f.classification, "confidence": f.confidence, "match_count": f.match_count,
            "reason": decrypt(f.reason_encrypted), "segment": decrypt(f.segment_encrypted),
            "review_status": f.review_status, "detector_version": scan.detector_version, "coverage_status": obj.status}


@app.get("/api/findings")
def findings(scan_id: str | None = None, review_status: str | None = None, entity_type: str | None = None,
             user=Depends(current_user), db=Depends(database)):
    query = select(m.Finding)
    for column, value in [(m.Finding.scan_id, scan_id), (m.Finding.review_status, review_status), (m.Finding.entity_type, entity_type)]:
        if value:
            query = query.where(column == value)
    return [finding_json(f, db) for f in db.scalars(query.order_by(m.Finding.id))]


@app.get("/api/findings/{finding_id}/evidence")
def finding_evidence(finding_id: str, user=Depends(roles("admin", "reviewer")), db=Depends(database)):
    finding = db.get(m.Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    scan = db.get(m.Scan, finding.scan_id)
    captured = scan.options.get("capture_evidence") is True
    row = db.get(m.FindingEvidence, finding_id) if captured else None
    payload = decrypt(row.payload_encrypted) if row else {"examples": [], "truncated": False}
    examples = payload["examples"]
    # Commit the access record before returning evidence. Never copy values to
    # the audit trail, whose retention can exceed the finding retention policy.
    audit(db, user.username, "finding_evidence_viewed", {"finding_id": finding.id,
          "scan_id": finding.scan_id, "example_count": len(examples)})
    db.commit()
    notice = ("Evidence was not retained. Run a new scan with evidence capture enabled." if not captured else
              "No matching text is available for this finding; it may come from schema or contextual classification." if not examples else
              "Up to three bounded examples. Excerpts are extracted text and OCR may contain errors. Segment offsets are not original-file byte positions or stable record identifiers.")
    return {"finding_id": finding.id, "captured": captured, "available": bool(examples),
            "examples": examples, "truncated": payload.get("truncated", False), "notice": notice}


@app.patch("/api/findings/{finding_id}/review")
def review(finding_id: str, body: s.Review, user=Depends(current_user), db=Depends(database)):
    finding = db.get(m.Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    finding.review_status = body.status
    audit(db, user.username, "finding_reviewed", {"finding_id": finding.id, "status": body.status, "note": body.note})
    db.commit()
    return finding_json(finding, db)


@app.get("/api/compare")
def compare(baseline: str, current: str, user=Depends(current_user), db=Depends(database)):
    try:
        result = compare_scans(db, get_scan(db, baseline), get_scan(db, current))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, user.username, "scan_comparison", {"baseline": baseline, "current": current})
    db.commit()
    return result


@app.get("/api/overview")
def overview(user=Depends(current_user), db=Depends(database)):
    coverage = {}
    for status, count in db.execute(select(m.ScanObject.status, func.count()).group_by(m.ScanObject.status)):
        coverage[status] = count
    return {"sources": db.scalar(select(func.count()).select_from(m.Source)),
            "scans": db.scalar(select(func.count()).select_from(m.Scan)),
            "findings": db.scalar(select(func.count()).select_from(m.Finding)), "coverage": coverage,
            "recent_scans": [scan_json(x, db) for x in db.scalars(select(m.Scan).order_by(m.Scan.created_at.desc()).limit(8))],
            "capabilities": capabilities()}


@app.get("/api/settings")
def read_settings(user=Depends(current_user), db=Depends(database)):
    p = db.get(m.Policy, 1)
    return {"retention_days": p.retention_days, "audit_retention_days": p.audit_retention_days,
            "retention_approved": p.retention_approved, "environment": settings().environment,
            "detector_mode": settings().detector_mode, "capabilities": capabilities()}


@app.patch("/api/settings")
def update_settings(body: s.PolicyUpdate, user=Depends(roles("admin")), db=Depends(database)):
    p = db.get(m.Policy, 1)
    for key, value in body.model_dump().items():
        setattr(p, key, value)
    audit(db, user.username, "retention_updated", body.model_dump())
    db.commit()
    return read_settings(user, db)


@app.get("/api/audit")
def audit_log(user=Depends(roles("admin")), db=Depends(database)):
    return [{"id": x.id, "at": x.at, "actor": x.actor, "action": x.action, "detail": decrypt(x.detail_encrypted)}
            for x in db.scalars(select(m.Audit).order_by(m.Audit.at.desc()).limit(1000))]


@app.get("/api/scans/{scan_id}/export")
def export(scan_id: str, format: str = "json", report: str = "findings", user=Depends(current_user), db=Depends(database)):
    scan = get_scan(db, scan_id)
    rows = [finding_json(f, db) for f in db.scalars(select(m.Finding).where(m.Finding.scan_id == scan_id))]
    audit(db, user.username, "findings_exported", {"scan_id": scan_id, "format": format})
    db.commit()
    headers = {"Content-Disposition": f'attachment; filename="discovery-{scan.id}.{format if format in {"csv", "json"} else "txt"}"'}
    if format == "json":
        from fastapi.encoders import jsonable_encoder
        payload = {"scan": scan_json(scan, db), "objects": objects(scan_id, user, db), "findings": rows,
                   "notice": "Match counts are not unique patient counts. No matches does not establish absence of sensitive data."}
        return JSONResponse(jsonable_encoder(payload), headers=headers)
    if format != "csv":
        raise HTTPException(422, "Format must be csv or json.")
    output = io.StringIO()
    if report not in {"findings", "coverage"}:
        raise HTTPException(422, "Report must be findings or coverage.")
    keys = ["location", "entity_type", "classification", "match_count", "confidence", "coverage_status", "reason", "review_status", "detector_version"]
    if report == "coverage":
        rows = objects(scan_id, user, db)
        keys = ["location", "status", "reason", "examined", "unit", "findings"]
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    for row in rows:
        safe = {}
        for key in keys:
            value = str(row[key])
            safe[key] = "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value
        writer.writerow(safe)
    return Response(output.getvalue(), media_type="text/csv", headers=headers)


@app.get("/api/openapi.json")
def authenticated_schema(user=Depends(roles("admin"))):
    return app.openapi()


frontend = settings().frontend_dir
if (frontend / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")


@app.get("/{path:path}")
def frontend_app(path: str):
    if path.startswith("api/"):
        raise HTTPException(404, "Endpoint not found.")
    index = frontend / "index.html"
    if not index.is_file():
        return JSONResponse({"application": "Sentry Discovery", "detail": "Build the React frontend or run its Vite development server."})
    return FileResponse(index)
