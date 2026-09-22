"""Single-writer discovery worker with optional encrypted finding evidence."""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import timedelta, timezone
import os
from pathlib import Path
import signal
import threading
import time

from sqlalchemy import delete, select, text, update

from . import models as m
from .config import settings
from .db import engine, initialize, session
from .security import audit, decrypt, encrypt, stable_hash
from .sources import normalize_config
from .connectors import STRUCTURED_KINDS

STOP = threading.Event()
STATUSES = {"full", "sampled", "partial", "inaccessible", "unsupported", "excluded", "failed"}
RETENTION_EXPIRED = "retention_expired"
HOUSEKEEPING_INTERVAL_SECONDS = 30
RETENTION_BATCH_SIZE = 100
# PostgreSQL row locks coordinate CLI/API processes; this also serializes the
# housekeeping and scan writer in SQLite's development-only catalogue.
_CATALOG_WRITE_LOCK = threading.RLock()
_ACTIVE_SCANS = set()


def _approved_policy(db):
    return db.scalar(select(m.Policy).where(m.Policy.id == 1).with_for_update())


def _expired(scan, policy, at=None):
    if not policy or not policy.retention_approved:
        return False
    created = scan.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (at or m.now()) >= created + timedelta(days=policy.retention_days)


def _delete_scan_content(db, scan):
    # FindingEvidence is deleted by its database foreign-key cascade.
    db.execute(delete(m.Finding).where(m.Finding.scan_id == scan.id))
    db.execute(delete(m.ScanObject).where(m.ScanObject.scan_id == scan.id))
    scan.coverage = {}


def _expire_scan(db, scan, at):
    """Purge PHI immediately; leave a cancellation marker while a worker owns it."""
    _delete_scan_content(db, scan)
    leased = scan.heartbeat_at is not None and (scan.status in {"running", "paused"} or scan.error == RETENTION_EXPIRED)
    if scan.id in _ACTIVE_SCANS or leased:
        scan.status, scan.error, scan.finished_at = "cancelled", RETENTION_EXPIRED, at
        return False
    db.delete(scan)
    return True


def _scan_for_write(db, scan_id):
    policy = _approved_policy(db)
    scan = db.scalar(select(m.Scan).where(m.Scan.id == scan_id).with_for_update())
    if scan is not None and _expired(scan, policy):
        _expire_scan(db, scan, m.now())
        db.commit()
        return None, policy
    return scan, policy



def bounded_evidence(finding):
    """Allow only bounded display fields into the encrypted evidence payload."""
    examples = []
    truncated = False
    for item in finding.get("evidence", []):
        if not isinstance(item, dict) or not isinstance(item.get("value"), str) or not item["value"]:
            continue
        start, end = item.get("start"), item.get("end")
        if type(start) is not int or type(end) is not int or start < 0 or end <= start:
            continue
        if len(examples) == 3:
            truncated = True
            break
        value, excerpt = item["value"], item.get("excerpt", "")
        if not isinstance(excerpt, str):
            excerpt = ""
        truncated |= len(value) > 256 or len(excerpt) > 400 or end - start > len(value)
        examples.append({"value": value[:256], "excerpt": excerpt[:400], "start": start, "end": end,
                         "segment": str(item.get("segment", "document"))[:256], "offset_scope": "segment"})
    truncated |= int(finding.get("match_count", 0)) > len(examples)
    return {"examples": examples, "truncated": truncated}


def run_scan(scan_id: str):
    from .source_locks import SourceBusy, source_database_lock
    # Stored source configuration is already normalized. Lock acquisition itself
    # performs no source DNS, connection, query or detector work.
    with session() as db:
        scan = db.get(m.Scan, scan_id)
        if scan is None or scan.status != "queued":
            return
        source = db.get(m.Source, scan.source_id)
        kind, config = source.kind, decrypt(source.config_encrypted)
    try:
        with source_database_lock(kind, config):
            _owned_scan(scan_id)
    except SourceBusy:
        return  # The next worker pass can retry; keep the original queued run.
    except ValueError:
        # Malformed legacy identities must not crash the worker or contact a source.
        with _CATALOG_WRITE_LOCK, session() as db:
            scan, _ = _scan_for_write(db, scan_id)
            if scan is not None and scan.status == "queued":
                scan.status, scan.error, scan.finished_at = "failed", "source_no_longer_allowed", m.now()
                db.commit()


def _owned_scan(scan_id):
    with _CATALOG_WRITE_LOCK:
        if scan_id in _ACTIVE_SCANS:
            return
        _ACTIVE_SCANS.add(scan_id)
    try:
        _run_scan(scan_id)
    finally:
        with _CATALOG_WRITE_LOCK:
            _ACTIVE_SCANS.discard(scan_id)
            with session() as db:
                scan = db.scalar(select(m.Scan).where(m.Scan.id == scan_id).with_for_update())
                if scan is not None and scan.error == RETENTION_EXPIRED:
                    _delete_scan_content(db, scan)
                    db.delete(scan)
                    db.commit()
                elif scan is not None and scan.status == "paused":
                    # Also cover a pause arriving during detector initialization.
                    scan.heartbeat_at = None
                    scan.error = "scan_paused_worker_released_resume_restarts_inventory"
                    db.commit()


def _run_scan(scan_id: str):
    from .detection import Detector
    from .scanning import scan_source
    # Network/DNS preflight must not hold the housekeeping catalogue lock.
    with session() as db:
        scan = db.get(m.Scan, scan_id)
        if scan is None or scan.status != "queued":
            return
        source = db.get(m.Source, scan.source_id)
        kind, original, options = source.kind, decrypt(source.config_encrypted), dict(scan.options)
    normalization_failed = False
    try:
        config = normalize_config(kind, original)
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        normalization_failed = True
        config = {}
    with _CATALOG_WRITE_LOCK, session() as db:
        scan, policy = _scan_for_write(db, scan_id)
        if scan is None or scan.status != "queued":
            return
        source = db.get(m.Source, scan.source_id)
        if not source.enabled or not source.safety_validated or not policy or not policy.retention_approved:
            scan.status, scan.error, scan.finished_at = "failed", "source_or_retention_gate_not_satisfied", m.now()
            db.commit()
            return
        if normalization_failed:
            scan.status, scan.error, scan.finished_at = "failed", "source_no_longer_allowed", m.now()
            db.commit()
            return
        current_config = decrypt(source.config_encrypted)
        config.update({k: current_config[k] for k in ("full_scan_allowed", "workload_validation_note") if k in current_config})
        if options.get("full_scan") and not config.get("full_scan_allowed"):
            scan.status, scan.error, scan.finished_at = "failed", "full_scan_approval_revoked", m.now()
            db.commit()
            return
        _delete_scan_content(db, scan)
        scan.status, scan.started_at, scan.finished_at = "running", m.now(), None
        scan.error, scan.heartbeat_at = None, m.now()
        audit(db, "worker", "scan_started", {"scan_id": scan_id})
        db.commit()
    heartbeat_stop = threading.Event()
    database_pause_released = threading.Event()

    def heartbeat():
        while not heartbeat_stop.wait(5):
            try:
                with session() as db:
                    db.execute(update(m.Scan).where(m.Scan.id == scan_id).values(heartbeat_at=m.now()))
                    db.commit()
            except Exception:
                STOP.set()
                return

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()

    def control():
        while True:
            if STOP.is_set():
                return "cancelled"
            with _CATALOG_WRITE_LOCK, session() as db:
                row, _ = _scan_for_write(db, scan_id)
                state = row.status if row else "cancelled"
            if state == "paused" and kind in STRUCTURED_KINDS:
                database_pause_released.set()
                return "cancelled"
            if state != "paused":
                return "running" if state == "running" else "cancelled"
            time.sleep(0.25)

    iterator = None
    try:
        detector = Detector(mode=settings().detector_mode, model=settings().spacy_model)
        with _CATALOG_WRITE_LOCK, session() as db:
            scan, _ = _scan_for_write(db, scan_id)
            if scan is None or scan.status != "running":
                return
            scan.detector_version = detector.version
            db.commit()
        coverage = Counter()
        iterator = scan_source(kind, config, options, detector, control)
        for item in iterator:
            if control() == "cancelled":
                break
            status = item.get("status", "failed")
            if status not in STATUSES:
                status = "failed"
            with _CATALOG_WRITE_LOCK, session() as db:
                scan, policy = _scan_for_write(db, scan_id)
                if scan is None or scan.status != "running" or STOP.is_set():
                    break
                obj = m.ScanObject(scan_id=scan_id, object_key=stable_hash(scan.source_id + ":" + item["object_key"]),
                                   location_encrypted=encrypt(item["location"]), status=status,
                                   reason=item.get("reason"), examined=int(item.get("examined", 0)),
                                   unit=item.get("unit", "bytes"),
                                   fingerprint=stable_hash(item["fingerprint"]) if item.get("fingerprint") else None,
                                   metadata_encrypted=encrypt(item.get("metadata", {})))
                db.add(obj)
                db.flush()
                for finding in item.get("findings", []):
                    row = m.Finding(scan_id=scan_id, object_id=obj.id, entity_type=finding["entity_type"],
                                     classification=finding["classification"], confidence=float(finding["confidence"]),
                                     match_count=int(finding["match_count"]), reason_encrypted=encrypt(finding["reason"]),
                                     segment_encrypted=encrypt(finding.get("segment", "document")))
                    db.add(row)
                    if options.get("capture_evidence") is True:
                        payload = bounded_evidence(finding)
                        if payload["examples"]:
                            db.flush()
                            db.add(m.FindingEvidence(finding_id=row.id, payload_encrypted=encrypt(payload)))
                coverage[status] += 1
                scan.coverage, scan.heartbeat_at = dict(coverage), m.now()
                db.flush()
                # The object may take time to encrypt/flush. Recheck immediately
                # before commit so a batch spanning its deadline is rolled back.
                if _expired(scan, policy) or STOP.is_set():
                    db.rollback()
                    scan, _ = _scan_for_write(db, scan_id)
                    break
                db.commit()
        if iterator is not None:
            close = getattr(iterator, "close", None)
            if close is not None:
                close()
            iterator = None
        heartbeat_stop.set()
        thread.join(timeout=6)
        with _CATALOG_WRITE_LOCK, session() as db:
            scan, _ = _scan_for_write(db, scan_id)
            if scan is None:
                return
            if scan.error == RETENTION_EXPIRED:
                scan.status = "cancelled"
            elif STOP.is_set():
                scan.status, scan.error = "interrupted", "worker_stopped_resume_restarts_inventory"
            elif database_pause_released.is_set() and scan.status == "running":
                scan.status, scan.heartbeat_at = "queued", None
                scan.error = "database_pause_released_transaction_restarting_inventory"
            elif scan.status == "paused":
                scan.heartbeat_at = None
                scan.error = "scan_paused_worker_released_resume_restarts_inventory"
            elif scan.status != "cancelled":
                scan.status = "completed"
            scan.finished_at = None if scan.status in {"paused", "queued"} else m.now()
            audit(db, "worker", "scan_" + scan.status, {"scan_id": scan_id, "coverage": scan.coverage})
            db.commit()
    except Exception:
        with _CATALOG_WRITE_LOCK, session() as db:
            scan, _ = _scan_for_write(db, scan_id)
            if scan is not None:
                if scan.status != "cancelled":
                    scan.status, scan.error, scan.finished_at = "failed", "scan_failed_no_raw_error_logged", m.now()
                audit(db, "worker", "scan_" + scan.status, {"scan_id": scan_id})
                db.commit()
    finally:
        try:
            if iterator is not None:
                close = getattr(iterator, "close", None)
                if close is not None:
                    close()
        finally:
            heartbeat_stop.set()
            thread.join(timeout=6)


def purge_expired():
    """One bounded purge; never delete a scan while its writer owns the row."""
    with _CATALOG_WRITE_LOCK, session() as db:
        if engine().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout='1s'"))
            db.execute(text("SET LOCAL statement_timeout='5s'"))
        policy = _approved_policy(db)
        if not policy or not policy.retention_approved:
            return False
        at = m.now()
        cutoff = at - timedelta(days=policy.retention_days)
        scans = list(db.scalars(select(m.Scan).where(m.Scan.created_at <= cutoff)
                               .order_by(m.Scan.created_at).limit(RETENTION_BATCH_SIZE).with_for_update(skip_locked=True)))
        removed = deferred = 0
        for scan in scans:
            if _expire_scan(db, scan, at):
                removed += 1
            else:
                deferred += 1
        session_ids = list(db.scalars(select(m.LoginSession.token_hash).where(m.LoginSession.expires_at <= at)
                                     .limit(RETENTION_BATCH_SIZE)))
        audit_ids = list(db.scalars(select(m.Audit.id).where(m.Audit.at <= at - timedelta(days=policy.audit_retention_days))
                                   .limit(RETENTION_BATCH_SIZE)))
        if session_ids:
            db.execute(delete(m.LoginSession).where(m.LoginSession.token_hash.in_(session_ids)))
        if audit_ids:
            db.execute(delete(m.Audit).where(m.Audit.id.in_(audit_ids)))
        if removed or deferred:
            audit(db, "worker", "retention_purge", {"scans_deleted": removed, "active_scans_expired": deferred})
        db.commit()
        return any(count >= RETENTION_BATCH_SIZE for count in (len(scans), len(session_ids), len(audit_ids)))


@contextmanager
def retention_housekeeping(interval=HOUSEKEEPING_INTERVAL_SECONDS):
    """Purge independently of synchronous source reads, including a paused scan."""
    stop = threading.Event()
    # Do not begin scanning if the initial retention pass cannot finish.
    backlog = purge_expired()

    def housekeeping():
        delay = 0.1 if backlog else interval
        while not stop.wait(delay):
            try:
                delay = 0.1 if purge_expired() else interval
            except Exception:
                # Fail closed: the scan checks STOP before its next PHI write.
                STOP.set()
                return

    thread = threading.Thread(target=housekeeping, name="retention-housekeeping", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=6)


@contextmanager
def exclusive_worker():
    if engine().dialect.name == "postgresql":
        with engine().connect() as lock:
            if not lock.execute(text("SELECT pg_try_advisory_lock(746382091)")).scalar():
                raise RuntimeError("Another discovery worker is active.")
            try:
                yield
            finally:
                lock.execute(text("SELECT pg_advisory_unlock(746382091)"))
    else:
        import fcntl
        path = Path(engine().url.database + ".worker.lock")
        with path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Process at most one queued scan.")
    args = parser.parse_args()
    initialize()
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    with exclusive_worker():
        with session() as db:
            for scan in db.scalars(select(m.Scan).where(m.Scan.status.in_(["running", "paused"]))):
                scan.status, scan.error = "interrupted", "worker_restart_requires_explicit_resume"
                scan.heartbeat_at = None
            for scan in db.scalars(select(m.Scan).where(m.Scan.error == RETENTION_EXPIRED)):
                scan.heartbeat_at = None
            db.commit()
        with retention_housekeeping():
            while not STOP.is_set():
                with session() as db:
                    scan_id = db.scalar(select(m.Scan.id).where(m.Scan.status == "queued").order_by(m.Scan.created_at).limit(1))
                if scan_id:
                    run_scan(scan_id)
                if args.once:
                    break
                STOP.wait(1)


if __name__ == "__main__":
    main()
