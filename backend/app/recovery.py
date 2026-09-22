"""Trusted offline catalog preparation; never opens a configured discovery source.

The operator must keep API, worker and ingress stopped and source routes blocked.
The worker advisory lock adds a local catalog guard; it does not attest those
operating conditions. Use the original APP_SECRET_KEY and SESSION_SECRET.
"""
from datetime import timedelta
import hashlib
import hmac

from sqlalchemy import delete, func, inspect, select, update

from . import models as m
from .db import Base, engine, session
from .security import audit, decrypt, encrypt, stable_hash
from .worker import exclusive_worker, purge_expired


RESTORE_QUARANTINE_REASON = "restored_catalog_requires_new_validated_scan"
RESUMABLE_STATUSES = ("queued", "running", "paused", "interrupted")


class RecoveryPreparationError(RuntimeError):
    """Only fixed, values-free reason codes may cross the CLI boundary."""


def _preflight(db):
    # Iterate bounded result buffers; decrypted values live only during validation.
    fields = ((m.Source.name_encrypted, str), (m.Source.config_encrypted, dict),
              (m.ScanObject.location_encrypted, str), (m.ScanObject.metadata_encrypted, dict),
              (m.Finding.reason_encrypted, str), (m.Finding.segment_encrypted, str),
              (m.FindingEvidence.payload_encrypted, dict), (m.Audit.detail_encrypted, dict))
    checked = 0
    for column, expected_type in fields:
        for ciphertext in db.scalars(select(column).execution_options(yield_per=100)):
            if not isinstance(decrypt(ciphertext), expected_type):
                raise RecoveryPreparationError("encrypted_catalog_shape_invalid")
            checked += 1
    identities = 0
    statement = select(m.Scan.source_id, m.ScanObject.location_encrypted, m.ScanObject.object_key).join(
        m.ScanObject, m.ScanObject.scan_id == m.Scan.id).execution_options(yield_per=100)
    for source_id, location_ciphertext, object_key in db.execute(statement):
        location_hash = hashlib.sha256(decrypt(location_ciphertext).encode("utf-8", errors="surrogatepass")).hexdigest()
        expected = stable_hash(source_id + ":" + location_hash)
        if not hmac.compare_digest(expected, object_key):
            raise RecoveryPreparationError("catalog_identity_key_mismatch")
        identities += 1
    if db.scalar(select(m.Scan.id).where(m.Scan.status.not_in(
            (*RESUMABLE_STATUSES, "completed", "cancelled", "failed"))).limit(1)):
        raise RecoveryPreparationError("unsupported_scan_state")
    return checked, identities


def _expired_count(retention_days, audit_retention_days):
    with session() as db:
        at = m.now()
        return sum(db.scalar(select(func.count()).select_from(model).where(predicate)) for model, predicate in (
            (m.Scan, m.Scan.created_at <= at - timedelta(days=retention_days)),
            (m.LoginSession, m.LoginSession.expires_at <= at),
            (m.Audit, m.Audit.at <= at - timedelta(days=audit_retention_days))))


def prepare_restored_catalog(*, retention_days, audit_retention_days, confirm_isolated_restore=False):
    """Quarantine a restored catalog, then drain the explicitly approved policy.

Quarantine commits before purge. A later cleanup failure leaves sources disabled
and sessions/jobs invalidated, and returns no success. Existing secret material,
source IDs and surviving finding/object/review identities are never regenerated.
"""
    if confirm_isolated_restore is not True:
        raise RecoveryPreparationError("isolated_restore_confirmation_required")
    if any(type(value) is not int or not 1 <= value <= 3650 for value in (retention_days, audit_retention_days)):
        raise RecoveryPreparationError("approved_retention_out_of_range")
    try:
        if not set(Base.metadata.tables).issubset(inspect(engine()).get_table_names()):
            raise RecoveryPreparationError("matching_catalog_schema_required")
        with exclusive_worker():
            with session() as db:
                checked, identities = _preflight(db)
                sessions_revoked = db.execute(delete(m.LoginSession)).rowcount
                users_disabled = db.execute(update(m.User).values(active=False)).rowcount
                sources_disabled = 0
                for source in db.scalars(select(m.Source).execution_options(yield_per=100)):
                    config = decrypt(source.config_encrypted)
                    # Workload approval is tied to the prior deployment context.
                    config.pop("full_scan_allowed", None)
                    config.pop("workload_validation_note", None)
                    source.config_encrypted = encrypt(config)
                    source.enabled = source.safety_validated = False
                    sources_disabled += 1
                    if sources_disabled % 100 == 0:
                        db.flush()
                at = m.now()
                scans_quarantined = db.execute(update(m.Scan).where(m.Scan.status.in_(RESUMABLE_STATUSES)).values(
                    status="cancelled", error=RESTORE_QUARANTINE_REASON, finished_at=at, heartbeat_at=None)).rowcount
                db.execute(update(m.Scan).where(m.Scan.heartbeat_at.is_not(None)).values(heartbeat_at=None))
                policy = db.get(m.Policy, 1)
                if policy is None:
                    policy = m.Policy(id=1)
                    db.add(policy)
                policy.retention_days, policy.audit_retention_days = retention_days, audit_retention_days
                policy.retention_approved = True
                summary = {"sessions_revoked": sessions_revoked, "users_disabled": users_disabled,
                           "sources_disabled": sources_disabled,
                           "scans_quarantined": scans_quarantined, "encrypted_fields_verified": checked,
                           "object_identities_verified": identities,
                           "retention_days": retention_days, "audit_retention_days": audit_retention_days}
                audit(db, "local-cli", "restored_catalog_quarantined", summary)
                db.commit()
            passes = 0
            while True:
                before = _expired_count(retention_days, audit_retention_days)
                purge_expired()
                passes += 1
                remaining = _expired_count(retention_days, audit_retention_days)
                if not remaining:
                    break
                if remaining >= before:
                    raise RecoveryPreparationError("retention_cleanup_did_not_progress")
            with session() as db:
                policy = db.get(m.Policy, 1)
                if (not policy or not policy.retention_approved or policy.retention_days != retention_days
                        or policy.audit_retention_days != audit_retention_days
                        or db.scalar(select(m.LoginSession.token_hash).limit(1))
                        or db.scalar(select(m.User.id).where(m.User.active).limit(1))
                        or db.scalar(select(m.Source.id).where(m.Source.enabled | m.Source.safety_validated).limit(1))
                        or db.scalar(select(m.Scan.id).where(m.Scan.status.in_(RESUMABLE_STATUSES)).limit(1))):
                    raise RecoveryPreparationError("catalog_quarantine_changed_during_preparation")
                summary.update({"status": "offline_preparation_completed", "retention_passes": passes,
                                "remaining_expired_records": 0, "sources_require_revalidation": True,
                                "fresh_administrator_required": True,
                                "object_identity_key_verified": identities > 0,
                                "session_secret_verification": "verified_from_stored_object_identities" if identities
                                    else "not_verifiable_no_stored_objects"})
                audit(db, "local-cli", "restored_catalog_prepared", summary)
                db.commit()
            return summary
    except RecoveryPreparationError:
        raise
    except Exception:
        # SQL drivers and cryptography exceptions may include unsafe details.
        # Preserve no raw exception text, source path or encrypted payload.
        raise RecoveryPreparationError("catalog_preparation_failed") from None
