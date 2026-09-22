import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now():
    return datetime.now(timezone.utc)


def uid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="reviewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name_encrypted: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(20))
    config_encrypted: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    safety_validated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    detector_version: Mapped[str] = mapped_column(Text, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class ScanObject(Base):
    __tablename__ = "scan_objects"
    __table_args__ = (UniqueConstraint("scan_id", "object_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    object_key: Mapped[str] = mapped_column(String(64))
    location_encrypted: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    examined: Mapped[int] = mapped_column(Integer, default=0)
    unit: Mapped[str] = mapped_column(String(20))
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_encrypted: Mapped[str] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    object_id: Mapped[str] = mapped_column(ForeignKey("scan_objects.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(80))
    classification: Mapped[str] = mapped_column(String(80))
    confidence: Mapped[float] = mapped_column(Float)
    match_count: Mapped[int] = mapped_column(Integer)
    reason_encrypted: Mapped[str] = mapped_column(Text)
    segment_encrypted: Mapped[str] = mapped_column(Text)
    review_status: Mapped[str] = mapped_column(String(20), default="needs_review")


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    payload_encrypted: Mapped[str] = mapped_column(Text)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(80))
    detail_encrypted: Mapped[str] = mapped_column(Text)


class Policy(Base):
    __tablename__ = "policy"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    audit_retention_days: Mapped[int] = mapped_column(Integer, default=365)
    retention_approved: Mapped[bool] = mapped_column(Boolean, default=False)
