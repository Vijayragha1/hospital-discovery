from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class SourceCreate(Input):
    name: str = Field(min_length=1, max_length=150)
    kind: Literal["filesystem", "smb", "postgresql", "mysql", "mssql", "s3", "azure_blob", "azure_table", "sqlite"]
    config: dict
    safety_validated: bool = False


class ScanOptions(Input):
    max_file_bytes: int = Field(default=20 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    max_files: int = Field(default=10000, ge=1, le=100000)
    max_text_chars: int = Field(default=1000000, ge=100, le=10000000)
    table_sample_rows: int = Field(default=1000, ge=1, le=1000)
    batch_size: int = Field(default=100, ge=1, le=100)
    statement_timeout_ms: int = Field(default=5000, ge=100, le=5000)
    lock_timeout_ms: int = Field(default=1000, ge=100, le=1000)
    full_scan: bool = False
    capture_evidence: bool = False


class ScanCreate(Input):
    source_id: str
    options: ScanOptions = Field(default_factory=ScanOptions)


class Review(Input):
    status: Literal["confirmed", "false_positive", "needs_review"]
    note: str = Field(default="", max_length=2000)


class PolicyUpdate(Input):
    retention_days: int = Field(ge=1, le=3650)
    audit_retention_days: int = Field(ge=1, le=3650)
    retention_approved: bool


class UserCreate(Input):
    username: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["admin", "operator", "reviewer"]


class SourceUpdate(Input):
    enabled: bool | None = None
    full_scan_allowed: bool | None = None
    workload_validation_note: str | None = Field(default=None, max_length=1000)


class SourceCredentials(Input):
    credentials: dict[str, str] = Field(min_length=1, max_length=3)
