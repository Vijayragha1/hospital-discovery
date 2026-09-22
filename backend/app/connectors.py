"""Shared connector categories and the safe projection of connection diagnostics."""

LIVE_KINDS = ("filesystem", "smb", "postgresql", "mysql", "mssql", "s3", "azure_blob", "azure_table")
DATABASE_KINDS = frozenset({"postgresql", "mysql", "mssql"})
CLOUD_KINDS = frozenset({"s3", "azure_blob", "azure_table"})
STRUCTURED_KINDS = DATABASE_KINDS | {"sqlite", "azure_table"}
SECRET_FIELDS = frozenset({"password", "dsn", "token", "secret", "access_key_id", "secret_access_key",
                           "session_token", "sas_token", "connection_string", "account_key"})


def validated_check(kind: str, result: dict) -> dict:
    """Do not trust truthy flags or return arbitrary driver diagnostics to a browser."""
    required = {"ok", "safety_validated"}
    required.add("read_only_operations" if kind in CLOUD_KINDS | {"smb"} else "read_only")
    if kind in DATABASE_KINDS:
        required.add("cancellation_verified")
    if not isinstance(result, dict) or any(result.get(key) is not True for key in required):
        raise ValueError("source_safety_check_incomplete")
    check = {key: result[key] for key in ("ok", "safety_validated", "read_only", "read_only_operations", "cancellation_verified")
             if isinstance(result.get(key), bool)}
    if kind in CLOUD_KINDS | {"smb"}:
        check["note"] = "Confirm the account has read-only source permissions during hospital acceptance."
    return check
