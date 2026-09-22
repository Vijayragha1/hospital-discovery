"""Bootstrap local credentials without default accounts or passwords."""
import argparse
import getpass
import json
import os
from pathlib import Path
import secrets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    env = sub.add_parser("init-env")
    env.add_argument("--output", type=Path, default=Path(".env"))
    env.add_argument("--development", action="store_true")
    env.add_argument("--database-url")
    env.add_argument("--source-root", type=Path)
    admin = sub.add_parser("init-admin")
    admin.add_argument("--username", required=True)
    add = sub.add_parser("create-user")
    add.add_argument("--username", required=True)
    add.add_argument("--role", choices=["admin", "operator", "reviewer"], default="reviewer")
    sub.add_parser("purge-expired")
    restore = sub.add_parser("prepare-restored-catalog", description=(
        "Prepare an isolated restored catalog with its original APP_SECRET_KEY and SESSION_SECRET. "
        "Keep API, worker and ingress stopped and source routes blocked until preparation succeeds; "
        "this command cannot attest those operating conditions."))
    restore.add_argument("--retention-days", type=int, required=True)
    restore.add_argument("--audit-retention-days", type=int, required=True)
    restore.add_argument("--confirm-isolated-restore", action="store_true", required=True,
                         help="Confirm stopped services, blocked source routes and original application/session secrets.")
    sub.add_parser("capabilities")
    args = parser.parse_args()
    if args.command == "init-env":
        from cryptography.fernet import Fernet
        if args.output.exists():
            parser.error("Refusing to replace an existing environment file.")
        if not args.development and not args.database_url:
            parser.error("Production requires --database-url; use deployment configuration tooling for containers.")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        database = args.database_url or "sqlite:///" + str(args.output.parent.resolve() / "discovery.db")
        roots = [str(args.source_root.resolve())] if args.source_root else []
        values = {"ENVIRONMENT": "development" if args.development else "production", "DATABASE_URL": database,
                  "APP_SECRET_KEY": Fernet.generate_key().decode(), "SESSION_SECRET": secrets.token_urlsafe(48),
                  "DETECTOR_MODE": "rules" if args.development else "presidio", "SPACY_MODEL": "en_core_web_lg",
                  "SECURE_COOKIES": "false" if args.development else "true", "SOURCE_ALLOWED_ROOTS": json.dumps(roots)}
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            for key, value in values.items():
                stream.write(key + "='" + value.replace("'", "\\'") + "'\n")
        print("Environment configuration created. Keep it local and out of source control.")
        return
    if args.command == "prepare-restored-catalog":
        from .recovery import RecoveryPreparationError, prepare_restored_catalog
        try:
            result = prepare_restored_catalog(retention_days=args.retention_days,
                audit_retention_days=args.audit_retention_days,
                confirm_isolated_restore=args.confirm_isolated_restore)
        except RecoveryPreparationError as exc:
            parser.exit(1, "Restore preparation failed (" + str(exc) + "). "
                        "Keep API, worker and ingress stopped and source routes blocked.\n")
        print(json.dumps(result, sort_keys=True))
        return
    from .db import initialize, session
    from .models import Policy, User
    from .security import audit, hash_password
    from sqlalchemy import select
    initialize()
    if args.command in {"init-admin", "create-user"}:
        password = getpass.getpass("Password (at least 12 characters): ")
        if password != getpass.getpass("Confirm password: "):
            parser.error("Passwords do not match.")
        with session() as db:
            if db.scalar(select(User).where(User.username == args.username)):
                parser.error("User already exists; credentials were not changed.")
            role = "admin" if args.command == "init-admin" else args.role
            db.add(User(username=args.username, password_hash=hash_password(password), role=role))
            if not db.get(Policy, 1):
                db.add(Policy(id=1))
            audit(db, "local-cli", "user_created", {"username": args.username, "role": role})
            db.commit()
        print("User created. Approve retention and validate sources before scanning.")
    elif args.command == "purge-expired":
        from .worker import purge_expired
        purge_expired()
        print("Configured retention policy applied. Backup retention must be applied separately.")
    else:
        from .main import capabilities
        print(json.dumps(capabilities(), indent=2))


if __name__ == "__main__":
    main()
