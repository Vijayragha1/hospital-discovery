from functools import lru_cache

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


@lru_cache
def engine():
    url = settings().database_url
    result = create_engine(url, pool_pre_ping=True, echo=False,
                           connect_args={"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {})
    if url.startswith("sqlite"):
        @event.listens_for(result, "connect")
        def pragmas(connection, record):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
    return result


def session():
    return sessionmaker(engine(), expire_on_commit=False)()


def initialize():
    from . import models  # noqa: F401
    if engine().dialect.name == "postgresql":
        # API and worker may start together on a fresh offline deployment.
        with engine().begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(746382092)"))
            Base.metadata.create_all(connection)
    else:
        Base.metadata.create_all(engine())
