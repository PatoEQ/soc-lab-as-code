"""Persistence for IOC lookups (lookup history).

DATABASE_URL selects the backend:
  - not set: in-memory SQLite (local development and tests, lost on restart)
  - postgresql+psycopg://user:password@host:5432/dbname (docker compose)
"""

import os
from datetime import datetime, timezone

from sqlalchemy import DateTime, Engine, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import StaticPool

DEFAULT_URL = "sqlite+pysqlite:///:memory:"


class Base(DeclarativeBase):
    pass


class Lookup(Base):
    __tablename__ = "ioc_lookups"

    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(253), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16))
    verdict: Mapped[str | None] = mapped_column(String(32))
    score: Mapped[int | None]
    source: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


_engine: Engine | None = None


def get_engine() -> Engine:
    """Create the engine and the tables the first time they are needed."""
    global _engine
    if _engine is None:
        url = os.getenv("DATABASE_URL", DEFAULT_URL)
        if url == DEFAULT_URL:
            # One shared in-memory database for every request in this process
            engine = create_engine(
                url, connect_args={"check_same_thread": False}, poolclass=StaticPool
            )
        else:
            engine = create_engine(url, pool_pre_ping=True)
        Base.metadata.create_all(engine)
        _engine = engine
    return _engine


def record_lookup(
    value: str,
    ioc_type: str,
    verdict: str | None = None,
    score: int | None = None,
    source: str | None = None,
) -> None:
    with Session(get_engine()) as session:
        session.add(
            Lookup(value=value, ioc_type=ioc_type, verdict=verdict, score=score, source=source)
        )
        session.commit()


def list_lookups(limit: int, value: str | None = None) -> list[Lookup]:
    query = select(Lookup).order_by(Lookup.created_at.desc(), Lookup.id.desc()).limit(limit)
    if value:
        query = query.where(Lookup.value == value)
    with Session(get_engine()) as session:
        return list(session.scalars(query))
