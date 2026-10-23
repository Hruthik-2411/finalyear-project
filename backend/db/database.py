"""Engine / session handling. SQLite file in data/, reset = drop + recreate + reseed."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from backend.config import get_config
from backend.db.models import Base

_engine = None
_SessionLocal = None
_lock = threading.RLock()


def engine():
    global _engine, _SessionLocal
    with _lock:
        if _engine is None:
            path = get_config()["db_path"]
            url = "sqlite://" if path == ":memory:" else f"sqlite:///{path}"
            kwargs = {"connect_args": {"check_same_thread": False}}
            if path == ":memory:":
                from sqlalchemy.pool import StaticPool

                kwargs["poolclass"] = StaticPool
            _engine = create_engine(url, **kwargs)

            @event.listens_for(_engine, "connect")
            def _pragma(dbapi_conn, _):  # pragma: no cover - sqlite tuning
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.close()

            _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
        return _engine


def SessionLocal() -> Session:
    engine()
    return _SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def create_all() -> None:
    Base.metadata.create_all(engine())


def drop_all() -> None:
    Base.metadata.drop_all(engine())


def reset_engine() -> None:
    """Forget the engine (used by tests that switch db_path)."""
    global _engine, _SessionLocal
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _SessionLocal = None
