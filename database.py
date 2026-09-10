"""
database.py

Sets up the SQLAlchemy engine and session for IDShield.

WHY WAL MODE:
The Attack Lab will fire many requests at the backend in a short window
(e.g. 50 login attempts in 10 seconds). SQLite's default journal mode
takes an exclusive lock on every write, which causes "database is locked"
errors under that kind of burst traffic. WAL (Write-Ahead Logging) mode
allows concurrent readers alongside a single writer and is far more
tolerant of the demo's traffic pattern. This is a known, defensible
choice to explain to a jury if asked "why SQLite for a fraud system?"
"""

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

# Ensure the data/ directory exists before SQLAlchemy tries to create the
# .db file inside it — matters on platforms (e.g. a fresh Render deploy)
# where the repo might not carry an empty directory through git, since
# git doesn't track empty folders by default.
Path("data").mkdir(exist_ok=True)

DATABASE_URL = "sqlite:///./data/idshield.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # needed for FastAPI's threaded requests
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Enable WAL mode and foreign key enforcement on every new connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a DB session and guarantees it closes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables. Called once at app startup."""
    import models  # noqa: F401 (ensures models are registered on Base before create_all)
    Base.metadata.create_all(bind=engine)
