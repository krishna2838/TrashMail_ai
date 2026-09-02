"""Local investigation history persistence using SQLite and SQLModel."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlmodel import Field, Session, SQLModel, create_engine, select

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).parent
DB_PATH = DB_DIR / "history.sqlite3"
SQLITE_URL = f"sqlite:///{DB_PATH}"

# Connect args for SQLite to allow multi-threaded access in FastAPI
engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})


class Investigation(SQLModel, table=True):
    """Investigation model storing persistent email analysis records."""

    id: str = Field(primary_key=True, description="SHA256 email_hash")
    subject: str = Field(default="(No Subject)")
    sender: str = Field(default="Unknown")
    verdict: str = Field(default="Unknown")
    risk_score: int = Field(default=0)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    full_result_json: str = Field(description="JSON serialized analysis result")


def init_db() -> None:
    """Create SQLite database tables if they do not exist."""
    try:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        SQLModel.metadata.create_all(engine)
        logger.info("Initialized investigation history SQLite database at %s", DB_PATH)
    except Exception as exc:
        logger.error("Failed to initialize SQLite database: %s", exc)


# Auto-create tables on import
init_db()


def save_investigation(analysis: dict[str, Any]) -> None:
    """Persist or update an investigation record in SQLite."""
    email_hash = analysis.get("email_hash")
    if not email_hash:
        logger.warning("Cannot save investigation: missing 'email_hash'")
        return

    subject = analysis.get("subject") or "(No Subject)"
    sender = analysis.get("sender") or "Unknown"
    verdict = analysis.get("verdict") or "Unknown"
    risk_score = int(analysis.get("risk_score", 0))

    try:
        full_json = json.dumps(analysis)
    except Exception as exc:
        logger.warning("Could not serialize analysis dict to JSON: %s", exc)
        full_json = "{}"

    try:
        with Session(engine) as session:
            existing = session.exec(
                select(Investigation).where(Investigation.id == email_hash)
            ).first()

            if existing:
                existing.subject = subject
                existing.sender = sender
                existing.verdict = verdict
                existing.risk_score = risk_score
                existing.analyzed_at = datetime.now(timezone.utc)
                existing.full_result_json = full_json
                session.add(existing)
            else:
                record = Investigation(
                    id=email_hash,
                    subject=subject,
                    sender=sender,
                    verdict=verdict,
                    risk_score=risk_score,
                    analyzed_at=datetime.now(timezone.utc),
                    full_result_json=full_json,
                )
                session.add(record)
            session.commit()
            logger.info("Saved investigation %s to history database", email_hash)
    except Exception as exc:
        logger.error("Failed to save investigation to SQLite history: %s", exc)


def list_investigations(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent investigation summaries (without heavy full_result_json)."""
    try:
        with Session(engine) as session:
            statement = (
                select(
                    Investigation.id,
                    Investigation.subject,
                    Investigation.sender,
                    Investigation.verdict,
                    Investigation.risk_score,
                    Investigation.analyzed_at,
                )
                .order_by(Investigation.analyzed_at.desc())
                .limit(limit)
            )
            results = session.exec(statement).all()

            investigations = []
            for row in results:
                # row can be a tuple or row object
                r_id, r_subject, r_sender, r_verdict, r_risk, r_time = row
                investigations.append({
                    "id": r_id,
                    "email_hash": r_id,
                    "subject": r_subject,
                    "sender": r_sender,
                    "verdict": r_verdict,
                    "risk_score": r_risk,
                    "analyzed_at": r_time.isoformat() if hasattr(r_time, "isoformat") else str(r_time),
                })
            return investigations
    except Exception as exc:
        logger.error("Failed to list investigations from SQLite: %s", exc)
        return []


def get_investigation(id: str) -> Optional[dict[str, Any]]:
    """Retrieve full analysis result dictionary by email_hash."""
    try:
        with Session(engine) as session:
            record = session.exec(
                select(Investigation).where(Investigation.id == id)
            ).first()

            if not record:
                return None

            return json.loads(record.full_result_json)
    except Exception as exc:
        logger.error("Failed to retrieve investigation %s from SQLite: %s", id, exc)
        return None
