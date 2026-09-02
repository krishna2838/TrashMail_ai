"""Database persistence package for TrashMail AI."""

from __future__ import annotations

from app.db.history import (
    Investigation,
    get_investigation,
    init_db,
    list_investigations,
    save_investigation,
)

__all__ = [
    "Investigation",
    "init_db",
    "save_investigation",
    "list_investigations",
    "get_investigation",
]
