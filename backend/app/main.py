"""Main FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_analyze import router as analyze_router
from app.api.routes_batch import router as batch_router
from app.api.routes_chat import router as chat_router
from app.api.routes_graph import router as graph_router
from app.api.routes_history import router as history_router
from app.api.routes_reports import router as reports_router
from app.core.config import settings
from app.db.history import init_db
from app.ml.classifier import get_model


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan context manager to pre-warm ML model and initialize SQLite DB."""
    # Pre-load ML model into memory
    get_model()
    # Initialize SQLite database schema
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Phishing/Scam Email Detection and Sender-Tracing Backend API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "app": settings.APP_NAME}


# Mount API routers
app.include_router(analyze_router, prefix="/api")
app.include_router(batch_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(graph_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
