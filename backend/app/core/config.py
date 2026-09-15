"""Application configuration using pydantic-settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Core application settings."""

    APP_NAME: str = "TraceMail AI"
    MAX_EMAIL_SIZE_BYTES: int = 5_000_000
    MAX_BATCH_FILES: int = 20
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]
    VIRUSTOTAL_API_KEY: str = ""
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo5j"
    NEO4J_PASSWORD: str = "trashmail8856"
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_PRIMARY_MODEL: str = "qwen2.5:7b"
    OLLAMA_FALLBACK_MODEL: str = "qwen2.5:3b"
    OLLAMA_TIMEOUT_SECONDS: int = 45

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
