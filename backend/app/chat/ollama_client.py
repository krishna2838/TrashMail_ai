"""Ollama LLM client with primary/fallback model strategy.

Uses httpx async client to call the local Ollama REST API.
Primary model: qwen2.5:7b — Fallback: qwen2.5:3b (faster, lower quality).
If both fail (Ollama not running), raises OllamaUnavailableError.
"""

from __future__ import annotations

import httpx

from app.core.config import settings


class OllamaUnavailableError(Exception):
    """Raised when neither the primary nor fallback Ollama model responds."""


async def _generate(prompt: str, system: str, model: str) -> str:
    """Send a single generate request to the Ollama API."""
    async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT_SECONDS) as client:
        resp = await client.post(
            f"{settings.OLLAMA_URL}/api/generate",
            json={
                "model": model,
                "system": system,
                "prompt": prompt,
                "stream": False,
            },
        )
        resp.raise_for_status()
        return resp.json()["response"]


async def ask_ollama(prompt: str, system: str) -> str:
    """Try the primary model first, fall back to the smaller model on timeout/error.

    Raises OllamaUnavailableError if both models fail.
    """
    try:
        return await _generate(prompt, system, settings.OLLAMA_PRIMARY_MODEL)
    except (httpx.TimeoutException, httpx.HTTPStatusError):
        try:
            return await _generate(prompt, system, settings.OLLAMA_FALLBACK_MODEL)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError) as exc:
            raise OllamaUnavailableError(
                "Chat assistant is unavailable — check that Ollama is running locally."
            ) from exc
    except httpx.ConnectError as exc:
        raise OllamaUnavailableError(
            "Chat assistant is unavailable — check that Ollama is running locally."
        ) from exc
