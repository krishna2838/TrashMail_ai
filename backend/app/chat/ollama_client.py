"""Ollama LLM client with primary/fallback model strategy.

Uses httpx async client to call the local Ollama REST API.
Primary model: qwen2.5:7b — Fallback: qwen2.5:3b (faster, lower quality).
If both fail (Ollama not running), raises OllamaUnavailableError.
"""

from __future__ import annotations

import logging
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


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
        print(f"[OLLAMA GENERATE] Response produced by model: {model}", flush=True)
        logger.info("[OLLAMA GENERATE] Response produced by model: %s", model)
        return resp.json()["response"]


async def ask_ollama(prompt: str, system: str) -> str:
    """Try the primary model first, fall back to the smaller model on timeout/error.

    Raises OllamaUnavailableError if both models fail.
    """
    try:
        return await _generate(prompt, system, settings.OLLAMA_PRIMARY_MODEL)
    except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
        logger.warning(
            "[OLLAMA GENERATE] Primary model %s failed (%s), falling back to %s",
            settings.OLLAMA_PRIMARY_MODEL,
            type(exc).__name__,
            settings.OLLAMA_FALLBACK_MODEL,
        )
        try:
            return await _generate(prompt, system, settings.OLLAMA_FALLBACK_MODEL)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError) as fallback_exc:
            raise OllamaUnavailableError(
                "Chat assistant is unavailable — check that Ollama is running locally."
            ) from fallback_exc
    except httpx.ConnectError as exc:
        raise OllamaUnavailableError(
            "Chat assistant is unavailable — check that Ollama is running locally."
        ) from exc


async def _chat(messages: list[dict], model: str) -> str:
    """Send a multi-turn chat request to the Ollama /api/chat endpoint."""
    async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT_SECONDS) as client:
        resp = await client.post(
            f"{settings.OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
            },
        )
        resp.raise_for_status()
        print(f"[OLLAMA CHAT] Response produced by model: {model}", flush=True)
        logger.info("[OLLAMA CHAT] Response produced by model: %s", model)
        return resp.json()["message"]["content"]


async def ask_ollama_chat(messages: list[dict], model: str | None = None) -> str:
    """Multi-turn chat via Ollama's /api/chat endpoint.

    `messages` is a list of {"role": "system"|"user"|"assistant", "content": str} dicts, oldest first.
    Tries primary model first, falls back to fallback model on timeout/status error.
    Raises OllamaUnavailableError if both fail or connection fails.
    """
    primary = model or settings.OLLAMA_PRIMARY_MODEL
    try:
        return await _chat(messages, primary)
    except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
        logger.warning(
            "[OLLAMA CHAT] Primary model %s failed (%s), falling back to %s",
            primary,
            type(exc).__name__,
            settings.OLLAMA_FALLBACK_MODEL,
        )
        try:
            return await _chat(messages, settings.OLLAMA_FALLBACK_MODEL)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError) as fallback_exc:
            raise OllamaUnavailableError(
                "Chat assistant is unavailable — check that Ollama is running locally."
            ) from fallback_exc
    except httpx.ConnectError as exc:
        raise OllamaUnavailableError(
            "Chat assistant is unavailable — check that Ollama is running locally."
        ) from exc

