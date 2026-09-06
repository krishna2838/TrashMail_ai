"""Chat assistant package — Ollama-powered explain and freeform modes."""

from __future__ import annotations

from app.chat.ollama_client import ask_ollama, ask_ollama_chat
from app.chat.prompts import build_explain_prompt, build_freeform_prompt

__all__ = ["ask_ollama", "ask_ollama_chat", "build_explain_prompt", "build_freeform_prompt"]
