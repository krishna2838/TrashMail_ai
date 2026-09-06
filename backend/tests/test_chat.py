"""Unit tests for chat endpoints — Ollama calls mocked."""

from __future__ import annotations

import asyncio
import httpx
import pytest
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient

from app.chat.ollama_client import OllamaUnavailableError, ask_ollama_chat
from app.chat.prompts import build_explain_prompt, build_freeform_prompt
from app.main import app

client = TestClient(app)


# ── Prompt builder tests ─────────────────────────────────────────────


def test_build_explain_prompt_excludes_body():
    """Ensure the explain prompt only includes scored results, not raw email body."""
    analysis = {
        "verdict": "Phishing/Scam",
        "risk_score": 95,
        "ml_phishing_probability": 0.97,
        "indicators": ["DKIM failed", "Suspicious attachment"],
        "body_text": "This is UNTRUSTED email body text that should NOT appear",
        "subject": "URGENT! Click here now!",
        "origin_geo": {"country": "Germany", "city": "Berlin", "ip": "1.2.3.4"},
        "threat_intel": {
            "originating_ip_reputation": {"available": True, "reputation": "malicious", "malicious": 5},
            "domain_reputations": {"evil.com": {"available": True, "reputation": "malicious"}},
        },
        "campaign": {"campaign_size": 2, "related_emails": []},
    }
    system, prompt = build_explain_prompt(analysis)

    # Body/subject should NOT appear in the prompt
    assert "UNTRUSTED email body" not in prompt
    assert "URGENT! Click here now!" not in prompt

    # Scored results SHOULD appear
    assert "Phishing/Scam" in prompt
    assert "95" in prompt
    assert "DKIM failed" in prompt
    assert "Germany" in prompt
    assert "campaign_size" in prompt

    # System prompt should be present
    assert "cybersecurity assistant" in system


def test_build_freeform_prompt():
    """Freeform prompt builds system prompt with analyst instructions."""
    system = build_freeform_prompt()
    assert "cybersecurity assistant" in system
    assert "UNTRUSTED DATA" in system


def test_build_freeform_prompt_with_single_email_context():
    """Freeform prompt incorporates single email forensic context."""
    context = {
        "verdict": "Phishing/Scam",
        "risk_score": 88,
        "subject": "Urgent wire transfer",
        "sender": "finance@evil-corp.com",
        "ml_phishing_probability": 0.92,
        "indicators": [{"name": "SPF fail", "category": "auth"}],
        "campaign_size": 3,
        "origin_geo": {"city": "Frankfurt", "country": "Germany"},
    }
    system = build_freeform_prompt(context=context)
    assert "CURRENT EMAIL FORENSIC CONTEXT:" in system
    assert "Urgent wire transfer" in system
    assert "finance@evil-corp.com" in system
    assert "Phishing/Scam" in system
    assert "88/100" in system
    assert "92.0%" in system
    assert "SPF fail" in system
    assert "Frankfurt, Germany" in system


def test_build_freeform_prompt_with_batch_context():
    """Freeform prompt incorporates batch triage context."""
    context = {
        "batch_size": 5,
        "cluster_count": 2,
        "verdicts": {"Phishing/Scam": 3, "Safe": 2},
    }
    system = build_freeform_prompt(context=context)
    assert "CURRENT BATCH TRIAGE CONTEXT:" in system
    assert "Total Email Complaints in Batch: 5" in system
    assert "Coordinated Threat Campaigns/Clusters Detected: 2" in system
    assert "Phishing/Scam: 3" in system



# ── Chat API route tests ─────────────────────────────────────────────


@patch("app.api.routes_chat.ask_ollama_chat", new_callable=AsyncMock)
def test_chat_ask_returns_response(mock_chat):
    mock_chat.return_value = "Likely Scam — this contains urgency language and asks for credentials."
    response = client.post("/api/chat/ask", json={"message": "Your account is locked! Click here now!"})
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "Likely Scam" in data["response"]
    mock_chat.assert_called_once()
    messages = mock_chat.call_args[0][0]
    assert len(messages) == 2  # system + user
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "Your account is locked!" in messages[1]["content"]


@patch("app.api.routes_chat.ask_ollama_chat", new_callable=AsyncMock)
def test_chat_ask_with_context(mock_chat):
    mock_chat.return_value = "This email was flagged Phishing/Scam due to failed SPF and wire transfer urgency."
    response = client.post(
        "/api/chat/ask",
        json={
            "message": "Why was this email flagged?",
            "context": {
                "verdict": "Phishing/Scam",
                "risk_score": 85,
                "subject": "Wire Transfer Request",
            },
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    mock_chat.assert_called_once()
    messages = mock_chat.call_args[0][0]
    assert len(messages) == 2
    assert "Wire Transfer Request" in messages[0]["content"]
    assert "Why was this email flagged?" in messages[1]["content"]


@patch("app.api.routes_chat.ask_ollama_chat", new_callable=AsyncMock)
def test_chat_ask_with_history(mock_chat):
    mock_chat.return_value = "No, this is not safe based on the shared threat infrastructure discussed."
    response = client.post(
        "/api/chat/ask",
        json={
            "message": "so is this safe?",
            "history": [
                {"role": "user", "content": "is this all connected?"},
                {"role": "assistant", "content": "Yes, complaints 1 and 2 share the same domain and IP."},
            ],
        },
    )
    assert response.status_code == 200
    mock_chat.assert_called_once()
    messages = mock_chat.call_args[0][0]
    assert len(messages) == 4
    assert messages[0]["role"] == "system"
    assert messages[1] == {"role": "user", "content": "is this all connected?"}
    assert messages[2] == {"role": "assistant", "content": "Yes, complaints 1 and 2 share the same domain and IP."}
    assert messages[3] == {"role": "user", "content": "so is this safe?"}


@patch("app.api.routes_chat.ask_ollama_chat", new_callable=AsyncMock)
def test_chat_ask_history_capped_at_10(mock_chat):
    mock_chat.return_value = "Understood."
    # Send 15 history items
    excess_history = [
        {"role": "user" if i % 2 == 0 else "assistant", "content": f"Turn {i}"}
        for i in range(15)
    ]
    response = client.post(
        "/api/chat/ask",
        json={
            "message": "Latest question",
            "history": excess_history,
        },
    )
    assert response.status_code == 200
    mock_chat.assert_called_once()
    messages = mock_chat.call_args[0][0]
    # system + last 10 history + current user message = 12 total
    assert len(messages) == 12
    # Verify the first history turn is Turn 5 (15 - 10 = index 5)
    assert messages[1]["content"] == "Turn 5"
    assert messages[10]["content"] == "Turn 14"
    assert messages[11]["content"] == "Latest question"


def test_chat_ask_empty_message_fails():
    response = client.post("/api/chat/ask", json={"message": "   "})
    assert response.status_code == 400


@patch("app.api.routes_chat.ask_ollama_chat", new_callable=AsyncMock)
def test_chat_ask_ollama_unavailable(mock_chat):
    mock_chat.side_effect = OllamaUnavailableError("Chat assistant is unavailable")
    response = client.post("/api/chat/ask", json={"message": "Is this a scam?"})
    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"].lower()


@patch("app.api.routes_chat.ask_ollama", new_callable=AsyncMock)
def test_chat_explain_with_analysis_json(mock_ollama):
    mock_ollama.return_value = "This email is flagged as Phishing/Scam with a risk score of 95."
    analysis = {
        "verdict": "Phishing/Scam",
        "risk_score": 95,
        "ml_phishing_probability": 0.97,
        "indicators": ["SPF failed"],
    }
    response = client.post("/api/chat/explain", json={"analysis": analysis})
    assert response.status_code == 200
    data = response.json()
    assert "explanation" in data
    assert "Phishing" in data["explanation"]


def test_chat_explain_no_hash_or_analysis():
    response = client.post("/api/chat/explain", json={})
    assert response.status_code == 404


@patch("app.api.routes_chat.ask_ollama", new_callable=AsyncMock)
@patch("app.api.routes_chat.get_cached_analysis")
def test_chat_explain_with_cached_hash(mock_cache, mock_ollama):
    mock_cache.return_value = {
        "verdict": "Safe",
        "risk_score": 5,
        "ml_phishing_probability": 0.02,
        "indicators": [],
    }
    mock_ollama.return_value = "This email appears to be legitimate."
    response = client.post("/api/chat/explain", json={"email_hash": "cached-hash-123"})
    assert response.status_code == 200
    assert "explanation" in response.json()
    mock_cache.assert_called_once_with("cached-hash-123")


# ── ask_ollama_chat client tests ─────────────────────────────────────


@patch("app.chat.ollama_client._chat", new_callable=AsyncMock)
def test_ask_ollama_chat_success(mock_chat):
    mock_chat.return_value = "Hello! I can help you evaluate emails."
    res = asyncio.run(ask_ollama_chat([{"role": "user", "content": "hello"}]))
    assert res == "Hello! I can help you evaluate emails."
    mock_chat.assert_called_once()


@patch("app.chat.ollama_client._chat", new_callable=AsyncMock)
def test_ask_ollama_chat_fallback(mock_chat):
    # Primary model times out, fallback succeeds
    mock_chat.side_effect = [
        httpx.TimeoutException("Primary model timed out"),
        "Fallback model response",
    ]
    res = asyncio.run(ask_ollama_chat([{"role": "user", "content": "hello"}]))
    assert res == "Fallback model response"
    assert mock_chat.call_count == 2


@patch("app.chat.ollama_client._chat", new_callable=AsyncMock)
def test_ask_ollama_chat_both_fail(mock_chat):
    # Both models time out
    mock_chat.side_effect = [
        httpx.TimeoutException("Primary timed out"),
        httpx.TimeoutException("Fallback timed out"),
    ]
    with pytest.raises(OllamaUnavailableError):
        asyncio.run(ask_ollama_chat([{"role": "user", "content": "hello"}]))

