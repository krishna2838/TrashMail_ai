"""Unit tests for chat endpoints — Ollama calls mocked."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient

from app.chat.ollama_client import OllamaUnavailableError
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
    """Freeform prompt wraps user text properly."""
    system, prompt = build_freeform_prompt("Is this email a scam?")
    assert "Analyze this text:" in prompt
    assert "Is this email a scam?" in prompt
    assert "cybersecurity assistant" in system


# ── Chat API route tests ─────────────────────────────────────────────


@patch("app.api.routes_chat.ask_ollama", new_callable=AsyncMock)
def test_chat_ask_returns_response(mock_ollama):
    mock_ollama.return_value = "Likely Scam — this contains urgency language and asks for credentials."
    response = client.post("/api/chat/ask", json={"message": "Your account is locked! Click here now!"})
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "Likely Scam" in data["response"]


@patch("app.api.routes_chat.ask_ollama", new_callable=AsyncMock)
def test_chat_ask_empty_message_fails(mock_ollama):
    response = client.post("/api/chat/ask", json={"message": "   "})
    assert response.status_code == 400


@patch("app.api.routes_chat.ask_ollama", new_callable=AsyncMock)
def test_chat_ask_ollama_unavailable(mock_ollama):
    mock_ollama.side_effect = OllamaUnavailableError("Chat assistant is unavailable")
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
