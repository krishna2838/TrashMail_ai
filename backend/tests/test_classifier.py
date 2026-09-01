"""Unit tests for ML classifier module."""

from __future__ import annotations

from app.ml.classifier import classify_text, get_model


def test_get_model_loads_pipeline():
    model = get_model()
    assert model is not None
    assert hasattr(model, "predict_proba")


def test_classify_phishing_text():
    subject = "URGENT: Your account has been suspended! Verify immediately"
    body = "Dear Customer, click here http://scam.ru/verify to restore your bank account now or lose access forever."
    result = classify_text(subject, body)

    assert "phishing_probability" in result
    assert "ml_label" in result
    assert isinstance(result["phishing_probability"], float)
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert result["phishing_probability"] >= 0.5
    assert result["ml_label"] == "phishing"


def test_classify_legitimate_text():
    subject = "Meeting agenda for tomorrow afternoon"
    body = "Hi team, let's review the quarterly roadmap tomorrow at 2pm in conference room B. Thanks!"
    result = classify_text(subject, body)

    assert result["phishing_probability"] < 0.5
    assert result["ml_label"] == "legitimate"
