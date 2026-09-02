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


def test_explain_classification_phishing():
    from app.ml.classifier import explain_classification

    subject = "URGENT: Unauthorized login detected on your account!"
    body = "Dear customer, please verify your identity immediately or your account will be suspended."
    phrases = explain_classification(subject, body, top_n=5)

    assert isinstance(phrases, list)
    assert len(phrases) > 0
    assert len(phrases) <= 5

    for item in phrases:
        assert "phrase" in item
        assert "contribution" in item
        assert isinstance(item["phrase"], str)
        assert isinstance(item["contribution"], float)

    # Verify descending sort order by contribution
    contributions = [item["contribution"] for item in phrases]
    assert contributions == sorted(contributions, reverse=True)

    # Phishing email should have prominent positive-contribution phrases
    positive_phrases = [item["phrase"] for item in phrases if item["contribution"] > 0]
    assert len(positive_phrases) > 0
    # Plausible red-flag words
    assert any(word in positive_phrases for word in ["account", "urgent", "verify", "suspended", "login"])


def test_explain_classification_benign():
    from app.ml.classifier import explain_classification

    subject = "Your Monthly Acme Statement"
    body = "Hello Customer, your statement is ready. If you have questions, visit our help portal. Thanks, Support Team."
    phrases = explain_classification(subject, body, top_n=5)

    assert isinstance(phrases, list)
    assert len(phrases) > 0

    # Verify descending sort order
    contributions = [item["contribution"] for item in phrases]
    assert contributions == sorted(contributions, reverse=True)

    # Negative contribution phrases pushing toward legitimate
    negative_phrases = [item["phrase"] for item in phrases if item["contribution"] < 0]
    assert len(negative_phrases) > 0
    assert any(word in negative_phrases for word in ["thanks", "questions", "statement", "help"])


def test_explain_classification_short_text_returns_empty():
    from app.ml.classifier import explain_classification

    # Under 10 words should return empty to avoid noise
    assert explain_classification("Hello", "short text") == []
    assert explain_classification("", "") == []


def test_explain_classification_respects_top_n():
    from app.ml.classifier import explain_classification

    subject = "URGENT: Unauthorized login detected on your account! Verify now."
    body = "Please immediately verify your identity or your banking account will be suspended permanently."
    top_3 = explain_classification(subject, body, top_n=3)
    top_5 = explain_classification(subject, body, top_n=5)

    assert len(top_3) <= 3
    assert len(top_5) <= 5
    assert len(top_3) <= len(top_5)
