"""Pre-trained ML classifier module for phishing/scam email detection."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
import warnings
import joblib

MODEL_PATH = Path(__file__).parent / "model" / "phishtrace_classifier.joblib"


@lru_cache(maxsize=1)
def get_model() -> Any:
    """Load and cache the pre-trained scikit-learn pipeline."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        model = joblib.load(MODEL_PATH)
    # Ensure backwards/cross-version compatibility across scikit-learn releases
    if hasattr(model, "steps"):
        for _, step in model.steps:
            if not hasattr(step, "multi_class"):
                setattr(step, "multi_class", "auto")
    return model


def classify_text(subject: str, body: str) -> dict[str, Any]:
    """
    Classify email text using the pre-trained TF-IDF + LogisticRegression pipeline.
    Combines subject and body, truncated to 4000 characters.
    """
    model = get_model()
    clean_subject = (subject or "").strip()
    clean_body = (body or "").strip()
    text = f"{clean_subject} {clean_body}"[:4000]

    proba = model.predict_proba([text])[0]
    phishing_probability = float(proba[1])

    return {
        "phishing_probability": round(phishing_probability, 4),
        "ml_label": "phishing" if phishing_probability >= 0.5 else "legitimate",
    }
