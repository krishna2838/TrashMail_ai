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


def explain_classification(subject: str, body: str, top_n: int = 5) -> list[dict]:
    """Explain which phrases in this email most influenced the ML phishing score.

    Reads the trained TF-IDF vectorizer weights and LogisticRegression coefficients
    to find the top contributing features for this specific email text.

    Returns a list of ``{"phrase": str, "contribution": float}`` sorted descending
    by contribution (positive = pushes toward phishing, negative = toward legitimate).
    """
    import numpy as np

    clean_subject = (subject or "").strip()
    clean_body = (body or "").strip()
    text = f"{clean_subject} {clean_body}"[:4000]

    # Skip very short emails where TF-IDF features would be noise
    if len(text.split()) < 10:
        return []

    try:
        model = get_model()

        # Access pipeline steps — expected: ('tfidf', TfidfVectorizer), ('clf', LogisticRegression)
        if not hasattr(model, "named_steps"):
            return []

        vectorizer = model.named_steps.get("tfidf")
        classifier = model.named_steps.get("clf")

        if vectorizer is None or classifier is None:
            return []
        if not hasattr(classifier, "coef_") or not hasattr(vectorizer, "get_feature_names_out"):
            return []

        # 1. Transform text through TF-IDF vectorizer
        tfidf_vector = vectorizer.transform([text])

        # 2. Get LogisticRegression coefficients for the phishing class (class 1)
        coef = classifier.coef_[0]

        # 3. Element-wise multiply: contribution = tfidf_value * coefficient
        #    Only consider features where TF-IDF is non-zero (words actually in this email)
        tfidf_dense = np.asarray(tfidf_vector.todense()).flatten()
        contributions = tfidf_dense * coef

        # 4. Get feature names
        feature_names = vectorizer.get_feature_names_out()

        # 5. Find non-zero contributions and sort by absolute magnitude
        nonzero_mask = tfidf_dense != 0
        nonzero_indices = np.where(nonzero_mask)[0]

        if len(nonzero_indices) == 0:
            return []

        # Sort by absolute contribution descending
        nonzero_contributions = contributions[nonzero_indices]
        sorted_local_indices = np.argsort(np.abs(nonzero_contributions))[::-1][:top_n]

        result = []
        for local_idx in sorted_local_indices:
            global_idx = nonzero_indices[local_idx]
            result.append({
                "phrase": str(feature_names[global_idx]),
                "contribution": round(float(contributions[global_idx]), 4),
            })

        # Sort descending by contribution, positive = pushes toward phishing
        result.sort(key=lambda x: x["contribution"], reverse=True)
        return result
    except Exception:
        # Never fail the analysis pipeline — gracefully return empty
        return []
