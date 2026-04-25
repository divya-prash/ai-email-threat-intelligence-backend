"""
TF-IDF + Logistic Regression detection service.

This module builds a simple TF-IDF + LogisticRegression pipeline on a small
synthetic dataset at startup and exposes `predict_malicious_score(subject, body)`
which returns a float between 0.0 and 1.0 indicating likelihood of malicious
content.
"""
from asyncio.log import logger
from typing import List
import threading
import pickle
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import numpy as np

# Simple synthetic training data to seed the model. In production replace with
# persisted dataset or model file loading.
_TRAIN_TEXTS: List[str] = [
    "verify your account click here to update payment",
    "your password will expire re-enter password now",
    "congratulations you are a winner claim prize",
    "meeting agenda for tomorrow",
    "monthly invoice attached",
    "team lunch on friday",
    "project update and timeline",
    "please find attached the report",
]

# Labels: 1 = malicious/phishing/spam, 0 = benign
_TRAIN_LABELS = [1, 1, 1, 0, 0, 0, 0, 0]

_model_pipeline: Pipeline | None = None
_model_lock = threading.Lock()
# Default model file: look for `phishlens_model.pkl` in the backend directory
_MODEL_FILE = Path(__file__).parent / "datasets" / "trained_phishlens_model.pkl"


def _build_pipeline() -> Pipeline:
    vect = TfidfVectorizer(ngram_range=(1, 2), max_features=2000)
    clf = LogisticRegression(solver="liblinear")
    pipe = Pipeline([("tfidf", vect), ("lr", clf)])
    return pipe


def _train_default_model():
    global _model_pipeline
    pipe = _build_pipeline()
    pipe.fit(_TRAIN_TEXTS, _TRAIN_LABELS)
    _model_pipeline = pipe


def _load_persisted_model() -> bool:
    """Attempt to load persisted model file. Return True if loaded."""
    global _model_pipeline
    try:
        # Only look in the `datasets/` folder for the trained model
        path = _MODEL_FILE
        if Path(path).exists():
            with Path(path).open("rb") as fh:
                obj = pickle.load(fh)
                if hasattr(obj, "predict_proba"):
                    _model_pipeline = obj
                    return True
    except Exception:
        pass
    return False


def ensure_model_ready():
    """Ensure the model pipeline is trained and ready (thread-safe)."""
    global _model_pipeline
    if _model_pipeline is None:
        with _model_lock:
            if _model_pipeline is None:
                # Try loading persisted model first (recommended workflow)
                loaded = _load_persisted_model()
                logger.info(f"Model loaded from file: {loaded}")
                if not loaded:
                    _train_default_model()


def predict_malicious_score(subject: str, body: str) -> float:
    """Return a probability score (0.0-1.0) that the email is malicious.

    Args:
        subject: Email subject
        body: Email body

    Returns:
        float probability from logistic regression's `predict_proba` for class 1.
    """
    ensure_model_ready()
    text = (subject or "") + " " + (body or "")
    prob = _model_pipeline.predict_proba([text])[0][1]
    # clamp and return
    return float(np.clip(prob, 0.0, 1.0))


# Train on import so service is ready for first requests
ensure_model_ready()
