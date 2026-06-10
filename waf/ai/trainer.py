"""
waf.ai.trainer
~~~~~~~~~~~~~~

Offline training pipeline for the AI threat classifier and anomaly detector.

**This module is NOT imported at WAF runtime.**  It is only used to
produce the serialised model artifacts that the classifier and anomaly
detector load at startup.

Pipeline architecture
---------------------
The scikit-learn pipeline has two parallel feature branches, merged via
``FeatureUnion``:

1. **TF-IDF character n-grams** (ngram_range=(2,5), sublinear_tf=True)
   — captures lexical patterns without tokenisation assumptions.

2. **Hand-crafted features** via :mod:`waf.ai.features`
   — entropy, char ratios, keyword counts → passed through
   ``FunctionTransformer`` + ``DictVectorizer``.

Both branches are concatenated and fed into a
``GradientBoostingClassifier`` (150 estimators, lr=0.15, max_depth=5).
The full pipeline is saved as a single ``joblib`` pickle so the runtime
classifier can ``predict_proba`` in a single call.

Anomaly detector
----------------
A separate ``IsolationForest`` model is trained on the **benign-only**
samples from the dataset.  It learns the statistical profile of normal
traffic so that the runtime anomaly detector can flag requests that
deviate from this baseline — catching zero-day attacks.

Label encoding
--------------
* 0 → benign
* 1 → sqli
* 2 → xss
* 3 → cmdi (command injection)
* 4 → path_traversal
* 5 → generic_attack

Usage
-----
Run via ``python scripts/train_model.py`` (which simply calls
``train_and_save()`` with the configured paths).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer
import joblib

from waf.ai.features import extract_features
from waf.ai.models import (
    THREAT_BENIGN, THREAT_SQLI, THREAT_XSS,
    THREAT_CMD, THREAT_PATH, THREAT_GENERIC,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Label mapping
# ---------------------------------------------------------------------------

LABEL_MAP: dict[int, str] = {
    0: THREAT_BENIGN,
    1: THREAT_SQLI,
    2: THREAT_XSS,
    3: THREAT_CMD,
    4: THREAT_PATH,
    5: THREAT_GENERIC,
}

MODEL_VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# Feature extraction helpers for sklearn pipeline
# ---------------------------------------------------------------------------

def _to_feature_dicts(texts: list[str]) -> list[dict[str, float]]:
    """Wrap extract_features for use in FunctionTransformer."""
    return [extract_features(t) for t in texts]


# ---------------------------------------------------------------------------
# Pipeline construction
# ---------------------------------------------------------------------------

def build_pipeline() -> Pipeline:
    """
    Build and return an untrained sklearn Pipeline.

    The pipeline uses FeatureUnion to combine character-level TF-IDF
    with hand-crafted features before feeding to a gradient boosted tree.
    """
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        max_features=30_000,
        sublinear_tf=True,
        strip_accents="unicode",
        min_df=2,
    )

    hand_crafted = Pipeline([
        ("extract", FunctionTransformer(_to_feature_dicts, validate=False)),
        ("vectorize", DictVectorizer(sparse=False)),
    ])

    union = FeatureUnion([
        ("tfidf", tfidf),
        ("hand_crafted", hand_crafted),
    ])

    clf = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.15,
        max_depth=5,
        subsample=0.8,
        min_samples_leaf=5,
        random_state=42,
        verbose=0,
    )

    return Pipeline([
        ("features", union),
        ("clf", clf),
    ])


# ---------------------------------------------------------------------------
# Classifier training
# ---------------------------------------------------------------------------

def train_and_save(
    data_path: str | Path = "data/training_data.csv",
    model_path: str | Path = "models/waf_ai_model.pkl",
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Train the AI classifier on *data_path* and save to *model_path*.

    Args:
        data_path:    CSV with columns ``payload`` (str) and ``label`` (int).
        model_path:   Output path for the serialised ``joblib`` artifact.
        test_size:    Fraction of data held out for evaluation.
        random_state: RNG seed for reproducibility.

    Returns:
        A dict with keys ``f1_macro``, ``report``, and ``model_version``.

    Raises:
        FileNotFoundError: If *data_path* does not exist.
        ValueError:        If required columns are missing.
    """
    data_path = Path(data_path)
    model_path = Path(model_path)

    if not data_path.exists():
        raise FileNotFoundError(f"Training data not found: {data_path}")

    log.info("Loading training data from %s …", data_path)
    df = pd.read_csv(data_path, encoding="utf-8")

    required_cols = {"payload", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(
            f"CSV must contain columns {required_cols}, got {set(df.columns)}"
        )

    # Drop rows with missing payload
    df = df.dropna(subset=["payload"])
    df["payload"] = df["payload"].astype(str)
    df["label"] = df["label"].astype(int)

    X = df["payload"].tolist()
    y = df["label"].tolist()

    log.info(
        "Dataset: %d samples | classes: %s",
        len(X),
        {k: int((np.array(y) == k).sum()) for k in sorted(set(y))},
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    log.info("Building pipeline and training …")
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    f1 = f1_score(y_test, y_pred, average="macro")
    report = classification_report(
        y_test, y_pred,
        target_names=[LABEL_MAP.get(i, str(i)) for i in sorted(set(y))],
    )

    log.info("Test F1 (macro): %.4f", f1)
    log.info("Classification report:\n%s", report)

    # Attach metadata to the artifact
    artifact = {
        "pipeline": pipeline,
        "label_map": LABEL_MAP,
        "model_version": MODEL_VERSION,
        "f1_macro": float(f1),
        "feature_names": list(
            pipeline.named_steps["features"]
            .transformer_list[1][1]
            .named_steps["vectorize"]
            .feature_names_
        ),
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path, compress=3)
    log.info("Model saved → %s (%.1f KB)", model_path, model_path.stat().st_size / 1024)

    return {"f1_macro": float(f1), "report": report, "model_version": MODEL_VERSION}


# ---------------------------------------------------------------------------
# Anomaly model training
# ---------------------------------------------------------------------------

def train_anomaly_model(
    data_path: str | Path = "data/training_data.csv",
    model_path: str | Path = "models/waf_anomaly_model.pkl",
    contamination: float = 0.05,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Train an Isolation Forest anomaly detector on **benign-only** samples.

    The model learns the statistical profile of normal HTTP traffic so
    it can flag requests that deviate from this baseline at runtime.

    Args:
        data_path:     CSV with columns ``payload`` (str) and ``label`` (int).
                       Only rows with ``label == 0`` (benign) are used.
        model_path:    Output path for the serialised anomaly model.
        contamination: Expected fraction of outliers in the training data.
        random_state:  RNG seed for reproducibility.

    Returns:
        A dict with keys ``model_version``, ``n_samples``, and ``contamination``.
    """
    data_path = Path(data_path)
    model_path = Path(model_path)

    if not data_path.exists():
        raise FileNotFoundError(f"Training data not found: {data_path}")

    log.info("Loading training data for anomaly model from %s …", data_path)
    df = pd.read_csv(data_path, encoding="utf-8")
    df = df.dropna(subset=["payload"])
    df["payload"] = df["payload"].astype(str)
    df["label"] = df["label"].astype(int)

    # Extract ONLY benign samples for the anomaly detector
    benign_df = df[df["label"] == 0]
    log.info("Benign samples for anomaly training: %d (of %d total)", len(benign_df), len(df))

    if len(benign_df) < 20:
        log.warning(
            "Too few benign samples (%d) for anomaly training — need at least 20.",
            len(benign_df),
        )
        return {"model_version": "failed", "n_samples": 0}

    # Extract feature vectors for all benign samples
    log.info("Extracting features for anomaly model …")
    feature_dicts = [extract_features(text) for text in benign_df["payload"].tolist()]
    feature_names = sorted(feature_dicts[0].keys())
    X = np.array([[fd[k] for k in feature_names] for fd in feature_dicts])

    log.info("Training Isolation Forest (contamination=%.3f, samples=%d) …", contamination, len(X))

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        random_state=random_state,
        n_jobs=-1,
        verbose=0,
    )
    model.fit(X)

    # Validate: score the training data and check anomaly rate
    scores = model.score_samples(X)
    predictions = model.predict(X)
    n_anomalies = int((predictions == -1).sum())
    anomaly_pct = n_anomalies / len(predictions) * 100

    log.info(
        "Anomaly model trained — %d/%d benign samples flagged as anomalous (%.1f%%) "
        "[expected ~%.1f%%]",
        n_anomalies, len(predictions), anomaly_pct, contamination * 100,
    )

    # Also test on attack samples to verify the model flags them
    attack_df = df[df["label"] != 0]
    if len(attack_df) > 0:
        attack_features = [extract_features(t) for t in attack_df["payload"].tolist()]
        X_attack = np.array([[fd[k] for k in feature_names] for fd in attack_features])
        attack_predictions = model.predict(X_attack)
        attack_flagged = int((attack_predictions == -1).sum())
        log.info(
            "Anomaly model catch rate on known attacks: %d/%d (%.1f%%)",
            attack_flagged, len(attack_predictions),
            attack_flagged / len(attack_predictions) * 100,
        )

    # Save artifact
    anomaly_version = f"{MODEL_VERSION}-anomaly"
    artifact = {
        "model": model,
        "feature_names": feature_names,
        "model_version": anomaly_version,
        "contamination": contamination,
        "n_training_samples": len(X),
        "score_stats": {
            "mean": float(np.mean(scores)),
            "std": float(np.std(scores)),
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
        },
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path, compress=3)
    log.info(
        "Anomaly model saved → %s (%.1f KB)",
        model_path, model_path.stat().st_size / 1024,
    )

    return {
        "model_version": anomaly_version,
        "n_samples": len(X),
        "contamination": contamination,
    }
