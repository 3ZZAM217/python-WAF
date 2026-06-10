"""
waf.ai.models
~~~~~~~~~~~~~

Typed result objects for the AI detection layer.

``AIDecision`` is the counterpart to ``BlockDecision`` — it carries the
machine-learning verdict, confidence score, threat classification, and a
list of the top contributing features so that security engineers can
understand *why* the model flagged a request.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Threat-type constants
# ---------------------------------------------------------------------------

THREAT_SQLI = "sqli"
THREAT_XSS = "xss"
THREAT_CMD = "cmdi"          # Command injection
THREAT_PATH = "path_traversal"
THREAT_GENERIC = "generic_attack"
THREAT_BENIGN = "benign"
THREAT_ANOMALY = "anomaly"   # Zero-day / unknown pattern flagged by anomaly detector

# ---------------------------------------------------------------------------
# Detection source constants — tracks which AI model produced the verdict
# ---------------------------------------------------------------------------

SOURCE_CLASSIFIER = "classifier"
SOURCE_ANOMALY = "anomaly_detector"
SOURCE_COMBINED = "classifier+anomaly"


@dataclass(frozen=True, slots=True)
class AIDecision:
    """
    Result produced by :class:`~waf.ai.classifier.AIClassifier`.

    Attributes:
        is_malicious:    ``True`` when the model classifies the payload
                         as an attack with confidence ≥ threshold.
        confidence:      Model's probability estimate for the malicious
                         class (0.0 – 1.0).
        threat_type:     Predicted attack category (e.g. ``"sqli"``).
                         ``"benign"`` when the request is clean.
        top_features:    Up to 10 feature names/tokens that most strongly
                         influenced the prediction — useful for audit logs
                         and analyst triage.
        model_version:   Identifier of the model artifact that produced
                         this decision (loaded from the pickle metadata).
        detection_source: Which AI model produced this verdict — one of
                         ``"classifier"``, ``"anomaly_detector"``, or
                         ``"classifier+anomaly"`` (both agreed).
    """

    is_malicious: bool
    confidence: float
    threat_type: str = THREAT_BENIGN
    top_features: list[str] = field(default_factory=list, hash=False, compare=False)
    model_version: str = "unknown"
    detection_source: str = SOURCE_CLASSIFIER

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def benign(
        cls,
        confidence: float = 1.0,
        model_version: str = "unknown",
        detection_source: str = SOURCE_CLASSIFIER,
    ) -> "AIDecision":
        """Factory: request looks clean."""
        return cls(
            is_malicious=False,
            confidence=confidence,
            threat_type=THREAT_BENIGN,
            model_version=model_version,
            detection_source=detection_source,
        )

    @classmethod
    def malicious(
        cls,
        confidence: float,
        threat_type: str = THREAT_GENERIC,
        top_features: list[str] | None = None,
        model_version: str = "unknown",
        detection_source: str = SOURCE_CLASSIFIER,
    ) -> "AIDecision":
        """Factory: request classified as an attack."""
        return cls(
            is_malicious=True,
            confidence=confidence,
            threat_type=threat_type,
            top_features=top_features or [],
            model_version=model_version,
            detection_source=detection_source,
        )

    def __str__(self) -> str:
        status = "MALICIOUS" if self.is_malicious else "BENIGN"
        return (
            f"AIDecision({status} | type={self.threat_type} | "
            f"confidence={self.confidence:.3f} | model={self.model_version} | "
            f"source={self.detection_source})"
        )
