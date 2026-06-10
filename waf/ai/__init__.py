"""
waf.ai
~~~~~~

AI-powered threat detection layer for Python Shield WAF.

This package provides a dual-model AI system that runs as Rules 7–8 in
the inspection pipeline:

* **Classifier** (Rule 7) — a supervised scikit-learn pipeline that
  identifies known attack types (SQLi, XSS, CMDi, path traversal).

* **Anomaly Detector** (Rule 8) — an unsupervised Isolation Forest that
  catches **zero-day / unknown attacks** by flagging traffic that deviates
  from the learned baseline of normal traffic patterns.

* **Self-Learning Pipeline** — automatically collects data from blocked
  and allowed requests, periodically retrains both models, and hot-swaps
  them into the live pipeline with zero downtime.

Components
----------
* :mod:`waf.ai.models`            — ``AIDecision`` dataclass
* :mod:`waf.ai.features`          — hand-crafted feature extraction helpers
* :mod:`waf.ai.classifier`        — ``AIClassifier`` runtime inference class
* :mod:`waf.ai.anomaly_detector`  — ``AnomalyDetector`` Isolation Forest inference
* :mod:`waf.ai.learner`           — ``WAFLearner`` self-learning pipeline
* :mod:`waf.ai.trainer`           — offline training pipeline (not imported at runtime)
"""
