"""
waf.core.engine
~~~~~~~~~~~~~~~~

Central inspection pipeline for Python Shield WAF.

Threat model
------------
The engine evaluates every inbound HTTP request against the following
ordered rule chain (fail-fast on first match):

    1. IP Blocklist      — known-malicious IPs / CIDRs
    2. Rate Limiter      — per-IP sliding-window DoS / brute-force mitigation
    3. URL Path          — SQLi and XSS in the path component
    4. Query String      — SQLi and XSS in decoded query parameters
    5. Request Body      — SQLi and XSS in POST / PUT bodies
    6. Headers           — anomaly checks on User-Agent and Referer
    7. AI Classifier     — supervised ML model for known attack patterns
    8. Anomaly Detector  — unsupervised Isolation Forest for zero-day attacks

Rule ordering justification
---------------------------
* IP and rate-limit checks are cheap O(n) / O(1) operations — they
  eliminate bulk attack traffic before invoking more expensive regex scans.
* Header inspection is last in the regex chain because legitimate
  applications rarely inject attack strings via headers.
* The AI classifier runs after regex rules to catch obfuscated payloads
  that evade signature matching.
* The anomaly detector runs last as a catch-all safety net — if everything
  else says "benign" but the request looks statistically unusual, it flags it.

Self-learning integration
-------------------------
After every inspection decision, the engine feeds the result to the
:class:`~waf.ai.learner.WAFLearner`:
* Blocked requests → recorded as confirmed attacks (auto-labeled).
* Allowed requests → probabilistically sampled as benign baseline.
* The learner periodically retrains and hot-swaps models in the background.

Configurability
---------------
All rule categories can be toggled via ``config/waf_config.yaml``.
Rule parameters (limits, patterns) are also YAML-configurable — the engine
reads from a :class:`~waf.utils.config_parser.WAFConfig` instance rather
than hardcoded constants.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Callable

from waf.core.models import BlockDecision, InspectionContext
from waf.security.ip_filter import IPFilter
from waf.security.rate_limiter import RateLimiter
from waf.security.rules_sqli import RULE_ID as SQLI_RULE_ID, detect_sqli
from waf.security.rules_xss import RULE_ID as XSS_RULE_ID, detect_xss
from waf.utils.config_parser import WAFConfig, load_config
from waf.utils.logger import get_logger, log_blocked_request
from waf.ai.classifier import AIClassifier
from waf.ai.anomaly_detector import AnomalyDetector
from waf.ai.learner import WAFLearner

log: logging.Logger = get_logger(__name__)

# Headers worth scanning for injection payloads.  Limiting to a curated
# set avoids false positives from legitimate content-type or auth headers.
_INSPECTABLE_HEADERS = frozenset({"user-agent", "referer", "x-forwarded-for"})

# Rule IDs used by the AI detection layers.
_AI_RULE_ID = "AI-001"
_AI_ANOMALY_RULE_ID = "AI-ANOMALY-001"


class WAFEngine:
    """
    Stateful inspection engine.  Instantiate once per process lifetime.

    Args:
        config: Optional pre-built :class:`WAFConfig`.  When omitted the
                engine loads ``config/waf_config.yaml`` automatically.
    """

    def __init__(self, config: WAFConfig | None = None) -> None:
        self._cfg = config or load_config()
        rl_cfg = self._cfg.rate_limit
        ipf_cfg = self._cfg.ip_filter

        self._rate_limiter = RateLimiter(
            max_requests=rl_cfg.max_requests,
            window_seconds=rl_cfg.window_seconds,
            max_ips=rl_cfg.max_tracked_ips,
        )
        self._ip_filter = IPFilter(
            blocklist_path=ipf_cfg.blocklist_path,
            hot_reload=ipf_cfg.hot_reload,
        )

        # ---- AI classifier (Rule 7) -----------------------------------
        ai_cfg = self._cfg.ai
        if ai_cfg.enabled:
            self._ai_classifier: AIClassifier | None = AIClassifier(
                model_path=ai_cfg.model_path,
                confidence_threshold=ai_cfg.confidence_threshold,
            )
        else:
            self._ai_classifier = None

        # ---- Anomaly detector (Rule 8) ---------------------------------
        if ai_cfg.enabled and ai_cfg.anomaly_detection:
            self._anomaly_detector: AnomalyDetector | None = AnomalyDetector(
                model_path=ai_cfg.anomaly_model_path,
                contamination=ai_cfg.anomaly_contamination,
            )
        else:
            self._anomaly_detector = None

        # ---- Self-learning pipeline ------------------------------------
        if ai_cfg.learning_enabled:
            self._learner: WAFLearner | None = WAFLearner(
                data_dir=ai_cfg.learning_data_dir,
                retrain_after_samples=ai_cfg.retrain_after_samples,
                retrain_interval_hours=ai_cfg.retrain_interval_hours,
                min_f1_for_deploy=ai_cfg.min_f1_for_deploy,
                baseline_sample_rate=ai_cfg.baseline_sample_rate,
                classifier=self._ai_classifier,
                anomaly_detector=self._anomaly_detector,
            )
        else:
            self._learner = None

        log.info(
            "WAF Engine initialised — target=%s | rate_limit=%d/%ds | "
            "blocklist_entries=%d | ai=%s (mode=%s, model=%s) | "
            "anomaly=%s | learning=%s",
            self._cfg.target_url,
            rl_cfg.max_requests,
            rl_cfg.window_seconds,
            self._ip_filter.blocked_network_count,
            "enabled" if ai_cfg.enabled else "disabled",
            ai_cfg.mode,
            self._ai_classifier.is_available if self._ai_classifier else "n/a",
            "enabled" if self._anomaly_detector and self._anomaly_detector.is_available
            else "disabled",
            "enabled" if self._learner else "disabled",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def inspect(self, ctx: InspectionContext) -> BlockDecision:
        """
        Evaluate *ctx* against the full rule chain.

        Args:
            ctx: Immutable snapshot of the incoming request.

        Returns:
            A :class:`BlockDecision` — check ``decision.allowed`` to
            determine whether to forward or drop the request.
        """
        rules = self._cfg.rules

        # ----------------------------------------------------------
        # Rule 1: IP blocklist
        # ----------------------------------------------------------
        if self._ip_filter.is_blocked(ctx.ip):
            decision = self._block(ctx, "IP address is on the blocklist", "IPBLOCK-001")
            await self._learn_from_decision(ctx, decision)
            return decision

        # ----------------------------------------------------------
        # Rule 2: Rate limiter
        # ----------------------------------------------------------
        if not await self._rate_limiter.is_allowed(ctx.ip):
            return self._block(
                ctx,
                f"Rate limit exceeded ({self._cfg.rate_limit.max_requests} "
                f"requests / {self._cfg.rate_limit.window_seconds}s)",
                "RATELIMIT-001",
            )
            # Note: rate-limited requests are NOT fed to the learner —
            # they're not attack patterns, just volume abuse.

        # ----------------------------------------------------------
        # Rule 3: URL path inspection
        # ----------------------------------------------------------
        if rules.inspect_url_path:
            decision = self._scan_surface(ctx, ctx.path, "URL path")
            if not decision.allowed:
                await self._learn_from_decision(ctx, decision)
                return decision

        # ----------------------------------------------------------
        # Rule 4: Query string inspection
        # ----------------------------------------------------------
        if rules.inspect_query_string and ctx.query_string:
            decoded_qs = urllib.parse.unquote_plus(ctx.query_string)
            decision = self._scan_surface(ctx, decoded_qs, "query string")
            if not decision.allowed:
                await self._learn_from_decision(ctx, decision)
                return decision

        # ----------------------------------------------------------
        # Rule 5: Request body inspection
        # ----------------------------------------------------------
        if rules.inspect_request_body and ctx.body:
            body_str = self._decode_body(ctx.body)
            if body_str:
                truncated = body_str[: rules.max_body_inspect_bytes]
                decision = self._scan_surface(ctx, truncated, "request body")
                if not decision.allowed:
                    await self._learn_from_decision(ctx, decision)
                    return decision

        # ----------------------------------------------------------
        # Rule 6: Header inspection
        # ----------------------------------------------------------
        if rules.inspect_headers:
            for header_name in _INSPECTABLE_HEADERS:
                header_value = ctx.headers.get(header_name, "")
                if header_value:
                    decision = self._scan_surface(ctx, header_value, f"header:{header_name}")
                    if not decision.allowed:
                        await self._learn_from_decision(ctx, decision)
                        return decision

        # ----------------------------------------------------------
        # Rule 7: AI threat classifier
        # ----------------------------------------------------------
        surface = self._build_ai_surface(ctx)
        ai_decision = await self._run_ai_classifier(ctx, surface)
        if ai_decision is not None:
            await self._learn_from_decision(ctx, ai_decision, surface=surface)
            return ai_decision

        # ----------------------------------------------------------
        # Rule 8: Anomaly detector (zero-day catch-all)
        # ----------------------------------------------------------
        anomaly_decision = await self._run_anomaly_detector(ctx, surface)
        if anomaly_decision is not None:
            await self._learn_from_decision(ctx, anomaly_decision, surface=surface)
            return anomaly_decision

        # ----------------------------------------------------------
        # All clear — request passed every check
        # ----------------------------------------------------------
        allowed = BlockDecision.allow()
        await self._learn_from_decision(ctx, allowed, surface=surface)
        return allowed

    # ------------------------------------------------------------------
    # AI surface builder
    # ------------------------------------------------------------------

    def _build_ai_surface(self, ctx: InspectionContext) -> str:
        """Build a combined surface string from all request parts for AI models."""
        ai_cfg = self._cfg.ai

        body_snippet = ""
        if ctx.body:
            try:
                body_snippet = ctx.body.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body_snippet = ""

        surface = " ".join(filter(None, [
            ctx.path,
            ctx.query_string,
            body_snippet,
        ]))[: ai_cfg.max_surface_bytes]

        return surface

    # ------------------------------------------------------------------
    # AI classifier (Rule 7)
    # ------------------------------------------------------------------

    async def _run_ai_classifier(
        self, ctx: InspectionContext, surface: str,
    ) -> BlockDecision | None:
        """
        Run the AI classifier (Rule 7) against the combined request surface.

        Returns
        -------
        * ``None``            — classifier not available, disabled, or benign verdict.
        * ``BlockDecision``   — only in ``block`` mode when AI flags the request.

        In shadow mode the AI verdict is always logged but ``None`` is returned
        so the request passes through.
        """
        if self._ai_classifier is None or not self._ai_classifier.is_available:
            return None

        if not surface.strip():
            return None

        ai_cfg = self._cfg.ai
        ai_decision = await self._ai_classifier.predict(surface)

        if not ai_decision.is_malicious:
            return None

        # Compose a human-readable reason for audit logs
        reason = (
            f"AI classifier detected {ai_decision.threat_type} "
            f"(confidence={ai_decision.confidence:.2%}, "
            f"model={ai_decision.model_version})"
        )
        top = ", ".join(ai_decision.top_features[:5]) if ai_decision.top_features else "n/a"

        if ai_cfg.mode == "block":
            log.warning(
                "AI BLOCK — ip=%s [%s] %s — %s | top_features=[%s]",
                ctx.ip, ctx.method, ctx.path, reason, top,
            )
            return self._block(ctx, reason, _AI_RULE_ID)

        # Shadow mode: log but allow
        log.info(
            "AI SHADOW — ip=%s [%s] %s — %s | top_features=[%s] (not blocking)",
            ctx.ip, ctx.method, ctx.path, reason, top,
        )
        return None

    # ------------------------------------------------------------------
    # Anomaly detector (Rule 8)
    # ------------------------------------------------------------------

    async def _run_anomaly_detector(
        self, ctx: InspectionContext, surface: str,
    ) -> BlockDecision | None:
        """
        Run the anomaly detector (Rule 8) against the combined request surface.

        This is the zero-day catch-all — it flags anything that looks
        statistically unusual compared to the learned baseline of normal
        traffic, even if it doesn't match any known attack signature.

        Returns
        -------
        * ``None``            — detector not available or request is normal.
        * ``BlockDecision``   — only in ``block`` mode when flagged as anomalous.
        """
        if self._anomaly_detector is None or not self._anomaly_detector.is_available:
            return None

        if not surface.strip():
            return None

        ai_cfg = self._cfg.ai
        anomaly_result = await self._anomaly_detector.score(surface)

        if anomaly_result is None or not anomaly_result.is_malicious:
            return None

        reason = (
            f"Anomaly detector flagged unusual traffic pattern "
            f"(confidence={anomaly_result.confidence:.2%}, "
            f"model={anomaly_result.model_version})"
        )
        top = ", ".join(anomaly_result.top_features[:5]) if anomaly_result.top_features else "n/a"

        if ai_cfg.mode == "block":
            log.warning(
                "ANOMALY BLOCK — ip=%s [%s] %s — %s | anomalous_features=[%s]",
                ctx.ip, ctx.method, ctx.path, reason, top,
            )
            return self._block(ctx, reason, _AI_ANOMALY_RULE_ID)

        # Shadow mode: log but allow
        log.info(
            "ANOMALY SHADOW — ip=%s [%s] %s — %s | anomalous_features=[%s] (not blocking)",
            ctx.ip, ctx.method, ctx.path, reason, top,
        )
        return None

    # ------------------------------------------------------------------
    # Self-learning integration
    # ------------------------------------------------------------------

    async def _learn_from_decision(
        self,
        ctx: InspectionContext,
        decision: BlockDecision,
        surface: str = "",
    ) -> None:
        """
        Feed the inspection result to the self-learning pipeline.

        Blocked requests are recorded as confirmed attacks; allowed
        requests are probabilistically sampled as benign baseline.
        """
        if self._learner is None:
            return

        # Build surface if not already built
        if not surface:
            surface = self._build_ai_surface(ctx)
        if not surface.strip():
            return

        try:
            if not decision.allowed:
                await self._learner.record_blocked(
                    surface=surface,
                    rule_id=decision.rule_id,
                )
            else:
                await self._learner.record_allowed(surface=surface)

            # Check if retraining is needed
            await self._learner.check_retrain()
        except Exception as exc:  # noqa: BLE001
            # Never let learning failures break request processing
            log.debug("Learning pipeline error (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_surface(
        self, ctx: InspectionContext, text: str, surface_label: str
    ) -> BlockDecision:
        """
        Run SQLi and XSS detectors against *text*.

        Returns a blocking decision on the first match, or
        :meth:`~BlockDecision.allow` if *text* is clean.
        """
        rules = self._cfg.rules

        if rules.sqli_detection and detect_sqli(text):
            return self._block(
                ctx,
                f"SQL Injection detected in {surface_label}",
                SQLI_RULE_ID,
            )

        if rules.xss_detection and detect_xss(text):
            return self._block(
                ctx,
                f"XSS detected in {surface_label}",
                XSS_RULE_ID,
            )

        return BlockDecision.allow()

    @staticmethod
    def _block(ctx: InspectionContext, reason: str, rule_id: str) -> BlockDecision:
        """Emit an audit log record and return a :class:`BlockDecision`."""
        log_blocked_request(
            ip=ctx.ip,
            method=ctx.method,
            path=ctx.path,
            rule_id=rule_id,
            reason=reason,
        )
        return BlockDecision.block(reason=reason, rule_id=rule_id)

    @staticmethod
    def _decode_body(body: bytes) -> str:
        """
        Best-effort UTF-8 decode of a request body.

        Returns an empty string for non-text bodies (binary uploads, etc.)
        so that the engine silently skips body inspection rather than
        crashing on ``UnicodeDecodeError``.
        """
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return body.decode("latin-1")
            except UnicodeDecodeError:
                return ""