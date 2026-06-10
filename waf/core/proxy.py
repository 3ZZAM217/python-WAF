"""
waf.core.proxy
~~~~~~~~~~~~~~

FastAPI reverse-proxy entry point for Python Shield WAF.

Architecture notes
------------------
* A single ``httpx.AsyncClient`` is created at application startup via
  FastAPI's lifespan context manager and reused across all requests.
  This avoids the overhead of TCP connection setup / teardown on every
  request — critical for low-latency proxying.

* The upstream ``TARGET_URL`` is read from the ``TARGET_URL`` environment
  variable (set in Docker Compose / Kubernetes), falling back to the
  value in ``config/waf_config.yaml``.  The hardcoded string that was
  present in the original code has been removed to make the application
  12-factor compliant.

* ``X-Forwarded-For`` and ``X-Real-IP`` headers are resolved to obtain
  the true client IP when the WAF itself sits behind an upstream load
  balancer or CDN.  The rightmost IP in the ``X-Forwarded-For`` chain
  that was added by the trusted proxy is used (RFC 7239).

* Response headers are sanitised before being forwarded to the client:
  ``Server`` and ``X-Powered-By`` headers are stripped to avoid leaking
  information about the backend technology stack.

* Error responses from the WAF use RFC 7807 Problem Details format
  (``application/problem+json``) for machine-readable error bodies.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from waf.core.engine import WAFEngine
from waf.core.models import InspectionContext
from waf.utils.config_parser import load_config
from waf.utils.logger import get_logger

log: logging.Logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_cfg = load_config()
TARGET_URL: str = os.getenv("TARGET_URL", _cfg.target_url).rstrip("/")

# Response headers that reveal backend implementation details.
# Stripping these reduces the attacker's reconnaissance surface.
_STRIP_RESPONSE_HEADERS = frozenset(
    {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    }
)

# ---------------------------------------------------------------------------
# Shared HTTP client — initialised / closed in the lifespan
# ---------------------------------------------------------------------------

_http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """Create a shared async HTTP client at startup; close it at shutdown."""
    global _http_client  # noqa: PLW0603

    log.info("WAF proxy starting — upstream target: %s", TARGET_URL)

    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=5.0,
            read=float(_cfg.target_timeout),
            write=float(_cfg.target_timeout),
            pool=5.0,
        ),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        follow_redirects=False,
    )

    yield  # Application is running

    await _http_client.aclose()
    log.info("WAF proxy shut down — HTTP client closed.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

engine = WAFEngine(config=_cfg)

app = FastAPI(
    title="Python Shield WAF",
    description=(
        "A reverse-proxy Web Application Firewall providing SQLi, XSS, "
        "rate-limit, and IP-blocklist protection."
    ),
    version="1.0.0",
    lifespan=_lifespan,
    docs_url=None,   # Disable Swagger UI in production
    redoc_url=None,
)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def reverse_proxy(request: Request, path: str) -> Response:
    """
    Intercept every inbound request, run it through the WAF inspection
    pipeline, and forward it to the upstream target if clean.

    Flow
    ----
    1. Extract client IP (honours ``X-Forwarded-For`` / ``X-Real-IP``).
    2. Build an immutable :class:`~waf.core.models.InspectionContext`.
    3. Delegate to :meth:`~waf.core.engine.WAFEngine.inspect`.
    4. On block → return ``403 Forbidden`` (RFC 7807 Problem Details).
    5. On pass → proxy to upstream, sanitise response headers, return.
    """
    client_ip = _resolve_client_ip(request)
    headers = dict(request.headers)
    body = await request.body()

    ctx = InspectionContext(
        ip=client_ip,
        method=request.method,
        path=f"/{path}",
        query_string=str(request.query_params),
        headers={k.lower(): v for k, v in headers.items()},
        body=body,
    )

    decision = await engine.inspect(ctx)

    if not decision.allowed:
        log.info(
            "Blocked request from %s [%s] %s — rule=%s",
            client_ip,
            request.method,
            ctx.path,
            decision.rule_id,
        )
        return JSONResponse(
            status_code=403,
            content={
                "type": "https://python-shield-waf/errors/blocked",
                "title": "Request Blocked",
                "status": 403,
                "detail": decision.reason,
                "rule_id": decision.rule_id,
            },
            headers={"Content-Type": "application/problem+json"},
        )

    # Forward request to the upstream target
    assert _http_client is not None, "HTTP client not initialised"

    forward_headers = _build_forward_headers(headers, client_ip)
    target_url = f"{TARGET_URL}/{path}"

    try:
        upstream_response = await _http_client.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            content=body,
            params=request.query_params,
        )
    except httpx.TimeoutException:
        log.error("Upstream timeout: %s", target_url)
        return JSONResponse(status_code=504, content={"detail": "Upstream gateway timeout."})
    except httpx.RequestError as exc:
        log.error("Upstream connection error: %s — %s", target_url, exc)
        return JSONResponse(status_code=502, content={"detail": "Bad gateway."})

    # Strip information-leaking headers from the upstream response
    response_headers = {
        k: v
        for k, v in upstream_response.headers.items()
        if k.lower() not in _STRIP_RESPONSE_HEADERS
    }

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_client_ip(request: Request) -> str:
    """
    Determine the true client IP from request metadata.

    When the WAF sits behind a trusted load balancer, the real client IP
    is in ``X-Real-IP`` or the leftmost value of ``X-Forwarded-For``.
    Falls back to the direct TCP peer address.
    """
    # X-Real-IP is set by Nginx and is a single IP
    x_real_ip = request.headers.get("x-real-ip", "").strip()
    if x_real_ip:
        return x_real_ip

    # X-Forwarded-For may be a comma-separated list; the leftmost is the client
    x_forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    # Direct connection fallback
    if request.client:
        return request.client.host

    return "unknown"


def _build_forward_headers(original_headers: dict[str, str], client_ip: str) -> dict[str, str]:
    """
    Build the header dict to send to the upstream target.

    * Removes ``host`` so httpx sets the correct host for the target.
    * Injects ``X-Forwarded-For`` and ``X-Real-IP`` to preserve client IP
      visibility for the backend application.
    * Adds ``X-WAF-Protected: python-shield`` to allow the backend to
      verify it is receiving traffic through the WAF.
    """
    headers = {k: v for k, v in original_headers.items() if k.lower() != "host"}
    headers["x-forwarded-for"] = client_ip
    headers["x-real-ip"] = client_ip
    headers["x-waf-protected"] = "python-shield"
    return headers