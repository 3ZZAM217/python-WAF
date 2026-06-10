# Python Shield WAF 🛡️
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A production-grade, reverse-proxy **Web Application Firewall** built in Python with FastAPI and HTTPX. Python Shield sits in front of vulnerable web applications, inspecting and filtering malicious HTTP traffic in real-time — with zero third-party security dependencies.

---

## Architecture

```
Client Request
      │
      ▼
┌─────────────────────────────────────────────────┐
│              Python Shield WAF  :8000            
│                                                 
│  1. IP Blocklist Filter   ─── config/malicious_ips.txt
│  2. Rate Limiter          ─── sliding window, per-IP async lock
│  3. Anomaly Detector      ─── AI-based zero-day detection
│  4. URL Path Inspector    ─── SQLi + XSS regex + double-decode
│  5. Query String Inspector─── decoded param scanning
│  6. Request Body Inspector─── configurable size limit
│  7. Header Inspector      ─── User-Agent, Referer, X-Forwarded-For
│  8. Self-Learning Pipe    ─── automated retraining loop
│                                                 
│  ✅ PASS → forward via shared AsyncClient        
│  ❌ BLOCK → 403 (RFC 7807 Problem Details) + log 
└─────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Backend App  :5000  │  (never exposed directly)
└──────────────────────┘
```

---

## Features

| Capability | Detail |
|---|---|
| **SQL Injection Detection** | UNION-based, boolean-blind, time-based (SLEEP/WAITFOR), error-based, stacked queries, hex literals, double-URL-decoded |
| **XSS Detection** | `<script>`, SVG/MathML, event handlers, `javascript:`/`data:` URIs, CSS `expression()`, DOM exfiltration patterns, HTML entity + double-URL decoded |
| **IP Blocklist** | CIDR range matching via stdlib `ipaddress`, hot-reload on file change |
| **Rate Limiting** | Sliding window, per-IP `asyncio.Lock` (race-condition-free), LRU eviction (bounded memory) |
| **Structured Logging** | Rotating JSON log (NDJSON) compatible with Elasticsearch / Splunk / Loki |
| **Config-driven** | All parameters in `waf_config.yaml`; env vars override for Docker/K8s |
| **Response Sanitisation** | Strips `Server`, `X-Powered-By` headers from upstream responses |
| **12-Factor Compliant** | `TARGET_URL`, `WAF_LOG_FILE` configurable via environment variables |

---

## Project Structure

```
python-shield-waf/
├── waf/
│   ├── core/
│   │   ├── engine.py        # Inspection pipeline (rule chain)
│   │   ├── models.py        # InspectionContext + BlockDecision dataclasses
│   │   └── proxy.py         # FastAPI reverse proxy + lifespan client pool
│   ├── security/
│   │   ├── ip_filter.py     # CIDR blocklist with hot-reload
│   │   ├── rate_limiter.py  # Async sliding-window rate limiter
│   │   ├── rules_sqli.py    # SQL Injection detection (SQLI-001)
│   │   └── rules_xss.py     # XSS detection (XSS-001)
│   └── utils/
│       ├── config_parser.py # YAML → typed WAFConfig dataclass
│       └── logger.py        # Rotating JSON logger
├── config/
│   ├── waf_config.yaml      # All runtime parameters
│   └── malicious_ips.txt    # Blocked IPs and CIDR ranges
├── demo_app/
│   └── app.py               # Intentionally vulnerable Flask target
├── tests/
│   ├── conftest.py
│   ├── test_sqli_rules.py   # 30+ SQLi vectors
│   ├── test_xss_rules.py    # 26+ XSS vectors
│   ├── test_rate_limiter.py # Async concurrency tests
│   └── test_ip_filter.py    # CIDR + hot-reload tests
├── Dockerfile               # Multi-stage, non-root user
├── docker-compose.yml       # WAF + demo app with healthchecks
├── pyproject.toml           # Pytest, ruff, coverage config
├── requirements.txt
└── requirements-dev.txt
```

---

## Quick Start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/[YOUR_GITHUB_USERNAME]/python-shield-waf.git
cd python-shield-waf
docker compose up --build
```

The WAF is now listening on **port 8000**. The demo app is reachable only through the WAF.

### Option B — Local development

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Start the vulnerable demo app (terminal 1)
python demo_app/app.py

# 4. Start the WAF (terminal 2)
uvicorn waf.core.proxy:app --host 0.0.0.0 --port 8000 --reload
```

---

## Attack Demo

With the stack running, open a second terminal and run the following:

```bash
# ✅ Legitimate request — should receive 200 OK
curl -s http://localhost:8000/

# ❌ SQL Injection in query string — should receive 403 Forbidden
curl -s "http://localhost:8000/login?id=1'+OR+1%3D1--"

# ❌ XSS in POST body — should receive 403 Forbidden
curl -s -X POST http://localhost:8000/login \
  --data "username=<script>alert(1)</script>&password=test"

# ❌ Rate limit — send 35 rapid requests, last ones should be blocked
for i in $(seq 1 35); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/; done
```

Blocked requests are logged to `logs/waf_alerts.log` as NDJSON:

```json
{"timestamp": "2024-01-15T10:30:42", "level": "WARNING", "message": "Request blocked",
 "attacker_ip": "172.17.0.1", "http_method": "GET", "target_path": "/login",
 "rule_id": "SQLI-001", "block_reason": "SQL Injection detected in query string"}
```

---

## Configuration

Edit `config/waf_config.yaml` to tune all parameters:

```yaml
rate_limit:
  max_requests: 30       # requests per window
  window_seconds: 60     # sliding window duration

rules:
  sqli_detection: true
  xss_detection: true
  inspect_query_string: true
  inspect_request_body: true
  max_body_inspect_bytes: 65536
```

Add blocked IPs/CIDRs to `config/malicious_ips.txt` (hot-reloaded on change):

```
# Known attacker ranges
192.168.100.1
10.0.0.0/8
2001:db8::/32
```

---

## Running Tests

```bash
pytest tests/ -v --cov=waf --cov-report=term-missing
```

Expected output: **100% pass rate** across 70+ test cases with >85% branch coverage.

---

## Security Design Notes

- **No third-party security libraries** — all detection uses stdlib `re`, `ipaddress`, `html`, `urllib.parse`. Fewer dependencies = smaller attack surface.
- **Fail-fast rule ordering** — cheap O(1) checks (IP blocklist, rate limit) run before expensive regex scans.
- **Double-decode normalisation** — payloads like `%2527` → `%27` → `'` are caught even after two rounds of URL encoding.
- **Dual-Model AI Layer**: Uses a supervised gradient boosted tree for known attacks and an unsupervised Isolation Forest for zero-days.
- **Self-Learning Pipeline**: Automatically collects attacks and benign baselines, retrains models, and hot-swaps them with zero downtime.
- **Immutable request context** — `InspectionContext` is a frozen dataclass; no rule can mutate the request mid-pipeline.
- **Per-IP async locks** — rate limiter uses `asyncio.Lock` per IP to prevent over-admission under concurrent load.
- **Non-root Docker user** — the WAF process runs as `appuser` (no write access to system paths).
- **Response header stripping** — `Server` and `X-Powered-By` are removed from upstream responses to reduce reconnaissance.

---

## License

MIT — see [LICENSE](LICENSE).
