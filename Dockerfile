# =============================================================================
# Python Shield WAF — Multi-Stage Dockerfile
# =============================================================================
#
# Stage 1 (builder): install Python dependencies into an isolated venv.
# Stage 2 (runtime): copy only the venv and application code — no build tools.
#
# Running as a non-root user (appuser) follows the principle of least privilege;
# a compromised container cannot write to system paths even if a vulnerability
# exists in the application layer.

# ---------------------------------------------------------------------------
# Stage 1: dependency builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into an explicit prefix so Stage 2 can COPY it cleanly
COPY requirements.txt .
RUN pip install --upgrade pip --quiet \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Create a non-root user and group
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup --no-create-home appuser

WORKDIR /app

# Copy installed packages from the builder stage
COPY --from=builder /install /usr/local

# Copy application source (exclude .git, __pycache__, tests via .dockerignore)
COPY waf/       ./waf/
COPY config/    ./config/

# Create the log directory and ensure the non-root user can write to it
RUN mkdir -p /app/logs && chown -R appuser:appgroup /app

# Switch to non-root user for all subsequent commands
USER appuser

# Expose the WAF listening port
EXPOSE 8000

# Health check — the WAF proxies /health to the backend; a 200 means
# both the WAF and the backend are operational.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# Run with uvicorn; workers=1 keeps rate-limiter state in a single process.
# For horizontal scaling, replace in-memory state with Redis.
CMD ["uvicorn", "waf.core.proxy:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
