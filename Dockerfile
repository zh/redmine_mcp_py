FROM python:3.12-slim

# Version tracks the TODO.md plan phase number. Bump in lockstep with
# config.VERSION and docker-compose.yml's image tag.
ARG VERSION=1.7
LABEL org.opencontainers.image.title="redmine-mcp" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/zhware/redmine_mcp_py" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=7860

WORKDIR /app

# Install deps as root (system site-packages); the runtime user only needs
# read+exec on them.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# UID 1000 matches Hugging Face Spaces' convention and works unchanged on
# Render, Fly.io, Cloud Run, Railway, and self-hosted Docker.
RUN groupadd --gid 1000 app \
    && useradd --uid 1000 --gid 1000 --home /app --no-create-home app

COPY --chown=app:app server.py config.py ./
COPY --chown=app:app auth ./auth

USER app

# $PORT defaults to 7860 (HF Spaces, which sets app_port: 7860 in README
# frontmatter and does NOT inject PORT). Render injects 10000, Fly/Cloud
# Run/Railway inject their own. Shell form lets the value expand at runtime.
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
        urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"7860\")}/healthz', timeout=3); \
        sys.exit(0)" || exit 1

CMD exec uvicorn server:app \
    --host 0.0.0.0 \
    --port ${PORT:-7860} \
    --proxy-headers \
    --forwarded-allow-ips '*'
