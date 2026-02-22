# Multi-stage build for AI Code Review Platform
FROM python:3.11-slim as builder

WORKDIR /app

# System deps — libpq-dev required to compile psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Production stage ─────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/root/.local/bin:$PATH

# Runtime deps — libpq required for psycopg2 at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 appuser && \
    mkdir -p /app && \
    chown -R appuser:appuser /app

WORKDIR /app

COPY --from=builder /root/.local /root/.local
COPY --chown=appuser:appuser . .

RUN mkdir -p backend/uploads backend/processed backend/output backend/reports \
    backend/vector_db backend/instance backend/models backend/.cache && \
    chown -R appuser:appuser backend

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

WORKDIR /app/backend

# Use gunicorn in production; falls back gracefully if not installed
CMD ["sh", "-c", "python -c 'from models.user import User; User.init_db()' && gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 120 app:app"]
