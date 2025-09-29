# ChronoGuard Audit Sink - Ingests decisions/logs and writes hash-chained audit records
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd --gid 1000 chronoguard \
    && useradd --uid 1000 --gid chronoguard --shell /bin/bash chronoguard

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY pyproject.toml ./
RUN pip install --upgrade pip \
    && pip install -e .

# Copy audit sink specific code
COPY audit_sink/ ./audit_sink/
COPY src/domain/ ./src/domain/
COPY src/core/ ./src/core/
COPY src/infrastructure/ ./src/infrastructure/

# Create necessary directories
RUN mkdir -p /app/logs /app/data \
    && chown -R chronoguard:chronoguard /app

# Switch to application user
USER chronoguard

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Expose port
EXPOSE 8001

# Labels
LABEL org.opencontainers.image.title="ChronoGuard Audit Sink"
LABEL org.opencontainers.image.description="Ingests access decisions and creates hash-chained audit records"
LABEL org.opencontainers.image.vendor="ChronoGuard"
LABEL org.opencontainers.image.version="1.0.0"

# Start audit sink service
CMD ["python", "-m", "audit_sink.main"]