# ChronoGuard Metrics Exporter - Prometheus/OTel metrics for temporal windows and audit lag
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
    && pip install -e . \
    && pip install prometheus-client>=0.19.0

# Copy metrics exporter specific code
COPY metrics_exporter/ ./metrics_exporter/
COPY src/domain/ ./src/domain/
COPY src/core/ ./src/core/
COPY src/infrastructure/ ./src/infrastructure/

# Create necessary directories
RUN mkdir -p /app/logs \
    && chown -R chronoguard:chronoguard /app

# Switch to application user
USER chronoguard

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/metrics || exit 1

# Expose port
EXPOSE 8002

# Labels
LABEL org.opencontainers.image.title="ChronoGuard Metrics Exporter"
LABEL org.opencontainers.image.description="Prometheus/OTel metrics for temporal windows, denials, and audit lag"
LABEL org.opencontainers.image.vendor="ChronoGuard"
LABEL org.opencontainers.image.version="1.0.0"

# Start metrics exporter
CMD ["python", "-m", "metrics_exporter.main"]