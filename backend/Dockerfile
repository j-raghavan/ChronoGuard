# Multi-stage production-ready Dockerfile for ChronoGuard backend

# Stage 1: Build dependencies and install packages
FROM python:3.11-slim as builder

# Set environment variables for build
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies required for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd --gid 1000 chronoguard \
    && useradd --uid 1000 --gid chronoguard --shell /bin/bash --create-home chronoguard

# Set working directory
WORKDIR /app

# Copy dependency metadata and application source required for packaging
COPY pyproject.toml README.md poetry.lock ./
COPY backend ./backend

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies from pyproject.toml
RUN pip install --upgrade pip \
    && pip install -e .

# Stage 2: Production runtime
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    CHRONOGUARD_ENV=production

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user
RUN groupadd --gid 1000 chronoguard \
    && useradd --uid 1000 --gid chronoguard --shell /bin/bash --create-home chronoguard

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code and metadata with proper ownership
COPY --chown=chronoguard:chronoguard backend/src/ ./src/
COPY --chown=chronoguard:chronoguard backend/alembic/ ./alembic/
COPY --chown=chronoguard:chronoguard pyproject.toml README.md poetry.lock ./

# Create necessary directories
RUN mkdir -p /app/logs /app/data \
    && chown -R chronoguard:chronoguard /app

# Switch to non-root user
USER chronoguard

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# Stage 3: Development runtime (optional)
FROM production as development

# Switch back to root to install dev dependencies
USER root

# Install development system dependencies
RUN apt-get update && apt-get install -y \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install development dependencies from pyproject.toml
RUN pip install -e ".[dev,lint,security]"

# Switch back to application user
USER chronoguard

# Override command for development
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
