# ChronoGuard Playwright Runner - Playwright + proxy prewired for demo/smoke tests
FROM mcr.microsoft.com/playwright:v1.40.0-focal as base

# Install additional tools
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd --gid 1000 chronoguard \
    && useradd --uid 1000 --gid chronoguard --shell /bin/bash --create-home chronoguard

# Set working directory
WORKDIR /app

# Install Node.js dependencies for test runner
COPY playwright-runner/package*.json ./
RUN npm ci

# Install Python for ChronoGuard SDK integration
RUN apt-get update && apt-get install -y python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy ChronoGuard Python SDK
COPY sdk/python/ ./sdk/python/
RUN pip3 install -e ./sdk/python/

# Copy test scripts and configurations
COPY playwright-runner/tests/ ./tests/
COPY playwright-runner/config/ ./config/
COPY playwright-runner/src/ ./src/

# Copy proxy configuration
COPY docker/proxy/envoy-proxy.yaml ./config/proxy/

# Create necessary directories and set permissions
RUN mkdir -p /app/reports /app/screenshots /app/logs \
    && chown -R chronoguard:chronoguard /app

# Switch to application user
USER chronoguard

# Install Playwright browsers
RUN npx playwright install

# Health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=30s --retries=2 \
    CMD curl -f http://localhost:8003/health || exit 1

# Expose port for test results API
EXPOSE 8003

# Labels
LABEL org.opencontainers.image.title="ChronoGuard Playwright Runner"
LABEL org.opencontainers.image.description="Playwright + proxy prewired for demo and scripted smoke tests"
LABEL org.opencontainers.image.vendor="ChronoGuard"
LABEL org.opencontainers.image.version="1.0.0"

# Default command runs smoke tests
CMD ["npm", "run", "test:smoke"]