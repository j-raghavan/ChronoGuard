# ChronoGuard Proxy - Envoy forward proxy with TLS, DFP, and OPA ext_authz defaults
FROM envoyproxy/envoy:v1.28-latest as base

# Install curl for health checks
USER root
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create envoy user and directories
RUN groupadd --gid 1000 envoy \
    && useradd --uid 1000 --gid envoy --shell /bin/bash envoy

RUN mkdir -p /etc/envoy /var/log/envoy /tmp/envoy \
    && chown -R envoy:envoy /etc/envoy /var/log/envoy /tmp/envoy

# Copy Envoy configuration
COPY envoy-proxy.yaml /etc/envoy/envoy.yaml
COPY certs/ /etc/envoy/certs/

# Set proper permissions
RUN chown -R envoy:envoy /etc/envoy
RUN chmod 644 /etc/envoy/envoy.yaml
RUN chmod -R 600 /etc/envoy/certs/

# Switch to envoy user
USER envoy

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9901/ready || exit 1

# Expose ports
EXPOSE 8080 9901

# Labels for image metadata
LABEL org.opencontainers.image.title="ChronoGuard Proxy"
LABEL org.opencontainers.image.description="Envoy forward proxy with TLS, DFP, and OPA ext_authz"
LABEL org.opencontainers.image.vendor="ChronoGuard"
LABEL org.opencontainers.image.version="1.0.0"

# Start Envoy
CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]