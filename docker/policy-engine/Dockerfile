# ChronoGuard Policy Engine - OPA with temporal-access Rego bundle
FROM openpolicyagent/opa:latest-envoy as base

# Install curl for health checks
USER root
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create opa user and directories
RUN groupadd --gid 1000 opa \
    && useradd --uid 1000 --gid opa --shell /bin/bash opa

RUN mkdir -p /policies /data /logs \
    && chown -R opa:opa /policies /data /logs

# Copy Rego policies
COPY policies/ /policies/
COPY temporal-access-bundle.tar.gz /policies/

# Set permissions
RUN chown -R opa:opa /policies
RUN chmod -R 644 /policies/*.rego

# Switch to opa user
USER opa

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8181/health?bundle=true || exit 1

# Expose ports
EXPOSE 8181 8182 9192

# Labels
LABEL org.opencontainers.image.title="ChronoGuard Policy Engine"
LABEL org.opencontainers.image.description="OPA with temporal-access Rego policies for time-based authorization"
LABEL org.opencontainers.image.vendor="ChronoGuard"
LABEL org.opencontainers.image.version="1.0.0"

# Start OPA with gRPC server for Envoy ext_authz
CMD ["run", \
     "--server", \
     "--addr=0.0.0.0:8181", \
     "--diagnostic-addr=0.0.0.0:8182", \
     "--set=plugins.envoy_ext_authz_grpc.addr=:9192", \
     "--set=plugins.envoy_ext_authz_grpc.enable_reflection=true", \
     "--set=decision_logs.console=true", \
     "--bundle=/policies/", \
     "/policies"]