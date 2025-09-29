# ChronoGuard Scripts

This directory contains utility scripts for managing the ChronoGuard development and deployment lifecycle.

## Available Scripts

### `docker_management.sh`
Comprehensive Docker management script for ChronoGuard services.

**Usage:**
```bash
./scripts/docker_management.sh [COMMAND]
```

**Commands:**
- `build-all` - Build all 6 ChronoGuard Docker images locally
- `push-all` - Push all images to Docker Hub (requires `docker login`)
- `pull-all` - Pull all images from Docker Hub
- `start-stack` - Start complete ChronoGuard stack with all services
- `stop-stack` - Stop the entire ChronoGuard stack
- `restart-stack` - Restart the entire stack
- `logs [service]` - View logs (all services or specific service)
- `status` - Show current status of all services
- `cleanup` - Remove all containers and volumes (destructive)
- `help` - Show usage information

**Examples:**
```bash
# Build all images locally
./scripts/docker_management.sh build-all

# Start the complete stack
./scripts/docker_management.sh start-stack

# View logs for specific service
./scripts/docker_management.sh logs chronoguard-api

# Check service status
./scripts/docker_management.sh status

# Stop everything
./scripts/docker_management.sh stop-stack
```

**Prerequisites:**
- Docker and Docker Compose installed
- `.env` file configured (copies from `deployments/docker/.env.example`)
- For push operations: `docker login` with chronoguard credentials

**Services Started:**
1. **chronoguard/proxy** - Envoy forward proxy (port 8080)
2. **chronoguard/policy-engine** - OPA temporal policies (port 8181)
3. **chronoguard/audit-sink** - Audit log ingestion (port 8001)
4. **chronoguard/metrics-exporter** - Prometheus metrics (port 8002)
5. **chronoguard/dashboard** - Web UI (port 3000)
6. **chronoguard/playwright-runner** - Smoke tests (on-demand)

Plus supporting infrastructure (PostgreSQL, Redis, Prometheus, Grafana, Jaeger).

### `verify_foundation.py`
Verification script to ensure Phase 1 foundation is properly implemented.

**Usage:**
```bash
python scripts/verify_foundation.py
```

**Checks:**
- Project structure compliance
- Module import validation
- Core functionality verification
- Architecture pattern enforcement

**Exit Codes:**
- `0` - All verification passed
- `1` - Verification failed