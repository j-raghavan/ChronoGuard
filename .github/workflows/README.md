# ChronoGuard GitHub Actions Workflows

## Overview

ChronoGuard uses two types of Docker workflows:

1. **docker-build.yml** - Automatic validation (PR/push to dev branches)
2. **docker-images.yml** - Manual release builds (workflow_dispatch)

## Workflows

### 1. Test Suite (`test-suite.yml`)

**Trigger**: Automatic on push/PR to `master`, `develop`, or `feat/*` branches

**What it does**:
- ✅ Runs unit tests with 95%+ coverage requirement
- ✅ Runs integration tests with full stack
- ✅ Runs security analysis
- ✅ Uploads coverage to Codecov

### 2. Code Quality (`code-quality.yml`)

**Trigger**: Automatic on push/PR

**What it does**:
- ✅ Linting (ruff + black)
- ✅ Type checking (mypy)
- ✅ Security scanning (bandit)
- ✅ Import validation

### 3. Docker Build Validation (`docker-build.yml`)

**Trigger**: Automatic on PR or push to `develop`/`feat/*`

**What it does**:
- ✅ Validates Dockerfiles build successfully
- ✅ Builds images locally (no push)
- ✅ Single platform (linux/amd64) for speed
- ✅ Tests Docker Compose stack
- ❌ Does NOT push to Docker Hub
- ❌ Does NOT run security scans

**Purpose**: Fast feedback loop for developers

### 4. Docker Images - Release Build (`docker-images.yml`) ⭐

**Trigger**: **MANUAL ONLY** via workflow_dispatch

**What it does**:
- 🏗️ Builds all 6 ChronoGuard images
- 🏷️ Tags with release version
- 📦 Optionally pushes to Docker Hub
- 🔒 Runs Trivy security scans
- 🧪 Tests image functionality
- 📝 Updates Docker Hub descriptions
- 🌍 Multi-platform builds (amd64 + arm64)

## How to Release Docker Images

### Step 1: Test Build (Dry Run)

First, test the build without pushing:

```bash
gh workflow run docker-images.yml \
  -f release_tag=v1.0.0 \
  -f push_to_registry=false \
  -f platforms=linux/amd64
```

**What happens**:
- ✅ Validates tag format
- ✅ Builds all images locally
- ❌ Does NOT push to Docker Hub
- ❌ Does NOT run security scans
- ❌ Does NOT test images
- ❌ Does NOT update descriptions

### Step 2: Production Release

Once test build succeeds, do the real release:

```bash
gh workflow run docker-images.yml \
  -f release_tag=v1.0.0 \
  -f push_to_registry=true \
  -f platforms=linux/amd64,linux/arm64
```

**What happens**:
- ✅ Validates tag format
- ✅ Builds all images for multiple platforms
- ✅ Pushes to Docker Hub
- ✅ Runs Trivy security scans
- ✅ Tests each image
- ✅ Updates Docker Hub descriptions

### Step 3: Verify Release

Check the workflow run:
```bash
gh run watch
```

Verify images are on Docker Hub:
```bash
docker pull chronoguard/proxy:v1.0.0
docker pull chronoguard/policy-engine:v1.0.0
docker pull chronoguard/audit-sink:v1.0.0
docker pull chronoguard/metrics-exporter:v1.0.0
docker pull chronoguard/dashboard:v1.0.0
docker pull chronoguard/playwright-runner:v1.0.0
```

## Workflow Parameters

### docker-images.yml Inputs

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `release_tag` | ✅ Yes | string | - | Release tag in semver format (e.g., v1.0.0) |
| `push_to_registry` | ✅ Yes | boolean | false | Push to Docker Hub (false = dry run) |
| `platforms` | ❌ No | string | linux/amd64,linux/arm64 | Target platforms |

**Tag Format Rules**:
- ✅ Must start with `v`
- ✅ Must follow semver: `v{major}.{minor}.{patch}`
- ✅ Can include pre-release: `v1.0.0-beta.1`, `v1.0.0-rc.2`
- ❌ No `latest` tags - use `v` versions only

**Valid Examples**:
- `v1.0.0` - Production release
- `v1.2.3` - Production release
- `v2.0.0-beta.1` - Beta release
- `v1.0.0-rc.1` - Release candidate

**Invalid Examples**:
- `1.0.0` - Missing `v` prefix
- `latest` - Not semver
- `v1.0` - Missing patch version
- `main` - Not semver

## Release Process

### Full Release Workflow

1. **Merge to master**
   ```bash
   git checkout master
   git pull origin master
   ```

2. **Run test build**
   ```bash
   gh workflow run docker-images.yml \
     -f release_tag=v1.0.0 \
     -f push_to_registry=false
   ```

3. **Wait for build to complete**
   ```bash
   gh run watch
   ```

4. **If successful, do production release**
   ```bash
   gh workflow run docker-images.yml \
     -f release_tag=v1.0.0 \
     -f push_to_registry=true
   ```

5. **Create GitHub release**
   ```bash
   gh release create v1.0.0 \
     --title "ChronoGuard v1.0.0" \
     --notes "See CHANGELOG.md for details"
   ```

6. **Update CHANGELOG.md**
   - Document what changed in this release
   - Commit and push

## Images Built

All workflows build these 6 images:

1. **chronoguard/proxy** - Envoy forward proxy with TLS and OPA
2. **chronoguard/policy-engine** - OPA with temporal policies
3. **chronoguard/audit-sink** - Audit log ingestion with hash chaining
4. **chronoguard/metrics-exporter** - Prometheus/OTel metrics
5. **chronoguard/dashboard** - React web UI
6. **chronoguard/playwright-runner** - Pre-configured test automation

## Environment Variables

Images use these environment variables (set in docker-compose):

- `CHRONOGUARD_ENV` - Environment (development, staging, production)
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `SECRET_KEY` - Application secret key
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OpenTelemetry collector endpoint

## Secrets Required

### For Docker Publishing (docker-images.yml)

- `DOCKERHUB_PAT` - Docker Hub Personal Access Token
  - Required permission: Push to repositories
  - Generate at: https://hub.docker.com/settings/security

### For Test Coverage (test-suite.yml)

- `CODECOV_TOKEN` - Codecov upload token (optional)
  - Get from: https://codecov.io/gh/YOUR_ORG/chronoguard

## Troubleshooting

### "Invalid tag format" error
```
❌ Invalid tag format. Expected semver like v1.0.0
```
**Fix**: Use `v1.0.0` format, not `1.0.0` or `latest`

### Build succeeds but push fails
**Check**:
- `DOCKERHUB_PAT` secret is set
- Token hasn't expired
- Docker Hub repositories exist

### Security scan fails
**Action**: Review Trivy results in workflow artifacts
- Address CRITICAL and HIGH severity issues
- LOW/MEDIUM can be documented

### Multi-platform build too slow
**Solution**: Use single platform for testing
```bash
-f platforms=linux/amd64
```

## Workflow Comparison

| Feature | docker-build.yml | docker-images.yml |
|---------|------------------|-------------------|
| **Trigger** | Automatic (PR/push) | Manual only |
| **Purpose** | Validation | Release |
| **Push to Docker Hub** | ❌ Never | ✅ Optional |
| **Platforms** | linux/amd64 only | Multi-platform |
| **Security Scans** | ❌ No | ✅ Yes (if pushed) |
| **Image Testing** | ✅ Docker Compose | ✅ Individual + Compose |
| **Speed** | ⚡ Fast (~5 min) | 🐢 Slower (~20 min) |
| **Use Case** | Development validation | Production releases |

## Best Practices

### Development
- Let automatic workflows run on every push
- Fix any failing checks before requesting review
- Ensure coverage stays ≥95%

### Releases
- Always test build first (`push_to_registry=false`)
- Review security scan results before pushing
- Tag production releases with clean semver (v1.0.0, v1.2.0)
- Use pre-release tags for testing (v1.0.0-beta.1, v1.0.0-rc.1)

### Versioning Strategy
- **v1.0.0** - Major production release
- **v1.1.0** - Minor feature additions
- **v1.0.1** - Patch/bugfix releases
- **v2.0.0-beta.1** - Beta testing
- **v1.5.0-rc.1** - Release candidates

## Monitoring

```bash
# Watch current workflow
gh run watch

# List all runs
gh run list --workflow=docker-images.yml

# View specific run
gh run view <run-id> --log

# Download artifacts
gh run download <run-id>
```

## Status Badges

Add to README.md:

```markdown
[![Test Suite](https://github.com/YOUR_ORG/chronoguard/actions/workflows/test-suite.yml/badge.svg)](https://github.com/YOUR_ORG/chronoguard/actions/workflows/test-suite.yml)
[![Code Quality](https://github.com/YOUR_ORG/chronoguard/actions/workflows/code-quality.yml/badge.svg)](https://github.com/YOUR_ORG/chronoguard/actions/workflows/code-quality.yml)
[![Docker Build](https://github.com/YOUR_ORG/chronoguard/actions/workflows/docker-build.yml/badge.svg)](https://github.com/YOUR_ORG/chronoguard/actions/workflows/docker-build.yml)
[![codecov](https://codecov.io/gh/YOUR_ORG/chronoguard/branch/master/graph/badge.svg)](https://codecov.io/gh/YOUR_ORG/chronoguard)
```
