# Changelog

All notable changes to ChronoGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-08 - MVP Release

### Added

#### Core Architecture
- **Domain Layer** with clean architecture principles (no infrastructure dependencies)
- **Application Layer** implementing CQRS pattern with Commands and Queries
- **Presentation Layer** with FastAPI REST API
- **Infrastructure Layer** with PostgreSQL, Redis, and OPA integrations

#### Policy Engine Integration
- Open Policy Agent (OPA) integration for policy evaluation
- Policy compilation to Rego format (`infrastructure/opa/policy_compiler.py`)
- OPA decision log ingestion via internal API endpoints:
  - `POST /api/v1/internal/opa/decisions` - Single decision ingestion
  - `POST /api/v1/internal/opa/decisions/batch` - Batch decision ingestion
- Envoy ext_authz integration for proxy-level policy enforcement
- OPA configuration files in `configs/opa/`

#### Proxy Infrastructure
- Envoy forward proxy with mTLS authentication
- Static proxy configuration in `configs/envoy/envoy.yaml`
- 6-service Docker Compose stack:
  1. Envoy Proxy (Port 8080)
  2. OPA Policy Engine (Port 8181/9192)
  3. FastAPI Backend (Port 8000)
  4. React Dashboard (Port 3000)
  5. PostgreSQL + TimescaleDB (Port 5432)
  6. Redis (Port 6379)

#### Audit Trail
- Immutable audit entries with cryptographic hash chaining
- Automatic audit entry creation from OPA decision logs
- TimescaleDB hypertable for time-series audit data
- Hash chain verification for audit log integrity
- Temporal analytics queries for compliance reporting

#### Testing & Quality
- Comprehensive unit test suite (1,600+ tests)
- Integration test infrastructure with Docker Compose
- 96%+ test coverage maintained across all modules
- Code quality enforcement: mypy, ruff, black, isort
- PostgreSQL and TimescaleDB integration tests

#### Frontend
- React + Vite dashboard for monitoring
- Agent management UI
- Policy management UI
- Audit log viewer with temporal filters
- Real-time service health indicators

#### API Endpoints
- **Agents:**
  - `POST /api/v1/agents` - Create agent
  - `GET /api/v1/agents/{agent_id}` - Get agent
  - `GET /api/v1/agents` - List agents (paginated)
  - `PUT /api/v1/agents/{agent_id}` - Update agent
- **Policies:**
  - `POST /api/v1/policies` - Create policy
  - `GET /api/v1/policies/{policy_id}` - Get policy
  - `GET /api/v1/policies` - List policies (paginated)
  - `PUT /api/v1/policies/{policy_id}` - Update policy
  - `DELETE /api/v1/policies/{policy_id}` - Delete policy
- **Audit:**
  - `GET /api/v1/audit` - List audit entries (filtered, paginated)
  - `GET /api/v1/audit/{entry_id}` - Get audit entry
  - `GET /api/v1/audit/analytics/temporal` - Temporal analytics
- **Health:**
  - `GET /health` - Health check
  - `GET /metrics` - Prometheus metrics

### Changed

#### Architecture Decisions
- **OPA Integration Flow:** Changed from FastAPI→OPA to Envoy→OPA (ext_authz) for better performance
- **Audit Scope:** Focused on access control decisions rather than all CRUD operations
- **Deployment:** Simplified to docker-compose instead of complex Kubernetes setup for MVP

#### Domain Layer Cleanup
- Removed infrastructure dependencies from domain services
- Signer remains as known limitation (documented for post-MVP cleanup)
- Domain entities are pure business logic with no external dependencies

### Fixed

- Domain layer independence violations (Phase 1)
- OPA decision log ingestion endpoint implementation (Phase 3)
- Policy compilation and deployment to OPA (Phase 4)
- Audit side effects for access operations (Phase 6)
- Docker deployment configuration (Phase 5)

### Technical Details

- **Test Coverage:** 96.40%
- **Total Tests:** 1,651 passing
- **Services:** 6 (Envoy, OPA, FastAPI, Dashboard, PostgreSQL, Redis)
- **Architecture:** Clean Architecture + DDD + CQRS
- **Python Version:** 3.11+
- **Database:** PostgreSQL 15 + TimescaleDB
- **Code Quality:** All linting, type checking, and formatting checks passing

### Deferred to Future Releases

The following features were planned but deferred to post-MVP:

- gRPC server with streaming support (v0.2.0)
- WebSocket event streaming for real-time updates (v0.2.0)
- Dynamic Envoy configuration via xDS protocol (v0.2.0)
- Advanced rate limiting with Redis (v0.2.0)
- Feature-flag-controlled dependency injection (v0.2.0)
- Kubernetes deployment manifests (v0.3.0)
- Multi-tenancy hardening (v0.2.0)
- Policy versioning and rollback (v0.2.0)

### Known Limitations

1. **Signer Dependency:** Domain layer still imports infrastructure signer (technical debt)
2. **CRUD Audit Trail:** Agent/policy create/update/delete operations not audited (only access attempts)
3. **Static Configuration:** Envoy uses static config instead of dynamic xDS
4. **Limited Rate Limiting:** Basic implementation, not Redis-backed

### Documentation

- Updated `README.md` with accurate Quick Start and Architecture sections
- Updated `MISSING.md` to reflect implementation status
- Updated `docs/architecture/architecture.md` with implementation notes
- Created `CHANGELOG.md` to track releases

---

## [Unreleased] - v0.2.0

### Planned Features

- gRPC server with bidirectional streaming
- WebSocket endpoints for real-time event streaming
- Advanced Redis-backed rate limiting
- Dynamic Envoy configuration via xDS
- Policy versioning and rollback
- Enhanced multi-tenancy controls
- Performance optimization and benchmarking

---

## Release History

- **v0.1.0** (2025-11-08) - MVP Release
  - Core domain models
  - OPA integration
  - Envoy proxy
  - Audit trail
  - Docker deployment
  - Web dashboard
  - 96%+ test coverage
