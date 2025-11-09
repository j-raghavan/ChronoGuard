# ChronoGuard

**Zero-trust proxy for browser automation with temporal controls**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/coverage-95%25+-green.svg)](backend/tests)

## Overview

ChronoGuard is an open-source zero-trust proxy that provides network-enforced authorization for browser automation through a mandatory forward proxy. It controls all egress traffic from centralized agent infrastructure (CI/CD, Kubernetes, VM fleets) and provides temporal visibility into automation activities.

**Core value proposition:** *"Know not just WHERE your automation goes, but WHEN - with network-enforced controls that can't be bypassed."*

### Key Features

- **Zero-Trust Network Enforcement** - Browser agents physically cannot reach the internet except through the proxy
- **Domain-Level Access Control** - Allowlists and blocklists enforced at the network layer via Open Policy Agent (OPA)
- **Temporal Controls** - Time-based access windows with real-time visibility and analytics
- **Immutable Audit Logs** - Chronological, hash-chained audit trails with cryptographic verification
- **mTLS Authentication** - Agent identity verification through X.509 client certificates
- **Real-Time Monitoring** - WebSocket-based event streaming and Prometheus metrics
- **Multi-Tenancy** - Complete tenant isolation for enterprise deployments

### Target Use Cases

- E-commerce intelligence and competitive analysis
- Fintech research and market monitoring
- Healthcare data operations with compliance requirements
- Quality assurance and testing providers
- Any organization running browser agents in controlled infrastructure with compliance obligations

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 13+ with TimescaleDB extension
- Redis 6+
- Docker and Docker Compose (for local development)

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/j-raghavan/chronoguard.git
cd chronoguard

# Install dependencies
make install

# Run quality checks (linting, type checking, tests)
make pre-commit

# Start the complete stack (Envoy, OPA, PostgreSQL, Redis)
make docker-start

# Run the backend server
make run-backend

# Run the frontend dashboard
make run-frontend
```

### Running Tests

```bash
# Run unit tests with coverage
make test-unit

# Run integration tests
make test-integration

# View coverage report
make coverage-html
```

## Architecture

ChronoGuard follows **Domain-Driven Design (DDD)** with **Clean Architecture** principles and implements **CQRS** (Command Query Responsibility Segregation) for clear separation of concerns.

### High-Level Architecture

```
┌────────────────────┐     ┌────────────────────┐     ┌────────────────┐
│  Browser Agents    │────▶│   ChronoGuard      │────▶│   Internet     │
│  - Playwright      │     │   Proxy (Envoy)    │     │                │
│  - Puppeteer       │     │   + OPA + Time     │     │                │
│  - Selenium        │     │   Enforcement      │     │                │
└────────────────────┘     └────────────────────┘     └────────────────┘
                                    │
                            ┌───────▼────────┐
                            │  Chronological │
                            │   Audit Logs   │
                            │  (TimescaleDB) │
                            └────────────────┘
```

### Core Components

- **Envoy Proxy** - Forward proxy with mTLS support for agent authentication
- **Open Policy Agent (OPA)** - Policy evaluation engine for access control decisions
- **FastAPI Backend** - REST API for management and configuration
- **PostgreSQL + TimescaleDB** - Primary persistence with time-series optimization
- **Redis** - Caching and rate limiting
- **React Dashboard** - Web-based monitoring and administration interface

For detailed architecture documentation, see:
- [Architecture Overview](docs/architecture/architecture-overview.md) - High-level design and patterns
- [Detailed Architecture](docs/architecture/architecture.md) - In-depth technical specifications
- [Architecture Diagrams](docs/architecture/architecture-diagrams.md) - Visual representations
- [Architecture Index](docs/architecture/architecture-index.md) - Component reference

## Code Structure

```
ChronoGuard/
├── backend/               # Python backend application
│   ├── src/               # Source code
│   │   ├── presentation/  # Presentation layer
│   │   │   ├── api/       # FastAPI REST routes
│   │   │   ├── grpc/      # gRPC services
│   │   │   └── websocket/ # WebSocket handlers
│   │   ├── application/   # CQRS commands and queries
│   │   ├── domain/        # Domain entities, services, repositories
│   │   ├── infrastructure/# External integrations (OPA, Envoy, persistence)
│   │   └── core/          # Cross-cutting concerns (config, logging, DI)
│   └── tests/             # Test suite
│       ├── unit/          # Unit tests (95%+ coverage)
│       └── integration/   # Integration tests
├── frontend/              # React + TypeScript dashboard
│   └── src/
│       ├── components/    # React components
│       ├── pages/         # Page components
│       ├── services/      # API clients
│       ├── hooks/         # Custom React hooks
│       ├── types/         # TypeScript type definitions
│       └── lib/           # Utilities and helpers
├── sdk/                   # Client SDKs
│   ├── python/            # Python SDK for agent integration
│   ├── javascript/        # JavaScript/TypeScript SDK
│   └── go/                # Go SDK
├── configs/               # Configuration templates
│   ├── envoy/             # Envoy proxy configurations
│   ├── opa/               # OPA policy templates
│   └── nginx/             # Nginx configurations
├── deployments/           # Deployment manifests
│   ├── docker/            # Docker Compose files
│   ├── kubernetes/        # Kubernetes manifests
│   └── helm/              # Helm charts
├── docker/                # Dockerfiles for various services
├── scripts/               # Development and deployment scripts
└── docs/                  # Documentation
    ├── architecture/      # Architecture documentation
    ├── api/               # API documentation
    ├── guides/            # User guides
    ├── project/           # Project management docs
    └── testing/           # Testing documentation
```

## Development Workflow

### Code Quality Standards

ChronoGuard maintains strict code quality standards:

- **95%+ Test Coverage** - All code must have comprehensive test coverage
- **Type Safety** - Full type hints with mypy validation
- **Code Formatting** - Black and isort for consistent style
- **Linting** - Ruff for fast, comprehensive linting
- **Security** - Bandit for security issue detection

See [CODING_GUIDELINES.md](CODING_GUIDELINES.md) for detailed standards.

### Development Commands

```bash
# Install dependencies
make install

# Code formatting
make format

# Linting
make lint

# Type checking
make typecheck

# Run all quality checks
make pre-commit

# Run tests
make test

# Generate coverage report
make coverage

# Start development servers
make dev
```

## Contributing

We welcome contributions! ChronoGuard is an open-source project under the Apache 2.0 license.

### How to Contribute

1. **Fork the repository** on GitHub
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Follow coding standards** - Run `make pre-commit` before committing
4. **Write tests** - Maintain 95%+ coverage
5. **Commit your changes** (`git commit -m 'Add amazing feature'`)
6. **Push to the branch** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

### Pull Request Guidelines

- Ensure all tests pass and coverage remains at 95%+
- Follow the [coding guidelines](CODING_GUIDELINES.md)
- Update documentation as needed
- Include descriptive commit messages
- Reference any related issues

### Development Setup

See the [Quick Start](#quick-start) section for local development setup.

## Documentation

- **[PROJECT_PLAN.md](PROJECT_PLAN.md)** - High-level project plan and roadmap
- **[DEVPLAN.md](DEVPLAN.md)** - Detailed development plan (internal)
- **[CLAUDE.md](CLAUDE.md)** - Project instructions for AI assistance
- **[CODING_GUIDELINES.md](CODING_GUIDELINES.md)** - Code quality standards
- **[docs/architecture/](docs/architecture/)** - Architecture documentation
- **[docs/testing/](docs/testing/)** - Testing documentation
- **[docs/guides/](docs/guides/)** - User guides

## API Documentation

The ChronoGuard REST API is documented with OpenAPI (Swagger):

- **API Docs (Swagger UI)**: http://localhost:8000/docs
- **API Schema**: http://localhost:8000/openapi.json

## Monitoring and Observability

ChronoGuard provides comprehensive monitoring capabilities:

- **Prometheus Metrics**: http://localhost:8000/metrics
- **Health Check**: http://localhost:8000/health
- **Real-Time Events**: WebSocket endpoint at ws://localhost:8000/ws/v1/events
- **Distributed Tracing**: OpenTelemetry integration (optional Jaeger backend)
- **Structured Logging**: JSON format with correlation IDs

## Security

### Reporting Security Issues

If you discover a security vulnerability, please report it through [GitHub Security Advisories](https://github.com/j-raghavan/chronoguard/security/advisories/new). This allows us to handle the issue privately before public disclosure.

**Do not create public GitHub issues for security vulnerabilities.**

### Security Features

- mTLS authentication for agent identity verification
- Cryptographic hash chains for audit log integrity
- Multi-tenant isolation with tenant-scoped queries
- Policy-based access control via OPA
- Rate limiting and domain restrictions
- Certificate expiry tracking and validation

## License

ChronoGuard is licensed under the [Apache License 2.0](LICENSE).

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/j-raghavan/chronoguard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/j-raghavan/chronoguard/discussions)

## Roadmap

### Phase 1: Foundation (Complete ✅)
- Core domain models and entities
- PostgreSQL persistence with TimescaleDB
- Basic CRUD operations with multi-tenancy
- Comprehensive test suite (95%+ coverage)

### Phase 2: Policy Engine (Complete ✅)
- OPA integration
- Policy compilation and evaluation
- Domain-based access control
- Time-based restrictions

### Phase 3: Proxy Integration (Complete ✅)
- Envoy proxy integration
- mTLS authentication
- xDS configuration management
- Real-time policy updates

### Phase 4: Monitoring & Analytics (Complete ✅)
- Temporal analytics
- WebSocket event streaming
- Prometheus metrics
- Dashboard UI

### Phase 5: Production Readiness (In Progress)
- Enhanced security features
- Performance optimization
- Documentation
- Deployment guides

## Acknowledgments

ChronoGuard is built with:

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Envoy Proxy](https://www.envoyproxy.io/) - High-performance proxy
- [Open Policy Agent](https://www.openpolicyagent.org/) - Policy engine
- [PostgreSQL](https://www.postgresql.org/) + [TimescaleDB](https://www.timescale.com/) - Time-series database
- [React](https://reactjs.org/) - Frontend framework

---

**Built with ❤️ for the browser automation community**
