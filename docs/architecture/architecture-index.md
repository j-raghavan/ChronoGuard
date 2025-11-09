# ChronoGuard Architecture Documentation Index

This folder contains comprehensive architecture analysis and documentation for the ChronoGuard project.

## Documentation Files

### 1. **CHRONOGUARD_ARCHITECTURE.md** (40 KB)
**Comprehensive architecture specification with all details**

Complete reference guide covering:
- Overall architecture pattern (DDD + Clean Architecture + CQRS)
- All domain entities with attributes, behaviors, and business rules
  - Agent (with state transitions and policy assignment)
  - Policy (with rules, time restrictions, rate limits)
  - AuditEntry (with cryptographic hash chain and risk scoring)
  - Value Objects (X509Certificate, DomainName, TimeRange)
- Infrastructure components in detail
  - Persistence layer (PostgreSQL, TimescaleDB, Redis)
  - OPA integration (client, compiler, bundle builder)
  - Envoy proxy integration (xDS server, config generator)
  - Observability (OpenTelemetry, Prometheus, tracing)
  - Security infrastructure (cryptographic signing)
- Presentation layers (FastAPI REST, gRPC, WebSocket)
- Application layer (Commands, Queries, DTOs, Mappers)
- Core layer (Configuration, DI Container, Logging, Features)
- Request flow examples
- Data relationships and cardinality
- Concurrency & data integrity mechanisms
- Scalability and performance considerations

**Best for:** Reference documentation, detailed understanding of all components

---

### 2. **ARCHITECTURE_DIAGRAMS.md** (57 KB)
**Visual diagrams and flowcharts**

ASCII diagrams showing:
1. **System Architecture Overview** - Complete layered architecture with all components
2. **Request Flow: Agent Creation** - Step-by-step flow from API to database
3. **Request Flow: Policy Evaluation** - Complete flow through OPA and Envoy
4. **Data Model Relationships** - ER diagram with cardinality
5. **Concurrency & Data Integrity** - Optimistic locking and hash chain mechanisms
6. **Deployment Architecture** - Kubernetes structure with stateful services
7. **Feature Flags & Progressive Delivery** - Feature management system
8. **Error Handling & Recovery Patterns** - Exception hierarchy and retry strategies

**Best for:** Creating presentations, team discussions, understanding data flows

---

### 3. **ARCHITECTURE_SUMMARY.txt** (28 KB)
**Quick reference guide in text format**

Organized sections:
1. Overall Architecture Pattern - Layered DDD architecture
2. Main Domain Entities - Agent, Policy, AuditEntry summaries
3. Infrastructure Components - All subsystems overview
4. Presentation Layers - API endpoints and protocols
5. Application Layer - Commands, Queries, DTOs
6. Core Layer - Configuration and cross-cutting concerns
7. Key Integrations - Request flows and dependencies
8. Architectural Patterns - Design and architectural patterns used
9. Concurrency & Data Integrity - Locking and verification
10. Scalability & Performance - Optimization strategies
11. Security Considerations - Authentication, authorization, data protection

**Best for:** Quick lookups, printing, sharing with team members

---

## How to Use These Documents

### For Understanding Architecture:
1. Start with **ARCHITECTURE_SUMMARY.txt** for quick overview
2. Review **ARCHITECTURE_DIAGRAMS.md** for visual understanding
3. Deep dive into **CHRONOGUARD_ARCHITECTURE.md** for complete details

### For Creating Diagrams:
- Use the ASCII diagrams in **ARCHITECTURE_DIAGRAMS.md** as templates
- Convert to tools like: PlantUML, Miro, Lucidchart, Draw.io

### For Team Onboarding:
1. Share **ARCHITECTURE_SUMMARY.txt** with new team members
2. Walk through **ARCHITECTURE_DIAGRAMS.md** Section 2 (Request Flows)
3. Reference specific components in **CHRONOGUARD_ARCHITECTURE.md** as needed

### For Documentation:
- Use sections from any document for wiki/confluence
- Convert diagrams to professional graphics for presentations
- Quote specific patterns for design decision justification

---

## Key Architectural Concepts

### Domain-Driven Design (DDD)
- **Entities**: Agent, Policy, AuditEntry
- **Value Objects**: X509Certificate, DomainName, TimeRange
- **Services**: AgentService, PolicyService, AuditService
- **Repositories**: Abstract interfaces with PostgreSQL implementations
- **Exceptions**: Custom domain exceptions for business rules

### Clean Architecture
- **Dependency Rule**: Dependencies flow inward only
- **Layers**: Presentation → Application → Domain ← Infrastructure
- **Core Layer**: Cross-cutting concerns isolated

### CQRS Pattern
- **Commands**: Mutations (Create, Update, Delete)
- **Queries**: Reads (Get, List, Search)
- **DTOs**: Data Transfer Objects for API boundaries
- **Mappers**: Entity ↔ DTO conversion

### Key Features
- **Multi-tenancy**: Tenant ID isolation in all queries
- **Optimistic Locking**: Version field prevents lost updates
- **Audit Chain**: Cryptographic hash chain for tamper detection
- **Feature Flags**: Gradual rollout without redeployment
- **Async-First**: Non-blocking I/O throughout
- **Type Safety**: Python hints + Pydantic validation

---

## External Systems

### Required Services
- **PostgreSQL 13+**: Primary data persistence
- **TimescaleDB**: Time-series optimization for audit logs
- **Redis**: Caching and rate limiting
- **Open Policy Agent (OPA)**: Policy evaluation engine
- **Envoy Proxy**: mTLS-aware proxy with dynamic config

### Optional Services
- **Prometheus**: Metrics collection
- **Jaeger**: Distributed tracing
- **Grafana**: Dashboard visualization
- **Loki**: Log aggregation

---

## Directory Structure Reference

```
/backend/src/
├── presentation/
│   ├── api/
│   │   ├── routes/        (FastAPI endpoints)
│   │   ├── middleware/    (Auth, CORS, logging)
│   │   └── dependencies.py (DI providers)
│   ├── grpc/              (gRPC services)
│   └── websocket/         (WebSocket handlers)
├── application/
│   ├── commands/          (CQRS mutations)
│   ├── queries/           (CQRS reads)
│   └── dto/               (DTOs and mappers)
├── domain/
│   ├── agent/             (Agent aggregate)
│   ├── policy/            (Policy aggregate)
│   ├── audit/             (AuditEntry aggregate)
│   └── common/            (Value objects, exceptions)
├── infrastructure/
│   ├── persistence/       (PostgreSQL, Redis)
│   ├── opa/               (OPA integration)
│   ├── envoy/             (Envoy xDS server)
│   ├── observability/     (Telemetry)
│   └── security/          (Cryptographic signing)
└── core/
    ├── container.py       (DI container)
    ├── config.py          (Configuration)
    ├── logging.py         (Structured logging)
    ├── database.py        (DB setup)
    ├── security.py        (Security config)
    ├── features.py        (Feature manager)
    └── celery_app.py      (Task queue setup)
```

---

## Document Statistics

| Document | Size | Lines | Focus |
|----------|------|-------|-------|
| CHRONOGUARD_ARCHITECTURE.md | 40 KB | 800+ | Complete reference |
| ARCHITECTURE_DIAGRAMS.md | 57 KB | 600+ | Visual flows |
| ARCHITECTURE_SUMMARY.txt | 28 KB | 500+ | Quick reference |

**Total Documentation**: 125+ KB, 1,900+ lines, 100+ detailed sections

---

## Quick Links to Common Sections

### Agent Entity
- Definition: See **CHRONOGUARD_ARCHITECTURE.md** Section 2.1
- Diagram: See **ARCHITECTURE_DIAGRAMS.md** Section 4
- Create flow: See **ARCHITECTURE_DIAGRAMS.md** Section 2

### Policy Entity
- Definition: See **CHRONOGUARD_ARCHITECTURE.md** Section 2.2
- Diagram: See **ARCHITECTURE_DIAGRAMS.md** Section 4

### Audit Entry
- Definition: See **CHRONOGUARD_ARCHITECTURE.md** Section 2.3
- Hash chain: See **ARCHITECTURE_DIAGRAMS.md** Section 5

### Database Schema
- Models: See **CHRONOGUARD_ARCHITECTURE.md** Section 3.1
- Cardinality: See **ARCHITECTURE_DIAGRAMS.md** Section 4

### Request Flows
- Agent creation: See **ARCHITECTURE_DIAGRAMS.md** Section 2
- Policy evaluation: See **ARCHITECTURE_DIAGRAMS.md** Section 3

### Integration Points
- OPA: See **CHRONOGUARD_ARCHITECTURE.md** Section 3.2
- Envoy: See **CHRONOGUARD_ARCHITECTURE.md** Section 3.3
- WebSocket: See **CHRONOGUARD_ARCHITECTURE.md** Section 4.3

### Deployment
- Architecture: See **ARCHITECTURE_DIAGRAMS.md** Section 6
- Services: See **CHRONOGUARD_ARCHITECTURE.md** Section 10 (Deployment)

---

## Maintenance

These documents were generated through systematic codebase analysis on **2024-11-08**.

**To update documentation:**
1. Run codebase analysis again when major architecture changes occur
2. Update diagrams when request flows change
3. Reflect new entities/services in all three documents
4. Keep this index file current with links to new sections

---

## License & Usage

These documents are part of the ChronoGuard project and follow the same license as the codebase. Internal documentation - use for team knowledge sharing and onboarding.

---

**Last Updated**: 2024-11-08
**Created By**: Claude Code (Anthropic)
**Sections**: 11 major topics, 50+ subtopics, 100+ diagrams and flowcharts
