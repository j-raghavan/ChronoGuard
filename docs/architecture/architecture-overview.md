# ChronoGuard Architecture Overview

**Project:** ChronoGuard - Zero-trust Proxy for Browser Automation with Temporal Controls
**Architecture Pattern:** Domain-Driven Design (DDD) + Clean Architecture + CQRS

## Table of Contents

1. [Overall Architecture Pattern](#1-overall-architecture-pattern)
2. [Main Domain Entities](#2-main-domain-entities)
3. [Infrastructure Components](#3-infrastructure-components)
4. [Presentation Layers](#4-presentation-layers)
5. [Application Layer (CQRS Pattern)](#5-application-layer-cqrs-pattern)
6. [Core Layer (Cross-Cutting Concerns)](#6-core-layer-cross-cutting-concerns)
7. [Key Integrations and Dependencies](#7-key-integrations-and-dependencies)
8. [Architectural Patterns Used](#8-architectural-patterns-used)
9. [Concurrency & Data Integrity](#9-concurrency--data-integrity)
10. [Scalability & Performance](#10-scalability--performance)
11. [Security Considerations](#11-security-considerations)

---

## 1. Overall Architecture Pattern

### Layered Architecture (Dependency Flow: Inward)

```
Presentation Layer (FastAPI, gRPC, WebSocket)
         ↓
Application Layer (CQRS - Commands, Queries, DTOs)
         ↓
Domain Layer (DDD - Entities, Services, Value Objects, Repositories)
         ↓
Infrastructure Layer (Persistence, OPA, Envoy, Security, Telemetry)
         ↓
Core Layer (Configuration, Logging, DI Container, Features)
```

### Key Characteristics

- **Domain independence** - No external dependencies in domain layer
- **Repository pattern** - Persistence abstraction
- **CQRS** - Separating reads from mutations
- **Async-first design** - asyncio throughout
- **Type safety** - Python hints + Pydantic validation
- **Feature flags** - Gradual rollout
- **Multi-tenancy isolation** - Tenant-based data separation
- **Optimistic locking** - Concurrency control
- **Immutable audit logs** - Cryptographic verification

---

## 2. Main Domain Entities

### Agent

**Represents:** Browser automation agents connecting to ChronoGuard

**Key Attributes:**
- `agent_id` (UUID) - Unique identifier
- `tenant_id` (UUID) - Multi-tenancy isolation
- `name` (String 3-100 chars, unique per tenant)
- `certificate` (X509Certificate) - mTLS client certificate
- `status` (Enum) - PENDING → ACTIVE ↔ SUSPENDED → DEACTIVATED | EXPIRED
- `policy_ids` (List[UUID], max 50) - Assigned policies
- `version` (int) - Optimistic locking for concurrency
- `metadata` (Dict) - Flexible storage for state transitions, reasons

**Core Behaviors:**
- `activate()` / `suspend()` / `deactivate()` / `mark_expired()`
- `assign_policy()` / `remove_policy()` / `update_certificate()`
- `can_make_requests()` - Check if active AND certificate not expired

**Business Rules Enforced in AgentService:**
- Agent name unique per tenant
- Certificate fingerprint globally unique
- Certificate must be valid (not expired)
- Max 1000 agents per tenant
- Max 50 policies per agent

### Policy

**Represents:** Access control rules, restrictions, and rate limits

**Key Attributes:**
- `policy_id` (UUID) - Unique identifier
- `tenant_id` (UUID)
- `name` (String 3-100 chars, unique per tenant)
- `status` (Enum) - DRAFT → ACTIVE ↔ SUSPENDED → ARCHIVED
- `priority` (int 1-1000) - Evaluation order
- `rules` (List[PolicyRule], max 100) - Individual access rules
- `time_restrictions` (Optional[TimeRestriction]) - Time-based access
- `rate_limits` (Optional[RateLimit]) - Request rate limiting
- `allowed_domains` (Set[String], max 1000) - Whitelist
- `blocked_domains` (Set[String], max 1000) - Blacklist
- `version` (int) - Optimistic locking
- `created_by` (UUID) - User who created policy

**PolicyRule Structure:**
- `rule_id`, `name`, `description`
- `conditions[]` - Conditions with field/operator/value
- `action` - ALLOW | DENY | LOG | RATE_LIMIT
- `priority` (1-1000)

**Core Behaviors:**
- `add_rule()` / `remove_rule()` / `activate()` / `suspend()` / `archive()`
- `add_allowed_domain()` / `add_blocked_domain()` / `remove_domain()`
- `set_time_restrictions()` / `set_rate_limits()`
- `is_active()` - Check if policy is active

**Business Rules:**
- Policy name unique per tenant
- Cannot activate without rules or domain restrictions
- Cannot activate archived policy
- Max 100 rules, 20 conditions per rule, 10 time ranges
- Allowed and blocked domains mutually exclusive

### Audit Entry

**Represents:** Immutable, cryptographically verified access logs

**Key Attributes:**
- `entry_id` (UUID) - Unique identifier
- `agent_id` (UUID) - Agent making the request
- `timestamp` (DateTime) - Request time (always UTC)
- `domain` (DomainName) - Target domain
- `decision` (AccessDecision) - ALLOW | DENY | BLOCK | RATE_LIMITED | TIME_RESTRICTED | POLICY_VIOLATION
- `reason` (String, max 500) - Decision reason
- `policy_id` / `rule_id` - Matching policy/rule
- `request_*` (method, path, user_agent, source_ip)
- `response_*` (status, size_bytes, processing_time_ms)
- `timed_access_metadata` - Temporal context (hour, day of week, business hours, etc.)
- `previous_hash` / `current_hash` - Hash chain for integrity
- `sequence_number` (int) - Position in chain
- `risk_score` (int 0-100) - Calculated from decision + context
- `metadata` (Dict) - Flexible storage

**Core Behaviors:**
- `calculate_hash()` / `with_hash()` / `verify_hash()` - Cryptographic integrity
- `is_access_allowed()` / `is_access_denied()`
- `get_risk_score()` - Risk calculation
- `to_json_dict()` - Serialization for export

**Immutability:**
- `frozen = True` in Pydantic
- No post-creation modifications allowed
- Prevents tampering with audit records

**Hash Chain (Tamper Detection):**
- Entry[n].previous_hash = Entry[n-1].current_hash
- Entry[n].current_hash = SHA256(Entry[n].data + Entry[n].previous_hash)
- Optional: HMAC-SHA256 with secret key
- Verification: For each entry, recalculate hash and compare

### Value Objects

Domain-Driven Design Primitives:

**X509Certificate**
- PEM-encoded certificate validation
- Properties: fingerprint_sha256, not_valid_before, not_valid_after, days_until_expiry
- Validations: PEM format, not expired, security constraints

**DomainName**
- DNS name or IP validation
- Properties: is_valid, has_wildcard
- Max 500 characters

**TimeRange**
- Start/end time validation
- start_time < end_time (HH:MM format)

---

## 3. Infrastructure Components

### Persistence Layer

**PostgreSQL (asyncpg driver)**

**Models:**
- `AgentModel` - agents table with indexes: (tenant_id,name), (tenant_id,status), metadata GIN
- `PolicyModel` - policies table with indexes: (tenant_id,name), (tenant_id,status), (tenant_id,priority)
- `AuditEntryModel` - audit_entries table (TimescaleDB hypertable)
  - Chunk interval: 7 days
  - Compression: auto-enabled after 30 days
  - Retention: 1 year (auto-deletion)
  - Indexes: (tenant_id,timestamp), (agent_id,timestamp), (tenant_id,decision,timestamp)

**Repositories (PostgreSQL implementations):**
- `PostgresAgentRepository` - CRUD + tenant filtering + duplicate checks
- `PostgresPolicyRepository` - CRUD + status/priority filtering
- `PostgresAuditRepository` - Time-series optimized queries

**Caching Layer (Redis):**
- `RedisCacheRepository` - get/set/delete with TTL
- `RateLimiter` - Token bucket algorithm (per-minute/hour/day)
- `CacheService` - High-level policy/agent cache management

**Database Optimization:**
- Optimistic locking (version field in Agent/Policy)
- Unique constraints on (tenant_id, name)
- GIN indexes on JSONB fields for fast searches
- Connection pooling via SQLAlchemy session factory
- Async I/O via asyncpg driver

### Open Policy Agent (OPA) Integration

**OPAClient (HTTP REST API, port 8181)**
- `check_policy(policy_input)` - Evaluate policy → true/false
- `update_policy(name, rego_code)` - Upload Rego policy
- `get_policy(name)` - Retrieve Rego code
- `delete_policy(name)` - Remove policy
- `health_check()` - Verify OPA availability
- Retry logic: Max 3 attempts with exponential backoff
- Timeout: 30s (configurable)

**PolicyCompiler** - Converts domain Policy entities to Rego code
- Uses Jinja2 templates for rule generation
- Handles conditions, time restrictions, rate limits
- Generates syntactically valid Rego

**BundleBuilder** - Creates OPA policy bundles (tar.gz) for offline deployment

**DecisionLogger** - Logs OPA evaluation decisions for audit

**Error Handling:**
- `OPAClientError` (base)
- `OPAConnectionError` (network issues) - Triggers retry
- `OPAPolicyError` (policy operations)
- `OPAEvaluationError` (policy eval failure)

### Envoy Proxy Integration

**XDSServer (gRPC, port 18000)**
- Implements Envoy xDS (Discovery Service) protocol
- Dynamic configuration delivery to Envoy proxies
- Supports mTLS for secure control plane
- Configuration updates pushed on policy changes

**ConfigGenerator** - Generates Envoy v3 configs from domain models
- Listeners - Inbound connection handling
- Routes - Domain-based routing with policies
- Clusters - Upstream backend services
- Endpoints - Load balancing endpoints

**DiscoveryService** - Manages xDS resource versioning
- Tracks configuration versions
- Incremental updates support
- Nonce validation for ordering

**Workflow:**
1. Envoy connects via gRPC
2. Server pushes listener/route/cluster configs
3. Configs include policies, domains, rate limits
4. Proxy applies immediately
5. Server pushes updates on policy changes

### Observability

- OpenTelemetry (OTLP exporter)
- Prometheus metrics (/metrics endpoint)
- Distributed tracing (spans)
- Structured logging (JSON, correlation IDs)
- Key metrics: request counts, latencies, OPA eval time, cache ratios, errors
- Optional: Jaeger (tracing), Prometheus (metrics), Grafana (dashboards), Loki (logs)

### Security Infrastructure

- `CryptographicSigner` - HMAC-SHA256 for audit chain signing
- Audit entry verification - Hash chain integrity checking
- Key management - Load from environment or files
- Support for key rotation

---

## 4. Presentation Layers

### FastAPI REST API (Port 8000)

**Agent Routes:**
- `POST /api/v1/agents` - Create agent (201 Created)
- `GET /api/v1/agents/{agent_id}` - Get agent (200 OK)
- `GET /api/v1/agents` - List agents paginated (200 OK)
- `PUT /api/v1/agents/{agent_id}` - Update agent (200 OK)

**Policy Routes:**
- `POST /api/v1/policies` - Create policy (201 Created)
- `GET /api/v1/policies/{policy_id}` - Get policy (200 OK)
- `GET /api/v1/policies` - List policies paginated (200 OK)
- `PUT /api/v1/policies/{policy_id}` - Update policy (200 OK)
- `DELETE /api/v1/policies/{policy_id}` - Delete policy (204 No Content)

**Audit Routes:**
- `GET /api/v1/audit` - List audit entries paginated (200 OK)
- `GET /api/v1/audit/{entry_id}` - Get audit entry (200 OK)
- `GET /api/v1/audit/export` - Export audit (CSV/JSON) (200 OK)
- `GET /api/v1/audit/analytics/temporal` - Time-series analytics (200 OK)

**Health Routes:**
- `GET /health` - Health check (200 OK)
- `GET /metrics` - Prometheus metrics (200 OK)

**Middleware:**
- Auth - Tenant ID extraction, mTLS cert validation
- CORS - http://localhost:3000 (configurable)
- Logging - Request/response logging with correlation IDs

**Error Handling:**
- 400 Bad Request - Validation errors
- 404 Not Found - Entity not found
- 409 Conflict - Duplicate/concurrency errors
- 422 Unprocessable Entity - Business rule violations
- 500 Internal Server Error - Unexpected errors

### gRPC Server (Port 50051)

- `AgentService` - check_access, update_policy, etc.
- `PolicyService` - get_policy, list_policies
- `AuditService` - log_access, get_audit_entries

**Features:**
- mTLS authentication
- Stream processing for bulk operations
- Bidirectional streaming support

### WebSocket Handlers

**Endpoint:** `/ws/v1/events` (real-time event stream)

**WebSocketManager:**
- Connection registry
- Topic-based pub/sub (agent-events, policy-events, audit-events)
- Broadcast messaging
- Connection lifecycle management

**Message Format:**
```json
{
  "event_type": "agent_created" | "policy_updated" | "audit_entry",
  "data": {...},
  "timestamp": "ISO8601"
}
```

---

## 5. Application Layer (CQRS Pattern)

### Commands (Mutations - Write Operations)

**CreateAgentCommand**
- Input: CreateAgentRequest (name, certificate_pem), tenant_id
- Process: AgentService.create_agent() with validation
- Output: AgentDTO
- Exceptions: DuplicateEntityError, ValidationError, BusinessRuleViolationError

**UpdateAgentCommand**
- Handles: Name change, certificate update, status transition, policy assignment
- Output: AgentDTO

**CreatePolicyCommand**
- Input: CreatePolicyRequest (name, description, rules, etc.)
- Output: PolicyDTO

**UpdatePolicyCommand**
- Handles: Rules, time restrictions, rate limits, domain management
- Output: PolicyDTO

**DeletePolicyCommand**
- Cascades: Unassigns from agents
- Archives: Audit references

### Queries (Reads - Read-Only Operations)

**GetAgentQuery** - Get by agent_id + tenant_id
- Output: AgentDTO or None

**ListAgentsQuery** - Paginated list with status filtering
- Output: AgentListResponse (items[], total, page, page_size)

**GetPolicyQuery** - Get by policy_id + tenant_id
- Output: PolicyDTO or None

**ListPoliciesQuery** - Paginated list with status/priority filtering
- Output: PolicyListResponse

**GetAuditEntriesQuery** - Time-series optimized queries
- Filters: agent_id, decision type, time range
- Output: List[AuditEntryDTO]

**AuditExporter** - Export audit logs
- Formats: CSV, JSON
- Methods: export_csv(), export_json()

**TemporalAnalyticsQuery** - Advanced time-series analytics
- Aggregations: Access by hour/day/week, decision distribution, risk trends
- Output: Time-series analytics data

### Data Transfer Objects (DTOs)

**AgentDTO** - Serializable agent representation
- Exposes: agent_id, tenant_id, name, status, policy_ids, cert fingerprint, timestamps

**CreateAgentRequest** - Input validation
- Fields: name, certificate_pem

**UpdateAgentRequest** - Partial update validation
- Fields: Optional[name, certificate_pem, status]

**PolicyDTO** - Serializable policy representation
- Exposes: policy_id, name, description, status, rules count, domain counts, timestamps

**AuditEntryDTO** - Serializable audit entry
- Exposes: entry_id, agent_id, timestamp, domain, decision, risk_score, request details

**Mappers** - Entity ↔ DTO conversion
- AgentMapper.from_create_request() → Agent
- AgentMapper.to_dto() → AgentDTO
- (Similar for Policy and Audit)

---

## 6. Core Layer (Cross-Cutting Concerns)

### Configuration (ProxySettings)

- **Database:** URL, pool_size, max_overflow
- **OPA:** opa_url, policy_path, timeout
- **Envoy:** xds_port, management_port
- **Redis:** redis_url, cache_ttl
- **Security:** enable_mtls, cert_path, key_path, ca_cert_path
- **Environment:** environment (dev|test|prod), log_level

### Dependency Injection Container

**ServiceRegistry**
- `register_singleton()` / `register_factory()`
- `get()` - Service resolution
- `is_registered()` - Availability check
- Feature flag integration

**DependencyContainer**
- Global singleton management
- Health check capabilities
- `get_registered_services()`

**FastAPI Dependencies:**
- `get_agent_repository()` → PostgresAgentRepository
- `get_agent_service()` → AgentService
- `get_create_agent_command()` → CreateAgentCommand
- `get_tenant_id()` → UUID (from header)
- Similar for other services/commands/queries

### Feature Manager

Gradual feature rollout without redeployment

**Features:**
- `POLICY_EVALUATION` - OPA integration (enabled/canary percentage)
- `DYNAMIC_PROXY_CONFIG` - Envoy xDS (enabled/canary percentage)
- `REAL_TIME_EVENTS` - WebSocket events (enabled/canary percentage)
- `TEMPORAL_ANALYTICS` - Time-series analytics (enabled/canary percentage)
- `RATE_LIMITING` - Redis rate limiting (enabled/canary percentage)

**Integration:**
- DependencyContainer aware
- Services check feature before registering
- Runtime enable/disable without restart

**Deployment Progression:**
- Disabled (0%) → Canary (5-10%) → Gradual (10%→50%→100%) → Enabled (100%)

### Logging

- **Framework:** loguru (structured logging)
- **Formats:** JSON (production), console (development)
- **Features:**
  - Structured logs with context
  - Correlation IDs for request tracing
  - Log rotation and retention
  - Error traceback capture
- **Usage:** logger.info(), logger.warning(), logger.error(), etc.

### Database Setup

- `create_engine()` - SQLAlchemy async engine with asyncpg
- `create_all_tables()` - Schema creation from models
- `setup_timescaledb()` - TimescaleDB extension and hypertables
  - Hypertable: audit_entries (7-day chunks)
  - Compression: 30-day policy
  - Retention: 1-year policy
- `health_check()` - Database availability verification

### Security Configuration

- TLS/mTLS setup
- Certificate management and validation
- Secret key management
- JWT token handling
- `setup_mTLS(app)` - FastAPI security integration

---

## 7. Key Integrations and Dependencies

### Request Flow: Agent Creation

1. Client → FastAPI Route (`POST /api/v1/agents`)
2. Route extracts tenant_id, injects CreateAgentCommand
3. CreateAgentCommand.execute(request, tenant_id)
4. AgentMapper converts request → Agent entity
5. AgentService.create_agent() validates:
   - Duplicate name check
   - Duplicate certificate check
   - Certificate validity
   - Tenant agent limit
6. AgentRepository.create(agent) → INSERT agents table
7. Side effects:
   - Create AuditEntry
   - Publish WebSocket event (agent-events)
8. Return AgentDTO (201 Created)

### Request Flow: Policy Evaluation

1. External client → Envoy Proxy (HTTPS request)
2. Envoy mTLS verification, request context extraction
3. Envoy queries ChronoGuard policy check
4. OPAClient.check_policy(policy_input) → OPA evaluation
5. OPA Rego policies evaluate:
   - Domain matching
   - Time-based restrictions
   - Rate limit checks
   - Custom rules
6. OPA returns decision (ALLOW/DENY)
7. ChronoGuard creates AuditEntry:
   - Store decision
   - Calculate risk score
   - Hash chain computation
   - INSERT audit_entries (TimescaleDB)
8. Side effects:
   - WebSocket event broadcast
   - Cache updates (last_seen_at)
   - Redis rate limit increment
9. Return decision to Envoy
10. Envoy forwards or blocks request

### External Dependencies

- PostgreSQL 13+ (primary persistence)
- TimescaleDB (time-series optimization)
- Redis (caching and rate limiting)
- Open Policy Agent (OPA, policy engine)
- Envoy Proxy (mTLS-aware proxy)
- OpenTelemetry (observability)
- Optional: Prometheus, Jaeger, Grafana, Loki

### Python Libraries

- FastAPI (REST API framework)
- SQLAlchemy (async ORM)
- asyncpg (PostgreSQL async driver)
- aiohttp (async HTTP client for OPA)
- Pydantic (data validation)
- loguru (structured logging)
- cryptography (X.509, HMAC-SHA256)
- grpcio (gRPC support)
- Jinja2 (template rendering for Rego)
- OpenTelemetry SDK (telemetry)

---

## 8. Architectural Patterns Used

### Design Patterns

- **Domain-Driven Design (DDD)** - Entities, aggregates, value objects, bounded contexts
- **Command Query Responsibility Segregation (CQRS)** - Separate reads from writes
- **Repository Pattern** - Abstraction of persistence
- **Service Pattern** - Domain business logic encapsulation
- **Factory Pattern** - Dependency container service creation
- **Mapper Pattern** - Entity ↔ DTO conversion
- **Value Object Pattern** - Immutable domain primitives
- **Pub/Sub Pattern** - WebSocket event broadcasting
- **Strategy Pattern** - Multiple repository implementations
- **Observer Pattern** - Event listeners (audit, WebSocket)
- **Decorator Pattern** - Middleware wrapping
- **Async/Await Pattern** - Non-blocking I/O throughout

### Architectural Patterns

- **Layered Architecture** - Clear separation of concerns
- **Dependency Injection** - Loose coupling, testability
- **Feature Flags** - Gradual rollout without redeployment
- **Optimistic Locking** - Concurrent update conflict detection
- **Event Sourcing (Partial)** - Immutable audit logs
- **Circuit Breaker (OPA Client)** - Failure handling with retries
- **Connection Pooling** - SQLAlchemy session factory
- **Caching Strategy** - Redis with TTL-based expiration

---

## 9. Concurrency & Data Integrity

### Optimistic Locking

**Fields:** version (int) in Agent and Policy entities

**Mechanism:**
1. Read current version
2. UPDATE WHERE id = ? AND version = ?
3. If 0 rows updated → ConcurrencyError
4. Increment version on successful update

**Prevents:** Lost updates, stale data writes

**Client Handling:** Retry with fresh data after error

### Audit Chain Integrity

**Mechanism:**
- Entry[n].previous_hash = Entry[n-1].current_hash
- Entry[n].current_hash = SHA256(Entry[n].data + Entry[n].previous_hash)
- Optional HMAC-SHA256 with secret key for authentication

**Verification:**
```
FOR each entry:
  calculated = SHA256(entry.data + entry.previous_hash)
  IF calculated != entry.current_hash → TAMPERED
  ELSE → VALID
```

**Reports:** Integrity percentage, critical issues

**Immutability:** Pydantic frozen = True prevents post-creation modifications

### PostgreSQL ACID Properties

- **Atomicity** - Transactions all-or-nothing
- **Consistency** - Unique constraints, foreign keys
- **Isolation** - Serializable isolation (configurable)
- **Durability** - Persistent writes to disk

---

## 10. Scalability & Performance

### Database Optimization

**Indexes:**
- Composite indexes on filtered fields
- JSONB GIN indexes for metadata search
- Unique indexes for duplicates detection

**TimescaleDB:**
- 7-day chunks for audit entries
- Auto-compression after 30 days
- Auto-retention after 1 year
- Optimized time-range queries

**Query Optimization:**
- Pagination (page, page_size parameters)
- Filtering (status, decision, time range)
- Projections (select specific columns)

**Connection Management:**
- SQLAlchemy async session factory
- Connection pooling with pre-ping
- Singleton repository instances

### Caching Strategy

**Redis Cache:**
- Policy caching with TTL
- Agent status cache
- Automatic invalidation on updates

**Rate Limiting:**
- Token bucket algorithm
- Per-minute/hour/day counters
- Stored in Redis for fast checks

**Cache Hits:** Reduce database load

### Async-First Design

- No blocking I/O anywhere
- concurrent.futures for CPU-bound work
- asyncio event loop for coordination
- Concurrent request handling
- Resource efficiency

### Performance Considerations

- OPA Client Retry: Backoff prevents thundering herd
- Connection Pooling: Reuse across requests
- Pagination: Prevent large result sets
- Caching: Reduce database hits
- Time-based indexes: Fast temporal queries
- Compression: Reduce storage after 30 days
- Monitoring: Prometheus metrics for bottleneck detection

---

## 11. Security Considerations

### Authentication & Authorization

**Multi-tenancy Isolation**
- Every query filtered by tenant_id
- No cross-tenant data leakage

**mTLS Client Certificates**
- Agent authentication via X.509
- Certificate validation and verification
- Fingerprint tracking for uniqueness

**JWT Tokens (optional)**
- User authentication for admin UI
- Token validation in middleware

**Header-based Tenant ID**
- X-Tenant-ID header extraction
- Validation and tenant isolation

### Data Protection

**Audit Log Integrity**
- Cryptographic hash chain
- HMAC-SHA256 signatures (optional)
- Tamper detection

**Certificate Management**
- Secure PEM storage
- Expiry tracking
- Validation on every use

**Secrets Management**
- Environment variable loading
- No hardcoded secrets
- Key rotation support

**Access Control**
- Policy-based access via OPA
- Time-based restrictions
- Rate limiting
- Domain whitelisting/blacklisting

### Infrastructure Security

- gRPC mTLS (optional, for agent communication)
- HTTPS (TLS 1.3+) for REST API
- PostgreSQL connection encryption
- Redis authentication (if applicable)
- Network segmentation
- Regular secret rotation

---

## Related Documentation

For more detailed information, see:
- [Detailed Architecture Documentation](./architecture.md) - In-depth technical specifications
- [Architecture Diagrams](./architecture-diagrams.md) - Visual representations and workflows

---

*This overview provides a high-level understanding of ChronoGuard's architecture. For implementation details, code examples, and specific component documentation, refer to the detailed architecture documentation.*
