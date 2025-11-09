# ChronoGuard Architecture Diagrams

**Note:** This document shows the complete system architecture. Sections marked with ⚠️ indicate features planned but not yet implemented in MVP v0.1.0. See [MISSING.md](../../MISSING.md) and [CHANGELOG.md](../../CHANGELOG.md) for implementation status.

## 1. System Architecture Overview

**Legend:**
- ✅ = Implemented in MVP v0.1.0
- ⚠️ = Planned for future releases (v0.2.0+)
- 🔧 = Partially implemented

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENTS & INTERFACES                             │
├─────────────┬──────────────────┬────────────────┬──────────────────┤
│  Web Browser│  Agent ⚠️(gRPC)  │  Envoy Proxy   │  Admin Dashboard  │
│  (Frontend) │  (browser bots)  │  ✅(mTLS)      │  ✅(React)        │
└──────┬──────┴──────────┬───────┴────────┬───────┴──────────┬────────┘
       │                 │                │                  │
       │ ✅HTTP/REST     │ ⚠️gRPC        │ ⚠️xDS            │ 🔧WebSocket
       │                 │                │ (static config   │ (handlers
       │                 │                │  used in MVP)    │  exist)
       │                 │                │                  │
┌──────▼─────────────────▼────────────────▼──────────────────▼────────────┐
│                    CHRONOGUARD BACKEND API                              │
├──────────────────────────────────────────────────────────────────────────┤
│                    Presentation Layer (FastAPI)                         │
│  ┌─────────────────┬──────────────────┬──────────────┬─────────────┐   │
│  │ REST Routes     │ gRPC Server      │ WebSocket    │ Health      │   │
│  │ /api/v1/*       │ :50051           │ /ws/v1/*     │ /health     │   │
│  └─────────────────┴──────────────────┴──────────────┴─────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Middleware: Auth (mTLS, JWT), CORS, Logging                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└──────┬───────────────────────────────────────────────────────────────────┘
       │
       │ (Dependency Injection)
       │
┌──────▼───────────────────────────────────────────────────────────────────┐
│                   Application Layer (CQRS Pattern)                       │
├──────────────────────────────────────────────────────────────────────────┤
│  COMMANDS (Mutations)          │  QUERIES (Reads)                        │
│  ├─ CreateAgentCommand         │  ├─ GetAgentQuery                       │
│  ├─ UpdateAgentCommand         │  ├─ ListAgentsQuery                     │
│  ├─ CreatePolicyCommand        │  ├─ GetPolicyQuery                      │
│  ├─ UpdatePolicyCommand        │  ├─ ListPoliciesQuery                   │
│  └─ DeletePolicyCommand        │  ├─ GetAuditEntriesQuery                │
│                                │  ├─ AuditExporter (CSV/JSON)            │
│                                │  └─ TemporalAnalyticsQuery              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ DTOs & Mappers (Entity ↔ DTO conversion)                        │  │
│  │ AgentDTO, PolicyDTO, AuditEntryDTO + Mappers                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────┬───────────────────────────────────────────────────────────────────┘
       │
       │ (Repository interfaces)
       │
┌──────▼───────────────────────────────────────────────────────────────────┐
│                   Domain Layer (DDD Pattern)                             │
├──────────────────────────────────────────────────────────────────────────┤
│  AGGREGATES & ENTITIES                                                   │
│  ┌──────────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Agent Aggregate      │  │ Policy Aggregate │  │ AuditEntry       │  │
│  ├──────────────────────┤  ├──────────────────┤  │ (Immutable)      │  │
│  │ - agent_id (UUID)    │  │ - policy_id      │  ├──────────────────┤  │
│  │ - tenant_id          │  │ - tenant_id      │  │ - entry_id       │  │
│  │ - name               │  │ - name           │  │ - agent_id       │  │
│  │ - certificate        │  │ - rules[]        │  │ - decision       │  │
│  │ - status (enum)      │  │ - time_restrict  │  │ - timestamp      │  │
│  │ - policy_ids[]       │  │ - rate_limits    │  │ - hash chain     │  │
│  │ - version (lock)     │  │ - domains        │  │ - risk_score     │  │
│  │                      │  │ - version (lock) │  │ - metadata       │  │
│  │ BEHAVIORS:           │  │                  │  └──────────────────┘  │
│  │ - activate()         │  │ BEHAVIORS:       │                        │
│  │ - suspend()          │  │ - add_rule()     │  VALUE OBJECTS:        │
│  │ - deactivate()       │  │ - activate()     │  ├─ X509Certificate   │
│  │ - assign_policy()    │  │ - set_time_rest()│  ├─ DomainName        │
│  │ - update_cert()      │  │ - set_rate_lim() │  └─ TimeRange         │
│  └──────────────────────┘  └──────────────────┘                        │
│                                                                          │
│  DOMAIN SERVICES                                                         │
│  ├─ AgentService (create, update, certificate mgmt)                    │
│  ├─ PolicyService (create, update, compilation)                        │
│  └─ AuditService (entry creation, verification, export)                │
│                                                                          │
│  REPOSITORY INTERFACES (Abstract contracts)                             │
│  ├─ AgentRepository                                                     │
│  ├─ PolicyRepository                                                    │
│  └─ AuditRepository                                                     │
│                                                                          │
│  DOMAIN EXCEPTIONS (Business rule violations)                           │
│  ├─ ValidationError                                                     │
│  ├─ BusinessRuleViolationError                                          │
│  ├─ DuplicateEntityError                                                │
│  ├─ EntityNotFoundError                                                 │
│  └─ InvalidStateTransitionError                                         │
└──────┬───────────────────────────────────────────────────────────────────┘
       │
       │ (Repository implementations)
       │
┌──────▼───────────────────────────────────────────────────────────────────┐
│               Infrastructure Layer (Implementation Details)              │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  PERSISTENCE LAYER                 POLICY ENGINE                        │
│  ┌──────────────────────────┐     ┌──────────────────────────┐         │
│  │ PostgreSQL (asyncpg)     │     │ Open Policy Agent (OPA) │         │
│  │ ├─ PostgresAgentRepo     │     │ ├─ OPAClient (HTTP)     │         │
│  │ ├─ PostgresPolicyRepo    │     │ │  ├─ check_policy()    │         │
│  │ └─ PostgresAuditRepo     │     │ │  ├─ update_policy()   │         │
│  │                          │     │ │  └─ health_check()    │         │
│  │ Models:                  │     │ ├─ PolicyCompiler      │         │
│  │ ├─ AgentModel            │     │ │  ├─ Jinja2 templates  │         │
│  │ ├─ PolicyModel           │     │ │  └─ Rego generation   │         │
│  │ └─ AuditEntryModel       │     │ ├─ BundleBuilder       │         │
│  │    (TimescaleDB hyper)   │     │ └─ DecisionLogger      │         │
│  │                          │     └──────────────────────────┘         │
│  │ TimescaleDB:             │                                           │
│  │ ├─ Hypertable: audit     │     PROXY INTEGRATION                   │
│  │ ├─ 7-day chunks          │     ┌──────────────────────────┐         │
│  │ ├─ Compression @30 days  │     │ Envoy xDS Server        │         │
│  │ └─ Retention: 1 year     │     │ ├─ XDSServer (gRPC)    │         │
│  └──────────────────────────┘     │ │  Port: 18000           │         │
│                                    │ ├─ ConfigGenerator      │         │
│  CACHING LAYER                     │ │  ├─ Listeners         │         │
│  ┌──────────────────────────┐     │ │  ├─ Routes            │         │
│  │ Redis Cache              │     │ │  ├─ Clusters          │         │
│  │ ├─ CacheRepository       │     │ │  └─ Endpoints         │         │
│  │ ├─ RateLimiter (token    │     │ └─ DiscoveryService    │         │
│  │ │   bucket algorithm)    │     └──────────────────────────┘         │
│  │ └─ CacheService          │                                           │
│  └──────────────────────────┘     OBSERVABILITY                        │
│                                    ┌──────────────────────────┐         │
│  SECURITY                          │ Telemetry               │         │
│  ┌──────────────────────────┐     │ ├─ OpenTelemetry OTLP  │         │
│  │ CryptographicSigner      │     │ ├─ Prometheus metrics  │         │
│  │ ├─ sign_entry()         │     │ ├─ Tracing (spans)     │         │
│  │ └─ verify_entry()       │     │ └─ Structured logging  │         │
│  └──────────────────────────┘     └──────────────────────────┘         │
└──────┬───────────────────────────────────────────────────────────────────┘
       │
┌──────▼───────────────────────────────────────────────────────────────────┐
│                    Core Layer (Cross-cutting Concerns)                   │
├──────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Configuration (ProxySettings) - DB, OPA, Envoy, Redis, Security   │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Dependency Injection Container                                     │ │
│  │ ├─ ServiceRegistry                                                 │ │
│  │ ├─ DependencyContainer                                             │ │
│  │ └─ Feature Flag Integration                                        │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Feature Manager (Gradual Rollout)                                  │ │
│  │ ├─ OPA integration flag                                            │ │
│  │ ├─ Envoy xDS flag                                                  │ │
│  │ ├─ WebSocket flag                                                  │ │
│  │ └─ Rate limiting flag                                              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Logging (loguru) - Structured, JSON, correlation IDs              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Database Setup - Schema creation, migrations, TimescaleDB         │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

**MVP v0.1.0 Implementation Status:**

✅ **Fully Implemented:**
- REST API (FastAPI) with all CRUD endpoints
- Domain Layer (DDD with Clean Architecture)
- Application Layer (CQRS commands/queries)
- PostgreSQL + TimescaleDB persistence
- Redis caching and rate limiting
- OPA policy engine integration (PolicyCompiler, decision logs)
- Envoy mTLS forward proxy (static configuration)
- React dashboard (Vite)
- Cryptographic signer for audit chain
- OpenTelemetry observability

⚠️ **Planned (Not Implemented):**
- **gRPC Server**: Code exists but not exposed (deferred to v0.2.0)
- **Envoy xDS Server**: Code exists but MVP uses static `envoy.yaml` config
- **BundleBuilder**: Code exists but policies deployed via OPA Policy API instead

🔧 **Partially Implemented:**
- **WebSocket**: Handlers and managers exist, events not fully wired
- **OPAClient.check_policy()**: Exists but not called by Envoy (Envoy→OPA uses ext_authz directly)

**Key Architectural Decision (MVP):**
- **Envoy → OPA Integration**: Uses ext_authz filter (gRPC port 9192) instead of ChronoGuard→OPA HTTP calls
- **Decision Logging**: OPA decision_logs plugin → FastAPI `/api/v1/internal/opa/decisions` (asynchronous)
- **Policy Deployment**: PolicyCompiler → OPA Policy API (not bundles)
- **Configuration**: Static Envoy configuration (not dynamic xDS)

See [Section 3](#3-request-flow-policy-evaluation-actual-mvp-implementation) for actual request flow diagram.

---

## 2. Request Flow: Agent Creation

```
CLIENT (Admin UI / API)
         │
         │ POST /api/v1/agents
         │ { name: "agent-1", certificate_pem: "..." }
         ↓
┌─────────────────────────────────────────────────────────────┐
│           FastAPI Route Handler (agents.py)                 │
│  create_agent(request, tenant_id, create_command)           │
│  ├─ Extract tenant_id from headers                          │
│  └─ Dependency Inject: CreateAgentCommand                   │
└────────┬────────────────────────────────────────────────────┘
         │
         │ await create_command.execute(request, tenant_id)
         ↓
┌─────────────────────────────────────────────────────────────┐
│         CreateAgentCommand (application/commands)           │
│  ├─ AgentMapper.from_create_request()                       │
│  │  └─ Convert CreateAgentRequest → Agent entity            │
│  │                                                           │
│  └─ await agent_service.create_agent(...)                   │
└────────┬────────────────────────────────────────────────────┘
         │
         │
         ↓
┌─────────────────────────────────────────────────────────────┐
│            AgentService (domain/agent/service.py)           │
│  async def create_agent(tenant_id, name, certificate):      │
│                                                              │
│  1. Check: agent_repository.exists_by_name()               │
│     └─ Raise DuplicateEntityError if exists                │
│                                                              │
│  2. Check: agent_repository.exists_by_cert_fingerprint()   │
│     └─ Raise DuplicateEntityError if exists                │
│                                                              │
│  3. Validate: certificate.is_valid_now                      │
│     └─ Raise BusinessRuleViolationError if expired          │
│                                                              │
│  4. Check: agent_repository.count_by_tenant()              │
│     └─ Raise BusinessRuleViolationError if >= 1000         │
│                                                              │
│  5. Create: agent = Agent(...)                             │
│     └─ Domain entity with all validations                  │
│                                                              │
│  6. Return: await agent_repository.create(agent)           │
└────────┬────────────────────────────────────────────────────┘
         │
         │
         ↓
┌─────────────────────────────────────────────────────────────┐
│   PostgresAgentRepository (infrastructure/persistence)      │
│  async def create(agent: Agent) → Agent:                    │
│                                                              │
│  1. Convert Agent → AgentModel (SQLAlchemy)                │
│  2. BEGIN TRANSACTION                                       │
│  3. INSERT agents table                                     │
│     └─ Unique constraint: (tenant_id, name)               │
│     └─ Unique constraint: certificate_fingerprint          │
│  4. SELECT inserted row                                     │
│  5. COMMIT TRANSACTION                                      │
│  6. Convert AgentModel → Agent (entity)                    │
│  7. RETURN agent                                            │
│                                                              │
│  On Error:                                                  │
│  ├─ IntegrityError → DuplicateEntityError                  │
│  └─ SQLAlchemyError → RepositoryError                      │
└────────┬────────────────────────────────────────────────────┘
         │ (saves to PostgreSQL)
         ↓
    ┌─────────────────────┐
    │   PostgreSQL DB     │
    │  agents table       │
    │  (asyncpg driver)   │
    └─────────────────────┘
         │ agent created
         ↓
┌─────────────────────────────────────────────────────────────┐
│         Back to CreateAgentCommand                          │
│  ├─ Receive Agent entity from repository                    │
│  ├─ Side Effect: Create audit entry                         │
│  │  └─ AuditService.log_agent_created()                    │
│  │     └─ Stores in audit_entries table                    │
│  │                                                           │
│  ├─ Side Effect: Publish WebSocket event                    │
│  │  └─ WebSocketManager.broadcast()                         │
│  │     ├─ Topic: "agent-events"                             │
│  │     └─ Payload: { event_type: "agent_created", ... }   │
│  │                                                           │
│  └─ Return: AgentMapper.to_dto(agent)                      │
└────────┬────────────────────────────────────────────────────┘
         │
         │ AgentDTO
         ↓
┌─────────────────────────────────────────────────────────────┐
│         FastAPI Route Handler                               │
│  ├─ HTTP 201 Created                                        │
│  ├─ Content-Type: application/json                          │
│  └─ Body: { agent_id, tenant_id, name, status, ... }      │
└────────┬────────────────────────────────────────────────────┘
         │
         │
         ↓
RESPONSE to CLIENT
```

---

## 3. Request Flow: Policy Evaluation (ACTUAL MVP IMPLEMENTATION)

**Note:** This diagram reflects the actual MVP implementation using Envoy ext_authz → OPA with asynchronous decision logging.

```
BROWSER AGENT (Playwright, Puppeteer, Selenium)
       │
       │ HTTPS Request to example.com/api/data
       │ (via configured proxy: https://chronoguard-proxy:8080)
       │
       ↓
┌─────────────────────────────────────────────────────────────┐
│       Envoy Forward Proxy (Port 8080 - mTLS required)       │
│                                                              │
│  1. mTLS Authentication:                                     │
│     ├─ Verify client certificate (agent certificate)        │
│     ├─ Extract agent_id from certificate CN/SAN             │
│     └─ Reject if certificate invalid/expired (403)          │
│                                                              │
│  2. Extract Request Context:                                │
│     ├─ Domain: example.com                                  │
│     ├─ Method: GET                                          │
│     ├─ Path: /api/data                                      │
│     ├─ User-Agent: Mozilla/5.0...                           │
│     ├─ Source IP: 192.168.1.100                             │
│     └─ Timestamp: 2025-01-08T12:00:00Z                      │
│                                                              │
│  3. ext_authz Filter Triggered:                             │
│     └─ Calls OPA for authorization decision                 │
└────────┬────────────────────────────────────────────────────┘
         │
         │ gRPC call to OPA ext_authz endpoint
         │ envoy.service.auth.v3.CheckRequest
         │ {
         │   attributes: {
         │     source: { principal: "agent-id-from-cert" },
         │     request: {
         │       http: {
         │         host: "example.com",
         │         method: "GET",
         │         path: "/api/data",
         │         headers: { "user-agent": "..." }
         │       }
         │     }
         │   }
         │ }
         │
         ↓
┌─────────────────────────────────────────────────────────────┐
│    Open Policy Agent (OPA) - Port 9192 (gRPC ext_authz)    │
│                                                              │
│  1. Load Rego Policy from /config/policies/chronoguard.rego │
│     ├─ Policy deployed by PolicyCompiler (Phase 4)          │
│     └─ Data bundle with agent policies                      │
│                                                              │
│  2. Evaluate Policy Rules:                                  │
│     ├─ agent_authenticated: ✓ (mTLS principal exists)      │
│     ├─ domain_allowed: Check example.com in allowed_domains │
│     │  └─ Query: data.policies[agent_id].allowed_domains   │
│     ├─ domain_blocked: Check NOT in blocked_domains         │
│     ├─ time_window_valid: Check current time restrictions   │
│     └─ rate_limit_ok: Check rate limits (placeholder MVP)   │
│                                                              │
│  3. Compute Decision:                                       │
│     └─ allow = agent_authenticated AND domain_allowed       │
│                AND time_window_valid AND rate_limit_ok      │
│                                                              │
│  4. Return to Envoy:                                        │
│     └─ envoy.service.auth.v3.CheckResponse                 │
│        ├─ status: OK (allow) or PERMISSION_DENIED (deny)   │
│        └─ headers: decision metadata                        │
└────────┬────────────────────────────────────────────────────┘
         │                                │
         │ gRPC Response                  │ (PARALLEL - Non-blocking)
         │ (synchronous)                  │
         │                                │ OPA decision_logs plugin
         │                                │ (configured in config.yaml)
         │                                ↓
         ↓                    ┌─────────────────────────────────┐
┌────────────────────────┐   │  POST /api/v1/internal/opa/     │
│  Envoy Proxy           │   │       decisions                  │
│  (decision received)   │   │                                  │
│                        │   │  Authorization: Bearer           │
│  If ALLOW:             │   │    CHRONOGUARD_INTERNAL_SECRET  │
│  ├─ Forward to         │   │                                  │
│  │  example.com        │   │  Body: OPADecisionLog {          │
│  └─ Return response    │   │    decision_id,                  │
│     to agent           │   │    timestamp,                    │
│                        │   │    input: { attributes },        │
│  If DENY:              │   │    result: { allow: true/false },│
│  └─ Return 403         │   │    path: "chronoguard/authz"     │
│     Forbidden          │   │  }                               │
└────────┬───────────────┘   └────────┬────────────────────────┘
         │                            │
         │                            ↓
         │              ┌──────────────────────────────────────┐
         │              │  FastAPI Internal Route Handler      │
         │              │  (routes/internal.py)                │
         │              │                                       │
         │              │  async def ingest_opa_decision():    │
         │              │                                       │
         │              │  1. Verify Bearer token auth         │
         │              │     └─ Check CHRONOGUARD_INTERNAL_   │
         │              │        SECRET matches                │
         │              │                                       │
         │              │  2. Parse OPADecisionLog DTO         │
         │              │     ├─ Extract agent_id from         │
         │              │     │  input.attributes.source.      │
         │              │     │  principal                      │
         │              │     ├─ Extract domain from           │
         │              │     │  input.attributes.request.     │
         │              │     │  http.host                      │
         │              │     └─ Extract decision from         │
         │              │        result.allow (true/false)     │
         │              │                                       │
         │              │  3. Create AccessRequest:            │
         │              │     └─ Map OPA decision to domain   │
         │              │        AccessRequest DTO             │
         │              │                                       │
         │              │  4. Call AuditService:               │
         │              │     └─ await audit_service.          │
         │              │        record_access(request)        │
         │              └────────┬─────────────────────────────┘
         │                       │
         │                       ↓
         │              ┌──────────────────────────────────────┐
         │              │  AuditService (domain layer)         │
         │              │                                       │
         │              │  1. Create AuditEntry:               │
         │              │     ├─ entry_id: UUID                │
         │              │     ├─ agent_id: from request        │
         │              │     ├─ tenant_id: from request       │
         │              │     ├─ domain: example.com           │
         │              │     ├─ decision: ALLOW/DENY          │
         │              │     ├─ timestamp: UTC now            │
         │              │     ├─ request metadata              │
         │              │     ├─ previous_hash: from chain     │
         │              │     └─ current_hash: SHA256(entry)   │
         │              │                                       │
         │              │  2. Save to Repository:              │
         │              │     └─ await audit_repository.       │
         │              │        create(audit_entry)           │
         │              └────────┬─────────────────────────────┘
         │                       │
         │                       ↓
         │              ┌──────────────────────────────────────┐
         │              │  PostgreSQL + TimescaleDB            │
         │              │  (audit_entries hypertable)          │
         │              │                                       │
         │              │  INSERT INTO audit_entries:          │
         │              │  ├─ Partitioned by timestamp         │
         │              │  │  (7-day chunks)                   │
         │              │  ├─ Hash chain integrity             │
         │              │  └─ Indexed: agent_id, tenant_id,    │
         │              │     timestamp                        │
         │              │                                       │
         │              │  Audit trail complete ✓              │
         │              └──────────────────────────────────────┘
         │
         │ HTTP 200 OK (if allowed)
         │ or HTTP 403 Forbidden (if denied)
         │ + Response from example.com (if allowed)
         │
         ↓
BROWSER AGENT receives response
```

**Key Implementation Details:**

1. **Synchronous Path (Blocking):**
   - Envoy → OPA (gRPC ext_authz) → Decision → Envoy → Forward/Block
   - This path is FAST (policy evaluation in milliseconds)
   - Agent receives response immediately

2. **Asynchronous Path (Non-blocking):**
   - OPA decision_logs plugin → FastAPI → AuditService → PostgreSQL
   - Runs in PARALLEL, does NOT block the request
   - Audit entries created after response sent
   - Configured in `configs/opa/config.yaml`

3. **No Direct ChronoGuard → OPA Call:**
   - The original design showed FastAPI calling OPA
   - The MVP implementation uses Envoy ext_authz (more efficient)
   - PolicyCompiler deploys policies to OPA (Phase 4)
   - OPA operates independently for decision making

4. **Authentication:**
   - Agent → Envoy: mTLS with client certificates
   - Envoy → OPA: gRPC (internal, no auth needed)
   - OPA → FastAPI: Bearer token (CHRONOGUARD_INTERNAL_SECRET)

---

---

## 4. Data Model Relationships

```
┌─────────────────────────────────────────────────────────────────┐
│                      TENANT                                      │
│          (Multi-tenancy isolation boundary)                     │
│          - tenant_id (UUID)                                     │
│          - organization metadata                                │
└────────────────┬────────────────────────────────┬───────────────┘
                 │                                │
        ┌────────▼────────┐            ┌─────────▼──────────┐
        │     AGENTS      │            │    POLICIES        │
        ├─────────────────┤            ├────────────────────┤
        │ agent_id (PK)   │◄──┐        │ policy_id (PK)     │
        │ tenant_id (FK)  │   │        │ tenant_id (FK)     │
        │ name (unique)   │   │        │ name (unique)      │
        │ certificate     │   │        │ description        │
        │ status          │   │        │ status             │
        │ policy_ids[]────┼───┼──┐     │ rules[] (JSONB)    │
        │ version         │   │  │     │ rate_limits        │
        │ metadata        │   │  │     │ time_restrictions  │
        │ last_seen_at    │   │  │     │ allowed_domains    │
        │ created_at      │   │  │     │ blocked_domains    │
        │ updated_at      │   │  │     │ priority           │
        └────────┬────────┘   │  │     │ version            │
                 │            │  └─────┼────────────────────┘
                 │            │        │ created_by (user)
                 │            │        │
        ┌────────▼────────┐   │        │ POLICY_RULE
        │  AUDIT ENTRIES  │   │        │ ├─ rule_id
        │  (TimescaleDB   │   │        │ ├─ name
        │   Hypertable)   │   │        │ ├─ conditions[]
        ├─────────────────┤   │        │ ├─ action
        │ entry_id (PK)   │   │        │ └─ priority
        │ tenant_id       │◄──┼────┐   │
        │ agent_id (FK)   │   │    │   RULE_CONDITION
        │ timestamp (idx) │   │    │   ├─ field
        │ domain          │   │    │   ├─ operator
        │ decision        │   │    │   └─ value
        │ policy_id (FK)  │◄──┘    │
        │ rule_id (FK)    │────────┘
        │ request_*       │         RATE_LIMIT
        │ response_*      │         ├─ requests_per_minute
        │ timed_access_   │         ├─ requests_per_hour
        │  metadata       │         ├─ requests_per_day
        │ previous_hash   │         └─ burst_limit
        │ current_hash    │
        │ sequence_number │         TIME_RESTRICTION
        │ metadata        │         ├─ allowed_time_ranges[]
        │ risk_score      │         ├─ allowed_days_of_week
        └─────────────────┘         └─ timezone

Cardinality:
- 1 Tenant : M Agents
- 1 Tenant : M Policies
- 1 Agent : M AuditEntries
- 1 Policy : M AuditEntries (via policy_id)
- M Agents : N Policies (via agent.policy_ids[])
```

---

## 5. Concurrency & Data Integrity

```
┌──────────────────────────────────────────────────────────────┐
│          OPTIMISTIC LOCKING (Agent, Policy)                  │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Agent v1 (Client A):          Agent v1 (Client B):         │
│  ├─ version = 1                ├─ version = 1               │
│  ├─ name = "agent-1"           ├─ name = "agent-1"          │
│  └─ status = "pending"         └─ status = "pending"        │
│                                                               │
│  Update A:                      Update B:                    │
│  UPDATE agents                 UPDATE agents                │
│    SET status = "active"         SET name = "agent-1-new"   │
│    WHERE agent_id = ? AND       WHERE agent_id = ? AND      │
│          version = 1            version = 1                 │
│                                                               │
│  ✓ Success (0→1)  ✗ Conflict (0 rows updated)              │
│    version = 2      → ConcurrencyError raised               │
│                     → Client B must retry with fresh data   │
│                                                               │
│  Final State: Agent v2                                       │
│  ├─ version = 2                                             │
│  ├─ name = "agent-1"                                        │
│  └─ status = "active"                                       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│          AUDIT CHAIN INTEGRITY (Tamper Detection)             │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Entry[0] Entry[1]     Entry[2]        Entry[3]             │
│  ┌──────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │...   │ │...       │ │...       │ │...       │            │
│  │prev  │ │prev      │ │prev      │ │prev      │            │
│  │hash  │ │hash      │ │hash      │ │hash      │            │
│  │= ""  │ │= SHA256( │ │= SHA256( │ │= SHA256( │            │
│  │      │ │  Entry0) │ │  Entry1) │ │  Entry2) │            │
│  │curr  │ │curr    │ │curr    │ │curr    │            │
│  │hash  │ │hash    │ │hash    │ │hash    │            │
│  │= SHA │ │= SHA256│ │= SHA256│ │= SHA256│            │
│  │256() │ │(Entry1 │ │(Entry2 │ │(Entry3 │            │
│  │      │ │+ prev) │ │+ prev) │ │+ prev) │            │
│  └──────┘ └──────────┘ └──────────┘ └──────────┘            │
│     ↓          ↓          ↓          ↓                        │
│     └──────────┼──────────┼──────────┘                        │
│              Chain Link                                       │
│                                                               │
│  Verification Algorithm:                                     │
│  FOR each entry E in chain:                                 │
│    calculated = SHA256(E.data + E.previous_hash)           │
│    IF calculated != E.current_hash:                         │
│      → INTEGRITY VIOLATION DETECTED                         │
│      → Entry tampered or chain broken                       │
│      → Audit log compromised                                │
│    ELSE:                                                     │
│      → Entry valid, continue to next                        │
│                                                               │
│  Optional: HMAC-SHA256 with secret key for additional       │
│  authentication (signature verification)                    │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. Deployment Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────┐ │
│  │  Ingress/LB      │  │  Envoy Proxies   │  │  ChronoGuard│ │
│  │  (TLS)           │──│  (mTLS sidecar)  │──│  API Server │ │
│  └──────────────────┘  └──────────────────┘  └─────────────┘ │
│        ↓                                            ↓         │
│     Port 443                                   Port 8000      │
│     (External HTTPS)                           (Internal)     │
│                                                 ↓             │
│                                         ┌────────────────┐   │
│                                         │  gRPC (50051)  │   │
│                                         │  REST (8000)   │   │
│                                         │  WebSocket     │   │
│                                         └────────────────┘   │
│                                                               │
├────────────────────────────────────────────────────────────────┤
│  STATEFUL SERVICES (Kubernetes StatefulSets)                  │
│                                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │  PostgreSQL     │  │     Redis       │  │     OPA      │  │
│  │  Cluster        │  │   (Cache +      │  │   (Policy    │  │
│  │  (Primary +     │  │   Rate Limit)   │  │   Engine)    │  │
│  │   Replicas)     │  │                 │  │              │  │
│  │                 │  │   Port: 6379    │  │  Port: 8181  │  │
│  │  Port: 5432     │  └─────────────────┘  └──────────────┘  │
│  │                 │                                           │
│  │  TimescaleDB:   │                                           │
│  │  ├─ agents      │                                           │
│  │  ├─ policies    │                                           │
│  │  └─ audit_      │                                           │
│  │     entries     │                                           │
│  │     (hyper)     │                                           │
│  └─────────────────┘                                           │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Observability Stack (Optional)                         │ │
│  │  ├─ Prometheus (metrics scraping /metrics)             │ │
│  │  ├─ Jaeger (distributed tracing from OTLP)            │ │
│  │  ├─ Grafana (dashboards)                              │ │
│  │  └─ Loki (log aggregation)                            │ │
│  └─────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘

CLIENTS:
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  Browser         │  │  Agent (gRPC)    │  │  Admin Dashboard │
│  (React SPA)     │  │  (bot automation)│  │  (monitoring)    │
└──────────────────┘  └──────────────────┘  └──────────────────┘
       ↓                      ↓                      ↓
   https://                gRPC+mTLS            https://
   chronoguard              Port 50051           dashboard
     .local                 (optional)           .local
```

---

## 7. Feature Flags & Progressive Delivery

```
┌───────────────────────────────────────────────────────────┐
│            FEATURE MANAGER                               │
│  (core/features.py)                                      │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  POLICY_EVALUATION:                                      │
│  ├─ Status: ENABLED                                      │
│  ├─ Percentage: 100%                                     │
│  └─ Feature: OPA client integration active              │
│                                                           │
│  DYNAMIC_PROXY_CONFIG:                                   │
│  ├─ Status: ENABLED                                      │
│  ├─ Percentage: 75%                                      │
│  ├─ Feature: Envoy xDS server active                    │
│  └─ Canary: Only 75% of requests use xDS                │
│                                                           │
│  REAL_TIME_EVENTS:                                       │
│  ├─ Status: ENABLED                                      │
│  ├─ Percentage: 100%                                     │
│  └─ Feature: WebSocket event streaming active           │
│                                                           │
│  TEMPORAL_ANALYTICS:                                     │
│  ├─ Status: DISABLED                                     │
│  └─ Feature: Advanced time-series analytics not yet live │
│                                                           │
│  RATE_LIMITING:                                          │
│  ├─ Status: ENABLED                                      │
│  ├─ Percentage: 50%                                      │
│  ├─ Feature: Redis rate limiter active                  │
│  └─ Beta: Only enforced for 50% of agents              │
│                                                           │
│  USAGE:                                                  │
│  ├─ Container: DependencyContainer(feature_manager)     │
│  ├─ Services: Check feature before registering          │
│  └─ Runtime: Gradual feature rollout without redeployment
│                                                           │
└───────────────────────────────────────────────────────────┘

DEPLOYMENT PROGRESSION:
└─ Feature disabled (0%)
   ├─ Code deployed but inactive
   ├─ No performance impact
   └─ Zero downtime
                ↓
└─ Canary (5-10%)
   ├─ Tested with subset of traffic
   ├─ Monitor metrics for issues
   └─ Rollback if issues detected
                ↓
└─ Gradual rollout (10% → 50% → 100%)
   ├─ Increase percentage over time
   ├─ Monitor system impact
   └─ Adjust based on observability
                ↓
└─ Feature fully enabled (100%)
   ├─ Used by all requests
   └─ Legacy code paths can be removed in next release
```

---

## 8. Error Handling & Recovery Patterns

```
┌──────────────────────────────────────────────────────────────┐
│         DOMAIN EXCEPTIONS (Business Logic)                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ValidationError ─────────────────────────────┐              │
│  ├─ field, value, message                    │              │
│  └─ HTTP: 400 Bad Request                    │              │
│                                                │              │
│  BusinessRuleViolationError ───────────────────┤              │
│  ├─ rule_name, context                       │              │
│  └─ HTTP: 409 Conflict or 422 Unprocessable  │              │
│                                                │              │
│  DuplicateEntityError ──────────────────────────┤──┐          │
│  ├─ entity_type, field, value                  │  │          │
│  └─ HTTP: 409 Conflict                        │  │          │
│                                                   │  │          │
│  EntityNotFoundError ────────────────────────────┤──┼──┐      │
│  ├─ entity_type, id                             │  │  │      │
│  └─ HTTP: 404 Not Found                        │  │  │      │
│                                                   │  │  │      │
│  InvalidStateTransitionError ─────────────────────┤──┼──┤──┐  │
│  ├─ entity_type, current_state, requested_state  │  │  │  │  │
│  └─ HTTP: 422 Unprocessable Entity              │  │  │  │  │
│                                                   │  │  │  │  │
│  ConcurrencyError ──────────────────────────────────┼──┼──┤──┤
│  ├─ entity_id, current_version, expected_version   │  │  │  │
│  └─ HTTP: 409 Conflict (retry recommended)        │  │  │  │
│                                                   │  │  │  │
│  ┌────────────────────────────────────────────────┘  │  │  │
│  │  ┌───────────────────────────────────────────────┘  │  │
│  │  │  ┌──────────────────────────────────────────────┘  │
│  │  │  │  ┌───────────────────────────────────────────┘
│  │  │  │  │
│  ↓  ↓  ↓  ↓
│  FastAPI exception_handlers()
│  ├─ Catch domain exceptions
│  ├─ Log error with correlation ID
│  ├─ Return HTTP response with message
│  └─ Maintain request context for debugging
│                                                               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│    INFRASTRUCTURE EXCEPTIONS (Technical)                     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  RepositoryError ─────────────────────┐                      │
│  ├─ Database operation failures        │                      │
│  ├─ original_error preserved           │                      │
│  └─ HTTP: 500 Internal Server Error    │                      │
│                                         │                      │
│  OPAClientError ───────────────────────┼──┐                   │
│  ├─ OPAConnectionError (network issue) │  │                   │
│  ├─ OPAPolicyError (policy op failure) │  │                   │
│  ├─ OPAEvaluationError (eval failure)  │  │                   │
│  └─ Retry logic in client              │  │                   │
│                                         │  │                   │
│  ServiceNotFoundError ──────────────────┼──┼──┐               │
│  ├─ Dependency injection failure       │  │  │               │
│  └─ Configuration error (500)          │  │  │               │
│                                         │  │  │               │
│  FeatureDisabledError ──────────────────┼──┼──┼──┐            │
│  ├─ Required feature not enabled       │  │  │  │            │
│  └─ Configuration check (500)          │  │  │  │            │
│                                         │  │  │  │            │
│  ┌─────────────────────────────────────┘  │  │  │            │
│  │  ┌─────────────────────────────────────┘  │  │            │
│  │  │  ┌─────────────────────────────────────┘  │            │
│  │  │  │  ┌──────────────────────────────────┘  │            │
│  │  │  │  │                                      │            │
│  ↓  ↓  ↓  ↓                                      │            │
│  exception_handlers()                          │            │
│  ├─ Log with full traceback                    │            │
│  ├─ Telemetry: record error metric             │            │
│  ├─ Return 500 with generic message            │            │
│  └─ Never expose internal details to client    │            │
│                                                  │            │
└──────────────────────────────────────────────────────────────┘

RETRY STRATEGY:
├─ OPA client: Exponential backoff (3 attempts)
├─ Repository: No automatic retry (let caller handle)
├─ Rate limiter: Fail fast (return rate_limited decision)
└─ Cache: Fallback to database on miss
```

This architecture documentation provides comprehensive coverage for creating detailed architecture diagrams for presentations, documentation, or team understanding.
