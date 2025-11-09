# ChronoGuard Architecture Diagrams

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENTS & INTERFACES                             │
├─────────────┬──────────────────┬────────────────┬──────────────────┤
│  Web Browser│  Agent (gRPC)    │  Envoy Proxy   │  Admin Dashboard  │
│  (Frontend) │  (browser bots)  │  (mTLS)        │  (React)          │
└──────┬──────┴──────────┬───────┴────────┬───────┴──────────┬────────┘
       │                 │                │                  │
       │ HTTP/REST       │ gRPC          │ xDS              │ WebSocket
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

## 3. Request Flow: Policy Evaluation (via Envoy)

```
EXTERNAL CLIENT
       │
       │ HTTPS Request to agent.example.com/api/data
       │
       ↓
┌─────────────────────────────────────────────────────────────┐
│            Envoy Proxy (mTLS termination)                   │
│  ├─ Verify client certificate (agent cert)                 │
│  ├─ Extract: agent_id from cert CN                         │
│  ├─ Extract: request domain, method, path, user-agent      │
│  ├─ Extract: source IP                                      │
│  │                                                           │
│  ├─ Query xDS control plane (ChronoGuard)                   │
│  │  └─ Get listener & route configuration                  │
│  │                                                           │
│  └─ Check policy via gRPC/HTTP to ChronoGuard             │
└────────┬────────────────────────────────────────────────────┘
         │
         │ GET /v1/data/chronoguard/policy
         │ { input: {
         │     agent_id: "abc-123",
         │     domain: "agent.example.com",
         │     method: "GET",
         │     path: "/api/data",
         │     timestamp: "2024-01-01T12:00:00Z",
         │     source_ip: "203.0.113.5",
         │     user_agent: "Mozilla/5.0..."
         │   }
         │ }
         ↓
┌─────────────────────────────────────────────────────────────┐
│         OPAClient.check_policy() (infrastructure/opa)       │
│  ├─ POST to OPA REST API (port 8181)                       │
│  ├─ Retry logic: max 3 attempts                            │
│  ├─ Timeout: 30 seconds                                     │
│  └─ Log attempt                                             │
└────────┬────────────────────────────────────────────────────┘
         │
         │ HTTP POST to OPA
         │ http://opa-server:8181/v1/data/chronoguard/policy
         │
         ↓
    ┌─────────────────────────────┐
    │  Open Policy Agent (OPA)    │
    │  (external service)         │
    │                             │
    │  Rego Policies:             │
    │  ├─ Domain matching rules   │
    │  ├─ Time-based restrictions │
    │  ├─ Rate limit checks       │
    │  ├─ User agent validation   │
    │  └─ Custom rules            │
    │                             │
    │  → Evaluates input          │
    │  ← Returns decision: true/false
    │                             │
    │  (Compiled from Policy      │
    │   entities via             │
    │   PolicyCompiler)           │
    └─────────────────────────────┘
         │
         │ OPA Decision: ALLOW or DENY
         │ { result: true } or { result: false }
         │
         ↓
┌─────────────────────────────────────────────────────────────┐
│       Back to ChronoGuard (decision received)               │
│                                                              │
│  1. Create AuditEntry:                                     │
│     ├─ agent_id (from request)                             │
│     ├─ domain (from request)                               │
│     ├─ decision (from OPA)                                 │
│     ├─ timestamp (UTC now)                                 │
│     ├─ request details (method, path, user-agent, ip)     │
│     ├─ timed_access_metadata (calculated)                 │
│     ├─ risk_score (calculated from decision + context)    │
│     └─ hash chain (calculated with previous entry)        │
│                                                              │
│  2. Store AuditEntry:                                      │
│     └─ INSERT into audit_entries table (TimescaleDB)      │
│        └─ Partitioned by timestamp (7-day chunks)         │
│                                                              │
│  3. Side Effects:                                          │
│     ├─ Publish WebSocket event (audit-events topic)       │
│     ├─ Update cache: agent last_seen_at                    │
│     └─ Redis: increment rate limit counters               │
│                                                              │
│  4. Return Decision to Envoy:                              │
│     └─ { decision: "allow" | "deny" }                     │
└────────┬────────────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────────────┐
│            Envoy Proxy (decision received)                  │
│  ├─ If decision == ALLOW:                                  │
│  │  └─ Forward request to upstream backend                 │
│  │     └─ Wait for response from backend                   │
│  │                                                           │
│  └─ If decision == DENY:                                   │
│     └─ Return 403 Forbidden to client                      │
│        └─ Include reason in response                       │
└────────┬────────────────────────────────────────────────────┘
         │
         │ Response (200 OK or 403 Forbidden)
         │
         ↓
EXTERNAL CLIENT
```

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
