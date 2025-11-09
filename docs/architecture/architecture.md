# ChronoGuard Architecture Summary

## Implementation Status

**Last Updated:** 2025-11-08
**Version:** MVP (v0.1.0)
**Test Coverage:** 96%+

### Completed Components

- ✅ **Domain Layer** - Clean architecture with no infrastructure dependencies (except Signer - known limitation)
- ✅ **Application Layer** - CQRS Commands/Queries for all operations
- ✅ **Presentation Layer** - REST API with FastAPI, comprehensive route coverage
- ✅ **Infrastructure Layer** - PostgreSQL, Redis, OPA client implementations
- ✅ **Envoy Integration** - Forward proxy with mTLS authentication
- ✅ **OPA Policy Engine** - Decision log ingestion, policy compilation and deployment
- ✅ **Docker Deployment** - 6-service stack (Envoy, OPA, API, Dashboard, PostgreSQL, Redis)
- ✅ **Frontend** - React + Vite dashboard for monitoring

### Not Yet Implemented (Deferred to v0.2.0+)

- ⏳ **gRPC Server** - Partial implementation exists, not wired into runtime
- ⏳ **WebSocket Event Streaming** - Infrastructure exists, endpoints not exposed
- ⏳ **Envoy xDS Server** - Static configuration used instead of dynamic control plane
- ⏳ **Advanced Rate Limiting** - Basic implementation only, Redis integration minimal
- ⏳ **Feature-Flag DI** - Container exists but not used for routing decisions

### Architecture Divergences from Original Design

**OPA Integration Flow:**
- **Original Design:** FastAPI → OPA for policy checks
- **Actual Implementation:** Envoy → OPA (ext_authz) → FastAPI (decision logs)
- **Reason:** More efficient to have Envoy handle policy enforcement at proxy layer

**Audit Trail:**
- **Original Design:** All agent/policy CRUD operations create audit entries
- **Actual Implementation:** Only access attempts (OPA decisions) create audit entries
- **Reason:** Focused on access control audit trail as primary compliance requirement

---

## 1. OVERALL ARCHITECTURE PATTERN: Domain-Driven Design (DDD) Layered Architecture

ChronoGuard implements Clean Architecture with Domain-Driven Design principles, organized into vertical slices with the following layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                           │
│  (FastAPI REST APIs, gRPC, WebSocket handlers)                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  APPLICATION LAYER (CQRS)                       │
│  (Commands, Queries, DTOs, Mappers)                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     DOMAIN LAYER (DDD)                          │
│  (Entities, Repositories, Services, Value Objects,             │
│   Business Logic, Exceptions)                                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                INFRASTRUCTURE LAYER                             │
│  (Persistence, OPA, Envoy, Telemetry, Security)                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    CORE LAYER (Cross-cutting)                   │
│  (Configuration, Logging, Dependency Injection, Features)       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Architecture Characteristics:
- **Dependency Rule**: Dependencies flow inward (Presentation → Application → Domain ← Infrastructure)
- **Domain Independence**: Domain layer has no external dependencies
- **Repository Pattern**: All persistence abstracted behind repository interfaces
- **CQRS**: Commands for mutations, Queries for reads
- **Feature Flag Management**: Feature toggles integrated at container level
- **Async-First**: Async/await patterns throughout
- **Type Safety**: Strong typing with Python type hints and Pydantic validation

---

## 2. MAIN DOMAIN ENTITIES AND RELATIONSHIPS

### 2.1 AGENT ENTITY
**Location**: `/backend/src/domain/agent/entity.py`

**Responsibility**: Represents browser automation agents that connect to ChronoGuard

**Key Attributes**:
- `agent_id` (UUID): Unique identifier
- `tenant_id` (UUID): Tenant association for multi-tenancy
- `name` (String, 3-100 chars): Agent name with alphanumeric validation
- `certificate` (X509Certificate): mTLS certificate for secure identification
- `status` (Enum): PENDING → ACTIVE → SUSPENDED → DEACTIVATED or EXPIRED
- `policy_ids` (List[UUID], max 50): Assigned policies
- `last_seen_at` (DateTime): Last connection timestamp
- `version` (Integer): Optimistic locking for concurrency control
- `metadata` (Dict): Flexible storage for transitions, suspension reasons, etc.

**State Transitions**:
```
PENDING → ACTIVE (from SUSPENDED) → SUSPENDED → DEACTIVATED
       ↘ EXPIRED (certificate expiry from ACTIVE/SUSPENDED)
```

**Core Behaviors**:
- `activate()`: Move from PENDING/SUSPENDED to ACTIVE
- `suspend()`: Pause agent with optional reason
- `deactivate()`: Permanently disable agent
- `mark_expired()`: Mark as expired when certificate expires
- `assign_policy()`: Add policy (max 50 per agent)
- `remove_policy()`: Remove assigned policy
- `update_certificate()`: Replace certificate (validates not expired)
- `can_make_requests()`: Check if agent can make requests (ACTIVE + valid cert)

**Relationships**:
```
Agent → (M:N) → Policy (via policy_ids)
Agent → (1:N) → AuditEntry (via agent_id)
Agent → (1:1) → X509Certificate (embedded value object)
```

**Business Rules** (Enforced in AgentService):
- Agent name must be unique per tenant
- Certificate fingerprint must be globally unique
- Certificate must be valid (not expired)
- Max 1000 agents per tenant
- Max 50 policies per agent

---

### 2.2 POLICY ENTITY
**Location**: `/backend/src/domain/policy/entity.py`

**Responsibility**: Defines access control rules, restrictions, and rate limits

**Key Attributes**:
- `policy_id` (UUID): Unique identifier
- `tenant_id` (UUID): Tenant association
- `name` (String, 3-100 chars): Policy name
- `description` (String, max 1000 chars): Policy description
- `status` (Enum): DRAFT → ACTIVE → SUSPENDED → ARCHIVED
- `priority` (Integer, 1-1000): Evaluation order (lower = higher priority)
- `rules` (List[PolicyRule], max 100): Individual policy rules
- `time_restrictions` (Optional[TimeRestriction]): Time-based access control
- `rate_limits` (Optional[RateLimit]): Request rate limiting
- `allowed_domains` (Set[String], max 1000): Whitelist of domains
- `blocked_domains` (Set[String], max 1000): Blacklist of domains
- `version` (Integer): Optimistic locking

**PolicyRule Structure**:
```
{
  "rule_id": UUID,
  "name": String,
  "description": String,
  "conditions": List[RuleCondition],
  "action": RuleAction (ALLOW | DENY | LOG | RATE_LIMIT),
  "priority": Integer (1-1000),
  "enabled": Boolean,
  "metadata": Dict[String, String]
}
```

**RuleCondition Structure**:
```
{
  "field": String (domain | method | path | user_agent | source_ip | time | day_of_week | request_count),
  "operator": String (equals | not_equals | contains | starts_with | regex_match | in | greater_than | less_than | etc),
  "value": String
}
```

**RateLimit Structure**:
```
{
  "requests_per_minute": int (>= 1),
  "requests_per_hour": int (>= 1),
  "requests_per_day": int (>= 1),
  "burst_limit": int (1-1000, default 10),
  "enabled": bool
}
```

**TimeRestriction Structure**:
```
{
  "allowed_time_ranges": List[TimeRange],  # 1-10 ranges
  "allowed_days_of_week": Set[int],       # 0-6 (Monday-Sunday)
  "timezone": String,                     # Default "UTC"
  "enabled": bool
}
```

**State Transitions**:
```
DRAFT → ACTIVE → SUSPENDED → ARCHIVED
    ↖_____________↗
```

**Core Behaviors**:
- `add_rule()`: Add rule (validates uniqueness and max count)
- `remove_rule()`: Remove rule by ID
- `activate()`: Move to ACTIVE (requires rules or domain restrictions)
- `suspend()`: Temporarily disable policy
- `archive()`: Permanently archive policy
- `add_allowed_domain()`: Add to whitelist (validates not in blacklist)
- `add_blocked_domain()`: Add to blacklist (validates not in whitelist)
- `remove_domain()`: Remove from both lists
- `set_time_restrictions()`: Configure time-based access
- `set_rate_limits()`: Configure rate limiting

**Business Rules** (Enforced in PolicyService):
- Policy name must be unique per tenant
- Cannot activate policy without rules or domain restrictions
- Cannot activate archived policy
- Max 100 rules per policy
- Max 20 conditions per rule
- Max 10 time ranges per restriction
- Allowed and blocked domains are mutually exclusive per domain

---

### 2.3 AUDIT ENTRY ENTITY
**Location**: `/backend/src/domain/audit/entity.py`

**Responsibility**: Immutable, cryptographically verified access logs with temporal analytics

**Key Attributes**:
- `entry_id` (UUID): Unique identifier
- `tenant_id` (UUID): Tenant association
- `agent_id` (UUID): Accessing agent
- `timestamp` (DateTime): Request timestamp (always UTC)
- `timestamp_nanos` (int): Nanosecond precision timestamp
- `domain` (DomainName): Target domain
- `decision` (AccessDecision): ALLOW | DENY | BLOCK | RATE_LIMITED | TIME_RESTRICTED | POLICY_VIOLATION
- `reason` (String, max 500): Decision reason
- `policy_id` (Optional[UUID]): Matching policy
- `rule_id` (Optional[UUID]): Matching rule
- `request_method` (String): HTTP method (default GET)
- `request_path` (String): Request path
- `user_agent` (Optional[String]): Client user agent
- `source_ip` (Optional[String]): Client IP (validated)
- `response_status` (Optional[int]): HTTP response code
- `response_size_bytes` (Optional[int]): Response size
- `processing_time_ms` (Optional[float]): Processing duration
- `timed_access_metadata` (TimedAccessContext): Temporal metadata
- `previous_hash` (String): Hash of previous entry (chain)
- `current_hash` (String): Entry's cryptographic hash
- `sequence_number` (int): Position in chain (for integrity)
- `metadata` (Dict): Flexible storage

**TimedAccessContext Structure**:
```
{
  "request_timestamp": DateTime,
  "processing_timestamp": DateTime,
  "timezone_offset": int (minutes from UTC),
  "day_of_week": int (0=Monday, 6=Sunday),
  "hour_of_day": int,
  "is_business_hours": bool (9am-5pm UTC),
  "is_weekend": bool,
  "week_of_year": int,
  "month_of_year": int,
  "quarter_of_year": int
}
```

**Core Behaviors**:
- `calculate_hash()`: Generate SHA-256 hash (with optional HMAC-SHA256)
- `with_hash()`: Create new entry with calculated hash
- `verify_hash()`: Verify entry integrity
- `is_access_allowed()`: Check if decision is ALLOW
- `is_access_denied()`: Check if decision is denial-type
- `get_risk_score()`: Calculate risk score (0-100)
  - Base 30 for denied access
  - +20 for off-hours
  - +15 for weekend
  - +25 for suspicious user agents
- `to_json_dict()`: Serialize for JSON (includes risk_score)

**Chain Verification**:
```
Entry[n-1] hash → Entry[n].previous_hash
Entry[n] calculated hash ≈ Entry[n].current_hash (using secret key if available)
```

**Immutability**: 
- `frozen = True` in Pydantic (no post-creation modifications)
- Prevents tampering with audit records

**Relationships**:
```
AuditEntry ← N:1 ← Agent
AuditEntry ← N:1 ← Policy
AuditEntry ← N:1 ← PolicyRule
AuditEntry (temporal chain) ← N:1 ← Tenant
```

**Business Rules**:
- One entry per access attempt
- Timestamp always UTC
- IP addresses must be valid IPv4/IPv6
- Sequence numbers non-negative
- Hash chain forms immutable audit log
- Reason max 500 characters

---

### 2.4 VALUE OBJECTS (Domain-Driven Design)

**Location**: `/backend/src/domain/common/value_objects/`

#### X509Certificate
```python
class X509Certificate(BaseModel):
    pem_data: str  # PEM-encoded certificate
    
    Properties:
    - fingerprint_sha256: Hex string fingerprint for uniqueness
    - not_valid_before: datetime
    - not_valid_after: datetime
    - is_valid_now: bool
    - days_until_expiry: int
    
    Validations:
    - Must be valid PEM format
    - Must not already be expired
    - Must meet security constraints
    - Uses cryptography library for parsing
```

#### DomainName
```python
class DomainName(BaseModel):
    value: str
    
    Properties:
    - is_valid: bool
    - has_wildcard: bool
    
    Validations:
    - Must be valid DNS name or IP
    - Max 500 characters
    - Wildcard domains supported (*.example.com)
```

#### TimeRange
```python
class TimeRange(BaseModel):
    start_time: str  # HH:MM format
    end_time: str    # HH:MM format
    
    Validations:
    - Valid time format
    - start_time < end_time
```

---

## 3. INFRASTRUCTURE COMPONENTS

### 3.1 PERSISTENCE LAYER

**Location**: `/backend/src/infrastructure/persistence/`

#### PostgreSQL Persistence
- **Engine**: SQLAlchemy async ORM with asyncpg driver
- **Databases**: 
  - `chronoguard_dev` (development)
  - Production varies by deployment

#### Database Models
**Location**: `/backend/src/infrastructure/persistence/models.py`

```
AgentModel
├── Columns: agent_id, tenant_id, name, certificate_pem, status
├── policy_ids (ARRAY), metadata (JSONB)
├── version (optimistic locking)
└── Indexes:
    ├── ix_agent_tenant_name (unique)
    ├── ix_agent_tenant_status
    └── ix_agent_metadata_gin (JSONB GIN index)

PolicyModel
├── Columns: policy_id, tenant_id, name, description, status, priority
├── rules (JSONB), time_restrictions (JSONB), rate_limits (JSONB)
├── allowed_domains (ARRAY), blocked_domains (ARRAY)
├── version, metadata (JSONB)
└── Indexes:
    ├── ix_policy_tenant_name (unique)
    ├── ix_policy_tenant_status
    ├── ix_policy_tenant_priority
    └── ix_policy_metadata_gin, ix_policy_rules_gin

AuditEntryModel (TimescaleDB Hypertable)
├── Columns: entry_id, tenant_id, agent_id, timestamp, timestamp_nanos
├── domain, decision, reason, policy_id, rule_id
├── request_* (method, path, user_agent, ip), response_*
├── timed_access_metadata (JSONB), hashes, sequence_number
└── Indexes:
    ├── ix_audit_tenant_timestamp
    ├── ix_audit_agent_timestamp
    ├── ix_audit_tenant_decision
    ├── ix_audit_hash_chain
    └── GIN indexes for JSONB fields
```

#### TimescaleDB Integration
**Location**: `/backend/src/infrastructure/persistence/timescale.py`

```python
async def setup_timescaledb(engine: AsyncEngine):
    # Creates hypertable on audit_entries
    # Chunk interval: 7 days
    # Compression: enabled after 30 days
    # Retention: 1 year (automatic deletion after 1 year)
```

#### Repository Implementations

**Agent Repository**:
- `PostgresAgentRepository` implements `AgentRepository` interface
- Methods:
  - `create()`: Insert new agent
  - `find_by_id()`: Get by agent_id
  - `find_by_tenant_id()`: Get all for tenant
  - `exists_by_name()`: Check duplicate name
  - `exists_by_certificate_fingerprint()`: Check duplicate cert
  - `count_by_tenant()`: Count for tenant
  - `update()`: Update with version check (concurrency)
  - `delete()`: Soft/hard delete
  - `list_by_status()`: Filter by status

**Policy Repository**:
- `PostgresPolicyRepository` implements `PolicyRepository` interface
- Similar CRUD + filtering by status, tenant, priority

**Audit Repository**:
- `PostgresAuditRepository` implements `AuditRepository` interface
- Methods optimized for time-series data:
  - `create()`: Insert audit entry
  - `find_by_id()`: Get by entry_id
  - `find_by_tenant_and_time_range()`: Temporal queries
  - `find_by_agent_and_decision()`: Filter by agent + decision
  - `get_chain_for_verification()`: Retrieve entries for chain verification
  - `get_latest_sequence_number()`: For sequence generation

#### Redis Caching Layer
**Location**: `/backend/src/infrastructure/persistence/redis/`

```
cache_repository.py
├── RedisCacheRepository
├── Methods: get(), set(), delete(), exists()
└── TTL-based expiration

cache_service.py
├── CacheService (higher-level abstraction)
├── Policy caching with invalidation
└── Agent status caching

rate_limiter.py
├── RedisRateLimiter
├── Implements token bucket algorithm
├── Tracks: requests_per_minute, requests_per_hour, requests_per_day
└── Methods: check_limit(), increment()
```

---

### 3.2 OPEN POLICY AGENT (OPA) INTEGRATION

**Location**: `/backend/src/infrastructure/opa/`

#### OPA Client
**File**: `client.py`

```python
class OPAClient:
    """Async HTTP client for OPA REST API (port 8181)"""
    
    Methods:
    - check_policy(policy_input) → bool
      * POST /v1/data/{policy_path}
      * Supports retry logic (max 3 attempts)
      * Timeout: 30s (configurable)
    
    - update_policy(policy_name, rego_code) → None
      * PUT /v1/policies/{policy_path}
      * Uploads Rego code to OPA
    
    - get_policy(policy_name) → str
      * GET /v1/policies/{policy_path}
      * Retrieves Rego code
    
    - delete_policy(policy_name) → None
      * DELETE /v1/policies/{policy_path}
    
    - health_check() → dict
      * GET /health
      * Verifies OPA availability
    
    Error Handling:
    - OPAClientError (base)
    - OPAConnectionError (network issues)
    - OPAPolicyError (policy operations)
    - OPAEvaluationError (evaluation failures)
```

#### Policy Compiler
**File**: `policy_compiler.py`

```python
class PolicyCompiler:
    """Converts domain policies to OPA Rego format"""
    
    Methods:
    - compile_policy(policy: Policy) → str
      * Converts Policy entity to Rego code
      * Uses Jinja2 templates
      * Generates rule conditions, time restrictions, rate limits
    
    - deploy_policy(policy: Policy) → None
      * Compiles and uploads to OPA
      * Handles policy updates
    
    - generate_bundle() → bytes
      * Creates OPA policy bundle (tar.gz)
      * For offline deployment
    
    Templates:
    - policy_rule.rego.j2 (rule conditions)
    - time_restriction.rego.j2 (time-based access)
    - rate_limit.rego.j2 (rate limiting logic)
```

#### Decision Logger
**File**: `decision_logger.py`

```python
class OPADecisionLogger:
    """Logs OPA policy evaluation decisions"""
    
    Methods:
    - log_decision(decision_info) → None
      * Records policy evaluation result
      * Links decision to audit entry
      * Tracks OPA performance metrics
```

#### Bundle Builder
**File**: `bundle_builder.py`

```python
class OPABundleBuilder:
    """Builds OPA policy bundles for deployment"""
    
    Methods:
    - add_policy(name, rego_code) → None
    - build() → bytes (tar.gz bundle)
    - sign_bundle() → None (cryptographic signing)
```

---

### 3.3 ENVOY PROXY INTEGRATION

**Location**: `/backend/src/infrastructure/envoy/`

#### xDS Server
**File**: `xds_server.py`

```python
class XDSServer:
    """Implements Envoy xDS protocol for dynamic configuration"""
    
    Components:
    - gRPC server (port 18000 by default)
    - Configuration cache manager
    - Listener, Route, Cluster, Endpoint discovery
    
    Features:
    - Dynamic configuration updates
    - mTLS support for secure control plane
    - Certificate management
    
    Workflow:
    1. Envoy proxies connect via gRPC
    2. Server pushes configuration snapshots
    3. Configuration includes policies, allowed domains, rate limits
    4. Proxies apply configuration immediately
    5. Server pushes updates on policy changes
```

#### Config Generator
**File**: `config_generator.py`

```python
class ConfigGenerator:
    """Generates Envoy configuration from domain models"""
    
    Methods:
    - generate_listeners(agents) → List[Listener]
      * Creates Envoy listeners (inbound connections)
    
    - generate_routes(policies) → List[Route]
      * Creates route configuration from policies
      * Includes domain matching, rate limiting
    
    - generate_clusters(agent_backends) → List[Cluster]
      * Creates upstream clusters (backend services)
    
    - generate_endpoints(agents) → List[Endpoint]
      * Creates endpoint load balancing
    
    Output: envoy.config.v3 protobuf structures
```

#### Discovery Service
**File**: `discovery_service.py`

```python
class DiscoveryService:
    """Manages xDS resource discovery and versioning"""
    
    Methods:
    - get_listeners() → List[Listener]
    - get_routes() → List[Route]
    - get_clusters() → List[Cluster]
    - get_endpoints() → List[Endpoint]
    
    Versioning:
    - Tracks configuration versions
    - Incremental updates support
    - Nonce validation for ordering
```

---

### 3.4 TELEMETRY & OBSERVABILITY

**Location**: `/backend/src/infrastructure/observability/`

**File**: `telemetry.py`

```python
class TelemetryManager:
    """OpenTelemetry integration for observability"""
    
    Components:
    - Tracing (spans for request tracking)
    - Metrics (counters, gauges, histograms)
    - Logging (structured logs)
    
    Exporters:
    - OTLP (OpenTelemetry Protocol)
    - Prometheus metrics endpoint (/metrics)
    - Console logging
    
    Key Metrics:
    - Agent request count
    - Policy evaluation latency
    - OPA evaluation time
    - Audit entry creation rate
    - Cache hit/miss ratios
    - Error rates by operation
```

---

### 3.5 SECURITY INFRASTRUCTURE

**Location**: `/backend/src/infrastructure/security/`

**File**: `signer.py`

```python
class CryptographicSigner:
    """Signs and verifies audit entries"""
    
    Methods:
    - sign_entry(audit_entry) → str (signature)
      * HMAC-SHA256 with secret key
      * Used for audit chain integrity
    
    - verify_entry(audit_entry) → bool
      * Verifies signature is valid
      * Detects tampering
    
    Key Management:
    - Loads keys from environment or files
    - Supports key rotation
```

---

## 4. PRESENTATION LAYERS

### 4.1 FastAPI REST API

**Location**: `/backend/src/presentation/api/`

#### Routes

**Agent Routes** (`routes/agents.py`)
```
POST   /api/v1/agents                    → create_agent()
GET    /api/v1/agents/{agent_id}        → get_agent()
GET    /api/v1/agents                   → list_agents() [paginated]
PUT    /api/v1/agents/{agent_id}        → update_agent()
```

**Policy Routes** (`routes/policies.py`)
```
POST   /api/v1/policies                 → create_policy()
GET    /api/v1/policies/{policy_id}     → get_policy()
GET    /api/v1/policies                 → list_policies() [paginated]
PUT    /api/v1/policies/{policy_id}     → update_policy()
DELETE /api/v1/policies/{policy_id}     → delete_policy()
```

**Audit Routes** (`routes/audit.py`)
```
GET    /api/v1/audit                    → list_audit_entries() [paginated, filtered]
GET    /api/v1/audit/{entry_id}        → get_audit_entry()
GET    /api/v1/audit/export              → export_audit_entries() [CSV, JSON]
GET    /api/v1/audit/analytics/temporal → get_temporal_analytics()
```

**Health Routes** (`routes/health.py`)
```
GET    /health                          → health_check()
GET    /metrics                         → prometheus_metrics()
```

#### Middleware

**Auth Middleware** (`middleware/auth.py`)
- Extracts tenant_id from request headers/JWT
- Validates X.509 client certificates
- Implements multi-tenancy isolation

**CORS Middleware** (`middleware/cors.py`)
- Configured for frontend (http://localhost:3000)
- Allowed methods: GET, POST, PUT, DELETE, PATCH
- Credential support

#### Dependencies
**File**: `dependencies.py`

```python
# Singleton repository instances (connection pooling)
_agent_repository: PostgresAgentRepository
_policy_repository: PostgresPolicyRepository
_audit_repository: PostgresAuditRepository

# Dependency providers
def get_agent_repository() → PostgresAgentRepository
def get_policy_repository() → PostgresPolicyRepository
def get_audit_repository() → PostgresAuditRepository

def get_agent_service() → AgentService
def get_policy_service() → PolicyService
def get_audit_service() → AuditService

def get_create_agent_command() → CreateAgentCommand
def get_update_agent_command() → UpdateAgentCommand
def get_create_policy_command() → CreatePolicyCommand
def get_update_policy_command() → UpdatePolicyCommand
def get_delete_policy_command() → DeletePolicyCommand

def get_get_agent_query() → GetAgentQuery
def get_list_agents_query() → ListAgentsQuery
def get_get_policy_query() → GetPolicyQuery
def get_list_policies_query() → ListPoliciesQuery
def get_get_audit_query() → GetAuditEntriesQuery

def get_tenant_id(header: X-Tenant-ID) → UUID
```

---

### 4.2 gRPC Server

**Location**: `/backend/src/presentation/grpc/`

**File**: `server.py`

```python
class GRPCServer:
    """gRPC service for agent communication"""
    
    Services:
    - AgentService (check_access, update_policy, etc)
    - PolicyService (get_policy, list_policies)
    - AuditService (log_access, get_audit_entries)
    
    Features:
    - Stream processing for bulk operations
    - mTLS authentication
    - Bidirectional streaming support
    
    Port: 50051 (configurable)
```

---

### 4.3 WebSocket Handlers

**Location**: `/backend/src/presentation/websocket/`

#### Manager
**File**: `manager.py`

```python
class WebSocketManager:
    """Pub/Sub manager for real-time updates"""
    
    Features:
    - Connection registry
    - Topic-based subscriptions
    - Broadcast messaging
    - Connection lifecycle management
    
    Methods:
    - register(websocket, client_id, metadata) → None
    - subscribe(client_id, topic) → None
    - unsubscribe(client_id, topic) → None
    - broadcast(topic, message) → None
    - send_to_client(client_id, message) → None
    - unregister(client_id) → None
    
    Topics:
    - agent-events (agent creation, status changes)
    - policy-events (policy updates, activations)
    - audit-events (new audit entries)
```

#### Handlers
**File**: `handlers.py`

```python
class WebSocketHandlers:
    """WebSocket endpoint handlers"""
    
    Endpoints:
    - /ws/v1/events (real-time event stream)
    
    Message Format:
    {
        "event_type": "agent_created" | "policy_updated" | "audit_entry",
        "data": {...},
        "timestamp": ISO8601
    }
```

---

## 5. APPLICATION LAYER (CQRS)

### 5.1 Commands

**Location**: `/backend/src/application/commands/`

#### Command Pattern Implementation
```
User Request → FastAPI Route → Command Handler → Domain Service → Repository
                    ↓
              CreateAgentCommand.execute()
                    ↓
              AgentService.create_agent()
                    ↓
              AgentRepository.save()
                    ↓
              AuditEntry Created (side effect)
```

#### Agent Commands
- **CreateAgentCommand** (`create_agent.py`)
  - Input: CreateAgentRequest (name, certificate_pem)
  - Calls: AgentService.create_agent()
  - Output: AgentDTO
  - Exceptions: DuplicateEntityError, ValidationError

- **UpdateAgentCommand** (`update_agent.py`)
  - Input: UpdateAgentRequest (partial fields)
  - Calls: AgentService.update_agent()
  - Output: AgentDTO
  - Handles: Certificate updates, policy assignment

#### Policy Commands
- **CreatePolicyCommand** (`create_policy.py`)
  - Input: CreatePolicyRequest
  - Calls: PolicyService.create_policy()
  - Output: PolicyDTO

- **UpdatePolicyCommand** (`update_policy.py`)
  - Input: UpdatePolicyRequest
  - Calls: PolicyService.update_policy()
  - Updates: Rules, time restrictions, rate limits, domains

- **DeletePolicyCommand** (`delete_policy.py`)
  - Input: policy_id
  - Calls: PolicyService.delete_policy()
  - Cascades: Unassigns from agents, archives audit references

---

### 5.2 Queries

**Location**: `/backend/src/application/queries/`

#### Query Pattern Implementation
```
User Request → FastAPI Route → Query Handler → Repository Query → Response DTO
                    ↓
              GetAgentQuery.execute()
                    ↓
              AgentRepository.find_by_id()
                    ↓
              AgentMapper.to_dto()
```

#### Agent Queries
- **GetAgentQuery** (`get_agent.py`)
  - Input: agent_id, tenant_id
  - Output: AgentDTO or None
  - Filters: Tenant isolation

- **ListAgentsQuery** (`list_agents.py`)
  - Input: tenant_id, page, page_size, status_filter
  - Output: AgentListResponse (paginated)
  - Supports: Pagination, status filtering

#### Policy Queries
- **GetPolicyQuery** (`get_policy.py`)
  - Input: policy_id, tenant_id
  - Output: PolicyDTO or None

- **ListPoliciesQuery** (`list_policies.py`)
  - Input: tenant_id, page, page_size, status_filter, priority_range
  - Output: PolicyListResponse (paginated)

#### Audit Queries
- **GetAuditEntriesQuery** (`get_audit.py`)
  - Input: tenant_id, agent_id, time_range, decision_filter
  - Output: List[AuditEntryDTO]
  - Time-series optimized queries for TimescaleDB

- **AuditExporter** (`audit_export.py`)
  - Input: tenant_id, time_range, format (CSV/JSON)
  - Output: Exported audit logs
  - Methods: export_csv(), export_json()

- **TemporalAnalyticsQuery** (`temporal_analytics.py`)
  - Input: tenant_id, time_range
  - Aggregations: Access by hour/day/week, decision distribution, risk trends
  - Output: Time-series analytics

---

### 5.3 Data Transfer Objects (DTOs)

**Location**: `/backend/src/application/dto/`

#### Agent DTO
```python
class AgentDTO(BaseModel):
    agent_id: UUID
    tenant_id: UUID
    name: str
    status: str  # From enum
    policy_ids: List[UUID]
    certificate_fingerprint: str  # Partial exposure
    created_at: datetime
    updated_at: datetime
    last_seen_at: Optional[datetime]
    version: int

class CreateAgentRequest(BaseModel):
    name: str
    certificate_pem: str  # Full PEM certificate

class UpdateAgentRequest(BaseModel):
    name: Optional[str] = None
    certificate_pem: Optional[str] = None
    status: Optional[str] = None

class AgentListResponse(BaseModel):
    items: List[AgentDTO]
    total: int
    page: int
    page_size: int
```

#### Policy DTO
```python
class PolicyDTO(BaseModel):
    policy_id: UUID
    tenant_id: UUID
    name: str
    description: str
    status: str
    priority: int
    rules_count: int
    has_time_restrictions: bool
    has_rate_limits: bool
    allowed_domains_count: int
    blocked_domains_count: int
    created_at: datetime
    updated_at: datetime
    version: int

class CreatePolicyRequest(BaseModel):
    name: str
    description: str
    rules: List[PolicyRuleDTO] = []
    # ... rule/restriction/limit details

class UpdatePolicyRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    # ... optional fields
```

#### Audit DTO
```python
class AuditEntryDTO(BaseModel):
    entry_id: UUID
    tenant_id: UUID
    agent_id: UUID
    timestamp: datetime
    domain: str
    decision: str
    reason: str
    policy_id: Optional[UUID]
    rule_id: Optional[UUID]
    request_method: str
    request_path: str
    user_agent: Optional[str]
    source_ip: Optional[str]
    response_status: Optional[int]
    processing_time_ms: Optional[float]
    risk_score: int
    sequence_number: int
```

#### Mapper
**File**: `mappers.py`

```python
class AgentMapper:
    @staticmethod
    def from_create_request(request, tenant_id) → Agent
    @staticmethod
    def from_update_request(agent, request) → Agent
    @staticmethod
    def to_dto(agent: Agent) → AgentDTO

class PolicyMapper:
    @staticmethod
    def from_create_request(request, tenant_id) → Policy
    @staticmethod
    def from_update_request(policy, request) → Policy
    @staticmethod
    def to_dto(policy: Policy) → PolicyDTO

class AuditMapper:
    @staticmethod
    def to_dto(entry: AuditEntry) → AuditEntryDTO
```

---

## 6. CORE LAYER (Cross-Cutting Concerns)

**Location**: `/backend/src/core/`

### 6.1 Configuration
**File**: `config.py`

```python
class ProxySettings:
    """Application-wide settings"""
    
    Database:
    - database_url: str
    - pool_size: int
    - max_overflow: int
    
    OPA:
    - opa_url: str (default http://localhost:8181)
    - opa_policy_path: str
    - opa_timeout: int (seconds)
    
    Envoy:
    - envoy_xds_port: int (18000)
    - envoy_management_port: int (9901)
    
    Redis:
    - redis_url: str
    - cache_ttl: int
    
    Security:
    - enable_mtls: bool
    - cert_path: str
    - key_path: str
    - ca_cert_path: str
    
    Environment:
    - environment: str (dev|test|prod)
    - log_level: str (DEBUG|INFO|WARNING|ERROR)
```

### 6.2 Logging
**File**: `logging.py`

```python
def configure_logging(level, structured, environment):
    """Setup structured logging with loguru"""
    
    Features:
    - JSON structured logs (production)
    - Console logs (development)
    - Log rotation and retention
    - Correlation IDs for request tracing
    
    Logger: loguru.logger (used throughout codebase)
```

### 6.3 Dependency Injection Container
**File**: `container.py`

```python
class ServiceRegistry:
    """Registry for services with feature flag support"""
    
    Methods:
    - register_singleton(interface, instance, required_features)
    - register_factory(interface, factory, required_features)
    - get(interface) → T
    - is_registered(interface) → bool
    - get_registered_services() → dict

class DependencyContainer:
    """Main DI container"""
    
    Methods:
    - register_singleton(...)
    - register_factory(...)
    - get(interface) → T
    - health_check() → dict

# Global container management
def get_container() → DependencyContainer
def configure_container(feature_manager) → DependencyContainer
@cache
def get_service(interface) → T
```

### 6.4 Feature Management
**File**: `features.py`

```python
class FeatureManager:
    """Feature flags for gradual rollout and A/B testing"""
    
    Features:
    - OPA integration (policy_evaluation)
    - Envoy xDS (dynamic_proxy_config)
    - WebSocket (real_time_events)
    - Temporal analytics (temporal_queries)
    - Rate limiting (rate_limiting)
    
    Methods:
    - is_enabled(feature_name) → bool
    - enable_feature(feature_name) → None
    - disable_feature(feature_name) → None
    - should_enable_component(component, required_features) → bool
    - get_enabled_features_by_category(category) → dict
```

### 6.5 Database Setup
**File**: `database.py`

```python
class Database:
    """Database initialization and management"""
    
    Methods:
    - create_engine(database_url) → AsyncEngine
    - create_all_tables(engine) → None
    - setup_timescaledb(engine) → None
    - health_check() → bool
    
    Features:
    - SQLAlchemy async support
    - Connection pooling
    - TimescaleDB setup
```

### 6.6 Security Configuration
**File**: `security.py`

```python
class SecurityConfig:
    """Security settings and initialization"""
    
    Features:
    - TLS/mTLS configuration
    - Certificate management
    - Secret key management
    - JWT token handling
    
    Methods:
    - load_certificates() → None
    - validate_certificate(cert) → bool
    - setup_mTLS(app) → None
```

---

## 7. KEY INTEGRATIONS AND DEPENDENCIES

### 7.1 Request Flow Example: Create Agent

```
HTTP POST /api/v1/agents
    ↓
FastAPI Route: create_agent()
    ├─ Validates CreateAgentRequest
    ├─ Extracts tenant_id from header
    ├─ Depends: get_create_agent_command (injected)
    ↓
CreateAgentCommand.execute(request, tenant_id)
    ├─ AgentMapper.from_create_request()
    ├─ AgentService.create_agent()
    │   ├─ Check duplicate name
    │   ├─ Check duplicate certificate
    │   ├─ Validate certificate not expired
    │   ├─ Check tenant agent limits
    │   ├─ Create Agent entity
    │   └─ AgentRepository.save()
    │       ├─ INSERT into agents table
    │       └─ Return saved entity
    ├─ Create AuditEntry (side effect)
    ├─ Publish WebSocket event (agent_created)
    └─ AgentMapper.to_dto()
    ↓
HTTP 201 Created with AgentDTO
```

### 7.2 Request Flow Example: Access Control (ACTUAL IMPLEMENTATION)

**Note:** This reflects the actual MVP implementation, which differs from the original design.

```
Agent makes HTTP request
    ↓
Envoy Proxy receives request (mTLS authentication)
    ↓
Envoy ext_authz filter queries OPA via gRPC (port 9192)
    ├─ Extracts: domain, method, path, agent cert, source IP
    └─ Sends to OPA for policy evaluation
    ↓
OPA evaluates Rego policies
    ├─ Loads policies from /config/policies/
    ├─ Evaluates domain allowlist/blocklist
    ├─ Checks time restrictions
    ├─ Evaluates policy rules
    └─ Returns decision: ALLOW or DENY
    ↓
OPA decision_logs plugin sends decision to ChronoGuard
    ├─ POST /api/v1/internal/opa/decisions
    ├─ Includes: decision, request context, metadata
    └─ Authenticated with CHRONOGUARD_INTERNAL_SECRET
    ↓
ChronoGuard FastAPI receives decision log
    ↓
Create AuditEntry (via AuditService)
    ├─ Extract agent_id, domain, decision from OPA log
    ├─ Record context (method, path, IP, user-agent)
    ├─ Calculate cryptographic hash (chain integrity)
    ├─ Assign sequence number
    └─ PostgreSQL/TimescaleDB insert (via AuditRepository)
    ↓
Return 204 No Content to OPA
    ↓
Meanwhile, Envoy receives OPA decision
    ├─ If ALLOW: forwards request to target domain
    └─ If DENY: returns 403 Forbidden to agent
```

**Key Implementation Details:**

1. **Envoy → OPA Direct:** Policy enforcement happens at proxy layer via ext_authz
2. **OPA → FastAPI Async:** Decision logs sent asynchronously via decision_logs plugin
3. **No Blocking:** Audit logging doesn't block request flow
4. **Static Config:** Envoy uses static configuration from `configs/envoy/envoy.yaml`
5. **OPA Config:** Decision log endpoint configured in `configs/opa/config.yaml`

### 7.3 External Dependencies

**Database**:
- PostgreSQL 13+ (async via asyncpg)
- TimescaleDB extension (time-series optimization)
- Redis (caching, rate limiting)

**Policy Engine**:
- Open Policy Agent (OPA)
- Port 8181 (REST API)
- Rego policy language

**Proxy**:
- Envoy Proxy
- Port 18000 (xDS gRPC server)
- Port 10000 (proxy listening)
- Port 9901 (admin interface)

**Observability**:
- OpenTelemetry (OTLP exporter)
- Prometheus (metrics scraping)

**HTTP/gRPC**:
- aiohttp (async HTTP client)
- grpcio (gRPC framework)
- asyncio (async runtime)

---

## 8. ARCHITECTURAL PATTERNS SUMMARY

| Pattern | Implementation | Location |
|---------|----------------|----------|
| DDD | Entities, Services, Repositories, Value Objects | `/domain/` |
| Repository | Interface + PostgreSQL impl | `/domain/*/repository.py` + `/infrastructure/persistence/` |
| Service | Domain business logic | `/domain/*/service.py` |
| Command | CQRS mutations | `/application/commands/` |
| Query | CQRS reads | `/application/queries/` |
| DTO | Data transfer objects | `/application/dto/` |
| Mapper | Entity ↔ DTO conversion | `/application/dto/mappers.py` |
| Dependency Injection | FastAPI Depends + custom container | `/presentation/api/dependencies.py` + `/core/container.py` |
| Async | async/await throughout | All layers |
| Type Safety | Pydantic validation + type hints | Throughout |
| Feature Flags | FeatureManager integration | `/core/features.py` |
| Telemetry | OpenTelemetry OTLP | `/infrastructure/observability/` |
| Event Sourcing (partial) | Audit entries as immutable events | `/domain/audit/` |
| Pub/Sub | WebSocket manager | `/presentation/websocket/manager.py` |
| Factory | Dependency container factories | `/core/container.py` |
| Strategy | Multiple repository implementations | `/infrastructure/persistence/` |
| Observer | Event webhooks, audit listeners | WebSocket handlers |

---

## 9. CONCURRENCY & DATA INTEGRITY

### Optimistic Locking
```python
Agent/Policy/AuditEntry:
    version: int

Update Operation:
    WHERE entity_id = ? AND version = ?
    SET ... , version = version + 1
    
ConcurrencyError raised if 0 rows updated
```

### ACID Properties
- PostgreSQL transactions ensure ACID
- Async operations don't compromise consistency
- Repository layer manages sessions

### Chain of Custody (Audit)
```
Entry[n-1].current_hash = SHA256(...)
Entry[n].previous_hash = Entry[n-1].current_hash

Verification:
    FOR each entry:
        calculated = SHA256(entry data + previous_hash)
        assert calculated == entry.current_hash
```

---

## 10. SCALABILITY & PERFORMANCE

### Database Optimization
- **Indexes**: Composite indexes on commonly filtered fields
- **JSONB GIN**: Full-text search on metadata
- **TimescaleDB**: Automatic partitioning for audit entries
- **Compression**: Automatic after 30 days
- **Retention**: Automatic deletion after 1 year

### Caching Strategy
- **Redis**: Policy cache with TTL
- **Agent status**: Cached with automatic invalidation
- **Rate limit counters**: Stored in Redis (per-minute, hour, day)

### Connection Pooling
- SQLAlchemy async session factory
- Singleton repository instances
- Connection reuse across requests

### Async-First Design
- No blocking I/O
- Concurrent request handling
- Non-blocking database operations

---

This architecture provides a solid foundation for a zero-trust proxy with temporal controls, audit logging, and policy-based access management. The layering ensures maintainability, testability, and extensibility while maintaining security and performance.
