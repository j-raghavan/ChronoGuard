# ChronoGuard Security Architecture

**Version**: 1.0
**Last Updated**: 2025-11-08
**Status**: Active

## Overview

This document describes the security architecture and design decisions for ChronoGuard, a zero-trust Agent Identity & Compliance Platform for AI agents with temporal access control.

---

## Security Principles

### 1. Zero Trust

**Principle**: Never trust, always verify

- **Agents are assumed compromised** - No client-side security controls
- **Network is assumed hostile** - All traffic authenticated and encrypted
- **Every request is evaluated** - No implicit trust after initial authentication

**Implementation**:
- mTLS for every connection
- Policy evaluation for every request
- No "remember this device" or session trust
- Server-side enforcement only

### 2. Fail-Closed Security

**Principle**: When in doubt, deny access

- **OPA unavailable** → DENY all requests
- **Policy evaluation error** → DENY request
- **Certificate validation fails** → REJECT connection
- **Database unavailable** → DENY (audit cannot be guaranteed)

**Implementation**:
```yaml
# Envoy ext_authz configuration
failure_mode_allow: false  # Fail-closed
```

### 3. Defense in Depth

**Principle**: Multiple independent security controls

**Layers**:
1. **Network**: Mandatory proxy enforcement
2. **Authentication**: mTLS certificates
3. **Authorization**: OPA policy evaluation
4. **Audit**: Immutable hash-chained logs
5. **Encryption**: TLS 1.3 everywhere

### 4. Least Privilege

**Principle**: Minimal permissions required for operation

- **Agents**: Only proxy access, no admin capabilities
- **Database users**: Read/write separation
- **OPA**: Read-only policy storage
- **Service accounts**: Minimal permissions

---

## Authentication Architecture

### mTLS (Mutual TLS)

**Design Decision**: Use mTLS instead of API keys or passwords

**Rationale**:
- Stronger authentication (cryptographic proof)
- Resistant to credential theft (private key required)
- Standard in microservices architectures
- Enables certificate-based identity

**Flow**:
```
Agent                          Envoy Proxy
  │                                │
  ├──── TLS ClientHello ──────────▶│
  │◀─── TLS ServerHello ───────────│
  │     + Server Certificate       │
  │     + Client Certificate Req   │
  │                                │
  ├──── Client Certificate ────────▶│
  │     + Certificate Verify       │ ◀─── Verify against CA cert
  │                                │      Extract agent_id from CN
  │                                │      Check expiration
  │◀─── TLS Finished ──────────────│
  │                                │
  ├──── HTTP Request ──────────────▶│ ◀─── Authenticated!
```

**Certificate Fields**:
```
Subject: CN=agent-{agent_id}
         OU=ChronoGuard-Agents
         O=YourOrganization
SAN: DNS:agent-{agent_id}.chronoguard.local
     URI:spiffe://chronoguard.local/agent/{agent_id}
Validity: 90 days (recommended)
Key Usage: Digital Signature, Key Encipherment
Extended: TLS Web Client Authentication
```

---

## Authorization Architecture

### Policy Engine (OPA)

**Design Decision**: Use OPA instead of code-based authorization

**Rationale**:
- Declarative policies (easier to audit)
- Policy as code (version controlled)
- Separation of policy from application logic
- Industry-standard tool (CNCF project)

**Policy Evaluation Flow**:
```
Envoy ext_authz Request
    ↓
OPA receives: {
  source: { principal: "agent-id" },
  request: {
    http: {
      host: "example.com",
      method: "GET",
      path: "/api/data"
    }
  }
}
    ↓
OPA evaluates Rego policy:
  1. agent_authenticated: ✓
  2. domain_allowed: Check allowed_domains[]
  3. domain_blocked: Check blocked_domains[]
  4. time_window_valid: Check time restrictions
  5. rate_limit_ok: Check rate limits
    ↓
OPA returns: {
  status: OK (allow) or PERMISSION_DENIED (deny)
}
```

**Policy Isolation**:
- Each tenant has separate policy namespace
- Agents cannot access other tenants' policies
- Policy data loaded from ChronoGuard API
- Policies compiled and deployed by PolicyCompiler

---

## Audit Architecture

### Cryptographic Hash Chain

**Design Decision**: Use SHA-256 hash chaining for audit integrity

**Rationale**:
- Tamper detection without external verification
- Efficient cryptographic operation
- Industry-standard (blockchain-inspired)
- No central authority required

**Hash Chain Algorithm**:
```python
# First entry
Entry[0].previous_hash = ""
Entry[0].current_hash = SHA256(Entry[0].data)

# Subsequent entries
Entry[N].previous_hash = Entry[N-1].current_hash
Entry[N].current_hash = SHA256(Entry[N].data + Entry[N].previous_hash)
```

**Verification Algorithm**:
```python
def verify_chain(entries):
    for i, entry in enumerate(entries):
        if i == 0:
            # First entry
            calculated = SHA256(entry.data)
        else:
            # Verify link to previous
            if entry.previous_hash != entries[i-1].current_hash:
                return False, f"Chain broken at entry {i}"

            calculated = SHA256(entry.data + entry.previous_hash)

        if calculated != entry.current_hash:
            return False, f"Hash mismatch at entry {i}"

    return True, "Chain valid"
```

**Properties**:
- **Append-only**: Cannot insert entries without breaking chain
- **Tamper-evident**: Modifying entry invalidates all subsequent entries
- **Verifiable**: Can verify entire chain independently
- **Efficient**: O(n) verification time

**Optional Enhancement**:
- HMAC-SHA256 with secret key for authentication
- RSA/ECDSA signatures for non-repudiation

---

## Data Protection

### Encryption at Rest

**Current**: Database encryption not enforced in MVP

**Recommendation** for production:
```yaml
# PostgreSQL with encryption
POSTGRES_INITDB_ARGS: "-E UTF8 --data-checksums"
# + dm-crypt/LUKS at volume level
# or
# + PostgreSQL transparent data encryption (TDE)
```

### Encryption in Transit

**Implemented**:
- Agent → Envoy: TLS 1.3 with mTLS
- Envoy → OPA: gRPC (internal, can add TLS)
- OPA → FastAPI: HTTPS with Bearer token
- FastAPI → PostgreSQL: TLS (configurable)
- Dashboard → FastAPI: HTTPS

**Configuration**:
```python
# Enforce TLS for database
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db?ssl=require
```

### Data Minimization

**Principle**: Collect only necessary data

**What We Log**:
- Agent ID (identity, required for access control)
- Domain (accessed resource, required for policy)
- Decision (allow/deny, required for compliance)
- Timestamp (when, required for temporal analysis)
- Request metadata (method, path, IP - minimal)

**What We DON'T Log**:
- Request/response bodies (privacy)
- Authentication tokens (security)
- Query parameters (may contain PII)
- Full URLs (may expose sensitive paths)

---

## Secret Management

### Secrets in MVP

| Secret | Purpose | Storage | Rotation |
|--------|---------|---------|----------|
| DB_PASSWORD | PostgreSQL auth | .env file | Manual |
| SECRET_KEY | FastAPI session | .env file | Manual |
| CHRONOGUARD_INTERNAL_SECRET | OPA→API auth | .env file | Manual |
| AUDIT_SECRET_KEY | HMAC for hash chain | .env file | Manual |
| Agent Private Keys | mTLS auth | Agent filesystem | 90 days |

### Production Recommendations

**Use External Secret Management**:
```yaml
# Kubernetes Secrets (better than .env)
apiVersion: v1
kind: Secret
metadata:
  name: chronoguard-secrets
type: Opaque
data:
  db-password: <base64>
  api-secret-key: <base64>

# Or use:
# - HashiCorp Vault
# - AWS Secrets Manager
# - Azure Key Vault
# - Google Secret Manager
```

**Secret Rotation**:
- Database passwords: 90 days
- API keys: 30 days
- Agent certificates: 90 days
- HMAC keys: 180 days (coordinate with audit retention)

---

## Access Control

### Role-Based Access (Future)

**Planned Roles**:
```
Admin (Full Control):
├─ Create/update/delete agents
├─ Create/update/delete policies
├─ Access all audit logs
└─ Manage users

Operator (Day-to-day):
├─ Create/update agents
├─ View policies (no delete)
├─ Access audit logs (own tenant)
└─ No user management

Auditor (Read-only):
├─ View agents (no changes)
├─ View policies (no changes)
├─ Access audit logs (all)
└─ Export audit reports

Agent (Proxy Only):
├─ Proxy traffic only
└─ No API access
```

**Current MVP**: No RBAC, all authenticated users have admin access

---

## Network Security

### Network Segmentation

**Recommended Deployment**:
```
┌─────────────────────────────────────────┐
│  UNTRUSTED ZONE (Agent Network)         │
│  - Agent hosts                          │
│  - Can only reach: Proxy (8080)         │
│  - Cannot reach: Internet directly      │
└────────────┬────────────────────────────┘
             │ mTLS
             ↓
┌─────────────────────────────────────────┐
│  DMZ (Proxy Zone)                       │
│  - Envoy Proxy (8080)                   │
│  - Firewall: Allow 8080 from agents     │
└────────────┬────────────────────────────┘
             │ Internal
             ↓
┌─────────────────────────────────────────┐
│  TRUSTED ZONE (Backend Services)        │
│  - FastAPI, OPA, PostgreSQL, Redis      │
│  - Private network, no internet access  │
│  - Firewall: Only from DMZ              │
└─────────────────────────────────────────┘
```

### Firewall Rules

**Agent Network**:
```bash
# Allow outbound to proxy only
iptables -A OUTPUT -p tcp --dport 8080 -d proxy.internal -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j DROP  # Block direct HTTPS
iptables -A OUTPUT -p tcp --dport 80 -j DROP   # Block direct HTTP
```

**Proxy Zone**:
```bash
# Allow inbound from agents
iptables -A INPUT -p tcp --dport 8080 -s agent-network -j ACCEPT
# Allow outbound to internet
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
```

---

## Security Headers

### API Responses

**Implemented**:
```python
# CORS Middleware
Access-Control-Allow-Origin: https://dashboard.chronoguard.local
Access-Control-Allow-Credentials: true

# Security Headers
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Proxy Responses

**Envoy Configuration**:
```yaml
response_headers_to_add:
  - header:
      key: X-ChronoGuard-Decision
      value: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:decision)%"
  - header:
      key: Strict-Transport-Security
      value: max-age=31536000
```

---

## Vulnerability Management

### Dependency Scanning

**Tools**:
```bash
# Python dependencies
poetry audit

# Docker base images
docker scan chronoguard-api:latest

# SAST (Static Application Security Testing)
bandit -r backend/src/
```

**Frequency**: Weekly automated scans

### Security Updates

**Process**:
1. Monitor GitHub security advisories
2. Review CVEs for dependencies
3. Test updates in staging
4. Deploy to production
5. Notify users of critical updates

**SLA**:
- Critical vulnerabilities: 48 hours
- High vulnerabilities: 7 days
- Medium vulnerabilities: 30 days

---

## Compliance Controls

### SOC 2 Controls

**CC6 - Logical and Physical Access Controls**:
- ✅ CC6.1: mTLS authentication for all agents
- ✅ CC6.2: Access policies with temporal restrictions
- ✅ CC6.6: Comprehensive audit logging
- ⚠️ CC6.7: User access revocation (certificate revocation - partial)

**CC7 - System Operations**:
- ✅ CC7.2: System monitoring (health checks, metrics)
- ✅ CC7.3: Data backup and recovery (database backups)
- ⚠️ CC7.4: Change management (policy versioning - partial)

**CC8 - Change Management**:
- ✅ CC8.1: Change authorization (policy approval via API)
- ⚠️ CC8.2: Change testing (policy testing - manual)

### HIPAA Controls

**§164.308(a)(1)(ii)(D) - Information System Activity Review**:
- ✅ Comprehensive audit logs
- ✅ Hash chain integrity verification
- ✅ Tamper-evident log storage

**§164.308(a)(3)(ii)(B) - Workforce Clearance**:
- ⚠️ Access control to audit logs (partial - no RBAC in MVP)

**§164.312(a)(2)(i) - Unique User Identification**:
- ✅ Unique agent certificates
- ✅ Certificate-based identity

**§164.312(b) - Audit Controls**:
- ✅ Record and examine activity
- ✅ Cryptographic integrity

**§164.312(c)(1) - Integrity Controls**:
- ✅ Hash-chained audit trail
- ✅ Tamper detection

**§164.312(e)(1) - Transmission Security**:
- ✅ TLS encryption for all transmission
- ✅ mTLS for mutual authentication

---

## Cryptographic Standards

### Algorithms

**Approved Algorithms**:
- **Symmetric**: AES-256-GCM
- **Asymmetric**: RSA-2048 or ECDSA P-256
- **Hashing**: SHA-256
- **MAC**: HMAC-SHA256
- **TLS**: TLS 1.3 only (TLS 1.2 minimum)

**Prohibited Algorithms**:
- ❌ MD5 (broken)
- ❌ SHA-1 (collision attacks)
- ❌ DES/3DES (weak)
- ❌ RSA-1024 (insufficient key length)
- ❌ RC4 (broken)

### Key Management

**Certificate Generation**:
```bash
# Agent certificate (RSA-2048, 90-day validity)
openssl req -new -x509 \
  -key agent-key.pem \
  -out agent-cert.pem \
  -days 90 \
  -subj "/CN=agent-{id}/OU=ChronoGuard-Agents/O=YourOrg"

# Or use ECDSA P-256 (smaller, faster)
openssl ecparam -name prime256v1 -genkey -out agent-key.pem
```

**Key Storage**:
- **Development**: Filesystem with 0600 permissions
- **Production**: HSM, KMS, or encrypted storage
- **Rotation**: Automated with 30-day overlap

---

## Audit Security

### Immutability

**Design Decision**: Use hash chaining instead of append-only storage

**Implementation**:
```sql
-- TimescaleDB hypertable (time-series optimized)
CREATE TABLE audit_entries (
    entry_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    -- ... other fields ...
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    sequence_number BIGINT NOT NULL
);

-- Partition by time (7-day chunks)
SELECT create_hypertable('audit_entries', 'timestamp');

-- Retention policy (1 year)
SELECT add_retention_policy('audit_entries', INTERVAL '1 year');
```

**Immutability Enforcement**:
- No UPDATE or DELETE operations on audit_entries
- INSERT-only table
- Triggers reject modifications (future enhancement)
- Hash chain detects any tampering

### Integrity Verification

**Regular Verification** (recommended daily):
```bash
# Verify complete chain for tenant
python -c "
from audit_service import verify_chain_integrity
result = verify_chain_integrity(tenant_id='...', start_date='2025-01-01')
print(f'Valid: {result.is_valid}')
print(f'Integrity Score: {result.integrity_score}')
print(f'Violations: {len(result.violations)}')
"
```

**Alerting**:
- Alert on integrity score < 1.0
- Alert on verification failures
- Alert on sequence number gaps

---

## Secure Development Practices

### Input Validation

**All user inputs validated**:
```python
# Example: Domain name validation
class DomainName(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        # Prevent injection attacks
        if not re.match(r'^[a-zA-Z0-9.-]+$', v):
            raise ValidationError("Invalid domain name")

        # Prevent subdomain wildcards in certain contexts
        if v.count('*') > 1:
            raise ValidationError("Multiple wildcards not allowed")

        return v.lower()
```

### SQL Injection Prevention

**Use parameterized queries only**:
```python
# ✅ GOOD - Parameterized query
stmt = select(Agent).where(Agent.agent_id == agent_id)

# ❌ BAD - String concatenation
query = f"SELECT * FROM agents WHERE agent_id = '{agent_id}'"
```

**ORM Usage**:
- SQLAlchemy with parameterized queries
- No raw SQL strings
- Validate all filter parameters

### Command Injection Prevention

**No shell execution**:
```python
# ❌ AVOID
os.system(f"openssl verify {cert_path}")

# ✅ PREFERRED
subprocess.run(["openssl", "verify", cert_path], check=True)
```

### XSS Prevention

**API returns JSON only** (not HTML)
- Content-Type: application/json
- X-Content-Type-Options: nosniff
- No user-generated HTML rendering

**Dashboard**:
- React with automatic XSS protection
- DOMPurify for any HTML rendering
- CSP headers (future enhancement)

---

## Logging and Monitoring

### Secure Logging

**What to Log**:
- ✅ Authentication attempts (success/failure)
- ✅ Authorization decisions
- ✅ Policy changes
- ✅ Administrative actions
- ✅ Error conditions

**What NOT to Log**:
- ❌ Passwords or secrets
- ❌ Full certificate content
- ❌ Request/response bodies (may contain PII)
- ❌ Database connection strings

**Log Sanitization**:
```python
# Example: Sanitize before logging
logger.info(
    "Agent authenticated",
    agent_id=str(agent_id),
    # Don't log: certificate content, private keys
)
```

### Security Monitoring

**Key Metrics**:
```
# Authentication failures
chronoguard_auth_failures_total{reason="expired_cert"}
chronoguard_auth_failures_total{reason="invalid_cert"}

# Authorization denials
chronoguard_authz_denials_total{reason="domain_blocked"}
chronoguard_authz_denials_total{reason="time_restricted"}

# Audit integrity
chronoguard_audit_chain_integrity_score{tenant_id}
chronoguard_audit_verification_failures_total
```

**Alerting Rules**:
- Auth failure rate > 10/minute → Alert
- Audit integrity score < 1.0 → Critical Alert
- Policy evaluation errors > 1% → Alert
- Certificate expiration < 7 days → Warning

---

## Deployment Security

### Docker Security

**Base Image Security**:
```dockerfile
# Use official, minimal images
FROM python:3.11-slim

# Run as non-root
RUN adduser --disabled-password --gecos '' chronoguard
USER chronoguard

# Read-only root filesystem
docker run --read-only --tmpfs /tmp chronoguard-api
```

**Container Scanning**:
```bash
# Scan for vulnerabilities
docker scan chronoguard-api:latest
trivy image chronoguard-api:latest
```

### Kubernetes Security

**Pod Security Standards** (recommended):
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: chronoguard-api
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: api
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: chronoguard-api
spec:
  podSelector:
    matchLabels:
      app: chronoguard-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: chronoguard-proxy
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
  - to:
    - podSelector:
        matchLabels:
          app: redis
```

---

## Security Checklist

### Pre-Deployment

- [ ] All default secrets changed
- [ ] TLS certificates from trusted CA
- [ ] Database encryption at rest enabled
- [ ] Network policies configured
- [ ] Security headers enabled
- [ ] Debug mode disabled
- [ ] Secrets not in git/logs
- [ ] Vulnerability scan clean

### Post-Deployment

- [ ] Monitoring and alerting configured
- [ ] Log aggregation working
- [ ] Backup and recovery tested
- [ ] Incident response plan ready
- [ ] Security contacts documented
- [ ] Penetration test scheduled

### Ongoing

- [ ] Weekly dependency scans
- [ ] Monthly security reviews
- [ ] Quarterly penetration tests
- [ ] Annual threat model update
- [ ] Certificate rotation automated
- [ ] Audit log integrity verified daily

---

## References

- [OWASP Application Security](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [CNCF Security Best Practices](https://www.cncf.io/blog/2019/11/12/top-10-cloud-native-security-best-practices/)

---

**Document Owner**: Security Team
**Review Frequency**: Quarterly
**Next Review**: 2025-02-08
