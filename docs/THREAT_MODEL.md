# ChronoGuard Threat Model

**Version**: 1.0
**Last Updated**: 2025-11-08
**Status**: Active

## Executive Summary

ChronoGuard is a zero-trust forward proxy for browser automation agents with temporal access control and comprehensive audit logging. This document identifies potential threats, attack vectors, and mitigation strategies.

---

## System Overview

### Components

1. **Envoy Forward Proxy** - mTLS termination, traffic forwarding
2. **OPA Policy Engine** - Policy evaluation, decision logging
3. **FastAPI Backend** - Management API, audit ingestion
4. **PostgreSQL + TimescaleDB** - Persistent storage, audit logs
5. **Redis** - Caching, rate limiting
6. **React Dashboard** - Administrative interface

### Trust Boundaries

```
UNTRUSTED                    TRUSTED                    UNTRUSTED
┌────────────┐         ┌──────────────────┐         ┌──────────┐
│   Agent    │────────▶│  ChronoGuard     │────────▶│ Internet │
│  (mTLS)    │         │  (Proxy + Policy)│         │          │
└────────────┘         └──────────────────┘         └──────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │  Audit Trail │
                       │  (Protected) │
                       └──────────────┘
```

**Key Assumption**: Agents are compromised / untrusted (zero-trust model)

---

## Assets and Security Objectives

### Assets

| Asset | Confidentiality | Integrity | Availability | Impact if Compromised |
|-------|----------------|-----------|--------------|----------------------|
| Agent Certificates | HIGH | CRITICAL | MEDIUM | Identity theft, unauthorized access |
| Access Policies | MEDIUM | CRITICAL | HIGH | Policy bypass, unauthorized access |
| Audit Logs | LOW | CRITICAL | HIGH | Compliance violations, lost evidence |
| Agent Traffic | HIGH | MEDIUM | HIGH | Data exposure, privacy violations |
| Admin Credentials | CRITICAL | CRITICAL | MEDIUM | Complete system compromise |

### Security Objectives

1. **Authentication**: Only valid mTLS certificates can access proxy
2. **Authorization**: All requests evaluated against current policies
3. **Audit**: Complete tamper-proof audit trail of all access attempts
4. **Confidentiality**: Agent traffic not logged or exposed
5. **Availability**: Fail-closed if policy engine unavailable

---

## Threat Analysis (STRIDE)

### 1. Spoofing (Identity Threats)

#### T1.1: Agent Certificate Theft

**Description**: Attacker steals agent's private key and certificate
**Likelihood**: MEDIUM
**Impact**: HIGH
**Attack Vector**: Filesystem access on agent host, memory dump, backup exposure

**Mitigations**:
- Certificate rotation policy (recommended: 90 days)
- Certificate fingerprint tracking (detect duplicate use)
- Audit trail shows unusual access patterns
- Certificate revocation capability

**Residual Risk**: MEDIUM - Agent hosts are assumed compromised

#### T1.2: Certificate Authority Compromise

**Description**: Attacker compromises CA to issue rogue certificates
**Likelihood**: LOW
**Impact**: CRITICAL
**Attack Vector**: CA private key theft, CA system compromise

**Mitigations**:
- Use reputable CA or properly secured internal CA
- Certificate Transparency logging
- Short certificate validity periods
- Monitor for unexpected certificate issuance

**Residual Risk**: LOW

#### T1.3: Man-in-the-Middle on Proxy Connection

**Description**: Attacker intercepts agent→proxy communication
**Likelihood**: LOW
**Impact**: HIGH
**Attack Vector**: Network interception, ARP poisoning, DNS hijacking

**Mitigations**:
- mTLS prevents MITM (mutual authentication)
- Certificate pinning (optional)
- Network segmentation
- TLS 1.3 minimum version

**Residual Risk**: LOW

---

### 2. Tampering (Data Integrity Threats)

#### T2.1: Audit Log Tampering

**Description**: Attacker modifies audit entries to hide activity
**Likelihood**: MEDIUM
**Impact**: CRITICAL
**Attack Vector**: Direct database access, SQL injection, backup modification

**Mitigations**:
- Cryptographic hash chaining (SHA-256)
- HMAC with secret key
- Immutable TimescaleDB hypertables
- Regular chain integrity verification
- Database access controls

**Residual Risk**: LOW

#### T2.2: Policy Manipulation

**Description**: Attacker modifies policies to grant unauthorized access
**Likelihood**: MEDIUM
**Impact**: CRITICAL
**Attack Vector**: Admin credential theft, API vulnerability, database access

**Mitigations**:
- Admin authentication (API keys, JWT)
- Policy version control
- Audit trail of policy changes
- Policy validation before deployment
- Read-only policy storage in OPA

**Residual Risk**: MEDIUM

#### T2.3: Time Manipulation

**Description**: Attacker manipulates system time to bypass temporal restrictions
**Likelihood**: LOW
**Impact**: HIGH
**Attack Vector**: NTP spoofing, system clock modification

**Mitigations**:
- Server-side timestamps only
- NTP synchronization with trusted sources
- Timestamp validation (reject future timestamps)
- Audit log sequence numbers

**Residual Risk**: LOW

---

### 3. Repudiation (Non-Repudiation Threats)

#### T3.1: Denial of Access Attempt

**Description**: Agent denies making access request
**Likelihood**: MEDIUM
**Impact**: MEDIUM
**Attack Vector**: Claim certificate was stolen, dispute logs

**Mitigations**:
- Immutable audit trail with timestamps
- Hash chain prevents backdating
- mTLS binds request to certificate
- Cryptographic signatures (optional)

**Residual Risk**: LOW

#### T3.2: Policy Change Denial

**Description**: Admin denies making policy change
**Likelihood**: LOW
**Impact**: MEDIUM
**Attack Vector**: Shared credentials, insider threat

**Mitigations**:
- Audit trail of policy CRUD operations
- User attribution in audit logs
- Policy version history
- Change approval workflow (future)

**Residual Risk**: MEDIUM - Audit of policy changes partially implemented

---

### 4. Information Disclosure (Confidentiality Threats)

#### T4.1: Audit Log Information Leakage

**Description**: Audit logs expose sensitive information
**Likelihood**: LOW
**Impact**: MEDIUM
**Attack Vector**: Database breach, log file exposure, backup theft

**Mitigations**:
- Minimal PII in audit logs
- Database encryption at rest (optional)
- Access controls on audit query endpoints
- Log retention policies

**Residual Risk**: LOW

#### T4.2: Policy Information Disclosure

**Description**: Policies reveal business logic or security posture
**Likelihood**: LOW
**Impact**: LOW
**Attack Vector**: Unauthorized API access, OPA endpoint exposure

**Mitigations**:
- Admin authentication on policy endpoints
- OPA internal-only (not exposed to internet)
- Policy data access controls

**Residual Risk**: LOW

#### T4.3: Traffic Content Exposure

**Description**: Proxy logs or exposes agent traffic content
**Likelihood**: LOW
**Impact**: HIGH
**Attack Vector**: Debug logging, traffic inspection, memory dumps

**Mitigations**:
- Envoy configured for forwarding only (no content logging)
- No request/response body inspection in MVP
- Disable debug logging in production
- Memory is not persisted

**Residual Risk**: LOW

---

### 5. Denial of Service (Availability Threats)

#### T5.1: Resource Exhaustion via Audit Log Flooding

**Description**: Attacker floods system with requests to fill disk
**Likelihood**: MEDIUM
**Impact**: MEDIUM
**Attack Vector**: Rapid requests from compromised agent

**Mitigations**:
- Rate limiting on agent requests
- Audit log retention policies (1 year)
- TimescaleDB compression (automatic)
- Disk space monitoring and alerts

**Residual Risk**: MEDIUM

#### T5.2: OPA Policy Engine Overload

**Description**: Complex policies cause evaluation slowdown
**Likelihood**: LOW
**Impact**: MEDIUM
**Attack Vector**: Malicious policy upload, policy complexity

**Mitigations**:
- Policy complexity limits
- OPA caching of evaluation results
- Timeout on policy evaluation (1s)
- OPA horizontal scaling capability

**Residual Risk**: LOW

#### T5.3: Database Connection Exhaustion

**Description**: Too many concurrent requests exhaust DB connections
**Likelihood**: LOW
**Impact**: HIGH
**Attack Vector**: Request flood, connection leak

**Mitigations**:
- Connection pooling (asyncpg)
- Connection limits and timeouts
- Circuit breakers on DB calls
- Asynchronous processing (non-blocking)

**Residual Risk**: LOW

---

### 6. Elevation of Privilege (Authorization Threats)

#### T6.1: Agent Accesses Unauthorized Domains

**Description**: Agent bypasses domain restrictions
**Likelihood**: MEDIUM
**Impact**: HIGH
**Attack Vector**: Policy misconfiguration, OPA bypass, Envoy bypass

**Mitigations**:
- Fail-closed design (default DENY)
- Policy validation before deployment
- Envoy as mandatory proxy (network enforcement)
- Regular policy audits

**Residual Risk**: LOW

#### T6.2: Agent Accesses During Restricted Times

**Description**: Agent bypasses temporal restrictions
**Likelihood**: MEDIUM
**Impact**: MEDIUM
**Attack Vector**: Time manipulation, policy misconfiguration

**Mitigations**:
- Server-side time only (no client trust)
- NTP synchronization
- Time validation in OPA policies
- Audit timestamps

**Residual Risk**: LOW

#### T6.3: Admin Privilege Escalation

**Description**: Low-privilege user gains admin access
**Likelihood**: LOW
**Impact**: CRITICAL
**Attack Vector**: API vulnerability, JWT manipulation, session hijacking

**Mitigations**:
- Role-based access control (future)
- JWT validation with signature
- Session management
- Audit trail of admin actions

**Residual Risk**: MEDIUM - Full RBAC not implemented in MVP

---

## Attack Scenarios

### Scenario 1: Compromised Agent Attempts Unauthorized Access

**Attack Flow**:
1. Attacker compromises agent host
2. Attacker modifies agent code to access unauthorized domain
3. Agent attempts to connect to blocked domain

**ChronoGuard Response**:
1. Envoy verifies mTLS certificate (succeeds - valid cert)
2. Envoy ext_authz → OPA policy evaluation
3. OPA checks domain against policy (domain NOT in allowed_domains)
4. OPA returns DENY decision
5. Envoy blocks request with 403
6. OPA logs decision → FastAPI → Audit trail
7. Admin alerted to suspicious activity

**Outcome**: Attack blocked, fully audited ✅

---

### Scenario 2: Audit Log Tampering Attempt

**Attack Flow**:
1. Attacker gains database access
2. Attacker modifies audit entry to hide activity
3. Attacker changes `current_hash` to match modification

**ChronoGuard Response**:
1. Next audit entry creation attempts to link chain
2. `previous_hash` (from attacker's entry) ≠ actual hash of modified entry
3. Chain verification detects integrity violation
4. Alert triggered for audit tampering
5. Investigation initiated

**Outcome**: Tampering detected via hash chain ✅

---

### Scenario 3: Time Restriction Bypass Attempt

**Attack Flow**:
1. Agent has time restriction (Monday-Friday, 9am-5pm)
2. Attacker attempts access Saturday 2am
3. Attacker manipulates local system time on agent

**ChronoGuard Response**:
1. Envoy receives request (client time ignored)
2. OPA evaluates with server-side timestamp
3. OPA checks: current time = Saturday 2am (server NTP)
4. Time restriction policy: deny (weekend + off-hours)
5. Request blocked with 403
6. Audit trail shows temporal violation

**Outcome**: Time bypass prevented, server-side enforcement ✅

---

### Scenario 4: Policy Bypass via Direct Internet Access

**Attack Flow**:
1. Attacker compromises agent
2. Attacker configures agent to bypass proxy
3. Agent connects directly to internet

**ChronoGuard Response**:
- **Network-level enforcement required** (firewall rules)
- Agent network must block direct internet access
- Only proxy egress allowed

**Outcome**: Depends on network configuration ⚠️

**Recommendation**: Deploy with network policies blocking direct internet access

---

## Mitigations Summary

### Implemented Controls

| Control | Type | Coverage | Effectiveness |
|---------|------|----------|---------------|
| mTLS Authentication | Preventive | Authentication | HIGH |
| OPA Policy Engine | Preventive | Authorization | HIGH |
| Hash-Chained Audit | Detective | Integrity | HIGH |
| Fail-Closed Design | Preventive | Availability | HIGH |
| Server-Side Time | Preventive | Time Bypass | HIGH |
| Certificate Validation | Preventive | Identity | HIGH |

### Recommended Additional Controls

| Control | Priority | Benefit | Implementation Complexity |
|---------|----------|---------|--------------------------|
| Network Policies (K8s) | HIGH | Prevent proxy bypass | LOW |
| Certificate Rotation Automation | HIGH | Limit cert theft impact | MEDIUM |
| SPIFFE/SPIRE Integration | MEDIUM | Better identity management | HIGH |
| Audit Encryption at Rest | MEDIUM | Protect audit confidentiality | LOW |
| Policy Approval Workflow | MEDIUM | Prevent accidental changes | MEDIUM |
| SIEM Integration | LOW | Better threat detection | MEDIUM |

---

## Compliance Considerations

### SOC 2

- **CC6.1** (Logical Access): mTLS authentication implemented
- **CC6.6** (Audit Logging): Comprehensive audit trail with integrity
- **CC7.2** (System Monitoring): Health checks, metrics endpoints
- **CC8.1** (Change Management): Policy versioning (partial)

### GDPR

- **Article 32** (Security): Encryption in transit, access controls
- **Article 30** (Records**: Audit logs document processing activities
- **Article 25** (Data Protection by Design): Minimal data collection

### HIPAA

- **§164.312(a)(1)** (Access Control): mTLS + policy-based access
- **§164.312(b)** (Audit Controls): Immutable audit logs
- **§164.312(c)(1)** (Integrity): Hash-chained audit trail
- **§164.312(e)(1)** (Transmission Security): TLS encryption

---

## Threat Prioritization

### Critical Threats

1. **Admin Credential Compromise** → Complete system control
2. **CA Compromise** → Rogue certificate issuance
3. **Audit Log Tampering** → Evidence destruction

### High Threats

4. **Agent Certificate Theft** → Unauthorized access until revoked
5. **Policy Bypass** → Access control failure
6. **Time Manipulation** → Temporal restriction bypass

### Medium Threats

7. **DoS via Log Flooding** → Service degradation
8. **Policy Information Disclosure** → Security posture exposure

### Low Threats

9. **Traffic Content Disclosure** → Privacy concern (mitigated by design)
10. **Session Hijacking** → Dashboard access (low value)

---

## Security Testing Recommendations

### Penetration Testing Focus Areas

1. **mTLS Authentication Bypass**: Test certificate validation edge cases
2. **Policy Bypass**: Attempt domain/time restrictions circumvention
3. **Audit Tampering**: Test hash chain integrity under attack
4. **Time Bypass**: Test time manipulation resistance
5. **DoS Resilience**: Load testing, resource exhaustion

### Security Test Cases

```bash
# Test 1: Reject invalid certificate
curl --cert invalid.pem --key invalid-key.pem https://proxy:8080/example.com
# Expected: TLS handshake failure

# Test 2: Reject expired certificate
curl --cert expired.pem --key expired-key.pem https://proxy:8080/example.com
# Expected: 403 Forbidden (certificate expired)

# Test 3: Block unauthorized domain
curl --cert agent.pem --key agent-key.pem https://proxy:8080/blocked.com
# Expected: 403 Forbidden (domain not allowed)

# Test 4: Block off-hours access
# Set time to 11 PM
curl --cert agent.pem --key agent-key.pem https://proxy:8080/example.com
# Expected: 403 Forbidden (outside allowed hours)

# Test 5: Verify audit trail integrity
python scripts/verify-audit-chain.py --tenant-id <uuid>
# Expected: Chain valid: True, no integrity violations
```

---

## Incident Response

### Detection

**Indicators of Compromise (IOCs)**:
- Multiple failed mTLS handshakes (brute force)
- Policy evaluation failures spike
- Audit chain integrity violations
- Unusual access patterns (off-hours, new domains)
- Certificate fingerprint duplicates

**Monitoring**:
- Prometheus alerts on failure rates
- Audit chain verification (daily)
- Certificate expiration monitoring
- Policy evaluation latency

### Response Procedures

**Severity 1 - Critical (Admin Compromise, CA Compromise)**:
1. Isolate affected systems immediately
2. Revoke all agent certificates
3. Rotate all secrets (DB passwords, API keys)
4. Verify audit log integrity
5. Investigate root cause
6. Issue security advisory

**Severity 2 - High (Agent Certificate Theft)**:
1. Revoke compromised certificate
2. Issue new certificate to agent
3. Review audit logs for unauthorized access
4. Investigate how certificate was stolen
5. Update certificate rotation policy if needed

**Severity 3 - Medium (Audit Anomaly)**:
1. Verify hash chain integrity
2. Identify source of anomaly
3. Restore from backup if needed
4. Fix underlying issue

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-08 | Initial threat model for MVP v0.1.0 |

---

**Document Owner**: Security Team
**Review Frequency**: Quarterly
**Next Review**: 2025-02-08
