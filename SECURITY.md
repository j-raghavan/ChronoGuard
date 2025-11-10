# Security Policy

## Threat Model

ChronoGuard operates as a mandatory forward proxy for browser automation, providing zero-trust access control and comprehensive audit logging.

### Assets Protected

- **Browser automation traffic** - Sensitive corporate data accessed by automated agents
- **Temporal access control policies** - Business logic defining when/where agents can access resources
- **Audit trails** - Compliance evidence with cryptographic integrity
- **Agent certificates** - Identity credentials for mTLS authentication

### Trust Boundaries

1. **Agent ↔ ChronoGuard Proxy**: mTLS authentication required, zero-trust enforcement
2. **ChronoGuard ↔ Internet**: All traffic filtered based on OPA policies
3. **ChronoGuard ↔ Management API**: Admin authentication required for policy management
4. **OPA ↔ FastAPI**: Internal Bearer token authentication for decision logs

### Attack Vectors Mitigated

- **Proxy Bypass**: Network-level enforcement, no agent-side controls that can be circumvented
- **Time Manipulation**: Server-side timestamps only, NTP synchronization with tamper detection
- **Policy Bypass**: Fail-closed design - default DENY if OPA unavailable or policy evaluation fails
- **Audit Tampering**: Hash-chained audit logs with cryptographic verification, immutable TimescaleDB storage

### Assumptions

- Network infrastructure is trusted (Kubernetes, VPC, internal network)
- Certificate authorities are trusted (proper CA validation)
- Time sources (NTP) are trusted
- **Agent hosts are compromised** (zero-trust assumption - agents are not trusted)

---

## Vulnerability Reporting

### Security Contact

**Email**: [Create GitHub Security Advisory](https://github.com/j-raghavan/ChronoGuard/security/advisories/new)

For sensitive security issues, please use GitHub Security Advisories for private disclosure.

### Disclosure Process

1. **Private Report**: Create a GitHub Security Advisory with full details
2. **Acknowledgment**: Maintainers will respond within **48 hours**
3. **Investigation**: Initial assessment within **7 days**
4. **Fix Development**: Work on patch with reporter collaboration
5. **Coordinated Disclosure**: Public disclosure after fix is released and users have time to upgrade

### Response Timeline

- **Critical vulnerabilities** (authentication bypass, RCE): 24-48 hours
- **High severity** (policy bypass, audit tampering): 7 days
- **Medium severity** (DoS, information disclosure): 30 days
- **Low severity** (minor issues): 90 days

---

## Scope

### In Scope

Security issues in the following areas are considered in scope:

- Authentication bypass vulnerabilities (mTLS, API tokens)
- Authorization bypass (policy enforcement, OPA evaluation)
- Audit log tampering or deletion
- Time-based access control bypass
- Certificate validation bypass
- SQL injection or command injection
- Privilege escalation
- Information disclosure (sensitive data leakage)
- Cryptographic weaknesses in hash chaining

### Out of Scope

The following are NOT considered security vulnerabilities:

- Social engineering attacks against users
- Physical access attacks on infrastructure
- Attacks requiring admin access to ChronoGuard infrastructure
- Issues in third-party dependencies (report to upstream projects)
- Theoretical attacks without proof of concept
- Denial of service requiring massive resources
- Issues already reported and known

---

## Security Advisories

Security advisories will be published at:

- **GitHub Security Advisories**: https://github.com/j-raghavan/ChronoGuard/security/advisories
- **Releases Page**: Security fixes noted in CHANGELOG.md
- **Documentation**: `security/security-advisories/` directory

Subscribers to the repository will be notified of security advisories automatically.

---

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Notes                    |
| ------- | ------------------ | ------------------------ |
| 1.x.x   | :white_check_mark: | Current stable release   |
| 0.2.x   | :white_check_mark: | Previous minor version   |
| 0.1.x   | :x:                | MVP - upgrade recommended |
| < 0.1   | :x:                | Development versions     |

**Recommendation**: Always run the latest stable release for security updates.

---

## Security Architecture

### Defense in Depth

ChronoGuard implements multiple layers of security:

1. **Network Level**: Mandatory proxy, no direct internet access for agents
2. **Authentication**: mTLS client certificates for all agents (mutual authentication)
3. **Authorization**: OPA policy engine with temporal and domain-based rules
4. **Audit**: Cryptographic hash-chained audit trail (tamper detection)
5. **Encryption**: TLS for all network communication
6. **Isolation**: Multi-tenancy with database-level isolation

### Security Features

- **mTLS Authentication**: Mutual TLS for agent identity verification
- **Policy-Based Access Control**: OPA Rego policies for fine-grained authorization
- **Temporal Restrictions**: Time-window and day-of-week access controls
- **Immutable Audit Logs**: Cryptographic hash chaining prevents tampering
- **Fail-Closed Design**: Default DENY when policy engine unavailable
- **Zero-Trust Model**: Agents are never trusted, every request is evaluated

### Certificate Management

- **Agent Certificates**: Unique X.509 certificates per agent
- **Certificate Rotation**: Supports certificate updates without downtime
- **Expiration Checking**: Automatic rejection of expired certificates
- **Fingerprint Validation**: Certificate fingerprints stored and validated

### Cryptographic Hash Chain

Audit entries use SHA-256 hash chaining:
```
Entry[N].previous_hash = SHA256(Entry[N-1])
Entry[N].current_hash = SHA256(Entry[N].data + Entry[N].previous_hash)
```

Optional HMAC-SHA256 with secret key for additional authentication.

---

## Security Best Practices

### For Operators

1. **Certificate Management**:
   - Rotate agent certificates at least annually
   - Use proper CA for production (not self-signed)
   - Store private keys securely (HSM/KMS recommended)

2. **Policy Management**:
   - Review policies regularly for overly permissive rules
   - Use version control for policy changes
   - Test policies in staging before production

3. **Monitoring**:
   - Monitor for unusual access patterns
   - Set up alerts for policy evaluation failures
   - Review audit logs regularly
   - Monitor hash chain integrity

4. **Configuration**:
   - Change all default secrets (DB_PASSWORD, SECRET_KEY, etc.)
   - Use strong passwords (minimum 32 characters)
   - Enable encryption at rest for audit logs
   - Disable debug mode in production

### For Developers

1. **Code Security**:
   - Never log secrets or sensitive data
   - Validate all inputs (defense against injection)
   - Use parameterized queries (prevent SQL injection)
   - Implement rate limiting on all endpoints

2. **Dependencies**:
   - Keep dependencies updated
   - Review dependency security advisories
   - Use `poetry audit` for vulnerability scanning
   - Pin dependency versions in production

---

## Responsible Disclosure

We appreciate security researchers who responsibly disclose vulnerabilities.

### Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be acknowledged here (with their permission):

- (No disclosures yet)

### Bug Bounty

We do not currently have a bug bounty program. However, we greatly appreciate responsible disclosure and will acknowledge researchers publicly.

---

## Contact

For security issues: [Create GitHub Security Advisory](https://github.com/j-raghavan/ChronoGuard/security/advisories/new)

For general security questions: Create a GitHub Discussion in the Security category

---

**Last Updated**: 2025-11-08
**Version**: 1.0
