# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of ChronoGuard seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Use **GitHub's private vulnerability reporting**:
   - Go to the [Security tab](../../security) of this repository
   - Click "Report a vulnerability"
   - Fill out the security advisory form
3. Alternatively, contact the maintainers directly via GitHub
4. Include as much detail as possible:
   - Type of vulnerability (e.g., injection, authentication bypass, privilege escalation)
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Expect

- **Initial Response**: Within 48 hours of your report
- **Status Update**: Within 7 days with our assessment
- **Resolution Timeline**: Critical issues within 30 days; others based on severity

### Disclosure Policy

- We follow responsible disclosure practices
- We will credit reporters (unless anonymity is requested) once the issue is fixed
- We request that you do not publicly disclose the vulnerability until we have addressed it

## Security Best Practices for ChronoGuard Deployments

### Certificate Management

1. **Never commit private keys** to version control
2. **Rotate certificates** before expiration (default validity: 365 days)
3. **Use a proper CA** in production (not the demo self-signed certificates)
4. **Store certificates securely** using secrets management (e.g., HashiCorp Vault, AWS Secrets Manager)

### mTLS Configuration

1. **Always verify certificates** in production (`verify=True`)
2. **Use strong cipher suites** (TLS 1.2+ only)
3. **Disable demo mode** in production environments
4. **Configure proper certificate revocation** (CRL or OCSP)

### Database Security

1. **Use strong, unique passwords** for PostgreSQL
2. **Enable SSL/TLS** for database connections
3. **Restrict network access** to database ports
4. **Regular backups** with encryption at rest

### API Security

1. **Change default secrets** before deployment:
   - `CHRONOGUARD_SECURITY_SECRET_KEY`
   - `CHRONOGUARD_INTERNAL_SECRET`
   - `CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD`
2. **Enable HTTPS** for all API endpoints
3. **Configure proper CORS** settings for your domain
4. **Set secure cookie attributes** (`Secure`, `HttpOnly`, `SameSite`)

### OPA Policy Engine

1. **Review policies** before deployment
2. **Use allowlists** instead of blocklists where possible
3. **Audit policy changes** through the audit log
4. **Test policies** in staging before production

### Docker/Kubernetes Deployment

1. **Run containers as non-root** users
2. **Use read-only file systems** where possible
3. **Limit container resources** (CPU, memory)
4. **Scan images** for vulnerabilities regularly
5. **Use network policies** to restrict container communication

### Monitoring and Alerting

1. **Monitor audit logs** for suspicious patterns
2. **Set up alerts** for:
   - Failed authentication attempts
   - Policy violations
   - Certificate expiration warnings
   - Unusual traffic patterns
3. **Retain logs** according to compliance requirements

## Known Security Considerations

### Demo Mode

The demo mode (`CHRONOGUARD_SECURITY_DEMO_MODE_ENABLED=true`) is intended for evaluation only and includes:
- Pre-configured admin password
- Relaxed security settings
- Self-signed certificates

**Never use demo mode in production.**

### Self-Signed Certificates

The demo certificates in `playground/demo-certs/` are for testing only. They:
- Are not trusted by browsers/systems
- Have verification disabled in demo scripts
- Should never be used in production

## Security Features

ChronoGuard includes several security features by design:

1. **mTLS Authentication**: All agent communication uses mutual TLS
2. **Cryptographic Audit Trail**: Audit entries are hash-chained for tamper detection
3. **Policy-Based Access Control**: Fine-grained access control via OPA
4. **Time-Based Restrictions**: Limit agent access to specific time windows
5. **Rate Limiting**: Prevent abuse through configurable rate limits
6. **Domain Allowlisting**: Explicit control over accessible domains

## Dependency Security

We regularly update dependencies to address security vulnerabilities. To check for known vulnerabilities in your installation:

```bash
# Python dependencies
pip install safety
safety check

# Or using pip-audit
pip install pip-audit
pip-audit

# JavaScript dependencies (frontend)
cd frontend && npm audit
```

## Contributing Security Improvements

We welcome security improvements! Please:

1. Follow our contribution guidelines
2. Include tests for security fixes
3. Document any security-related changes
4. Consider backwards compatibility

Thank you for helping keep ChronoGuard secure!

---

This project is licensed under the [Apache License 2.0](LICENSE).
