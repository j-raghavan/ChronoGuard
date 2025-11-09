# Healthcare Policy Examples

HIPAA-compliant OPA policies for healthcare and medical systems.

## Policies

### operational-hours.rego
- Operational hours: 6am-10pm (configurable timezone)
- Emergency access override (24/7 for emergency responders)
- On-call staff access
- **Compliance**: HIPAA §164.308(a)(3) - Workforce access management

### phi-protection.rego
- Role-based PHI access control
- HIPAA training verification (annual requirement)
- Minimum Necessary Rule enforcement
- Sensitive PHI extra authorization
- Break-glass emergency access (logged)
- **Compliance**: HIPAA §164.502(b) - Minimum necessary, §164.514(d) - De-identification

### audit-requirements.rego
- Audit metadata completeness verification
- Access reason requirement for PHI
- Bulk export detection and alerting
- 6-year retention policy marker
- **Compliance**: HIPAA §164.312(b) - Audit controls, §164.316(b)(2) - Retention

## HIPAA Compliance Features

### Access Controls (§164.308)
- ✅ Unique user identification (agent certificates)
- ✅ Emergency access procedure (break-glass with logging)
- ✅ Automatic logoff (session timeouts via operational hours)
- ✅ Workforce clearance (role-based access)

### Audit Controls (§164.312(b))
- ✅ Detailed audit logging of all PHI access
- ✅ Access reason capture (Minimum Necessary)
- ✅ 6-year retention period
- ✅ Tamper-evident logs (hash chaining)

### Technical Safeguards (§164.312)
- ✅ Access control (role-based + time-based)
- ✅ Audit controls (comprehensive logging)
- ✅ Integrity controls (hash-chained audit trail)
- ✅ Transmission security (mTLS encryption)

## Usage

### Deploy to ChronoGuard

```bash
# Copy policies to OPA config directory
cp *.rego /path/to/chronoguard/configs/opa/policies/healthcare/

# Restart OPA
docker compose restart chronoguard-policy-engine

# Verify policies loaded
curl http://localhost:8181/v1/policies | jq '.result[].id'
```

### Test Policies

```bash
# Test input example
cat > test_input.json <<EOF
{
  "attributes": {
    "source": {
      "principal": "agent-physician-001",
      "address": {
        "socketAddress": {
          "address": "10.0.1.50"
        }
      }
    },
    "request": {
      "http": {
        "host": "ehr.hospital.internal",
        "method": "GET",
        "path": "/api/patients/12345/records"
      }
    }
  }
}
EOF

# Test PHI protection policy
docker run --rm -v $(pwd):/policies openpolicyagent/opa eval \
  -d /policies/phi-protection.rego \
  -i test_input.json \
  'data.chronoguard.healthcare.phi_protection.allow'
```

## Agent Configuration

Agents must include HIPAA-required metadata:

```json
{
  "agent_id": "agent-physician-001",
  "name": "Dr. Jane Smith",
  "roles": ["physician"],
  "department": "clinical",
  "facility": "General Hospital East",
  "status": "active",
  "hipaa_training_date": "2024-06-01T00:00:00Z",
  "access_reason": "Patient care - routine rounds",
  "emergency_override": false,
  "currently_on_call": false
}
```

## Audit Trail

All PHI access is logged with:
- Agent identity (name, ID, roles)
- Access timestamp
- Accessed resource (domain, path)
- Access reason (Minimum Necessary)
- Decision (allow/deny) with reason
- Training status
- Emergency access flag

Logs retained for **6 years** per HIPAA §164.316(b)(2).

## Customization

### Operational Hours

Edit `operational_hours.rego`:
```rego
operational_hours := {
    "start_hour_utc": 11,  # Change to your timezone
    "end_hour_utc": 3,
    "timezone": "America/New_York",
}
```

### Authorized Roles

Edit `phi_protection.rego`:
```rego
phi_authorized_roles := {
    "physician",
    "your_custom_role",  # Add your roles
}
```

### Sensitive PHI Categories

Edit `phi-protection.rego`:
```rego
sensitive_phi_paths := {
    "/api/patients/mental-health",
    "/api/patients/your-category",  # Add your paths
}
```

---

## HIPAA Compliance Checklist

When deploying these policies:

- [ ] Customize roles to match your organization
- [ ] Configure operational hours for your timezone
- [ ] Set up HIPAA training verification workflow
- [ ] Enable break-glass emergency access logging
- [ ] Configure 6-year audit retention
- [ ] Test all policies before production deployment
- [ ] Document policy changes for compliance review
- [ ] Train staff on access policies
- [ ] Set up monitoring for policy violations
- [ ] Establish periodic policy review process

---

**Disclaimer**: These policies are examples for reference. Consult with your compliance team and legal counsel to ensure they meet your specific HIPAA obligations.
