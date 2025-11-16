# ChronoGuard Playground 🎮

Welcome to the ChronoGuard interactive demo! This playground lets you experience ChronoGuard's zero-trust browser automation control in action.

## 🎯 What You'll Learn

- How ChronoGuard blocks unauthorized domains
- How ChronoGuard allows whitelisted domains
- How audit logs capture every request with cryptographic verification
- How policies control access in real-time

---

## 🚀 Quick Start

### Demo 1: See Requests Get BLOCKED ❌

```bash
python playground/demo-blocked.py
```

**What happens:**
- Playwright attempts to access `google.com`
- ChronoGuard blocks the request (domain not in allowlist)
- Terminal shows detailed flow of the blocking
- Audit log entry created with timestamp

**You'll see:**
```
✅ ChronoGuard successfully BLOCKED the request!
  • Domain: google.com
  • Status: BLOCKED
  • Reason: Domain not in allowlist
```

---

### Demo 2: See Requests Get ALLOWED ✅

```bash
python playground/demo-allowed.py
```

**What happens:**
- Playwright accesses `example.com`
- ChronoGuard allows the request (domain in allowlist)
- Page loads successfully
- Audit log captures the allowed access

**You'll see:**
```
✅ ChronoGuard successfully ALLOWED the request!
  • Domain: example.com
  • Status: ALLOWED (200)
  • Reason: Domain in allowlist
```

---

### Demo 3: Interactive Audit Viewer 📊

```bash
python playground/demo-interactive.py
```

**What happens:**
- Live terminal UI showing real-time audit logs
- Color-coded allow/deny decisions
- Updates every 2 seconds
- Stats dashboard

**Features:**
- 📋 Real-time audit log table
- 📊 Statistics (total, allowed, denied)
- 🎨 Color-coded decisions
- ⏰ Timestamps for all requests

---

## 📚 Understanding the Demo

### Architecture Flow

```
┌─────────────┐         ┌───────────────┐         ┌─────────────┐
│  Playwright │────────>│ Envoy Proxy   │────────>│ OPA Policy  │
│   Browser   │  mTLS   │ (Port 8080)   │  gRPC   │  Engine     │
└─────────────┘         └───────┬───────┘         └──────┬──────┘
                                │                         │
                                │ Decision Log            │ Policy
                                ↓                         │ Check
                        ┌───────────────┐                │
                        │  FastAPI      │<───────────────┘
                        │  Backend      │
                        └───────┬───────┘
                                │
                                ↓
                        ┌───────────────┐
                        │  PostgreSQL   │
                        │  (Audit Log)  │
                        └───────────────┘
```

### How It Works

1. **Playwright sends request** through ChronoGuard proxy
2. **Envoy intercepts** and authenticates via mTLS
3. **OPA evaluates** policy (domain allowlist/blocklist)
4. **Decision made**: ALLOW or DENY
5. **OPA sends decision log** to FastAPI backend
6. **Backend creates audit entry** with cryptographic hash chain
7. **Request forwarded** (if allowed) or blocked (if denied)

---

## 🔧 Customize the Demo

### Add Your Own Domain to Allowlist

1. **Via API** (requires authentication):
```bash
# Login and get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "chronoguard-admin-2025"}' | jq -r '.access_token')

# Get existing policy ID
POLICY_ID=$(curl -s http://localhost:8000/api/v1/policies/ \
  -H "Authorization: Bearer $TOKEN" | jq -r '.items[0].policy_id')

# Add domain to allowlist
curl -X PUT http://localhost:8000/api/v1/policies/$POLICY_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allowed_domains": ["example.com", "your-domain.com"]}'
```

2. **Via Dashboard**:
   - Open http://localhost:3000
   - Navigate to Policies
   - Click on a policy
   - Add domain to "Allowed Domains"
   - Save

### View Audit Logs

**Via Dashboard:**
- Navigate to: http://localhost:3000
- Click: "Audit Logs" in sidebar
- Filter by date, agent, or domain

**Via API:**
```bash
# Get recent logs
curl http://localhost:8000/api/v1/audit/analytics | jq

# Export to CSV
curl -X POST http://localhost:8000/api/v1/audit/export \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "start_time": "2025-01-01T00:00:00Z", "end_time": "2025-12-31T23:59:59Z"}' \
  --output audit-export.csv
```

**Via Database:**
```bash
docker compose exec postgres psql -U chronoguard -c \
  "SELECT timestamp, domain, decision, reason FROM audit_entries ORDER BY timestamp DESC LIMIT 10;"
```

---

## 🎓 Next Steps

After exploring the demo, try:

1. **Read the Architecture Docs**: `docs/architecture/architecture.md`
2. **Set Up Your Own Agent**: `docs/guides/agent-setup.md`
3. **Write Custom Policies**: OPA Rego policies in `configs/opa/policies/`
4. **Deploy to Production**: `docs/DEPLOYMENT_SECURITY.md`

---

## 🐛 Troubleshooting

### Demo script fails with "Connection refused"
**Cause:** Services not running
**Solution:**
```bash
docker compose -f docker-compose.demo.yml ps
docker compose -f docker-compose.demo.yml up -d
```

### Playwright fails with SSL/certificate error
**Cause:** Demo certificates not trusted
**Solution:** Scripts use `--ignore-certificate-errors` flag (safe for demo)

### Dashboard not loading
**Cause:** Frontend still building
**Solution:**
```bash
docker compose logs chronoguard-dashboard
# Wait for "ready" message
```

### "Policy not found" error
**Cause:** Database not seeded
**Solution:**
```bash
cd backend
PYTHONPATH=src poetry run python scripts/seed_database.py
```

---

## 💡 Tips

- **Fast Reset:** `docker compose -f docker-compose.demo.yml down -v && docker compose -f docker-compose.demo.yml up -d`
- **View All Logs:** `docker compose -f docker-compose.demo.yml logs -f`
- **Check Service Health:** `curl http://localhost:8000/health`
- **View Envoy Stats:** `curl http://localhost:9901/stats`
- **Check OPA Policies:** `curl http://localhost:8181/v1/policies`

---

## 🤝 Contributing

Found an issue with the demo? Want to add a new demo scenario?
- Open an issue: [GitHub Issues](https://github.com/j-raghavan/ChronoGuard/issues)
- Submit a PR: [Contributing Guide](../CONTRIBUTING.md)

---

## 📖 Learning Resources

- **API Documentation**: http://localhost:8000/docs
- **Architecture Guide**: `docs/architecture/architecture.md`
- **Security Model**: `docs/SECURITY_ARCHITECTURE.md`
- **Deployment Guide**: `docs/DEPLOYMENT_SECURITY.md`

---

**Enjoy the demo!** 🎉

If ChronoGuard helps secure your browser automation, please ⭐ **star the repo** on GitHub!
