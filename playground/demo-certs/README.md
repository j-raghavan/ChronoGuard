# Demo Certificates

These are **pre-generated self-signed certificates** for demo purposes only.

## Files

- `ca-cert.pem` - Certificate Authority certificate
- `ca-key.pem` - CA private key
- `demo-agent-cert.pem` - Demo agent mTLS certificate
- `demo-agent-key.pem` - Demo agent private key
- `server-cert.pem` - Envoy server certificate
- `server-key.pem` - Envoy server private key

## ⚠️ Security Warning

**DO NOT use these certificates in production!**

These certificates are:
- Self-signed (not from trusted CA)
- Committed to public repository
- Valid for 365 days from generation
- Intended ONLY for demo/development

For production, generate proper certificates from a trusted CA or use Let's Encrypt.

## Usage

These certificates are automatically used by:
- Envoy proxy (server-cert.pem, server-key.pem, ca-cert.pem)
- Demo Playwright scripts (demo-agent-cert.pem, demo-agent-key.pem)

No manual configuration needed for demos!
