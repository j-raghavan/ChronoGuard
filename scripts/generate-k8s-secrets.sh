#!/bin/bash
# ChronoGuard Kubernetes Secret Generation Script
# This script generates secure secrets for Kubernetes deployment

set -e

echo "========================================="
echo "ChronoGuard Kubernetes Secret Generator"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for required commands
for cmd in openssl python3 kubectl base64; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed."
        exit 1
    fi
done

# Output directory
SECRETS_DIR="deployments/kubernetes/secrets"
mkdir -p "$SECRETS_DIR"

echo "This script will generate secure secrets for ChronoGuard Kubernetes deployment."
echo "Generated files will be placed in: $SECRETS_DIR/"
echo ""

# Generate database password
echo -e "${GREEN}[1/3] Generating database secrets...${NC}"
DB_PASSWORD=$(openssl rand -base64 32)
echo "  ✓ Generated strong database password (32 chars)"

# Generate API secrets
echo -e "${GREEN}[2/3] Generating application secrets...${NC}"
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(43))")
INTERNAL_SECRET=$(openssl rand -base64 32)
echo "  ✓ Generated JWT secret key (43 chars)"
echo "  ✓ Generated internal API secret (32 chars)"

# TLS certificates
echo -e "${GREEN}[3/3] TLS Certificate configuration...${NC}"
echo ""
echo "Do you have TLS certificates for Envoy? (y/n)"
read -r has_certs

if [ "$has_certs" = "y" ]; then
    echo "Please provide paths to your certificate files:"
    read -p "Server certificate path (PEM): " cert_path
    read -p "Server private key path (PEM): " key_path
    read -p "CA certificate path (PEM): " ca_path

    if [ -f "$cert_path" ] && [ -f "$key_path" ] && [ -f "$ca_path" ]; then
        CERT_BASE64=$(cat "$cert_path" | base64 -w 0 2>/dev/null || cat "$cert_path" | base64)
        KEY_BASE64=$(cat "$key_path" | base64 -w 0 2>/dev/null || cat "$key_path" | base64)
        CA_BASE64=$(cat "$ca_path" | base64 -w 0 2>/dev/null || cat "$ca_path" | base64)
        echo "  ✓ Certificates encoded successfully"
        CERTS_PROVIDED=true
    else
        echo "  ✗ One or more certificate files not found. You'll need to add them manually."
        CERTS_PROVIDED=false
    fi
else
    echo "  ℹ You'll need to add TLS certificates manually later."
    CERTS_PROVIDED=false
fi

echo ""
echo "========================================="
echo "Creating Kubernetes Secret manifests..."
echo "========================================="
echo ""

# Create database secrets
cat > "$SECRETS_DIR/database-secrets.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: chronoguard-db-secret
  namespace: chronoguard
  labels:
    app.kubernetes.io/name: chronoguard
    app.kubernetes.io/component: database
type: Opaque
stringData:
  CHRONOGUARD_DB_PASSWORD: "$DB_PASSWORD"
  POSTGRES_PASSWORD: "$DB_PASSWORD"
EOF
echo "✓ Created: $SECRETS_DIR/database-secrets.yaml"

# Create app secrets
cat > "$SECRETS_DIR/app-secrets.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: chronoguard-app-secret
  namespace: chronoguard
  labels:
    app.kubernetes.io/name: chronoguard
    app.kubernetes.io/component: api
type: Opaque
stringData:
  CHRONOGUARD_SECURITY_SECRET_KEY: "$JWT_SECRET"
  CHRONOGUARD_INTERNAL_SECRET: "$INTERNAL_SECRET"
EOF
echo "✓ Created: $SECRETS_DIR/app-secrets.yaml"

# Create TLS secrets
if [ "$CERTS_PROVIDED" = true ]; then
    cat > "$SECRETS_DIR/tls-secrets.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: chronoguard-tls-secret
  namespace: chronoguard
  labels:
    app.kubernetes.io/name: chronoguard
    app.kubernetes.io/component: proxy
type: Opaque
data:
  server-cert.pem: $CERT_BASE64
  server-key.pem: $KEY_BASE64
  ca-cert.pem: $CA_BASE64
EOF
    echo "✓ Created: $SECRETS_DIR/tls-secrets.yaml (with certificates)"
else
    cat > "$SECRETS_DIR/tls-secrets.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: chronoguard-tls-secret
  namespace: chronoguard
  labels:
    app.kubernetes.io/name: chronoguard
    app.kubernetes.io/component: proxy
type: Opaque
stringData:
  server-cert.pem: |
    # REPLACE WITH YOUR SERVER CERTIFICATE
    # -----BEGIN CERTIFICATE-----
    # ...
    # -----END CERTIFICATE-----
  server-key.pem: |
    # REPLACE WITH YOUR SERVER PRIVATE KEY
    # -----BEGIN PRIVATE KEY-----
    # ...
    # -----END PRIVATE KEY-----
  ca-cert.pem: |
    # REPLACE WITH YOUR CA CERTIFICATE
    # -----BEGIN CERTIFICATE-----
    # ...
    # -----END CERTIFICATE-----
EOF
    echo "✓ Created: $SECRETS_DIR/tls-secrets.yaml (template - needs certificates)"
fi

echo ""
echo "========================================="
echo "Secrets generated successfully!"
echo "========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Review the generated secrets:"
echo "   ls -la $SECRETS_DIR/"
echo ""

if [ "$CERTS_PROVIDED" = false ]; then
    echo -e "${YELLOW}2. Edit tls-secrets.yaml and add your TLS certificates${NC}"
    echo ""
fi

echo "3. Apply secrets to your cluster:"
echo "   kubectl apply -f $SECRETS_DIR/database-secrets.yaml"
echo "   kubectl apply -f $SECRETS_DIR/app-secrets.yaml"
echo "   kubectl apply -f $SECRETS_DIR/tls-secrets.yaml"
echo ""
echo "4. Continue with deployment:"
echo "   kubectl apply -k deployments/kubernetes/"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Keep these secret files secure and do not commit to version control!${NC}"
echo "   Add them to .gitignore:"
echo "   echo 'deployments/kubernetes/secrets/*.yaml' >> .gitignore"
echo "   echo '!deployments/kubernetes/secrets/*.template' >> .gitignore"
echo ""
echo "========================================="
