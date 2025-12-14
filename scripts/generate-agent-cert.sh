#!/bin/bash
# Generate agent certificates for ChronoGuard mTLS authentication
#
# Usage: ./scripts/generate-agent-cert.sh <agent-name>
# Example: ./scripts/generate-agent-cert.sh my-python-agent
#
# This creates:
#   - certs/<agent-name>-cert.pem  (client certificate)
#   - certs/<agent-name>-key.pem   (private key)
#   - certs/ca-cert.pem            (CA certificate, if not exists)
#   - certs/ca-key.pem             (CA private key, if not exists)

set -e

AGENT_NAME="${1:-my-agent}"
CERTS_DIR="${2:-certs}"
DAYS_VALID=365

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}ChronoGuard Agent Certificate Generator${NC}"
echo "========================================="
echo ""

# Create certs directory
mkdir -p "$CERTS_DIR"

# Generate CA if it doesn't exist
if [ ! -f "$CERTS_DIR/ca-cert.pem" ]; then
    echo -e "${YELLOW}Generating CA certificate...${NC}"

    # Generate CA private key
    openssl genrsa -out "$CERTS_DIR/ca-key.pem" 2048 2>/dev/null

    # Generate CA certificate
    openssl req -new -x509 \
        -key "$CERTS_DIR/ca-key.pem" \
        -out "$CERTS_DIR/ca-cert.pem" \
        -days $DAYS_VALID \
        -subj "/C=US/ST=Demo/L=Demo/O=ChronoGuard/CN=ChronoGuard CA" \
        2>/dev/null

    echo -e "${GREEN}✓ CA certificate created${NC}"
else
    echo -e "${GREEN}✓ Using existing CA certificate${NC}"
fi

# Generate agent certificate
echo -e "${YELLOW}Generating certificate for agent: ${AGENT_NAME}${NC}"

# Generate agent private key
openssl genrsa -out "$CERTS_DIR/${AGENT_NAME}-key.pem" 2048 2>/dev/null

# Generate CSR
openssl req -new \
    -key "$CERTS_DIR/${AGENT_NAME}-key.pem" \
    -out "$CERTS_DIR/${AGENT_NAME}.csr" \
    -subj "/C=US/ST=Demo/L=Demo/O=ChronoGuard/CN=${AGENT_NAME}" \
    2>/dev/null

# Sign with CA
openssl x509 -req \
    -in "$CERTS_DIR/${AGENT_NAME}.csr" \
    -CA "$CERTS_DIR/ca-cert.pem" \
    -CAkey "$CERTS_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERTS_DIR/${AGENT_NAME}-cert.pem" \
    -days $DAYS_VALID \
    2>/dev/null

# Clean up CSR
rm -f "$CERTS_DIR/${AGENT_NAME}.csr" "$CERTS_DIR/ca.srl"

# Verify the certificate
echo ""
echo -e "${GREEN}✓ Agent certificate created successfully!${NC}"
echo ""
echo "Certificate files:"
echo "  - Agent cert: $CERTS_DIR/${AGENT_NAME}-cert.pem"
echo "  - Agent key:  $CERTS_DIR/${AGENT_NAME}-key.pem"
echo "  - CA cert:    $CERTS_DIR/ca-cert.pem"
echo ""

# Verify chain
echo "Verifying certificate chain..."
if openssl verify -CAfile "$CERTS_DIR/ca-cert.pem" "$CERTS_DIR/${AGENT_NAME}-cert.pem" 2>/dev/null | grep -q "OK"; then
    echo -e "${GREEN}✓ Certificate chain verified${NC}"
else
    echo -e "${RED}✗ Certificate verification failed${NC}"
    exit 1
fi

echo ""
echo "Usage example:"
echo "  export CHRONOGUARD_CERT=$CERTS_DIR/${AGENT_NAME}-cert.pem"
echo "  export CHRONOGUARD_KEY=$CERTS_DIR/${AGENT_NAME}-key.pem"
echo "  export CHRONOGUARD_CA=$CERTS_DIR/ca-cert.pem"
echo "  python examples/generic_python_agent.py"
echo ""
echo -e "${YELLOW}Note: For the demo environment, you may want to use the pre-generated${NC}"
echo -e "${YELLOW}certificates in playground/demo-certs/ instead.${NC}"
