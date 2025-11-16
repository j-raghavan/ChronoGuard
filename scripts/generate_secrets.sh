#!/bin/bash
#
# ChronoGuard Secret Generation Script
# =====================================
# Generates cryptographically secure secrets for .env file
#
# Usage:
#   ./scripts/generate_secrets.sh          # Interactive mode
#   ./scripts/generate_secrets.sh --auto   # Auto-generate and save to .env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         ChronoGuard Secret Generation Tool                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if .env already exists
if [ -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}⚠️  WARNING: $ENV_FILE already exists!${NC}"
    echo ""
    read -p "Do you want to OVERWRITE it? (yes/no): " -r
    echo
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        echo -e "${RED}❌ Aborted. Existing .env file preserved.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}📝 Generating secure secrets...${NC}"
echo ""

# Generate secrets
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(43))')
INTERNAL_SECRET=$(openssl rand -base64 32 | tr -d '\n')

# Check if user wants demo mode
echo -e "${BLUE}🎭 Demo Mode Configuration${NC}"
echo "Demo mode enables simplified authentication for development/testing."
echo -e "${RED}WARNING: Never enable in production!${NC}"
echo ""
read -p "Enable demo mode? (y/N): " -r ENABLE_DEMO
echo ""

DEMO_MODE_ENABLED="false"
DEMO_ADMIN_PASSWORD=""

if [[ $ENABLE_DEMO =~ ^[Yy]$ ]]; then
    DEMO_MODE_ENABLED="true"

    echo "Enter a strong password for demo admin (min 16 characters):"
    read -s -p "Password: " DEMO_ADMIN_PASSWORD
    echo ""
    read -s -p "Confirm password: " DEMO_ADMIN_PASSWORD_CONFIRM
    echo ""

    if [ "$DEMO_ADMIN_PASSWORD" != "$DEMO_ADMIN_PASSWORD_CONFIRM" ]; then
        echo -e "${RED}❌ Passwords don't match!${NC}"
        exit 1
    fi

    if [ ${#DEMO_ADMIN_PASSWORD} -lt 16 ]; then
        echo -e "${RED}❌ Password must be at least 16 characters!${NC}"
        exit 1
    fi
fi

# Create .env file
cat > "$ENV_FILE" << EOF
# ChronoGuard Environment Configuration
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# =====================================

# -----------------------------------------------------------------------------
# PRODUCTION ESSENTIALS (Required)
# -----------------------------------------------------------------------------

# Database Password
CHRONOGUARD_DB_PASSWORD=$DB_PASSWORD

# JWT Secret Key
CHRONOGUARD_SECURITY_SECRET_KEY=$SECRET_KEY

# OPA→API Internal Authentication
CHRONOGUARD_INTERNAL_SECRET=$INTERNAL_SECRET

EOF

# Add demo mode config if enabled
if [ "$DEMO_MODE_ENABLED" = "true" ]; then
    cat >> "$ENV_FILE" << EOF
# -----------------------------------------------------------------------------
# DEMO MODE (Development/Demo Only)
# -----------------------------------------------------------------------------
# WARNING: Never enable in production!

CHRONOGUARD_SECURITY_DEMO_MODE_ENABLED=true
CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD=$DEMO_ADMIN_PASSWORD

EOF
fi

# Add comment about advanced options
cat >> "$ENV_FILE" << EOF
# -----------------------------------------------------------------------------
# ADVANCED (Optional)
# -----------------------------------------------------------------------------
# See .env.example for additional configuration options.
# All settings below have sensible defaults.

EOF

echo -e "${GREEN}✅ Secrets generated successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Summary:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "✓ Database Password:     ${GREEN}Generated (32 bytes)${NC}"
echo -e "✓ JWT Secret Key:        ${GREEN}Generated (43 chars)${NC}"
echo -e "✓ Internal API Secret:   ${GREEN}Generated (32 bytes)${NC}"

if [ "$DEMO_MODE_ENABLED" = "true" ]; then
    echo -e "✓ Demo Mode:             ${YELLOW}ENABLED${NC}"
    echo -e "✓ Demo Admin Password:   ${YELLOW}Set (${#DEMO_ADMIN_PASSWORD} chars)${NC}"
else
    echo -e "○ Demo Mode:             ${BLUE}Disabled${NC}"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}✅ Configuration saved to:${NC} $ENV_FILE"
echo ""
echo -e "${BLUE}📚 Next Steps:${NC}"
echo "1. Review the generated .env file"
echo "2. Update OPA config with CHRONOGUARD_INTERNAL_SECRET"
echo "3. Start services: docker compose up -d"
echo "4. Check deployment guide: docs/DEPLOYMENT_SECURITY.md"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
echo "• Keep .env file secure (already in .gitignore)"
echo "• Never commit secrets to git"
echo "• Rotate secrets regularly in production"
if [ "$DEMO_MODE_ENABLED" = "true" ]; then
    echo -e "• ${RED}DISABLE demo mode before deploying to production!${NC}"
fi
echo ""
