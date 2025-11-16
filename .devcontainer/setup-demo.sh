#!/bin/bash
set -e

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║         🔒 ChronoGuard Demo Environment Setup 🔒          ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Install Python dependencies for demo scripts
echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
pip install --quiet playwright requests rich pydantic 2>/dev/null || true
playwright install chromium --quiet 2>/dev/null || true
echo -e "${GREEN}✅ Python dependencies installed${NC}"

# 2. Create .env file if it doesn't exist
echo -e "${BLUE}🔐 Configuring environment...${NC}"
if [ ! -f .env ]; then
    cat > .env <<EOF
# ChronoGuard Demo Configuration
# Auto-generated for GitHub Codespaces

# Database Configuration
CHRONOGUARD_DB_HOST=postgres
CHRONOGUARD_DB_PORT=5432
CHRONOGUARD_DB_USER=chronoguard
CHRONOGUARD_DB_PASSWORD=demo-password-$(openssl rand -hex 8)
CHRONOGUARD_DB_DATABASE=chronoguard

# Security
CHRONOGUARD_SECURITY_SECRET_KEY=$(openssl rand -hex 32)
CHRONOGUARD_INTERNAL_SECRET=$(openssl rand -hex 32)

# Demo Mode
CHRONOGUARD_SECURITY_DEMO_MODE_ENABLED=true
CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD=chronoguard-admin-2025
CHRONOGUARD_SECURITY_SESSION_COOKIE_SECURE=false

# Observability
OTEL_SDK_DISABLED=true
EOF
    echo -e "${GREEN}✅ Environment configured${NC}"
else
    echo -e "${YELLOW}⚠️  .env already exists, skipping${NC}"
fi

# 3. Wait for Docker services to be ready
echo -e "${BLUE}⏳ Waiting for services to start...${NC}"
echo -e "${YELLOW}   This may take 1-2 minutes...${NC}"
sleep 20

# Check backend health
for i in {1..30}; do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Backend API is healthy${NC}"
        break
    fi
    sleep 2
done

# Check dashboard
if curl -sf http://localhost:3000 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Dashboard is ready${NC}"
else
    echo -e "${YELLOW}⚠️  Dashboard may still be starting...${NC}"
fi

# 4. Seed demo data
echo -e "${BLUE}🌱 Seeding demo data...${NC}"
cd backend
PYTHONPATH=src poetry install --quiet 2>/dev/null || true
PYTHONPATH=src poetry run python scripts/seed_database.py 2>/dev/null || echo -e "${YELLOW}⚠️  Seed script failed (may already be seeded)${NC}"
cd ..

echo ""
echo -e "${BOLD}${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║              ✨ ChronoGuard is Ready! ✨                   ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}🎯 Quick Start Guide:${NC}"
echo ""
echo -e "1️⃣  ${BOLD}View Dashboard:${NC}"
echo -e "   ${BLUE}http://localhost:3000${NC}"
echo -e "   Login password: ${YELLOW}chronoguard-admin-2025${NC}"
echo ""
echo -e "2️⃣  ${BOLD}Run Demo (Blocked Request):${NC}"
echo -e "   ${GREEN}python playground/demo-blocked.py${NC}"
echo ""
echo -e "3️⃣  ${BOLD}Run Demo (Allowed Request):${NC}"
echo -e "   ${GREEN}python playground/demo-allowed.py${NC}"
echo ""
echo -e "4️⃣  ${BOLD}Interactive Audit Viewer:${NC}"
echo -e "   ${GREEN}python playground/demo-interactive.py${NC}"
echo ""
echo -e "5️⃣  ${BOLD}API Documentation:${NC}"
echo -e "   ${BLUE}http://localhost:8000/docs${NC}"
echo ""
echo -e "${YELLOW}📚 Full demo guide: ${NC}${BLUE}playground/README.md${NC}"
echo ""
echo -e "${BOLD}${GREEN}Happy exploring! 🚀${NC}"
echo ""
