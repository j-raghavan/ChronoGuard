#!/bin/bash
set -e

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

API_BASE_URL="${CHRONOGUARD_API_URL:-http://localhost:8000}"
API_BASE_URL="${API_BASE_URL%/}"
DASHBOARD_BASE_URL="${CHRONOGUARD_DASHBOARD_URL:-http://localhost:3000}"
DASHBOARD_BASE_URL="${DASHBOARD_BASE_URL%/}"
PROXY_BASE_URL="${CHRONOGUARD_PROXY_URL:-http://localhost:8080}"
PROXY_BASE_URL="${PROXY_BASE_URL%/}"
DEMO_ADMIN_PASSWORD="${CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD:-chronoguard-admin-2025}"
DEMO_MODE_ENABLED="${CHRONOGUARD_SECURITY_DEMO_MODE_ENABLED:-true}"
SESSION_COOKIE_SECURE="${CHRONOGUARD_SECURITY_SESSION_COOKIE_SECURE:-false}"

get_env_value() {
    local key="$1"
    local file="$2"
    if [ -f "$file" ]; then
        grep -E "^${key}=" "$file" | tail -n 1 | cut -d= -f2-
    fi
}

set_env_value() {
    local file="$1"
    local key="$2"
    local value="$3"
    if [ ! -f "$file" ]; then
        touch "$file"
    fi
    if grep -q "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

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

# Ensure demo-related environment variables match repo defaults
set_env_value ".env" "CHRONOGUARD_SECURITY_DEMO_MODE_ENABLED" "${DEMO_MODE_ENABLED}"
set_env_value ".env" "CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD" "${DEMO_ADMIN_PASSWORD}"
set_env_value ".env" "CHRONOGUARD_SECURITY_SESSION_COOKIE_SECURE" "${SESSION_COOKIE_SECURE}"

# CRITICAL: Override database settings for Docker demo environment
# The root .env may have local dev settings (localhost:5433) that won't work in Docker
echo -e "${BLUE}🔧 Configuring database for Docker environment...${NC}"
set_env_value ".env" "CHRONOGUARD_DB_HOST" "postgres"
set_env_value ".env" "CHRONOGUARD_DB_PORT" "5432"
set_env_value ".env" "CHRONOGUARD_DB_DATABASE" "chronoguard"
set_env_value ".env" "CHRONOGUARD_DB_USER" "chronoguard"
set_env_value ".env" "CHRONOGUARD_DB_PASSWORD" "demo-password"

# Align frontend configuration with backend endpoints/password
# IMPORTANT: VITE_API_URL must be EMPTY for Docker/Codespaces so nginx proxies /api/* to backend
# Setting it to a Docker hostname like http://chronoguard-api:8000 would cause Mixed Content errors
# because the browser can't resolve Docker internal hostnames
set_env_value "frontend/.env" "VITE_API_URL" ""
set_env_value "frontend/.env" "VITE_DEFAULT_PASSWORD" "${DEMO_ADMIN_PASSWORD}"

# 3. Start Docker services (Docker-in-Docker mode in Codespaces)
echo -e "${BLUE}🐳 Starting Docker services...${NC}"
echo -e "${YELLOW}   This may take 2-3 minutes on first run...${NC}"

# Check if Docker is available
if command -v docker &> /dev/null; then
    # Start all services except workspace (we're already in it)
    docker compose -f docker-compose.demo.yml up -d postgres redis chronoguard-policy-engine chronoguard-proxy chronoguard-api chronoguard-dashboard 2>/dev/null || \
    docker-compose -f docker-compose.demo.yml up -d postgres redis chronoguard-policy-engine chronoguard-proxy chronoguard-api chronoguard-dashboard 2>/dev/null || \
    echo -e "${YELLOW}⚠️  Could not start Docker services automatically${NC}"
    echo -e "${GREEN}✅ Docker services starting...${NC}"
else
    echo -e "${YELLOW}⚠️  Docker not available - services may need manual start${NC}"
fi

# 4. Wait for Docker services to be ready
echo -e "${BLUE}⏳ Waiting for services to be healthy...${NC}"
echo -e "${YELLOW}   This may take 1-2 minutes...${NC}"
sleep 30

# Check backend health
for i in {1..30}; do
    if curl -sf "${API_BASE_URL}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Backend API is healthy${NC}"
        break
    fi
    sleep 2
done

# Check dashboard
if curl -sf "${DASHBOARD_BASE_URL}" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Dashboard is ready${NC}"
else
    echo -e "${YELLOW}⚠️  Dashboard may still be starting...${NC}"
fi

# 5. Seed demo data
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
echo -e "   ${BLUE}${DASHBOARD_BASE_URL}${NC}"
echo -e "   Login password: ${YELLOW}${DEMO_ADMIN_PASSWORD}${NC}"
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
echo -e "   ${BLUE}${API_BASE_URL}/docs${NC}"
echo ""
echo -e "${YELLOW}📚 Full demo guide: ${NC}${BLUE}playground/README.md${NC}"
echo ""
echo -e "${BOLD}${GREEN}Happy exploring! 🚀${NC}"
echo ""
