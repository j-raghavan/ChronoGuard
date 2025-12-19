#!/bin/bash
# ChronoGuard Kubernetes Health Check Script
# This script verifies the health of all ChronoGuard services in Kubernetes

set -e

NAMESPACE="chronoguard"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "ChronoGuard Kubernetes Health Check"
echo "========================================="
echo ""

# Check kubectl availability
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed${NC}"
    exit 1
fi

# Check namespace exists
if ! kubectl get namespace $NAMESPACE &> /dev/null; then
    echo -e "${RED}Error: Namespace '$NAMESPACE' does not exist${NC}"
    exit 1
fi

# Function to check pod status
check_pods() {
    local component=$1
    local expected_count=$2

    echo -n "Checking $component pods... "

    local ready_count=$(kubectl get pods -n $NAMESPACE \
        -l app.kubernetes.io/component=$component \
        -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
        | grep -c "True" || echo "0")

    local total_count=$(kubectl get pods -n $NAMESPACE \
        -l app.kubernetes.io/component=$component \
        --no-headers | wc -l)

    if [ "$ready_count" -ge "$expected_count" ]; then
        echo -e "${GREEN}✓ $ready_count/$total_count ready${NC}"
        return 0
    else
        echo -e "${RED}✗ Only $ready_count/$total_count ready${NC}"
        return 1
    fi
}

# Function to check service endpoints
check_service() {
    local service_name=$1

    echo -n "Checking $service_name service endpoints... "

    local endpoints=$(kubectl get endpoints $service_name -n $NAMESPACE \
        -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)

    if [ -n "$endpoints" ]; then
        local count=$(echo $endpoints | wc -w)
        echo -e "${GREEN}✓ $count endpoint(s) ready${NC}"
        return 0
    else
        echo -e "${RED}✗ No endpoints ready${NC}"
        return 1
    fi
}

# Function to test HTTP endpoint
test_http_endpoint() {
    local pod_name=$1
    local port=$2
    local path=$3
    local description=$4

    echo -n "Testing $description... "

    if kubectl exec $pod_name -n $NAMESPACE -- \
        wget -q -O- --timeout=5 "http://localhost:$port$path" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Responding${NC}"
        return 0
    else
        echo -e "${RED}✗ Not responding${NC}"
        return 1
    fi
}

# Track overall health
HEALTH_CHECK_FAILED=0

echo "=== Pod Health ==="
echo ""

check_pods "database" 1 || HEALTH_CHECK_FAILED=1
check_pods "cache" 1 || HEALTH_CHECK_FAILED=1
check_pods "policy-engine" 1 || HEALTH_CHECK_FAILED=1
check_pods "api" 1 || HEALTH_CHECK_FAILED=1
check_pods "proxy" 1 || HEALTH_CHECK_FAILED=1
check_pods "dashboard" 1 || HEALTH_CHECK_FAILED=1

echo ""
echo "=== Service Endpoints ==="
echo ""

check_service "postgres-service" || HEALTH_CHECK_FAILED=1
check_service "redis-service" || HEALTH_CHECK_FAILED=1
check_service "opa-service" || HEALTH_CHECK_FAILED=1
check_service "api-service" || HEALTH_CHECK_FAILED=1
check_service "envoy-service" || HEALTH_CHECK_FAILED=1
check_service "dashboard-service" || HEALTH_CHECK_FAILED=1

echo ""
echo "=== Application Health Checks ==="
echo ""

# Get pod names
POSTGRES_POD=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/component=database -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
REDIS_POD=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/component=cache -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
OPA_POD=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/component=policy-engine -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
API_POD=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
ENVOY_POD=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/component=proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
DASHBOARD_POD=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/component=dashboard -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

# PostgreSQL health
if [ -n "$POSTGRES_POD" ]; then
    echo -n "Testing PostgreSQL connection... "
    if kubectl exec $POSTGRES_POD -n $NAMESPACE -- \
        pg_isready -U chronoguard -d chronoguard > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Connected${NC}"
    else
        echo -e "${RED}✗ Connection failed${NC}"
        HEALTH_CHECK_FAILED=1
    fi
fi

# Redis health
if [ -n "$REDIS_POD" ]; then
    echo -n "Testing Redis connection... "
    if kubectl exec $REDIS_POD -n $NAMESPACE -- \
        redis-cli ping > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Responding${NC}"
    else
        echo -e "${RED}✗ Not responding${NC}"
        HEALTH_CHECK_FAILED=1
    fi
fi

# OPA health
if [ -n "$OPA_POD" ]; then
    test_http_endpoint "$OPA_POD" 8181 "/health" "OPA health" || HEALTH_CHECK_FAILED=1
fi

# API health
if [ -n "$API_POD" ]; then
    test_http_endpoint "$API_POD" 8000 "/health" "API health" || HEALTH_CHECK_FAILED=1
fi

# Envoy health
if [ -n "$ENVOY_POD" ]; then
    test_http_endpoint "$ENVOY_POD" 9901 "/ready" "Envoy readiness" || HEALTH_CHECK_FAILED=1
fi

# Dashboard health
if [ -n "$DASHBOARD_POD" ]; then
    test_http_endpoint "$DASHBOARD_POD" 80 "/" "Dashboard" || HEALTH_CHECK_FAILED=1
fi

echo ""
echo "=== Resource Usage ==="
echo ""

# Get resource usage
kubectl top pods -n $NAMESPACE 2>/dev/null || echo -e "${YELLOW}Note: Metrics server not available. Install metrics-server to see resource usage.${NC}"

echo ""
echo "========================================="

if [ $HEALTH_CHECK_FAILED -eq 0 ]; then
    echo -e "${GREEN}All health checks passed!${NC}"
    echo "========================================="
    exit 0
else
    echo -e "${RED}Some health checks failed!${NC}"
    echo "========================================="
    echo ""
    echo "For detailed diagnostics, run:"
    echo "  kubectl get pods -n $NAMESPACE"
    echo "  kubectl describe pods -n $NAMESPACE"
    echo "  kubectl logs <pod-name> -n $NAMESPACE"
    echo ""
    exit 1
fi
