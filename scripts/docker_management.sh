#!/bin/bash
# ChronoGuard Docker Management Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Docker Hub configuration
DOCKERHUB_USERNAME="chronoguard"
IMAGES=("proxy" "policy-engine" "audit-sink" "metrics-exporter" "dashboard" "playwright-runner")

print_usage() {
    echo "ChronoGuard Docker Management"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build-all       Build all 6 ChronoGuard images locally"
    echo "  push-all        Push all images to Docker Hub"
    echo "  pull-all        Pull all images from Docker Hub"
    echo "  start-stack     Start complete ChronoGuard stack"
    echo "  stop-stack      Stop ChronoGuard stack"
    echo "  restart-stack   Restart ChronoGuard stack"
    echo "  logs [service]  View logs for service (or all services)"
    echo "  status          Show status of all services"
    echo "  cleanup         Remove all containers and volumes"
    echo "  help            Show this help message"
}

build_all_images() {
    echo -e "${BLUE}🏗️  Building all ChronoGuard images...${NC}"

    for image in "${IMAGES[@]}"; do
        echo -e "${YELLOW}Building chronoguard/$image...${NC}"
        docker build -t "chronoguard/$image:latest" "./docker/$image/"
        echo -e "${GREEN}✅ Built chronoguard/$image${NC}"
    done

    echo -e "${GREEN}🎉 All images built successfully!${NC}"
}

push_all_images() {
    echo -e "${BLUE}📤 Pushing all ChronoGuard images to Docker Hub...${NC}"

    # Check if logged in to Docker Hub
    if ! docker info | grep -q "Username: $DOCKERHUB_USERNAME"; then
        echo -e "${YELLOW}⚠️  Not logged in to Docker Hub. Please run: docker login${NC}"
        exit 1
    fi

    for image in "${IMAGES[@]}"; do
        echo -e "${YELLOW}Pushing chronoguard/$image...${NC}"
        docker push "chronoguard/$image:latest"
        echo -e "${GREEN}✅ Pushed chronoguard/$image${NC}"
    done

    echo -e "${GREEN}🎉 All images pushed successfully!${NC}"
}

pull_all_images() {
    echo -e "${BLUE}📥 Pulling all ChronoGuard images from Docker Hub...${NC}"

    for image in "${IMAGES[@]}"; do
        echo -e "${YELLOW}Pulling chronoguard/$image...${NC}"
        docker pull "chronoguard/$image:latest"
        echo -e "${GREEN}✅ Pulled chronoguard/$image${NC}"
    done

    echo -e "${GREEN}🎉 All images pulled successfully!${NC}"
}

start_stack() {
    echo -e "${BLUE}🚀 Starting complete ChronoGuard stack...${NC}"

    if [ ! -f ".env" ]; then
        echo -e "${YELLOW}⚠️  No .env file found. Creating from example...${NC}"
        cp deployments/docker/.env.example .env
        echo -e "${RED}🔧 Please edit .env file with proper values before running again${NC}"
        exit 1
    fi

    docker-compose -f deployments/docker/docker-compose.full.yml up -d

    echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
    sleep 30

    echo -e "${GREEN}✅ ChronoGuard stack started!${NC}"
    echo -e "${BLUE}🌐 Services available at:${NC}"
    echo "  • API: http://localhost:8000"
    echo "  • Dashboard: http://localhost:3000"
    echo "  • Proxy: http://localhost:8080"
    echo "  • Policy Engine: http://localhost:8181"
    echo "  • Audit Sink: http://localhost:8001"
    echo "  • Metrics: http://localhost:8002"
    echo "  • Grafana: http://localhost:3001"
    echo "  • Prometheus: http://localhost:9090"
}

stop_stack() {
    echo -e "${BLUE}🛑 Stopping ChronoGuard stack...${NC}"
    docker-compose -f deployments/docker/docker-compose.full.yml down
    echo -e "${GREEN}✅ ChronoGuard stack stopped${NC}"
}

restart_stack() {
    echo -e "${BLUE}🔄 Restarting ChronoGuard stack...${NC}"
    stop_stack
    start_stack
}

show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        echo -e "${BLUE}📋 Showing logs for all services...${NC}"
        docker-compose -f deployments/docker/docker-compose.full.yml logs -f
    else
        echo -e "${BLUE}📋 Showing logs for $service...${NC}"
        docker-compose -f deployments/docker/docker-compose.full.yml logs -f "$service"
    fi
}

show_status() {
    echo -e "${BLUE}📊 ChronoGuard Services Status:${NC}"
    echo ""
    docker-compose -f deployments/docker/docker-compose.full.yml ps
}

cleanup() {
    echo -e "${RED}🧹 Cleaning up ChronoGuard environment...${NC}"
    echo -e "${YELLOW}⚠️  This will remove all containers, volumes, and data!${NC}"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose -f deployments/docker/docker-compose.full.yml down -v
        docker system prune -f
        echo -e "${GREEN}✅ Cleanup completed${NC}"
    else
        echo -e "${YELLOW}Cleanup cancelled${NC}"
    fi
}

# Main script logic
case "${1:-help}" in
    build-all)
        build_all_images
        ;;
    push-all)
        push_all_images
        ;;
    pull-all)
        pull_all_images
        ;;
    start-stack)
        start_stack
        ;;
    stop-stack)
        stop_stack
        ;;
    restart-stack)
        restart_stack
        ;;
    logs)
        show_logs "$2"
        ;;
    status)
        show_status
        ;;
    cleanup)
        cleanup
        ;;
    help|*)
        print_usage
        ;;
esac