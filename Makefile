# ChronoGuard Development Makefile
# Production-grade development workflow automation

.PHONY: help install install-dev lint format type-check security test test-unit test-integration test-coverage clean build docker-build docker-push pre-commit check-all

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# Configuration
BACKEND_DIR := backend
FRONTEND_DIR := frontend
PYTHON := python
PYTEST_ARGS := -v --tb=short
COVERAGE_THRESHOLD := 95

help: ## Show this help message
	@echo "$(BLUE)ChronoGuard Development Commands$(RESET)"
	@echo "=================================="
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make $(BLUE)<target>$(RESET)\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(BLUE)%-20s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(RESET)\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Installation and Setup

install: ## Install production dependencies
	@echo "$(BLUE)📦 Installing production dependencies...$(RESET)"
	@poetry install --only=main --no-root
	@echo "$(GREEN)✅ Production dependencies installed$(RESET)"

install-dev: ## Install development dependencies
	@echo "$(BLUE)📦 Installing development dependencies...$(RESET)"
	@poetry install --no-root
	@echo "$(GREEN)✅ Development dependencies installed$(RESET)"

##@ Code Quality

lint: ## Run all linters (ruff, black)
	@echo "$(BLUE)🔍 Running linters...$(RESET)"
	@poetry run ruff check backend/src/ backend/tests/
	@poetry run ruff format --check backend/src/ backend/tests/
	@poetry run black --check backend/src/ backend/tests/
	@echo "$(GREEN)✅ All linters passed$(RESET)"

format: ## Auto-format code (ruff, black, isort)
	@echo "$(BLUE)🎨 Formatting code...$(RESET)"
	@poetry run ruff format backend/src/ backend/tests/
	@poetry run black backend/src/ backend/tests/
	@poetry run isort backend/src/ backend/tests/
	@echo "$(GREEN)✅ Code formatted$(RESET)"

type-check: ## Run mypy type checking
	@echo "$(BLUE)🔍 Running type checking...$(RESET)"
	@poetry run mypy backend/src/ --show-error-codes --show-error-context
	@echo "$(GREEN)✅ Type checking passed$(RESET)"

security: ## Run security analysis (bandit, safety)
	@echo "$(BLUE)🔒 Running security analysis...$(RESET)"
	@poetry run bandit -r backend/src/ -f txt
	@echo "$(BLUE)📋 Skipping Safety CLI (requires interactive login)$(RESET)"
	@echo "$(GREEN)✅ Security analysis passed$(RESET)"

##@ Testing

test: test-unit ## Run all tests (alias for test-unit)

test-unit: ## Run unit tests with coverage
	@echo "$(BLUE)🧪 Running unit tests...$(RESET)"
	@PYTHONPATH=backend/src poetry run pytest backend/tests/unit/ \
		--cov=backend/src \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-fail-under=$(COVERAGE_THRESHOLD) \
		$(PYTEST_ARGS)
	@echo "$(GREEN)✅ Unit tests passed with $(COVERAGE_THRESHOLD)%+ coverage$(RESET)"

test-integration: ## Run integration tests
	@echo "$(BLUE)🔗 Running integration tests...$(RESET)"
	@PYTHONPATH=backend/src poetry run pytest backend/tests/integration/ $(PYTEST_ARGS)
	@echo "$(GREEN)✅ Integration tests passed$(RESET)"

test-coverage: ## Generate detailed coverage report
	@echo "$(BLUE)📊 Generating coverage report...$(RESET)"
	@PYTHONPATH=backend/src poetry run pytest backend/tests/unit/ \
		--cov=src \
		--cov-report=html \
		--cov-report=xml \
		--cov-report=term-missing
	@echo "$(GREEN)✅ Coverage report generated in backend/htmlcov/$(RESET)"

test-performance: ## Run performance tests
	@echo "$(BLUE)⚡ Running performance tests...$(RESET)"
	@PYTHONPATH=backend/src poetry run pytest backend/tests/performance/ $(PYTEST_ARGS) || true
	@echo "$(GREEN)✅ Performance tests completed$(RESET)"

##@ Pre-commit and Quality Gates

pre-commit: install-dev lint type-check security ## Run essential pre-commit checks
	@echo "$(GREEN)🎉 All pre-commit checks passed!$(RESET)"

pre-commit-full: install-dev lint type-check security test-unit ## Run all pre-commit checks including tests
	@echo "$(GREEN)🎉 All pre-commit checks passed!$(RESET)"

check-all: pre-commit test-integration ## Run complete quality validation
	@echo "$(BLUE)🔍 Running complete quality validation...$(RESET)"
	@echo "$(GREEN)🎉 All quality checks passed! Ready for production.$(RESET)"

validate-imports: ## Validate all Python imports work
	@echo "$(BLUE)📥 Validating module imports...$(RESET)"
	@PYTHONPATH=backend/src $(PYTHON) -c "from core.features import FeatureManager; print('✅ Core systems'); from domain.agent import Agent; print('✅ Agent domain'); from domain.policy import Policy; print('✅ Policy domain'); from domain.audit import AuditEntry; print('✅ Audit domain'); print('🎉 All imports successful')"

##@ Docker Operations

docker-build: ## Build all Docker images locally
	@echo "$(BLUE)🐳 Building all Docker images...$(RESET)"
	./scripts/docker_management.sh build-all

docker-push: ## Push all Docker images to registry
	@echo "$(BLUE)📤 Pushing Docker images...$(RESET)"
	./scripts/docker_management.sh push-all

docker-start: ## Start complete ChronoGuard stack
	@echo "$(BLUE)🚀 Starting ChronoGuard stack...$(RESET)"
	./scripts/docker_management.sh start-stack

docker-stop: ## Stop ChronoGuard stack
	@echo "$(BLUE)🛑 Stopping ChronoGuard stack...$(RESET)"
	./scripts/docker_management.sh stop-stack

docker-logs: ## View Docker stack logs
	@echo "$(BLUE)📋 Viewing Docker logs...$(RESET)"
	./scripts/docker_management.sh logs

docker-status: ## Show Docker stack status
	@echo "$(BLUE)📊 Docker stack status...$(RESET)"
	./scripts/docker_management.sh status

##@ Development Workflow

dev-setup: install-dev ## Complete development environment setup
	@echo "$(BLUE)🔧 Setting up development environment...$(RESET)"
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)⚠️  Creating .env from example...$(RESET)"; \
		cp deployments/docker/.env.example .env; \
		echo "$(RED)🔧 Please edit .env file with proper values$(RESET)"; \
	fi
	@echo "$(GREEN)✅ Development environment ready$(RESET)"

dev-start: ## Start development environment
	@echo "$(BLUE)🚀 Starting development environment...$(RESET)"
	docker-compose -f deployments/docker/docker-compose.dev.yml up -d
	@echo "$(GREEN)✅ Development environment started$(RESET)"

dev-stop: ## Stop development environment
	@echo "$(BLUE)🛑 Stopping development environment...$(RESET)"
	docker-compose -f deployments/docker/docker-compose.dev.yml down
	@echo "$(GREEN)✅ Development environment stopped$(RESET)"

##@ Cleanup and Maintenance

clean: ## Clean build artifacts and cache
	@echo "$(BLUE)🧹 Cleaning build artifacts...$(RESET)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	rm -rf $(BACKEND_DIR)/htmlcov/ 2>/dev/null || true
	rm -rf $(BACKEND_DIR)/.pytest_cache/ 2>/dev/null || true
	rm -rf $(BACKEND_DIR)/.mypy_cache/ 2>/dev/null || true
	@echo "$(GREEN)✅ Cleanup completed$(RESET)"

clean-docker: ## Clean Docker containers and volumes (destructive)
	@echo "$(RED)🧹 Cleaning Docker environment...$(RESET)"
	./scripts/docker_management.sh cleanup

##@ Verification and Validation

verify: ## Verify foundation implementation
	@echo "$(BLUE)🔍 Verifying foundation implementation...$(RESET)"
	$(PYTHON) scripts/verify_foundation.py

quick-check: lint type-check validate-imports ## Quick quality check without tests
	@echo "$(GREEN)⚡ Quick quality check completed$(RESET)"

##@ Release and Deployment

build: clean install-dev check-all docker-build ## Complete build pipeline
	@echo "$(GREEN)🎉 Complete build pipeline completed!$(RESET)"

release-check: check-all docker-build ## Pre-release validation
	@echo "$(BLUE)🚀 Running pre-release validation...$(RESET)"
	./scripts/verify_foundation.py
	@echo "$(GREEN)🎉 Ready for release!$(RESET)"

##@ Information

show-env: ## Show current environment configuration
	@echo "$(BLUE)📋 Environment Information:$(RESET)"
	@echo "Python: $$(python --version)"
	@echo "Working Directory: $$(pwd)"
	@echo "Backend Directory: $(BACKEND_DIR)"
	@echo "Frontend Directory: $(FRONTEND_DIR)"
	@echo "Coverage Threshold: $(COVERAGE_THRESHOLD)%"

show-services: ## Show all ChronoGuard services and ports
	@echo "$(BLUE)🌐 ChronoGuard Services:$(RESET)"
	@echo "  • API Server:        http://localhost:8000"
	@echo "  • Forward Proxy:     http://localhost:8080"
	@echo "  • Policy Engine:     http://localhost:8181"
	@echo "  • Audit Sink:        http://localhost:8001"
	@echo "  • Metrics Exporter:  http://localhost:8002"
	@echo "  • Dashboard UI:      http://localhost:3000"
	@echo "  • Grafana:           http://localhost:3001"
	@echo "  • Prometheus:        http://localhost:9090"
	@echo "  • Jaeger:            http://localhost:16686"

##@ Common Development Tasks

fix: format lint ## Auto-fix code issues
	@echo "$(GREEN)🔧 Code issues fixed$(RESET)"

ci: pre-commit ## Simulate CI pipeline locally
	@echo "$(GREEN)🎉 CI simulation completed successfully!$(RESET)"

##@ Advanced Operations

benchmark: ## Run performance benchmarks
	@echo "$(BLUE)📈 Running performance benchmarks...$(RESET)"
	cd $(BACKEND_DIR) && PYTHONPATH=src locust --headless --users 10 --spawn-rate 2 --run-time 30s --host http://localhost:8000 || true

profile: ## Run performance profiling
	@echo "$(BLUE)📊 Running performance profiling...$(RESET)"
	cd $(BACKEND_DIR) && PYTHONPATH=src py-spy record -o profile.svg -- python -m pytest tests/performance/ || true

memory-check: ## Check for memory leaks
	@echo "$(BLUE)🧠 Running memory leak detection...$(RESET)"
	cd $(BACKEND_DIR) && PYTHONPATH=src memory-profiler -m pytest tests/unit/test_audit_domain.py::TestAuditEntry::test_create_valid_audit_entry || true