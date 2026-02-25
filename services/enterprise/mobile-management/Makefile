# OpenDirectory Mobile Management Suite Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help install start stop restart status clean test build deploy logs health

# Default target
.DEFAULT_GOAL := help

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
MAGENTA := \033[35m
CYAN := \033[36m
RESET := \033[0m

# Service configuration
SERVICES := ios android mam mtd
DOCKER_COMPOSE_FILE := docker-compose.yml
PROJECT_NAME := mobile-management

help: ## Show this help message
	@echo "$(CYAN)OpenDirectory Mobile Management Suite$(RESET)"
	@echo "$(CYAN)====================================$(RESET)"
	@echo ""
	@echo "$(GREEN)Available commands:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(GREEN)Service management:$(RESET)"
	@echo "  $(BLUE)start-ios$(RESET)           Start iOS Management Service"
	@echo "  $(BLUE)start-android$(RESET)       Start Android Enterprise Service"
	@echo "  $(BLUE)start-mam$(RESET)           Start Mobile App Management Service"
	@echo "  $(BLUE)start-mtd$(RESET)           Start Mobile Threat Defense Service"
	@echo ""
	@echo "$(GREEN)Docker commands:$(RESET)"
	@echo "  $(BLUE)docker-build$(RESET)        Build Docker images"
	@echo "  $(BLUE)docker-up$(RESET)           Start all services with Docker"
	@echo "  $(BLUE)docker-down$(RESET)         Stop all Docker services"
	@echo "  $(BLUE)docker-restart$(RESET)      Restart Docker services"

install: ## Install dependencies
	@echo "$(YELLOW)Installing dependencies...$(RESET)"
	npm install
	@echo "$(GREEN)Dependencies installed successfully!$(RESET)"

start: ## Start all mobile management services
	@echo "$(YELLOW)Starting Mobile Management Suite...$(RESET)"
	npm run start:all

start-ios: ## Start iOS Management Service
	@echo "$(YELLOW)Starting iOS Management Service...$(RESET)"
	npm run start:ios

start-android: ## Start Android Enterprise Service
	@echo "$(YELLOW)Starting Android Enterprise Service...$(RESET)"
	npm run start:android

start-mam: ## Start Mobile App Management Service
	@echo "$(YELLOW)Starting Mobile App Management Service...$(RESET)"
	npm run start:mam

start-mtd: ## Start Mobile Threat Defense Service
	@echo "$(YELLOW)Starting Mobile Threat Defense Service...$(RESET)"
	npm run start:mtd

dev: ## Start all services in development mode
	@echo "$(YELLOW)Starting services in development mode...$(RESET)"
	npm run dev

stop: ## Stop all running services
	@echo "$(YELLOW)Stopping all services...$(RESET)"
	@pkill -f "ios-management-service\|android-enterprise-service\|mobile-app-management-service\|mobile-threat-defense-service" || true
	@echo "$(GREEN)All services stopped!$(RESET)"

restart: stop start ## Restart all services

status: ## Check status of all services
	@echo "$(CYAN)Mobile Management Suite Status$(RESET)"
	@echo "$(CYAN)==============================$(RESET)"
	@echo ""
	@echo "$(YELLOW)Checking service ports...$(RESET)"
	@for port in 3011 3012 3013 3014; do \
		if lsof -i :$$port >/dev/null 2>&1; then \
			echo "  Port $$port: $(GREEN)✓ Active$(RESET)"; \
		else \
			echo "  Port $$port: $(RED)✗ Inactive$(RESET)"; \
		fi; \
	done
	@echo ""
	@echo "$(YELLOW)Service Health Checks...$(RESET)"
	@$(MAKE) health

health: ## Perform health checks on all services
	@for port in 3011 3012 3013 3014; do \
		echo -n "  Port $$port health: "; \
		if curl -s -f http://localhost:$$port/health >/dev/null 2>&1; then \
			echo "$(GREEN)✓ Healthy$(RESET)"; \
		else \
			echo "$(RED)✗ Unhealthy$(RESET)"; \
		fi; \
	done

test: ## Run all tests
	@echo "$(YELLOW)Running test suite...$(RESET)"
	npm test
	@echo "$(GREEN)Tests completed!$(RESET)"

test-unit: ## Run unit tests
	@echo "$(YELLOW)Running unit tests...$(RESET)"
	npm run test:unit

test-integration: ## Run integration tests
	@echo "$(YELLOW)Running integration tests...$(RESET)"
	npm run test:integration

test-e2e: ## Run end-to-end tests
	@echo "$(YELLOW)Running end-to-end tests...$(RESET)"
	npm run test:e2e

coverage: ## Generate test coverage report
	@echo "$(YELLOW)Generating coverage report...$(RESET)"
	npm run test:coverage
	@echo "$(GREEN)Coverage report generated in ./coverage/$(RESET)"

lint: ## Run linting
	@echo "$(YELLOW)Running linter...$(RESET)"
	npm run lint
	@echo "$(GREEN)Linting completed!$(RESET)"

lint-fix: ## Fix linting issues automatically
	@echo "$(YELLOW)Fixing linting issues...$(RESET)"
	npm run lint:fix
	@echo "$(GREEN)Linting fixes applied!$(RESET)"

clean: ## Clean up temporary files and caches
	@echo "$(YELLOW)Cleaning up...$(RESET)"
	rm -rf node_modules/.cache
	rm -rf /tmp/mam-apps/*
	rm -rf logs/*.log
	npm cache clean --force
	@echo "$(GREEN)Cleanup completed!$(RESET)"

build: ## Build the application
	@echo "$(YELLOW)Building application...$(RESET)"
	npm run build
	@echo "$(GREEN)Build completed!$(RESET)"

# Docker commands
docker-build: ## Build Docker images
	@echo "$(YELLOW)Building Docker images...$(RESET)"
	docker-compose build
	@echo "$(GREEN)Docker images built successfully!$(RESET)"

docker-up: ## Start services with Docker Compose
	@echo "$(YELLOW)Starting services with Docker Compose...$(RESET)"
	docker-compose up -d
	@echo "$(GREEN)Services started successfully!$(RESET)"
	@echo ""
	@echo "$(CYAN)Service URLs:$(RESET)"
	@echo "  iOS Management:      http://localhost:3011"
	@echo "  Android Enterprise:  http://localhost:3012"
	@echo "  Mobile App Mgmt:     http://localhost:3013"
	@echo "  Mobile Threat Def:   http://localhost:3014"
	@echo "  Proxy (All Services): http://localhost:3010"

docker-down: ## Stop Docker services
	@echo "$(YELLOW)Stopping Docker services...$(RESET)"
	docker-compose down
	@echo "$(GREEN)Docker services stopped!$(RESET)"

docker-restart: docker-down docker-up ## Restart Docker services

docker-logs: ## Show Docker service logs
	@echo "$(YELLOW)Showing Docker logs...$(RESET)"
	docker-compose logs -f

docker-logs-ios: ## Show iOS service logs
	@docker-compose logs -f ios-management

docker-logs-android: ## Show Android service logs
	@docker-compose logs -f android-enterprise

docker-logs-mam: ## Show MAM service logs
	@docker-compose logs -f mobile-app-management

docker-logs-mtd: ## Show MTD service logs
	@docker-compose logs -f mobile-threat-defense

docker-shell: ## Open shell in service container
	@echo "$(YELLOW)Available services: ios-management, android-enterprise, mobile-app-management, mobile-threat-defense$(RESET)"
	@read -p "Enter service name: " service; \
	docker-compose exec $$service /bin/sh

docker-status: ## Show Docker service status
	@echo "$(CYAN)Docker Service Status$(RESET)"
	@echo "$(CYAN)====================$(RESET)"
	@docker-compose ps

docker-clean: ## Clean up Docker resources
	@echo "$(YELLOW)Cleaning up Docker resources...$(RESET)"
	docker-compose down --volumes --rmi all
	docker system prune -f
	@echo "$(GREEN)Docker cleanup completed!$(RESET)"

# Deployment commands
deploy-dev: ## Deploy to development environment
	@echo "$(YELLOW)Deploying to development environment...$(RESET)"
	@$(MAKE) docker-build
	@$(MAKE) docker-up
	@echo "$(GREEN)Development deployment completed!$(RESET)"

deploy-staging: ## Deploy to staging environment
	@echo "$(YELLOW)Deploying to staging environment...$(RESET)"
	@echo "$(RED)Staging deployment not implemented yet$(RESET)"

deploy-prod: ## Deploy to production environment
	@echo "$(YELLOW)Deploying to production environment...$(RESET)"
	@echo "$(RED)Production deployment requires additional configuration$(RESET)"

# Monitoring commands
logs: ## Show application logs
	@echo "$(YELLOW)Showing application logs...$(RESET)"
	@if [ -d "logs" ]; then \
		tail -f logs/*.log; \
	else \
		echo "$(RED)No log directory found$(RESET)"; \
	fi

logs-error: ## Show error logs only
	@echo "$(YELLOW)Showing error logs...$(RESET)"
	@if [ -d "logs" ]; then \
		tail -f logs/*.log | grep -i error; \
	else \
		echo "$(RED)No log directory found$(RESET)"; \
	fi

monitor: ## Start real-time monitoring
	@echo "$(YELLOW)Starting real-time monitoring...$(RESET)"
	@echo "$(CYAN)Press Ctrl+C to stop monitoring$(RESET)"
	@echo ""
	@while true; do \
		clear; \
		echo "$(CYAN)Mobile Management Suite - Live Monitor$(RESET)"; \
		echo "$(CYAN)=====================================$(RESET)"; \
		echo ""; \
		$(MAKE) status --no-print-directory; \
		echo ""; \
		echo "$(YELLOW)Last updated: $$(date)$(RESET)"; \
		sleep 10; \
	done

# Security commands
security-scan: ## Run security vulnerability scan
	@echo "$(YELLOW)Running security vulnerability scan...$(RESET)"
	npm audit
	@echo "$(GREEN)Security scan completed!$(RESET)"

security-fix: ## Fix security vulnerabilities
	@echo "$(YELLOW)Fixing security vulnerabilities...$(RESET)"
	npm audit fix
	@echo "$(GREEN)Security fixes applied!$(RESET)"

# Database commands
db-setup: ## Set up database
	@echo "$(YELLOW)Setting up database...$(RESET)"
	@echo "$(RED)Database setup not implemented yet$(RESET)"

db-migrate: ## Run database migrations
	@echo "$(YELLOW)Running database migrations...$(RESET)"
	@echo "$(RED)Database migrations not implemented yet$(RESET)"

db-seed: ## Seed database with test data
	@echo "$(YELLOW)Seeding database with test data...$(RESET)"
	@echo "$(RED)Database seeding not implemented yet$(RESET)"

# Backup commands
backup: ## Create backup of application data
	@echo "$(YELLOW)Creating backup...$(RESET)"
	@timestamp=$$(date +%Y%m%d_%H%M%S); \
	backup_dir="backups/backup_$$timestamp"; \
	mkdir -p $$backup_dir; \
	cp -r data/ $$backup_dir/ 2>/dev/null || true; \
	cp -r certificates/ $$backup_dir/ 2>/dev/null || true; \
	cp -r logs/ $$backup_dir/ 2>/dev/null || true; \
	cp .env $$backup_dir/ 2>/dev/null || true; \
	echo "$(GREEN)Backup created at $$backup_dir$(RESET)"

restore: ## Restore from backup
	@echo "$(YELLOW)Available backups:$(RESET)"
	@ls -la backups/ 2>/dev/null || echo "$(RED)No backups found$(RESET)"
	@echo ""
	@echo "$(RED)Restore functionality requires manual implementation$(RESET)"

# Configuration commands
config-validate: ## Validate configuration
	@echo "$(YELLOW)Validating configuration...$(RESET)"
	@if [ -f ".env" ]; then \
		echo "$(GREEN)✓ .env file found$(RESET)"; \
		echo "$(YELLOW)Checking required variables...$(RESET)"; \
		@node -e " \
			require('dotenv').config(); \
			const required = ['NODE_ENV']; \
			const missing = required.filter(key => !process.env[key]); \
			if (missing.length > 0) { \
				console.log('$(RED)✗ Missing required variables:', missing.join(', ')); \
				process.exit(1); \
			} else { \
				console.log('$(GREEN)✓ All required variables present$(RESET)'); \
			} \
		"; \
	else \
		echo "$(RED)✗ .env file not found$(RESET)"; \
		echo "$(YELLOW)Creating from template...$(RESET)"; \
		cp .env.example .env; \
		echo "$(GREEN)✓ .env created from template$(RESET)"; \
	fi

config-edit: ## Edit configuration file
	@if [ -f ".env" ]; then \
		${EDITOR:-nano} .env; \
	else \
		echo "$(RED).env file not found$(RESET)"; \
	fi

# Performance commands
benchmark: ## Run performance benchmarks
	@echo "$(YELLOW)Running performance benchmarks...$(RESET)"
	@echo "$(RED)Benchmark functionality not implemented yet$(RESET)"

stress-test: ## Run stress tests
	@echo "$(YELLOW)Running stress tests...$(RESET)"
	@echo "$(RED)Stress test functionality not implemented yet$(RESET)"

# Documentation commands
docs: ## Generate documentation
	@echo "$(YELLOW)Generating documentation...$(RESET)"
	@echo "$(RED)Documentation generation not implemented yet$(RESET)"

api-docs: ## View API documentation
	@echo "$(YELLOW)Opening API documentation...$(RESET)"
	@echo "$(CYAN)API endpoints:$(RESET)"
	@echo "  iOS Management:      http://localhost:3011/api/ios"
	@echo "  Android Enterprise:  http://localhost:3012/api/android"
	@echo "  Mobile App Mgmt:     http://localhost:3013/api/mam"
	@echo "  Mobile Threat Def:   http://localhost:3014/api/mtd"
	@echo ""
	@echo "$(CYAN)Health checks:$(RESET)"
	@echo "  http://localhost:3011/health"
	@echo "  http://localhost:3012/health"
	@echo "  http://localhost:3013/health"
	@echo "  http://localhost:3014/health"

# Quick commands
quick-start: install start ## Quick start for development
	@echo "$(GREEN)Quick start completed!$(RESET)"

quick-docker: docker-build docker-up ## Quick Docker deployment
	@echo "$(GREEN)Quick Docker deployment completed!$(RESET)"

quick-test: install test ## Quick test run
	@echo "$(GREEN)Quick test completed!$(RESET)"

version: ## Show version information
	@echo "$(CYAN)OpenDirectory Mobile Management Suite$(RESET)"
	@echo "$(CYAN)====================================$(RESET)"
	@echo "Version: $(GREEN)1.0.0$(RESET)"
	@echo "Node.js: $(YELLOW)$$(node --version)$(RESET)"
	@echo "npm: $(YELLOW)$$(npm --version)$(RESET)"
	@if command -v docker >/dev/null 2>&1; then \
		echo "Docker: $(YELLOW)$$(docker --version | cut -d' ' -f3 | cut -d',' -f1)$(RESET)"; \
	fi
	@if command -v docker-compose >/dev/null 2>&1; then \
		echo "Docker Compose: $(YELLOW)$$(docker-compose --version | cut -d' ' -f3 | cut -d',' -f1)$(RESET)"; \
	fi