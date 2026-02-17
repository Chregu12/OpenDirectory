# OpenDirectory Makefile
# Simplifies common development tasks

.PHONY: help install dev build test deploy clean

# Colors for terminal output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)OpenDirectory - Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

install: ## Install all dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	@npm install --prefix services/identity-service
	@npm install --prefix services/auth-service
	@npm install --prefix services/device-service
	@npm install --prefix services/policy-service
	@npm install --prefix frontend/web-app
	@echo "$(GREEN)Dependencies installed!$(NC)"

dev: ## Start development environment
	@echo "$(GREEN)Starting development environment...$(NC)"
	docker-compose up -d postgres redis mongodb rabbitmq lldap
	@echo "$(YELLOW)Waiting for databases to be ready...$(NC)"
	@sleep 10
	@echo "$(GREEN)Development environment ready!$(NC)"
	@echo "PostgreSQL: localhost:5432"
	@echo "Redis: localhost:6379"
	@echo "MongoDB: localhost:27017"
	@echo "RabbitMQ: localhost:15672"
	@echo "LLDAP: localhost:17170"

dev-full: ## Start full development stack
	@echo "$(GREEN)Starting full development stack...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Full stack started!$(NC)"
	@echo "Web App: http://localhost:3000"
	@echo "API Gateway: http://localhost"
	@echo "Traefik Dashboard: http://localhost:8080"
	@echo "Authentik: http://localhost:9000"
	@echo "Keycloak: http://localhost:8180"
	@echo "Grafana: http://localhost:3500"

build: ## Build all services
	@echo "$(GREEN)Building all services...$(NC)"
	docker-compose build --parallel
	@echo "$(GREEN)Build complete!$(NC)"

test: ## Run all tests
	@echo "$(GREEN)Running tests...$(NC)"
	@npm test --prefix services/identity-service
	@npm test --prefix services/auth-service
	@npm test --prefix services/device-service
	@npm test --prefix services/policy-service
	@npm test --prefix frontend/web-app
	@echo "$(GREEN)All tests passed!$(NC)"

test-unit: ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(NC)"
	@npm run test:unit --prefix services/identity-service
	@npm run test:unit --prefix services/auth-service

test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(NC)"
	@npm run test:integration --prefix services/identity-service
	@npm run test:integration --prefix services/auth-service

test-e2e: ## Run end-to-end tests
	@echo "$(GREEN)Running e2e tests...$(NC)"
	@npm run test:e2e --prefix frontend/web-app

lint: ## Run linters
	@echo "$(GREEN)Running linters...$(NC)"
	@npm run lint --prefix services/identity-service
	@npm run lint --prefix services/auth-service
	@npm run lint --prefix frontend/web-app

format: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	@npm run format --prefix services/identity-service
	@npm run format --prefix services/auth-service
	@npm run format --prefix frontend/web-app

migrate: ## Run database migrations
	@echo "$(GREEN)Running database migrations...$(NC)"
	@npm run migrate --prefix services/identity-service
	@npm run migrate --prefix services/auth-service
	@npm run migrate --prefix services/policy-service

seed: ## Seed databases with test data
	@echo "$(GREEN)Seeding databases...$(NC)"
	@npm run seed --prefix services/identity-service
	@npm run seed --prefix services/device-service

logs: ## Show logs for all services
	docker-compose logs -f

logs-service: ## Show logs for specific service (usage: make logs-service SERVICE=identity-service)
	docker-compose logs -f $(SERVICE)

stop: ## Stop all services
	@echo "$(RED)Stopping all services...$(NC)"
	docker-compose down
	@echo "$(GREEN)Services stopped!$(NC)"

clean: ## Clean up everything (containers, volumes, node_modules)
	@echo "$(RED)Cleaning up...$(NC)"
	docker-compose down -v
	rm -rf services/*/node_modules
	rm -rf frontend/*/node_modules
	rm -rf services/*/dist
	rm -rf frontend/*/.next
	@echo "$(GREEN)Cleanup complete!$(NC)"

reset: clean install ## Reset everything and reinstall
	@echo "$(GREEN)Reset complete!$(NC)"

# Kubernetes commands
k8s-deploy: ## Deploy to Kubernetes
	@echo "$(GREEN)Deploying to Kubernetes...$(NC)"
	kubectl apply -k infrastructure/kubernetes/
	@echo "$(GREEN)Deployment complete!$(NC)"

k8s-delete: ## Delete from Kubernetes
	@echo "$(RED)Deleting from Kubernetes...$(NC)"
	kubectl delete -k infrastructure/kubernetes/
	@echo "$(GREEN)Deletion complete!$(NC)"

k8s-status: ## Check Kubernetes deployment status
	@echo "$(GREEN)Checking deployment status...$(NC)"
	kubectl get pods -n opendirectory
	kubectl get svc -n opendirectory
	kubectl get ingress -n opendirectory

# Docker commands
docker-push: ## Push images to registry
	@echo "$(GREEN)Pushing images to registry...$(NC)"
	docker-compose push
	@echo "$(GREEN)Push complete!$(NC)"

# Development helpers
create-service: ## Create a new microservice (usage: make create-service NAME=my-service)
	@echo "$(GREEN)Creating new service: $(NAME)...$(NC)"
	@mkdir -p services/$(NAME)
	@cp -r templates/service/* services/$(NAME)/
	@echo "$(GREEN)Service $(NAME) created!$(NC)"

create-domain: ## Create a new domain (usage: make create-domain NAME=my-domain)
	@echo "$(GREEN)Creating new domain: $(NAME)...$(NC)"
	@mkdir -p domains/$(NAME)/{domain,application,infrastructure,presentation}
	@echo "$(GREEN)Domain $(NAME) created!$(NC)"

# Documentation
docs: ## Generate documentation
	@echo "$(GREEN)Generating documentation...$(NC)"
	@npm run docs --prefix services/identity-service
	@npm run docs --prefix frontend/web-app
	@echo "$(GREEN)Documentation generated!$(NC)"

# Monitoring
monitor: ## Open monitoring dashboards
	@echo "$(GREEN)Opening monitoring dashboards...$(NC)"
	@open http://localhost:3500 # Grafana
	@open http://localhost:9090 # Prometheus
	@open http://localhost:15672 # RabbitMQ

# Health checks
health: ## Check health of all services
	@echo "$(GREEN)Checking service health...$(NC)"
	@curl -s http://localhost:3001/health | jq '.' || echo "Identity Service: $(RED)Down$(NC)"
	@curl -s http://localhost:3002/health | jq '.' || echo "Auth Service: $(RED)Down$(NC)"
	@curl -s http://localhost:3003/health | jq '.' || echo "Device Service: $(RED)Down$(NC)"
	@curl -s http://localhost:3004/health | jq '.' || echo "Policy Service: $(RED)Down$(NC)"

# Version management
version: ## Show current version
	@echo "$(GREEN)OpenDirectory Version:$(NC)"
	@cat VERSION

release: ## Create a new release (usage: make release VERSION=1.0.0)
	@echo "$(GREEN)Creating release $(VERSION)...$(NC)"
	@echo $(VERSION) > VERSION
	@git add .
	@git commit -m "Release v$(VERSION)"
	@git tag -a v$(VERSION) -m "Release v$(VERSION)"
	@echo "$(GREEN)Release v$(VERSION) created!$(NC)"
	@echo "$(YELLOW)Don't forget to push: git push origin main --tags$(NC)"