# OpenDirectory Service Integration Agent

A comprehensive integration service that provides native embedding of external services into the OpenDirectory platform, eliminating the need for external links and creating a unified user experience.

## Overview

This integration service provides API proxies and embedded UI components for:

- **LLDAP (User Directory)** - Port 30170: User and group management
- **Grafana (Monitoring)** - Port 30300: Embedded dashboards and visualizations
- **Prometheus (Metrics)** - Port 30909: Metrics collection and analysis
- **Vault (Secrets)** - Port 30820: Secret management and storage

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     OpenDirectory Frontend                     │
│                        (Next.js App)                           │
├─────────────────────────────────────────────────────────────────┤
│                  Integration Service API                       │
│                     (Express.js)                               │
├─────────────────────────────────────────────────────────────────┤
│     LLDAP    │    Grafana    │   Prometheus   │     Vault      │
│   :30170     │    :30300     │     :30909     │    :30820      │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### LLDAP Integration
- User and group management through native UI components
- Real-time user search and filtering
- Group membership management
- LDAP authentication validation
- User statistics and analytics

### Grafana Integration
- Embedded dashboards using iframe integration
- Custom OpenDirectory dashboard creation
- Theme and time range controls
- Panel-level embedding for specific metrics
- Automatic dashboard provisioning

### Prometheus Integration
- Native metrics visualization with Recharts
- Real-time KPI displays
- Custom query execution
- Service health monitoring
- Time series data visualization

### Vault Integration
- Secret management through native UI
- Service credential storage
- API key management
- Health and seal status monitoring
- Secure secret creation and deletion

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 20+ (for development)
- Git

### 1. Clone and Setup

```bash
git clone <repository-url>
cd opendirectory
```

### 2. Environment Configuration

Create a `.env` file in the root directory:

```bash
# Database
DB_PASSWORD=your_secure_password

# LLDAP
LLDAP_ADMIN_PASSWORD=admin_password
LLDAP_JWT_SECRET=your_jwt_secret

# Grafana
GRAFANA_PASSWORD=grafana_admin_password

# Vault
VAULT_ROOT_TOKEN=your_vault_root_token

# Redis
REDIS_PASSWORD=redis_password

# RabbitMQ
RABBITMQ_PASSWORD=rabbitmq_password

# Node Environment
NODE_ENV=development
LOG_LEVEL=info
```

### 3. Start Services

```bash
# Build and start all services
docker-compose up -d

# Check service health
docker-compose ps
```

### 4. Access Services

- **OpenDirectory Dashboard**: http://localhost:3000
- **Integration Service API**: http://localhost:3005
- **Direct Service Access**:
  - LLDAP: http://localhost:30170
  - Grafana: http://localhost:30300
  - Prometheus: http://localhost:30909
  - Vault: http://localhost:30820

## API Endpoints

### Health Checks

```bash
# Overall health
GET /health

# Individual service health
GET /health/lldap
GET /health/grafana  
GET /health/prometheus
GET /health/vault
```

### LLDAP API

```bash
# Users
GET /api/lldap/users
GET /api/lldap/users/:userId
POST /api/lldap/users
PUT /api/lldap/users/:userId
DELETE /api/lldap/users/:userId

# Groups
GET /api/lldap/groups
GET /api/lldap/groups/:groupId

# Statistics
GET /api/lldap/stats
```

### Grafana API

```bash
# Dashboards
GET /api/grafana/dashboards
GET /api/grafana/dashboards/opendirectory
GET /api/grafana/dashboards/uid/:uid

# Embed URLs
GET /api/grafana/embed/dashboard/:uid
GET /api/grafana/embed/panel/:uid/:panelId

# Setup
POST /api/grafana/setup/opendirectory
```

### Prometheus API

```bash
# Queries
GET /api/prometheus/query?query=:query
GET /api/prometheus/query_range

# Metrics
GET /api/prometheus/service-metrics
GET /api/prometheus/system-metrics
GET /api/prometheus/kpis
GET /api/prometheus/timeseries
```

### Vault API

```bash
# Secrets
GET /api/vault/secrets
GET /api/vault/secrets/:path
PUT /api/vault/secrets/:path
DELETE /api/vault/secrets/:path

# System
GET /api/vault/sys/health
GET /api/vault/sys/seal-status

# OpenDirectory specific
GET /api/vault/opendirectory/secrets
GET /api/vault/opendirectory/services/:service/credentials
```

## Development

### Project Structure

```
services/integration-service/
├── src/
│   ├── config/          # Service configurations
│   ├── lib/             # Utilities (HTTP client, logger)
│   ├── routes/          # API route handlers
│   ├── services/        # Service integration classes
│   └── types/           # TypeScript type definitions
├── package.json
├── tsconfig.json
└── Dockerfile

frontend/web-app/
├── src/
│   ├── app/             # Next.js app pages
│   ├── components/      # React components
│   │   └── integrations/ # Service integration components
│   └── lib/             # API client and utilities
├── package.json
├── next.config.js
└── Dockerfile
```

### Local Development

1. **Start backend services**:
```bash
docker-compose up -d postgres redis mongodb rabbitmq lldap prometheus grafana vault
```

2. **Run integration service**:
```bash
cd services/integration-service
npm install
npm run dev
```

3. **Run frontend**:
```bash
cd frontend/web-app
npm install
npm run dev
```

### Running Tests

```bash
# Integration service tests
cd services/integration-service
npm test

# Frontend tests
cd frontend/web-app
npm test
```

## Configuration

### Service URLs

The integration service automatically detects service locations using the following priority:

1. Environment variables
2. Docker Compose service names (internal networking)
3. Default localhost ports (development)

### Security

- All API endpoints support authentication via JWT tokens
- Service credentials are securely stored in Vault
- CORS is configured for the frontend domain
- Rate limiting is applied to prevent abuse

### Monitoring

- Health checks on all integrated services
- Prometheus metrics collection
- Structured logging with Pino
- Error tracking and reporting

## Troubleshooting

### Common Issues

1. **Services not accessible**:
   - Check if all containers are running: `docker-compose ps`
   - Verify port mappings in docker-compose.yml
   - Check service logs: `docker-compose logs <service-name>`

2. **Integration service connection errors**:
   - Verify environment variables are set correctly
   - Check network connectivity between containers
   - Review integration service logs: `docker-compose logs integration-service`

3. **Frontend not loading integrations**:
   - Ensure integration service is running on port 3005
   - Check browser network tab for API errors
   - Verify CORS configuration

### Health Monitoring

```bash
# Check integration service health
curl http://localhost:3005/health

# Individual service health
curl http://localhost:3005/health/lldap
curl http://localhost:3005/health/grafana
curl http://localhost:3005/health/prometheus
curl http://localhost:3005/health/vault
```

### Logs

```bash
# View all service logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f integration-service
docker-compose logs -f web-app
```

## Production Deployment

### Environment Variables

Set the following for production:

```bash
NODE_ENV=production
LOG_LEVEL=warn
API_URL=https://your-domain/api
CORS_ORIGINS=https://your-domain

# Use strong passwords and secrets
DB_PASSWORD=strong_production_password
LLDAP_ADMIN_PASSWORD=strong_admin_password
VAULT_ROOT_TOKEN=production_vault_token
```

### Security Considerations

1. Use HTTPS in production
2. Set strong passwords for all services
3. Configure proper firewall rules
4. Enable Vault TLS and authentication
5. Use production-grade databases (not dev mode)

### Scaling

- Run multiple instances of the integration service behind a load balancer
- Use external databases (PostgreSQL, MongoDB)
- Configure Redis clustering for session storage
- Use container orchestration (Kubernetes) for automatic scaling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see LICENSE file for details.