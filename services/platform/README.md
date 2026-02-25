# Platform Services

Core infrastructure services that provide the foundation for the OpenDirectory UEM platform.

## 🚀 Services

### API Gateway (`api-gateway/`)
**Auto-extending API Gateway with service discovery**

- **Purpose**: Central entry point for all services
- **Features**:
  - Automatic service discovery (scans ports 3001-3008+)
  - Load balancing (Round-Robin, Least-Connections, Weighted)
  - Circuit breaker pattern for resilience
  - JWT authentication and token forwarding
  - WebSocket gateway for real-time communication
  - Rate limiting and security middleware
  - Health monitoring and metrics collection

- **Ports**: 3000 (HTTP), 3001 (WebSocket)
- **Dependencies**: Redis

### API Backend (`api-backend/`)
**Main REST API backend**

- **Purpose**: Core REST API endpoints
- **Features**:
  - Device management endpoints
  - User management endpoints
  - Policy management endpoints
  - Application store endpoints
  - Real-time WebSocket support

- **Port**: 8080
- **Dependencies**: Database, Authentication Service

### Integration Service (`integration-service/`)
**External system integrations**

- **Purpose**: Connect with external enterprise systems
- **Integrations**:
  - LDAP/LLDAP user directory
  - Grafana monitoring dashboards  
  - Prometheus metrics collection
  - Vault secrets management

- **Port**: 4000
- **Dependencies**: External systems

## 🔄 Service Discovery

The API Gateway automatically discovers and registers services that:

1. **Expose `/health` endpoint** with service metadata
2. **Run on standard ports** (3001-3008+)
3. **Return proper health response**:
   ```json
   {
     "status": "healthy",
     "service": "my-service",
     "version": "1.0.0",
     "capabilities": ["feature1", "feature2"],
     "uptime": 12345
   }
   ```

## 🚀 Quick Start

### Start All Platform Services
```bash
cd services/platform
docker-compose up -d
```

### Start Individual Services
```bash
# API Gateway
cd api-gateway && npm start

# API Backend  
cd api-backend && npm start

# Integration Service
cd integration-service && npm start
```

## 🔧 Configuration

### Environment Variables
```bash
# API Gateway
API_GATEWAY_PORT=3000
REDIS_HOST=localhost
REDIS_PORT=6379

# API Backend
API_BACKEND_PORT=8080
DATABASE_URL=postgresql://...

# Integration Service
INTEGRATION_PORT=4000
LLDAP_URL=http://localhost:17170
GRAFANA_URL=http://localhost:3000
```

## 📊 Health Monitoring

Check platform health:
```bash
# Gateway health
curl http://localhost:3000/health

# Backend health
curl http://localhost:8080/health

# Integration health
curl http://localhost:4000/health
```

## 📚 Documentation

- [API Gateway Documentation](api-gateway/DOCUMENTATION.md)
- [API Backend Documentation](api-backend/README.md)
- [Integration Service Documentation](integration-service/README.md)