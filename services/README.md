# 🚀 OpenDirectory Services

Consolidated service architecture for the OpenDirectory Universal Endpoint Management platform.

## 📁 Service Organization

```
services/
├── platform/          # Platform infrastructure services
│   ├── api-gateway/   # Auto-extending API Gateway
│   ├── api-backend/   # Main REST API backend
│   └── integration-service/ # External integrations
├── core/              # Core business services
├── enterprise/        # Enterprise-grade services (50+ services)
├── domains/           # Domain-Driven Design bounded contexts
└── service-manager.sh # Service management script
```

## 🏗️ Architecture Overview

### Platform Services (`/platform`)
Core infrastructure services that provide the foundation:
- **api-gateway** - Auto-extending API Gateway with service discovery
- **api-backend** - Main REST API backend  
- **integration-service** - External system integrations

### Core Services (`/core`)
Essential platform services including:
- **auth-service** - Authentication and authorization
- **device-service** - Device management core
- **policy-service** - Policy engine core
- **identity-service** - Identity management
- **gateway-service** - API gateway
- **notification-service** - Notification system
- **deployment-service** - Deployment orchestration

### Enterprise Services (`/enterprise`)
Advanced enterprise capabilities:
- **AI Analytics** - Machine learning and predictive analytics
- **Security Framework** - Zero-trust, PAM, DLP, threat intelligence
- **Automation** - Workflow engine, NLP interface, task scheduler
- **Multi-Tenancy** - Complete tenant isolation and management
- **Disaster Recovery** - Business continuity and geo-replication
- **Certificate Management** - Full PKI infrastructure
- **Container Management** - Kubernetes and cloud orchestration

### Domain Services (`/domains`)
Domain-Driven Design bounded contexts:
- **identity** - User and identity domain
- **device-management** - Device lifecycle management
- **policy-engine** - Policy definition and enforcement
- **application-delivery** - Application deployment
- **audit** - Audit and compliance
- **authentication** - Authentication mechanisms
- **authorization** - Access control


## 🔧 Service Communication

### Internal Communication
- **Event Bus** - Asynchronous event-driven communication
- **gRPC** - High-performance service-to-service calls
- **REST** - Standard HTTP/JSON APIs

### External Communication
- **REST API** - Public API endpoints
- **WebSocket** - Real-time updates
- **GraphQL** - Flexible query interface (planned)

## 🚀 Deployment

### Docker Compose
```bash
docker-compose up -d
```

### Kubernetes
```bash
kubectl apply -f infrastructure/kubernetes/
```

### Individual Services
Each service can be run independently:
```bash
cd services/[service-name]
npm install
npm start
```

## 📊 Service Metrics

| Category | Services | Purpose |
|----------|----------|---------|
| Platform | 3 | Infrastructure and gateway services |
| Core | 10 | Essential platform functionality |
| Enterprise | 50+ | Advanced enterprise features |
| Domains | 7 | Business logic separation |

## 🔒 Security

All services implement:
- JWT-based authentication
- Role-based access control (RBAC)
- TLS encryption for all communications
- Audit logging
- Security scanning
- Container security best practices

## 📈 Scalability

- **Horizontal Scaling** - All services support multiple instances
- **Load Balancing** - Automatic load distribution
- **Auto-scaling** - Kubernetes HPA support
- **Caching** - Redis-based caching layer
- **Database Sharding** - Supported for large deployments

## 🧪 Testing

```bash
# Run all service tests
npm run test:all

# Run specific service tests
cd services/[service-name]
npm test
```

## 📚 Documentation

Detailed documentation for each service is available in their respective directories:
- [Platform Services](./platform/README.md)
- [Core Services](./core/README.md)
- [Enterprise Services](./enterprise/README.md)
- [Domain Services](./domains/README.md)

## 🤝 Contributing

When adding new services:
1. Choose the appropriate category (core/enterprise/domains)
2. Follow the service template structure
3. Implement standard interfaces
4. Add comprehensive tests
5. Update this documentation

## 📄 License

Part of the OpenDirectory UEM Platform - Enterprise-grade endpoint management solution.