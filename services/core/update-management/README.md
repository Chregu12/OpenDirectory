# OpenDirectory Update Management Service

A comprehensive update management and remote device actions service for the OpenDirectory platform, providing enterprise-grade update deployment, mobile application management, and multi-tenant support.

## Features

### Update Management
- **Windows Update Management**: Windows Update for Business, WSUS-style policies, Group Policy integration
- **macOS Update Management**: Software Update, App Store, Homebrew package management
- **Linux Update Management**: APT, YUM, DNF, Snap, Flatpak support with unattended upgrades
- **Cross-platform Policy Management**: Unified policy creation and deployment across all platforms

### Remote Device Actions
- **Device Lock**: Remote lock with custom messages and passcode reset
- **Device Wipe**: Full, selective, and enterprise wipe capabilities
- **Device Restart**: Scheduled and immediate restart with user notifications
- **Device Locate**: GPS location retrieval with sound and message display
- **Lost Mode**: Enable lost mode with contact information
- **Key Rotation**: BitLocker/FileVault encryption key rotation
- **Policy Sync**: Force synchronization of policies and configurations

### Update Rings & Deployment
- **Staged Deployment**: Pilot, Early Adopters, Broad Deployment, Critical Systems
- **Approval Workflows**: Multi-step approval processes with escalation
- **Health Monitoring**: Real-time deployment health checks and rollback
- **Rollout Control**: Percentage-based, device-count, and time-based rollouts
- **Maintenance Windows**: Scheduled deployment during specified time windows

### Mobile Application Management (MAM)
- **Data Protection**: Prevent data loss, encryption, copy/paste restrictions
- **Application Protection**: App-level security policies without device enrollment
- **Conditional Access**: Risk-based access control and compliance checking
- **Selective Wipe**: Remove corporate data while preserving personal data
- **Cross-platform Support**: iOS, Android, Windows with native MDM integration

### Terms of Use Enforcement
- **Multi-platform Deployment**: Web, mobile, desktop with consistent experience
- **Acceptance Tracking**: Tamper-evident logging with digital signatures
- **Compliance Monitoring**: Real-time compliance checking and reporting
- **Enforcement Actions**: Block access, temporary access, warning notifications
- **Multi-language Support**: Localized terms with acceptance tracking

### Multi-Tenant Management
- **Tenant Isolation**: Network, data, compute, and storage isolation levels
- **Resource Quotas**: Configurable limits for users, devices, storage, API calls
- **Custom Branding**: Tenant-specific branding and custom domains
- **Service Configuration**: Feature-level enablement per tenant
- **Infrastructure Automation**: Terraform, Kubernetes, Docker Compose support

## Quick Start

### Prerequisites
- Node.js 16+ 
- PostgreSQL 12+
- Redis 6+
- Docker (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/opendirectory/services.git
cd services/core/update-management

# Install dependencies
npm install

# Copy configuration template
cp src/config/development.json.example src/config/development.json

# Edit configuration
vim src/config/development.json

# Start the service
npm start
```

### Docker Deployment

```bash
# Build the image
docker build -t opendirectory/update-management .

# Run with Docker Compose
docker-compose up -d

# Or run standalone
docker run -p 3000:3000 -e DATABASE_URL=postgresql://... opendirectory/update-management
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Or use Helm
helm install update-management ./helm-chart
```

## Configuration

### Environment Variables

```bash
# Server Configuration
PORT=3000
HOST=0.0.0.0
NODE_ENV=production

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/opendirectory
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# Multi-tenant Configuration
ENABLE_MULTI_TENANT=true
DEFAULT_TENANT_ISOLATION_LEVEL=standard

# External Integrations
MICROSOFT_CLIENT_ID=your-client-id
MICROSOFT_CLIENT_SECRET=your-client-secret
APPLE_ORG_ID=your-org-id
GOOGLE_PROJECT_ID=your-project-id

# Monitoring
PROMETHEUS_ENABLED=true
APM_ENABLED=true
APM_SERVER_URL=https://apm.example.com

# Security
ENCRYPTION_REQUIRED=true
AUDIT_LOG_RETENTION=2555
REQUIRE_HTTPS=true
```

### Feature Flags

```bash
# Platform Support
FEATURE_WINDOWS_UPDATES=true
FEATURE_MACOS_UPDATES=true
FEATURE_LINUX_UPDATES=true
FEATURE_REMOTE_ACTIONS=true

# Advanced Features
FEATURE_UPDATE_RINGS=true
FEATURE_MAM=true
FEATURE_TERMS_OF_USE=true
FEATURE_MULTI_TENANT=true
FEATURE_ADVANCED_REPORTING=true
```

## API Documentation

The service provides a comprehensive REST API with OpenAPI 3.0 documentation available at `/api/v1/docs`.

### Authentication

All API endpoints require JWT authentication via the `Authorization` header:

```http
Authorization: Bearer <jwt-token>
```

### Example Requests

#### Create Windows Update Policy

```bash
curl -X POST http://localhost:3000/api/v1/updates/windows/policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Windows Updates",
    "description": "Standard Windows update policy for production systems",
    "featureUpdateDeferralDays": 30,
    "qualityUpdateDeferralDays": 7,
    "automaticMaintenance": true,
    "updateRing": "Production",
    "activeHoursStart": "08:00",
    "activeHoursEnd": "18:00"
  }'
```

#### Execute Remote Device Lock

```bash
curl -X POST http://localhost:3000/api/v1/remote-actions/lock \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "device-uuid-here",
    "message": "Device locked for security reasons",
    "phoneNumber": "+1234567890",
    "reason": "Security incident reported",
    "requireAdminUnlock": true
  }'
```

#### Create MAM Policy

```bash
curl -X POST http://localhost:3000/api/v1/mam/policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Corporate Data Protection",
    "type": "data-protection",
    "platform": "all",
    "preventDataLoss": true,
    "encryptAppData": true,
    "allowDataTransferTo": "managed-apps-only",
    "requirePinForAccess": true,
    "sessionTimeout": 30
  }'
```

## Architecture

### Service Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Gateway   │────│ Load Balancer   │────│  Update Mgmt    │
└─────────────────┘    └─────────────────┘    │    Service      │
                                              └─────────────────┘
                                                       │
                       ┌─────────────────┬─────────────┼─────────────────┐
                       │                 │             │                 │
           ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
           │    Windows      │  │     macOS       │  │     Linux       │
           │ Update Service  │  │ Update Service  │  │ Update Service  │
           └─────────────────┘  └─────────────────┘  └─────────────────┘
                       │                 │             │
           ┌─────────────────┬─────────────────┬─────────────────┐
           │                 │                 │                 │
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │   Remote    │  │   Update    │  │    MAM      │  │   Terms     │
    │  Actions    │  │   Rings     │  │  Service    │  │  Service    │
    └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
```

### Data Flow

1. **Policy Creation**: Administrators create update policies via REST API
2. **Device Assignment**: Devices are assigned to update rings based on criteria
3. **Deployment Orchestration**: Update rings manage staged deployment with approvals
4. **Agent Execution**: Platform-specific scripts execute on target devices
5. **Status Reporting**: Devices report back status and compliance information
6. **Audit Logging**: All actions are logged for compliance and security monitoring

### Multi-Tenant Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Tenant A      │    │   Tenant B      │    │   Tenant C      │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   Data    │  │    │  │   Data    │  │    │  │   Data    │  │
│  │ Isolation │  │    │  │ Isolation │  │    │  │ Isolation │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │ Compute   │  │    │  │ Compute   │  │    │  │ Compute   │  │
│  │Resources  │  │    │  │Resources  │  │    │  │Resources  │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Shared Service │
                    │  Infrastructure │
                    └─────────────────┘
```

## Platform-Specific Implementation

### Windows
- **PowerShell DSC**: Configuration management and policy enforcement
- **Group Policy**: Integration with existing AD infrastructure
- **WMI/WinRM**: Remote management and status reporting
- **Windows Update API**: Direct integration with Microsoft update services
- **WSUS Integration**: Support for existing WSUS infrastructure

### macOS
- **Configuration Profiles**: MDM-style configuration deployment
- **Swift/Objective-C**: Native tooling for system integration
- **Software Update API**: Direct integration with Apple update services
- **Homebrew Management**: Third-party package management
- **Apple Business Manager**: Enterprise device management integration

### Linux
- **Package Managers**: Native support for APT, YUM, DNF, Snap, Flatpak
- **Systemd Integration**: Service management and scheduling
- **Unattended Upgrades**: Automated security update installation
- **Configuration Management**: Ansible, Puppet, Chef integration support
- **Container Awareness**: Docker, Podman, Kubernetes support

## Security

### Authentication & Authorization
- JWT-based authentication with refresh tokens
- Role-based access control (RBAC) with fine-grained permissions
- Multi-factor authentication support
- API key authentication for service-to-service communication

### Data Protection
- End-to-end encryption for sensitive data
- At-rest encryption for database and file storage
- In-transit encryption with TLS 1.3
- Secure key management with rotation policies

### Audit & Compliance
- Comprehensive audit logging with tamper-evident chains
- GDPR, SOC 2, HIPAA compliance support
- Real-time security monitoring and alerting
- Automated compliance reporting

### Network Security
- IP allowlisting and geofencing
- Rate limiting and DDoS protection
- Network segmentation and micro-segmentation
- VPN and zero-trust network integration

## Monitoring & Observability

### Metrics
- Prometheus metrics with Grafana dashboards
- Application performance monitoring (APM)
- Real-time deployment success/failure rates
- Resource utilization and capacity planning

### Logging
- Structured logging with correlation IDs
- Centralized log aggregation (ELK, Splunk)
- Log retention and archival policies
- Security event monitoring and alerting

### Health Checks
- Application health endpoints
- Database connectivity monitoring
- External service dependency checking
- Kubernetes readiness and liveness probes

### Alerting
- PagerDuty, Slack, email integrations
- Threshold-based and anomaly detection alerts
- Escalation policies and on-call rotations
- SLA monitoring and reporting

## Development

### Local Development Setup

```bash
# Install dependencies
npm install

# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Run database migrations
npm run migrate

# Seed test data
npm run seed

# Start in development mode
npm run dev

# Run tests
npm test

# Run with coverage
npm run test:coverage
```

### Testing

```bash
# Unit tests
npm run test:unit

# Integration tests  
npm run test:integration

# End-to-end tests
npm run test:e2e

# Load testing
npm run test:load

# Security testing
npm run test:security
```

### Code Quality

```bash
# Linting
npm run lint
npm run lint:fix

# Type checking
npm run type-check

# Security audit
npm audit
npm run audit:fix

# Dependency checking
npm run deps:check
npm run deps:update
```

## Deployment

### Production Checklist

- [ ] Environment variables configured
- [ ] SSL/TLS certificates installed
- [ ] Database migrations applied
- [ ] External service integrations tested
- [ ] Security hardening applied
- [ ] Monitoring and alerting configured
- [ ] Backup and disaster recovery tested
- [ ] Load balancing configured
- [ ] Auto-scaling policies set
- [ ] Documentation updated

### Scaling Considerations

- **Horizontal Scaling**: Stateless service design enables easy horizontal scaling
- **Database Sharding**: Multi-tenant data isolation supports database sharding
- **Caching Strategy**: Redis caching for frequently accessed data
- **CDN Integration**: Static asset delivery via CDN
- **Message Queues**: Asynchronous processing for long-running operations

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check configuration
npm run config:validate

# Check database connectivity
npm run db:ping

# Check external dependencies
npm run deps:health

# View logs
docker logs update-management-service
```

#### High Memory Usage
```bash
# Enable heap profiling
NODE_OPTIONS="--inspect --max-old-space-size=4096" npm start

# Check for memory leaks
npm run profile:memory

# Monitor garbage collection
NODE_OPTIONS="--trace-gc" npm start
```

#### Deployment Failures
```bash
# Check device connectivity
curl -f http://device-ip:port/health

# Validate scripts
npm run scripts:validate

# Check deployment logs
kubectl logs -f deployment/update-management
```

### Debug Mode

```bash
# Enable debug logging
DEBUG=update-management:* npm start

# Enable verbose logging
LOG_LEVEL=debug npm start

# Enable request tracing
TRACE_REQUESTS=true npm start
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Ensure all tests pass: `npm test`
5. Submit a pull request

### Development Guidelines

- Follow the existing code style and patterns
- Add comprehensive tests for new functionality
- Update documentation for any API changes
- Use semantic commit messages
- Ensure security best practices are followed

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Documentation: https://docs.opendirectory.local
- Community Forum: https://community.opendirectory.local
- Bug Reports: https://github.com/opendirectory/services/issues
- Security Issues: security@opendirectory.local

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

**OpenDirectory Update Management Service** - Enterprise-grade update management and remote device actions for modern IT infrastructure.