# License Management Service

A comprehensive enterprise license management service for the OpenDirectory UEM platform.

## Overview

The License Management Service provides complete software license tracking, compliance monitoring, and optimization capabilities. It supports all major license types and integrates seamlessly with the existing OpenDirectory ecosystem, including mobile app license management.

## Features

### Core License Management
- **Software License Tracking**: Support for all major license types (perpetual, subscription, concurrent, per-device, open source, cloud)
- **License Lifecycle Management**: From procurement to retirement
- **Multi-vendor Support**: Microsoft, Adobe, Autodesk, and custom vendors
- **Real-time Usage Tracking**: Monitor license utilization and prevent overages

### Compliance Monitoring
- **Automated Violation Detection**: Real-time compliance checking
- **Audit Trail**: Complete audit logging of all license activities
- **Policy Enforcement**: Configurable compliance rules and thresholds
- **Risk Assessment**: Continuous compliance risk evaluation

### Optimization & Analytics
- **Cost Analysis**: Detailed financial analysis and forecasting
- **Usage Analytics**: Comprehensive utilization reporting
- **Optimization Recommendations**: AI-driven cost saving opportunities
- **Renewal Management**: Automated renewal tracking and notifications

### Asset Management
- **Software Asset Discovery**: Automated discovery of installed software
- **Hardware Integration**: Link licenses to physical and virtual assets
- **Lifecycle Tracking**: Complete asset lifecycle management
- **Reconciliation**: Automatic license-to-asset mapping

### Mobile Integration
- **MAM Service Integration**: Seamless integration with Mobile App Management
- **Mobile License Sync**: Bi-directional synchronization of mobile app licenses
- **Cross-platform Support**: iOS and Android license management
- **Mobile Compliance**: Mobile-specific compliance monitoring

### Alerting & Notifications
- **Real-time Alerts**: Configurable alert rules and thresholds
- **Multi-channel Notifications**: Email, WebSocket, webhook, and database logging
- **Escalation Management**: Automated alert escalation workflows
- **Dashboard Integration**: Real-time alert visualization

### Reporting
- **Comprehensive Reports**: 8+ pre-built report templates
- **Multiple Output Formats**: PDF, Excel, JSON
- **Scheduled Reports**: Automated report generation and distribution
- **Executive Dashboards**: High-level summary reports for stakeholders

## Quick Start

### Prerequisites
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional)

### Installation

1. Clone the repository and navigate to the service directory
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up environment variables (see Configuration section)
4. Initialize the database:
   ```bash
   psql -h localhost -U postgres -d opendirectory_licenses -f scripts/init-db.sql
   ```
5. Start the service:
   ```bash
   npm start
   ```

### Docker Deployment

1. Build and start with Docker Compose:
   ```bash
   docker-compose up -d
   ```

The service will be available at `http://localhost:3018`

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LICENSE_SERVICE_PORT` | Service port | `3018` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://localhost/opendirectory_licenses` |
| `MOBILE_SERVICE_URL` | Mobile management service URL | `http://mobile-management:3013` |
| `MOBILE_API_KEY` | API key for mobile service | - |
| `ALERTING_ENABLED` | Enable email alerting | `true` |
| `SMTP_HOST` | SMTP server host | `localhost` |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username | - |
| `SMTP_PASSWORD` | SMTP password | - |
| `AUTO_REMEDIATION` | Enable automatic remediation | `false` |
| `UTILIZATION_THRESHOLD` | High utilization threshold (%) | `85` |
| `EXPIRY_WARNING_DAYS` | License expiry warning days | `30` |
| `OVERUSAGE_THRESHOLD` | Usage overrun threshold | `5` |

### Alert Configuration

The service includes pre-configured alert rules for:
- License expiry warnings
- Usage overruns and high utilization
- Compliance violations
- Maintenance contract expiry
- Cost threshold breaches
- Renewal notifications

Alert channels can be configured for:
- Email notifications
- Real-time WebSocket updates
- Webhook integrations
- Database logging

### Mobile Integration

The service automatically syncs with the Mobile App Management service every 5 minutes. Configure the integration using:
- `MOBILE_SERVICE_URL`: URL of the MAM service
- `MOBILE_API_KEY`: Authentication key for API access
- `MOBILE_SYNC_INTERVAL`: Sync frequency in milliseconds

## API Documentation

### Core Endpoints

#### License Management
- `GET /api/license/licenses` - List all licenses
- `POST /api/license/licenses` - Create new license
- `GET /api/license/licenses/:id` - Get license details
- `PUT /api/license/licenses/:id` - Update license
- `DELETE /api/license/licenses/:id` - Delete license

#### Usage Tracking
- `POST /api/license/usage/track` - Track license usage
- `GET /api/license/usage/:licenseId` - Get license usage data
- `GET /api/license/usage` - Get usage overview

#### Compliance
- `POST /api/license/compliance/scan` - Start compliance scan
- `GET /api/license/compliance/violations` - List violations
- `GET /api/license/compliance/overview` - Compliance dashboard

#### Optimization
- `GET /api/license/optimization/recommendations` - Get optimization recommendations
- `POST /api/license/optimization/analyze` - Run optimization analysis
- `GET /api/license/optimization/cost-analysis` - Cost analysis

#### Reports
- `POST /api/license/reports/generate` - Generate report
- `GET /api/license/reports` - List reports
- `GET /api/license/reports/:reportId/download` - Download report

#### Asset Management
- `POST /api/license/assets/discovery` - Start asset discovery
- `GET /api/license/assets` - List assets
- `PUT /api/license/assets/:assetId` - Update asset

### WebSocket Events

Connect to `ws://localhost:3018/ws/license` for real-time updates:
- `license_created` - New license added
- `license_updated` - License modified
- `usage_tracked` - Usage activity recorded
- `violation_detected` - Compliance violation found
- `alert_created` - New alert generated

## License Types Supported

### Perpetual Licenses
- Windows, Office, Adobe Creative Suite
- AutoCAD, MATLAB, SolidWorks
- One-time purchase with permanent rights

### Subscription Licenses
- Microsoft 365, Adobe Creative Cloud
- Monthly/annual recurring billing
- Cloud-based and on-premise versions

### Concurrent/Floating Licenses
- Engineering software (AutoCAD, MATLAB)
- Shared license pools with usage limits
- Network-based license management

### Per-Device Licenses
- Mobile applications (iOS/Android)
- Device-specific software installations
- Hardware-locked licenses

### Open Source Licenses
- GPL, MIT, Apache licenses
- Compliance tracking and reporting
- License obligation management

### Cloud Service Licenses
- AWS, Azure, Google Cloud
- Usage-based billing integration
- Multi-cloud license management

## Integration Points

### API Gateway
The service automatically registers with the OpenDirectory API Gateway and is accessible through:
- `/api/license/*` - Main license management endpoints

### Mobile Management Service
Bi-directional integration with the Mobile App Management service:
- Automatic sync of mobile app licenses
- Cross-platform usage tracking
- Unified compliance monitoring

### Authentication Service
Integrates with the OpenDirectory authentication system for:
- User authentication and authorization
- Audit trail user tracking
- Role-based access control

### Monitoring & Alerting
Connects to the monitoring infrastructure for:
- Service health monitoring
- Performance metrics
- Alert distribution

## Monitoring & Health Checks

### Health Endpoint
- `GET /health` - Basic health check
- `GET /health/detailed` - Comprehensive health status

### Metrics
The service exposes metrics for:
- License count and status
- Usage statistics
- Compliance rates
- Alert counts
- Performance indicators

### Logging
Comprehensive logging includes:
- Request/response logs
- Audit trail events
- Error tracking
- Performance metrics

## Development

### Running in Development
```bash
npm run dev
```

### Testing
```bash
npm test
```

### Linting
```bash
npm run lint
```

### Building Docker Image
```bash
docker build -t opendirectory/license-management:latest .
```

## Security

### Authentication
- JWT token validation
- API key authentication
- Role-based access control

### Data Protection
- Encrypted sensitive data
- Audit logging
- Secure communication protocols

### Compliance
- SOC 2, GDPR, HIPAA support
- Data retention policies
- Access control monitoring

## Support

### Documentation
- API documentation available at `/docs`
- OpenAPI specification at `/docs/openapi.json`

### Troubleshooting
- Check service logs in `/app/logs/`
- Monitor health endpoints
- Review audit logs for activity tracking

### Performance Optimization
- Database indexing for large datasets
- Caching for frequently accessed data
- Asynchronous processing for heavy operations

## License

This service is part of the OpenDirectory UEM platform.
Copyright (c) 2024 OpenDirectory Team.

## Version History

### v1.0.0
- Initial release with complete license management capabilities
- Mobile integration with MAM service
- Comprehensive reporting and analytics
- Real-time alerting and compliance monitoring