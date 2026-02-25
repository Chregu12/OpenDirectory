# OpenDirectory Mobile Management Suite

A comprehensive Mobile Device Management (MDM), Mobile Application Management (MAM), and Mobile Threat Defense (MTD) solution for enterprise environments.

## Overview

The OpenDirectory Mobile Management Suite provides enterprise-grade mobile device security and management capabilities through four integrated services:

- **iOS Management Service** - Apple DEP/VPP integration and iOS device management
- **Android Enterprise Service** - Android for Work and Samsung Knox support
- **Mobile App Management (MAM) Service** - App-specific policies and data protection
- **Mobile Threat Defense (MTD) Service** - Real-time threat detection and security

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                API Gateway (Port 3000)                  │
│                    Load Balancer                        │
├─────────────────────────────────────────────────────────┤
│            Mobile Management Proxy (Port 3010)          │
│                     Nginx Proxy                        │
├─────────────┬───────────────┬────────────┬──────────────┤
│iOS Mgmt     │Android Ent.   │MAM Service │MTD Service   │
│(Port 3011)  │(Port 3012)    │(Port 3013) │(Port 3014)   │
│             │               │            │              │
│• DEP/VPP    │• Google EMM   │• App       │• Real-time   │
│• Profiles   │• Knox         │  Wrapping  │  Scanning    │
│• MDM Cmds   │• Work Profile │• Policies  │• ML Detection│
│• Compliance │• Zero-Touch   │• Analytics │• Threat Intel│
└─────────────┴───────────────┴────────────┴──────────────┘
```

## Services

### 🍎 iOS Management Service (Port 3011)

**Capabilities:**
- Apple Device Enrollment Program (DEP) integration
- Volume Purchase Program (VPP) management  
- Configuration profile deployment
- MDM command execution
- iOS compliance monitoring
- Enterprise certificate management

**Key Features:**
- DEP/VPP token management
- Supervised device management
- App Store Connect integration
- Configuration profile signing
- Real-time device monitoring
- Compliance violation detection

**API Endpoints:**
```
POST   /api/ios/dep/token              Create DEP token
GET    /api/ios/dep/devices            Get DEP devices
POST   /api/ios/vpp/apps/purchase      Purchase VPP app
POST   /api/ios/profiles               Create configuration profile
POST   /api/ios/commands/device-lock   Lock device remotely
GET    /api/ios/compliance/violations  Get compliance violations
```

### 🤖 Android Enterprise Service (Port 3012)

**Capabilities:**
- Google Play EMM API integration
- Android Enterprise management
- Samsung Knox integration
- Work profile management
- Zero-touch enrollment
- Enterprise app management

**Key Features:**
- Enterprise creation and management
- Enrollment token generation
- Device policy enforcement
- Work profile isolation
- Knox container management
- Bulk device operations

**API Endpoints:**
```
POST   /api/android/enterprises        Create enterprise
POST   /api/android/enrollment-tokens  Create enrollment token
GET    /api/android/devices            Get managed devices
POST   /api/android/policies           Create device policy
POST   /api/android/apps/approve       Approve Play Store app
POST   /api/android/knox/profiles      Create Knox profile
```

### 📱 Mobile App Management Service (Port 3013)

**Capabilities:**
- App-specific data protection policies
- Conditional access controls
- App wrapping and SDK integration
- Custom app distribution
- License management
- Performance monitoring

**Key Features:**
- Application catalog management
- Data protection policies
- App wrapping service
- Compliance scanning
- Usage analytics
- License tracking

**API Endpoints:**
```
POST   /api/mam/apps                   Upload/create app
POST   /api/mam/policies               Create app policy
POST   /api/mam/data-protection-policies Create data policy
POST   /api/mam/wrapping/jobs          Start app wrapping
POST   /api/mam/compliance/scan        Start compliance scan
GET    /api/mam/analytics/dashboard    Get analytics
```

### 🛡️ Mobile Threat Defense Service (Port 3014)

**Capabilities:**
- Real-time threat detection
- Malware analysis and quarantine
- Network security monitoring
- Behavioral analysis
- Incident response automation
- Threat intelligence integration

**Key Features:**
- ML-powered threat detection
- Device integrity validation
- Network anomaly detection
- Security incident management
- Threat intelligence feeds
- Automated response actions

**API Endpoints:**
```
POST   /api/mtd/threats/scan          Initiate threat scan
POST   /api/mtd/devices/register      Register device
POST   /api/mtd/incidents             Create security incident
POST   /api/mtd/malware/analyze       Analyze malware
GET    /api/mtd/analytics/dashboard   Get security dashboard
POST   /api/mtd/policies              Create security policy
```

## Installation

### Prerequisites

- Node.js 18.0.0 or higher
- npm 9.0.0 or higher
- Docker and Docker Compose (for containerized deployment)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/opendirectory/mobile-management.git
   cd mobile-management
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start all services:**
   ```bash
   npm run start:all
   ```

### Docker Deployment

1. **Build and start with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

2. **Check service status:**
   ```bash
   docker-compose ps
   ```

3. **View logs:**
   ```bash
   docker-compose logs -f
   ```

## Configuration

### Environment Variables

#### Apple iOS Configuration
```bash
APPLE_DEP_CLIENT_ID=your_dep_client_id
APPLE_DEP_CLIENT_SECRET=your_dep_secret
APPLE_VPP_CLIENT_ID=your_vpp_client_id
APPLE_VPP_CLIENT_SECRET=your_vpp_secret
APPLE_PUSH_CERT=path/to/push/cert.pem
APPLE_PUSH_CERT_PASSWORD=cert_password
```

#### Google Android Configuration
```bash
GOOGLE_CLIENT_EMAIL=service@project.iam.gserviceaccount.com
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
GOOGLE_PROJECT_ID=your_project_id
ANDROID_ENTERPRISE_ID=your_enterprise_id
```

#### Samsung Knox Configuration
```bash
KNOX_CLIENT_ID=your_knox_client_id
KNOX_CLIENT_SECRET=your_knox_client_secret
```

#### App Wrapping Configuration
```bash
APP_WRAPPING_ENABLED=true
APP_WRAPPING_ENDPOINT=https://wrapping.service.com/api
APP_WRAPPING_API_KEY=your_wrapping_api_key
```

#### Threat Intelligence Configuration
```bash
VIRUSTOTAL_ENABLED=true
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SIEM_ENABLED=true
SIEM_ENDPOINT=https://your.siem.com/api
SIEM_API_KEY=your_siem_api_key
```

### Service Ports

| Service | Default Port | Environment Variable |
|---------|-------------|---------------------|
| iOS Management | 3011 | `IOS_MANAGEMENT_PORT` |
| Android Enterprise | 3012 | `ANDROID_ENTERPRISE_PORT` |
| Mobile App Management | 3013 | `MAM_SERVICE_PORT` |
| Mobile Threat Defense | 3014 | `MTD_SERVICE_PORT` |
| Nginx Proxy | 3010 | `PROXY_PORT` |

## API Documentation

### Authentication

All API endpoints require authentication via Bearer token:

```bash
curl -H "Authorization: Bearer <your_token>" \
     -H "Content-Type: application/json" \
     https://your-domain/api/mobile/ios/health
```

### Request/Response Format

All APIs use JSON format with consistent response structure:

```json
{
  "success": true,
  "data": { /* response data */ },
  "requestId": "uuid-v4",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

Error responses:
```json
{
  "error": "Error description",
  "details": "Detailed error information",
  "requestId": "uuid-v4",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### WebSocket Integration

Each service provides real-time updates via WebSocket:

```javascript
// iOS Management WebSocket
const iosWs = new WebSocket('ws://localhost:3011/ws/ios');

iosWs.on('message', (data) => {
  const event = JSON.parse(data);
  console.log('iOS Event:', event);
});

// Subscribe to specific events
iosWs.send(JSON.stringify({
  type: 'subscribe_ios_events',
  requestId: 'unique-id'
}));
```

Available WebSocket event types:
- `device_enrolled` - New device enrollment
- `compliance_violation` - Policy violation detected
- `threat_detected` - Security threat identified
- `app_installed` - Application installation completed

## Monitoring and Health Checks

### Health Endpoints

Each service provides a comprehensive health check:

```bash
# Individual service health
curl http://localhost:3011/health  # iOS Management
curl http://localhost:3012/health  # Android Enterprise
curl http://localhost:3013/health  # Mobile App Management
curl http://localhost:3014/health  # Mobile Threat Defense

# Proxy health check
curl http://localhost:3010/health
```

### Monitoring Integration

The services provide metrics for monitoring systems:

- **Prometheus metrics** - Available at `/metrics` endpoint
- **Health status** - Detailed component health information
- **Performance metrics** - Request timing, throughput, error rates
- **Business metrics** - Device counts, threat detections, policy compliance

### Logging

Structured logging with configurable levels:

```javascript
// Log format
{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "level": "info",
  "service": "ios-management",
  "requestId": "uuid-v4",
  "message": "Device enrolled successfully",
  "metadata": {
    "deviceId": "device-123",
    "platform": "iOS",
    "version": "17.0"
  }
}
```

## Security

### Data Protection

- **Encryption at rest** - All sensitive data encrypted with AES-256
- **Encryption in transit** - TLS 1.3 for all communications
- **Zero-trust architecture** - Continuous authentication and authorization
- **Data isolation** - Tenant-specific data segregation

### Access Control

- **Role-based access control (RBAC)** - Fine-grained permissions
- **Multi-factor authentication** - Required for administrative access
- **API rate limiting** - Protection against abuse
- **Audit logging** - Complete audit trail

### Compliance

Supported compliance frameworks:
- **GDPR** - Data privacy and protection
- **HIPAA** - Healthcare information security
- **SOX** - Financial data controls
- **ISO 27001** - Information security management

## Integration

### API Gateway Integration

The services automatically register with the OpenDirectory API Gateway:

```javascript
// Service discovery configuration
const serviceConfig = {
  service: 'ios-management-service',
  version: '1.0.0',
  port: 3011,
  path: '/api/mobile/ios',
  capabilities: [
    'apple-dep',
    'apple-vpp', 
    'ios-profiles',
    'mdm-commands'
  ]
};
```

### External Integrations

- **Apple Business Manager** - DEP/VPP integration
- **Google Admin Console** - Android Enterprise management
- **Microsoft Intune** - Policy synchronization
- **VMware Workspace ONE** - Co-management scenarios
- **CrowdStrike** - Extended threat detection
- **SIEM platforms** - Security event forwarding

## Development

### Project Structure

```
mobile-management/
├── ios-management-service.js           # iOS service implementation
├── android-enterprise-service.js      # Android service implementation  
├── mobile-app-management-service.js   # MAM service implementation
├── mobile-threat-defense-service.js   # MTD service implementation
├── index.js                          # Service orchestrator
├── package.json                      # Dependencies and scripts
├── Dockerfile                        # Container image definition
├── docker-compose.yml               # Multi-service deployment
├── nginx.conf                       # Reverse proxy configuration
├── README.md                        # This documentation
├── docs/                           # Additional documentation
│   ├── api/                       # API specifications
│   ├── deployment/               # Deployment guides
│   └── integration/             # Integration examples
└── tests/                        # Test suites
    ├── unit/                    # Unit tests
    ├── integration/            # Integration tests
    └── e2e/                   # End-to-end tests
```

### Running Tests

```bash
# Unit tests
npm test

# Integration tests  
npm run test:integration

# End-to-end tests
npm run test:e2e

# Coverage report
npm run test:coverage
```

### Development Mode

Start services in development mode with hot reload:

```bash
# Start all services in development mode
npm run dev

# Start individual services
npm run dev:ios
npm run dev:android
npm run dev:mam
npm run dev:mtd
```

## Troubleshooting

### Common Issues

1. **Service fails to start**
   - Check port availability
   - Verify environment variables
   - Review application logs

2. **Apple DEP/VPP integration fails**
   - Validate Apple Business Manager configuration
   - Check certificate expiration
   - Verify API credentials

3. **Android Enterprise issues**
   - Confirm Google service account permissions
   - Check Play Console configuration
   - Validate Knox licensing

4. **High memory usage**
   - Review scan job concurrency
   - Check for memory leaks in threat detection
   - Adjust ML model parameters

### Debug Commands

```bash
# Check service health
npm run health-check

# View detailed logs
docker-compose logs -f [service_name]

# Connect to service container
docker-compose exec [service_name] /bin/sh

# Test API endpoints
npm run api-test

# Validate configuration
npm run config-validate
```

### Performance Tuning

1. **Increase worker processes**
   ```bash
   export WORKERS=4  # Number of worker processes
   ```

2. **Adjust scan concurrency**
   ```bash
   export MAX_CONCURRENT_SCANS=5
   ```

3. **Tune ML model sensitivity**
   ```bash
   export ML_SENSITIVITY=medium  # low, medium, high
   ```

## Support

### Community

- **Documentation**: [https://docs.opendirectory.io/mobile](https://docs.opendirectory.io/mobile)
- **GitHub Issues**: [https://github.com/opendirectory/mobile-management/issues](https://github.com/opendirectory/mobile-management/issues)
- **Discussion Forum**: [https://community.opendirectory.io](https://community.opendirectory.io)

### Enterprise Support

- **Professional Services**: Implementation and integration assistance
- **24/7 Support**: Critical issue resolution
- **Training**: Administrator and developer training programs
- **Custom Development**: Feature requests and customizations

## Changelog

### Version 1.0.0 (Current)

**Features:**
- ✅ iOS Management Service with Apple DEP/VPP integration
- ✅ Android Enterprise Service with Google Play EMM
- ✅ Mobile App Management with data protection policies
- ✅ Mobile Threat Defense with ML-powered detection
- ✅ Comprehensive API Gateway integration
- ✅ Real-time WebSocket event streaming
- ✅ Docker containerization and orchestration
- ✅ Advanced security and compliance features

**Security:**
- 🔒 End-to-end encryption for all communications
- 🔐 Multi-factor authentication support
- 🛡️ Zero-trust security architecture
- 📊 Comprehensive audit logging
- 🔍 Real-time threat detection and response

**Performance:**
- ⚡ High-performance async architecture
- 📈 Horizontal scaling support
- 🎯 Optimized database queries
- 🚀 Efficient caching strategies
- 📊 Real-time monitoring and alerting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**OpenDirectory Mobile Management Suite v1.0.0**  
*Enterprise Mobile Security Made Simple*