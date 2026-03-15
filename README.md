# 🚀 OpenDirectory - Universal Endpoint Management Platform

<div align="center">

![OpenDirectory Logo](https://img.shields.io/badge/OpenDirectory-UEM-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=for-the-badge)
![Node](https://img.shields.io/badge/node-%3E%3D%2018.0.0-brightgreen?style=for-the-badge)
![Docker](https://img.shields.io/badge/docker-%3E%3D%2020.10-blue?style=for-the-badge)

**Enterprise-grade Universal Endpoint Management (UEM) platform that replaces Microsoft Intune, Active Directory, and traditional MDM solutions**

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing) • [License](#-license)

</div>

---

## 🎯 Overview

OpenDirectory is a comprehensive, open-source Universal Endpoint Management platform that provides enterprise-grade device management, security, and automation capabilities across all major platforms. Built with modern microservices architecture, it offers a complete alternative to expensive proprietary solutions like Microsoft Intune, Jamf Pro, and traditional Active Directory.

### 🌟 Key Highlights

- **🌍 True Cross-Platform Support**: Manage Windows, macOS, Linux, iOS, and Android from a single platform
- **🔐 Zero Trust Security**: Built-in conditional access, device compliance, and modern authentication
- **🚀 Auto-Scaling Architecture**: Microservices design with automatic service discovery
- **💰 Cost-Effective**: Open-source alternative to expensive enterprise solutions
- **🔧 Extensible**: Plugin architecture and comprehensive REST APIs

## ✨ Features

### 📱 Device Management
- **Multi-Platform MDM**: Complete mobile device management for iOS and Android
- **Desktop Management**: Full support for Windows 10/11, macOS, and Linux distributions
- **Zero-Touch Enrollment**: Automated device provisioning and configuration
- **Remote Actions**: Lock, wipe, restart, and locate devices remotely

### 🔒 Security & Compliance
- **Zero Trust Architecture**: Conditional access policies with continuous verification
- **Device Compliance**: Real-time compliance monitoring and automated remediation
- **BitLocker/FileVault Management**: Full disk encryption management across platforms
- **Certificate Authority**: Built-in PKI infrastructure with certificate lifecycle management

### 📋 Policy Management
- **Group Policy Engine**: Windows GPO-compatible policy management for all platforms
- **Configuration Profiles**: Deploy settings, restrictions, and configurations
- **Update Management**: Centralized OS and application update control
- **Software Deployment**: Automated software installation and management

### 🖨️ Infrastructure Services
- **Print Server**: Centralized print management with driver distribution
- **Network Configuration**: WiFi, VPN, and email profile deployment
- **File Sharing**: SMB/CIFS network drive mapping and management
- **Directory Services**: Complete Active Directory replacement

### 🔍 Unified Endpoint Intelligence (NEW)
- **AD Graph Explorer**: Neo4j-style relationship visualization of Users, Groups, Devices, Policies, and Update Rings with attack path detection and shadow admin discovery
- **Policy Simulator**: "What-If" analysis for policy changes showing impact on devices, users, and compliance before applying
- **Security Exposure Scanner**: CIS/NIST/DISA STIG compliance benchmarking with GPO analysis, privilege escalation detection, and automated remediation scripts
- **Drift Detection**: Real-time comparison of expected policy state vs actual device configuration
- **Compliance Timeline**: Full historical compliance tracking per device (enrolled, policy applied, compliance gained/lost, remediated)
- **Device Lifecycle Manager**: Complete lifecycle state machine (Provisioned → Enrolled → Compliant → Retiring → Retired) with risk scoring (0-100)
- **Auto Remediation Engine**: Detects compliance issues and generates platform-specific remediation scripts (PowerShell/Bash) with approval workflows

### 🔄 Integration & Automation
- **API Gateway**: Auto-extending API gateway with service discovery
- **License Management**: Software license tracking and compliance
- **Workflow Automation**: Event-driven automation and orchestration
- **Multi-Tenant Support**: Complete isolation for multiple organizations
- **Terraform Provider**: Infrastructure-as-code with 8 resources and 2 data sources
- **Ansible Collection**: 5 modules, inventory plugin, roles, and playbooks for automation

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   OpenDirectory Platform                 │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Platform    │  │     Core     │  │  Enterprise  │ │
│  │   Services    │  │   Services   │  │   Services   │ │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤ │
│  │ • API Gateway │  │ • Auth       │  │ • Zero Trust │ │
│  │ • Backend API │  │ • Device Mgmt│  │ • Compliance │ │
│  │ • Integration │  │ • Policy     │  │ • Analytics  │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │            Supported Platforms                    │  │
│  ├──────────────────────────────────────────────────┤  │
│  │ Windows 10/11 │ macOS │ Linux │ iOS │ Android   │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+ and Docker Compose
- Node.js 18+ (for development)
- 8GB RAM minimum (16GB recommended)
- 50GB available storage

### 🐳 Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/opendirectory.git
cd opendirectory

# Copy environment template
cp .env.example .env

# Edit .env with your settings
nano .env

# Start all services
docker-compose up -d

# Check service health
docker-compose ps

# Access the web interface
# http://localhost:3000
```

### 💻 Local Development

```bash
# Install dependencies
npm install

# Initialize database
npm run db:init

# Start development servers
npm run dev

# In another terminal, start the frontend
cd frontend/web-app
npm install
npm run dev
```

## 📚 Documentation

### Getting Started
- [Installation Guide](docs/installation.md)
- [Configuration](docs/configuration.md)
- [First Device Enrollment](docs/enrollment.md)

### Administration
- [Policy Management](docs/policies.md)
- [User Management](docs/users.md)
- [Device Management](docs/devices.md)
- [Security Configuration](docs/security.md)

### Platform Guides
- [Windows Management](docs/platforms/windows.md)
- [macOS Management](docs/platforms/macos.md)
- [Linux Management](docs/platforms/linux.md)
- [Mobile Management](docs/platforms/mobile.md)

### API Reference
- [REST API Documentation](docs/api/README.md)
- [Authentication](docs/api/auth.md)
- [Webhooks](docs/api/webhooks.md)

## 🛠️ Services

### Platform Services (`/services/platform`)
- **API Gateway**: Intelligent routing and service discovery
- **Backend API**: Core REST API endpoints
- **Integration Service**: External system connectors

### Core Services (`/services/core`)
- **Authentication Service**: Identity and access management
- **Device Service**: Device lifecycle management
- **Policy Service**: Policy engine and enforcement
- **Certificate Network**: PKI and network profiles
- **Update Management**: OS and application updates
- **Conditional Access**: Zero trust implementation

### Enterprise Services (`/services/enterprise`)
- **Mobile Management**: iOS and Android MDM
- **License Management**: Software asset management
- **Analytics**: Advanced reporting and insights

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/opendirectory
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=your-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here

# Services
API_GATEWAY_PORT=3000
BACKEND_PORT=8080

# External Services (Optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=notifications@example.com
SMTP_PASS=password
```

### Docker Compose Override

For production deployments, create `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  api-gateway:
    environment:
      - NODE_ENV=production
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Use ESLint configuration provided
- Follow conventional commits specification
- Write tests for new features
- Update documentation

## 🧪 Testing

```bash
# Run all tests
npm test

# Run specific service tests
npm run test:device-service

# Run integration tests
npm run test:integration

# Generate coverage report
npm run test:coverage
```

## 🚢 Deployment

### Production with Docker

```bash
# Build production images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Deploy with scaling
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale api-gateway=3

# View logs
docker-compose logs -f api-gateway
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f infrastructure/kubernetes/

# Check deployment status
kubectl get pods -n opendirectory

# Access via port-forward (development)
kubectl port-forward -n opendirectory svc/api-gateway 3000:3000
```

## 📊 Monitoring

- **Health Check**: `http://localhost:3000/health`
- **Metrics**: `http://localhost:3000/metrics`
- **API Documentation**: `http://localhost:3000/api-docs`

## 🔒 Security

- All communications encrypted with TLS
- JWT-based authentication
- Role-based access control (RBAC)
- Audit logging for all actions
- Regular security updates

For security issues, please email security@opendirectory.io instead of using issue tracker.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Node.js, Express, React, and Docker
- Inspired by enterprise management needs
- Community-driven development

## 💬 Community & Support

- **Documentation**: [https://docs.opendirectory.io](https://docs.opendirectory.io)
- **Discord**: [Join our community](https://discord.gg/opendirectory)
- **Issues**: [GitHub Issues](https://github.com/yourusername/opendirectory/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/opendirectory/discussions)

## 🗺️ Roadmap

- [x] Backup and disaster recovery
- [x] Advanced reporting dashboard
- [x] Machine learning for threat detection
- [x] GraphQL API support
- [x] Terraform provider
- [x] Ansible collection
- [x] AD Graph Explorer with attack path detection
- [x] Policy Simulator with what-if analysis
- [x] Security Exposure Scanner (CIS/NIST/STIG)
- [x] Drift Detection and Compliance Timeline
- [x] Device Lifecycle Management
- [x] Auto Remediation Engine
- [ ] SaaS multi-tenant deployment
- [ ] Mobile app for admins (iOS/Android)
- [ ] AI-powered anomaly detection
- [ ] SIEM/Splunk native integration
- [ ] Terraform provider
- [ ] Ansible modules

---

<div align="center">
Made with ❤️ by the OpenDirectory Community

**[Website](https://opendirectory.io)** • **[Documentation](https://docs.opendirectory.io)** • **[Blog](https://blog.opendirectory.io)**
</div>