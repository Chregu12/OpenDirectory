# 🚀 OpenDirectory MDM

A comprehensive Enterprise Mobile Device Management (MDM) solution built on Kubernetes, designed as a modern alternative to Microsoft Intune.

## 🚀 Features

### Core MDM Capabilities
- **Multi-Platform Device Management**: Support for Windows, macOS, and Linux devices
- **Policy-Based Management**: Version control, security policies, and maintenance scheduling
- **Application Store**: Multi-platform application deployment with automated installation
- **Real-time Monitoring**: Integration with Grafana and Prometheus
- **LDAP Integration**: Central user management via LLDAP
- **Compliance Tracking**: Real-time compliance monitoring and reporting

### Current Implementation
- **UniFi-Style Interface**: Modern, responsive web UI
- **Device Groups**: Servers, Workstations, Mobile devices, Printers, IoT
- **User Management**: LDAP-based directory service with group management
- **Application Deployment**: Policy-controlled app deployment with version management
- **External Service Integration**: Grafana, Prometheus, Vault, LLDAP

## 📁 Project Structure

```
OpenDirectory/
├── multi-platform-app-store.yaml      # Current production deployment
├── enhanced-device-management.yaml     # Enhanced device management features
├── opendirectory-enhancement-plan.md   # Roadmap for missing features
├── macos-deployment-agent.sh          # macOS deployment agent
├── windows-deployment-agent.ps1       # Windows deployment agent
└── README.md                          # This file
```

## 🛠️ Current Status

### ✅ Implemented Features
- **Multi-Platform Application Store** with Windows, macOS, and Linux support
- **Device Management** with real device integration (CT2001 Ubuntu container)
- **User Management** via LLDAP integration
- **Policy Management** with scheduling and version control
- **Modern Web Interface** with UniFi-inspired design
- **External Service Integration** (Grafana, Prometheus, Vault)

### 📋 Deployment Files

#### multi-platform-app-store.yaml
Current production deployment featuring:
- Complete multi-platform application store
- Full device management with groups and compliance
- LDAP-integrated user management
- Policy management interface
- External service integration

#### enhanced-device-management.yaml
Previous version with enhanced device management features:
- Advanced device grouping
- Application version management
- Policy-based deployment system

## 🚀 Quick Start

### Prerequisites
- Kubernetes cluster (K3s recommended)
- LLDAP service running on port 30170
- Grafana service on port 30300
- Prometheus service on port 30909
- Vault service on port 30820

### Deployment

```bash
# Deploy the current OpenDirectory MDM system
kubectl apply -f multi-platform-app-store.yaml

# Check deployment status
kubectl get pods -n opendirectory

# Access the web interface
# http://your-k3s-server:30055
```

### Adding Devices

OpenDirectory supports automatic device registration via:
- **Linux**: Direct integration via container deployment
- **Windows**: PowerShell deployment agent
- **macOS**: Bash deployment agent

## 🔄 Comparison with Enterprise Solutions

### vs. Microsoft Intune
- **Cost**: Open-source vs. $6-15/user/month
- **Deployment**: Self-hosted Kubernetes vs. Cloud-only
- **Customization**: Full control vs. Limited customization
- **Integration**: Native Kubernetes ecosystem vs. Microsoft ecosystem

### vs. Jamf Pro
- **Platform Support**: Multi-platform vs. Apple-focused
- **Architecture**: Modern container-based vs. Traditional server
- **API**: Modern REST APIs vs. Legacy APIs

## 🧪 Testing Environment

### Services
- **LLDAP**: Port 30170 - User directory management
- **Grafana**: Port 30300 - Monitoring and dashboards
- **Prometheus**: Port 30909 - Metrics collection
- **Vault**: Port 30820 - Secrets management
- **OpenDirectory**: Port 30055 - Main MDM interface

## 📊 Current Metrics

- **Supported Platforms**: 3 (Windows, macOS, Linux)
- **Application Categories**: 6 (Browsers, Development, Productivity, Security, Media, Utilities)
- **Deployment Methods**: 4 (MSI/EXE, DMG/PKG, APT/DEB, Homebrew)
- **Policy Types**: 4 (Version, Security, Maintenance, Deployment)
- **Device Groups**: 5 (Servers, Workstations, Mobile, Printers, IoT)

## 🤝 Contributing

OpenDirectory is actively developed. Key areas for contribution:
- Multi-platform deployment agents
- Additional application integrations
- Enhanced reporting capabilities
- Security policy templates

## 📄 License

Open source project - see individual file headers for specific license information.

---

**OpenDirectory MDM** - Enterprise device management for the modern era
