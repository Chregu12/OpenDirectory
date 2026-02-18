# 📋 OpenDirectory MDM - Technical Documentation

## 📖 Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Components](#components)
5. [API Documentation](#api-documentation)
6. [Database Schema](#database-schema)
7. [Security](#security)
8. [Deployment](#deployment)
9. [Monitoring](#monitoring)
10. [Development](#development)

---

## 1. System Overview

### 🎯 **Purpose**
OpenDirectory MDM is an enterprise Mobile Device Management platform designed as an alternative to Microsoft Intune, providing comprehensive device management, application deployment, and user administration capabilities.

### 🏢 **Business Requirements**
- **Multi-Platform Support**: Windows, macOS, Linux, iOS, Android
- **Enterprise Integration**: LDAP, PKI, SSO, Monitoring
- **Scalability**: Support for 1000+ devices
- **Security**: Zero-trust architecture, compliance monitoring
- **Real-time**: Live device status and management

### 🎨 **User Personas**
- **IT Administrators**: Device management, policy enforcement
- **Security Teams**: Compliance monitoring, threat response
- **End Users**: Self-service app installation, device enrollment

---

## 2. Architecture

### 🏗️ **System Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Frontend  │    │  Mobile Apps    │    │  Desktop Apps   │
│   (Vue.js)      │    │  (React Native) │    │  (Electron)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
          ┌────────────────────────────────────────────┐
          │            Load Balancer / Ingress          │
          │              (Traefik/Nginx)               │
          └────────────────────┬───────────────────────┘
                               │
          ┌────────────────────────────────────────────┐
          │               API Gateway                   │
          │            (Express.js/Node.js)            │
          └────────────────────┬───────────────────────┘
                               │
    ┌──────────────┬───────────┼───────────┬─────────────┐
    │              │           │           │             │
┌───▼───┐    ┌────▼────┐ ┌───▼────┐ ┌────▼────┐ ┌─────▼─────┐
│Device │    │User     │ │Policy  │ │App      │ │Monitoring │
│Service│    │Service  │ │Engine  │ │Store    │ │Service    │
└───┬───┘    └────┬────┘ └───┬────┘ └────┬────┘ └─────┬─────┘
    │             │          │           │            │
    └─────────────┼──────────┼───────────┼────────────┘
                  │          │           │
          ┌───────▼──────────▼───────────▼────────┐
          │         Message Queue/Events          │
          │            (WebSocket)                │
          └────────────────┬───────────────────────┘
                           │
          ┌────────────────────────────────────────┐
          │           Data Layer                   │
          │  ┌─────────┐ ┌─────────┐ ┌──────────┐ │
          │  │ Device  │ │  User   │ │  Config  │ │
          │  │  Store  │ │ Store   │ │  Store   │ │
          │  └─────────┘ └─────────┘ └──────────┘ │
          └────────────────────────────────────────┘
```

### 🔄 **Microservices Architecture**

```
Enterprise Services (48 Services)
├── Real-Time Services
│   ├── realtime-backend.js (WebSocket server)
│   └── health-monitor.js (System monitoring)
├── Policy Engine
│   ├── policy-engine.js (Smart policies)
│   └── compliance-scanner.js (Compliance automation)
├── AI Analytics (4 services)
│   ├── ai-analytics.js (ML predictions)
│   ├── pattern-engine.js (Behavioral patterns)
│   ├── recommendations.js (AI recommendations)
│   └── predictive-maintenance.js (Predictive maintenance)
├── Security Framework (7 services)
│   ├── microsegmentation.js (Network security)
│   ├── zero-trust-auth.js (Zero-trust auth)
│   ├── pam-system.js (Privileged access)
│   └── ... (4 more security services)
└── ... (35 more enterprise services)
```

---

## 3. Technology Stack

### 🎨 **Frontend Technologies**

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Main Dashboard** | Vue.js | 3.x | Primary admin interface |
| **Web App** | React + Next.js | 14.x | Advanced web interface |
| **Mobile** | React Native | 0.72.x | iOS/Android apps |
| **Desktop** | Electron | 27.x | Cross-platform desktop |
| **Styling** | Tailwind CSS | 3.x | Utility-first CSS |
| **Icons** | Font Awesome | 6.x | Icon library |
| **State Management** | Vuex/Redux | Latest | State management |

### ⚙️ **Backend Technologies**

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Runtime** | Node.js | 18.x LTS | JavaScript runtime |
| **Framework** | Express.js | 4.18.x | Web framework |
| **WebSocket** | ws | 8.14.x | Real-time communication |
| **HTTP Client** | Axios | 1.6.x | HTTP requests |
| **Validation** | Joi | 17.x | Data validation |
| **Logging** | Winston | 3.x | Application logging |
| **Process Manager** | PM2 | 5.x | Production process management |

### 🏗️ **Infrastructure Technologies**

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Orchestration** | Kubernetes | 1.34.x | Container orchestration |
| **Container Runtime** | K3s | 1.34.3 | Lightweight Kubernetes |
| **Containers** | Docker | 24.x | Application containerization |
| **Load Balancer** | Traefik | 2.x | Ingress controller |
| **Service Mesh** | Istio | 1.19.x | Service-to-service communication |
| **Storage** | Longhorn | 1.5.x | Distributed storage |

### 🗄️ **Data Technologies**

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Primary DB** | PostgreSQL | 15.x | Relational database |
| **Cache** | Redis | 7.x | In-memory cache |
| **Search** | Elasticsearch | 8.x | Full-text search |
| **Time Series** | InfluxDB | 2.x | Metrics storage |
| **Message Queue** | RabbitMQ | 3.12.x | Async messaging |

### 🔐 **Security & Auth Technologies**

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Authentication** | Authentik | Latest | Identity provider |
| **LDAP** | LLDAP | Stable | Lightweight LDAP |
| **PKI** | Step-CA | Latest | Certificate authority |
| **Secrets** | HashiCorp Vault | Latest | Secret management |
| **Zero Trust** | Open Policy Agent | 0.57.x | Policy engine |

---

## 4. Components

### 📱 **Frontend Components**

#### **Vue.js Dashboard (`multi-platform-app-store.yaml`)**
```javascript
// Main Dashboard Component Structure
const OpenDirectoryApp = {
  data() {
    return {
      currentView: 'dashboard',
      devices: [],
      users: [],
      applications: [],
      notifications: [],
      ws: null // WebSocket connection
    }
  },
  
  components: {
    DeviceManagement,
    UserManagement, 
    ApplicationStore,
    PolicyEngine,
    MonitoringDashboard
  },
  
  methods: {
    // Real-time WebSocket integration
    connectWebSocket() {
      this.ws = new WebSocket('ws://192.168.1.200/ws');
      this.ws.onmessage = this.handleWebSocketMessage;
    },
    
    // API integration methods
    async refreshDevices() {
      const response = await fetch('/api/devices');
      this.devices = await response.json();
    }
  }
}
```

#### **React Web App (`frontend/web-app/`)**
```typescript
// Next.js App Structure
interface OpenDirectoryProps {
  initialData: {
    devices: Device[];
    users: User[];
  };
}

export default function OpenDirectoryApp({ initialData }: OpenDirectoryProps) {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main className="container mx-auto px-4 py-8">
        <Routes>
          <Route path="/devices" component={DeviceManagement} />
          <Route path="/users" component={UserManagement} />
          <Route path="/apps" component={ApplicationStore} />
        </Routes>
      </main>
    </div>
  );
}
```

### ⚙️ **Backend Services**

#### **API Gateway (`services/gateway-service/`)**
```javascript
// Express.js API Gateway
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
app.use(cors());
app.use(express.json());

// Service routing
app.use('/api/devices', createProxyMiddleware({
  target: 'http://device-service:3001',
  changeOrigin: true
}));

app.use('/api/users', createProxyMiddleware({
  target: 'http://user-service:3002',
  changeOrigin: true
}));

app.use('/api/policies', createProxyMiddleware({
  target: 'http://policy-service:3003',
  changeOrigin: true
}));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date() });
});

app.listen(3000, () => {
  console.log('API Gateway running on port 3000');
});
```

#### **Device Service (`services/device-service/`)**
```javascript
// Device Management Service
class DeviceService {
  constructor() {
    this.devices = new Map();
    this.setupWebSocket();
  }
  
  async registerDevice(deviceInfo) {
    const device = {
      id: deviceInfo.id,
      name: deviceInfo.name,
      platform: deviceInfo.platform,
      status: 'online',
      lastSeen: new Date(),
      installedApps: [],
      complianceScore: 0
    };
    
    this.devices.set(device.id, device);
    this.broadcastDeviceUpdate(device);
    return device;
  }
  
  async installApplication(deviceId, appInfo) {
    const device = this.devices.get(deviceId);
    if (!device) throw new Error('Device not found');
    
    // Execute installation based on platform
    switch (device.platform) {
      case 'linux':
        await this.installLinuxApp(device, appInfo);
        break;
      case 'windows':
        await this.installWindowsApp(device, appInfo);
        break;
      case 'macos':
        await this.installMacApp(device, appInfo);
        break;
    }
    
    device.installedApps.push({
      ...appInfo,
      installedAt: new Date(),
      status: 'installed'
    });
    
    this.broadcastDeviceUpdate(device);
    return device;
  }
  
  async installLinuxApp(device, appInfo) {
    const { NodeSSH } = require('node-ssh');
    const ssh = new NodeSSH();
    
    await ssh.connect({
      host: device.ip_address,
      username: 'root',
      privateKey: process.env.SSH_PRIVATE_KEY
    });
    
    const command = this.getLinuxInstallCommand(appInfo);
    const result = await ssh.execCommand(command);
    
    if (result.code !== 0) {
      throw new Error(`Installation failed: ${result.stderr}`);
    }
    
    ssh.dispose();
  }
}
```

---

## 5. API Documentation

### 🔗 **REST API Endpoints**

#### **Device Management API**

##### **GET /api/devices**
Get all registered devices

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "CT2001",
      "name": "Ubuntu-CT2001",
      "platform": "linux",
      "os": "Ubuntu",
      "osVersion": "25.10",
      "status": "online",
      "ip_address": "192.168.1.51",
      "lastSeen": "2026-02-18T20:30:00.000Z",
      "complianceScore": 85,
      "installedApps": [
        {
          "app": "docker",
          "name": "Docker",
          "version": "24.0.7",
          "installedAt": "2026-02-18T19:45:00.000Z"
        }
      ]
    }
  ]
}
```

##### **POST /api/devices/{id}/apps/install**
Install application on device

**Request:**
```json
{
  "appId": "docker",
  "appName": "Docker",
  "version": "24.0.7"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Docker installation initiated on Ubuntu-CT2001",
  "data": {
    "id": "CT2001",
    "name": "Ubuntu-CT2001",
    "installedApps": [...]
  }
}
```

#### **User Management API**

##### **GET /api/users**
Get all users from LDAP

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "admin",
      "username": "admin",
      "email": "admin@opendirectory.local",
      "displayName": "Administrator",
      "groups": ["admin"],
      "active": true,
      "lastLogin": "2026-02-18T20:15:00.000Z"
    }
  ]
}
```

##### **POST /api/users/sync**
Synchronize users with LDAP directory

**Response:**
```json
{
  "success": true,
  "message": "Users synced successfully",
  "data": {
    "syncedCount": 15,
    "totalUsers": 245
  }
}
```

#### **Policy Management API**

##### **GET /api/policies**
Get all device policies

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "version_mgmt",
      "name": "Version Management Policy",
      "description": "Automatic application updates with version control",
      "active": true,
      "platforms": ["linux", "windows", "macos"],
      "rules": {
        "autoUpdate": true,
        "updateWindow": "maintenance",
        "rollbackEnabled": true
      }
    }
  ]
}
```

### 🔌 **WebSocket API**

#### **Connection**
```javascript
const ws = new WebSocket('ws://192.168.1.200/ws');

ws.onopen = () => {
  console.log('Connected to OpenDirectory real-time updates');
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  handleRealtimeUpdate(message);
};
```

#### **Message Types**

##### **Device Status Update**
```json
{
  "type": "device_status",
  "data": [
    {
      "id": "CT2001",
      "status": "online",
      "lastSeen": "2026-02-18T20:30:00.000Z"
    }
  ]
}
```

##### **Application Installation**
```json
{
  "type": "app_installed",
  "data": {
    "deviceId": "CT2001",
    "app": {
      "appId": "docker",
      "appName": "Docker",
      "version": "24.0.7"
    }
  }
}
```

##### **Device Heartbeat**
```json
{
  "type": "device_heartbeat",
  "data": {
    "deviceId": "CT2001",
    "status": "online",
    "lastSeen": "2026-02-18T20:30:15.000Z"
  }
}
```

---

## 6. Database Schema

### 🗄️ **PostgreSQL Schema**

#### **Devices Table**
```sql
CREATE TABLE devices (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    platform VARCHAR(20) NOT NULL CHECK (platform IN ('linux', 'windows', 'macos', 'ios', 'android')),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'maintenance')),
    ip_address INET,
    mac_address MACADDR,
    serial_number VARCHAR(100),
    model VARCHAR(100),
    manufacturer VARCHAR(100),
    enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    compliance_score INTEGER CHECK (compliance_score >= 0 AND compliance_score <= 100),
    group_id VARCHAR(50),
    tags JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_platform ON devices(platform);
CREATE INDEX idx_devices_group ON devices(group_id);
```

#### **Applications Table**
```sql
CREATE TABLE applications (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    version VARCHAR(50),
    category VARCHAR(100),
    platform VARCHAR(20) NOT NULL,
    download_url TEXT,
    icon_url TEXT,
    install_command TEXT,
    uninstall_command TEXT,
    requirements JSONB,
    metadata JSONB,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_applications_platform ON applications(platform);
CREATE INDEX idx_applications_category ON applications(category);
```

#### **Device Applications Table**
```sql
CREATE TABLE device_applications (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(50) REFERENCES devices(id) ON DELETE CASCADE,
    application_id VARCHAR(50) REFERENCES applications(id) ON DELETE CASCADE,
    version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'installed' CHECK (status IN ('installed', 'installing', 'failed', 'uninstalled')),
    installed_at TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB,
    UNIQUE(device_id, application_id)
);

CREATE INDEX idx_device_apps_device ON device_applications(device_id);
CREATE INDEX idx_device_apps_status ON device_applications(status);
```

#### **Users Table**
```sql
CREATE TABLE users (
    id VARCHAR(50) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    active BOOLEAN DEFAULT true,
    groups JSONB,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(active);
```

#### **Policies Table**
```sql
CREATE TABLE policies (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    rules JSONB NOT NULL,
    platforms TEXT[] DEFAULT '{}',
    groups TEXT[] DEFAULT '{}',
    active BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_policies_type ON policies(type);
CREATE INDEX idx_policies_active ON policies(active);
```

### 📊 **Redis Cache Schema**

#### **Device Status Cache**
```
Key: device:status:{device_id}
Value: {
  "status": "online",
  "lastSeen": "2026-02-18T20:30:00.000Z",
  "complianceScore": 85
}
TTL: 300 seconds (5 minutes)
```

#### **User Sessions Cache**
```
Key: session:{session_id}
Value: {
  "userId": "admin",
  "username": "admin",
  "groups": ["admin"],
  "loginTime": "2026-02-18T20:00:00.000Z"
}
TTL: 3600 seconds (1 hour)
```

---

## 7. Security

### 🔐 **Authentication & Authorization**

#### **Multi-Factor Authentication Flow**
```
1. User submits credentials
   ↓
2. Authentik validates username/password
   ↓
3. If valid, request TOTP/SMS code
   ↓
4. Validate second factor
   ↓
5. Generate JWT token with claims
   ↓
6. Return token to client
```

#### **Zero Trust Architecture**
```javascript
// Zero Trust Middleware
const zeroTrustMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check token blacklist
    if (await isTokenBlacklisted(token)) {
      return res.status(401).json({ error: 'Token revoked' });
    }
    
    // Verify user is still active
    const user = await getUserById(decoded.userId);
    if (!user || !user.active) {
      return res.status(401).json({ error: 'User inactive' });
    }
    
    // Check permissions for specific resource
    if (!await hasPermission(decoded.userId, req.method, req.path)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
```

#### **Role-Based Access Control (RBAC)**
```json
{
  "roles": {
    "super_admin": {
      "permissions": ["*"],
      "description": "Full system access"
    },
    "device_admin": {
      "permissions": [
        "devices:read",
        "devices:write", 
        "devices:install_apps",
        "devices:uninstall_apps"
      ],
      "description": "Device management access"
    },
    "user_admin": {
      "permissions": [
        "users:read",
        "users:write",
        "groups:read",
        "groups:write"
      ],
      "description": "User management access"
    },
    "readonly": {
      "permissions": [
        "devices:read",
        "users:read",
        "policies:read"
      ],
      "description": "Read-only access"
    }
  }
}
```

### 🛡️ **Data Security**

#### **Encryption at Rest**
- **Database**: AES-256 encryption for sensitive columns
- **Files**: GPG encryption for stored files
- **Backups**: Encrypted backup storage

#### **Encryption in Transit**
- **HTTPS**: TLS 1.3 for all web traffic
- **API**: Certificate-based authentication
- **Internal**: mTLS between services

#### **Certificate Management**
```javascript
// Step-CA Integration
const stepCA = require('@smallstep/step-ca');

class CertificateManager {
  async issueCertificate(deviceId, commonName) {
    const cert = await stepCA.certificate.create({
      subject: commonName,
      sans: [deviceId],
      template: 'device-certificate',
      validityPeriod: '30d'
    });
    
    return {
      certificate: cert.certificate,
      privateKey: cert.privateKey,
      rootCA: cert.rootCA
    };
  }
  
  async revokeCertificate(serialNumber) {
    await stepCA.certificate.revoke(serialNumber);
  }
}
```

---

## 8. Deployment

### 🚀 **Kubernetes Deployment**

#### **Production Deployment**
```yaml
# opendirectory-production.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: opendirectory-prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opendirectory-api
  namespace: opendirectory-prod
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: opendirectory-api
  template:
    metadata:
      labels:
        app: opendirectory-api
    spec:
      containers:
      - name: api
        image: opendirectory/api:v1.0.0
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: url
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

#### **Ingress Configuration**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: opendirectory-ingress
  namespace: opendirectory-prod
  annotations:
    traefik.ingress.kubernetes.io/router.tls: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - mdm.company.com
    secretName: opendirectory-tls
  rules:
  - host: mdm.company.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: opendirectory-api-service
            port:
              number: 3000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: opendirectory-frontend-service
            port:
              number: 80
```

### 🐳 **Docker Configuration**

#### **Production Dockerfile**
```dockerfile
# Multi-stage build for production
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .
RUN npm run build

# Production image
FROM node:18-alpine AS production

RUN addgroup -g 1001 -S nodejs
RUN adduser -S opendirectory -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=opendirectory:nodejs /app/dist ./dist
COPY --from=builder --chown=opendirectory:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=opendirectory:nodejs /app/package*.json ./

USER opendirectory

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "dist/server.js"]
```

### ⚙️ **Environment Configuration**

#### **Production Environment Variables**
```bash
# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/opendirectory
REDIS_URL=redis://redis:6379/0

# Authentication
JWT_SECRET=your-256-bit-secret
JWT_EXPIRES_IN=1h
AUTHENTIK_URL=https://auth.company.com
AUTHENTIK_CLIENT_ID=opendirectory
AUTHENTIK_CLIENT_SECRET=secret

# LDAP
LDAP_URL=ldap://lldap:3890
LDAP_BIND_DN=uid=admin,ou=people,dc=company,dc=com
LDAP_BIND_PASSWORD=password

# Certificates
STEP_CA_URL=https://ca.company.com
STEP_CA_ROOT=/etc/ssl/certs/root_ca.crt

# Monitoring
PROMETHEUS_ENDPOINT=http://prometheus:9090
GRAFANA_URL=https://grafana.company.com

# External Services
VAULT_ADDR=https://vault.company.com:8200
VAULT_TOKEN=hvs.CAESIJQK...
```

---

## 9. Monitoring

### 📊 **Metrics Collection**

#### **Application Metrics**
```javascript
// Prometheus metrics integration
const prometheus = require('prom-client');

// Custom metrics
const deviceCount = new prometheus.Gauge({
  name: 'opendirectory_devices_total',
  help: 'Total number of registered devices',
  labelNames: ['platform', 'status']
});

const apiRequestDuration = new prometheus.Histogram({
  name: 'opendirectory_api_request_duration_seconds',
  help: 'Duration of API requests in seconds',
  labelNames: ['method', 'route', 'status_code']
});

const appInstallations = new prometheus.Counter({
  name: 'opendirectory_app_installations_total',
  help: 'Total number of app installations',
  labelNames: ['app', 'platform', 'status']
});

// Middleware to collect metrics
const metricsMiddleware = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    apiRequestDuration
      .labels(req.method, req.route?.path || 'unknown', res.statusCode)
      .observe(duration);
  });
  
  next();
};
```

#### **Health Checks**
```javascript
// Comprehensive health check
app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date(),
    version: process.env.npm_package_version,
    services: {}
  };
  
  // Database check
  try {
    await db.query('SELECT 1');
    health.services.database = 'healthy';
  } catch (error) {
    health.services.database = 'unhealthy';
    health.status = 'unhealthy';
  }
  
  // Redis check
  try {
    await redis.ping();
    health.services.redis = 'healthy';
  } catch (error) {
    health.services.redis = 'unhealthy';
    health.status = 'unhealthy';
  }
  
  // LDAP check
  try {
    await ldapClient.search('dc=company,dc=com', {
      scope: 'base',
      sizeLimit: 1
    });
    health.services.ldap = 'healthy';
  } catch (error) {
    health.services.ldap = 'unhealthy';
    health.status = 'unhealthy';
  }
  
  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});
```

### 📈 **Grafana Dashboards**

#### **System Overview Dashboard**
```json
{
  "dashboard": {
    "title": "OpenDirectory MDM Overview",
    "panels": [
      {
        "title": "Active Devices",
        "type": "stat",
        "targets": [{
          "expr": "sum(opendirectory_devices_total{status=\"online\"})"
        }]
      },
      {
        "title": "Device Status Distribution",
        "type": "piechart", 
        "targets": [{
          "expr": "opendirectory_devices_total"
        }]
      },
      {
        "title": "API Response Time",
        "type": "graph",
        "targets": [{
          "expr": "histogram_quantile(0.95, opendirectory_api_request_duration_seconds_bucket)"
        }]
      },
      {
        "title": "App Installation Success Rate",
        "type": "stat",
        "targets": [{
          "expr": "rate(opendirectory_app_installations_total{status=\"success\"}[5m]) / rate(opendirectory_app_installations_total[5m]) * 100"
        }]
      }
    ]
  }
}
```

### 🚨 **Alerting Rules**

#### **Prometheus Alerting**
```yaml
# opendirectory-alerts.yml
groups:
- name: opendirectory
  rules:
  - alert: HighAPILatency
    expr: histogram_quantile(0.95, opendirectory_api_request_duration_seconds_bucket) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High API latency detected"
      description: "95th percentile latency is {{ $value }}s"
      
  - alert: DeviceOffline
    expr: opendirectory_devices_total{status="offline"} > 10
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Multiple devices offline"
      description: "{{ $value }} devices are currently offline"
      
  - alert: AppInstallationFailure
    expr: rate(opendirectory_app_installations_total{status="failed"}[5m]) > 0.1
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "High app installation failure rate"
      description: "{{ $value }} installations failing per second"
```

---

## 10. Development

### 🛠️ **Development Environment Setup**

#### **Local Development**
```bash
# Clone repository
git clone https://github.com/Chregu12/OpenDirectory.git
cd OpenDirectory

# Install dependencies
npm install

# Setup environment
cp .env.example .env

# Start development services
docker-compose up -d postgres redis

# Run database migrations
npm run migrate

# Start development server
npm run dev
```

#### **Development Environment Variables**
```bash
# .env.development
NODE_ENV=development
PORT=3000

# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/opendirectory_dev
REDIS_URL=redis://localhost:6379/0

# Authentication (development)
JWT_SECRET=development-secret-key
JWT_EXPIRES_IN=24h

# External services (mock/local)
AUTHENTIK_URL=http://localhost:9000
LDAP_URL=ldap://localhost:3890
```

### 🧪 **Testing**

#### **Unit Tests**
```javascript
// tests/unit/deviceService.test.js
const DeviceService = require('../../src/services/deviceService');
const { expect } = require('chai');

describe('DeviceService', () => {
  let deviceService;
  
  beforeEach(() => {
    deviceService = new DeviceService();
  });
  
  describe('registerDevice', () => {
    it('should register a new device', async () => {
      const deviceInfo = {
        id: 'test-device',
        name: 'Test Device',
        platform: 'linux'
      };
      
      const result = await deviceService.registerDevice(deviceInfo);
      
      expect(result.id).to.equal('test-device');
      expect(result.status).to.equal('online');
      expect(result.installedApps).to.be.an('array').that.is.empty;
    });
    
    it('should throw error for duplicate device', async () => {
      const deviceInfo = {
        id: 'test-device',
        name: 'Test Device',
        platform: 'linux'
      };
      
      await deviceService.registerDevice(deviceInfo);
      
      try {
        await deviceService.registerDevice(deviceInfo);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).to.include('already registered');
      }
    });
  });
});
```

#### **Integration Tests**
```javascript
// tests/integration/api.test.js
const request = require('supertest');
const app = require('../../src/app');

describe('Device API', () => {
  describe('GET /api/devices', () => {
    it('should return list of devices', async () => {
      const response = await request(app)
        .get('/api/devices')
        .expect(200);
        
      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });
  
  describe('POST /api/devices/:id/apps/install', () => {
    it('should install app on device', async () => {
      const appInfo = {
        appId: 'test-app',
        appName: 'Test App',
        version: '1.0.0'
      };
      
      const response = await request(app)
        .post('/api/devices/CT2001/apps/install')
        .send(appInfo)
        .expect(200);
        
      expect(response.body.success).to.be.true;
      expect(response.body.message).to.include('installation initiated');
    });
  });
});
```

#### **End-to-End Tests**
```javascript
// tests/e2e/dashboard.test.js
const { Builder, By, until } = require('selenium-webdriver');
const { expect } = require('chai');

describe('OpenDirectory Dashboard', () => {
  let driver;
  
  before(async () => {
    driver = await new Builder().forBrowser('chrome').build();
  });
  
  after(async () => {
    await driver.quit();
  });
  
  it('should load dashboard and show devices', async () => {
    await driver.get('http://localhost:3000');
    
    // Wait for dashboard to load
    await driver.wait(until.titleContains('OpenDirectory'), 10000);
    
    // Click on devices tab
    const devicesTab = await driver.findElement(By.css('[data-testid="devices-tab"]'));
    await devicesTab.click();
    
    // Verify device list loads
    const deviceList = await driver.wait(
      until.elementLocated(By.css('[data-testid="device-list"]')), 
      5000
    );
    
    const devices = await deviceList.findElements(By.css('.device-card'));
    expect(devices.length).to.be.greaterThan(0);
  });
  
  it('should install app on device', async () => {
    // Navigate to device details
    const deviceCard = await driver.findElement(By.css('.device-card'));
    await deviceCard.click();
    
    // Click install app button
    const installButton = await driver.findElement(By.css('[data-testid="install-app-btn"]'));
    await installButton.click();
    
    // Select app from dropdown
    const appSelect = await driver.findElement(By.css('[data-testid="app-select"]'));
    await appSelect.click();
    
    const dockerOption = await driver.findElement(By.css('[data-value="docker"]'));
    await dockerOption.click();
    
    // Confirm installation
    const confirmButton = await driver.findElement(By.css('[data-testid="confirm-install"]'));
    await confirmButton.click();
    
    // Wait for success message
    const successMessage = await driver.wait(
      until.elementLocated(By.css('.notification.success')), 
      10000
    );
    
    const messageText = await successMessage.getText();
    expect(messageText).to.include('installation initiated');
  });
});
```

### 📚 **Code Standards**

#### **ESLint Configuration**
```json
{
  "extends": [
    "eslint:recommended",
    "@typescript-eslint/recommended"
  ],
  "rules": {
    "indent": ["error", 2],
    "quotes": ["error", "single"],
    "semi": ["error", "always"],
    "no-unused-vars": "error",
    "no-console": "warn",
    "prefer-const": "error",
    "no-var": "error"
  }
}
```

#### **Git Workflow**
```bash
# Feature branch workflow
git checkout -b feature/device-management-improvements
git add .
git commit -m "feat: add bulk device operations"
git push origin feature/device-management-improvements

# Create pull request
# After review and approval:
git checkout main
git merge feature/device-management-improvements
git push origin main
git tag v1.1.0
git push origin v1.1.0
```

---

## 📚 Appendices

### A. **Troubleshooting Guide**

#### **Common Issues**

##### **API Not Responding**
```bash
# Check service status
kubectl get pods -n opendirectory
kubectl logs -f deployment/opendirectory-api -n opendirectory

# Check database connectivity
kubectl exec -it deployment/opendirectory-api -n opendirectory -- npm run db:check

# Restart service
kubectl rollout restart deployment/opendirectory-api -n opendirectory
```

##### **Device Connection Issues**
```bash
# Test device connectivity
ping 192.168.1.51

# Check SSH access
ssh root@192.168.1.51 'echo "Connection test"'

# Verify certificates
openssl s_client -connect 192.168.1.51:443 -verify_return_error
```

### B. **Performance Tuning**

#### **Database Optimization**
```sql
-- Create indexes for better performance
CREATE INDEX CONCURRENTLY idx_devices_last_seen ON devices(last_seen);
CREATE INDEX CONCURRENTLY idx_device_apps_installed_at ON device_applications(installed_at);

-- Update statistics
ANALYZE devices;
ANALYZE device_applications;

-- Monitor slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
WHERE mean_time > 1000 
ORDER BY mean_time DESC;
```

#### **Redis Configuration**
```bash
# redis.conf optimizations
maxmemory 2gb
maxmemory-policy allkeys-lru
tcp-keepalive 300
timeout 300
```

### C. **Security Checklist**

- [ ] All endpoints require authentication
- [ ] Role-based access control implemented
- [ ] Input validation on all API endpoints
- [ ] SQL injection protection enabled
- [ ] XSS protection headers set
- [ ] HTTPS enforced in production
- [ ] Certificate expiration monitoring
- [ ] Regular security scans performed
- [ ] Secrets stored securely (Vault)
- [ ] Audit logging enabled

### D. **Backup and Recovery**

#### **Database Backup**
```bash
# Automated daily backups
pg_dump -h postgres -U postgres -d opendirectory | \
  gzip > /backups/opendirectory-$(date +%Y%m%d).sql.gz
  
# Upload to cloud storage
aws s3 cp /backups/opendirectory-$(date +%Y%m%d).sql.gz \
  s3://company-backups/opendirectory/
```

#### **Kubernetes Backup**
```bash
# Backup cluster configuration
kubectl get all,pv,pvc,secrets,configmaps -n opendirectory -o yaml > \
  opendirectory-backup-$(date +%Y%m%d).yaml
```

---

## 📝 Document Information

- **Version**: 1.0.0
- **Last Updated**: 2026-02-18
- **Author**: OpenDirectory Development Team
- **Review Status**: ✅ Approved
- **Next Review**: 2026-03-18

---

*This document is part of the OpenDirectory MDM project. For updates and contributions, see the [GitHub repository](https://github.com/Chregu12/OpenDirectory).*