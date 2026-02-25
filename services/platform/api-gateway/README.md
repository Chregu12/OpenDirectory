# OpenDirectory Auto-Extending API Gateway

Ein generisches API Gateway, das automatisch neue Services entdeckt und sich dynamisch erweitert.

## 🚀 Features

### Automatische Service Discovery
- **Port-Scanning**: Automatische Erkennung von Services auf Standard-Ports
- **Health-Check Integration**: Services müssen einen `/health` Endpoint bereitstellen
- **Intelligente Pfad-Zuordnung**: Automatische URL-Pfad-Generierung basierend auf Service-Namen
- **Metadata-Extraktion**: Sammelt Service-Informationen wie Version, Capabilities, etc.

### Load Balancing & Resilience
- **Multiple Strategien**: Round-Robin, Least-Connections, Weighted
- **Circuit Breaker**: Automatische Fehlerbehandlung und Service-Isolation
- **Health Monitoring**: Kontinuierliche Überwachung der Service-Gesundheit
- **Graceful Degradation**: Fallback-Mechanismen bei Service-Ausfällen

### Security & Rate Limiting
- **JWT Authentication**: Token-basierte Authentifizierung
- **Rate Limiting**: Schutz vor Überlastung
- **CORS Support**: Konfigurierbare Cross-Origin-Requests
- **Security Headers**: Umfassende Sicherheits-Header

### Real-time Communication
- **WebSocket Gateway**: Bidirektionale Echtzeitkommunikation
- **Event Broadcasting**: Live-Updates über Service-Änderungen
- **Subscription Management**: Flexible Topic-basierte Nachrichten

### Monitoring & Observability
- **Structured Logging**: Winston-basierte Logs mit Rotation
- **Metrics Collection**: Detaillierte Performance-Metriken
- **Health Aggregation**: Zentrale Übersicht aller Service-Status
- **Request Tracing**: Vollständige Request-Verfolgung

## 📦 Installation

```bash
cd services/api-gateway
npm install
```

## 🔧 Konfiguration

### Environment Variables

```bash
# Gateway Configuration
API_GATEWAY_PORT=3000
LOG_LEVEL=info

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# JWT Configuration
JWT_SECRET=your-jwt-secret

# Service Discovery
DISCOVERY_ENABLED=true
DISCOVERY_INTERVAL=30000
DISCOVERY_TIMEOUT=5000
DISCOVERY_RETRIES=3

# Health Checking
HEALTH_CHECK_INTERVAL=15000
HEALTH_CHECK_TIMEOUT=3000
HEALTH_CHECK_UNHEALTHY_THRESHOLD=3

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=1000

# Load Balancing
LOAD_BALANCE_STRATEGY=round-robin
```

### Service Registration

Services können sich auf zwei Arten registrieren:

#### 1. Automatische Discovery
Services müssen einen `/health` Endpoint bereitstellen:

```json
{
  "status": "healthy",
  "service": "authentication-service",
  "version": "1.0.0",
  "uptime": 12345,
  "capabilities": ["oauth", "ldap", "mfa"],
  "environment": "production"
}
```

#### 2. Manuelle Registration
```bash
curl -X POST http://localhost:3000/gateway/register \
  -H "Content-Type: application/json" \
  -d '{
    "id": "auth-service",
    "name": "authentication-service", 
    "host": "localhost",
    "port": 3001,
    "path": "/api/auth",
    "version": "1.0.0",
    "metadata": {
      "capabilities": ["oauth", "ldap"]
    }
  }'
```

## 🚀 Start

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

### Docker
```bash
docker-compose up -d
```

## 🔍 Service Discovery

Das Gateway entdeckt automatisch Services durch:

1. **Port Scanning** auf definierten Ports (3001-3008)
2. **Health Check** auf `/health` Endpoint
3. **Metadata Parsing** zur Service-Klassifizierung
4. **Path Mapping** basierend auf Service-Namen

### Unterstützte Service-Typen

| Service Name | Auto-Generated Path | Description |
|--------------|-------------------|-------------|
| `authentication-service` | `/api/auth/*` | Authentifizierung |
| `device-service` | `/api/devices/*` | Geräte-Management |
| `network-infrastructure` | `/api/network/*` | Netzwerk-Services |
| `monitoring-service` | `/api/monitoring/*` | Überwachung |
| `user-service` | `/api/users/*` | Benutzer-Management |

## 🌐 API Endpoints

### Gateway Management
```bash
GET  /health              # Gateway Health Status
GET  /status              # Detailed Gateway Status  
GET  /services            # Registered Services
GET  /metrics             # Gateway Metrics
POST /gateway/register    # Register Service
DELETE /gateway/register/:id  # Unregister Service
```

### Admin Endpoints
```bash
GET  /admin/services/:id/health  # Service Health
POST /admin/services/:id/reload  # Reload Service
GET  /admin/connections          # Active Connections
```

### Service Proxying
```bash
# Automatisches Routing zu Services
GET    /api/{service}/*    # GET Requests
POST   /api/{service}/*    # POST Requests  
PUT    /api/{service}/*    # PUT Requests
DELETE /api/{service}/*    # DELETE Requests
PATCH  /api/{service}/*    # PATCH Requests
```

## 🔌 WebSocket Gateway

WebSocket-Verbindung auf Port `3001`:

```javascript
const ws = new WebSocket('ws://localhost:3001');

// Authentifizierung
ws.send(JSON.stringify({
  type: 'authenticate',
  data: { token: 'your-jwt-token' }
}));

// Subscribe to events
ws.send(JSON.stringify({
  type: 'subscribe', 
  data: { topics: ['service:*', 'gateway:*'] }
}));
```

### WebSocket Events
- `service:discovered` - Neuer Service entdeckt
- `service:removed` - Service entfernt
- `service:health` - Health Status geändert
- `gateway:status` - Gateway Status Update

## 📊 Load Balancing

### Strategien

#### Round Robin (Default)
```javascript
// Gleichmäßige Verteilung der Requests
service1 -> service2 -> service3 -> service1 ...
```

#### Least Connections
```javascript
// Weiterleitung an Service mit wenigsten aktiven Verbindungen
connections: {service1: 5, service2: 2, service3: 8}
// -> Wählt service2
```

#### Weighted
```javascript
// Gewichtete Verteilung basierend auf Service-Kapazität
weights: {service1: 3, service2: 1, service3: 2}
// -> service1 bekommt 50%, service3 33%, service2 17%
```

## 🛡️ Security Features

### Authentication
- JWT Token Validation
- User Context Forwarding
- Role-based Access Control

### Rate Limiting
- IP-based Limiting
- Service-specific Limits
- Adaptive Rate Limiting

### Headers
- Security Headers (Helmet.js)
- CORS Configuration
- Request ID Tracking

## 📈 Monitoring

### Metrics
```bash
curl http://localhost:3000/metrics
```

```json
{
  "total": 1250,
  "successful": 1198,
  "failed": 52,
  "averageResponseTime": 245,
  "services": {
    "total": 5,
    "healthy": 4
  },
  "connections": {
    "active": 12,
    "websocket": 3
  }
}
```

### Logs
- **Access Logs**: HTTP Request/Response Logs
- **Error Logs**: Fehler und Exceptions
- **Discovery Logs**: Service Discovery Events
- **Performance Logs**: Langsame Requests und Bottlenecks

### Log Rotation
- Daily rotation
- Compression
- Configurable retention

## 🔧 Health Checks

### Gateway Health
```bash
curl http://localhost:3000/health
```

```json
{
  "status": "healthy",
  "gateway": {
    "version": "2.0.0", 
    "uptime": 3600,
    "memory": {...},
    "activeConnections": 15
  },
  "services": {
    "total": 5,
    "healthy": 4,
    "unhealthy": 1
  }
}
```

### Service Health
```bash
curl http://localhost:3000/admin/services/auth-service/health
```

## 🐳 Docker Deployment

### Single Gateway
```bash
docker build -t opendirectory/api-gateway .
docker run -d \
  --name api-gateway \
  -p 3000:3000 \
  -p 3001:3001 \
  -e REDIS_HOST=redis \
  opendirectory/api-gateway
```

### Complete Stack
```bash
docker-compose up -d
```

### Services
- **api-gateway**: Haupt-Gateway Service
- **redis**: Service Registry und Caching
- **service-registrar**: External Service Discovery
- **gateway-monitor**: Prometheus Monitoring
- **log-aggregator**: Fluentd Log Collection

## 📚 Integration Examples

### Service Integration
```javascript
// services/my-service/src/index.js
const express = require('express');
const app = express();

// Health check endpoint (required)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'my-service',
    version: '1.0.0',
    capabilities: ['feature1', 'feature2'],
    uptime: process.uptime()
  });
});

// Your service endpoints
app.get('/api/data', (req, res) => {
  // Gateway forwards requests to /api/my-service/data
  res.json({ data: 'Hello from my-service!' });
});

app.listen(3005, () => {
  console.log('Service running on port 3005');
  // Gateway discovers automatically!
});
```

### Client Integration
```javascript
// Frontend API calls
const baseURL = 'http://localhost:3000/api';

// Automatically routed to correct service
const authResponse = await fetch(`${baseURL}/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password })
});

const deviceResponse = await fetch(`${baseURL}/devices/list`, {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## 🎯 Use Cases

### Microservices Architecture
- Zentraler Entry Point für alle Services
- Automatische Service Discovery
- Load Balancing zwischen Service-Instanzen
- Circuit Breaking für Resilience

### Development Environment
- Lokale Service Discovery
- Hot-Reload Support  
- Development-friendly Logging
- Easy Service Integration

### Production Deployment
- High Availability Load Balancing
- Health Monitoring
- Security and Rate Limiting
- Observability and Metrics

## 🔄 Auto-Extension

Das Gateway erweitert sich automatisch wenn:

1. **Neue Services gestartet werden** - Automatic Discovery
2. **Services sich registrieren** - Manual Registration
3. **Service-Konfiguration ändert** - Dynamic Updates
4. **Health Status ändert** - Automatic Routing Updates

### Flow Diagram
```
New Service Starts
       ↓
Health Check Detection
       ↓
Metadata Extraction
       ↓
Path Generation
       ↓
Route Registration
       ↓
Load Balancer Update
       ↓
WebSocket Broadcast
       ↓
Ready for Traffic
```

## 🛠️ Troubleshooting

### Common Issues

1. **Service not discovered**
   ```bash
   # Check if health endpoint exists
   curl http://localhost:3005/health
   
   # Check gateway discovery logs
   docker logs opendirectory-api-gateway | grep DISCOVERY
   ```

2. **Requests not routing**
   ```bash
   # Check registered services
   curl http://localhost:3000/services
   
   # Check specific service health
   curl http://localhost:3000/admin/services/my-service/health
   ```

3. **Load balancing issues**
   ```bash
   # Check active connections
   curl http://localhost:3000/admin/connections
   
   # Check metrics
   curl http://localhost:3000/metrics
   ```

## 🔗 Related Services

- [Authentication Service](../authentication-service/README.md)
- [Device Management Service](../device-service/README.md)
- [Network Infrastructure Service](../network-infrastructure/README.md)
- [Monitoring Service](../monitoring-service/README.md)

---

**OpenDirectory API Gateway v2.0** - Generisches, selbst-erweiterndes Gateway für moderne Microservice-Architekturen.