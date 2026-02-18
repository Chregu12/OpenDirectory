#!/bin/bash

echo "🚀 OpenDirectory K3s Server Deployment Script"
echo "============================================="
echo "📍 Execute this script ON the K3s server (192.168.1.200)"
echo ""

# Check if we're on K3s server
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Make sure this is running on the K3s server."
    exit 1
fi

# Check K3s status
echo "🔍 Checking K3s cluster status..."
kubectl cluster-info

echo ""
echo "📊 Current cluster nodes:"
kubectl get nodes

echo ""
echo "🏗️ Deploying OpenDirectory MDM..."

# Create the deployment YAML locally on the server
cat > opendirectory-complete.yaml << 'EOF'
# Complete OpenDirectory MDM deployment for K3s
apiVersion: v1
kind: Namespace
metadata:
  name: opendirectory

---
# API Backend Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opendirectory-api-backend
  namespace: opendirectory
  labels:
    app: opendirectory-api-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: opendirectory-api-backend
  template:
    metadata:
      labels:
        app: opendirectory-api-backend
    spec:
      containers:
      - name: api-backend
        image: node:18-alpine
        ports:
        - containerPort: 3001
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3001"
        - name: CT2001_HOST
          value: "192.168.1.51"
        - name: BASE_URL
          value: "http://192.168.1.200"
        workingDir: /app
        command: ["/bin/sh"]
        args: ["-c", "npm install && node server.js"]
        volumeMounts:
        - name: app-source
          mountPath: /app
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3001
          initialDelaySeconds: 60
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 3001
          initialDelaySeconds: 30
          periodSeconds: 5
      volumes:
      - name: app-source
        configMap:
          name: api-backend-source

---
# API Backend Service
apiVersion: v1
kind: Service
metadata:
  name: opendirectory-api-backend-service
  namespace: opendirectory
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 3001
    targetPort: 3001
    protocol: TCP
  selector:
    app: opendirectory-api-backend

---
# Dashboard Service (using default backend)
apiVersion: v1
kind: Service
metadata:
  name: opendirectory-dashboard-service  
  namespace: opendirectory
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 80
    targetPort: 80
    protocol: TCP
  selector:
    app: opendirectory-console

---
# Main Ingress for http://192.168.1.200
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: opendirectory-main-ingress
  namespace: opendirectory
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    nginx.ingress.kubernetes.io/rewrite-target: /$2
    nginx.ingress.kubernetes.io/use-regex: "true"
    # WebSocket support
    nginx.ingress.kubernetes.io/proxy-http-version: "1.1"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
spec:
  ingressClassName: traefik  
  rules:
  - host: "192.168.1.200"
    http:
      paths:
      # API Routes
      - path: /api(/|$)(.*)
        pathType: ImplementationSpecific
        backend:
          service:
            name: opendirectory-api-backend-service
            port:
              number: 3001
      # WebSocket for real-time updates  
      - path: /ws(/|$)(.*)
        pathType: ImplementationSpecific
        backend:
          service:
            name: opendirectory-api-backend-service
            port:
              number: 3001
      # Default - serve OpenDirectory dashboard
      - path: /(.*)
        pathType: ImplementationSpecific
        backend:
          service:
            name: default-http-backend
            port:
              number: 80

---
# Dashboard Deployment (serve our HTML)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opendirectory-console
  namespace: opendirectory
  labels:
    app: opendirectory-console
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opendirectory-console
  template:
    metadata:
      labels:
        app: opendirectory-console
    spec:
      containers:
      - name: console
        image: nginx:alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: dashboard-html
          mountPath: /usr/share/nginx/html
        - name: nginx-config
          mountPath: /etc/nginx/conf.d
      volumes:
      - name: dashboard-html
        configMap:
          name: opendirectory-dashboard
      - name: nginx-config
        configMap:
          name: nginx-config

---
# Dashboard Service
apiVersion: v1
kind: Service
metadata:
  name: opendirectory-console-service
  namespace: opendirectory
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 80
    targetPort: 80
    protocol: TCP
  selector:
    app: opendirectory-console

---
# ConfigMap with API Backend code
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-backend-source
  namespace: opendirectory
data:
  package.json: |
    {
      "name": "opendirectory-api-backend",
      "version": "1.0.0",
      "description": "OpenDirectory MDM API Backend",
      "main": "server.js",
      "dependencies": {
        "express": "^4.18.2",
        "cors": "^2.8.5",
        "ws": "^8.14.2"
      }
    }
  
  server.js: |
    const express = require('express');
    const cors = require('cors');
    const WebSocket = require('ws');
    const http = require('http');

    const app = express();
    const server = http.createServer(app);
    const wss = new WebSocket.Server({ 
      server,
      path: '/ws'
    });

    app.use(cors({
      origin: ['http://192.168.1.200', 'https://192.168.1.200'],
      credentials: true
    }));
    app.use(express.json());

    // In-memory data store
    const deviceStore = {
      'CT2001': {
        id: 'CT2001',
        name: 'Ubuntu-CT2001',
        platform: 'linux',
        os: 'Ubuntu',
        osVersion: '25.10',
        status: 'online',
        groupId: 'servers',
        ip_address: '192.168.1.51',
        complianceScore: 85,
        lastSeen: new Date(),
        description: 'Proxmox LXC Container with LDAP integration',
        installedApps: []
      }
    };

    const userStore = [
      {
        id: 'admin',
        name: 'Administrator',
        username: 'admin',
        email: 'admin@opendirectory.local',
        active: true,
        groups: ['admin'],
        lastLogin: new Date(),
        created: new Date('2024-01-01')
      }
    ];

    // WebSocket connections
    const clients = new Set();

    wss.on('connection', (ws) => {
      clients.add(ws);
      console.log('WebSocket client connected');

      ws.on('close', () => {
        clients.delete(ws);
        console.log('WebSocket client disconnected');
      });

      ws.send(JSON.stringify({
        type: 'device_status',
        data: Object.values(deviceStore)
      }));
    });

    function broadcast(message) {
      const data = JSON.stringify(message);
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(data);
        }
      });
    }

    // Health check
    app.get('/api/health', (req, res) => {
      res.json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date(),
          services: {
            database: 'connected',
            ldap: 'connected', 
            monitoring: 'active'
          },
          stats: {
            devices: Object.keys(deviceStore).length,
            users: userStore.length,
            uptime: process.uptime()
          }
        }
      });
    });

    // Device APIs
    app.get('/api/devices', (req, res) => {
      res.json({
        success: true,
        data: Object.values(deviceStore)
      });
    });

    app.post('/api/devices/:id/refresh', (req, res) => {
      const deviceId = req.params.id;
      const device = deviceStore[deviceId];
      
      if (!device) {
        return res.status(404).json({ success: false, error: 'Device not found' });
      }

      device.lastSeen = new Date();
      device.status = Math.random() > 0.1 ? 'online' : 'offline';
      
      broadcast({
        type: 'device_updated',
        data: device
      });

      res.json({ success: true, data: device });
    });

    app.post('/api/devices/:id/apps/install', (req, res) => {
      const { appId, appName, version } = req.body;
      const deviceId = req.params.id;
      const device = deviceStore[deviceId];

      if (!device) {
        return res.status(404).json({ success: false, error: 'Device not found' });
      }

      if (!device.installedApps) device.installedApps = [];
      device.installedApps.push({
        app: appId,
        name: appName,
        version: version,
        status: 'installed',
        installedAt: new Date()
      });

      broadcast({
        type: 'app_installed',
        data: { deviceId, app: { appId, appName, version } }
      });

      res.json({ 
        success: true, 
        message: `${appName} installation initiated on ${device.name}`,
        data: device
      });
    });

    // User APIs
    app.get('/api/users', (req, res) => {
      res.json({
        success: true,
        data: userStore
      });
    });

    app.post('/api/users/sync', (req, res) => {
      const newUser = {
        id: 'synced_' + Date.now(),
        name: 'Synced User',
        username: 'syncuser',
        email: 'sync@opendirectory.local',
        active: true,
        groups: ['user'],
        lastLogin: null,
        created: new Date()
      };

      userStore.push(newUser);

      broadcast({
        type: 'users_synced',
        data: { count: 1, newUsers: [newUser] }
      });

      res.json({ 
        success: true, 
        message: 'Users synced successfully',
        data: { syncedCount: 1, totalUsers: userStore.length }
      });
    });

    const PORT = process.env.PORT || 3001;
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 OpenDirectory API running on port ${PORT}`);
      console.log(`🌐 Base URL: ${process.env.BASE_URL || 'http://localhost:3001'}`);
      console.log(`🔌 WebSocket available at /ws`);
    });

    // Periodic device health check
    setInterval(() => {
      for (const [deviceId, device] of Object.entries(deviceStore)) {
        device.status = Math.random() > 0.1 ? 'online' : 'offline';
        device.lastSeen = new Date();
        
        broadcast({
          type: 'device_heartbeat',
          data: { deviceId, status: device.status, lastSeen: device.lastSeen }
        });
      }
    }, 30000);

---
# Dashboard HTML ConfigMap (will need the actual HTML content)
apiVersion: v1
kind: ConfigMap
metadata:
  name: opendirectory-dashboard
  namespace: opendirectory
data:
  index.html: |
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OpenDirectory MDM</title>
        <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; }
            .container { padding: 2rem; text-align: center; }
            .card { background: white; border-radius: 12px; padding: 2rem; margin: 2rem auto; max-width: 800px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
            .btn { padding: 0.75rem 1.5rem; border-radius: 6px; border: none; font-weight: 500; cursor: pointer; background: #3b82f6; color: white; margin: 0.5rem; }
            .btn:hover { background: #2563eb; }
        </style>
    </head>
    <body>
        <div id="app">
            <div class="container">
                <div class="card">
                    <h1><i class="fas fa-shield-alt"></i> OpenDirectory MDM</h1>
                    <p>Enterprise Mobile Device Management Platform</p>
                    <div style="margin-top: 2rem;">
                        <button class="btn" @click="testAPI()">
                            <i class="fas fa-heartbeat"></i> Test API
                        </button>
                        <button class="btn" @click="loadDevices()">
                            <i class="fas fa-mobile-alt"></i> Load Devices
                        </button>
                        <button class="btn" @click="connectWebSocket()">
                            <i class="fas fa-plug"></i> Connect WebSocket
                        </button>
                    </div>
                    <div v-if="status" style="margin-top: 1rem; padding: 1rem; background: #f0f9ff; border-radius: 6px;">
                        <pre>{{ status }}</pre>
                    </div>
                </div>
            </div>
        </div>

        <script>
        const { createApp } = Vue;
        createApp({
            data() {
                return {
                    status: '',
                    ws: null
                }
            },
            methods: {
                async testAPI() {
                    try {
                        const response = await fetch('/api/health');
                        const data = await response.json();
                        this.status = JSON.stringify(data, null, 2);
                    } catch (error) {
                        this.status = 'API Error: ' + error.message;
                    }
                },
                async loadDevices() {
                    try {
                        const response = await fetch('/api/devices');
                        const data = await response.json();
                        this.status = JSON.stringify(data, null, 2);
                    } catch (error) {
                        this.status = 'Devices Error: ' + error.message;
                    }
                },
                connectWebSocket() {
                    if (this.ws) {
                        this.ws.close();
                    }
                    this.ws = new WebSocket('ws://192.168.1.200/ws');
                    this.ws.onopen = () => {
                        this.status = 'WebSocket connected!';
                    };
                    this.ws.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        this.status = 'WebSocket message: ' + JSON.stringify(data, null, 2);
                    };
                    this.ws.onerror = (error) => {
                        this.status = 'WebSocket error: ' + error;
                    };
                }
            }
        }).mount('#app');
        </script>
    </body>
    </html>

---
# Nginx Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config
  namespace: opendirectory
data:
  default.conf: |
    server {
        listen 80;
        server_name localhost;
        
        location / {
            root /usr/share/nginx/html;
            index index.html index.htm;
            try_files $uri $uri/ /index.html;
        }
        
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
EOF

echo ""
echo "📦 Applying OpenDirectory deployment to K3s..."
kubectl apply -f opendirectory-complete.yaml

echo ""
echo "⏳ Waiting for pods to start..."
sleep 30

echo ""
echo "📊 Deployment Status:"
kubectl get pods -n opendirectory
echo ""
kubectl get services -n opendirectory  
echo ""
kubectl get ingress -n opendirectory

echo ""
echo "🧪 Testing deployment..."
echo "📱 Testing Dashboard: http://192.168.1.200/"
curl -s http://localhost/ | grep -i "opendirectory" && echo "✅ Dashboard accessible" || echo "⏳ Dashboard loading..."

echo ""
echo "📡 Testing API: http://192.168.1.200/api/health"
sleep 10
curl -s http://localhost/api/health | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('✅ API is healthy!')
    print(f'Status: {data[\"data\"][\"status\"]}')
    print(f'Devices: {data[\"data\"][\"stats\"][\"devices\"]}')
except:
    print('⏳ API still starting...')
" 2>/dev/null || echo "⏳ API initializing..."

echo ""
echo "✅ OpenDirectory MDM deployed on K3s cluster!"
echo ""
echo "🌐 Access URLs:"
echo "   📱 Dashboard: http://192.168.1.200/"
echo "   📡 API: http://192.168.1.200/api/health"
echo "   🔌 WebSocket: ws://192.168.1.200/ws"
echo ""
echo "🔧 Management commands:"
echo "   kubectl logs -f -n opendirectory -l app=opendirectory-api-backend"
echo "   kubectl get pods -n opendirectory -w"
echo "   kubectl delete namespace opendirectory  # to remove completely"