# 🚀 OpenDirectory K3s Deployment via Nexterm

## 📋 Nexterm Login:
```
URL: https://nexterm.heusser.local/servers
User: cheusser
Password: Waistrei1994@
```

## 🎯 Server: 192.168.1.200 (K3s Cluster)

### Schritt 1: Mit K3s Server verbinden
1. Gehe zu https://nexterm.heusser.local/servers
2. Login mit: cheusser / Waistrei1994@
3. Wähle Server 192.168.1.200
4. Öffne Terminal

### Schritt 2: K3s Status prüfen
```bash
# K3s Cluster Status
kubectl cluster-info
kubectl get nodes
kubectl get namespaces
```

### Schritt 3: OpenDirectory Deployment erstellen
```bash
# Erstelle Deployment-Datei
cat > opendirectory-k3s.yaml << 'EOF'
# OpenDirectory MDM für K3s mit Traefik Ingress
apiVersion: v1
kind: Namespace
metadata:
  name: opendirectory

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opendirectory-api
  namespace: opendirectory
spec:
  replicas: 2
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
        image: node:18-alpine
        ports:
        - containerPort: 3001
        env:
        - name: PORT
          value: "3001"
        - name: BASE_URL
          value: "http://192.168.1.200"
        workingDir: /app
        command: ["/bin/sh"]
        args: ["-c", "npm install && node server.js"]
        volumeMounts:
        - name: app-code
          mountPath: /app
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: app-code
        configMap:
          name: api-source

---
apiVersion: v1
kind: Service
metadata:
  name: opendirectory-api-service
  namespace: opendirectory
spec:
  selector:
    app: opendirectory-api
  ports:
  - port: 3001
    targetPort: 3001

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opendirectory-dashboard
  namespace: opendirectory
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opendirectory-dashboard
  template:
    metadata:
      labels:
        app: opendirectory-dashboard
    spec:
      containers:
      - name: dashboard
        image: nginx:alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: dashboard-html
          mountPath: /usr/share/nginx/html
      volumes:
      - name: dashboard-html
        configMap:
          name: dashboard-html

---
apiVersion: v1
kind: Service
metadata:
  name: opendirectory-dashboard-service
  namespace: opendirectory
spec:
  selector:
    app: opendirectory-dashboard
  ports:
  - port: 80
    targetPort: 80

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: opendirectory-ingress
  namespace: opendirectory
  annotations:
    traefik.ingress.kubernetes.io/router.rule: "Host(\`192.168.1.200\`)"
spec:
  rules:
  - host: "192.168.1.200"
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: opendirectory-api-service
            port:
              number: 3001
      - path: /
        pathType: Prefix
        backend:
          service:
            name: opendirectory-dashboard-service
            port:
              number: 80

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-source
  namespace: opendirectory
data:
  package.json: |
    {
      "name": "opendirectory-api",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2",
        "cors": "^2.8.5",
        "ws": "^8.14.2"
      }
    }
  server.js: |
    const express = require('express');
    const cors = require('cors');
    const app = express();
    
    app.use(cors());
    app.use(express.json());
    
    const devices = [{
      id: 'CT2001',
      name: 'Ubuntu-CT2001', 
      platform: 'linux',
      status: 'online',
      lastSeen: new Date()
    }];
    
    app.get('/api/health', (req, res) => {
      res.json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date(),
          stats: { devices: devices.length, users: 1 }
        }
      });
    });
    
    app.get('/api/devices', (req, res) => {
      res.json({ success: true, data: devices });
    });
    
    app.post('/api/devices/:id/refresh', (req, res) => {
      const device = devices.find(d => d.id === req.params.id);
      if (device) {
        device.lastSeen = new Date();
        device.status = Math.random() > 0.1 ? 'online' : 'offline';
      }
      res.json({ success: true, data: device });
    });
    
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(\`OpenDirectory API running on port \${PORT}\`);
    });

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: dashboard-html
  namespace: opendirectory
data:
  index.html: |
    <!DOCTYPE html>
    <html>
    <head>
        <title>OpenDirectory MDM</title>
        <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .card { background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
            .btn:hover { background: #0056b3; }
            .status { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; margin: 10px 0; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <div id="app">
            <div class="container">
                <div class="card">
                    <h1>🚀 OpenDirectory MDM</h1>
                    <p>Enterprise Mobile Device Management Platform</p>
                    
                    <div>
                        <button class="btn" @click="testAPI">Test API Health</button>
                        <button class="btn" @click="loadDevices">Load Devices</button>
                        <button class="btn" @click="refreshDevice">Refresh CT2001</button>
                    </div>
                    
                    <div v-if="status" class="status">{{ status }}</div>
                </div>
            </div>
        </div>
        
        <script>
        const { createApp } = Vue;
        createApp({
            data() {
                return { status: '' };
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
                async refreshDevice() {
                    try {
                        const response = await fetch('/api/devices/CT2001/refresh', { method: 'POST' });
                        const data = await response.json();
                        this.status = JSON.stringify(data, null, 2);
                    } catch (error) {
                        this.status = 'Refresh Error: ' + error.message;
                    }
                }
            }
        }).mount('#app');
        </script>
    </body>
    </html>
EOF
```

### Schritt 4: Deployment ausführen
```bash
# OpenDirectory deployen
kubectl apply -f opendirectory-k3s.yaml

# Status prüfen
kubectl get pods -n opendirectory
kubectl get services -n opendirectory
kubectl get ingress -n opendirectory
```

### Schritt 5: Deployment überwachen
```bash
# Pods-Status verfolgen
kubectl get pods -n opendirectory -w

# API-Logs ansehen
kubectl logs -f -n opendirectory -l app=opendirectory-api

# Services testen
kubectl get svc -n opendirectory
```

### Schritt 6: Testen
```bash
# API testen (auf K3s-Server)
curl http://localhost/api/health

# Oder von außen
curl http://192.168.1.200/api/health
```

## 🌐 Erwartetes Ergebnis:

Nach erfolgreichem Deployment:
```
✅ http://192.168.1.200/          → OpenDirectory Dashboard
✅ http://192.168.1.200/api/health → API Health Check
```

## 🔧 Nützliche Befehle:

```bash
# Alles löschen
kubectl delete namespace opendirectory

# Neu starten
kubectl rollout restart deployment/opendirectory-api -n opendirectory

# Service-Status
kubectl describe ingress opendirectory-ingress -n opendirectory
```

## ✅ Das war's!

OpenDirectory MDM läuft dann auf http://192.168.1.200 mit Traefik Ingress im K3s-Cluster!