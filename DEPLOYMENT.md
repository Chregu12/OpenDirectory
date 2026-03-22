# 🚀 OpenDirectory MDM - Deployment Guide

## 📦 Production Deployment Files:

### **Main Application:**
- `multi-platform-app-store.yaml` - Complete Kubernetes deployment
- `infrastructure/kubernetes/` - All K8s manifests

### **Quick Deployment:**
- `deploy-to-k3s-cluster.sh` - Deploy to K3s cluster
- `k3s-server-deployment.sh` - Run directly on K3s server

### **Client Agents:**
- `macos-deployment-agent.sh` - macOS agent
- `windows-deployment-agent.ps1` - Windows agent

## 🎯 Deployment Options:

### **Option 1: K3s Cluster (Recommended)**
```bash
./deploy-to-k3s-cluster.sh
```
Access: http://192.168.1.200

### **Option 2: Direct on K3s Server**
Copy `k3s-server-deployment.sh` to server and run:
```bash
./k3s-server-deployment.sh
```

### **Option 3: Docker Compose**
```bash
docker-compose up -d
```

## 📋 Architecture:
See `ARCHITECTURE.md` for complete system overview.

## 🔧 Integration:
See `NEXTERM_DEPLOYMENT_GUIDE.md` for nexterm deployment.

## ⚙️ Environment Variables (web-app)

The following `NEXT_PUBLIC_*` variables can be set in the web-app deployment to reflect the correct environment in Settings → System:

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_DEPLOY_PLATFORM` | `Docker Compose` | Shown under Settings → System → About. Set to `Kubernetes / k3s` for K8s deployments. |
| `NEXT_PUBLIC_DEPLOY_NAMESPACE` | `opendirectory` | Kubernetes namespace or logical grouping name. |
| `NEXT_PUBLIC_API_URL` | _(empty — relative)_ | Override API base URL if the frontend is not served from the same origin. |
| `PRINTER_SERVICE_URL` | `http://printer-service:3006` | Internal URL of the printer-service (used by Next.js server-side rewrites). |

### Kubernetes / k3s Example

Add to the `web-app` Deployment manifest under `spec.containers[].env`:

```yaml
- name: NEXT_PUBLIC_DEPLOY_PLATFORM
  value: "Kubernetes / k3s"
- name: NEXT_PUBLIC_DEPLOY_NAMESPACE
  value: "opendirectory"
```

### Docker Compose Example

Add to `docker-compose.yml` under `web-app.environment`:

```yaml
- NEXT_PUBLIC_DEPLOY_PLATFORM=Kubernetes / k3s
- NEXT_PUBLIC_DEPLOY_NAMESPACE=opendirectory
```

**Ready for production deployment!** 🎉