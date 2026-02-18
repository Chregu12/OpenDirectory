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

**Ready for production deployment!** 🎉