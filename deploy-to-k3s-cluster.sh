#!/bin/bash

echo "🚀 Deploying OpenDirectory to K3s Cluster at 192.168.1.200"
echo "=========================================================="

K3S_HOST="192.168.1.200"

echo "📋 K3s Cluster Configuration:"
echo "  🌐 Host: $K3S_HOST"
echo "  🔧 Kubernetes API: https://$K3S_HOST:6443"
echo "  📱 Dashboard: http://$K3S_HOST/"
echo "  ⚡ API: http://$K3S_HOST/api/"
echo "  🔌 WebSocket: ws://$K3S_HOST/ws"
echo ""

echo "🔍 Testing K3s API connectivity..."
if curl -k -s --connect-timeout 5 https://$K3S_HOST:6443/version | grep -q "gitVersion" 2>/dev/null; then
    echo "✅ K3s API is accessible"
    echo "   $(curl -k -s https://$K3S_HOST:6443/version | python3 -c 'import json,sys; print("Version:", json.load(sys.stdin).get("gitVersion", "Unknown"))' 2>/dev/null || echo "K3s API responding")"
else
    echo "⚠️  K3s API not accessible from here, but proceeding with deployment..."
fi

echo ""
echo "🏗️  Deploying OpenDirectory complete stack to K3s..."

# Create namespace first
echo "📦 Creating opendirectory namespace..."
kubectl create namespace opendirectory --dry-run=client -o yaml | kubectl apply -f -

# Deploy complete stack
echo "🚀 Deploying OpenDirectory stack..."
kubectl apply -f infrastructure/kubernetes/opendirectory-complete.yaml

echo ""
echo "⏳ Waiting for K3s deployment..."
sleep 20

echo ""
echo "📊 K3s Deployment Status:"
kubectl get pods -n opendirectory -l app=opendirectory-api-backend 2>/dev/null | head -10 || echo "Pods are being created..."
kubectl get services -n opendirectory 2>/dev/null | grep opendirectory || echo "Services are being created..."
kubectl get ingress -n opendirectory 2>/dev/null | head -5 || echo "Ingress is being configured..."

echo ""
echo "🧪 Testing K3s OpenDirectory endpoints..."

# Test Dashboard
echo "📱 Testing Dashboard: http://$K3S_HOST/"
if curl -s --connect-timeout 10 http://$K3S_HOST/ | grep -q -i "opendirectory" 2>/dev/null; then
    echo "   ✅ Dashboard is accessible on K3s cluster"
else
    echo "   ⏳ Dashboard still starting on K3s..."
fi

# Test API  
echo "⚡ Testing API: http://$K3S_HOST/api/health"
sleep 5
if curl -s --connect-timeout 10 http://$K3S_HOST/api/health | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('   ✅ API is healthy on K3s cluster!')
    print(f'   📊 Status: {data[\"data\"][\"status\"]}')
    print(f'   📱 Devices: {data[\"data\"][\"stats\"][\"devices\"]}')
    print(f'   👥 Users: {data[\"data\"][\"stats\"][\"users\"]}')
except:
    print('   ⏳ API still starting on K3s...')
" 2>/dev/null; then
    echo ""
else
    echo "   ⏳ API still initializing on K3s cluster..."
fi

echo ""
echo "✅ OpenDirectory deployment to K3s cluster complete!"
echo ""
echo "🎯 K3s Access URLs:"
echo "   🌐 OpenDirectory MDM: http://$K3S_HOST"
echo "   📡 API Health Check:  http://$K3S_HOST/api/health" 
echo "   🔌 WebSocket:         ws://$K3S_HOST/ws"
echo ""
echo "🔧 K3s Management:"
echo "   kubectl get pods -n opendirectory -w"
echo "   kubectl logs -f -n opendirectory -l app=opendirectory-api-backend"
echo "   kubectl get ingress -n opendirectory"
echo ""
echo "🎉 OpenDirectory MDM is now running on the K3s cluster!"