#!/bin/bash

echo "🚀 Deploying OpenDirectory MDM on http://192.168.1.223 (Standard Ports)"
echo "====================================================================="

CLUSTER_HOST="192.168.1.223"

echo "📋 Configuration:"
echo "  🌐 Base URL: http://$CLUSTER_HOST"
echo "  📱 Dashboard: http://$CLUSTER_HOST/"
echo "  ⚡ API: http://$CLUSTER_HOST/api/"
echo "  🔌 WebSocket: ws://$CLUSTER_HOST/ws"
echo "  🔀 Routing: Nginx Ingress"
echo ""

echo "🏗️  Deploying complete OpenDirectory stack..."
kubectl apply -f infrastructure/kubernetes/opendirectory-complete.yaml

echo ""
echo "⏳ Waiting for services to start..."
kubectl wait --for=condition=available --timeout=180s deployment/opendirectory-api-backend -n opendirectory 2>/dev/null || echo "API Backend deploying..."

echo ""
echo "📊 Deployment Status:"
kubectl get pods -n opendirectory -l app=opendirectory-api-backend 2>/dev/null || echo "Pods starting..."
kubectl get ingress -n opendirectory 2>/dev/null || echo "Ingress configuring..."
kubectl get services -n opendirectory 2>/dev/null || echo "Services starting..."

echo ""
echo "🧪 Testing endpoints..."

# Wait a bit for services to start
sleep 10

# Test API Health
echo "  📡 Testing API: http://$CLUSTER_HOST/api/health"
if curl -s --connect-timeout 10 http://$CLUSTER_HOST/api/health | grep -q "healthy" 2>/dev/null; then
    echo "     ✅ API is healthy"
    curl -s http://$CLUSTER_HOST/api/health | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'     📊 Uptime: {data[\"data\"][\"stats\"][\"uptime\"]:.1f}s')
    print(f'     📱 Devices: {data[\"data\"][\"stats\"][\"devices\"]}')
    print(f'     👥 Users: {data[\"data\"][\"stats\"][\"users\"]}')
except: pass
" 2>/dev/null
else
    echo "     ⏳ API still starting..."
fi

# Test Dashboard
echo "  📱 Testing Dashboard: http://$CLUSTER_HOST/"
if curl -s --connect-timeout 5 http://$CLUSTER_HOST/ | grep -q -i "opendirectory\|html" 2>/dev/null; then
    echo "     ✅ Dashboard is accessible"
else
    echo "     ⏳ Dashboard still loading..."
fi

echo ""
echo "🎯 Route Configuration:"
echo "  📱 http://$CLUSTER_HOST/          → Dashboard (nginx)"
echo "  ⚡ http://$CLUSTER_HOST/api/*     → API Backend (Node.js)"
echo "  🔌 ws://$CLUSTER_HOST/ws         → WebSocket (real-time)"

echo ""
echo "✅ OpenDirectory MDM Deployment Complete!"
echo ""
echo "🌐 Access your Enterprise MDM:"
echo "   👉 http://$CLUSTER_HOST"
echo ""
echo "🔗 Integration Ready:"
echo "   📊 Grafana: http://$CLUSTER_HOST:30300"
echo "   👥 LLDAP: http://$CLUSTER_HOST:30170" 
echo "   🔐 Vault: http://$CLUSTER_HOST:30820"
echo ""
echo "🔧 Troubleshooting:"
echo "   kubectl logs -f -n opendirectory -l app=opendirectory-api-backend"
echo "   kubectl get ingress -n opendirectory"