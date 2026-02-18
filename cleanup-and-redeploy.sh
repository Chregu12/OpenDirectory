#!/bin/bash

echo "🧹 Cleaning up existing OpenDirectory deployment"
echo "=============================================="

echo "🔍 Removing OpenDirectory API Backend..."
kubectl delete deployment opendirectory-api-backend -n opendirectory --ignore-not-found=true

echo "🔍 Removing OpenDirectory services..."
kubectl delete service opendirectory-api-backend-service -n opendirectory --ignore-not-found=true
kubectl delete service opendirectory-dashboard-service -n opendirectory --ignore-not-found=true

echo "🔍 Removing OpenDirectory ingress..."
kubectl delete ingress opendirectory-main-ingress -n opendirectory --ignore-not-found=true
kubectl delete ingress opendirectory-ingress -n opendirectory --ignore-not-found=true

echo "🔍 Removing OpenDirectory configmaps..."
kubectl delete configmap api-backend-source -n opendirectory --ignore-not-found=true

echo "🔍 Removing any OpenDirectory pods..."
kubectl delete pods -l app=opendirectory-api-backend -n opendirectory --ignore-not-found=true

echo ""
echo "⏳ Waiting for cleanup to complete..."
sleep 10

echo ""
echo "📊 Current namespace status:"
kubectl get all -n opendirectory | grep -v "authentik\|grafana\|lldap\|loki\|prometheus\|redis\|step-ca\|vault\|working-integration" || echo "Only core services remaining"

echo ""
echo "🚀 Starting fresh OpenDirectory deployment..."
echo "============================================="

# Deploy fresh
kubectl apply -f infrastructure/kubernetes/opendirectory-complete.yaml

echo ""
echo "⏳ Waiting for new deployment..."
sleep 15

echo ""
echo "📊 New deployment status:"
kubectl get pods -n opendirectory -l app=opendirectory-api-backend 2>/dev/null || echo "New pods starting..."
kubectl get services -n opendirectory | grep opendirectory 2>/dev/null || echo "New services creating..."
kubectl get ingress -n opendirectory 2>/dev/null || echo "New ingress configuring..."

echo ""
echo "🧪 Testing fresh deployment..."

# Test API
echo "📡 Testing API: http://192.168.1.223/api/health"
sleep 5
if curl -s --connect-timeout 10 http://192.168.1.223/api/health | grep -q "healthy" 2>/dev/null; then
    echo "✅ Fresh API is responding!"
    curl -s http://192.168.1.223/api/health | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'📊 Status: {data[\"data\"][\"status\"]}')
    print(f'📱 Devices: {data[\"data\"][\"stats\"][\"devices\"]}')
except: pass
" 2>/dev/null
else
    echo "⏳ API still starting after cleanup..."
fi

# Test Dashboard
echo "📱 Testing Dashboard: http://192.168.1.223/"
if curl -s --connect-timeout 5 http://192.168.1.223/ | grep -q -i "opendirectory" 2>/dev/null; then
    echo "✅ Fresh Dashboard is accessible!"
else
    echo "⏳ Dashboard still loading..."
fi

echo ""
echo "✅ OpenDirectory cleanup and redeploy complete!"
echo ""
echo "🌐 Fresh deployment available at:"
echo "   👉 http://192.168.1.223"
echo ""
echo "🔧 Monitor deployment:"
echo "   kubectl logs -f -n opendirectory -l app=opendirectory-api-backend"
echo "   kubectl get pods -n opendirectory -w"