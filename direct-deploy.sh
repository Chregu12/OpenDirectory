#!/bin/bash

echo "🚀 Direct Kubernetes Deployment to 192.168.1.200"
echo "================================================"

CLUSTER_HOST="192.168.1.200"
K8S_TOKEN=""  # Add your token here if needed

# Test cluster connectivity
echo "🔍 Testing cluster connectivity..."
if curl -k -s https://$CLUSTER_HOST:6443/version | grep -q "gitVersion"; then
    echo "✅ Kubernetes API is accessible"
else
    echo "❌ Cannot reach Kubernetes API"
    echo "   Make sure kubectl is configured or provide authentication"
    exit 1
fi

echo ""
echo "📦 Creating deployment manifests..."

# Create namespace manifest
cat > /tmp/namespace.yaml << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: opendirectory
EOF

# Apply via kubectl (assuming it's configured)
echo "🏗️  Applying namespace..."
if command -v kubectl >/dev/null 2>&1; then
    kubectl apply -f /tmp/namespace.yaml
    kubectl apply -f infrastructure/kubernetes/api-backend-deployment.yaml
    kubectl apply -f multi-platform-app-store.yaml
    
    echo "⏳ Waiting for services to start..."
    sleep 20
    
    echo "📊 Checking status..."
    kubectl get pods -n opendirectory --no-headers 2>/dev/null | grep -E "(Running|Ready)" && echo "✅ Pods are running" || echo "⏳ Pods still starting"
    kubectl get services -n opendirectory 2>/dev/null | grep -E "NodePort|LoadBalancer" && echo "✅ Services exposed" || echo "⚠️  Services not ready"
else
    echo "❌ kubectl not available"
    exit 1
fi

echo ""
echo "🌐 Testing endpoints..."
echo "  - API Health: http://$CLUSTER_HOST:30301/api/health"
echo "  - Dashboard:  http://$CLUSTER_HOST:30080"

# Test API
if curl -s --connect-timeout 5 http://$CLUSTER_HOST:30301/api/health | grep -q "healthy"; then
    echo "✅ API is responding"
    curl -s http://$CLUSTER_HOST:30301/api/health | python3 -m json.tool | head -10
else
    echo "⏳ API not yet ready (may take a few minutes)"
fi

# Test Dashboard
if curl -s --connect-timeout 5 http://$CLUSTER_HOST:30080/ | grep -q "OpenDirectory"; then
    echo "✅ Dashboard is accessible"
else
    echo "⏳ Dashboard not yet ready"
fi

echo ""
echo "✅ Deployment completed!"
echo "🔧 Useful commands:"
echo "   kubectl logs -f -n opendirectory -l app=opendirectory-api-backend"
echo "   kubectl get pods -n opendirectory -w"