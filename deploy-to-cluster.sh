#!/bin/bash

echo "🚀 Deploying OpenDirectory MDM to Kubernetes Cluster"
echo "===================================================="

CLUSTER_HOST=${CLUSTER_HOST:-"192.168.1.200"}
KUBE_CONFIG=${KUBE_CONFIG:-"$HOME/.kube/config"}

echo "📋 Configuration:"
echo "  - Cluster Host: $CLUSTER_HOST"
echo "  - Kube Config: $KUBE_CONFIG"
echo ""

# Check if kubectl is configured
if ! kubectl cluster-info &>/dev/null; then
    echo "❌ kubectl not configured or cluster not reachable"
    echo "   Please configure kubectl to connect to $CLUSTER_HOST"
    echo ""
    echo "💡 Quick setup:"
    echo "   kubectl config set-cluster opendirectory --server=https://$CLUSTER_HOST:6443 --insecure-skip-tls-verify=true"
    echo "   kubectl config set-context opendirectory --cluster=opendirectory"
    echo "   kubectl config use-context opendirectory"
    exit 1
fi

echo "✅ Connected to Kubernetes cluster"
kubectl cluster-info

echo ""
echo "🏗️  Creating namespace..."
kubectl create namespace opendirectory --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "🚀 Deploying API Backend..."
kubectl apply -f infrastructure/kubernetes/api-backend-deployment.yaml

echo ""
echo "📱 Deploying Dashboard..."
kubectl apply -f multi-platform-app-store.yaml

echo ""
echo "⏳ Waiting for deployments..."
kubectl wait --for=condition=available --timeout=300s deployment/opendirectory-api-backend -n opendirectory
kubectl wait --for=condition=available --timeout=300s deployment/working-console -n opendirectory 2>/dev/null || echo "Dashboard deployment might use different name"

echo ""
echo "📊 Deployment Status:"
kubectl get pods -n opendirectory
kubectl get services -n opendirectory

echo ""
echo "🌐 Access URLs:"
echo "  - Dashboard: http://$CLUSTER_HOST:30080"
echo "  - API Backend: http://$CLUSTER_HOST:30301"
echo "  - Health Check: http://$CLUSTER_HOST:30301/api/health"

echo ""
echo "✅ OpenDirectory MDM deployed successfully!"
echo ""
echo "🔧 Useful commands:"
echo "  - Check logs: kubectl logs -f deployment/opendirectory-api-backend -n opendirectory"
echo "  - Scale API: kubectl scale deployment opendirectory-api-backend --replicas=2 -n opendirectory"
echo "  - Delete: kubectl delete namespace opendirectory"