#!/bin/bash

echo "🚀 Quick Deploy to 192.168.1.200 Cluster"

# Direct deployment using existing kubectl context
kubectl create namespace opendirectory --dry-run=client -o yaml | kubectl apply -f -

echo "📦 Deploying API Backend..."
kubectl apply -f infrastructure/kubernetes/api-backend-deployment.yaml

echo "📱 Deploying Dashboard..."  
kubectl apply -f multi-platform-app-store.yaml

echo "⏳ Waiting for pods..."
sleep 10

echo "📊 Status:"
kubectl get pods -n opendirectory
kubectl get services -n opendirectory

echo ""
echo "🌐 Access URLs:"
echo "  Dashboard: http://192.168.1.200:30080"
echo "  API: http://192.168.1.200:30301"
echo "  Health: http://192.168.1.200:30301/api/health"