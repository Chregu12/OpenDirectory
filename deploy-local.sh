#!/bin/bash

echo "🚀 OpenDirectory MDM - Local Deployment"
echo "========================================"

# Configuration
CLUSTER_IP=${CLUSTER_IP:-"192.168.1.223"}
API_PORT=${API_PORT:-"30301"}
DASHBOARD_PORT=${DASHBOARD_PORT:-"30080"}

echo "📋 Configuration:"
echo "  - Cluster IP: $CLUSTER_IP"
echo "  - API Port: $API_PORT"  
echo "  - Dashboard Port: $DASHBOARD_PORT"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Please install Node.js first."
    exit 1
fi

echo "🔍 Checking cluster connectivity..."
if ! ping -c 1 -W 2 $CLUSTER_IP &> /dev/null; then
    echo "⚠️  Cluster $CLUSTER_IP not reachable. Setting up local deployment instead."
    CLUSTER_IP="localhost"
    API_PORT="3001"
    DASHBOARD_PORT="8080"
fi

echo "🛠️  Setting up API Backend..."
cd services/api-backend

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo "📦 Installing API dependencies..."
    npm install
fi

# Update configuration for deployment
cat > config.js << EOF
module.exports = {
    port: process.env.PORT || $API_PORT,
    host: process.env.HOST || '0.0.0.0',
    ct2001Host: process.env.CT2001_HOST || '192.168.1.51',
    clusterIp: '$CLUSTER_IP'
};
EOF

# Start API Backend in background
echo "🌐 Starting API Backend on http://$CLUSTER_IP:$API_PORT..."
if [ "$CLUSTER_IP" = "localhost" ]; then
    node server.js &
    API_PID=$!
    echo "   API Backend PID: $API_PID"
else
    echo "   Deploying to cluster..."
fi

cd ../..

echo "🎯 Setting up Dashboard..."

# Update dashboard configuration
sed -i.bak "s|http://[^:]*:[0-9]*|http://$CLUSTER_IP:$API_PORT|g" multi-platform-app-store.yaml
sed -i.bak "s|ws://[^:]*:[0-9]*|ws://$CLUSTER_IP:$API_PORT|g" multi-platform-app-store.yaml

if [ "$CLUSTER_IP" = "localhost" ]; then
    # Local HTTP server for dashboard
    echo "📱 Starting Dashboard on http://$CLUSTER_IP:$DASHBOARD_PORT..."
    
    # Extract HTML from YAML and serve locally
    python3 -c "
import yaml
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import threading
import webbrowser

# Read and parse YAML
with open('multi-platform-app-store.yaml', 'r') as f:
    content = f.read()

# Extract HTML content
yaml_data = yaml.safe_load(content)
html_content = yaml_data['data']['index.html']

# Write to temporary HTML file
with open('dashboard.html', 'w') as f:
    f.write(html_content)

print('Dashboard HTML extracted to dashboard.html')
print('Starting HTTP server...')

class CORSHTTPRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()
    
    def do_GET(self):
        if self.path == '/' or self.path == '':
            self.path = '/dashboard.html'
        return super().do_GET()

os.chdir('$PWD')
httpd = HTTPServer(('0.0.0.0', $DASHBOARD_PORT), CORSHTTPRequestHandler)
print(f'Dashboard available at: http://$CLUSTER_IP:$DASHBOARD_PORT')

# Open browser
threading.Timer(2, lambda: webbrowser.open(f'http://$CLUSTER_IP:$DASHBOARD_PORT')).start()

httpd.serve_forever()
" &
    DASHBOARD_PID=$!
    echo "   Dashboard PID: $DASHBOARD_PID"
else
    # Deploy to Kubernetes cluster
    echo "📦 Deploying to Kubernetes cluster..."
    kubectl apply -f infrastructure/kubernetes/api-backend-deployment.yaml
    kubectl apply -f multi-platform-app-store.yaml
fi

echo ""
echo "✅ OpenDirectory MDM Deployment Complete!"
echo "========================================"
echo "🌐 Dashboard: http://$CLUSTER_IP:$DASHBOARD_PORT"
echo "⚡ API Backend: http://$CLUSTER_IP:$API_PORT"
echo "📊 Health Check: http://$CLUSTER_IP:$API_PORT/api/health"
echo ""

if [ "$CLUSTER_IP" = "localhost" ]; then
    echo "🎮 Local Deployment Active"
    echo "   - API Backend PID: $API_PID"
    echo "   - Dashboard PID: $DASHBOARD_PID"
    echo ""
    echo "📝 To stop the services:"
    echo "   kill $API_PID $DASHBOARD_PID"
    echo ""
    echo "📱 Opening dashboard in browser..."
    
    # Create stop script
    cat > stop-local.sh << EOF
#!/bin/bash
echo "🛑 Stopping OpenDirectory MDM..."
kill $API_PID $DASHBOARD_PID 2>/dev/null
rm -f dashboard.html config.js
echo "✅ Services stopped."
EOF
    chmod +x stop-local.sh
    
    # Wait for services
    wait
else
    echo "☁️  Cluster Deployment Active"
    echo "   - Check status: kubectl get pods -n opendirectory"
    echo "   - View logs: kubectl logs -f deployment/opendirectory-api-backend -n opendirectory"
fi