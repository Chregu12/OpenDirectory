#!/bin/bash

echo "🚀 Starting OpenDirectory API Backend..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Start the server
echo "🌐 Starting API server on http://localhost:3001"
echo "🔌 WebSocket server ready for real-time updates"
echo "📱 Connect your OpenDirectory dashboard to this backend"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

node server.js