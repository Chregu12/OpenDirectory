const express = require('express');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const http = require('http');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration
const CT2001_CONFIG = {
    host: '192.168.1.51',
    username: 'root',
    password: 'your_password_here', // Update this with actual password
    port: 22,
    readyTimeout: 60000
};

const PORT = 3001;
const METRICS_INTERVAL = 30000; // 30 seconds

// Middleware
app.use(cors());
app.use(express.json());

// Store connected WebSocket clients
const clients = new Set();

// Real-time device metrics storage
let deviceMetrics = {
    'CT2001': {
        id: 'CT2001',
        name: 'Ubuntu-CT2001',
        platform: 'linux',
        os: 'Ubuntu',
        osVersion: '25.10',
        status: 'offline',
        groupId: 'servers',
        ip_address: '192.168.1.51',
        complianceScore: 85,
        lastSeen: null,
        description: 'Proxmox LXC Container with LDAP integration',
        metrics: {
            cpu: {
                usage: 0,
                cores: 0,
                temperature: null
            },
            memory: {
                total: 0,
                used: 0,
                free: 0,
                percentage: 0
            },
            disk: {
                total: 0,
                used: 0,
                free: 0,
                percentage: 0
            },
            network: {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                interface: 'eth0'
            },
            uptime: 0,
            load_average: [0, 0, 0]
        },
        installedApps: []
    }
};

// SSH Connection Pool
class SSHConnection {
    constructor(config) {
        this.config = config;
        this.client = null;
        this.connected = false;
    }

    async connect() {
        return new Promise((resolve, reject) => {
            this.client = new Client();
            
            this.client.on('ready', () => {
                console.log(`✅ SSH connection established to ${this.config.host}`);
                this.connected = true;
                resolve();
            });

            this.client.on('error', (err) => {
                console.error(`❌ SSH connection error to ${this.config.host}:`, err.message);
                this.connected = false;
                reject(err);
            });

            this.client.on('close', () => {
                console.log(`🔌 SSH connection closed to ${this.config.host}`);
                this.connected = false;
            });

            this.client.connect(this.config);
        });
    }

    async executeCommand(command) {
        return new Promise((resolve, reject) => {
            if (!this.connected) {
                reject(new Error('SSH connection not established'));
                return;
            }

            this.client.exec(command, (err, stream) => {
                if (err) {
                    reject(err);
                    return;
                }

                let output = '';
                let errorOutput = '';

                stream.on('close', (code, signal) => {
                    if (code === 0) {
                        resolve(output);
                    } else {
                        reject(new Error(`Command failed with exit code ${code}: ${errorOutput}`));
                    }
                });

                stream.on('data', (data) => {
                    output += data.toString();
                });

                stream.stderr.on('data', (data) => {
                    errorOutput += data.toString();
                });
            });
        });
    }

    disconnect() {
        if (this.client) {
            this.client.end();
            this.connected = false;
        }
    }
}

// Initialize SSH connection
const sshConnection = new SSHConnection(CT2001_CONFIG);

// Collect system metrics from CT2001
async function collectMetrics() {
    try {
        if (!sshConnection.connected) {
            console.log('🔄 Attempting to connect to CT2001...');
            await sshConnection.connect();
        }

        // Execute the metrics collection script
        const metricsJSON = await sshConnection.executeCommand('/tmp/collect-metrics.sh');
        const metrics = JSON.parse(metricsJSON);

        // Update device metrics
        const device = deviceMetrics['CT2001'];
        device.status = 'online';
        device.lastSeen = new Date();
        device.metrics = metrics.system;
        device.installedApps = metrics.applications || [];

        console.log(`📊 Metrics collected from CT2001 - CPU: ${metrics.system.cpu.usage}%, Memory: ${metrics.system.memory.percentage}%`);

        // Broadcast to all connected clients
        broadcastMetrics();

    } catch (error) {
        console.error('❌ Failed to collect metrics:', error.message);
        
        // Update device status to offline
        const device = deviceMetrics['CT2001'];
        device.status = 'offline';
        device.lastSeen = device.lastSeen || new Date();
        
        broadcastMetrics();
    }
}

// Broadcast metrics to all WebSocket clients
function broadcastMetrics() {
    const message = JSON.stringify({
        type: 'metrics_update',
        timestamp: new Date().toISOString(),
        devices: deviceMetrics
    });

    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// WebSocket connection handling
wss.on('connection', (ws, req) => {
    console.log(`🔌 New WebSocket client connected from ${req.socket.remoteAddress}`);
    clients.add(ws);

    // Send initial device data
    ws.send(JSON.stringify({
        type: 'initial_data',
        timestamp: new Date().toISOString(),
        devices: deviceMetrics
    }));

    ws.on('close', () => {
        console.log('🔌 WebSocket client disconnected');
        clients.delete(ws);
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        clients.delete(ws);
    });

    // Handle client messages
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);
            handleClientMessage(ws, message);
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    });
});

// Handle client messages
function handleClientMessage(ws, message) {
    switch (message.type) {
        case 'refresh_metrics':
            console.log('📊 Client requested metrics refresh');
            collectMetrics();
            break;
        
        case 'install_application':
            console.log(`📦 Client requested application installation: ${message.app}`);
            installApplication(message.app, message.device);
            break;
        
        default:
            console.log('Unknown message type:', message.type);
    }
}

// Install application on device
async function installApplication(appId, deviceId) {
    try {
        if (!sshConnection.connected) {
            await sshConnection.connect();
        }

        const command = getInstallCommand(appId);
        if (command) {
            console.log(`🚀 Installing ${appId} on ${deviceId}...`);
            const result = await sshConnection.executeCommand(command);
            console.log(`✅ Installation completed: ${result}`);
            
            // Refresh metrics after installation
            setTimeout(() => collectMetrics(), 5000);
        }
    } catch (error) {
        console.error(`❌ Failed to install ${appId}:`, error.message);
    }
}

// Get installation command for different applications
function getInstallCommand(appId) {
    const commands = {
        'docker': 'apt update && apt install -y docker.io && systemctl enable docker && systemctl start docker',
        'vscode': 'wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg && install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/ && echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list && apt update && apt install -y code',
        'firefox': 'snap install firefox',
        'vlc': 'apt update && apt install -y vlc',
        'chrome': 'wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list && apt update && apt install -y google-chrome-stable'
    };
    
    return commands[appId] || null;
}

// REST API endpoints
app.get('/api/devices', (req, res) => {
    res.json({
        success: true,
        devices: Object.values(deviceMetrics)
    });
});

app.get('/api/devices/:deviceId', (req, res) => {
    const device = deviceMetrics[req.params.deviceId];
    if (device) {
        res.json({
            success: true,
            device: device
        });
    } else {
        res.status(404).json({
            success: false,
            message: 'Device not found'
        });
    }
});

app.post('/api/devices/:deviceId/install', async (req, res) => {
    const { deviceId } = req.params;
    const { appId } = req.body;
    
    try {
        await installApplication(appId, deviceId);
        res.json({
            success: true,
            message: `Installation of ${appId} started on ${deviceId}`
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

app.post('/api/metrics/refresh', async (req, res) => {
    try {
        await collectMetrics();
        res.json({
            success: true,
            message: 'Metrics refresh initiated'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        uptime: process.uptime(),
        ssh_connected: sshConnection.connected,
        websocket_clients: clients.size,
        timestamp: new Date().toISOString()
    });
});

// Start the server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 OpenDirectory Realtime Backend running on port ${PORT}`);
    console.log(`📊 WebSocket server ready for connections`);
    console.log(`🔧 Health check available at http://localhost:${PORT}/health`);
    
    // Initial connection attempt
    setTimeout(() => {
        console.log('🔄 Starting initial metrics collection...');
        collectMetrics();
        
        // Set up periodic metrics collection
        setInterval(collectMetrics, METRICS_INTERVAL);
    }, 2000);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 Received SIGTERM, shutting down gracefully...');
    sshConnection.disconnect();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('🛑 Received SIGINT, shutting down gracefully...');
    sshConnection.disconnect();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});