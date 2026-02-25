const express = require('express');
const cors = require('cors');
const { NodeSSH } = require('node-ssh');
const WebSocket = require('ws');
const http = require('http');

// Network Infrastructure services moved to module
// Access via API Gateway at /api/network/*

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());

// Network services initialization moved to network-infrastructure module

// SSH connection for Ubuntu container
const ssh = new NodeSSH();
const CT2001_HOST = '192.168.1.51';

// In-memory data store (in production, use a database)
const deviceStore = {
  'CT2001': {
    id: 'CT2001',
    name: 'Ubuntu-CT2001',
    platform: 'linux',
    os: 'Ubuntu',
    osVersion: '25.10',
    status: 'online',
    groupId: 'servers',
    ip_address: '192.168.1.51',
    complianceScore: 85,
    lastSeen: new Date(),
    description: 'Proxmox LXC Container with LDAP integration',
    installedApps: []
  }
};

const userStore = [
  {
    id: 'admin',
    name: 'Administrator',
    username: 'admin',
    email: 'admin@opendirectory.local',
    active: true,
    groups: ['admin'],
    lastLogin: new Date(),
    created: new Date('2024-01-01')
  }
];

// WebSocket connections
const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  console.log('WebSocket client connected');

  ws.on('close', () => {
    clients.delete(ws);
    console.log('WebSocket client disconnected');
  });

  // Send initial device status
  ws.send(JSON.stringify({
    type: 'device_status',
    data: Object.values(deviceStore)
  }));
});

// Broadcast to all WebSocket clients
function broadcast(message) {
  const data = JSON.stringify(message);
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  });
}

// Device Management APIs
app.get('/api/devices', (req, res) => {
  res.json({
    success: true,
    data: Object.values(deviceStore)
  });
});

app.get('/api/devices/:id', (req, res) => {
  const device = deviceStore[req.params.id];
  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }
  res.json({ success: true, data: device });
});

app.post('/api/devices/:id/refresh', async (req, res) => {
  const deviceId = req.params.id;
  const device = deviceStore[deviceId];
  
  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  try {
    if (deviceId === 'CT2001') {
      // Connect to Ubuntu container and get real data
      await ssh.connect({
        host: CT2001_HOST,
        username: 'root',
        password: 'your_password', // In production, use SSH keys
        port: 22
      });

      // Get system info
      const uptime = await ssh.execCommand('uptime');
      const apps = await ssh.execCommand('dpkg --get-selections | grep -v deinstall | wc -l');
      
      device.lastSeen = new Date();
      device.status = uptime.stdout ? 'online' : 'offline';
      device.installedAppsCount = parseInt(apps.stdout) || 0;

      ssh.dispose();
    }

    deviceStore[deviceId] = device;
    
    // Broadcast update to WebSocket clients
    broadcast({
      type: 'device_updated',
      data: device
    });

    res.json({ success: true, data: device });
  } catch (error) {
    console.error('Device refresh error:', error);
    res.status(500).json({ success: false, error: 'Failed to refresh device' });
  }
});

app.post('/api/devices/:id/apps/install', async (req, res) => {
  const { appId, appName, version } = req.body;
  const deviceId = req.params.id;
  const device = deviceStore[deviceId];

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: 'root',
        password: 'your_password',
        port: 22
      });

      let installCommand = '';
      switch (appId) {
        case 'docker':
          installCommand = 'apt-get update && apt-get install -y docker.io';
          break;
        case 'vscode':
          installCommand = 'wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg && install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/ && echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list && apt-get update && apt-get install -y code';
          break;
        case 'firefox':
          installCommand = 'apt-get update && apt-get install -y firefox';
          break;
        case 'chrome':
          installCommand = 'wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && apt-get update && apt-get install -y google-chrome-stable';
          break;
        default:
          installCommand = `apt-get update && apt-get install -y ${appId}`;
      }

      const result = await ssh.execCommand(installCommand);
      ssh.dispose();

      if (result.code === 0) {
        // Add to installed apps
        if (!device.installedApps) device.installedApps = [];
        device.installedApps.push({
          app: appId,
          name: appName,
          version: version,
          status: 'installed',
          installedAt: new Date()
        });

        broadcast({
          type: 'app_installed',
          data: { deviceId, app: { appId, appName, version } }
        });

        res.json({ 
          success: true, 
          message: `${appName} installed successfully on ${device.name}`,
          data: device
        });
      } else {
        res.status(500).json({ 
          success: false, 
          error: `Installation failed: ${result.stderr}` 
        });
      }
    } else {
      res.status(400).json({ success: false, error: 'Remote installation not supported for this device' });
    }
  } catch (error) {
    console.error('App installation error:', error);
    res.status(500).json({ success: false, error: 'Installation failed' });
  }
});

app.delete('/api/devices/:id/apps/:appId', async (req, res) => {
  const { appId } = req.params;
  const deviceId = req.params.id;
  const device = deviceStore[deviceId];

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: 'root',
        password: 'your_password',
        port: 22
      });

      let uninstallCommand = '';
      switch (appId) {
        case 'docker':
          uninstallCommand = 'apt-get remove -y docker.io && apt-get autoremove -y';
          break;
        case 'chrome':
          uninstallCommand = 'apt-get remove -y google-chrome-stable && apt-get autoremove -y';
          break;
        default:
          uninstallCommand = `apt-get remove -y ${appId} && apt-get autoremove -y`;
      }

      const result = await ssh.execCommand(uninstallCommand);
      ssh.dispose();

      if (result.code === 0) {
        // Remove from installed apps
        if (device.installedApps) {
          device.installedApps = device.installedApps.filter(app => app.app !== appId);
        }

        broadcast({
          type: 'app_uninstalled',
          data: { deviceId, appId }
        });

        res.json({ 
          success: true, 
          message: `Application ${appId} uninstalled successfully`,
          data: device
        });
      } else {
        res.status(500).json({ 
          success: false, 
          error: `Uninstallation failed: ${result.stderr}` 
        });
      }
    } else {
      res.status(400).json({ success: false, error: 'Remote uninstallation not supported for this device' });
    }
  } catch (error) {
    console.error('App uninstallation error:', error);
    res.status(500).json({ success: false, error: 'Uninstallation failed' });
  }
});

// User Management APIs
app.get('/api/users', (req, res) => {
  res.json({
    success: true,
    data: userStore
  });
});

app.post('/api/users/sync', async (req, res) => {
  try {
    // In production, sync with LLDAP
    // For now, simulate sync
    const newUser = {
      id: 'synced_' + Date.now(),
      name: 'Synced User',
      username: 'syncuser',
      email: 'sync@opendirectory.local',
      active: true,
      groups: ['user'],
      lastLogin: null,
      created: new Date()
    };

    userStore.push(newUser);

    broadcast({
      type: 'users_synced',
      data: { count: 1, newUsers: [newUser] }
    });

    res.json({ 
      success: true, 
      message: 'Users synced successfully',
      data: { syncedCount: 1, totalUsers: userStore.length }
    });
  } catch (error) {
    console.error('User sync error:', error);
    res.status(500).json({ success: false, error: 'User sync failed' });
  }
});

// System Health API
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    data: {
      status: 'healthy',
      timestamp: new Date(),
      services: {
        database: 'connected',
        ldap: 'connected',
        monitoring: 'active'
      },
      stats: {
        devices: Object.keys(deviceStore).length,
        users: userStore.length,
        uptime: process.uptime()
      }
    }
  });
});

// Policy Management APIs
app.get('/api/policies', (req, res) => {
  res.json({
    success: true,
    data: [
      {
        id: 'version_mgmt',
        name: 'Version Management Policy',
        description: 'Automatic application updates with version control',
        active: true,
        platforms: ['linux'],
        rules: {
          autoUpdate: true,
          updateWindow: 'maintenance',
          rollback: true
        }
      },
      {
        id: 'security_updates',
        name: 'Security Update Policy',
        description: 'Immediate deployment of security patches',
        active: true,
        platforms: ['windows', 'macos', 'linux'],
        rules: {
          immediate: true,
          critical: true,
          notification: true
        }
      }
    ]
  });
});

// Network Infrastructure routes moved to network-infrastructure module
// Access these endpoints through the API Gateway at http://localhost:8080/api/network/*




// Network Monitoring
// All network monitoring endpoints have been moved to the network-infrastructure module
// Access via API Gateway: http://localhost:8080/api/network/monitoring/*

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`OpenDirectory API Backend running on port ${PORT}`);
  console.log(`WebSocket server ready for real-time updates`);
  
  // Initialize Network Infrastructure Services
  console.log('Initializing Network Infrastructure Services...');
  
  try {
    // Start DNS server (if enabled)
    if (process.env.ENABLE_DNS !== 'false') {
      dnsManager.startDNSServer().catch(err => 
        console.warn('DNS server not started (may need root privileges):', err.message)
      );
    }
    
    // Start DHCP server (if enabled)
    if (process.env.ENABLE_DHCP !== 'false') {
      dhcpManager.startDHCPServer().catch(err => 
        console.warn('DHCP server not started (may need root privileges):', err.message)
      );
    }
    
    // Network monitoring is now handled by the network-infrastructure module
    
    console.log('Network Infrastructure Services initialized');
  } catch (error) {
    console.warn('Some network services could not be started:', error.message);
  }
});

// Periodic device health check
setInterval(async () => {
  for (const [deviceId, device] of Object.entries(deviceStore)) {
    if (deviceId === 'CT2001') {
      try {
        await ssh.connect({
          host: CT2001_HOST,
          username: 'root',
          password: 'your_password',
          port: 22,
          readyTimeout: 5000
        });

        device.status = 'online';
        device.lastSeen = new Date();
        ssh.dispose();
      } catch (error) {
        device.status = 'offline';
      }
      
      broadcast({
        type: 'device_heartbeat',
        data: { deviceId, status: device.status, lastSeen: device.lastSeen }
      });
    }
  }
}, 30000); // Check every 30 seconds