const http = require('http');
const url = require('url');

// In-memory data store
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

// Simple CORS and JSON parsing
function handleRequest(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const path = parsedUrl.pathname;
  const method = req.method;

  console.log(`${method} ${path}`);

  // Parse JSON body for POST requests
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    let jsonBody = {};
    if (body) {
      try {
        jsonBody = JSON.parse(body);
      } catch (e) {
        jsonBody = {};
      }
    }

    // Route handling
    if (path === '/api/health' && method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({
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
      }));
    } else if (path === '/api/devices' && method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({
        success: true,
        data: Object.values(deviceStore)
      }));
    } else if (path.startsWith('/api/devices/') && path.endsWith('/refresh') && method === 'POST') {
      const deviceId = path.split('/')[3];
      const device = deviceStore[deviceId];
      
      if (!device) {
        res.writeHead(404);
        res.end(JSON.stringify({ success: false, error: 'Device not found' }));
        return;
      }

      device.lastSeen = new Date();
      device.status = Math.random() > 0.1 ? 'online' : 'offline';
      
      res.writeHead(200);
      res.end(JSON.stringify({ success: true, data: device }));
    } else if (path.startsWith('/api/devices/') && path.endsWith('/apps/install') && method === 'POST') {
      const deviceId = path.split('/')[3];
      const device = deviceStore[deviceId];
      const { appId, appName, version } = jsonBody;
      
      if (!device) {
        res.writeHead(404);
        res.end(JSON.stringify({ success: false, error: 'Device not found' }));
        return;
      }

      // Simulate installation
      if (!device.installedApps) device.installedApps = [];
      device.installedApps.push({
        app: appId,
        name: appName,
        version: version,
        status: 'installed',
        installedAt: new Date()
      });

      res.writeHead(200);
      res.end(JSON.stringify({ 
        success: true, 
        message: `${appName} installation initiated on ${device.name}`,
        data: device
      }));
    } else if (path === '/api/users' && method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({
        success: true,
        data: userStore
      }));
    } else if (path === '/api/users/sync' && method === 'POST') {
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

      res.writeHead(200);
      res.end(JSON.stringify({ 
        success: true, 
        message: 'Users synced successfully',
        data: { syncedCount: 1, totalUsers: userStore.length }
      }));
    } else if (path === '/api/policies' && method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({
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
          }
        ]
      }));
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ success: false, error: 'Endpoint not found' }));
    }
  });
}

// Create server
const server = http.createServer(handleRequest);

const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 OpenDirectory API Backend running on http://localhost:${PORT}`);
  console.log(`📊 Health Check: http://localhost:${PORT}/api/health`);
  console.log(`📱 Devices API: http://localhost:${PORT}/api/devices`);
  console.log(`👥 Users API: http://localhost:${PORT}/api/users`);
});

// Periodic device health check
setInterval(() => {
  for (const [deviceId, device] of Object.entries(deviceStore)) {
    device.status = Math.random() > 0.1 ? 'online' : 'offline';
    device.lastSeen = new Date();
  }
}, 30000);