const express = require('express');
const cors = require('cors');
const { NodeSSH } = require('node-ssh');
const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');

// ── Auth helpers (no extra npm deps — uses built-in crypto) ─────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'opendirectory-dev-secret';

function hashPassword(password) {
  return crypto.createHmac('sha256', JWT_SECRET).update(password).digest('hex');
}

function signToken(payload) {
  const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body    = Buffer.from(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 })).toString('base64url');
  const sig     = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (expected !== sig) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  req.user = payload;
  next();
}
// ────────────────────────────────────────────────────────────────────────────

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

// In-memory device store — populated via enrollment
const deviceStore = {};

const userStore = [
  {
    id: 'admin',
    name: 'Administrator',
    username: 'admin',
    email: 'admin@opendirectory.local',
    role: 'System Administrator',
    active: true,
    groups: ['admin'],
    passwordHash: null, // set below after hashPassword is defined
    lastLogin: new Date(),
    created: new Date('2024-01-01')
  }
];
// Set default admin password (admin!)
userStore[0].passwordHash = hashPassword('admin!');

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

// ── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ success: false, error: 'Username and password required' });

  const user = userStore.find(u => (u.username === username || u.email === username) && u.active);
  if (!user || user.passwordHash !== hashPassword(password))
    return res.status(401).json({ success: false, error: 'Invalid username or password' });

  user.lastLogin = new Date();
  const token = signToken({ id: user.id, username: user.username, name: user.name, role: user.role, groups: user.groups });
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: { token, user: safeUser } });
});

app.post('/api/auth/logout', (req, res) => {
  // Tokens are stateless; client just discards it
  res.json({ success: true, message: 'Logged out' });
});

app.get('/api/auth/profile', authMiddleware, (req, res) => {
  const user = userStore.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const user = userStore.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  const { name, email } = req.body;
  if (name)  user.name  = name;
  if (email) user.email = email;
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.post('/api/auth/change-password', authMiddleware, (req, res) => {
  const user = userStore.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  const { currentPassword, newPassword } = req.body || {};
  if (user.passwordHash !== hashPassword(currentPassword))
    return res.status(400).json({ success: false, error: 'Current password is incorrect' });
  user.passwordHash = hashPassword(newPassword);
  res.json({ success: true, message: 'Password changed' });
});
// ────────────────────────────────────────────────────────────────────────────

// Users API — list + create + update + delete
app.get('/api/users', (req, res) => {
  res.json({ success: true, data: userStore.map(({ passwordHash, ...u }) => u) });
});

app.post('/api/users', (req, res) => {
  const { username, name, email, password, role, groups } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ success: false, error: 'username and password are required' });
  if (userStore.find(u => u.username === username))
    return res.status(409).json({ success: false, error: 'Username already exists' });
  const user = {
    id: 'user_' + Date.now(),
    username, name: name || username,
    email: email || `${username}@opendirectory.local`,
    role: role || 'User',
    active: true,
    groups: groups || ['user'],
    passwordHash: hashPassword(password),
    lastLogin: null,
    created: new Date(),
  };
  userStore.push(user);
  const { passwordHash, ...safeUser } = user;
  res.status(201).json({ success: true, data: safeUser });
});

app.put('/api/users/:id', (req, res) => {
  const user = userStore.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  const { name, email, role, groups, active, password } = req.body || {};
  if (name   !== undefined) user.name   = name;
  if (email  !== undefined) user.email  = email;
  if (role   !== undefined) user.role   = role;
  if (groups !== undefined) user.groups = groups;
  if (active !== undefined) user.active = active;
  if (password) user.passwordHash = hashPassword(password);
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.delete('/api/users/:id', (req, res) => {
  const idx = userStore.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'User not found' });
  if (userStore[idx].id === 'admin')
    return res.status(400).json({ success: false, error: 'Cannot delete the default admin user' });
  userStore.splice(idx, 1);
  res.json({ success: true, message: 'User deleted' });
});

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
        password: process.env.SSH_PASSWORD || '', // In production, use SSH keys
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
        password: process.env.SSH_PASSWORD || '',
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
        password: process.env.SSH_PASSWORD || '',
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

// System Resources API
const os = require('os');

app.get('/api/system/resources', (req, res) => {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;

  res.json({
    success: true,
    data: {
      ram: {
        totalMB: Math.round(totalMem / 1024 / 1024),
        usedMB: Math.round(usedMem / 1024 / 1024),
        freeMB: Math.round(freeMem / 1024 / 1024),
        usagePercent: Math.round((usedMem / totalMem) * 100),
      },
      cpu: {
        cores: os.cpus().length,
        model: os.cpus()[0]?.model || 'Unknown',
      },
      uptime: os.uptime(),
      platform: os.platform(),
      hostname: os.hostname(),
    }
  });
});

// Setup Wizard APIs
let setupConfig = null;

app.get('/api/config/setup-status', (req, res) => {
  res.json({
    success: true,
    data: {
      isFirstRun: setupConfig === null,
      config: setupConfig,
    }
  });
});

app.get('/api/config/wizard/available-modules', (req, res) => {
  res.json({
    success: true,
    data: [
      { id: 'network', name: 'Netzwerk', ram: '192 MB', profile: 'network' },
      { id: 'printers', name: 'Drucker', ram: '192 MB', profile: 'printers' },
      { id: 'monitoring', name: 'Monitoring', ram: '448 MB', profile: 'monitoring' },
      { id: 'security', name: 'Security', ram: '320 MB', profile: 'security' },
      { id: 'lifecycle', name: 'Lifecycle', ram: '448 MB', profile: 'lifecycle' },
    ]
  });
});

app.post('/api/config/wizard/setup', (req, res) => {
  const { orgName, modules, devices, completedAt } = req.body;
  setupConfig = { orgName, modules, devices, completedAt };
  console.log('Setup wizard completed:', setupConfig);
  res.json({
    success: true,
    message: 'Setup completed',
    data: setupConfig,
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

// ── Device Enrollment APIs ──────────────────────────────────────────
// (crypto already required at top)

// In-memory enrollment token store
const enrollmentTokens = {};

// Generate enrollment token
app.post('/api/devices/enroll/token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
  enrollmentTokens[token] = {
    token,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    used: false,
  };
  res.json({
    success: true,
    data: { token, expiresAt: expiresAt.toISOString() },
  });
});

// Enroll a device using a token
app.post('/api/devices/enroll', (req, res) => {
  const { token, hostname, platform, os: deviceOs, osVersion } = req.body;

  if (!token || !enrollmentTokens[token]) {
    return res.status(401).json({ success: false, error: 'Invalid enrollment token' });
  }
  const tokenData = enrollmentTokens[token];
  if (tokenData.used || new Date(tokenData.expiresAt) < new Date()) {
    return res.status(401).json({ success: false, error: 'Token expired or already used' });
  }

  // Mark token as used
  tokenData.used = true;

  const deviceId = `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const newDevice = {
    id: deviceId,
    name: hostname || `Device-${deviceId}`,
    platform: platform || 'unknown',
    os: deviceOs || 'Unknown',
    osVersion: osVersion || '',
    status: 'online',
    enrolledAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  };

  // Add to device store
  deviceStore[deviceId] = newDevice;

  res.json({
    success: true,
    data: { deviceId, message: 'Device enrolled successfully', device: newDevice },
  });
});

// Discover printers on the network (mock)
app.get('/api/printers/discover', (req, res) => {
  res.json({
    success: true,
    data: [
      { name: 'HP LaserJet Pro M404n', ip: '192.168.1.200', protocol: 'ipp', status: 'online' },
      { name: 'Brother HL-L2350DW', ip: '192.168.1.201', protocol: 'lpd', status: 'online' },
    ],
  });
});

// Add printer manually
app.post('/api/printers', (req, res) => {
  const { name, ip, protocol } = req.body;
  if (!name || !ip) {
    return res.status(400).json({ success: false, error: 'Name and IP are required' });
  }
  const printerId = `PRT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  res.json({
    success: true,
    data: { id: printerId, name, ip, protocol: protocol || 'ipp', status: 'online' },
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
          password: process.env.SSH_PASSWORD || '',
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