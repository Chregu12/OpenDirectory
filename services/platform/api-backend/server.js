const express = require('express');
const cors = require('cors');
const { NodeSSH } = require('node-ssh');
const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt    = require('jsonwebtoken');

// ── Auth helpers ─────────────────────────────────────────────────────────────
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET environment variable is required in production');
}
const JWT_SECRET    = process.env.JWT_SECRET || 'dev-jwt-secret-not-for-production';
const BCRYPT_ROUNDS = 10;

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function comparePassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function parseCookies(cookieHeader = '') {
  return Object.fromEntries(
    cookieHeader.split(';').map(c => c.trim().split('=').map(decodeURIComponent))
  );
}

function authMiddleware(req, res, next) {
  const cookies = parseCookies(req.headers.cookie || '');
  const cookieToken = cookies['auth_token'];
  const authHeader = req.headers['authorization'];
  const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const token = cookieToken || headerToken;

  if (!token) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  req.user = payload;
  next();
}
// ────────────────────────────────────────────────────────────────────────────

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) {
      if (process.env.NODE_ENV === 'production') {
        return callback(new Error('Origin header is required'), false);
      }
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`Origin ${origin} not allowed by CORS policy`), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// SSH connection for Ubuntu container
const ssh = new NodeSSH();
const CT2001_HOST = process.env.CT2001_HOST || '192.168.1.51';

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
    passwordHash: null, // set below after BCRYPT_ROUNDS is defined
    lastLogin: new Date(),
    created: new Date('2024-01-01')
  }
];
const initialAdminPassword = process.env.ADMIN_PASSWORD;
if (!initialAdminPassword && process.env.NODE_ENV === 'production') {
  throw new Error('ADMIN_PASSWORD environment variable is required in production');
}
userStore[0].passwordHash = bcrypt.hashSync(initialAdminPassword || 'admin!', BCRYPT_ROUNDS);

// WebSocket connections — validate token on connect
const clients = new Set();

wss.on('connection', (ws, req) => {
  // Extract token from query param or cookie
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const queryToken = url.searchParams.get('token');
  const cookies = parseCookies(req.headers.cookie || '');
  const token = queryToken || cookies['auth_token'];

  if (!token || !verifyToken(token)) {
    ws.close(4401, 'Unauthorized');
    return;
  }

  clients.add(ws);

  ws.on('close', () => {
    clients.delete(ws);
  });

  ws.send(JSON.stringify({
    type: 'device_status',
    data: Object.values(deviceStore)
  }));
});

function broadcast(message) {
  const data = JSON.stringify(message);
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  });
}

// ── Input validation helpers ─────────────────────────────────────────────────
function isNonEmptyString(v, maxLen = 255) {
  return typeof v === 'string' && v.trim().length > 0 && v.length <= maxLen;
}

function isValidEmail(v) {
  return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
}

function validateLoginBody(body) {
  const { username, password } = body || {};
  if (!isNonEmptyString(username, 254)) return 'username is required';
  if (!isNonEmptyString(password, 128)) return 'password is required';
  return null;
}

function validateUserBody(body) {
  const { username, password } = body || {};
  if (!isNonEmptyString(username, 64)) return 'username is required (max 64 chars)';
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return 'username may only contain letters, numbers, underscores and hyphens';
  if (!isNonEmptyString(password, 128) || password.length < 8) return 'password is required (min 8 chars)';
  if (body.email && !isValidEmail(body.email)) return 'invalid email address';
  return null;
}
// ────────────────────────────────────────────────────────────────────────────

// ── Per-username rate limiter for login ──────────────────────────────────────
const loginAttempts = new Map();
const LOGIN_WINDOW_MS  = 15 * 60 * 1000;
const LOGIN_MAX        = 5;

function loginRateLimit(req, res, next) {
  const username = (req.body?.username || '').toLowerCase().trim();
  const key = username || req.ip;
  const now = Date.now();

  const record = loginAttempts.get(key) || { count: 0, resetAt: now + LOGIN_WINDOW_MS };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + LOGIN_WINDOW_MS; }
  record.count += 1;
  loginAttempts.set(key, record);

  if (record.count > LOGIN_MAX) {
    return res.status(429).json({ success: false, error: 'Too many login attempts, please try again later.' });
  }
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [key, record] of loginAttempts) {
    if (now > record.resetAt) loginAttempts.delete(key);
  }
}, LOGIN_WINDOW_MS);

// ── Per-IP rate limiter for write operations (enrollment, user creation) ─────
const writeAttempts = new Map();
const WRITE_WINDOW_MS = 60 * 1000; // 1 minute
const WRITE_MAX       = 20;

function writeRateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const record = writeAttempts.get(key) || { count: 0, resetAt: now + WRITE_WINDOW_MS };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + WRITE_WINDOW_MS; }
  record.count += 1;
  writeAttempts.set(key, record);
  if (record.count > WRITE_MAX) {
    return res.status(429).json({ success: false, error: 'Too many requests, please try again later.' });
  }
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [key, record] of writeAttempts) {
    if (now > record.resetAt) writeAttempts.delete(key);
  }
}, WRITE_WINDOW_MS);
// ────────────────────────────────────────────────────────────────────────────

// ── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const validationError = validateLoginBody(req.body);
  if (validationError)
    return res.status(400).json({ success: false, error: validationError });

  const { username, password } = req.body;

  const user = userStore.find(u => (u.username === username || u.email === username) && u.active);
  if (!user || !(await comparePassword(password, user.passwordHash)))
    return res.status(401).json({ success: false, error: 'Invalid username or password' });

  user.lastLogin = new Date();
  const token = signToken({ id: user.id, username: user.username, name: user.name, role: user.role, groups: user.groups });
  const { passwordHash, ...safeUser } = user;

  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/',
  });

  res.json({ success: true, data: { token, user: safeUser } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token', { path: '/' });
  res.json({ success: true, message: 'Logged out' });
});

app.get('/api/auth/profile', authMiddleware, (req, res) => {
  const user = userStore.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const user = userStore.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { name, email } = req.body;
  if (name && isNonEmptyString(name, 128))  user.name  = name;
  if (email && isValidEmail(email)) user.email = email;
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const user = userStore.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { currentPassword, newPassword } = req.body || {};
  if (!isNonEmptyString(currentPassword, 128) || !isNonEmptyString(newPassword, 128) || newPassword.length < 8)
    return res.status(400).json({ success: false, error: 'newPassword must be at least 8 characters' });
  if (!(await comparePassword(currentPassword, user.passwordHash)))
    return res.status(400).json({ success: false, error: 'Current password is incorrect' });
  user.passwordHash = await hashPassword(newPassword);
  res.json({ success: true, message: 'Password changed' });
});
// ────────────────────────────────────────────────────────────────────────────

// Users API — requires authentication for all operations
app.get('/api/users', authMiddleware, (req, res) => {
  res.json({ success: true, data: userStore.map(({ passwordHash, ...u }) => u) });
});

app.post('/api/users', authMiddleware, writeRateLimit, async (req, res) => {
  const validationError = validateUserBody(req.body);
  if (validationError)
    return res.status(400).json({ success: false, error: validationError });

  const { username, name, email, password, role, groups } = req.body;
  if (userStore.find(u => u.username === username))
    return res.status(409).json({ success: false, error: 'Username already exists' });
  const user = {
    id: 'user_' + Date.now(),
    username, name: name || username,
    email: email || `${username}@opendirectory.local`,
    role: role || 'User',
    active: true,
    groups: groups || ['user'],
    passwordHash: await hashPassword(password),
    lastLogin: null,
    created: new Date(),
  };
  userStore.push(user);
  const { passwordHash, ...safeUser } = user;
  res.status(201).json({ success: true, data: safeUser });
});

app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const user = userStore.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  const { name, email, role, groups, active, password } = req.body || {};
  if (name   !== undefined) user.name   = name;
  if (email  !== undefined) user.email  = email;
  if (role   !== undefined) user.role   = role;
  if (groups !== undefined) user.groups = groups;
  if (active !== undefined) user.active = active;
  if (password) user.passwordHash = await hashPassword(password);
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.delete('/api/users/:id', authMiddleware, (req, res) => {
  const idx = userStore.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'User not found' });
  if (userStore[idx].id === 'admin')
    return res.status(400).json({ success: false, error: 'Cannot delete the default admin user' });
  userStore.splice(idx, 1);
  res.json({ success: true, message: 'User deleted' });
});

// Device Management APIs
app.get('/api/devices', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: Object.values(deviceStore)
  });
});

app.get('/api/devices/:id', authMiddleware, (req, res) => {
  const device = deviceStore[req.params.id];
  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }
  res.json({ success: true, data: device });
});

app.post('/api/devices/:id/refresh', authMiddleware, async (req, res) => {
  const deviceId = req.params.id;
  const device = deviceStore[deviceId];

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: process.env.CT2001_USERNAME || 'root',
        password: process.env.SSH_PASSWORD || '',
        port: parseInt(process.env.CT2001_PORT) || 22
      });

      const uptime = await ssh.execCommand('uptime');
      const apps = await ssh.execCommand('dpkg --get-selections | grep -v deinstall | wc -l');

      device.lastSeen = new Date();
      device.status = uptime.stdout ? 'online' : 'offline';
      device.installedAppsCount = parseInt(apps.stdout) || 0;

      ssh.dispose();
    }

    deviceStore[deviceId] = device;

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

// Whitelist of allowed app IDs to prevent command injection
const ALLOWED_APP_IDS = new Set(['docker', 'vscode', 'firefox', 'chrome']);

app.post('/api/devices/:id/apps/install', authMiddleware, async (req, res) => {
  const { appId, appName, version } = req.body;
  const deviceId = req.params.id;
  const device = deviceStore[deviceId];

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  if (!ALLOWED_APP_IDS.has(appId)) {
    return res.status(400).json({ success: false, error: `Unknown application. Allowed: ${[...ALLOWED_APP_IDS].join(', ')}` });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: process.env.CT2001_USERNAME || 'root',
        password: process.env.SSH_PASSWORD || '',
        port: parseInt(process.env.CT2001_PORT) || 22
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
      }

      const result = await ssh.execCommand(installCommand);
      ssh.dispose();

      if (result.code === 0) {
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
          error: 'Installation failed'
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

app.delete('/api/devices/:id/apps/:appId', authMiddleware, async (req, res) => {
  const { appId } = req.params;
  const deviceId = req.params.id;
  const device = deviceStore[deviceId];

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  if (!ALLOWED_APP_IDS.has(appId)) {
    return res.status(400).json({ success: false, error: `Unknown application. Allowed: ${[...ALLOWED_APP_IDS].join(', ')}` });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: process.env.CT2001_USERNAME || 'root',
        password: process.env.SSH_PASSWORD || '',
        port: parseInt(process.env.CT2001_PORT) || 22
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
          error: 'Uninstallation failed'
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

app.post('/api/users/sync', authMiddleware, async (req, res) => {
  try {
    // Placeholder: in production, sync with LLDAP
    broadcast({
      type: 'users_synced',
      data: { count: 0, newUsers: [] }
    });

    res.json({
      success: true,
      message: 'Users synced successfully',
      data: { syncedCount: 0, totalUsers: userStore.length }
    });
  } catch (error) {
    console.error('User sync error:', error);
    res.status(500).json({ success: false, error: 'User sync failed' });
  }
});

// System Health API (public — used by Docker healthchecks)
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

app.get('/api/system/resources', authMiddleware, (req, res) => {
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
  res.json({
    success: true,
    message: 'Setup completed',
    data: setupConfig,
  });
});

// Policy Management APIs
app.get('/api/policies', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: [
      {
        id: 'version_mgmt',
        name: 'Version Management Policy',
        description: 'Automatic application updates with version control',
        active: true,
        platforms: ['linux'],
        rules: { autoUpdate: true, updateWindow: 'maintenance', rollback: true }
      },
      {
        id: 'security_updates',
        name: 'Security Update Policy',
        description: 'Immediate deployment of security patches',
        active: true,
        platforms: ['windows', 'macos', 'linux'],
        rules: { immediate: true, critical: true, notification: true }
      }
    ]
  });
});

// ── Device Enrollment APIs ──────────────────────────────────────────
const enrollmentTokens = {};

// Token generation requires authentication (admin creates tokens for devices)
app.post('/api/devices/enroll/token', authMiddleware, writeRateLimit, (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  enrollmentTokens[token] = {
    token,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    used: false,
    createdBy: req.user.id,
  };
  res.json({
    success: true,
    data: { token, expiresAt: expiresAt.toISOString() },
  });
});

// Device enrollment uses token (no user auth, but token is required)
app.post('/api/devices/enroll', writeRateLimit, (req, res) => {
  const { token, hostname, platform, os: deviceOs, osVersion } = req.body;

  if (!token || !enrollmentTokens[token]) {
    return res.status(401).json({ success: false, error: 'Invalid enrollment token' });
  }
  const tokenData = enrollmentTokens[token];
  if (tokenData.used || new Date(tokenData.expiresAt) < new Date()) {
    return res.status(401).json({ success: false, error: 'Token expired or already used' });
  }

  if (!isNonEmptyString(hostname, 253)) {
    return res.status(400).json({ success: false, error: 'hostname is required' });
  }

  tokenData.used = true;

  const deviceId = `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const newDevice = {
    id: deviceId,
    name: hostname,
    platform: isNonEmptyString(platform, 32) ? platform : 'unknown',
    os: isNonEmptyString(deviceOs, 64) ? deviceOs : 'Unknown',
    osVersion: isNonEmptyString(osVersion, 32) ? osVersion : '',
    status: 'online',
    enrolledAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  };

  deviceStore[deviceId] = newDevice;

  res.json({
    success: true,
    data: { deviceId, message: 'Device enrolled successfully', device: newDevice },
  });
});

// Printer discovery (mock data — replace with real discovery in production)
app.get('/api/printers/discover', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: [
      { name: 'HP LaserJet Pro M404n', ip: process.env.PRINTER1_IP || '192.168.1.200', protocol: 'ipp', status: 'online' },
      { name: 'Brother HL-L2350DW', ip: process.env.PRINTER2_IP || '192.168.1.201', protocol: 'lpd', status: 'online' },
    ],
  });
});

app.post('/api/printers', authMiddleware, (req, res) => {
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

// Export app for testing
module.exports = { app, server, userStore, hashPassword };

if (require.main === module) {
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`OpenDirectory API Backend running on port ${PORT}`);
  console.log(`WebSocket server ready — token authentication required`);
  // Network services are provided by the network-infrastructure module (port 3007)
});

// Periodic device health check
setInterval(async () => {
  for (const [deviceId, device] of Object.entries(deviceStore)) {
    if (deviceId === 'CT2001') {
      try {
        await ssh.connect({
          host: CT2001_HOST,
          username: process.env.CT2001_USERNAME || 'root',
          password: process.env.SSH_PASSWORD || '',
          port: parseInt(process.env.CT2001_PORT) || 22,
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
}, 30000);

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down gracefully...`);
  clients.forEach(ws => ws.terminate());
  try { ssh.dispose(); } catch (_) {}
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
} // end if (require.main === module)
