'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const winston = require('winston');
const WebSocket = require('ws');
const http = require('http');
const promClient = require('prom-client');

const CatalogManager = require('./catalog/catalogManager');
const ClientDetector = require('./detection/clientDetector');
const DistributionEngine = require('./distribution/distributionEngine');
const AssignmentEngine = require('./assignment/assignmentEngine');

// --- Logger ---
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'app-store' },
  transports: [new winston.transports.Console()],
});

// --- Configuration ---
const PORT = parseInt(process.env.PORT, 10) || 3906;
const DB_CONFIG = {
  host: process.env.DB_HOST || 'postgres',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  database: process.env.DB_NAME || 'opendirectory',
  user: process.env.DB_USER || 'opendirectory',
  password: process.env.DB_PASSWORD || 'opendirectory',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
};

// --- Prometheus Metrics ---
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics({ prefix: 'app_store_' });
const httpRequestDuration = new promClient.Histogram({
  name: 'app_store_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5],
});

// --- Initialize ---
const app = express();
const server = http.createServer(app);

// WebSocket server for real-time install status updates
const wss = new WebSocket.Server({ server, path: '/ws/store' });
wss.on('connection', (ws) => {
  logger.info('WebSocket client connected');
  ws.on('close', () => logger.debug('WebSocket client disconnected'));
});

// Database pool
const pool = new Pool(DB_CONFIG);
pool.on('error', (err) => {
  logger.error('Unexpected database error', { error: err.message });
});

// Service instances
const catalogManager = new CatalogManager(pool);
const clientDetector = new ClientDetector(pool);
const distributionEngine = new DistributionEngine(pool, wss);
const assignmentEngine = new AssignmentEngine(pool, distributionEngine);

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// Request duration tracking
app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer();
  res.on('finish', () => {
    end({ method: req.method, route: req.route?.path || req.path, status: res.statusCode });
  });
  next();
});

// Request logging
app.use((req, res, next) => {
  logger.debug('Request', { method: req.method, path: req.path });
  next();
});

// --- Health & Metrics ---
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'app-store', timestamp: new Date().toISOString() });
});

app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
  } catch (error) {
    res.status(500).json({ error: 'Failed to collect metrics' });
  }
});

// ========================================================================
// Admin API - Catalog Management
// ========================================================================

// List all apps (admin catalog view)
app.get('/api/store/catalog', async (req, res) => {
  try {
    const { search, category, platform, tags, enabled, page, limit } = req.query;
    const result = await catalogManager.listApps({
      search,
      category,
      platform,
      tags: tags ? tags.split(',') : undefined,
      enabled: enabled !== undefined ? enabled === 'true' : undefined,
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 50,
    });
    res.json(result);
  } catch (error) {
    logger.error('Failed to list apps', { error: error.message });
    res.status(500).json({ error: 'Failed to list apps' });
  }
});

// Add app to catalog
app.post('/api/store/catalog', async (req, res) => {
  try {
    const app = await catalogManager.createApp(req.body);
    res.status(201).json(app);
  } catch (error) {
    logger.error('Failed to create app', { error: error.message });
    res.status(400).json({ error: error.message });
  }
});

// Update app
app.put('/api/store/catalog/:id', async (req, res) => {
  try {
    const app = await catalogManager.updateApp(req.params.id, req.body);
    if (!app) {
      return res.status(404).json({ error: 'App not found' });
    }
    res.json(app);
  } catch (error) {
    logger.error('Failed to update app', { error: error.message });
    res.status(400).json({ error: error.message });
  }
});

// Remove app
app.delete('/api/store/catalog/:id', async (req, res) => {
  try {
    const result = await catalogManager.deleteApp(req.params.id);
    if (!result) {
      return res.status(404).json({ error: 'App not found' });
    }
    res.json({ message: 'App deleted', ...result });
  } catch (error) {
    logger.error('Failed to delete app', { error: error.message });
    res.status(500).json({ error: 'Failed to delete app' });
  }
});

// Assign app to targets
app.post('/api/store/catalog/:id/assign', async (req, res) => {
  try {
    const { targets, install_type, created_by } = req.body;
    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: 'targets array is required' });
    }
    const assignments = await assignmentEngine.assignApp(
      req.params.id,
      targets,
      install_type || 'available',
      created_by || req.headers['x-user-id'] || null
    );
    res.status(201).json(assignments);
  } catch (error) {
    logger.error('Failed to assign app', { error: error.message });
    res.status(400).json({ error: error.message });
  }
});

// Remove assignment
app.delete('/api/store/catalog/:id/assign/:assignId', async (req, res) => {
  try {
    const result = await assignmentEngine.removeAssignment(req.params.assignId);
    if (!result) {
      return res.status(404).json({ error: 'Assignment not found' });
    }
    res.json({ message: 'Assignment removed', ...result });
  } catch (error) {
    logger.error('Failed to remove assignment', { error: error.message });
    res.status(500).json({ error: 'Failed to remove assignment' });
  }
});

// List assignments for an app
app.get('/api/store/catalog/:id/assignments', async (req, res) => {
  try {
    const assignments = await assignmentEngine.getAppAssignments(req.params.id);
    res.json(assignments);
  } catch (error) {
    logger.error('Failed to list assignments', { error: error.message });
    res.status(500).json({ error: 'Failed to list assignments' });
  }
});

// List categories
app.get('/api/store/categories', async (req, res) => {
  try {
    const categories = await catalogManager.listCategories();
    res.json(categories);
  } catch (error) {
    logger.error('Failed to list categories', { error: error.message });
    res.status(500).json({ error: 'Failed to list categories' });
  }
});

// Seed default apps
app.post('/api/store/catalog/seed', async (req, res) => {
  try {
    const result = await catalogManager.seedDefaultApps();
    res.json({ message: 'Default apps seeded', ...result });
  } catch (error) {
    logger.error('Failed to seed default apps', { error: error.message });
    res.status(500).json({ error: 'Failed to seed default apps' });
  }
});

// ========================================================================
// Client / Self-Service API
// ========================================================================

// Get available apps for a device (personalized catalog)
app.get('/api/store/available/:deviceId', async (req, res) => {
  try {
    const clientInfo = await clientDetector.detectClient(req.params.deviceId, {
      userId: req.headers['x-user-id'],
      platform: req.query.platform,
    });
    const apps = await clientDetector.getAvailableApps(clientInfo);
    res.json(apps);
  } catch (error) {
    logger.error('Failed to get available apps', { error: error.message });
    res.status(500).json({ error: 'Failed to get available apps' });
  }
});

// Get required apps for a device
app.get('/api/store/required/:deviceId', async (req, res) => {
  try {
    const clientInfo = await clientDetector.detectClient(req.params.deviceId, {
      userId: req.headers['x-user-id'],
      platform: req.query.platform,
    });
    const apps = await clientDetector.getAvailableApps(clientInfo);
    res.json(apps.required);
  } catch (error) {
    logger.error('Failed to get required apps', { error: error.message });
    res.status(500).json({ error: 'Failed to get required apps' });
  }
});

// Get installed apps on a device
app.get('/api/store/installed/:deviceId', async (req, res) => {
  try {
    const installed = await clientDetector.getInstalledApps(req.params.deviceId);
    res.json(installed);
  } catch (error) {
    logger.error('Failed to get installed apps', { error: error.message });
    res.status(500).json({ error: 'Failed to get installed apps' });
  }
});

// Request installation
app.post('/api/store/install', async (req, res) => {
  try {
    const { appId, deviceId } = req.body;
    if (!appId || !deviceId) {
      return res.status(400).json({ error: 'appId and deviceId are required' });
    }
    const userId = req.headers['x-user-id'] || req.body.userId || null;
    const result = await distributionEngine.requestInstall(appId, deviceId, userId);
    res.status(202).json(result);
  } catch (error) {
    logger.error('Failed to request install', { error: error.message });
    const status = error.message.includes('not found') || error.message.includes('not available')
      ? 404
      : error.message.includes('already installed') || error.message.includes('No licenses')
        ? 409
        : 500;
    res.status(status).json({ error: error.message });
  }
});

// Request uninstall
app.post('/api/store/uninstall', async (req, res) => {
  try {
    const { appId, deviceId } = req.body;
    if (!appId || !deviceId) {
      return res.status(400).json({ error: 'appId and deviceId are required' });
    }
    const result = await distributionEngine.requestUninstall(appId, deviceId);
    res.status(202).json(result);
  } catch (error) {
    logger.error('Failed to request uninstall', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get install status
app.get('/api/store/install/:installId/status', async (req, res) => {
  try {
    const status = await distributionEngine.getInstallStatus(req.params.installId);
    if (!status) {
      return res.status(404).json({ error: 'Installation not found' });
    }
    res.json(status);
  } catch (error) {
    logger.error('Failed to get install status', { error: error.message });
    res.status(500).json({ error: 'Failed to get install status' });
  }
});

// Update install status (called by device agents)
app.put('/api/store/install/:installId/status', async (req, res) => {
  try {
    const { status, progress, error } = req.body;
    const result = await distributionEngine.updateInstallStatus(
      req.params.installId, status, progress, error
    );
    res.json(result);
  } catch (error) {
    logger.error('Failed to update install status', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// ========================================================================
// Reporting API
// ========================================================================

// Installation history
app.get('/api/store/history', async (req, res) => {
  try {
    const { deviceId, appId, status, page, limit } = req.query;
    const result = await distributionEngine.getInstallHistory({
      deviceId,
      appId,
      status,
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 50,
    });
    res.json(result);
  } catch (error) {
    logger.error('Failed to get installation history', { error: error.message });
    res.status(500).json({ error: 'Failed to get installation history' });
  }
});

// License usage report
app.get('/api/store/licenses', async (req, res) => {
  try {
    const report = await distributionEngine.getLicenseReport();
    res.json(report);
  } catch (error) {
    logger.error('Failed to get license report', { error: error.message });
    res.status(500).json({ error: 'Failed to get license report' });
  }
});

// App store statistics
app.get('/api/store/stats', async (req, res) => {
  try {
    const stats = await catalogManager.getStats();
    res.json(stats);
  } catch (error) {
    logger.error('Failed to get store stats', { error: error.message });
    res.status(500).json({ error: 'Failed to get store stats' });
  }
});

// ========================================================================
// Share Scan — list installer files on an apps-purpose SMB/NFS share
// ========================================================================

const INSTALLER_EXTENSIONS = ['.exe', '.msi', '.msix', '.dmg', '.pkg', '.app.zip', '.deb', '.rpm', '.sh', '.run', '.appimage'];

function guessplatform(filename) {
  const f = filename.toLowerCase();
  const platforms = [];
  if (f.endsWith('.exe') || f.endsWith('.msi') || f.endsWith('.msix')) platforms.push('windows');
  if (f.endsWith('.dmg') || f.endsWith('.pkg')) platforms.push('macos');
  if (f.endsWith('.deb') || f.endsWith('.rpm') || f.endsWith('.sh') || f.endsWith('.run') || f.endsWith('.appimage')) platforms.push('linux');
  if (platforms.length === 0) platforms.push('windows', 'macos', 'linux');
  return platforms;
}

function guessAppName(filename) {
  return filename
    .replace(/\.(exe|msi|msix|dmg|pkg|deb|rpm|sh|run|appimage|zip)$/i, '')
    .replace(/[-_.]v?\d[\d.]+.*$/i, '')
    .replace(/[-_.]+/g, ' ')
    .trim()
    .replace(/\b\w/g, c => c.toUpperCase());
}

async function scanShareFiles(share) {
  const { execFile } = require('child_process');
  const { promisify } = require('util');
  const execFileAsync = promisify(execFile);

  const files = [];

  if (share.protocol === 'SMB') {
    // Use smbclient to list files recursively
    const server = share.server;
    const sharePath = share.path.startsWith('/') ? share.path.slice(1) : share.path;
    const uncShare = `//${server}/${sharePath}`;
    const args = [uncShare, '-N', '-c', 'recurse; ls'];
    if (share.username) args.push('-U', share.username);

    try {
      const { stdout } = await execFileAsync('smbclient', args, { timeout: 15000 });
      const lines = stdout.split('\n');
      let currentDir = '';
      for (const line of lines) {
        const dirMatch = line.match(/^\s*\\(.+)$/);
        if (dirMatch) { currentDir = dirMatch[1].replace(/\\/g, '/'); continue; }
        const fileMatch = line.match(/^\s{2}(.+?)\s+[AHRS]*\s+\d+\s+\w/);
        if (fileMatch) {
          const name = fileMatch[1].trim();
          const ext = '.' + name.split('.').pop().toLowerCase();
          if (INSTALLER_EXTENSIONS.includes(ext)) {
            const relativePath = currentDir ? `${currentDir}/${name}` : name;
            files.push({ name, relativePath, platforms: guessplatform(name), suggestedName: guessAppName(name) });
          }
        }
      }
    } catch (e) {
      // smbclient not available or unreachable — return empty list with error
      return { files: [], error: `smbclient: ${e.message.split('\n')[0]}` };
    }
  } else if (share.protocol === 'NFS') {
    // Try direct filesystem listing (only works if share is already mounted in container)
    const fs = require('fs');
    const mountPath = `/mnt/nfs/${share.name}`;
    try {
      const walk = (dir, base = '') => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const e of entries) {
          if (e.isDirectory()) walk(`${dir}/${e.name}`, base ? `${base}/${e.name}` : e.name);
          else {
            const ext = '.' + e.name.split('.').pop().toLowerCase();
            if (INSTALLER_EXTENSIONS.includes(ext)) {
              const relativePath = base ? `${base}/${e.name}` : e.name;
              files.push({ name: e.name, relativePath, platforms: guessplatform(e.name), suggestedName: guessAppName(e.name) });
            }
          }
        }
      };
      walk(mountPath);
    } catch {
      return { files: [], error: 'NFS share nicht erreichbar (nicht gemountet)' };
    }
  }

  return { files };
}

// POST /api/store/shares/:id/scan — scan an apps-purpose share for installer files
app.post('/api/store/shares/:shareId/scan', async (req, res) => {
  try {
    const { shareId } = req.params;

    // Fetch share details from integration-service
    const integrationUrl = process.env.INTEGRATION_SERVICE_URL || 'http://integration-service:4000';
    const shareRes = await fetch(`${integrationUrl}/api/network/shares`).then(r => r.json());
    const share = (shareRes.shares || []).find(s => s.id === shareId);

    if (!share) return res.status(404).json({ error: 'Share not found' });
    if (!share.purpose?.includes('apps')) return res.status(400).json({ error: 'Share is not marked as apps-purpose' });

    const result = await scanShareFiles(share);
    res.json({ shareId, shareName: share.name, ...result });
  } catch (err) {
    logger.error('Share scan error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================
// Startup
// ========================================================================

async function runMigrations() {
  const fs = require('fs');
  const path = require('path');
  const migrationFile = path.join(__dirname, 'db/migrations/001_app_store.sql');
  try {
    const sql = fs.readFileSync(migrationFile, 'utf8');
    await pool.query(sql);
    logger.info('Database migrations applied');
  } catch (err) {
    // Ignore "already exists" errors — tables/indexes may already be present
    if (!err.message.includes('already exists')) {
      logger.warn('Migration warning:', { error: err.message });
    }
  }
}

async function start() {
  try {
    // Verify database connection
    const client = await pool.connect();
    logger.info('Database connection established');
    client.release();

    // Run migrations
    await runMigrations();

    // Initialize messaging
    await distributionEngine.initializeMessaging();

    // Start HTTP server
    server.listen(PORT, '0.0.0.0', () => {
      logger.info(`App Store service running on port ${PORT}`);
    });
  } catch (error) {
    logger.error('Failed to start App Store service', { error: error.message });
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await distributionEngine.shutdown();
  server.close(() => {
    pool.end();
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down');
  await distributionEngine.shutdown();
  server.close(() => {
    pool.end();
    process.exit(0);
  });
});

start();

module.exports = app;
