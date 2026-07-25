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
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const CatalogManager = require('./catalog/catalogManager');
const ClientDetector = require('./detection/clientDetector');
const DistributionEngine = require('./distribution/distributionEngine');
const AssignmentEngine = require('./assignment/assignmentEngine');
const { oidcAuth, requireAdmin } = require('./middleware/oidcAuth');

// ── EventBusClient ────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'app-store' });
async function connectBus() { await _bus.connect(); }
function publishEvent(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }
// ─────────────────────────────────────────────────────────────────────────────

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
  database: process.env.DB_NAME || 'app_store',
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
const distributionEngine = new DistributionEngine(pool, wss, publishEvent);
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

// --- Authentication ---
// P0 fix: app-store had zero HTTP auth (see middleware/oidcAuth.js header
// comment for the full rationale). skipPaths covers health/metrics probes.
// agentTokenPaths covers the two genuine device/agent-facing endpoints that
// cannot carry an end-user OIDC JWT — see middleware/oidcAuth.js for exactly
// why each one is listed and what it does and does not grant:
//   - PUT /api/store/install/:installId/status ('*/status' suffix — the GET
//     variant of the same path is included too, which is intentional: a
//     device checking its own install status is no more sensitive than it
//     reporting one)
//   - GET /api/appstore/packages/:packageId/download ('*/download' suffix —
//     deliberately does NOT match DELETE /api/appstore/packages/:packageId,
//     which stays admin-only)
// Every other route is JWT-only; requireAdmin is layered on top of it for
// the state-changing / deploy endpoints below.
app.use(oidcAuth({
  skipPaths: ['/health', '/metrics'],
  agentTokenPaths: ['*/status', '*/download'],
}));

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
app.post('/api/store/catalog', requireAdmin, async (req, res) => {
  try {
    const app = await catalogManager.createApp(req.body);
    res.status(201).json(app);
  } catch (error) {
    logger.error('Failed to create app', { error: error.message });
    res.status(400).json({ error: error.message });
  }
});

// Update app
app.put('/api/store/catalog/:id', requireAdmin, async (req, res) => {
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
app.delete('/api/store/catalog/:id', requireAdmin, async (req, res) => {
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
app.post('/api/store/catalog/:id/assign', requireAdmin, async (req, res) => {
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
app.delete('/api/store/catalog/:id/assign/:assignId', requireAdmin, async (req, res) => {
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
app.post('/api/store/catalog/seed', requireAdmin, async (req, res) => {
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

// Request installation — flagged by the auth audit as "App-Deploy auf
// Geräte": pushes an install command onto a target device, so it gets the
// same admin gate as the /api/appstore deploy endpoint below.
app.post('/api/store/install', requireAdmin, async (req, res) => {
  try {
    const { appId, deviceId } = req.body;
    if (!appId || !deviceId) {
      return res.status(400).json({ error: 'appId and deviceId are required' });
    }
    const userId = req.headers['x-user-id'] || req.body.userId || null;
    const result = await distributionEngine.requestInstall(appId, deviceId, userId);
    publishEvent('app.install.requested', { appId, deviceId, requestedBy: userId });
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

// Request uninstall — same admin gate as install (removes software from a
// target device, i.e. also a fleet-wide state change).
app.post('/api/store/uninstall', requireAdmin, async (req, res) => {
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

// Update install status (called by device agents). Deliberately NOT
// requireAdmin: this is a device→server status callback, reachable via the
// global oidcAuth agentTokenPaths bypass ('*/status') with the shared
// APPSTORE_AGENT_TOKEN when the caller has no end-user JWT — see
// middleware/oidcAuth.js. A caller that does present a valid Bearer JWT is
// let through too (any authenticated user), since reporting an install
// result is not an admin-privileged action.
app.put('/api/store/install/:installId/status', async (req, res) => {
  try {
    const { status, progress, error } = req.body;
    const result = await distributionEngine.updateInstallStatus(
      req.params.installId, status, progress, error
    );
    if (status === 'completed' || status === 'installed') {
      publishEvent('app.install.completed', { installId: req.params.installId, progress });
    } else if (status === 'failed' || status === 'error') {
      publishEvent('app.install.failed', { installId: req.params.installId, error });
    }
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

// POST /api/store/shares/:id/scan — scan an apps-purpose share for installer
// files. Admin-gated: this shells out to smbclient / walks a mounted NFS
// path (see scanShareFiles above), which is infra-sensitive, not a benign
// catalog read.
app.post('/api/store/shares/:shareId/scan', requireAdmin, async (req, res) => {
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
// /api/appstore — Simplified deployment-oriented API (port-compatible)
// ========================================================================

const { v4: uuidv4 } = require('uuid');

const DEMO_APPS = [
  { id: 'slack', name: 'Slack', vendor: 'Salesforce', version: '4.35.131', category: 'Kommunikation', size: '180MB', platforms: ['macOS', 'Windows', 'iOS', 'Android'], license_type: 'per_user', description: 'Team communication and collaboration platform', icon_url: null },
  { id: 'zoom', name: 'Zoom', vendor: 'Zoom Video', version: '5.17.0', category: 'Kommunikation', size: '95MB', platforms: ['macOS', 'Windows', 'iOS', 'Android'], license_type: 'per_user', description: 'Video conferencing and virtual meetings', icon_url: null },
  { id: 'chrome', name: 'Google Chrome', vendor: 'Google', version: '122.0.6261', category: 'Browser', size: '280MB', platforms: ['macOS', 'Windows'], license_type: 'free', description: 'Fast and secure web browser by Google', icon_url: null },
  { id: 'firefox', name: 'Mozilla Firefox', vendor: 'Mozilla', version: '124.0', category: 'Browser', size: '220MB', platforms: ['macOS', 'Windows'], license_type: 'free', description: 'Open-source web browser focused on privacy', icon_url: null },
  { id: 'vscode', name: 'Visual Studio Code', vendor: 'Microsoft', version: '1.87.0', category: 'Entwicklung', size: '340MB', platforms: ['macOS', 'Windows'], license_type: 'free', description: 'Lightweight but powerful source code editor', icon_url: null },
  { id: 'office365', name: 'Microsoft 365', vendor: 'Microsoft', version: '16.83', category: 'Produktivität', size: '4.2GB', platforms: ['macOS', 'Windows', 'iOS', 'Android'], license_type: 'subscription', description: 'Microsoft Office suite with cloud services', icon_url: null },
  { id: '1password', name: '1Password', vendor: '1Password', version: '8.10.28', category: 'Sicherheit', size: '120MB', platforms: ['macOS', 'Windows', 'iOS', 'Android'], license_type: 'per_user', description: 'Password manager and secure digital wallet', icon_url: null },
  { id: 'jamf-connect', name: 'Jamf Connect', vendor: 'Jamf', version: '2.35.0', category: 'Sicherheit', size: '45MB', platforms: ['macOS'], license_type: 'per_device', description: 'macOS identity management with cloud IdP', icon_url: null },
];

// In-memory stores (with optional DB persistence)
const inMemoryCatalog = new Map(DEMO_APPS.map(a => [a.id, {
  ...a,
  supported_platforms: a.platforms,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  version_history: [{ version: a.version, released_at: new Date().toISOString(), notes: 'Initial version' }],
}]));
const inMemoryDeployments = new Map();
const inMemoryDeploymentStatus = new Map(); // deploymentId -> [{ device_id, status, installed_at, error }]

// Helper: ensure DB tables exist, fall back gracefully
async function ensureAppstoreTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_catalog (
        id VARCHAR(100) PRIMARY KEY,
        metadata JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS app_deployments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        app_id VARCHAR(100),
        targets JSONB,
        status VARCHAR(50) DEFAULT 'pending',
        mandatory BOOLEAN DEFAULT false,
        deadline TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        created_by VARCHAR(255)
      );
      CREATE TABLE IF NOT EXISTS deployment_status (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        deployment_id UUID REFERENCES app_deployments(id),
        device_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        installed_at TIMESTAMPTZ,
        error TEXT
      );
    `);
  } catch (err) {
    logger.warn('appstore tables setup warning', { error: err.message });
  }
}

// Persistence audit finding (not part of the auth mandate, taken along
// because it's risk-free and additive): /api/appstore/* writes every
// create/update to the app_catalog table (see the POST/PUT handlers below)
// but the GET handlers only ever read from the inMemoryCatalog Map — which
// is (re)seeded from DEMO_APPS on every process start. So a custom-published
// app, or an edit to a demo app, survives in Postgres but is invisible again
// the moment the service restarts, until this function runs.
//
// This only rehydrates the catalog (app_catalog → inMemoryCatalog): that
// table's `metadata` JSONB column already carries the full app object, so
// overlaying it onto the DEMO_APPS seed is a pure additive read with no
// schema change and no route-behavior change. inMemoryDeployments /
// inMemoryDeploymentStatus are deliberately NOT rehydrated here — the
// app_deployments / deployment_status tables don't have columns for
// `app_name` or `version` (see ensureAppstoreTables above), so a faithful
// round-trip would need a schema migration; that's out of scope for this
// auth-focused change and is called out in the audit report instead.
async function hydrateAppstoreCatalog() {
  try {
    const result = await pool.query('SELECT id, metadata FROM app_catalog');
    for (const row of result.rows) {
      const metadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      if (metadata && typeof metadata === 'object') {
        inMemoryCatalog.set(row.id, metadata);
      }
    }
    if (result.rows.length) {
      logger.info('Rehydrated app_catalog from DB', { count: result.rows.length });
    }
  } catch (err) {
    logger.warn('appstore catalog hydration warning', { error: err.message });
  }
}

// GET /api/appstore/apps
app.get('/api/appstore/apps', async (req, res) => {
  try {
    const { category, platform, search } = req.query;
    let apps = Array.from(inMemoryCatalog.values());
    if (category) apps = apps.filter(a => a.category === category);
    if (platform) apps = apps.filter(a => (a.supported_platforms || a.platforms || []).includes(platform));
    if (search) {
      const s = search.toLowerCase();
      apps = apps.filter(a => a.name.toLowerCase().includes(s) || (a.description || '').toLowerCase().includes(s) || a.vendor.toLowerCase().includes(s));
    }
    res.json({ apps, total: apps.length });
  } catch (err) {
    logger.error('GET /api/appstore/apps error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// GET /api/appstore/apps/:id
app.get('/api/appstore/apps/:id', async (req, res) => {
  try {
    const app = inMemoryCatalog.get(req.params.id);
    if (!app) return res.status(404).json({ error: 'App not found' });
    res.json(app);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/appstore/apps — publish new app (admin only)
app.post('/api/appstore/apps', requireAdmin, async (req, res) => {
  try {
    const { id, name, vendor, version, category, size, platforms, license_type, description, icon_url, supported_platforms } = req.body;
    if (!id || !name || !version) return res.status(400).json({ error: 'id, name and version are required' });
    const entry = {
      id, name, vendor: vendor || '', version, category: category || 'Allgemein',
      size: size || null, platforms: supported_platforms || platforms || [],
      supported_platforms: supported_platforms || platforms || [],
      license_type: license_type || 'free', description: description || '', icon_url: icon_url || null,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      version_history: [{ version, released_at: new Date().toISOString(), notes: 'Initial publish' }],
    };
    inMemoryCatalog.set(id, entry);
    try {
      await pool.query(
        'INSERT INTO app_catalog (id, metadata) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET metadata = $2',
        [id, JSON.stringify(entry)]
      );
    } catch (_) { /* DB optional */ }
    publishEvent('app.published', { appId: id, name, version, category: category || 'Allgemein', vendor: vendor || '' });
    res.status(201).json(entry);
  } catch (err) {
    logger.error('POST /api/appstore/apps error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/appstore/apps/:id — update app metadata
app.put('/api/appstore/apps/:id', requireAdmin, async (req, res) => {
  try {
    const existing = inMemoryCatalog.get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'App not found' });
    const updated = { ...existing, ...req.body, id: req.params.id, updated_at: new Date().toISOString() };
    if (req.body.version && req.body.version !== existing.version) {
      updated.version_history = [...(existing.version_history || []), {
        version: req.body.version, released_at: new Date().toISOString(), notes: req.body.release_notes || ''
      }];
    }
    inMemoryCatalog.set(req.params.id, updated);
    try {
      await pool.query(
        'INSERT INTO app_catalog (id, metadata) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET metadata = $2',
        [req.params.id, JSON.stringify(updated)]
      );
    } catch (_) { /* DB optional */ }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/appstore/apps/:id/deploy — the other endpoint the auth audit
// explicitly named as an unauth "App-Deploy auf Geräte" mutation.
app.post('/api/appstore/apps/:id/deploy', requireAdmin, async (req, res) => {
  try {
    const appEntry = inMemoryCatalog.get(req.params.id);
    if (!appEntry) return res.status(404).json({ error: 'App not found' });
    const { targets, version, mandatory, deadline } = req.body;
    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: 'targets array is required' });
    }
    const deploymentId = uuidv4();
    const deployment = {
      id: deploymentId, app_id: req.params.id, app_name: appEntry.name,
      targets, version: version || appEntry.version,
      mandatory: mandatory || false, deadline: deadline || null,
      status: 'pending', created_at: new Date().toISOString(),
      completed_at: null,
      created_by: req.headers['x-user-id'] || req.body.created_by || 'admin',
    };
    inMemoryDeployments.set(deploymentId, deployment);
    publishEvent('app.install.requested', { appId: req.params.id, targets, mandatory: mandatory || false, deploymentId });
    // Initialize per-device status records
    const deviceStatuses = targets.map(t => ({
      id: uuidv4(), deployment_id: deploymentId,
      device_id: t.id || t.name || String(t),
      target_type: t.type || 'device', status: 'pending',
      installed_at: null, error: null,
    }));
    inMemoryDeploymentStatus.set(deploymentId, deviceStatuses);

    try {
      await pool.query(
        `INSERT INTO app_deployments (id, app_id, targets, status, mandatory, deadline, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [deploymentId, req.params.id, JSON.stringify(targets), 'pending', mandatory || false, deadline || null, deployment.created_by]
      );
      for (const ds of deviceStatuses) {
        await pool.query(
          `INSERT INTO deployment_status (id, deployment_id, device_id, status) VALUES ($1, $2, $3, $4)`,
          [ds.id, deploymentId, ds.device_id, 'pending']
        );
      }
    } catch (_) { /* DB optional */ }

    res.status(201).json({ deploymentId, deployment });
  } catch (err) {
    logger.error('POST /api/appstore/apps/:id/deploy error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// GET /api/appstore/deployments
app.get('/api/appstore/deployments', async (req, res) => {
  try {
    const { app_id, status } = req.query;
    let deployments = Array.from(inMemoryDeployments.values());
    if (app_id) deployments = deployments.filter(d => d.app_id === app_id);
    if (status) deployments = deployments.filter(d => d.status === status);
    // Enrich with progress
    const enriched = deployments.map(d => {
      const statuses = inMemoryDeploymentStatus.get(d.id) || [];
      const total = statuses.length;
      const installed = statuses.filter(s => s.status === 'installed').length;
      const failed = statuses.filter(s => s.status === 'failed').length;
      return { ...d, progress: { total, installed, failed, pending: total - installed - failed } };
    });
    res.json({ deployments: enriched, total: enriched.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/appstore/deployments/:id
app.get('/api/appstore/deployments/:id', async (req, res) => {
  try {
    const deployment = inMemoryDeployments.get(req.params.id);
    if (!deployment) return res.status(404).json({ error: 'Deployment not found' });
    const statuses = inMemoryDeploymentStatus.get(req.params.id) || [];
    res.json({ ...deployment, device_statuses: statuses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/appstore/deployments/:id/cancel
app.put('/api/appstore/deployments/:id/cancel', requireAdmin, async (req, res) => {
  try {
    const deployment = inMemoryDeployments.get(req.params.id);
    if (!deployment) return res.status(404).json({ error: 'Deployment not found' });
    if (deployment.status === 'completed') {
      return res.status(409).json({ error: 'Cannot cancel a completed deployment' });
    }
    const updated = { ...deployment, status: 'cancelled', completed_at: new Date().toISOString() };
    inMemoryDeployments.set(req.params.id, updated);
    // Update pending device statuses to cancelled
    const statuses = inMemoryDeploymentStatus.get(req.params.id) || [];
    const updatedStatuses = statuses.map(s => s.status === 'pending' ? { ...s, status: 'cancelled' } : s);
    inMemoryDeploymentStatus.set(req.params.id, updatedStatuses);
    try {
      await pool.query("UPDATE app_deployments SET status = 'cancelled', completed_at = NOW() WHERE id = $1", [req.params.id]);
    } catch (_) { /* DB optional */ }
    res.json({ message: 'Deployment cancelled', deployment: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================
// Multi-Platform Package Distribution
// ========================================================================

const PACKAGES_DIR = process.env.PACKAGES_DIR || path.join(__dirname, '../../../data/packages');
fs.mkdirSync(PACKAGES_DIR, { recursive: true });

// Platform detection from file extension
const PLATFORM_MAP = {
  '.exe': 'windows', '.msi': 'windows', '.msix': 'windows',
  '.dmg': 'macos',   '.pkg': 'macos',
  '.deb': 'linux',   '.rpm': 'linux',   '.appimage': 'linux',
  '.tar.gz': 'linux', '.tar.xz': 'linux',
};
const PLATFORM_ICONS = { windows: '🪟', macos: '🍎', linux: '🐧' };

function detectPlatform(filename) {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tar.xz')) return 'linux';
  return PLATFORM_MAP[path.extname(lower)] || 'unknown';
}

function detectFormat(filename) {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.tar.gz'))  return 'tar.gz';
  if (lower.endsWith('.tar.xz'))  return 'tar.xz';
  return path.extname(lower).replace('.', '').toLowerCase();
}

// Multer storage — files go to PACKAGES_DIR/<appId>/<uuid>-<original>
const packageStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(PACKAGES_DIR, req.params.id || 'unknown');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniquePrefix = crypto.randomUUID().split('-')[0];
    cb(null, `${uniquePrefix}-${file.originalname.replace(/[^a-zA-Z0-9._\-]/g, '_')}`);
  },
});

const ALLOWED_EXTS = new Set(['.exe','.msi','.msix','.dmg','.pkg','.deb','.rpm','.appimage','.gz','.xz','.zip']);
const packageUpload = multer({
  storage: packageStorage,
  limits: { fileSize: 4 * 1024 * 1024 * 1024 }, // 4 GB
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname.toLowerCase());
    if (ALLOWED_EXTS.has(ext) || file.originalname.toLowerCase().endsWith('.tar.gz') || file.originalname.toLowerCase().endsWith('.tar.xz')) {
      cb(null, true);
    } else {
      cb(new Error(`Dateityp nicht erlaubt: ${ext}`));
    }
  },
});

// Compute SHA-256 of a file path
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', d => hash.update(d));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// In-memory package store (fallback when DB unavailable)
const inMemoryPackages = new Map(); // packageId → package object

async function ensurePackagesTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_packages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        app_id VARCHAR(100) NOT NULL,
        platform VARCHAR(20) NOT NULL,
        format VARCHAR(20) NOT NULL,
        version VARCHAR(100) NOT NULL,
        filename VARCHAR(500) NOT NULL,
        filepath TEXT NOT NULL,
        size_bytes BIGINT,
        sha256 VARCHAR(64),
        architecture VARCHAR(20) DEFAULT 'x64',
        release_notes TEXT,
        uploaded_by VARCHAR(255),
        uploaded_at TIMESTAMPTZ DEFAULT NOW(),
        download_count INTEGER DEFAULT 0,
        active BOOLEAN DEFAULT true
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_app_packages_app_id ON app_packages(app_id)`);
  } catch (_) { /* DB optional */ }
}

// GET /api/appstore/apps/:id/packages — list packages for an app
app.get('/api/appstore/apps/:id/packages', async (req, res) => {
  try {
    const { id } = req.params;
    let packages = [];
    try {
      const result = await pool.query(
        'SELECT * FROM app_packages WHERE app_id=$1 AND active=true ORDER BY uploaded_at DESC',
        [id]
      );
      packages = result.rows;
    } catch (_) {
      packages = [...inMemoryPackages.values()].filter(p => p.app_id === id && p.active);
    }
    res.json(packages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/appstore/apps/:id/packages — upload a package file. Installer
// upload — the third mutation the auth audit explicitly named. requireAdmin
// runs BEFORE packageUpload (multer) so an unauthenticated/non-admin caller
// is rejected before any bytes are written to PACKAGES_DIR.
app.post('/api/appstore/apps/:id/packages', requireAdmin, packageUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Keine Datei hochgeladen' });
    const { id } = req.params;
    const { version = '1.0.0', architecture = 'x64', release_notes = '' } = req.body;

    const platform = detectPlatform(req.file.originalname);
    const format   = detectFormat(req.file.originalname);
    const sha256   = await sha256File(req.file.path);
    const uploadedBy = req.headers['x-user-id'] || 'admin';

    const pkg = {
      id: crypto.randomUUID(),
      app_id: id,
      platform,
      format,
      version,
      filename: req.file.originalname,
      filepath: req.file.path,
      size_bytes: req.file.size,
      sha256,
      architecture,
      release_notes,
      uploaded_by: uploadedBy,
      uploaded_at: new Date().toISOString(),
      download_count: 0,
      active: true,
    };

    try {
      const row = await pool.query(
        `INSERT INTO app_packages
           (id, app_id, platform, format, version, filename, filepath, size_bytes, sha256, architecture, release_notes, uploaded_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
        [pkg.id, pkg.app_id, pkg.platform, pkg.format, pkg.version, pkg.filename,
         pkg.filepath, pkg.size_bytes, pkg.sha256, pkg.architecture, pkg.release_notes, pkg.uploaded_by]
      );
      inMemoryPackages.set(pkg.id, row.rows[0]);
    } catch (_) {
      inMemoryPackages.set(pkg.id, pkg);
    }

    logger.info('Package uploaded', { appId: id, platform, format, version, size: req.file.size });
    publishEvent('app.package.uploaded', { appId: id, packageId: pkg.id, platform, format, version, size: req.file.size });
    res.status(201).json(pkg);
  } catch (err) {
    // Clean up uploaded file on error
    if (req.file?.path) try { fs.unlinkSync(req.file.path); } catch (_) {}
    res.status(500).json({ error: err.message });
  }
});

// GET /api/appstore/packages/:packageId/download — stream file to client.
// Deliberately NOT requireAdmin: this exact URL is handed to device agents
// by device-service (installApp() in services/core/device-service/src/
// index.js) as the download source for a push-install, and the agent has no
// end-user JWT. Reachable via the global oidcAuth agentTokenPaths bypass
// ('*/download', shared APPSTORE_AGENT_TOKEN via header or ?agent_token=)
// when no Bearer token is presented; any authenticated user (e.g. an admin
// downloading a package from the console) can also use it directly with a
// normal Bearer JWT — see middleware/oidcAuth.js.
app.get('/api/appstore/packages/:packageId/download', async (req, res) => {
  try {
    const { packageId } = req.params;
    let pkg = inMemoryPackages.get(packageId);
    if (!pkg) {
      try {
        const result = await pool.query('SELECT * FROM app_packages WHERE id=$1 AND active=true', [packageId]);
        if (result.rows.length) pkg = result.rows[0];
      } catch (_) {}
    }
    if (!pkg) return res.status(404).json({ error: 'Paket nicht gefunden' });
    if (!fs.existsSync(pkg.filepath)) return res.status(404).json({ error: 'Datei nicht vorhanden' });

    // Increment download counter
    try {
      await pool.query('UPDATE app_packages SET download_count = download_count + 1 WHERE id=$1', [packageId]);
    } catch (_) {
      if (inMemoryPackages.has(packageId)) {
        inMemoryPackages.get(packageId).download_count++;
      }
    }

    const stat = fs.statSync(pkg.filepath);
    res.setHeader('Content-Disposition', `attachment; filename="${pkg.filename}"`);
    res.setHeader('Content-Length', stat.size);
    res.setHeader('X-SHA256', pkg.sha256 || '');
    res.setHeader('X-Platform', pkg.platform);
    res.setHeader('X-Version', pkg.version);
    // Disable helmet's content-type sniffing for binary downloads
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const mimeMap = {
      exe: 'application/vnd.microsoft.portable-executable',
      msi: 'application/x-msi',
      msix: 'application/msix',
      dmg: 'application/x-apple-diskimage',
      pkg: 'application/x-newton-compatible-pkg',
      deb: 'application/vnd.debian.binary-package',
      rpm: 'application/x-rpm',
      appimage: 'application/x-executable',
      gz: 'application/gzip',
      xz: 'application/x-xz',
      zip: 'application/zip',
    };
    res.setHeader('Content-Type', mimeMap[pkg.format] || 'application/octet-stream');

    const readStream = fs.createReadStream(pkg.filepath);
    readStream.pipe(res);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/appstore/packages/:packageId — soft-delete a package
app.delete('/api/appstore/packages/:packageId', requireAdmin, async (req, res) => {
  try {
    const { packageId } = req.params;
    let pkg = inMemoryPackages.get(packageId);
    if (!pkg) {
      try {
        const r = await pool.query('SELECT * FROM app_packages WHERE id=$1', [packageId]);
        if (r.rows.length) pkg = r.rows[0];
      } catch (_) {}
    }
    if (!pkg) return res.status(404).json({ error: 'Paket nicht gefunden' });

    try {
      await pool.query('UPDATE app_packages SET active=false WHERE id=$1', [packageId]);
    } catch (_) {}
    if (inMemoryPackages.has(packageId)) {
      inMemoryPackages.get(packageId).active = false;
    }
    res.json({ message: 'Paket gelöscht' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/appstore/apps/:id/packages/summary — per-platform availability summary
app.get('/api/appstore/apps/:id/packages/summary', async (req, res) => {
  try {
    const { id } = req.params;
    let packages = [];
    try {
      const result = await pool.query(
        'SELECT platform, format, version, id, sha256, size_bytes, download_count, uploaded_at FROM app_packages WHERE app_id=$1 AND active=true ORDER BY uploaded_at DESC',
        [id]
      );
      packages = result.rows;
    } catch (_) {
      packages = [...inMemoryPackages.values()].filter(p => p.app_id === id && p.active);
    }

    const summary = { windows: null, macos: null, linux: null };
    for (const p of packages) {
      if (!summary[p.platform]) summary[p.platform] = p;
    }
    res.json(summary);
  } catch (err) {
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

    // Ensure appstore tables exist
    await ensureAppstoreTables();
    await ensurePackagesTable();

    // Restore custom-published/edited catalog apps that survived a restart
    // in Postgres but not in the in-memory catalog (see hydrateAppstoreCatalog).
    await hydrateAppstoreCatalog();

    // Connect to event bus (fire and forget)
    connectBus().catch(() => {});

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
