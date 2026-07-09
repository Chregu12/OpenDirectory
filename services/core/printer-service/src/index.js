const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const { createServer } = require('http');
const WebSocket = require('ws');
const winston = require('winston');

const PrinterDiscoveryService = require('./services/discovery');
const CUPSIntegration = require('./services/cups');
const PrinterManager = require('./services/printerManager');
const PrintJobQueue = require('./services/printQueue');
const ScannerService = require('./services/scanner');
const PermissionManager = require('./services/permissions');
let PrinterDeployment; try { PrinterDeployment = require('./services/deployment'); } catch (e) { PrinterDeployment = class { generateConfig() { return ''; } deployPrinters() { return []; } }; }
const PrinterAgentService = require('./services/PrinterAgentService');
const QuotaManager = require('./services/quota');
const PrintAnalytics = require('./services/analytics');
const ScanDestinationManager = require('./services/scanDestinationManager');
const PrintPoolManager = require('./services/printPool');
const driverRoutes = require('./routes/driverRoutes');

const catalogRoutes = require('./routes/catalogRoutes');
const PrinterApplicationService = require('./application/PrinterApplicationService');
const createPrinterRoutes = require('./routes/printerRoutes');
const { oidcAuth } = require('./middleware/oidcAuth');

const app = express();
const server = createServer(app);
const wss = new WebSocket.Server({ server });

// ─── RabbitMQ Event Bus ───────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'printer-service' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'printer-service.log' })
  ]
});

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '50mb' }));

// OIDC token verification (RS256 via JWKS). /health is unauthenticated so
// orchestrators/load balancers can probe liveness; /metrics is skipped for
// future-proofing (no /metrics route currently exists on this service).
// Everything else — including the driver-catalog search endpoints used by
// the frontend's DriverCatalogBrowser (/api/printer/catalog/search,
// /vendors, /openprinting, /dell) — requires a valid bearer token.
app.use(oidcAuth({ skipPaths: ['/health', '/metrics'] }));

const discovery = new PrinterDiscoveryService();
const cups = new CUPSIntegration();
const printerManager = new PrinterManager(cups);
const printQueue = new PrintJobQueue();
const scanner = new ScannerService();
const permissions = new PermissionManager();
const deployment = new PrinterDeployment();
const quota = new QuotaManager();
const analytics = new PrintAnalytics();

// PrinterApplicationService — printer CRUD, deployment and print-job-queue
// (read/cancel) use cases, layered behind routes/printerRoutes.js. Built
// from the manager instances above rather than its own, since printerManager
// and printQueue are also used directly by routes that stay inline below
// (permissions, quota, scanner, print-pool, agent, and POST /api/print,
// which is cross-cut with permissions/quota).
const printerAppService = new PrinterApplicationService({ printerManager, discovery, deployment, printQueue });

// ─── PostgreSQL Pool ─────────────────────────────────────────────────────────
const { Pool } = require('pg');
const db = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/printers',
});

// ─── Scan Destination Manager ────────────────────────────────────────────────
const scanDestMgr = new ScanDestinationManager({ db });
scanDestMgr.initDatabase().catch(err => logger.warn('scan_destinations init:', err.message));
scanner.setDestinationManager(scanDestMgr);

// ─── Print Pool Manager ──────────────────────────────────────────────────────
const printPoolMgr = new PrintPoolManager({ db, cupsService: cups, printerManager });
printPoolMgr.initDatabase().catch(err => logger.warn('print_pools init:', err.message));

// PrinterAgentService – generic server-push printer management via device-service WebSocket
// deviceService is injected when available (passed via environment or inter-service communication)
const printerAgent = new PrinterAgentService(null); // deviceService injected at runtime

// Allow external injection of deviceService reference
app.set('printerAgent', printerAgent);
app.injectDeviceService = (deviceService) => {
  printerAgent.deviceService = deviceService;
  logger.info('PrinterAgentService: deviceService injected');
};

// WebSocket connections for real-time updates
wss.on('connection', (ws) => {
  logger.info('New WebSocket connection');
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      switch (data.type) {
        case 'subscribe_printer_status':
          ws.printerSubscriptions = data.printers;
          break;
        case 'subscribe_job_status':
          ws.jobSubscriptions = data.jobs;
          break;
      }
    } catch (error) {
      logger.error('WebSocket message error:', error);
    }
  });
});

// Broadcast printer status updates
function broadcastPrinterStatus(printerId, status) {
  if (status === 'offline') {
    publish('printer.offline', { printerId });
  }
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN &&
        client.printerSubscriptions?.includes(printerId)) {
      client.send(JSON.stringify({
        type: 'printer_status',
        printerId,
        status
      }));
    }
  });
}

// Broadcast job status updates
function broadcastJobStatus(jobId, status) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && 
        client.jobSubscriptions?.includes(jobId)) {
      client.send(JSON.stringify({
        type: 'job_status',
        jobId,
        status
      }));
    }
  });
}

// API Routes

// Printer CRUD, deployment, probe, frontend-compatible printer routes and
// print-job-queue (read/cancel) — layered behind PrinterApplicationService.
// See routes/printerRoutes.js for the extracted route definitions.
app.use(createPrinterRoutes(printerAppService));

// POST /api/printer/test-scan — verify scanner reachability via eSCL
app.post('/api/printer/test-scan', async (req, res) => {
  try {
    const { ip, name } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip is required' });

    // Fetch eSCL capabilities (port 80 preferred, fallback 8080)
    const fetchEscl = (port) => new Promise((resolve, reject) => {
      const http = require('http');
      const req2 = http.get(
        { host: ip, port, path: '/eSCL/ScannerCapabilities', timeout: 4000 },
        (r) => {
          if (r.statusCode !== 200) return reject(new Error(`HTTP ${r.statusCode}`));
          let data = '';
          r.on('data', d => data += d);
          r.on('end', () => resolve(data));
        }
      );
      req2.on('error', reject);
      req2.on('timeout', () => { req2.destroy(); reject(new Error('timeout')); });
    });

    let xml = null;
    for (const port of [80, 8080]) {
      try { xml = await fetchEscl(port); break; } catch (_) {}
    }
    if (!xml) return res.status(503).json({ error: 'Scanner eSCL not reachable' });

    // Parse key fields from XML (no xml parser needed — simple regex)
    const get = (tag) => (xml.match(new RegExp(tag + '>([^<]+)<'))||[])[1]?.trim() || null;
    const getAll = (tag) => [...xml.matchAll(new RegExp(tag + '>([^<]+)<', 'g'))]
      .map(m => m[1].trim()).filter(Boolean);

    const capabilities = {
      makeAndModel: get('MakeAndModel'),
      manufacturer: get('Manufacturer'),
      serialNumber: get('SerialNumber'),
      colorModes:   [...new Set(getAll('ColorMode'))],
      formats:      [...new Set(getAll('DocumentFormat'))],
      maxWidthPx:   get('MaxWidth'),
      maxHeightPx:  get('MaxHeight'),
    };

    logger.info(`Test scan OK: ${name || ip} — ${capabilities.makeAndModel}`);
    res.json({ success: true, ip, capabilities });
  } catch (error) {
    logger.error('Test scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/printer/scanners — return printers that have eSCL scan capability
app.get('/api/printer/scanners', async (req, res) => {
  try {
    const allPrinters = await printerManager.listPrinters();
    if (allPrinters.length === 0) return res.json({ data: [] });

    const http = require('http');
    const checkEscl = (ip) => new Promise(resolve => {
      const req2 = http.get(
        { host: ip, port: 80, path: '/eSCL/ScannerCapabilities', timeout: 2000 },
        r => { resolve(r.statusCode === 200); r.resume(); }
      );
      req2.on('error', () => resolve(false));
      req2.on('timeout', () => { req2.destroy(); resolve(false); });
    });

    const results = await Promise.all(
      allPrinters.map(async p => {
        const ip = p.address || p.ip_address || p.ip;
        if (!ip) return null;
        const esclOnline = await checkEscl(ip);
        const hasEscl = p.isMultifunction || p.is_multifunction || esclOnline;
        if (!hasEscl) return null;
        return {
          id:      p.id,
          name:    p.name,
          ip,
          model:   p.model,
          status:  esclOnline ? 'online' : 'offline',
          formats: p.scanFormats?.length ? p.scanFormats
                 : p.scan_formats?.length ? p.scan_formats
                 : ['PDF', 'JPEG'],
        };
      })
    );

    res.json({ data: results.filter(Boolean) });
  } catch (error) {
    logger.error('List scanners (frontend) error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Printer permissions and access control
app.post('/api/printers/:id/permissions', async (req, res) => {
  try {
    const { users, groups, departments, allowAll = false } = req.body;
    
    await permissions.setPrinterPermissions(req.params.id, {
      users,
      groups,
      departments,
      allowAll
    });
    
    res.json({ success: true });
  } catch (error) {
    logger.error('Set permissions error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/printers/:id/permissions', async (req, res) => {
  try {
    const perms = await permissions.getPrinterPermissions(req.params.id);
    res.json({ success: true, permissions: perms });
  } catch (error) {
    logger.error('Get permissions error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/printers/check-access', async (req, res) => {
  try {
    const { printerId, userId } = req.body;
    const hasAccess = await permissions.checkAccess(printerId, userId);
    res.json({ success: true, hasAccess });
  } catch (error) {
    logger.error('Check access error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Print job management
app.post('/api/print', async (req, res) => {
  try {
    const {
      printerId,
      userId,
      document,
      documentType,
      options = {},
      priority = 50
    } = req.body;
    
    // Check permissions
    const hasAccess = await permissions.checkAccess(printerId, userId);
    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied to printer' });
    }
    
    // Check quota
    const quotaOk = await quota.checkQuota(userId, printerId);
    if (!quotaOk) {
      return res.status(403).json({ error: 'Print quota exceeded' });
    }
    
    // Add to print queue
    const job = await printQueue.addJob({
      printerId,
      userId,
      document,
      documentType,
      options,
      priority
    });
    
    publish('printer.job.created', { jobId: job.id, printerId, userId });

    // Process job asynchronously
    printQueue.processJob(job.id).then(result => {
      broadcastJobStatus(job.id, result.status);
      publish('printer.job.completed', { jobId: job.id, printerId });
    });

    res.json({ success: true, jobId: job.id });
  } catch (error) {
    logger.error('Print error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Scanner functionality
app.get('/api/scanners', async (req, res) => {
  try {
    const scanners = await scanner.listScanners();
    res.json({ success: true, scanners });
  } catch (error) {
    logger.error('List scanners error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/scan', async (req, res) => {
  try {
    const {
      scannerId,
      userId,
      format = 'pdf',
      resolution = 300,
      color = true,
      duplex = false,
      destination
    } = req.body;
    
    const scanJob = await scanner.scan({
      scannerId,
      userId,
      format,
      resolution,
      color,
      duplex,
      destination
    });
    
    res.json({ success: true, scanJob });
  } catch (error) {
    logger.error('Scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ─── Scan Destination Routes ─────────────────────────────────────────────────

// GET /api/scan-destinations — list all (admin)
app.get('/api/scan-destinations', async (req, res) => {
  try {
    const destinations = await scanDestMgr.listAll();
    res.json({ success: true, destinations });
  } catch (error) {
    logger.error('List scan destinations error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/scan-destinations/user/:userId
app.get('/api/scan-destinations/user/:userId', async (req, res) => {
  try {
    const destination = await scanDestMgr.getUserDestination(req.params.userId);
    if (!destination) return res.status(404).json({ error: 'No destination configured for this user' });
    res.json({ success: true, destination });
  } catch (error) {
    logger.error('Get user scan destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/scan-destinations/user/:userId
app.put('/api/scan-destinations/user/:userId', async (req, res) => {
  try {
    const destination = await scanDestMgr.setUserDestination(req.params.userId, req.body);
    res.json({ success: true, destination });
  } catch (error) {
    logger.error('Set user scan destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/scan-destinations/user/:userId
app.delete('/api/scan-destinations/user/:userId', async (req, res) => {
  try {
    const deleted = await scanDestMgr.deleteDestination('user', req.params.userId);
    if (!deleted) return res.status(404).json({ error: 'Destination not found' });
    res.json({ success: true });
  } catch (error) {
    logger.error('Delete user scan destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/scan-destinations/group/:groupId
app.get('/api/scan-destinations/group/:groupId', async (req, res) => {
  try {
    const destination = await scanDestMgr.getGroupDestination(req.params.groupId);
    if (!destination) return res.status(404).json({ error: 'No destination configured for this group' });
    res.json({ success: true, destination });
  } catch (error) {
    logger.error('Get group scan destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/scan-destinations/group/:groupId
app.put('/api/scan-destinations/group/:groupId', async (req, res) => {
  try {
    const destination = await scanDestMgr.setGroupDestination(req.params.groupId, req.body);
    res.json({ success: true, destination });
  } catch (error) {
    logger.error('Set group scan destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/scan-destinations/group/:groupId
app.delete('/api/scan-destinations/group/:groupId', async (req, res) => {
  try {
    const deleted = await scanDestMgr.deleteDestination('group', req.params.groupId);
    if (!deleted) return res.status(404).json({ error: 'Destination not found' });
    res.json({ success: true });
  } catch (error) {
    logger.error('Delete group scan destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/scan/with-destination — scan + auto-resolve destination for user
app.post('/api/scan/with-destination', async (req, res) => {
  try {
    const {
      scannerId,
      userId,
      userGroups = [],
      format = 'pdf',
      resolution = 300,
      color = true,
      duplex = false,
      ocr = false,
    } = req.body;

    const scanJob = await scanner.scan({
      scannerId,
      userId,
      userGroups,
      format,
      resolution,
      color,
      duplex,
      ocr,
    });

    res.json({ success: true, scanJob });
  } catch (error) {
    logger.error('Scan with destination error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ─── Print Pool Routes ───────────────────────────────────────────────────────

// GET /api/print-pools — list all pools
app.get('/api/print-pools', async (req, res) => {
  try {
    const pools = await printPoolMgr.listPools();
    res.json({ success: true, pools });
  } catch (error) {
    logger.error('List print pools error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/print-pools — create pool
app.post('/api/print-pools', async (req, res) => {
  try {
    const { name, displayName, algorithm, description, cupsQueueName } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const pool = await printPoolMgr.createPool({ name, displayName, algorithm, description, cupsQueueName });
    res.status(201).json({ success: true, pool });
  } catch (error) {
    logger.error('Create print pool error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/print-pools/:poolId — get pool with members
app.get('/api/print-pools/:poolId', async (req, res) => {
  try {
    const pool = await printPoolMgr.getPool(req.params.poolId);
    if (!pool) return res.status(404).json({ error: 'Pool not found' });
    res.json({ success: true, pool });
  } catch (error) {
    logger.error('Get print pool error:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/print-pools/:poolId — delete pool
app.delete('/api/print-pools/:poolId', async (req, res) => {
  try {
    const deleted = await printPoolMgr.deletePool(req.params.poolId);
    if (!deleted) return res.status(404).json({ error: 'Pool not found' });
    res.json({ success: true });
  } catch (error) {
    logger.error('Delete print pool error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/print-pools/:poolId/members — add member
app.post('/api/print-pools/:poolId/members', async (req, res) => {
  try {
    const { printerId, printerName, printerUri, weight, priority } = req.body;
    if (!printerId) return res.status(400).json({ error: 'printerId is required' });
    const member = await printPoolMgr.addMember(req.params.poolId, { printerId, printerName, printerUri, weight, priority });
    res.status(201).json({ success: true, member });
  } catch (error) {
    logger.error('Add pool member error:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/print-pools/:poolId/members/:printerId — remove member
app.delete('/api/print-pools/:poolId/members/:printerId', async (req, res) => {
  try {
    const removed = await printPoolMgr.removeMember(req.params.poolId, req.params.printerId);
    if (!removed) return res.status(404).json({ error: 'Member not found' });
    res.json({ success: true });
  } catch (error) {
    logger.error('Remove pool member error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/print-pools/:poolId/test-route — dry run routing (no job increment)
app.post('/api/print-pools/:poolId/test-route', async (req, res) => {
  try {
    const member = await printPoolMgr.selectPrinter(req.params.poolId);
    if (!member) return res.status(404).json({ error: 'No active members in pool' });
    res.json({ success: true, selectedMember: member });
  } catch (error) {
    logger.error('Test route error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Quota management
app.get('/api/quota/:userId', async (req, res) => {
  try {
    const userQuota = await quota.getUserQuota(req.params.userId);
    res.json({ success: true, quota: userQuota });
  } catch (error) {
    logger.error('Get quota error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/quota/:userId', async (req, res) => {
  try {
    const { daily, monthly, pageTypes } = req.body;
    await quota.setUserQuota(req.params.userId, { daily, monthly, pageTypes });
    res.json({ success: true });
  } catch (error) {
    logger.error('Set quota error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Analytics
app.get('/api/analytics/usage', async (req, res) => {
  try {
    const { startDate, endDate, groupBy = 'day' } = req.query;
    const usage = await analytics.getUsageStats(startDate, endDate, groupBy);
    res.json({ success: true, usage });
  } catch (error) {
    logger.error('Get usage error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/costs', async (req, res) => {
  try {
    const { startDate, endDate, department } = req.query;
    const costs = await analytics.getCosts(startDate, endDate, department);
    res.json({ success: true, costs });
  } catch (error) {
    logger.error('Get costs error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Agent-based printer management (server-push via WebSocket)
// Generic endpoints – platform-specific logic runs on the agents
// ═══════════════════════════════════════════════════════════════════════════

// Deploy printers to devices (push command to agents)
app.post('/api/agent/deploy', async (req, res) => {
  try {
    const { deviceIds, printers, options = {} } = req.body;
    if (!deviceIds?.length || !printers?.length) {
      return res.status(400).json({ error: 'deviceIds and printers are required' });
    }
    const results = printerAgent.deployPrintersToDevices(deviceIds, printers, options);
    res.json({ success: true, results });
  } catch (error) {
    logger.error('Agent deploy error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Remove printer from devices
app.post('/api/agent/remove', async (req, res) => {
  try {
    const { deviceIds, printerName } = req.body;
    if (!deviceIds?.length || !printerName) {
      return res.status(400).json({ error: 'deviceIds and printerName are required' });
    }
    const results = printerAgent.removePrinterFromDevices(deviceIds, printerName);
    res.json({ success: true, results });
  } catch (error) {
    logger.error('Agent remove error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Set default printer on a device
app.post('/api/agent/set-default', async (req, res) => {
  try {
    const { deviceId, printerName } = req.body;
    if (!deviceId || !printerName) {
      return res.status(400).json({ error: 'deviceId and printerName are required' });
    }
    const result = printerAgent.setDefaultPrinter(deviceId, printerName);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent set-default error:', error);
    res.status(500).json({ error: error.message });
  }
});

// List installed printers on a device
app.post('/api/agent/list', async (req, res) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId is required' });
    }
    const result = printerAgent.listDevicePrinters(deviceId);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent list error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get printer status from a device
app.post('/api/agent/status', async (req, res) => {
  try {
    const { deviceId, printerName } = req.body;
    const result = printerAgent.getPrinterStatus(deviceId, printerName);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update printer settings on a device
app.post('/api/agent/update-settings', async (req, res) => {
  try {
    const { deviceId, printerName, settings } = req.body;
    const result = printerAgent.updatePrinterSettings(deviceId, printerName, settings);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent update-settings error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Apply printer policy to devices (policy-based deployment)
app.post('/api/agent/apply-policy', async (req, res) => {
  try {
    const { deviceIds, policy } = req.body;
    if (!deviceIds?.length || !policy) {
      return res.status(400).json({ error: 'deviceIds and policy are required' });
    }
    const results = printerAgent.applyPrinterPolicy(deviceIds, policy);
    res.json({ success: true, results });
  } catch (error) {
    logger.error('Agent apply-policy error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Pause/resume printer on a device
app.post('/api/agent/set-paused', async (req, res) => {
  try {
    const { deviceId, printerName, paused } = req.body;
    const result = printerAgent.setPrinterPaused(deviceId, printerName, paused);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent set-paused error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Cancel print job on a device
app.post('/api/agent/cancel-job', async (req, res) => {
  try {
    const { deviceId, printerName, jobId } = req.body;
    const result = printerAgent.cancelPrintJob(deviceId, printerName, jobId);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent cancel-job error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Clear all jobs from a printer queue on a device
app.post('/api/agent/clear-queue', async (req, res) => {
  try {
    const { deviceId, printerName } = req.body;
    const result = printerAgent.clearPrintQueue(deviceId, printerName);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent clear-queue error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Test print on a device
app.post('/api/agent/test-print', async (req, res) => {
  try {
    const { deviceId, printerName } = req.body;
    const result = printerAgent.testPrint(deviceId, printerName);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Agent test-print error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get deployment status overview
app.get('/api/agent/deployment-status', (req, res) => {
  try {
    const status = printerAgent.getDeploymentStatus();
    res.json({ success: true, deployments: status });
  } catch (error) {
    logger.error('Agent deployment-status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ── Printer Driver Management ─────────────────────────────────────────────────
app.use('/api/printer', driverRoutes);

// ── Driver Catalog (OpenPrinting + manufacturer catalog) ──────────────────────
app.use('/api/printer/catalog', catalogRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    service: 'printer-service',
    timestamp: new Date().toISOString()
  });
});

// Start server
const PORT = process.env.PORT || 3006;
server.listen(PORT, () => {
  logger.info(`Printer Service running on port ${PORT}`);

  // Start background services
  discovery.startAutoDiscovery();
  printerManager.startMonitoring();
  printQueue.startProcessor();
  quota.startQuotaReset();
  connectBus();
});

function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully`);
  discovery.stopAutoDiscovery?.();
  printerManager.stopMonitoring?.();
  printQueue.stopProcessor?.();
  server.close(() => { logger.info('Printer service stopped'); process.exit(0); });
  setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

module.exports = app;