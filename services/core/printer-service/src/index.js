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
const PrinterDeployment = require('./services/deployment');
const QuotaManager = require('./services/quota');
const PrintAnalytics = require('./services/analytics');

const app = express();
const server = createServer(app);
const wss = new WebSocket.Server({ server });

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

const discovery = new PrinterDiscoveryService();
const cups = new CUPSIntegration();
const printerManager = new PrinterManager(cups);
const printQueue = new PrintJobQueue();
const scanner = new ScannerService();
const permissions = new PermissionManager();
const deployment = new PrinterDeployment();
const quota = new QuotaManager();
const analytics = new PrintAnalytics();

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

// Printer discovery and management
app.post('/api/printers/discover', async (req, res) => {
  try {
    const { method = 'all', subnet, timeout = 30000 } = req.body;
    const printers = await discovery.discoverPrinters(method, subnet, timeout);
    res.json({ success: true, printers });
  } catch (error) {
    logger.error('Discovery error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/printers/add', async (req, res) => {
  try {
    const { 
      name, 
      address, 
      driver, 
      protocol = 'ipp',
      port,
      description,
      location,
      autoDetect = true
    } = req.body;
    
    const printer = await printerManager.addPrinter({
      name,
      address,
      driver,
      protocol,
      port,
      description,
      location,
      autoDetect
    });
    
    res.json({ success: true, printer });
  } catch (error) {
    logger.error('Add printer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/printers', async (req, res) => {
  try {
    const printers = await printerManager.listPrinters();
    res.json({ success: true, printers });
  } catch (error) {
    logger.error('List printers error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/printers/:id', async (req, res) => {
  try {
    const printer = await printerManager.getPrinter(req.params.id);
    res.json({ success: true, printer });
  } catch (error) {
    logger.error('Get printer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/printers/:id', async (req, res) => {
  try {
    const printer = await printerManager.updatePrinter(req.params.id, req.body);
    res.json({ success: true, printer });
  } catch (error) {
    logger.error('Update printer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/printers/:id', async (req, res) => {
  try {
    await printerManager.removePrinter(req.params.id);
    res.json({ success: true });
  } catch (error) {
    logger.error('Remove printer error:', error);
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
    
    // Process job asynchronously
    printQueue.processJob(job.id).then(result => {
      broadcastJobStatus(job.id, result.status);
    });
    
    res.json({ success: true, jobId: job.id });
  } catch (error) {
    logger.error('Print error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/jobs', async (req, res) => {
  try {
    const { userId, printerId, status } = req.query;
    const jobs = await printQueue.listJobs({ userId, printerId, status });
    res.json({ success: true, jobs });
  } catch (error) {
    logger.error('List jobs error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await printQueue.getJob(req.params.id);
    res.json({ success: true, job });
  } catch (error) {
    logger.error('Get job error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/jobs/:id', async (req, res) => {
  try {
    await printQueue.cancelJob(req.params.id);
    res.json({ success: true });
  } catch (error) {
    logger.error('Cancel job error:', error);
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

// Deployment endpoints
app.post('/api/deployment/generate', async (req, res) => {
  try {
    const { platform, printers, settings } = req.body;
    const config = await deployment.generateConfig(platform, printers, settings);
    res.json({ success: true, config });
  } catch (error) {
    logger.error('Generate config error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/deployment/deploy', async (req, res) => {
  try {
    const { targetDevices, printers, platform } = req.body;
    const result = await deployment.deployPrinters(targetDevices, printers, platform);
    res.json({ success: true, result });
  } catch (error) {
    logger.error('Deploy error:', error);
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
});

module.exports = app;