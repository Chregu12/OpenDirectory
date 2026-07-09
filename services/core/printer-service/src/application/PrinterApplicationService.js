'use strict';

const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

const printerProbe = require('../infrastructure/printerProbe');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'printer-service.log' }),
  ],
});

// ─── Error types used to select HTTP status codes in the thin route layer ────
class ValidationError extends Error {}
class NotFoundError extends Error {}

// ─── Frontend field-name mapping (moved verbatim from index.js) ──────────────
// Maps frontend field names (ip, model, isMultifunction, scanFormats) to the
// service's internal printer config shape, and back.
function mapFrontendPayload(body) {
  const { ip, ipAddress, name, model, protocol, driver, location, isMultifunction, scanFormats, description } = body;
  const address = ip || ipAddress || body.address;
  const proto = (protocol || 'IPP').toLowerCase();
  return {
    name:            name,
    displayName:     name,
    address,
    protocol:        proto,
    port:            proto === 'ipp' ? 631 : proto === 'lpd' ? 515 : 9100,
    driver:          driver || 'everywhere',
    model:           model || '',
    description:     description || model || '',
    location:        location || '',
    isMultifunction: !!isMultifunction,
    scanFormats:     scanFormats || [],
  };
}

function mapToFrontend(p) {
  return {
    id:              p.id,
    name:            p.display_name || p.name,
    ip:              p.address,
    model:           p.model || '',
    protocol:        (p.protocol || 'IPP').toUpperCase(),
    status:          p.status === 'idle' || p.status === 'online' ? 'online' : p.status === 'offline' ? 'offline' : 'online',
    queueDepth:      p.queue_depth || 0,
    location:        p.location || '',
    isMultifunction: p.is_multifunction || false,
    scanFormats:     p.scan_formats || [],
  };
}

/**
 * PrinterApplicationService
 *
 * Orchestrates the printer CRUD, deployment and print-job-queue-read use
 * cases that used to be defined inline in src/index.js. Routes
 * (routes/printerRoutes.js) call only this service.
 *
 * Persistence: `printerManager` (services/printerManager.js) already
 * implements the IPrinterRepository contract (domain/IPrinterRepository.js)
 * backed by PostgreSQL + CUPS side effects; it is injected here unmodified
 * rather than rewritten, since its monitoring/event-emitter behavior is out
 * of scope for this refactor.
 *
 * `deployment` (PrinterDeployment) and the network probe are pure,
 * stateless protocol/config wrappers and are injected as-is.
 *
 * `printQueue` is used here only for the read/cancel side of the job queue
 * (GET /api/jobs, GET /api/jobs/:id, DELETE /api/jobs/:id). Submitting a new
 * print job (POST /api/print) stays in index.js because it is cross-cut with
 * the permissions/quota slices, which are out of scope for this refactor.
 */
class PrinterApplicationService {
  /**
   * @param {object} deps
   * @param {import('../domain/IPrinterRepository')} deps.printerManager
   * @param {object} deps.discovery - PrinterDiscoveryService
   * @param {object} deps.deployment - PrinterDeployment
   * @param {object} [deps.printQueue] - PrintJobQueue (read/cancel use cases only)
   */
  constructor({ printerManager, discovery, deployment, printQueue }) {
    this.printerManager = printerManager;
    this.discovery = discovery;
    this.deployment = deployment;
    this.printQueue = printQueue;

    // In-memory job log for the frontend test-print flow — survives only for
    // the process lifetime, exactly as it did as a module-level array in
    // index.js.
    this._jobLog = [];
  }

  _addJobLog(entry) {
    this._jobLog.unshift({ id: uuidv4(), submitted: new Date().toISOString(), ...entry });
    if (this._jobLog.length > 200) this._jobLog.length = 200; // cap at 200 entries
  }

  // ── Discovery ────────────────────────────────────────────────────────────

  async discoverPrinters(method = 'all', subnet, timeout = 30000) {
    return this.discovery.discoverPrinters(method, subnet, timeout);
  }

  // Quick IPP-only scan used by the frontend alias route — swallows errors
  // and returns an empty list rather than surfacing a 500, matching the
  // original index.js behavior.
  async discoverPrintersQuick(subnet) {
    try {
      return await this.discovery.discoverPrinters('ipp', subnet, 8000);
    } catch (_error) {
      return [];
    }
  }

  async probePrinter(ip) {
    return printerProbe.probe(ip);
  }

  // ── Printer CRUD ─────────────────────────────────────────────────────────

  async addPrinter(body) {
    const {
      name,
      address,
      driver,
      protocol = 'ipp',
      port,
      description,
      location,
      autoDetect = true,
    } = body;

    return this.printerManager.addPrinter({
      name, address, driver, protocol, port, description, location, autoDetect,
    });
  }

  async listPrinters() {
    return this.printerManager.listPrinters();
  }

  async getPrinter(id) {
    return this.printerManager.getPrinter(id);
  }

  async updatePrinter(id, updates) {
    return this.printerManager.updatePrinter(id, updates);
  }

  async removePrinter(id) {
    await this.printerManager.removePrinter(id);
  }

  // ── Frontend-compatible printer CRUD (used via /api/printer/* gateway) ────

  async addPrinterFrontend(body) {
    const config = mapFrontendPayload(body);
    if (!config.name)    throw new ValidationError('Printer name is required');
    if (!config.address) throw new ValidationError('IP address is required');
    const printer = await this.printerManager.addPrinter(config);
    return mapToFrontend(printer);
  }

  async listPrintersFrontend() {
    const printers = await this.printerManager.listPrinters();
    return printers.map(mapToFrontend);
  }

  async removePrinterFrontend(id) {
    await this.printerManager.removePrinter(id);
  }

  // ── Test print (IPP Print-Job) + job log ───────────────────────────────────

  async submitTestPrintJob({ printer_name, document_name = 'Test Page', user_name = 'admin', pages }) {
    if (!printer_name) throw new ValidationError('printer_name is required');

    const allPrinters = await this.printerManager.listPrinters();
    const printer = allPrinters.find(p =>
      p.name === printer_name || p.address === printer_name || p.id === printer_name
    );
    if (!printer) throw new NotFoundError(`Printer "${printer_name}" not found`);

    const ip = printer.address || printer.ip_address;
    if (!ip) throw new ValidationError('Printer has no IP address stored');

    try {
      // Build a PCL5 test page (supported by all HP printers)
      const ESC = '\x1B';
      const now = new Date().toLocaleString('de-CH');
      const lines = [
        '================================================',
        '   OpenDirectory  -  Test Page',
        '================================================',
        '',
        `  Printer  : ${printer.name}`,
        `  Address  : ${ip}`,
        `  Document : ${document_name}`,
        `  Sent by  : ${user_name}`,
        `  Time     : ${now}`,
        '',
        '------------------------------------------------',
        '  If you can read this, the printer',
        '  connection is working correctly.',
        '------------------------------------------------',
      ];
      let pcl = ESC + 'E';            // Reset printer
      pcl += ESC + '&l0O';            // Portrait
      pcl += ESC + '(0U';             // US ASCII symbol set
      pcl += ESC + '(s0p10h12v0s0b3T'; // Courier 12pt fixed
      pcl += ESC + '&a5R' + ESC + '&a5C'; // Start at row 5, col 5
      lines.forEach(line => { pcl += line + '\r\n'; });
      pcl += ESC + 'E';               // Reset + eject page
      const jobData = Buffer.from(pcl, 'latin1');

      // Send via IPP Print-Job request
      const ipp = require('ipp');
      const printerUrl = `http://${ip}:631/ipp/print`;
      const ippPrinter = ipp.Printer(printerUrl);

      const ippMsg = {
        'operation-attributes-tag': {
          'requesting-user-name': user_name,
          'job-name': document_name,
          'document-format': 'application/vnd.hp-PCL',
        },
        data: jobData,
      };

      await new Promise((resolve, reject) => {
        ippPrinter.execute('Print-Job', ippMsg, (err, response) => {
          if (err) return reject(err);
          const status = response?.statusCode || response?.['status-code'];
          if (status && !String(status).startsWith('successful')) {
            return reject(new Error(`IPP error: ${status}`));
          }
          resolve(response);
        });
      });

      this._addJobLog({
        printer: printer.name,
        documentName: document_name,
        user: user_name,
        pages: pages || 1,
        status: 'completed',
      });
      logger.info(`Test page sent to ${printer.name} (${ip}) by ${user_name}`);
      return { message: `Test page sent to ${printer.name}` };
    } catch (error) {
      this._addJobLog({
        printer: printer_name,
        documentName: document_name,
        user: user_name,
        pages: pages || 1,
        status: 'failed',
      });
      throw error;
    }
  }

  getJobLog(printerFilter) {
    return printerFilter
      ? this._jobLog.filter(j => j.printer === printerFilter)
      : this._jobLog;
  }

  // ── Deployment ────────────────────────────────────────────────────────────

  async generateDeploymentConfig(platform, printers, settings) {
    return this.deployment.generateConfig(platform, printers, settings);
  }

  async deployPrintersConfig(targetDevices, printers, platform) {
    return this.deployment.deployPrinters(targetDevices, printers, platform);
  }

  // ── Print job queue (read/cancel) ──────────────────────────────────────────

  async listJobs(filters) {
    return this.printQueue.listJobs(filters);
  }

  async getJob(id) {
    return this.printQueue.getJob(id);
  }

  async cancelJob(id) {
    await this.printQueue.cancelJob(id);
  }
}

// ─── Default instance wired with the real implementations ─────────────────────
// Useful for standalone consumers/tests that want the production wiring.
// Deliberately NOT constructed eagerly at module load (unlike the singleton
// export in DriverCatalogApplicationService): PrinterManager/PrintJobQueue
// open real PostgreSQL pools and PrintJobQueue's Bull queue connects to
// Redis immediately on construction, so building one just because this
// module was required (e.g. for its error-class exports) would open
// redundant, unwanted connections. Call createDefaultInstance() explicitly
// when the real wiring is actually needed.
//
// The running service (index.js) does not use this at all — it constructs
// its own PrinterApplicationService instance, injecting the manager
// instances it already owns (and shares with routes that were not moved
// into this slice) rather than duplicating them.
function createDefaultInstance() {
  const CUPSIntegration = require('../services/cups');
  const PrinterManager = require('../services/printerManager');
  const PrinterDiscoveryService = require('../services/discovery');
  const PrintJobQueue = require('../services/printQueue');
  let PrinterDeployment;
  try { PrinterDeployment = require('../services/deployment'); }
  catch (e) { PrinterDeployment = class { generateConfig() { return ''; } deployPrinters() { return []; } }; }

  const cups = new CUPSIntegration();

  return new PrinterApplicationService({
    printerManager: new PrinterManager(cups),
    discovery: new PrinterDiscoveryService(),
    deployment: new PrinterDeployment(),
    printQueue: new PrintJobQueue(),
  });
}

module.exports = PrinterApplicationService;
module.exports.PrinterApplicationService = PrinterApplicationService;
module.exports.createDefaultInstance = createDefaultInstance;
module.exports.ValidationError = ValidationError;
module.exports.NotFoundError = NotFoundError;
