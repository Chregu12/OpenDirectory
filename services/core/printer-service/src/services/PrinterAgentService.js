const { EventEmitter } = require('events');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * PrinterAgentService - Generic server-side printer management via WebSocket push
 *
 * Architecture:
 *   Server (this) → device-service.sendToDevice() → WebSocket → Agent (platform-specific)
 *
 * All printer operations are pushed as commands to the connected agents.
 * Agents execute platform-specific logic (PowerShell/lpadmin/CUPS) and report results.
 * This service is platform-agnostic – it only knows about printer objects and command types.
 */
class PrinterAgentService extends EventEmitter {
  constructor(deviceService) {
    super();
    this.deviceService = deviceService;
    this.pendingCommands = new Map();  // commandId → { resolve, reject, timeout }
    this.deployedPrinters = new Map(); // deviceId → [{ printerId, printerName, ... }]
    this.commandTimeout = 120_000;     // 2 min
  }

  // ─── Generic command dispatch ──────────────────────────────────────────

  /**
   * Send a printer command to one device and optionally wait for result.
   * Returns immediately if no callback tracking needed.
   */
  sendPrinterCommand(deviceId, commandType, data, options = {}) {
    const commandId = `prt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const message = {
      type: 'command',
      id: commandId,
      command_type: commandType,
      data,
      category: 'printer'
    };

    const sent = this.deviceService.sendToDevice(deviceId, message);

    if (!sent && options.queueOffline !== false) {
      // Cache for offline delivery (device-service handles Redis queue)
      this.deviceService.cacheForOfflineDevice?.(deviceId, message);
      logger.info(`Printer command ${commandType} queued for offline device ${deviceId}`);
    }

    logger.info(`Printer command ${commandType} → device ${deviceId} (sent=${sent})`);
    this.emit('commandSent', { deviceId, commandType, commandId, sent });

    return { commandId, sent };
  }

  /**
   * Send a printer command to multiple devices.
   */
  sendPrinterCommandToDevices(deviceIds, commandType, data) {
    const results = [];
    for (const deviceId of deviceIds) {
      results.push({
        deviceId,
        ...this.sendPrinterCommand(deviceId, commandType, data)
      });
    }
    return results;
  }

  // ─── High-level printer operations (platform-agnostic) ─────────────────

  /**
   * Deploy printers to a device.
   * The agent handles platform-specific installation (PowerShell / lpadmin / CUPS).
   */
  deployPrinters(deviceId, printers, options = {}) {
    const data = {
      printers: printers.map(p => this.normalizePrinter(p)),
      setDefault: options.defaultPrinter || null,
      removeExisting: options.removeExisting || false,
      notifyUser: options.notifyUser !== false
    };

    const result = this.sendPrinterCommand(deviceId, 'deploy_printers', data);

    // Track deployed printers per device
    this.deployedPrinters.set(deviceId, data.printers);
    this.emit('printersDeployed', { deviceId, printers: data.printers, commandId: result.commandId });

    return result;
  }

  /**
   * Deploy printers to multiple devices (e.g. policy-based group deployment).
   */
  deployPrintersToDevices(deviceIds, printers, options = {}) {
    const results = [];
    for (const deviceId of deviceIds) {
      results.push({
        deviceId,
        ...this.deployPrinters(deviceId, printers, options)
      });
    }
    this.emit('bulkDeployment', { deviceIds, printerCount: printers.length, results });
    return results;
  }

  /**
   * Remove a printer from a device.
   */
  removePrinter(deviceId, printerName) {
    const result = this.sendPrinterCommand(deviceId, 'remove_printer', { printerName });
    this.emit('printerRemoved', { deviceId, printerName, commandId: result.commandId });
    return result;
  }

  /**
   * Remove printers from multiple devices.
   */
  removePrinterFromDevices(deviceIds, printerName) {
    return this.sendPrinterCommandToDevices(deviceIds, 'remove_printer', { printerName });
  }

  /**
   * Set the default printer on a device.
   */
  setDefaultPrinter(deviceId, printerName) {
    return this.sendPrinterCommand(deviceId, 'set_default_printer', { printerName });
  }

  /**
   * Request the list of installed printers from a device.
   */
  listDevicePrinters(deviceId) {
    return this.sendPrinterCommand(deviceId, 'list_printers', {});
  }

  /**
   * Request printer status / diagnostics from a device.
   */
  getPrinterStatus(deviceId, printerName) {
    return this.sendPrinterCommand(deviceId, 'get_printer_status', { printerName });
  }

  /**
   * Push printer configuration/settings update (e.g. duplex, color, paper size defaults).
   */
  updatePrinterSettings(deviceId, printerName, settings) {
    return this.sendPrinterCommand(deviceId, 'update_printer_settings', {
      printerName,
      settings
    });
  }

  /**
   * Deploy printer driver to a device (pre-stage before adding printer).
   */
  deployDriver(deviceId, driver) {
    return this.sendPrinterCommand(deviceId, 'deploy_driver', {
      driverName: driver.name,
      driverSource: driver.source,  // URL or UNC path
      platform: driver.platform
    });
  }

  /**
   * Pause or resume a printer on a device.
   */
  setPrinterPaused(deviceId, printerName, paused) {
    return this.sendPrinterCommand(deviceId, 'set_printer_paused', {
      printerName,
      paused
    });
  }

  /**
   * Cancel a specific print job on a device.
   */
  cancelPrintJob(deviceId, printerName, jobId) {
    return this.sendPrinterCommand(deviceId, 'cancel_print_job', {
      printerName,
      jobId
    });
  }

  /**
   * Clear all jobs from a printer queue on a device.
   */
  clearPrintQueue(deviceId, printerName) {
    return this.sendPrinterCommand(deviceId, 'clear_print_queue', { printerName });
  }

  /**
   * Run a test print on a device.
   */
  testPrint(deviceId, printerName) {
    return this.sendPrinterCommand(deviceId, 'test_print', { printerName });
  }

  // ─── Policy-based deployment ──────────────────────────────────────────

  /**
   * Apply a printer policy to a set of devices.
   * Policy format:
   *   { printers: [...], defaultPrinter: "name", removeUnmanaged: false }
   */
  applyPrinterPolicy(deviceIds, policy) {
    const results = [];

    for (const deviceId of deviceIds) {
      const data = {
        printers: (policy.printers || []).map(p => this.normalizePrinter(p)),
        setDefault: policy.defaultPrinter || null,
        removeUnmanaged: policy.removeUnmanaged || false,
        policyId: policy.id || null,
        notifyUser: policy.notifyUser !== false
      };

      results.push({
        deviceId,
        ...this.sendPrinterCommand(deviceId, 'apply_printer_policy', data)
      });
    }

    this.emit('policyApplied', { deviceIds, policyId: policy.id, printerCount: (policy.printers || []).length });
    return results;
  }

  // ─── Handle command results from agents ───────────────────────────────

  handleCommandResult(deviceId, result) {
    logger.info(`Printer command result from ${deviceId}: ${result.commandId} → ${result.status}`);

    this.emit('commandResult', {
      deviceId,
      commandId: result.commandId,
      status: result.status,
      output: result.output
    });

    // Update deployed printers state from agent feedback
    if (result.status === 'completed' && result.installedPrinters) {
      this.deployedPrinters.set(deviceId, result.installedPrinters);
    }
  }

  // ─── Helper: normalize printer object for agent consumption ───────────

  normalizePrinter(printer) {
    return {
      name: printer.name || printer.shareName,
      displayName: printer.displayName || printer.name,
      address: printer.address || printer.deviceIP,
      port: printer.port || printer.devicePort || null,
      protocol: (printer.protocol || 'ipp').toLowerCase(),
      driver: printer.driver || null,
      location: printer.location || '',
      description: printer.description || '',
      isDefault: printer.isDefault || false,
      color: printer.color || printer.capabilities?.color || false,
      duplex: printer.duplex || printer.capabilities?.duplex || false,
      paperSizes: printer.paperSizes || printer.capabilities?.paperSizes || ['A4'],
      shared: printer.shared !== false,
      // Server-side connection (when using OpenDirectory as print server)
      serverPath: printer.serverPath || null
    };
  }

  // ─── Status ───────────────────────────────────────────────────────────

  getDeploymentStatus() {
    const status = {};
    this.deployedPrinters.forEach((printers, deviceId) => {
      status[deviceId] = printers.map(p => ({ name: p.name, displayName: p.displayName }));
    });
    return status;
  }
}

module.exports = PrinterAgentService;
