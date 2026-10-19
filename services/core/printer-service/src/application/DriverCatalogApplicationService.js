'use strict';

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const winston = require('winston');

const FilePrinterDriverRepository = require('../infrastructure/FilePrinterDriverRepository');
const DriverCatalogManager = require('../services/driverCatalogManager');
const dellCatalog = require('../services/dellCatalogService');
const { downloadFile } = require('../infrastructure/httpDownload');

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

// ─── Storage paths for downloaded catalog/URL imports ─────────────────────────
const PRINTER_DRIVER_DIR = process.env.PRINTER_DRIVERS_DIR || '/var/lib/opendirectory/printer-drivers';
const DEVICE_DRIVER_DIR  = process.env.DEVICE_DRIVERS_DIR || '/var/lib/opendirectory/device-drivers';

// printerDriverManager (the repository) only stores a single OS value
// (linux|windows|macos|universal) and list()/get() filter on it with strict
// equality. Catalog/import records may carry an array of supported OSes
// (e.g. ['linux', 'macos']); collapse that to a single value that still
// makes sense for that filtering.
function normalizeOs(os) {
  if (Array.isArray(os)) {
    return os.length === 1 ? os[0] : 'universal';
  }
  return os || 'universal';
}

// Guess a safe file extension for a downloaded driver from a format hint or
// the URL itself.
function guessExtension(url, formatHint) {
  if (formatHint) {
    // Strip anything but alphanumerics so a crafted format value (e.g.
    // containing "/" or "..") can't be used to escape the storage dir.
    const clean = String(formatHint).replace(/^\./, '').replace(/[^a-z0-9]/gi, '');
    if (clean) return `.${clean}`;
  }
  const match = (url || '').match(/\.([a-z0-9]{1,8})(?:[?#]|$)/i);
  return match ? `.${match[1].toLowerCase()}` : '.bin';
}

/**
 * DriverCatalogApplicationService
 *
 * Orchestrates the printer-driver + driver-catalog use cases that used to be
 * scattered across driverRoutes.js/catalogRoutes.js (persistImportedDriver)
 * and driverCatalogManager.js (importFromCatalog/importFromUrl/downloadFile).
 * Routes call only this service; it composes the driver repository, the
 * catalog data provider (vendor catalog + OpenPrinting + Dell) and the raw
 * HTTP download helper.
 */
class DriverCatalogApplicationService {
  /**
   * @param {object} deps
   * @param {import('../domain/IPrinterDriverRepository')} deps.driverRepo
   * @param {import('../services/driverCatalogManager')} deps.catalogManager
   * @param {object} deps.dellCatalog - live Dell catalog service (search/getStats/refresh)
   */
  constructor({ driverRepo, catalogManager, dellCatalog }) {
    this.driverRepo = driverRepo;
    this.catalogManager = catalogManager;
    this.dellCatalog = dellCatalog;
  }

  // ── Driver CRUD passthrough (thin routes call these directly) ────────────────

  get FILES_DIR() {
    return this.driverRepo.FILES_DIR;
  }

  async ensureStorage() {
    return this.driverRepo.ensureStorage();
  }

  async listDrivers(filter) {
    return this.driverRepo.list(filter);
  }

  async getDriver(id) {
    return this.driverRepo.get(id);
  }

  async deleteDriver(id) {
    return this.driverRepo.remove(id);
  }

  async assignDriverToPrinter(driverId, printerId) {
    return this.driverRepo.assignToPrinter(driverId, printerId);
  }

  async unassignDriverFromPrinter(driverId, printerId) {
    return this.driverRepo.unassignFromPrinter(driverId, printerId);
  }

  async getDriversForPrinter(printerId) {
    return this.driverRepo.getForPrinter(printerId);
  }

  // ── Manual upload (multer already wrote the file to tmpPath) ─────────────────

  /**
   * @param {string} tmpPath - path multer wrote the uploaded file to
   * @param {object} fileInfo - { originalname, size }
   * @param {object} metadata - { name, version, vendor, os, format, models } (models: comma-sep string)
   * @returns {Promise<object>} the created driver record
   */
  async uploadDriver(tmpPath, fileInfo, metadata = {}) {
    const originalname = fileInfo.originalname || 'driver.bin';
    const ext = path.extname(originalname).replace('.', '').toLowerCase();
    const { name, version, vendor, os, format, models } = metadata;

    const modelList = models
      ? models.split(',').map(m => m.trim()).filter(Boolean)
      : [];

    let driver;
    try {
      // Register the driver — metadata defaults are derived from the filename
      driver = await this.driverRepo.add({
        name: name || path.basename(originalname, path.extname(originalname)),
        version: version || '0.0.0',
        vendor: vendor || 'Unbekannt',
        os: os || 'universal',
        format: format || ext || 'bin',
        models: modelList,
        filename: originalname,
        fileSize: fileInfo.size,
      });

      // Rename temp upload to the canonical path computed by add()
      await fs.rename(tmpPath, driver.filePath);

      logger.info(`Driver uploaded: ${name} v${version} (id=${driver.id})`);
      return driver;
    } catch (err) {
      // Clean up tmp file on error
      if (tmpPath) await fs.unlink(tmpPath).catch(() => {});
      // If the catalog record was already persisted (add() succeeded) but
      // the rename above failed, don't leave a driver entry pointing at a
      // file that was never actually written.
      if (driver) await this.driverRepo.remove(driver.id).catch(() => {});
      throw err;
    }
  }

  // ── Catalog search / vendors ──────────────────────────────────────────────────

  async searchCatalog(q, filters) {
    return this.catalogManager.searchCatalog(q, filters);
  }

  async searchOpenPrinting(q) {
    return this.catalogManager.searchOpenPrinting(q);
  }

  async getVendors() {
    return this.catalogManager.getVendors();
  }

  // ── Dell live catalog ──────────────────────────────────────────────────────────

  async searchDell(q, filters, limit) {
    const results = await this.dellCatalog.search(q, filters);
    return { count: results.length, results: results.slice(0, limit) };
  }

  async getDellStats() {
    return this.dellCatalog.getStats();
  }

  async refreshDell() {
    return this.dellCatalog.refresh();
  }

  // ── Import from catalog entry / arbitrary URL (download + persist) ───────────

  /**
   * Download a catalog entry's driver file and register it with the driver
   * repository. Rolls back (removes the downloaded file, and the repo
   * record if it was already created) if any step fails.
   * @param {object} entry - a CatalogEntry, e.g. from searchCatalog()
   * @returns {Promise<object>} the created driver record
   */
  async importCatalogEntry(entry) {
    if (!entry || !entry.id) throw new Error('Invalid catalog entry');
    if (!entry.downloadUrl) throw new Error('This entry has no download URL');

    const storageDir = entry.deviceType === 'printer' ? PRINTER_DRIVER_DIR : DEVICE_DRIVER_DIR;
    await fs.mkdir(storageDir, { recursive: true });

    const ext = guessExtension(entry.downloadUrl, entry.format);
    const safeId = entry.id.replace(/[^a-z0-9_-]/gi, '_');
    const safeVersion = String(entry.version || 'unknown').replace(/[^a-z0-9_.-]/gi, '_');
    const fileName = `${safeId}-${safeVersion}${ext}`;
    const destPath = path.join(storageDir, fileName);

    logger.info(`Downloading catalog entry "${entry.name}" → ${destPath}`);

    try {
      await downloadFile(entry.downloadUrl, destPath);
    } catch (err) {
      throw new Error(`Failed to download driver: ${err.message}`);
    }

    const stat = await fs.stat(destPath);
    const record = {
      id: entry.id,
      name: entry.name,
      version: entry.version || '',
      vendor: entry.vendor,
      os: entry.os,
      deviceType: entry.deviceType,
      format: entry.format,
      architecture: entry.architecture || 'universal',
      description: entry.description || '',
      downloadUrl: entry.downloadUrl,
      models: entry.models || [],
      tags: entry.tags || [],
      licenseType: entry.licenseType || 'freeware',
      localPath: destPath,
      fileSize: stat.size,
      importedAt: new Date().toISOString(),
    };

    logger.info(`Driver imported: ${entry.name} (${stat.size} bytes)`);
    return this._persistImportedDriver(record);
  }

  /**
   * Download an arbitrary URL and register it with the driver repository.
   * @param {string} url
   * @param {object} [metadata] - { name, version, vendor, os, deviceType, format, ... }
   * @returns {Promise<object>} the created driver record
   */
  async importFromUrl(url, metadata = {}) {
    if (!url) throw new Error('url is required');

    const storageDir = (metadata.deviceType === 'printer') ? PRINTER_DRIVER_DIR : DEVICE_DRIVER_DIR;
    await fs.mkdir(storageDir, { recursive: true });

    const ext = guessExtension(url, metadata.format);
    const hash = crypto.createHash('md5').update(url).digest('hex').slice(0, 8);
    const safeName = (metadata.name || 'driver').replace(/[^a-z0-9_-]/gi, '_');
    const fileName = `${safeName}-${hash}${ext}`;
    const destPath = path.join(storageDir, fileName);

    logger.info(`Downloading from URL "${url}" → ${destPath}`);

    try {
      await downloadFile(url, destPath);
    } catch (err) {
      throw new Error(`Failed to download from URL: ${err.message}`);
    }

    const stat = await fs.stat(destPath);
    const record = {
      id: `url-${hash}`,
      name: metadata.name || fileName,
      version: metadata.version || '',
      vendor: metadata.vendor || 'Unknown',
      os: metadata.os ? (Array.isArray(metadata.os) ? metadata.os : [metadata.os]) : [],
      deviceType: metadata.deviceType || 'generic',
      format: metadata.format || ext.replace('.', ''),
      architecture: metadata.architecture || 'universal',
      description: metadata.description || `Imported from ${url}`,
      downloadUrl: url,
      models: metadata.models || [],
      tags: metadata.tags || [],
      licenseType: metadata.licenseType || 'freeware',
      localPath: destPath,
      fileSize: stat.size,
      importedAt: new Date().toISOString(),
    };

    logger.info(`Driver imported from URL: ${url} (${stat.size} bytes)`);
    return this._persistImportedDriver(record);
  }

  // ── Private: register an already-downloaded record with the driver repo ──────
  // Without this, importCatalogEntry()/importFromUrl() would only produce an
  // in-memory record and the driver would never show up in GET /drivers.

  async _persistImportedDriver(record) {
    let driver;
    try {
      driver = await this.driverRepo.add({
        name: record.name,
        version: record.version || '0.0.0',
        vendor: record.vendor || 'Unbekannt',
        os: normalizeOs(record.os),
        format: record.format || 'bin',
        models: record.models || [],
        filename: path.basename(record.localPath),
        fileSize: record.fileSize,
      });

      try {
        await fs.rename(record.localPath, driver.filePath);
      } catch (err) {
        if (err.code === 'EXDEV') {
          await fs.copyFile(record.localPath, driver.filePath);
          await fs.unlink(record.localPath);
        } else {
          throw err;
        }
      }

      return driver;
    } catch (err) {
      if (record.localPath) await fs.unlink(record.localPath).catch(() => {});
      if (driver) await this.driverRepo.remove(driver.id).catch(() => {});
      throw err;
    }
  }
}

// ─── Default instance wired with the real implementations ─────────────────────
const defaultDriverRepo = new FilePrinterDriverRepository();
const defaultCatalogManager = new DriverCatalogManager();

const instance = new DriverCatalogApplicationService({
  driverRepo: defaultDriverRepo,
  catalogManager: defaultCatalogManager,
  dellCatalog,
});

module.exports = instance;
module.exports.DriverCatalogApplicationService = DriverCatalogApplicationService;
