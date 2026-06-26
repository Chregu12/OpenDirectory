'use strict';

const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');

const STORAGE_BASE = '/var/lib/opendirectory/printer-drivers';
const DRIVERS_JSON  = path.join(STORAGE_BASE, 'drivers.json');
const FILES_DIR     = path.join(STORAGE_BASE, 'files');

const VALID_OS      = new Set(['linux', 'windows', 'macos', 'universal']);
const VALID_FORMAT  = new Set(['ppd', 'inf', 'cab', 'pkg', 'zip']);

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

// Ensure storage directories exist (called lazily before first operation)
let _storageReady = false;
async function ensureStorage() {
  if (_storageReady) return;
  await fs.mkdir(FILES_DIR, { recursive: true });
  _storageReady = true;
}

// Read the drivers catalog from disk; return [] if not yet created
async function readCatalog() {
  try {
    const raw = await fs.readFile(DRIVERS_JSON, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

// Persist the drivers catalog to disk
async function writeCatalog(drivers) {
  await ensureStorage();
  await fs.writeFile(DRIVERS_JSON, JSON.stringify(drivers, null, 2), 'utf-8');
}

/**
 * List all drivers, optionally filtered by os and/or format.
 * @param {object} [filter]
 * @param {string} [filter.os]
 * @param {string} [filter.format]
 * @returns {Promise<object[]>}
 */
async function listDrivers(filter = {}) {
  await ensureStorage();
  let drivers = await readCatalog();

  if (filter.os)     drivers = drivers.filter(d => d.os === filter.os);
  if (filter.format) drivers = drivers.filter(d => d.format === filter.format);

  return drivers;
}

/**
 * Get a single driver by id, or null if not found.
 * @param {string} id
 * @returns {Promise<object|null>}
 */
async function getDriver(id) {
  await ensureStorage();
  const drivers = await readCatalog();
  return drivers.find(d => d.id === id) || null;
}

/**
 * Add a new driver record (does not store the file — caller moves the file first).
 * @param {object} params
 * @param {string} params.name
 * @param {string} params.version
 * @param {string} params.vendor
 * @param {string} params.os       - linux | windows | macos | universal
 * @param {string} params.format   - ppd | inf | cab | pkg | zip
 * @param {string[]} params.models - compatible printer model names
 * @param {string} params.filename - original filename
 * @param {number} params.fileSize - bytes
 * @returns {Promise<object>} created driver
 */
async function addDriver({ name, version, vendor, os, format, models = [], filename, fileSize }) {
  if (!VALID_OS.has(os))     throw new Error(`Invalid os value: ${os}`);
  if (!VALID_FORMAT.has(format)) throw new Error(`Invalid format value: ${format}`);

  await ensureStorage();
  const drivers = await readCatalog();

  const id = Date.now().toString(36);
  const safeFilename = `${id}-${path.basename(filename)}`;
  const filePath = path.join(FILES_DIR, safeFilename);

  const driver = {
    id,
    name,
    version,
    vendor,
    os,
    format,
    models: Array.isArray(models) ? models : [],
    filename: safeFilename,
    fileSize: fileSize || 0,
    filePath,
    assignedPrinters: [],
    uploadedAt: new Date().toISOString(),
  };

  drivers.push(driver);
  await writeCatalog(drivers);

  logger.info(`Driver added: ${name} v${version} (id=${id})`);
  return driver;
}

/**
 * Delete a driver record and its stored file.
 * @param {string} id
 * @returns {Promise<boolean>} true if deleted, false if not found
 */
async function deleteDriver(id) {
  await ensureStorage();
  const drivers = await readCatalog();
  const idx = drivers.findIndex(d => d.id === id);
  if (idx === -1) return false;

  const [removed] = drivers.splice(idx, 1);
  await writeCatalog(drivers);

  // Best-effort file removal
  try {
    if (removed.filePath) await fs.unlink(removed.filePath);
  } catch (err) {
    logger.warn(`Could not delete driver file ${removed.filePath}: ${err.message}`);
  }

  logger.info(`Driver deleted: id=${id}`);
  return true;
}

/**
 * Assign a driver to a printer (idempotent).
 * @param {string} driverId
 * @param {string} printerId
 * @returns {Promise<object>} updated driver
 */
async function assignDriverToPrinter(driverId, printerId) {
  await ensureStorage();
  const drivers = await readCatalog();
  const driver = drivers.find(d => d.id === driverId);
  if (!driver) throw new Error(`Driver not found: ${driverId}`);

  if (!driver.assignedPrinters.includes(printerId)) {
    driver.assignedPrinters.push(printerId);
    await writeCatalog(drivers);
    logger.info(`Driver ${driverId} assigned to printer ${printerId}`);
  }

  return driver;
}

/**
 * Remove the assignment of a driver from a printer.
 * @param {string} driverId
 * @param {string} printerId
 * @returns {Promise<object>} updated driver
 */
async function unassignDriverFromPrinter(driverId, printerId) {
  await ensureStorage();
  const drivers = await readCatalog();
  const driver = drivers.find(d => d.id === driverId);
  if (!driver) throw new Error(`Driver not found: ${driverId}`);

  driver.assignedPrinters = driver.assignedPrinters.filter(pid => pid !== printerId);
  await writeCatalog(drivers);
  logger.info(`Driver ${driverId} unassigned from printer ${printerId}`);

  return driver;
}

/**
 * Get all drivers assigned to a specific printer.
 * @param {string} printerId
 * @returns {Promise<object[]>}
 */
async function getDriversForPrinter(printerId) {
  await ensureStorage();
  const drivers = await readCatalog();
  return drivers.filter(d => d.assignedPrinters.includes(printerId));
}

module.exports = {
  ensureStorage,
  listDrivers,
  getDriver,
  addDriver,
  deleteDriver,
  assignDriverToPrinter,
  unassignDriverFromPrinter,
  getDriversForPrinter,
  FILES_DIR,
};
