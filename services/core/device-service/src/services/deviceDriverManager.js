'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const DRIVERS_DIR = '/var/lib/opendirectory/device-drivers';
const CATALOG_FILE = path.join(DRIVERS_DIR, 'drivers.json');
const FILES_DIR = path.join(DRIVERS_DIR, 'files');

// Ensure storage directories exist on first use
async function ensureStorage() {
  await fs.promises.mkdir(FILES_DIR, { recursive: true });
}

async function readCatalog() {
  try {
    const data = await fs.promises.readFile(CATALOG_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') return { drivers: [] };
    throw err;
  }
}

async function writeCatalog(catalog) {
  // Write to a temp file and rename to avoid leaving a truncated/corrupt
  // drivers.json behind if the process crashes mid-write.
  const tmpFile = `${CATALOG_FILE}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(tmpFile, JSON.stringify(catalog, null, 2), 'utf8');
  await fs.promises.rename(tmpFile, CATALOG_FILE);
}

// Serialize all read-modify-write operations on the catalog file so
// concurrent addDriver/deleteDriver/deployDriver/updateDeploymentStatus
// calls can't clobber each other's changes (lost update).
let catalogQueue = Promise.resolve();
function withCatalogLock(task) {
  const run = catalogQueue.then(task, task);
  catalogQueue = run.then(() => {}, () => {});
  return run;
}

/**
 * List drivers with optional filters: { os, deviceType, vendor }
 */
async function listDrivers(filters = {}) {
  await ensureStorage();
  const catalog = await readCatalog();
  let drivers = catalog.drivers;

  if (filters.os) {
    drivers = drivers.filter(d =>
      Array.isArray(d.os) ? d.os.includes(filters.os) : d.os === filters.os
    );
  }
  if (filters.deviceType) {
    drivers = drivers.filter(d => d.deviceType === filters.deviceType);
  }
  if (filters.vendor) {
    drivers = drivers.filter(d =>
      (d.vendor || '').toLowerCase().includes(filters.vendor.toLowerCase())
    );
  }

  return drivers;
}

/**
 * Get a single driver by id, or null if not found
 */
async function getDriver(id) {
  await ensureStorage();
  const catalog = await readCatalog();
  return catalog.drivers.find(d => d.id === id) || null;
}

/**
 * Add a new driver. metadata must include all required fields plus
 * fileBuffer (Buffer) and filename to compute checksum and persist the file.
 *
 * Returns the created driver object.
 */
async function addDriver(metadata) {
  await ensureStorage();

  const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
  const { fileBuffer, filename, name, version, vendor, os, deviceType,
          format, architecture, description, tags } = metadata;

  // Persist file
  const destFilename = `${id}-${filename}`;
  const filePath = path.join(FILES_DIR, destFilename);
  await fs.promises.writeFile(filePath, fileBuffer);

  // Compute sha256 checksum
  const checksum = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  const driver = {
    id,
    name,
    version,
    vendor,
    os,
    deviceType,
    format,
    architecture,
    description: description || '',
    filename: destFilename,
    fileSize: fileBuffer.length,
    filePath,
    checksum,
    tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()) : []),
    deployments: [],
    uploadedAt: new Date().toISOString(),
  };

  await withCatalogLock(async () => {
    const catalog = await readCatalog();
    catalog.drivers.push(driver);
    await writeCatalog(catalog);
  });

  logger.info('Driver added', { id, name, version, vendor, os, format });
  return driver;
}

/**
 * Delete a driver by id and remove its file.
 * Returns true if deleted, false if not found.
 */
async function deleteDriver(id) {
  await ensureStorage();
  return withCatalogLock(async () => {
    const catalog = await readCatalog();
    const idx = catalog.drivers.findIndex(d => d.id === id);
    if (idx === -1) return false;

    const driver = catalog.drivers[idx];

    // Remove file
    try {
      await fs.promises.unlink(driver.filePath);
    } catch (err) {
      // Warn but continue — file may already be gone
      logger.warn('Driver file not found during delete', { id, filePath: driver.filePath });
    }

    catalog.drivers.splice(idx, 1);
    await writeCatalog(catalog);

    logger.info('Driver deleted', { id });
    return true;
  });
}

/**
 * Create deployment records for a driver → array of device IDs.
 * Returns the array of created deployment objects.
 */
async function deployDriver(driverId, deviceIds) {
  await ensureStorage();
  return withCatalogLock(async () => {
    const catalog = await readCatalog();
    const driver = catalog.drivers.find(d => d.id === driverId);
    if (!driver) throw new Error(`Driver ${driverId} not found`);

    const now = new Date().toISOString();
    const deployments = deviceIds.map(deviceId => ({
      id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
      driverId,
      deviceId,
      status: 'pending',
      deployedAt: now,
      updatedAt: now,
      error: null,
    }));

    driver.deployments.push(...deployments);
    await writeCatalog(catalog);

    logger.info('Driver deployed', { driverId, deviceCount: deviceIds.length });
    return deployments;
  });
}

/**
 * Get all deployment records for a driver.
 */
async function getDeployments(driverId) {
  const driver = await getDriver(driverId);
  if (!driver) throw new Error(`Driver ${driverId} not found`);
  return driver.deployments;
}

/**
 * Update status (and optionally error message) of a deployment.
 * Returns the updated deployment object, or null if not found.
 */
async function updateDeploymentStatus(deploymentId, status, error = null) {
  await ensureStorage();
  return withCatalogLock(async () => {
    const catalog = await readCatalog();

    for (const driver of catalog.drivers) {
      const deployment = driver.deployments.find(dep => dep.id === deploymentId);
      if (deployment) {
        deployment.status = status;
        deployment.error = error !== undefined ? error : deployment.error;
        deployment.updatedAt = new Date().toISOString();
        await writeCatalog(catalog);
        logger.info('Deployment status updated', { deploymentId, status });
        return deployment;
      }
    }

    return null;
  });
}

module.exports = {
  listDrivers,
  getDriver,
  addDriver,
  deleteDriver,
  deployDriver,
  getDeployments,
  updateDeploymentStatus,
};
