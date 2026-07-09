'use strict';

const fs = require('fs');
const path = require('path');
const winston = require('winston');

const IDriverRepository = require('../../domain/repositories/IDriverRepository');
const DriverAggregate = require('../../domain/aggregates/DriverAggregate');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

/**
 * FileDriverRepository
 *
 * JSON-file backed implementation of IDriverRepository — this is the same
 * storage strategy previously implemented as a transaction script in
 * services/deviceDriverManager.js, now persisting DriverAggregate instances
 * (via toJSON/fromJSON) and serializing all read-modify-write operations
 * on the catalog file through a lock so concurrent requests can't clobber
 * each other's changes (lost update).
 */
class FileDriverRepository extends IDriverRepository {
  constructor(driversDir) {
    super();
    this._driversDir = driversDir || process.env.DEVICE_DRIVERS_DIR || '/var/lib/opendirectory/device-drivers';
    this._catalogFile = path.join(this._driversDir, 'drivers.json');
    this._filesDir = path.join(this._driversDir, 'files');
    // Serializes all read-modify-write operations on the catalog file.
    this._catalogQueue = Promise.resolve();
  }

  async _ensureStorage() {
    await fs.promises.mkdir(this._filesDir, { recursive: true });
  }

  async _readCatalog() {
    try {
      const data = await fs.promises.readFile(this._catalogFile, 'utf8');
      return JSON.parse(data);
    } catch (err) {
      if (err.code === 'ENOENT') return { drivers: [] };
      throw err;
    }
  }

  async _writeCatalog(catalog) {
    // Write to a temp file and rename to avoid leaving a truncated/corrupt
    // drivers.json behind if the process crashes mid-write.
    const tmpFile = `${this._catalogFile}.${process.pid}.${Date.now()}.tmp`;
    await fs.promises.writeFile(tmpFile, JSON.stringify(catalog, null, 2), 'utf8');
    await fs.promises.rename(tmpFile, this._catalogFile);
  }

  _withCatalogLock(task) {
    const run = this._catalogQueue.then(task, task);
    this._catalogQueue = run.then(() => {}, () => {});
    return run;
  }

  // ── IDriverRepository ──────────────────────────────────────────────────────

  async saveFile(driverId, filename, fileBuffer) {
    await this._ensureStorage();
    const destFilename = `${driverId}-${filename}`;
    const filePath = path.join(this._filesDir, destFilename);
    await fs.promises.writeFile(filePath, fileBuffer);
    return { filePath, destFilename };
  }

  async findById(driverId) {
    await this._ensureStorage();
    const catalog = await this._readCatalog();
    const raw = catalog.drivers.find(d => d.id === driverId);
    return raw ? DriverAggregate.fromJSON(raw) : null;
  }

  async findAll(filters = {}) {
    await this._ensureStorage();
    const catalog = await this._readCatalog();
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

    return drivers.map(d => DriverAggregate.fromJSON(d));
  }

  async exists(driverId) {
    const driver = await this.findById(driverId);
    return driver !== null;
  }

  async save(driverAggregate) {
    await this._ensureStorage();
    await this._withCatalogLock(async () => {
      const catalog = await this._readCatalog();
      const idx = catalog.drivers.findIndex(d => d.id === driverAggregate.id);
      const json = driverAggregate.toJSON();
      if (idx === -1) catalog.drivers.push(json);
      else catalog.drivers[idx] = json;
      await this._writeCatalog(catalog);
    });
    logger.info('Driver saved', { id: driverAggregate.id, name: driverAggregate.name });
    return driverAggregate;
  }

  async delete(driverId) {
    await this._ensureStorage();
    return this._withCatalogLock(async () => {
      const catalog = await this._readCatalog();
      const idx = catalog.drivers.findIndex(d => d.id === driverId);
      if (idx === -1) return false;

      const driver = catalog.drivers[idx];
      try {
        await fs.promises.unlink(driver.filePath);
      } catch (err) {
        // Warn but continue — file may already be gone
        logger.warn('Driver file not found during delete', { id: driverId, filePath: driver.filePath });
      }

      catalog.drivers.splice(idx, 1);
      await this._writeCatalog(catalog);
      logger.info('Driver deleted', { id: driverId });
      return true;
    });
  }

  // ── atomic deployment operations (must read-mutate-write within one lock
  //    scope to avoid lost updates between concurrent deploy/status calls) ────

  /**
   * Adds one deployment per deviceId to the driver's aggregate and persists
   * the result atomically. Returns { deployments, events }.
   */
  async addDeployments(driverId, deviceIds) {
    await this._ensureStorage();
    return this._withCatalogLock(async () => {
      const catalog = await this._readCatalog();
      const idx = catalog.drivers.findIndex(d => d.id === driverId);
      if (idx === -1) throw new Error(`Driver ${driverId} not found`);

      const aggregate = DriverAggregate.fromJSON(catalog.drivers[idx]);
      const deployments = deviceIds.map(deviceId => aggregate.addDeployment(deviceId));
      catalog.drivers[idx] = aggregate.toJSON();
      await this._writeCatalog(catalog);

      logger.info('Driver deployed', { driverId, deviceCount: deviceIds.length });
      return { deployments, events: aggregate.getAndClearDomainEvents() };
    });
  }

  /**
   * Updates a deployment's status wherever it lives in the catalog, atomically.
   * Returns the updated deployment, or null if the deployment id is unknown.
   */
  async updateDeploymentStatus(deploymentId, status, error) {
    await this._ensureStorage();
    return this._withCatalogLock(async () => {
      const catalog = await this._readCatalog();

      for (let i = 0; i < catalog.drivers.length; i++) {
        const raw = catalog.drivers[i];
        if (!Array.isArray(raw.deployments) || !raw.deployments.some(d => d.id === deploymentId)) continue;

        const aggregate = DriverAggregate.fromJSON(raw);
        const updated = aggregate.updateDeploymentStatus(deploymentId, status, error);
        if (!updated) return null;

        catalog.drivers[i] = aggregate.toJSON();
        await this._writeCatalog(catalog);
        logger.info('Deployment status updated', { deploymentId, status });
        return updated;
      }

      return null;
    });
  }

  /**
   * Returns the deployments for a driver. Throws if the driver doesn't exist.
   */
  async getDeployments(driverId) {
    const driver = await this.findById(driverId);
    if (!driver) throw new Error(`Driver ${driverId} not found`);
    return driver.getDeployments();
  }
}

module.exports = FileDriverRepository;
