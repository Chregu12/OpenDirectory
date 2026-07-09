'use strict';

const crypto = require('crypto');
const path = require('path');
const http = require('http');
const https = require('https');

const DriverAggregate = require('../domain/aggregates/DriverAggregate');
const { DeviceEvents } = require('../domain/events/DeviceEvents');

const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB

// ── URL import helpers (moved from routes/driverRoutes.js) ─────────────────

// Download a URL into a Buffer, following redirects.
function downloadToBuffer(url, timeoutMs = 300000, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    if (!/^https?:\/\//i.test(url)) return reject(new Error('Nur http(s)-URLs erlaubt'));
    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, res => {
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('Zu viele Redirects'));
        if (!res.headers.location) return reject(new Error('Redirect ohne Location-Header'));
        let nextUrl;
        try { nextUrl = new URL(res.headers.location, url).toString(); }
        catch (_) { return reject(new Error('Ungültige Redirect-URL')); }
        return downloadToBuffer(nextUrl, timeoutMs, redirectsLeft - 1)
          .then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} von ${url}`));
      }
      const chunks = [];
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > MAX_DOWNLOAD_BYTES) {
          req.destroy();
          return reject(new Error('Datei überschreitet 512 MB Limit'));
        }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Download-Timeout')); });
    req.on('error', reject);
  });
}

function filenameFromUrl(url, fallback = 'driver.bin') {
  try {
    const base = path.basename(new URL(url).pathname);
    return base || fallback;
  } catch (_) { return fallback; }
}

function normalizeOsList(os) {
  if (!os) return ['universal'];
  if (Array.isArray(os)) return os;
  return String(os).split(',').map(s => s.trim()).filter(Boolean);
}

function newDriverId() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * DriverApplicationService
 *
 * Use cases for driver catalog management, hardware reporting and driver
 * matching. Routes should only translate HTTP <-> these methods; all
 * validation, defaulting and persistence orchestration lives here.
 */
class DriverApplicationService {
  constructor(driverRepo, reportRepo, { matchDrivers, eventBus } = {}) {
    this._driverRepo = driverRepo;
    this._reportRepo = reportRepo;
    this._matchDrivers = matchDrivers;
    this._eventBus = eventBus;
  }

  _publish(type, payload) {
    if (!this._eventBus || typeof this._eventBus.publish !== 'function') return;
    try {
      Promise.resolve(this._eventBus.publish(type, payload)).catch(() => {});
    } catch (_) {
      // fire-and-forget
    }
  }

  _publishEvents(events) {
    for (const event of events) {
      this._publish(event.type, event.payload);
    }
  }

  // ── driver catalog ──────────────────────────────────────────────────────

  async uploadDriver(fileBuffer, filename, metadata = {}) {
    const originalname = filename || 'driver.bin';
    const ext = path.extname(originalname).replace('.', '').toLowerCase();
    const { name, version, vendor, os, deviceType, format, architecture, description, tags } = metadata;

    const id = newDriverId();
    const checksum = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    const { filePath, destFilename } = await this._driverRepo.saveFile(id, originalname, fileBuffer);

    const driver = DriverAggregate.create({
      id,
      name: name || path.basename(originalname, path.extname(originalname)),
      version: version || '0.0.0',
      vendor: vendor || 'Unbekannt',
      os: normalizeOsList(os),
      deviceType: deviceType || 'other',
      format: format || ext || 'bin',
      architecture: architecture || 'universal',
      description: description || '',
      filename: destFilename,
      fileSize: fileBuffer.length,
      filePath,
      checksum,
      tags,
    });

    await this._driverRepo.save(driver);
    this._publishEvents(driver.getAndClearDomainEvents());
    return driver;
  }

  async importFromUrl(url, metadata = {}) {
    if (!url) throw new Error('url ist erforderlich');

    const fileBuffer = await downloadToBuffer(url);
    const filename = filenameFromUrl(url);

    return this.uploadDriver(fileBuffer, filename, {
      ...metadata,
      name: metadata.name || filename,
      description: metadata.description || `Importiert von ${url}`,
    });
  }

  async listDrivers(filter) {
    return this._driverRepo.findAll(filter);
  }

  async getDriver(id) {
    return this._driverRepo.findById(id);
  }

  async deleteDriver(id) {
    return this._driverRepo.delete(id);
  }

  async deployDriver(driverId, deviceIds) {
    const { deployments, events } = await this._driverRepo.addDeployments(driverId, deviceIds);
    this._publishEvents(events);
    return deployments;
  }

  async getDeployments(driverId) {
    return this._driverRepo.getDeployments(driverId);
  }

  async updateDeploymentStatus(deploymentId, status, error) {
    return this._driverRepo.updateDeploymentStatus(deploymentId, status, error);
  }

  // ── hardware detection & driver matching ────────────────────────────────

  async reportHardware(profile) {
    const report = {
      hostname: profile.hostname,
      deviceId: profile.deviceId,
      manufacturer: profile.manufacturer,
      model: profile.model,
      os: profile.os,
      osVersion: profile.osVersion,
      hardwareIds: profile.hardwareIds,
      reportedAt: new Date().toISOString(),
    };

    await this._reportRepo.save(profile.key, report);

    const recommendations = await this._matchDrivers({
      manufacturer: profile.manufacturer,
      model: profile.model,
      os: profile.os,
      hardwareIds: profile.hardwareIds,
    });
    await this._reportRepo.saveRecommendations(profile.key, recommendations);

    this._publish(DeviceEvents.HARDWARE_REPORTED, {
      key: profile.key, hostname: profile.hostname, deviceId: profile.deviceId,
    });

    return { key: profile.key, report, recommendations };
  }

  async getHardwareReport(key) {
    return this._reportRepo.findByKey(key);
  }

  async getRecommendations(key) {
    let cached = await this._reportRepo.findRecommendations(key);
    if (!cached) {
      const report = await this._reportRepo.findByKey(key);
      if (!report) return null;
      const recommendations = await this._matchDrivers(report);
      cached = await this._reportRepo.saveRecommendations(key, recommendations);
    }
    return cached;
  }

  async detectDrivers(key, overrides = {}) {
    let hwInfo = overrides || {};
    if (!hwInfo.manufacturer) {
      const stored = await this._reportRepo.findByKey(key);
      if (!stored) return null;
      hwInfo = { ...stored, ...hwInfo };
    }

    const recommendations = await this._matchDrivers(hwInfo);
    await this._reportRepo.saveRecommendations(key, recommendations);
    return { recommendations, count: recommendations.length };
  }
}

module.exports = DriverApplicationService;
