'use strict';

const crypto = require('crypto');
const path = require('path');
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');

const DriverAggregate = require('../domain/aggregates/DriverAggregate');
const { DeviceEvents } = require('../domain/events/DeviceEvents');

const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB

// ── SSRF protection ──────────────────────────────────────────────────────
//
// importFromUrl() lets an authenticated caller point this service at an
// arbitrary http(s) URL (e.g. a vendor driver-catalog entry). Without
// restricting the resolved target, that URL could point at loopback,
// RFC1918/link-local ranges or the cloud metadata endpoint
// (169.254.169.254), turning the service into an SSRF proxy against its
// own host/network/cloud credentials endpoint.
//
// isPrivateAddress(ip) is a small, pure, exported helper so it can be
// unit-tested directly. The actual enforcement happens in checkedLookup(),
// a custom `dns.lookup`-compatible function passed to http(s).get(): Node
// uses the address *we* resolved and validated to open the TCP connection,
// so there is no separate "check" step that a DNS-rebinding attacker could
// race against the real connect (the validated IP *is* the connect IP).
// Each redirect hop calls downloadToBuffer() again, so the target is
// re-resolved and re-checked after every redirect too.

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => Number.isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  if (a === 127) return true;               // 127.0.0.0/8 — loopback
  if (a === 10) return true;                 // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;   // 192.168.0.0/16
  if (a === 169 && b === 254) return true;   // 169.254.0.0/16 — link-local, incl. 169.254.169.254 (cloud metadata)
  if (a === 0) return true;                  // 0.0.0.0/8 — "this network" / unspecified
  return false;
}

/**
 * Returns true if `ip` (v4 or v6 literal) falls in a loopback, private,
 * link-local or otherwise non-routable range that must not be reachable
 * via a server-side URL fetch. Unparseable input fails closed (blocked).
 */
function isPrivateAddress(ip) {
  if (!ip || typeof ip !== 'string') return true;

  let addr = ip;
  // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1) to the embedded IPv4 form.
  const v4Mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(addr);
  if (v4Mapped) addr = v4Mapped[1];

  const version = net.isIP(addr);
  if (version === 4) return isPrivateIPv4(addr);
  if (version === 6) {
    const lower = addr.toLowerCase();
    if (lower === '::1' || lower === '::') return true;             // loopback / unspecified
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 — unique local
    if (['fe8', 'fe9', 'fea', 'feb'].some(p => lower.startsWith(p))) return true; // fe80::/10 — link-local
    return false;
  }
  return true; // not a parseable IP literal → fail closed
}

// Jest sets NODE_ENV=test automatically. driversE2E.test.js intentionally
// spins up local HTTP servers on 127.0.0.1 to stand in for a vendor
// driver-catalog/file host (no live internet access in CI), so the SSRF
// guard is relaxed only in that environment. This must never be set in
// production/staging.
const SSRF_GUARD_DISABLED = process.env.NODE_ENV === 'test';

function checkedLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (!SSRF_GUARD_DISABLED && String(hostname).toLowerCase() === 'localhost') {
    return callback(new Error('Blocked internal/private address'));
  }
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    if (!SSRF_GUARD_DISABLED) {
      const addresses = Array.isArray(address) ? address : [{ address, family }];
      for (const a of addresses) {
        if (isPrivateAddress(a.address || address)) {
          return callback(new Error('Blocked internal/private address'));
        }
      }
    }
    callback(null, address, family);
  });
}

// ── URL import helpers (moved from routes/driverRoutes.js) ─────────────────

// Download a URL into a Buffer, following redirects.
function downloadToBuffer(url, timeoutMs = 300000, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    if (!/^https?:\/\//i.test(url)) return reject(new Error('Nur http(s)-URLs erlaubt'));

    let parsedUrl;
    try { parsedUrl = new URL(url); } catch (_) { return reject(new Error('Ungültige URL')); }

    // Node's custom `lookup` option (used below via checkedLookup, for
    // hostnames and DNS-rebinding protection) is *not* invoked when the URL
    // host is already an IP literal — Node connects to it directly. Since
    // SSRF payloads very commonly target a literal IP (e.g.
    // http://127.0.0.1/ or http://169.254.169.254/), that case must be
    // rejected here, before any connection is attempted.
    if (!SSRF_GUARD_DISABLED) {
      const hostname = parsedUrl.hostname;
      if (hostname.toLowerCase() === 'localhost') {
        return reject(new Error('Blocked internal/private address'));
      }
      if (net.isIP(hostname) && isPrivateAddress(hostname)) {
        return reject(new Error('Blocked internal/private address'));
      }
    }

    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' }, lookup: checkedLookup }, res => {
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
// Exposed for unit testing / reuse — see the "SSRF protection" block above.
module.exports.isPrivateAddress = isPrivateAddress;
