'use strict';

const http  = require('http');
const https = require('https');
const winston = require('winston');

let DriverCatalog;
try {
  ({ DriverCatalog } = require('@opendirectory/driver-catalog'));
} catch (_) {
  try { ({ DriverCatalog } = require('../../../../../packages/driver-catalog/src')); }
  catch (__) { throw new Error('Could not load @opendirectory/driver-catalog'); }
}

const PRINTER_SERVICE_URL = (process.env.PRINTER_SERVICE_URL || 'http://printer-service:3006').replace(/\/$/, '');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

// ─── Dell live-catalog provider (via printer-service HTTP) ───────────────────

function fetchJson(url, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetchJson(res.headers.location, timeoutMs).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('Invalid JSON')); }
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Dell catalog timeout')); });
    req.on('error', reject);
  });
}

async function fetchDellDrivers(query, filters = {}) {
  const q   = query ? encodeURIComponent(query) : '';
  const sm  = filters.systemModel ? `&systemModel=${encodeURIComponent(filters.systemModel)}` : '';
  const osp = filters.os ? `&os=${filters.os}` : '';
  const url = `${PRINTER_SERVICE_URL}/api/printer/catalog/dell?q=${q}${sm}${osp}&limit=300`;

  try {
    const data = await fetchJson(url, 15000);
    return Array.isArray(data?.results) ? data.results : [];
  } catch (err) {
    logger.warn('Dell catalog query failed', { message: err.message });
    return [];
  }
}

// ─── Singleton catalog with Dell provider injected ───────────────────────────

const catalog = new DriverCatalog();
catalog.registerProvider('dell', fetchDellDrivers);

// ─── Public API (same interface as before) ───────────────────────────────────

async function matchDrivers(hwInfo) {
  logger.info('Driver matching', {
    vendor: hwInfo.manufacturer,
    model:  hwInfo.model,
    os:     hwInfo.os,
    hwIds:  (hwInfo.hardwareIds || []).length,
  });
  return catalog.matchDrivers(hwInfo);
}

module.exports = { matchDrivers };
