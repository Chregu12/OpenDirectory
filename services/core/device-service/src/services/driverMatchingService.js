'use strict';

const https = require('https');
const http = require('http');
const winston = require('winston');

const PRINTER_SERVICE_URL = (process.env.PRINTER_SERVICE_URL || 'http://printer-service:3006').replace(/\/$/, '');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

// Static driver catalog for non-Dell vendors (device drivers, not printer-only)
const STATIC_CATALOG = {
  hp: [
    { id: 'hp-net-broadcom', name: 'HP Broadcom NetXtreme Gigabit Network Driver', version: '22.4.0.0', vendor: 'HP', os: ['windows'], deviceType: 'network', format: 'exe', architecture: 'x86_64', description: 'Broadcom NetXtreme Gigabit Ethernet driver for HP workstations', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138452.exe', models: ['Z4 G4', 'Z6 G4', 'Z8 G4'], fileSize: 9437184, tags: ['network', 'broadcom', 'gigabit'], licenseType: 'freeware' },
    { id: 'hp-audio-conexant', name: 'HP Conexant SmartAudio Driver', version: '9.0.232.0', vendor: 'HP', os: ['windows'], deviceType: 'audio', format: 'exe', architecture: 'x86_64', description: 'Conexant SmartAudio driver for HP EliteBook / ProBook series', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138000.exe', models: ['EliteBook 840 G9', 'ProBook 450 G9'], fileSize: 52428800, tags: ['audio', 'conexant'], licenseType: 'freeware' },
    { id: 'hp-display-intel-iris', name: 'HP Intel Iris Xe Graphics Driver', version: '31.0.101.2115', vendor: 'HP', os: ['windows'], deviceType: 'display', format: 'exe', architecture: 'x86_64', description: 'Intel Iris Xe graphics driver for HP EliteBook 12th gen', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp139000.exe', models: ['EliteBook 840 G9', 'EliteBook 1040 G9'], fileSize: 167772160, tags: ['display', 'intel', 'iris'], licenseType: 'freeware' },
  ],
  lenovo: [
    { id: 'lenovo-net-i219', name: 'Lenovo ThinkPad Intel I219-LM Ethernet Driver', version: '12.19.2.36', vendor: 'Lenovo', os: ['windows'], deviceType: 'network', format: 'exe', architecture: 'x86_64', description: 'Intel I219-LM Gigabit Ethernet driver for ThinkPad', downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xne05w.exe', models: ['ThinkPad T14 Gen 3', 'ThinkPad L14 Gen 3'], fileSize: 8388608, tags: ['network', 'ethernet', 'intel'], licenseType: 'freeware' },
    { id: 'lenovo-audio-realtek', name: 'Lenovo ThinkPad Realtek Audio Driver', version: '6.0.9374.1', vendor: 'Lenovo', os: ['windows'], deviceType: 'audio', format: 'exe', architecture: 'x86_64', description: 'Realtek HD Audio driver for ThinkPad', downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xau12w.exe', models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10'], fileSize: 262144000, tags: ['audio', 'realtek'], licenseType: 'freeware' },
    { id: 'lenovo-display-iris', name: 'Lenovo ThinkPad Intel Iris Xe Graphics Driver', version: '31.0.101.2115', vendor: 'Lenovo', os: ['windows'], deviceType: 'display', format: 'exe', architecture: 'x86_64', description: 'Intel Iris Xe Graphics driver for ThinkPad 12th gen', downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r1xvd04w.exe', models: ['ThinkPad X1 Carbon Gen 10', 'ThinkPad T14s Gen 3'], fileSize: 167772160, tags: ['display', 'intel', 'iris'], licenseType: 'freeware' },
  ],
};

// Normalize vendor name to a canonical key
function normalizeVendor(raw) {
  if (!raw) return null;
  const v = raw.toLowerCase();
  if (v.includes('dell')) return 'dell';
  if (v.includes('hp') || v.includes('hewlett')) return 'hp';
  if (v.includes('lenovo')) return 'lenovo';
  if (v.includes('microsoft')) return 'microsoft';
  if (v.includes('apple')) return 'apple';
  if (v.includes('asus')) return 'asus';
  if (v.includes('acer')) return 'acer';
  if (v.includes('toshiba')) return 'toshiba';
  if (v.includes('fujitsu')) return 'fujitsu';
  return v;
}

// Score a driver match (higher = better)
function scoreMatch(driver, { model, os }) {
  let score = 0;
  if (model && driver.models) {
    const m = model.toLowerCase();
    for (const dm of driver.models) {
      if (dm.toLowerCase().includes(m) || m.includes(dm.toLowerCase())) {
        score += 20;
        break;
      }
    }
  }
  if (os && driver.os && driver.os.includes(os.toLowerCase())) score += 10;
  return score;
}

// Simple HTTP GET returning parsed JSON
function fetchJson(url, timeoutMs = 10000) {
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
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Timeout')); });
    req.on('error', reject);
  });
}

class DriverMatchingService {
  // Match drivers based on device hardware info
  async matchDrivers({ manufacturer, model, os, hardwareIds = [] }) {
    const vendor = normalizeVendor(manufacturer);
    const osLabel = this._normalizeOs(os);

    logger.info('Driver matching', { vendor, model, osLabel });

    const results = [];

    // Dell: query live catalog via printer-service
    if (vendor === 'dell') {
      try {
        const q = model ? encodeURIComponent(model) : '';
        const sm = model ? `&systemModel=${encodeURIComponent(model)}` : '';
        const osParam = osLabel ? `&os=${osLabel}` : '';
        const url = `${PRINTER_SERVICE_URL}/api/printer/catalog/dell?q=${q}${sm}${osParam}`;
        const data = await fetchJson(url, 15000);
        if (data && Array.isArray(data.results)) {
          for (const d of data.results) {
            results.push({ ...d, matchScore: scoreMatch(d, { model, os: osLabel }), matchedVia: 'dell-catalog' });
          }
        }
      } catch (err) {
        logger.warn('Dell catalog query failed during driver matching', { message: err.message });
      }
    }

    // Static catalog for HP, Lenovo, etc.
    const staticEntries = STATIC_CATALOG[vendor] || [];
    for (const d of staticEntries) {
      if (osLabel && !d.os.includes(osLabel)) continue;
      results.push({ ...d, matchScore: scoreMatch(d, { model, os: osLabel }), matchedVia: 'static-catalog' });
    }

    // Sort by score descending
    results.sort((a, b) => (b.matchScore || 0) - (a.matchScore || 0));

    return results;
  }

  _normalizeOs(raw) {
    if (!raw) return null;
    const s = (raw || '').toLowerCase();
    if (s.includes('windows')) return 'windows';
    if (s.includes('linux')) return 'linux';
    if (s.includes('mac') || s.includes('darwin')) return 'macos';
    return null;
  }
}

module.exports = new DriverMatchingService();
