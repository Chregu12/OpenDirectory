'use strict';

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const fsp    = require('fs').promises;
const path   = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const winston = require('winston');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

const CATALOG_URL  = 'https://downloads.dell.com/catalog/CatalogPC.cab';
const CACHE_DIR    = '/var/lib/opendirectory/driver-catalogs/dell';
const CAB_PATH     = path.join(CACHE_DIR, 'CatalogPC.cab');
const XML_PATH     = path.join(CACHE_DIR, 'CatalogPC.xml');
const INDEX_PATH   = path.join(CACHE_DIR, 'index.json');
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 h

// ─── OS code → label mapping ──────────────────────────────────────────────────
const OS_CODE_MAP = {
  W10P4: 'windows', W21P4: 'windows', W11TM: 'windows',
  IOT01:  'windows', EXCAL: 'windows', WTCLD: 'windows',
  PE1064: 'windows', LX10:  'linux',   RHEL7: 'linux',
  ESXI:   'linux',   UBUNTU: 'linux',
};

// ─── Category code → deviceType ───────────────────────────────────────────────
const CATEGORY_MAP = {
  NI: 'network', ND: 'network',  NW: 'network',
  VI: 'display', DI: 'display',
  AU: 'audio',
  SA: 'storage', HH: 'storage',  ST: 'storage',
  BI: 'other',   FW: 'other',    AP: 'other',
  CS: 'other',   CM: 'other',    MM: 'other',
  IN: 'usb',     CH: 'other',
};

class DellCatalogService {
  constructor() {
    this.drivers  = [];
    this.loaded   = false;
    this._loading = null; // Promise while loading
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  async search(query = '', filters = {}) {
    await this._ensureLoaded();
    const q = query.toLowerCase().trim();
    return this.drivers.filter(d => {
      if (q) {
        const haystack = `${d.name} ${d.description} ${d.models.join(' ')}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      if (filters.os         && !d.os.includes(filters.os))          return false;
      if (filters.deviceType && d.deviceType !== filters.deviceType)  return false;
      if (filters.systemModel) {
        const sm = filters.systemModel.toLowerCase();
        if (!d.models.some(m => m.toLowerCase().includes(sm))) return false;
      }
      return true;
    });
  }

  async getStats() {
    if (!this.loaded) return { loaded: false, count: 0 };
    return { loaded: true, count: this.drivers.length };
  }

  // Force a fresh refresh (ignores TTL)
  async refresh() {
    // If a load is already in flight, wait for it to settle before starting
    // a new one — otherwise two _load() calls would run concurrently and
    // race on the same CAB/XML/index cache files.
    if (this._loading) {
      try { await this._loading; } catch (_) {}
    }
    this.loaded   = false;
    this._loading = null;
    this.drivers  = [];
    await this._ensureLoaded();
    return { count: this.drivers.length };
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  async _ensureLoaded() {
    if (this.loaded) return;
    if (this._loading) return this._loading;
    this._loading = this._load().finally(() => { this._loading = null; });
    return this._loading;
  }

  async _load() {
    await fsp.mkdir(CACHE_DIR, { recursive: true });

    // Try cached index first
    try {
      const stat = await fsp.stat(INDEX_PATH);
      if (Date.now() - stat.mtimeMs < CACHE_TTL_MS) {
        const data = JSON.parse(await fsp.readFile(INDEX_PATH, 'utf-8'));
        if (Array.isArray(data.drivers) && data.drivers.length > 0) {
          this.drivers = data.drivers;
          this.loaded  = true;
          logger.info('Dell catalog loaded from cache', { count: this.drivers.length });
          return;
        }
      }
    } catch (_) {}

    // Download → extract → parse → cache
    logger.info('Downloading Dell CatalogPC.cab…');
    await this._download(CATALOG_URL, CAB_PATH);
    logger.info('Extracting Dell catalog XML…');
    await this._extract();
    logger.info('Parsing Dell catalog XML (55 MB)…');
    this.drivers = await this._parse();
    this.loaded  = true;
    logger.info('Dell catalog parsed', { count: this.drivers.length });

    // Write to a temp file and rename into place so a crash mid-write can
    // never leave a truncated/corrupt index.json behind.
    const tmpIndexPath = `${INDEX_PATH}.tmp`;
    await fsp.writeFile(tmpIndexPath, JSON.stringify({
      drivers:  this.drivers,
      cachedAt: new Date().toISOString(),
      count:    this.drivers.length,
    }));
    await fsp.rename(tmpIndexPath, INDEX_PATH);
  }

  _download(url, dest) {
    return new Promise((resolve, reject) => {
      const proto = url.startsWith('https') ? https : http;
      const file  = fs.createWriteStream(dest);
      // Any failure path closes the (possibly partially written) file and
      // removes it, so a failed download never leaves a truncated CAB
      // behind for the next _extract()/_parse() to trip over.
      const fail  = err => { file.close(() => fs.unlink(dest, () => reject(err))); };
      const req   = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, res => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          res.resume();
          if (!res.headers.location) return fail(new Error(`Redirect from ${url} had no Location header`));
          const nextUrl = new URL(res.headers.location, url).toString();
          file.close(() => fs.unlink(dest, () => this._download(nextUrl, dest).then(resolve).catch(reject)));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          return fail(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        res.on('error', fail);
        file.on('error', fail);
        res.pipe(file);
        file.on('finish', () => file.close(resolve));
      });
      req.on('error', fail);
    });
  }

  async _extract() {
    // Try cabextract, fallback to 7z
    const errors = [];
    for (const [cmd, args] of [
      ['cabextract', [CAB_PATH, '-d', CACHE_DIR]],
      ['7z',         ['e', CAB_PATH, `-o${CACHE_DIR}`, '-y']],
    ]) {
      try {
        await execFileAsync(cmd, args, { timeout: 60000 });
        return;
      } catch (err) {
        errors.push(`${cmd}: ${err.message}`);
      }
    }
    throw new Error(`Could not extract Dell catalog — ${errors.join('; ')}`);
  }

  async _parse() {
    // Dell catalog is UTF-16 LE with BOM
    const buf = await fsp.readFile(XML_PATH);
    let xml;
    if (buf[0] === 0xFF && buf[1] === 0xFE) {
      xml = buf.slice(2).toString('utf16le');
    } else if (buf[0] === 0xFE && buf[1] === 0xFF) {
      // Big-endian — swap bytes
      const swapped = Buffer.alloc(buf.length - 2);
      for (let i = 0; i < swapped.length - 1; i += 2) {
        swapped[i]     = buf[i + 3];
        swapped[i + 1] = buf[i + 2];
      }
      xml = swapped.toString('utf16le');
    } else {
      xml = buf.toString('utf-8');
    }

    // baseLocation from Manifest
    const baseMatch  = xml.match(/baseLocation="([^"]+)"/);
    const baseLocation = baseMatch ? baseMatch[1] : 'downloads.dell.com';

    const drivers = [];

    // Split by </SoftwareComponent> to get individual chunks — avoids
    // catastrophic backtracking on the full 55 MB string.
    const parts = xml.split('</SoftwareComponent>');

    for (const part of parts) {
      const start = part.lastIndexOf('<SoftwareComponent ');
      if (start === -1) continue;
      const chunk = part.slice(start);

      const getAttr = name => {
        const m = chunk.match(new RegExp(`\\s${name}="([^"]*)"`));
        return m ? m[1] : '';
      };
      const getCdata = tag => {
        const re = new RegExp(`<${tag}[^>]*>[\\s\\S]*?<!\\[CDATA\\[([^\\]]+)\\]\\]>`, 'i');
        const m  = chunk.match(re);
        return m ? m[1].trim() : '';
      };

      const drivPath   = getAttr('path');
      const vendorVer  = getAttr('vendorVersion');
      const dellVer    = getAttr('dellVersion');
      const pkgID      = getAttr('packageID') || getAttr('releaseID');
      const size       = parseInt(getAttr('size') || '0', 10);
      const pkgType    = getAttr('packageType');
      const releaseDate = getAttr('releaseDate');

      if (!drivPath || !pkgID) continue;

      const name        = getCdata('Name');
      const description = getCdata('Description');
      if (!name) continue;

      // Category
      const catMatch  = chunk.match(/CategoryValue\s*=\s*"([^"]+)"|<Category\s+value="([^"]+)"/i);
      const catCode   = (catMatch ? (catMatch[1] || catMatch[2]) : '').substring(0, 2).toUpperCase();
      const deviceType = CATEGORY_MAP[catCode] || 'other';

      // OS — collect osCode attributes inside <SupportedOperatingSystems>
      const osBlock = chunk.match(/<SupportedOperatingSystems>([\s\S]*?)<\/SupportedOperatingSystems>/i);
      const osCodes = [];
      if (osBlock) {
        const osRe = /osCode="([^"]+)"/g;
        let om;
        while ((om = osRe.exec(osBlock[1])) !== null) osCodes.push(om[1]);
      }
      const osLabels = [...new Set(osCodes.map(c => OS_CODE_MAP[c] || (
        c.startsWith('W') ? 'windows' : c.includes('LX') || c.includes('RHEL') || c.includes('UBUNTU') ? 'linux' : null
      )).filter(Boolean))];
      if (!osLabels.length) osLabels.push('windows');

      // Models — all CDATA display names inside <Model> tags
      const models = [];
      const sysBlock = chunk.match(/<SupportedSystems>([\s\S]*?)<\/SupportedSystems>/i);
      if (sysBlock) {
        const mRe2 = /<Model[^>]*>[\s\S]*?<!\[CDATA\[([^\]]+)\]\]>/g;
        let mm;
        while ((mm = mRe2.exec(sysBlock[1])) !== null) {
          const modelName = mm[1].trim();
          if (modelName && !models.includes(modelName)) models.push(modelName);
          if (models.length >= 15) break;
        }
      }

      // Architecture
      let arch = 'x86_64';
      if (pkgType.includes('ARM') || pkgType.includes('A64')) arch = 'arm64';
      else if (pkgType === 'LX32' || pkgType === 'LW32')       arch = 'x86_32';

      // Format
      const ext = drivPath.split('.').pop().toLowerCase();
      const format = ['exe','msi','zip','cab'].includes(ext) ? ext : 'exe';

      drivers.push({
        id:          `dell-${pkgID}`,
        source:      'dell',
        name,
        version:     vendorVer || dellVer || '',
        vendor:      'Dell',
        os:          osLabels,
        deviceType,
        format,
        architecture: arch,
        description,
        downloadUrl: `https://${baseLocation}/${drivPath}`,
        models:      models.slice(0, 10),
        fileSize:    size,
        tags:        [catCode.toLowerCase()].filter(Boolean),
        licenseType: 'freeware',
        releaseDate,
      });
    }

    return drivers;
  }
}

module.exports = new DellCatalogService();
