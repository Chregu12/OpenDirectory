'use strict';

const express = require('express');
const multer = require('multer');
const path = require('path');
const http = require('http');
const https = require('https');
const winston = require('winston');

const manager = require('../services/deviceDriverManager');

const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB

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

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const router = express.Router();

// Store uploads in memory so we can compute sha256 before writing to disk.
// Cap file size to match the import-url download limit so a huge upload
// can't exhaust process memory.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_DOWNLOAD_BYTES } });

// GET /drivers — list with optional filters
router.get('/', async (req, res) => {
  try {
    const { os, deviceType, vendor } = req.query;
    const drivers = await manager.listDrivers({ os, deviceType, vendor });
    res.json({ success: true, data: drivers });
  } catch (err) {
    logger.error('listDrivers error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /drivers/:id — single driver with deployments
router.get('/:id', async (req, res) => {
  try {
    const driver = await manager.getDriver(req.params.id);
    if (!driver) return res.status(404).json({ error: 'Treiber nicht gefunden' });
    res.json({ success: true, data: driver });
  } catch (err) {
    logger.error('getDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/upload — multipart upload (file field: "driver" or "file").
// Metadata fields are optional; sensible defaults are derived from the filename.
// Note: this route must be declared before /:id to avoid being shadowed
router.post('/upload', upload.fields([{ name: 'driver', maxCount: 1 }, { name: 'file', maxCount: 1 }]), async (req, res) => {
  try {
    const file = req.files?.driver?.[0] || req.files?.file?.[0];
    if (!file) {
      return res.status(400).json({ error: 'Keine Treiberdatei hochgeladen (Feld: driver oder file)' });
    }

    const originalname = file.originalname || 'driver.bin';
    const ext = path.extname(originalname).replace('.', '').toLowerCase();
    const { name, version, vendor, os, deviceType, format, architecture, description, tags } = req.body;

    const osList = os
      ? (Array.isArray(os) ? os : String(os).split(',').map(s => s.trim()).filter(Boolean))
      : ['universal'];

    const driver = await manager.addDriver({
      fileBuffer: file.buffer,
      filename: originalname,
      name: name || path.basename(originalname, path.extname(originalname)),
      version: version || '0.0.0',
      vendor: vendor || 'Unbekannt',
      os: osList,
      deviceType: deviceType || 'other',
      format: format || ext || 'bin',
      architecture: architecture || 'universal',
      description,
      tags,
    });

    res.status(201).json({ success: true, data: driver });
  } catch (err) {
    logger.error('uploadDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/import-url — download a driver from a URL and register it.
// Body: { url, name?, version?, vendor?, os?, deviceType?, format?, architecture?, description?, tags? }
// Used by the frontend to import recommended drivers (Dell catalog, vendor catalogs).
router.post('/import-url', async (req, res) => {
  try {
    const { url, name, version, vendor, os, deviceType, format, architecture, description, tags } = req.body;
    if (!url) return res.status(400).json({ error: 'url ist erforderlich' });

    const fileBuffer = await downloadToBuffer(url);
    const filename = filenameFromUrl(url);
    const ext = path.extname(filename).replace('.', '').toLowerCase();

    const osList = os
      ? (Array.isArray(os) ? os : String(os).split(',').map(s => s.trim()).filter(Boolean))
      : ['universal'];

    const driver = await manager.addDriver({
      fileBuffer,
      filename,
      name: name || filename,
      version: version || '0.0.0',
      vendor: vendor || 'Unbekannt',
      os: osList,
      deviceType: deviceType || 'other',
      format: format || ext || 'bin',
      architecture: architecture || 'universal',
      description: description || `Importiert von ${url}`,
      tags,
    });

    res.status(201).json({ success: true, data: driver });
  } catch (err) {
    logger.error('importDriverFromUrl error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /drivers/:id
router.delete('/:id', async (req, res) => {
  try {
    const deleted = await manager.deleteDriver(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Treiber nicht gefunden' });
    res.json({ success: true });
  } catch (err) {
    logger.error('deleteDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/:id/deploy — body: { deviceIds: string[] }
router.post('/:id/deploy', async (req, res) => {
  try {
    const { deviceIds } = req.body;
    if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'deviceIds muss ein nicht-leeres Array sein' });
    }
    const deployments = await manager.deployDriver(req.params.id, deviceIds);
    res.status(201).json({ success: true, data: deployments });
  } catch (err) {
    logger.error('deployDriver error:', err);
    const status = err.message.includes('nicht gefunden') || err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// GET /drivers/:id/deployments
router.get('/:id/deployments', async (req, res) => {
  try {
    const deployments = await manager.getDeployments(req.params.id);
    res.json({ success: true, data: deployments });
  } catch (err) {
    logger.error('getDeployments error:', err);
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// PATCH /drivers/:id/deployments/:deploymentId — body: { status, error? }
router.patch('/:id/deployments/:deploymentId', async (req, res) => {
  try {
    const { status, error } = req.body;
    if (!status) return res.status(400).json({ error: 'status ist erforderlich' });

    const deployment = await manager.updateDeploymentStatus(req.params.deploymentId, status, error);
    if (!deployment) return res.status(404).json({ error: 'Deployment nicht gefunden' });
    res.json({ success: true, data: deployment });
  } catch (err) {
    logger.error('updateDeploymentStatus error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
