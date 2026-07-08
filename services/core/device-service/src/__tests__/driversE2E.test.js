'use strict';

// End-to-end tests for the driver management and hardware detection chain.
// Boots the real routers on an ephemeral port with isolated temp storage,
// a mock printer-service (Dell catalog) and a mock file server.
//
//   npx jest src/__tests__/driversE2E.test.js

const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');

// Isolated storage — must be set BEFORE the modules under test are required.
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'device-e2e-'));
process.env.DEVICE_DRIVERS_DIR = path.join(TMP_ROOT, 'device-drivers');
process.env.DEVICE_HARDWARE_DIR = path.join(TMP_ROOT, 'device-hardware');

const express = require('express');

// ─── Mock servers ─────────────────────────────────────────────────────────────

const FAKE_DRIVER = Buffer.from('MZfakedriverbinarycontent-' + 'x'.repeat(512));

function startFileMock() {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      if (req.url === '/fake.exe') {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(FAKE_DRIVER);
      } else if (req.url === '/redirect') {
        res.writeHead(302, { Location: '/fake.exe' });
        res.end();
      } else {
        res.writeHead(404); res.end();
      }
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

function startPrinterMock(fileMockPort) {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      if (req.url.startsWith('/api/printer/catalog/dell')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          results: [
            {
              id: 'dell-TEST01', name: 'Dell Test Chipset Driver', version: '1.0',
              vendor: 'Dell', os: ['windows'], deviceType: 'chipset', format: 'exe',
              models: ['OptiPlex 7090'],
              downloadUrl: `http://127.0.0.1:${fileMockPort}/fake.exe`,
            },
            {
              id: 'dell-TEST02', name: 'Dell Test Audio Driver', version: '2.0',
              vendor: 'Dell', os: ['windows'], deviceType: 'audio', format: 'exe',
              models: ['OptiPlex 7090'],
              downloadUrl: `http://127.0.0.1:${fileMockPort}/fake.exe`,
            },
          ],
        }));
      } else {
        res.writeHead(404); res.end();
      }
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

// ─── HTTP helpers (no supertest dependency) ───────────────────────────────────

function request(port, method, reqPath, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : Buffer.isBuffer(body) ? body
      : Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1', port, method, path: reqPath,
      headers: {
        ...(payload && !Buffer.isBuffer(body) ? { 'Content-Type': 'application/json' } : {}),
        ...(payload ? { 'Content-Length': payload.length } : {}),
        ...headers,
      },
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (_) {}
        resolve({ status: res.statusCode, json, raw: data });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function multipartBody(fieldName, filename, content) {
  const boundary = '----e2eboundary42';
  const body = Buffer.concat([
    Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`
    ),
    content,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

// ─── Suite ────────────────────────────────────────────────────────────────────

jest.setTimeout(30000);

let app, appServer, appPort, fileMock, fileMockPort, printerMock;

beforeAll(async () => {
  fileMock = await startFileMock();
  fileMockPort = fileMock.address().port;

  printerMock = await startPrinterMock(fileMockPort);
  process.env.PRINTER_SERVICE_URL = `http://127.0.0.1:${printerMock.address().port}`;

  // Require AFTER env is fully prepared.
  const driverRoutes = require('../routes/driverRoutes');
  const deviceDetectionRoutes = require('../routes/deviceDetectionRoutes');

  app = express();
  app.use(express.json());
  app.use('/api/drivers', driverRoutes);
  app.use('/api/devices', deviceDetectionRoutes);

  await new Promise(resolve => {
    appServer = app.listen(0, '127.0.0.1', () => {
      appPort = appServer.address().port;
      resolve();
    });
  });
});

afterAll(async () => {
  await Promise.all([
    new Promise(r => appServer.close(r)),
    new Promise(r => fileMock.close(r)),
    new Promise(r => printerMock.close(r)),
  ]);
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe('hardware detection & driver matching', () => {
  test('report-hardware (Dell/Windows) returns Dell catalog recommendations', async () => {
    const res = await request(appPort, 'POST', '/api/devices/report-hardware', {
      hostname: 'TEST-PC', manufacturer: 'Dell Inc.', model: 'OptiPlex 7090', os: 'windows',
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    const ids = res.json.recommendations.map(r => r.id);
    expect(ids).toEqual(expect.arrayContaining(['dell-TEST01', 'dell-TEST02']));
    expect(res.json.recommendations[0].matchedVia).toBe('dell-catalog');
  });

  test('driver-recommendations are cached and hostname is case-normalised', async () => {
    const res = await request(appPort, 'GET', '/api/devices/test-pc/driver-recommendations');
    expect(res.status).toBe(200);
    expect(res.json.recommendations.length).toBeGreaterThan(0);
  });

  test('report-hardware (Lenovo/Linux) maps PCI/USB IDs to apt packages', async () => {
    const res = await request(appPort, 'POST', '/api/devices/report-hardware', {
      hostname: 'LNX-01', manufacturer: 'LENOVO', model: 'ThinkPad T14 Gen 3', os: 'linux',
      hardwareIds: [
        { deviceId: '8086:a0f0', class: '0280' },
        { deviceId: '0bda:8153', class: 'usb' },
      ],
    });
    expect(res.status).toBe(200);
    const pkgs = res.json.recommendations.map(r => r.aptPackage).filter(Boolean);
    expect(pkgs).toEqual(expect.arrayContaining(['firmware-iwlwifi', 'firmware-realtek']));
    expect(pkgs.length).toBe(new Set(pkgs).size); // deduped
  });

  test('hardware IDs without class info still yield vendor-level matches (score 8)', async () => {
    const res = await request(appPort, 'POST', '/api/devices/report-hardware', {
      hostname: 'LNX-02', manufacturer: 'Unknown Corp', model: 'Box 3000', os: 'linux',
      hardwareIds: ['8086:a0f0'],
    });
    expect(res.status).toBe(200);
    const vendorMatches = res.json.recommendations.filter(r => r.matchedVia === 'pci-vendor');
    expect(vendorMatches.length).toBeGreaterThan(0);
    expect(vendorMatches.every(r => r.matchScore === 8)).toBe(true);
  });

  test('detect-drivers reuses the stored hardware report', async () => {
    const res = await request(appPort, 'POST', '/api/devices/lnx-01/detect-drivers', {});
    expect(res.status).toBe(200);
    expect(res.json.count).toBeGreaterThan(0);
  });

  test('report-hardware without hostname → 400', async () => {
    const res = await request(appPort, 'POST', '/api/devices/report-hardware', { os: 'linux' });
    expect(res.status).toBe(400);
  });

  test('recommendations for unknown device → 404', async () => {
    const res = await request(appPort, 'GET', '/api/devices/never-seen/driver-recommendations');
    expect(res.status).toBe(404);
  });
});

describe('driver import, upload, deploy', () => {
  let importedId;

  test('import-url downloads and registers a driver', async () => {
    const res = await request(appPort, 'POST', '/api/drivers/import-url', {
      url: `http://127.0.0.1:${fileMockPort}/fake.exe`, name: 'E2E Driver', os: ['windows'],
    });
    expect(res.status).toBe(201);
    expect(res.json.data.name).toBe('E2E Driver');
    expect(res.json.data.checksum).toHaveLength(64);
    importedId = res.json.data.id;

    const list = await request(appPort, 'GET', '/api/drivers');
    expect(list.json.data.some(d => d.id === importedId)).toBe(true);
  });

  test('import-url follows redirects', async () => {
    const res = await request(appPort, 'POST', '/api/drivers/import-url', {
      url: `http://127.0.0.1:${fileMockPort}/redirect`, name: 'Redirected Driver',
    });
    expect(res.status).toBe(201);
    expect(res.json.data.fileSize).toBe(FAKE_DRIVER.length);
  });

  test('upload accepts multipart field "driver" and "file"', async () => {
    for (const field of ['driver', 'file']) {
      const { body, contentType } = multipartBody(field, `via-${field}.inf`, FAKE_DRIVER);
      const res = await request(appPort, 'POST', '/api/drivers/upload', body, {
        'Content-Type': contentType,
      });
      expect(res.status).toBe(201);
      expect(res.json.data.format).toBe('inf');
    }
  });

  test('deploy creates one deployment per device', async () => {
    const res = await request(appPort, 'POST', `/api/drivers/${importedId}/deploy`, {
      deviceIds: ['dev1', 'dev2'],
    });
    expect(res.status).toBe(201);
    expect(res.json.data).toHaveLength(2);

    const deps = await request(appPort, 'GET', `/api/drivers/${importedId}/deployments`);
    expect(deps.json.data).toHaveLength(2);
  });

  test('import-url without url → 400; unreachable host → 500 without orphans', async () => {
    const missing = await request(appPort, 'POST', '/api/drivers/import-url', { name: 'x' });
    expect(missing.status).toBe(400);

    const before = (await request(appPort, 'GET', '/api/drivers')).json.data.length;
    const dead = await request(appPort, 'POST', '/api/drivers/import-url', {
      url: 'http://127.0.0.1:1/nope.exe', name: 'dead',
    });
    expect(dead.status).toBe(500);
    const after = (await request(appPort, 'GET', '/api/drivers')).json.data.length;
    expect(after).toBe(before); // no orphaned catalog entries
  });

  test('5 parallel imports produce 5 unique ids and a valid catalog', async () => {
    const before = (await request(appPort, 'GET', '/api/drivers')).json.data.length;
    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        request(appPort, 'POST', '/api/drivers/import-url', {
          url: `http://127.0.0.1:${fileMockPort}/fake.exe`, name: `parallel-${i}`,
        })
      )
    );
    expect(results.every(r => r.status === 201)).toBe(true);
    const ids = results.map(r => r.json.data.id);
    expect(new Set(ids).size).toBe(5);

    const list = await request(appPort, 'GET', '/api/drivers');
    expect(list.json.data.length).toBe(before + 5);

    // drivers.json on disk must be valid JSON
    const raw = fs.readFileSync(
      path.join(process.env.DEVICE_DRIVERS_DIR, 'drivers.json'), 'utf8'
    );
    expect(() => JSON.parse(raw)).not.toThrow();
  });
});
