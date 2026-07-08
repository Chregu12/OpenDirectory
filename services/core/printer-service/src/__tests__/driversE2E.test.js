'use strict';

// End-to-end tests for the printer-service driver and catalog chain.
// Boots the real routers on an ephemeral port with isolated temp storage
// and a mock file server; the Dell parser is tested against a UTF-16 LE
// fixture that reproduces Dell's Brand/Model nesting.
//
//   npx jest src/__tests__/driversE2E.test.js

const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');

// Isolated storage — must be set BEFORE the modules under test are required.
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'printer-e2e-'));
process.env.PRINTER_DRIVERS_DIR = path.join(TMP_ROOT, 'printer-drivers');
process.env.DEVICE_DRIVERS_DIR = path.join(TMP_ROOT, 'device-drivers');
process.env.DELL_CATALOG_CACHE_DIR = path.join(TMP_ROOT, 'dell-cache');

const express = require('express');

const FAKE_DRIVER = Buffer.from('%!PS-fake-ppd-content-' + 'y'.repeat(400));

// ─── Dell catalog fixture (UTF-16 LE with BOM, Brand/Model nesting) ──────────

const DELL_XML = `<?xml version="1.0" encoding="utf-16"?>
<Manifest baseLocation="downloads.dell.com" version="1.0">
<SoftwareComponent path="FOLDER123/1/Chipset_Driver_TEST_WN64_1.0_A00.EXE" vendorVersion="1.0" dellVersion="A00" packageID="TEST1" size="1048576" packageType="LWXP" releaseDate="January 05, 2026">
<Name><Display lang="en"><![CDATA[Dell Test Chipset Driver]]></Display></Name>
<Description><Display lang="en"><![CDATA[Chipset driver for testing]]></Display></Description>
<Category value="CS"><Display lang="en"><![CDATA[Chipset]]></Display></Category>
<SupportedOperatingSystems><OperatingSystem osCode="W11TM" osVendor="Microsoft"><Display lang="en"><![CDATA[Windows 11]]></Display></OperatingSystem></SupportedOperatingSystems>
<SupportedSystems>
<Brand key="1" prefix="OP"><Display lang="en"><![CDATA[Optiplex]]></Display>
<Model systemID="0A52"><Display lang="en"><![CDATA[7090]]></Display></Model>
<Model systemID="0A53"><Display lang="en"><![CDATA[5090]]></Display></Model>
</Brand>
</SupportedSystems>
</SoftwareComponent>
<SoftwareComponent path="FOLDER456/1/Network_Driver_TEST_WN64_2.0_A00.EXE" vendorVersion="2.0" dellVersion="A00" packageID="TEST2" size="2097152" packageType="LWXP" releaseDate="January 06, 2026">
<Name><Display lang="en"><![CDATA[Dell Test Network Driver]]></Display></Name>
<Description><Display lang="en"><![CDATA[Network driver for testing]]></Display></Description>
<Category value="NI"><Display lang="en"><![CDATA[Network]]></Display></Category>
<SupportedOperatingSystems><OperatingSystem osCode="W11TM" osVendor="Microsoft"><Display lang="en"><![CDATA[Windows 11]]></Display></OperatingSystem></SupportedOperatingSystems>
<SupportedSystems>
<Brand key="2" prefix="LAT"><Display lang="en"><![CDATA[Latitude]]></Display>
<Model systemID="0B10"><Display lang="en"><![CDATA[5520]]></Display></Model>
</Brand>
</SupportedSystems>
</SoftwareComponent>
</Manifest>`;

function writeUtf16LeFixture(filePath, text) {
  const bom = Buffer.from([0xff, 0xfe]);
  fs.writeFileSync(filePath, Buffer.concat([bom, Buffer.from(text, 'utf16le')]));
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function startFileMock() {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      if (req.url === '/fake-driver.ppd') {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(FAKE_DRIVER);
      } else if (req.url === '/redirect') {
        res.writeHead(302, { Location: '/fake-driver.ppd' });
        res.end();
      } else {
        res.writeHead(404); res.end();
      }
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

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
  const boundary = '----e2eboundary77';
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

let appServer, appPort, fileMock, fileMockPort;

beforeAll(async () => {
  fileMock = await startFileMock();
  fileMockPort = fileMock.address().port;

  // Prime the Dell cache with the fixture so no network access is needed:
  // an index.json younger than the TTL short-circuits download/extract.
  const cacheDir = process.env.DELL_CATALOG_CACHE_DIR;
  fs.mkdirSync(cacheDir, { recursive: true });
  writeUtf16LeFixture(path.join(cacheDir, 'CatalogPC.xml'), DELL_XML);

  const dellService = require('../services/dellCatalogService');
  const parsed = await dellService._parse();
  fs.writeFileSync(path.join(cacheDir, 'index.json'), JSON.stringify({
    drivers: parsed, cachedAt: new Date().toISOString(), count: parsed.length,
  }));

  const driverRoutes = require('../routes/driverRoutes');
  const catalogRoutes = require('../routes/catalogRoutes');

  const app = express();
  app.use(express.json());
  app.use('/api/printer', driverRoutes);
  app.use('/api/printer/catalog', catalogRoutes);

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
  ]);
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe('Dell catalog parser (UTF-16 LE fixture with Brand/Model nesting)', () => {
  test('parses both components with combined brand + model names', async () => {
    const dellService = require('../services/dellCatalogService');
    const drivers = await dellService.search('', {});
    expect(drivers).toHaveLength(2);

    const chipset = drivers.find(d => d.id === 'dell-TEST1');
    expect(chipset).toBeDefined();
    expect(chipset.name).toBe('Dell Test Chipset Driver');
    expect(chipset.downloadUrl).toBe(
      'https://downloads.dell.com/FOLDER123/1/Chipset_Driver_TEST_WN64_1.0_A00.EXE'
    );
    // The Brand/Model fix: models must carry the brand prefix.
    expect(chipset.models).toEqual(expect.arrayContaining(['Optiplex 7090', 'Optiplex 5090']));
    expect(chipset.os).toContain('windows');
  });

  test('systemModel search matches brand-qualified models', async () => {
    const res = await request(appPort, 'GET',
      '/api/printer/catalog/dell?q=optiplex%207090&systemModel=OptiPlex%207090');
    expect(res.status).toBe(200);
    expect(res.json.count).toBeGreaterThan(0);
    expect(res.json.results[0].id).toBe('dell-TEST1');
  });

  test('dell route enforces the result limit', async () => {
    const res = await request(appPort, 'GET', '/api/printer/catalog/dell?q=&limit=1');
    expect(res.status).toBe(200);
    expect(res.json.results).toHaveLength(1);
    expect(res.json.count).toBe(2); // total count still reported
  });
});

describe('driver upload and catalog import persistence', () => {
  test('upload without metadata derives defaults and returns 201', async () => {
    const { body, contentType } = multipartBody('driver', 'testfile.ppd', FAKE_DRIVER);
    const res = await request(appPort, 'POST', '/api/printer/drivers/upload', body, {
      'Content-Type': contentType,
    });
    expect(res.status).toBe(201);
    expect(res.json.data.name).toBe('testfile');
    expect(res.json.data.format).toBe('ppd');
    expect(res.json.data.vendor).toBe('Unbekannt');
  });

  test('catalog import downloads, registers, and shows up in the driver list', async () => {
    const entry = {
      id: 'e2e-import-1', name: 'E2E Catalog Driver', version: '1.2.3', vendor: 'HP',
      os: ['linux'], deviceType: 'printer', format: 'ppd',
      downloadUrl: `http://127.0.0.1:${fileMockPort}/fake-driver.ppd`,
    };
    const res = await request(appPort, 'POST', '/api/printer/catalog/import', { entry });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);

    const list = await request(appPort, 'GET', '/api/printer/drivers');
    const found = list.json.data.find(d => d.name === 'E2E Catalog Driver');
    expect(found).toBeDefined();
    expect(fs.existsSync(found.filePath)).toBe(true);
  });

  test('import-url follows redirects and registers', async () => {
    const res = await request(appPort, 'POST', '/api/printer/catalog/import-url', {
      url: `http://127.0.0.1:${fileMockPort}/redirect`,
      name: 'Redirected PPD', deviceType: 'printer', format: 'ppd',
    });
    expect(res.status).toBe(200);

    const list = await request(appPort, 'GET', '/api/printer/drivers');
    expect(list.json.data.some(d => d.name === 'Redirected PPD')).toBe(true);
  });

  test('failed import leaves no orphans in the catalog', async () => {
    const before = (await request(appPort, 'GET', '/api/printer/drivers')).json.data.length;
    const res = await request(appPort, 'POST', '/api/printer/catalog/import-url', {
      url: 'http://127.0.0.1:1/unreachable.ppd', name: 'dead',
    });
    expect(res.status).toBe(500);
    const after = (await request(appPort, 'GET', '/api/printer/drivers')).json.data.length;
    expect(after).toBe(before);
  });

  test('delete removes the catalog entry and its file', async () => {
    const list = await request(appPort, 'GET', '/api/printer/drivers');
    const victim = list.json.data[0];
    const res = await request(appPort, 'DELETE', `/api/printer/drivers/${victim.id}`);
    expect(res.status).toBe(200);
    expect(fs.existsSync(victim.filePath)).toBe(false);
  });
});

describe('catalog search robustness', () => {
  test('static catalog search finds HP entries', async () => {
    const res = await request(appPort, 'GET', '/api/printer/catalog/search?q=laserjet');
    expect(res.status).toBe(200);
    expect(res.json.count).toBeGreaterThan(0);
  });

  test('repeated query params do not crash (?q=a&q=b)', async () => {
    const res = await request(appPort, 'GET', '/api/printer/catalog/search?q=a&q=b');
    expect(res.status).toBe(200);
  });

  test('vendors endpoint reports counts including live Dell', async () => {
    const res = await request(appPort, 'GET', '/api/printer/catalog/vendors');
    expect(res.status).toBe(200);
    const dell = res.json.vendors.find(v => v.id === 'dell');
    expect(dell).toBeDefined();
    expect(dell.count).toBe(2); // fixture entries
  });
});
