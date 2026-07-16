'use strict';

// ═════════════════════════════════════════════════════════════════════════════
// REAL cross-service integration test: device-service ⇄ printer-service
// ═════════════════════════════════════════════════════════════════════════════
//
// WHAT THIS PROVES (the gap no other committed test covers)
// ---------------------------------------------------------
// The device-service and printer-service driver/catalog chain is exercised
// end-to-end as TWO separate, really-booted Node processes talking over real
// HTTP on real (ephemeral) ports, with real file persistence:
//
//   1. PERSISTENCE — a multipart driver upload to device-service actually lands
//      in drivers.json on disk (DEVICE_DRIVERS_DIR), read back straight from the
//      filesystem, not from an API response.
//
//   2. REAL CROSS-SERVICE HTTP — POST /api/devices/report-hardware on
//      device-service triggers driverMatchingService, which performs a genuine
//      HTTP GET against the *running printer-harness* at
//      /api/printer/catalog/dell. The recommendation returned carries a marker
//      (id + name) that exists ONLY in the printer-service catalog we seeded —
//      it is impossible for device-service to produce it locally, so a passing
//      assertion is proof the bytes crossed the service boundary over HTTP.
//
// Both harnesses require the REAL routers from the repo
// (driverRoutes, deviceDetectionRoutes, catalogRoutes) — no service logic is
// duplicated. The printer-service Dell catalog is seeded via a cached
// index.json (dellCatalogService's normal cache path), so the run is fully
// offline and deterministic — no network download of Dell's CatalogPC.cab.
//
// WHAT THIS DOES *NOT* COVER (honest scope)
// -----------------------------------------
//   • Auth — oidcAuth middleware is intentionally bypassed (the routers are
//     mounted without it) so the test can focus on the service-to-service path.
//   • Postgres / Redis / RabbitMQ — the full index.js of each service is NOT
//     booted. Only the driver/catalog/hardware routers, which boot cleanly
//     without a database, are mounted (file-backed repositories in tmp dirs).
//   • Browser / frontend — this is a backend HTTP-chain test, no DOM.
//   • The live Dell CatalogPC.cab download/parse path — deliberately short-
//     circuited by a seeded cache so the test is hermetic.
//
// HOW TO RUN
// ----------
//   cd services/tests/integration && npm run test:integration
//   (or: node --test cross-service.integration.test.js)
//
// This suite is intentionally kept OUT of the per-service `jest` unit gate; it
// is a separately-invoked integration script (slower, spawns processes).
// ═════════════════════════════════════════════════════════════════════════════

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const HARNESS_DIR = path.join(__dirname, 'harness');

// ─── Deterministic marker that can ONLY come from the printer catalog ─────────
// Distinctive strings so a passing assertion cannot be a coincidence with any
// static/built-in driver data device-service knows about.
const MARKER_MODEL = 'OptiPlex XSEED-9000';
const MARKER_ID = 'dell-XCROSSMARK9000';
const MARKER_NAME = 'XCROSSMARKER Chipset Driver (printer-catalog-only)';

// State shared across tests, populated in before().
const ctx = {
  tmpRoot: null,
  deviceDriversDir: null,
  deviceHardwareDir: null,
  printerDriversDir: null,
  dellCacheDir: null,
  device: null, // { proc, port, baseUrl }
  printer: null,
};

// ─── Seed the printer-service Dell catalog cache (offline, deterministic) ─────
function seedDellCatalog(dellCacheDir) {
  fs.mkdirSync(dellCacheDir, { recursive: true });
  const index = {
    cachedAt: new Date().toISOString(),
    count: 2,
    drivers: [
      {
        id: MARKER_ID,
        source: 'dell',
        name: MARKER_NAME,
        version: '9.9.9',
        vendor: 'Dell',
        os: ['windows'],
        deviceType: 'other',
        format: 'exe',
        architecture: 'x86_64',
        description: 'Seeded catalog entry that lives ONLY in printer-service.',
        downloadUrl: 'https://downloads.dell.com/FOLDER-XSEED/marker.exe',
        models: [MARKER_MODEL],
        fileSize: 12345,
        tags: ['bi'],
        licenseType: 'freeware',
        releaseDate: '2026-01-01',
      },
      {
        // A decoy for a different model, to prove filtering happens server-side.
        id: 'dell-DECOY0001',
        source: 'dell',
        name: 'Dell Decoy Audio Driver',
        version: '1.0.0',
        vendor: 'Dell',
        os: ['windows'],
        deviceType: 'audio',
        format: 'exe',
        architecture: 'x86_64',
        description: 'Should not match the XSEED-9000 query.',
        downloadUrl: 'https://downloads.dell.com/FOLDER-DECOY/decoy.exe',
        models: ['Latitude 5540'],
        fileSize: 6789,
        tags: ['au'],
        licenseType: 'freeware',
        releaseDate: '2026-01-01',
      },
    ],
  };
  // dellCatalogService trusts index.json when its mtime is < 24h old; a fresh
  // write satisfies that, so no network fetch is ever attempted.
  fs.writeFileSync(path.join(dellCacheDir, 'index.json'), JSON.stringify(index));
}

// ─── Spawn one harness process and wait for its HARNESS_READY handshake ───────
function startHarness(scriptName, extraEnv) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(HARNESS_DIR, scriptName);
    const proc = spawn(process.execPath, [scriptPath], {
      cwd: ctx.tmpRoot, // keep any stray log files inside the tmp dir
      env: {
        ...process.env,
        REPO_ROOT,
        NODE_ENV: 'integration', // NOT 'test' — keep real code paths
        ...extraEnv,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      proc.kill('SIGKILL');
      reject(new Error(`${scriptName} did not become ready in time.\nSTDERR:\n${stderr}\nSTDOUT:\n${stdout}`));
    }, 20000);

    proc.stdout.on('data', chunk => {
      stdout += chunk.toString();
      const m = stdout.match(/HARNESS_READY (\{.*\})/);
      if (m && !settled) {
        settled = true;
        clearTimeout(timer);
        const { port } = JSON.parse(m[1]);
        resolve({ proc, port, baseUrl: `http://127.0.0.1:${port}` });
      }
    });
    proc.stderr.on('data', chunk => { stderr += chunk.toString(); });

    proc.on('exit', code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`${scriptName} exited early (code ${code}).\nSTDERR:\n${stderr}\nSTDOUT:\n${stdout}`));
    });
  });
}

function stopHarness(h) {
  return new Promise(resolve => {
    if (!h || !h.proc || h.proc.exitCode !== null || h.proc.signalCode) return resolve();
    h.proc.once('exit', () => resolve());
    // Kill by PID (never pkill -f) so we only ever stop the process we spawned.
    try { h.proc.kill('SIGTERM'); } catch (_) { /* already gone */ }
    setTimeout(() => {
      try { h.proc.kill('SIGKILL'); } catch (_) {}
      resolve();
    }, 3000).unref();
  });
}

// ─────────────────────────────────────────────────────────────────────────────

before(async () => {
  ctx.tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'od-xsvc-e2e-'));
  ctx.deviceDriversDir = path.join(ctx.tmpRoot, 'device-drivers');
  ctx.deviceHardwareDir = path.join(ctx.tmpRoot, 'device-hardware');
  ctx.printerDriversDir = path.join(ctx.tmpRoot, 'printer-drivers');
  ctx.dellCacheDir = path.join(ctx.tmpRoot, 'dell-cache');

  seedDellCatalog(ctx.dellCacheDir);

  // 1) printer-harness first — device-harness needs its URL.
  ctx.printer = await startHarness('printer-harness.js', {
    DELL_CATALOG_CACHE_DIR: ctx.dellCacheDir,
    PRINTER_DRIVERS_DIR: ctx.printerDriversDir,
    DEVICE_DRIVERS_DIR: ctx.deviceDriversDir,
  });

  // 2) device-harness, pointed at the real printer-harness.
  ctx.device = await startHarness('device-harness.js', {
    DEVICE_DRIVERS_DIR: ctx.deviceDriversDir,
    DEVICE_HARDWARE_DIR: ctx.deviceHardwareDir,
    PRINTER_SERVICE_URL: ctx.printer.baseUrl,
  });
});

after(async () => {
  await stopHarness(ctx.device);
  await stopHarness(ctx.printer);
  if (ctx.tmpRoot) {
    fs.rmSync(ctx.tmpRoot, { recursive: true, force: true });
  }
});

// ─── Sanity: the seeded printer catalog is really served over HTTP ────────────
test('printer-service serves the seeded Dell catalog over real HTTP', async () => {
  const url = `${ctx.printer.baseUrl}/api/printer/catalog/dell?q=${encodeURIComponent(MARKER_MODEL)}&systemModel=${encodeURIComponent(MARKER_MODEL)}&os=windows&limit=50`;
  const res = await fetch(url);
  assert.strictEqual(res.status, 200, 'catalog/dell should respond 200');
  const body = await res.json();
  assert.strictEqual(body.success, true);
  assert.ok(Array.isArray(body.results), 'results must be an array');

  const marker = body.results.find(r => r.id === MARKER_ID);
  assert.ok(marker, `seeded marker driver ${MARKER_ID} must be returned`);
  assert.strictEqual(marker.name, MARKER_NAME);

  // Server-side filtering: the decoy (different model) must be excluded.
  assert.ok(
    !body.results.some(r => r.id === 'dell-DECOY0001'),
    'decoy for a different model must be filtered out by printer-service'
  );
});

// ─── (a) PERSISTENCE — upload lands in drivers.json on disk ───────────────────
test('driver upload persists to drivers.json on device-service disk', async () => {
  const fileBytes = Buffer.from('MZ' + 'X'.repeat(2048)); // fake driver binary
  const form = new FormData();
  form.set('driver', new Blob([fileBytes]), 'crosstest-driver.inf');
  form.set('name', 'CROSS-UPLOAD-DRIVER');
  form.set('vendor', 'Dell');
  form.set('version', '1.2.3');
  form.set('os', 'windows');
  form.set('deviceType', 'chipset');

  const res = await fetch(`${ctx.device.baseUrl}/api/drivers/upload`, {
    method: 'POST',
    body: form,
  });
  assert.strictEqual(res.status, 201, 'upload should return 201');
  const body = await res.json();
  assert.strictEqual(body.success, true);
  assert.ok(body.data && body.data.id, 'response must carry the created driver id');
  const uploadedId = body.data.id;

  // Read the persisted catalog straight from the filesystem — not the API.
  const catalogFile = path.join(ctx.deviceDriversDir, 'drivers.json');
  assert.ok(fs.existsSync(catalogFile), `${catalogFile} must exist after upload`);
  const catalog = JSON.parse(fs.readFileSync(catalogFile, 'utf8'));
  assert.ok(Array.isArray(catalog.drivers), 'drivers.json must contain a drivers array');

  const persisted = catalog.drivers.find(d => d.id === uploadedId);
  assert.ok(persisted, 'uploaded driver must be present in drivers.json on disk');
  assert.strictEqual(persisted.name, 'CROSS-UPLOAD-DRIVER');
  assert.strictEqual(persisted.vendor, 'Dell');
  assert.strictEqual(persisted.version, '1.2.3');

  // The actual driver file bytes must have been written under files/.
  assert.ok(persisted.filePath && fs.existsSync(persisted.filePath), 'driver file must be on disk');
  assert.strictEqual(fs.readFileSync(persisted.filePath).length, fileBytes.length);
});

// ─── (b) REAL CROSS-SERVICE HTTP — device consults printer over HTTP ──────────
test('report-hardware pulls a recommendation that ONLY the printer-service catalog can produce', async () => {
  const res = await fetch(`${ctx.device.baseUrl}/api/devices/report-hardware`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hostname: 'xseed-workstation-01',
      manufacturer: 'Dell',
      model: MARKER_MODEL,
      os: 'Windows 11',
      osVersion: '10.0.22631',
      hardwareIds: ['PCI\\VEN_8086&DEV_1234'],
    }),
  });
  assert.strictEqual(res.status, 200, 'report-hardware should return 200');
  const body = await res.json();
  assert.strictEqual(body.success, true);
  assert.ok(Array.isArray(body.recommendations), 'recommendations must be an array');

  // The marker driver exists nowhere in device-service — only in the seeded
  // printer-service catalog. Finding it here means device-service really
  // fetched it from printer-service over HTTP.
  const fromPrinter = body.recommendations.find(r => r.id === MARKER_ID);
  assert.ok(
    fromPrinter,
    `recommendation ${MARKER_ID} must be present — proves the real device→printer HTTP call`
  );
  assert.strictEqual(fromPrinter.name, MARKER_NAME);
  assert.strictEqual(
    fromPrinter.matchedVia,
    'dell-catalog',
    'entry must be tagged as coming from the (cross-service) Dell catalog provider'
  );

  // And the recommendation must have been persisted to disk alongside it.
  const key = 'xseed-workstation-01';
  const recRes = await fetch(`${ctx.device.baseUrl}/api/devices/${encodeURIComponent(key)}/driver-recommendations`);
  assert.strictEqual(recRes.status, 200, 'cached recommendations should be retrievable');
  const recBody = await recRes.json();
  assert.ok(
    recBody.recommendations.some(r => r.id === MARKER_ID),
    'persisted recommendations must include the printer-sourced marker'
  );
});
