'use strict';

// End-to-end characterization tests for the printer-service printer
// CRUD / deployment / print-job-queue slice (routes/printerRoutes.js +
// application/PrinterApplicationService.js). Boots the real router on an
// ephemeral port.
//
// External infrastructure is faked at the module boundary, not the business
// logic under test:
//   - 'pg'  → an in-memory Pool that understands the small set of SQL shapes
//             printerManager.js / printQueue.js actually issue.
//   - 'bull'→ a stub Queue (real Bull eagerly connects to Redis on
//             construction, which isn't available here).
//   - 'ipp' → a stub Printer whose execute() always reports success.
// CUPS is faked by passing a plain object (not services/cups.js) into
// PrinterManager's constructor — PrinterManager only ever calls a handful
// of methods on it, and cups.js itself shells out to `lpadmin`/`lpstat`
// which isn't installed here either.
//
// These tests intentionally document some pre-existing quirks of the
// current contract rather than "fixing" them, e.g. GET /api/printers/:id
// and GET /api/jobs/:id return 500 (not 404) for a missing id, because the
// route's catch-all doesn't special-case the repository's generic
// "not found" Error. The refactor must preserve this behavior exactly.
//
//   npx jest src/__tests__/printersE2E.test.js

const express = require('express');

// ─── Fake PostgreSQL ('pg') ────────────────────────────────────────────────
// A tiny in-memory SQL engine that understands exactly the query shapes used
// by printerManager.js and printQueue.js (INSERT ... RETURNING *, UPDATE ...
// SET <dynamic fields> WHERE id = $N, DELETE ... WHERE id = $1, SELECT ...
// WHERE id = $1, SELECT ... WHERE 1=1 ... ORDER BY ...). Each `new Pool()`
// call gets its own isolated table store, mirroring one manager instance
// per test suite.
jest.mock('pg', () => {
  function createFakePool() {
    const tables = new Map();
    let seq = 1;
    const table = (name) => {
      if (!tables.has(name)) tables.set(name, new Map());
      return tables.get(name);
    };
    const nextId = () => `fake-${seq++}`;

    async function query(sql, values = []) {
      const s = sql.replace(/\s+/g, ' ').trim();
      let m;

      if (/^CREATE (TABLE|INDEX)/i.test(s)) return { rows: [], rowCount: 0 };

      if ((m = s.match(/^INSERT INTO (\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)(\s+RETURNING \*)?/i))) {
        const tbl = m[1];
        const cols = m[2].split(',').map(c => c.trim());
        const row = {};
        cols.forEach((col, i) => { row[col] = values[i] !== undefined ? values[i] : null; });
        row.id = row.id || nextId();
        if (!('created_at' in row))   row.created_at = new Date().toISOString();
        if (!('updated_at' in row))   row.updated_at = new Date().toISOString();
        if (tbl === 'print_jobs' && !('submitted_at' in row)) row.submitted_at = new Date().toISOString();
        if (tbl === 'printers') {
          row.total_jobs = row.total_jobs ?? 0;
          row.page_count = row.page_count ?? 0;
        }
        table(tbl).set(row.id, row);
        return { rows: m[4] ? [row] : [], rowCount: 1 };
      }

      if ((m = s.match(/^UPDATE (\w+)\s+SET (.+?)\s+WHERE id = \$(\d+)(\s+RETURNING \*)?$/i))) {
        const tbl = m[1];
        const id = values[Number(m[3]) - 1];
        const row = table(tbl).get(id);
        if (row) {
          m[2].split(',').forEach(part => {
            const mm = part.trim().match(/^(\w+)\s*=\s*(?:\$(\d+)|CURRENT_TIMESTAMP)/i);
            if (mm) row[mm[1]] = mm[2] ? values[Number(mm[2]) - 1] : new Date().toISOString();
          });
        }
        return { rows: row && m[4] ? [row] : [], rowCount: row ? 1 : 0 };
      }

      if ((m = s.match(/^DELETE FROM (\w+) WHERE id = \$1$/i))) {
        const existed = table(m[1]).delete(values[0]);
        return { rows: [], rowCount: existed ? 1 : 0 };
      }

      if ((m = s.match(/^SELECT \* FROM (\w+) WHERE id = \$1$/i))) {
        const row = table(m[1]).get(values[0]);
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }

      if ((m = s.match(/^SELECT \* FROM (\w+) WHERE 1=1/i))) {
        const rows = [...table(m[1]).values()];
        return { rows, rowCount: rows.length };
      }

      throw new Error(`FakePgPool: unhandled SQL: ${s}`);
    }

    return { query: jest.fn(query) };
  }

  return { Pool: jest.fn(() => createFakePool()) };
});

// ─── Fake Bull queue (Redis-backed in production) ─────────────────────────
jest.mock('bull', () => jest.fn().mockImplementation(() => ({
  process: jest.fn(),
  on: jest.fn(),
  add: jest.fn().mockResolvedValue({ id: 'bull-job-1' }),
  getJob: jest.fn().mockResolvedValue(null),
  getWaitingCount: jest.fn().mockResolvedValue(0),
  getActiveCount: jest.fn().mockResolvedValue(0),
  getCompletedCount: jest.fn().mockResolvedValue(0),
  getFailedCount: jest.fn().mockResolvedValue(0),
  pause: jest.fn().mockResolvedValue(),
  resume: jest.fn().mockResolvedValue(),
  empty: jest.fn().mockResolvedValue(),
})));

// ─── Fake IPP client (used by the test-print flow) ────────────────────────
jest.mock('ipp', () => ({
  Printer: jest.fn().mockImplementation(() => ({
    execute: (op, msg, cb) => cb(null, { statusCode: 'successful-ok' }),
  })),
}));

// ─── HTTP helper ────────────────────────────────────────────────────────────

function request(port, method, reqPath, body) {
  const http = require('http');
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1', port, method, path: reqPath,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
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

// ─── Suite ────────────────────────────────────────────────────────────────

jest.setTimeout(20000);

let appServer, appPort;
let printerManager, printQueue, appService;

beforeAll(async () => {
  const PrinterManager = require('../services/printerManager');
  const PrintJobQueue = require('../services/printQueue');
  // NOTE: services/deployment.js currently has a syntax error (an
  // unescaped PowerShell backtick line-continuation inside a JS template
  // literal around line 107) and fails to `require()` at all. index.js
  // guards the require in a try/catch and falls back to a no-op stub
  // (generateConfig() → '', deployPrinters() → []); that guard — not the
  // real PrinterDeployment class — is what actually runs in production
  // today. Mirror it here so the characterization test reflects the true
  // current contract rather than the (currently unreachable) real logic.
  let PrinterDeployment;
  try { PrinterDeployment = require('../services/deployment'); }
  catch (e) { PrinterDeployment = class { generateConfig() { return ''; } deployPrinters() { return []; } }; }
  const PrinterDiscoveryService = require('../services/discovery');
  const { PrinterApplicationService } = require('../application/PrinterApplicationService');
  const createPrinterRoutes = require('../routes/printerRoutes');

  // Fake CUPS: PrinterManager only calls a handful of methods on it, and the
  // real services/cups.js shells out to `lpadmin`/`lpstat`, which isn't
  // installed in this environment either — so a plain stub is injected
  // directly rather than mocking services/cups.js.
  const fakeCups = {
    addPrinter: jest.fn().mockResolvedValue({ success: true }),
    removePrinter: jest.fn().mockResolvedValue({ success: true }),
    updatePrinter: jest.fn().mockResolvedValue({ success: true }),
    getPrinterInfo: jest.fn().mockResolvedValue({ state: 3, stateReasons: null, pagesPrinted: 0 }),
  };

  printerManager = new PrinterManager(fakeCups);
  printQueue = new PrintJobQueue();
  const deployment = new PrinterDeployment();
  const discovery = new PrinterDiscoveryService();

  appService = new PrinterApplicationService({ printerManager, discovery, deployment, printQueue });

  const app = express();
  app.use(express.json());
  app.use(createPrinterRoutes(appService));

  await new Promise(resolve => {
    appServer = app.listen(0, '127.0.0.1', () => {
      appPort = appServer.address().port;
      resolve();
    });
  });
});

afterAll(async () => {
  await new Promise(r => appServer.close(r));
});

// ─── Printer CRUD ───────────────────────────────────────────────────────────

describe('printer CRUD', () => {
  let printerId;

  test('POST /api/printers/add creates a printer', async () => {
    const res = await request(appPort, 'POST', '/api/printers/add', {
      name: 'hp-floor2', address: '10.0.0.5', protocol: 'ipp', location: 'Floor 2',
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.printer.name).toBe('hp-floor2');
    expect(res.json.printer.id).toBeDefined();
    printerId = res.json.printer.id;
  });

  test('GET /api/printers lists the created printer', async () => {
    const res = await request(appPort, 'GET', '/api/printers');
    expect(res.status).toBe(200);
    expect(res.json.printers.some(p => p.id === printerId)).toBe(true);
  });

  test('GET /api/printers/:id returns the printer', async () => {
    const res = await request(appPort, 'GET', `/api/printers/${printerId}`);
    expect(res.status).toBe(200);
    expect(res.json.printer.id).toBe(printerId);
    expect(res.json.printer.address).toBe('10.0.0.5');
  });

  test('GET /api/printers/:id for an unknown id currently returns 500, not 404 (pre-existing contract)', async () => {
    const res = await request(appPort, 'GET', '/api/printers/does-not-exist');
    expect(res.status).toBe(500);
    expect(res.json.error).toMatch(/not found/i);
  });

  test('PUT /api/printers/:id updates the printer', async () => {
    const res = await request(appPort, 'PUT', `/api/printers/${printerId}`, { location: 'Floor 3' });
    expect(res.status).toBe(200);
    expect(res.json.printer.location).toBe('Floor 3');
  });

  test('DELETE /api/printers/:id removes the printer', async () => {
    const res = await request(appPort, 'DELETE', `/api/printers/${printerId}`);
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);

    const after = await request(appPort, 'GET', `/api/printers/${printerId}`);
    expect(after.status).toBe(500); // same pre-existing "not found → 500" quirk
  });
});

// ─── Frontend-compatible printer routes ────────────────────────────────────

describe('frontend-compatible printer routes (/api/printer/printers)', () => {
  test('POST rejects a payload missing name with 400', async () => {
    const res = await request(appPort, 'POST', '/api/printer/printers', { ip: '10.0.0.9' });
    expect(res.status).toBe(400);
    expect(res.json.error).toMatch(/name/i);
  });

  test('POST rejects a payload missing address with 400', async () => {
    const res = await request(appPort, 'POST', '/api/printer/printers', { name: 'no-ip-printer' });
    expect(res.status).toBe(400);
    expect(res.json.error).toMatch(/address/i);
  });

  test('POST creates a printer and maps it to the frontend shape', async () => {
    const res = await request(appPort, 'POST', '/api/printer/printers', {
      name: 'frontend-printer', ip: '10.0.0.42', protocol: 'IPP', model: 'LaserJet',
    });
    expect(res.status).toBe(200);
    expect(res.json.ip).toBe('10.0.0.42');
    expect(res.json.protocol).toBe('IPP');
    expect(res.json.id).toBeDefined();

    const list = await request(appPort, 'GET', '/api/printer/printers');
    expect(list.status).toBe(200);
    expect(list.json.some(p => p.id === res.json.id)).toBe(true);

    const del = await request(appPort, 'DELETE', `/api/printer/printers/${res.json.id}`);
    expect(del.status).toBe(200);
    expect(del.json.success).toBe(true);
  });
});

// ─── Probe endpoint ─────────────────────────────────────────────────────────

describe('POST /api/printer/probe', () => {
  test('400 when ip is missing', async () => {
    const res = await request(appPort, 'POST', '/api/printer/probe', {});
    expect(res.status).toBe(400);
  });

  test('404 when nothing responds on the common printer ports', async () => {
    const res = await request(appPort, 'POST', '/api/printer/probe', { ip: '127.0.0.1' });
    expect(res.status).toBe(404);
    expect(res.json.error).toMatch(/no printer found/i);
  });
});

// ─── Test print / job log ──────────────────────────────────────────────────

describe('POST /api/printer/jobs (IPP test print) + GET /api/printer/jobs (job log)', () => {
  test('400 when printer_name is missing', async () => {
    const res = await request(appPort, 'POST', '/api/printer/jobs', {});
    expect(res.status).toBe(400);
  });

  test('404 when printer_name does not match any known printer', async () => {
    const res = await request(appPort, 'POST', '/api/printer/jobs', { printer_name: 'ghost-printer' });
    expect(res.status).toBe(404);
    expect(res.json.error).toMatch(/ghost-printer/);
  });

  test('sends a test page and records it in the job log', async () => {
    const add = await request(appPort, 'POST', '/api/printers/add', {
      name: 'test-print-target', address: '10.0.0.77', protocol: 'ipp',
    });
    expect(add.status).toBe(200);

    const res = await request(appPort, 'POST', '/api/printer/jobs', {
      printer_name: 'test-print-target', user_name: 'jdoe',
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.message).toMatch(/test-print-target/);

    const log = await request(appPort, 'GET', '/api/printer/jobs?printer=test-print-target');
    expect(log.status).toBe(200);
    expect(log.json.data[0]).toMatchObject({
      printer: 'test-print-target', user: 'jdoe', status: 'completed',
    });
  });
});

// ─── Deployment ─────────────────────────────────────────────────────────────

describe('deployment endpoints', () => {
  // services/deployment.js fails to load in this environment (see the
  // require guard in beforeAll) — production falls back to a no-op stub,
  // so both endpoints currently succeed but return empty results
  // regardless of input. That is the real current contract.

  test('POST /api/deployment/generate responds 200 with the (currently empty) stub config', async () => {
    const res = await request(appPort, 'POST', '/api/deployment/generate', {
      platform: 'windows',
      printers: [{ name: 'hp-floor2', uri: 'ipp://10.0.0.5/ipp/print' }],
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.config).toBe('');
  });

  test('POST /api/deployment/deploy responds 200 with the (currently empty) stub result', async () => {
    const res = await request(appPort, 'POST', '/api/deployment/deploy', {
      targetDevices: [{ id: 'device-1' }],
      printers: [{ name: 'hp-floor2', uri: 'ipp://10.0.0.5/ipp/print' }],
      platform: 'windows',
    });
    expect(res.status).toBe(200);
    expect(res.json.result).toEqual([]);
  });
});

// ─── Print job queue (read/cancel) ─────────────────────────────────────────

describe('print job queue (read/cancel)', () => {
  let jobId;

  test('seed a job directly through printQueue (POST /api/print stays out of scope — see report)', async () => {
    const job = await printQueue.addJob({
      printerId: 'printer-abc', userId: 'jdoe', document: 'raw text', documentType: 'raw',
    });
    expect(job.id).toBeDefined();
    jobId = job.id;
  });

  test('GET /api/jobs lists the seeded job', async () => {
    const res = await request(appPort, 'GET', '/api/jobs');
    expect(res.status).toBe(200);
    expect(res.json.jobs.some(j => j.id === jobId)).toBe(true);
  });

  test('GET /api/jobs/:id returns the job', async () => {
    const res = await request(appPort, 'GET', `/api/jobs/${jobId}`);
    expect(res.status).toBe(200);
    expect(res.json.job.id).toBe(jobId);
  });

  test('GET /api/jobs/:id for an unknown id currently returns 500, not 404 (pre-existing contract)', async () => {
    const res = await request(appPort, 'GET', '/api/jobs/does-not-exist');
    expect(res.status).toBe(500);
  });

  test('DELETE /api/jobs/:id cancels the job', async () => {
    const res = await request(appPort, 'DELETE', `/api/jobs/${jobId}`);
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
  });
});
