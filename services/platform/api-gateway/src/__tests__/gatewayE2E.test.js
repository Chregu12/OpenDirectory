'use strict';

/**
 * E2E tests for the platform API gateway.
 *
 * Boots the REAL gateway (src/index.js) as a child process on an ephemeral
 * port with an unreachable Redis — the gateway must degrade gracefully
 * (log errors, keep serving) instead of crashing. Exactly this used to
 * kill the process: the Redis subscriber had no error handler, so
 * "Redis down" meant "gateway down".
 *
 *   npx jest src/__tests__/gatewayE2E.test.js
 */

const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

const GATEWAY_DIR = path.join(__dirname, '..', '..');
const PORT = 39000 + Math.floor(Math.random() * 900);

function get(reqPath, method = 'GET', body) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request({
      host: '127.0.0.1', port: PORT, path: reqPath, method,
      headers: payload
        ? { 'Content-Type': 'application/json', 'Content-Length': payload.length }
        : {},
      timeout: 5000,
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (_) {}
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitForHealth(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const res = await get('/health');
      if (res.status === 200) return;
    } catch (err) { lastErr = err; }
    await new Promise(r => setTimeout(r, 400));
  }
  throw new Error(`Gateway did not become healthy: ${lastErr?.message}`);
}

jest.setTimeout(40000);

let child;

beforeAll(async () => {
  // The winston file transport writes to logs/ relative to the cwd.
  fs.mkdirSync(path.join(GATEWAY_DIR, 'logs'), { recursive: true });

  child = spawn('node', ['src/index.js'], {
    cwd: GATEWAY_DIR,
    env: {
      ...process.env,
      API_GATEWAY_PORT: String(PORT),
      // Deliberately unreachable Redis: the gateway must survive this.
      REDIS_HOST: '127.0.0.1',
      REDIS_PORT: '1',
      LOG_LEVEL: 'error',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let exited = false;
  child.on('exit', () => { exited = true; });

  await waitForHealth();
  expect(exited).toBe(false);
});

afterAll(() => {
  if (child && !child.killed) child.kill('SIGKILL');
});

describe('boot resilience (no Redis available)', () => {
  test('gateway serves /health despite an unreachable Redis', async () => {
    const res = await get('/health');
    expect(res.status).toBe(200);
    expect(res.json.status).toBe('no-services');
    expect(res.json.gateway).toHaveProperty('uptime');
  });

  test('gateway stays alive after a registration attempt that needs Redis', async () => {
    // Registration persists to Redis — with Redis down this may fail,
    // but it must fail as an HTTP error, never crash the process.
    await get('/gateway/register', 'POST', {
      id: 'test-service', name: 'test-service', host: '127.0.0.1', port: 39999,
    }).catch(() => {});

    const res = await get('/health');
    expect(res.status).toBe(200);
  });
});

describe('service routing & path extraction', () => {
  test('GET /services lists registered services (none)', async () => {
    const res = await get('/services');
    expect(res.status).toBe(200);
  });

  test('unknown service id is extracted from /api/<id>/… and reported in the 404', async () => {
    const res = await get('/api/devices/foo');
    expect(res.status).toBe(404);
    expect(res.json.serviceId).toBe('devices');
    expect(Array.isArray(res.json.availableServices)).toBe(true);
  });

  test('service id extraction handles deep paths', async () => {
    const res = await get('/api/some-unknown/a/b/c');
    expect(res.status).toBe(404);
    expect(res.json.serviceId).toBe('some-unknown');
  });

  test('non-API routes get the unregistered-route response with help text', async () => {
    const res = await get('/definitely/not/api');
    expect(res.status).toBe(404);
    expect(res.json.error).toBe('Route not found');
    expect(res.json).toHaveProperty('help');
  });
});
