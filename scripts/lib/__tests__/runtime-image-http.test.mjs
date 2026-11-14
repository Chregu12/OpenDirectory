import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readJson } from '../runtime-image-http.cjs';

for (const phase of ['connection', 'body']) test(`startup deadline keeps an otherwise idle child alive through ${phase}`, () => {
  const helper = fileURLToPath(new URL('../runtime-image-http.cjs', import.meta.url));
  const result = spawnSync(process.execPath, ['-e', `
    const { readJson } = require(${JSON.stringify(helper)});
    global.fetch = (_url, { signal }) => {
      const pending = () => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
      return ${JSON.stringify(phase)} === 'connection' ? pending() : Promise.resolve({ status: 200, ok: true, json: pending });
    };
    readJson('http://runtime.test/health', 25).then(() => { process.exitCode = 1; }, error => {
      if (error.message !== 'Runtime HTTP deadline exceeded') process.exitCode = 1;
      else process.stdout.write('deadline observed');
    });
  `], { encoding: 'utf8', timeout: 3000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'deadline observed');
});

test('runtime HTTP probes read actual health and authorization JSON', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(req.url === '/health' ? 200 : 401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(req.url === '/health' ? { status: 'healthy' } : { error: 'unauthorized' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = 'http://127.0.0.1:' + server.address().port;
    assert.deepEqual(await readJson(base + '/health'), { status: 200, ok: true, body: { status: 'healthy' } });
    assert.deepEqual(await readJson(base + '/private'), { status: 401, ok: false, body: { error: 'unauthorized' } });
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
