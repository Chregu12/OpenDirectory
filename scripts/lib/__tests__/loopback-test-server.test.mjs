import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { listenLoopback, closeServer } from '../loopback-test-server.cjs';

test('HTTP fixtures listen on the same IPv4 address their clients actually call', async () => {
  const held = await listenLoopback((_req, res) => { res.statusCode = 401; res.end('other-fixture'); });
  const target = await listenLoopback((_req, res) => res.end('original-fixture'));
  try {
    assert.equal(target.address().address, '127.0.0.1');
    assert.equal(target.address().family, 'IPv4');
    assert.notEqual(target.address().port, held.address().port);
    const response = await fetch('http://127.0.0.1:' + target.address().port + '/health');
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'original-fixture');
  } finally { await closeServer(target); await closeServer(held); }
});
test('a supplied server retains its handler and fixture teardown waits for the actual socket to close', async () => {
  const supplied = createServer((_req, res) => res.end('supplied-handler'));
  const bound = await listenLoopback(supplied);
  assert.equal(bound, supplied);
  assert.equal(await (await fetch('http://127.0.0.1:' + bound.address().port)).text(), 'supplied-handler');
  await closeServer(bound);
  assert.equal(bound.listening, false);
});
