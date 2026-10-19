'use strict';

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');

test('real signed tokens pass through the unmocked verifier and operation guards against a local JWKS', async () => {
  const { stdout } = await promisify(execFile)(process.execPath, [path.join(__dirname, 'fixtures/signedAuthorization.cjs')], { timeout: 15000 });
  const result = /Signed authorization: (\d+) checks passed/.exec(stdout);
  expect(Number(result?.[1])).toBeGreaterThanOrEqual(28);
});
