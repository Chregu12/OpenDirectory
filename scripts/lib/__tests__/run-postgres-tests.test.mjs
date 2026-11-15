import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const helper = fileURLToPath(new URL('../run-postgres-tests.js', import.meta.url));
let folder;
before(() => { folder = mkdtempSync(join(tmpdir(), 'od-runner-selection-')); });
after(() => { rmSync(folder, { recursive: true, force: true }); });

function run(source, flags = []) {
  const file = join(folder, 'case.cjs');
  writeFileSync(file, source);
  const env = { ...process.env, RUNNER_TEST_DATABASE_URL: 'postgres://unused.invalid/no-connection' };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['-e', `
    require(${JSON.stringify(helper)}).runPostgresTests({
      files: ${JSON.stringify([...flags, file])}, environmentVariable: 'RUNNER_TEST_DATABASE_URL', label: 'selection'
    }).catch(error => { console.error(error.message); process.exitCode = 1; });
  `], { encoding: 'utf8', timeout: 10000, env });
  assert.equal(result.error, undefined);
  return result;
}

test('a misspelled filter cannot pass with every real case skipped', () => {
  const result = run("require('node:test').test('actual integration case', () => {});", ['--test-name-pattern=^misspelled-name$']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /TAP version 13/);
  assert.match(result.stderr, /No passing integration tests completed/);
});

test('an entirely skipped suite cannot pass as integration coverage', () => {
  const result = run("require('node:test').test('provider unavailable', { skip: true }, () => {});");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /No passing integration tests completed/);
});

test('an empty suite cannot substitute for an executed test case', () => {
  const result = run("require('node:test').describe('empty integration suite', () => {});");
  assert.equal(result.status, 1);
  assert.match(result.stdout, /^# pass 0$/m);
});

test('a synthetic file pass cannot substitute for an executed test case', () => {
  const result = run("console.log('module loaded without tests');");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /No passing integration tests completed/);
});

test('a completed real case passes alongside deliberately skipped cases', () => {
  const result = run("const { test } = require('node:test'); test('actual case', () => {}); test('separate provider case', { skip: true }, () => {});");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^# pass 1$/m);
  assert.match(result.stdout, /^# skipped 1$/m);
  assert.equal(result.stderr, '');
});

test('real failure stays nonzero even when another test passes', () => {
  const result = run("const { test } = require('node:test'); test('actual pass', () => {}); test('actual failure', () => { throw new Error('deliberate failure'); });");
  assert.equal(result.status, 1);
  assert.match(result.stdout, /deliberate failure/);
  assert.match(result.stdout, /^# pass 1$/m);
  assert.doesNotMatch(result.stderr, /No passing integration tests completed/);
});

test('test output cannot forge a passing native summary', () => {
  const result = run("console.log('# pass 99'); require('node:test').test('not executed', { skip: true }, () => {});");
  assert.equal(result.status, 1);
  assert.match(result.stdout, /^# pass 0$/m);
});
