'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

test.each([['browser', 'test-browser.js', 'browser.postgres.cjs'], ['OAuth', 'test-postgres.js', 'revocations.postgres.cjs']])('Node 20 %s filters partition the literal integration cases into nonempty fresh groups', async (_label, script, cases) => {
  const directory = path.join(__dirname, '../../scripts');
  const runs = [];
  await vm.runInNewContext(fs.readFileSync(path.join(directory, script), 'utf8'), {
    __dirname: directory,
    require: id => id.endsWith('/run-postgres-tests')
      ? { runPostgresTests: async options => { runs.push(options); } }
      : require(id),
    process: { exitCode: 0 },
    console,
  });
  const source = fs.readFileSync(path.join(__dirname, cases), 'utf8');
  const names = [...source.matchAll(/^test\('([^'\\\r\n]+)'/gm)].map(match => match[1]);
  expect(names.length).toBe(source.match(/^test\(/gm).length);
  expect(names.length).toBeGreaterThan(0);
  const filters = runs.map(({ files }) => {
    expect(files[0]).toMatch(/^--test-name-pattern=/);
    expect(files).toContain(path.join(__dirname, cases));
    return new RegExp(files[0].slice('--test-name-pattern='.length));
  });
  for (const name of names) expect(filters.filter(filter => filter.test(name))).toHaveLength(1);
  for (const filter of filters) expect(names.some(name => filter.test(name))).toBe(true);
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'od-browser-filter-'));
  const probe = path.join(folder, 'probe.cjs');
  try {
    fs.writeFileSync(probe, `const { test } = require('node:test'); for (const name of ${JSON.stringify(names)}) test(name, () => console.log('EXECUTED ' + JSON.stringify(name)));`);
    for (let index = 0; index < runs.length; index++) {
      const result = spawnSync(process.execPath, ['--test', runs[index].files[0], probe], { encoding: 'utf8', timeout: 10000 });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      const executed = [...result.stdout.matchAll(/^# EXECUTED (.+)$/gm)].map(match => JSON.parse(match[1]));
      expect(executed).toEqual(names.filter(name => filters[index].test(name)));
    }
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
});
