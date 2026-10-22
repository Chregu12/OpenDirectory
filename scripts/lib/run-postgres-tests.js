'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn, spawnSync } = require('child_process');

function execute(binary, args, options = {}) {
  const result = spawnSync(binary, args, { encoding: 'utf8', ...options });
  if (result.error || result.status !== 0) throw new Error(result.error?.message || result.stderr || `Command failed: ${binary}`);
  return result;
}

async function runPostgresTests({ files, environmentVariable, label }) {
  let cluster;
  let binaries;
  let started = false;
  let databaseUrl = process.env[environmentVariable];
  try {
    if (!databaseUrl) {
      const candidates = [process.env.PG_BIN, '/opt/homebrew/opt/postgresql@16/bin', '/usr/local/opt/postgresql@16/bin',
        ...['18', '17', '16', '15', '14'].map(version => `/usr/lib/postgresql/${version}/bin`)].filter(Boolean);
      binaries = candidates.find(directory => fs.existsSync(path.join(directory, 'initdb')) && fs.existsSync(path.join(directory, 'pg_ctl')));
      if (!binaries) throw new Error('Set ' + environmentVariable + ' to a disposable PostgreSQL database or PG_BIN to PostgreSQL binaries.');
      cluster = fs.mkdtempSync(path.join(os.tmpdir(), 'opendirectory-' + label + '-tests-'));
      const portProbe = net.createServer();
      await new Promise((resolve, reject) => { portProbe.once('error', reject); portProbe.listen(0, '127.0.0.1', resolve); });
      const port = portProbe.address().port;
      await new Promise(resolve => portProbe.close(resolve));
      execute(path.join(binaries, 'initdb'), ['-D', path.join(cluster, 'data'), '-U', 'postgres', '-A', 'trust', '--no-locale', '-E', 'UTF8']);
      execute(path.join(binaries, 'pg_ctl'), ['-D', path.join(cluster, 'data'), '-l', path.join(cluster, 'postgres.log'),
        '-o', `-h 127.0.0.1 -p ${port} -k ${cluster} -c max_connections=40 -c max_locks_per_transaction=256`, '-w', 'start']);
      started = true;
      databaseUrl = `postgres://postgres@127.0.0.1:${port}/postgres`;
    }
    const child = spawn(process.execPath, ['--test', ...files], {
      stdio: 'inherit', env: { ...process.env, [environmentVariable]: databaseUrl },
    });
    const interrupt = () => child.kill('SIGINT');
    const terminate = () => child.kill('SIGTERM');
    process.once('SIGINT', interrupt);
    process.once('SIGTERM', terminate);
    try {
      const result = await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (status, signal) => resolve({ status, signal }));
      });
      process.exitCode = result.status || (result.signal ? 1 : 0);
    } finally {
      process.removeListener('SIGINT', interrupt);
      process.removeListener('SIGTERM', terminate);
    }
  } finally {
    if (started) execute(path.join(binaries, 'pg_ctl'), ['-D', path.join(cluster, 'data'), '-m', 'fast', '-w', 'stop']);
    if (cluster) fs.rmSync(cluster, { recursive: true, force: true });
  }
}

module.exports = { runPostgresTests };
