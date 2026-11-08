'use strict';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'health-test-only';
process.env.ADMIN_PASSWORD = 'HealthTest123!';
jest.mock('../db', () => ({ initDb: jest.fn(async () => {}), isAvailable: () => true,
  query: jest.fn(async () => ({ rows: [] })), pool: { end: jest.fn() } }));
const request = require('supertest');
const db = require('../db');
const { app } = require('../server');

test('health checks the current database connection on every request', async () => {
  const healthy = await request(app).get('/api/health');
  expect(healthy.status).toBe(200);
  expect(healthy.body.data.services.database).toBe('connected');
  expect(healthy.body.data.services.ldap).toBe('not-checked');
  db.query.mockImplementation(async sql => {
    if (sql === 'SELECT 1') throw new Error('Connection lost');
    return { rows: [] };
  });
  const failed = await request(app).get('/api/health');
  expect(failed.status).toBe(503);
  expect(failed.body.success).toBe(false);
  expect(failed.body.data.stats.users).toBeNull();
});

test('production startup fails instead of serving an in-memory fallback when PostgreSQL is unavailable', () => {
  const result = require('child_process').spawnSync(process.execPath, ['server.js'], {
    cwd: require('path').resolve(__dirname, '..'),
    env: { ...process.env, NODE_ENV: 'production', JWT_SECRET: 'startup-test-only', ADMIN_PASSWORD: 'StartupTest123!', DATABASE_URL: '', DB_HOST: '127.0.0.1', DB_PORT: '1', PORT: '0' },
    encoding: 'utf8', timeout: 8000,
  });
  expect(result.error).toBeUndefined();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('PostgreSQL is required');
}, 10000);
