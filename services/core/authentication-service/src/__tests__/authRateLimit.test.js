'use strict';

const express = require('express');
const request = require('supertest');
const { authRateLimit } = require('../middleware/authRateLimit');

function application(options = { skipSuccessfulRequests: true }) {
  const app = express();
  app.use(express.json());
  app.post('/login', ...authRateLimit(options), (req, res) => res.status(req.body.status || 200).json({ success: true }));
  return request(app);
}

test('successful logins and password-verified MFA prompts do not exhaust account or shared service IP limits', async () => {
  const api = application();
  for (let i = 0; i < 30; i++) {
    const status = i % 2 ? 200 : 202;
    expect((await api.post('/login').send({ username: 'alice', status })).status).toBe(status);
  }
});

test('five actual failures still throttle the normalized username and return a retry time', async () => {
  const api = application();
  for (let i = 0; i < 5; i++) expect((await api.post('/login').send({ username: ' Alice ', status: 401 })).status).toBe(401);
  const denied = await api.post('/login').send({ username: 'alice' });
  expect(denied.status).toBe(429);
  expect(denied.body.error).toBe('authentication_rate_limited');
  expect(Number(denied.headers['retry-after'])).toBeGreaterThan(0);
  expect((await api.post('/login').send({ username: 'bob' })).status).toBe(200);
});

test('successful login does not consume an additional failure slot', async () => {
  const api = application();
  for (let i = 0; i < 4; i++) expect((await api.post('/login').send({ username: 'alice', status: 401 })).status).toBe(401);
  for (let i = 0; i < 8; i++) expect((await api.post('/login').send({ username: 'alice' })).status).toBe(200);
  expect((await api.post('/login').send({ username: 'alice', status: 401 })).status).toBe(401);
  expect((await api.post('/login').send({ username: 'alice' })).status).toBe(429);
});

test('distributed username failures still exhaust the per-IP budget', async () => {
  const api = application();
  for (let i = 0; i < 20; i++) expect((await api.post('/login').send({ username: 'user-' + i, status: 401 })).status).toBe(401);
  expect((await api.post('/login').send({ username: 'other' })).status).toBe(429);
});

test('registration continues to count successful requests', async () => {
  const api = application({ skipSuccessfulRequests: false });
  for (let i = 0; i < 5; i++) expect((await api.post('/login').send({ username: 'alice' })).status).toBe(200);
  expect((await api.post('/login').send({ username: 'alice' })).status).toBe(429);
});

test('malformed usernames cannot crash the limiter', async () => {
  const api = application();
  for (const username of [null, {}, 42, '', ' ']) expect((await api.post('/login').send({ username, status: 400 })).status).toBe(400);
});
