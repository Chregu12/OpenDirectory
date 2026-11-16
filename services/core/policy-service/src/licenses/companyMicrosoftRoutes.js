'use strict';

const { Router } = require('express');
const { randomUUID } = require('node:crypto');
const { identifier } = require('../../../../../packages/company-license-contract');
const { validRevision } = require('../../../../../packages/identity-authorization-contract');
const { CompanyMicrosoftBridge } = require('./CompanyMicrosoftBridge');
const { CompanyMicrosoftDelivery } = require('./CompanyMicrosoftDelivery');
const { exact } = require('../../../../../packages/company-license-contract');

function etag(kind, row) { return `"company-microsoft-${kind}-${row.id}-${row.revision}"`; }
function precondition(value, kind, id = null) {
  const match = typeof value === 'string' && value.match(new RegExp(`^"company-microsoft-${kind}-([a-f0-9-]{36})-([1-9][0-9]*)"$`));
  if (!match || !validRevision(match[2])) throw Object.assign(new Error('Current Microsoft binding version required'), { status: 428 });
  identifier(match[1]);
  if (id !== null && match[1] !== id) throw Object.assign(new Error('Microsoft binding changed'), { status: 412 });
  return { id: match[1], revision: match[2] };
}
function companyMicrosoftRoutes(companies, options) {
  const router = Router(); const bridge = new CompanyMicrosoftBridge(companies, options); const delivery = new CompanyMicrosoftDelivery(bridge, options?.delivery);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); res.set('X-Correlation-ID', randomUUID());
    if (!['GET', 'POST'].includes(req.method)) return res.status(404).json({ error: 'Microsoft operation unsupported' });
    if (req.headers['x-api-key'] !== undefined || req.method === 'POST' && Object.keys(req.query).length
      || req.method === 'GET' && (Object.keys(req.body || {}).length || Number(req.headers['content-length'] || 0) || req.headers['transfer-encoding'] !== undefined))
      return res.status(400).json({ error: 'Exact company Microsoft request required' });
    next();
  });
  const route = handler => (req, res, next) => Promise.resolve().then(() => handler(req, res)).catch(next);
  const noQuery = req => { if (Object.keys(req.query).length) throw Object.assign(new Error('Microsoft selectors unsupported'), { status: 400 }); };
  const key = req => identifier(req.headers['idempotency-key']);
  const reply = (res, result, kind, field, status = 200) => res.status(result.historical ? 200 : status).set('ETag', etag(kind, result[field])).json(result);
  router.get('/state', route(async (req, res) => { noQuery(req); const result = await bridge.state(req.user, req.headers.authorization); if (result.connection) res.set('ETag', etag('connection', result.connection)); res.json(result); }));
  router.get('/products', route(async (req, res) => {
    noQuery(req); const controller = new AbortController(); const abort = () => controller.abort(); res.once('close', abort);
    try { const result = await bridge.products(req.user, req.headers.authorization, controller.signal); if (!controller.signal.aborted) res.json(result); }
    finally { res.removeListener('close', abort); }
  }));
  router.get('/pools/:id/mappings', route(async (req, res) => res.json(await bridge.mappings(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/history', route(async (req, res) => res.json(await bridge.history(req.query, req.user, req.headers.authorization))));
  router.post('/pools/:id/users/:userId/preview', route(async (req, res) => { exact(req.body, []); res.json(await delivery.preview(req.params.id, req.params.userId, req.user, req.headers.authorization)); }));
  router.post('/connections', route(async (req, res) => reply(res, await bridge.connect(req.body, key(req), req.user, req.headers.authorization), 'connection', 'connection', 201)));
  router.post('/connections/:id/renew', route(async (req, res) => reply(res, await bridge.connect(req.body, key(req), req.user, req.headers.authorization,
    precondition(req.headers['if-match'], 'connection', identifier(req.params.id))), 'connection', 'connection')));
  router.post('/pools/:id/bind', route(async (req, res) => reply(res, await bridge.bindPool(req.params.id, req.body,
    precondition(req.headers['if-match'], 'connection'), key(req), req.user, req.headers.authorization), 'pool', 'pool', 201)));
  router.post('/users/:id/bind', route(async (req, res) => reply(res, await bridge.bindUser(req.params.id, req.body,
    precondition(req.headers['if-match'], 'connection'), key(req), req.user, req.headers.authorization), 'user', 'user', 201)));
  for (const [path, kind] of [['connections', 'connection'], ['pool-mappings', 'pool'], ['user-mappings', 'user']]) {
    router.post(`/${path}/:id/retire`, route(async (req, res) => reply(res, await bridge.retire(kind, req.params.id,
      precondition(req.headers['if-match'], kind, identifier(req.params.id)).revision, key(req), req.body, req.user, req.headers.authorization), kind, 'binding')));
  }
  router.use((_req, res) => res.status(404).json({ error: 'Microsoft operation unsupported' }));
  router.use((error, _req, res, _next) => {
    const status = error.status || ({ '40001': 412, '23505': 409, '23514': 409, '23503': 409, P0002: 404, '42501': 503, '22P02': 400, '55P03': 409, '57014': 503 }[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'Company Microsoft source, configuration or provider unavailable' : error.message });
  });
  return router;
}
module.exports = { companyMicrosoftRoutes, etag, precondition };
