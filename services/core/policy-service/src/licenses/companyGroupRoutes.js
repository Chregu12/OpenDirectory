'use strict';
const { Router } = require('express');
const { identifier } = require('../../../../../packages/company-license-contract');
const { CompanyLicenseGroups } = require('./CompanyLicenseGroups');
function companyGroupRoutes(companies, options) {
  const router = Router(); const store = new CompanyLicenseGroups(companies, options);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'HEAD') return res.status(404).json({ error: 'Company license group operation unsupported' });
    if (req.headers['x-api-key'] !== undefined || req.method !== 'GET' && Object.keys(req.query).length
      || req.method === 'GET' && (Object.keys(req.body || {}).length || Number(req.headers['content-length'] || 0) || req.headers['transfer-encoding'])) return res.status(400).json({ error: 'Exact company license group request required' });
    next();
  });
  const route = handler => (req, res, next) => Promise.resolve().then(() => handler(req, res)).catch(next);
  const reply = (res, value, status = 200) => res.status(status).set('ETag', `"company-license-group-${value.rule.id}-${value.rule.revision}"`).json(value);
  router.get('/', route(async (req, res) => res.json(await store.list(req.query, req.user, req.headers.authorization))));
  router.post('/', route(async (req, res) => reply(res, await store.link(req.body, identifier(req.headers['idempotency-key']), req.user, req.headers.authorization), 201)));
  router.get('/:id/preview', route(async (req, res) => { if (Object.keys(req.query).length) throw Object.assign(new Error('Exact group preview required'), { status: 400 }); reply(res, await store.preview(req.params.id, req.user, req.headers.authorization)); }));
  router.post('/:id/sync', route(async (req, res) => reply(res, await store.sync(req.params.id, req.body, req.user, req.headers.authorization))));
  router.post('/:id/unlink', route(async (req, res) => reply(res, await store.unlink(req.params.id, req.body, req.headers['if-match'], identifier(req.headers['idempotency-key']), req.user, req.headers.authorization))));
  router.use((_req, res) => res.status(404).json({ error: 'Company license group operation unsupported' }));
  router.use((error, _req, res, _next) => {
    const status = error.status || ({ '23505': 409, '40001': 412, P0002: 404, '23514': 409, '42501': 503 }[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'License group source or receiving evidence unavailable; earlier member operations may be committed' : error.message });
  });
  return router;
}
module.exports = { companyGroupRoutes };
