'use strict';

const { Router } = require('express');
const { randomUUID } = require('node:crypto');
const { CompanyBlueprints } = require('./CompanyBlueprints');
const { etag, identifier } = require('../../../../packages/company-blueprint-contract');

function companyBlueprintRoutes(database, options = {}) {
  const router = Router(); const store = options.store || new CompanyBlueprints(database, options);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); req.companyBlueprintCorrelation = randomUUID(); res.set('X-Correlation-ID', req.companyBlueprintCorrelation);
    const suppliedBody = Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined;
    if (req.headers['x-api-key'] !== undefined || req.method !== 'GET' && Object.keys(req.query).length || req.method === 'GET' && (suppliedBody || Object.keys(req.body || {}).length)) return res.status(400).json({ error: 'Exact company blueprint request required', correlationId: req.companyBlueprintCorrelation });
    if (!['GET', 'POST', 'PUT'].includes(req.method)) return res.status(404).json({ error: 'Company blueprint operation unsupported', correlationId: req.companyBlueprintCorrelation }); next();
  });
  const route = operation => (req, res, next) => Promise.resolve().then(() => operation(req, res)).catch(next);
  const noSelectors = req => { if (Object.keys(req.query).length) throw Object.assign(new Error('Company blueprint selectors unsupported'), { status: 400 }); };
  const mutate = action => route(async (req, res) => {
    const operationId = identifier(req.headers['idempotency-key']);
    const result = await store.change(action, req.params.id, req.body, req.headers['if-match'], operationId, req.user, req.headers.authorization, req.companyBlueprintCorrelation);
    res.status(action === 'created' && result.outcome === 'applied' ? 201 : 200).json(result);
  });
  router.get('/capabilities', route(async (req, res) => { noSelectors(req); res.json(await store.capabilities(req.user, req.headers.authorization)); }));
  router.get('/', route(async (req, res) => res.json(await store.list(req.query, req.user, req.headers.authorization))));
  router.post('/', mutate('created'));
  router.get('/:id/versions/:version', route(async (req, res) => { noSelectors(req); res.json(await store.version(req.params.id, req.params.version, req.user, req.headers.authorization)); }));
  router.get('/:id/versions', route(async (req, res) => res.json(await store.versions(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/:id/history', route(async (req, res) => res.json(await store.history(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/:id', route(async (req, res) => { noSelectors(req); const result = await store.get(req.params.id, req.user, req.headers.authorization); res.set('ETag', etag(result.blueprint)).json(result); }));
  router.put('/:id', mutate('updated')); router.post('/:id/publish', mutate('published')); router.post('/:id/restore', mutate('restored'));
  router.use((_req, res) => res.status(404).json({ error: 'Company blueprint operation unsupported' }));
  router.use((error, req, res, _next) => res.status(error.status || 503).json({ error: error.status && error.status < 500 ? error.message : 'Company blueprint source or receiving evidence unavailable', correlationId: req.companyBlueprintCorrelation }));
  return router;
}
module.exports = { companyBlueprintRoutes };
