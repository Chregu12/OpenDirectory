'use strict';

const { Router } = require('express');
const { randomUUID } = require('node:crypto');
const { CompanyBlueprintAssignments } = require('./licenses/CompanyBlueprintAssignments');
const { identifier, revision } = require('../../../../packages/company-blueprint-contract');

function companyBlueprintAssignmentRoutes(database, options = {}) {
  const router = Router(); const store = options.store || new CompanyBlueprintAssignments(database, options);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); req.companyBlueprintAssignmentCorrelation = randomUUID(); res.set('X-Correlation-ID', req.companyBlueprintAssignmentCorrelation);
    const suppliedBody = Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined;
    if (req.headers['x-api-key'] !== undefined || req.method !== 'GET' && Object.keys(req.query).length
      || req.method === 'GET' && (suppliedBody || Array.isArray(req.body) || Object.keys(req.body || {}).length)) return res.status(400).json({ error: 'Exact company blueprint assignment request required', correlationId: req.companyBlueprintAssignmentCorrelation });
    if (!['GET', 'POST'].includes(req.method)) return res.status(404).json({ error: 'Company blueprint assignment operation unsupported', correlationId: req.companyBlueprintAssignmentCorrelation }); next();
  });
  const route = operation => (req, res, next) => Promise.resolve().then(() => operation(req, res)).catch(next);
  const noSelectors = req => { if (Object.keys(req.query).length) throw Object.assign(new Error('Company blueprint assignment selectors unsupported'), { status: 400 }); };
  const mutate = action => route(async (req, res) => {
    const operationId = identifier(req.headers['idempotency-key']);
    const result = await store.change(action, req.params.id, req.body, req.headers['if-match'], operationId, req.user, req.headers.authorization, req.companyBlueprintAssignmentCorrelation);
    res.status(action === 'assigned' && result.outcome === 'applied' ? 201 : 200).json(result);
  });
  router.get('/capabilities', route(async (req, res) => { noSelectors(req); res.json(await store.capabilities(req.user, req.headers.authorization)); }));
  router.get('/users/:userId/effective', route(async (req, res) => { noSelectors(req); res.json(await store.effective(req.params.userId, req.user, req.headers.authorization)); }));
  router.post('/preview', route(async (req, res) => res.json(await store.preview(req.body, req.user, req.headers.authorization))));
  router.get('/', route(async (req, res) => res.json(await store.list(req.query, req.user, req.headers.authorization))));
  router.post('/', mutate('assigned'));
  router.get('/:id/removal-preview', route(async (req, res) => {
    noSelectors(req); const result = await store.removalPreview(req.params.id, req.user, req.headers.authorization);
    res.set('ETag', `"company-blueprint-assignment-${identifier(result.assignment.id)}-${revision(result.assignment.revision)}"`).json(result);
  }));
  router.get('/:id', route(async (req, res) => {
    noSelectors(req); const result = await store.get(req.params.id, req.user, req.headers.authorization);
    res.set('ETag', `"company-blueprint-assignment-${identifier(result.assignment.id)}-${revision(result.assignment.revision)}"`).json(result);
  }));
  router.post('/:id/remove', mutate('removed'));
  router.use((_req, res) => res.status(404).json({ error: 'Company blueprint assignment operation unsupported' }));
  router.use((error, req, res, _next) => {
    const status = error.status || ({ '40001': 412, '23505': 409, '23514': 409, '23503': 409, '42501': 503, '22P02': 400, '22023': 400, '22003': 409, '55P03': 409, '57014': 503 }[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'Company blueprint assignment authority or receiving evidence unavailable' : error.message, correlationId: req.companyBlueprintAssignmentCorrelation });
  });
  return router;
}
module.exports = { companyBlueprintAssignmentRoutes };
