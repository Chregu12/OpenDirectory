'use strict';

const { Router } = require('express');
const { randomUUID } = require('node:crypto');
const { identifier, offboardingEtag } = require('../../../../../packages/company-license-contract');

function companyLicenseV2Routes(store, offboarding) {
  const router = Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); req.companyLicenseCorrelation = randomUUID(); res.set('X-Correlation-ID', req.companyLicenseCorrelation);
    const suppliedBody = Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined;
    if (req.headers['x-api-key'] !== undefined || req.method !== 'GET' && Object.keys(req.query).length
      || req.method === 'GET' && (suppliedBody || Array.isArray(req.body) || Object.keys(req.body || {}).length)) return res.status(400).json({ error: 'Exact company license protocol 2 request required', correlationId: req.companyLicenseCorrelation });
    if (!['GET', 'POST'].includes(req.method)) return res.status(404).json({ error: 'Company license protocol 2 operation unsupported', correlationId: req.companyLicenseCorrelation }); next();
  });
  const route = operation => (req, res, next) => Promise.resolve().then(() => operation(req, res)).catch(next);
  const noSelectors = req => { if (Object.keys(req.query).length) throw Object.assign(new Error('Company license protocol 2 selectors unsupported'), { status: 400 }); };
  const key = req => identifier(req.headers['idempotency-key']);
  const workflow = (res, result, status = 200) => res.status(status).set('ETag', offboardingEtag(result.workflow)).json(result);
  router.get('/capabilities', route(async (req, res) => { noSelectors(req); res.json(await store.capabilities(req.user, req.headers.authorization)); }));
  router.get('/pools/:id/assignments', route(async (req, res) => res.json(await store.assignments(req.params.id, req.query, req.user, req.headers.authorization))));
  router.post('/pools/:id/assignment-preview', route(async (req, res) => res.json(await store.assignmentPreview(req.params.id, req.body, req.user, req.headers.authorization))));
  router.post('/pools/:id/assignments', route(async (req, res) => {
    const result = await store.assign(req.params.id, req.body, req.headers['if-match'], key(req), req.user, req.headers.authorization, req.companyLicenseCorrelation);
    res.status(result.outcome === 'applied' ? 201 : 200).json(result);
  }));
  router.post('/pools/:id/assignments/:assignmentId/revoke', route(async (req, res) => res.json(await store.revoke(req.params.id, req.params.assignmentId, req.body, req.headers['if-match'], key(req), req.user, req.headers.authorization, req.companyLicenseCorrelation))));
  router.get('/users/:userId/license-returns', route(async (req, res) => res.json(await store.returnPreview(req.params.userId, req.query, req.user, req.headers.authorization))));
  router.post('/users/:userId/license-returns', route(async (req, res) => res.json(await store.returnLicenses(req.params.userId, req.body, key(req), req.user, req.headers.authorization, req.companyLicenseCorrelation))));
  router.get('/offboarding-workflows/capabilities', route(async (req, res) => { noSelectors(req); res.json(await offboarding.capabilities(req.user, req.headers.authorization)); }));
  router.get('/offboarding-workflows', route(async (req, res) => res.json(await offboarding.list(req.query, req.user, req.headers.authorization))));
  router.post('/offboarding-workflows', route(async (req, res) => {
    const result = await offboarding.create(req.body, key(req), req.user, req.headers.authorization); workflow(res, result.result, result.created ? 201 : 200);
  }));
  router.get('/offboarding-workflows/:id/history', route(async (req, res) => res.json(await offboarding.history(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/offboarding-workflows/:id', route(async (req, res) => { noSelectors(req); workflow(res, await offboarding.get(req.params.id, req.user, req.headers.authorization)); }));
  router.post('/offboarding-workflows/:id/continue', route(async (req, res) => workflow(res, await offboarding.continue(req.params.id, req.body, req.headers['if-match'], key(req), req.user, req.headers.authorization))));
  router.get('/users/:userId/offboarding-preview', route(async (req, res) => { noSelectors(req); res.json(await offboarding.preview(req.params.userId, req.user, req.headers.authorization)); }));
  router.use((_req, res) => res.status(404).json({ error: 'Company license protocol 2 operation unsupported' }));
  router.use((error, req, res, _next) => {
    const status = error.status || ({ '40001': 412, '23505': 409, '23514': 409, '23503': 409, '42501': 503, '22P02': 400, '22023': 400, '22003': 409, '55P03': 409, '57014': 503 }[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'Company license protocol 2 source or receiving evidence unavailable' : error.message, correlationId: req.companyLicenseCorrelation });
  });
  return router;
}
module.exports = { companyLicenseV2Routes };
