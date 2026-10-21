'use strict';

const { Router } = require('express');
const { randomUUID } = require('node:crypto');
const { CompanyLicenses } = require('./CompanyLicenses');
const { CompanyOffboarding } = require('./CompanyOffboarding');
const { poolEtag, offboardingEtag } = require('../../../../../packages/company-license-contract');
function companyLicenseRoutes(allocator, options) {
  const router = Router(); const store = new CompanyLicenses(allocator, options);
  const offboarding = new CompanyOffboarding(store, options?.offboarding);
  router.use('/groups', require('./companyGroupRoutes').companyGroupRoutes(store, options?.groups));
  router.use('/v2', require('./companyV2Routes').companyLicenseV2Routes(store.v2, offboarding.v2));
  router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); req.companyLicenseCorrelation = randomUUID(); res.set('X-Correlation-ID', req.companyLicenseCorrelation);
    if (req.headers['x-api-key'] || req.method !== 'GET' && Object.keys(req.query).length || req.method === 'GET' && Object.keys(req.body || {}).length) return res.status(400).json({ error: 'Exact company license request required' }); next(); });
  const route = operation => (req, res, next) => Promise.resolve().then(() => operation(req, res)).catch(next);
  const reply = (res, pool, status = 200) => res.status(status).set('ETag', poolEtag(pool)).json(pool);
  const workflow = (res, result, status = 200) => res.status(status).set('ETag', offboardingEtag(result.workflow)).json(result);
  const noSelectors = req => { if (Object.keys(req.query).length) throw Object.assign(new Error('Offboarding selectors unsupported'), { status: 400 }); };
  router.get('/offboarding-workflows/capabilities', route(async (req, res) => { noSelectors(req); res.json(await offboarding.capabilities(req.user, req.headers.authorization)); }));
  router.get('/offboarding-workflows', route(async (req, res) => res.json(await offboarding.list(req.query, req.user, req.headers.authorization))));
  router.post('/offboarding-workflows', route(async (req, res) => {
    const result = await offboarding.create(req.body, req.user, req.headers.authorization); workflow(res, result.result, result.created ? 201 : 200);
  }));
  router.get('/offboarding-workflows/:id/history', route(async (req, res) => res.json(await offboarding.history(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/offboarding-workflows/:id', route(async (req, res) => { noSelectors(req); workflow(res, await offboarding.get(req.params.id, req.user, req.headers.authorization)); }));
  router.post('/offboarding-workflows/:id/continue', route(async (req, res) => workflow(res, await offboarding.continue(req.params.id, req.body, req.headers['if-match'], req.user, req.headers.authorization))));
  router.get('/users/:userId/offboarding-preview', route(async (req, res) => { noSelectors(req); res.json(await offboarding.preview(req.params.userId, req.user, req.headers.authorization)); }));
  router.get('/capabilities', route(async (req, res) => { if (Object.keys(req.query).length) throw Object.assign(new Error('Company capability selectors unsupported'), { status: 400 }); res.json(await store.capabilities(req.user, req.headers.authorization)); }));
  router.get('/pools', route(async (req, res) => res.json(await store.list(req.query, req.user, req.headers.authorization))));
  router.get('/users/:userId/license-returns', route(async (req, res) => res.json(await store.returnPreview(req.params.userId, req.query, req.user, req.headers.authorization))));
  router.post('/users/:userId/license-returns', route(async (req, res) => {
    const result = await store.returnLicenses(req.params.userId, req.body, req.user, req.headers.authorization, req.companyLicenseCorrelation);
    res.status(result.results.every(item => item.status === 'released') ? 200 : 207).json(result);
  }));
  router.post('/pools', route(async (req, res) => reply(res, await store.create(req.body, req.user, req.headers.authorization, req.companyLicenseCorrelation), 201)));
  router.get('/pools/:id/assignments', route(async (req, res) => res.json(await store.assignments(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/pools/:id/history', route(async (req, res) => res.json(await store.history(req.params.id, req.query, req.user, req.headers.authorization))));
  router.get('/pools/:id/edit-capabilities', route(async (req, res) => { noSelectors(req); res.json(await store.editCapabilities(req.params.id, req.user, req.headers.authorization)); }));
  router.get('/pools/:id', route(async (req, res) => { if (Object.keys(req.query).length) throw Object.assign(new Error('Company pool selectors unsupported'), { status: 400 }); reply(res, await store.get(req.params.id, req.user, req.headers.authorization)); }));
  router.patch('/pools/:id', route(async (req, res) => reply(res, await store.update(req.params.id, req.body, req.headers['if-match'], req.user, req.headers.authorization, req.companyLicenseCorrelation))));
  router.post('/pools/:id/assignments', route(async (req, res) => reply(res, await store.assign(req.params.id, req.body, req.headers['if-match'], req.user, req.headers.authorization, req.companyLicenseCorrelation), 201)));
  router.post('/pools/:id/assignments/:assignmentId/revoke', route(async (req, res) => reply(res, await store.revoke(req.params.id, req.params.assignmentId, req.body, req.headers['if-match'], req.user, req.headers.authorization, req.companyLicenseCorrelation))));
  router.use((_req, res) => res.status(404).json({ error: 'Company license operation unsupported' }));
  router.use((error, req, res, _next) => {
    const status = error.status || ({ '40001': 412, '23505': 409, '23514': 409, '23503': 409, '42501': 503, '22P02': 400, '22003': 409, '55P03': 409, '57014': 503 }[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'Persistent company license source or receiving evidence unavailable' : error.message, correlationId: req.companyLicenseCorrelation });
  });
  return router;
}
module.exports = { companyLicenseRoutes };
