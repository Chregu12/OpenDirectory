'use strict';
const { Router } = require('express');
const { CompanyAutomation } = require('./CompanyAutomation');
const { exact, fail } = require('../../../../packages/company-automation-contract');
function companyAutomationRoutes(database, options) {
  const router = Router(); const store = new CompanyAutomation(database, options);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'HEAD') return res.status(404).json({ error: 'Automation operation unavailable' });
    if (req.headers['x-api-key'] !== undefined || req.method !== 'GET' && Object.keys(req.query).length
      || req.method === 'GET' && (Array.isArray(req.body) || Object.keys(req.body || {}).length || Number(req.headers['content-length'] || 0) || req.headers['transfer-encoding'])) return res.status(400).json({ error: 'Exact automation request required' });
    next();
  });
  const route = handler => (req, res, next) => Promise.resolve().then(() => handler(req, res)).catch(next);
  const credentials = req => [req.user, req.headers.authorization];
  const noQuery = req => { if (Object.keys(req.query).length) fail(400, 'Unexpected automation selectors'); };
  const confirmation = req => { exact(req.body, ['confirm']); if (req.body.confirm !== true) fail(400, 'Confirm automation change'); };
  const reply = (res, value, status = 200) => {
    const entity = ['grant', 'job', 'schedule'].find(key => value[key]);
    if (entity) res.set('ETag', `"company-automation-${entity}-${value[entity].id}-${value[entity].revision}"`);
    return res.status(status).json(value);
  };
  router.post('/enrollments', route(async (req, res) => res.status(201).json(await store.enroll(req.body, ...credentials(req)))));
  router.get('/enrollments/:id', route(async (req, res) => { noQuery(req); res.json(await store.enrollment(req.params.id, ...credentials(req))); }));
  router.get('/grants', route(async (req, res) => res.json(await store.grants(...credentials(req), req.query))));
  router.post('/grants', route(async (req, res) => reply(res, await store.approve(req.body, ...credentials(req)), 201)));
  router.post('/grants/:id/revoke', route(async (req, res) => reply(res, await store.revoke(req.params.id, req.body, req.headers['if-match'], ...credentials(req)))));
  for (const [name, scheduled] of [['jobs', false], ['schedules', true]]) {
    router.get('/' + name, route(async (req, res) => res.json(await store.list(req.query, ...credentials(req), scheduled))));
    router.post('/' + name, route(async (req, res) => reply(res, await store.enqueue(req.body, ...credentials(req), scheduled), 201)));
  }
  router.post('/run', route(async (req, res) => { const result = await store.run(req.body, ...credentials(req)); return result ? reply(res, result) : res.status(204).end(); }));
  router.get('/jobs/:id/result', route(async (req, res) => { noQuery(req); res.json(await store.result(req.params.id, ...credentials(req))); }));
  router.get('/jobs/:id/history', route(async (req, res) => res.json(await store.history(req.params.id, ...credentials(req), req.query))));
  for (const action of ['retry', 'cancel']) router.post('/jobs/:id/' + action, route(async (req, res) => {
    confirmation(req); reply(res, await store.changeJob(req.params.id, action, req.headers['if-match'], ...credentials(req)));
  }));
  router.post('/schedules/:id/disable', route(async (req, res) => { confirmation(req); reply(res, await store.disableSchedule(req.params.id, req.headers['if-match'], ...credentials(req))); }));
  router.use((_req, res) => res.status(404).json({ error: 'Automation operation unavailable' }));
  router.use((error, _req, res, _next) => {
    const status = error.status || ({'23505':409,'23514':409,'23503':409,'42501':503,'40001':412,'55P03':409}[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'Automation result unconfirmed; inspect durable jobs before retrying' : error.message });
  });
  return router;
}
module.exports = { companyAutomationRoutes };
