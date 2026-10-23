'use strict';
const { Router } = require('express'); const { CompanyGroupRules } = require('./CompanyGroupRules'); const { etag } = require('../../../../packages/company-group-rule-contract');
function companyGroupRuleRoutes(database, options) {
 const router = Router({ mergeParams: true }); const service = new CompanyGroupRules(database, options);
 router.use((req, res, next) => { res.set('Cache-Control', 'no-store');
  if (req.method === 'HEAD') return res.status(404).json({ error: 'Group rule operation unavailable' });
  if (req.headers['x-api-key'] !== undefined || Object.keys(req.query).some(key => req.method !== 'GET' || req.path !== '/history' || key !== 'page') || req.method === 'GET' && (Object.keys(req.body || {}).length || Number(req.headers['content-length'] || 0) || req.headers['transfer-encoding'])) return res.status(400).json({ error: 'Exact group rule request required' }); next();
 });
 const route = handler => (req, res, next) => Promise.resolve().then(() => handler(req, res)).catch(next);
 const credentials = req => [req.user, req.headers.authorization];
 router.get('/', route(async (req, res) => { const value = await service.get(req.params.id, ...credentials(req)); res.set('ETag', value.etag).json(value); }));
 router.put('/', route(async (req, res) => { const value = await service.save(req.params.id, req.body, req.headers['if-match'], req.headers['idempotency-key'], ...credentials(req)); res.set('ETag', etag(value.rule.groupId, value.rule.revision)).json(value); }));
 router.get('/preview', route(async (req, res) => res.json(await service.preview(req.params.id, ...credentials(req)))));
 router.get('/history', route(async (req, res) => res.json(await service.history(req.params.id, req.query, ...credentials(req)))));
 router.post('/sync', route(async (req, res) => res.json(await service.sync(req.params.id, req.body, ...credentials(req)))));
 router.use((_req, res) => res.status(404).json({ error: 'Group rule operation unavailable' }));
 router.use((error, _req, res, _next) => { const status = error.status || ({ '42501': 503, '23514': 409, '23503': 404, '23505': 409, '40001': 412, '55P03': 409, '57014': 503 }[error.code]) || 503;
  res.status(status).json({ error: status >= 500 ? 'Group rule result unconfirmed; inspect retained state before retrying' : error.message });
 }); return router;
}
module.exports = { companyGroupRuleRoutes };
