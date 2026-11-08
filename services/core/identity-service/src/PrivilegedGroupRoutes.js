'use strict';
const { Router } = require('express');
const { PrivilegedGroups } = require('./PrivilegedGroups');
const { fields, uuid } = require('./PrivilegedActivation');
function privilegedGroupRoutes(database) {
  const router = Router(); const groups = new PrivilegedGroups(database);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'HEAD') return res.status(404).json({ error: 'pim_group_method_unsupported' });
    if (req.headers['x-api-key'] !== undefined || (req.method === 'GET' && (Object.keys(req.body || {}).length || Number(req.headers['content-length'] || 0) || req.headers['transfer-encoding']))) return res.status(400).json({ error: 'exact_pim_group_request_required' });
    next();
  });
  const route = handler => (req, res, next) => Promise.resolve().then(() => handler(req, res)).catch(next);
  router.get('/', route(async (req, res) => { fields(req.query, []); res.json(await groups.catalog(req.user)); }));
  router.post('/', route(async (req, res) => { fields(req.query, []); res.status(201).json(await groups.create(req.body, req.user, req.headers.authorization)); }));
  router.post('/initialize', route(async (req, res) => { fields(req.query, []); res.json(await groups.initialize(req.body, req.user, req.headers.authorization)); }));
  router.post('/:id/disable', route(async (req, res) => { fields(req.query, []); res.json(await groups.disable(req.params.id, req.body, req.user, req.headers.authorization)); }));
  router.get('/:id/members', route(async (req, res) => res.json(await groups.members(req.params.id, req.query, req.user))));
  router.get('/:id/history', route(async (req, res) => res.json(await groups.history(req.params.id, req.query, req.user))));
  router.post('/:id/eligibilities', route(async (req, res) => {
    fields(req.query, []); fields(req.body, ['userId', 'maxDurationSeconds', 'validForSeconds', 'reason', 'confirm']);
    if (req.body.confirm !== true) return res.status(400).json({ error: 'explicit_pim_group_confirmation_required' });
    const { confirm, ...input } = req.body; const groupId = uuid(req.params.id);
    const eligibility = await groups.pim.grantEligibility({ ...input, groupId }, req.user, req.headers.authorization);
    res.status(201).json({ schemaVersion: 1, groupId, eligibility });
  }));
  router.use((_req, res) => res.status(404).json({ error: 'pim_group_operation_unsupported' }));
  router.use((error, _req, res, _next) => res.status(error.status || ({ '23505': 409, '23503': 404, '23514': 409, '40001': 409, '55P03': 409 }[error.code]) || 503).json({ error: error.code || 'pim_group_result_unconfirmed' }));
  return router;
}
module.exports = { privilegedGroupRoutes };
