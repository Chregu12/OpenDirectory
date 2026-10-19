'use strict';

const express = require('express');
const { requireLicensePermission } = require('../middleware/licenseAccess');
const { LicenseGrants, etag } = require('./LicenseGrants');

function grantRoutes(allocator) {
  const router = express.Router({ mergeParams: true });
  const grants = new LicenseGrants(allocator);
  const route = handler => (req, res, next) => Promise.resolve(handler(req, res)).catch(next);
  router.use(requireLicensePermission('licenses.assignments.read'));
  router.get('/', route(async (req, res) => {
    if (Object.keys(req.query).some(key => key !== 'after') || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'invalid_license_grant_fields' });
    res.json(await grants.list(req.params.licenseId, req.query.after));
  }));
  router.use((req, res, next) => Object.keys(req.query).length ? res.status(400).json({ error: 'invalid_license_grant_query' }) : next());
  router.get('/:id', route(async (req, res) => {
    if (Object.keys(req.body || {}).length) return res.status(400).json({ error: 'invalid_license_grant_fields' });
    const grant = await grants.get(req.params.licenseId, req.params.id);
    res.set('ETag', etag(grant)).json(grant);
  }));
  router.post('/:id/revoke', requireLicensePermission('licenses.assignments.manage'), route(async (req, res) => {
    const result = await grants.revoke(req.params.licenseId, req.params.id, req.headers['if-match'], req.body, req.user, req.licensePrincipal, req.headers.authorization);
    res.set('ETag', etag(result.grant)).json(result);
  }));
  router.use((_req, res) => res.status(404).json({ error: 'license_grant_route_not_found' }));
  router.use((error, _req, res, _next) => res.status(error.status || (['23514', '23503', '23505', '42501', '55P03', '40P01'].includes(error.code) ? 409 : 503))
    .json({ error: error.status ? error.message : 'license_grant_storage_unavailable' }));
  return router;
}

module.exports = { grantRoutes };
