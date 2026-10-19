'use strict';

const express = require('express');
const { LicenseReviews, policyTag, reviewTag } = require('./LicenseReviews');
function reviewRoutes(allocator) {
  const router = express.Router(); const reviews = new LicenseReviews(allocator);
  const route = handler => (req, res, next) => Promise.resolve(handler(req, res)).catch(next);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (Object.keys(req.query).length || req.method === 'GET' && Object.keys(req.body || {}).length) return res.status(400).json({ error: 'invalid_review_fields' });
    next();
  });
  router.get('/policies/:licenseId', route(async (req, res) => {
    const result = await reviews.policy(req.params.licenseId, req.user, req.licensePrincipal);
    if (result.policy) res.set('ETag', policyTag(result.policy)); res.json(result);
  }));
  router.post('/policies', route(async (req, res) => {
    const result = await reviews.create(req.body, req.user, req.licensePrincipal, req.headers.authorization); res.status(201).set('ETag', policyTag(result)).json(result);
  }));
  router.post('/policies/:id/retire', route(async (req, res) => {
    const result = await reviews.retire(req.params.id, req.headers['if-match'], req.body, req.user, req.licensePrincipal, req.headers.authorization); res.set('ETag', policyTag(result)).json(result);
  }));
  router.get('/self', route(async (req, res) => res.json(await reviews.self(req.user, req.licensePrincipal))));
  router.get('/:id', route(async (req, res) => { const result = await reviews.get(req.params.id, req.user, req.licensePrincipal); res.set('ETag', reviewTag(result)).json(result); }));
  router.post('/:id/decisions', route(async (req, res) => { const result = await reviews.decide(req.params.id, req.headers['if-match'], req.body, req.user, req.licensePrincipal, req.headers.authorization); res.set('ETag', reviewTag(result)).json(result); }));
  router.use((_req, res) => res.status(404).json({ error: 'license_review_route_not_found' }));
  router.use((error, _req, res, _next) => res.status(error.status || (['23505', '23514', '23503', '42501', '55P03', '40P01'].includes(error.code) ? 409 : 503))
    .json({ error: error.status ? error.message : 'license_reviews_unavailable' }));
  return router;
}
module.exports = { reviewRoutes };
