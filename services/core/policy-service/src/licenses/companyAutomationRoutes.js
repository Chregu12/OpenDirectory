'use strict';
const { Router } = require('express');
const { CompanyLicenseAutomation } = require('./CompanyLicenseAutomation');
function companyAutomationRoutes(database, options) {
  const router = Router(); const service = new CompanyLicenseAutomation(database, options);
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method !== 'POST') return res.status(404).json({ error: 'App license operation unavailable' });
    if (req.headers['x-api-key'] !== undefined || Object.keys(req.query).length) return res.status(400).json({ error: 'Exact app license request required' }); next();
  });
  router.post('/observe', (req,res,next)=>Promise.resolve().then(()=>service.observe(req.body,req.user,req.headers.authorization)).then(value=>res.json(value)).catch(next));
  router.post('/step', (req, res, next) => Promise.resolve().then(() => service.step(req.body, req.user, req.headers.authorization)).then(value => res.json(value)).catch(next));
  router.use((_req, res) => res.status(404).json({ error: 'App license operation unavailable' }));
  router.use((error, _req, res, _next) => {
    const status = error.status || ({ '40001': 412, '23505': 409, '23514': 409 }[error.code]) || 503;
    res.status(status).json({ error: status >= 500 ? 'License step unconfirmed; inspect durable member receipts' : error.message });
  }); return router;
}
module.exports = { companyAutomationRoutes };
