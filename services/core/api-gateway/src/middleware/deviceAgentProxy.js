'use strict';

const { createProxyMiddleware } = require('http-proxy-middleware');

// Receiver authenticates single-use enrollment / device-only credentials independently.
function deviceAgentProxy(target) {
  const origin = new URL(target);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('Invalid device agent receiver');
  const proxy = createProxyMiddleware({ target, changeOrigin: true, proxyTimeout: 10000, timeout: 12000 });
  return (req, res, next) => {
    if (!req.path.startsWith('/api/device-agent')) return next();
    res.set('Cache-Control', 'no-store');
    if (req.method !== 'POST' || !['/api/device-agent/register', '/api/device-agent/heartbeat'].includes(req.path) || Object.keys(req.query).length) return res.status(404).json({ error: 'Agent operation not found' });
    if (req.headers['x-api-key'] || req.headers['x-enrollment-token']) return res.status(401).json({ error: 'Device-only credentials required' });
    proxy(req, res, next);
  };
}
module.exports = { deviceAgentProxy };
