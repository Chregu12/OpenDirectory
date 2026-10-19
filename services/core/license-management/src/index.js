'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer, STATUS_CODES } = require('http');
const { PolicyLicenseClient, AdapterError, bearer, requireActive } = require('./PolicyLicenseClient');
const { registerRoutes } = require('./routes/licenseRoutes');

function createApp({ client = new PolicyLicenseClient() } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(compression());
  app.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use(cors({ origin: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',').map(value => value.trim()).filter(value => value && value !== '*'),
    methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Authorization', 'Content-Type'] }));
  app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'license-management', mode: 'canonical-adapter', canonicalApi: '/api/licenses' }));
  app.use('/api/license', rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/license', async (req, res, next) => {
    try {
      req.licenseAccess = await client.access(bearer(req.headers.authorization));
      if (!(req.method === 'GET' && ['/access', '/kiosk'].includes(req.path))) requireActive(req.licenseAccess);
      next();
    } catch (error) { next(error); }
  });
  registerRoutes(app, client);
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((error, _req, res, _next) => {
    const status = error instanceof AdapterError ? error.status : error.status === 413 ? 413 : error.type === 'entity.parse.failed' ? 400 : 503;
    if (status === 401) res.set('WWW-Authenticate', 'Bearer');
    res.status(status).json({ error: error instanceof AdapterError ? error.message : status === 400 ? 'Invalid JSON body' : status === 413 ? 'Request body exceeds the limit' : 'Canonical license adapter unavailable' });
  });
  return app;
}

function createService({ client = new PolicyLicenseClient() } = {}) {
  const app = createApp({ client }); const server = createServer(app);
  let pendingUpgrades = 0;
  server.on('upgrade', async (req, socket) => {
    socket.on('error', () => socket.destroy());
    const reject = (status, message) => {
      if (socket.destroyed) return;
      const body = JSON.stringify({ error: message, canonicalApi: '/api/licenses' });
      socket.setTimeout(0);
      socket.end(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    };
    if (req.url !== '/ws/license') return reject(404, 'WebSocket endpoint not found');
    if (pendingUpgrades >= 8) return reject(503, 'License upgrade limit reached');
    pendingUpgrades++;
    socket.setTimeout(11000, () => socket.destroy());
    try {
      const access = await client.access(bearer(req.headers.authorization));
      requireActive(access);
      reject(410, 'Legacy license event stream retired; no canonical event feed is implemented');
    } catch (error) { reject(error instanceof AdapterError ? error.status : 503, 'License stream authorization unavailable'); }
    finally { pendingUpgrades--; }
  });
  return { app, server };
}

if (require.main === module) {
  const { server } = createService();
  server.listen(Number(process.env.LICENSE_SERVICE_PORT || 3018), () => process.stdout.write('License compatibility adapter started; policy-service remains authoritative\n'));
  const stop = () => {
    server.close(() => process.exit(0));
    setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 10000).unref();
  };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
}

module.exports = { createApp, createService };
