'use strict';

const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const compression  = require('compression');
const rateLimit    = require('express-rate-limit');

const { ping, SERVICES } = require('./utils/serviceClient');

const servicePrincipalOrchestrator  = require('./orchestrators/servicePrincipalOrchestrator');
const deviceEnrollmentOrchestrator  = require('./orchestrators/deviceEnrollmentOrchestrator');
const userOnboardingOrchestrator    = require('./orchestrators/userOnboardingOrchestrator');
const policyOrchestrator            = require('./orchestrators/policyOrchestrator');

const PORT = parseInt(process.env.PORT, 10) || 3950;

const app = express();

// ── Middleware ─────────────────────────────────────────────────────────────────

app.use(helmet());
app.use(compression());
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '1mb' }));

// Rate limiter: 200 requests per minute per IP
app.use('/api/', rateLimit({
  windowMs: 60_000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please slow down.' },
}));

// ── Request logging ────────────────────────────────────────────────────────────

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ── Error wrapper ──────────────────────────────────────────────────────────────

/**
 * Wrap an async route handler — catches unhandled rejections and returns 500.
 */
function wrap(fn) {
  return async (req, res) => {
    try {
      await fn(req, res);
    } catch (err) {
      console.error('[quick-actions] Unhandled error:', err);
      res.status(500).json({ success: false, error: err.message || 'Internal server error' });
    }
  };
}

// ── Health ─────────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'quick-actions', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

/**
 * Ping all downstream services and return a unified status report.
 * GET /api/quick/status
 */
app.get('/api/quick/status', wrap(async (_req, res) => {
  const serviceKeys = Object.keys(SERVICES);
  const results = await Promise.all(serviceKeys.map(k => ping(k)));

  const statuses = {};
  let   anyUnhealthy = false;
  for (let i = 0; i < serviceKeys.length; i++) {
    const key    = serviceKeys[i];
    const result = results[i];
    // Use the Kubernetes service name as the display key
    const svcName = SERVICES[key].replace('http://', '');
    statuses[svcName] = result;
    if (!result.healthy) anyUnhealthy = true;
  }

  const healthyCount = results.filter(r => r.healthy).length;
  const overall = healthyCount === results.length
    ? 'healthy'
    : healthyCount === 0 ? 'unhealthy' : 'degraded';

  res.json({ services: statuses, overall, checkedAt: new Date().toISOString() });
}));

// ── Service Principals ─────────────────────────────────────────────────────────

/**
 * POST /api/quick/service-principals
 * Create a new service principal (app identity across AD/Kerberos/auth).
 * Body: { appName, description, permissions[], createdBy }
 */
app.post('/api/quick/service-principals', wrap(async (req, res) => {
  const result = await servicePrincipalOrchestrator.createServicePrincipal(req.body);
  res.status(result.success ? 201 : 207).json(result);
}));

/**
 * GET /api/quick/service-principals
 * List all service principals.
 */
app.get('/api/quick/service-principals', wrap(async (_req, res) => {
  const result = await servicePrincipalOrchestrator.listServicePrincipals();
  res.json(result);
}));

/**
 * GET /api/quick/service-principals/:id
 * Get full details for a single service principal.
 */
app.get('/api/quick/service-principals/:id', wrap(async (req, res) => {
  const result = await servicePrincipalOrchestrator.getServicePrincipalDetails(req.params.id);
  res.json(result);
}));

/**
 * DELETE /api/quick/service-principals/:id
 * Revoke and delete a service principal from all systems.
 */
app.delete('/api/quick/service-principals/:id', wrap(async (req, res) => {
  const result = await servicePrincipalOrchestrator.deleteServicePrincipal(req.params.id);
  res.json(result);
}));

/**
 * POST /api/quick/service-principals/:id/rotate-secret
 * Generate a new client secret and propagate it everywhere.
 */
app.post('/api/quick/service-principals/:id/rotate-secret', wrap(async (req, res) => {
  const result = await servicePrincipalOrchestrator.rotateServicePrincipalSecret(req.params.id);
  res.json(result);
}));

// ── Device Enrollment ──────────────────────────────────────────────────────────

/**
 * POST /api/quick/devices/enroll
 * Enroll a single device (OS-aware: macos | windows | linux | ios | android).
 * Body: { platform, deviceName, serialNumber?, enrollmentToken?, assignedUserId?, ouDn? }
 */
app.post('/api/quick/devices/enroll', wrap(async (req, res) => {
  const result = await deviceEnrollmentOrchestrator.enrollDevice(req.body);
  res.status(result.success ? 201 : 207).json(result);
}));

/**
 * POST /api/quick/devices/bulk-enroll
 * Enroll multiple devices in parallel.
 * Body: { devices: [...] }
 */
app.post('/api/quick/devices/bulk-enroll', wrap(async (req, res) => {
  const { devices } = req.body;
  if (!Array.isArray(devices) || devices.length === 0) {
    return res.status(400).json({ success: false, error: 'devices must be a non-empty array' });
  }
  const result = await deviceEnrollmentOrchestrator.bulkEnroll(devices);
  res.json(result);
}));

/**
 * GET /api/quick/devices/:id/enrollment-status
 * Get the MDM/AD enrollment status for a device.
 */
app.get('/api/quick/devices/:id/enrollment-status', wrap(async (req, res) => {
  const result = await deviceEnrollmentOrchestrator.getEnrollmentStatus(req.params.id);
  res.json(result);
}));

/**
 * POST /api/quick/devices/:id/unenroll
 * Unenroll a device; optionally trigger a remote wipe.
 * Body: { wipe: boolean }
 */
app.post('/api/quick/devices/:id/unenroll', wrap(async (req, res) => {
  const { wipe = false } = req.body;
  const result = await deviceEnrollmentOrchestrator.unenrollDevice(req.params.id, { wipe });
  res.json(result);
}));

// ── User Lifecycle ─────────────────────────────────────────────────────────────

/**
 * POST /api/quick/users/onboard
 * Onboard a new employee — creates AD user, auth account, role, group, welcome email.
 * Body: { firstName, lastName, email, department?, jobTitle?, role?, manager?, assignDeviceId? }
 */
app.post('/api/quick/users/onboard', wrap(async (req, res) => {
  const result = await userOnboardingOrchestrator.onboardUser(req.body);
  res.status(result.success ? 201 : 207).json(result);
}));

/**
 * POST /api/quick/users/:id/offboard
 * Offboard a departing employee — disable account, revoke privileges, unassign devices.
 * Body: { revokeDevices?, transferFilesTo?, disableAccount? }
 */
app.post('/api/quick/users/:id/offboard', wrap(async (req, res) => {
  const result = await userOnboardingOrchestrator.offboardUser(req.params.id, req.body);
  res.json(result);
}));

// ── Policy ─────────────────────────────────────────────────────────────────────

/**
 * POST /api/quick/policies/deploy
 * Deploy a policy to a target (user, group, OU, device, or all).
 * Body: { policyId, targetType, targetId?, enforced?, dryRun? }
 */
app.post('/api/quick/policies/deploy', wrap(async (req, res) => {
  const result = await policyOrchestrator.deployPolicy(req.body);
  res.status(result.success ? 200 : 207).json(result);
}));

/**
 * GET /api/quick/policies/deployments/:id
 * Get the status of a specific policy deployment.
 */
app.get('/api/quick/policies/deployments/:id', wrap(async (req, res) => {
  const result = await policyOrchestrator.getPolicyDeploymentStatus(req.params.id);
  if (!result.success) return res.status(404).json(result);
  res.json(result);
}));

/**
 * POST /api/quick/policies/deployments/:id/rollback
 * Roll back a policy deployment.
 */
app.post('/api/quick/policies/deployments/:id/rollback', wrap(async (req, res) => {
  const result = await policyOrchestrator.rollbackPolicy(req.params.id);
  res.json(result);
}));

/**
 * GET /api/quick/compliance/snapshot
 * Get a quick overview of device compliance across all policies.
 */
app.get('/api/quick/compliance/snapshot', wrap(async (_req, res) => {
  const result = await policyOrchestrator.getComplianceSnapshot();
  res.json(result);
}));

// ── 404 fallback ───────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

// ── Global error handler ───────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[quick-actions] Express error handler:', err);
  res.status(500).json({ success: false, error: err.message || 'Internal server error' });
});

// ── Start ──────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[quick-actions] Service started on port ${PORT}`);
  console.log(`[quick-actions] Routes available:`);
  console.log('  POST   /api/quick/service-principals');
  console.log('  GET    /api/quick/service-principals');
  console.log('  GET    /api/quick/service-principals/:id');
  console.log('  DELETE /api/quick/service-principals/:id');
  console.log('  POST   /api/quick/service-principals/:id/rotate-secret');
  console.log('  POST   /api/quick/devices/enroll');
  console.log('  POST   /api/quick/devices/bulk-enroll');
  console.log('  GET    /api/quick/devices/:id/enrollment-status');
  console.log('  POST   /api/quick/devices/:id/unenroll');
  console.log('  POST   /api/quick/users/onboard');
  console.log('  POST   /api/quick/users/:id/offboard');
  console.log('  POST   /api/quick/policies/deploy');
  console.log('  GET    /api/quick/policies/deployments/:id');
  console.log('  POST   /api/quick/policies/deployments/:id/rollback');
  console.log('  GET    /api/quick/compliance/snapshot');
  console.log('  GET    /api/quick/status');
  console.log('  GET    /health');
});

module.exports = app;
