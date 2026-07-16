'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// device-harness — boots the REAL device-service driver + hardware-detection
// routers as a standalone HTTP process, WITHOUT the full device-service
// index.js (no Postgres, no Redis, no RabbitMQ, no WebSocket cluster).
//
// It mounts:
//   services/core/device-service/src/routes/driverRoutes.js          → /api/drivers
//   services/core/device-service/src/routes/deviceDetectionRoutes.js → /api/devices
//
// Both routers use the real FileDriverRepository / FileHardwareReportRepository
// (file persistence under DEVICE_DRIVERS_DIR / DEVICE_HARDWARE_DIR) and the
// real driverMatchingService, which performs a genuine cross-service HTTP GET
// to PRINTER_SERVICE_URL + /api/printer/catalog/dell. Nothing is duplicated;
// every module is required straight from the repo.
//
// Required env (set by the spawning test before this process starts):
//   REPO_ROOT             — absolute path to the repo root
//   DEVICE_DRIVERS_DIR    — file-repo dir for the driver catalog (drivers.json)
//   DEVICE_HARDWARE_DIR   — file-repo dir for hardware reports / recommendations
//   PRINTER_SERVICE_URL   — base URL of the running printer-harness
//
// On listen it prints one line to stdout:  HARNESS_READY {"port":<n>}
// ─────────────────────────────────────────────────────────────────────────────

const path = require('path');

const REPO_ROOT = process.env.REPO_ROOT;
if (!REPO_ROOT) {
  console.error('device-harness: REPO_ROOT env is required');
  process.exit(2);
}

const SERVICE_DIR = path.join(REPO_ROOT, 'services/core/device-service');
// Resolve express from the device-service's own node_modules (this harness
// dir has none of its own) so we reuse the exact dependency the service ships.
const express = require(require.resolve('express', { paths: [SERVICE_DIR] }));

const driverRoutesPath = path.join(SERVICE_DIR, 'src/routes/driverRoutes.js');
const deviceDetectionRoutesPath = path.join(SERVICE_DIR, 'src/routes/deviceDetectionRoutes.js');

// Require the REAL routers (pull in DriverApplicationService, the file
// repositories and driverMatchingService — the cross-service HTTP client).
const driverRoutes = require(driverRoutesPath);
const deviceDetectionRoutes = require(deviceDetectionRoutesPath);

const app = express();
app.use(express.json({ limit: '10mb' }));

app.use('/api/drivers', driverRoutes);
app.use('/api/devices', deviceDetectionRoutes);

app.get('/__ping', (_req, res) => res.json({ ok: true }));

const server = app.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  process.stdout.write(`HARNESS_READY ${JSON.stringify({ port })}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
