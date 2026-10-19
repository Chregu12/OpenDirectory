'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// printer-harness — boots the REAL printer-service catalog router as a
// standalone HTTP process, WITHOUT the full printer-service index.js
// (no oidcAuth, no Postgres, no CUPS, no RabbitMQ).
//
// It mounts services/core/printer-service/src/routes/catalogRoutes.js at
// /api/printer/catalog — exactly the path device-service's
// driverMatchingService calls (`${PRINTER_SERVICE_URL}/api/printer/catalog/dell`).
//
// The real DriverCatalogApplicationService → dellCatalogService chain is used
// unchanged. dellCatalogService loads its data from a cached index.json in
// DELL_CATALOG_CACHE_DIR when that file is fresh (< 24 h) — the integration
// test seeds that file, so NO network download happens and the catalog content
// is fully deterministic. All service logic is required from the repo; nothing
// is duplicated here.
//
// Required env (set by the spawning test before this process starts):
//   REPO_ROOT               — absolute path to the repo root
//   DELL_CATALOG_CACHE_DIR  — dir holding the seeded index.json
//   PRINTER_DRIVERS_DIR     — file-repo dir for printer drivers
//   DEVICE_DRIVERS_DIR      — file-repo dir for device drivers (import target)
//
// On listen it prints one line to stdout:  HARNESS_READY {"port":<n>}
// ─────────────────────────────────────────────────────────────────────────────

const path = require('path');

const REPO_ROOT = process.env.REPO_ROOT;
if (!REPO_ROOT) {
  console.error('printer-harness: REPO_ROOT env is required');
  process.exit(2);
}

const SERVICE_DIR = path.join(REPO_ROOT, 'services/core/printer-service');
// Resolve express from the printer-service's own node_modules (this harness
// dir has none of its own) so we reuse the exact dependency the service ships.
const express = require(require.resolve('express', { paths: [SERVICE_DIR] }));

const catalogRoutesPath = path.join(SERVICE_DIR, 'src/routes/catalogRoutes.js');

// Require the REAL router (pulls in DriverCatalogApplicationService +
// dellCatalogService + FilePrinterDriverRepository, resolved against
// printer-service/node_modules).
const catalogRoutes = require(catalogRoutesPath);

const app = express();
app.use(express.json({ limit: '10mb' }));

// Mount at the exact path device-service expects.
app.use('/api/printer/catalog', catalogRoutes);

// Trivial liveness probe used only by the harness handshake.
app.get('/__ping', (_req, res) => res.json({ ok: true }));

const server = app.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  process.stdout.write(`HARNESS_READY ${JSON.stringify({ port })}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
  // Safety net if a keep-alive socket lingers.
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
