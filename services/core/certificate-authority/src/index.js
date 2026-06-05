'use strict';
require('dotenv').config();
const express = require('express');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');

const promClient = require('prom-client');
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// HTTP request counter
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
});

// HTTP request duration
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [register],
});

const certsIssuedCounter = new promClient.Counter({ name: 'ca_certificates_issued_total', help: 'Total certificates issued', labelNames: ['type'], registers: [register] });
const certsRevokedCounter = new promClient.Counter({ name: 'ca_certificates_revoked_total', help: 'Total certificates revoked', registers: [register] });

const app = express();
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// ─── RabbitMQ Event Bus ───────────────────────────────────────────────────────
let channel, connection;

async function connectBus() {
  try {
    const amqplib = require('amqplib');
    const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://opendirectory:changeme@rabbitmq:5672/';
    try {
      connection = await amqplib.connect(RABBITMQ_URL);
      connection.on('error', () => { channel = null; });
      connection.on('close', () => { channel = null; setTimeout(connectBus, 5000); });
      channel = await connection.createChannel();
      await channel.assertExchange('opendirectory.events', 'topic', { durable: true });
      console.log('[bus] RabbitMQ connected');
    } catch (e) {
      console.warn('[bus] RabbitMQ unavailable, retrying in 10s:', e.message);
      setTimeout(connectBus, 10000);
    }
  } catch (e) {
    console.warn('[bus] connectBus error:', e.message);
  }
}

function publish(routingKey, payload) {
  if (!channel) return;
  try {
    channel.publish('opendirectory.events', routingKey,
      Buffer.from(JSON.stringify({ ...payload, _source: 'certificate-authority', _ts: Date.now() })),
      { persistent: true, contentType: 'application/json' }
    );
  } catch (e) { /* fail silently */ }
}

// ─── Prometheus metrics middleware ────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const route = req.route?.path ?? req.path ?? 'unknown';
    const duration = (Date.now() - start) / 1000;
    httpRequestsTotal.inc({ method: req.method, route, status: res.statusCode });
    httpRequestDuration.observe({ method: req.method, route }, duration);
  });
  next();
});

app.get('/metrics', async (req, res) => {
  res.setHeader('Content-Type', register.contentType);
  res.send(await register.metrics());
});

const PORT = parseInt(process.env.CA_PORT || '3012');
const CA_COMMON_NAME = process.env.CA_COMMON_NAME || 'OpenDirectory Internal CA';
const CA_ORG = process.env.CA_ORG || 'OpenDirectory';
const CA_COUNTRY = process.env.CA_COUNTRY || 'CH';
const CA_VALIDITY_YEARS = parseInt(process.env.CA_VALIDITY_YEARS || '10');

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'auth',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '',
  max: 5,
  connectionTimeoutMillis: 3000,
});

let dbReady = false;

async function initDb() {
  try {
    await pool.query('SELECT 1');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ca_certificates (
        id VARCHAR(255) PRIMARY KEY,
        type VARCHAR(50) NOT NULL,
        common_name VARCHAR(255) NOT NULL,
        subject_alt_names JSONB DEFAULT '[]',
        certificate_pem TEXT NOT NULL,
        private_key_pem TEXT,
        serial_number VARCHAR(255),
        issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN DEFAULT FALSE,
        revoked_at TIMESTAMPTZ,
        issued_to VARCHAR(255),
        metadata JSONB DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_ca_certs_issued_to ON ca_certificates(issued_to);
      CREATE INDEX IF NOT EXISTS idx_ca_certs_expires ON ca_certificates(expires_at);
    `);
    dbReady = true;
    console.log('[CA] Database ready');
  } catch (err) {
    console.warn('[CA] DB not available:', err.message);
  }
}

// ─── CA Root Key & Certificate ────────────────────────────────────────────────

let caKey, caCert;
let caKeyPem, caCertPem;

function initCA() {
  console.log('[CA] Generating CA key pair...');
  const keys = forge.pki.rsa.generateKeyPair({ bits: 4096, e: 0x10001 });
  caKey = keys.privateKey;

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + CA_VALIDITY_YEARS);

  const attrs = [
    { name: 'commonName', value: CA_COMMON_NAME },
    { name: 'organizationName', value: CA_ORG },
    { name: 'countryName', value: CA_COUNTRY },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(caKey, forge.md.sha256.create());
  caCert = cert;
  caKeyPem = forge.pki.privateKeyToPem(caKey);
  caCertPem = forge.pki.certificateToPem(caCert);
  console.log(`[CA] Root CA ready: ${CA_COMMON_NAME}`);
}

function issueCertificate({ commonName, sans = [], durationDays = 365, isServer = true, isClient = false }) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + durationDays);

  cert.setSubject([{ name: 'commonName', value: commonName }, { name: 'organizationName', value: CA_ORG }]);
  cert.setIssuer(caCert.subject.attributes);

  const extensions = [
    { name: 'basicConstraints', cA: false },
    { name: 'authorityKeyIdentifier', keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes() },
    { name: 'subjectKeyIdentifier' },
  ];

  const keyUsages = { digitalSignature: true, keyEncipherment: isServer };
  extensions.push({ name: 'keyUsage', ...keyUsages, critical: true });

  const extKeyUsage = {};
  if (isServer) extKeyUsage.serverAuth = true;
  if (isClient) extKeyUsage.clientAuth = true;
  extensions.push({ name: 'extKeyUsage', ...extKeyUsage });

  if (sans.length > 0) {
    extensions.push({
      name: 'subjectAltName',
      altNames: sans.map(san => {
        if (san.startsWith('IP:')) return { type: 7, ip: san.slice(3) };
        if (/^\d+\.\d+\.\d+\.\d+$/.test(san)) return { type: 7, ip: san };
        return { type: 2, value: san };
      })
    });
  }

  cert.setExtensions(extensions);
  cert.sign(caKey, forge.md.sha256.create());

  return {
    certificate: forge.pki.certificateToPem(cert),
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    serialNumber: cert.serialNumber,
    expiresAt: cert.validity.notAfter,
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/ca/root', (req, res) => {
  res.setHeader('Content-Type', 'application/x-pem-file');
  res.setHeader('Content-Disposition', 'attachment; filename="opendirectory-ca.pem"');
  res.send(caCertPem);
});

app.get('/ca/root/json', (req, res) => {
  res.json({ certificate: caCertPem, commonName: CA_COMMON_NAME, expiresAt: caCert.validity.notAfter });
});

app.post('/ca/issue', async (req, res) => {
  const { commonName, sans, durationDays = 365, type = 'server', issuedTo } = req.body;
  if (!commonName) return res.status(400).json({ error: 'commonName required' });

  const result = issueCertificate({ commonName, sans: sans || [commonName], durationDays, isServer: type !== 'client', isClient: type === 'client' || type === 'both' });

  const id = uuidv4();
  if (dbReady) {
    await pool.query(
      `INSERT INTO ca_certificates(id, type, common_name, subject_alt_names, certificate_pem, private_key_pem, serial_number, expires_at, issued_to)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, type, commonName, JSON.stringify(sans || []), result.certificate, result.privateKey, result.serialNumber, result.expiresAt, issuedTo || null]
    ).catch(err => console.error('[CA] DB insert:', err.message));
  }

  certsIssuedCounter.inc({ type });
  publish('certificate.issued', { certId: id, subject: commonName, expiresAt: result.expiresAt });
  res.status(201).json({ id, commonName, certificate: result.certificate, privateKey: result.privateKey, serialNumber: result.serialNumber, expiresAt: result.expiresAt, caCertificate: caCertPem });
});

app.get('/ca/certificates', async (req, res) => {
  if (dbReady) {
    try {
      const r = await pool.query('SELECT id, type, common_name, serial_number, issued_at, expires_at, revoked, issued_to FROM ca_certificates ORDER BY issued_at DESC');
      return res.json(r.rows);
    } catch {}
  }
  res.json([]);
});

app.post('/ca/revoke/:id', async (req, res) => {
  if (dbReady) {
    await pool.query('UPDATE ca_certificates SET revoked=true, revoked_at=NOW() WHERE id=$1', [req.params.id]).catch(() => {});
  }
  certsRevokedCounter.inc();
  const revokedAt = new Date().toISOString();
  publish('certificate.revoked', { certId: req.params.id, revokedAt });
  res.json({ success: true });
});

app.get('/ca/crl', (req, res) => {
  // Return basic CRL (Certificate Revocation List)
  res.setHeader('Content-Type', 'application/pkix-crl');
  res.send(Buffer.from('CRL not implemented — use OCSP'));
});

app.get('/health', (req, res) => res.json({ status: 'ok', caReady: !!caCert }));

initCA();
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[certificate-authority] listening on :${PORT}`);
    connectBus();
  });
});
