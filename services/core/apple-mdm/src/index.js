// Apple MDM Server — APNs push, DeviceLock/Erase/InstallApp/InstallProfile/RemoveProfile
'use strict';
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const { XMLParser, XMLBuilder } = require('fast-xml-parser');

// ─── Prometheus metrics ───────────────────────────────────────────────────────

const promClient = require('prom-client');
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpRequestsTotal = new promClient.Counter({
  name: 'mdm_http_requests_total',
  help: 'Total HTTP requests to Apple MDM service',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
});

const httpRequestDuration = new promClient.Histogram({
  name: 'mdm_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [register],
});

const enrolledDevicesGauge = new promClient.Gauge({
  name: 'mdm_enrolled_devices_total',
  help: 'Total enrolled Apple devices',
  registers: [register],
});

const pushNotificationCounter = new promClient.Counter({
  name: 'mdm_push_notifications_total',
  help: 'Total APNs push notifications sent',
  labelNames: ['result'],
  registers: [register],
});

const commandQueuedCounter = new promClient.Counter({
  name: 'mdm_commands_queued_total',
  help: 'Total MDM commands queued',
  labelNames: ['request_type'],
  registers: [register],
});

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.APPLE_MDM_PORT || process.env.PORT || '3014', 10);

// MDM server base URL — used in enrollment profile (should be HTTPS in production)
const MDM_SERVER_URL = process.env.MDM_SERVER_URL || `http://localhost:${PORT}`;

// APNs / MDM push topic (must match MDM push certificate Subject CN)
// NOTE: Apple MDM requires a special MDM push certificate obtained via Apple Push
// Certificates Portal (https://identity.apple.com/pushcert/). This is different
// from a regular APNs certificate. The topic must be the UID field of the MDM
// push certificate (format: com.apple.mgmt.External.<UUID>).
const APNS_TOPIC = process.env.APNS_TOPIC || process.env.MDM_TOPIC || '';

// ─── PostgreSQL (with in-memory fallback) ────────────────────────────────────

const pgPool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME || process.env.POSTGRES_DB || 'auth',
  user: process.env.DB_USER || process.env.POSTGRES_USER || 'postgres',
  password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || '',
  max: 5,
  connectionTimeoutMillis: 3000,
});

let dbReady = false;

async function initDb() {
  try {
    await pgPool.query('SELECT 1');
    dbReady = true;
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS mdm_devices (
        udid VARCHAR(255) PRIMARY KEY,
        push_token TEXT,
        device_name VARCHAR(255),
        model VARCHAR(255),
        os_version VARCHAR(50),
        enrolled_at TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        status VARCHAR(50) DEFAULT 'active'
      )
    `);
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS mdm_commands (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        udid VARCHAR(255) REFERENCES mdm_devices(udid) ON DELETE CASCADE,
        command_uuid UUID DEFAULT gen_random_uuid(),
        request_type VARCHAR(100) NOT NULL,
        payload JSONB DEFAULT '{}',
        status VARCHAR(50) DEFAULT 'pending',
        issued_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ
      )
    `);
    await pgPool.query(`
      CREATE INDEX IF NOT EXISTS idx_mdm_commands_udid_status
        ON mdm_commands(udid, status)
    `);
    console.log('[apple-mdm] PostgreSQL connected and schema ready');
  } catch (err) {
    dbReady = false;
    console.warn('[apple-mdm] PostgreSQL unavailable, using in-memory store:', err.message);
  }
}

// ─── In-memory fallback stores ───────────────────────────────────────────────

const memDevices = new Map();   // udid -> device object
const memCommands = new Map();  // id   -> command object

// ─── DB helpers ──────────────────────────────────────────────────────────────

async function upsertDevice(device) {
  const { udid, push_token, device_name, model, os_version } = device;
  if (dbReady) {
    await pgPool.query(
      `INSERT INTO mdm_devices (udid, push_token, device_name, model, os_version, last_seen)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (udid) DO UPDATE SET
         push_token   = EXCLUDED.push_token,
         device_name  = COALESCE(EXCLUDED.device_name, mdm_devices.device_name),
         model        = COALESCE(EXCLUDED.model, mdm_devices.model),
         os_version   = COALESCE(EXCLUDED.os_version, mdm_devices.os_version),
         last_seen    = NOW(),
         status       = 'active'`,
      [udid, push_token || null, device_name || null, model || null, os_version || null]
    );
  } else {
    const existing = memDevices.get(udid) || { udid, enrolled_at: new Date().toISOString(), status: 'active' };
    memDevices.set(udid, {
      ...existing,
      push_token: push_token || existing.push_token,
      device_name: device_name || existing.device_name,
      model: model || existing.model,
      os_version: os_version || existing.os_version,
      last_seen: new Date().toISOString(),
    });
  }
}

async function markDeviceCheckedOut(udid) {
  if (dbReady) {
    await pgPool.query(
      `UPDATE mdm_devices SET status = 'unenrolled', last_seen = NOW() WHERE udid = $1`,
      [udid]
    );
  } else {
    const d = memDevices.get(udid);
    if (d) memDevices.set(udid, { ...d, status: 'unenrolled', last_seen: new Date().toISOString() });
  }
}

async function getDevice(udid) {
  if (dbReady) {
    const r = await pgPool.query('SELECT * FROM mdm_devices WHERE udid = $1', [udid]);
    return r.rows[0] || null;
  }
  return memDevices.get(udid) || null;
}

async function listDevices() {
  if (dbReady) {
    const r = await pgPool.query("SELECT * FROM mdm_devices WHERE status = 'active' ORDER BY enrolled_at DESC");
    return r.rows;
  }
  return Array.from(memDevices.values()).filter(d => d.status === 'active');
}

async function enqueueCommand(udid, requestType, payload) {
  const id = uuidv4();
  const commandUuid = uuidv4();
  if (dbReady) {
    await pgPool.query(
      `INSERT INTO mdm_commands (id, udid, command_uuid, request_type, payload)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, udid, commandUuid, requestType, JSON.stringify(payload || {})]
    );
  } else {
    memCommands.set(id, {
      id,
      udid,
      command_uuid: commandUuid,
      request_type: requestType,
      payload: payload || {},
      status: 'pending',
      issued_at: new Date().toISOString(),
      completed_at: null,
    });
  }
  commandQueuedCounter.inc({ request_type: requestType });
  return { id, command_uuid: commandUuid };
}

async function getNextPendingCommand(udid) {
  if (dbReady) {
    const r = await pgPool.query(
      `SELECT * FROM mdm_commands
       WHERE udid = $1 AND status = 'pending'
       ORDER BY issued_at ASC
       LIMIT 1`,
      [udid]
    );
    return r.rows[0] || null;
  }
  for (const cmd of memCommands.values()) {
    if (cmd.udid === udid && cmd.status === 'pending') return cmd;
  }
  return null;
}

async function markCommandCompleted(commandUuid, udid) {
  if (dbReady) {
    await pgPool.query(
      `UPDATE mdm_commands SET status = 'acknowledged', completed_at = NOW()
       WHERE command_uuid = $1 AND udid = $2`,
      [commandUuid, udid]
    );
  } else {
    for (const [id, cmd] of memCommands) {
      if (cmd.command_uuid === commandUuid && cmd.udid === udid) {
        memCommands.set(id, { ...cmd, status: 'acknowledged', completed_at: new Date().toISOString() });
        break;
      }
    }
  }
}

// ─── APNs provider (lazy initialisation) ─────────────────────────────────────

let apnsProvider = null;

function initApns() {
  const certB64 = process.env.APNS_CERT || '';
  const keyB64 = process.env.APNS_KEY || '';
  const topic = APNS_TOPIC;

  if (!certB64 || !keyB64 || !topic) {
    console.warn(
      '[apple-mdm] APNs not configured — set APNS_CERT (base64 PEM), APNS_KEY (base64 PEM) ' +
      'and APNS_TOPIC (MDM push cert UID) to enable push notifications.\n' +
      '           NOTE: Apple MDM requires an MDM push certificate from ' +
      'https://identity.apple.com/pushcert/ — not a regular APNs cert.'
    );
    return null;
  }

  try {
    const apn = require('@parse/node-apn');
    const cert = Buffer.from(certB64, 'base64').toString('utf8');
    const key = Buffer.from(keyB64, 'base64').toString('utf8');

    const provider = new apn.Provider({
      cert,
      key,
      production: process.env.NODE_ENV === 'production',
    });
    console.log('[apple-mdm] APNs provider initialised (topic:', topic, ')');
    return provider;
  } catch (err) {
    console.warn('[apple-mdm] Failed to initialise APNs provider:', err.message);
    return null;
  }
}

// ─── APNs push helper ─────────────────────────────────────────────────────────

async function sendMdmPush(pushToken) {
  if (!apnsProvider) {
    console.warn('[apple-mdm] APNs push skipped — provider not configured');
    pushNotificationCounter.inc({ result: 'skipped' });
    return { sent: false, reason: 'provider_not_configured' };
  }
  if (!pushToken) {
    pushNotificationCounter.inc({ result: 'no_token' });
    return { sent: false, reason: 'no_push_token' };
  }

  try {
    const apn = require('@parse/node-apn');
    // MDM wakeup: empty payload with content-available=1
    // Apple MDM protocol uses a silent push to wake the device so it polls /mdm/commands
    const note = new apn.Notification();
    note.topic = APNS_TOPIC;
    note.contentAvailable = 1;
    note.payload = {};
    note.pushType = 'mdm';   // Required for MDM pushes on iOS 13+

    const result = await apnsProvider.send(note, pushToken);

    if (result.failed && result.failed.length > 0) {
      const err = result.failed[0];
      console.warn('[apple-mdm] APNs push failed:', err.response || err.error);
      pushNotificationCounter.inc({ result: 'failed' });
      return { sent: false, reason: err.response?.reason || 'unknown', details: err.response };
    }

    pushNotificationCounter.inc({ result: 'success' });
    return { sent: true };
  } catch (err) {
    console.error('[apple-mdm] APNs push error:', err.message);
    pushNotificationCounter.inc({ result: 'error' });
    return { sent: false, reason: err.message };
  }
}

// ─── Plist helpers ────────────────────────────────────────────────────────────

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseTagValue: true,
  parseAttributeValue: true,
});

/**
 * Parse an Apple plist XML body into a plain JS object.
 * Handles the common <dict><key>K</key><string>V</string>...</dict> pattern.
 */
function parsePlist(xml) {
  try {
    const parsed = xmlParser.parse(xml);
    const dict = parsed?.plist?.dict;
    if (!dict) return {};
    return parsePlistDict(dict);
  } catch (err) {
    console.error('[apple-mdm] plist parse error:', err.message);
    return {};
  }
}

function parsePlistDict(dict) {
  const result = {};
  const keys = Array.isArray(dict.key) ? dict.key : (dict.key ? [dict.key] : []);

  // fast-xml-parser flattens sibling nodes into arrays per tag name
  // We reconstruct k/v pairs by interleaving in document order
  // using a simplified positional approach on the raw text instead.
  // For the MDM check-in use-case we only need top-level string/data values.
  const strings = Array.isArray(dict.string) ? [...dict.string] : (dict.string != null ? [dict.string] : []);
  const datas = Array.isArray(dict.data) ? [...dict.data] : (dict.data != null ? [dict.data] : []);

  let si = 0;
  let di = 0;

  for (const key of keys) {
    // Heuristic: consume the next available string or data value
    if (si < strings.length) {
      result[key] = String(strings[si++]);
    } else if (di < datas.length) {
      result[key] = String(datas[di++]);
    }
  }

  return result;
}

/**
 * Minimal plist dict builder.
 */
function buildPlistDict(obj) {
  let inner = '';
  for (const [k, v] of Object.entries(obj)) {
    inner += `\t<key>${k}</key>\n`;
    if (typeof v === 'boolean') {
      inner += `\t<${v ? 'true' : 'false'}/>\n`;
    } else if (typeof v === 'number') {
      inner += `\t<integer>${v}</integer>\n`;
    } else if (typeof v === 'object' && v !== null) {
      // nested dict
      inner += `\t<dict>\n`;
      for (const [k2, v2] of Object.entries(v)) {
        inner += `\t\t<key>${k2}</key>\n\t\t<string>${v2}</string>\n`;
      }
      inner += `\t</dict>\n`;
    } else {
      inner += `\t<string>${v}</string>\n`;
    }
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
${inner}</dict>
</plist>`;
}

const EMPTY_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>`;

// ─── Express app ──────────────────────────────────────────────────────────────

const app = express();

// MDM endpoints receive XML plist — parse as raw text for /mdm/* paths
app.use('/mdm', express.text({ type: ['application/x-apple-aspen-config', 'text/xml', 'application/xml', '*/*'], limit: '1mb' }));
app.use('/api', express.json({ limit: '1mb' }));
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));

// Prometheus request tracking
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

// ─── Health & Metrics ─────────────────────────────────────────────────────────

app.get('/health', async (req, res) => {
  const devices = await listDevices().catch(() => []);
  enrolledDevicesGauge.set(devices.length);
  res.json({
    status: 'ok',
    service: 'apple-mdm',
    port: PORT,
    db: dbReady ? 'postgres' : 'in-memory',
    apns: apnsProvider ? 'configured' : 'not_configured',
    enrolled_devices: devices.length,
    timestamp: new Date().toISOString(),
  });
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ─── GET /mdm/enroll ─ Serve enrollment .mobileconfig profile ─────────────────
//
// A real MDM enrollment profile must be signed with a trusted certificate
// and served over HTTPS. In development, the device must trust the server cert.
// The CheckInURL and ServerURL should point to this server.

app.get('/mdm/enroll', (req, res) => {
  const topic = APNS_TOPIC || 'com.apple.mgmt.External.YOUR_MDM_PUSH_CERT_UUID';
  const orgName = process.env.MDM_ORG_NAME || 'OpenDirectory';
  const serverUrl = MDM_SERVER_URL;

  // NOTE: In production this XML must be signed with CMS (PKCS#7 / S/MIME)
  // using a certificate trusted by Apple (e.g. issued by a public CA).
  // Unsigned profiles will show a warning on the device.
  const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>AccessRights</key>
      <integer>8191</integer>
      <key>CheckInURL</key>
      <string>${serverUrl}/mdm/checkin</string>
      <key>CheckOutWhenRemoved</key>
      <true/>
      <key>IdentifierType</key>
      <string>com.opendirectory.mdm</string>
      <key>PayloadDescription</key>
      <string>Configures MDM enrollment for ${orgName}</string>
      <key>PayloadDisplayName</key>
      <string>${orgName} MDM</string>
      <key>PayloadIdentifier</key>
      <string>com.opendirectory.mdm.profile</string>
      <key>PayloadOrganization</key>
      <string>${orgName}</string>
      <key>PayloadType</key>
      <string>com.apple.mdm</string>
      <key>PayloadUUID</key>
      <string>${uuidv4()}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>ServerURL</key>
      <string>${serverUrl}/mdm/commands</string>
      <key>SignMessage</key>
      <false/>
      <key>Topic</key>
      <string>${topic}</string>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>${orgName} MDM Enrollment Profile</string>
  <key>PayloadDisplayName</key>
  <string>${orgName} MDM Enrollment</string>
  <key>PayloadIdentifier</key>
  <string>com.opendirectory.mdm.enrollment</string>
  <key>PayloadOrganization</key>
  <string>${orgName}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${uuidv4()}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`;

  res.set('Content-Type', 'application/x-apple-aspen-config');
  res.set('Content-Disposition', 'attachment; filename="mdm-enroll.mobileconfig"');
  res.send(profile);
});

// ─── PUT /mdm/checkin ─ MDM device check-in (enrollment lifecycle) ────────────
//
// Apple devices send XML plist messages here during enrollment and un-enrollment.
// MessageType values:
//   Authenticate  — device presents itself; respond with empty dict plist
//   TokenUpdate   — device sends its APNs push token; save it
//   CheckOut      — device being un-enrolled; mark inactive

app.put('/mdm/checkin', async (req, res) => {
  const body = typeof req.body === 'string' ? req.body : '';

  let msg = {};
  try {
    msg = parsePlist(body);
  } catch (err) {
    console.error('[apple-mdm] Failed to parse check-in plist:', err.message);
    return res.status(400).send('Bad plist');
  }

  const messageType = msg.MessageType || '';
  const udid = msg.UDID || msg.DeviceUDID || '';

  console.log(`[apple-mdm] check-in MessageType=${messageType} UDID=${udid}`);

  switch (messageType) {
    case 'Authenticate': {
      // Device is starting enrollment — record it (no push token yet)
      if (udid) {
        await upsertDevice({ udid, device_name: msg.DeviceName, model: msg.Model }).catch(err =>
          console.error('[apple-mdm] upsertDevice error:', err.message)
        );
      }
      res.set('Content-Type', 'text/xml');
      return res.send(EMPTY_PLIST);
    }

    case 'TokenUpdate': {
      // Device sends its APNs push token (hex-encoded) — save it
      const pushToken = msg.PushMagic || msg.Token || msg.push_token || '';
      const token = msg.Token || '';  // binary token, usually base64 in XML plist

      if (udid) {
        await upsertDevice({
          udid,
          push_token: pushToken || token,
          device_name: msg.DeviceName,
          model: msg.Model,
          os_version: msg.OSVersion,
        }).catch(err => console.error('[apple-mdm] upsertDevice error:', err.message));
      }
      res.set('Content-Type', 'text/xml');
      return res.send(EMPTY_PLIST);
    }

    case 'CheckOut': {
      if (udid) {
        await markDeviceCheckedOut(udid).catch(err =>
          console.error('[apple-mdm] markDeviceCheckedOut error:', err.message)
        );
      }
      return res.status(200).send('');
    }

    default:
      console.warn('[apple-mdm] Unknown MessageType:', messageType);
      res.set('Content-Type', 'text/xml');
      return res.send(EMPTY_PLIST);
  }
});

// ─── PUT /mdm/commands ─ Device polls for pending MDM commands ─────────────────
//
// After receiving an APNs push (or on its own schedule), a managed device
// POSTs to this endpoint. We dequeue the next pending command and return it
// as a plist. If no commands are pending, we respond with Status=Idle.
//
// The device also sends Status/CommandUUID for the previous command result —
// we mark that command as acknowledged.

app.put('/mdm/commands', async (req, res) => {
  const body = typeof req.body === 'string' ? req.body : '';
  let msg = {};
  try {
    msg = parsePlist(body);
  } catch (err) {
    console.error('[apple-mdm] Failed to parse command poll plist:', err.message);
    return res.status(400).send('Bad plist');
  }

  const udid = msg.UDID || msg.DeviceUDID || '';
  const prevStatus = msg.Status || '';
  const prevCmdUuid = msg.CommandUUID || '';

  // Acknowledge the result of the last command if device reported one
  if (prevCmdUuid && udid && prevStatus && prevStatus !== 'Idle') {
    await markCommandCompleted(prevCmdUuid, udid).catch(() => {});
    // Update last_seen
    await upsertDevice({ udid }).catch(() => {});
  }

  if (!udid) {
    return res.status(400).send('Missing UDID');
  }

  // Fetch next pending command
  let cmd = null;
  try {
    cmd = await getNextPendingCommand(udid);
  } catch (err) {
    console.error('[apple-mdm] getNextPendingCommand error:', err.message);
  }

  if (!cmd) {
    // No commands — tell device to idle
    const idlePlist = buildPlistDict({ Status: 'Idle' });
    res.set('Content-Type', 'text/xml');
    return res.send(idlePlist);
  }

  // Build MDM command plist response
  const commandUuidStr = cmd.command_uuid || uuidv4();
  const requestType = cmd.request_type || 'DeviceLock';
  const payload = typeof cmd.payload === 'string' ? JSON.parse(cmd.payload) : (cmd.payload || {});

  // Build inner Command dict entries
  const commandFields = { RequestType: requestType };
  // Attach command-specific fields from payload
  if (requestType === 'InstallApplication' && payload.ManifestURL) {
    commandFields.ManifestURL = payload.ManifestURL;
  }
  if (requestType === 'InstallProfile' && payload.Payload) {
    commandFields.Payload = payload.Payload;
  }
  if (requestType === 'DeviceLock' && payload.PIN) {
    commandFields.PIN = payload.PIN;
  }
  if (requestType === 'EraseDevice' && payload.PIN) {
    commandFields.PIN = payload.PIN;
  }

  // Build the complete MDM command response plist
  let commandPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>CommandUUID</key>
\t<string>${commandUuidStr}</string>
\t<key>Command</key>
\t<dict>
`;
  for (const [k, v] of Object.entries(commandFields)) {
    commandPlist += `\t\t<key>${k}</key>\n\t\t<string>${v}</string>\n`;
  }
  commandPlist += `\t</dict>
</dict>
</plist>`;

  res.set('Content-Type', 'text/xml');
  return res.send(commandPlist);
});

// ─── Admin API ────────────────────────────────────────────────────────────────

// GET /api/mdm/devices — list enrolled devices
app.get('/api/mdm/devices', async (req, res) => {
  try {
    const devices = await listDevices();
    enrolledDevicesGauge.set(devices.length);
    res.json({ devices, count: devices.length });
  } catch (err) {
    console.error('[apple-mdm] listDevices error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mdm/devices/:udid/push — trigger APNs push to wake device
app.post('/api/mdm/devices/:udid/push', async (req, res) => {
  const { udid } = req.params;
  try {
    const device = await getDevice(udid);
    if (!device) return res.status(404).json({ error: 'Device not found', udid });
    if (!device.push_token) return res.status(400).json({ error: 'Device has no push token', udid });

    const result = await sendMdmPush(device.push_token);
    res.json({ udid, push: result });
  } catch (err) {
    console.error('[apple-mdm] push error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mdm/devices/:udid/lock — queue DeviceLock command
app.post('/api/mdm/devices/:udid/lock', async (req, res) => {
  const { udid } = req.params;
  const { pin, message } = req.body || {};
  try {
    const device = await getDevice(udid);
    if (!device) return res.status(404).json({ error: 'Device not found', udid });

    const payload = {};
    if (pin) payload.PIN = pin;
    if (message) payload.Message = message;

    const { id, command_uuid } = await enqueueCommand(udid, 'DeviceLock', payload);

    // Optionally push to wake device immediately
    if (device.push_token) {
      await sendMdmPush(device.push_token).catch(() => {});
    }

    res.status(202).json({ queued: true, command: { id, command_uuid, request_type: 'DeviceLock', udid } });
  } catch (err) {
    console.error('[apple-mdm] lock error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mdm/devices/:udid/wipe — queue EraseDevice command
app.post('/api/mdm/devices/:udid/wipe', async (req, res) => {
  const { udid } = req.params;
  const { pin } = req.body || {};
  try {
    const device = await getDevice(udid);
    if (!device) return res.status(404).json({ error: 'Device not found', udid });

    const payload = {};
    if (pin) payload.PIN = pin;

    const { id, command_uuid } = await enqueueCommand(udid, 'EraseDevice', payload);

    if (device.push_token) {
      await sendMdmPush(device.push_token).catch(() => {});
    }

    res.status(202).json({ queued: true, command: { id, command_uuid, request_type: 'EraseDevice', udid } });
  } catch (err) {
    console.error('[apple-mdm] wipe error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mdm/devices/:udid/install-app — queue InstallApplication command
app.post('/api/mdm/devices/:udid/install-app', async (req, res) => {
  const { udid } = req.params;
  const { manifest_url, identifier, options } = req.body || {};
  if (!manifest_url) {
    return res.status(400).json({ error: 'manifest_url is required' });
  }
  try {
    const device = await getDevice(udid);
    if (!device) return res.status(404).json({ error: 'Device not found', udid });

    const payload = { ManifestURL: manifest_url };
    if (identifier) payload.iTunesStoreID = identifier;
    if (options) payload.ManagementFlags = options.management_flags || 0;

    const { id, command_uuid } = await enqueueCommand(udid, 'InstallApplication', payload);

    if (device.push_token) {
      await sendMdmPush(device.push_token).catch(() => {});
    }

    res.status(202).json({ queued: true, command: { id, command_uuid, request_type: 'InstallApplication', udid } });
  } catch (err) {
    console.error('[apple-mdm] install-app error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mdm/devices/:udid/install-profile — queue InstallProfile command
app.post('/api/mdm/devices/:udid/install-profile', async (req, res) => {
  const { udid } = req.params;
  const { profile_payload } = req.body || {};
  if (!profile_payload) {
    return res.status(400).json({ error: 'profile_payload (base64-encoded mobileconfig) is required' });
  }
  try {
    const device = await getDevice(udid);
    if (!device) return res.status(404).json({ error: 'Device not found', udid });

    const { id, command_uuid } = await enqueueCommand(udid, 'InstallProfile', { Payload: profile_payload });

    if (device.push_token) {
      await sendMdmPush(device.push_token).catch(() => {});
    }

    res.status(202).json({ queued: true, command: { id, command_uuid, request_type: 'InstallProfile', udid } });
  } catch (err) {
    console.error('[apple-mdm] install-profile error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mdm/devices/:udid/remove-profile — queue RemoveProfile command
app.post('/api/mdm/devices/:udid/remove-profile', async (req, res) => {
  const { udid } = req.params;
  const { identifier } = req.body || {};
  if (!identifier) {
    return res.status(400).json({ error: 'identifier (payload identifier of profile to remove) is required' });
  }
  try {
    const device = await getDevice(udid);
    if (!device) return res.status(404).json({ error: 'Device not found', udid });

    const { id, command_uuid } = await enqueueCommand(udid, 'RemoveProfile', { Identifier: identifier });

    if (device.push_token) {
      await sendMdmPush(device.push_token).catch(() => {});
    }

    res.status(202).json({ queued: true, command: { id, command_uuid, request_type: 'RemoveProfile', udid } });
  } catch (err) {
    console.error('[apple-mdm] remove-profile error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── GET/POST /api/mdm/config ─ APNs cert & MDM settings ─────────────────────

app.get('/api/mdm/config', (req, res) => {
  res.json({
    topic: process.env.APNS_TOPIC || '',
    serverUrl: process.env.MDM_SERVER_URL || MDM_SERVER_URL,
    orgName: process.env.MDM_ORG_NAME || 'OpenDirectory',
    apnsConfigured: !!(process.env.APNS_CERT && process.env.APNS_KEY && process.env.APNS_TOPIC),
  });
});

// In-memory config store (persisted to env-overrides file in production via volume mount)
let runtimeConfig = {};

app.post('/api/mdm/config', async (req, res) => {
  const { topic, serverUrl, orgName, apnsCert, apnsKey } = req.body || {};

  if (topic)     runtimeConfig.APNS_TOPIC    = topic;
  if (serverUrl) runtimeConfig.MDM_SERVER_URL = serverUrl;
  if (orgName)   runtimeConfig.MDM_ORG_NAME   = orgName;

  // If new certs provided, try to reinitialise APNs provider
  if (apnsCert) {
    process.env.APNS_CERT = apnsCert;
    runtimeConfig.APNS_CERT = apnsCert;
  }
  if (apnsKey) {
    process.env.APNS_KEY = apnsKey;
    runtimeConfig.APNS_KEY = apnsKey;
  }
  if (topic) process.env.APNS_TOPIC = topic;

  if (apnsCert || apnsKey || topic) {
    apnsProvider = initApns();
  }

  // Persist to /data/mdm-config.json if writable (Docker volume)
  try {
    const fs = require('fs');
    const configPath = '/data/mdm-config.json';
    fs.mkdirSync('/data', { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(runtimeConfig, null, 2));
  } catch (_) { /* not writable — config lives in RAM until restart */ }

  res.json({
    saved: true,
    apnsConfigured: !!(process.env.APNS_CERT && process.env.APNS_KEY && process.env.APNS_TOPIC),
    topic: process.env.APNS_TOPIC || '',
    serverUrl: process.env.MDM_SERVER_URL || MDM_SERVER_URL,
    orgName: process.env.MDM_ORG_NAME || 'OpenDirectory',
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

async function start() {
  await initDb();
  apnsProvider = initApns();

  app.listen(PORT, () => {
    console.log(`[apple-mdm] Apple MDM server listening on port ${PORT}`);
    console.log(`[apple-mdm] Enrollment profile: GET ${MDM_SERVER_URL}/mdm/enroll`);
    console.log(`[apple-mdm] Check-in endpoint:  PUT ${MDM_SERVER_URL}/mdm/checkin`);
    console.log(`[apple-mdm] Command endpoint:   PUT ${MDM_SERVER_URL}/mdm/commands`);
    console.log(`[apple-mdm] Admin API:          ${MDM_SERVER_URL}/api/mdm/devices`);
    console.log(`[apple-mdm] DB backend:         ${dbReady ? 'PostgreSQL' : 'in-memory (no persistence)'}`);
    console.log(`[apple-mdm] APNs push:          ${apnsProvider ? 'enabled' : 'disabled (APNS_CERT/APNS_KEY/APNS_TOPIC not set)'}`);
  });
}

start().catch(err => {
  console.error('[apple-mdm] Fatal startup error:', err);
  process.exit(1);
});

process.on('SIGTERM', () => { pgPool.end().catch(() => {}); process.exit(0); });
process.on('SIGINT',  () => { pgPool.end().catch(() => {}); process.exit(0); });

module.exports = app;
