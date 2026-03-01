'use strict';
const express    = require('express');
const cors       = require('cors');
const axios      = require('axios');
const net        = require('net');
const fs         = require('fs');
const path       = require('path');
const { exec }   = require('child_process');
const util       = require('util');
const execAsync  = util.promisify(exec);
const { Pool }   = require('pg');

// Policy Compiler + Templates (loaded dynamically if available)
let policyCompiler = null;
let policyTemplates = null;
try {
  policyCompiler  = require('./policy-compiler');
  policyTemplates = require('./policy-templates');
  console.log('Policy Compiler loaded');
} catch (e) {
  console.log('Policy Compiler not available:', e.message);
}

// ── Printer dispatch (JetDirect PCL via port 9100) ─────────────────────────
// HP OfficeJet Pro and most HP inkjets support PCL over JetDirect (port 9100).
// IPP with PostScript is NOT used because HP inkjet printers don't support PS.

function buildTestPagePCL(printerName) {
  const ESC = '\x1b';
  const FF  = '\x0c';
  const now = new Date().toLocaleString('de-CH', { timeZone: 'Europe/Zurich' });
  return [
    ESC + 'E',           // Printer Reset
    ESC + '&l0O',        // Portrait orientation
    ESC + '&l2A',        // US Letter paper
    ESC + '*p200x400Y',  // Cursor position (x=200 dots, y=400 dots from top-left)
    ESC + '(s14V',       // Font size 14pt
    ESC + '(s3B',        // Bold weight
    ESC + '(s3T',        // Courier typeface
    'OpenDirectory Test Page\r\n',
    ESC + '(s0B',        // Normal weight
    ESC + '(s12V',       // 12pt
    '============================\r\n\r\n',
    `Drucker:  ${printerName}\r\n`,
    `Datum:    ${now}\r\n`,
    'System:   opendirectory.heusser.local\r\n\r\n',
    'Dieser Ausdruck bestaetigt, dass der Drucker\r\n',
    'korrekt in OpenDirectory konfiguriert ist.\r\n',
    FF,                  // Form Feed — ejects the page
    ESC + 'E',           // Printer Reset
  ].join('');
}

async function printTestPage(printerIp, printerName) {
  const pcl = buildTestPagePCL(printerName);
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    socket.setTimeout(10000);
    let done = false;
    const finish = (ok, err) => {
      if (done) return; done = true;
      socket.destroy();
      ok ? resolve({ success: true }) : reject(err || new Error('JetDirect failed'));
    };
    socket.connect(9100, printerIp, () => {
      socket.write(Buffer.from(pcl, 'binary'));
      // JetDirect is fire-and-forget — wait briefly then declare success
      setTimeout(() => finish(true), 4000);
    });
    socket.on('error',   (e) => finish(false, e));
    socket.on('timeout', ()  => finish(true));  // timeout after data sent = normal
  });
}

const app  = express();
const port = process.env.PORT || 3005;

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

const db = new Pool({
  host:     process.env.PGHOST     || 'postgres',
  port:     parseInt(process.env.PGPORT || '5432'),
  database: process.env.PGDATABASE || 'opendirectory',
  user:     process.env.PGUSER     || 'opendirectory',
  password: process.env.PGPASSWORD || 'SecurePass2024!',
  max: 10,
  idleTimeoutMillis: 30000,
});

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id              TEXT PRIMARY KEY,
      name            TEXT NOT NULL,
      platform        TEXT DEFAULT 'linux',
      os              TEXT DEFAULT '',
      os_version      TEXT DEFAULT '',
      ip_address      TEXT DEFAULT '',
      group_id        TEXT DEFAULT 'servers',
      description     TEXT DEFAULT '',
      compliance_score INTEGER DEFAULT 0,
      kernel          TEXT DEFAULT '',
      package_manager TEXT DEFAULT 'apt',
      status          TEXT DEFAULT 'online',
      last_seen       TIMESTAMPTZ DEFAULT NOW(),
      registered_at   TIMESTAMPTZ DEFAULT NOW(),
      decommissioned  BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS device_software (
      id           TEXT PRIMARY KEY,
      device_id    TEXT REFERENCES devices(id) ON DELETE CASCADE,
      name         TEXT NOT NULL,
      version      TEXT DEFAULT '',
      category     TEXT DEFAULT '',
      status       TEXT DEFAULT 'installed',
      installed_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS printers (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      ip          TEXT NOT NULL,
      model       TEXT DEFAULT '',
      protocol    TEXT DEFAULT 'IPP',
      status      TEXT DEFAULT 'online',
      queue_depth INTEGER DEFAULT 0,
      location    TEXT DEFAULT '',
      driver      TEXT DEFAULT '',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scanners (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      ip         TEXT NOT NULL,
      model      TEXT DEFAULT '',
      status     TEXT DEFAULT 'online',
      formats    JSONB DEFAULT '["PDF","JPEG"]',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS print_jobs (
      id            TEXT PRIMARY KEY,
      document_name TEXT DEFAULT '',
      user_name     TEXT DEFAULT '',
      printer_name  TEXT DEFAULT '',
      pages         INTEGER DEFAULT 1,
      submitted     TIMESTAMPTZ DEFAULT NOW(),
      status        TEXT DEFAULT 'pending'
    );
    CREATE TABLE IF NOT EXISTS print_quotas (
      user_id     TEXT PRIMARY KEY,
      username    TEXT NOT NULL,
      used_pages  INTEGER DEFAULT 0,
      quota_limit INTEGER DEFAULT 500,
      reset_date  DATE DEFAULT (CURRENT_DATE + INTERVAL '30 days')
    );
    CREATE TABLE IF NOT EXISTS policies (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      type        TEXT DEFAULT 'custom',
      description TEXT DEFAULT '',
      enabled     BOOLEAN DEFAULT TRUE,
      targets     JSONB DEFAULT '[]',
      settings    JSONB DEFAULT '{}',
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS gpos (
      id         TEXT PRIMARY KEY,
      policy_id  TEXT REFERENCES policies(id) ON DELETE CASCADE,
      name       TEXT NOT NULL,
      scope      TEXT DEFAULT 'ou',
      linked_ous JSONB DEFAULT '[]',
      settings   JSONB DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ou_entries (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      parent_id  TEXT,
      type       TEXT DEFAULT 'ou',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS security_alerts (
      id          TEXT PRIMARY KEY,
      severity    TEXT DEFAULT 'medium',
      title       TEXT NOT NULL,
      description TEXT DEFAULT '',
      source      TEXT DEFAULT 'system',
      status      TEXT DEFAULT 'open',
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      resolved_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id         TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      user_name  TEXT DEFAULT 'system',
      resource   TEXT DEFAULT '',
      action     TEXT DEFAULT '',
      details    JSONB DEFAULT '{}',
      ip_address TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS network_shares (
      id               TEXT PRIMARY KEY,
      name             TEXT NOT NULL,
      protocol         TEXT NOT NULL DEFAULT 'SMB',
      server           TEXT DEFAULT '',
      path             TEXT DEFAULT '',
      permissions      TEXT DEFAULT 'rw',
      enabled          BOOLEAN DEFAULT true,
      username         TEXT DEFAULT '',
      has_credentials  BOOLEAN DEFAULT false,
      drive_letter     TEXT DEFAULT '',
      allowed_groups   JSONB DEFAULT '[]',
      allowed_users    JSONB DEFAULT '[]',
      created_at       TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // Add MFP columns to printers if they don't exist yet (idempotent migrations)
  await db.query(`ALTER TABLE printers ADD COLUMN IF NOT EXISTS is_multifunction BOOLEAN DEFAULT FALSE`);
  await db.query(`ALTER TABLE printers ADD COLUMN IF NOT EXISTS scan_formats JSONB DEFAULT '["PDF","JPEG"]'`);
  await db.query(`ALTER TABLE scanners ADD COLUMN IF NOT EXISTS scan_profiles JSONB DEFAULT '[]'`);
  await db.query(`ALTER TABLE print_jobs ADD COLUMN IF NOT EXISTS hp_job_id INTEGER`);
  // DNS records table
  await db.query(`CREATE TABLE IF NOT EXISTS dns_records (
    id         TEXT PRIMARY KEY,
    zone       TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL,
    type       TEXT DEFAULT 'A',
    value      TEXT NOT NULL,
    ttl        INTEGER DEFAULT 3600,
    synced     BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  // AD/DC configuration (wizard output stored here)
  await db.query(`CREATE TABLE IF NOT EXISTS ad_config (
    id           TEXT PRIMARY KEY DEFAULT 'default',
    dc_ip        TEXT DEFAULT '',
    dc_hostname  TEXT DEFAULT 'dc01',
    domain       TEXT DEFAULT '',
    realm        TEXT DEFAULT '',
    admin_user   TEXT DEFAULT 'Administrator',
    admin_pass   TEXT DEFAULT '',
    nas_ip       TEXT DEFAULT '',
    nas_share    TEXT DEFAULT '',
    drive_letter TEXT DEFAULT 'Z',
    portal_ip    TEXT DEFAULT '',
    updated_at   TIMESTAMPTZ DEFAULT NOW()
  )`);
  // Security settings (persistent, per wizard)
  await db.query(`CREATE TABLE IF NOT EXISTS security_settings (
    id         TEXT PRIMARY KEY DEFAULT 'default',
    settings   JSONB DEFAULT '{}',
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  // Network shares: add missing columns for edit support
  await db.query(`ALTER TABLE network_shares ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`);
  // Policy-as-Code extensions
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS intent_json    JSONB  DEFAULT '{}'`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS compiled_json  JSONB  DEFAULT NULL`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS version        TEXT   DEFAULT '1.0'`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS category       TEXT   DEFAULT 'custom'`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS platforms      JSONB  DEFAULT '["windows","linux","macos"]'`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS target_groups  JSONB  DEFAULT '[]'`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS deploy_status  TEXT   DEFAULT 'draft'`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS last_deployed  TIMESTAMPTZ DEFAULT NULL`);
  await db.query(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS gpo_guid       TEXT   DEFAULT NULL`);
  await db.query(`ALTER TABLE print_quotas ADD COLUMN IF NOT EXISTS period     TEXT   DEFAULT 'monthly'`);
  // Policy version history
  await db.query(`CREATE TABLE IF NOT EXISTS policy_versions (
    id          TEXT PRIMARY KEY,
    policy_id   TEXT NOT NULL,
    version     TEXT NOT NULL,
    intent_json JSONB DEFAULT '{}',
    compiled_at TIMESTAMPTZ DEFAULT NOW(),
    deployed_by TEXT DEFAULT 'system',
    comment     TEXT DEFAULT ''
  )`);
  // Compliance / drift results
  await db.query(`CREATE TABLE IF NOT EXISTS compliance_results (
    id          TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    policy_id   TEXT NOT NULL,
    compliant   BOOLEAN DEFAULT false,
    drift       JSONB DEFAULT '[]',
    checked_at  TIMESTAMPTZ DEFAULT NOW()
  )`);
  // Device-Policy Zuweisung (welche Geräte haben welche Policy)
  await db.query(`CREATE TABLE IF NOT EXISTS policies_assigned (
    id             TEXT PRIMARY KEY,
    policy_id      TEXT NOT NULL,
    device_id      TEXT NOT NULL,
    platform       TEXT DEFAULT '',
    target_group   TEXT DEFAULT '',
    deploy_status  TEXT DEFAULT 'pending',
    last_sync      TIMESTAMPTZ DEFAULT NULL,
    assigned_at    TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(policy_id, device_id)
  )`);
  // hp_job_id schon vorhanden, aber idempotent
  await db.query(`ALTER TABLE print_jobs ADD COLUMN IF NOT EXISTS hp_job_id INTEGER`);
  const existing = await db.query('SELECT id FROM devices WHERE id = $1', ['CT2001']);
  if (existing.rowCount === 0) {
    await db.query(
      `INSERT INTO devices (id,name,platform,os,os_version,ip_address,group_id,description,compliance_score,kernel,package_manager,registered_at)
       VALUES ('CT2001','Ubuntu-CT2001','linux','Ubuntu','25.10','192.168.1.51','servers','Proxmox LXC Container with LDAP integration',85,'6.11.0-19-generic','apt','2026-01-15T10:23:00Z')`
    );
  }
  console.log('Database initialized');
}

const services = {
  lldap:      { url: 'http://lldap:17170',    name: 'LLDAP' },
  grafana:    { url: 'http://grafana:3000',    name: 'Grafana' },
  prometheus: { url: 'http://prometheus:9090', name: 'Prometheus' },
  vault:      { url: 'http://vault:8200',      name: 'Vault' },
};

const moduleState = {
  'authentication-service': { name: 'Authentication (LLDAP)', enabled: true,  port: 17170, description: 'LDAP Identity Provider',  features: { ldap: true, graphql: true, webui: true } },
  'monitoring-analytics':   { name: 'Monitoring & Analytics', enabled: true,  port: 3000,  description: 'Grafana + Prometheus',    features: { metrics: true, dashboards: true, alerts: true } },
  'secrets-management':     { name: 'Secrets Management',     enabled: true,  port: 8200,  description: 'HashiCorp Vault',         features: { kv: true, pki: true, transit: true } },
  'automation-workflows':   { name: 'Automation (n8n)',        enabled: true,  port: 5678,  description: 'n8n Workflow Automation', features: { workflows: true, scheduling: true } },
  'device-management':      { name: 'Device Management',       enabled: true,  port: 3001,  description: 'MDM + Patch Management',  features: { mdm: true, patching: true } },
  'network-infrastructure': { name: 'Network Infrastructure',  enabled: true,  port: 8080,  description: 'DNS, DHCP, File Shares',  features: { dns: true,  dhcp: true,  shares: true  } },
  'security-suite':         { name: 'Security Suite (Wazuh)',  enabled: true,  port: 5601,  description: 'SIEM + IDS/IPS',         features: { siem: true,  ids: true  } },
};
const CORE_MODULES = ['authentication-service'];

const checkService = async (name, service) => {
  for (const path of ['/health', '/-/healthy']) {
    try {
      const start = Date.now();
      await axios.get(`${service.url}${path}`, { timeout: 3000 });
      return { name, description: service.name, status: 'healthy', responseTime: Date.now() - start, lastCheck: new Date().toISOString() };
    } catch {}
  }
  return { name, description: service.name, status: 'unhealthy', lastCheck: new Date().toISOString() };
};

const tcpCheck = (host, portNum, timeout = 3000) => new Promise((resolve) => {
  const socket = new net.Socket();
  socket.setTimeout(timeout);
  socket.connect(portNum, host, () => { socket.destroy(); resolve(true); });
  socket.on('error', () => { socket.destroy(); resolve(false); });
  socket.on('timeout', () => { socket.destroy(); resolve(false); });
});

// ── Health & Config ────────────────────────────────────────────────────────────

app.get('/health', async (req, res) => {
  const statuses = await Promise.all(Object.entries(services).map(([n, s]) => checkService(n, s)));
  const h = statuses.filter(s => s.status === 'healthy').length;
  res.json({ status: h === statuses.length ? 'healthy' : h > 0 ? 'degraded' : 'unhealthy', timestamp: new Date().toISOString(), services: statuses });
});
app.get('/health/detailed', async (req, res) => {
  const statuses = await Promise.all(Object.entries(services).map(([n, s]) => checkService(n, s)));
  const h = statuses.filter(s => s.status === 'healthy').length;
  res.json({ status: h === statuses.length ? 'healthy' : h > 0 ? 'degraded' : 'critical', timestamp: new Date().toISOString(), services: statuses, gateway: { uptime: process.uptime(), memory: process.memoryUsage() } });
});
app.get('/health/ready', (req, res) => res.json({ status: 'ready' }));
app.get('/health/live',  (req, res) => res.json({ status: 'alive' }));
app.get('/api/services', async (req, res) => {
  const statuses = await Promise.all(Object.entries(services).map(([n, s]) => checkService(n, s)));
  res.json(statuses);
});
app.get('/api/config/modules', (req, res) => res.json(moduleState));
app.post('/api/config/modules/:moduleId', (req, res) => {
  const { moduleId } = req.params; const { enabled } = req.body;
  if (!moduleState[moduleId]) return res.status(404).json({ success: false, error: `Module '${moduleId}' not found` });
  if (CORE_MODULES.includes(moduleId)) return res.status(403).json({ success: false, error: `Module '${moduleId}' is a core module` });
  moduleState[moduleId].enabled = enabled;
  res.json({ success: true, moduleId, enabled, module: moduleState[moduleId] });
});
app.get('/api/gateway/stats', (req, res) => res.json({ totalRequests: 0, activeConnections: 0, uptime: process.uptime() }));

// ── Devices ────────────────────────────────────────────────────────────────────

app.get('/api/devices', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM devices ORDER BY registered_at DESC');
    const devices = await Promise.all(result.rows.map(async (d) => {
      const reachable = d.ip_address ? await tcpCheck(d.ip_address, 22).catch(() => false) : false;
      return { ...d, status: d.decommissioned ? 'decommissioned' : (reachable ? 'online' : 'offline'), lastSeen: new Date().toISOString() };
    }));
    res.json({ success: true, data: devices });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/devices/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM devices WHERE id=$1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ success: false, error: 'Device not found' });
    const d = result.rows[0];
    const reachable = d.ip_address ? await tcpCheck(d.ip_address, 22).catch(() => false) : false;
    res.json({ success: true, data: { ...d, status: d.decommissioned ? 'decommissioned' : (reachable ? 'online' : 'offline'), lastSeen: new Date().toISOString() } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/devices/enrollment-token', (req, res) => {
  res.json({ success: true, token: genId() + genId(), expiresAt: new Date(Date.now() + 86400000).toISOString() });
});
app.post('/api/devices/enroll', async (req, res) => {
  try {
    const { id, device_id, name, hostname, platform, os, os_version, ip_address, kernel, package_manager } = req.body;
    const devId = device_id || id || genId();
    const devName = name || hostname || devId;
    await db.query(
      `INSERT INTO devices (id,name,platform,os,os_version,ip_address,kernel,package_manager)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET name=$2,last_seen=NOW()`,
      [devId, devName, platform||'linux', os||'', os_version||'', ip_address||'', kernel||'', package_manager||'']
    );
    const result = await db.query('SELECT * FROM devices WHERE id=$1', [devId]);
    res.json({ success: true, device_id: devId, data: result.rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/devices/register', async (req, res) => {
  const { device_id, hostname, platform, os_version, kernel_version, package_manager, ip_address } = req.body;
  if (!device_id) return res.status(400).json({ success: false, error: 'device_id is required' });
  try {
    await db.query(
      `INSERT INTO devices (id,name,platform,os_version,ip_address,kernel,package_manager)
       VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET last_seen=NOW()`,
      [device_id, hostname||device_id, platform||'linux', os_version||'', ip_address||'', kernel_version||'', package_manager||'']
    );
    res.json({ success: true, device_id, message: 'Device registered successfully' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/devices/:id/refresh', async (req, res) => {
  try {
    await db.query('UPDATE devices SET last_seen=NOW() WHERE id=$1', [req.params.id]);
    const result = await db.query('SELECT * FROM devices WHERE id=$1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ success: false, error: 'Device not found' });
    const d = result.rows[0];
    const reachable = d.ip_address ? await tcpCheck(d.ip_address, 22).catch(() => false) : false;
    res.json({ success: true, data: { ...d, status: reachable ? 'online' : 'offline', lastSeen: new Date().toISOString() } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/devices/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT name FROM devices WHERE id=$1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ success: false, error: 'Device not found' });
    await db.query('UPDATE devices SET decommissioned=TRUE WHERE id=$1', [req.params.id]);
    res.json({ success: true, message: `Device ${result.rows[0].name} decommissioned` });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/devices/:id/software', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM device_software WHERE device_id=$1 ORDER BY installed_at', [req.params.id]);
    res.json({ success: true, data: result.rows.map(r => ({ id: r.id, app: r.id, name: r.name, version: r.version, category: r.category, status: r.status, installedAt: r.installed_at })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/devices/:id/software', async (req, res) => {
  try {
    const { name, version, category, appId } = req.body;
    const id = appId || genId();
    await db.query(
      'INSERT INTO device_software (id,device_id,name,version,category) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO UPDATE SET version=$3',
      [id, req.params.id, name||'', version||'', category||'']
    );
    res.json({ success: true, message: `${name} installation initiated`, data: { id, name, version, status: 'installed' } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/devices/:id/software/update-all', (req, res) => res.json({ success: true, message: 'Update initiated for all packages' }));
app.post('/api/devices/:id/software/:appId/update', async (req, res) => {
  try {
    const { version } = req.body;
    if (version) await db.query('UPDATE device_software SET version=$1 WHERE id=$2 AND device_id=$3', [version, req.params.appId, req.params.id]);
    res.json({ success: true, message: 'Software updated' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/devices/:id/software/:appId', async (req, res) => {
  try {
    await db.query('DELETE FROM device_software WHERE id=$1 AND device_id=$2', [req.params.appId, req.params.id]);
    res.json({ success: true, message: 'Software removed' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/devices/:id/hardware', (req, res) => {
  res.json({ success: true, data: { cpu: { model: 'Intel Xeon E5-2678 v3', cores: 2, usage: Math.floor(Math.random()*30+10) }, memory: { total: 2048, used: Math.floor(Math.random()*1000+500), free: Math.floor(Math.random()*500+200) }, disk: [{ device: '/dev/sda', total: 32768, used: Math.floor(Math.random()*10000+5000), mount: '/' }] } });
});
app.get('/api/devices/:id/network', async (req, res) => {
  try {
    const result = await db.query('SELECT ip_address FROM devices WHERE id=$1', [req.params.id]);
    const ip = result.rows[0]?.ip_address || '';
    res.json({ success: true, data: { interfaces: [{ name: 'eth0', ipv4: ip, mac: '00:00:00:00:00:00', speed: '1Gbps', status: 'up' }], dns: ['192.168.1.1'], gateway: '192.168.1.1' } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/devices/:id/logs',       (req, res) => res.json({ success: true, data: [] }));
// ── Device: Policies (aus policies_assigned) ──────────────────────────────────
app.get('/api/devices/:id/policies', async (req, res) => {
  try {
    const r = await db.query(`
      SELECT pa.id, pa.policy_id, pa.deploy_status, pa.last_sync, pa.assigned_at,
             p.name, p.category, p.version, p.deploy_status AS policy_deploy_status
      FROM policies_assigned pa
      JOIN policies p ON p.id = pa.policy_id
      WHERE pa.device_id = $1
      ORDER BY pa.assigned_at DESC
    `, [req.params.id]);
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/devices/:id/policies', async (req, res) => {
  const { policy_id, target_group } = req.body;
  if (!policy_id) return res.status(400).json({ error: 'policy_id required' });
  try {
    const dev = await db.query('SELECT platform FROM devices WHERE id=$1', [req.params.id]);
    if (dev.rowCount === 0) return res.status(404).json({ error: 'Device not found' });
    const platform = dev.rows[0].platform || 'unknown';
    await db.query(`
      INSERT INTO policies_assigned (id,policy_id,device_id,platform,target_group,deploy_status)
      VALUES ($1,$2,$3,$4,$5,'pending')
      ON CONFLICT (policy_id,device_id) DO UPDATE
        SET deploy_status='pending', target_group=EXCLUDED.target_group
    `, [genId(), policy_id, req.params.id, platform, target_group||'']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── Device: Compliance (echt aus compliance_results) ─────────────────────────
app.get('/api/devices/:id/compliance', async (req, res) => {
  try {
    const r = await db.query(`
      SELECT cr.*, p.name AS policy_name
      FROM compliance_results cr
      LEFT JOIN policies p ON p.id = cr.policy_id
      WHERE cr.device_id = $1
      ORDER BY cr.checked_at DESC
    `, [req.params.id]);
    const results  = r.rows;
    const total    = results.length;
    const ok       = results.filter(x => x.compliant).length;
    const score    = total > 0 ? Math.round((ok / total) * 100) : 100;
    const issues   = results.filter(x => !x.compliant)
                            .flatMap(x => (x.drift||[]).map(d => ({ policy: x.policy_name, ...d })));
    res.json({ success: true, data: { score, issues, results, totalPolicies: total, compliantPolicies: ok } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── Device: Sync triggern ─────────────────────────────────────────────────────
app.post('/api/devices/:id/sync', async (req, res) => {
  try {
    await db.query(
      "UPDATE policies_assigned SET deploy_status='sync_pending' WHERE device_id=$1",
      [req.params.id]
    );
    res.json({ success: true, message: 'Sync scheduled — client picks up on next check-in' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── Printers ──────────────────────────────────────────────────────────────────

app.get('/api/printer/printers', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM printers ORDER BY created_at');
    res.json({ success: true, data: result.rows.map(r => ({
      id: r.id, name: r.name, ip: r.ip, model: r.model,
      protocol: r.protocol, status: r.status, queueDepth: r.queue_depth,
      location: r.location, driver: r.driver,
      isMultifunction: r.is_multifunction || false,
      scanFormats: r.scan_formats || ['PDF','JPEG'],
    })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/printer/printers', async (req, res) => {
  try {
    const { name, ip, model, protocol, status, location, driver, isMultifunction, scanFormats } = req.body;
    if (!name || !ip) return res.status(400).json({ success: false, error: 'name and ip are required' });
    const id = genId();
    const mfp = isMultifunction || false;
    const fmts = scanFormats?.length ? scanFormats : ['PDF','JPEG'];
    await db.query(
      'INSERT INTO printers (id,name,ip,model,protocol,status,location,driver,is_multifunction,scan_formats) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [id, name, ip, model||'', protocol||'IPP', status||'online', location||'', driver||'', mfp, JSON.stringify(fmts)]);
    if (mfp) {
      // Auto-create matching scanner entry for the multifunction device
      const scId = genId();
      await db.query(
        'INSERT INTO scanners (id,name,ip,model,status,formats) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
        [scId, name, ip, model||'', 'online', JSON.stringify(fmts)]);
    }
    res.json({ id, name, ip, model: model||'', protocol: protocol||'IPP', status: status||'online',
      queueDepth: 0, location: location||'', driver: driver||'', isMultifunction: mfp, scanFormats: fmts });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/printer/printers/:id', async (req, res) => {
  try {
    await markPoliciesForRecompile({ printerIds: [req.params.id] });
    const pr = await db.query('SELECT ip, is_multifunction FROM printers WHERE id=$1', [req.params.id]);
    if (pr.rowCount && pr.rows[0].is_multifunction) {
      await db.query('DELETE FROM scanners WHERE ip=$1', [pr.rows[0].ip]);
    }
    await db.query('DELETE FROM printers WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.patch('/api/printer/printers/:id', async (req, res) => {
  const { name, ip, model, protocol, status, location, driver, isMultifunction, scanFormats } = req.body;
  try {
    await db.query(
      `UPDATE printers SET
         name=COALESCE($1,name), ip=COALESCE($2,ip), model=COALESCE($3,model),
         protocol=COALESCE($4,protocol), status=COALESCE($5,status),
         location=COALESCE($6,location), driver=COALESCE($7,driver),
         is_multifunction=COALESCE($8,is_multifunction),
         scan_formats=COALESCE($9,scan_formats)
       WHERE id=$10`,
      [name, ip, model, protocol, status, location, driver,
       isMultifunction, scanFormats ? JSON.stringify(scanFormats) : null,
       req.params.id]
    );
    await markPoliciesForRecompile({ printerIds: [req.params.id] });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/printer/discover', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM printers ORDER BY created_at');
    res.json({ success: true, printers: result.rows.map(r => ({ ip: r.ip, hostname: r.name, vendor: (r.model||'').split(' ')[0]||'', model: r.model, protocols: [r.protocol] })) });
  } catch (e) { res.json({ success: true, printers: [] }); }
});
app.get('/api/printer/scanners', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM scanners ORDER BY created_at');
    res.json({ success: true, data: result.rows.map(r => ({
      id: r.id, name: r.name, ip: r.ip, model: r.model, status: r.status,
      formats: r.formats, profiles: r.scan_profiles || [],
    })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.put('/api/printer/scanners/:id/profiles', async (req, res) => {
  try {
    const { profiles } = req.body;
    await db.query('UPDATE scanners SET scan_profiles=$1 WHERE id=$2', [JSON.stringify(profiles || []), req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/printer/scanners/:id/scan', (req, res) => res.json({ success: true, scanId: genId(), message: 'Scan queued' }));
app.get('/api/printer/jobs', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM print_jobs ORDER BY submitted DESC LIMIT 100');
    res.json({ success: true, data: result.rows.map(r => ({ id: r.id, documentName: r.document_name, user: r.user_name, printer: r.printer_name, pages: r.pages, submitted: r.submitted, status: r.status })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
// ipp-gateway: record a job (without printing — gateway handles the actual print)
app.post('/api/printer/jobs/record', async (req, res) => {
  try {
    const { id, document_name, user_name, printer_name, status } = req.body;
    if (!id) return res.status(400).json({ success: false, error: 'id is required' });
    await db.query(
      `INSERT INTO print_jobs (id, document_name, user_name, printer_name, status)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`,
      [id, document_name || '', user_name || '', printer_name || 'HP', status || 'pending']
    );
    res.json({ id });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ipp-gateway: update status + hp_job_id after print submission or poll
app.patch('/api/printer/jobs/:id/status', async (req, res) => {
  try {
    const { status, hp_job_id } = req.body;
    await db.query(
      `UPDATE print_jobs SET status=$1, hp_job_id=COALESCE($2,hp_job_id) WHERE id=$3`,
      [status, hp_job_id ?? null, req.params.id]
    );
    res.json({ updated: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/printer/jobs', async (req, res) => {
  try {
    const { document_name, user_name, printer_name, pages } = req.body;
    const id   = genId();
    const pg   = parseInt(pages) || 1;
    const user = user_name || 'admin';
    const docName = document_name || 'Document';
    await db.query(
      'INSERT INTO print_jobs (id,document_name,user_name,printer_name,pages,status) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, docName, user, printer_name || '', pg, 'pending']);

    // Track quota usage for this user (upsert)
    await db.query(`
      INSERT INTO print_quotas (user_id, username, used_pages, quota_limit)
      VALUES ($1, $2, $3, 500)
      ON CONFLICT (user_id) DO UPDATE SET used_pages = print_quotas.used_pages + $3
    `, [user, user, pg]);

    const jobObj = { id, documentName: docName, user, printer: printer_name || '',
      pages: pg, submitted: new Date().toISOString(), status: 'pending' };

    // For test pages: dispatch a real IPP job to the printer, then mark completed/failed
    if (docName === 'Test Page' && printer_name) {
      const prRow = await db.query('SELECT ip, name FROM printers WHERE name=$1 LIMIT 1', [printer_name]);
      const printerIp = prRow.rows[0]?.ip;
      if (printerIp) {
        // Respond immediately so UI isn't blocked; dispatch async
        res.json({ success: true, data: jobObj });
        printTestPage(printerIp, printer_name)
          .then(() => db.query("UPDATE print_jobs SET status='completed' WHERE id=$1", [id]))
          .catch(() => db.query("UPDATE print_jobs SET status='failed'    WHERE id=$1", [id]));
        return;
      }
    }
    res.json({ success: true, data: jobObj });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/printer/jobs/:id', async (req, res) => {
  try { await db.query("UPDATE print_jobs SET status='cancelled' WHERE id=$1", [req.params.id]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/printer/quotas', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM print_quotas ORDER BY username');
    res.json({ success: true, data: result.rows.map(r => ({
      id:          r.user_id,
      user_name:   r.username,
      used_pages:  r.used_pages,
      quota_limit: r.quota_limit,
      period:      r.period || 'monthly',
      reset_date:  r.reset_date,
    })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.put('/api/printer/quotas/:userId', async (req, res) => {
  try {
    const { quota, username } = req.body;
    await db.query('INSERT INTO print_quotas (user_id,username,quota_limit) VALUES ($1,$2,$3) ON CONFLICT (user_id) DO UPDATE SET quota_limit=$3',
      [req.params.userId, username||req.params.userId, quota]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/printer/scans', (req, res) => res.json({ success: true, data: [] }));

// ── Policies ──────────────────────────────────────────────────────────────────

app.get('/api/policies', async (req, res) => {
  try {
    const policies = await db.query('SELECT * FROM policies ORDER BY created_at');
    const data = await Promise.all(policies.rows.map(async (p) => {
      const gpos = await db.query('SELECT * FROM gpos WHERE policy_id=$1 ORDER BY created_at', [p.id]);
      return { ...p, gpos: gpos.rows };
    }));
    res.json({ success: true, data });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/policies/ou-tree', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM ou_entries ORDER BY name');
    const nodes = result.rows;
    const build = (p) => ({ ...p, children: nodes.filter(n => n.parent_id === p.id).map(build) });
    res.json({ success: true, data: nodes.filter(n => !n.parent_id).map(build) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/policies/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM policies WHERE id=$1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ success: false, error: 'Policy not found' });
    const gpos = await db.query('SELECT * FROM gpos WHERE policy_id=$1 ORDER BY created_at', [req.params.id]);
    res.json({ success: true, data: { ...result.rows[0], gpos: gpos.rows } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/policies', async (req, res) => {
  try {
    const { name, type, description, enabled, targets, settings } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'name is required' });
    const id = genId();
    await db.query('INSERT INTO policies (id,name,type,description,enabled,targets,settings) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, name, type||'custom', description||'', enabled!==false, JSON.stringify(targets||[]), JSON.stringify(settings||{})]);
    const result = await db.query('SELECT * FROM policies WHERE id=$1', [id]);
    res.json({ success: true, data: { ...result.rows[0], gpos: [] } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.put('/api/policies/:id', async (req, res) => {
  try {
    const { name, type, description, enabled, targets, settings } = req.body;
    await db.query(
      `UPDATE policies SET name=COALESCE($1,name),type=COALESCE($2,type),description=COALESCE($3,description),
       enabled=COALESCE($4,enabled),targets=COALESCE($5,targets),settings=COALESCE($6,settings),updated_at=NOW() WHERE id=$7`,
      [name, type, description, enabled, targets?JSON.stringify(targets):null, settings?JSON.stringify(settings):null, req.params.id]);
    const result = await db.query('SELECT * FROM policies WHERE id=$1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ success: false, error: 'Policy not found' });
    const gpos = await db.query('SELECT * FROM gpos WHERE policy_id=$1', [req.params.id]);
    res.json({ success: true, data: { ...result.rows[0], gpos: gpos.rows } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/policies/:id', async (req, res) => {
  try { await db.query('DELETE FROM policies WHERE id=$1', [req.params.id]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/policies/:id/gpos', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM gpos WHERE policy_id=$1 ORDER BY created_at', [req.params.id]);
    res.json({ success: true, data: result.rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/policies/:id/gpos', async (req, res) => {
  try {
    const { name, scope, linked_ous, settings } = req.body;
    const id = genId();
    await db.query('INSERT INTO gpos (id,policy_id,name,scope,linked_ous,settings) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, req.params.id, name||'New GPO', scope||'ou', JSON.stringify(linked_ous||[]), JSON.stringify(settings||{})]);
    const result = await db.query('SELECT * FROM gpos WHERE id=$1', [id]);
    res.json({ success: true, data: result.rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.put('/api/gpos/:id', async (req, res) => {
  try {
    const { name, scope, linked_ous, settings } = req.body;
    await db.query(
      `UPDATE gpos SET name=COALESCE($1,name),scope=COALESCE($2,scope),
       linked_ous=COALESCE($3,linked_ous),settings=COALESCE($4,settings),updated_at=NOW() WHERE id=$5`,
      [name, scope, linked_ous?JSON.stringify(linked_ous):null, settings?JSON.stringify(settings):null, req.params.id]);
    const result = await db.query('SELECT * FROM gpos WHERE id=$1', [req.params.id]);
    res.json({ success: true, data: result.rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── Security ──────────────────────────────────────────────────────────────────

app.get('/api/security/alerts', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 200');
    res.json({ success: true, data: result.rows.map(r => ({ id: r.id, severity: r.severity, title: r.title, description: r.description, source: r.source, status: r.status, timestamp: r.created_at, resolvedAt: r.resolved_at })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/security/alerts', async (req, res) => {
  try {
    const { severity, title, description, source } = req.body;
    const id = genId();
    await db.query('INSERT INTO security_alerts (id,severity,title,description,source) VALUES ($1,$2,$3,$4,$5)',
      [id, severity||'medium', title||'', description||'', source||'system']);
    res.json({ success: true, data: { id } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/security/alerts/:id/resolve', async (req, res) => {
  try { await db.query("UPDATE security_alerts SET status='resolved',resolved_at=NOW() WHERE id=$1", [req.params.id]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/security/threats',      (req, res) => res.json({ success: true, data: [] }));
app.get('/api/security/pam/sessions', (req, res) => res.json({ success: true, data: [] }));
app.get('/api/security/dlp/policies', (req, res) => res.json({ success: true, data: [] }));
app.get('/api/security/compliance', async (req, res) => {
  try {
    const devices = await db.query('SELECT compliance_score FROM devices WHERE NOT decommissioned');
    const scores = devices.rows.map(d => d.compliance_score || 0);
    const avg = scores.length ? Math.round(scores.reduce((s, x) => s + x, 0) / scores.length) : 0;
    res.json({ success: true, data: { overall: avg, devices: devices.rowCount, compliant: scores.filter(s => s >= 80).length } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── Audit ─────────────────────────────────────────────────────────────────────

app.get('/api/audit/events', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 200');
    res.json({ success: true, data: result.rows.map(r => ({ id: r.id, type: r.event_type, user: r.user_name, resource: r.resource, action: r.action, details: r.details, ipAddress: r.ip_address, timestamp: r.created_at })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/audit/events', async (req, res) => {
  try {
    const { event_type, user_name, resource, action, details, ip_address } = req.body;
    const id = genId();
    await db.query('INSERT INTO audit_events (id,event_type,user_name,resource,action,details,ip_address) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, event_type||'unknown', user_name||'system', resource||'', action||'', JSON.stringify(details||{}), ip_address||'']);
    res.json({ success: true, data: { id } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── LLDAP ─────────────────────────────────────────────────────────────────────

app.get('/api/lldap/users', (req, res) => {
  res.json({ users: [
    { id: '1', displayName: 'Administrator', firstName: 'Admin', lastName: 'User', email: 'admin@opendirectory.local', groups: ['admins','lldap_admin'], createdAt: '2026-01-01T00:00:00.000Z' },
    { id: '2', displayName: 'Christian Heusser', firstName: 'Christian', lastName: 'Heusser', email: 'christian@opendirectory.local', groups: ['users','admins'], createdAt: '2026-01-15T00:00:00.000Z' },
  ]});
});
app.get('/api/lldap/users/search', (req, res) => res.json({ users: [] }));
app.get('/api/lldap/groups', (req, res) => {
  res.json({ groups: [
    { id: '1', displayName: 'admins',      members: ['admin','christian'] },
    { id: '2', displayName: 'users',       members: ['christian'] },
    { id: '3', displayName: 'lldap_admin', members: ['admin'] },
  ]});
});
app.get('/api/lldap/stats',  (req, res) => res.json({ statistics: { total: 2, active: 2, groups: 3 } }));
app.get('/api/lldap/status', (req, res) => res.json({ status: 'healthy' }));

// ── Grafana ───────────────────────────────────────────────────────────────────

const gHeaders = () => ({ Authorization: 'Basic ' + Buffer.from('admin:admin').toString('base64') });
app.get('/api/grafana/dashboards', async (req, res) => {
  try { const r = await axios.get(`${services.grafana.url}/api/search`, { headers: gHeaders(), timeout: 10000 }); res.json({ dashboards: r.data||[] }); }
  catch { res.json({ dashboards: [{ id: 1, uid: 'opendirectory', title: 'OpenDirectory Overview', url: '/d/opendirectory/overview', tags: ['opendirectory'], type: 'dash-db', folderTitle: '' }] }); }
});
app.get('/api/grafana/dashboards/opendirectory', async (req, res) => {
  try { const r = await axios.get(`${services.grafana.url}/api/search?query=opendirectory`, { headers: gHeaders(), timeout: 10000 }); res.json({ dashboards: r.data||[] }); }
  catch { res.json({ dashboards: [{ id: 1, uid: 'opendirectory', title: 'OpenDirectory Overview', url: 'https://monitor.heusser.local/d/opendirectory/overview', tags: ['opendirectory'], type: 'dash-db', folderTitle: 'OpenDirectory' }] }); }
});
app.get('/api/grafana/dashboards/uid/:uid', async (req, res) => {
  try { const r = await axios.get(`${services.grafana.url}/api/dashboards/uid/${req.params.uid}`, { headers: gHeaders(), timeout: 10000 }); res.json(r.data); }
  catch { res.status(404).json({ error: 'Dashboard not found' }); }
});
app.get('/api/grafana/embed/dashboard/:uid', (req, res) => res.json({ url: `${services.grafana.url}/d/${req.params.uid}?orgId=1&kiosk` }));
app.get('/api/grafana/status', async (req, res) => {
  try { await axios.get(`${services.grafana.url}/api/health`, { timeout: 5000 }); res.json({ status: 'healthy' }); }
  catch { res.json({ status: 'unhealthy' }); }
});

// ── Prometheus ────────────────────────────────────────────────────────────────

const promQuery = async (q) => {
  try { const r = await axios.get(`${services.prometheus.url}/api/v1/query?query=${encodeURIComponent(q)}`, { timeout: 5000 }); return r.data; }
  catch { return { status: 'success', data: { resultType: 'vector', result: [] } }; }
};
app.get('/api/prometheus/query',           async (req, res) => res.json(await promQuery(req.query.query || 'up')));
app.get('/api/prometheus/service-metrics', async (req, res) => res.json(await promQuery('up')));
app.get('/api/prometheus/status', async (req, res) => {
  try { await axios.get(`${services.prometheus.url}/-/healthy`, { timeout: 5000 }); res.json({ status: 'healthy' }); }
  catch { res.json({ status: 'unhealthy' }); }
});
app.get('/api/prometheus/kpis', async (req, res) => {
  const [a, b, c, d] = await Promise.all([
    promQuery('avg(up) * 100'),
    promQuery('sum(http_requests_total) or vector(0)'),
    promQuery('sum(rate(http_requests_total{code=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100 or vector(0)'),
    promQuery('avg(http_request_duration_seconds) or vector(0)'),
  ]);
  res.json({ kpis: { serviceUptime: a, totalRequests: b, errorRate: c, avgResponseTime: d, activeUsers: { status: 'success', data: { result: [{ value: [Date.now()/1000, '2'] }] } } } });
});

// ── Vault ─────────────────────────────────────────────────────────────────────

app.get('/api/vault/sys/health', async (req, res) => {
  try { const r = await axios.get(`${services.vault.url}/v1/sys/health`, { timeout: 10000 }); res.json(r.data); }
  catch { res.json({ initialized: true, sealed: false, standby: false, version: '1.14.0' }); }
});
app.get('/api/vault/status', async (req, res) => {
  try { const r = await axios.get(`${services.vault.url}/v1/sys/health`, { timeout: 5000 }); res.json({ status: 'healthy', data: r.data }); }
  catch { res.json({ status: 'unhealthy' }); }
});
app.get('/api/vault/secrets', (req, res) => res.json({ secrets: ['secret/database', 'secret/api-keys', 'secret/ldap'] }));
app.get('/api/vault/secrets/:path(*)', (req, res) => {
  const m = { 'secret/database': { host: 'postgres', port: '5432' }, 'secret/api-keys': { grafana: '(stored)' }, 'secret/ldap': { bind_dn: 'cn=admin,dc=opendirectory,dc=local' } };
  res.json({ path: req.params.path, data: m[req.params.path] || {}, metadata: { created_time: new Date().toISOString(), version: 1 } });
});
app.put('/api/vault/secrets/:path(*)', async (req, res) => {
  try {
    const token = process.env.VAULT_TOKEN || 'root';
    await axios.post(
      `${services.vault.url}/v1/secret/data/${req.params.path}`,
      { data: req.body },
      { headers: { 'X-Vault-Token': token }, timeout: 5000 }
    );
    res.json({ success: true });
  } catch {
    res.json({ success: true, warning: 'Vault write skipped' });
  }
});

// ── Network: Devices (Discovery-Tab) ──────────────────────────────────────────
// Alias auf /api/devices — gibt alle aktiven Geräte für den Network-Discovery-Tab zurück.

app.get('/api/network/devices', async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM devices WHERE status != 'decommissioned' ORDER BY last_seen DESC"
    );
    res.json({ devices: result.rows });
  } catch (e) { res.json({ devices: [], error: e.message }); }
});

app.post('/api/network/devices', async (req, res) => {
  const { name, ip_address, platform, description } = req.body;
  try {
    const id = genId();
    await db.query(
      `INSERT INTO devices (id, name, ip_address, platform, description, status, registered_at, last_seen)
       VALUES ($1,$2,$3,$4,$5,'active',NOW(),NOW())
       ON CONFLICT (id) DO NOTHING`,
      [id, name || 'Unknown', ip_address || '', platform || 'unknown', description || '']
    );
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── Policy: Recompile-Trigger ─────────────────────────────────────────────────
// Wird aufgerufen wenn Shares oder Drucker geändert/gelöscht werden.
// Markiert alle Policies die diese IDs referenzieren als 'needs_recompile'.
async function markPoliciesForRecompile({ shareIds = [], printerIds = [] }) {
  if (!shareIds.length && !printerIds.length) return 0;
  try {
    const all = await db.query(
      "SELECT id, intent_json FROM policies WHERE deploy_status NOT IN ('draft') AND intent_json IS NOT NULL"
    );
    const toMark = [];
    for (const row of all.rows) {
      const s = row.intent_json?.settings || {};
      const drives   = (s.networkDrives || []).map(d => d._shareId).filter(Boolean);
      const printers = (s.printers      || []).map(p => p._printerId).filter(Boolean);
      const hit = shareIds.some(id => drives.includes(id)) ||
                  printerIds.some(id => printers.includes(id));
      if (hit) toMark.push(row.id);
    }
    if (toMark.length > 0) {
      await db.query(
        "UPDATE policies SET deploy_status='needs_recompile', updated_at=NOW() WHERE id = ANY($1)",
        [toMark]
      );
    }
    return toMark.length;
  } catch { return 0; }
}

// ── Network: File Shares ───────────────────────────────────────────────────────

app.get('/api/network/shares', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM network_shares ORDER BY created_at DESC');
    res.json({ shares: result.rows });
  } catch {
    res.json({ shares: [] });
  }
});

app.post('/api/network/shares', async (req, res) => {
  const { name, protocol, server, path, permissions, enabled, username, has_credentials, drive_letter, allowed_groups, allowed_users } = req.body;
  if (!name || !protocol) return res.status(400).json({ error: 'name and protocol required' });
  const id = genId();
  try {
    await db.query(
      `INSERT INTO network_shares (id, name, protocol, server, path, permissions, enabled, username, has_credentials, drive_letter, allowed_groups, allowed_users)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, name, protocol, server || '', path || '', permissions || 'rw', enabled !== false,
       username || '', has_credentials || false, drive_letter || '',
       JSON.stringify(allowed_groups || []), JSON.stringify(allowed_users || [])]
    );
    res.json({ id, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/network/shares/:id', async (req, res) => {
  try {
    await markPoliciesForRecompile({ shareIds: [req.params.id] });
    await db.query('DELETE FROM network_shares WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Returns shares accessible to a specific user (used by login scripts)
app.get('/api/network/shares/for-user/:username', async (req, res) => {
  const username = req.params.username.toLowerCase();
  const userGroups = (req.query.groups || '').split(',').filter(Boolean).map(g => g.trim().toLowerCase());
  try {
    const result = await db.query('SELECT * FROM network_shares WHERE enabled = true ORDER BY name');
    const shares = result.rows.filter(share => {
      const groups = (share.allowed_groups || []).map(g => g.toLowerCase());
      const users  = (share.allowed_users  || []).map(u => u.toLowerCase());
      if (groups.length === 0 && users.length === 0) return true; // no ACL = all users
      if (users.some(u => u === username || u.includes(username) || username.includes(u))) return true;
      if (userGroups.some(g => groups.includes(g))) return true;
      return false;
    }).map(s => ({
      id:           s.id,
      name:         s.name,
      protocol:     s.protocol,
      server:       s.server,
      path:         s.path,
      permissions:  s.permissions,
      drive_letter: s.drive_letter || '',
      username:     s.username || '',
      has_credentials: s.has_credentials,
      unc_path:     s.protocol === 'SMB' ? `\\\\${s.server}\\${s.path}` : null,
      smb_url:      s.protocol === 'SMB' ? `smb://${s.server}/${s.path}` : null,
      nfs_path:     s.protocol === 'NFS' ? `${s.server}:${s.path}` : null,
    }));
    res.json({ username, shares });
  } catch {
    res.json({ username, shares: [] });
  }
});

// ── Auto-Mount Install Scripts ─────────────────────────────────────────────────

const PORTAL_URL = process.env.PORTAL_URL || 'https://opendirectory.heusser.local';

function makeInstallScript(os) {
  const p = PORTAL_URL;
  const tok = process.env.CLIENT_TOKEN || 'od-client-secret-change-me';

  if (os === 'windows') {
    // PowerShell install script: creates two scheduled tasks
    // 1. OpenDirectory-MountDrives  — mounts network shares at logon
    // 2. OpenDirectory-PolicyAgent  — fetches & applies policies at logon + every 4h (SYSTEM)
    return [
      '# OpenDirectory Client Setup (Windows)',
      '# Als Administrator ausfuehren:',
      '#   Set-ExecutionPolicy RemoteSigned -Scope LocalMachine',
      '#   Invoke-Expression (Invoke-WebRequest -Uri "' + p + '/api/network/install-script/windows" -UseBasicParsing).Content',
      '',
      "$ErrorActionPreference = 'SilentlyContinue'",
      "$PortalUrl = '" + p + "'",
      "$OdToken   = '" + tok + "'",
      '$ScriptDir = "$env:ProgramData\\OpenDirectory"',
      'New-Item -ItemType Directory -Force -Path $ScriptDir | Out-Null',
      '',
      '# ── 1. Netzlaufwerke (pro Benutzer, bei Login) ──────────────────────────',
      '$MountScript = "$ScriptDir\\mount-drives.ps1"',
      "@'\r\n$PortalUrl = '" + p + "'\r\n$Username = $env:USERNAME\r\ntry {\r\n  $r = Invoke-RestMethod -Uri \"$PortalUrl/api/network/shares/for-user/$Username\" -UseBasicParsing -TimeoutSec 10\r\n  foreach ($s in $r.shares) {\r\n    if ($s.protocol -ne 'SMB') { continue }\r\n    $l = $s.drive_letter -replace ':',''\r\n    if ($l -and !(Get-PSDrive -Name $l -EA SilentlyContinue)) {\r\n      net use \"${l}:\" $s.unc_path /persistent:yes 2>$null\r\n    }\r\n  }\r\n} catch {}\r\n'@ | Out-File -FilePath $MountScript -Encoding UTF8 -Force",
      '',
      "Unregister-ScheduledTask -TaskName 'OpenDirectory-MountDrives' -Confirm:$false -EA SilentlyContinue",
      "Register-ScheduledTask -TaskName 'OpenDirectory-MountDrives' `",
      "  -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-WindowStyle Hidden -ExecutionPolicy Bypass -File `\"$MountScript`\"\") `",
      "  -Trigger (New-ScheduledTaskTrigger -AtLogOn) `",
      "  -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) `",
      "  -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive) | Out-Null",
      '',
      '# ── 2. Policy Agent (als SYSTEM, bei Login + alle 4h) ───────────────────',
      '$PolicyScript = "$ScriptDir\\policy-agent.ps1"',
      '$DeviceIdFile = "$ScriptDir\\device-id.txt"',
      '',
      '# Device-ID: einmalig generieren und persistent speichern',
      'if (!(Test-Path $DeviceIdFile)) {',
      '  [System.Guid]::NewGuid().ToString() | Out-File $DeviceIdFile -Encoding ASCII',
      '}',
      '$DeviceId = (Get-Content $DeviceIdFile -Raw).Trim()',
      '',
      "@'\r\n$PortalUrl = '" + p + "'\r\n$OdToken   = '" + tok + "'\r\n$ScriptDir = \"$env:ProgramData\\OpenDirectory\"\r\n$DeviceId  = (Get-Content \"$ScriptDir\\device-id.txt\" -Raw -EA SilentlyContinue).Trim()\r\nif (!$DeviceId) { exit 0 }\r\n$headers   = @{ 'X-OD-Token' = $OdToken; 'Content-Type' = 'application/json' }\r\n# Heartbeat\r\ntry { Invoke-RestMethod -Method Post -Uri \"$PortalUrl/api/client/heartbeat\" -Headers $headers -Body (@{device_id=$DeviceId;platform='windows';os_version=[System.Environment]::OSVersion.VersionString} | ConvertTo-Json) -UseBasicParsing -TimeoutSec 10 } catch {}\r\n# Policies holen\r\ntry {\r\n  $pol = Invoke-RestMethod -Uri \"$PortalUrl/api/client/policies?device_id=$DeviceId\" -Headers $headers -UseBasicParsing -TimeoutSec 20\r\n  foreach ($p in $pol.policies) {\r\n    $arts = $p.artifacts.windows\r\n    if (!$arts) { continue }\r\n    foreach ($a in $arts) {\r\n      $path = \"$ScriptDir\\$($a.filename)\"\r\n      $a.content | Out-File $path -Encoding UTF8 -Force\r\n      if ($a.filename -match '\\.inf$') {\r\n        secedit /configure /db \"$ScriptDir\\od-secedit.sdb\" /cfg $path /quiet 2>$null\r\n      }\r\n    }\r\n    Invoke-RestMethod -Method Post -Uri \"$PortalUrl/api/client/compliance-report\" -Headers $headers -Body (@{device_id=$DeviceId;policy_id=$p.id;compliant=$true;drift=@()} | ConvertTo-Json) -UseBasicParsing -TimeoutSec 10 -EA SilentlyContinue\r\n  }\r\n} catch {}\r\n'@ | Out-File -FilePath $PolicyScript -Encoding UTF8 -Force",
      '',
      "Unregister-ScheduledTask -TaskName 'OpenDirectory-PolicyAgent' -Confirm:$false -EA SilentlyContinue",
      "$triggers = @(",
      "  (New-ScheduledTaskTrigger -AtStartup),",
      "  (New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 4) -Once -At '00:00')",
      ")",
      "Register-ScheduledTask -TaskName 'OpenDirectory-PolicyAgent' `",
      "  -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-WindowStyle Hidden -ExecutionPolicy Bypass -File `\"$PolicyScript`\"\") `",
      "  -Trigger $triggers `",
      "  -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)) `",
      "  -RunLevel Highest -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount) | Out-Null",
      '',
      '# Device registrieren',
      'try {',
      '  $regHeaders = @{ "X-OD-Token" = $OdToken; "Content-Type" = "application/json" }',
      '  $regBody = @{',
      '    device_id     = $DeviceId',
      '    hostname      = $env:COMPUTERNAME',
      '    platform      = "windows"',
      '    os_version    = [System.Environment]::OSVersion.VersionString',
      '    ip_address    = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet*","Wi-Fi*" -EA SilentlyContinue | Select-Object -First 1).IPAddress',
      '  } | ConvertTo-Json',
      '  Invoke-RestMethod -Method Post -Uri "$PortalUrl/api/client/register" -Headers $regHeaders -Body $regBody -UseBasicParsing -TimeoutSec 10 -EA SilentlyContinue',
      '} catch {}',
      '',
      '# Sofort ausführen',
      '& powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $MountScript',
      '& powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $PolicyScript',
      "Write-Host 'OpenDirectory Client installiert!' -ForegroundColor Green",
      "Write-Host \"Device-ID: $DeviceId\" -ForegroundColor Cyan",
      "Write-Host 'Laufwerke und Policies werden bei jedem Start automatisch angewendet.' -ForegroundColor Cyan",
    ].join('\r\n');
  }

  if (os === 'macos') {
    return [
      '#!/bin/bash',
      '# OpenDirectory Client Setup (macOS)',
      '# Ausfuehren: sudo bash <(curl -sk ' + p + '/api/network/install-script/macos)',
      '',
      'set -e',
      "PORTAL='" + p + "'",
      "OD_TOKEN='" + tok + "'",
      'SCRIPT_DIR="/Library/OpenDirectory"',
      'mkdir -p "$SCRIPT_DIR"',
      '',
      '# Persistente Konfiguration (gelesen von enforce.sh + od-agent)',
      'echo "$PORTAL"   > "$SCRIPT_DIR/portal-url"',
      'echo "$OD_TOKEN" > "$SCRIPT_DIR/od-token"',
      'chmod 600 "$SCRIPT_DIR/od-token"',
      '',
      '# Device-ID: einmalig generieren',
      'DEVID_FILE="$SCRIPT_DIR/device-id"',
      'if [ ! -f "$DEVID_FILE" ]; then',
      '  uuidgen > "$DEVID_FILE" 2>/dev/null || cat /proc/sys/kernel/random/uuid > "$DEVID_FILE" 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())" > "$DEVID_FILE"',
      'fi',
      'DEVICE_ID=$(cat "$DEVID_FILE")',
      '',
      '# ── Haupt-Agent-Script ────────────────────────────────────────────────────',
      'cat > "$SCRIPT_DIR/od-agent.sh" << \'AGENTEOF\'',
      '#!/bin/bash',
      "PORTAL='" + p + "'",
      "OD_TOKEN='" + tok + "'",
      'SCRIPT_DIR="/Library/OpenDirectory"',
      'DEVICE_ID=$(cat "$SCRIPT_DIR/device-id" 2>/dev/null); [ -z "$DEVICE_ID" ] && exit 0',
      'USERNAME=$(stat -f "%Su" /dev/console 2>/dev/null || echo "$USER")',
      '',
      '# Heartbeat',
      'curl -sk -X POST "$PORTAL/api/client/heartbeat" \\',
      '  -H "X-OD-Token: $OD_TOKEN" -H "Content-Type: application/json" \\',
      '  -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"macos\",\"os_version\":\"$(sw_vers -productVersion)\"}" >/dev/null 2>&1 || true',
      '',
      '# Netzlaufwerke (für den aktuellen Benutzer)',
      'shares=$(curl -sk --max-time 10 "$PORTAL/api/network/shares/for-user/$USERNAME" 2>/dev/null)',
      'if [ -n "$shares" ]; then',
      '  echo "$shares" | python3 -c "',
      'import json,sys,subprocess',
      'data=json.load(sys.stdin)',
      "for s in data.get(\"shares\",[]):",
      "  if s[\"protocol\"]==\"SMB\": subprocess.run([\"open\",s[\"smb_url\"]],capture_output=True)",
      '  " 2>/dev/null || true',
      'fi',
      '',
      '# Policies holen + anwenden',
      'policies=$(curl -sk --max-time 30 -H "X-OD-Token: $OD_TOKEN" "$PORTAL/api/client/policies?device_id=$DEVICE_ID" 2>/dev/null)',
      '[ -z "$policies" ] && exit 0',
      'echo "$policies" | python3 - "$SCRIPT_DIR" "$PORTAL" "$OD_TOKEN" "$DEVICE_ID" << \'PYEOF\'',
      'import json,sys,subprocess,os,tempfile',
      'script_dir,portal,token,device_id = sys.argv[1:5]',
      'data = json.loads(sys.stdin.read())',
      "for p in data.get('policies',[]):",
      "  arts = p.get('artifacts',{}).get('macos',[])",
      '  compliant = True',
      '  for a in arts:',
      "    path = os.path.join(script_dir, a['filename'])",
      "    open(path,'w').write(a['content'])",
      "    if a['filename'].endswith('.mobileconfig'):",
      "      r = subprocess.run(['profiles','install','-path',path],capture_output=True)",
      "      if r.returncode != 0: compliant = False",
      '  import urllib.request',
      "  req = urllib.request.Request(f\"{portal}/api/client/compliance-report\",",
      "    data=json.dumps({'device_id':device_id,'policy_id':p['id'],'compliant':compliant,'drift':[]}).encode(),",
      "    headers={'X-OD-Token':token,'Content-Type':'application/json'}, method='POST')",
      '  try: urllib.request.urlopen(req,timeout=10)',
      '  except: pass',
      'PYEOF',
      'AGENTEOF',
      'chmod +x "$SCRIPT_DIR/od-agent.sh"',
      '',
      '# ── LaunchDaemon (als root, bei Start + alle 4h) ──────────────────────────',
      'cat > /Library/LaunchDaemons/local.opendirectory.agent.plist << \'PLISTEOF\'',
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
      '<plist version="1.0"><dict>',
      '  <key>Label</key><string>local.opendirectory.agent</string>',
      '  <key>ProgramArguments</key><array><string>/bin/bash</string><string>/Library/OpenDirectory/od-agent.sh</string></array>',
      '  <key>RunAtLoad</key><true/>',
      '  <key>StartInterval</key><integer>14400</integer>',
      '  <key>StandardErrorPath</key><string>/var/log/od-agent.log</string>',
      '</dict></plist>',
      'PLISTEOF',
      '',
      'launchctl unload /Library/LaunchDaemons/local.opendirectory.agent.plist 2>/dev/null || true',
      'launchctl load -w /Library/LaunchDaemons/local.opendirectory.agent.plist',
      '',
      '# Device registrieren',
      'curl -sk -X POST "$PORTAL/api/client/register" \\',
      '  -H "X-OD-Token: $OD_TOKEN" -H "Content-Type: application/json" \\',
      '  -d "{\"device_id\":\"$DEVICE_ID\",\"hostname\":\"$(hostname -s)\",\"platform\":\"macos\",\"os_version\":\"$(sw_vers -productVersion)\",\"ip_address\":\"$(ipconfig getifaddr en0 2>/dev/null || echo \'\')\",\"kernel_version\":\"$(uname -r)\"}" >/dev/null 2>&1 || true',
      '',
      'bash "$SCRIPT_DIR/od-agent.sh" &',
      '',
      '# ── MDM-Enrollment (empfohlen fuer verwaltete Geraete) ──────────────────',
      'MDM_ENROLL_URL="https://' + MDM_HOST + '/enrollment.mobileconfig"',
      'echo ""',
      'echo "── MDM-Enrollment fuer verwaltete Geraete ───────────────────────────"',
      'curl -sk --max-time 10 "$MDM_ENROLL_URL" -o /tmp/od-mdm-enrollment.mobileconfig 2>/dev/null || true',
      'if [ -s /tmp/od-mdm-enrollment.mobileconfig ]; then',
      '  open /tmp/od-mdm-enrollment.mobileconfig',
      '  echo "Das MDM-Enrollment-Profil wird in den Systemeinstellungen geoeffnet."',
      '  echo "Profil installieren - dann sind Policies MDM-verwaltet und koennen nicht entfernt werden."',
      'else',
      '  echo "MDM-Server nicht erreichbar. Enrollment spaeter nachholen:"',
      '  echo "  open https://' + MDM_HOST + '/enroll"',
      'fi',
      '',
      'echo "OpenDirectory Client installiert!"',
      'echo "Device-ID: $DEVICE_ID"',
      'echo "Laufwerke und Policies werden bei jedem Start automatisch angewendet."',
    ].join('\n');
  }

  // ── Linux ─────────────────────────────────────────────────────────────────────
  return [
    '#!/bin/bash',
    '# OpenDirectory Client Setup (Linux)',
    '# Als root ausfuehren: bash <(curl -sk ' + p + '/api/network/install-script/linux)',
    '',
    'set -e',
    "PORTAL='" + p + "'",
    "OD_TOKEN='" + tok + "'",
    'SCRIPT_DIR="/etc/opendirectory"',
    'mkdir -p "$SCRIPT_DIR"',
    '',
    '# Abhängigkeiten installieren',
    'if command -v apt-get &>/dev/null; then',
    '  apt-get install -y -q cifs-utils nfs-common curl python3 2>/dev/null || true',
    'elif command -v yum &>/dev/null; then',
    '  yum install -y -q cifs-utils nfs-utils curl python3 2>/dev/null || true',
    'fi',
    '',
    '# Device-ID: einmalig generieren',
    'DEVID_FILE="$SCRIPT_DIR/device-id"',
    'if [ ! -f "$DEVID_FILE" ]; then',
    '  (cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c "import uuid;print(uuid.uuid4())") > "$DEVID_FILE"',
    'fi',
    'DEVICE_ID=$(cat "$DEVID_FILE")',
    '',
    '# ── Haupt-Agent-Script ────────────────────────────────────────────────────',
    'cat > /usr/local/bin/od-agent << \'AGENTEOF\'',
    '#!/bin/bash',
    "PORTAL='" + p + "'",
    "OD_TOKEN='" + tok + "'",
    'SCRIPT_DIR="/etc/opendirectory"',
    'DEVICE_ID=$(cat "$SCRIPT_DIR/device-id" 2>/dev/null); [ -z "$DEVICE_ID" ] && exit 0',
    'USERNAME="${PAM_USER:-$(who am i 2>/dev/null | awk \'{print $1}\') }"',
    'USERNAME="${USERNAME:-$(whoami)}"',
    '',
    '# Heartbeat',
    'curl -sk -X POST "$PORTAL/api/client/heartbeat" \\',
    '  -H "X-OD-Token: $OD_TOKEN" -H "Content-Type: application/json" \\',
    '  -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"linux\",\"os_version\":\"$(uname -r)\",\"ip_address\":\"$(hostname -I | awk \'{print $1}\')\"}" >/dev/null 2>&1 || true',
    '',
    '# Netzlaufwerke für Benutzer',
    'shares=$(curl -sk --max-time 10 "$PORTAL/api/network/shares/for-user/$USERNAME" 2>/dev/null)',
    'if [ -n "$shares" ]; then',
    '  echo "$shares" | python3 -c "',
    'import json,sys,subprocess,os',
    'data=json.load(sys.stdin)',
    "for s in data.get(\"shares\",[]):",
    "  if s.get(\"protocol\")==\"SMB\":",
    "    mp=f\"/mnt/{s['name'].lower().replace(' ','-')}\"",
    '    os.makedirs(mp,exist_ok=True)',
    "    unc=f\"//{s['server']}/{s['path'].lstrip(\\'/ \\')}\"",
    "    subprocess.run([\"mount\",\"-t\",\"cifs\",unc,mp,\"-o\",\"guest,uid=$(id -u $USER)\"],capture_output=True)",
    '  " 2>/dev/null || true',
    'fi',
    '',
    '# Policies holen + anwenden',
    'policies=$(curl -sk --max-time 30 -H "X-OD-Token: $OD_TOKEN" "$PORTAL/api/client/policies?device_id=$DEVICE_ID" 2>/dev/null)',
    '[ -z "$policies" ] && exit 0',
    'echo "$policies" | python3 - "$SCRIPT_DIR" "$PORTAL" "$OD_TOKEN" "$DEVICE_ID" << \'PYEOF\'',
    'import json,sys,subprocess,os,hashlib,urllib.request',
    'script_dir,portal,token,device_id = sys.argv[1:5]',
    'data = json.loads(sys.stdin.read())',
    '',
    '# ── Drift Detection: bestehende Hashes prüfen ─────────────────────────────',
    'manifest_path = "/etc/opendirectory/od-manifest.json"',
    'drift_detected = []',
    'if os.path.exists(manifest_path):',
    '  stored = json.loads(open(manifest_path).read())',
    '  for fpath, expected_hash in stored.items():',
    '    if os.path.exists(fpath):',
    '      actual = hashlib.sha256(open(fpath,"rb").read()).hexdigest()',
    '      if actual != expected_hash:',
    "        drift_detected.append({'file':fpath,'expected':expected_hash[:8],'actual':actual[:8]})",
    '',
    "for p in data.get('policies',[]):",
    "  arts = p.get('artifacts',{}).get('linux',[])",
    '  compliant = True',
    '  drift = []',
    '  for a in arts:',
    "    fn = a['filename']",
    "    content = a['content']",
    "    install_path = a.get('install_path','')",
    "    if fn == 'firefox-policies.json':",
    "      os.makedirs('/etc/firefox/policies',exist_ok=True)",
    "      open('/etc/firefox/policies/policies.json','w').write(content)",
    "    elif fn == 'chrome-policy.json':",
    "      os.makedirs('/etc/opt/chrome/policies/managed',exist_ok=True)",
    "      open('/etc/opt/chrome/policies/managed/od-policy.json','w').write(content)",
    "    elif fn.endswith('-sudoers'):",
    "      path=f'/etc/sudoers.d/{fn}'",
    "      open(path,'w').write(content); os.chmod(path,0o440)",
    "    elif fn == 'dconf-settings.ini':",
    "      path=os.path.join(script_dir,fn)",
    "      open(path,'w').write(content)",
    "      subprocess.run(['dconf','load','/'],input=content.encode(),capture_output=True)",
    "    elif fn == 'od-enforce.path' or fn == 'od-enforce.service':",
    "      dest = f'/etc/systemd/system/{fn}'",
    "      open(dest,'w').write(content)",
    "      subprocess.run(['systemctl','daemon-reload'],capture_output=True)",
    "      subprocess.run(['systemctl','enable','--now',fn],capture_output=True)",
    "    elif fn == 'od-manifest.json':",
    "      os.makedirs('/etc/opendirectory',exist_ok=True)",
    "      open('/etc/opendirectory/od-manifest.json','w').write(content)",
    "    elif fn.endswith('.sh'):",
    "      path=os.path.join(script_dir,fn)",
    "      open(path,'w').write(content); os.chmod(path,0o755)",
    "      subprocess.run(['bash',path],capture_output=True)",
    "    elif install_path:",
    "      os.makedirs(os.path.dirname(install_path),exist_ok=True)",
    "      open(install_path,'w').write(content)",
    "      if 'sshd_config' in install_path:",
    "        subprocess.run(['systemctl','reload-or-restart','sshd'],capture_output=True)",
    "      elif 'sysctl' in install_path:",
    "        subprocess.run(['sysctl','-p',install_path],capture_output=True)",
    "      elif 'audit/rules.d' in install_path:",
    "        subprocess.run(['augenrules','--load'],capture_output=True)",
    "        subprocess.run(['systemctl','reload-or-restart','auditd'],capture_output=True)",
    '  drift = [d for d in drift_detected if any(d["file"] in (a.get("install_path","")) for a in arts)]',
    '  compliant = len(drift) == 0',
    '  req = urllib.request.Request(f"{portal}/api/client/compliance-report",',
    "    data=json.dumps({'device_id':device_id,'policy_id':p['id'],'compliant':compliant,'drift':drift}).encode(),",
    "    headers={'X-OD-Token':token,'Content-Type':'application/json'}, method='POST')",
    '  try: urllib.request.urlopen(req,timeout=10)',
    '  except: pass',
    'PYEOF',
    'AGENTEOF',
    'chmod +x /usr/local/bin/od-agent',
    '',
    '# ── systemd Timer (alle 4h) ───────────────────────────────────────────────',
    'cat > /etc/systemd/system/od-agent.service << \'SVCEOF\'',
    '[Unit]',
    'Description=OpenDirectory Policy Agent',
    'After=network-online.target',
    'Wants=network-online.target',
    '[Service]',
    'Type=oneshot',
    'ExecStart=/usr/local/bin/od-agent',
    'StandardOutput=journal',
    'SVCEOF',
    '',
    'cat > /etc/systemd/system/od-agent.timer << \'TIMEREOF\'',
    '[Unit]',
    'Description=OpenDirectory Policy Agent Timer',
    '[Timer]',
    'OnBootSec=1min',
    'OnUnitActiveSec=4h',
    '[Install]',
    'WantedBy=timers.target',
    'TIMEREOF',
    '',
    'if command -v systemctl &>/dev/null; then',
    '  systemctl daemon-reload',
    '  systemctl enable --now od-agent.timer 2>/dev/null || true',
    'fi',
    '',
    '# PAM: Agent bei Benutzer-Login aufrufen',
    'cat > /etc/pam.d/od-agent << PAMEOF',
    'session optional pam_exec.so seteuid /usr/local/bin/od-agent',
    'PAMEOF',
    '',
    'if ! grep -q od-agent /etc/pam.d/common-session 2>/dev/null; then',
    '  echo "@include od-agent" >> /etc/pam.d/common-session',
    'fi',
    '',
    '# Device registrieren',
    'curl -sk -X POST "$PORTAL/api/client/register" \\',
    '  -H "X-OD-Token: $OD_TOKEN" -H "Content-Type: application/json" \\',
    "  -d \"{\\\"device_id\\\":\\\"$DEVICE_ID\\\",\\\"hostname\\\":\\\"$(hostname -s)\\\",\\\"platform\\\":\\\"linux\\\",\\\"os_version\\\":\\\"$(uname -r)\\\",\\\"ip_address\\\":\\\"$(hostname -I | awk '{print $1}')\\\",\\\"kernel_version\\\":\\\"$(uname -r)\\\",\\\"package_manager\\\":\\\"$(command -v apt-get &>/dev/null && echo apt || echo yum)\\\"}\" >/dev/null 2>&1 || true",
    '',
    '/usr/local/bin/od-agent &',
    'echo "OpenDirectory Client installiert!"',
    'echo "Device-ID: $DEVICE_ID"',
    'echo "Laufwerke und Policies werden bei jedem Login automatisch angewendet."',
  ].join('\n');
}

app.get('/api/network/install-script/windows', (req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="Install-OpenDirectory.ps1"');
  res.send(makeInstallScript('windows'));
});

app.get('/api/network/install-script/macos', (req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="install-od-mounts.sh"');
  res.send(makeInstallScript('macos'));
});

app.get('/api/network/install-script/linux', (req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="install-od-mounts.sh"');
  res.send(makeInstallScript('linux'));
});

// ── Policy-as-Code: Templates ──────────────────────────────────────────────────
app.get('/api/policies/templates', (req, res) => {
  if (!policyTemplates) return res.json({ templates: [], categories: [] });
  const cat = req.query.category;
  const templates = cat && cat !== 'all'
    ? policyTemplates.POLICY_TEMPLATES.filter(t => t.category === cat)
    : policyTemplates.POLICY_TEMPLATES;
  res.json({ templates, categories: policyTemplates.CATEGORIES });
});

app.get('/api/policies/templates/:templateId', (req, res) => {
  if (!policyTemplates) return res.status(503).json({ error: 'Compiler not loaded' });
  const tpl = policyTemplates.POLICY_TEMPLATES.find(t => t.templateId === req.params.templateId);
  if (!tpl) return res.status(404).json({ error: 'Template not found' });
  res.json(tpl);
});

// ── Intent Resource Resolver ───────────────────────────────────────────────────
// Ersetzt _shareId / _printerId Referenzen im Policy-Intent mit aktuellen DB-Daten.
// So bleibt die gespeicherte Policy immer auf dem neuesten Stand der Infrastruktur.
async function resolveIntentResources(intent) {
  if (!intent || !intent.settings) return intent;
  const settings = { ...intent.settings };

  // Netzlaufwerke: _shareId → aktuelle Daten aus network_shares
  if (Array.isArray(settings.networkDrives) && settings.networkDrives.length > 0) {
    const ids = settings.networkDrives.map(d => d._shareId).filter(Boolean);
    if (ids.length > 0) {
      const res = await db.query('SELECT * FROM network_shares WHERE id = ANY($1)', [ids]);
      const shareMap = Object.fromEntries(res.rows.map(s => [s.id, s]));
      settings.networkDrives = settings.networkDrives.map(d => {
        if (!d._shareId) return d;
        const s = shareMap[d._shareId];
        if (!s) return null;
        return {
          _shareId:   s.id,
          letter:     s.drive_letter || 'Z',
          label:      s.name,
          type:       s.protocol === 'nfs' ? 'nfs' : 'smb',
          server:     s.server,
          share:      s.path.replace(/^\//, ''),
          mountPoint: `/mnt/${s.name.toLowerCase().replace(/\s+/g, '-')}`,
          reconnect:  true,
        };
      }).filter(Boolean);
    }
  }

  // Drucker: _printerId → aktuelle Daten aus printers
  if (Array.isArray(settings.printers) && settings.printers.length > 0) {
    const ids = settings.printers.map(p => p._printerId).filter(Boolean);
    if (ids.length > 0) {
      const res = await db.query('SELECT * FROM printers WHERE id = ANY($1)', [ids]);
      const printerMap = Object.fromEntries(res.rows.map(p => [p.id, p]));
      settings.printers = settings.printers.map(p => {
        if (!p._printerId) return p;
        const pr = printerMap[p._printerId];
        if (!pr) return null;
        return {
          _printerId: pr.id,
          name:       pr.name.replace(/\s+/g, '-'),
          label:      pr.name,
          ipAddress:  pr.ip,
          protocol:   pr.protocol || 'ipp',
          driver:     pr.driver  || 'HP Universal Printing PCL 6',
          location:   pr.location || '',
          default:    p.default || false,
        };
      }).filter(Boolean);
    }
  }

  return { ...intent, settings };
}

// ── Policy-as-Code: Compile ────────────────────────────────────────────────────
app.post('/api/policies/compile', async (req, res) => {
  if (!policyCompiler) return res.status(503).json({ error: 'Policy Compiler not available' });
  try {
    const raw = req.body;
    if (!raw.name) return res.status(400).json({ error: 'policy.name required' });
    const policy = await resolveIntentResources(raw);
    const result = policyCompiler.compile(policy);
    res.json({ success: true, result });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Policy-as-Code: Save + Compile ────────────────────────────────────────────
app.post('/api/policies/save-compiled', async (req, res) => {
  if (!policyCompiler) return res.status(503).json({ error: 'Policy Compiler not available' });
  try {
    const { name, description, category, intent, platforms, target_groups } = req.body;
    if (!name || !intent) return res.status(400).json({ error: 'name and intent required' });

    // Intent-Referenzen (shareId/printerId) zur Compile-Zeit auflösen
    const resolvedIntent = await resolveIntentResources({ ...intent, name, targets: { platforms, groups: target_groups } });
    const compiled = policyCompiler.compile(resolvedIntent);
    const id = genId();
    const version = '1.0';

    await db.query(`
      INSERT INTO policies (id, name, description, type, category, enabled, intent_json, compiled_json, version, platforms, target_groups, deploy_status, created_at, updated_at)
      VALUES ($1,$2,$3,'policy-as-code',$4,true,$5,$6,$7,$8,$9,'compiled',NOW(),NOW())
      ON CONFLICT (id) DO UPDATE SET
        name=EXCLUDED.name, description=EXCLUDED.description,
        intent_json=EXCLUDED.intent_json, compiled_json=EXCLUDED.compiled_json,
        version=EXCLUDED.version, updated_at=NOW()
    `, [id, name, description||'', category||'custom',
        JSON.stringify(intent), JSON.stringify(compiled),
        version, JSON.stringify(platforms||['windows','linux','macos']),
        JSON.stringify(target_groups||[])]);

    // Save to version history
    await db.query(
      'INSERT INTO policy_versions (id,policy_id,version,intent_json) VALUES ($1,$2,$3,$4)',
      [genId(), id, version, JSON.stringify(intent)]
    );

    // Auto-MDM-Push: wenn NanoMDM konfiguriert → alle enrolled macOS-Geräte pushen
    if (NANOMDM_API_KEY && compiled?.artifacts?.macos?.length > 0) {
      setImmediate(async () => {
        try {
          const macDevices = await db.query(
            "SELECT id FROM devices WHERE platform='macos' AND status != 'decommissioned'"
          );
          const macosArtifacts = compiled.artifacts.macos.filter(a => a.type === 'mobileconfig');
          if (macosArtifacts.length === 0 || macDevices.rowCount === 0) return;
          const profilePayload = macosArtifacts[0].content;
          for (const dev of macDevices.rows) {
            const command = {
              udid: dev.id,
              request_type: 'InstallProfile',
              payload: Buffer.from(profilePayload).toString('base64'),
            };
            await axios.post(`${NANOMDM_URL}/v1/enqueue/${dev.id}`, command, {
              headers: { Authorization: `Basic ${Buffer.from(`nanomdm:${NANOMDM_API_KEY}`).toString('base64')}` },
              timeout: 5000,
            }).catch(() => {}); // ignore per-device errors
          }
          console.log(`MDM push triggered for ${macDevices.rowCount} macOS device(s) after policy compile`);
        } catch (e) {
          console.error('Auto MDM push failed:', e.message);
        }
      });
    }

    res.json({ success: true, id, compiled });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Policy: Get compiled artifacts ────────────────────────────────────────────
app.get('/api/policies/:id/compiled', async (req, res) => {
  try {
    const r = await db.query('SELECT compiled_json, name, version FROM policies WHERE id=$1', [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Policy not found' });
    const { compiled_json, name, version } = r.rows[0];
    if (!compiled_json) return res.json({ compiled: null, message: 'Policy not yet compiled' });
    res.json({ policy: name, version, compiled: compiled_json });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Policy: Download artifact ──────────────────────────────────────────────────
app.get('/api/policies/:id/artifact/:platform/:filename', async (req, res) => {
  try {
    const r = await db.query('SELECT compiled_json FROM policies WHERE id=$1', [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Policy not found' });
    const compiled = r.rows[0].compiled_json;
    const { platform, filename } = req.params;
    const platformArtifacts = compiled?.artifacts?.[platform] || [];
    const artifact = platformArtifacts.find(a => a.filename === filename);
    if (!artifact) return res.status(404).json({ error: 'Artifact not found' });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(artifact.content);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Samba GPO Auto-Deployment via SSH ─────────────────────────────────────────
// SSH-Key: /etc/ssh/samba_key (aus K8s Secret samba-ssh-key gemountet)
// Env: SAMBA_SSH_USER (default: root), SAMBA_SSH_KEY_PATH

const SAMBA_SSH_USER = process.env.SAMBA_SSH_USER || 'root';
const SAMBA_SSH_KEY  = process.env.SAMBA_SSH_KEY_PATH || '/etc/ssh/samba_key';

async function deploySambaGPO({ policyId, policyName, dcIp, domain, adminUser, adminPass, compiled, existingGpoGuid }) {
  const sshOpts = `-i "${SAMBA_SSH_KEY}" -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes`;
  const target  = `${SAMBA_SSH_USER}@${dcIp}`;

  // Run a command on the DC via SSH
  const ssh = (cmd) => execAsync(`ssh ${sshOpts} ${target} ${JSON.stringify(cmd)}`);

  // Write a local temp file and SCP it to a remote path
  const scpContent = async (content, remotePath) => {
    const tmp = `/tmp/od-gpo-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    fs.writeFileSync(tmp, content, 'utf8');
    try {
      await execAsync(`scp ${sshOpts} "${tmp}" "${target}:${remotePath}"`);
    } finally {
      try { fs.unlinkSync(tmp); } catch {}
    }
  };

  const creds = `-U '${adminUser}%${adminPass.replace(/'/g, "'\\''")}'`;

  // Bug 7: Delete previous GPO if re-deploying, to avoid stale GPOs accumulating on the DC
  if (existingGpoGuid) {
    await ssh(`samba-tool gpo del '${existingGpoGuid.replace(/'/g, "'\\''")}'  ${creds} 2>/dev/null || true`);
  }

  // 1. Create GPO — samba-tool returns the GUID
  // Bug 1 fix: use "'\''" pattern (end-quote, literal-quote, re-open) for bash single-quote escaping.
  // The old "\'" pattern does NOT escape in bash single-quoted strings — \ is always literal there.
  const safeName = policyName.replace(/'/g, "'\\''");
  const { stdout: gpoOut } = await ssh(`samba-tool gpo create '${safeName}' ${creds}`);
  const gpoGuid = gpoOut.match(/\{[0-9A-Fa-f-]{36}\}/)?.[0];
  if (!gpoGuid) throw new Error(`samba-tool gpo create returned no GUID:\n${gpoOut}`);

  // 2. Create SYSVOL directory structure
  const sysvol = `/var/lib/samba/sysvol/${domain}/Policies/${gpoGuid}`;
  await ssh([
    `mkdir -p`,
    `"${sysvol}/Machine/Microsoft/Windows NT/SecEdit"`,
    `"${sysvol}/Machine/Scripts/Startup"`,
    `"${sysvol}/Machine/Scripts/Shutdown"`,
    `"${sysvol}/Machine/Preferences/Registry"`,
    `"${sysvol}/User/Preferences/Registry"`,
    `"${sysvol}/User/Preferences/Drives"`,
    `"${sysvol}/User/Preferences/Printers"`,
  ].join(' '));

  // 3. Write GPT.INI (required for clients to read the GPO)
  const gptIni = `[General]\r\nVersion=65537\r\nDisplayName=Version 1\r\n`;
  await scpContent(gptIni, `${sysvol}/GPT.INI`);

  // 4. Copy each Windows artifact to its SYSVOL path
  // gpt_ini is skipped here — we wrote it directly in step 3 with Version=65537
  const winArtifacts = compiled?.artifacts?.windows || [];
  let deployed = 0;
  for (const artifact of winArtifacts) {
    if (!artifact.sysvol_path) continue;
    if (artifact.type === 'gpt_ini') continue; // written directly in step 3
    const remotePath = `${sysvol}/${artifact.sysvol_path}`;
    const remoteDir  = remotePath.substring(0, remotePath.lastIndexOf('/'));
    await ssh(`mkdir -p "${remoteDir}"`);
    await scpContent(artifact.content, remotePath);
    deployed++;
  }

  // 5. Fix SYSVOL permissions (Samba requires specific ACLs)
  await ssh(`samba-tool ntacl sysvolreset --use-ntvfs 2>/dev/null || true`);

  // 6. Link GPO to domain root OU
  const domainDN = domain.split('.').map(p => `DC=${p}`).join(',');
  await ssh(`samba-tool gpo link '${domainDN}' ${gpoGuid} ${creds} 2>/dev/null || true`);

  // 6.5 Register CSE GUIDs on the GPO object in AD (required for clients to apply settings)
  // Without these attributes, Windows ignores the GPO contents entirely.
  // Pairs: [{CSE_GUID}{TOOL_GUID}]  — tool GUIDs are standard Microsoft extension GUIDs
  const hasMachineReg  = winArtifacts.some(a => a.sysvol_path?.startsWith('Machine/Preferences/Registry'));
  const hasUserReg     = winArtifacts.some(a => a.sysvol_path?.startsWith('User/Preferences/Registry'));
  const hasSecurity    = winArtifacts.some(a => a.type === 'security_template');
  const hasScripts     = winArtifacts.some(a => a.type === 'scripts_ini');

  const machineCses = [
    hasMachineReg && '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]',
    hasSecurity   && '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]',
    hasScripts    && '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]',
  ].filter(Boolean).join('');

  const userCses = [
    hasUserReg && '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]',
  ].filter(Boolean).join('');

  const gpoDn = `CN=${gpoGuid},CN=Policies,CN=System,${domainDN}`;
  const samLdb = '/var/lib/samba/private/sam.ldb';

  // Bug 1 fix: pass LDIF via scpContent (temp file) so real newlines are preserved.
  // echo ${JSON.stringify(ldif)} on the remote shell produces literal \n, not newlines.
  const applyLdif = async (ldif) => {
    const remoteTmp = `/tmp/od-ldif-${gpoGuid.replace(/[{}]/g,'')}-${Date.now()}.ldif`;
    await scpContent(ldif, remoteTmp);
    await ssh(`ldbmodify -H ${samLdb} ${remoteTmp} 2>/dev/null; rm -f ${remoteTmp}`);
  };

  if (machineCses) {
    await applyLdif([
      `dn: ${gpoDn}`,
      'changetype: modify',
      'replace: gPCMachineExtensionNames',
      `gPCMachineExtensionNames: ${machineCses}`,
      '',
    ].join('\n'));
  }

  if (userCses) {
    await applyLdif([
      `dn: ${gpoDn}`,
      'changetype: modify',
      'replace: gPCUserExtensionNames',
      `gPCUserExtensionNames: ${userCses}`,
      '',
    ].join('\n'));
  }

  // 7. Update DB
  await db.query(
    "UPDATE policies SET deploy_status='deployed', gpo_guid=$1, last_deployed=NOW() WHERE id=$2",
    [gpoGuid, policyId]
  );

  return { gpoGuid, deployed, sysvol };
}

// ── Policy: Deploy to Samba SYSVOL (Windows) ──────────────────────────────────
app.post('/api/policies/:id/deploy/windows', async (req, res) => {
  try {
    const polR = await db.query('SELECT compiled_json, name, gpo_guid AS existing_gpo_guid FROM policies WHERE id=$1', [req.params.id]);
    if (polR.rowCount === 0) return res.status(404).json({ error: 'Policy not found' });
    const { compiled_json: compiled, name: policyName, existing_gpo_guid: existingGpoGuid } = polR.rows[0];
    const winArtifacts = compiled?.artifacts?.windows || [];

    // Get DC config
    const cfgR = await db.query("SELECT dc_ip, domain, admin_user, admin_pass FROM ad_config WHERE id='default'");
    const cfg = cfgR.rows[0];

    // Check if SSH key exists and DC is configured → try auto-deploy
    const sshKeyExists = fs.existsSync(SAMBA_SSH_KEY);
    if (cfg?.dc_ip && sshKeyExists) {
      try {
        const result = await deploySambaGPO({
          policyId:        req.params.id,
          policyName,
          dcIp:            cfg.dc_ip,
          domain:          cfg.domain,
          adminUser:       cfg.admin_user || 'Administrator',
          adminPass:       cfg.admin_pass || '',
          compiled,
          existingGpoGuid, // Bug 7: delete old GPO before creating new one
        });
        return res.json({
          success:  true,
          auto:     true,
          message:  `GPO «${policyName}» automatisch auf DC deployed`,
          gpo_guid: result.gpoGuid,
          deployed: result.deployed,
          sysvol:   result.sysvol,
          dc_ip:    cfg.dc_ip,
          domain:   cfg.domain,
        });
      } catch (sshErr) {
        // SSH failed → fall through to manual instructions
        console.error('SYSVOL auto-deploy failed:', sshErr.message);
      }
    }

    // Fallback: return manual instructions
    if (!cfg?.dc_ip) {
      return res.json({
        success: false,
        auto:    false,
        message: 'DC nicht konfiguriert. Konfiguriere den DC unter Einstellungen → Active Directory.',
        artifacts: winArtifacts,
        instructions: winArtifacts
          .filter(a => a.sysvol_path)
          .map(a => `scp ${a.filename} root@<DC_IP>:/var/lib/samba/sysvol/<DOMAIN>/Policies/<GPO_GUID>/${a.sysvol_path}`),
      });
    }

    const { dc_ip, domain } = cfg;
    const instructions = winArtifacts
      .filter(a => a.sysvol_path)
      .map(a => `scp ${a.filename} root@${dc_ip}:/var/lib/samba/sysvol/${domain}/Policies/<GPO_GUID>/${a.sysvol_path}`);

    // Mark as deployed even in manual mode
    await db.query("UPDATE policies SET deploy_status='deployed', last_deployed=NOW() WHERE id=$1", [req.params.id]);

    res.json({
      success:      true,
      auto:         false,
      message:      `SSH-Key nicht gefunden (${SAMBA_SSH_KEY}). Manuelle Deployment-Anweisungen:`,
      setup_hint:   `kubectl create secret generic samba-ssh-key --from-file=id_ed25519=/root/.ssh/id_ed25519 -n opendirectory`,
      dc_ip, domain,
      instructions,
      artifacts: winArtifacts,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Policy: Get version history ────────────────────────────────────────────────
app.get('/api/policies/:id/versions', async (req, res) => {
  try {
    const r = await db.query(
      'SELECT id, version, compiled_at, deployed_by, comment FROM policy_versions WHERE policy_id=$1 ORDER BY compiled_at DESC',
      [req.params.id]
    );
    res.json({ versions: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Policy: Assign to device / group ──────────────────────────────────────────
app.post('/api/policies/:id/assign', async (req, res) => {
  const { device_ids = [], target_group = '', push = false } = req.body;
  if (!device_ids.length && !target_group && !push) {
    return res.status(400).json({ error: 'device_ids, target_group, or push:true required' });
  }
  try {
    let ids = [...device_ids];
    // push:true → assign to all active devices
    if (push) {
      const allDevices = await db.query(
        "SELECT id FROM devices WHERE status != 'decommissioned'"
      );
      allDevices.rows.forEach(r => { if (!ids.includes(r.id)) ids.push(r.id); });
    }
    // If target_group specified: find all devices in that group
    if (target_group) {
      const grpDevices = await db.query(
        "SELECT id FROM devices WHERE $1 = ANY(groups) AND decommissioned IS NOT TRUE",
        [target_group]
      );
      grpDevices.rows.forEach(r => { if (!ids.includes(r.id)) ids.push(r.id); });
    }
    let assigned = 0;
    for (const device_id of ids) {
      const dev = await db.query('SELECT platform FROM devices WHERE id=$1', [device_id]);
      if (dev.rowCount === 0) continue;
      await db.query(`
        INSERT INTO policies_assigned (id,policy_id,device_id,platform,target_group,deploy_status)
        VALUES ($1,$2,$3,$4,$5,'pending')
        ON CONFLICT (policy_id,device_id) DO UPDATE
          SET deploy_status='pending', target_group=EXCLUDED.target_group
      `, [genId(), req.params.id, device_id, dev.rows[0].platform||'unknown', target_group]);
      assigned++;
    }
    res.json({ success: true, assigned });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Policy: Recompile (nach needs_recompile) ───────────────────────────────────
app.post('/api/policies/:id/recompile', async (req, res) => {
  if (!policyCompiler) return res.status(503).json({ error: 'Policy Compiler not available' });
  try {
    const r = await db.query('SELECT * FROM policies WHERE id=$1', [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Policy not found' });
    const policy = r.rows[0];
    const intent  = policy.intent_json || {};
    const resolved = await resolveIntentResources({ ...intent, name: policy.name });
    const compiled = policyCompiler.compile(resolved);
    const newVersion = (() => {
      const parts = (policy.version || '1.0').split('.').map(Number);
      parts[1] = (parts[1] || 0) + 1;
      return parts.join('.');
    })();
    await db.query(
      `UPDATE policies SET compiled_json=$1, version=$2, deploy_status='compiled', updated_at=NOW() WHERE id=$3`,
      [JSON.stringify(compiled), newVersion, req.params.id]
    );
    await db.query(
      'INSERT INTO policy_versions (id,policy_id,version,intent_json) VALUES ($1,$2,$3,$4)',
      [genId(), req.params.id, newVersion, JSON.stringify(intent)]
    );

    // Auto-MDM-Push nach Recompile
    if (NANOMDM_API_KEY && compiled?.artifacts?.macos?.length > 0) {
      setImmediate(async () => {
        try {
          const macDevices = await db.query(
            "SELECT id FROM devices WHERE platform='macos' AND status != 'decommissioned'"
          );
          const macosArtifacts = compiled.artifacts.macos.filter(a => a.type === 'mobileconfig');
          if (macosArtifacts.length === 0 || macDevices.rowCount === 0) return;
          const profilePayload = macosArtifacts[0].content;
          for (const dev of macDevices.rows) {
            await axios.post(`${NANOMDM_URL}/v1/enqueue/${dev.id}`, {
              udid: dev.id, request_type: 'InstallProfile',
              payload: Buffer.from(profilePayload).toString('base64'),
            }, {
              headers: { Authorization: `Basic ${Buffer.from(`nanomdm:${NANOMDM_API_KEY}`).toString('base64')}` },
              timeout: 5000,
            }).catch(() => {});
          }
          console.log(`MDM push triggered for ${macDevices.rowCount} macOS device(s) after recompile`);
        } catch (e) { console.error('Auto MDM push (recompile) failed:', e.message); }
      });
    }

    res.json({ success: true, version: newVersion, compiled });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Client API (aufgerufen von OD-Client auf den Endpoints) ───────────────────
// Client registriert sich und fragt nach Policies + meldet Compliance zurück.
// Authentifizierung: einfaches shared secret via X-OD-Token Header.

const CLIENT_TOKEN = process.env.CLIENT_TOKEN || 'od-client-secret-change-me';

function requireClientToken(req, res, next) {
  const token = req.headers['x-od-token'] || req.query.token;
  if (token !== CLIENT_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// POST /api/client/register  — Gerät beim ersten Start registrieren (upsert)
app.post('/api/client/register', requireClientToken, async (req, res) => {
  const { device_id, hostname, platform, os_version, ip_address, kernel_version, package_manager } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id required' });
  try {
    await db.query(
      `INSERT INTO devices (id,name,platform,os_version,ip_address,kernel,package_manager,last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
       ON CONFLICT (id) DO UPDATE SET
         name=EXCLUDED.name, os_version=EXCLUDED.os_version,
         ip_address=EXCLUDED.ip_address, kernel=EXCLUDED.kernel,
         package_manager=EXCLUDED.package_manager, last_seen=NOW()`,
      [device_id, hostname||device_id, platform||'linux', os_version||'', ip_address||'', kernel_version||'', package_manager||'']
    );
    res.json({ success: true, device_id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/client/policies?device_id=xxx  — liefert alle kompilierten Policies für dieses Gerät
app.get('/api/client/policies', requireClientToken, async (req, res) => {
  const { device_id } = req.query;
  if (!device_id) return res.status(400).json({ error: 'device_id required' });
  try {
    // Update last_seen
    await db.query('UPDATE devices SET last_seen=NOW() WHERE id=$1', [device_id]);

    const r = await db.query(`
      SELECT pa.id AS assignment_id, pa.deploy_status,
             p.id, p.name, p.category, p.version, p.compiled_json, p.platforms
      FROM policies_assigned pa
      JOIN policies p ON p.id = pa.policy_id
      WHERE pa.device_id = $1
        AND pa.deploy_status IN ('pending','sync_pending','deployed')
        AND p.compiled_json IS NOT NULL
      ORDER BY pa.assigned_at
    `, [device_id]);

    const policies = r.rows.map(row => ({
      assignmentId: row.assignment_id,
      id:      row.id,
      name:    row.name,
      version: row.version,
      category: row.category,
      artifacts: row.compiled_json?.artifacts || {},
      deployStatus: row.deploy_status,
    }));

    // Mark as deployed
    const assignIds = r.rows.map(x => x.assignment_id);
    if (assignIds.length > 0) {
      await db.query(
        "UPDATE policies_assigned SET deploy_status='deployed', last_sync=NOW() WHERE id = ANY($1)",
        [assignIds]
      );
    }

    res.json({ success: true, device_id, policies });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/client/compliance-report  — Client meldet Compliance-Status
app.post('/api/client/compliance-report', requireClientToken, async (req, res) => {
  const { device_id, policy_id, compliant, drift = [], platform } = req.body;
  if (!device_id || !policy_id) return res.status(400).json({ error: 'device_id and policy_id required' });
  try {
    await db.query('UPDATE devices SET last_seen=NOW() WHERE id=$1', [device_id]);
    await db.query(
      `INSERT INTO compliance_results (id,device_id,policy_id,compliant,drift)
       VALUES ($1,$2,$3,$4,$5)`,
      [genId(), device_id, policy_id, !!compliant, JSON.stringify(drift)]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/client/heartbeat  — Client-Heartbeat (last_seen aktualisieren)
app.post('/api/client/heartbeat', requireClientToken, async (req, res) => {
  const { device_id, ip_address, os_version, platform } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id required' });
  try {
    await db.query(
      `UPDATE devices SET last_seen=NOW(),
         ip_address=COALESCE($1,ip_address),
         os_version=COALESCE($2,os_version),
         platform=COALESCE($3,platform)
       WHERE id=$4`,
      [ip_address||null, os_version||null, platform||null, device_id]
    );
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── MDM (NanoMDM Integration) ─────────────────────────────────────────────────
const NANOMDM_URL     = process.env.NANOMDM_URL     || 'http://nanomdm:9000';
const NANOMDM_API_KEY = process.env.NANOMDM_API_KEY || '';
const MDM_HOST        = process.env.MDM_HOST        || 'mdm.heusser.local';
const SCEP_CHALLENGE  = process.env.SCEP_CHALLENGE  || 'od-scep-challenge';

// GET /enrollment.mobileconfig — Enrollment Profile für macOS-Geräte
app.get('/enrollment.mobileconfig', (req, res) => {
  const profileId = 'local.opendirectory.mdm';
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.scep</string>
      <key>PayloadIdentifier</key>
      <string>${profileId}.scep</string>
      <key>PayloadUUID</key>
      <string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadDisplayName</key>
      <string>OpenDirectory SCEP</string>
      <key>PayloadContent</key>
      <dict>
        <key>URL</key>
        <string>https://${MDM_HOST}/scep</string>
        <key>Name</key>
        <string>OpenDirectory MDM</string>
        <key>Challenge</key>
        <string>${SCEP_CHALLENGE}</string>
        <key>KeySize</key>
        <integer>2048</integer>
        <key>KeyType</key>
        <string>RSA</string>
        <key>KeyUsage</key>
        <integer>5</integer>
        <key>Retries</key>
        <integer>3</integer>
        <key>RetryDelay</key>
        <integer>10</integer>
      </dict>
    </dict>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.mdm</string>
      <key>PayloadIdentifier</key>
      <string>${profileId}.mdm</string>
      <key>PayloadUUID</key>
      <string>B2C3D4E5-F6A7-8901-BCDE-F12345678901</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadDisplayName</key>
      <string>OpenDirectory MDM</string>
      <key>ServerURL</key>
      <string>https://${MDM_HOST}/mdm</string>
      <key>CheckInURL</key>
      <string>https://${MDM_HOST}/mdm/checkin</string>
      <key>CheckOutWhenRemoved</key>
      <true/>
      <key>AccessRights</key>
      <integer>8191</integer>
      <key>IdentityCertificateUUID</key>
      <string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
      <key>Topic</key>
      <string>com.apple.mgmt.External.opendirectory</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>OpenDirectory MDM Enrollment</string>
  <key>PayloadIdentifier</key>
  <string>${profileId}</string>
  <key>PayloadOrganization</key>
  <string>OpenDirectory</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>C3D4E5F6-A7B8-9012-CDEF-123456789012</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`;
  res.setHeader('Content-Type', 'application/x-apple-aspen-config');
  res.setHeader('Content-Disposition', 'attachment; filename="OpenDirectory-MDM.mobileconfig"');
  res.send(plist);
});

// GET /api/mdm/devices — enrolled macOS Geräte
app.get('/api/mdm/devices', async (req, res) => {
  try {
    const r = await db.query(
      "SELECT * FROM devices WHERE platform='macos' ORDER BY last_seen DESC"
    );
    // Anreichern mit MDM-Status aus NanoMDM (best-effort)
    const devices = r.rows.map(d => ({
      ...d,
      mdm_enrolled: !!d.mdm_enrolled,
    }));
    res.json({ success: true, data: devices });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/mdm/push/:deviceId — Profile an macOS-Gerät pushen
app.post('/api/mdm/push/:deviceId', async (req, res) => {
  const { policy_id } = req.body;
  if (!NANOMDM_API_KEY) {
    return res.json({
      success: false,
      message: 'NanoMDM nicht konfiguriert (NANOMDM_API_KEY fehlt)',
      hint: 'Setze NANOMDM_API_KEY als Umgebungsvariable im Integration Service Deployment.',
    });
  }
  try {
    // Lade compiled Policy
    const polR = await db.query('SELECT compiled_json, name FROM policies WHERE id=$1', [policy_id]);
    if (polR.rowCount === 0) return res.status(404).json({ error: 'Policy not found' });
    const macArtifacts = polR.rows[0].compiled_json?.artifacts?.macos || [];
    const profile = macArtifacts.find(a => a.filename.endsWith('.mobileconfig'));
    if (!profile) return res.status(400).json({ error: 'Kein .mobileconfig Artefakt für diese Policy' });

    // NanoMDM Command: InstallProfile
    const command = {
      command: {
        RequestType: 'InstallProfile',
        Payload: Buffer.from(profile.content).toString('base64'),
      },
      udids: [req.params.deviceId],
    };

    const pushRes = await axios.post(`${NANOMDM_URL}/v1/push/${req.params.deviceId}`, command, {
      headers: { Authorization: `Basic ${Buffer.from(`nanomdm:${NANOMDM_API_KEY}`).toString('base64')}` },
      timeout: 10000,
    });

    res.json({ success: true, message: `Profile an Gerät ${req.params.deviceId} gepusht`, nanomdm: pushRes.data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message,
      hint: `NanoMDM URL: ${NANOMDM_URL} — läuft der nanomdm Pod?` });
  }
});

// POST /api/mdm/enroll — Webhook von NanoMDM bei neuem MDM Enrollment
app.post('/api/mdm/enroll', async (req, res) => {
  try {
    const { UDID, SerialNumber, DeviceName, OSVersion, ProductName } = req.body || {};
    if (!UDID) return res.status(400).json({ error: 'UDID required' });
    await db.query(
      `INSERT INTO devices (id,name,platform,os_version,last_seen)
       VALUES ($1,$2,'macos',$3,NOW())
       ON CONFLICT (id) DO UPDATE SET
         name=EXCLUDED.name, os_version=EXCLUDED.os_version,
         last_seen=NOW()`,
      [UDID, DeviceName || SerialNumber || UDID, OSVersion || '']
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/mdm/status — NanoMDM Erreichbarkeit
app.get('/api/mdm/status', async (req, res) => {
  const configured = !!NANOMDM_API_KEY;
  if (!configured) {
    return res.json({ configured: false, reachable: false,
      setup: 'kubectl apply -f /tmp/nanommd-k8s.yaml' });
  }
  const reachable = await axios.get(`${NANOMDM_URL}/version`, { timeout: 3000 })
    .then(() => true).catch(() => false);
  const enrolled = await db.query("SELECT COUNT(*) FROM devices WHERE platform='macos'")
    .then(r => parseInt(r.rows[0].count)).catch(() => 0);
  res.json({ configured, reachable, enrolled, mdm_host: MDM_HOST, nanomdm_url: NANOMDM_URL });
});

// GET /enroll — MDM Enrollment landing page (human-readable)
app.get('/enroll', (req, res) => {
  const host = MDM_HOST;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenDirectory MDM Enrollment</title>
<style>
  body{font-family:-apple-system,sans-serif;max-width:600px;margin:60px auto;padding:0 20px;color:#1d1d1f}
  h1{font-size:28px;font-weight:700}
  .step{background:#f5f5f7;border-radius:12px;padding:20px;margin:16px 0}
  .step h3{margin:0 0 8px;font-size:15px;color:#6e6e73}
  a.btn{display:inline-block;background:#0071e3;color:#fff;text-decoration:none;
        padding:12px 24px;border-radius:8px;font-weight:600;margin-top:8px}
  code{background:#e8e8ed;padding:2px 6px;border-radius:4px;font-size:13px}
</style>
</head><body>
<h1>MDM-Enrollment</h1>
<p>Registriere dieses Mac-Gerät in OpenDirectory MDM, damit Policies automatisch verwaltet werden.</p>

<div class="step">
  <h3>Schritt 1 — Enrollment-Profil installieren</h3>
  <p>Klicke auf den Button, um das Profil herunterzuladen und zu installieren.</p>
  <a class="btn" href="/enrollment.mobileconfig">Enrollment-Profil laden</a>
</div>

<div class="step">
  <h3>Schritt 2 — Profil in Systemeinstellungen bestätigen</h3>
  <p>Öffne <strong>Systemeinstellungen → Datenschutz &amp; Sicherheit → Profile</strong>
  und klicke auf <em>Installieren</em>.</p>
</div>

<div class="step">
  <h3>Schritt 3 — Fertig</h3>
  <p>Nach der Installation sendet das Gerät einen Heartbeat an OpenDirectory.<br>
  Policies werden automatisch angewendet und können nicht vom Benutzer entfernt werden.</p>
</div>

<hr style="margin:32px 0;border:none;border-top:1px solid #d2d2d7">
<p style="color:#6e6e73;font-size:13px">
  SCEP: <code>https://${host}/scep</code><br>
  MDM Server: <code>https://${host}/mdm</code>
</p>
</body></html>`);
});

// ── Compliance Results ─────────────────────────────────────────────────────────
app.get('/api/compliance', async (req, res) => {
  try {
    const r = await db.query(`
      SELECT cr.*, d.name as device_name, p.name as policy_name
      FROM compliance_results cr
      LEFT JOIN devices d ON cr.device_id = d.id
      LEFT JOIN policies p ON cr.policy_id = p.id
      ORDER BY cr.checked_at DESC LIMIT 200
    `);
    res.json({ results: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/compliance', async (req, res) => {
  try {
    const { device_id, policy_id, compliant, drift } = req.body;
    await db.query(
      'INSERT INTO compliance_results (id,device_id,policy_id,compliant,drift) VALUES ($1,$2,$3,$4,$5)',
      [genId(), device_id, policy_id, compliant, JSON.stringify(drift||[])]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/compliance/summary — Live-Compliance-Übersicht (Phase 4)
app.get('/api/compliance/summary', async (req, res) => {
  try {
    // Letzte Compliance pro (device_id, policy_id)
    const byPolicyRows = await db.query(`
      SELECT
        cr.policy_id,
        p.name                                                          AS policy_name,
        COUNT(DISTINCT cr.device_id)                                    AS total_devices,
        COUNT(DISTINCT cr.device_id) FILTER (WHERE cr.compliant = true) AS compliant_devices
      FROM compliance_results cr
      JOIN (
        SELECT device_id, policy_id, MAX(checked_at) AS latest
        FROM compliance_results GROUP BY device_id, policy_id
      ) latest
        ON cr.device_id = latest.device_id
       AND cr.policy_id = latest.policy_id
       AND cr.checked_at = latest.latest
      LEFT JOIN policies p ON cr.policy_id = p.id
      GROUP BY cr.policy_id, p.name
      ORDER BY p.name
    `);

    // Letzte Compliance pro Gerät
    const byDeviceRows = await db.query(`
      SELECT
        d.id                                                               AS device_id,
        d.name                                                             AS device_name,
        d.platform,
        d.last_seen,
        EXTRACT(EPOCH FROM (NOW() - d.last_seen)) / 3600                  AS hours_since_heartbeat,
        COUNT(DISTINCT cr.policy_id)                                       AS total_policies,
        COUNT(DISTINCT cr.policy_id) FILTER (WHERE cr.compliant = true)   AS compliant_policies,
        MAX(cr.checked_at)                                                 AS last_check
      FROM devices d
      LEFT JOIN compliance_results cr ON d.id = cr.device_id
      WHERE d.status != 'decommissioned'
      GROUP BY d.id, d.name, d.platform, d.last_seen
      ORDER BY d.last_seen DESC NULLS LAST
    `);

    const policies = byPolicyRows.rows.map(r => ({
      policy_id:         r.policy_id,
      policy_name:       r.policy_name || r.policy_id,
      total_devices:     parseInt(r.total_devices),
      compliant_devices: parseInt(r.compliant_devices),
      pct_compliant:     r.total_devices > 0
        ? Math.round(100 * r.compliant_devices / r.total_devices) : null,
    }));

    const devices = byDeviceRows.rows.map(r => {
      const hrs = parseFloat(r.hours_since_heartbeat);
      return {
        device_id:            r.device_id,
        device_name:          r.device_name,
        platform:             r.platform,
        last_seen:            r.last_seen,
        stale:                isNaN(hrs) || hrs > 24,
        hours_since_heartbeat: isNaN(hrs) ? null : Math.round(hrs * 10) / 10,
        total_policies:       parseInt(r.total_policies) || 0,
        compliant_policies:   parseInt(r.compliant_policies) || 0,
        last_check:           r.last_check,
      };
    });

    const totalDevices     = devices.length;
    const compliantDevices = devices.filter(
      d => !d.stale && d.total_policies > 0 && d.compliant_policies === d.total_policies
    ).length;

    res.json({
      overall: {
        total_devices:     totalDevices,
        compliant_devices: compliantDevices,
        stale_devices:     devices.filter(d => d.stale).length,
        pct_compliant:     totalDevices > 0 ? Math.round(100 * compliantDevices / totalDevices) : null,
      },
      policies,
      devices,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AD / DC Configuration ──────────────────────────────────────────────────────
app.get('/api/ad/config', async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM ad_config WHERE id='default'");
    if (r.rowCount === 0) return res.json({ configured: false });
    const cfg = r.rows[0];
    // never expose password over API
    delete cfg.admin_pass;
    res.json({ configured: !!(cfg.dc_ip && cfg.domain), ...cfg });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/ad/config', async (req, res) => {
  try {
    const { dc_ip, dc_hostname, domain, realm, admin_user, admin_pass, nas_ip, nas_share, drive_letter, portal_ip } = req.body;
    const r = realm || (domain ? domain.toUpperCase() : '');
    await db.query(`
      INSERT INTO ad_config (id, dc_ip, dc_hostname, domain, realm, admin_user, admin_pass, nas_ip, nas_share, drive_letter, portal_ip, updated_at)
      VALUES ('default',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
      ON CONFLICT (id) DO UPDATE SET
        dc_ip=EXCLUDED.dc_ip, dc_hostname=EXCLUDED.dc_hostname,
        domain=EXCLUDED.domain, realm=EXCLUDED.realm,
        admin_user=EXCLUDED.admin_user,
        admin_pass=CASE WHEN $6='' THEN ad_config.admin_pass ELSE EXCLUDED.admin_pass END,
        nas_ip=EXCLUDED.nas_ip, nas_share=EXCLUDED.nas_share,
        drive_letter=EXCLUDED.drive_letter, portal_ip=EXCLUDED.portal_ip,
        updated_at=NOW()
    `, [dc_ip||'', dc_hostname||'dc01', domain||'', r, admin_user||'Administrator', admin_pass||'', nas_ip||'', nas_share||'', drive_letter||'Z', portal_ip||'']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ad/status', async (req, res) => {
  try {
    const r = await db.query("SELECT dc_ip, domain, realm, dc_hostname FROM ad_config WHERE id='default'");
    if (r.rowCount === 0 || !r.rows[0].dc_ip) return res.json({ configured: false, reachable: false });
    const { dc_ip, domain, realm, dc_hostname } = r.rows[0];
    const [ldap, kerberos, dns53] = await Promise.all([
      tcpCheck(dc_ip, 389, 2000),
      tcpCheck(dc_ip, 88,  2000),
      tcpCheck(dc_ip, 53,  2000),
    ]);
    res.json({ configured: true, dc_ip, domain, realm, dc_hostname,
      reachable: ldap || kerberos, services: { ldap, kerberos, dns: dns53 } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DNS Records ────────────────────────────────────────────────────────────────
app.get('/api/dns/status', async (req, res) => {
  try {
    const cfg = await db.query("SELECT dc_ip, domain FROM ad_config WHERE id='default'");
    if (cfg.rowCount === 0 || !cfg.rows[0].dc_ip) {
      return res.json({ running: false, reason: 'DC not configured', dc_ip: null });
    }
    const dc_ip = cfg.rows[0].dc_ip;
    const domain = cfg.rows[0].domain;
    const running = await tcpCheck(dc_ip, 53, 2000);
    res.json({ running, dc_ip, domain, reason: running ? 'Samba DNS reachable' : `DC ${dc_ip} port 53 not responding` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/dns/records', async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM dns_records ORDER BY created_at DESC');
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/dns/records', async (req, res) => {
  try {
    const { name, type, value, zone, ttl } = req.body;
    if (!name || !value) return res.status(400).json({ error: 'name and value required' });
    const cfg = await db.query("SELECT dc_ip, domain, admin_pass FROM ad_config WHERE id='default'");
    const dcIp   = cfg.rows[0]?.dc_ip   || '';
    const domain = zone || cfg.rows[0]?.domain || '';
    const id = genId();
    await db.query(
      'INSERT INTO dns_records (id,zone,name,type,value,ttl) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, domain, name, type||'A', value, ttl||3600]
    );
    // Generate samba-tool command for reference
    const cmd = `samba-tool dns add ${dcIp} ${domain} ${name} ${type||'A'} ${value} -U Administrator --password="<AD_PASSWORD>"`;
    res.json({ success: true, id, sambaCommand: cmd,
      note: 'Record saved. Apply to DC via: ' + cmd });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/dns/records/:id', async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM dns_records WHERE id=$1', [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'not found' });
    const rec = r.rows[0];
    await db.query('DELETE FROM dns_records WHERE id=$1', [req.params.id]);
    const cfg = await db.query("SELECT dc_ip FROM ad_config WHERE id='default'");
    const dcIp = cfg.rows[0]?.dc_ip || '';
    const cmd = `samba-tool dns delete ${dcIp} ${rec.zone} ${rec.name} ${rec.type} ${rec.value} -U Administrator --password="<AD_PASSWORD>"`;
    res.json({ success: true, sambaCommand: cmd });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DHCP Status ────────────────────────────────────────────────────────────────
app.get('/api/dhcp/status', async (req, res) => {
  try {
    // Check common DHCP server IPs from network (gateway = x.x.x.1, x.x.x.254)
    // Also check if DC has DHCP role (Samba can act as DHCP)
    const cfg = await db.query("SELECT dc_ip FROM ad_config WHERE id='default'");
    const dcIp = cfg.rows[0]?.dc_ip || '';
    // DHCP runs on UDP 67 — can't TCP-check UDP, so we check if known DHCP hosts respond on common mgmt ports
    const checks = [];
    if (dcIp) checks.push(tcpCheck(dcIp, 445, 1000).then(ok => ({ host: dcIp, role: 'DC', reachable: ok })));
    const results = await Promise.all(checks);
    const running = results.some(r => r.reachable);
    res.json({
      running,
      note: running
        ? 'DC reachable — DHCP may be configured on DC or network router'
        : 'No DHCP server detected. Configure DHCP on DC (dnsmasq) or router.',
      servers: results,
      recommendation: 'For Samba AD: use dnsmasq on DC or configure DHCP on your router/firewall.'
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── File Share Edit (PATCH) ────────────────────────────────────────────────────
app.patch('/api/network/shares/:id', async (req, res) => {
  try {
    const { name, protocol, server, path, permissions, username, drive_letter,
            allowed_groups, allowed_users, enabled, description } = req.body;
    const existing = await db.query('SELECT * FROM network_shares WHERE id=$1', [req.params.id]);
    if (existing.rowCount === 0) return res.status(404).json({ error: 'Share not found' });
    const cur = existing.rows[0];
    await db.query(`
      UPDATE network_shares SET
        name           = COALESCE($1, name),
        protocol       = COALESCE($2, protocol),
        server         = COALESCE($3, server),
        path           = COALESCE($4, path),
        permissions    = COALESCE($5, permissions),
        username       = COALESCE($6, username),
        drive_letter   = COALESCE($7, drive_letter),
        allowed_groups = COALESCE($8::jsonb, allowed_groups),
        allowed_users  = COALESCE($9::jsonb, allowed_users),
        enabled        = COALESCE($10, enabled),
        description    = COALESCE($11, description)
      WHERE id = $12
    `, [
      name||null, protocol||null, server||null, path||null,
      permissions||null, username||null, drive_letter||null,
      allowed_groups ? JSON.stringify(allowed_groups) : null,
      allowed_users  ? JSON.stringify(allowed_users)  : null,
      enabled !== undefined ? enabled : null,
      description||null,
      req.params.id
    ]);
    const updated = await db.query('SELECT * FROM network_shares WHERE id=$1', [req.params.id]);
    await markPoliciesForRecompile({ shareIds: [req.params.id] });
    res.json({ success: true, share: updated.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Monitoring Status (Prometheus + Grafana connectivity) ─────────────────────
app.get('/api/monitoring/status', async (req, res) => {
  try {
    const [prom, graf] = await Promise.all([
      axios.get(`${services.prometheus.url}/-/healthy`, { timeout: 3000 }).then(() => 'healthy').catch(() => 'unreachable'),
      axios.get(`${services.grafana.url}/api/health`,   { timeout: 3000 }).then(() => 'healthy').catch(() => 'unreachable'),
    ]);
    res.json({
      prometheus: { status: prom, url: services.prometheus.url,
        hint: prom === 'unreachable' ? 'Prometheus nicht erreichbar — Metriken nicht verfügbar' : null },
      grafana:    { status: graf, url: services.grafana.url,
        hint: graf === 'unreachable' ? 'Grafana nicht erreichbar — Dashboards nicht verfügbar' : null },
      overall: prom === 'healthy' && graf === 'healthy' ? 'healthy' : 'degraded',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Security Settings ──────────────────────────────────────────────────────────
// Security Defaults — abgeleitet aus Policy-Templates (einzige Quelle).
// Wenn policy-templates.js nicht geladen ist, werden statische Fallback-Werte verwendet.
// Mapping: template.settings (nested) → flat Security-Defaults-Objekt für die UI.
function getSecurityDefaults() {
  const fromTemplate = (templateId, extra = {}) => {
    if (!policyTemplates) return null;
    const tpl = policyTemplates.POLICY_TEMPLATES.find(t => t.templateId === templateId);
    if (!tpl) return null;
    const s = tpl.settings || {};
    return {
      firewall:           !!(s.firewall?.enabled),
      screenLock:         !!(s.screenLock?.enabled),
      screenLockTimeout:  s.screenLock?.timeoutMinutes   ?? 5,
      encryption:         !!(s.encryption?.diskEncryption || s.encryption?.requireBitLocker),
      passwordMinLength:  s.password?.minLength          ?? 8,
      passwordComplexity: !!(s.password?.complexity),
      auditLogging:       !!(s.audit?.enabled),
      sshHardening:       !!(s.ssh?.enabled),
      ...extra,
    };
  };

  return {
    workstation: fromTemplate('hardening-workstation', {
      autoUpdates: true, antivirus: true, mfa: false,
      guestAccount: false, remoteDesktop: false, usbStorage: 'blocked',
    }) || {
      firewall: true, autoUpdates: true, screenLock: true, screenLockTimeout: 5,
      encryption: true, antivirus: true, passwordMinLength: 12,
      passwordComplexity: true, mfa: false, guestAccount: false,
      remoteDesktop: false, usbStorage: 'blocked', auditLogging: true,
    },
    server: fromTemplate('hardening-server', {
      autoUpdates: false, antivirus: true, mfa: true,
      guestAccount: false, remoteDesktop: true, usbStorage: 'blocked',
      failBan: true, selinux: 'enforcing',
    }) || {
      firewall: true, autoUpdates: false, screenLock: true, screenLockTimeout: 15,
      encryption: true, antivirus: true, passwordMinLength: 16,
      passwordComplexity: true, mfa: true, guestAccount: false,
      remoteDesktop: true, usbStorage: 'blocked', auditLogging: true,
      sshHardening: true, failBan: true, selinux: 'enforcing',
    },
    laptop: fromTemplate('hardening-laptop', {
      autoUpdates: true, antivirus: true, mfa: true,
      guestAccount: false, remoteDesktop: false, usbStorage: 'ask',
      vpnRequired: true, geofencing: false,
    }) || {
      firewall: true, autoUpdates: true, screenLock: true, screenLockTimeout: 3,
      encryption: true, antivirus: true, passwordMinLength: 12,
      passwordComplexity: true, mfa: true, guestAccount: false,
      remoteDesktop: false, usbStorage: 'ask', auditLogging: true,
      vpnRequired: true, geofencing: false,
    },
    // Kein Template für Mobile — bleibt statisch
    mobile: {
      screenLock: true, screenLockTimeout: 1, encryption: true,
      remoteWipe: true, mfa: true, vpnRequired: false,
      appWhitelist: false, containerization: false, auditLogging: true,
    },
    kiosk: fromTemplate('hardening-kiosk', {
      autoUpdates: true, antivirus: true, mfa: false,
      guestAccount: true, remoteDesktop: false, usbStorage: 'blocked',
      kioskMode: true, browserRestrictions: true,
    }) || {
      firewall: true, autoUpdates: true, screenLock: false,
      encryption: false, antivirus: true, passwordMinLength: 8,
      passwordComplexity: false, mfa: false, guestAccount: true,
      remoteDesktop: false, usbStorage: 'blocked', auditLogging: true,
      kioskMode: true, browserRestrictions: true,
    },
  };
}

app.get('/api/security/defaults/:deviceType', (req, res) => {
  const dt = req.params.deviceType.toLowerCase();
  const all = getSecurityDefaults();
  const defaults = all[dt] || all.workstation;
  res.json({ deviceType: dt, defaults, source: policyTemplates ? 'policy-templates' : 'static-fallback' });
});

app.get('/api/security/settings', async (req, res) => {
  try {
    const r = await db.query("SELECT settings, updated_at FROM security_settings WHERE id='default'");
    if (r.rowCount === 0) return res.json({ settings: {}, configured: false });
    res.json({ settings: r.rows[0].settings, configured: true, updated_at: r.rows[0].updated_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/security/settings', async (req, res) => {
  try {
    const { settings } = req.body;
    await db.query(`
      INSERT INTO security_settings (id, settings, updated_at) VALUES ('default', $1, NOW())
      ON CONFLICT (id) DO UPDATE SET settings=EXCLUDED.settings, updated_at=NOW()
    `, [JSON.stringify(settings || {})]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── System Info (Uptime fix) ───────────────────────────────────────────────────
const SERVICE_START = Date.now();
app.get('/api/system/info', (req, res) => {
  const uptimeSec = Math.floor((Date.now() - SERVICE_START) / 1000);
  const uptimeH   = Math.floor(uptimeSec / 3600);
  const uptimeM   = Math.floor((uptimeSec % 3600) / 60);
  res.json({
    name: 'OpenDirectory Integration Service',
    version: '3.1.0',
    uptime: uptimeSec,
    uptimeFormatted: `${uptimeH}h ${uptimeM}m`,
    nodeUptime: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => res.json({ name: 'OpenDirectory Integration Service', version: '3.1.0' }));

// ── Start ─────────────────────────────────────────────────────────────────────

initDB()
  .then(() => app.listen(port, () => console.log(`Integration Service v3.0 running on port ${port} with PostgreSQL`)))
  .catch(err => {
    console.error('DB init failed:', err.message);
    app.listen(port, () => console.log(`Integration Service v3.0 running on port ${port} (DB unavailable)`));
  });
