'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const path = require('path');
const fs = require('fs');

const db = require('./db/postgres');
const { RSOPEngine } = require('./engines/gpoProcessor');
const { ConflictResolver } = require('./engines/conflictResolver');
const { InheritanceEngine } = require('./engines/inheritanceEngine');
const { WindowsPolicyCompiler } = require('./compilers/windowsCompiler');
const { MacOSPolicyCompiler } = require('./compilers/macosCompiler');
const { LinuxPolicyCompiler } = require('./compilers/linuxCompiler');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const app = express();
const PORT = process.env.PORT || 3004;

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));

// --- Engine singletons ---
const rsopEngine = new RSOPEngine();
const conflictResolver = new ConflictResolver();
const inheritanceEngine = new InheritanceEngine();
const compilers = {
  windows: new WindowsPolicyCompiler(),
  macos: new MacOSPolicyCompiler(),
  linux: new LinuxPolicyCompiler()
};

// --- Template cache ---
let templateCache = null;

function loadTemplates() {
  if (templateCache) return templateCache;
  const dir = path.join(__dirname, 'templates');
  if (!fs.existsSync(dir)) return [];
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  templateCache = files.map(f => {
    const raw = fs.readFileSync(path.join(dir, f), 'utf-8');
    return JSON.parse(raw);
  });
  return templateCache;
}

// --- RabbitMQ Event Bus ---
let _amqpChannel = null;

async function connectBus() {
  try {
    const amqplib = require('amqplib');
    const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672';
    try {
      const conn = await amqplib.connect(RABBITMQ_URL);
      conn.on('error', () => { _amqpChannel = null; });
      conn.on('close', () => { _amqpChannel = null; setTimeout(connectBus, 5000); });
      const ch = await conn.createChannel();
      await ch.assertExchange('opendirectory.events', 'topic', { durable: true });
      _amqpChannel = ch;
      logger.info('[bus] RabbitMQ connected');
    } catch (e) {
      logger.warn('[bus] RabbitMQ unavailable, retrying in 10s: ' + e.message);
      setTimeout(connectBus, 10000);
    }
  } catch (e) {
    logger.warn('[bus] connectBus error: ' + e.message);
  }
}

function publish(routingKey, payload) {
  if (!_amqpChannel) return;
  try {
    _amqpChannel.publish('opendirectory.events', routingKey,
      Buffer.from(JSON.stringify({ ...payload, _timestamp: new Date().toISOString(), _source: 'policy-service' })),
      { persistent: true, contentType: 'application/json' }
    );
  } catch (e) { /* fail silently */ }
}

// --- Audit helper ---
async function auditLog(policyId, action, actor, changes) {
  try {
    await db.query(
      `INSERT INTO policy_audit_log (policy_id, action, actor, changes)
       VALUES ($1, $2, $3, $4)`,
      [policyId, action, actor || 'system', changes ? JSON.stringify(changes) : null]
    );
  } catch (err) {
    logger.error('Failed to write audit log', { policyId, action, error: err.message });
  }
}

// ============================
// Health check
// ============================
app.get('/health', async (_req, res) => {
  const dbOk = await db.testConnection();
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'healthy' : 'degraded',
    service: 'policy-service',
    database: dbOk ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

// ============================
// Policies CRUD
// ============================

// List policies
app.get('/api/policies', async (req, res) => {
  try {
    const { page = 1, limit = 50, type, status, platform } = req.query;
    const pageNum = Math.max(1, Number(page));
    const limitNum = Math.min(200, Math.max(1, Number(limit)));
    const offset = (pageNum - 1) * limitNum;

    let where = '';
    const params = [];
    const conditions = [];

    if (type) {
      params.push(type);
      conditions.push(`type = $${params.length}`);
    }
    if (status) {
      params.push(status);
      conditions.push(`status = $${params.length}`);
    }
    if (platform) {
      params.push(platform);
      conditions.push(`(platform = $${params.length} OR platform = 'all')`);
    }
    if (conditions.length > 0) {
      where = 'WHERE ' + conditions.join(' AND ');
    }

    const countResult = await db.query(`SELECT COUNT(*) AS total FROM policies ${where}`, params);
    const total = parseInt(countResult.rows[0].total, 10);

    params.push(limitNum, offset);
    const dataResult = await db.query(
      `SELECT * FROM policies ${where} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    res.json({ policies: dataResult.rows, total, page: pageNum, limit: limitNum });
  } catch (err) {
    logger.error('Failed to list policies', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single policy
app.get('/api/policies/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM policies WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Failed to get policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create policy
app.post('/api/policies', async (req, res) => {
  try {
    const { name, description, type, platform, rules, settings, priority, enforce, block_inheritance, wmi_filter, security_filter, created_by } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'name and type are required' });

    const validTypes = ['security', 'software', 'registry', 'network', 'firewall', 'encryption', 'password', 'compliance'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
    }

    const result = await db.query(
      `INSERT INTO policies (name, description, type, platform, rules, settings, priority, enforce, block_inheritance, wmi_filter, security_filter, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        name, description || null, type, platform || 'all',
        JSON.stringify(rules || []), JSON.stringify(settings || {}),
        priority || 100, enforce || false, block_inheritance || false,
        wmi_filter ? JSON.stringify(wmi_filter) : null,
        security_filter ? JSON.stringify(security_filter) : null,
        created_by || null
      ]
    );

    const policy = result.rows[0];
    await auditLog(policy.id, 'created', created_by, { name, type });
    try { publish('policy.created', { policyId: policy.id, name: policy.name, type: policy.type, createdBy: created_by || null }); } catch (e) {}
    logger.info(`Policy created: ${name} (${type})`, { id: policy.id });
    res.status(201).json(policy);
  } catch (err) {
    logger.error('Failed to create policy', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update policy
app.put('/api/policies/:id', async (req, res) => {
  try {
    const existing = await db.query('SELECT * FROM policies WHERE id = $1', [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });

    const old = existing.rows[0];
    const { name, description, type, platform, rules, settings, priority, enforce, block_inheritance, wmi_filter, security_filter } = req.body;

    const result = await db.query(
      `UPDATE policies SET
        name = COALESCE($1, name),
        description = COALESCE($2, description),
        type = COALESCE($3, type),
        platform = COALESCE($4, platform),
        rules = COALESCE($5, rules),
        settings = COALESCE($6, settings),
        priority = COALESCE($7, priority),
        enforce = COALESCE($8, enforce),
        block_inheritance = COALESCE($9, block_inheritance),
        wmi_filter = COALESCE($10, wmi_filter),
        security_filter = COALESCE($11, security_filter),
        version = version + 1,
        updated_at = NOW()
       WHERE id = $12
       RETURNING *`,
      [
        name || null, description !== undefined ? description : null,
        type || null, platform || null,
        rules ? JSON.stringify(rules) : null, settings ? JSON.stringify(settings) : null,
        priority || null, enforce !== undefined ? enforce : null,
        block_inheritance !== undefined ? block_inheritance : null,
        wmi_filter ? JSON.stringify(wmi_filter) : null,
        security_filter ? JSON.stringify(security_filter) : null,
        req.params.id
      ]
    );

    const updated = result.rows[0];
    await auditLog(updated.id, 'updated', req.body.updated_by, { before: old, after: updated });
    try { publish('policy.updated', { policyId: updated.id, name: updated.name, changes: Object.keys(req.body) }); } catch (e) {}
    res.json(updated);
  } catch (err) {
    logger.error('Failed to update policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete policy
app.delete('/api/policies/:id', async (req, res) => {
  try {
    const result = await db.query('DELETE FROM policies WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    await auditLog(req.params.id, 'deleted', req.query.actor);
    res.status(204).send();
  } catch (err) {
    logger.error('Failed to delete policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Policy Activation / Deactivation
// ============================
app.post('/api/policies/:id/activate', async (req, res) => {
  try {
    const result = await db.query(
      `UPDATE policies SET status = 'active', activated_at = NOW(), updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    await auditLog(req.params.id, 'activated', req.body.actor);
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Failed to activate policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/policies/:id/deactivate', async (req, res) => {
  try {
    const result = await db.query(
      `UPDATE policies SET status = 'inactive', updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    await auditLog(req.params.id, 'deactivated', req.body.actor);
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Failed to deactivate policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Policy Assignments
// ============================
app.get('/api/policies/:id/assignments', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM policy_assignments WHERE policy_id = $1 ORDER BY assigned_at DESC',
      [req.params.id]
    );
    res.json({ assignments: result.rows });
  } catch (err) {
    logger.error('Failed to get assignments', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/policies/:id/assign', async (req, res) => {
  try {
    const { targetType, targetId, assigned_by } = req.body;
    if (!targetType || !targetId) return res.status(400).json({ error: 'targetType and targetId are required' });

    // Verify policy exists
    const policyCheck = await db.query('SELECT id FROM policies WHERE id = $1', [req.params.id]);
    if (policyCheck.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });

    const result = await db.query(
      `INSERT INTO policy_assignments (policy_id, target_type, target_id, assigned_by)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, targetType, targetId, assigned_by || null]
    );

    await auditLog(req.params.id, 'assigned', assigned_by, { targetType, targetId });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('Failed to assign policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Policy Evaluation (legacy endpoint for agents)
// ============================
app.post('/api/policies/evaluate', async (req, res) => {
  try {
    const { deviceId, userId, context } = req.body;
    const result = await db.query(
      `SELECT * FROM policies WHERE status = 'active' ORDER BY priority ASC`
    );
    // Publish violation events for any enforce=true policies when a deviceId is provided
    if (deviceId && Array.isArray(result.rows)) {
      for (const p of result.rows) {
        if (p.enforce && context?.violations?.[p.id]) {
          const v = context.violations[p.id];
          try { publish('policy.violated', { policyId: p.id, deviceId, violation: v.violation || 'policy_not_met', severity: v.severity || 'medium' }); } catch (e) {}
        }
      }
    }
    res.json({ applicablePolicies: result.rows, evaluatedAt: new Date().toISOString() });
  } catch (err) {
    logger.error('Failed to evaluate policies', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// RSoP (Resultant Set of Policy)
// ============================
app.post('/api/policies/rsop', async (req, res) => {
  try {
    const { deviceId, userId, context } = req.body;
    if (!deviceId && !userId) {
      return res.status(400).json({ error: 'At least one of deviceId or userId is required' });
    }

    const rsop = await rsopEngine.calculateRSOP(deviceId, userId, context || {});
    res.json({
      rsop,
      evaluatedAt: new Date().toISOString()
    });
  } catch (err) {
    logger.error('RSoP calculation failed', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Templates
// ============================
app.get('/api/policies/templates', (_req, res) => {
  try {
    const templates = loadTemplates();
    res.json({
      templates: templates.map(t => ({
        id: t.id,
        name: t.name,
        description: t.description,
        type: t.type,
        platform: t.platform,
        version: t.version
      })),
      total: templates.length
    });
  } catch (err) {
    logger.error('Failed to list templates', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/policies/from-template', async (req, res) => {
  try {
    const { templateId, name, description, priority, created_by } = req.body;
    if (!templateId) return res.status(400).json({ error: 'templateId is required' });

    const templates = loadTemplates();
    const template = templates.find(t => t.id === templateId);
    if (!template) return res.status(404).json({ error: 'Template not found' });

    const policyName = name || template.name;
    const result = await db.query(
      `INSERT INTO policies (name, description, type, platform, settings, priority, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        policyName,
        description || template.description,
        template.type,
        template.platform,
        JSON.stringify(template.settings),
        priority || 100,
        created_by || null
      ]
    );

    const policy = result.rows[0];
    await auditLog(policy.id, 'created_from_template', created_by, { templateId, templateName: template.name });
    logger.info(`Policy created from template: ${policyName}`, { id: policy.id, templateId });
    res.status(201).json(policy);
  } catch (err) {
    logger.error('Failed to create policy from template', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Compile for Platform
// ============================
app.post('/api/policies/:id/compile/:platform', async (req, res) => {
  try {
    const { platform } = req.params;
    const compiler = compilers[platform];
    if (!compiler) {
      return res.status(400).json({ error: `Unsupported platform: ${platform}. Supported: windows, macos, linux` });
    }

    // Build a minimal RSoP from just this policy's settings
    const policyResult = await db.query('SELECT * FROM policies WHERE id = $1', [req.params.id]);
    if (policyResult.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });

    const policy = policyResult.rows[0];
    const rsopResult = {
      settings: rsopEngine._flattenObject(policy.settings || {}),
      sources: {},
      conflicts: [],
      appliedPolicies: [{ id: policy.id, name: policy.name, type: policy.type, priority: policy.priority }]
    };

    const compiled = compiler.compile(rsopResult);
    res.json({ policyId: policy.id, policyName: policy.name, compiled });
  } catch (err) {
    logger.error('Failed to compile policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Inheritance Chain
// ============================
app.get('/api/policies/inheritance/:ouId', async (req, res) => {
  try {
    const { ouId } = req.params;
    const chain = await inheritanceEngine.getInheritanceChain('ou', ouId);
    res.json(chain);
  } catch (err) {
    logger.error('Failed to get inheritance chain', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Extended inheritance chain endpoint (supports all target types)
app.get('/api/policies/inheritance/:targetType/:targetId', async (req, res) => {
  try {
    const { targetType, targetId } = req.params;
    const validTargetTypes = ['ou', 'site', 'domain', 'device', 'group'];
    if (!validTargetTypes.includes(targetType)) {
      return res.status(400).json({ error: `targetType must be one of: ${validTargetTypes.join(', ')}` });
    }

    const chain = await inheritanceEngine.getInheritanceChain(targetType, targetId);
    res.json(chain);
  } catch (err) {
    logger.error('Failed to get inheritance chain', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Policy Links
// ============================
app.post('/api/policies/:id/link', async (req, res) => {
  try {
    const { target_type, target_id, target_name, enforce, link_order } = req.body;
    if (!target_type || !target_id) {
      return res.status(400).json({ error: 'target_type and target_id are required' });
    }

    const validTargetTypes = ['ou', 'site', 'domain', 'group', 'device'];
    if (!validTargetTypes.includes(target_type)) {
      return res.status(400).json({ error: `target_type must be one of: ${validTargetTypes.join(', ')}` });
    }

    // Verify policy exists
    const policyCheck = await db.query('SELECT id FROM policies WHERE id = $1', [req.params.id]);
    if (policyCheck.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });

    const result = await db.query(
      `INSERT INTO policy_links (policy_id, target_type, target_id, target_name, enforce, link_order)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        req.params.id, target_type, target_id,
        target_name || null, enforce || false, link_order || 0
      ]
    );

    await auditLog(req.params.id, 'linked', req.body.actor, { target_type, target_id, enforce });
    logger.info('Policy linked', { policyId: req.params.id, target_type, target_id });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('Failed to link policy', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/policies/:id/link/:linkId', async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM policy_links WHERE id = $1 AND policy_id = $2 RETURNING *',
      [req.params.linkId, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Link not found' });

    await auditLog(req.params.id, 'unlinked', req.query.actor, { linkId: req.params.linkId });
    res.status(204).send();
  } catch (err) {
    logger.error('Failed to remove link', { id: req.params.id, linkId: req.params.linkId, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// List links for a policy
app.get('/api/policies/:id/links', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM policy_links WHERE policy_id = $1 ORDER BY link_order ASC',
      [req.params.id]
    );
    res.json({ links: result.rows });
  } catch (err) {
    logger.error('Failed to get links', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Conflict Detection
// ============================
app.get('/api/policies/conflicts', async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM policies WHERE status = 'active' ORDER BY priority ASC`
    );
    const activePolicies = result.rows;

    if (activePolicies.length < 2) {
      return res.json({ conflicts: [], explanation: [] });
    }

    const resolution = conflictResolver.resolveConflicts(activePolicies);
    res.json({
      conflicts: resolution.conflicts,
      explanation: resolution.explanation,
      activePolicyCount: activePolicies.length,
      resolvedSettingCount: Object.keys(resolution.resolved).length
    });
  } catch (err) {
    logger.error('Failed to detect conflicts', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// WMI Filter
// ============================
app.post('/api/policies/:id/wmi-filter', async (req, res) => {
  try {
    const { wmi_filter } = req.body;
    if (!wmi_filter || !wmi_filter.conditions || !Array.isArray(wmi_filter.conditions)) {
      return res.status(400).json({ error: 'wmi_filter must include a conditions array' });
    }

    // Validate condition structure
    for (const cond of wmi_filter.conditions) {
      if (!cond.property || !cond.operator || cond.value === undefined) {
        return res.status(400).json({ error: 'Each condition must have property, operator, and value' });
      }
    }

    const result = await db.query(
      `UPDATE policies SET wmi_filter = $1, updated_at = NOW()
       WHERE id = $2 RETURNING *`,
      [JSON.stringify(wmi_filter), req.params.id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });

    await auditLog(req.params.id, 'wmi_filter_set', req.body.actor, { wmi_filter });
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Failed to set WMI filter', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Audit Log
// ============================
app.get('/api/policies/:id/audit', async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const result = await db.query(
      `SELECT * FROM policy_audit_log WHERE policy_id = $1
       ORDER BY timestamp DESC LIMIT $2 OFFSET $3`,
      [req.params.id, Math.min(200, Number(limit)), Number(offset)]
    );
    res.json({ auditLog: result.rows });
  } catch (err) {
    logger.error('Failed to get audit log', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================
// Phase 6: Simulate, Conflicts, Baselines (in-memory augment)
// ============================

// In-memory baselines (CIS Benchmarks — full profiles)
const CIS_BASELINES = [
  {
    id: 'cis-ubuntu-22-l1',
    name: 'CIS Ubuntu 22.04 LTS — Level 1',
    platform: 'linux',
    level: 1,
    controls: 89,
    description: 'Server hardening baseline for Ubuntu 22.04 — suitable for most environments',
    settings: {
      'fs.suid_dumpable': '0',
      'kernel.randomize_va_space': '2',
      'net.ipv4.ip_forward': '0',
      'net.ipv4.conf.all.send_redirects': '0',
      'ssh_PermitRootLogin': 'no',
      'ssh_PasswordAuthentication': 'no',
      'ssh_MaxAuthTries': '4',
      'ufw_enabled': 'true',
      'auditd_enabled': 'true',
      'apparmor_enabled': 'true',
    }
  },
  {
    id: 'cis-ubuntu-22-l2',
    name: 'CIS Ubuntu 22.04 LTS — Level 2',
    platform: 'linux',
    level: 2,
    controls: 147,
    description: 'Enhanced hardening for high-security Ubuntu environments',
    settings: {
      'fs.suid_dumpable': '0',
      'kernel.randomize_va_space': '2',
      'net.ipv4.ip_forward': '0',
      'ssh_PermitRootLogin': 'no',
      'ssh_PasswordAuthentication': 'no',
      'ssh_MaxAuthTries': '3',
      'ufw_enabled': 'true',
      'auditd_enabled': 'true',
      'apparmor_enabled': 'true',
      'aide_enabled': 'true',
      'rsyslog_remote': 'true',
      'cron_restricted': 'true',
      'at_restricted': 'true',
    }
  },
  {
    id: 'cis-macos-14-l1',
    name: 'CIS macOS 14 Sonoma — Level 1',
    platform: 'macos',
    level: 1,
    controls: 76,
    description: 'Standard hardening for managed macOS Sonoma devices',
    settings: {
      'SoftwareUpdateDelay': '0',
      'GatekeeperEnabled': 'true',
      'FirewallEnabled': 'true',
      'FileVaultEnabled': 'true',
      'ScreenLockEnabled': 'true',
      'ScreenLockDelay': '300',
      'GuestAccountDisabled': 'true',
      'RemoteLoginDisabled': 'true',
      'BluetoothSharing': 'disabled',
      'AirDropEnabled': 'contacts-only',
    }
  },
  {
    id: 'cis-windows-11-l1',
    name: 'CIS Windows 11 — Level 1',
    platform: 'windows',
    level: 1,
    controls: 193,
    description: 'Standard security baseline for Windows 11 enterprise workstations',
    settings: {
      'PasswordMinLength': '14',
      'PasswordComplexity': 'enabled',
      'LockoutThreshold': '5',
      'LockoutDuration': '15',
      'AuditLogonEvents': 'success,failure',
      'WindowsDefender': 'enabled',
      'SmartScreen': 'enabled',
      'UAC': 'enabled',
      'BitLocker': 'required',
      'WindowsFirewall': 'enabled',
      'RemoteDesktop': 'disabled',
      'GuestAccount': 'disabled',
    }
  },
  {
    id: 'cis-windows-11-l2',
    name: 'CIS Windows 11 — Level 2',
    platform: 'windows',
    level: 2,
    controls: 284,
    description: 'Enhanced security for high-security Windows 11 environments',
    settings: {
      'PasswordMinLength': '15',
      'PasswordComplexity': 'enabled',
      'LockoutThreshold': '3',
      'LockoutDuration': '30',
      'AuditLogonEvents': 'success,failure',
      'WindowsDefender': 'enabled',
      'SmartScreen': 'block',
      'UAC': 'enabled',
      'BitLocker': 'required',
      'WindowsFirewall': 'enabled',
      'RemoteDesktop': 'disabled',
      'GuestAccount': 'disabled',
      'PowerShellScriptBlockLogging': 'enabled',
      'CredentialGuard': 'enabled',
      'DeviceGuard': 'enabled',
      'LAPS': 'enabled',
    }
  }
];

// In-memory policy store for baseline-applied policies (fallback when DB unavailable)
const inMemoryPolicies = new Map();

// GET /api/policies/simulate
app.get('/api/policies/simulate', async (req, res) => {
  try {
    const { userId, deviceId } = req.query;
    if (!userId && !deviceId) return res.status(400).json({ error: 'userId or deviceId required' });

    let policies = [];
    try {
      const result = await db.query(`SELECT * FROM policies WHERE status = 'active' ORDER BY priority ASC`);
      policies = result.rows;
    } catch {
      // DB unavailable — return empty
    }

    const effectiveSettings = {};
    const sources = {};
    for (const p of policies) {
      const s = typeof p.settings === 'string' ? JSON.parse(p.settings) : p.settings;
      for (const [k, v] of Object.entries(s ?? {})) {
        if (!effectiveSettings[k]) { effectiveSettings[k] = v; sources[k] = { policyId: p.id, policyName: p.name, priority: p.priority }; }
      }
    }

    res.json({ userId, deviceId, effectiveSettings, sources, appliedPoliciesCount: policies.length, simulatedAt: new Date().toISOString() });
  } catch (err) {
    logger.error('Policy simulate failed', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/policies/baselines
app.get('/api/policies/baselines', (req, res) => {
  res.json({ baselines: CIS_BASELINES, total: CIS_BASELINES.length });
});

// ============================
// Update Rings
// ============================

const updateRings = new Map([
  ['stable', { id: 'stable', name: 'Stable', deferralDays: { windows: 14, macos: 7, linux: 0 }, description: 'Production devices — 2-week deferral', deviceCount: 8, assignedDevices: [] }],
  ['beta',   { id: 'beta',   name: 'Beta',   deferralDays: { windows: 3,  macos: 3, linux: 0 }, description: 'Early adopters — 3-day deferral', deviceCount: 3, assignedDevices: [] }],
  ['dev',    { id: 'dev',    name: 'Dev',     deferralDays: { windows: 0,  macos: 0, linux: 0 }, description: 'Developers — no deferral', deviceCount: 2, assignedDevices: [] }],
]);

app.get('/api/update-rings', (_req, res) => {
  res.json([...updateRings.values()]);
});

app.put('/api/update-rings/:id', (req, res) => {
  const ring = updateRings.get(req.params.id);
  if (!ring) return res.status(404).json({ error: 'Ring not found' });
  const { deferralDays, description } = req.body;
  if (deferralDays) {
    if (typeof deferralDays.windows === 'number') ring.deferralDays.windows = deferralDays.windows;
    if (typeof deferralDays.macos === 'number') ring.deferralDays.macos = deferralDays.macos;
    if (typeof deferralDays.linux === 'number') ring.deferralDays.linux = deferralDays.linux;
  }
  if (description) ring.description = description;
  updateRings.set(req.params.id, ring);
  res.json(ring);
});

app.post('/api/update-rings/:id/assign', (req, res) => {
  const ring = updateRings.get(req.params.id);
  if (!ring) return res.status(404).json({ error: 'Ring not found' });
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });
  if (!ring.assignedDevices.includes(deviceId)) {
    ring.assignedDevices.push(deviceId);
    ring.deviceCount = ring.assignedDevices.length;
  }
  updateRings.set(req.params.id, ring);
  res.json({ ringId: req.params.id, deviceId, assignedDevices: ring.assignedDevices });
});

// POST /api/policies/baselines/:id/apply
app.post('/api/policies/baselines/:id/apply', async (req, res) => {
  const baseline = CIS_BASELINES.find(b => b.id === req.params.id);
  if (!baseline) return res.status(404).json({ error: 'Baseline not found' });

  const { assigned_to, created_by } = req.body;

  try {
    const result = await db.query(
      `INSERT INTO policies (name, description, type, platform, settings, priority, created_by, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'active') RETURNING *`,
      [baseline.name, baseline.description, 'compliance', baseline.platform, JSON.stringify(baseline.settings), 50, created_by ?? 'system']
    );

    const policy = result.rows[0];
    // Also store in memory for fast access
    inMemoryPolicies.set(policy.id, policy);
    logger.info(`Baseline applied: ${baseline.name}`, { policyId: policy.id });
    res.status(201).json({ message: `Baseline "${baseline.name}" applied`, policy, baseline });
  } catch (err) {
    logger.error('Failed to apply baseline via DB, using in-memory store', { id: req.params.id, error: err.message });
    // Create in-memory policy entry when DB unavailable
    const id = `baseline-${req.params.id}-${Date.now()}`;
    const policy = {
      id,
      name: baseline.name,
      description: baseline.description,
      type: 'compliance',
      platform: baseline.platform,
      settings: baseline.settings,
      priority: 50,
      status: 'active',
      created_by: created_by ?? 'system',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    inMemoryPolicies.set(id, policy);
    res.status(201).json({ message: `Baseline "${baseline.name}" applied`, policy, baseline });
  }
});

// ─── Group Policy Objects ─────────────────────────────────────────────────────

const GPO_TEMPLATES = {
  password_policy: {
    name: 'Passwort-Richtlinie',
    settings: { minLength: 12, requireUppercase: true, requireNumbers: true, requireSpecial: true, maxAge: 90, historyCount: 5 }
  },
  screen_lock: {
    name: 'Bildschirmsperre',
    settings: { enabled: true, timeoutMinutes: 15, requirePassword: true }
  },
  firewall: {
    name: 'Firewall-Einstellungen',
    settings: { enabled: true, blockInbound: true, allowOutbound: true }
  },
  windows_update: {
    name: 'Windows Update',
    settings: { autoUpdate: true, deferFeatureUpdates: 14, deferQualityUpdates: 7, activeHours: '08:00-18:00' }
  },
  bitlocker: {
    name: 'BitLocker-Verschlüsselung',
    settings: { enabled: true, method: 'AES256', recoveryKeyBackup: true }
  },
  usb_control: {
    name: 'USB-Geräte',
    settings: { blockAll: false, allowApproved: true, logUsage: true }
  },
  software_restriction: {
    name: 'Software-Einschränkung',
    settings: { allowlist: [], blocklist: ['torrent', 'crack', 'keygen'], mode: 'allowlist' }
  },
};

// In-memory GPO store
const gpos = new Map();

// Seed default GPOs
Object.entries(GPO_TEMPLATES).forEach(([type, template], i) => {
  const id = `gpo-${i+1}`;
  gpos.set(id, { id, type, name: template.name, settings: { ...template.settings }, enabled: true, assignedTo: [], platforms: ['windows', 'macos', 'linux'], createdAt: new Date().toISOString() });
});

app.get('/api/gpo', (req, res) => {
  res.json([...gpos.values()]);
});

app.post('/api/gpo', async (req, res) => {
  const { type, name, settings, platforms, assignedTo } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const template = GPO_TEMPLATES[type] || {};
  const id = `gpo-${Date.now()}`;
  const gpo = { id, type: type || 'custom', name, settings: { ...(template.settings || {}), ...settings }, enabled: true, assignedTo: assignedTo || [], platforms: platforms || ['windows', 'macos', 'linux'], createdAt: new Date().toISOString() };
  gpos.set(id, gpo);

  // Persist to DB if available
  try {
    await db.query(
      `INSERT INTO policies(id, name, platform, type, status, settings) VALUES($1,$2,$3,'gpo','active',$4) ON CONFLICT(id) DO UPDATE SET name=$2, settings=$4`,
      [id, name, (platforms || ['all']).join(','), JSON.stringify(gpo)]
    );
  } catch (_) {}
  res.status(201).json(gpo);
});

app.put('/api/gpo/:id', (req, res) => {
  const gpo = gpos.get(req.params.id);
  if (!gpo) return res.status(404).json({ error: 'GPO not found' });
  Object.assign(gpo, req.body, { updatedAt: new Date().toISOString() });
  res.json(gpo);
});

app.delete('/api/gpo/:id', (req, res) => {
  if (!gpos.has(req.params.id)) return res.status(404).json({ error: 'GPO not found' });
  gpos.delete(req.params.id);
  res.json({ success: true });
});

// Get effective GPOs for a device/platform
app.get('/api/gpo/effective/:platform', (req, res) => {
  const { platform } = req.params;
  const ouId = req.query.ouId;
  const groups = (req.query.groups || '').split(',').filter(Boolean);

  const effective = [...gpos.values()].filter(gpo => {
    if (!gpo.enabled) return false;
    if (!gpo.platforms.includes(platform) && !gpo.platforms.includes('all')) return false;
    if (gpo.assignedTo.length === 0) return true; // global
    if (ouId && gpo.assignedTo.includes(ouId)) return true;
    if (groups.some(g => gpo.assignedTo.includes(g))) return true;
    return false;
  });

  // Merge settings
  const merged = {};
  for (const gpo of effective) {
    Object.assign(merged, gpo.settings);
  }

  res.json({ platform, effectivePolicies: effective.length, settings: merged, gpos: effective });
});

// Apply GPO to devices via MDM command
app.post('/api/gpo/:id/apply', async (req, res) => {
  const gpo = gpos.get(req.params.id);
  if (!gpo) return res.status(404).json({ error: 'GPO not found' });

  const OAUTH_PROVIDER = process.env.OAUTH_PROVIDER_URL || 'http://oauth-provider';

  try {
    // Get all devices from registry
    const devRes = await fetch(`${OAUTH_PROVIDER}/api/devices/registry`);
    const devices = devRes.ok ? await devRes.json() : [];

    const results = [];
    for (const device of devices.filter(d => gpo.platforms.includes(d.platform || 'unknown'))) {
      const cmdRes = await fetch(`${OAUTH_PROVIDER}/api/devices/${device.id}/commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'update_policy', payload: { gpoId: gpo.id, gpoName: gpo.name, settings: gpo.settings } })
      });
      results.push({ deviceId: device.id, hostname: device.hostname, success: cmdRes.ok });
    }

    res.json({ gpoId: gpo.id, devicesTargeted: results.length, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================
// Blueprints (ABM-style device configuration profiles)
// ============================

// In-memory fallback stores
const inMemoryBlueprints = new Map();
const inMemoryBlueprintConfigs = new Map();
const inMemoryBlueprintAssignments = new Map();

// Seed a demo blueprint in memory
(function seedBlueprints() {
  const id = 'demo-blueprint-1';
  inMemoryBlueprints.set(id, {
    id,
    name: 'Corporate macOS Standard',
    description: 'Standard configuration for all corporate macOS devices',
    platform: 'macos',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  const cfg1 = 'demo-cfg-1';
  inMemoryBlueprintConfigs.set(cfg1, {
    id: cfg1,
    blueprint_id: id,
    config_type: 'filevault',
    config_name: 'FileVault Encryption',
    payload: { enabled: true, recoveryKeyEscrow: true },
    created_at: new Date().toISOString(),
  });
  const cfg2 = 'demo-cfg-2';
  inMemoryBlueprintConfigs.set(cfg2, {
    id: cfg2,
    blueprint_id: id,
    config_type: 'screen_lock',
    config_name: 'Screen Lock Policy',
    payload: { maxInactiveMinutes: 5, requirePassword: true },
    created_at: new Date().toISOString(),
  });
})();

// GET /api/blueprints — list all blueprints with config count
app.get('/api/blueprints', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT b.*,
             COUNT(DISTINCT bc.id)::int AS config_count,
             COUNT(DISTINCT ba.id)::int AS assignment_count
      FROM blueprints b
      LEFT JOIN blueprint_configurations bc ON bc.blueprint_id = b.id
      LEFT JOIN blueprint_assignments ba ON ba.blueprint_id = b.id
      GROUP BY b.id
      ORDER BY b.created_at DESC
    `);
    res.json({ blueprints: result.rows, total: result.rows.length });
  } catch (err) {
    logger.warn('DB unavailable for blueprints list, using in-memory', { error: err.message });
    const blueprints = [...inMemoryBlueprints.values()].map(b => ({
      ...b,
      config_count: [...inMemoryBlueprintConfigs.values()].filter(c => c.blueprint_id === b.id).length,
      assignment_count: [...inMemoryBlueprintAssignments.values()].filter(a => a.blueprint_id === b.id).length,
    }));
    res.json({ blueprints, total: blueprints.length });
  }
});

// POST /api/blueprints — create blueprint
app.post('/api/blueprints', async (req, res) => {
  const { name, description, platform } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  try {
    const result = await db.query(
      `INSERT INTO blueprints (name, description, platform)
       VALUES ($1, $2, $3) RETURNING *`,
      [name, description || null, platform || 'all']
    );
    logger.info(`Blueprint created: ${name}`, { id: result.rows[0].id });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, storing blueprint in memory', { error: err.message });
    const id = `bp-${Date.now()}`;
    const blueprint = {
      id, name, description: description || null, platform: platform || 'all',
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    };
    inMemoryBlueprints.set(id, blueprint);
    res.status(201).json(blueprint);
  }
});

// GET /api/blueprints/:id — get blueprint with all configurations
app.get('/api/blueprints/:id', async (req, res) => {
  try {
    const bpResult = await db.query('SELECT * FROM blueprints WHERE id = $1', [req.params.id]);
    if (bpResult.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });
    const cfgResult = await db.query(
      'SELECT * FROM blueprint_configurations WHERE blueprint_id = $1 ORDER BY created_at ASC',
      [req.params.id]
    );
    res.json({ ...bpResult.rows[0], configurations: cfgResult.rows });
  } catch (err) {
    logger.warn('DB unavailable, using in-memory blueprint', { error: err.message });
    const bp = inMemoryBlueprints.get(req.params.id);
    if (!bp) return res.status(404).json({ error: 'Blueprint not found' });
    const configs = [...inMemoryBlueprintConfigs.values()].filter(c => c.blueprint_id === req.params.id);
    res.json({ ...bp, configurations: configs });
  }
});

// PUT /api/blueprints/:id — update blueprint
app.put('/api/blueprints/:id', async (req, res) => {
  const { name, description, platform } = req.body;
  try {
    const result = await db.query(
      `UPDATE blueprints SET
         name = COALESCE($1, name),
         description = COALESCE($2, description),
         platform = COALESCE($3, platform),
         updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [name || null, description !== undefined ? description : null, platform || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });
    res.json(result.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, updating in-memory blueprint', { error: err.message });
    const bp = inMemoryBlueprints.get(req.params.id);
    if (!bp) return res.status(404).json({ error: 'Blueprint not found' });
    const updated = {
      ...bp,
      name: name || bp.name,
      description: description !== undefined ? description : bp.description,
      platform: platform || bp.platform,
      updated_at: new Date().toISOString(),
    };
    inMemoryBlueprints.set(req.params.id, updated);
    res.json(updated);
  }
});

// DELETE /api/blueprints/:id — delete blueprint
app.delete('/api/blueprints/:id', async (req, res) => {
  try {
    const result = await db.query('DELETE FROM blueprints WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });
    res.status(204).send();
  } catch (err) {
    logger.warn('DB unavailable, deleting in-memory blueprint', { error: err.message });
    if (!inMemoryBlueprints.has(req.params.id)) return res.status(404).json({ error: 'Blueprint not found' });
    inMemoryBlueprints.delete(req.params.id);
    // Also delete associated configs and assignments
    for (const [k, v] of inMemoryBlueprintConfigs.entries()) {
      if (v.blueprint_id === req.params.id) inMemoryBlueprintConfigs.delete(k);
    }
    for (const [k, v] of inMemoryBlueprintAssignments.entries()) {
      if (v.blueprint_id === req.params.id) inMemoryBlueprintAssignments.delete(k);
    }
    res.status(204).send();
  }
});

// POST /api/blueprints/:id/configurations — add config to blueprint
app.post('/api/blueprints/:id/configurations', async (req, res) => {
  const { config_type, config_name, payload } = req.body;
  if (!config_type || !config_name) return res.status(400).json({ error: 'config_type and config_name are required' });

  const VALID_CONFIG_TYPES = ['wifi', 'vpn', 'filevault', 'gatekeeper', 'software_update', 'screen_lock', 'certificate', 'webfilter', 'airdrop'];
  if (!VALID_CONFIG_TYPES.includes(config_type)) {
    return res.status(400).json({ error: `config_type must be one of: ${VALID_CONFIG_TYPES.join(', ')}` });
  }

  try {
    // Verify blueprint exists
    const bpCheck = await db.query('SELECT id FROM blueprints WHERE id = $1', [req.params.id]);
    if (bpCheck.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });

    const result = await db.query(
      `INSERT INTO blueprint_configurations (blueprint_id, config_type, config_name, payload)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, config_type, config_name, JSON.stringify(payload || {})]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, storing config in memory', { error: err.message });
    if (!inMemoryBlueprints.has(req.params.id)) return res.status(404).json({ error: 'Blueprint not found' });
    const id = `cfg-${Date.now()}`;
    const config = {
      id, blueprint_id: req.params.id, config_type, config_name,
      payload: payload || {}, created_at: new Date().toISOString(),
    };
    inMemoryBlueprintConfigs.set(id, config);
    res.status(201).json(config);
  }
});

// DELETE /api/blueprints/:id/configurations/:configId — remove config
app.delete('/api/blueprints/:id/configurations/:configId', async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM blueprint_configurations WHERE id = $1 AND blueprint_id = $2 RETURNING id',
      [req.params.configId, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Configuration not found' });
    res.status(204).send();
  } catch (err) {
    logger.warn('DB unavailable, deleting in-memory config', { error: err.message });
    const cfg = inMemoryBlueprintConfigs.get(req.params.configId);
    if (!cfg || cfg.blueprint_id !== req.params.id) return res.status(404).json({ error: 'Configuration not found' });
    inMemoryBlueprintConfigs.delete(req.params.configId);
    res.status(204).send();
  }
});

// POST /api/blueprints/:id/assign — assign blueprint to device/group
app.post('/api/blueprints/:id/assign', async (req, res) => {
  const { target_type, target_id, assigned_by } = req.body;
  if (!target_type || !target_id) return res.status(400).json({ error: 'target_type and target_id are required' });

  const VALID_TARGET_TYPES = ['device', 'group'];
  if (!VALID_TARGET_TYPES.includes(target_type)) {
    return res.status(400).json({ error: `target_type must be one of: ${VALID_TARGET_TYPES.join(', ')}` });
  }

  try {
    const bpCheck = await db.query('SELECT id FROM blueprints WHERE id = $1', [req.params.id]);
    if (bpCheck.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });

    const result = await db.query(
      `INSERT INTO blueprint_assignments (blueprint_id, target_type, target_id, assigned_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (blueprint_id, target_type, target_id) DO NOTHING
       RETURNING *`,
      [req.params.id, target_type, target_id, assigned_by || null]
    );
    res.status(201).json(result.rows[0] || { blueprint_id: req.params.id, target_type, target_id, assigned_by });
  } catch (err) {
    logger.warn('DB unavailable, storing assignment in memory', { error: err.message });
    if (!inMemoryBlueprints.has(req.params.id)) return res.status(404).json({ error: 'Blueprint not found' });
    // Check for duplicate
    const existing = [...inMemoryBlueprintAssignments.values()].find(
      a => a.blueprint_id === req.params.id && a.target_type === target_type && a.target_id === target_id
    );
    if (existing) return res.status(201).json(existing);
    const id = `asgn-${Date.now()}`;
    const assignment = {
      id, blueprint_id: req.params.id, target_type, target_id,
      assigned_by: assigned_by || null, assigned_at: new Date().toISOString(),
    };
    inMemoryBlueprintAssignments.set(id, assignment);
    res.status(201).json(assignment);
  }
});

// GET /api/blueprints/:id/assignments — list assignments
app.get('/api/blueprints/:id/assignments', async (req, res) => {
  try {
    const bpCheck = await db.query('SELECT id FROM blueprints WHERE id = $1', [req.params.id]);
    if (bpCheck.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });

    const result = await db.query(
      'SELECT * FROM blueprint_assignments WHERE blueprint_id = $1 ORDER BY assigned_at DESC',
      [req.params.id]
    );
    res.json({ assignments: result.rows });
  } catch (err) {
    logger.warn('DB unavailable, using in-memory assignments', { error: err.message });
    if (!inMemoryBlueprints.has(req.params.id)) return res.status(404).json({ error: 'Blueprint not found' });
    const assignments = [...inMemoryBlueprintAssignments.values()].filter(a => a.blueprint_id === req.params.id);
    res.json({ assignments });
  }
});

// POST /api/blueprints/:id/apply — apply blueprint: push MDM commands to assigned devices
app.post('/api/blueprints/:id/apply', async (req, res) => {
  const OAUTH_PROVIDER = process.env.OAUTH_PROVIDER_URL || 'http://oauth-provider:3010';

  let blueprint;
  let configs = [];
  let assignments = [];

  // Load blueprint data (DB-first, memory fallback)
  try {
    const bpResult = await db.query('SELECT * FROM blueprints WHERE id = $1', [req.params.id]);
    if (bpResult.rows.length === 0) return res.status(404).json({ error: 'Blueprint not found' });
    blueprint = bpResult.rows[0];

    const cfgResult = await db.query(
      'SELECT * FROM blueprint_configurations WHERE blueprint_id = $1',
      [req.params.id]
    );
    configs = cfgResult.rows;

    const asnResult = await db.query(
      'SELECT * FROM blueprint_assignments WHERE blueprint_id = $1',
      [req.params.id]
    );
    assignments = asnResult.rows;
  } catch (err) {
    logger.warn('DB unavailable for blueprint apply, using in-memory', { error: err.message });
    blueprint = inMemoryBlueprints.get(req.params.id);
    if (!blueprint) return res.status(404).json({ error: 'Blueprint not found' });
    configs = [...inMemoryBlueprintConfigs.values()].filter(c => c.blueprint_id === req.params.id);
    assignments = [...inMemoryBlueprintAssignments.values()].filter(a => a.blueprint_id === req.params.id);
  }

  const results = [];

  // For each assignment, push MDM commands to the assigned device(s)
  for (const assignment of assignments) {
    if (assignment.target_type === 'device') {
      // Push each config as a separate MDM command
      for (const config of configs) {
        try {
          const cmdRes = await fetch(`${OAUTH_PROVIDER}/api/devices/${assignment.target_id}/commands`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              command: 'apply_blueprint_config',
              payload: {
                blueprintId: blueprint.id,
                blueprintName: blueprint.name,
                configType: config.config_type,
                configName: config.config_name,
                settings: config.payload,
              }
            })
          });
          results.push({
            targetType: assignment.target_type,
            targetId: assignment.target_id,
            configType: config.config_type,
            success: cmdRes.ok,
          });
        } catch (e) {
          results.push({
            targetType: assignment.target_type,
            targetId: assignment.target_id,
            configType: config.config_type,
            success: false,
            error: e.message,
          });
        }
      }

      // Handle certificate config specially — call certificate-authority service
      const certConfigs = configs.filter(c => c.config_type === 'certificate');
      for (const certConfig of certConfigs) {
        try {
          const caUrl = process.env.CA_SERVICE_URL || 'http://certificate-authority:3018';
          await fetch(`${caUrl}/api/certificates/issue`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: assignment.target_id,
              blueprintId: blueprint.id,
              commonName: certConfig.payload.commonName,
              sans: certConfig.payload.sans || [],
            })
          });
        } catch (_) {
          // Certificate issuance is best-effort
        }
      }
    }
  }

  logger.info(`Blueprint applied: ${blueprint.name}`, {
    blueprintId: blueprint.id,
    assignmentsCount: assignments.length,
    configsCount: configs.length,
    resultsCount: results.length,
  });

  try { publish('policy.applied', { blueprintId: blueprint.id, name: blueprint.name, deviceCount: assignments.filter(a => a.target_type === 'device').length, appliedBy: req.body.applied_by || null }); } catch (e) {}

  res.json({
    blueprintId: blueprint.id,
    blueprintName: blueprint.name,
    assignmentsTargeted: assignments.length,
    configsApplied: configs.length,
    results,
    appliedAt: new Date().toISOString(),
  });
});

// ============================
// License Management
// ============================

// In-memory stores for licenses (fallback when DB unavailable)
const inMemoryLicenses = new Map();
const inMemoryLicenseAssignments = new Map();
const inMemoryLicenseRequests = new Map();

// Seed demo licenses
(function seedLicenses() {
  const demos = [
    {
      id: 'lic-demo-1',
      name: 'Microsoft 365 Business',
      vendor: 'Microsoft',
      category: 'Productivity',
      license_type: 'per_user',
      total_seats: 50,
      used_seats: 32,
      cost_per_seat: 12.50,
      currency: 'CHF',
      renewal_date: null,
      auto_approve: false,
      description: 'Office-Suite inkl. Exchange, Teams, SharePoint',
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'lic-demo-2',
      name: 'Adobe Creative Cloud',
      vendor: 'Adobe',
      category: 'Design',
      license_type: 'per_user',
      total_seats: 10,
      used_seats: 8,
      cost_per_seat: 60.00,
      currency: 'CHF',
      renewal_date: null,
      auto_approve: false,
      description: 'Photoshop, Illustrator, Premiere Pro, und mehr',
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'lic-demo-3',
      name: 'JetBrains All Products',
      vendor: 'JetBrains',
      category: 'Developer',
      license_type: 'per_user',
      total_seats: 20,
      used_seats: 12,
      cost_per_seat: 25.00,
      currency: 'CHF',
      renewal_date: null,
      auto_approve: true,
      description: 'IntelliJ, WebStorm, PyCharm, Rider und alle IDEs',
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];
  for (const lic of demos) {
    inMemoryLicenses.set(lic.id, lic);
  }
})();

// Helper: get used_seats count from assignments table (DB)
async function getLicenseWithSeats(licenseId) {
  const licResult = await db.query('SELECT * FROM license_catalog WHERE id = $1', [licenseId]);
  if (licResult.rows.length === 0) return null;
  const asnResult = await db.query(
    'SELECT COUNT(*) AS cnt FROM license_assignments WHERE license_id = $1',
    [licenseId]
  );
  const lic = licResult.rows[0];
  lic.used_seats = parseInt(asnResult.rows[0].cnt, 10);
  return lic;
}

// ── Catalog (admin) ───────────────────────────────────────────────────────────

// GET /api/licenses — list all licenses with used_seats count
app.get('/api/licenses', async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT lc.*,
             COALESCE(COUNT(la.id), 0)::int AS used_seats
      FROM license_catalog lc
      LEFT JOIN license_assignments la ON la.license_id = lc.id
      GROUP BY lc.id
      ORDER BY lc.name ASC
    `);
    res.json({ licenses: result.rows, total: result.rows.length });
  } catch (err) {
    logger.warn('DB unavailable for licenses list, using in-memory', { error: err.message });
    const licenses = [...inMemoryLicenses.values()];
    res.json({ licenses, total: licenses.length });
  }
});

// GET /api/licenses/kiosk — public self-service catalog (hides cost/notes)
app.get('/api/licenses/kiosk', async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT lc.id, lc.name, lc.vendor, lc.category, lc.license_type,
             lc.total_seats, lc.auto_approve, lc.description, lc.icon_url,
             COALESCE(COUNT(la.id), 0)::int AS used_seats,
             (lc.total_seats - COALESCE(COUNT(la.id), 0))::int AS available_seats
      FROM license_catalog lc
      LEFT JOIN license_assignments la ON la.license_id = lc.id
      GROUP BY lc.id
      ORDER BY lc.name ASC
    `);
    res.json({ licenses: result.rows, total: result.rows.length });
  } catch (err) {
    logger.warn('DB unavailable for kiosk, using in-memory', { error: err.message });
    const licenses = [...inMemoryLicenses.values()].map(({ cost_per_seat, notes, ...pub }) => ({
      ...pub,
      available_seats: pub.total_seats - pub.used_seats,
    }));
    res.json({ licenses, total: licenses.length });
  }
});

// GET /api/licenses/requests — list license requests (query: ?status=pending)
app.get('/api/licenses/requests', async (req, res) => {
  try {
    const { status } = req.query;
    const params = [];
    let where = '';
    if (status) {
      params.push(status);
      where = 'WHERE status = $1';
    }
    const result = await db.query(
      `SELECT * FROM license_requests ${where} ORDER BY requested_at DESC`,
      params
    );
    res.json({ requests: result.rows, total: result.rows.length });
  } catch (err) {
    logger.warn('DB unavailable for license requests, using in-memory', { error: err.message });
    let requests = [...inMemoryLicenseRequests.values()];
    if (req.query.status) {
      requests = requests.filter(r => r.status === req.query.status);
    }
    res.json({ requests, total: requests.length });
  }
});

// POST /api/licenses — create license
app.post('/api/licenses', async (req, res) => {
  const { name, vendor, category, license_type, total_seats, cost_per_seat, currency, renewal_date, auto_approve, description } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  try {
    const result = await db.query(
      `INSERT INTO license_catalog
         (name, vendor, category, license_type, total_seats, cost_per_seat, currency, renewal_date, auto_approve, description)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING *`,
      [
        name,
        vendor || null,
        category || 'Software',
        license_type || 'per_user',
        total_seats || 0,
        cost_per_seat || null,
        currency || 'CHF',
        renewal_date || null,
        auto_approve || false,
        description || null,
      ]
    );
    logger.info(`License created: ${name}`, { id: result.rows[0].id });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, storing license in memory', { error: err.message });
    const id = `lic-${Date.now()}`;
    const license = {
      id, name,
      vendor: vendor || null,
      category: category || 'Software',
      license_type: license_type || 'per_user',
      total_seats: total_seats || 0,
      used_seats: 0,
      cost_per_seat: cost_per_seat || null,
      currency: currency || 'CHF',
      renewal_date: renewal_date || null,
      auto_approve: auto_approve || false,
      description: description || null,
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    inMemoryLicenses.set(id, license);
    res.status(201).json(license);
  }
});

// PUT /api/licenses/:id — update license
app.put('/api/licenses/:id', async (req, res) => {
  const { name, vendor, category, license_type, total_seats, cost_per_seat, currency, renewal_date, auto_approve, description, notes, icon_url } = req.body;
  try {
    const result = await db.query(
      `UPDATE license_catalog SET
         name = COALESCE($1, name),
         vendor = COALESCE($2, vendor),
         category = COALESCE($3, category),
         license_type = COALESCE($4, license_type),
         total_seats = COALESCE($5, total_seats),
         cost_per_seat = COALESCE($6, cost_per_seat),
         currency = COALESCE($7, currency),
         renewal_date = COALESCE($8, renewal_date),
         auto_approve = COALESCE($9, auto_approve),
         description = COALESCE($10, description),
         notes = COALESCE($11, notes),
         icon_url = COALESCE($12, icon_url),
         updated_at = NOW()
       WHERE id = $13
       RETURNING *`,
      [
        name || null, vendor || null, category || null, license_type || null,
        total_seats != null ? total_seats : null,
        cost_per_seat != null ? cost_per_seat : null,
        currency || null, renewal_date || null,
        auto_approve != null ? auto_approve : null,
        description || null, notes || null, icon_url || null,
        req.params.id,
      ]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'License not found' });
    res.json(result.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, updating in-memory license', { error: err.message });
    const lic = inMemoryLicenses.get(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });
    const updated = {
      ...lic,
      ...(name != null && { name }),
      ...(vendor != null && { vendor }),
      ...(category != null && { category }),
      ...(license_type != null && { license_type }),
      ...(total_seats != null && { total_seats }),
      ...(cost_per_seat != null && { cost_per_seat }),
      ...(currency != null && { currency }),
      ...(renewal_date != null && { renewal_date }),
      ...(auto_approve != null && { auto_approve }),
      ...(description != null && { description }),
      ...(notes != null && { notes }),
      ...(icon_url != null && { icon_url }),
      updated_at: new Date().toISOString(),
    };
    inMemoryLicenses.set(req.params.id, updated);
    res.json(updated);
  }
});

// DELETE /api/licenses/:id — delete license
app.delete('/api/licenses/:id', async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM license_catalog WHERE id = $1 RETURNING id',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'License not found' });
    res.status(204).send();
  } catch (err) {
    logger.warn('DB unavailable, deleting in-memory license', { error: err.message });
    if (!inMemoryLicenses.has(req.params.id)) return res.status(404).json({ error: 'License not found' });
    inMemoryLicenses.delete(req.params.id);
    // Remove associated assignments and requests
    for (const [k, v] of inMemoryLicenseAssignments.entries()) {
      if (v.license_id === req.params.id) inMemoryLicenseAssignments.delete(k);
    }
    for (const [k, v] of inMemoryLicenseRequests.entries()) {
      if (v.license_id === req.params.id) inMemoryLicenseRequests.delete(k);
    }
    res.status(204).send();
  }
});

// ── Assignments (admin) ───────────────────────────────────────────────────────

// GET /api/licenses/:id/assignments — list who has this license
app.get('/api/licenses/:id/assignments', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM license_assignments WHERE license_id = $1 ORDER BY assigned_at DESC',
      [req.params.id]
    );
    res.json({ assignments: result.rows, total: result.rows.length });
  } catch (err) {
    logger.warn('DB unavailable for assignments list, using in-memory', { error: err.message });
    const assignments = [...inMemoryLicenseAssignments.values()].filter(a => a.license_id === req.params.id);
    res.json({ assignments, total: assignments.length });
  }
});

// POST /api/licenses/:id/assign — assign license to user/group/device
app.post('/api/licenses/:id/assign', async (req, res) => {
  const { assignee_type, assignee_id, assignee_name, assigned_by, expires_at } = req.body;
  if (!assignee_type || !assignee_id) {
    return res.status(400).json({ error: 'assignee_type and assignee_id are required' });
  }
  const validTypes = ['user', 'group', 'device'];
  if (!validTypes.includes(assignee_type)) {
    return res.status(400).json({ error: `assignee_type must be one of: ${validTypes.join(', ')}` });
  }

  try {
    // Check seats available
    const lic = await getLicenseWithSeats(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });
    if (lic.total_seats > 0 && lic.used_seats >= lic.total_seats) {
      return res.status(409).json({ error: 'No seats available for this license' });
    }

    const result = await db.query(
      `INSERT INTO license_assignments (license_id, assignee_type, assignee_id, assignee_name, assigned_by, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [req.params.id, assignee_type, assignee_id, assignee_name || null, assigned_by || null, expires_at || null]
    );

    // Update used_seats on catalog
    await db.query(
      'UPDATE license_catalog SET used_seats = used_seats + 1, updated_at = NOW() WHERE id = $1',
      [req.params.id]
    );

    logger.info(`License assigned: ${req.params.id} -> ${assignee_type}:${assignee_id}`);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'This assignee already has this license' });
    }
    logger.warn('DB unavailable, assigning in-memory', { error: err.message });
    const lic = inMemoryLicenses.get(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });

    // Check seats
    const currentAssignments = [...inMemoryLicenseAssignments.values()].filter(a => a.license_id === req.params.id);
    if (lic.total_seats > 0 && currentAssignments.length >= lic.total_seats) {
      return res.status(409).json({ error: 'No seats available for this license' });
    }
    // Check duplicate
    const dup = currentAssignments.find(a => a.assignee_type === assignee_type && a.assignee_id === assignee_id);
    if (dup) return res.status(409).json({ error: 'This assignee already has this license' });

    const id = `lasgn-${Date.now()}`;
    const assignment = {
      id,
      license_id: req.params.id,
      assignee_type,
      assignee_id,
      assignee_name: assignee_name || null,
      assigned_at: new Date().toISOString(),
      assigned_by: assigned_by || null,
      expires_at: expires_at || null,
    };
    inMemoryLicenseAssignments.set(id, assignment);
    lic.used_seats = (lic.used_seats || 0) + 1;
    inMemoryLicenses.set(req.params.id, lic);
    res.status(201).json(assignment);
  }
});

// DELETE /api/licenses/:id/assignments/:assigneeId — revoke assignment
app.delete('/api/licenses/:id/assignments/:assigneeId', async (req, res) => {
  try {
    // assigneeId is the assignee_id value
    const result = await db.query(
      'DELETE FROM license_assignments WHERE license_id = $1 AND assignee_id = $2 RETURNING id',
      [req.params.id, req.params.assigneeId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Assignment not found' });

    // Decrement used_seats
    await db.query(
      'UPDATE license_catalog SET used_seats = GREATEST(used_seats - 1, 0), updated_at = NOW() WHERE id = $1',
      [req.params.id]
    );

    logger.info(`License assignment revoked: ${req.params.id} -> ${req.params.assigneeId}`);
    res.status(204).send();
  } catch (err) {
    logger.warn('DB unavailable, revoking in-memory assignment', { error: err.message });
    let found = false;
    for (const [k, v] of inMemoryLicenseAssignments.entries()) {
      if (v.license_id === req.params.id && v.assignee_id === req.params.assigneeId) {
        inMemoryLicenseAssignments.delete(k);
        found = true;
        break;
      }
    }
    if (!found) return res.status(404).json({ error: 'Assignment not found' });
    const lic = inMemoryLicenses.get(req.params.id);
    if (lic) {
      lic.used_seats = Math.max((lic.used_seats || 0) - 1, 0);
      inMemoryLicenses.set(req.params.id, lic);
    }
    res.status(204).send();
  }
});

// ── Kiosk / Requests ──────────────────────────────────────────────────────────

// POST /api/licenses/:id/request — user requests a license
app.post('/api/licenses/:id/request', async (req, res) => {
  const { requester_id, requester_name, justification, assignee_type, assignee_id, assignee_name } = req.body;
  if (!requester_id) return res.status(400).json({ error: 'requester_id is required' });

  try {
    // Check license exists and get seat info
    const lic = await getLicenseWithSeats(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });

    const seatsAvailable = lic.total_seats === 0 || lic.used_seats < lic.total_seats;
    const effectiveAssigneeType = assignee_type || 'user';
    const effectiveAssigneeId = assignee_id || requester_id;
    const effectiveAssigneeName = assignee_name || requester_name || null;

    // Auto-approve path
    if (lic.auto_approve && seatsAvailable) {
      // Create assignment directly
      await db.query(
        `INSERT INTO license_assignments (license_id, assignee_type, assignee_id, assignee_name, assigned_by)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (license_id, assignee_type, assignee_id) DO NOTHING`,
        [req.params.id, effectiveAssigneeType, effectiveAssigneeId, effectiveAssigneeName, requester_id]
      );
      await db.query(
        'UPDATE license_catalog SET used_seats = used_seats + 1, updated_at = NOW() WHERE id = $1',
        [req.params.id]
      );
      const reqResult = await db.query(
        `INSERT INTO license_requests
           (license_id, license_name, requester_id, requester_name, assignee_type, assignee_id, assignee_name, justification, status, decided_at, decided_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'approved',NOW(),'auto-approve')
         RETURNING *`,
        [req.params.id, lic.name, requester_id, requester_name || null, effectiveAssigneeType, effectiveAssigneeId, effectiveAssigneeName, justification || null]
      );
      logger.info(`License auto-approved: ${req.params.id} -> ${requester_id}`);
      return res.status(201).json(reqResult.rows[0]);
    }

    // Pending path
    const reqResult = await db.query(
      `INSERT INTO license_requests
         (license_id, license_name, requester_id, requester_name, assignee_type, assignee_id, assignee_name, justification, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending')
       RETURNING *`,
      [req.params.id, lic.name, requester_id, requester_name || null, effectiveAssigneeType, effectiveAssigneeId, effectiveAssigneeName, justification || null]
    );
    logger.info(`License request created: ${req.params.id} by ${requester_id}`);
    res.status(201).json(reqResult.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, processing license request in-memory', { error: err.message });
    const lic = inMemoryLicenses.get(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });

    const seatsAvailable = lic.total_seats === 0 || lic.used_seats < lic.total_seats;
    const effectiveAssigneeType = assignee_type || 'user';
    const effectiveAssigneeId = assignee_id || requester_id;
    const effectiveAssigneeName = assignee_name || requester_name || null;
    const id = `lreq-${Date.now()}`;
    const now = new Date().toISOString();

    if (lic.auto_approve && seatsAvailable) {
      // Create in-memory assignment
      const aId = `lasgn-${Date.now()}`;
      inMemoryLicenseAssignments.set(aId, {
        id: aId,
        license_id: req.params.id,
        assignee_type: effectiveAssigneeType,
        assignee_id: effectiveAssigneeId,
        assignee_name: effectiveAssigneeName,
        assigned_at: now,
        assigned_by: requester_id,
        expires_at: null,
      });
      lic.used_seats = (lic.used_seats || 0) + 1;
      inMemoryLicenses.set(req.params.id, lic);

      const request = {
        id, license_id: req.params.id, license_name: lic.name,
        requester_id, requester_name: requester_name || null,
        assignee_type: effectiveAssigneeType, assignee_id: effectiveAssigneeId, assignee_name: effectiveAssigneeName,
        justification: justification || null,
        status: 'approved',
        requested_at: now, decided_at: now, decided_by: 'auto-approve',
      };
      inMemoryLicenseRequests.set(id, request);
      return res.status(201).json(request);
    }

    const request = {
      id, license_id: req.params.id, license_name: lic.name,
      requester_id, requester_name: requester_name || null,
      assignee_type: effectiveAssigneeType, assignee_id: effectiveAssigneeId, assignee_name: effectiveAssigneeName,
      justification: justification || null,
      status: 'pending',
      requested_at: now, decided_at: null, decided_by: null,
    };
    inMemoryLicenseRequests.set(id, request);
    res.status(201).json(request);
  }
});

// POST /api/licenses/requests/:id/approve — admin approves request
app.post('/api/licenses/requests/:id/approve', async (req, res) => {
  const { decided_by } = req.body;
  try {
    const reqResult = await db.query('SELECT * FROM license_requests WHERE id = $1', [req.params.id]);
    if (reqResult.rows.length === 0) return res.status(404).json({ error: 'Request not found' });

    const licReq = reqResult.rows[0];
    if (licReq.status !== 'pending') {
      return res.status(409).json({ error: `Request is already ${licReq.status}` });
    }

    // Check seats
    const lic = await getLicenseWithSeats(licReq.license_id);
    if (!lic) return res.status(404).json({ error: 'License not found' });
    if (lic.total_seats > 0 && lic.used_seats >= lic.total_seats) {
      return res.status(409).json({ error: 'No seats available for this license' });
    }

    // Create assignment
    await db.query(
      `INSERT INTO license_assignments (license_id, assignee_type, assignee_id, assignee_name, assigned_by)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (license_id, assignee_type, assignee_id) DO NOTHING`,
      [licReq.license_id, licReq.assignee_type, licReq.assignee_id, licReq.assignee_name, decided_by || 'admin']
    );
    await db.query(
      'UPDATE license_catalog SET used_seats = used_seats + 1, updated_at = NOW() WHERE id = $1',
      [licReq.license_id]
    );

    // Mark request approved
    const updated = await db.query(
      `UPDATE license_requests SET status = 'approved', decided_at = NOW(), decided_by = $1
       WHERE id = $2 RETURNING *`,
      [decided_by || 'admin', req.params.id]
    );
    logger.info(`License request approved: ${req.params.id}`);
    res.json(updated.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, approving in-memory request', { error: err.message });
    const licReq = inMemoryLicenseRequests.get(req.params.id);
    if (!licReq) return res.status(404).json({ error: 'Request not found' });
    if (licReq.status !== 'pending') return res.status(409).json({ error: `Request is already ${licReq.status}` });

    const lic = inMemoryLicenses.get(licReq.license_id);
    if (!lic) return res.status(404).json({ error: 'License not found' });
    const currentAssignments = [...inMemoryLicenseAssignments.values()].filter(a => a.license_id === licReq.license_id);
    if (lic.total_seats > 0 && currentAssignments.length >= lic.total_seats) {
      return res.status(409).json({ error: 'No seats available for this license' });
    }

    const aId = `lasgn-${Date.now()}`;
    const now = new Date().toISOString();
    inMemoryLicenseAssignments.set(aId, {
      id: aId,
      license_id: licReq.license_id,
      assignee_type: licReq.assignee_type,
      assignee_id: licReq.assignee_id,
      assignee_name: licReq.assignee_name,
      assigned_at: now,
      assigned_by: decided_by || 'admin',
      expires_at: null,
    });
    lic.used_seats = (lic.used_seats || 0) + 1;
    inMemoryLicenses.set(licReq.license_id, lic);

    const updated = { ...licReq, status: 'approved', decided_at: now, decided_by: decided_by || 'admin' };
    inMemoryLicenseRequests.set(req.params.id, updated);
    res.json(updated);
  }
});

// POST /api/licenses/requests/:id/deny — admin denies request
app.post('/api/licenses/requests/:id/deny', async (req, res) => {
  const { decided_by } = req.body;
  try {
    const reqResult = await db.query('SELECT * FROM license_requests WHERE id = $1', [req.params.id]);
    if (reqResult.rows.length === 0) return res.status(404).json({ error: 'Request not found' });

    const licReq = reqResult.rows[0];
    if (licReq.status !== 'pending') {
      return res.status(409).json({ error: `Request is already ${licReq.status}` });
    }

    const updated = await db.query(
      `UPDATE license_requests SET status = 'denied', decided_at = NOW(), decided_by = $1
       WHERE id = $2 RETURNING *`,
      [decided_by || 'admin', req.params.id]
    );
    logger.info(`License request denied: ${req.params.id}`);
    res.json(updated.rows[0]);
  } catch (err) {
    logger.warn('DB unavailable, denying in-memory request', { error: err.message });
    const licReq = inMemoryLicenseRequests.get(req.params.id);
    if (!licReq) return res.status(404).json({ error: 'Request not found' });
    if (licReq.status !== 'pending') return res.status(409).json({ error: `Request is already ${licReq.status}` });

    const now = new Date().toISOString();
    const updated = { ...licReq, status: 'denied', decided_at: now, decided_by: decided_by || 'admin' };
    inMemoryLicenseRequests.set(req.params.id, updated);
    res.json(updated);
  }
});

// ============================
// Startup
// ============================
async function start() {
  try {
    // Test database connection
    const connected = await db.testConnection();
    if (!connected) {
      logger.warn('Database not available – service will start but DB features will fail');
    } else {
      // Run migrations
      await db.runMigrations();
      logger.info('Database migrations applied');
    }
  } catch (err) {
    logger.error('Database initialization error', { error: err.message });
    logger.warn('Starting service without database – some features will be unavailable');
  }

  // Pre-load templates
  loadTemplates();

  try { connectBus(); } catch (e) { logger.warn('[bus] startup connect error: ' + e.message); }

  app.listen(PORT, () => {
    logger.info(`Policy Service running on port ${PORT}`);
  });
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received – shutting down');
  await db.shutdown();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received – shutting down');
  await db.shutdown();
  process.exit(0);
});

start();

module.exports = app;
