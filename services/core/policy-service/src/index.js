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
