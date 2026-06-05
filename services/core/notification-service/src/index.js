'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const promClient = require('prom-client');
const { v4: uuidv4 } = require('uuid');

// ── RabbitMQ Event Bus ────────────────────────────────────────────────────────
let _amqpChannel = null;
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672';
const EVENTS_EXCHANGE = 'opendirectory.events';

async function connectBus(serviceName) {
  const amqplib = require('amqplib');
  try {
    const conn = await amqplib.connect(RABBITMQ_URL);
    conn.on('error', () => { _amqpChannel = null; });
    conn.on('close', () => { _amqpChannel = null; setTimeout(() => connectBus(serviceName), 5000); });
    const ch = await conn.createChannel();
    await ch.assertExchange(EVENTS_EXCHANGE, 'topic', { durable: true });
    _amqpChannel = ch;
    console.log(`[${serviceName}] RabbitMQ connected`);
    return ch;
  } catch (e) {
    console.warn(`[${serviceName}] RabbitMQ unavailable, retrying in 10s:`, e.message);
    setTimeout(() => connectBus(serviceName), 10000);
    return null;
  }
}

function publishEvent(routingKey, payload, source) {
  if (!_amqpChannel) return;
  try {
    _amqpChannel.publish(EVENTS_EXCHANGE, routingKey,
      Buffer.from(JSON.stringify({ ...payload, _timestamp: new Date().toISOString(), _source: source })),
      { persistent: true, contentType: 'application/json' }
    );
  } catch (_) {}
}

async function subscribeToEvents(queueName, routingKeys, handler) {
  if (!_amqpChannel) return;
  try {
    await _amqpChannel.assertQueue(queueName, {
      durable: true,
      arguments: { 'x-message-ttl': 86400000, 'x-max-length': 10000 }
    });
    for (const rk of routingKeys) {
      await _amqpChannel.bindQueue(queueName, EVENTS_EXCHANGE, rk);
    }
    _amqpChannel.prefetch(5);
    _amqpChannel.consume(queueName, async (msg) => {
      if (!msg) return;
      try {
        const payload = JSON.parse(msg.content.toString());
        await handler(msg.fields.routingKey, payload);
        _amqpChannel.ack(msg);
      } catch (e) {
        _amqpChannel.nack(msg, false, !msg.fields.redelivered);
      }
    });
  } catch (e) {
    console.warn('subscribe error:', e.message);
  }
}
// ─────────────────────────────────────────────────────────────────────────────

// --- Logger ---
function log(level, msg, meta = {}) {
  console.log(JSON.stringify({ level, message: msg, service: 'notification-service', timestamp: new Date().toISOString(), ...meta }));
}

// --- Configuration ---
const PORT = parseInt(process.env.PORT, 10) || 3020;
const DB_CONFIG = {
  host: process.env.DB_HOST || 'postgres',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  database: process.env.DB_NAME || 'opendirectory',
  user: process.env.DB_USER || 'opendirectory',
  password: process.env.DB_PASSWORD || 'opendirectory',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
};

// --- Prometheus Metrics ---
promClient.collectDefaultMetrics({ prefix: 'notification_' });
const notificationsSent = new promClient.Counter({
  name: 'notification_sent_total',
  help: 'Total notifications sent',
  labelNames: ['channel_type', 'status'],
});

// --- Express Setup ---
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// --- Database Pool ---
const pool = new Pool(DB_CONFIG);
pool.on('error', (err) => log('error', 'DB pool error', { error: err.message }));

// --- In-memory fallback stores ---
const inMemoryChannels = new Map([
  ['00000000-0000-0000-0000-000000000001', {
    id: '00000000-0000-0000-0000-000000000001',
    name: 'IT Alerts Email',
    type: 'email',
    config: { host: '', port: 587, secure: false, username: '', password: '', from_address: 'it@example.com' },
    enabled: false,
    created_at: new Date().toISOString(),
    last_used: null,
    test_status: null,
  }],
  ['00000000-0000-0000-0000-000000000002', {
    id: '00000000-0000-0000-0000-000000000002',
    name: 'Slack #it-alerts',
    type: 'slack',
    config: { webhook_url: '' },
    enabled: false,
    created_at: new Date().toISOString(),
    last_used: null,
    test_status: null,
  }],
]);
const inMemoryHistory = [];
const inMemoryTemplates = new Map([
  ['00000000-0000-0000-0001-000000000001', {
    id: '00000000-0000-0000-0001-000000000001',
    name: 'Alert-Benachrichtigung',
    subject: 'IT Alert: {{title}}',
    body: 'Hallo,\n\nEs gibt einen neuen IT-Alert:\n\nTitel: {{title}}\nBeschreibung: {{description}}\nSchweregrad: {{severity}}\n\nBitte handeln Sie entsprechend.\n\nIT-Team',
    type: 'email',
    created_at: new Date().toISOString(),
  }],
  ['00000000-0000-0000-0001-000000000002', {
    id: '00000000-0000-0000-0001-000000000002',
    name: 'Deployment abgeschlossen',
    subject: 'Deployment abgeschlossen: {{app_name}}',
    body: 'Das Deployment von {{app_name}} (v{{version}}) wurde abgeschlossen.\n\nStatus: {{status}}\nZiele: {{target_count}} Geräte\nErfolgreich: {{success_count}}\nFehlgeschlagen: {{failed_count}}\n\nIT-Administration',
    type: 'email',
    created_at: new Date().toISOString(),
  }],
]);

// --- DB Helper: try DB, fallback to in-memory ---
let dbAvailable = false;

async function tryDb(fn, fallbackFn) {
  if (!dbAvailable) return fallbackFn();
  try {
    return await fn();
  } catch (err) {
    log('warn', 'DB operation failed, using in-memory', { error: err.message });
    return fallbackFn();
  }
}

// --- DB Migrations ---
async function runMigrations() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notification_channels (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        config JSONB NOT NULL DEFAULT '{}',
        enabled BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_used TIMESTAMPTZ,
        test_status VARCHAR(50)
      );
      CREATE TABLE IF NOT EXISTS notification_history (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        channel_id UUID,
        subject VARCHAR(255),
        sent_at TIMESTAMPTZ DEFAULT NOW(),
        status VARCHAR(50),
        error TEXT,
        recipient TEXT
      );
      CREATE TABLE IF NOT EXISTS notification_templates (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255),
        subject VARCHAR(255),
        body TEXT,
        type VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    log('info', 'Notification service migrations applied');
    dbAvailable = true;

    // Seed example channels if table empty
    const { rows } = await pool.query('SELECT COUNT(*) FROM notification_channels');
    if (parseInt(rows[0].count, 10) === 0) {
      for (const ch of inMemoryChannels.values()) {
        await pool.query(
          `INSERT INTO notification_channels (id, name, type, config, enabled, created_at)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
          [ch.id, ch.name, ch.type, JSON.stringify(ch.config), ch.enabled, ch.created_at]
        );
      }
    }
    // Seed templates if empty
    const { rows: tRows } = await pool.query('SELECT COUNT(*) FROM notification_templates');
    if (parseInt(tRows[0].count, 10) === 0) {
      for (const t of inMemoryTemplates.values()) {
        await pool.query(
          `INSERT INTO notification_templates (id, name, subject, body, type, created_at)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
          [t.id, t.name, t.subject, t.body, t.type, t.created_at]
        );
      }
    }
  } catch (err) {
    log('warn', 'Migration failed, using in-memory mode', { error: err.message });
    dbAvailable = false;
  }
}

// ========================================================================
// Channels
// ========================================================================

// GET /api/notifications/channels
app.get('/api/notifications/channels', async (req, res) => {
  try {
    const channels = await tryDb(
      async () => {
        const { rows } = await pool.query('SELECT * FROM notification_channels ORDER BY created_at DESC');
        return rows;
      },
      () => Array.from(inMemoryChannels.values())
    );
    res.json({ channels, total: channels.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notifications/channels
app.post('/api/notifications/channels', async (req, res) => {
  try {
    const { name, type, config, enabled } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'name and type are required' });
    const validTypes = ['email', 'slack', 'webhook', 'teams'];
    if (!validTypes.includes(type)) return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });

    const id = uuidv4();
    const channel = { id, name, type, config: config || {}, enabled: enabled || false, created_at: new Date().toISOString(), last_used: null, test_status: null };

    await tryDb(
      async () => {
        const { rows } = await pool.query(
          `INSERT INTO notification_channels (id, name, type, config, enabled) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [id, name, type, JSON.stringify(config || {}), enabled || false]
        );
        return rows[0];
      },
      () => { inMemoryChannels.set(id, channel); return channel; }
    );

    inMemoryChannels.set(id, channel);
    res.status(201).json(channel);
  } catch (err) {
    log('error', 'POST /api/notifications/channels error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/notifications/channels/:id
app.put('/api/notifications/channels/:id', async (req, res) => {
  try {
    const existing = inMemoryChannels.get(req.params.id);
    const updates = req.body;

    const updated = await tryDb(
      async () => {
        const setClauses = [];
        const values = [];
        let i = 1;
        if (updates.name !== undefined) { setClauses.push(`name = $${i++}`); values.push(updates.name); }
        if (updates.type !== undefined) { setClauses.push(`type = $${i++}`); values.push(updates.type); }
        if (updates.config !== undefined) { setClauses.push(`config = $${i++}`); values.push(JSON.stringify(updates.config)); }
        if (updates.enabled !== undefined) { setClauses.push(`enabled = $${i++}`); values.push(updates.enabled); }
        if (setClauses.length === 0) return existing || {};
        values.push(req.params.id);
        const { rows } = await pool.query(
          `UPDATE notification_channels SET ${setClauses.join(', ')} WHERE id = $${i} RETURNING *`,
          values
        );
        if (rows.length === 0) throw new Error('not found');
        return rows[0];
      },
      () => {
        if (!existing) throw new Error('not found');
        const u = { ...existing, ...updates, id: req.params.id };
        inMemoryChannels.set(req.params.id, u);
        return u;
      }
    );

    inMemoryChannels.set(req.params.id, { ...(existing || {}), ...updated });
    res.json(updated);
  } catch (err) {
    if (err.message === 'not found') return res.status(404).json({ error: 'Channel not found' });
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/notifications/channels/:id
app.delete('/api/notifications/channels/:id', async (req, res) => {
  try {
    const existing = inMemoryChannels.get(req.params.id);
    await tryDb(
      async () => {
        const { rowCount } = await pool.query('DELETE FROM notification_channels WHERE id = $1', [req.params.id]);
        if (rowCount === 0) throw new Error('not found');
      },
      () => { if (!existing) throw new Error('not found'); }
    );
    inMemoryChannels.delete(req.params.id);
    res.json({ message: 'Channel deleted', id: req.params.id });
  } catch (err) {
    if (err.message === 'not found') return res.status(404).json({ error: 'Channel not found' });
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notifications/channels/:id/test
app.post('/api/notifications/channels/:id/test', async (req, res) => {
  try {
    const channel = inMemoryChannels.get(req.params.id);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });

    let testResult = { success: false, message: '' };

    if (channel.type === 'email') {
      testResult = await testEmailChannel(channel);
    } else if (channel.type === 'slack') {
      testResult = await testSlackChannel(channel);
    } else if (channel.type === 'webhook' || channel.type === 'teams') {
      testResult = await testWebhookChannel(channel);
    } else {
      testResult = { success: false, message: `Unknown channel type: ${channel.type}` };
    }

    // Update test_status
    const testStatus = testResult.success ? 'ok' : 'error';
    inMemoryChannels.set(req.params.id, { ...channel, test_status: testStatus });
    await tryDb(
      async () => pool.query('UPDATE notification_channels SET test_status = $1 WHERE id = $2', [testStatus, req.params.id]),
      () => {}
    );

    res.json({ ...testResult, channel_id: req.params.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================
// Send Notification
// ========================================================================

// POST /api/notifications/send
app.post('/api/notifications/send', async (req, res) => {
  try {
    const { channel_id, subject, body, to, template, data } = req.body;
    if (!channel_id) return res.status(400).json({ error: 'channel_id is required' });
    if (!subject && !template) return res.status(400).json({ error: 'subject or template is required' });

    const channel = inMemoryChannels.get(channel_id);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });

    // Resolve template
    let resolvedSubject = subject || '';
    let resolvedBody = body || '';
    if (template) {
      const tmpl = Array.from(inMemoryTemplates.values()).find(t => t.name === template || t.id === template);
      if (tmpl) {
        resolvedSubject = resolvedSubject || interpolate(tmpl.subject, data || {});
        resolvedBody = resolvedBody || interpolate(tmpl.body, data || {});
      }
    }

    if (!channel.enabled) {
      // Log but don't actually send
      const historyEntry = {
        id: uuidv4(), channel_id, subject: resolvedSubject,
        sent_at: new Date().toISOString(), status: 'skipped',
        error: 'Channel is disabled', recipient: (to || []).join(', '),
      };
      inMemoryHistory.push(historyEntry);
      notificationsSent.inc({ channel_type: channel.type, status: 'skipped' });
      return res.json({ message: 'Channel is disabled, notification skipped', ...historyEntry });
    }

    let sendResult = { success: false, message: '' };
    if (channel.type === 'email') {
      sendResult = await sendEmail(channel, resolvedSubject, resolvedBody, to);
    } else if (channel.type === 'slack') {
      sendResult = await sendSlack(channel, resolvedSubject, resolvedBody);
    } else if (channel.type === 'webhook' || channel.type === 'teams') {
      sendResult = await sendWebhook(channel, resolvedSubject, resolvedBody);
    }

    const status = sendResult.success ? 'sent' : 'failed';
    const historyEntry = {
      id: uuidv4(), channel_id, subject: resolvedSubject,
      sent_at: new Date().toISOString(), status,
      error: sendResult.success ? null : sendResult.message,
      recipient: (to || []).join(', '),
    };
    inMemoryHistory.push(historyEntry);
    notificationsSent.inc({ channel_type: channel.type, status });

    // Persist history + update last_used
    await tryDb(async () => {
      await pool.query(
        `INSERT INTO notification_history (id, channel_id, subject, status, error, recipient) VALUES ($1, $2, $3, $4, $5, $6)`,
        [historyEntry.id, channel_id, resolvedSubject, status, historyEntry.error, historyEntry.recipient]
      );
      await pool.query('UPDATE notification_channels SET last_used = NOW() WHERE id = $1', [channel_id]);
    }, () => {});
    inMemoryChannels.set(channel_id, { ...channel, last_used: new Date().toISOString() });

    if (!sendResult.success) {
      return res.status(500).json({ error: sendResult.message, ...historyEntry });
    }
    res.json({ message: 'Notification sent', ...historyEntry });
  } catch (err) {
    log('error', 'POST /api/notifications/send error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================
// History
// ========================================================================

// GET /api/notifications/history
app.get('/api/notifications/history', async (req, res) => {
  try {
    const { channel_id, status, limit = 100 } = req.query;
    const history = await tryDb(
      async () => {
        let q = 'SELECT * FROM notification_history';
        const conditions = [];
        const values = [];
        if (channel_id) { conditions.push(`channel_id = $${values.length + 1}`); values.push(channel_id); }
        if (status) { conditions.push(`status = $${values.length + 1}`); values.push(status); }
        if (conditions.length) q += ' WHERE ' + conditions.join(' AND ');
        q += ` ORDER BY sent_at DESC LIMIT $${values.length + 1}`;
        values.push(parseInt(limit, 10));
        const { rows } = await pool.query(q, values);
        return rows;
      },
      () => {
        let h = [...inMemoryHistory];
        if (channel_id) h = h.filter(e => e.channel_id === channel_id);
        if (status) h = h.filter(e => e.status === status);
        return h.reverse().slice(0, parseInt(limit, 10));
      }
    );
    res.json({ history, total: history.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================
// Templates
// ========================================================================

// GET /api/notifications/templates
app.get('/api/notifications/templates', async (req, res) => {
  try {
    const templates = await tryDb(
      async () => {
        const { rows } = await pool.query('SELECT * FROM notification_templates ORDER BY created_at DESC');
        return rows;
      },
      () => Array.from(inMemoryTemplates.values())
    );
    res.json({ templates, total: templates.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notifications/templates
app.post('/api/notifications/templates', async (req, res) => {
  try {
    const { name, subject, body, type } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const id = uuidv4();
    const template = { id, name, subject: subject || '', body: body || '', type: type || 'email', created_at: new Date().toISOString() };
    await tryDb(
      async () => {
        await pool.query(
          `INSERT INTO notification_templates (id, name, subject, body, type) VALUES ($1, $2, $3, $4, $5)`,
          [id, name, subject || '', body || '', type || 'email']
        );
      },
      () => {}
    );
    inMemoryTemplates.set(id, template);
    res.status(201).json(template);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================
// Health & Metrics
// ========================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'notification-service', port: PORT, timestamp: new Date().toISOString() });
});

app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
  } catch (err) {
    res.status(500).json({ error: 'Failed to collect metrics' });
  }
});

// ========================================================================
// Channel Implementations
// ========================================================================

function interpolate(template, data) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => (data[key] !== undefined ? data[key] : `{{${key}}}`));
}

async function testEmailChannel(channel) {
  const { host, port, secure, username, password, from_address } = channel.config;
  if (!host) return { success: false, message: 'Email host not configured' };
  try {
    const transporter = nodemailer.createTransport({
      host, port: port || 587, secure: secure || false,
      auth: username ? { user: username, pass: password } : undefined,
    });
    await transporter.verify();
    return { success: true, message: 'SMTP connection verified' };
  } catch (err) {
    return { success: false, message: `SMTP connection failed: ${err.message}` };
  }
}

async function testSlackChannel(channel) {
  const { webhook_url } = channel.config;
  if (!webhook_url) return { success: false, message: 'Slack webhook URL not configured' };
  try {
    const resp = await fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'OpenDirectory: Notification channel test - this message confirms your Slack integration is working.' }),
    });
    if (resp.ok) return { success: true, message: 'Test message sent to Slack' };
    const text = await resp.text();
    return { success: false, message: `Slack returned ${resp.status}: ${text}` };
  } catch (err) {
    return { success: false, message: `Slack webhook failed: ${err.message}` };
  }
}

async function testWebhookChannel(channel) {
  const { url, method = 'POST', headers: customHeaders = {}, secret } = channel.config;
  if (!url) return { success: false, message: 'Webhook URL not configured' };
  try {
    const payload = JSON.stringify({ event: 'test', message: 'OpenDirectory notification channel test', timestamp: new Date().toISOString() });
    const reqHeaders = { 'Content-Type': 'application/json', ...customHeaders };
    if (secret) {
      const crypto = require('crypto');
      reqHeaders['X-Signature'] = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    }
    const resp = await fetch(url, { method: method || 'POST', headers: reqHeaders, body: payload });
    if (resp.ok) return { success: true, message: `Webhook responded with ${resp.status}` };
    return { success: false, message: `Webhook returned ${resp.status}` };
  } catch (err) {
    return { success: false, message: `Webhook failed: ${err.message}` };
  }
}

async function sendEmail(channel, subject, body, to) {
  const { host, port, secure, username, password, from_address } = channel.config;
  if (!host) return { success: false, message: 'Email host not configured' };
  try {
    // In development, use Ethereal (fake SMTP) if no real credentials
    let transportConfig;
    if (!host || host === 'localhost' || host === '') {
      // Use nodemailer test account / Ethereal
      const testAccount = await nodemailer.createTestAccount();
      transportConfig = {
        host: 'smtp.ethereal.email', port: 587, secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass },
      };
    } else {
      transportConfig = {
        host, port: port || 587, secure: secure || false,
        auth: username ? { user: username, pass: password } : undefined,
      };
    }
    const transporter = nodemailer.createTransport(transportConfig);
    const recipients = Array.isArray(to) && to.length > 0 ? to : [from_address || 'admin@example.com'];
    const info = await transporter.sendMail({
      from: from_address || 'noreply@opendirectory.local',
      to: recipients.join(', '),
      subject, text: body,
    });
    log('info', 'Email sent', { messageId: info.messageId, previewUrl: nodemailer.getTestMessageUrl(info) });
    return { success: true, message: `Email sent (${info.messageId})` };
  } catch (err) {
    log('error', 'Email send failed', { error: err.message });
    return { success: false, message: `Email failed: ${err.message}` };
  }
}

async function sendSlack(channel, subject, body) {
  const { webhook_url } = channel.config;
  if (!webhook_url) return { success: false, message: 'Slack webhook URL not configured' };
  try {
    const resp = await fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `*${subject}*`,
        blocks: [
          { type: 'header', text: { type: 'plain_text', text: subject } },
          { type: 'section', text: { type: 'mrkdwn', text: body } },
        ],
      }),
    });
    if (resp.ok) return { success: true, message: 'Slack message sent' };
    const text = await resp.text();
    return { success: false, message: `Slack error: ${resp.status} ${text}` };
  } catch (err) {
    return { success: false, message: `Slack send failed: ${err.message}` };
  }
}

async function sendWebhook(channel, subject, body) {
  const { url, method = 'POST', headers: customHeaders = {}, secret } = channel.config;
  if (!url) return { success: false, message: 'Webhook URL not configured' };
  try {
    const payload = JSON.stringify({ subject, body, timestamp: new Date().toISOString(), source: 'opendirectory' });
    const reqHeaders = { 'Content-Type': 'application/json', ...customHeaders };
    if (secret) {
      const crypto = require('crypto');
      reqHeaders['X-Signature'] = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    }
    const resp = await fetch(url, { method: method || 'POST', headers: reqHeaders, body: payload });
    if (resp.ok) return { success: true, message: `Webhook sent (${resp.status})` };
    return { success: false, message: `Webhook error: ${resp.status}` };
  } catch (err) {
    return { success: false, message: `Webhook send failed: ${err.message}` };
  }
}

// ========================================================================
// Startup
// ========================================================================

async function start() {
  try {
    // Attempt DB connection but don't fail if unavailable
    try {
      const client = await pool.connect();
      client.release();
      log('info', 'Database connection established');
      await runMigrations();
    } catch (err) {
      log('warn', 'Database unavailable, running in in-memory mode', { error: err.message });
      dbAvailable = false;
    }

    // Connect to RabbitMQ event bus and subscribe to alert-triggering events
    connectBus('notification-service');
    setTimeout(async () => {
      await subscribeToEvents('notification.alerts', [
        'identity.login.failed',
        'identity.account.locked',
        'identity.mfa.disabled',
        'device.non_compliant',
        'app.install.failed',
        'system.backup.failed',
        'security.pim.granted',
        'security.pim.expired',
        'security.cert.expiring',
        'policy.violated',
        'compliance.failed',
      ], async (routingKey, payload) => {
        try {
          const notifMessages = {
            'identity.login.failed':   `Fehlgeschlagener Login: ${payload.username} von ${payload.ip}`,
            'identity.account.locked': `Konto gesperrt: ${payload.username}`,
            'device.non_compliant':    `Gerät nicht konform: ${payload.deviceId}`,
            'app.install.failed':      `Installation fehlgeschlagen: ${payload.appId} auf ${payload.deviceId}`,
            'system.backup.failed':    `Backup fehlgeschlagen: ${payload.error || 'Unbekannter Fehler'}`,
            'security.pim.granted':    `PIM Zugriff gewährt: ${payload.userId} → ${payload.roleId}`,
            'security.cert.expiring':  `Zertifikat läuft ab: ${payload.subject || payload.id}`,
            'policy.violated':         `Policy verletzt: ${payload.policyId} auf ${payload.deviceId}`,
            'compliance.failed':       `Compliance-Check fehlgeschlagen: ${payload.deviceId}`,
          };

          const message = notifMessages[routingKey] || JSON.stringify(payload);
          const severity = routingKey.includes('failed') || routingKey.includes('locked') || routingKey.includes('violated') ? 'error' : 'warning';

          const entry = {
            id: require('crypto').randomUUID(),
            channel_id: null,
            subject: `[${severity.toUpperCase()}] ${routingKey}`,
            body: message,
            sent_at: new Date().toISOString(),
            status: 'received',
            source: payload._source || 'system',
            routing_key: routingKey,
          };

          inMemoryHistory.unshift(entry);
          if (inMemoryHistory.length > 500) inMemoryHistory.length = 500;

          // Try to send via enabled channels
          for (const channel of inMemoryChannels.values()) {
            if (!channel.enabled) continue;
            try {
              if (channel.type === 'email') {
                await sendEmail(channel, entry.subject, message, []);
              } else if (channel.type === 'slack') {
                await sendSlack(channel, entry.subject, message);
              } else if (channel.type === 'webhook' || channel.type === 'teams') {
                await sendWebhook(channel, entry.subject, message);
              }
            } catch (_) {}
          }
        } catch (e) {
          log('warn', 'Event notification handler error', { error: e.message });
        }
      });
    }, 3000);

    app.listen(PORT, '0.0.0.0', () => {
      log('info', `Notification service running on port ${PORT}`);
    });
  } catch (err) {
    log('error', 'Failed to start notification service', { error: err.message });
    process.exit(1);
  }
}

process.on('SIGTERM', () => {
  log('info', 'SIGTERM received, shutting down');
  pool.end();
  process.exit(0);
});

process.on('SIGINT', () => {
  log('info', 'SIGINT received, shutting down');
  pool.end();
  process.exit(0);
});

start();

module.exports = app;
