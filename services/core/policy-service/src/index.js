const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const app = express();
const PORT = process.env.PORT || 3004;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));

// In-memory store (replace with PostgreSQL in production)
const policies = new Map();
const assignments = new Map();

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'policy-service', timestamp: new Date().toISOString() });
});

// ==================
// Policies API
// ==================
app.get('/api/policies', (req, res) => {
  const { page = 1, limit = 50, type, status } = req.query;
  let result = Array.from(policies.values());
  if (type) result = result.filter(p => p.type === type);
  if (status) result = result.filter(p => p.status === status);
  const start = (page - 1) * limit;
  res.json({ policies: result.slice(start, start + Number(limit)), total: result.length, page: Number(page) });
});

app.get('/api/policies/:id', (req, res) => {
  const policy = policies.get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });
  res.json(policy);
});

app.post('/api/policies', (req, res) => {
  const { name, description, type, rules, priority } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'name and type are required' });
  const id = require('crypto').randomUUID();
  const policy = {
    id, name, description, type, rules: rules || [],
    priority: priority || 100, status: 'draft', version: 1,
    createdAt: new Date().toISOString()
  };
  policies.set(id, policy);
  logger.info(`Policy created: ${name} (${type})`);
  res.status(201).json(policy);
});

app.put('/api/policies/:id', (req, res) => {
  const policy = policies.get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });
  Object.assign(policy, req.body, { version: policy.version + 1, updatedAt: new Date().toISOString() });
  policies.set(req.params.id, policy);
  res.json(policy);
});

app.delete('/api/policies/:id', (req, res) => {
  if (!policies.has(req.params.id)) return res.status(404).json({ error: 'Policy not found' });
  policies.delete(req.params.id);
  res.status(204).send();
});

// Policy activation
app.post('/api/policies/:id/activate', (req, res) => {
  const policy = policies.get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });
  policy.status = 'active';
  policy.activatedAt = new Date().toISOString();
  res.json(policy);
});

app.post('/api/policies/:id/deactivate', (req, res) => {
  const policy = policies.get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });
  policy.status = 'inactive';
  res.json(policy);
});

// ==================
// Policy Assignments
// ==================
app.get('/api/policies/:id/assignments', (req, res) => {
  const policyAssignments = assignments.get(req.params.id) || [];
  res.json({ assignments: policyAssignments });
});

app.post('/api/policies/:id/assign', (req, res) => {
  const { targetType, targetId } = req.body;
  if (!targetType || !targetId) return res.status(400).json({ error: 'targetType and targetId are required' });
  const policyAssignments = assignments.get(req.params.id) || [];
  policyAssignments.push({ targetType, targetId, assignedAt: new Date().toISOString() });
  assignments.set(req.params.id, policyAssignments);
  res.status(201).json({ targetType, targetId });
});

// Policy evaluation endpoint (used by agents)
app.post('/api/policies/evaluate', (req, res) => {
  const { deviceId, userId, context } = req.body;
  const activePolicies = Array.from(policies.values())
    .filter(p => p.status === 'active')
    .sort((a, b) => a.priority - b.priority);
  res.json({ applicablePolicies: activePolicies, evaluatedAt: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Policy Service running on port ${PORT}`);
});

module.exports = app;
