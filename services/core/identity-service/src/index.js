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
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));

// In-memory store (replace with PostgreSQL in production)
const users = new Map();
const groups = new Map();
const ous = new Map();

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'identity-service', timestamp: new Date().toISOString() });
});

// ==================
// Users API
// ==================
app.get('/api/users', (req, res) => {
  const { page = 1, limit = 50, search } = req.query;
  let result = Array.from(users.values());
  if (search) {
    const q = search.toLowerCase();
    result = result.filter(u => u.displayName?.toLowerCase().includes(q) || u.email?.toLowerCase().includes(q));
  }
  const start = (page - 1) * limit;
  res.json({ users: result.slice(start, start + Number(limit)), total: result.length, page: Number(page) });
});

app.get('/api/users/:id', (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.post('/api/users', (req, res) => {
  const { username, email, displayName, department, title } = req.body;
  if (!username || !email) return res.status(400).json({ error: 'username and email are required' });
  const id = require('crypto').randomUUID();
  const user = { id, username, email, displayName, department, title, enabled: true, createdAt: new Date().toISOString() };
  users.set(id, user);
  logger.info(`User created: ${username}`);
  res.status(201).json(user);
});

app.put('/api/users/:id', (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  Object.assign(user, req.body, { updatedAt: new Date().toISOString() });
  users.set(req.params.id, user);
  res.json(user);
});

app.delete('/api/users/:id', (req, res) => {
  if (!users.has(req.params.id)) return res.status(404).json({ error: 'User not found' });
  users.delete(req.params.id);
  res.status(204).send();
});

// ==================
// Groups API
// ==================
app.get('/api/groups', (req, res) => {
  res.json({ groups: Array.from(groups.values()), total: groups.size });
});

app.get('/api/groups/:id', (req, res) => {
  const group = groups.get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  res.json(group);
});

app.post('/api/groups', (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  const id = require('crypto').randomUUID();
  const group = { id, name, description, members: [], createdAt: new Date().toISOString() };
  groups.set(id, group);
  logger.info(`Group created: ${name}`);
  res.status(201).json(group);
});

app.post('/api/groups/:id/members', (req, res) => {
  const group = groups.get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const { userId } = req.body;
  if (!group.members.includes(userId)) group.members.push(userId);
  res.json(group);
});

app.delete('/api/groups/:id', (req, res) => {
  if (!groups.has(req.params.id)) return res.status(404).json({ error: 'Group not found' });
  groups.delete(req.params.id);
  res.status(204).send();
});

// ==================
// Identity (LDAP-compatible) endpoint
// ==================
app.get('/api/identity/search', (req, res) => {
  const { filter, base, scope } = req.query;
  const allUsers = Array.from(users.values());
  const allGroups = Array.from(groups.values());
  res.json({ entries: [...allUsers, ...allGroups], total: allUsers.length + allGroups.length });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Identity Service running on port ${PORT}`);
});

module.exports = app;
