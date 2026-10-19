'use strict';

const { AdapterError } = require('../PolicyLicenseClient');
const catalogFields = ['name', 'vendor', 'category', 'license_type', 'total_seats', 'cost_per_seat', 'currency', 'renewal_date', 'auto_approve', 'description'];
const actorFields = new Set(['createdBy', 'updatedBy', 'deletedBy', 'assignedBy', 'revokedBy', 'renewedBy', 'assigned_by', 'decided_by', 'requester_id', 'requester_name',
  'actor', 'authorization', 'roles', 'permissions', 'scope', 'scopes', 'directory_user_id']);
const operations = [
  ['GET', '/kiosk', '', '/kiosk'],
  ['GET', '/licenses', 'licenses.catalog.read', ''],
  ['POST', '/licenses', 'licenses.catalog.manage', '', catalogFields],
  ['GET', '/licenses/:id', 'licenses.catalog.read', '/:id'],
  ['PUT', '/licenses/:id', 'licenses.catalog.manage', '/:id', [...catalogFields, 'notes', 'icon_url']],
  ['DELETE', '/licenses/:id', 'licenses.catalog.manage', '/:id', []],
  ['GET', '/licenses/:id/assignments', 'licenses.assignments.read', '/:id/assignments'],
  ['POST', '/licenses/:id/assign', 'licenses.assignments.manage', '/:id/assign', ['assignee_type', 'assignee_id', 'assignee_name', 'expires_at']],
  ['DELETE', '/licenses/:id/assignments/:assigneeId', 'licenses.assignments.manage', '/:id/assignments/:assigneeId', [], ['assignee_type']],
  ['POST', '/licenses/:id/request', '', '/:id/request', ['justification', 'assignee_type', 'assignee_id', 'assignee_name']],
  ['GET', '/requests', '', '/requests', undefined, ['status']],
  ['POST', '/requests/:id/approve', 'licenses.requests.review', '/requests/:id/approve', []],
  ['POST', '/requests/:id/deny', 'licenses.requests.review', '/requests/:id/deny', []],
  ['GET', '/groups', 'licenses.assignments.read', '/groups'],
  ['POST', '/licenses/:id/groups/:groupId/reconcile', 'licenses.assignments.manage', '/:id/groups/:groupId/reconcile', []],
  ['GET', '/users', 'licenses.assignments.read', '/users'],
  ['POST', '/users/:id/reconcile', 'licenses.assignments.manage', '/users/:id/reconcile', []],
  ['POST', '/users/:id/offboard', 'licenses.subjects.offboard', '/users/:id/offboard', []],
  ['POST', '/users/:id/activate', 'licenses.subjects.manage', '/users/:id/activate', []],
  ['GET', '/licenses/:id/audit', 'licenses.assignments.read', '/:id/audit'],
];

function select(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AdapterError(400, 'A JSON object is required');
  const unsupported = Object.keys(value).filter(key => !fields.includes(key) && !actorFields.has(key));
  if (unsupported.length) throw new AdapterError(422, 'Unsupported legacy fields; use the canonical license schema');
  const result = {};
  for (const key of fields) if (Object.hasOwn(value, key)) result[key] = value[key];
  return result;
}

function registerRoutes(app, client) {
  app.get('/api/license/access', (req, res) => res.json(req.licenseAccess));
  for (const [method, path, permission, destination, fields, queryFields = []] of operations) {
    if (typeof permission !== 'string' || typeof destination !== 'string') throw new Error('License operations require explicit authorization and destination');
    app[method.toLowerCase()](`/api/license${path}`, async (req, res, next) => {
      try {
        if (req.method !== method) return next('route');
        if (permission && !req.licenseAccess.permissions.includes(permission)) throw new AdapterError(403, 'The canonical license permission is required');
        const target = destination.replace(/:([A-Za-z]+)/g, (_match, key) => {
          const value = req.params[key];
          if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/.test(value)) throw new AdapterError(400, 'Invalid license identifier');
          return encodeURIComponent(value);
        });
        const query = select(req.query, queryFields);
        if (Object.values(query).some(value => typeof value !== 'string')) throw new AdapterError(400, 'Query values must be strings');
        const body = fields === undefined ? undefined : select(req.body || {}, fields);
        const result = await client.request(method, `/api/licenses${target}`, req.headers.authorization, { body, query });
        if (result.retryAfter) res.set('Retry-After', result.retryAfter);
        if (result.status === 204) return res.status(204).end();
        res.status(result.status).json(result.body);
      } catch (error) { next(error); }
    });
  }
  app.use('/api/license', (req, res) => {
    const retired = /^\/(?:types|software|vendors|usage|compliance|optimization|assets|mobile|reports|dashboard|audit)(?:\/|$)/.test(req.path)
      || /^\/licenses\/[^/]+\/(?:renew|revoke)\/?$/.test(req.path);
    res.status(retired ? 410 : 404).json({ error: retired ? 'Legacy prototype operation retired; migrate to canonical entitlements' : 'License operation not found', canonicalApi: '/api/licenses' });
  });
}

module.exports = { registerRoutes, operations };
