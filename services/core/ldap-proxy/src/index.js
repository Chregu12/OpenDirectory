'use strict';
require('dotenv').config();
const ldap = require('ldapjs');
const http = require('http');

const promClient = require('prom-client');
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const SchemaManager = require('./schema/schemaManager');
const LDAPOperations = require('./operations/ldapOperations');
const { validateFilter, sanitizeFilter } = require('./schema/ldapFilterParser');

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

const ldapBindsCounter = new promClient.Counter({ name: 'ldap_binds_total', help: 'LDAP bind operations', labelNames: ['result'], registers: [register] });
const ldapSearchesCounter = new promClient.Counter({ name: 'ldap_searches_total', help: 'LDAP search operations', registers: [register] });

const LLDAP_URL = process.env.LLDAP_URL || 'ldap://localhost:3890';
const LLDAP_BASE_DN = process.env.LLDAP_BASE_DN || 'dc=opendirectory,dc=local';
const PROXY_PORT = parseInt(process.env.LDAP_PROXY_PORT || '389');
const REST_API_PORT = parseInt(process.env.LDAP_REST_PORT || '8389');
const METRICS_PORT = parseInt(process.env.METRICS_PORT || '9091');

// Parse LLDAP URL
const lldapUrl = new URL(LLDAP_URL.replace('ldap://', 'http://').replace('ldaps://', 'https://'));
const LLDAP_HOST = lldapUrl.hostname;
const LLDAP_PORT = parseInt(lldapUrl.port || '3890');

// ---------------------------------------------------------------------------
// LDAP Operations & Schema Manager (shared, using admin credentials)
// ---------------------------------------------------------------------------

const ldapOps = new LDAPOperations({
  host: LLDAP_HOST,
  port: LLDAP_PORT,
  bindDn: process.env.LLDAP_ADMIN_DN || `uid=${process.env.LLDAP_ADMIN_USER || 'admin'},ou=people,${LLDAP_BASE_DN}`,
  bindPassword: process.env.LLDAP_ADMIN_PASSWORD || '',
  useTLS: LLDAP_URL.startsWith('ldaps://'),
});

// SchemaManager starts with no live client (fallback to built-in schema).
// It can optionally be wired to a live ldapts client later.
const schemaManager = new SchemaManager(null);

// ---------------------------------------------------------------------------
// LDAP proxy server (existing behavior — preserved intact)
// ---------------------------------------------------------------------------

const server = ldap.createServer();

// Helper: create a connection to LLDAP
function connectToLLDAP() {
  return ldap.createClient({ url: LLDAP_URL, timeout: 5000, connectTimeout: 5000 });
}

// Bind — forward credentials to LLDAP
server.bind(LLDAP_BASE_DN, async (req, res, next) => {
  const dn = req.dn.toString();
  const password = req.credentials;

  const upstream = connectToLLDAP();
  upstream.bind(dn, password, (err) => {
    upstream.unbind();
    if (err) {
      ldapBindsCounter.inc({ result: 'failure' });
      console.log(`[ldap-proxy] bind failed for ${dn}: ${err.message}`);
      return next(new ldap.InvalidCredentialsError());
    }
    ldapBindsCounter.inc({ result: 'success' });
    console.log(`[ldap-proxy] bind success: ${dn}`);
    res.end();
    return next();
  });
});

// Also handle binds not under our base DN
server.bind('', async (req, res, next) => {
  const dn = req.dn.toString();
  const password = req.credentials;

  if (!dn) {
    // Anonymous bind
    ldapBindsCounter.inc({ result: 'anonymous' });
    res.end();
    return next();
  }

  const upstream = connectToLLDAP();
  upstream.bind(dn, password, (err) => {
    upstream.unbind();
    if (err) {
      ldapBindsCounter.inc({ result: 'failure' });
      return next(new ldap.InvalidCredentialsError());
    }
    ldapBindsCounter.inc({ result: 'success' });
    res.end();
    return next();
  });
});

// Search — forward to LLDAP
server.search(LLDAP_BASE_DN, (req, res, next) => {
  ldapSearchesCounter.inc();
  const upstream = connectToLLDAP();

  // Use admin credentials for upstream search
  const adminDn = `uid=${process.env.LLDAP_ADMIN_USER || 'admin'},ou=people,${LLDAP_BASE_DN}`;
  const adminPw = process.env.LLDAP_ADMIN_PASSWORD || '';

  upstream.bind(adminDn, adminPw, (bindErr) => {
    if (bindErr) {
      // Try anonymous
      console.warn('[ldap-proxy] admin bind failed, trying anonymous:', bindErr.message);
    }

    const opts = {
      filter: req.filter.toString(),
      scope: req.scope,
      attributes: req.attributes,
      sizeLimit: req.sizeLimit || 100,
      timeLimit: req.timeLimit || 10,
    };

    upstream.search(req.dn.toString(), opts, (searchErr, searchRes) => {
      if (searchErr) {
        upstream.unbind();
        return next(new ldap.OperationsError(searchErr.message));
      }

      searchRes.on('searchEntry', (entry) => {
        res.send(entry);
      });

      searchRes.on('searchReference', (referral) => {
        res.send(referral);
      });

      searchRes.on('end', (result) => {
        upstream.unbind();
        res.end();
        return next();
      });

      searchRes.on('error', (err) => {
        upstream.unbind();
        return next(new ldap.OperationsError(err.message));
      });
    });
  });
});

// Start LDAP proxy
const ldapPort = process.env.NODE_ENV === 'production' && process.getuid && process.getuid() === 0 ? PROXY_PORT : Math.max(PROXY_PORT, 1389);
server.listen(ldapPort, '0.0.0.0', () => {
  console.log(`[ldap-proxy] LDAP proxy listening on port ${ldapPort} → ${LLDAP_URL}`);
  console.log(`[ldap-proxy] Base DN: ${LLDAP_BASE_DN}`);
});

server.on('error', (err) => {
  console.error('[ldap-proxy] Server error:', err.message);
});

process.on('SIGTERM', () => {
  server.close();
  ldapOps.destroy().finally(() => process.exit(0));
});

// ---------------------------------------------------------------------------
// REST API helpers
// ---------------------------------------------------------------------------

/**
 * Read the full request body as a string, then parse JSON.
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); }
      catch (e) { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

/**
 * Send a JSON response.
 */
function jsonResponse(res, status, body) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(json);
}

/**
 * Middleware: verify request carries a valid auth header.
 * Accepts:
 *   Authorization: Bearer <token>   (token validated against LLDAP_API_TOKEN env var)
 *   X-Bind-DN + X-Bind-Password     (LDAP bind verification)
 *
 * Returns true if auth passes; writes 401 and returns false if it fails.
 */
async function requireAuth(req, res) {
  const authHeader = req.headers['authorization'] || '';
  const bindDn = req.headers['x-bind-dn'];
  const bindPassword = req.headers['x-bind-password'];

  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const expected = process.env.LLDAP_API_TOKEN || '';
    if (expected && token === expected) return true;
    // If no API token is configured, reject all bearer tokens
    if (!expected) {
      jsonResponse(res, 401, { error: 'Bearer auth not configured — set LLDAP_API_TOKEN' });
      return false;
    }
    jsonResponse(res, 401, { error: 'Invalid bearer token' });
    return false;
  }

  if (bindDn && bindPassword !== undefined) {
    // Verify by binding to LDAP
    try {
      const testOps = new LDAPOperations({
        host: LLDAP_HOST,
        port: LLDAP_PORT,
        bindDn,
        bindPassword,
        useTLS: LLDAP_URL.startsWith('ldaps://'),
      });
      const { sessionId } = await testOps.bind(bindDn, bindPassword);
      await testOps.unbind(sessionId);
      return true;
    } catch (_) {
      jsonResponse(res, 401, { error: 'LDAP bind failed — check X-Bind-DN and X-Bind-Password' });
      return false;
    }
  }

  jsonResponse(res, 401, { error: 'Authentication required. Provide Authorization: Bearer <token> or X-Bind-DN + X-Bind-Password headers' });
  return false;
}

/**
 * Wrap an async route handler with error catching.
 */
function wrapRoute(fn) {
  return async (req, res, params) => {
    const start = Date.now();
    try {
      await fn(req, res, params);
    } catch (err) {
      console.error('[ldap-proxy REST]', err.message);
      const status = err.code === 'NOT_FOUND' ? 404 : 500;
      if (!res.writableEnded) {
        jsonResponse(res, status, { error: err.message });
      }
    } finally {
      const route = req.url.replace(/\/[^/]+(?=\/[^/]+\/?$)/, '/:id').split('?')[0];
      httpRequestDuration.observe({ method: req.method, route }, (Date.now() - start) / 1000);
    }
  };
}

// ---------------------------------------------------------------------------
// Simple URL router
// ---------------------------------------------------------------------------

class Router {
  constructor() {
    this._routes = []; // { method, pattern, keys, handler }
  }

  _add(method, path, handler) {
    // Convert path params like :name to regex capture groups
    const keys = [];
    const pattern = new RegExp(
      '^' + path.replace(/:([^/]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '(?:\\?.*)?$'
    );
    this._routes.push({ method, pattern, keys, handler: wrapRoute(handler) });
  }

  get(path, handler) { this._add('GET', path, handler); }
  post(path, handler) { this._add('POST', path, handler); }
  put(path, handler) { this._add('PUT', path, handler); }
  delete(path, handler) { this._add('DELETE', path, handler); }

  async handle(req, res) {
    const urlPath = req.url.split('?')[0];
    for (const route of this._routes) {
      if (route.method !== req.method) continue;
      const m = urlPath.match(route.pattern);
      if (m) {
        const params = {};
        route.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
        await route.handler(req, res, params);
        return true;
      }
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// REST API — Schema endpoints
// ---------------------------------------------------------------------------

const router = new Router();

// GET /api/schema/object-classes
router.get('/api/schema/object-classes', async (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const result = await schemaManager.listObjectClasses({
    filter: q.get('filter') || undefined,
    page: q.get('page') || 1,
    limit: q.get('limit') || 50,
  });
  jsonResponse(res, 200, result);
});

// GET /api/schema/object-classes/:name
router.get('/api/schema/object-classes/:name', async (req, res, params) => {
  const oc = await schemaManager.getObjectClass(params.name);
  jsonResponse(res, 200, oc);
});

// GET /api/schema/attribute-types
router.get('/api/schema/attribute-types', async (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const result = await schemaManager.listAttributeTypes({
    filter: q.get('filter') || undefined,
    page: q.get('page') || 1,
    limit: q.get('limit') || 50,
  });
  jsonResponse(res, 200, result);
});

// GET /api/schema/attribute-types/:name
router.get('/api/schema/attribute-types/:name', async (req, res, params) => {
  const at = await schemaManager.getAttributeType(params.name);
  jsonResponse(res, 200, at);
});

// POST /api/schema/attribute-types — add custom attribute type (auth required)
router.post('/api/schema/attribute-types', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const at = await schemaManager.addAttributeType(body);
  jsonResponse(res, 201, at);
});

// POST /api/schema/object-classes — add custom object class (auth required)
router.post('/api/schema/object-classes', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const oc = await schemaManager.addObjectClass(body);
  jsonResponse(res, 201, oc);
});

// GET /api/schema/validate — validate entry against schema
router.get('/api/schema/validate', async (req, res) => {
  const body = await readBody(req);
  if (!body.dn || !body.attributes) {
    return jsonResponse(res, 400, { error: 'Request body must contain {dn, attributes}' });
  }
  const result = await schemaManager.validateEntry(body.dn, body.attributes);
  jsonResponse(res, 200, result);
});

// GET /api/dn/:dn/schema — get schema applicable for a DN
router.get('/api/dn/:dn/schema', async (req, res, params) => {
  const result = await schemaManager.getSchemaForDN(params.dn);
  jsonResponse(res, 200, result);
});

// ---------------------------------------------------------------------------
// REST API — LDAP operation endpoints (all require auth)
// ---------------------------------------------------------------------------

// POST /api/ldap/search
router.post('/api/ldap/search', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);

  const { baseDn, filter, scope, attributes, sizeLimit, timeLimit } = body;
  if (!baseDn) return jsonResponse(res, 400, { error: 'baseDn is required' });

  // Validate and sanitize filter
  if (filter) {
    const { valid, error } = validateFilter(filter);
    if (!valid) return jsonResponse(res, 400, { error: `Invalid LDAP filter: ${error}` });
  }

  const safeFilter = filter ? sanitizeFilter(filter) : '(objectClass=*)';
  const result = await ldapOps.search(baseDn, { filter: safeFilter, scope, attributes, sizeLimit, timeLimit });
  jsonResponse(res, 200, result);
});

// POST /api/ldap/add
router.post('/api/ldap/add', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const { dn, attributes } = body;
  if (!dn || !attributes) return jsonResponse(res, 400, { error: 'dn and attributes are required' });
  const result = await ldapOps.add(dn, attributes);
  jsonResponse(res, 201, result);
});

// PUT /api/ldap/modify
router.put('/api/ldap/modify', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const { dn, changes } = body;
  if (!dn || !Array.isArray(changes)) return jsonResponse(res, 400, { error: 'dn and changes[] are required' });
  const result = await ldapOps.modify(dn, changes);
  jsonResponse(res, 200, result);
});

// PUT /api/ldap/move
router.put('/api/ldap/move', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const { dn, newRDN, deleteOldRDN, newSuperior } = body;
  if (!dn || !newRDN) return jsonResponse(res, 400, { error: 'dn and newRDN are required' });
  const result = await ldapOps.modifyDN(dn, newRDN, deleteOldRDN !== false, newSuperior || null);
  jsonResponse(res, 200, result);
});

// DELETE /api/ldap/delete
router.delete('/api/ldap/delete', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const { dn } = body;
  if (!dn) return jsonResponse(res, 400, { error: 'dn is required' });
  const result = await ldapOps.delete(dn);
  jsonResponse(res, 200, result);
});

// POST /api/ldap/compare
router.post('/api/ldap/compare', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const { dn, attribute, value } = body;
  if (!dn || !attribute || value === undefined) return jsonResponse(res, 400, { error: 'dn, attribute, and value are required' });
  const result = await ldapOps.compare(dn, attribute, String(value));
  jsonResponse(res, 200, { dn, attribute, value, matches: result });
});

// POST /api/ldap/password-change
router.post('/api/ldap/password-change', async (req, res) => {
  if (!await requireAuth(req, res)) return;
  const body = await readBody(req);
  const { userDn, oldPassword, newPassword } = body;
  if (!userDn || !oldPassword || !newPassword) {
    return jsonResponse(res, 400, { error: 'userDn, oldPassword, and newPassword are required' });
  }
  const result = await ldapOps.changePassword(userDn, oldPassword, newPassword);
  jsonResponse(res, 200, result);
});

// ---------------------------------------------------------------------------
// REST API server (metrics + API on separate ports)
// ---------------------------------------------------------------------------

// Metrics-only server (original port 9091)
http.createServer(async (req, res) => {
  if (req.url === '/metrics') {
    res.setHeader('Content-Type', register.contentType);
    res.end(await register.metrics());
  } else if (req.url === '/healthz') {
    res.writeHead(200); res.end('ok');
  } else {
    res.writeHead(404); res.end();
  }
}).listen(METRICS_PORT, () => console.log(`[ldap-proxy] metrics on :${METRICS_PORT}`));

// REST API server
http.createServer(async (req, res) => {
  const start = Date.now();

  // CORS pre-flight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Bind-DN,X-Bind-Password',
    });
    res.end();
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    const matched = await router.handle(req, res);
    if (!matched) {
      jsonResponse(res, 404, { error: 'Route not found', path: req.url });
    }
  } catch (err) {
    console.error('[ldap-proxy REST] Unhandled error:', err.message);
    if (!res.writableEnded) {
      jsonResponse(res, 500, { error: 'Internal server error' });
    }
  } finally {
    if (!res.writableEnded) res.end();
    const route = req.url.replace(/\/[^/]+(?=\/[^/]+\/?$)/, '/:id').split('?')[0];
    const status = res.statusCode || 200;
    httpRequestsTotal.inc({ method: req.method, route, status: String(status) });
    httpRequestDuration.observe({ method: req.method, route }, (Date.now() - start) / 1000);
  }
}).listen(REST_API_PORT, '0.0.0.0', () => {
  console.log(`[ldap-proxy] REST API listening on port ${REST_API_PORT}`);
});
