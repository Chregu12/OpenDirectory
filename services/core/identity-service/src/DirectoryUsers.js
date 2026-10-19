'use strict';

const crypto = require('crypto');
const COLUMNS = 'id,username,email,display_name,department,title,enabled,created_at,updated_at,record_revision';
const PROFILE = { username: 'username', email: 'email', displayName: 'display_name', department: 'department', title: 'title' };

function rejected(status, message) { return Object.assign(new Error(message), { status }); }
function identifier(value) {
  if (typeof value !== 'string' || value.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)) throw rejected(400, 'A canonical user UUID is required');
}
function revision(value) { return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value).toString() === value && BigInt(value) <= 9223372036854775807n; }
function userEtag(user) { return `"user-${user.id}-${user.revision}"`; }
function matchVersion(value) {
  if (value === undefined) throw rejected(428, 'An exact If-Match user version is required');
  const matched = typeof value === 'string' && /^"user-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/.exec(value);
  if (!matched || matched[0].length !== value.length || !revision(matched[2])) throw rejected(400, 'One strong user ETag is required');
  identifier(matched[1]);
}

function userFromRow(row) {
  const iso = value => value instanceof Date ? value.toISOString() : value || undefined;
  return { id: row.id, username: row.username, email: row.email, displayName: row.display_name ?? undefined,
    department: row.department ?? undefined, title: row.title ?? undefined, enabled: row.enabled,
    createdAt: iso(row.created_at), updatedAt: iso(row.updated_at), revision: String(row.record_revision) };
}

function userListQuery(query = {}) {
  if (Object.keys(query).some(key => !['page', 'limit', 'search', 'enabled'].includes(key))) throw rejected(400, 'Unsupported user query');
  const integer = (value, fallback, maximum) => {
    if (value === undefined) return fallback;
    if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > maximum) throw rejected(400, 'Invalid pagination');
    return Number(value);
  };
  if (query.search !== undefined && (typeof query.search !== 'string' || query.search.length > 255)) throw rejected(400, 'Invalid search');
  if (query.enabled !== undefined && !['true', 'false'].includes(query.enabled)) throw rejected(400, 'Invalid status filter');
  return { page: integer(query.page, 1, 1000000), limit: integer(query.limit, 25, 100), search: (query.search || '').trim(), enabled: query.enabled === undefined ? null : query.enabled === 'true' };
}

function fields(body, creating = false) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !Object.keys(body).length
    || Object.keys(body).some(field => !Object.hasOwn(PROFILE, field) && (creating || field !== 'enabled'))) throw rejected(400, creating && body && !Object.keys(body).length ? 'username and email are required' : 'Unsupported user fields');
  const values = {};
  for (const [field, value] of Object.entries(body)) {
    if (field === 'enabled') { if (typeof value !== 'boolean') throw rejected(400, 'enabled must be boolean'); values[field] = value; continue; }
    const required = ['username', 'email'].includes(field);
    if (!required && value === null) { values[field] = null; continue; }
    if (typeof value !== 'string' || value.length > 255 || /[\u0000-\u001f\u007f]/.test(value) || (required && !value.trim())) throw rejected(400, 'Invalid user field');
    values[field] = value.trim() || null;
  }
  if (creating && (!values.username || !values.email)) throw rejected(400, 'username and email are required');
  if (values.email && !/^[^\s@]+@[^\s@]+$/.test(values.email)) throw rejected(400, 'Invalid email');
  return values;
}

class DirectoryUsers {
  constructor(database, { demo = false, memory = new Map() } = {}) { this.database = database; this.demo = demo; this.memory = memory; this.counter = 0; }
  useMemory() {
    if (this.database.isAvailable()) return false;
    if (!this.demo || process.env.NODE_ENV === 'production') throw rejected(503, 'Identity storage unavailable');
    return true;
  }

  async list(query = {}) {
    const { page, limit, search, enabled } = userListQuery(query);
    if (this.useMemory()) {
      const all = [...this.memory.values()].filter(user => (enabled === null || user.enabled === enabled)
        && [user.username, user.email, user.displayName, user.department, user.title].join(' ').toLowerCase().includes(search.toLowerCase()));
      return { users: all.slice((page - 1) * limit, page * limit), total: all.length, page, limit };
    }
    return this.database.transaction(async client => {
      const where = "WHERE ($1='' OR strpos(lower(concat_ws(' ',username,email,display_name,department,title)),lower($1))>0) AND ($2::boolean IS NULL OR enabled=$2)";
      const total = Number((await client.query('SELECT COUNT(*) AS count FROM users ' + where, [search, enabled])).rows[0].count);
      const result = await client.query(`SELECT ${COLUMNS} FROM users ${where} ORDER BY created_at,id LIMIT $3 OFFSET $4`, [search, enabled, limit, (page - 1) * limit]);
      return { users: result.rows.map(userFromRow), total, page, limit };
    }, { readOnly: true });
  }

  async get(id) {
    identifier(id);
    const user = this.useMemory() ? this.memory.get(id) : (await this.database.transaction(client => client.query(`SELECT ${COLUMNS} FROM users WHERE id=$1`, [id]), { readOnly: true })).rows.map(userFromRow)[0];
    if (!user) throw rejected(404, 'User not found');
    return user;
  }

  async create(body, actor) {
    const values = fields(body, true); const id = crypto.randomUUID();
    if (this.useMemory()) {
      if (this.memory.size >= 10000) throw rejected(503, 'Demo storage full');
      const user = { id, ...values, enabled: false, createdAt: new Date().toISOString(), revision: String(++this.counter) };
      this.memory.set(id, user); return user;
    }
    const result = await this.database.write(`INSERT INTO users(id,username,email,display_name,department,title,enabled)
      VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING ${COLUMNS}`, [id, values.username, values.email, values.displayName ?? null, values.department ?? null, values.title ?? null, false], actor);
    return userFromRow(result.rows[0]);
  }

  async mutate(id, expected, actor, operation) {
    identifier(id); matchVersion(expected);
    if (this.useMemory()) {
      const current = this.memory.get(id);
      if (!current) throw rejected(404, 'User not found');
      if (userEtag(current) !== expected) throw rejected(412, 'User changed; reload before retrying');
      return operation(null, current);
    }
    return this.database.transaction(async client => {
      const row = (await client.query(`SELECT ${COLUMNS} FROM users WHERE id=$1 FOR UPDATE`, [id])).rows[0];
      if (!row) throw rejected(404, 'User not found');
      const current = userFromRow(row);
      if (userEtag(current) !== expected) throw rejected(412, 'User changed; reload before retrying');
      return operation(client, current);
    }, { actor });
  }

  async update(id, body, expected, actor) {
    const values = fields(body);
    return this.mutate(id, expected, actor, async (client, current) => {
      if (!client) {
        const updated = { ...current, ...values, revision: String(++this.counter), updatedAt: new Date().toISOString() };
        this.memory.set(id, updated); return updated;
      }
      const entries = Object.entries(values);
      const assignments = entries.map(([field], index) => `${field === 'enabled' ? 'enabled' : PROFILE[field]}=$${index + 1}`).join(',');
      const result = await client.query(`UPDATE users SET ${assignments},updated_at=clock_timestamp() WHERE id=$${entries.length + 1} RETURNING ${COLUMNS}`, [...entries.map(([, value]) => value), id]);
      return userFromRow(result.rows[0]);
    });
  }

  async remove(id, expected, actor) {
    return this.mutate(id, expected, actor, async client => {
      if (client) await client.query('DELETE FROM users WHERE id=$1', [id]); else this.memory.delete(id);
    });
  }
}

module.exports = { DirectoryUsers, userEtag, userFromRow, userListQuery, userFields: fields, validateUserEtag: matchVersion, USER_COLUMNS: COLUMNS };
