'use strict';
const IUserRepository = require('../../domain/repositories/IUserRepository');
const UserAggregate = require('../../domain/aggregates/UserAggregate');

class PostgresUserRepository extends IUserRepository {
  constructor(db) { super(); this._db = db; }

  async findById(userId) {
    const r = await this._db.query('SELECT * FROM users WHERE id = $1', [userId]);
    return r.rows[0] ? this._toAggregate(r.rows[0]) : null;
  }

  async findByUsername(username) {
    const r = await this._db.query('SELECT * FROM users WHERE username = $1', [username]);
    return r.rows[0] ? this._toAggregate(r.rows[0]) : null;
  }

  async findByEmail(email) {
    const r = await this._db.query('SELECT * FROM users WHERE email = $1', [email]);
    return r.rows[0] ? this._toAggregate(r.rows[0]) : null;
  }

  async findAll(filters = {}) {
    let q = 'SELECT * FROM users WHERE 1=1';
    const params = [];
    if (filters.role) { params.push(`%${filters.role}%`); q += ` AND roles::text LIKE $${params.length}`; }
    if (filters.limit) { params.push(filters.limit); q += ` LIMIT $${params.length}`; }
    if (filters.offset) { params.push(filters.offset); q += ` OFFSET $${params.length}`; }
    const r = await this._db.query(q, params);
    return r.rows.map(row => this._toAggregate(row));
  }

  async save(user) {
    await this._db.query(
      `INSERT INTO users (id, username, email, password_hash, roles, mfa_enabled, mfa_secret, recovery_codes, locked, lock_until, login_attempts, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (id) DO UPDATE SET
         username=$2, email=$3, password_hash=$4, roles=$5, mfa_enabled=$6,
         mfa_secret=$7, recovery_codes=$8, locked=$9, lock_until=$10,
         login_attempts=$11, updated_at=$13`,
      [user.id, user.username, user.email, user.passwordHash,
       JSON.stringify(user.roles), user.mfaEnabled, user.mfaSecret,
       JSON.stringify(user.recoveryCodes), user.locked, user.lockUntil,
       user.loginAttempts, user.toJSON().createdAt, new Date()]
    );
    return user;
  }

  async delete(userId) {
    await this._db.query('DELETE FROM users WHERE id = $1', [userId]);
  }

  async exists(userId) {
    const r = await this._db.query('SELECT 1 FROM users WHERE id = $1', [userId]);
    return r.rows.length > 0;
  }

  _toAggregate(row) {
    return new UserAggregate({
      id: row.id, username: row.username, email: row.email,
      passwordHash: row.password_hash,
      roles: row.roles || ['user'],
      mfaEnabled: row.mfa_enabled || false,
      mfaSecret: row.mfa_secret,
      recoveryCodes: row.recovery_codes || [],
      locked: row.locked || false,
      lockUntil: row.lock_until,
      loginAttempts: row.login_attempts || 0,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }
}

module.exports = PostgresUserRepository;
