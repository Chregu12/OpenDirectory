'use strict';
const ISessionRepository = require('../../domain/repositories/ISessionRepository');
const SessionAggregate = require('../../domain/aggregates/SessionAggregate');

class PostgresSessionRepository extends ISessionRepository {
  constructor(db) { super(); this._db = db; }

  async findById(sessionId) {
    const r = await this._db.query('SELECT * FROM sessions WHERE session_id = $1', [sessionId]);
    return r.rows[0] ? this._toAggregate(r.rows[0]) : null;
  }

  async findByToken(token) {
    const r = await this._db.query('SELECT * FROM sessions WHERE token = $1', [token]);
    return r.rows[0] ? this._toAggregate(r.rows[0]) : null;
  }

  async findActiveByUser(userId) {
    const r = await this._db.query(
      'SELECT * FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()',
      [userId]
    );
    return r.rows.map(row => this._toAggregate(row));
  }

  async save(session) {
    await this._db.query(
      `INSERT INTO sessions (session_id, user_id, token, refresh_token, expires_at, created_at, revoked_at, ip, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (session_id) DO UPDATE SET
         revoked_at=$7`,
      [session.sessionId, session.userId, session.token, session._refreshToken,
       session.expiresAt, session._createdAt, session.revokedAt,
       session._ip, session._userAgent]
    );
    return session;
  }

  async revokeAllForUser(userId) {
    await this._db.query(
      'UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
      [userId]
    );
  }

  _toAggregate(row) {
    return new SessionAggregate({
      sessionId: row.session_id,
      userId: row.user_id,
      token: row.token,
      refreshToken: row.refresh_token,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      revokedAt: row.revoked_at,
      ip: row.ip,
      userAgent: row.user_agent,
    });
  }
}

module.exports = PostgresSessionRepository;
