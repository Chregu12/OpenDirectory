'use strict';

class RevocationUnavailable extends Error {
  constructor() { super('Token revocation authority unavailable'); this.status = 503; }
}

class TokenRevocationStore {
  constructor(database, { demo = false, production = process.env.NODE_ENV === 'production', now = Date.now, limit = 10000 } = {}) {
    if (demo && production) throw new Error('In-memory token revocation is forbidden in production');
    this.database = database;
    this.demo = demo;
    this.now = now;
    this.limit = limit;
    this.memory = new Map();
  }

  validateHash(hash) {
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) throw new RevocationUnavailable();
  }

  prune() {
    for (const [hash, expiry] of this.memory) if (expiry <= this.now()) this.memory.delete(hash);
  }

  async ready() {
    if (this.demo) return;
    try { await this.database.query('SELECT token_hash FROM oauth_token_revocations LIMIT 0'); }
    catch { throw new RevocationUnavailable(); }
  }

  async revoked(hash) {
    this.validateHash(hash);
    if (this.demo) { this.prune(); return this.memory.has(hash); }
    try {
      const result = await this.database.query('SELECT 1 FROM oauth_token_revocations WHERE token_hash=$1 AND expires_at>clock_timestamp()', [hash]);
      return result.rows.length > 0;
    } catch { throw new RevocationUnavailable(); }
  }

  async revoke(hash, clientId, expiresAt) {
    this.validateHash(hash);
    if (typeof clientId !== 'string' || !clientId || clientId.length > 255 || !Number.isFinite(expiresAt)) throw new RevocationUnavailable();
    if (expiresAt <= this.now()) return;
    if (this.demo) {
      this.prune();
      if (!this.memory.has(hash) && this.memory.size >= this.limit) throw new RevocationUnavailable();
      this.memory.set(hash, Math.max(this.memory.get(hash) || 0, expiresAt));
      return;
    }
    try {
      await this.database.query(`INSERT INTO oauth_token_revocations(token_hash,client_id,expires_at) VALUES($1,$2,$3)
        ON CONFLICT(token_hash) DO UPDATE SET expires_at=GREATEST(oauth_token_revocations.expires_at,EXCLUDED.expires_at)`, [hash, clientId, new Date(expiresAt)]);
    } catch { throw new RevocationUnavailable(); }
  }
}

module.exports = { TokenRevocationStore, RevocationUnavailable };
