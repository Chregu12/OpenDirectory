'use strict';
const { randomUUID } = require('crypto');

class PasswordApplicationService {
  constructor({ userRepository, messageBus, cache, logger, tokenGenerator }) {
    this._userRepo = userRepository;
    this._bus = messageBus;
    this._cache = cache;
    this._log = logger || console;
    // Defaults to a UUID; callers that need to preserve a specific legacy
    // token format (e.g. the 32-byte hex tokens the HTTP layer used to mint
    // itself) can inject their own generator.
    this._tokenGenerator = tokenGenerator || (() => randomUUID());
  }

  async requestReset(email) {
    const user = await this._userRepo.findByEmail(email);
    if (!user) return null; // silent — don't leak user existence

    const token = this._tokenGenerator();
    const expiry = Date.now() + 60 * 60 * 1000; // 1h

    if (this._cache) {
      await this._cache.set(`pwd_reset:${token}`, JSON.stringify({ userId: user.id, expiry }), 'EX', 3600);
    }

    return { userId: user.id, token, expiry, username: user.username, email: user.email };
  }

  /**
   * Read-only lookup of a pending reset token — does NOT consume/delete it.
   * Returns the same { userId, expiry } shape stored by requestReset(), or
   * null when the token is unknown or the cache is unavailable. Callers that
   * need the target userId ahead of actually performing the reset (e.g. for
   * policy validation or audit logging before the token is consumed) should
   * use this instead of resetWithToken().
   */
  async peekToken(token) {
    if (!this._cache) return null;
    const raw = await this._cache.get(`pwd_reset:${token}`);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  /**
   * Delete a reset token from the cache without touching the user's
   * password. Used by callers that perform the actual password mutation
   * themselves (e.g. via a different, already-battle-tested code path) and
   * only need PasswordApplicationService to manage the token's lifecycle.
   */
  async consumeToken(token) {
    if (!this._cache) return;
    await this._cache.del(`pwd_reset:${token}`);
  }

  async resetWithToken(token, newPlainPassword) {
    if (!this._cache) throw new Error('Cache not available');
    const raw = await this._cache.get(`pwd_reset:${token}`);
    if (!raw) throw Object.assign(new Error('Token expired or invalid'), { status: 400 });

    const { userId, expiry } = JSON.parse(raw);
    if (Date.now() > expiry) {
      await this._cache.del(`pwd_reset:${token}`);
      throw Object.assign(new Error('Token expired'), { status: 400 });
    }

    const user = await this._userRepo.findById(userId);
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

    // NOTE: the value-objects/Password module exports the class directly
    // (module.exports = Password), not { Password }. Destructuring it here
    // used to yield `undefined`, so every call below threw and the whole
    // reset silently failed. Require it as a plain default import.
    const Password = require('../domain/value-objects/Password');
    const pwObj = await Password.fromPlaintext(newPlainPassword);
    user.resetPassword(pwObj.hash);
    await this._userRepo.save(user);
    await this._cache.del(`pwd_reset:${token}`);

    await this._publishDomainEvents(user);
    return { success: true };
  }

  async _publishDomainEvents(aggregate) {
    if (!this._bus || !this._bus.isConnected()) return;
    const events = aggregate.getAndClearDomainEvents();
    for (const e of events) {
      try { this._bus.publish(e.type, { ...e.payload, _source: 'auth-service' }); } catch (_) {}
    }
  }
}

module.exports = PasswordApplicationService;
