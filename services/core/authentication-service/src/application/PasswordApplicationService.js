'use strict';
const { randomUUID } = require('crypto');

class PasswordApplicationService {
  constructor({ userRepository, messageBus, cache, logger }) {
    this._userRepo = userRepository;
    this._bus = messageBus;
    this._cache = cache;
    this._log = logger || console;
  }

  async requestReset(email) {
    const user = await this._userRepo.findByEmail(email);
    if (!user) return null; // silent — don't leak user existence

    const token = randomUUID();
    const expiry = Date.now() + 60 * 60 * 1000; // 1h

    if (this._cache) {
      await this._cache.set(`pwd_reset:${token}`, JSON.stringify({ userId: user.id, expiry }), 'EX', 3600);
    }

    return { userId: user.id, token, expiry };
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

    const { Password } = require('../domain/value-objects/Password');
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
