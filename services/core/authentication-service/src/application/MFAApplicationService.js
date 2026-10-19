'use strict';
const { randomUUID } = require('crypto');
const { AuthEvents } = require('../domain/events/AuthEvents');

class MFAApplicationService {
  constructor({ userRepository, messageBus, logger }) {
    this._userRepo = userRepository;
    this._bus = messageBus;
    this._log = logger || console;
  }

  async enableMFA(userId, secret, recoveryCodes = []) {
    const user = await this._userRepo.findById(userId);
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

    user.enableMFA(secret, recoveryCodes);
    await this._userRepo.save(user);
    await this._publishDomainEvents(user);

    return { mfaEnabled: true, recoveryCodes };
  }

  async disableMFA(userId) {
    const user = await this._userRepo.findById(userId);
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

    user.disableMFA();
    await this._userRepo.save(user);
    await this._publishDomainEvents(user);

    return { mfaEnabled: false };
  }

  async verifyMFA(userId, code, totpLib) {
    const user = await this._userRepo.findById(userId);
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });
    if (!user.mfaEnabled) throw Object.assign(new Error('MFA not enabled'), { status: 400 });

    const valid = totpLib ? totpLib.verify({ token: code, secret: user.mfaSecret }) : false;
    if (!valid) throw Object.assign(new Error('Invalid MFA code'), { status: 401 });

    if (this._bus && this._bus.isConnected()) {
      try {
        this._bus.publish(AuthEvents.MFA_VERIFIED, { userId, _source: 'auth-service' });
      } catch (_) {}
    }

    return { verified: true };
  }

  async _publishDomainEvents(aggregate) {
    if (!this._bus || !this._bus.isConnected()) return;
    const events = aggregate.getAndClearDomainEvents();
    for (const e of events) {
      try { this._bus.publish(e.type, { ...e.payload, _source: 'auth-service' }); } catch (_) {}
    }
  }
}

module.exports = MFAApplicationService;
