'use strict';
const SagaBase = require('./SagaBase');

/**
 * UserOnboardingSaga — Choreography saga for new user onboarding.
 *
 * Flow:
 *   identity.user.created
 *     → assign default license (if license-service available)
 *     → send welcome notification
 *     → trigger policy evaluation for user's devices
 *
 *   identity.user.deleted
 *     → revoke licenses
 *     → send farewell/audit notification
 */
class UserOnboardingSaga extends SagaBase {
  constructor(messageBus, { logger } = {}) {
    super(messageBus, logger);

    this
      .on('identity.user.created', this._onUserCreated.bind(this))
      .on('identity.user.deleted', this._onUserDeleted.bind(this));
  }

  async launch() {
    await this.start('saga.user-onboarding', [
      'identity.user.created',
      'identity.user.deleted',
    ]);
  }

  async _onUserCreated(payload) {
    const { userId, username, email, roles } = payload;

    // Step 1: Trigger default license assignment
    this.publish('license.assign.requested', {
      userId,
      username,
      licenseType: 'default',
      reason: 'new_user_onboarding',
    });

    // Step 2: Send welcome notification
    this.publish('notification.send', {
      channel: 'email',
      recipient: email || username,
      level: 'info',
      title: 'Willkommen bei OpenDirectory',
      message: `Ihr Konto (${username}) wurde erfolgreich erstellt. Sie können sich jetzt einloggen.`,
      userId,
    });

    this._log.info && this._log.info(`[UserOnboardingSaga] onboarding triggered for user: ${username} (${userId})`);
  }

  async _onUserDeleted(payload) {
    const { userId, username } = payload;

    // Compensating transaction: revoke licenses
    this.publish('license.revoke.requested', {
      userId,
      reason: 'user_deleted',
    });

    // Audit notification
    this.publish('notification.send', {
      channel: 'admin',
      level: 'warning',
      title: 'Benutzer gelöscht',
      message: `Benutzer ${username} (${userId}) wurde aus OpenDirectory entfernt. Lizenzen werden widerrufen.`,
      userId,
    });
  }
}

module.exports = UserOnboardingSaga;
