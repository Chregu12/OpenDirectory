'use strict';

const { validIdentifier } = require('./LicenseAllocator');

class LicenseLifecycleWorker {
  constructor({ allocator, bus, logger, groups, groupAuthorization, users, userAuthorization, intervalMs = 30000 }) {
    this.allocator = allocator;
    this.bus = bus;
    this.logger = logger;
    this.intervalMs = intervalMs;
    this.groups = groups;
    this.groupAuthorization = groupAuthorization;
    this.users = users;
    this.userAuthorization = userAuthorization;
    this.running = false;
    this.timer = null;
    this.stopped=false;
  }

  async handleUserEvent(payload, metadata) {
    if (!validIdentifier(payload?.userId)) {
      this.logger.warn('Invalid license lifecycle event');
      this.reject(metadata, false);
      return;
    }
    try {
      if ((await this.allocator.database.query('SELECT 1 FROM license_subjects WHERE user_id=$1 AND business_tenant_id IS NOT NULL', [payload.userId])).rows.length) {
        this.reject(metadata, false);
        return;
      }
      await this.allocator.offboard(payload.userId, 'system:license-lifecycle', { systemActor: true });
      metadata.ack();
    } catch (error) {
      this.logger.error('License lifecycle transaction failed', { error: error.message });
      this.reject(metadata, error.status !== 400 && error.status !== 403);
    }
  }

  reject(metadata, requeue) {
    try { metadata.nack(requeue); }
    catch (error) { this.logger.warn('License lifecycle channel unavailable', { error: error.message }); }
  }

  async sweep() {
    if (this.running||this.stopped) return;
    this.running = true;
    try {
      await this.allocator.expireAll();
      if (this.users && this.userAuthorization) await this.users.reconcileAll(this.userAuthorization);
      if (this.groups && this.groupAuthorization) await this.groups.reconcileAll(this.groupAuthorization);
    }
    catch (error) { this.logger.error('License lifecycle sweep failed', { error: error.message }); }
    finally { this.running = false; }
  }

  async start() {
    this.timer = setInterval(() => this.sweep(), this.intervalMs);
    this.timer.unref();
    try {
      await this.bus.subscribe('policy.license.user-lifecycle', ['identity.user.deleted', 'user.offboarded', 'user.offboarding.incomplete'],
        (payload, metadata) => this.handleUserEvent(payload, metadata));
    } catch (error) { this.logger.warn('License lifecycle subscription pending', { error: error.message }); }
    this.sweep();
  }

  stop() {
    this.stopped=true;
    this.groupAuthorization?.stop?.();this.userAuthorization?.stop?.();
    clearInterval(this.timer);
    this.timer = null;
  }
}

module.exports = { LicenseLifecycleWorker };
