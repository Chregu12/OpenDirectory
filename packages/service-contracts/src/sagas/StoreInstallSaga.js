'use strict';
const SagaBase = require('./SagaBase');

/**
 * StoreInstallSaga — Choreography saga for software installation.
 *
 * Flow:
 *   app.install.requested
 *     → (device-service) push store_install command to device via WS/RabbitMQ
 *     → (agent) executes install
 *   app.install.completed
 *     → (app-store) update deployment record
 *     → (notification-service) notify admin
 *   app.install.failed
 *     → (notification-service) alert admin
 *     → (monitoring-service) increment failure counter
 *
 * This saga runs in the app-store service to coordinate post-install actions.
 */
class StoreInstallSaga extends SagaBase {
  constructor(messageBus, { db, logger } = {}) {
    super(messageBus, logger);
    this._db = db;

    this
      .on('app.install.completed', this._onInstallCompleted.bind(this))
      .on('app.install.failed',    this._onInstallFailed.bind(this))
      .on('app.install.requested', this._onInstallRequested.bind(this));
  }

  async launch() {
    await this.start('saga.store-install', [
      'app.install.requested',
      'app.install.completed',
      'app.install.failed',
    ]);
  }

  async _onInstallRequested(payload) {
    const { appId, deviceId, jobId } = payload;
    if (!this._db) return;
    // Mark deployment as 'in_progress'
    try {
      await this._db.query(
        `UPDATE deployments SET status = 'in_progress', started_at = NOW() WHERE app_id = $1 AND device_id = $2 AND status = 'pending'`,
        [appId, deviceId]
      );
    } catch (_) { /* table may not exist yet — non-fatal */ }
    this._log.info && this._log.info(`[StoreInstallSaga] install requested: app=${appId} device=${deviceId} job=${jobId}`);
  }

  async _onInstallCompleted(payload) {
    const { appId, deviceId, jobId, version } = payload;
    if (!this._db) return;
    try {
      await this._db.query(
        `UPDATE deployments SET status = 'installed', installed_version = $3, installed_at = NOW() WHERE app_id = $1 AND device_id = $2`,
        [appId, deviceId, version || null]
      );
    } catch (_) {}

    // Publish follow-up: notify success
    this.publish('notification.send', {
      channel: 'admin',
      level: 'info',
      title: 'Installation erfolgreich',
      message: `App ${appId} wurde erfolgreich auf Gerät ${deviceId} installiert (v${version || 'unbekannt'})`,
      jobId,
    });
  }

  async _onInstallFailed(payload) {
    const { appId, deviceId, jobId, error } = payload;
    if (!this._db) {
      return;
    }
    try {
      await this._db.query(
        `UPDATE deployments SET status = 'failed', error = $3 WHERE app_id = $1 AND device_id = $2 AND status = 'in_progress'`,
        [appId, deviceId, error || 'unknown']
      );
    } catch (_) {}

    // Publish compensating event: alert admin
    this.publish('notification.send', {
      channel: 'admin',
      level: 'error',
      title: 'Installation fehlgeschlagen',
      message: `App ${appId} konnte nicht auf Gerät ${deviceId} installiert werden: ${error || 'Unbekannter Fehler'}`,
      jobId,
    });
  }
}

module.exports = StoreInstallSaga;
