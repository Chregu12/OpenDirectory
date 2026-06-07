'use strict';

const axios = require('axios');
const logger = require('../utils/logger');

/**
 * RemoteActionService — lock, unlock, wipe, and isolate devices.
 *
 * For each action the service:
 *   1. Verifies the device exists.
 *   2. Updates device status in the DB.
 *   3. Publishes an event on the eventBus.
 *   4. Attempts an MDM HTTP push (if MDM_PUSH_URL is configured).
 *      The MDM push is best-effort: DB update + event succeed even if the push fails.
 *   5. Sends a WebSocket command directly to any connected agent (via wss).
 */
class RemoteActionService {
  constructor(wss, eventBus) {
    this.wss = wss;
    this.eventBus = eventBus;
    this._db = null; // injected after construction via setDb()
    this._config = null;
    this._pendingActions = new Map(); // actionId → { deviceId, type, status, ... }
  }

  /** Called by EnterpriseDeviceManagementService after DB is ready. */
  setDb(db) {
    this._db = db;
  }

  _cfg() {
    if (!this._config) this._config = require('../config');
    return this._config;
  }

  _generateActionId(prefix = 'act') {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }

  /**
   * Attempt an MDM push (best-effort, never throws).
   * @param {string} action  e.g. 'lock', 'unlock', 'wipe'
   * @param {string} deviceId
   * @param {object} payload  Additional data to include in the push body
   */
  async _tryMdmPush(action, deviceId, payload = {}) {
    const cfg = this._cfg();
    if (!cfg.mdm || !cfg.mdm.pushUrl) return { pushed: false, reason: 'MDM_PUSH_URL not configured' };

    try {
      const url = `${cfg.mdm.pushUrl}/${action}`;
      const headers = cfg.mdm.pushToken ? { Authorization: `Bearer ${cfg.mdm.pushToken}` } : {};
      await axios.post(url, { deviceId, ...payload }, { headers, timeout: 10000 });
      logger.info(`MDM push succeeded: ${action} → ${deviceId}`);
      return { pushed: true };
    } catch (err) {
      logger.warn(`MDM push failed (non-fatal): ${action} → ${deviceId}: ${err.message}`);
      return { pushed: false, reason: err.message };
    }
  }

  /** Send a WebSocket command to a connected agent (best-effort). */
  _tryWsPush(deviceId, command) {
    if (!this.wss) return false;
    const WebSocket = require('ws');
    let sent = false;
    this.wss.clients.forEach((ws) => {
      if (ws.deviceId === deviceId && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ ...command, timestamp: new Date().toISOString() }));
        sent = true;
      }
    });
    return sent;
  }

  async _requireDevice(deviceId) {
    if (!this._db) throw new Error('RemoteActionService: db not initialised');
    const device = await this._db.findById('devices', deviceId);
    if (!device) {
      const err = new Error(`Device not found: ${deviceId}`);
      err.statusCode = 404;
      throw err;
    }
    return device;
  }

  async _recordAction(actionId, deviceId, type, status, meta = {}) {
    if (!this._db) return;
    await this._db.insert('remote_actions', {
      id: actionId,
      deviceId,
      type,
      status,
      ...meta,
      timestamp: new Date().toISOString()
    });
    this._pendingActions.set(actionId, { actionId, deviceId, type, status, ...meta, timestamp: new Date().toISOString() });
  }

  // ─── Lock ──────────────────────────────────────────────────────────────────

  /**
   * Lock a device: update DB status, publish event, attempt MDM push.
   * @param {string} deviceId
   * @param {string} [reason]  Human-readable reason for the lock
   * @returns {{ actionId, deviceId, status, mdmPush }}
   */
  async lockDevice(deviceId, reason = '') {
    const device = await this._requireDevice(deviceId);
    const actionId = this._generateActionId('lock');

    // 1. Update device status in DB
    await this._db.update('devices', deviceId, {
      status: 'locked',
      lockedAt: new Date().toISOString(),
      lockReason: reason || null
    });

    // 2. Publish event
    this.eventBus.emit('device.locked', { deviceId, reason, actionId, device });

    // 3. MDM push (best-effort)
    const mdmPush = await this._tryMdmPush('lock', deviceId, { reason });

    // 4. WebSocket push to connected agent
    this._tryWsPush(deviceId, { type: 'command', command_type: 'lock_device', data: { reason } });

    // 5. Record action
    await this._recordAction(actionId, deviceId, 'lock', 'completed', { reason, mdmPush });

    logger.info('Device locked', { deviceId, actionId, reason });
    return { actionId, deviceId, status: 'locked', mdmPush };
  }

  // ─── Unlock ────────────────────────────────────────────────────────────────

  /**
   * Unlock a device.
   * @param {string} deviceId
   * @returns {{ actionId, deviceId, status, mdmPush }}
   */
  async unlockDevice(deviceId) {
    const device = await this._requireDevice(deviceId);
    const actionId = this._generateActionId('unlk');

    // 1. Update device status in DB
    await this._db.update('devices', deviceId, {
      status: 'active',
      unlockedAt: new Date().toISOString(),
      lockReason: null
    });

    // 2. Publish event
    this.eventBus.emit('device.unlocked', { deviceId, actionId, device });

    // 3. MDM push (best-effort)
    const mdmPush = await this._tryMdmPush('unlock', deviceId);

    // 4. WebSocket push to connected agent
    this._tryWsPush(deviceId, { type: 'command', command_type: 'unlock_device', data: {} });

    // 5. Record action
    await this._recordAction(actionId, deviceId, 'unlock', 'completed', { mdmPush });

    logger.info('Device unlocked', { deviceId, actionId });
    return { actionId, deviceId, status: 'active', mdmPush };
  }

  // ─── Wipe ──────────────────────────────────────────────────────────────────

  /**
   * Wipe a device (factory reset).
   * @param {string} deviceId
   * @param {{ type: 'full'|'selective' }} [options]
   * @returns {{ actionId, deviceId, wipeType, status, mdmPush }}
   */
  async wipeDevice(deviceId, options = {}) {
    const device = await this._requireDevice(deviceId);
    const wipeType = options.type || 'full';
    const actionId = this._generateActionId('wipe');

    // 1. Update device status in DB
    await this._db.update('devices', deviceId, {
      status: 'wiped',
      wipedAt: new Date().toISOString(),
      wipeType
    });

    // 2. Publish event
    this.eventBus.emit('device.wiped', { deviceId, wipeType, actionId, device });

    // 3. MDM push (best-effort)
    const mdmPush = await this._tryMdmPush('wipe', deviceId, { wipeType });

    // 4. WebSocket push to connected agent
    this._tryWsPush(deviceId, { type: 'command', command_type: 'wipe_device', data: { wipeType } });

    // 5. Record action
    await this._recordAction(actionId, deviceId, 'wipe', 'completed', { wipeType, mdmPush });

    logger.info('Device wiped', { deviceId, actionId, wipeType });
    return { actionId, deviceId, wipeType, status: 'wiped', mdmPush };
  }

  // ─── Isolate ───────────────────────────────────────────────────────────────

  /**
   * Isolate a device from the network (triggered by critical threat detection).
   * @param {string} deviceId
   * @param {string} [reason]
   */
  async isolateDevice(deviceId, reason = '') {
    let device;
    try {
      device = await this._requireDevice(deviceId);
    } catch (err) {
      if (err.statusCode === 404) {
        logger.warn('isolateDevice: device not found', { deviceId });
        return;
      }
      throw err;
    }

    const actionId = this._generateActionId('isol');

    await this._db.update('devices', deviceId, {
      status: 'isolated',
      isolatedAt: new Date().toISOString(),
      isolationReason: reason
    });

    this.eventBus.emit('device.isolated', { deviceId, reason, actionId, device });
    await this._tryMdmPush('isolate', deviceId, { reason });
    this._tryWsPush(deviceId, { type: 'command', command_type: 'isolate_device', data: { reason } });
    await this._recordAction(actionId, deviceId, 'isolate', 'completed', { reason });

    logger.info('Device isolated', { deviceId, actionId, reason });
  }

  // ─── Generic remote execute ────────────────────────────────────────────────

  async executeAction(deviceId, action, payload = {}) {
    const device = await this._requireDevice(deviceId);
    const actionId = this._generateActionId('cmd');

    this._tryWsPush(deviceId, { type: 'command', command_type: action, data: payload });
    const mdmPush = await this._tryMdmPush(action, deviceId, payload);
    await this._recordAction(actionId, deviceId, action, 'sent', { payload, mdmPush });

    this.eventBus.emit('device.action', { deviceId, action, actionId, payload });
    return { actionId, deviceId, action, status: 'sent', mdmPush };
  }

  // ─── Bulk actions ──────────────────────────────────────────────────────────

  async executeBulkAction(deviceIds, action, payload = {}) {
    const results = await Promise.allSettled(
      deviceIds.map(id => this.executeAction(id, action, payload))
    );
    return results.map((r, i) => ({
      deviceId: deviceIds[i],
      success: r.status === 'fulfilled',
      result: r.value,
      error: r.reason?.message
    }));
  }

  // ─── Status ────────────────────────────────────────────────────────────────

  async getActionStatus(actionId) {
    if (!this._db) return null;
    const actions = await this._db.find('remote_actions', { id: actionId });
    return actions[0] || this._pendingActions.get(actionId) || null;
  }
}

module.exports = RemoteActionService;
