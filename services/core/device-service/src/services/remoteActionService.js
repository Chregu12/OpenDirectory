'use strict';

const axios = require('axios');
const logger = require('../utils/logger');

/**
 * RemoteActionService — lock, unlock, wipe, and isolate devices.
 *
 * For each action the service:
 *   1. Loads the DeviceAggregate via IDeviceRepository.
 *   2. Calls the appropriate command method on the aggregate (lock/wipe/isolate/reconnect).
 *   3. Persists the aggregate back via IDeviceRepository.save().
 *   4. Dispatches domain events collected on the aggregate via eventBus.publish().
 *   5. Attempts an MDM HTTP push (best-effort).
 *   6. Sends a WebSocket command directly to any connected agent (via wss).
 *
 * Falls back to the legacy db path for each operation when no deviceRepository
 * has been injected (backwards-compatibility during migration).
 *
 * Non-device tables (e.g. remote_actions log) continue to use this._db.
 */
class RemoteActionService {
  constructor(wss, eventBus) {
    this.wss = wss;
    this.eventBus = eventBus;
    this._db = null;               // injected after construction via setDb()
    this._deviceRepository = null; // injected via setDeviceRepository()
    this._config = null;
    this._pendingActions = new Map(); // actionId → { deviceId, type, status, ... }
  }

  /** Called by EnterpriseDeviceManagementService after DB is ready. */
  setDb(db) {
    this._db = db;
  }

  /** Inject the IDeviceRepository implementation. */
  setDeviceRepository(deviceRepository) {
    this._deviceRepository = deviceRepository;
  }

  _cfg() {
    if (!this._config) this._config = require('../config');
    return this._config;
  }

  _generateActionId(prefix = 'act') {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }

  /**
   * Publish all domain events collected on a DeviceAggregate and clear them.
   * Fire-and-forget: errors are suppressed so they never block the action.
   * @param {import('../domain/aggregates/DeviceAggregate')} device
   */
  _dispatchDomainEvents(device) {
    for (const event of device.getAndClearDomainEvents()) {
      this.eventBus?.publish(event.type, event.payload).catch(() => {});
    }
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

  /**
   * Load a device via the repository (preferred) or legacy db.
   * Throws with statusCode 404 if the device does not exist.
   */
  async _requireDevice(deviceId) {
    if (this._deviceRepository) {
      const device = await this._deviceRepository.findById(deviceId);
      if (!device) {
        const err = new Error(`Device not found: ${deviceId}`);
        err.statusCode = 404;
        throw err;
      }
      return device;
    }

    // Legacy fallback
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
   * Lock a device: update aggregate status, persist, publish events, attempt MDM push.
   * @param {string} deviceId
   * @param {string} [reason]  Human-readable reason for the lock
   * @returns {{ actionId, deviceId, status, mdmPush }}
   */
  async lockDevice(deviceId, reason = '') {
    const actionId = this._generateActionId('lock');

    if (this._deviceRepository) {
      const device = await this._requireDevice(deviceId);

      // 1. Mutate aggregate
      device.lock(reason);

      // 2. Persist
      await this._deviceRepository.save(device);

      // 3. Dispatch domain events
      this._dispatchDomainEvents(device);
    } else {
      // Legacy path
      await this._requireDevice(deviceId);
      await this._db.update('devices', deviceId, {
        status: 'locked',
        lockedAt: new Date().toISOString(),
        lockReason: reason || null
      });
      this.eventBus.emit('device.locked', { deviceId, reason, actionId });
    }

    // 4. MDM push (best-effort)
    const mdmPush = await this._tryMdmPush('lock', deviceId, { reason });

    // 5. WebSocket push to connected agent
    this._tryWsPush(deviceId, { type: 'command', command_type: 'lock_device', data: { reason } });

    // 6. Record action
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
    const actionId = this._generateActionId('unlk');

    if (this._deviceRepository) {
      const device = await this._requireDevice(deviceId);

      // 1. Mutate aggregate
      device.reconnect();

      // 2. Persist
      await this._deviceRepository.save(device);

      // 3. Dispatch domain events
      this._dispatchDomainEvents(device);
    } else {
      // Legacy path
      await this._requireDevice(deviceId);
      await this._db.update('devices', deviceId, {
        status: 'active',
        unlockedAt: new Date().toISOString(),
        lockReason: null
      });
      this.eventBus.emit('device.unlocked', { deviceId, actionId });
    }

    // 4. MDM push (best-effort)
    const mdmPush = await this._tryMdmPush('unlock', deviceId);

    // 5. WebSocket push to connected agent
    this._tryWsPush(deviceId, { type: 'command', command_type: 'unlock_device', data: {} });

    // 6. Record action
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
    const wipeType = options.type || 'full';
    const actionId = this._generateActionId('wipe');

    if (this._deviceRepository) {
      const device = await this._requireDevice(deviceId);

      // 1. Mutate aggregate
      device.wipe(wipeType);

      // 2. Persist
      await this._deviceRepository.save(device);

      // 3. Dispatch domain events
      this._dispatchDomainEvents(device);
    } else {
      // Legacy path
      await this._requireDevice(deviceId);
      await this._db.update('devices', deviceId, {
        status: 'wiped',
        wipedAt: new Date().toISOString(),
        wipeType
      });
      this.eventBus.emit('device.wiped', { deviceId, wipeType, actionId });
    }

    // 4. MDM push (best-effort)
    const mdmPush = await this._tryMdmPush('wipe', deviceId, { wipeType });

    // 5. WebSocket push to connected agent
    this._tryWsPush(deviceId, { type: 'command', command_type: 'wipe_device', data: { wipeType } });

    // 6. Record action
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

    if (this._deviceRepository) {
      // 1. Mutate aggregate
      device.isolate(reason);

      // 2. Persist
      await this._deviceRepository.save(device);

      // 3. Dispatch domain events
      this._dispatchDomainEvents(device);
    } else {
      // Legacy path
      await this._db.update('devices', deviceId, {
        status: 'isolated',
        isolatedAt: new Date().toISOString(),
        isolationReason: reason
      });
      this.eventBus.emit('device.isolated', { deviceId, reason, actionId, device });
    }

    await this._tryMdmPush('isolate', deviceId, { reason });
    this._tryWsPush(deviceId, { type: 'command', command_type: 'isolate_device', data: { reason } });
    await this._recordAction(actionId, deviceId, 'isolate', 'completed', { reason });

    logger.info('Device isolated', { deviceId, actionId, reason });
  }

  // ─── WinRM execution ──────────────────────────────────────────────────────

  /**
   * Execute a command on a Windows device via WS-Management (WinRM).
   *
   * Constructs a minimal WS-Management SOAP envelope and POSTs it to the
   * device's WinRM HTTP listener on port 5985.  Times out after 30 seconds.
   *
   * @param {{ hostname: string }} device
   * @param {string} command  Shell command to execute
   * @returns {{ stdout: string, stderr: string, exitCode: number }}
   */
  async _executeWinRM(device, command) {
    const hostname = device.hostname || (typeof device.toJSON === 'function' ? device.toJSON().hostname : null);
    const endpoint = `http://${hostname}:5985/wsman`;

    const soapEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <wsa:To>${endpoint}</wsa:To>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsa:MessageID>uuid:${this._generateActionId('winrm')}</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsman:OperationTimeout>PT30S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:Command>${command.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</rsp:Command>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>`;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);

      let response;
      try {
        response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/soap+xml; charset=UTF-8' },
          body: soapEnvelope,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      const responseText = await response.text();
      return { stdout: responseText, stderr: '', exitCode: 0 };
    } catch (error) {
      logger.warn(`WinRM execution failed for ${hostname}: ${error.message}`);
      return { stdout: '', stderr: error.message, exitCode: 1 };
    }
  }


  // ─── Generic remote execute ────────────────────────────────────────────────

  async executeAction(deviceId, action, payload = {}) {
    const device = await this._requireDevice(deviceId);
    const actionId = this._generateActionId('cmd');

    // For Windows devices with a known hostname, attempt WinRM first.
    // DeviceAggregate exposes .platform and .hostname as getters.
    const platform = device.platform;
    const hostname = device.hostname;
    let winrmResult = null;
    if (platform === 'windows' && hostname) {
      const command = payload.command || action;
      winrmResult = await this._executeWinRM(device, command);
      if (winrmResult.exitCode === 0) {
        await this._recordAction(actionId, deviceId, action, 'completed', { payload, winrm: winrmResult });
        this.eventBus.emit('device.action', { deviceId, action, actionId, payload });
        return { actionId, deviceId, action, status: 'completed', winrm: winrmResult };
      }
      // WinRM failed — fall through to WebSocket / MDM agent path
      logger.warn(`WinRM failed for device ${deviceId}, falling back to agent path`);
    }

    this._tryWsPush(deviceId, { type: 'command', command_type: action, data: payload });
    const mdmPush = await this._tryMdmPush(action, deviceId, payload);
    await this._recordAction(actionId, deviceId, action, 'sent', { payload, mdmPush, winrm: winrmResult });

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
