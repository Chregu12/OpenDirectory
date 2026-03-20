'use strict';
const { EventEmitter } = require('events');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * UpdateAgentService — Generic server-side update management via WebSocket push
 *
 * Architecture:
 *   Server (this) → device-service.sendToDevice() → WebSocket → Agent (platform-specific)
 *
 * The server sends platform-agnostic update intents. Agents translate them to:
 *   Windows → PSWindowsUpdate / winget / Registry / Scheduled Tasks
 *   macOS   → softwareupdate / mas (Mac App Store CLI)
 *   Linux   → apt / dnf / snap / flatpak / unattended-upgrades
 *
 * This service NEVER generates platform-specific scripts — that's the agent's job.
 */
class UpdateAgentService extends EventEmitter {
  constructor(deviceService) {
    super();
    this.deviceService = deviceService;
    this.deviceUpdateState = new Map();   // deviceId → { lastCheck, pending, installed }
    this.updatePolicies = new Map();      // deviceId → { policy settings }
    this.complianceState = new Map();     // deviceId → { compliant, outdatedApps[] }
  }

  // ─── Generic command dispatch ──────────────────────────────────────────

  sendUpdateCommand(deviceId, commandType, data) {
    const commandId = `upd-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const message = {
      type: 'command',
      id: commandId,
      command_type: commandType,
      data,
      category: 'update'
    };

    const sent = this.deviceService.sendToDevice(deviceId, message);
    if (!sent) {
      this.deviceService.cacheForOfflineDevice?.(deviceId, message);
    }

    logger.info(`Update command ${commandType} → device ${deviceId} (sent=${sent})`);
    this.emit('commandSent', { deviceId, commandType, commandId, sent });
    return { commandId, sent };
  }

  // ─── OS Update Policy ─────────────────────────────────────────────────

  /**
   * Configure OS update policy on a device.
   * Platform-agnostic schema:
   * {
   *   automatic: true,
   *   schedule: { interval: 'Daily', time: '03:00', rebootAllowed: false },
   *   maintenanceWindow: { start: '02:00', end: '06:00', daysOfWeek: ['Saturday'] },
   *   deferrals: {
   *     featureUpdates: 30,   // days to defer (Windows-specific, ignored by others)
   *     qualityUpdates: 7,
   *     securityUpdates: 0    // never defer security
   *   },
   *   rebootPolicy: 'scheduled' | 'immediate' | 'user-choice',
   *   notifyUser: true
   * }
   */
  configureUpdates(deviceId, policy) {
    const data = {
      policyId: policy.id || `upd-${deviceId}`,
      settings: {
        automatic: policy.automatic !== false,
        schedule: policy.schedule || { interval: 'Daily', time: '03:00' },
        maintenanceWindow: policy.maintenanceWindow || null,
        deferrals: policy.deferrals || {},
        rebootPolicy: policy.rebootPolicy || 'user-choice',
        notifyUser: policy.notifyUser !== false
      }
    };

    const result = this.sendUpdateCommand(deviceId, 'configure_updates', data);
    this.updatePolicies.set(deviceId, data.settings);
    this.emit('updatePolicyConfigured', { deviceId, ...data, commandId: result.commandId });
    return result;
  }

  /**
   * Configure OS updates on multiple devices.
   */
  configureUpdatesForDevices(deviceIds, policy) {
    return deviceIds.map(deviceId => ({
      deviceId,
      ...this.configureUpdates(deviceId, policy)
    }));
  }

  /**
   * Request update status check from agent.
   * Agent reports: available updates, last check time, pending reboots.
   */
  checkUpdateStatus(deviceId) {
    return this.sendUpdateCommand(deviceId, 'check_update_status', {});
  }

  /**
   * Trigger immediate update installation on device.
   */
  triggerUpdate(deviceId, options = {}) {
    return this.sendUpdateCommand(deviceId, 'trigger_update', {
      categories: options.categories || ['security', 'critical'],
      rebootIfNeeded: options.rebootIfNeeded || false,
      maxUpdates: options.maxUpdates || 0,  // 0 = all
      notifyUser: options.notifyUser !== false
    });
  }

  /**
   * Get update compliance report from agent.
   */
  getUpdateCompliance(deviceId) {
    return this.sendUpdateCommand(deviceId, 'get_update_compliance', {});
  }

  // ─── Winget / App Package Updates (Windows-specific intent) ────────────

  /**
   * Configure Winget Auto-Update on a Windows device.
   * Non-Windows agents will ignore this command gracefully.
   *
   * Schema:
   * {
   *   enabled: true,
   *   updateMode: 'whitelist' | 'blacklist',
   *   whitelist: ['Microsoft.VisualStudioCode', 'Google.Chrome'],
   *   blacklist: ['Mozilla.Firefox'],
   *   schedule: { interval: 'Daily', time: '06:00', timeDelay: 30 },
   *   notifications: 'Full' | 'SuccessOnly' | 'ErrorsOnly' | 'None',
   *   userContext: false,
   *   acceptAllSourceAgreements: true
   * }
   */
  configureWingetAutoUpdate(deviceId, policy) {
    const data = {
      policyId: policy.id || `wau-${deviceId}`,
      settings: {
        enabled: policy.enabled !== false,
        updateMode: policy.updateMode || 'blacklist',
        whitelist: policy.whitelist || [],
        blacklist: policy.blacklist || [],
        schedule: policy.schedule || { interval: 'Daily', time: '06:00' },
        notifications: policy.notifications || 'Full',
        userContext: policy.userContext || false,
        acceptAllSourceAgreements: policy.acceptAllSourceAgreements !== false
      }
    };

    const result = this.sendUpdateCommand(deviceId, 'configure_winget', data);
    this.emit('wingetConfigured', { deviceId, ...data, commandId: result.commandId });
    return result;
  }

  /**
   * Check winget update status (available app updates).
   */
  checkWingetStatus(deviceId) {
    return this.sendUpdateCommand(deviceId, 'check_winget_status', {});
  }

  // ─── Handle results from agents ───────────────────────────────────────

  handleCommandResult(deviceId, result) {
    logger.info(`Update result from ${deviceId}: ${result.commandId} → ${result.status}`);

    if (result.updateStatus) {
      this.deviceUpdateState.set(deviceId, {
        ...result.updateStatus,
        lastReport: new Date().toISOString()
      });
    }

    if (result.complianceReport) {
      this.complianceState.set(deviceId, {
        compliant: result.complianceReport.compliant,
        outdatedApps: result.complianceReport.outdatedApps || [],
        lastCheck: new Date().toISOString()
      });

      if (!result.complianceReport.compliant) {
        this.emit('updateComplianceViolation', {
          deviceId,
          outdatedApps: result.complianceReport.outdatedApps
        });
      }
    }

    this.emit('commandResult', { deviceId, ...result });
  }

  // ─── Status queries ───────────────────────────────────────────────────

  getDeviceUpdateStatus(deviceId) {
    return {
      deviceId,
      updateState: this.deviceUpdateState.get(deviceId) || null,
      policy: this.updatePolicies.get(deviceId) || null,
      compliance: this.complianceState.get(deviceId) || null
    };
  }
}

module.exports = UpdateAgentService;
