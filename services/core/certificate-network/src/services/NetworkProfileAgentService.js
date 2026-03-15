'use strict';
const { EventEmitter } = require('events');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * NetworkProfileAgentService — Generic server-side network profile dispatch via WebSocket push
 *
 * Architecture:
 *   Server (this) → device-service.sendToDevice() → WebSocket → Agent (platform-specific)
 *
 * The server sends platform-agnostic network profile intents. Agents translate them to:
 *   Windows → netsh wlan / rasphone / PowerShell / XML profiles
 *   macOS   → profiles install / .mobileconfig
 *   Linux   → NetworkManager nmcli / keyfiles
 *
 * Supported profile types: WiFi, VPN, Email
 * This service NEVER generates platform-specific profiles — that's the agent's job.
 */
class NetworkProfileAgentService extends EventEmitter {
  constructor(deviceService) {
    super();
    this.deviceService = deviceService;
    this.profileState = new Map();      // deviceId → { wifi: [...], vpn: [...], email: [...] }
    this.deploymentState = new Map();   // commandId → { deviceId, type, status }
  }

  // ─── Generic command dispatch ──────────────────────────────────────────

  sendProfileCommand(deviceId, commandType, data) {
    const commandId = `net-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const message = {
      type: 'command',
      id: commandId,
      command_type: commandType,
      data,
      category: 'network-profile'
    };

    const sent = this.deviceService.sendToDevice(deviceId, message);
    if (!sent) {
      this.deviceService.cacheForOfflineDevice?.(deviceId, message);
    }

    logger.info(`Network profile command ${commandType} → device ${deviceId} (sent=${sent})`);
    this.deploymentState.set(commandId, { deviceId, type: commandType, status: sent ? 'sent' : 'queued' });
    this.emit('commandSent', { deviceId, commandType, commandId, sent });
    return { commandId, sent };
  }

  // ─── WiFi Profile Management ──────────────────────────────────────────

  /**
   * Deploy WiFi profile to device.
   * Platform-agnostic schema:
   * {
   *   profileId: 'wifi-abc123',
   *   ssid: 'Corp-WiFi',
   *   security: 'WPA2-Enterprise',
   *   hidden: false,
   *   autoConnect: true,
   *   authentication: {
   *     method: 'EAP-TLS',
   *     innerMethod: 'MSCHAPv2',
   *     identity: 'user@corp.local',
   *     anonymousIdentity: 'anonymous@corp.local'
   *   },
   *   certificates: {
   *     ca: { data: '...', format: 'PEM' },
   *     client: { data: '...', format: 'PKCS12', password: '...' }
   *   },
   *   proxy: { type: 'none' | 'manual' | 'auto', ... }
   * }
   */
  configureWiFi(deviceId, profile) {
    const data = {
      profileId: profile.id || profile.profileId || `wifi-${deviceId}-${Date.now()}`,
      action: 'install',
      profile: {
        ssid: profile.ssid,
        security: profile.security || 'WPA2-Enterprise',
        hidden: profile.hidden || false,
        autoConnect: profile.autoConnect !== false,
        authentication: profile.authentication || {},
        certificates: profile.certificates || null,
        proxy: profile.proxy || { type: 'none' }
      }
    };

    return this.sendProfileCommand(deviceId, 'configure_wifi', data);
  }

  /**
   * Remove WiFi profile from device.
   */
  removeWiFi(deviceId, profileId, ssid) {
    return this.sendProfileCommand(deviceId, 'remove_wifi', {
      profileId,
      ssid
    });
  }

  /**
   * Deploy WiFi profile to multiple devices.
   */
  configureWiFiForDevices(deviceIds, profile) {
    return deviceIds.map(deviceId => ({
      deviceId,
      ...this.configureWiFi(deviceId, profile)
    }));
  }

  // ─── VPN Profile Management ───────────────────────────────────────────

  /**
   * Deploy VPN profile to device.
   * Platform-agnostic schema:
   * {
   *   profileId: 'vpn-abc123',
   *   name: 'Corp VPN',
   *   vpnType: 'openvpn' | 'wireguard' | 'ikev2' | 'l2tp',
   *   server: 'vpn.corp.local',
   *   port: 1194,
   *   protocol: 'udp' | 'tcp',
   *   authentication: {
   *     method: 'certificate' | 'credentials' | 'eap',
   *     identity: 'user@corp.local',
   *     certificates: { ca: '...', client: '...', key: '...' }
   *   },
   *   routing: {
   *     splitTunnel: true,
   *     includedRoutes: ['10.0.0.0/8'],
   *     excludedRoutes: [],
   *     dns: ['10.0.0.1']
   *   },
   *   autoConnect: false,
   *   killSwitch: false
   * }
   */
  configureVPN(deviceId, profile) {
    const data = {
      profileId: profile.id || profile.profileId || `vpn-${deviceId}-${Date.now()}`,
      action: 'install',
      profile: {
        name: profile.name,
        vpnType: profile.vpnType || profile.type || 'openvpn',
        server: profile.server,
        port: profile.port,
        protocol: profile.protocol || 'udp',
        authentication: profile.authentication || {},
        routing: profile.routing || {},
        autoConnect: profile.autoConnect || false,
        killSwitch: profile.killSwitch || false,
        extraConfig: profile.extraConfig || null
      }
    };

    return this.sendProfileCommand(deviceId, 'configure_vpn', data);
  }

  /**
   * Remove VPN profile from device.
   */
  removeVPN(deviceId, profileId) {
    return this.sendProfileCommand(deviceId, 'remove_vpn', { profileId });
  }

  /**
   * Deploy VPN profile to multiple devices.
   */
  configureVPNForDevices(deviceIds, profile) {
    return deviceIds.map(deviceId => ({
      deviceId,
      ...this.configureVPN(deviceId, profile)
    }));
  }

  // ─── Email Profile Management ──────────────────────────────────────────

  /**
   * Deploy Email profile to device.
   * Platform-agnostic schema:
   * {
   *   profileId: 'email-abc123',
   *   accountName: 'Corporate Email',
   *   accountType: 'exchange' | 'imap' | 'pop3',
   *   emailAddress: 'user@corp.local',
   *   displayName: 'John Doe',
   *   server: {
   *     incoming: { host: 'mail.corp.local', port: 993, ssl: true },
   *     outgoing: { host: 'smtp.corp.local', port: 587, ssl: true }
   *   },
   *   authentication: {
   *     method: 'password' | 'certificate' | 'oauth2',
   *     username: 'user@corp.local',
   *     oauthSettings: { ... }
   *   },
   *   smime: {
   *     signing: { certificate: '...', enabled: true },
   *     encryption: { certificate: '...', enabled: true }
   *   },
   *   syncSettings: {
   *     mailDays: 30,
   *     syncCalendar: true,
   *     syncContacts: true,
   *     syncTasks: true
   *   }
   * }
   */
  configureEmail(deviceId, profile) {
    const data = {
      profileId: profile.id || profile.profileId || `email-${deviceId}-${Date.now()}`,
      action: 'install',
      profile: {
        accountName: profile.accountName || profile.name,
        accountType: profile.accountType || profile.type || 'exchange',
        emailAddress: profile.emailAddress,
        displayName: profile.displayName,
        server: profile.server || {},
        authentication: profile.authentication || {},
        smime: profile.smime || null,
        syncSettings: profile.syncSettings || {
          mailDays: 30,
          syncCalendar: true,
          syncContacts: true
        }
      }
    };

    return this.sendProfileCommand(deviceId, 'configure_email', data);
  }

  /**
   * Remove Email profile from device.
   */
  removeEmail(deviceId, profileId) {
    return this.sendProfileCommand(deviceId, 'remove_email', { profileId });
  }

  /**
   * Deploy Email profile to multiple devices.
   */
  configureEmailForDevices(deviceIds, profile) {
    return deviceIds.map(deviceId => ({
      deviceId,
      ...this.configureEmail(deviceId, profile)
    }));
  }

  // ─── Handle results from agents ───────────────────────────────────────

  handleCommandResult(deviceId, result) {
    logger.info(`Network profile result from ${deviceId}: ${result.commandId} → ${result.status}`);

    const deployment = this.deploymentState.get(result.commandId);
    if (deployment) {
      deployment.status = result.status;
      deployment.completedAt = new Date().toISOString();
    }

    // Update per-device profile state
    if (result.profileState) {
      const current = this.profileState.get(deviceId) || { wifi: [], vpn: [], email: [] };
      if (result.profileState.wifi) current.wifi = result.profileState.wifi;
      if (result.profileState.vpn) current.vpn = result.profileState.vpn;
      if (result.profileState.email) current.email = result.profileState.email;
      this.profileState.set(deviceId, current);
    }

    this.emit('commandResult', { deviceId, ...result });
  }

  // ─── Status queries ───────────────────────────────────────────────────

  getDeviceProfileState(deviceId) {
    return {
      deviceId,
      profiles: this.profileState.get(deviceId) || { wifi: [], vpn: [], email: [] }
    };
  }

  getDeploymentStatus(commandId) {
    return this.deploymentState.get(commandId) || null;
  }
}

module.exports = NetworkProfileAgentService;
