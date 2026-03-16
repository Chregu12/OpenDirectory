'use strict';

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * Compiles merged RSoP results into macOS-native configuration profile
 * (mobileconfig) style settings.  Output mirrors the structure of Apple
 * Configuration Profiles so that downstream agents can directly install
 * the payload via `profiles` or MDM.
 */
class MacOSPolicyCompiler {
  /**
   * Compile the full RSoP result into a macOS-native payload.
   *
   * @param {object} rsopResult - Output from RSOPEngine.calculateRSOP()
   * @returns {object} macOS-formatted policy payload
   */
  compile(rsopResult) {
    const { settings, sources, appliedPolicies } = rsopResult;

    logger.info('Compiling RSoP for macOS', {
      settingCount: Object.keys(settings).length,
      policyCount: appliedPolicies.length
    });

    return {
      platform: 'macos',
      compiledAt: new Date().toISOString(),
      payloads: this._buildPayloads(settings),
      firewallRules: this.compileFirewall(settings),
      passwordPolicy: this.compilePasswordPolicy(settings),
      encryption: this.compileEncryption(settings),
      softwareUpdate: this.compileSoftwareUpdate(settings),
      gatekeeper: this.compileGatekeeper(settings),
      privacy: this.compilePrivacy(settings),
      sources
    };
  }

  /**
   * Build Apple Configuration Profile payloads.
   */
  _buildPayloads(settings) {
    const payloads = [];

    // Passcode payload
    if (this._hasPrefix(settings, 'password.')) {
      payloads.push({
        PayloadType: 'com.apple.mobiledevice.passwordpolicy',
        PayloadDisplayName: 'Passcode Policy',
        PayloadIdentifier: 'com.opendirectory.passcode',
        PayloadVersion: 1,
        minLength: settings['password.minLength'] || 12,
        requireAlphanumeric: settings['password.complexity'] !== false,
        maxPINAgeInDays: settings['password.maxAge'] || 90,
        pinHistory: settings['password.history'] || 24,
        maxFailedAttempts: settings['lockout.threshold'] || 5,
        minutesUntilFailedLoginReset: settings['lockout.window'] || 30
      });
    }

    // Screen lock / screensaver payload
    if (settings['screenLock.timeout'] !== undefined) {
      payloads.push({
        PayloadType: 'com.apple.screensaver',
        PayloadDisplayName: 'Screensaver Settings',
        PayloadIdentifier: 'com.opendirectory.screensaver',
        PayloadVersion: 1,
        idleTime: (settings['screenLock.timeout'] || 5) * 60,
        askForPassword: true,
        askForPasswordDelay: settings['screenLock.graceSeconds'] || 0
      });
    }

    // Restrictions payload
    const restrictions = {};
    if (settings['restrictions.allowCamera'] !== undefined) {
      restrictions.allowCamera = settings['restrictions.allowCamera'];
    }
    if (settings['restrictions.allowAirDrop'] !== undefined) {
      restrictions.allowAirDrop = settings['restrictions.allowAirDrop'];
    }
    if (settings['restrictions.allowiCloud'] !== undefined) {
      restrictions.allowCloudDocumentSync = settings['restrictions.allowiCloud'];
    }

    if (Object.keys(restrictions).length > 0) {
      payloads.push({
        PayloadType: 'com.apple.applicationaccess',
        PayloadDisplayName: 'Restrictions',
        PayloadIdentifier: 'com.opendirectory.restrictions',
        PayloadVersion: 1,
        ...restrictions
      });
    }

    // Network payload (Wi-Fi)
    if (settings['network.wifi.ssid']) {
      payloads.push({
        PayloadType: 'com.apple.wifi.managed',
        PayloadDisplayName: 'Wi-Fi',
        PayloadIdentifier: 'com.opendirectory.wifi',
        PayloadVersion: 1,
        SSID_STR: settings['network.wifi.ssid'],
        EncryptionType: settings['network.wifi.security'] || 'WPA2',
        AutoJoin: settings['network.wifi.autoJoin'] !== false,
        IsHiddenNetwork: settings['network.wifi.hidden'] || false
      });
    }

    return payloads;
  }

  /**
   * Compile macOS Application Firewall settings.
   */
  compileFirewall(settings) {
    return {
      enabled: settings['firewall.enabled'] !== undefined ? settings['firewall.enabled'] : true,
      stealthMode: settings['firewall.stealthMode'] || false,
      blockAllIncoming: settings['firewall.blockAllIncoming'] || false,
      allowSignedApps: settings['firewall.allowSignedApps'] !== false,
      applications: this._extractFirewallApps(settings)
    };
  }

  /**
   * Compile password policy for macOS.
   */
  compilePasswordPolicy(settings) {
    return {
      minLength: settings['password.minLength'] || 12,
      requireAlphanumeric: settings['password.complexity'] !== false,
      requireSymbol: settings['password.requireSymbol'] || false,
      maxAge: settings['password.maxAge'] || 90,
      history: settings['password.history'] || 24,
      maxFailedAttempts: settings['lockout.threshold'] || 5,
      lockoutDuration: settings['lockout.duration'] || 30
    };
  }

  /**
   * Compile FileVault encryption settings.
   */
  compileEncryption(settings) {
    return {
      fileVault: {
        required: settings['encryption.required'] !== false,
        algorithm: settings['encryption.algorithm'] || 'AES-256',
        personalRecoveryKey: settings['encryption.recoveryKey'] !== false,
        institutionalRecoveryKey: settings['encryption.institutionalKey'] || false,
        deferForceAtUserLogin: settings['encryption.deferAtLogin'] || false,
        deferMaxBypassAttempts: settings['encryption.maxBypassAttempts'] || 3,
        showRecoveryKey: settings['encryption.showRecoveryKey'] !== false,
        escrowLocation: settings['encryption.escrowDescription'] || 'OpenDirectory Server'
      }
    };
  }

  /**
   * Compile macOS Software Update settings.
   */
  compileSoftwareUpdate(settings) {
    return {
      automaticCheckEnabled: settings['updates.autoCheck'] !== false,
      automaticDownload: settings['updates.autoDownload'] !== false,
      autoInstall: settings['updates.autoInstall'] !== false,
      criticalUpdateInstall: settings['updates.criticalAutoInstall'] !== false,
      maxDeferDays: settings['updates.maxDeferDays'] || 7,
      restrictSoftwareUpdateServer: settings['updates.susCatalogURL'] || null
    };
  }

  /**
   * Compile Gatekeeper settings.
   */
  compileGatekeeper(settings) {
    return {
      allowIdentifiedDevelopers: settings['gatekeeper.allowIdentifiedDevelopers'] !== false,
      enableAssessment: settings['gatekeeper.enabled'] !== false
    };
  }

  /**
   * Compile privacy/TCC settings.
   */
  compilePrivacy(settings) {
    const tccEntries = [];

    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('privacy.tcc.')) {
        const parts = key.replace('privacy.tcc.', '').split('.');
        const bundleId = parts[0];
        const service = parts.slice(1).join('.');
        tccEntries.push({
          bundleIdentifier: bundleId,
          service,
          allowed: !!value
        });
      }
    }

    return { tccEntries };
  }

  _hasPrefix(settings, prefix) {
    return Object.keys(settings).some(k => k.startsWith(prefix));
  }

  _extractFirewallApps(settings) {
    const apps = [];
    const appEntries = {};

    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('firewall.apps.')) {
        const parts = key.replace('firewall.apps.', '').split('.');
        const appId = parts[0];
        const prop = parts.slice(1).join('.');
        if (!appEntries[appId]) appEntries[appId] = {};
        appEntries[appId][prop] = value;
      }
    }

    for (const [id, app] of Object.entries(appEntries)) {
      apps.push({
        bundleId: app.bundleId || id,
        allowed: app.allowed !== false
      });
    }

    return apps;
  }
}

module.exports = { MacOSPolicyCompiler };
