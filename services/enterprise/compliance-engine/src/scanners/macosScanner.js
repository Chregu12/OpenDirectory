'use strict';

/**
 * MacosScanner – defines macOS-specific compliance check definitions for
 * CIS, BSI and custom baselines.
 */
class MacosScanner {
  constructor({ logger }) {
    this.logger = logger;

    this.checkCatalog = {
      // ---------------------------------------------------------------
      // FileVault (disk encryption)
      // ---------------------------------------------------------------
      encryption: [
        {
          id: 'mac-enc-filevault',
          title: 'FileVault disk encryption enabled',
          category: 'Encryption',
          severity: 'critical',
          check: { type: 'filevault', operator: '==', value: true },
          remediation: { type: 'command', command: 'sudo fdesetup enable' },
        },
      ],

      // ---------------------------------------------------------------
      // Gatekeeper
      // ---------------------------------------------------------------
      gatekeeper: [
        {
          id: 'mac-sec-gatekeeper',
          title: 'Gatekeeper enabled',
          category: 'Application Security',
          severity: 'critical',
          check: { type: 'gatekeeper', operator: '==', value: true },
          remediation: { type: 'command', command: 'sudo spctl --master-enable' },
        },
      ],

      // ---------------------------------------------------------------
      // System Integrity Protection
      // ---------------------------------------------------------------
      sip: [
        {
          id: 'mac-sec-sip',
          title: 'System Integrity Protection (SIP) enabled',
          category: 'System Integrity',
          severity: 'critical',
          check: { type: 'sip', operator: '==', value: true },
          remediation: { type: 'manual', instructions: 'Reboot to Recovery Mode and run csrutil enable' },
        },
      ],

      // ---------------------------------------------------------------
      // Firewall
      // ---------------------------------------------------------------
      firewall: [
        {
          id: 'mac-fw-enabled',
          title: 'Application Firewall enabled',
          category: 'Firewall',
          severity: 'critical',
          check: { type: 'defaults', domain: '/Library/Preferences/com.apple.alf', key: 'globalstate', operator: '>=', value: 1 },
          remediation: { type: 'command', command: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on' },
        },
        {
          id: 'mac-fw-stealth',
          title: 'Firewall stealth mode enabled',
          category: 'Firewall',
          severity: 'high',
          check: { type: 'defaults', domain: '/Library/Preferences/com.apple.alf', key: 'stealthenabled', operator: '==', value: 1 },
          remediation: { type: 'command', command: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on' },
        },
      ],

      // ---------------------------------------------------------------
      // Screen lock / screensaver
      // ---------------------------------------------------------------
      screenlock: [
        {
          id: 'mac-sl-idle-time',
          title: 'Screen saver idle time <= 600 seconds (10 min)',
          category: 'Screen Lock',
          severity: 'medium',
          check: { type: 'defaults', domain: 'com.apple.screensaver', key: 'idleTime', operator: '<=', value: 600 },
          remediation: { type: 'defaults_write', domain: 'com.apple.screensaver', key: 'idleTime', value: 600 },
        },
        {
          id: 'mac-sl-ask-password',
          title: 'Require password after screen saver begins',
          category: 'Screen Lock',
          severity: 'high',
          check: { type: 'defaults', domain: 'com.apple.screensaver', key: 'askForPassword', operator: '==', value: 1 },
          remediation: { type: 'defaults_write', domain: 'com.apple.screensaver', key: 'askForPassword', value: 1 },
        },
        {
          id: 'mac-sl-password-delay',
          title: 'Password grace period <= 5 seconds',
          category: 'Screen Lock',
          severity: 'medium',
          check: { type: 'defaults', domain: 'com.apple.screensaver', key: 'askForPasswordDelay', operator: '<=', value: 5 },
          remediation: { type: 'defaults_write', domain: 'com.apple.screensaver', key: 'askForPasswordDelay', value: 0 },
        },
      ],

      // ---------------------------------------------------------------
      // Remote access
      // ---------------------------------------------------------------
      remote: [
        {
          id: 'mac-remote-login-disabled',
          title: 'Remote Login (SSH) disabled',
          category: 'Remote Access',
          severity: 'high',
          check: { type: 'command', command: 'systemsetup -getremotelogin', operator: '==', value: 'Off' },
          remediation: { type: 'command', command: 'sudo systemsetup -setremotelogin off' },
        },
        {
          id: 'mac-remote-management-disabled',
          title: 'Remote Management (ARD) disabled',
          category: 'Remote Access',
          severity: 'medium',
          check: { type: 'service_status', name: 'com.apple.RemoteDesktop.agent', operator: '==', value: 'disabled' },
          remediation: { type: 'command', command: 'sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop' },
        },
      ],

      // ---------------------------------------------------------------
      // Sharing
      // ---------------------------------------------------------------
      sharing: [
        {
          id: 'mac-share-file-disabled',
          title: 'File Sharing disabled',
          category: 'Sharing',
          severity: 'medium',
          check: { type: 'service_status', name: 'com.apple.smbd', operator: '==', value: 'disabled' },
          remediation: { type: 'command', command: 'sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist' },
        },
        {
          id: 'mac-share-bluetooth-disabled',
          title: 'Bluetooth Sharing disabled',
          category: 'Sharing',
          severity: 'low',
          check: { type: 'defaults', domain: 'com.apple.Bluetooth', key: 'PrefKeyServicesEnabled', operator: '==', value: 0 },
          remediation: { type: 'defaults_write', domain: 'com.apple.Bluetooth', key: 'PrefKeyServicesEnabled', value: 0 },
        },
      ],

      // ---------------------------------------------------------------
      // Software update
      // ---------------------------------------------------------------
      updates: [
        {
          id: 'mac-upd-auto-check',
          title: 'Automatic software update check enabled',
          category: 'Patch Management',
          severity: 'high',
          check: { type: 'defaults', domain: '/Library/Preferences/com.apple.SoftwareUpdate', key: 'AutomaticCheckEnabled', operator: '==', value: 1 },
          remediation: { type: 'defaults_write', domain: '/Library/Preferences/com.apple.SoftwareUpdate', key: 'AutomaticCheckEnabled', value: 1 },
        },
        {
          id: 'mac-upd-auto-download',
          title: 'Automatic download of updates enabled',
          category: 'Patch Management',
          severity: 'medium',
          check: { type: 'defaults', domain: '/Library/Preferences/com.apple.SoftwareUpdate', key: 'AutomaticDownload', operator: '==', value: 1 },
          remediation: { type: 'defaults_write', domain: '/Library/Preferences/com.apple.SoftwareUpdate', key: 'AutomaticDownload', value: 1 },
        },
        {
          id: 'mac-upd-critical-install',
          title: 'Automatic installation of critical updates enabled',
          category: 'Patch Management',
          severity: 'high',
          check: { type: 'defaults', domain: '/Library/Preferences/com.apple.SoftwareUpdate', key: 'CriticalUpdateInstall', operator: '==', value: 1 },
          remediation: { type: 'defaults_write', domain: '/Library/Preferences/com.apple.SoftwareUpdate', key: 'CriticalUpdateInstall', value: 1 },
        },
      ],

      // ---------------------------------------------------------------
      // Miscellaneous security
      // ---------------------------------------------------------------
      security: [
        {
          id: 'mac-sec-airdrop-contacts',
          title: 'AirDrop restricted to contacts only',
          category: 'Security',
          severity: 'low',
          check: { type: 'defaults', domain: 'com.apple.sharingd', key: 'DiscoverableMode', operator: '==', value: 'Contacts Only' },
          remediation: { type: 'defaults_write', domain: 'com.apple.sharingd', key: 'DiscoverableMode', value: 'Contacts Only' },
        },
        {
          id: 'mac-sec-safari-auto-open',
          title: 'Safari auto-open safe downloads disabled',
          category: 'Browser Security',
          severity: 'low',
          check: { type: 'defaults', domain: 'com.apple.Safari', key: 'AutoOpenSafeDownloads', operator: '==', value: 0 },
          remediation: { type: 'defaults_write', domain: 'com.apple.Safari', key: 'AutoOpenSafeDownloads', value: 0 },
        },
      ],
    };
  }

  /**
   * Get all check definitions applicable to a given baseline.
   */
  getChecksForBaseline(baselineId) {
    const allChecks = [];
    for (const category of Object.values(this.checkCatalog)) {
      allChecks.push(...category);
    }
    return allChecks;
  }

  getChecksByCategory(category) {
    return this.checkCatalog[category] || [];
  }

  getCategories() {
    return Object.keys(this.checkCatalog);
  }
}

module.exports = MacosScanner;
