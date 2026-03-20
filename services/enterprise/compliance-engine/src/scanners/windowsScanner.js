'use strict';

/**
 * WindowsScanner – defines Windows-specific compliance check definitions
 * for CIS, BSI and custom baselines. Each check describes what to collect
 * from a Windows endpoint agent.
 */
class WindowsScanner {
  constructor({ logger }) {
    this.logger = logger;

    /**
     * Map of baseline ID → array of check definitions.
     * Each check tells the agent *what* to inspect; the evaluator then
     * compares the returned value against the expected value.
     */
    this.checkCatalog = {
      // ---------------------------------------------------------------
      // Registry checks
      // ---------------------------------------------------------------
      registry: [
        {
          id: 'win-reg-password-history',
          title: 'Enforce password history >= 24',
          category: 'Account Policies',
          severity: 'high',
          check: {
            type: 'registry',
            path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
            key: 'PasswordHistorySize',
            operator: '>=',
            value: 24,
          },
          remediation: { type: 'registry_set', path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', key: 'PasswordHistorySize', value: 24 },
        },
        {
          id: 'win-reg-max-password-age',
          title: 'Maximum password age <= 365 days',
          category: 'Account Policies',
          severity: 'medium',
          check: {
            type: 'registry',
            path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
            key: 'MaximumPasswordAge',
            operator: '<=',
            value: 365,
          },
          remediation: { type: 'registry_set', value: 90 },
        },
        {
          id: 'win-reg-min-password-length',
          title: 'Minimum password length >= 14',
          category: 'Account Policies',
          severity: 'high',
          check: {
            type: 'registry',
            path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
            key: 'MinimumPasswordLength',
            operator: '>=',
            value: 14,
          },
          remediation: { type: 'registry_set', value: 14 },
        },
        {
          id: 'win-reg-lockout-threshold',
          title: 'Account lockout threshold <= 5',
          category: 'Account Policies',
          severity: 'high',
          check: {
            type: 'registry',
            path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
            key: 'LockoutThreshold',
            operator: '<=',
            value: 5,
          },
          remediation: { type: 'registry_set', value: 5 },
        },
        {
          id: 'win-reg-lockout-duration',
          title: 'Account lockout duration >= 15 minutes',
          category: 'Account Policies',
          severity: 'medium',
          check: {
            type: 'registry',
            path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
            key: 'LockoutDuration',
            operator: '>=',
            value: 15,
          },
          remediation: { type: 'registry_set', value: 30 },
        },
      ],

      // ---------------------------------------------------------------
      // Service status checks
      // ---------------------------------------------------------------
      services: [
        {
          id: 'win-svc-windows-defender',
          title: 'Windows Defender Antivirus service running',
          category: 'Antivirus',
          severity: 'critical',
          check: { type: 'service_status', name: 'WinDefend', operator: '==', value: 'running' },
          remediation: { type: 'service_start', name: 'WinDefend' },
        },
        {
          id: 'win-svc-firewall',
          title: 'Windows Firewall service running',
          category: 'Firewall',
          severity: 'critical',
          check: { type: 'service_status', name: 'MpsSvc', operator: '==', value: 'running' },
          remediation: { type: 'service_start', name: 'MpsSvc' },
        },
        {
          id: 'win-svc-wuauserv',
          title: 'Windows Update service running',
          category: 'Patch Management',
          severity: 'high',
          check: { type: 'service_status', name: 'wuauserv', operator: '==', value: 'running' },
          remediation: { type: 'service_start', name: 'wuauserv' },
        },
        {
          id: 'win-svc-remote-registry-disabled',
          title: 'Remote Registry service is disabled',
          category: 'Service Hardening',
          severity: 'medium',
          check: { type: 'service_status', name: 'RemoteRegistry', operator: '==', value: 'disabled' },
          remediation: { type: 'service_disable', name: 'RemoteRegistry' },
        },
      ],

      // ---------------------------------------------------------------
      // Firewall profile checks
      // ---------------------------------------------------------------
      firewall: [
        {
          id: 'win-fw-domain-enabled',
          title: 'Windows Firewall Domain profile enabled',
          category: 'Firewall',
          severity: 'critical',
          check: { type: 'firewall', profile: 'domain', operator: '==', value: true },
          remediation: { type: 'firewall_enable', profile: 'domain' },
        },
        {
          id: 'win-fw-private-enabled',
          title: 'Windows Firewall Private profile enabled',
          category: 'Firewall',
          severity: 'critical',
          check: { type: 'firewall', profile: 'private', operator: '==', value: true },
          remediation: { type: 'firewall_enable', profile: 'private' },
        },
        {
          id: 'win-fw-public-enabled',
          title: 'Windows Firewall Public profile enabled',
          category: 'Firewall',
          severity: 'critical',
          check: { type: 'firewall', profile: 'public', operator: '==', value: true },
          remediation: { type: 'firewall_enable', profile: 'public' },
        },
      ],

      // ---------------------------------------------------------------
      // BitLocker encryption
      // ---------------------------------------------------------------
      encryption: [
        {
          id: 'win-enc-bitlocker-os',
          title: 'BitLocker enabled on OS drive',
          category: 'Encryption',
          severity: 'critical',
          check: { type: 'encryption', target: 'os_drive', operator: '==', value: true },
          remediation: { type: 'enable_bitlocker', drive: 'C:' },
        },
      ],

      // ---------------------------------------------------------------
      // Windows Update compliance
      // ---------------------------------------------------------------
      updates: [
        {
          id: 'win-upd-compliant',
          title: 'All critical Windows updates installed',
          category: 'Patch Management',
          severity: 'critical',
          check: { type: 'software_update', operator: '==', value: true },
          remediation: { type: 'install_updates' },
        },
      ],

      // ---------------------------------------------------------------
      // Antivirus
      // ---------------------------------------------------------------
      antivirus: [
        {
          id: 'win-av-enabled',
          title: 'Antivirus real-time protection enabled',
          category: 'Antivirus',
          severity: 'critical',
          check: { type: 'antivirus', property: 'realtime_enabled', operator: '==', value: true },
          remediation: { type: 'enable_realtime_protection' },
        },
        {
          id: 'win-av-definitions-current',
          title: 'Antivirus definitions updated within 7 days',
          category: 'Antivirus',
          severity: 'high',
          check: { type: 'antivirus', property: 'definitions_age_days', operator: '<=', value: 7 },
          remediation: { type: 'update_definitions' },
        },
      ],

      // ---------------------------------------------------------------
      // UAC settings
      // ---------------------------------------------------------------
      uac: [
        {
          id: 'win-uac-enabled',
          title: 'UAC enabled',
          category: 'User Account Control',
          severity: 'high',
          check: {
            type: 'registry',
            path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
            key: 'EnableLUA',
            operator: '==',
            value: 1,
          },
          remediation: { type: 'registry_set', value: 1 },
        },
        {
          id: 'win-uac-consent-admin',
          title: 'UAC prompt for consent on secure desktop',
          category: 'User Account Control',
          severity: 'medium',
          check: {
            type: 'registry',
            path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
            key: 'ConsentPromptBehaviorAdmin',
            operator: '==',
            value: 2,
          },
          remediation: { type: 'registry_set', value: 2 },
        },
      ],

      // ---------------------------------------------------------------
      // Screen lock timeout
      // ---------------------------------------------------------------
      screenlock: [
        {
          id: 'win-sl-timeout',
          title: 'Screen lock timeout <= 900 seconds (15 min)',
          category: 'Screen Lock',
          severity: 'medium',
          check: { type: 'screen_lock', key: 'timeout', operator: '<=', value: 900 },
          remediation: { type: 'set_screenlock_timeout', value: 600 },
        },
      ],

      // ---------------------------------------------------------------
      // Audit policy
      // ---------------------------------------------------------------
      audit: [
        {
          id: 'win-audit-logon-success',
          title: 'Audit logon events (success)',
          category: 'Audit Policy',
          severity: 'medium',
          check: {
            type: 'audit_policy',
            category: 'Logon/Logoff',
            subcategory: 'Logon',
            operator: 'contains',
            value: 'Success',
          },
          remediation: { type: 'set_audit_policy', category: 'Logon/Logoff', subcategory: 'Logon', value: 'Success and Failure' },
        },
        {
          id: 'win-audit-logon-failure',
          title: 'Audit logon events (failure)',
          category: 'Audit Policy',
          severity: 'medium',
          check: {
            type: 'audit_policy',
            category: 'Logon/Logoff',
            subcategory: 'Logon',
            operator: 'contains',
            value: 'Failure',
          },
          remediation: { type: 'set_audit_policy', category: 'Logon/Logoff', subcategory: 'Logon', value: 'Success and Failure' },
        },
      ],
    };
  }

  /**
   * Get all check definitions applicable to a given baseline.
   * Falls back to returning the full catalog of Windows checks.
   */
  getChecksForBaseline(baselineId) {
    // Flatten all categories into a single array
    const allChecks = [];
    for (const category of Object.values(this.checkCatalog)) {
      allChecks.push(...category);
    }
    return allChecks;
  }

  /**
   * Get checks by category.
   */
  getChecksByCategory(category) {
    return this.checkCatalog[category] || [];
  }

  /**
   * Get all available check categories.
   */
  getCategories() {
    return Object.keys(this.checkCatalog);
  }
}

module.exports = WindowsScanner;
