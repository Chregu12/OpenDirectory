'use strict';

const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

/**
 * Device Security Analyzer - Evaluates device security posture from Intune/SCCM data.
 * Checks BitLocker encryption, EDR status, OS version currency, patch compliance,
 * firewall configuration, Secure Boot, TPM, Credential Guard, and more.
 *
 * Public API:
 *   analyzeDevice(device)       - Analyze a single device
 *   analyzeFleet(devices)       - Analyze an array of devices
 *   getDeviceRiskScore(device)  - Return a numeric risk score for a device
 */
class DeviceSecurityAnalyzer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logger = options.logger || console;

    // Supported OS versions and their end-of-life dates
    this.osLifecycle = {
      'Windows 10 21H2': { eol: new Date('2024-06-11'), extended: new Date('2027-01-12') },
      'Windows 10 22H2': { eol: new Date('2025-10-14'), extended: new Date('2028-10-14') },
      'Windows 11 22H2': { eol: new Date('2025-10-14'), extended: null },
      'Windows 11 23H2': { eol: new Date('2026-11-10'), extended: null },
      'Windows 11 24H2': { eol: new Date('2027-10-12'), extended: null },
      'Windows Server 2016': { eol: new Date('2022-01-11'), extended: new Date('2027-01-12') },
      'Windows Server 2019': { eol: new Date('2024-01-09'), extended: new Date('2029-01-09') },
      'Windows Server 2022': { eol: new Date('2026-10-13'), extended: new Date('2031-10-14') },
      'Windows Server 2025': { eol: new Date('2029-10-09'), extended: new Date('2034-10-10') },
    };

    // Critical patch categories
    this.criticalPatchCategories = [
      'Security Updates',
      'Critical Updates',
      'Definition Updates',
    ];

    // Compliance baselines per benchmark
    this.complianceBaselines = {
      CIS: {
        bitlocker: { required: true, algorithm: 'XTS-AES-256', protector: 'TPMAndPIN' },
        edr: { required: true, realTimeProtection: true, tamperProtection: true, cloudProtection: true },
        firewall: { domainEnabled: true, privateEnabled: true, publicEnabled: true, defaultInbound: 'Block' },
        os: { maxDaysPastEOL: 0 },
        patches: { maxMissingCritical: 0, maxDaysSinceLastScan: 7 },
        secureBoot: { required: true },
        tpm: { required: true, minVersion: '2.0' },
        credentialGuard: { required: true },
        screenLock: { maxInactivityMinutes: 15, requirePassword: true },
        uac: { enabled: true, consentPrompt: true },
      },
      NIST: {
        bitlocker: { required: true, algorithm: 'AES-256', protector: 'TPM' },
        edr: { required: true, realTimeProtection: true, tamperProtection: false, cloudProtection: false },
        firewall: { domainEnabled: true, privateEnabled: true, publicEnabled: true, defaultInbound: 'Block' },
        os: { maxDaysPastEOL: 0 },
        patches: { maxMissingCritical: 0, maxDaysSinceLastScan: 14 },
        secureBoot: { required: true },
        tpm: { required: true, minVersion: '2.0' },
        credentialGuard: { required: false },
        screenLock: { maxInactivityMinutes: 30, requirePassword: true },
        uac: { enabled: true, consentPrompt: false },
      },
      STIG: {
        bitlocker: { required: true, algorithm: 'XTS-AES-256', protector: 'TPMAndPIN' },
        edr: { required: true, realTimeProtection: true, tamperProtection: true, cloudProtection: true },
        firewall: { domainEnabled: true, privateEnabled: true, publicEnabled: true, defaultInbound: 'Block' },
        os: { maxDaysPastEOL: 0 },
        patches: { maxMissingCritical: 0, maxDaysSinceLastScan: 3 },
        secureBoot: { required: true },
        tpm: { required: true, minVersion: '2.0' },
        credentialGuard: { required: true },
        screenLock: { maxInactivityMinutes: 15, requirePassword: true },
        uac: { enabled: true, consentPrompt: true },
      },
    };
  }

  // ================================================================== //
  //  Public API
  // ================================================================== //

  /**
   * Analyze a single device's security posture.
   * @param {Object} device - Device data object
   * @param {string[]} [benchmarkIds=['CIS']] - Benchmark IDs to check against
   * @returns {Object} Analysis result with findings and summary
   */
  async analyzeDevice(device, benchmarkIds = ['CIS']) {
    const deviceName = device.name || device.hostname || device.deviceId || 'unknown';
    this.logger.info && this.logger.info(`Analyzing device: ${deviceName}`);

    const findings = [];

    const checks = [
      { name: 'bitlocker', method: '_checkBitLocker' },
      { name: 'edr', method: '_checkEDR' },
      { name: 'osVersion', method: '_checkOSVersion' },
      { name: 'patchCompliance', method: '_checkPatchCompliance' },
      { name: 'firewall', method: '_checkFirewall' },
      { name: 'secureBoot', method: '_checkSecureBoot' },
      { name: 'tpm', method: '_checkTPM' },
      { name: 'credentialGuard', method: '_checkCredentialGuard' },
      { name: 'screenLock', method: '_checkScreenLock' },
      { name: 'localAccounts', method: '_checkLocalAccounts' },
      { name: 'autoUpdates', method: '_checkAutoUpdates' },
      { name: 'uac', method: '_checkUAC' },
    ];

    for (const check of checks) {
      try {
        const checkFindings = this[check.method](device, benchmarkIds);
        findings.push(...checkFindings);
      } catch (err) {
        this.logger.error && this.logger.error(`Error in ${check.name} check for ${deviceName}: ${err.message}`);
        findings.push(this._createFinding({
          title: `Check Error: ${check.name}`,
          description: `Failed to run ${check.name} check on ${deviceName}: ${err.message}`,
          severity: 'Low',
          category: 'device-security',
          subcategory: check.name,
          affectedObjects: [{ type: 'device', name: deviceName }],
        }));
      }
    }

    this.emit('deviceAnalyzed', { device: deviceName, findingCount: findings.length });

    const riskScore = this._computeRiskScore(findings);

    return {
      deviceId: device.deviceId || device.id || uuidv4(),
      deviceName,
      platform: device.platform || device.osName || 'Windows',
      timestamp: new Date().toISOString(),
      findings,
      riskScore,
      summary: this._buildDeviceSummary(findings, riskScore),
    };
  }

  /**
   * Analyze an entire fleet of devices.
   * @param {Object[]} devices - Array of device data objects
   * @param {string[]} [benchmarkIds=['CIS']] - Benchmark IDs to check against
   * @param {Function} [onProgress] - Optional progress callback(percent, message)
   * @returns {Object} Fleet analysis result
   */
  async analyzeFleet(devices, benchmarkIds = ['CIS'], onProgress) {
    const totalDevices = devices.length;
    const deviceResults = [];
    const allFindings = [];

    this.logger.info && this.logger.info(`Starting fleet analysis for ${totalDevices} devices`);

    for (let i = 0; i < totalDevices; i++) {
      const device = devices[i];
      const progress = Math.round(((i) / totalDevices) * 100);

      if (onProgress) {
        onProgress(progress, `Analyzing device ${i + 1} of ${totalDevices}: ${device.name || device.hostname || 'unknown'}...`);
      }

      this.emit('progress', {
        phase: 'device-analysis',
        current: i + 1,
        total: totalDevices,
        progress,
      });

      const result = await this.analyzeDevice(device, benchmarkIds);
      deviceResults.push(result);
      allFindings.push(...result.findings);
    }

    if (onProgress) {
      onProgress(100, 'Fleet analysis complete');
    }

    const fleetRiskScore = this._computeFleetRiskScore(deviceResults);

    return {
      analyzer: 'device-security',
      timestamp: new Date().toISOString(),
      totalDevices,
      deviceResults,
      findings: allFindings,
      fleetRiskScore,
      summary: this._buildFleetSummary(allFindings, deviceResults),
      complianceRate: this._calculateComplianceRate(deviceResults),
    };
  }

  /**
   * Compute a risk score for a single device (0-100, higher = more risk).
   * @param {Object} device - Device data object
   * @param {string[]} [benchmarkIds=['CIS']] - Benchmark IDs
   * @returns {Object} Risk score details
   */
  async getDeviceRiskScore(device, benchmarkIds = ['CIS']) {
    const result = await this.analyzeDevice(device, benchmarkIds);

    return {
      deviceId: result.deviceId,
      deviceName: result.deviceName,
      riskScore: result.riskScore,
      riskLevel: this._riskLevel(result.riskScore),
      findingCounts: {
        total: result.findings.length,
        critical: result.findings.filter((f) => f.severity === 'Critical').length,
        high: result.findings.filter((f) => f.severity === 'High').length,
        medium: result.findings.filter((f) => f.severity === 'Medium').length,
        low: result.findings.filter((f) => f.severity === 'Low').length,
      },
      timestamp: new Date().toISOString(),
    };
  }

  // ================================================================== //
  //  Security Checks
  // ================================================================== //

  _checkBitLocker(device, benchmarkIds) {
    const findings = [];
    const bl = device.bitlocker || device.encryption || {};

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).bitlocker;
      if (!baseline) continue;

      // Encryption enabled?
      if (baseline.required && !bl.enabled) {
        findings.push(this._createFinding({
          title: 'BitLocker Not Enabled',
          description: `Device "${device.name || device.hostname}" does not have BitLocker encryption enabled. Data at rest is unprotected, risking data exposure if the device is lost or stolen.`,
          severity: 'Critical',
          category: 'device-security',
          subcategory: 'bitlocker',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable BitLocker encryption on all fixed drives.',
            steps: [
              'Ensure TPM 2.0 is available and enabled in BIOS/UEFI',
              'Open Group Policy Editor or Intune and deploy BitLocker policy',
              'Configure encryption algorithm to XTS-AES-256',
              'Require TPM + PIN protector for OS drive',
              'Enable BitLocker for all fixed data drives',
            ],
            powershell: `Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmAndPinProtector`,
            impact: 'One-time encryption process; minimal performance impact on modern hardware.',
            automatable: true,
          },
        }));
        continue; // No point checking algorithm if not enabled
      }

      // Encryption algorithm
      if (bl.enabled && baseline.algorithm && bl.algorithm !== baseline.algorithm) {
        findings.push(this._createFinding({
          title: 'BitLocker Weak Encryption Algorithm',
          description: `Device uses ${bl.algorithm || 'unknown'} encryption instead of the recommended ${baseline.algorithm}.`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'bitlocker',
          benchmark: bid,
          currentValue: bl.algorithm || 'unknown',
          recommendedValue: baseline.algorithm,
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: `Re-encrypt with ${baseline.algorithm}.`,
            steps: [
              `Decrypt the drive (manage-bde -off C:)`,
              `Set policy to use ${baseline.algorithm}`,
              `Re-encrypt (manage-bde -on C: -EncryptionMethod ${baseline.algorithm})`,
            ],
            powershell: `manage-bde -off C:\n# Wait for decryption...\nEnable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmAndPinProtector`,
            impact: 'Requires full re-encryption of the drive. Schedule during maintenance window.',
            automatable: true,
          },
        }));
      }

      // Protector type
      if (bl.enabled && baseline.protector && bl.protector !== baseline.protector) {
        findings.push(this._createFinding({
          title: 'BitLocker Insufficient Protector',
          description: `Device uses "${bl.protector || 'unknown'}" protector instead of "${baseline.protector}". TPM-only protectors are vulnerable to cold-boot and direct memory access attacks.`,
          severity: 'Medium',
          category: 'device-security',
          subcategory: 'bitlocker',
          benchmark: bid,
          currentValue: bl.protector || 'unknown',
          recommendedValue: baseline.protector,
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: `Change BitLocker protector to ${baseline.protector}.`,
            steps: [
              'Deploy updated BitLocker policy via GPO or Intune',
              'Require users to set a PIN on next boot',
            ],
            powershell: `Add-BitLockerKeyProtector -MountPoint "C:" -TpmAndPinProtector`,
            impact: 'Users will need to enter a PIN at boot.',
            automatable: true,
          },
        }));
      }

      // Recovery key escrowed?
      if (bl.enabled && bl.recoveryKeyEscrowed === false) {
        findings.push(this._createFinding({
          title: 'BitLocker Recovery Key Not Escrowed',
          description: `Recovery key for "${device.name || device.hostname}" has not been backed up to Active Directory or Azure AD. Key loss could result in permanent data inaccessibility.`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'bitlocker',
          benchmark: bid,
          currentValue: 'Not escrowed',
          recommendedValue: 'Escrowed to AD/AAD',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Back up BitLocker recovery key to directory.',
            steps: [
              'Deploy GPO or Intune policy to require AD/AAD backup of recovery keys',
              'Force key escrow for existing devices',
            ],
            powershell: `BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId ((Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).KeyProtectorId`,
            impact: 'None; the key is simply backed up.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  _checkEDR(device, benchmarkIds) {
    const findings = [];
    const edr = device.edr || device.endpointProtection || device.defender || {};

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).edr;
      if (!baseline) continue;

      // EDR installed/running?
      if (baseline.required && !edr.installed && !edr.running) {
        findings.push(this._createFinding({
          title: 'EDR/Endpoint Protection Not Installed',
          description: `No endpoint detection and response (EDR) solution detected on "${device.name || device.hostname}". The device lacks runtime threat protection.`,
          severity: 'Critical',
          category: 'device-security',
          subcategory: 'edr',
          benchmark: bid,
          currentValue: 'Not installed',
          recommendedValue: 'Installed and running',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Deploy EDR solution (e.g., Microsoft Defender for Endpoint).',
            steps: [
              'Ensure device is enrolled in Intune or SCCM',
              'Deploy MDE onboarding package via Intune configuration profile',
              'Verify sensor health after deployment',
            ],
            impact: 'Minimal; agent runs as a background service.',
            automatable: true,
          },
        }));
        continue;
      }

      // Real-time protection
      if (baseline.realTimeProtection && edr.realTimeProtection === false) {
        findings.push(this._createFinding({
          title: 'Real-Time Protection Disabled',
          description: `Real-time protection is disabled on "${device.name || device.hostname}". The device cannot detect threats in real time.`,
          severity: 'Critical',
          category: 'device-security',
          subcategory: 'edr',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable real-time protection.',
            powershell: `Set-MpPreference -DisableRealtimeMonitoring $false`,
            impact: 'Slight CPU overhead; critical for security.',
            automatable: true,
          },
        }));
      }

      // Tamper protection
      if (baseline.tamperProtection && edr.tamperProtection === false) {
        findings.push(this._createFinding({
          title: 'Tamper Protection Disabled',
          description: `Tamper protection is disabled on "${device.name || device.hostname}". Attackers can disable security features without resistance.`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'edr',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable tamper protection via Microsoft 365 Defender portal or Intune.',
            steps: [
              'Navigate to Microsoft 365 Defender portal > Settings > Endpoints > Advanced features',
              'Enable Tamper Protection',
              'Or deploy via Intune endpoint security policy',
            ],
            impact: 'Local administrators can no longer disable security features.',
            automatable: true,
          },
        }));
      }

      // Cloud-delivered protection
      if (baseline.cloudProtection && edr.cloudProtection === false) {
        findings.push(this._createFinding({
          title: 'Cloud-Delivered Protection Disabled',
          description: `Cloud-delivered protection is disabled on "${device.name || device.hostname}". The device cannot leverage cloud-based machine learning for threat detection.`,
          severity: 'Medium',
          category: 'device-security',
          subcategory: 'edr',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable cloud-delivered protection.',
            powershell: `Set-MpPreference -MAPSReporting Advanced`,
            impact: 'Requires internet connectivity for cloud lookups.',
            automatable: true,
          },
        }));
      }

      // Signature staleness
      if (edr.signatureAge !== undefined && edr.signatureAge > 3) {
        findings.push(this._createFinding({
          title: 'Outdated Antivirus Signatures',
          description: `Antivirus signatures on "${device.name || device.hostname}" are ${edr.signatureAge} days old. Signatures older than 3 days may miss recent threats.`,
          severity: edr.signatureAge > 7 ? 'High' : 'Medium',
          category: 'device-security',
          subcategory: 'edr',
          benchmark: bid,
          currentValue: `${edr.signatureAge} days old`,
          recommendedValue: 'Less than 3 days old',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Update antivirus signatures.',
            powershell: `Update-MpSignature`,
            impact: 'Brief network and CPU activity during update.',
            automatable: true,
          },
        }));
      }

      // Scan recency
      const lastScanDays = edr.lastFullScan
        ? Math.floor((Date.now() - new Date(edr.lastFullScan).getTime()) / (1000 * 60 * 60 * 24))
        : null;
      if (lastScanDays !== null && lastScanDays > 14) {
        findings.push(this._createFinding({
          title: 'No Recent Full Scan',
          description: `Last full antivirus scan on "${device.name || device.hostname}" was ${lastScanDays} days ago.`,
          severity: 'Medium',
          category: 'device-security',
          subcategory: 'edr',
          benchmark: bid,
          currentValue: `${lastScanDays} days ago`,
          recommendedValue: 'Within 14 days',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Schedule regular full scans.',
            powershell: `Start-MpScan -ScanType FullScan`,
            impact: 'High CPU usage during scan.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  _checkOSVersion(device, benchmarkIds) {
    const findings = [];
    const osName = device.osName || device.operatingSystem || '';
    const osVersion = device.osVersion || '';
    const osKey = `${osName} ${osVersion}`.trim();
    const lifecycle = this.osLifecycle[osKey];
    const now = new Date();

    if (!lifecycle) {
      // Unknown OS version -- warn but don't flag as critical
      if (osName) {
        findings.push(this._createFinding({
          title: 'Unknown OS Version',
          description: `OS version "${osKey}" is not in the known lifecycle database. Unable to verify patch currency.`,
          severity: 'Low',
          category: 'device-security',
          subcategory: 'os-version',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
        }));
      }
      return findings;
    }

    // Past end-of-life (no extended support)
    if (lifecycle.eol < now && (!lifecycle.extended || lifecycle.extended < now)) {
      findings.push(this._createFinding({
        title: 'End-of-Life Operating System',
        description: `"${device.name || device.hostname}" is running ${osKey} which is past end of life (${lifecycle.eol.toISOString().slice(0, 10)}). No security patches are available.`,
        severity: 'Critical',
        category: 'device-security',
        subcategory: 'os-version',
        currentValue: osKey,
        recommendedValue: 'Supported OS version',
        affectedObjects: [{ type: 'device', name: device.name || device.hostname, os: osKey }],
        remediation: {
          description: 'Upgrade to a supported operating system version.',
          steps: [
            'Plan upgrade path to latest supported Windows version',
            'Test application compatibility',
            'Schedule upgrade during maintenance window',
          ],
          impact: 'Full OS upgrade required; applications must be tested.',
          automatable: false,
        },
      }));
    } else if (lifecycle.eol < now && lifecycle.extended && lifecycle.extended >= now) {
      // In extended support only
      findings.push(this._createFinding({
        title: 'OS in Extended Support Only',
        description: `"${device.name || device.hostname}" is running ${osKey} which is in extended support until ${lifecycle.extended.toISOString().slice(0, 10)}. Only security updates are provided; plan upgrade.`,
        severity: 'Medium',
        category: 'device-security',
        subcategory: 'os-version',
        currentValue: osKey,
        recommendedValue: 'Current mainstream-supported OS',
        affectedObjects: [{ type: 'device', name: device.name || device.hostname, os: osKey }],
        remediation: {
          description: 'Begin planning upgrade to a mainstream-supported OS.',
          impact: 'OS upgrade required before extended support ends.',
          automatable: false,
        },
      }));
    }

    // Approaching EOL (within 6 months)
    const sixMonths = 6 * 30 * 24 * 60 * 60 * 1000;
    if (lifecycle.eol >= now && (lifecycle.eol.getTime() - now.getTime()) < sixMonths) {
      findings.push(this._createFinding({
        title: 'OS Approaching End of Life',
        description: `"${device.name || device.hostname}" is running ${osKey} which reaches end of life on ${lifecycle.eol.toISOString().slice(0, 10)}.`,
        severity: 'Low',
        category: 'device-security',
        subcategory: 'os-version',
        currentValue: osKey,
        affectedObjects: [{ type: 'device', name: device.name || device.hostname, os: osKey }],
        remediation: {
          description: 'Plan upgrade before end-of-life date.',
          automatable: false,
        },
      }));
    }

    return findings;
  }

  _checkPatchCompliance(device, benchmarkIds) {
    const findings = [];
    const patches = device.patches || device.patchStatus || {};
    const missingCritical = patches.missingCritical || [];
    const missingImportant = patches.missingImportant || [];
    const lastScanDate = patches.lastScanDate ? new Date(patches.lastScanDate) : null;
    const daysSinceScan = lastScanDate
      ? Math.floor((Date.now() - lastScanDate.getTime()) / (1000 * 60 * 60 * 24))
      : Infinity;

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).patches;
      if (!baseline) continue;

      // Missing critical patches
      if (missingCritical.length > baseline.maxMissingCritical) {
        findings.push(this._createFinding({
          title: 'Missing Critical Security Patches',
          description: `"${device.name || device.hostname}" is missing ${missingCritical.length} critical security patch(es). Missing patches leave known vulnerabilities unpatched.`,
          severity: 'Critical',
          category: 'device-security',
          subcategory: 'patch-compliance',
          benchmark: bid,
          currentValue: `${missingCritical.length} missing`,
          recommendedValue: `${baseline.maxMissingCritical} missing`,
          affectedObjects: missingCritical.map((p) => ({
            type: 'patch',
            id: p.kbId || p.id || p,
            title: p.title || p,
            severity: 'Critical',
          })),
          remediation: {
            description: 'Install missing critical patches immediately.',
            steps: [
              'Review missing patches for applicability',
              'Test in staging if possible',
              'Deploy via WSUS, SCCM, or Intune',
            ],
            powershell: `# List missing updates\nGet-WindowsUpdate -Category "Security Updates" -IsNotInstalled`,
            impact: 'May require restart.',
            automatable: true,
          },
        }));
      }

      // Missing important patches
      if (missingImportant.length > 2) {
        findings.push(this._createFinding({
          title: 'Missing Important Patches',
          description: `"${device.name || device.hostname}" is missing ${missingImportant.length} important patch(es).`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'patch-compliance',
          benchmark: bid,
          currentValue: `${missingImportant.length} missing`,
          recommendedValue: '0 missing',
          affectedObjects: missingImportant.map((p) => ({
            type: 'patch',
            id: p.kbId || p.id || p,
            title: p.title || p,
          })),
          remediation: {
            description: 'Install missing important patches within the next maintenance window.',
            impact: 'May require restart.',
            automatable: true,
          },
        }));
      }

      // Patch scan recency
      if (daysSinceScan > baseline.maxDaysSinceLastScan) {
        findings.push(this._createFinding({
          title: 'Stale Patch Scan',
          description: `Last patch scan for "${device.name || device.hostname}" was ${daysSinceScan === Infinity ? 'never' : daysSinceScan + ' days ago'}. Exceeds the ${bid} baseline of ${baseline.maxDaysSinceLastScan} days.`,
          severity: 'Medium',
          category: 'device-security',
          subcategory: 'patch-compliance',
          benchmark: bid,
          currentValue: daysSinceScan === Infinity ? 'Never' : `${daysSinceScan} days`,
          recommendedValue: `${baseline.maxDaysSinceLastScan} days`,
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Initiate a patch compliance scan.',
            powershell: `Start-ScheduledTask -TaskName "SoftwareDistribution\\Scan"`,
            impact: 'Brief network and CPU usage.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  _checkFirewall(device, benchmarkIds) {
    const findings = [];
    const fw = device.firewall || {};

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).firewall;
      if (!baseline) continue;

      const profiles = [
        { key: 'domainEnabled', label: 'Domain' },
        { key: 'privateEnabled', label: 'Private' },
        { key: 'publicEnabled', label: 'Public' },
      ];

      for (const profile of profiles) {
        if (baseline[profile.key] && fw[profile.key] === false) {
          findings.push(this._createFinding({
            title: `Firewall ${profile.label} Profile Disabled`,
            description: `Windows Firewall ${profile.label} profile is disabled on "${device.name || device.hostname}".`,
            severity: profile.label === 'Public' ? 'Critical' : 'High',
            category: 'device-security',
            subcategory: 'firewall',
            benchmark: bid,
            currentValue: 'Disabled',
            recommendedValue: 'Enabled',
            affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
            remediation: {
              description: `Enable Windows Firewall ${profile.label} profile.`,
              powershell: `Set-NetFirewallProfile -Profile ${profile.label} -Enabled True`,
              impact: 'May block unexpected inbound traffic.',
              automatable: true,
            },
          }));
        }
      }

      // Inbound default action
      if (baseline.defaultInbound && fw.defaultInbound && fw.defaultInbound !== baseline.defaultInbound) {
        findings.push(this._createFinding({
          title: 'Firewall Default Inbound Action Not Block',
          description: `Firewall default inbound action is "${fw.defaultInbound}" instead of "${baseline.defaultInbound}" on "${device.name || device.hostname}".`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'firewall',
          benchmark: bid,
          currentValue: fw.defaultInbound,
          recommendedValue: baseline.defaultInbound,
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Set default inbound action to Block.',
            powershell: `Set-NetFirewallProfile -DefaultInboundAction Block`,
            impact: 'Inbound connections not matching an allow rule will be blocked.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  _checkSecureBoot(device, benchmarkIds) {
    const findings = [];
    const sb = device.secureBoot;

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).secureBoot;
      if (!baseline || !baseline.required) continue;

      if (sb === false || (typeof sb === 'object' && sb.enabled === false)) {
        findings.push(this._createFinding({
          title: 'Secure Boot Disabled',
          description: `Secure Boot is disabled on "${device.name || device.hostname}". Without Secure Boot, the boot process is vulnerable to bootkits and rootkits.`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'secure-boot',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable Secure Boot in UEFI firmware settings.',
            steps: [
              'Verify firmware is UEFI (not legacy BIOS)',
              'Enter UEFI settings and enable Secure Boot',
              'Ensure OS was installed in UEFI mode',
            ],
            impact: 'Requires UEFI firmware and UEFI-mode OS installation.',
            automatable: false,
          },
        }));
      }
    }

    return findings;
  }

  _checkTPM(device, benchmarkIds) {
    const findings = [];
    const tpm = device.tpm || {};

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).tpm;
      if (!baseline || !baseline.required) continue;

      if (!tpm.present && !tpm.enabled) {
        findings.push(this._createFinding({
          title: 'TPM Not Present or Not Enabled',
          description: `No TPM detected on "${device.name || device.hostname}". TPM is required for BitLocker, Credential Guard, and measured boot.`,
          severity: 'Critical',
          category: 'device-security',
          subcategory: 'tpm',
          benchmark: bid,
          currentValue: 'Not present',
          recommendedValue: `TPM ${baseline.minVersion}+`,
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable TPM in BIOS/UEFI or replace hardware if TPM is absent.',
            impact: 'Hardware change may be required.',
            automatable: false,
          },
        }));
      } else if (tpm.version && baseline.minVersion) {
        const current = parseFloat(tpm.version);
        const required = parseFloat(baseline.minVersion);
        if (current < required) {
          findings.push(this._createFinding({
            title: 'TPM Version Below Minimum',
            description: `TPM version ${tpm.version} on "${device.name || device.hostname}" is below the required ${baseline.minVersion}.`,
            severity: 'High',
            category: 'device-security',
            subcategory: 'tpm',
            benchmark: bid,
            currentValue: tpm.version,
            recommendedValue: baseline.minVersion,
            affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
            remediation: {
              description: `Upgrade TPM firmware to version ${baseline.minVersion} or replace hardware.`,
              impact: 'May require firmware update or hardware replacement.',
              automatable: false,
            },
          }));
        }
      }
    }

    return findings;
  }

  _checkCredentialGuard(device, benchmarkIds) {
    const findings = [];
    const cg = device.credentialGuard;

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).credentialGuard;
      if (!baseline || !baseline.required) continue;

      const enabled = cg === true || (typeof cg === 'object' && cg.enabled === true);
      if (!enabled) {
        findings.push(this._createFinding({
          title: 'Credential Guard Not Enabled',
          description: `Credential Guard is not enabled on "${device.name || device.hostname}". Without it, LSASS is vulnerable to credential-dumping attacks (e.g., Mimikatz).`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'credential-guard',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable Windows Defender Credential Guard via Group Policy or Intune.',
            steps: [
              'Ensure hardware supports VBS (Virtualization-Based Security)',
              'Enable via GPO: Computer Configuration > Admin Templates > System > Device Guard',
              'Or deploy via Intune device configuration profile',
            ],
            powershell: `# Verify VBS support\nGet-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard`,
            impact: 'Requires VBS-capable hardware. Some older credential protocols may break.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  _checkScreenLock(device, benchmarkIds) {
    const findings = [];
    const lock = device.screenLock || device.lockScreen || {};

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).screenLock;
      if (!baseline) continue;

      if (lock.inactivityTimeout !== undefined && lock.inactivityTimeout > baseline.maxInactivityMinutes) {
        findings.push(this._createFinding({
          title: 'Screen Lock Timeout Too Long',
          description: `Screen lock timeout on "${device.name || device.hostname}" is ${lock.inactivityTimeout} minutes, exceeding the ${baseline.maxInactivityMinutes}-minute ${bid} maximum.`,
          severity: 'Medium',
          category: 'device-security',
          subcategory: 'screen-lock',
          benchmark: bid,
          currentValue: `${lock.inactivityTimeout} minutes`,
          recommendedValue: `${baseline.maxInactivityMinutes} minutes`,
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: `Set screen lock timeout to ${baseline.maxInactivityMinutes} minutes or less.`,
            powershell: `powercfg /change standby-timeout-ac ${baseline.maxInactivityMinutes}`,
            impact: 'Screen locks sooner during inactivity.',
            automatable: true,
          },
        }));
      }

      if (baseline.requirePassword && lock.requirePassword === false) {
        findings.push(this._createFinding({
          title: 'Screen Lock Does Not Require Password',
          description: `Screen lock on "${device.name || device.hostname}" does not require a password on resume, allowing unauthorized access.`,
          severity: 'High',
          category: 'device-security',
          subcategory: 'screen-lock',
          benchmark: bid,
          currentValue: 'Password not required',
          recommendedValue: 'Password required',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Require password on screen lock resume.',
            impact: 'Users must enter password to unlock.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  _checkLocalAccounts(device, benchmarkIds) {
    const findings = [];
    const localAccounts = device.localAccounts || device.localUsers || [];

    // Check for enabled local admin account
    const builtInAdmin = localAccounts.find(
      (a) => (a.name || '').toLowerCase() === 'administrator' && a.enabled !== false
    );
    if (builtInAdmin) {
      findings.push(this._createFinding({
        title: 'Built-In Administrator Account Enabled',
        description: `The built-in Administrator account is enabled on "${device.name || device.hostname}". This well-known account is a frequent brute-force target.`,
        severity: 'Medium',
        category: 'device-security',
        subcategory: 'local-accounts',
        affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
        remediation: {
          description: 'Disable or rename the built-in Administrator account.',
          powershell: `Disable-LocalUser -Name "Administrator"`,
          impact: 'Ensure LAPS or another local admin solution is in place.',
          automatable: true,
        },
      }));
    }

    // Check for enabled Guest account
    const guestAccount = localAccounts.find(
      (a) => (a.name || '').toLowerCase() === 'guest' && a.enabled === true
    );
    if (guestAccount) {
      findings.push(this._createFinding({
        title: 'Guest Account Enabled',
        description: `The Guest account is enabled on "${device.name || device.hostname}". Guest accounts provide unauthenticated access.`,
        severity: 'High',
        category: 'device-security',
        subcategory: 'local-accounts',
        affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
        remediation: {
          description: 'Disable the Guest account.',
          powershell: `Disable-LocalUser -Name "Guest"`,
          impact: 'None for properly configured environments.',
          automatable: true,
        },
      }));
    }

    // Too many local admins
    const localAdmins = localAccounts.filter((a) => a.isAdmin === true);
    if (localAdmins.length > 2) {
      findings.push(this._createFinding({
        title: 'Excessive Local Administrators',
        description: `"${device.name || device.hostname}" has ${localAdmins.length} local administrator accounts. Excessive local admins increase the attack surface.`,
        severity: 'Medium',
        category: 'device-security',
        subcategory: 'local-accounts',
        currentValue: localAdmins.length,
        recommendedValue: 2,
        affectedObjects: localAdmins.map((a) => ({ type: 'local-admin', name: a.name })),
        remediation: {
          description: 'Reduce local administrators to essential accounts only.',
          impact: 'Removed admins will lose local administrative rights.',
          automatable: false,
        },
      }));
    }

    return findings;
  }

  _checkAutoUpdates(device, benchmarkIds) {
    const findings = [];
    const updates = device.autoUpdates || device.windowsUpdate || {};

    if (updates.enabled === false) {
      findings.push(this._createFinding({
        title: 'Automatic Updates Disabled',
        description: `Automatic Windows Updates are disabled on "${device.name || device.hostname}". The device may miss critical security patches.`,
        severity: 'High',
        category: 'device-security',
        subcategory: 'auto-updates',
        currentValue: 'Disabled',
        recommendedValue: 'Enabled',
        affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
        remediation: {
          description: 'Enable automatic Windows Updates via GPO or Intune.',
          powershell: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -Name "NoAutoUpdate" -Value 0`,
          impact: 'Device will download and install updates automatically.',
          automatable: true,
        },
      }));
    }

    // Deferred too long
    if (updates.deferralDays !== undefined && updates.deferralDays > 30) {
      findings.push(this._createFinding({
        title: 'Excessive Update Deferral',
        description: `Updates are deferred by ${updates.deferralDays} days on "${device.name || device.hostname}". Extended deferral delays critical patches.`,
        severity: 'Medium',
        category: 'device-security',
        subcategory: 'auto-updates',
        currentValue: `${updates.deferralDays} days`,
        recommendedValue: '30 days or less',
        affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
        remediation: {
          description: 'Reduce update deferral to 30 days or less for quality updates.',
          impact: 'Updates will install sooner.',
          automatable: true,
        },
      }));
    }

    return findings;
  }

  _checkUAC(device, benchmarkIds) {
    const findings = [];
    const uac = device.uac || {};

    for (const bid of benchmarkIds) {
      const baseline = (this.complianceBaselines[bid] || {}).uac;
      if (!baseline) continue;

      if (baseline.enabled && uac.enabled === false) {
        findings.push(this._createFinding({
          title: 'User Account Control Disabled',
          description: `UAC is disabled on "${device.name || device.hostname}". Without UAC, all processes run with full privileges, negating the principle of least privilege.`,
          severity: 'Critical',
          category: 'device-security',
          subcategory: 'uac',
          benchmark: bid,
          currentValue: 'Disabled',
          recommendedValue: 'Enabled',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable User Account Control.',
            powershell: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value 1`,
            impact: 'Users will receive elevation prompts for administrative tasks.',
            automatable: true,
          },
        }));
      }

      if (baseline.consentPrompt && uac.consentPrompt === false) {
        findings.push(this._createFinding({
          title: 'UAC Consent Prompt Disabled',
          description: `UAC consent prompt is disabled on "${device.name || device.hostname}". Elevation occurs silently, reducing visibility of privileged actions.`,
          severity: 'Medium',
          category: 'device-security',
          subcategory: 'uac',
          benchmark: bid,
          currentValue: 'Silent elevation',
          recommendedValue: 'Prompt for consent',
          affectedObjects: [{ type: 'device', name: device.name || device.hostname }],
          remediation: {
            description: 'Enable UAC consent prompt for administrators.',
            powershell: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2`,
            impact: 'Administrators will see consent prompts on elevation.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  // ================================================================== //
  //  Scoring helpers
  // ================================================================== //

  _createFinding(params) {
    return {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      title: params.title,
      description: params.description,
      severity: params.severity || 'Medium',
      category: params.category || 'device-security',
      subcategory: params.subcategory || 'general',
      benchmark: params.benchmark || null,
      currentValue: params.currentValue !== undefined ? params.currentValue : null,
      recommendedValue: params.recommendedValue !== undefined ? params.recommendedValue : null,
      affectedObjects: params.affectedObjects || [],
      remediation: params.remediation || null,
      riskScore: this._severityToScore(params.severity),
      status: 'open',
    };
  }

  _severityToScore(severity) {
    const scores = { Critical: 10, High: 8, Medium: 5, Low: 2 };
    return scores[severity] || 5;
  }

  _computeRiskScore(findings) {
    if (findings.length === 0) return 0;
    const totalWeight = findings.reduce((sum, f) => sum + f.riskScore, 0);
    const maxPossible = findings.length * 10;
    // Scale to 0-100
    return Math.min(100, Math.round((totalWeight / Math.max(maxPossible, 1)) * 100));
  }

  _computeFleetRiskScore(deviceResults) {
    if (deviceResults.length === 0) return 0;
    const avg = deviceResults.reduce((sum, r) => sum + r.riskScore, 0) / deviceResults.length;
    return Math.round(avg);
  }

  _riskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Minimal';
  }

  _buildDeviceSummary(findings, riskScore) {
    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const bySubcategory = {};

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      bySubcategory[f.subcategory] = (bySubcategory[f.subcategory] || 0) + 1;
    }

    return {
      totalFindings: findings.length,
      bySeverity,
      bySubcategory,
      riskScore,
      riskLevel: this._riskLevel(riskScore),
    };
  }

  _buildFleetSummary(allFindings, deviceResults) {
    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const bySubcategory = {};

    for (const f of allFindings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      bySubcategory[f.subcategory] = (bySubcategory[f.subcategory] || 0) + 1;
    }

    const riskDistribution = { Critical: 0, High: 0, Medium: 0, Low: 0, Minimal: 0 };
    for (const r of deviceResults) {
      const level = this._riskLevel(r.riskScore);
      riskDistribution[level] = (riskDistribution[level] || 0) + 1;
    }

    return {
      totalFindings: allFindings.length,
      totalDevices: deviceResults.length,
      bySeverity,
      bySubcategory,
      riskDistribution,
    };
  }

  _calculateComplianceRate(deviceResults) {
    if (deviceResults.length === 0) return 100;
    const compliant = deviceResults.filter((r) => r.findings.length === 0).length;
    return Math.round((compliant / deviceResults.length) * 100);
  }
}

module.exports = DeviceSecurityAnalyzer;
