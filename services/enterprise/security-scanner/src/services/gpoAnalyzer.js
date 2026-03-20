'use strict';

const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

/**
 * GPO Analyzer - Analyzes Group Policy Objects for security weaknesses.
 * Evaluates password policies, audit policies, firewall rules, user rights
 * assignments, and security options against compliance benchmarks.
 */
class GPOAnalyzer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logger = options.logger || console;

    // CIS Benchmark recommended values for password policies
    this.benchmarks = {
      CIS: {
        passwordPolicy: {
          minLength: 14,
          maxAge: 60,
          minAge: 1,
          historySize: 24,
          complexity: true,
          reversibleEncryption: false,
          lockoutThreshold: 5,
          lockoutDuration: 15,
          lockoutWindow: 15,
        },
        auditPolicy: {
          accountLogon: 'Success, Failure',
          accountManagement: 'Success, Failure',
          logonEvents: 'Success, Failure',
          objectAccess: 'Success, Failure',
          policyChange: 'Success, Failure',
          privilegeUse: 'Success, Failure',
          processTracking: 'Success',
          systemEvents: 'Success, Failure',
          dsAccess: 'Success, Failure',
        },
        securityOptions: {
          lmHashStorage: false,
          anonymousSidTranslation: false,
          anonymousEnumeration: false,
          lanManagerAuth: 5, // NTLMv2 only
          ldapSigning: 2, // Required
          smbSigning: true,
          ntlmSspMinSecurity: 537395200,
        },
        firewall: {
          domainProfileEnabled: true,
          privateProfileEnabled: true,
          publicProfileEnabled: true,
          inboundDefaultBlock: true,
          outboundDefaultAllow: true,
        },
        userRights: {
          seNetworkLogonRight: ['Administrators', 'Authenticated Users'],
          seRemoteInteractiveLogonRight: ['Administrators', 'Remote Desktop Users'],
          seBatchLogonRight: [],
          seServiceLogonRight: [],
          denyNetworkLogon: ['Guests'],
          denyRemoteInteractiveLogon: ['Guests'],
          seDebugPrivilege: ['Administrators'],
          seTakeOwnershipPrivilege: ['Administrators'],
          seLoadDriverPrivilege: ['Administrators'],
          seBackupPrivilege: ['Administrators'],
          seRestorePrivilege: ['Administrators'],
        },
      },
      NIST: {
        passwordPolicy: {
          minLength: 12,
          maxAge: 0, // NIST 800-63B recommends no expiration with MFA
          minAge: 0,
          historySize: 12,
          complexity: false, // NIST prefers length over complexity
          reversibleEncryption: false,
          lockoutThreshold: 10,
          lockoutDuration: 30,
          lockoutWindow: 30,
        },
        auditPolicy: {
          accountLogon: 'Success, Failure',
          accountManagement: 'Success, Failure',
          logonEvents: 'Success, Failure',
          objectAccess: 'Failure',
          policyChange: 'Success',
          privilegeUse: 'Failure',
          systemEvents: 'Success, Failure',
          dsAccess: 'Success, Failure',
        },
      },
      DISA_STIG: {
        passwordPolicy: {
          minLength: 15,
          maxAge: 60,
          minAge: 1,
          historySize: 24,
          complexity: true,
          reversibleEncryption: false,
          lockoutThreshold: 3,
          lockoutDuration: 15,
          lockoutWindow: 15,
        },
        auditPolicy: {
          accountLogon: 'Success, Failure',
          accountManagement: 'Success, Failure',
          logonEvents: 'Success, Failure',
          objectAccess: 'Success, Failure',
          policyChange: 'Success, Failure',
          privilegeUse: 'Success, Failure',
          processTracking: 'Success, Failure',
          systemEvents: 'Success, Failure',
          dsAccess: 'Success, Failure',
        },
      },
    };
  }

  /**
   * Run full GPO analysis against specified benchmarks.
   * @param {Object} gpoData - GPO configuration data from Active Directory
   * @param {string[]} benchmarkIds - Benchmarks to compare against
   * @param {Function} onProgress - Progress callback
   * @returns {Object} Analysis results with findings
   */
  async analyze(gpoData, benchmarkIds = ['CIS'], onProgress) {
    const scanId = uuidv4();
    const findings = [];
    const steps = [
      { name: 'passwordPolicies', weight: 20 },
      { name: 'auditPolicies', weight: 20 },
      { name: 'firewallRules', weight: 20 },
      { name: 'userRights', weight: 15 },
      { name: 'securityOptions', weight: 15 },
      { name: 'administrativeTemplates', weight: 10 },
    ];

    let completedWeight = 0;

    for (const step of steps) {
      this.emit('progress', {
        scanId,
        phase: 'gpo-analysis',
        step: step.name,
        progress: completedWeight,
      });

      if (onProgress) {
        onProgress(completedWeight, `Analyzing ${step.name}...`);
      }

      try {
        const stepFindings = await this[`_analyze${this._capitalize(step.name)}`](
          gpoData,
          benchmarkIds
        );
        findings.push(...stepFindings);
      } catch (err) {
        this.logger.error(`Error analyzing ${step.name}:`, err.message);
        findings.push(this._createFinding({
          title: `GPO Analysis Error: ${step.name}`,
          description: `Failed to analyze ${step.name}: ${err.message}`,
          severity: 'Medium',
          category: 'gpo',
          subcategory: step.name,
          benchmarks: benchmarkIds,
        }));
      }

      completedWeight += step.weight;
    }

    if (onProgress) {
      onProgress(100, 'GPO analysis complete');
    }

    return {
      scanId,
      analyzer: 'gpo',
      timestamp: new Date().toISOString(),
      gpoCount: gpoData.policies ? gpoData.policies.length : 0,
      benchmarks: benchmarkIds,
      findings,
      summary: this._buildSummary(findings),
    };
  }

  /**
   * Analyze password policies against benchmarks.
   */
  async _analyzePasswordPolicies(gpoData, benchmarkIds) {
    const findings = [];
    const policies = gpoData.passwordPolicy || this._getDefaultPasswordPolicy();

    for (const benchmarkId of benchmarkIds) {
      const benchmark = this.benchmarks[benchmarkId];
      if (!benchmark || !benchmark.passwordPolicy) continue;
      const bp = benchmark.passwordPolicy;

      // Minimum password length
      if (policies.minLength < bp.minLength) {
        findings.push(this._createFinding({
          title: 'Weak Minimum Password Length',
          description: `Password minimum length is set to ${policies.minLength} characters. ${benchmarkId} recommends at least ${bp.minLength} characters.`,
          severity: policies.minLength < 8 ? 'Critical' : 'High',
          category: 'gpo',
          subcategory: 'password-policy',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-PWD-001`,
          currentValue: policies.minLength,
          recommendedValue: bp.minLength,
          remediation: {
            description: `Increase the minimum password length to ${bp.minLength} characters or more.`,
            steps: [
              'Open Group Policy Management Console (GPMC)',
              'Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy',
              `Set "Minimum password length" to ${bp.minLength}`,
              'Run gpupdate /force on domain controllers',
            ],
            powershell: `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -MinPasswordLength ${bp.minLength}`,
            impact: 'Users will be required to use longer passwords on next change. Consider implementing a phased rollout.',
            automatable: true,
          },
          affectedObjects: this._getAffectedGPOs(gpoData, 'password'),
        }));
      }

      // Maximum password age
      if (bp.maxAge > 0 && (policies.maxAge === 0 || policies.maxAge > bp.maxAge)) {
        findings.push(this._createFinding({
          title: 'Password Expiration Policy Too Lenient',
          description: `Maximum password age is ${policies.maxAge === 0 ? 'disabled' : policies.maxAge + ' days'}. ${benchmarkId} recommends ${bp.maxAge} days.`,
          severity: policies.maxAge === 0 ? 'High' : 'Medium',
          category: 'gpo',
          subcategory: 'password-policy',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-PWD-002`,
          currentValue: policies.maxAge,
          recommendedValue: bp.maxAge,
          remediation: {
            description: `Set maximum password age to ${bp.maxAge} days.`,
            steps: [
              'Open Group Policy Management Console',
              'Navigate to Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy',
              `Set "Maximum password age" to ${bp.maxAge} days`,
            ],
            powershell: `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -MaxPasswordAge (New-TimeSpan -Days ${bp.maxAge})`,
            impact: 'Users will need to change passwords more frequently.',
            automatable: true,
          },
        }));
      }

      // Password history
      if (policies.historySize < bp.historySize) {
        findings.push(this._createFinding({
          title: 'Insufficient Password History',
          description: `Password history is set to remember ${policies.historySize} passwords. ${benchmarkId} recommends ${bp.historySize}.`,
          severity: policies.historySize < 6 ? 'High' : 'Medium',
          category: 'gpo',
          subcategory: 'password-policy',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-PWD-003`,
          currentValue: policies.historySize,
          recommendedValue: bp.historySize,
          remediation: {
            description: `Set password history to remember ${bp.historySize} passwords.`,
            steps: [
              'Open Group Policy Management Console',
              'Navigate to Password Policy settings',
              `Set "Enforce password history" to ${bp.historySize}`,
            ],
            powershell: `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -PasswordHistoryCount ${bp.historySize}`,
            impact: 'Users cannot reuse recent passwords.',
            automatable: true,
          },
        }));
      }

      // Complexity requirements
      if (bp.complexity && !policies.complexity) {
        findings.push(this._createFinding({
          title: 'Password Complexity Disabled',
          description: `Password complexity requirements are disabled. ${benchmarkId} requires complexity to be enabled.`,
          severity: 'Critical',
          category: 'gpo',
          subcategory: 'password-policy',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-PWD-004`,
          currentValue: false,
          recommendedValue: true,
          remediation: {
            description: 'Enable password complexity requirements.',
            steps: [
              'Open Group Policy Management Console',
              'Navigate to Password Policy settings',
              'Enable "Password must meet complexity requirements"',
            ],
            powershell: 'Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -ComplexityEnabled $true',
            impact: 'Passwords must contain characters from at least three categories: uppercase, lowercase, digits, special characters.',
            automatable: true,
          },
        }));
      }

      // Reversible encryption
      if (policies.reversibleEncryption && !bp.reversibleEncryption) {
        findings.push(this._createFinding({
          title: 'Reversible Encryption Enabled',
          description: 'Passwords are being stored with reversible encryption, equivalent to storing plaintext.',
          severity: 'Critical',
          category: 'gpo',
          subcategory: 'password-policy',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-PWD-005`,
          currentValue: true,
          recommendedValue: false,
          remediation: {
            description: 'Disable reversible encryption for password storage.',
            steps: [
              'Open Group Policy Management Console',
              'Navigate to Password Policy settings',
              'Disable "Store passwords using reversible encryption"',
              'Force password reset for all affected accounts',
            ],
            powershell: 'Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -ReversibleEncryptionEnabled $false',
            impact: 'Applications relying on reversible encryption (e.g., CHAP, Digest Auth) may break.',
            automatable: true,
          },
        }));
      }

      // Account lockout
      if (policies.lockoutThreshold === 0 || policies.lockoutThreshold > bp.lockoutThreshold) {
        findings.push(this._createFinding({
          title: 'Weak Account Lockout Policy',
          description: `Account lockout threshold is ${policies.lockoutThreshold === 0 ? 'disabled' : policies.lockoutThreshold + ' attempts'}. ${benchmarkId} recommends ${bp.lockoutThreshold} attempts.`,
          severity: policies.lockoutThreshold === 0 ? 'Critical' : 'High',
          category: 'gpo',
          subcategory: 'password-policy',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-PWD-006`,
          currentValue: policies.lockoutThreshold,
          recommendedValue: bp.lockoutThreshold,
          remediation: {
            description: `Set account lockout threshold to ${bp.lockoutThreshold} invalid attempts.`,
            steps: [
              'Open Group Policy Management Console',
              'Navigate to Account Policies > Account Lockout Policy',
              `Set "Account lockout threshold" to ${bp.lockoutThreshold}`,
              `Set "Account lockout duration" to ${bp.lockoutDuration} minutes`,
              `Set "Reset account lockout counter after" to ${bp.lockoutWindow} minutes`,
            ],
            powershell: `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -LockoutThreshold ${bp.lockoutThreshold} -LockoutDuration (New-TimeSpan -Minutes ${bp.lockoutDuration}) -LockoutObservationWindow (New-TimeSpan -Minutes ${bp.lockoutWindow})`,
            impact: 'Accounts will be locked after failed login attempts. Ensure help desk is prepared for increased lockout calls.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  /**
   * Analyze audit policies.
   */
  async _analyzeAuditPolicies(gpoData, benchmarkIds) {
    const findings = [];
    const policies = gpoData.auditPolicy || this._getDefaultAuditPolicy();

    for (const benchmarkId of benchmarkIds) {
      const benchmark = this.benchmarks[benchmarkId];
      if (!benchmark || !benchmark.auditPolicy) continue;

      for (const [category, expectedSetting] of Object.entries(benchmark.auditPolicy)) {
        const currentSetting = policies[category] || 'No Auditing';

        if (!this._auditSettingMeetsRequirement(currentSetting, expectedSetting)) {
          const severityMap = {
            accountLogon: 'Critical',
            accountManagement: 'Critical',
            logonEvents: 'High',
            objectAccess: 'Medium',
            policyChange: 'High',
            privilegeUse: 'High',
            processTracking: 'Medium',
            systemEvents: 'High',
            dsAccess: 'High',
          };

          findings.push(this._createFinding({
            title: `Insufficient Audit Policy: ${this._formatCategoryName(category)}`,
            description: `Audit policy for ${this._formatCategoryName(category)} is set to "${currentSetting}". ${benchmarkId} recommends "${expectedSetting}".`,
            severity: severityMap[category] || 'Medium',
            category: 'gpo',
            subcategory: 'audit-policy',
            benchmark: benchmarkId,
            controlId: `${benchmarkId}-AUD-${category.toUpperCase().substring(0, 3)}`,
            currentValue: currentSetting,
            recommendedValue: expectedSetting,
            remediation: {
              description: `Configure ${this._formatCategoryName(category)} audit policy to "${expectedSetting}".`,
              steps: [
                'Open Group Policy Management Console',
                'Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration',
                `Set ${this._formatCategoryName(category)} auditing to "${expectedSetting}"`,
              ],
              powershell: `auditpol /set /subcategory:"${this._formatCategoryName(category)}" /success:enable /failure:enable`,
              impact: 'Increased event log volume. Ensure log storage capacity is sufficient.',
              automatable: true,
            },
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Analyze firewall rules in GPOs.
   */
  async _analyzeFirewallRules(gpoData, benchmarkIds) {
    const findings = [];
    const firewall = gpoData.firewallPolicy || this._getDefaultFirewallPolicy();

    for (const benchmarkId of benchmarkIds) {
      const benchmark = this.benchmarks[benchmarkId];
      if (!benchmark || !benchmark.firewall) continue;
      const bf = benchmark.firewall;

      // Check profile enablement
      const profiles = ['domain', 'private', 'public'];
      for (const profile of profiles) {
        const key = `${profile}ProfileEnabled`;
        if (bf[key] && !firewall[key]) {
          findings.push(this._createFinding({
            title: `Windows Firewall Disabled: ${this._capitalize(profile)} Profile`,
            description: `Windows Firewall is disabled for the ${profile} profile. This leaves systems unprotected against network-based attacks.`,
            severity: profile === 'public' ? 'Critical' : 'High',
            category: 'gpo',
            subcategory: 'firewall',
            benchmark: benchmarkId,
            controlId: `${benchmarkId}-FW-${profile.toUpperCase().substring(0, 3)}`,
            currentValue: false,
            recommendedValue: true,
            remediation: {
              description: `Enable Windows Firewall for the ${profile} profile.`,
              steps: [
                'Open Group Policy Management Console',
                'Navigate to Computer Configuration > Windows Settings > Security Settings > Windows Firewall with Advanced Security',
                `Right-click and select Properties, go to ${this._capitalize(profile)} Profile tab`,
                'Set Firewall state to "On (recommended)"',
              ],
              powershell: `Set-NetFirewallProfile -Profile ${this._capitalize(profile)} -Enabled True`,
              impact: 'Applications requiring inbound connections may need firewall rules created.',
              automatable: true,
            },
          }));
        }
      }

      // Check inbound default action
      if (bf.inboundDefaultBlock && !firewall.inboundDefaultBlock) {
        findings.push(this._createFinding({
          title: 'Firewall Inbound Default Not Set to Block',
          description: 'The default inbound action is not set to block. All inbound traffic not matching a rule will be allowed.',
          severity: 'Critical',
          category: 'gpo',
          subcategory: 'firewall',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-FW-INB`,
          currentValue: 'Allow',
          recommendedValue: 'Block',
          remediation: {
            description: 'Set the default inbound firewall action to block.',
            steps: [
              'Open Windows Firewall with Advanced Security',
              'Set inbound connections default to "Block" for all profiles',
            ],
            powershell: 'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block',
            impact: 'Inbound traffic not explicitly allowed by rules will be blocked.',
            automatable: true,
          },
        }));
      }

      // Analyze overly permissive rules
      const rules = firewall.rules || [];
      for (const rule of rules) {
        if (rule.enabled && rule.direction === 'Inbound' && rule.action === 'Allow') {
          // Flag rules allowing any source
          if (rule.remoteAddress === '*' || rule.remoteAddress === 'Any') {
            findings.push(this._createFinding({
              title: `Overly Permissive Firewall Rule: ${rule.name}`,
              description: `Inbound firewall rule "${rule.name}" allows connections from any source address on port(s) ${rule.localPort || 'all'}. This may expose services unnecessarily.`,
              severity: this._getFirewallRuleSeverity(rule),
              category: 'gpo',
              subcategory: 'firewall',
              benchmark: benchmarkId,
              controlId: `${benchmarkId}-FW-RULE`,
              affectedObjects: [{ type: 'firewall-rule', name: rule.name, gpo: rule.gpo }],
              remediation: {
                description: `Restrict the source addresses for firewall rule "${rule.name}" to only authorized networks.`,
                steps: [
                  `Open the firewall rule "${rule.name}"`,
                  'Go to the Scope tab',
                  'Restrict Remote IP addresses to specific subnets or addresses',
                ],
                powershell: `Set-NetFirewallRule -DisplayName "${rule.name}" -RemoteAddress <authorized_subnet>`,
                impact: 'Legitimate connections from non-authorized networks will be blocked.',
                automatable: false,
              },
            }));
          }

          // Flag rules with all ports open
          if (rule.localPort === '*' || rule.localPort === 'Any' || !rule.localPort) {
            findings.push(this._createFinding({
              title: `Firewall Rule Allows All Ports: ${rule.name}`,
              description: `Inbound firewall rule "${rule.name}" allows connections on all ports. This significantly increases the attack surface.`,
              severity: 'Critical',
              category: 'gpo',
              subcategory: 'firewall',
              benchmark: benchmarkId,
              controlId: `${benchmarkId}-FW-PORT`,
              affectedObjects: [{ type: 'firewall-rule', name: rule.name }],
              remediation: {
                description: 'Restrict the firewall rule to only necessary ports.',
                steps: [
                  `Edit firewall rule "${rule.name}"`,
                  'Specify only the required port numbers',
                ],
                powershell: `Set-NetFirewallRule -DisplayName "${rule.name}" -LocalPort <required_ports>`,
                impact: 'Only specified ports will be accessible.',
                automatable: false,
              },
            }));
          }
        }
      }
    }

    return findings;
  }

  /**
   * Analyze user rights assignments.
   */
  async _analyzeUserRights(gpoData, benchmarkIds) {
    const findings = [];
    const userRights = gpoData.userRightsAssignment || {};

    for (const benchmarkId of benchmarkIds) {
      const benchmark = this.benchmarks[benchmarkId];
      if (!benchmark || !benchmark.userRights) continue;

      // Check dangerous privileges
      const dangerousPrivileges = {
        seDebugPrivilege: {
          name: 'Debug Programs',
          risk: 'Allows reading/writing any process memory, extracting credentials, and bypassing security controls.',
        },
        seTakeOwnershipPrivilege: {
          name: 'Take Ownership',
          risk: 'Allows taking ownership of any securable object, bypassing DACL protection.',
        },
        seLoadDriverPrivilege: {
          name: 'Load and Unload Device Drivers',
          risk: 'Allows loading arbitrary kernel drivers, enabling rootkit installation.',
        },
        seBackupPrivilege: {
          name: 'Backup Files and Directories',
          risk: 'Allows reading any file regardless of ACLs, enabling data exfiltration.',
        },
        seRestorePrivilege: {
          name: 'Restore Files and Directories',
          risk: 'Allows writing to any file regardless of ACLs, enabling system compromise.',
        },
        seImpersonatePrivilege: {
          name: 'Impersonate a Client',
          risk: 'Can be used for privilege escalation via token impersonation attacks.',
        },
      };

      for (const [privilege, info] of Object.entries(dangerousPrivileges)) {
        const assigned = userRights[privilege] || [];
        const recommended = benchmark.userRights[privilege] || ['Administrators'];

        const extraAssignees = assigned.filter(
          (a) => !recommended.includes(a) && a !== 'LOCAL SERVICE' && a !== 'NETWORK SERVICE'
        );

        if (extraAssignees.length > 0) {
          findings.push(this._createFinding({
            title: `Excessive ${info.name} Privilege Assignment`,
            description: `The "${info.name}" (${privilege}) right is assigned to: ${assigned.join(', ')}. ${info.risk} Only ${recommended.join(', ')} should have this right per ${benchmarkId}.`,
            severity: 'High',
            category: 'gpo',
            subcategory: 'user-rights',
            benchmark: benchmarkId,
            controlId: `${benchmarkId}-UR-${privilege.substring(2, 5).toUpperCase()}`,
            currentValue: assigned,
            recommendedValue: recommended,
            affectedObjects: extraAssignees.map((a) => ({ type: 'principal', name: a })),
            remediation: {
              description: `Remove unnecessary accounts from the "${info.name}" user right.`,
              steps: [
                'Open Group Policy Management Console',
                'Navigate to Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment',
                `Edit "${info.name}" and remove: ${extraAssignees.join(', ')}`,
              ],
              powershell: extraAssignees.map((a) =>
                `Remove-AccountFromUserRight -Account "${a}" -Right "${privilege}"`
              ).join('\n'),
              impact: 'Affected accounts will lose the specified privilege.',
              automatable: true,
            },
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Analyze security options in GPOs.
   */
  async _analyzeSecurityOptions(gpoData, benchmarkIds) {
    const findings = [];
    const secOpts = gpoData.securityOptions || {};

    for (const benchmarkId of benchmarkIds) {
      const benchmark = this.benchmarks[benchmarkId];
      if (!benchmark || !benchmark.securityOptions) continue;
      const bs = benchmark.securityOptions;

      // LM Hash Storage
      if (secOpts.lmHashStorage !== false && bs.lmHashStorage === false) {
        findings.push(this._createFinding({
          title: 'LM Hash Storage Not Disabled',
          description: 'LM password hashes are being stored. LM hashes are cryptographically weak and easily cracked.',
          severity: 'Critical',
          category: 'gpo',
          subcategory: 'security-options',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-SO-LMH`,
          currentValue: true,
          recommendedValue: false,
          remediation: {
            description: 'Disable LM hash storage.',
            steps: [
              'Navigate to Security Options in Group Policy',
              'Enable "Network security: Do not store LAN Manager hash value on next password change"',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "NoLMHash" -Value 1',
            impact: 'Very old clients (Windows 95/98) will not be able to authenticate.',
            automatable: true,
          },
        }));
      }

      // LAN Manager Authentication Level
      if (secOpts.lanManagerAuth !== undefined && secOpts.lanManagerAuth < (bs.lanManagerAuth || 5)) {
        const authLevels = [
          'Send LM & NTLM responses',
          'Send LM & NTLM - use NTLMv2 if negotiated',
          'Send NTLM response only',
          'Send NTLMv2 response only',
          'Send NTLMv2 response only. Refuse LM',
          'Send NTLMv2 response only. Refuse LM & NTLM',
        ];
        findings.push(this._createFinding({
          title: 'Weak LAN Manager Authentication Level',
          description: `LAN Manager authentication level is set to ${secOpts.lanManagerAuth} (${authLevels[secOpts.lanManagerAuth]}). ${benchmarkId} recommends level ${bs.lanManagerAuth} (${authLevels[bs.lanManagerAuth]}).`,
          severity: secOpts.lanManagerAuth < 3 ? 'Critical' : 'High',
          category: 'gpo',
          subcategory: 'security-options',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-SO-LMA`,
          currentValue: secOpts.lanManagerAuth,
          recommendedValue: bs.lanManagerAuth,
          remediation: {
            description: 'Increase LAN Manager authentication level to NTLMv2 only.',
            steps: [
              'Navigate to Security Options in Group Policy',
              `Set "Network security: LAN Manager authentication level" to level ${bs.lanManagerAuth}`,
            ],
            powershell: `Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -Value ${bs.lanManagerAuth}`,
            impact: 'Older clients that cannot negotiate NTLMv2 will fail authentication.',
            automatable: true,
          },
        }));
      }

      // SMB Signing
      if (bs.smbSigning && !secOpts.smbSigning) {
        findings.push(this._createFinding({
          title: 'SMB Signing Not Required',
          description: 'SMB packet signing is not required. This allows man-in-the-middle attacks on SMB communications.',
          severity: 'High',
          category: 'gpo',
          subcategory: 'security-options',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-SO-SMB`,
          currentValue: false,
          recommendedValue: true,
          remediation: {
            description: 'Require SMB signing for all connections.',
            steps: [
              'Navigate to Security Options in Group Policy',
              'Enable "Microsoft network server: Digitally sign communications (always)"',
              'Enable "Microsoft network client: Digitally sign communications (always)"',
            ],
            powershell: [
              'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1',
              'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "RequireSecuritySignature" -Value 1',
            ].join('\n'),
            impact: 'Small performance impact on SMB operations.',
            automatable: true,
          },
        }));
      }

      // LDAP Signing
      if (bs.ldapSigning && (!secOpts.ldapSigning || secOpts.ldapSigning < bs.ldapSigning)) {
        findings.push(this._createFinding({
          title: 'LDAP Signing Not Required',
          description: 'LDAP signing is not required on domain controllers. This enables LDAP relay attacks.',
          severity: 'High',
          category: 'gpo',
          subcategory: 'security-options',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-SO-LDAP`,
          currentValue: secOpts.ldapSigning || 0,
          recommendedValue: bs.ldapSigning,
          remediation: {
            description: 'Require LDAP signing on all domain controllers.',
            steps: [
              'Navigate to Security Options in Group Policy (DC policy)',
              'Set "Domain controller: LDAP server signing requirements" to "Require signing"',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" -Name "LDAPServerIntegrity" -Value 2',
            impact: 'Clients that do not support LDAP signing will fail to bind.',
            automatable: true,
          },
        }));
      }

      // Anonymous access
      if (bs.anonymousEnumeration === false && secOpts.anonymousEnumeration !== false) {
        findings.push(this._createFinding({
          title: 'Anonymous Enumeration of SAM Accounts Allowed',
          description: 'Anonymous users can enumerate SAM accounts and shares. This aids reconnaissance attacks.',
          severity: 'High',
          category: 'gpo',
          subcategory: 'security-options',
          benchmark: benchmarkId,
          controlId: `${benchmarkId}-SO-ANON`,
          currentValue: true,
          recommendedValue: false,
          remediation: {
            description: 'Disable anonymous enumeration of SAM accounts.',
            steps: [
              'Navigate to Security Options in Group Policy',
              'Enable "Network access: Do not allow anonymous enumeration of SAM accounts"',
              'Enable "Network access: Do not allow anonymous enumeration of SAM accounts and shares"',
            ],
            powershell: [
              'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymousSAM" -Value 1',
              'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymous" -Value 1',
            ].join('\n'),
            impact: 'Applications relying on anonymous access may need reconfiguration.',
            automatable: true,
          },
        }));
      }
    }

    return findings;
  }

  /**
   * Analyze administrative templates in GPOs.
   */
  async _analyzeAdministrativeTemplates(gpoData, benchmarkIds) {
    const findings = [];
    const templates = gpoData.administrativeTemplates || {};

    // Check for common misconfigurations in admin templates
    const checks = [
      {
        setting: templates.autoplay,
        condition: (v) => v !== false && v !== 'disabled',
        finding: {
          title: 'AutoPlay Not Disabled',
          description: 'AutoPlay/AutoRun is not disabled via GPO. Malware can spread via removable media.',
          severity: 'Medium',
          subcategory: 'admin-templates',
          remediation: {
            description: 'Disable AutoPlay for all drives.',
            steps: [
              'Navigate to Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies',
              'Enable "Turn off Autoplay" and set to "All drives"',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 255',
            automatable: true,
          },
        },
      },
      {
        setting: templates.wdigest,
        condition: (v) => v !== false && v !== 0,
        finding: {
          title: 'WDigest Authentication Enabled',
          description: 'WDigest authentication stores plaintext credentials in memory, enabling credential theft via tools like Mimikatz.',
          severity: 'Critical',
          subcategory: 'admin-templates',
          remediation: {
            description: 'Disable WDigest authentication.',
            steps: [
              'Deploy registry setting via GPO Preferences',
              'Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Name "UseLogonCredential" -Value 0',
            automatable: true,
          },
        },
      },
      {
        setting: templates.lsaProtection,
        condition: (v) => v !== true && v !== 1,
        finding: {
          title: 'LSA Protection Not Enabled',
          description: 'LSA protection (RunAsPPL) is not enabled. Credential dumping tools can access LSASS process memory.',
          severity: 'High',
          subcategory: 'admin-templates',
          remediation: {
            description: 'Enable LSA protection.',
            steps: [
              'Deploy registry setting via GPO Preferences',
              'Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1',
            automatable: true,
          },
        },
      },
      {
        setting: templates.remoteDesktopNla,
        condition: (v) => v !== true && v !== 1,
        finding: {
          title: 'Network Level Authentication Not Required for RDP',
          description: 'Network Level Authentication (NLA) is not required for Remote Desktop connections, increasing risk of brute-force attacks.',
          severity: 'High',
          subcategory: 'admin-templates',
          remediation: {
            description: 'Require NLA for Remote Desktop.',
            steps: [
              'Navigate to Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security',
              'Enable "Require user authentication for remote connections by using NLA"',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1',
            automatable: true,
          },
        },
      },
      {
        setting: templates.powershellLogging,
        condition: (v) => v !== true && v !== 1,
        finding: {
          title: 'PowerShell Script Block Logging Not Enabled',
          description: 'PowerShell script block logging is disabled. Malicious scripts will not be logged for forensic analysis.',
          severity: 'Medium',
          subcategory: 'admin-templates',
          remediation: {
            description: 'Enable PowerShell script block logging.',
            steps: [
              'Navigate to Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell',
              'Enable "Turn on PowerShell Script Block Logging"',
            ],
            powershell: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1',
            automatable: true,
          },
        },
      },
    ];

    for (const check of checks) {
      if (check.condition(check.setting)) {
        findings.push(this._createFinding({
          ...check.finding,
          category: 'gpo',
          benchmark: benchmarkIds[0],
          controlId: `${benchmarkIds[0]}-AT-${check.finding.title.substring(0, 3).toUpperCase()}`,
          remediation: {
            ...check.finding.remediation,
            impact: 'May affect legacy applications or workflows.',
          },
        }));
      }
    }

    return findings;
  }

  // --- Utility methods ---

  _createFinding(params) {
    return {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      title: params.title,
      description: params.description,
      severity: params.severity || 'Medium',
      category: params.category || 'gpo',
      subcategory: params.subcategory || 'general',
      benchmark: params.benchmark || null,
      controlId: params.controlId || null,
      currentValue: params.currentValue !== undefined ? params.currentValue : null,
      recommendedValue: params.recommendedValue !== undefined ? params.recommendedValue : null,
      affectedObjects: params.affectedObjects || [],
      remediation: params.remediation || null,
      riskScore: this._calculateRiskScore(params.severity),
      status: 'open',
    };
  }

  _calculateRiskScore(severity) {
    const scores = { Critical: 10, High: 8, Medium: 5, Low: 2 };
    return scores[severity] || 5;
  }

  _buildSummary(findings) {
    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const bySubcategory = {};

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      bySubcategory[f.subcategory] = (bySubcategory[f.subcategory] || 0) + 1;
    }

    const totalScore = findings.reduce((sum, f) => sum + f.riskScore, 0);
    const maxPossibleScore = findings.length * 10;

    return {
      totalFindings: findings.length,
      bySeverity,
      bySubcategory,
      riskScore: totalScore,
      maxScore: maxPossibleScore,
      riskPercentage: maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0,
    };
  }

  _auditSettingMeetsRequirement(current, required) {
    if (!current || current === 'No Auditing') return false;
    const currentParts = current.split(',').map((s) => s.trim().toLowerCase());
    const requiredParts = required.split(',').map((s) => s.trim().toLowerCase());
    return requiredParts.every((r) => currentParts.includes(r));
  }

  _formatCategoryName(category) {
    return category.replace(/([A-Z])/g, ' $1').replace(/^./, (s) => s.toUpperCase()).trim();
  }

  _capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  _getAffectedGPOs(gpoData, policyType) {
    const gpos = gpoData.policies || [];
    return gpos
      .filter((g) => g.settings && g.settings.includes(policyType))
      .map((g) => ({ type: 'gpo', name: g.name, id: g.id }));
  }

  _getFirewallRuleSeverity(rule) {
    const highRiskPorts = ['3389', '22', '445', '135', '139', '1433', '3306', '5432', '23'];
    if (!rule.localPort || rule.localPort === '*' || rule.localPort === 'Any') return 'Critical';
    const ports = String(rule.localPort).split(',').map((p) => p.trim());
    if (ports.some((p) => highRiskPorts.includes(p))) return 'Critical';
    return 'High';
  }

  _getDefaultPasswordPolicy() {
    return {
      minLength: 7,
      maxAge: 42,
      minAge: 1,
      historySize: 12,
      complexity: true,
      reversibleEncryption: false,
      lockoutThreshold: 0,
      lockoutDuration: 30,
      lockoutWindow: 30,
    };
  }

  _getDefaultAuditPolicy() {
    return {
      accountLogon: 'No Auditing',
      accountManagement: 'Success',
      logonEvents: 'Success',
      objectAccess: 'No Auditing',
      policyChange: 'No Auditing',
      privilegeUse: 'No Auditing',
      processTracking: 'No Auditing',
      systemEvents: 'No Auditing',
      dsAccess: 'No Auditing',
    };
  }

  _getDefaultFirewallPolicy() {
    return {
      domainProfileEnabled: true,
      privateProfileEnabled: true,
      publicProfileEnabled: false,
      inboundDefaultBlock: false,
      outboundDefaultAllow: true,
      rules: [],
    };
  }
}

module.exports = GPOAnalyzer;
