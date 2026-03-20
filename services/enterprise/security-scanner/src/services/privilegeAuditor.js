'use strict';

const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

/**
 * Privilege Auditor - Audits privilege escalation risks in Active Directory.
 * Detects excessive admin group membership, nested group abuse, stale privileged
 * accounts, Kerberoastable accounts, delegation misconfigurations, and more.
 */
class PrivilegeAuditor extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logger = options.logger || console;

    // Well-known privileged groups (SID-based for reliability)
    this.privilegedGroups = {
      'S-1-5-32-544': { name: 'Administrators', tier: 0, risk: 'Critical' },
      'S-1-5-21-*-512': { name: 'Domain Admins', tier: 0, risk: 'Critical' },
      'S-1-5-21-*-519': { name: 'Enterprise Admins', tier: 0, risk: 'Critical' },
      'S-1-5-21-*-518': { name: 'Schema Admins', tier: 0, risk: 'Critical' },
      'S-1-5-32-548': { name: 'Account Operators', tier: 1, risk: 'High' },
      'S-1-5-32-549': { name: 'Server Operators', tier: 1, risk: 'High' },
      'S-1-5-32-550': { name: 'Print Operators', tier: 2, risk: 'Medium' },
      'S-1-5-32-551': { name: 'Backup Operators', tier: 1, risk: 'High' },
      'S-1-5-21-*-520': { name: 'Group Policy Creator Owners', tier: 1, risk: 'High' },
      'S-1-5-32-552': { name: 'Replicator', tier: 1, risk: 'High' },
      'S-1-5-21-*-527': { name: 'Key Admins', tier: 1, risk: 'High' },
      'S-1-5-21-*-526': { name: 'Enterprise Key Admins', tier: 0, risk: 'Critical' },
    };

    // Maximum recommended members for privileged groups
    this.groupSizeLimits = {
      'Domain Admins': 5,
      'Enterprise Admins': 3,
      'Schema Admins': 0, // Should be empty when not in use
      'Administrators': 5,
      'Account Operators': 3,
      'Server Operators': 3,
      'Backup Operators': 3,
    };

    // Dangerous delegation types
    this.dangerousDelegations = [
      'Unconstrained',
      'ConstrainedWithProtocolTransition',
    ];
  }

  /**
   * Run full privilege audit.
   * @param {Object} adData - Active Directory data
   * @param {Function} onProgress - Progress callback
   * @returns {Object} Audit results with findings
   */
  async audit(adData, onProgress) {
    const findings = [];
    const steps = [
      { name: 'groupMembership', method: '_auditGroupMembership', weight: 20 },
      { name: 'nestedGroups', method: '_auditNestedGroups', weight: 15 },
      { name: 'staleAccounts', method: '_auditStalePrivilegedAccounts', weight: 15 },
      { name: 'kerberoasting', method: '_auditKerberoastableAccounts', weight: 10 },
      { name: 'delegation', method: '_auditDelegation', weight: 15 },
      { name: 'adminSdHolder', method: '_auditAdminSdHolder', weight: 10 },
      { name: 'serviceAccounts', method: '_auditServiceAccounts', weight: 10 },
      { name: 'shadowAdmins', method: '_auditShadowAdmins', weight: 5 },
    ];

    let completedWeight = 0;

    for (const step of steps) {
      if (onProgress) {
        onProgress(completedWeight, `Auditing ${step.name}...`);
      }

      this.emit('progress', {
        phase: 'privilege-audit',
        step: step.name,
        progress: completedWeight,
      });

      try {
        const stepFindings = await this[step.method](adData);
        findings.push(...stepFindings);
      } catch (err) {
        this.logger.error(`Error auditing ${step.name}:`, err.message);
        findings.push(this._createFinding({
          title: `Privilege Audit Error: ${step.name}`,
          description: `Failed to audit ${step.name}: ${err.message}`,
          severity: 'Medium',
          subcategory: step.name,
        }));
      }

      completedWeight += step.weight;
    }

    if (onProgress) {
      onProgress(100, 'Privilege audit complete');
    }

    return {
      analyzer: 'privilege',
      timestamp: new Date().toISOString(),
      findings,
      summary: this._buildSummary(findings),
      escalationPaths: this._buildEscalationGraph(findings),
    };
  }

  /**
   * Audit privileged group membership for excess.
   */
  async _auditGroupMembership(adData) {
    const findings = [];
    const groups = adData.groups || [];
    const users = adData.users || [];

    for (const group of groups) {
      if (!this._isPrivilegedGroup(group.name)) continue;

      const members = group.members || [];
      const limit = this.groupSizeLimits[group.name];

      // Check for too many members
      if (limit !== undefined && members.length > limit) {
        findings.push(this._createFinding({
          title: `Excessive Members in ${group.name}`,
          description: `${group.name} has ${members.length} members, exceeding the recommended maximum of ${limit}. Large privileged groups increase the attack surface and risk of compromise.`,
          severity: group.name.includes('Enterprise') || group.name.includes('Schema') ? 'Critical' : 'High',
          subcategory: 'group-membership',
          currentValue: members.length,
          recommendedValue: limit,
          affectedObjects: members.map((m) => ({
            type: 'user',
            name: m.name || m,
            distinguishedName: m.distinguishedName || null,
          })),
          remediation: {
            description: `Review and reduce membership of ${group.name} to essential personnel only.`,
            steps: [
              `Open Active Directory Users and Computers`,
              `Navigate to ${group.name} group`,
              'Review each member and determine if they need permanent membership',
              'Consider using just-in-time privileged access instead',
              'Remove unnecessary members',
            ],
            powershell: `# List current members\nGet-ADGroupMember -Identity "${group.name}" | Select-Object Name, SamAccountName, ObjectClass\n\n# Remove a specific member\n# Remove-ADGroupMember -Identity "${group.name}" -Members "<username>" -Confirm:$false`,
            impact: 'Removed users will lose administrative privileges. Ensure alternative access methods are in place.',
            automatable: false,
          },
        }));
      }

      // Check for non-human accounts in privileged groups
      const serviceAccountMembers = members.filter((m) => {
        const name = (m.name || m).toLowerCase();
        return name.startsWith('svc') || name.startsWith('sa-') || name.includes('service') ||
               name.includes('admin') && !name.includes('administrator');
      });

      if (serviceAccountMembers.length > 0) {
        findings.push(this._createFinding({
          title: `Service Accounts in ${group.name}`,
          description: `${serviceAccountMembers.length} service account(s) found in ${group.name}. Service accounts in privileged groups present a high risk if compromised, as they often have weak or static passwords.`,
          severity: 'High',
          subcategory: 'group-membership',
          affectedObjects: serviceAccountMembers.map((m) => ({
            type: 'service-account',
            name: m.name || m,
          })),
          remediation: {
            description: 'Remove service accounts from privileged groups and use least-privilege delegation.',
            steps: [
              'Identify the specific permissions each service account needs',
              'Create custom delegated permissions or use Group Managed Service Accounts (gMSA)',
              `Remove service accounts from ${group.name}`,
              'Test services after permission changes',
            ],
            powershell: `# Identify service accounts in the group\nGet-ADGroupMember "${group.name}" | Where-Object {$_.SamAccountName -like "svc*" -or $_.SamAccountName -like "sa-*"}`,
            impact: 'Services may fail if not reconfigured with appropriate delegated permissions.',
            automatable: false,
          },
        }));
      }

      // Users in multiple privileged groups
      for (const member of members) {
        const memberName = member.name || member;
        const memberGroups = this._getUserPrivilegedGroups(memberName, groups);
        if (memberGroups.length > 2) {
          findings.push(this._createFinding({
            title: `User in Multiple Privileged Groups: ${memberName}`,
            description: `${memberName} is a member of ${memberGroups.length} privileged groups: ${memberGroups.join(', ')}. This violates the principle of least privilege and increases blast radius if the account is compromised.`,
            severity: 'High',
            subcategory: 'group-membership',
            affectedObjects: [{ type: 'user', name: memberName, groups: memberGroups }],
            remediation: {
              description: `Review ${memberName}'s group memberships and reduce to the minimum required.`,
              steps: [
                `Review the actual administrative needs of ${memberName}`,
                'Determine which single group membership is most appropriate',
                'Remove membership from all other privileged groups',
                'Consider implementing role-based access control with separate admin accounts',
              ],
              powershell: `# List all privileged group memberships for this user\nGet-ADUser "${memberName}" -Properties MemberOf | Select-Object -ExpandProperty MemberOf | Get-ADGroup | Where-Object {$_.Name -in @(${memberGroups.map((g) => `"${g}"`).join(',')})}`,
              impact: 'User may lose some administrative capabilities.',
              automatable: false,
            },
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Audit nested group abuse that could lead to privilege escalation.
   */
  async _auditNestedGroups(adData) {
    const findings = [];
    const groups = adData.groups || [];

    for (const group of groups) {
      if (!this._isPrivilegedGroup(group.name)) continue;

      const nestedGroups = (group.members || []).filter(
        (m) => (m.objectClass || m.type) === 'group'
      );

      if (nestedGroups.length > 0) {
        // Check nesting depth
        for (const nested of nestedGroups) {
          const depth = this._calculateNestingDepth(nested.name || nested, groups, 0);

          if (depth > 2) {
            findings.push(this._createFinding({
              title: `Deep Group Nesting in ${group.name}`,
              description: `Group "${nested.name || nested}" is nested in ${group.name} with a nesting depth of ${depth}. Deep nesting obscures effective membership and makes privilege auditing difficult.`,
              severity: 'High',
              subcategory: 'nested-groups',
              affectedObjects: [
                { type: 'group', name: group.name, role: 'parent' },
                { type: 'group', name: nested.name || nested, role: 'nested', depth },
              ],
              remediation: {
                description: 'Flatten nested group hierarchies in privileged groups.',
                steps: [
                  `Map the full nesting chain from "${nested.name || nested}" to "${group.name}"`,
                  'Identify the effective users gaining privileges through nesting',
                  'Add required users directly to the appropriate group',
                  'Remove the nested group membership',
                ],
                powershell: `# View effective nested members\nGet-ADGroupMember "${group.name}" -Recursive | Select-Object Name, SamAccountName, ObjectClass`,
                impact: 'Users gaining access through nesting may lose privileges.',
                automatable: false,
              },
            }));
          }

          // Check if non-privileged group is nested in privileged group
          if (!this._isPrivilegedGroup(nested.name || nested)) {
            const effectiveMembers = this._getEffectiveMembers(nested.name || nested, groups);
            if (effectiveMembers.length > 0) {
              findings.push(this._createFinding({
                title: `Non-Privileged Group Nested in ${group.name}`,
                description: `Non-privileged group "${nested.name || nested}" (${effectiveMembers.length} effective members) is nested in ${group.name}. All members of this group inherit administrative privileges, which may not be intended.`,
                severity: 'High',
                subcategory: 'nested-groups',
                affectedObjects: [
                  { type: 'group', name: nested.name || nested, memberCount: effectiveMembers.length },
                ],
                remediation: {
                  description: `Remove "${nested.name || nested}" from ${group.name} and add only required users directly.`,
                  steps: [
                    `List effective members: Get-ADGroupMember "${nested.name || nested}" -Recursive`,
                    'Determine which users actually need privileges',
                    `Remove "${nested.name || nested}" from ${group.name}`,
                    'Add only required users directly',
                  ],
                  powershell: `Remove-ADGroupMember -Identity "${group.name}" -Members "${nested.name || nested}" -Confirm:$false`,
                  impact: 'All effective members of the nested group will lose privileges.',
                  automatable: false,
                },
              }));
            }
          }
        }
      }
    }

    return findings;
  }

  /**
   * Audit stale privileged accounts (no recent logon, disabled, expired).
   */
  async _auditStalePrivilegedAccounts(adData) {
    const findings = [];
    const groups = adData.groups || [];
    const staleThresholdDays = 90;
    const now = new Date();

    for (const group of groups) {
      if (!this._isPrivilegedGroup(group.name)) continue;

      for (const member of (group.members || [])) {
        if ((member.objectClass || member.type) === 'group') continue;

        const memberName = member.name || member;
        const lastLogon = member.lastLogon ? new Date(member.lastLogon) : null;
        const daysSinceLogon = lastLogon
          ? Math.floor((now - lastLogon) / (1000 * 60 * 60 * 24))
          : Infinity;

        // Stale account
        if (daysSinceLogon > staleThresholdDays) {
          findings.push(this._createFinding({
            title: `Stale Privileged Account: ${memberName}`,
            description: `${memberName} is a member of ${group.name} but has not logged in for ${daysSinceLogon === Infinity ? 'an unknown period' : daysSinceLogon + ' days'}. Stale privileged accounts are prime targets for credential theft.`,
            severity: 'High',
            subcategory: 'stale-accounts',
            affectedObjects: [{
              type: 'user',
              name: memberName,
              lastLogon: member.lastLogon || 'Never',
              group: group.name,
            }],
            remediation: {
              description: `Remove ${memberName} from ${group.name} or verify the account is still needed.`,
              steps: [
                `Verify with the account owner if ${memberName} still requires privileges`,
                `If not needed, remove from ${group.name}`,
                'If the account is no longer used, disable it',
                'Consider implementing privileged access expiration policies',
              ],
              powershell: `# Check last logon\nGet-ADUser "${memberName}" -Properties LastLogonDate | Select-Object Name, LastLogonDate\n\n# Remove from group if stale\n# Remove-ADGroupMember -Identity "${group.name}" -Members "${memberName}" -Confirm:$false`,
              impact: 'Removed user will lose administrative access.',
              automatable: true,
            },
          }));
        }

        // Disabled account still in privileged group
        if (member.enabled === false || member.disabled === true) {
          findings.push(this._createFinding({
            title: `Disabled Account in ${group.name}: ${memberName}`,
            description: `${memberName} is disabled but remains a member of ${group.name}. If re-enabled, it would immediately have administrative privileges.`,
            severity: 'Medium',
            subcategory: 'stale-accounts',
            affectedObjects: [{
              type: 'user',
              name: memberName,
              status: 'disabled',
              group: group.name,
            }],
            remediation: {
              description: `Remove disabled account ${memberName} from ${group.name}.`,
              steps: [
                `Remove ${memberName} from ${group.name}`,
                'Update off-boarding procedures to include privileged group cleanup',
              ],
              powershell: `Remove-ADGroupMember -Identity "${group.name}" -Members "${memberName}" -Confirm:$false`,
              impact: 'None - account is already disabled.',
              automatable: true,
            },
          }));
        }

        // Password never expires on privileged account
        if (member.passwordNeverExpires === true) {
          findings.push(this._createFinding({
            title: `Privileged Account with Non-Expiring Password: ${memberName}`,
            description: `${memberName} (member of ${group.name}) has a password set to never expire. Privileged accounts should have regular password rotation.`,
            severity: 'High',
            subcategory: 'stale-accounts',
            affectedObjects: [{
              type: 'user',
              name: memberName,
              group: group.name,
            }],
            remediation: {
              description: 'Remove the "password never expires" flag and implement password rotation.',
              steps: [
                `Edit ${memberName} account properties`,
                'Uncheck "Password never expires"',
                'Consider implementing a PAM solution for privileged password management',
              ],
              powershell: `Set-ADUser "${memberName}" -PasswordNeverExpires $false`,
              impact: 'User will need to change password per domain password policy.',
              automatable: true,
            },
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Identify Kerberoastable accounts with elevated privileges.
   */
  async _auditKerberoastableAccounts(adData) {
    const findings = [];
    const users = adData.users || [];

    for (const user of users) {
      // Kerberoastable = has SPN set and is a regular user account
      if (!user.servicePrincipalNames || user.servicePrincipalNames.length === 0) continue;
      if (user.objectClass === 'computer' || user.objectClass === 'msDS-ManagedServiceAccount') continue;

      const isPrivileged = this._isUserPrivileged(user.name || user.samAccountName, adData.groups || []);
      const hasWeakEncryption = !user.supportedEncryptionTypes ||
        (user.supportedEncryptionTypes & 0x18) === 0; // No AES support

      if (isPrivileged || hasWeakEncryption) {
        findings.push(this._createFinding({
          title: `Kerberoastable ${isPrivileged ? 'Privileged ' : ''}Account: ${user.name || user.samAccountName}`,
          description: `User account "${user.name || user.samAccountName}" has SPN(s) set (${user.servicePrincipalNames.join(', ')}), making it vulnerable to Kerberoasting attacks.${isPrivileged ? ' This account has elevated privileges, making it a high-value target.' : ''}${hasWeakEncryption ? ' The account uses RC4 encryption, which is easily cracked.' : ''}`,
          severity: isPrivileged ? 'Critical' : (hasWeakEncryption ? 'High' : 'Medium'),
          subcategory: 'kerberoasting',
          affectedObjects: [{
            type: 'user',
            name: user.name || user.samAccountName,
            spns: user.servicePrincipalNames,
            privileged: isPrivileged,
            encryptionType: hasWeakEncryption ? 'RC4' : 'AES',
          }],
          remediation: {
            description: 'Mitigate Kerberoasting risk for this account.',
            steps: [
              'If the SPN is not needed, remove it from the user account',
              'If the SPN is needed, convert to a Group Managed Service Account (gMSA)',
              'If conversion is not possible, set a long (30+ character) random password',
              'Enable AES encryption types for the account',
              'Monitor for Kerberos TGS requests (Event ID 4769) targeting this SPN',
            ],
            powershell: [
              `# Remove unnecessary SPNs`,
              `# Set-ADUser "${user.name || user.samAccountName}" -ServicePrincipalNames @{Remove="${user.servicePrincipalNames[0]}"}`,
              ``,
              `# Enable AES encryption`,
              `Set-ADUser "${user.name || user.samAccountName}" -KerberosEncryptionType AES128,AES256`,
              ``,
              `# Or convert to gMSA`,
              `# New-ADServiceAccount -Name "${user.name || user.samAccountName}-gmsa" -DNSHostName "${user.name || user.samAccountName}.domain.com" -ManagedPasswordIntervalInDays 30`,
            ].join('\n'),
            impact: 'Service may need reconfiguration if SPN is removed or account is converted to gMSA.',
            automatable: false,
          },
        }));
      }
    }

    return findings;
  }

  /**
   * Audit delegation configurations for security risks.
   */
  async _auditDelegation(adData) {
    const findings = [];
    const accounts = [...(adData.users || []), ...(adData.computers || [])];

    for (const account of accounts) {
      const name = account.name || account.samAccountName;

      // Unconstrained delegation
      if (account.trustedForDelegation === true) {
        const isPrivileged = account.objectClass !== 'computer' &&
          this._isUserPrivileged(name, adData.groups || []);

        findings.push(this._createFinding({
          title: `Unconstrained Delegation: ${name}`,
          description: `${account.objectClass === 'computer' ? 'Computer' : 'User'} "${name}" is configured for unconstrained Kerberos delegation. Any user authenticating to this system will have their TGT cached, allowing impersonation of that user to any service.`,
          severity: 'Critical',
          subcategory: 'delegation',
          affectedObjects: [{
            type: account.objectClass || 'account',
            name,
            delegationType: 'Unconstrained',
            privileged: isPrivileged,
          }],
          remediation: {
            description: 'Replace unconstrained delegation with constrained delegation or resource-based constrained delegation.',
            steps: [
              `Identify which services ${name} needs to delegate to`,
              'Configure constrained delegation with only required services',
              'Remove the "Trust this computer/user for delegation to any service" setting',
              'Test all dependent services',
            ],
            powershell: [
              `# View current delegation settings`,
              `Get-ADObject "${name}" -Properties TrustedForDelegation, msDS-AllowedToDelegateTo`,
              ``,
              `# Remove unconstrained delegation`,
              `Set-ADAccountControl -Identity "${name}" -TrustedForDelegation $false`,
              ``,
              `# Configure constrained delegation instead`,
              `# Set-ADObject "${name}" -Add @{'msDS-AllowedToDelegateTo'=@('service/target.domain.com')}`,
            ].join('\n'),
            impact: 'Services relying on delegation may fail until constrained delegation is configured.',
            automatable: false,
          },
        }));
      }

      // Constrained delegation with protocol transition
      if (account.trustedToAuthForDelegation === true) {
        findings.push(this._createFinding({
          title: `Protocol Transition Delegation: ${name}`,
          description: `"${name}" is configured for constrained delegation with protocol transition (S4U2Self). This allows the account to impersonate any user to the configured services without the user authenticating first.`,
          severity: 'High',
          subcategory: 'delegation',
          affectedObjects: [{
            type: account.objectClass || 'account',
            name,
            delegationType: 'ConstrainedWithProtocolTransition',
            allowedServices: account.allowedToDelegateTo || [],
          }],
          remediation: {
            description: 'Review if protocol transition is truly required; prefer delegation without protocol transition.',
            steps: [
              'Determine if the service truly needs to impersonate users without their direct authentication',
              'If not needed, disable protocol transition',
              'If needed, restrict the allowed target services to the minimum required',
              'Monitor delegation events (Event IDs 4768, 4769)',
            ],
            powershell: `# Disable protocol transition\nSet-ADAccountControl -Identity "${name}" -TrustedToAuthForDelegation $false`,
            impact: 'Services using protocol transition may fail.',
            automatable: false,
          },
        }));
      }
    }

    return findings;
  }

  /**
   * Audit AdminSDHolder protected objects.
   */
  async _auditAdminSdHolder(adData) {
    const findings = [];
    const users = adData.users || [];

    for (const user of users) {
      // adminCount = 1 but not currently in privileged group
      if (user.adminCount === 1) {
        const isCurrentlyPrivileged = this._isUserPrivileged(
          user.name || user.samAccountName,
          adData.groups || []
        );

        if (!isCurrentlyPrivileged) {
          findings.push(this._createFinding({
            title: `Orphaned AdminSDHolder Protection: ${user.name || user.samAccountName}`,
            description: `User "${user.name || user.samAccountName}" has adminCount=1 but is not currently a member of any protected group. This indicates the account was previously privileged. The AdminSDHolder ACL is still applied, which may prevent proper permission inheritance.`,
            severity: 'Medium',
            subcategory: 'adminSdHolder',
            affectedObjects: [{
              type: 'user',
              name: user.name || user.samAccountName,
              adminCount: 1,
              currentlyPrivileged: false,
            }],
            remediation: {
              description: 'Clear the adminCount attribute and reset permissions inheritance.',
              steps: [
                `Set adminCount to 0 for ${user.name || user.samAccountName}`,
                'Re-enable permission inheritance on the user object',
                'Run SDProp to verify the fix (wait for AdminSDHolder cycle or force it)',
              ],
              powershell: [
                `# Clear adminCount`,
                `Set-ADUser "${user.name || user.samAccountName}" -Replace @{adminCount=0}`,
                ``,
                `# Re-enable inheritance (requires AD module and DSACLS)`,
                `$dn = (Get-ADUser "${user.name || user.samAccountName}").DistinguishedName`,
                `dsacls $dn /resetDefaultDACL`,
              ].join('\n'),
              impact: 'Permissions on the account will return to inherited defaults.',
              automatable: true,
            },
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Audit service accounts for security risks.
   */
  async _auditServiceAccounts(adData) {
    const findings = [];
    const users = adData.users || [];

    for (const user of users) {
      const name = (user.name || user.samAccountName || '').toLowerCase();
      const isServiceAccount = name.startsWith('svc') || name.startsWith('sa-') ||
        name.includes('service') || user.objectClass === 'msDS-ManagedServiceAccount' ||
        user.objectClass === 'msDS-GroupManagedServiceAccount';

      if (!isServiceAccount) continue;

      // Service account with interactive logon allowed
      if (user.userAccountControl && !(user.userAccountControl & 0x200000)) {
        // Not a managed service account, check for bad practices
        if (user.logonWorkstations === undefined || user.logonWorkstations === null) {
          findings.push(this._createFinding({
            title: `Service Account Without Logon Restriction: ${user.name || user.samAccountName}`,
            description: `Service account "${user.name || user.samAccountName}" is not restricted to specific logon workstations. This allows the account to be used for interactive logon from any computer if credentials are compromised.`,
            severity: 'Medium',
            subcategory: 'service-accounts',
            affectedObjects: [{ type: 'service-account', name: user.name || user.samAccountName }],
            remediation: {
              description: 'Restrict service account logon to required servers only.',
              steps: [
                'Identify which servers this service account runs on',
                'Set the "Log On To" list to only those servers',
                'Consider converting to a Group Managed Service Account (gMSA)',
              ],
              powershell: `Set-ADUser "${user.name || user.samAccountName}" -LogonWorkstations "server1,server2"`,
              impact: 'Service account can only log on to specified workstations.',
              automatable: false,
            },
          }));
        }

        // Old password on service account
        const passwordAge = user.passwordLastSet
          ? Math.floor((new Date() - new Date(user.passwordLastSet)) / (1000 * 60 * 60 * 24))
          : Infinity;

        if (passwordAge > 365) {
          findings.push(this._createFinding({
            title: `Service Account with Old Password: ${user.name || user.samAccountName}`,
            description: `Service account "${user.name || user.samAccountName}" has not had its password changed in ${passwordAge === Infinity ? 'an unknown period' : passwordAge + ' days'}. Long-lived service account passwords increase the window for credential theft.`,
            severity: 'High',
            subcategory: 'service-accounts',
            affectedObjects: [{
              type: 'service-account',
              name: user.name || user.samAccountName,
              passwordAgeDays: passwordAge,
            }],
            remediation: {
              description: 'Rotate the service account password and consider converting to gMSA.',
              steps: [
                'Schedule a maintenance window',
                'Change the service account password',
                'Update all services using this account',
                'Consider converting to a Group Managed Service Account for automatic rotation',
              ],
              powershell: `# Convert to gMSA\nNew-ADServiceAccount -Name "${user.name || user.samAccountName}-gmsa" -DNSHostName "${user.name || user.samAccountName}.domain.com" -PrincipalsAllowedToRetrieveManagedPassword "ServerGroup$" -ManagedPasswordIntervalInDays 30`,
              impact: 'Services will need to be updated with the new password or gMSA configuration.',
              automatable: false,
            },
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Detect shadow admin paths - users who can modify privileged group membership.
   */
  async _auditShadowAdmins(adData) {
    const findings = [];
    const aclData = adData.acls || [];

    for (const acl of aclData) {
      // Look for non-admin users with write access to privileged group objects
      if (!this._isPrivilegedGroup(acl.objectName)) continue;

      const dangerousPermissions = (acl.accessControlEntries || []).filter((ace) => {
        const isWriteAccess = ace.rights && (
          ace.rights.includes('WriteProperty') ||
          ace.rights.includes('WriteDacl') ||
          ace.rights.includes('WriteOwner') ||
          ace.rights.includes('GenericAll') ||
          ace.rights.includes('GenericWrite')
        );
        const isNonStandard = ace.principal &&
          ace.principal !== 'Domain Admins' &&
          ace.principal !== 'Enterprise Admins' &&
          ace.principal !== 'SYSTEM' &&
          ace.principal !== 'Administrators';

        return isWriteAccess && isNonStandard;
      });

      for (const ace of dangerousPermissions) {
        findings.push(this._createFinding({
          title: `Shadow Admin Path: ${ace.principal} -> ${acl.objectName}`,
          description: `"${ace.principal}" has ${ace.rights.join(', ')} permission on privileged group "${acl.objectName}". This non-admin principal can modify group membership, effectively granting themselves admin access (shadow admin).`,
          severity: 'Critical',
          subcategory: 'shadow-admins',
          affectedObjects: [
            { type: 'principal', name: ace.principal, rights: ace.rights },
            { type: 'group', name: acl.objectName },
          ],
          remediation: {
            description: `Remove write access from "${ace.principal}" on privileged group "${acl.objectName}".`,
            steps: [
              `Review why "${ace.principal}" has write access to "${acl.objectName}"`,
              'Remove the ACE granting write access',
              'Audit other objects for similar shadow admin paths',
              'Consider deploying BloodHound for comprehensive path analysis',
            ],
            powershell: `# View ACL on the group\n$group = Get-ADGroup "${acl.objectName}"\n$acl = Get-Acl "AD:\\$($group.DistinguishedName)"\n$acl.Access | Where-Object {$_.IdentityReference -like "*${ace.principal}*"}`,
            impact: 'The principal will lose the ability to modify the privileged group.',
            automatable: false,
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
      category: 'privilege',
      subcategory: params.subcategory || 'general',
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

  _buildEscalationGraph(findings) {
    const paths = [];
    const escalationFindings = findings.filter(
      (f) => ['shadow-admins', 'delegation', 'kerberoasting', 'nested-groups'].includes(f.subcategory)
    );

    for (const f of escalationFindings) {
      if (f.affectedObjects && f.affectedObjects.length > 0) {
        paths.push({
          id: f.id,
          type: f.subcategory,
          severity: f.severity,
          source: f.affectedObjects[0],
          target: f.affectedObjects.length > 1 ? f.affectedObjects[1] : null,
          description: f.title,
        });
      }
    }

    return paths;
  }

  _isPrivilegedGroup(name) {
    const privilegedNames = [
      'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
      'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators',
      'Replicator', 'Group Policy Creator Owners', 'Key Admins', 'Enterprise Key Admins',
      'DnsAdmins', 'DHCP Administrators',
    ];
    return privilegedNames.some((pn) => name && name.toLowerCase() === pn.toLowerCase());
  }

  _isUserPrivileged(userName, groups) {
    for (const group of groups) {
      if (!this._isPrivilegedGroup(group.name)) continue;
      const memberNames = (group.members || []).map((m) => (m.name || m).toLowerCase());
      if (memberNames.includes(userName.toLowerCase())) return true;
    }
    return false;
  }

  _getUserPrivilegedGroups(userName, groups) {
    const result = [];
    for (const group of groups) {
      if (!this._isPrivilegedGroup(group.name)) continue;
      const memberNames = (group.members || []).map((m) => (m.name || m).toLowerCase());
      if (memberNames.includes(userName.toLowerCase())) {
        result.push(group.name);
      }
    }
    return result;
  }

  _calculateNestingDepth(groupName, allGroups, currentDepth) {
    if (currentDepth > 10) return currentDepth; // Prevent infinite recursion
    const group = allGroups.find((g) => g.name === groupName);
    if (!group) return currentDepth;

    const nestedGroups = (group.members || []).filter(
      (m) => (m.objectClass || m.type) === 'group'
    );

    if (nestedGroups.length === 0) return currentDepth;

    let maxDepth = currentDepth;
    for (const nested of nestedGroups) {
      const depth = this._calculateNestingDepth(nested.name || nested, allGroups, currentDepth + 1);
      if (depth > maxDepth) maxDepth = depth;
    }
    return maxDepth;
  }

  _getEffectiveMembers(groupName, allGroups) {
    const group = allGroups.find((g) => g.name === groupName);
    if (!group) return [];

    const members = [];
    for (const member of (group.members || [])) {
      if ((member.objectClass || member.type) === 'group') {
        members.push(...this._getEffectiveMembers(member.name || member, allGroups));
      } else {
        members.push(member);
      }
    }
    return members;
  }
}

module.exports = PrivilegeAuditor;
