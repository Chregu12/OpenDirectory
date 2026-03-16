'use strict';

/**
 * RegulatoryMapper – maps technical compliance checks to regulatory frameworks
 * such as DSGVO/GDPR, ISO 27001 Annex A, and SOC2.
 */
class RegulatoryMapper {
  constructor({ logger }) {
    this.logger = logger;

    // ---------------------------------------------------------------------------
    // Regulatory framework mappings
    // ---------------------------------------------------------------------------

    /**
     * DSGVO/GDPR article mappings.
     * Maps check categories/types to relevant GDPR articles.
     */
    this.gdprMapping = {
      'Art. 5(1)(f) – Integrity & Confidentiality': {
        description: 'Appropriate security of personal data including protection against unauthorized or unlawful processing',
        checkCategories: ['Encryption', 'Firewall', 'Mandatory Access Control', 'File Permissions'],
        checkTypes: ['encryption', 'filevault', 'firewall', 'selinux', 'apparmor', 'file_permissions'],
      },
      'Art. 25 – Data Protection by Design': {
        description: 'Implement appropriate technical and organisational measures for ensuring data protection principles',
        checkCategories: ['Encryption', 'Account Policies', 'User Account Control', 'Authentication'],
        checkTypes: ['encryption', 'filevault', 'registry', 'pam'],
      },
      'Art. 32(1)(a) – Encryption': {
        description: 'Pseudonymisation and encryption of personal data',
        checkCategories: ['Encryption'],
        checkTypes: ['encryption', 'filevault'],
      },
      'Art. 32(1)(b) – Ongoing Confidentiality': {
        description: 'Ensure the ongoing confidentiality, integrity, availability and resilience of processing systems',
        checkCategories: ['Firewall', 'Antivirus', 'Patch Management', 'SSH', 'Screen Lock'],
        checkTypes: ['firewall', 'antivirus', 'software_update', 'file_content', 'screen_lock'],
      },
      'Art. 32(1)(d) – Testing & Evaluation': {
        description: 'Process for regularly testing, assessing and evaluating the effectiveness of technical measures',
        checkCategories: ['Audit', 'Audit Policy'],
        checkTypes: ['audit_policy'],
      },
      'Art. 33 – Breach Notification': {
        description: 'Notification of personal data breach to supervisory authority (requires logging/audit)',
        checkCategories: ['Audit', 'Audit Policy'],
        checkTypes: ['audit_policy'],
      },
    };

    /**
     * ISO 27001:2022 Annex A control mappings.
     */
    this.iso27001Mapping = {
      'A.5.15 – Access Control': {
        description: 'Rules for access to information and other associated assets',
        checkCategories: ['Account Policies', 'Authentication', 'User Account Control', 'SSH'],
        checkTypes: ['registry', 'pam', 'file_content', 'uac'],
      },
      'A.5.17 – Authentication Information': {
        description: 'Management of authentication information',
        checkCategories: ['Account Policies', 'Authentication'],
        checkTypes: ['registry', 'pam'],
      },
      'A.8.1 – User Endpoint Devices': {
        description: 'Information stored on, processed by or accessible via user endpoint devices shall be protected',
        checkCategories: ['Encryption', 'Screen Lock', 'Antivirus', 'Firewall'],
        checkTypes: ['encryption', 'filevault', 'screen_lock', 'antivirus', 'firewall'],
      },
      'A.8.5 – Secure Authentication': {
        description: 'Secure authentication technologies and procedures',
        checkCategories: ['Account Policies', 'Authentication', 'SSH'],
        checkTypes: ['registry', 'pam', 'file_content'],
      },
      'A.8.7 – Protection Against Malware': {
        description: 'Protection against malware shall be implemented',
        checkCategories: ['Antivirus', 'Application Security'],
        checkTypes: ['antivirus', 'gatekeeper'],
      },
      'A.8.8 – Management of Technical Vulnerabilities': {
        description: 'Information about technical vulnerabilities shall be obtained and appropriate measures taken',
        checkCategories: ['Patch Management'],
        checkTypes: ['software_update'],
      },
      'A.8.9 – Configuration Management': {
        description: 'Configurations including security configurations shall be established and managed',
        checkCategories: ['Kernel Hardening', 'Network Hardening', 'Service Hardening', 'System Integrity'],
        checkTypes: ['sysctl', 'service_status', 'sip'],
      },
      'A.8.15 – Logging': {
        description: 'Logs that record activities, exceptions, faults and other relevant events shall be produced',
        checkCategories: ['Audit', 'Audit Policy'],
        checkTypes: ['audit_policy', 'service_status'],
      },
      'A.8.20 – Networks Security': {
        description: 'Networks and network devices shall be secured, managed and controlled',
        checkCategories: ['Firewall', 'Network Hardening'],
        checkTypes: ['firewall', 'sysctl'],
      },
      'A.8.24 – Use of Cryptography': {
        description: 'Rules for the effective use of cryptography shall be defined and implemented',
        checkCategories: ['Encryption', 'SSH'],
        checkTypes: ['encryption', 'filevault', 'file_content'],
      },
    };

    /**
     * SOC2 Trust Service Criteria mappings.
     */
    this.soc2Mapping = {
      'CC6.1 – Logical and Physical Access': {
        description: 'Logical access security software, infrastructure, and architectures to protect information assets',
        checkCategories: ['Account Policies', 'Authentication', 'User Account Control', 'SSH', 'Firewall'],
        checkTypes: ['registry', 'pam', 'file_content', 'uac', 'firewall'],
      },
      'CC6.6 – Boundary Protection': {
        description: 'Logical access security measures to protect against threats from sources outside the system boundary',
        checkCategories: ['Firewall', 'Network Hardening'],
        checkTypes: ['firewall', 'sysctl'],
      },
      'CC6.7 – Mobility & Removable Media': {
        description: 'Restrict the transmission, movement, and removal of information',
        checkCategories: ['Encryption', 'Sharing', 'Remote Access'],
        checkTypes: ['encryption', 'filevault', 'service_status', 'command'],
      },
      'CC6.8 – Malware Prevention': {
        description: 'Controls to prevent or detect and act upon the introduction of unauthorized or malicious software',
        checkCategories: ['Antivirus', 'Application Security', 'System Integrity'],
        checkTypes: ['antivirus', 'gatekeeper', 'sip'],
      },
      'CC7.1 – Monitoring': {
        description: 'Detection and monitoring procedures to identify anomalies and security events',
        checkCategories: ['Audit', 'Audit Policy'],
        checkTypes: ['audit_policy', 'service_status'],
      },
      'CC7.2 – Incident Response': {
        description: 'Procedures for identifying and responding to security incidents',
        checkCategories: ['Audit', 'Audit Policy'],
        checkTypes: ['audit_policy'],
      },
      'CC8.1 – Change Management': {
        description: 'Changes to infrastructure, data, software and procedures are authorized, designed, developed, tested and implemented',
        checkCategories: ['Patch Management', 'Service Hardening'],
        checkTypes: ['software_update', 'service_status'],
      },
    };
  }

  /**
   * Map compliance check results to a regulatory framework.
   * @param {Array} checkResults - compliance result rows from the database
   * @param {string} framework - 'gdpr'|'dsgvo'|'iso27001'|'soc2'
   * @returns {object} regulatory mapping with coverage and gap analysis
   */
  mapToRegulation(checkResults, framework) {
    const mapping = this._getMapping(framework);
    if (!mapping) {
      return { error: `Unknown framework: ${framework}. Supported: gdpr, dsgvo, iso27001, soc2` };
    }

    // Flatten all check details from results
    const allChecks = [];
    for (const result of checkResults) {
      const details = Array.isArray(result.details) ? result.details : [];
      allChecks.push(...details);
    }

    const controls = {};
    let totalControls = 0;
    let coveredControls = 0;
    let compliantControls = 0;

    for (const [controlId, control] of Object.entries(mapping)) {
      totalControls++;

      // Find checks that map to this control
      const matchingChecks = allChecks.filter((check) => {
        const checkType = check.check?.type || this._inferType(check);
        const checkCategory = check.category || '';
        return (
          control.checkTypes.includes(checkType) ||
          control.checkCategories.includes(checkCategory)
        );
      });

      const covered = matchingChecks.length > 0;
      if (covered) coveredControls++;

      const passed = matchingChecks.filter((c) => c.status === 'pass').length;
      const failed = matchingChecks.filter((c) => c.status === 'fail').length;
      const total = matchingChecks.length;
      const complianceRate = total > 0 ? Math.round((passed / total) * 100) : 0;

      if (total > 0 && failed === 0) compliantControls++;

      controls[controlId] = {
        description: control.description,
        covered,
        totalChecks: total,
        passed,
        failed,
        complianceRate,
        checks: matchingChecks.map((c) => ({
          checkId: c.checkId,
          title: c.title,
          status: c.status,
          severity: c.severity,
        })),
      };
    }

    return {
      framework: framework.toUpperCase(),
      generatedAt: new Date().toISOString(),
      summary: {
        totalControls,
        coveredControls,
        compliantControls,
        coverageRate: totalControls > 0 ? Math.round((coveredControls / totalControls) * 100) : 0,
        complianceRate: coveredControls > 0 ? Math.round((compliantControls / coveredControls) * 100) : 0,
      },
      controls,
    };
  }

  /**
   * Get the mapping table for the given framework.
   */
  _getMapping(framework) {
    switch (framework.toLowerCase()) {
      case 'gdpr':
      case 'dsgvo':
        return this.gdprMapping;
      case 'iso27001':
        return this.iso27001Mapping;
      case 'soc2':
        return this.soc2Mapping;
      default:
        return null;
    }
  }

  /**
   * Infer check type from check result structure when type is not explicit.
   */
  _inferType(check) {
    if (check.checkId) {
      if (check.checkId.includes('enc') || check.checkId.includes('filevault') || check.checkId.includes('bitlocker')) return 'encryption';
      if (check.checkId.includes('fw') || check.checkId.includes('firewall')) return 'firewall';
      if (check.checkId.includes('av') || check.checkId.includes('antivirus')) return 'antivirus';
      if (check.checkId.includes('ssh')) return 'file_content';
      if (check.checkId.includes('sysctl')) return 'sysctl';
      if (check.checkId.includes('pam')) return 'pam';
      if (check.checkId.includes('audit')) return 'audit_policy';
      if (check.checkId.includes('upd')) return 'software_update';
      if (check.checkId.includes('reg')) return 'registry';
      if (check.checkId.includes('svc')) return 'service_status';
      if (check.checkId.includes('uac')) return 'uac';
      if (check.checkId.includes('sl') || check.checkId.includes('screen')) return 'screen_lock';
      if (check.checkId.includes('perm')) return 'file_permissions';
      if (check.checkId.includes('gatekeeper')) return 'gatekeeper';
      if (check.checkId.includes('sip')) return 'sip';
      if (check.checkId.includes('selinux')) return 'selinux';
      if (check.checkId.includes('apparmor')) return 'apparmor';
    }
    return 'unknown';
  }
}

module.exports = RegulatoryMapper;
