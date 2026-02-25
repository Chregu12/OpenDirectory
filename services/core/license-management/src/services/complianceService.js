const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

class ComplianceService {
  constructor(licenseService) {
    this.licenseService = licenseService;
    this.complianceRules = new Map();
    this.initializeComplianceRules();
  }

  initializeComplianceRules() {
    // License Expiry Rule
    this.complianceRules.set('license_expiry', {
      id: 'license_expiry',
      name: 'License Expiry Check',
      description: 'Ensures licenses have not expired',
      severity: 'critical',
      category: 'validity',
      checkFunction: this.checkLicenseExpiry.bind(this)
    });

    // Usage Limit Rule
    this.complianceRules.set('usage_limit', {
      id: 'usage_limit',
      name: 'Usage Limit Compliance',
      description: 'Checks if license usage exceeds allowed limits',
      severity: 'critical',
      category: 'usage',
      checkFunction: this.checkUsageLimit.bind(this)
    });

    // Platform Restriction Rule
    this.complianceRules.set('platform_restriction', {
      id: 'platform_restriction',
      name: 'Platform Restriction Check',
      description: 'Validates software is used on authorized platforms',
      severity: 'medium',
      category: 'restrictions',
      checkFunction: this.checkPlatformRestrictions.bind(this)
    });

    // Maintenance Expiry Rule
    this.complianceRules.set('maintenance_expiry', {
      id: 'maintenance_expiry',
      name: 'Maintenance Expiry Check',
      description: 'Checks if maintenance contracts have expired',
      severity: 'low',
      category: 'maintenance',
      checkFunction: this.checkMaintenanceExpiry.bind(this)
    });

    // Geographic Restriction Rule
    this.complianceRules.set('geo_restriction', {
      id: 'geo_restriction',
      name: 'Geographic Restriction Check',
      description: 'Ensures licenses are used within allowed geographic regions',
      severity: 'high',
      category: 'restrictions',
      checkFunction: this.checkGeographicRestrictions.bind(this)
    });

    // Concurrent Usage Rule
    this.complianceRules.set('concurrent_usage', {
      id: 'concurrent_usage',
      name: 'Concurrent Usage Check',
      description: 'Validates concurrent license usage limits',
      severity: 'high',
      category: 'usage',
      checkFunction: this.checkConcurrentUsage.bind(this)
    });

    // License Transfer Rule
    this.complianceRules.set('license_transfer', {
      id: 'license_transfer',
      name: 'License Transfer Compliance',
      description: 'Checks if license transfers comply with terms',
      severity: 'medium',
      category: 'transfers',
      checkFunction: this.checkLicenseTransfer.bind(this)
    });
  }

  async performFullComplianceAudit(licenseIds = null) {
    const auditId = uuidv4();
    const audit = {
      id: auditId,
      type: 'full_compliance_audit',
      startedAt: new Date().toISOString(),
      completedAt: null,
      status: 'running',
      licenseIds: licenseIds || Array.from(this.licenseService.licenses.keys()),
      results: [],
      summary: {
        totalLicenses: 0,
        compliantLicenses: 0,
        nonCompliantLicenses: 0,
        totalViolations: 0,
        violationsBySeverity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        },
        violationsByCategory: {
          validity: 0,
          usage: 0,
          restrictions: 0,
          maintenance: 0,
          transfers: 0
        }
      }
    };

    try {
      const totalLicenses = audit.licenseIds.length;
      audit.summary.totalLicenses = totalLicenses;

      for (let i = 0; i < audit.licenseIds.length; i++) {
        const licenseId = audit.licenseIds[i];
        const license = this.licenseService.licenses.get(licenseId);
        
        if (!license) continue;

        const licenseAudit = await this.auditSingleLicense(licenseId);
        audit.results.push(licenseAudit);

        // Update summary
        if (licenseAudit.isCompliant) {
          audit.summary.compliantLicenses++;
        } else {
          audit.summary.nonCompliantLicenses++;
        }

        // Count violations by severity and category
        licenseAudit.violations.forEach(violation => {
          audit.summary.totalViolations++;
          audit.summary.violationsBySeverity[violation.severity]++;
          audit.summary.violationsByCategory[violation.category]++;
        });

        // Update progress
        const progress = Math.floor(((i + 1) / totalLicenses) * 100);
        
        // Broadcast progress update
        this.licenseService.broadcastToSubscribers('compliance_audit_progress', {
          auditId,
          progress,
          processedLicenses: i + 1,
          totalLicenses
        });
      }

      audit.status = 'completed';
      audit.completedAt = new Date().toISOString();

      // Store audit results
      this.licenseService.compliance.set(auditId, audit);

      // Generate compliance report
      const report = this.generateComplianceReport(audit);
      this.licenseService.reports.set(`compliance_audit_${auditId}`, report);

      // Broadcast completion
      this.licenseService.broadcastToSubscribers('compliance_audit_completed', {
        auditId,
        summary: audit.summary,
        reportId: report.id
      });

      return audit;

    } catch (error) {
      audit.status = 'failed';
      audit.error = error.message;
      audit.completedAt = new Date().toISOString();
      
      this.licenseService.logger.error('Compliance audit failed', {
        auditId,
        error: error.message
      });

      return audit;
    }
  }

  async auditSingleLicense(licenseId) {
    const license = this.licenseService.licenses.get(licenseId);
    const violations = [];
    
    if (!license) {
      return {
        licenseId,
        isCompliant: false,
        violations: [{
          rule: 'license_existence',
          severity: 'critical',
          category: 'validity',
          message: 'License not found',
          timestamp: new Date().toISOString()
        }]
      };
    }

    // Run all compliance rules
    for (const [ruleId, rule] of this.complianceRules) {
      try {
        const ruleViolations = await rule.checkFunction(license);
        if (ruleViolations && ruleViolations.length > 0) {
          violations.push(...ruleViolations.map(violation => ({
            ...violation,
            rule: ruleId,
            severity: rule.severity,
            category: rule.category,
            timestamp: new Date().toISOString()
          })));
        }
      } catch (error) {
        this.licenseService.logger.error('Compliance rule check failed', {
          licenseId,
          ruleId,
          error: error.message
        });
      }
    }

    const isCompliant = violations.length === 0;

    // Store violations if any
    if (!isCompliant) {
      violations.forEach(violation => {
        const violationId = uuidv4();
        const violationRecord = {
          id: violationId,
          licenseId,
          ...violation
        };
        this.licenseService.violations.set(violationId, violationRecord);
      });
    }

    return {
      licenseId,
      licenseName: license.name,
      isCompliant,
      violations,
      auditedAt: new Date().toISOString()
    };
  }

  async checkLicenseExpiry(license) {
    const violations = [];
    
    if (license.expiryDate) {
      const expiryDate = new Date(license.expiryDate);
      const now = new Date();
      
      if (expiryDate < now) {
        violations.push({
          message: `License expired on ${moment(expiryDate).format('YYYY-MM-DD')}`,
          expiryDate: license.expiryDate,
          daysOverdue: moment(now).diff(moment(expiryDate), 'days')
        });
      }
    }

    return violations;
  }

  async checkUsageLimit(license) {
    const violations = [];
    const currentUsage = this.licenseService.calculateCurrentUsage(license.id);
    
    if (currentUsage.activeUsers > currentUsage.maxConcurrent) {
      violations.push({
        message: `License usage (${currentUsage.activeUsers}) exceeds limit (${currentUsage.maxConcurrent})`,
        currentUsers: currentUsage.activeUsers,
        maxUsers: currentUsage.maxConcurrent,
        overageCount: currentUsage.activeUsers - currentUsage.maxConcurrent
      });
    }

    return violations;
  }

  async checkPlatformRestrictions(license) {
    const violations = [];
    
    if (license.terms?.allowedPlatforms && license.terms.allowedPlatforms.length > 0) {
      const usageRecords = this.licenseService.usage.get(license.id) || [];
      const recentUsage = usageRecords.filter(record => 
        moment(record.timestamp).isAfter(moment().subtract(1, 'hour'))
      );

      for (const usage of recentUsage) {
        const userAgent = usage.userAgent || '';
        const isAuthorized = license.terms.allowedPlatforms.some(platform =>
          userAgent.toLowerCase().includes(platform.toLowerCase())
        );

        if (!isAuthorized) {
          violations.push({
            message: `Software used on unauthorized platform: ${userAgent}`,
            userId: usage.userId,
            userAgent,
            allowedPlatforms: license.terms.allowedPlatforms,
            timestamp: usage.timestamp
          });
        }
      }
    }

    return violations;
  }

  async checkMaintenanceExpiry(license) {
    const violations = [];
    
    if (license.maintenance?.included && license.maintenance.expiryDate) {
      const maintenanceExpiry = new Date(license.maintenance.expiryDate);
      const now = new Date();
      
      if (maintenanceExpiry < now) {
        violations.push({
          message: `Maintenance contract expired on ${moment(maintenanceExpiry).format('YYYY-MM-DD')}`,
          maintenanceExpiryDate: license.maintenance.expiryDate,
          daysOverdue: moment(now).diff(moment(maintenanceExpiry), 'days')
        });
      }
    }

    return violations;
  }

  async checkGeographicRestrictions(license) {
    const violations = [];
    
    if (license.compliance?.geoRestrictions && license.compliance.geoRestrictions.length > 0) {
      const usageRecords = this.licenseService.usage.get(license.id) || [];
      const recentUsage = usageRecords.filter(record => 
        moment(record.timestamp).isAfter(moment().subtract(1, 'hour'))
      );

      for (const usage of recentUsage) {
        const location = usage.location || usage.metadata?.location;
        
        if (location) {
          const isAuthorizedLocation = license.compliance.geoRestrictions.some(allowedLocation =>
            location.toLowerCase().includes(allowedLocation.toLowerCase())
          );

          if (!isAuthorizedLocation) {
            violations.push({
              message: `Software used in restricted geographic location: ${location}`,
              userId: usage.userId,
              location,
              allowedLocations: license.compliance.geoRestrictions,
              timestamp: usage.timestamp
            });
          }
        }
      }
    }

    return violations;
  }

  async checkConcurrentUsage(license) {
    const violations = [];
    
    if (license.terms?.concurrent) {
      const usageRecords = this.licenseService.usage.get(license.id) || [];
      const now = moment();
      
      // Group usage by time windows to check for concurrent violations
      const timeWindows = this.createTimeWindows(usageRecords, 5); // 5-minute windows
      
      for (const window of timeWindows) {
        const concurrentUsers = new Set();
        
        window.forEach(usage => {
          if (usage.action === 'start') {
            concurrentUsers.add(usage.userId);
          } else if (usage.action === 'stop') {
            concurrentUsers.delete(usage.userId);
          }
        });

        const maxAllowed = license.terms.maxUsers || license.quantity || 1;
        if (concurrentUsers.size > maxAllowed) {
          violations.push({
            message: `Concurrent usage limit exceeded: ${concurrentUsers.size} users (limit: ${maxAllowed})`,
            concurrentUsers: concurrentUsers.size,
            maxAllowed,
            windowStart: window[0]?.timestamp,
            windowEnd: window[window.length - 1]?.timestamp
          });
        }
      }
    }

    return violations;
  }

  async checkLicenseTransfer(license) {
    const violations = [];
    
    if (!license.terms?.transferable && license.assignments) {
      const transfers = license.assignments.filter(assignment =>
        assignment.transferredFrom || assignment.transferredTo
      );

      if (transfers.length > 0) {
        violations.push({
          message: 'License transfers detected on non-transferable license',
          transferCount: transfers.length,
          transfers: transfers.map(t => ({
            id: t.id,
            transferredAt: t.transferredAt
          }))
        });
      }
    }

    return violations;
  }

  createTimeWindows(usageRecords, windowSizeMinutes) {
    const windows = [];
    const sortedRecords = usageRecords.sort((a, b) => 
      new Date(a.timestamp) - new Date(b.timestamp)
    );

    let currentWindow = [];
    let windowStart = null;

    for (const record of sortedRecords) {
      const recordTime = moment(record.timestamp);
      
      if (!windowStart) {
        windowStart = recordTime;
        currentWindow = [record];
      } else if (recordTime.diff(windowStart, 'minutes') <= windowSizeMinutes) {
        currentWindow.push(record);
      } else {
        if (currentWindow.length > 0) {
          windows.push(currentWindow);
        }
        windowStart = recordTime;
        currentWindow = [record];
      }
    }

    if (currentWindow.length > 0) {
      windows.push(currentWindow);
    }

    return windows;
  }

  generateComplianceReport(audit) {
    const reportId = uuidv4();
    const report = {
      id: reportId,
      type: 'compliance_audit_report',
      auditId: audit.id,
      title: `License Compliance Audit Report - ${moment().format('YYYY-MM-DD')}`,
      generatedAt: new Date().toISOString(),
      summary: audit.summary,
      executiveSummary: this.generateExecutiveSummary(audit),
      detailedFindings: this.generateDetailedFindings(audit),
      recommendations: this.generateComplianceRecommendations(audit),
      actionPlan: this.generateActionPlan(audit),
      appendices: {
        licenseDetails: audit.results,
        complianceRules: Array.from(this.complianceRules.values())
      }
    };

    return report;
  }

  generateExecutiveSummary(audit) {
    const complianceRate = audit.summary.totalLicenses > 0 ? 
      (audit.summary.compliantLicenses / audit.summary.totalLicenses * 100).toFixed(1) : 0;

    return {
      overallComplianceRate: `${complianceRate}%`,
      totalLicensesAudited: audit.summary.totalLicenses,
      compliantLicenses: audit.summary.compliantLicenses,
      nonCompliantLicenses: audit.summary.nonCompliantLicenses,
      criticalViolations: audit.summary.violationsBySeverity.critical,
      riskLevel: this.calculateRiskLevel(audit.summary),
      keyFindings: this.extractKeyFindings(audit.results),
      immediateActions: this.getImmediateActions(audit.results)
    };
  }

  generateDetailedFindings(audit) {
    const findings = {
      violationsByCategory: audit.summary.violationsByCategory,
      violationsBySeverity: audit.summary.violationsBySeverity,
      topViolatedLicenses: this.getTopViolatedLicenses(audit.results, 10),
      complianceTrends: this.calculateComplianceTrends(),
      riskAssessment: this.performRiskAssessment(audit.results)
    };

    return findings;
  }

  generateComplianceRecommendations(audit) {
    const recommendations = [];

    // Critical violations recommendations
    if (audit.summary.violationsBySeverity.critical > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'immediate_action',
        title: 'Address Critical Compliance Violations',
        description: `${audit.summary.violationsBySeverity.critical} critical violations require immediate attention`,
        actions: [
          'Review and address expired licenses immediately',
          'Implement usage monitoring to prevent overages',
          'Establish emergency license procurement process'
        ]
      });
    }

    // Usage violations recommendations
    if (audit.summary.violationsByCategory.usage > 0) {
      recommendations.push({
        priority: 'high',
        category: 'usage_management',
        title: 'Implement Better Usage Controls',
        description: 'Usage violations detected across multiple licenses',
        actions: [
          'Deploy automated usage monitoring tools',
          'Implement real-time usage alerts',
          'Create usage approval workflows for overages'
        ]
      });
    }

    // Platform restrictions recommendations
    if (audit.summary.violationsByCategory.restrictions > 0) {
      recommendations.push({
        priority: 'medium',
        category: 'policy_enforcement',
        title: 'Strengthen Policy Enforcement',
        description: 'Platform and geographic restriction violations found',
        actions: [
          'Implement automated platform detection',
          'Create user training on license restrictions',
          'Deploy endpoint compliance agents'
        ]
      });
    }

    return recommendations;
  }

  generateActionPlan(audit) {
    const actionPlan = {
      immediate: [], // 0-30 days
      shortTerm: [], // 30-90 days
      longTerm: [] // 90+ days
    };

    // Immediate actions for critical violations
    const criticalViolations = audit.results.filter(result => 
      result.violations.some(v => v.severity === 'critical')
    );

    criticalViolations.forEach(result => {
      result.violations
        .filter(v => v.severity === 'critical')
        .forEach(violation => {
          actionPlan.immediate.push({
            licenseId: result.licenseId,
            licenseName: result.licenseName,
            action: this.getRemediationAction(violation),
            deadline: moment().add(7, 'days').format('YYYY-MM-DD'),
            responsible: 'license-admin'
          });
        });
    });

    // Short-term actions for high/medium violations
    const nonCriticalViolations = audit.results.filter(result => 
      result.violations.some(v => ['high', 'medium'].includes(v.severity))
    );

    nonCriticalViolations.forEach(result => {
      result.violations
        .filter(v => ['high', 'medium'].includes(v.severity))
        .forEach(violation => {
          actionPlan.shortTerm.push({
            licenseId: result.licenseId,
            licenseName: result.licenseName,
            action: this.getRemediationAction(violation),
            deadline: moment().add(30, 'days').format('YYYY-MM-DD'),
            responsible: 'license-team'
          });
        });
    });

    // Long-term process improvements
    actionPlan.longTerm.push(
      {
        action: 'Implement automated compliance monitoring',
        deadline: moment().add(90, 'days').format('YYYY-MM-DD'),
        responsible: 'it-operations'
      },
      {
        action: 'Establish license governance framework',
        deadline: moment().add(120, 'days').format('YYYY-MM-DD'),
        responsible: 'license-manager'
      }
    );

    return actionPlan;
  }

  getRemediationAction(violation) {
    const actionMap = {
      'license_expiry': 'Renew expired license immediately',
      'usage_limit': 'Reduce user count or purchase additional licenses',
      'platform_restriction': 'Remove software from unauthorized platforms',
      'maintenance_expiry': 'Renew maintenance contract',
      'geo_restriction': 'Restrict access to authorized geographic regions',
      'concurrent_usage': 'Implement usage monitoring and controls',
      'license_transfer': 'Review and approve license transfer or revert'
    };

    return actionMap[violation.rule] || 'Review and resolve violation';
  }

  calculateRiskLevel(summary) {
    const totalViolations = summary.totalViolations;
    const criticalViolations = summary.violationsBySeverity.critical;
    const totalLicenses = summary.totalLicenses;

    if (criticalViolations > 0 || (totalViolations / totalLicenses) > 0.3) {
      return 'high';
    } else if ((totalViolations / totalLicenses) > 0.1) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  extractKeyFindings(results) {
    const findings = [];
    
    // Count violations by type
    const violationCounts = {};
    results.forEach(result => {
      result.violations.forEach(violation => {
        violationCounts[violation.rule] = (violationCounts[violation.rule] || 0) + 1;
      });
    });

    // Get top violation types
    const sortedViolations = Object.entries(violationCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5);

    sortedViolations.forEach(([rule, count]) => {
      const ruleInfo = this.complianceRules.get(rule);
      findings.push(`${count} instances of ${ruleInfo?.name || rule} violations`);
    });

    return findings;
  }

  getImmediateActions(results) {
    const actions = [];
    
    results.forEach(result => {
      result.violations
        .filter(v => v.severity === 'critical')
        .forEach(violation => {
          actions.push({
            license: result.licenseName,
            action: this.getRemediationAction(violation)
          });
        });
    });

    return actions.slice(0, 10); // Top 10 immediate actions
  }

  getTopViolatedLicenses(results, limit) {
    return results
      .filter(result => !result.isCompliant)
      .sort((a, b) => b.violations.length - a.violations.length)
      .slice(0, limit)
      .map(result => ({
        licenseName: result.licenseName,
        violationCount: result.violations.length,
        criticalViolations: result.violations.filter(v => v.severity === 'critical').length,
        highViolations: result.violations.filter(v => v.severity === 'high').length
      }));
  }

  calculateComplianceTrends() {
    // This would typically analyze historical compliance data
    // For now, returning mock trend data
    return {
      trend: 'improving',
      changeFromLastMonth: '+5.2%',
      projectedCompliance: '92%'
    };
  }

  performRiskAssessment(results) {
    const riskFactors = {
      expiredLicenses: results.filter(r => 
        r.violations.some(v => v.rule === 'license_expiry')
      ).length,
      overusedLicenses: results.filter(r => 
        r.violations.some(v => v.rule === 'usage_limit')
      ).length,
      restrictionViolations: results.filter(r => 
        r.violations.some(v => v.category === 'restrictions')
      ).length
    };

    return {
      riskFactors,
      businessImpact: this.assessBusinessImpact(riskFactors),
      legalRisk: this.assessLegalRisk(riskFactors),
      financialRisk: this.assessFinancialRisk(riskFactors)
    };
  }

  assessBusinessImpact(riskFactors) {
    if (riskFactors.expiredLicenses > 5 || riskFactors.overusedLicenses > 3) {
      return 'high';
    } else if (riskFactors.expiredLicenses > 2 || riskFactors.overusedLicenses > 1) {
      return 'medium';
    }
    return 'low';
  }

  assessLegalRisk(riskFactors) {
    if (riskFactors.expiredLicenses > 3 || riskFactors.restrictionViolations > 5) {
      return 'high';
    } else if (riskFactors.expiredLicenses > 1 || riskFactors.restrictionViolations > 2) {
      return 'medium';
    }
    return 'low';
  }

  assessFinancialRisk(riskFactors) {
    if (riskFactors.overusedLicenses > 5) {
      return 'high';
    } else if (riskFactors.overusedLicenses > 2) {
      return 'medium';
    }
    return 'low';
  }
}

module.exports = ComplianceService;