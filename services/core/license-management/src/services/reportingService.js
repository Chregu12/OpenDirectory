const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const XLSX = require('xlsx');
const PDFDocument = require('pdf-lib').PDFDocument;
const fs = require('fs').promises;
const path = require('path');

class ReportingService {
  constructor(licenseService) {
    this.licenseService = licenseService;
    this.reportTemplates = new Map();
    this.scheduledReports = new Map();
    this.reportCache = new Map();
    
    this.initializeReportTemplates();
    this.startReportScheduler();
  }

  initializeReportTemplates() {
    // License Inventory Report
    this.reportTemplates.set('license_inventory', {
      id: 'license_inventory',
      name: 'License Inventory Report',
      description: 'Comprehensive inventory of all licenses',
      category: 'inventory',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        includeExpired: { type: 'boolean', default: true },
        vendorFilter: { type: 'string', default: null },
        statusFilter: { type: 'string', default: 'all' },
        groupBy: { type: 'enum', values: ['vendor', 'type', 'status'], default: 'vendor' }
      },
      generateFunction: this.generateLicenseInventoryReport.bind(this)
    });

    // Usage Analytics Report
    this.reportTemplates.set('usage_analytics', {
      id: 'usage_analytics',
      name: 'License Usage Analytics Report',
      description: 'Detailed analysis of license usage patterns',
      category: 'analytics',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        timeframe: { type: 'enum', values: ['7d', '30d', '90d', '1y'], default: '30d' },
        includeCharts: { type: 'boolean', default: true },
        licensesFilter: { type: 'array', default: null }
      },
      generateFunction: this.generateUsageAnalyticsReport.bind(this)
    });

    // Compliance Report
    this.reportTemplates.set('compliance', {
      id: 'compliance',
      name: 'License Compliance Report',
      description: 'Compliance status and violations summary',
      category: 'compliance',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        includeResolved: { type: 'boolean', default: false },
        severityFilter: { type: 'enum', values: ['critical', 'high', 'medium', 'low', 'all'], default: 'all' },
        timeframe: { type: 'enum', values: ['30d', '90d', '1y'], default: '90d' }
      },
      generateFunction: this.generateComplianceReport.bind(this)
    });

    // Cost Analysis Report
    this.reportTemplates.set('cost_analysis', {
      id: 'cost_analysis',
      name: 'License Cost Analysis Report',
      description: 'Financial analysis of license costs and trends',
      category: 'financial',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        timeframe: { type: 'enum', values: ['1y', '2y', '3y'], default: '1y' },
        groupBy: { type: 'enum', values: ['vendor', 'type', 'department'], default: 'vendor' },
        includeForecast: { type: 'boolean', default: true }
      },
      generateFunction: this.generateCostAnalysisReport.bind(this)
    });

    // Optimization Report
    this.reportTemplates.set('optimization', {
      id: 'optimization',
      name: 'License Optimization Report',
      description: 'Recommendations for license optimization',
      category: 'optimization',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        includeImplementationPlan: { type: 'boolean', default: true },
        priorityFilter: { type: 'enum', values: ['high', 'medium', 'low', 'all'], default: 'all' },
        savingsThreshold: { type: 'number', default: 1000 }
      },
      generateFunction: this.generateOptimizationReport.bind(this)
    });

    // Renewal Schedule Report
    this.reportTemplates.set('renewal_schedule', {
      id: 'renewal_schedule',
      name: 'License Renewal Schedule Report',
      description: 'Upcoming license renewals and planning',
      category: 'planning',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        lookAheadDays: { type: 'number', default: 365 },
        includeAutoRenewal: { type: 'boolean', default: false },
        sortBy: { type: 'enum', values: ['date', 'cost', 'name'], default: 'date' }
      },
      generateFunction: this.generateRenewalScheduleReport.bind(this)
    });

    // Executive Summary Report
    this.reportTemplates.set('executive_summary', {
      id: 'executive_summary',
      name: 'Executive Summary Report',
      description: 'High-level overview for executive stakeholders',
      category: 'executive',
      outputFormats: ['pdf', 'json'],
      parameters: {
        includeMetrics: { type: 'boolean', default: true },
        includeAlerts: { type: 'boolean', default: true },
        includeRecommendations: { type: 'boolean', default: true }
      },
      generateFunction: this.generateExecutiveSummaryReport.bind(this)
    });

    // Audit Trail Report
    this.reportTemplates.set('audit_trail', {
      id: 'audit_trail',
      name: 'License Audit Trail Report',
      description: 'Detailed audit log of license-related activities',
      category: 'audit',
      outputFormats: ['excel', 'json'],
      parameters: {
        timeframe: { type: 'enum', values: ['30d', '90d', '1y'], default: '90d' },
        actionsFilter: { type: 'array', default: null },
        userFilter: { type: 'string', default: null }
      },
      generateFunction: this.generateAuditTrailReport.bind(this)
    });

    // Mobile License Report
    this.reportTemplates.set('mobile_licenses', {
      id: 'mobile_licenses',
      name: 'Mobile License Report',
      description: 'Mobile application license analysis',
      category: 'mobile',
      outputFormats: ['pdf', 'excel', 'json'],
      parameters: {
        platformFilter: { type: 'enum', values: ['ios', 'android', 'all'], default: 'all' },
        includeUsage: { type: 'boolean', default: true },
        includeCompliance: { type: 'boolean', default: true }
      },
      generateFunction: this.generateMobileLicenseReport.bind(this)
    });
  }

  startReportScheduler() {
    // Check for scheduled reports every hour
    setInterval(() => {
      this.processScheduledReports();
    }, 60 * 60 * 1000);

    this.licenseService.logger.info('Report scheduler started');
  }

  async generateReport(templateId, parameters = {}, outputFormat = 'json') {
    const reportId = uuidv4();
    const template = this.reportTemplates.get(templateId);
    
    if (!template) {
      throw new Error(`Report template not found: ${templateId}`);
    }

    if (!template.outputFormats.includes(outputFormat)) {
      throw new Error(`Output format not supported: ${outputFormat}`);
    }

    const report = {
      id: reportId,
      templateId,
      templateName: template.name,
      parameters: { ...template.parameters, ...parameters },
      outputFormat,
      status: 'generating',
      startedAt: new Date().toISOString(),
      completedAt: null,
      error: null,
      data: null,
      metadata: {
        generatedBy: 'system',
        dataSourceVersion: '1.0.0',
        licenseCount: this.licenseService.licenses.size,
        generationMethod: 'automatic'
      }
    };

    try {
      this.licenseService.reports.set(reportId, report);

      // Generate report data
      const reportData = await template.generateFunction(parameters);
      
      // Format output based on requested format
      const formattedOutput = await this.formatReportOutput(reportData, outputFormat, template);

      report.status = 'completed';
      report.completedAt = new Date().toISOString();
      report.data = formattedOutput;
      report.metadata.sizeBytes = this.calculateReportSize(formattedOutput);
      report.metadata.recordCount = this.getRecordCount(reportData);

      this.licenseService.reports.set(reportId, report);

      // Cache report for future access
      this.reportCache.set(reportId, {
        data: formattedOutput,
        cachedAt: new Date().toISOString(),
        expiresAt: moment().add(24, 'hours').toISOString()
      });

      // Log audit event
      this.licenseService.logAuditEvent('report_generated', {
        reportId,
        templateId,
        outputFormat,
        recordCount: report.metadata.recordCount
      });

      this.licenseService.logger.info('Report generated successfully', {
        reportId,
        templateId,
        outputFormat,
        duration: moment(report.completedAt).diff(moment(report.startedAt), 'seconds')
      });

      return report;

    } catch (error) {
      report.status = 'failed';
      report.error = error.message;
      report.completedAt = new Date().toISOString();
      
      this.licenseService.reports.set(reportId, report);
      
      this.licenseService.logger.error('Report generation failed', {
        reportId,
        templateId,
        error: error.message
      });

      throw error;
    }
  }

  // Report Generation Functions
  async generateLicenseInventoryReport(parameters) {
    const licenses = Array.from(this.licenseService.licenses.values());
    
    // Apply filters
    let filteredLicenses = licenses;
    
    if (!parameters.includeExpired) {
      filteredLicenses = filteredLicenses.filter(license => 
        !license.expiryDate || new Date(license.expiryDate) >= new Date()
      );
    }

    if (parameters.vendorFilter) {
      filteredLicenses = filteredLicenses.filter(license => 
        license.vendorId === parameters.vendorFilter
      );
    }

    if (parameters.statusFilter && parameters.statusFilter !== 'all') {
      filteredLicenses = filteredLicenses.filter(license => 
        license.status === parameters.statusFilter
      );
    }

    // Enrich license data
    const enrichedLicenses = filteredLicenses.map(license => ({
      ...license,
      vendor: this.licenseService.vendors.get(license.vendorId),
      software: this.licenseService.software.get(license.softwareId),
      usage: this.licenseService.calculateLicenseUsage(license.id),
      compliance: this.licenseService.checkLicenseCompliance(license.id),
      daysToExpiry: license.expiryDate ? 
        moment(license.expiryDate).diff(moment(), 'days') : null
    }));

    // Group data
    const groupedData = this.groupLicensesByField(enrichedLicenses, parameters.groupBy);

    return {
      summary: {
        totalLicenses: filteredLicenses.length,
        activeLicenses: filteredLicenses.filter(l => l.status === 'active').length,
        expiringLicenses: filteredLicenses.filter(l => 
          l.expiryDate && moment(l.expiryDate).diff(moment(), 'days') <= 30
        ).length,
        totalValue: filteredLicenses.reduce((sum, l) => sum + (l.cost || 0), 0)
      },
      groupedData,
      details: enrichedLicenses,
      filters: parameters
    };
  }

  async generateUsageAnalyticsReport(parameters) {
    const timeframeDays = this.parseTimeframeToDays(parameters.timeframe);
    const cutoffDate = moment().subtract(timeframeDays, 'days');

    const licenses = Array.from(this.licenseService.licenses.values());
    let targetLicenses = licenses;

    if (parameters.licensesFilter && parameters.licensesFilter.length > 0) {
      targetLicenses = licenses.filter(license => 
        parameters.licensesFilter.includes(license.id)
      );
    }

    const usageAnalytics = [];

    for (const license of targetLicenses) {
      const usage = this.licenseService.calculateLicenseUsage(license.id);
      const usageRecords = this.licenseService.usage.get(license.id) || [];
      
      // Filter records by timeframe
      const recentUsage = usageRecords.filter(record => 
        moment(record.timestamp).isAfter(cutoffDate)
      );

      const analytics = {
        licenseId: license.id,
        licenseName: license.name,
        vendor: this.licenseService.vendors.get(license.vendorId)?.name || 'Unknown',
        currentUtilization: usage.utilizationRate,
        totalSessions: recentUsage.length,
        uniqueUsers: new Set(recentUsage.map(r => r.userId)).size,
        averageSessionDuration: this.calculateAverageSessionDuration(recentUsage),
        peakConcurrentUsers: this.calculatePeakConcurrentUsers(recentUsage),
        usageTrends: this.calculateUsageTrends(recentUsage, timeframeDays),
        costPerUser: usage.currentUsers > 0 ? (license.cost || 0) / usage.currentUsers : 0,
        efficiency: this.calculateUsageEfficiency(usage, recentUsage)
      };

      usageAnalytics.push(analytics);
    }

    return {
      summary: {
        timeframe: parameters.timeframe,
        totalLicenses: usageAnalytics.length,
        averageUtilization: usageAnalytics.reduce((sum, a) => sum + a.currentUtilization, 0) / usageAnalytics.length || 0,
        totalSessions: usageAnalytics.reduce((sum, a) => sum + a.totalSessions, 0),
        totalUniqueUsers: new Set(usageAnalytics.flatMap(a => a.uniqueUsers || [])).size,
        underutilizedLicenses: usageAnalytics.filter(a => a.currentUtilization < 50).length
      },
      analytics: usageAnalytics,
      trends: this.calculateOverallUsageTrends(usageAnalytics),
      recommendations: this.generateUsageRecommendations(usageAnalytics)
    };
  }

  async generateComplianceReport(parameters) {
    const timeframeDays = this.parseTimeframeToDays(parameters.timeframe);
    const cutoffDate = moment().subtract(timeframeDays, 'days');

    // Get violations
    let violations = Array.from(this.licenseService.violations.values())
      .filter(violation => moment(violation.detectedAt).isAfter(cutoffDate));

    if (!parameters.includeResolved) {
      violations = violations.filter(violation => violation.status === 'open');
    }

    if (parameters.severityFilter !== 'all') {
      violations = violations.filter(violation => violation.severity === parameters.severityFilter);
    }

    // Get compliance scans
    const complianceScans = Array.from(this.licenseService.compliance.values())
      .filter(scan => moment(scan.startedAt).isAfter(cutoffDate))
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));

    // Analyze compliance by license
    const licenses = Array.from(this.licenseService.licenses.values());
    const complianceByLicense = licenses.map(license => {
      const licenseViolations = violations.filter(v => v.licenseId === license.id);
      const complianceCheck = this.licenseService.checkLicenseCompliance(license.id);
      
      return {
        licenseId: license.id,
        licenseName: license.name,
        vendor: this.licenseService.vendors.get(license.vendorId)?.name || 'Unknown',
        isCompliant: complianceCheck.isCompliant,
        violationCount: licenseViolations.length,
        criticalViolations: licenseViolations.filter(v => v.severity === 'critical').length,
        lastChecked: complianceCheck.lastChecked,
        riskScore: this.calculateComplianceRiskScore(license, licenseViolations)
      };
    });

    return {
      summary: {
        timeframe: parameters.timeframe,
        totalViolations: violations.length,
        openViolations: violations.filter(v => v.status === 'open').length,
        criticalViolations: violations.filter(v => v.severity === 'critical').length,
        complianceRate: (licenses.length - complianceByLicense.filter(c => !c.isCompliant).length) / licenses.length * 100,
        scansPerformed: complianceScans.length
      },
      violations: violations.map(this.enrichViolationData.bind(this)),
      complianceByLicense,
      trends: this.calculateComplianceTrends(violations, timeframeDays),
      riskAssessment: this.generateComplianceRiskAssessment(violations, complianceByLicense),
      recommendations: this.generateComplianceRecommendations(violations, complianceByLicense)
    };
  }

  async generateCostAnalysisReport(parameters) {
    const licenses = Array.from(this.licenseService.licenses.values());
    const timeframeYears = parseInt(parameters.timeframe.replace('y', ''));

    // Current costs
    const currentCosts = this.calculateCurrentCosts(licenses);
    
    // Historical costs (simulated - would need historical data)
    const historicalCosts = this.calculateHistoricalCosts(licenses, timeframeYears);
    
    // Cost breakdown
    const costBreakdown = this.calculateCostBreakdown(licenses, parameters.groupBy);
    
    // Forecast (if enabled)
    let forecast = null;
    if (parameters.includeForecast) {
      forecast = this.generateCostForecast(licenses, historicalCosts);
    }

    return {
      summary: {
        timeframe: parameters.timeframe,
        totalCurrentCost: currentCosts.total,
        monthlyRecurring: currentCosts.monthly,
        annualRecurring: currentCosts.annual,
        averageCostPerLicense: currentCosts.total / licenses.length || 0,
        costTrend: this.calculateCostTrend(historicalCosts)
      },
      currentCosts,
      historicalCosts,
      costBreakdown,
      forecast,
      topCostLicenses: this.getTopCostLicenses(licenses, 10),
      savingsOpportunities: this.identifySavingsOpportunities(licenses),
      recommendations: this.generateCostRecommendations(licenses, costBreakdown)
    };
  }

  async generateOptimizationReport(parameters) {
    // Get optimization analysis
    const optimizationService = this.licenseService.optimizationService;
    const analysis = await optimizationService.performOptimizationAnalysis();

    let recommendations = analysis.results.recommendations;

    // Apply filters
    if (parameters.priorityFilter !== 'all') {
      recommendations = recommendations.filter(rec => rec.priority === parameters.priorityFilter);
    }

    if (parameters.savingsThreshold) {
      recommendations = recommendations.filter(rec => 
        (rec.potentialSavings || 0) >= parameters.savingsThreshold
      );
    }

    // Implementation plan
    let implementationPlan = null;
    if (parameters.includeImplementationPlan) {
      implementationPlan = this.generateDetailedImplementationPlan(recommendations);
    }

    return {
      summary: {
        totalOpportunities: recommendations.length,
        totalPotentialSavings: recommendations.reduce((sum, rec) => sum + (rec.potentialSavings || 0), 0),
        quickWins: recommendations.filter(rec => rec.implementation?.effort === 'low').length,
        implementationEffort: analysis.summary.implementationEffort,
        averageROI: this.calculateAverageROI(recommendations)
      },
      recommendations,
      implementationPlan,
      riskAssessment: analysis.results.riskAssessment,
      costBenefitAnalysis: this.generateCostBenefitAnalysis(recommendations),
      timeline: this.generateOptimizationTimeline(recommendations)
    };
  }

  async generateRenewalScheduleReport(parameters) {
    const cutoffDate = moment().add(parameters.lookAheadDays, 'days');
    
    let upcomingRenewals = Array.from(this.licenseService.licenses.values())
      .filter(license => 
        license.expiryDate && 
        moment(license.expiryDate).isBefore(cutoffDate) &&
        license.status === 'active'
      );

    if (!parameters.includeAutoRenewal) {
      upcomingRenewals = upcomingRenewals.filter(license => 
        !license.terms?.autoRenewal
      );
    }

    // Sort renewals
    const sortField = parameters.sortBy;
    upcomingRenewals.sort((a, b) => {
      switch (sortField) {
        case 'date':
          return new Date(a.expiryDate) - new Date(b.expiryDate);
        case 'cost':
          return (b.cost || 0) - (a.cost || 0);
        case 'name':
          return a.name.localeCompare(b.name);
        default:
          return new Date(a.expiryDate) - new Date(b.expiryDate);
      }
    });

    // Enrich renewal data
    const renewalSchedule = upcomingRenewals.map(license => ({
      licenseId: license.id,
      licenseName: license.name,
      vendor: this.licenseService.vendors.get(license.vendorId)?.name || 'Unknown',
      expiryDate: license.expiryDate,
      daysUntilExpiry: moment(license.expiryDate).diff(moment(), 'days'),
      currentCost: license.cost || 0,
      usage: this.licenseService.calculateLicenseUsage(license.id),
      autoRenewal: license.terms?.autoRenewal || false,
      renewalPriority: this.calculateRenewalPriority(license),
      recommendedAction: this.getRecommendedRenewalAction(license),
      estimatedRenewalCost: this.estimateRenewalCost(license)
    }));

    // Group by time periods
    const groupedByPeriod = {
      thisMonth: renewalSchedule.filter(r => r.daysUntilExpiry <= 30),
      nextMonth: renewalSchedule.filter(r => r.daysUntilExpiry > 30 && r.daysUntilExpiry <= 60),
      thisQuarter: renewalSchedule.filter(r => r.daysUntilExpiry > 60 && r.daysUntilExpiry <= 90),
      beyondQuarter: renewalSchedule.filter(r => r.daysUntilExpiry > 90)
    };

    return {
      summary: {
        totalRenewals: renewalSchedule.length,
        totalEstimatedCost: renewalSchedule.reduce((sum, r) => sum + r.estimatedRenewalCost, 0),
        urgentRenewals: renewalSchedule.filter(r => r.daysUntilExpiry <= 30).length,
        autoRenewals: renewalSchedule.filter(r => r.autoRenewal).length,
        highPriorityRenewals: renewalSchedule.filter(r => r.renewalPriority === 'high').length
      },
      renewalSchedule,
      groupedByPeriod,
      budgetPlanning: this.generateRenewalBudgetPlan(renewalSchedule),
      actionItems: this.generateRenewalActionItems(renewalSchedule)
    };
  }

  async generateExecutiveSummaryReport(parameters) {
    const licenses = Array.from(this.licenseService.licenses.values());
    const violations = Array.from(this.licenseService.violations.values());
    const alerts = Array.from(this.licenseService.alerts.values());

    // Key metrics
    const metrics = {
      totalLicenses: licenses.length,
      activeLicenses: licenses.filter(l => l.status === 'active').length,
      totalCost: licenses.reduce((sum, l) => sum + (l.cost || 0), 0),
      averageUtilization: this.calculateOverallUtilization(licenses),
      complianceRate: this.calculateOverallComplianceRate(licenses, violations),
      openViolations: violations.filter(v => v.status === 'open').length,
      activeAlerts: alerts.filter(a => a.status === 'open').length
    };

    // Key insights
    const insights = [
      this.generateCostInsight(licenses),
      this.generateUtilizationInsight(licenses),
      this.generateComplianceInsight(violations),
      this.generateRenewalInsight(licenses)
    ].filter(insight => insight !== null);

    // Top recommendations
    const recommendations = await this.getTopExecutiveRecommendations(licenses, violations);

    return {
      reportDate: new Date().toISOString(),
      executiveSummary: {
        overview: this.generateExecutiveOverview(metrics),
        keyMetrics: metrics,
        insights,
        recommendations: parameters.includeRecommendations ? recommendations : undefined,
        alerts: parameters.includeAlerts ? this.getExecutiveAlerts(alerts) : undefined
      },
      trends: {
        costTrend: 'increasing', // Would calculate from historical data
        utilizationTrend: 'stable',
        complianceTrend: 'improving'
      },
      nextSteps: this.generateExecutiveNextSteps(metrics, insights, recommendations)
    };
  }

  async generateAuditTrailReport(parameters) {
    const timeframeDays = this.parseTimeframeToDays(parameters.timeframe);
    const cutoffDate = moment().subtract(timeframeDays, 'days');

    let auditLogs = Array.from(this.licenseService.auditLogs.values())
      .filter(log => moment(log.timestamp).isAfter(cutoffDate));

    // Apply filters
    if (parameters.actionsFilter && parameters.actionsFilter.length > 0) {
      auditLogs = auditLogs.filter(log => 
        parameters.actionsFilter.includes(log.action)
      );
    }

    if (parameters.userFilter) {
      auditLogs = auditLogs.filter(log => 
        log.details.createdBy === parameters.userFilter ||
        log.details.updatedBy === parameters.userFilter ||
        log.details.deletedBy === parameters.userFilter
      );
    }

    // Sort by timestamp (newest first)
    auditLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Analyze audit patterns
    const auditAnalysis = {
      totalActions: auditLogs.length,
      uniqueUsers: new Set(auditLogs.map(log => 
        log.details.createdBy || log.details.updatedBy || 'system'
      )).size,
      actionBreakdown: this.groupAuditLogsByAction(auditLogs),
      userActivity: this.analyzeUserActivity(auditLogs),
      timelineAnalysis: this.analyzeAuditTimeline(auditLogs)
    };

    return {
      summary: {
        timeframe: parameters.timeframe,
        totalEntries: auditLogs.length,
        uniqueUsers: auditAnalysis.uniqueUsers,
        mostActiveUser: this.getMostActiveUser(auditLogs),
        mostCommonAction: this.getMostCommonAction(auditLogs)
      },
      auditLogs: auditLogs.slice(0, 1000), // Limit to 1000 entries for report
      analysis: auditAnalysis,
      securityInsights: this.generateSecurityInsights(auditLogs),
      compliance: {
        dataRetention: this.checkDataRetentionCompliance(),
        accessControls: this.analyzeAccessPatterns(auditLogs)
      }
    };
  }

  async generateMobileLicenseReport(parameters) {
    const mobileLicenses = Array.from(this.licenseService.licenses.values())
      .filter(license => license.source === 'mobile');

    let filteredLicenses = mobileLicenses;

    if (parameters.platformFilter !== 'all') {
      filteredLicenses = filteredLicenses.filter(license => 
        license.mobileData?.platform === parameters.platformFilter
      );
    }

    // Enrich with usage data
    const enrichedLicenses = filteredLicenses.map(license => {
      const usage = parameters.includeUsage ? 
        this.licenseService.calculateLicenseUsage(license.id) : null;
      const compliance = parameters.includeCompliance ? 
        this.licenseService.checkLicenseCompliance(license.id) : null;

      return {
        ...license,
        usage,
        compliance,
        deviceCount: this.calculateMobileDeviceCount(license),
        userCount: this.calculateMobileUserCount(license)
      };
    });

    // Mobile-specific analytics
    const mobileAnalytics = {
      platformDistribution: this.calculatePlatformDistribution(enrichedLicenses),
      averageUtilization: this.calculateMobileUtilization(enrichedLicenses),
      topApps: this.getTopMobileApps(enrichedLicenses, 10),
      complianceStatus: this.getMobileComplianceStatus(enrichedLicenses)
    };

    return {
      summary: {
        totalMobileLicenses: filteredLicenses.length,
        totalCost: filteredLicenses.reduce((sum, l) => sum + (l.cost || 0), 0),
        averageUtilization: mobileAnalytics.averageUtilization,
        complianceRate: mobileAnalytics.complianceStatus.complianceRate
      },
      licenses: enrichedLicenses,
      analytics: mobileAnalytics,
      trends: this.calculateMobileTrends(enrichedLicenses),
      recommendations: this.generateMobileRecommendations(enrichedLicenses)
    };
  }

  // Output Formatting Functions
  async formatReportOutput(reportData, format, template) {
    switch (format) {
      case 'json':
        return reportData;
      case 'excel':
        return await this.generateExcelOutput(reportData, template);
      case 'pdf':
        return await this.generatePDFOutput(reportData, template);
      default:
        throw new Error(`Unsupported output format: ${format}`);
    }
  }

  async generateExcelOutput(reportData, template) {
    const workbook = XLSX.utils.book_new();

    // Summary sheet
    if (reportData.summary) {
      const summarySheet = XLSX.utils.json_to_sheet([reportData.summary]);
      XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');
    }

    // Main data sheet
    if (reportData.details) {
      const dataSheet = XLSX.utils.json_to_sheet(reportData.details);
      XLSX.utils.book_append_sheet(workbook, dataSheet, 'Data');
    } else if (reportData.licenses) {
      const dataSheet = XLSX.utils.json_to_sheet(reportData.licenses);
      XLSX.utils.book_append_sheet(workbook, dataSheet, 'Licenses');
    }

    // Additional sheets based on report type
    if (reportData.violations) {
      const violationsSheet = XLSX.utils.json_to_sheet(reportData.violations);
      XLSX.utils.book_append_sheet(workbook, violationsSheet, 'Violations');
    }

    if (reportData.recommendations) {
      const recommendationsSheet = XLSX.utils.json_to_sheet(reportData.recommendations);
      XLSX.utils.book_append_sheet(workbook, recommendationsSheet, 'Recommendations');
    }

    // Convert to buffer
    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  async generatePDFOutput(reportData, template) {
    // Create PDF document
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage();
    const { width, height } = page.getSize();

    // Add title
    page.drawText(template.name, {
      x: 50,
      y: height - 50,
      size: 20
    });

    // Add generation date
    page.drawText(`Generated: ${moment().format('YYYY-MM-DD HH:mm:ss')}`, {
      x: 50,
      y: height - 80,
      size: 12
    });

    // Add summary data
    if (reportData.summary) {
      let yPosition = height - 120;
      Object.entries(reportData.summary).forEach(([key, value]) => {
        page.drawText(`${key}: ${value}`, {
          x: 50,
          y: yPosition,
          size: 10
        });
        yPosition -= 20;
      });
    }

    // Save PDF to buffer
    return await pdfDoc.save();
  }

  // Helper Functions
  parseTimeframeToDays(timeframe) {
    const map = {
      '7d': 7,
      '30d': 30,
      '90d': 90,
      '1y': 365,
      '2y': 730,
      '3y': 1095
    };
    return map[timeframe] || 30;
  }

  groupLicensesByField(licenses, field) {
    const groups = {};
    
    licenses.forEach(license => {
      let groupKey;
      switch (field) {
        case 'vendor':
          groupKey = license.vendor?.name || 'Unknown';
          break;
        case 'type':
          groupKey = license.type || 'Unknown';
          break;
        case 'status':
          groupKey = license.status || 'Unknown';
          break;
        default:
          groupKey = 'All';
      }
      
      if (!groups[groupKey]) {
        groups[groupKey] = [];
      }
      groups[groupKey].push(license);
    });

    return groups;
  }

  calculateReportSize(data) {
    if (Buffer.isBuffer(data)) {
      return data.length;
    }
    return JSON.stringify(data).length;
  }

  getRecordCount(reportData) {
    if (reportData.details) return reportData.details.length;
    if (reportData.licenses) return reportData.licenses.length;
    if (reportData.auditLogs) return reportData.auditLogs.length;
    return 0;
  }

  // Cleanup old reports
  async cleanupOldReports() {
    const retentionDays = 90;
    const cutoffDate = moment().subtract(retentionDays, 'days');

    for (const [reportId, report] of this.licenseService.reports) {
      if (moment(report.startedAt).isBefore(cutoffDate)) {
        this.licenseService.reports.delete(reportId);
        this.reportCache.delete(reportId);
      }
    }
  }

  // Scheduled Reports
  async scheduleReport(templateId, parameters, schedule, outputFormat = 'pdf', recipients = []) {
    const scheduleId = uuidv4();
    const scheduledReport = {
      id: scheduleId,
      templateId,
      parameters,
      outputFormat,
      schedule, // cron expression
      recipients,
      enabled: true,
      createdAt: new Date().toISOString(),
      lastRun: null,
      nextRun: this.calculateNextRun(schedule),
      runCount: 0
    };

    this.scheduledReports.set(scheduleId, scheduledReport);
    return scheduledReport;
  }

  async processScheduledReports() {
    const now = new Date();
    
    for (const [scheduleId, scheduledReport] of this.scheduledReports) {
      if (scheduledReport.enabled && 
          scheduledReport.nextRun && 
          new Date(scheduledReport.nextRun) <= now) {
        
        try {
          await this.runScheduledReport(scheduledReport);
          
          // Update schedule
          scheduledReport.lastRun = new Date().toISOString();
          scheduledReport.nextRun = this.calculateNextRun(scheduledReport.schedule);
          scheduledReport.runCount++;
          
          this.scheduledReports.set(scheduleId, scheduledReport);
          
        } catch (error) {
          this.licenseService.logger.error('Scheduled report failed', {
            scheduleId,
            error: error.message
          });
        }
      }
    }
  }

  async runScheduledReport(scheduledReport) {
    const report = await this.generateReport(
      scheduledReport.templateId,
      scheduledReport.parameters,
      scheduledReport.outputFormat
    );

    // Send to recipients
    if (scheduledReport.recipients.length > 0) {
      await this.distributeReport(report, scheduledReport.recipients);
    }

    return report;
  }

  calculateNextRun(cronExpression) {
    // Simple cron calculation - would use a proper cron library in production
    const now = moment();
    
    // For demo, assume daily at 9 AM
    if (cronExpression === '0 9 * * *') {
      const nextRun = now.clone().hour(9).minute(0).second(0);
      if (nextRun.isBefore(now)) {
        nextRun.add(1, 'day');
      }
      return nextRun.toISOString();
    }
    
    // Default to next day
    return now.add(1, 'day').toISOString();
  }

  async distributeReport(report, recipients) {
    // Implementation would depend on distribution method (email, file share, etc.)
    this.licenseService.logger.info('Report distributed', {
      reportId: report.id,
      recipients: recipients.length
    });
  }

  // Public API Methods
  getReportTemplates() {
    return Array.from(this.reportTemplates.values());
  }

  getReportHistory(limit = 50) {
    return Array.from(this.licenseService.reports.values())
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
      .slice(0, limit);
  }

  async downloadReport(reportId) {
    const cachedReport = this.reportCache.get(reportId);
    if (cachedReport && moment(cachedReport.expiresAt).isAfter(moment())) {
      return cachedReport.data;
    }

    const report = this.licenseService.reports.get(reportId);
    if (!report || report.status !== 'completed') {
      throw new Error('Report not found or not completed');
    }

    return report.data;
  }
}

module.exports = ReportingService;