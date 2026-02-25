const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const nodemailer = require('nodemailer');

class AlertService {
  constructor(licenseService) {
    this.licenseService = licenseService;
    this.alertRules = new Map();
    this.alertChannels = new Map();
    this.notificationHistory = new Map();
    this.activeAlerts = new Map();
    
    this.initializeAlertRules();
    this.initializeAlertChannels();
    this.startAlertMonitoring();
  }

  initializeAlertRules() {
    // License Expiry Alert
    this.alertRules.set('license_expiry', {
      id: 'license_expiry',
      name: 'License Expiry Alert',
      description: 'Alert when licenses are approaching expiry',
      category: 'expiry',
      severity: 'high',
      enabled: true,
      conditions: {
        daysBeforeExpiry: [30, 14, 7, 1], // Multiple warning thresholds
        licenseTypes: ['all'] // or specific types
      },
      checkFunction: this.checkLicenseExpiry.bind(this)
    });

    // Usage Overrun Alert
    this.alertRules.set('usage_overrun', {
      id: 'usage_overrun',
      name: 'License Usage Overrun',
      description: 'Alert when license usage exceeds allowed limits',
      category: 'usage',
      severity: 'critical',
      enabled: true,
      conditions: {
        overageThreshold: 0, // Any overage
        sustainedMinutes: 5 // Must be sustained for 5 minutes
      },
      checkFunction: this.checkUsageOverrun.bind(this)
    });

    // High Utilization Alert
    this.alertRules.set('high_utilization', {
      id: 'high_utilization',
      name: 'High License Utilization',
      description: 'Alert when license utilization is consistently high',
      category: 'usage',
      severity: 'medium',
      enabled: true,
      conditions: {
        utilizationThreshold: 85, // 85% utilization
        sustainedHours: 2 // Must be sustained for 2 hours
      },
      checkFunction: this.checkHighUtilization.bind(this)
    });

    // Maintenance Expiry Alert
    this.alertRules.set('maintenance_expiry', {
      id: 'maintenance_expiry',
      name: 'Maintenance Contract Expiry',
      description: 'Alert when maintenance contracts are expiring',
      category: 'maintenance',
      severity: 'medium',
      enabled: true,
      conditions: {
        daysBeforeExpiry: [60, 30, 14]
      },
      checkFunction: this.checkMaintenanceExpiry.bind(this)
    });

    // Compliance Violation Alert
    this.alertRules.set('compliance_violation', {
      id: 'compliance_violation',
      name: 'Compliance Violation Detected',
      description: 'Alert when license compliance violations are detected',
      category: 'compliance',
      severity: 'critical',
      enabled: true,
      conditions: {
        violationTypes: ['overusage', 'expired', 'unauthorized_platform']
      },
      checkFunction: this.checkComplianceViolations.bind(this)
    });

    // Low Utilization Alert
    this.alertRules.set('low_utilization', {
      id: 'low_utilization',
      name: 'Low License Utilization',
      description: 'Alert when licenses have consistently low utilization',
      category: 'optimization',
      severity: 'low',
      enabled: true,
      conditions: {
        utilizationThreshold: 20, // Below 20% utilization
        sustainedDays: 30 // For 30 days
      },
      checkFunction: this.checkLowUtilization.bind(this)
    });

    // Cost Threshold Alert
    this.alertRules.set('cost_threshold', {
      id: 'cost_threshold',
      name: 'License Cost Threshold Exceeded',
      description: 'Alert when license costs exceed defined thresholds',
      category: 'cost',
      severity: 'medium',
      enabled: true,
      conditions: {
        monthlyThreshold: 10000, // $10,000 per month
        annualThreshold: 100000  // $100,000 per year
      },
      checkFunction: this.checkCostThresholds.bind(this)
    });

    // Renewal Due Alert
    this.alertRules.set('renewal_due', {
      id: 'renewal_due',
      name: 'License Renewal Due',
      description: 'Alert for upcoming license renewals requiring action',
      category: 'renewal',
      severity: 'high',
      enabled: true,
      conditions: {
        daysBeforeRenewal: [90, 60, 30, 14],
        autoRenewalOnly: false // Alert for all renewals or only manual ones
      },
      checkFunction: this.checkRenewalsDue.bind(this)
    });
  }

  initializeAlertChannels() {
    // Email Channel
    this.alertChannels.set('email', {
      id: 'email',
      name: 'Email Notifications',
      type: 'email',
      enabled: this.licenseService.config.alertingEnabled,
      configuration: {
        smtp: this.licenseService.config.emailConfig.smtp,
        defaultRecipients: [
          'license-admin@company.com',
          'it-manager@company.com'
        ],
        templates: {
          critical: 'critical_alert_template',
          high: 'high_alert_template',
          medium: 'medium_alert_template',
          low: 'low_alert_template'
        }
      },
      sendFunction: this.sendEmailAlert.bind(this)
    });

    // WebSocket Channel
    this.alertChannels.set('websocket', {
      id: 'websocket',
      name: 'Real-time WebSocket Alerts',
      type: 'realtime',
      enabled: true,
      configuration: {
        subscriptions: ['critical_alerts', 'license_alerts', 'usage_alerts']
      },
      sendFunction: this.sendWebSocketAlert.bind(this)
    });

    // Webhook Channel
    this.alertChannels.set('webhook', {
      id: 'webhook',
      name: 'Webhook Notifications',
      type: 'webhook',
      enabled: false,
      configuration: {
        endpoints: [
          // 'https://hooks.slack.com/services/...',
          // 'https://api.pagerduty.com/...'
        ],
        retryAttempts: 3,
        timeout: 5000
      },
      sendFunction: this.sendWebhookAlert.bind(this)
    });

    // Database Log Channel
    this.alertChannels.set('database', {
      id: 'database',
      name: 'Database Alert Log',
      type: 'storage',
      enabled: true,
      configuration: {
        retention: 365 // days
      },
      sendFunction: this.logAlert.bind(this)
    });
  }

  startAlertMonitoring() {
    // Real-time monitoring interval (every minute)
    setInterval(() => {
      this.runRealTimeChecks();
    }, 60000); // 1 minute

    // Comprehensive monitoring interval (every 5 minutes)
    setInterval(() => {
      this.runComprehensiveChecks();
    }, 5 * 60000); // 5 minutes

    // Daily summary and cleanup
    setInterval(() => {
      this.runDailyMaintenance();
    }, 24 * 60 * 60000); // 24 hours

    this.licenseService.logger.info('Alert monitoring started');
  }

  async runRealTimeChecks() {
    const realTimeRules = ['usage_overrun', 'compliance_violation'];
    
    for (const ruleId of realTimeRules) {
      const rule = this.alertRules.get(ruleId);
      if (rule && rule.enabled) {
        try {
          await this.executeAlertRule(rule);
        } catch (error) {
          this.licenseService.logger.error('Real-time alert check failed', {
            ruleId,
            error: error.message
          });
        }
      }
    }
  }

  async runComprehensiveChecks() {
    const comprehensiveRules = [
      'license_expiry', 'high_utilization', 'maintenance_expiry', 
      'renewal_due', 'cost_threshold'
    ];
    
    for (const ruleId of comprehensiveRules) {
      const rule = this.alertRules.get(ruleId);
      if (rule && rule.enabled) {
        try {
          await this.executeAlertRule(rule);
        } catch (error) {
          this.licenseService.logger.error('Comprehensive alert check failed', {
            ruleId,
            error: error.message
          });
        }
      }
    }
  }

  async runDailyMaintenance() {
    try {
      // Check for low utilization (daily check is sufficient)
      const lowUtilRule = this.alertRules.get('low_utilization');
      if (lowUtilRule && lowUtilRule.enabled) {
        await this.executeAlertRule(lowUtilRule);
      }

      // Cleanup old alerts
      await this.cleanupOldAlerts();

      // Generate daily alert summary
      await this.generateDailyAlertSummary();

      this.licenseService.logger.info('Daily alert maintenance completed');
    } catch (error) {
      this.licenseService.logger.error('Daily alert maintenance failed', {
        error: error.message
      });
    }
  }

  async executeAlertRule(rule) {
    try {
      const alertResults = await rule.checkFunction(rule);
      
      if (alertResults && alertResults.length > 0) {
        for (const alertData of alertResults) {
          await this.createAlert(rule, alertData);
        }
      }
    } catch (error) {
      this.licenseService.logger.error('Alert rule execution failed', {
        ruleId: rule.id,
        error: error.message
      });
    }
  }

  async createAlert(rule, alertData) {
    const alertId = uuidv4();
    
    // Check for duplicate alerts (avoid spam)
    const isDuplicate = this.isDuplicateAlert(rule, alertData);
    if (isDuplicate) {
      return null;
    }

    const alert = {
      id: alertId,
      ruleId: rule.id,
      ruleName: rule.name,
      category: rule.category,
      severity: rule.severity,
      title: alertData.title || rule.name,
      message: alertData.message,
      details: alertData.details || {},
      licenseId: alertData.licenseId || null,
      licenseName: alertData.licenseName || null,
      assetId: alertData.assetId || null,
      status: 'open',
      createdAt: new Date().toISOString(),
      acknowledgedAt: null,
      acknowledgedBy: null,
      resolvedAt: null,
      resolvedBy: null,
      escalatedAt: null,
      escalatedTo: null,
      notificationsSent: [],
      metadata: alertData.metadata || {}
    };

    // Store the alert
    this.licenseService.alerts.set(alertId, alert);
    this.activeAlerts.set(alertId, alert);

    // Send notifications through configured channels
    await this.sendAlertNotifications(alert);

    // Log alert creation
    this.licenseService.logAuditEvent('alert_created', {
      alertId,
      ruleId: rule.id,
      severity: alert.severity,
      licenseId: alert.licenseId
    });

    // Broadcast to WebSocket subscribers
    this.licenseService.broadcastToSubscribers('alert_created', {
      alertId,
      alert: alert
    });

    this.licenseService.logger.info('Alert created', {
      alertId,
      ruleId: rule.id,
      severity: alert.severity,
      title: alert.title
    });

    return alert;
  }

  async sendAlertNotifications(alert) {
    const enabledChannels = Array.from(this.alertChannels.values())
      .filter(channel => channel.enabled);

    for (const channel of enabledChannels) {
      try {
        await channel.sendFunction(alert, channel);
        
        alert.notificationsSent.push({
          channel: channel.id,
          sentAt: new Date().toISOString(),
          status: 'sent'
        });
      } catch (error) {
        this.licenseService.logger.error('Alert notification failed', {
          alertId: alert.id,
          channel: channel.id,
          error: error.message
        });
        
        alert.notificationsSent.push({
          channel: channel.id,
          sentAt: new Date().toISOString(),
          status: 'failed',
          error: error.message
        });
      }
    }

    // Update alert with notification status
    this.licenseService.alerts.set(alert.id, alert);
  }

  isDuplicateAlert(rule, alertData) {
    const recentAlerts = Array.from(this.activeAlerts.values())
      .filter(alert => 
        alert.ruleId === rule.id &&
        alert.status === 'open' &&
        alert.licenseId === alertData.licenseId &&
        moment(alert.createdAt).isAfter(moment().subtract(1, 'hour'))
      );

    return recentAlerts.length > 0;
  }

  // Alert Rule Check Functions
  async checkLicenseExpiry(rule) {
    const alerts = [];
    const thresholds = rule.conditions.daysBeforeExpiry;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (!license.expiryDate || license.status !== 'active') continue;

      const daysUntilExpiry = moment(license.expiryDate).diff(moment(), 'days');
      
      if (thresholds.includes(daysUntilExpiry)) {
        alerts.push({
          title: `License Expiring in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? 's' : ''}`,
          message: `License "${license.name}" expires on ${moment(license.expiryDate).format('YYYY-MM-DD')}`,
          licenseId: license.id,
          licenseName: license.name,
          details: {
            expiryDate: license.expiryDate,
            daysUntilExpiry,
            vendor: this.licenseService.vendors.get(license.vendorId)?.name || 'Unknown'
          }
        });
      }
    }

    return alerts;
  }

  async checkUsageOverrun(rule) {
    const alerts = [];
    const overageThreshold = rule.conditions.overageThreshold;
    const sustainedMinutes = rule.conditions.sustainedMinutes;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active') continue;

      const currentUsage = this.licenseService.calculateCurrentUsage(licenseId);
      const overage = currentUsage.activeUsers - currentUsage.maxConcurrent;

      if (overage > overageThreshold) {
        // Check if overage has been sustained
        const isSustained = await this.checkSustainedOverage(licenseId, sustainedMinutes);
        
        if (isSustained) {
          alerts.push({
            title: `License Usage Overrun: ${license.name}`,
            message: `License usage (${currentUsage.activeUsers}) exceeds limit (${currentUsage.maxConcurrent}) by ${overage} user${overage !== 1 ? 's' : ''}`,
            licenseId: license.id,
            licenseName: license.name,
            details: {
              currentUsers: currentUsage.activeUsers,
              maxUsers: currentUsage.maxConcurrent,
              overage,
              utilizationRate: currentUsage.utilizationRate
            }
          });
        }
      }
    }

    return alerts;
  }

  async checkHighUtilization(rule) {
    const alerts = [];
    const utilizationThreshold = rule.conditions.utilizationThreshold;
    const sustainedHours = rule.conditions.sustainedHours;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active') continue;

      const currentUsage = this.licenseService.calculateCurrentUsage(licenseId);
      
      if (currentUsage.utilizationRate >= utilizationThreshold) {
        // Check if high utilization has been sustained
        const isSustained = await this.checkSustainedHighUtilization(licenseId, utilizationThreshold, sustainedHours);
        
        if (isSustained) {
          alerts.push({
            title: `High License Utilization: ${license.name}`,
            message: `License utilization (${currentUsage.utilizationRate.toFixed(1)}%) has exceeded ${utilizationThreshold}% for ${sustainedHours} hours`,
            licenseId: license.id,
            licenseName: license.name,
            details: {
              currentUtilization: currentUsage.utilizationRate,
              threshold: utilizationThreshold,
              sustainedHours,
              recommendation: 'Consider increasing license quantity or monitoring usage patterns'
            }
          });
        }
      }
    }

    return alerts;
  }

  async checkMaintenanceExpiry(rule) {
    const alerts = [];
    const thresholds = rule.conditions.daysBeforeExpiry;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (!license.maintenance?.included || !license.maintenance.expiryDate || license.status !== 'active') continue;

      const daysUntilExpiry = moment(license.maintenance.expiryDate).diff(moment(), 'days');
      
      if (thresholds.includes(daysUntilExpiry)) {
        alerts.push({
          title: `Maintenance Contract Expiring in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? 's' : ''}`,
          message: `Maintenance contract for "${license.name}" expires on ${moment(license.maintenance.expiryDate).format('YYYY-MM-DD')}`,
          licenseId: license.id,
          licenseName: license.name,
          details: {
            maintenanceExpiryDate: license.maintenance.expiryDate,
            daysUntilExpiry,
            maintenanceCost: license.maintenance.cost || 0,
            autoRenewal: license.maintenance.autoRenewal || false
          }
        });
      }
    }

    return alerts;
  }

  async checkComplianceViolations(rule) {
    const alerts = [];
    const violationTypes = rule.conditions.violationTypes;

    // Check recent violations
    const recentViolations = Array.from(this.licenseService.violations.values())
      .filter(violation => 
        violationTypes.includes(violation.type) &&
        moment(violation.detectedAt).isAfter(moment().subtract(5, 'minutes')) &&
        violation.status === 'open'
      );

    for (const violation of recentViolations) {
      const license = this.licenseService.licenses.get(violation.licenseId);
      
      alerts.push({
        title: `Compliance Violation: ${violation.type}`,
        message: `Compliance violation detected for license "${license?.name || 'Unknown'}"`,
        licenseId: violation.licenseId,
        licenseName: license?.name || 'Unknown',
        details: {
          violationType: violation.type,
          severity: violation.severity,
          violationDetails: violation.details,
          detectedAt: violation.detectedAt
        },
        metadata: {
          violationId: violation.id
        }
      });
    }

    return alerts;
  }

  async checkLowUtilization(rule) {
    const alerts = [];
    const utilizationThreshold = rule.conditions.utilizationThreshold;
    const sustainedDays = rule.conditions.sustainedDays;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active') continue;

      const currentUsage = this.licenseService.calculateLicenseUsage(licenseId);
      
      if (currentUsage.utilizationRate <= utilizationThreshold) {
        // Check if low utilization has been sustained
        const isSustained = await this.checkSustainedLowUtilization(licenseId, utilizationThreshold, sustainedDays);
        
        if (isSustained) {
          alerts.push({
            title: `Low License Utilization: ${license.name}`,
            message: `License utilization (${currentUsage.utilizationRate.toFixed(1)}%) has been below ${utilizationThreshold}% for ${sustainedDays} days`,
            licenseId: license.id,
            licenseName: license.name,
            details: {
              currentUtilization: currentUsage.utilizationRate,
              threshold: utilizationThreshold,
              sustainedDays,
              potentialSavings: this.calculateUnderutilizationSavings(license, currentUsage),
              recommendation: 'Consider reducing license quantity or reallocating to other teams'
            }
          });
        }
      }
    }

    return alerts;
  }

  async checkCostThresholds(rule) {
    const alerts = [];
    const monthlyThreshold = rule.conditions.monthlyThreshold;
    const annualThreshold = rule.conditions.annualThreshold;

    // Calculate current costs
    const currentMonthCosts = this.calculateCurrentMonthCosts();
    const projectedAnnualCosts = this.calculateProjectedAnnualCosts();

    if (currentMonthCosts > monthlyThreshold) {
      alerts.push({
        title: 'Monthly License Cost Threshold Exceeded',
        message: `Current month license costs ($${currentMonthCosts.toLocaleString()}) exceed threshold ($${monthlyThreshold.toLocaleString()})`,
        details: {
          currentCosts: currentMonthCosts,
          threshold: monthlyThreshold,
          overage: currentMonthCosts - monthlyThreshold,
          topCostLicenses: this.getTopCostLicenses(5)
        }
      });
    }

    if (projectedAnnualCosts > annualThreshold) {
      alerts.push({
        title: 'Annual License Cost Projection Exceeded',
        message: `Projected annual license costs ($${projectedAnnualCosts.toLocaleString()}) exceed threshold ($${annualThreshold.toLocaleString()})`,
        details: {
          projectedCosts: projectedAnnualCosts,
          threshold: annualThreshold,
          overage: projectedAnnualCosts - annualThreshold,
          recommendation: 'Review license optimization opportunities'
        }
      });
    }

    return alerts;
  }

  async checkRenewalsDue(rule) {
    const alerts = [];
    const thresholds = rule.conditions.daysBeforeRenewal;
    const autoRenewalOnly = rule.conditions.autoRenewalOnly;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (!license.expiryDate || license.status !== 'active') continue;
      
      // Skip auto-renewal licenses if configured to do so
      if (autoRenewalOnly && license.terms?.autoRenewal) continue;

      const daysUntilRenewal = moment(license.expiryDate).diff(moment(), 'days');
      
      if (thresholds.includes(daysUntilRenewal)) {
        alerts.push({
          title: `License Renewal Due in ${daysUntilRenewal} day${daysUntilRenewal !== 1 ? 's' : ''}`,
          message: `License "${license.name}" requires renewal action by ${moment(license.expiryDate).format('YYYY-MM-DD')}`,
          licenseId: license.id,
          licenseName: license.name,
          details: {
            renewalDate: license.expiryDate,
            daysUntilRenewal,
            currentCost: license.cost || 0,
            autoRenewal: license.terms?.autoRenewal || false,
            vendor: this.licenseService.vendors.get(license.vendorId)?.name || 'Unknown'
          }
        });
      }
    }

    return alerts;
  }

  // Alert Notification Functions
  async sendEmailAlert(alert, channel) {
    if (!channel.configuration.smtp.host) {
      throw new Error('SMTP configuration not available');
    }

    const transporter = nodemailer.createTransporter({
      host: channel.configuration.smtp.host,
      port: channel.configuration.smtp.port,
      secure: channel.configuration.smtp.port === 465,
      auth: {
        user: channel.configuration.smtp.user,
        pass: channel.configuration.smtp.password
      }
    });

    const template = this.getEmailTemplate(alert.severity);
    const emailContent = this.generateEmailContent(alert, template);

    const mailOptions = {
      from: channel.configuration.smtp.user,
      to: channel.configuration.defaultRecipients.join(', '),
      subject: `[${alert.severity.toUpperCase()}] ${alert.title}`,
      html: emailContent
    };

    await transporter.sendMail(mailOptions);
  }

  async sendWebSocketAlert(alert, channel) {
    // Send to all subscribed WebSocket clients
    this.licenseService.broadcastToSubscribers('license_alert', {
      alertId: alert.id,
      alert: alert
    });
  }

  async sendWebhookAlert(alert, channel) {
    const axios = require('axios');
    
    for (const endpoint of channel.configuration.endpoints) {
      try {
        await axios.post(endpoint, {
          alert: alert,
          timestamp: new Date().toISOString(),
          service: 'license-management'
        }, {
          timeout: channel.configuration.timeout,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'OpenDirectory-LicenseManagement/1.0'
          }
        });
      } catch (error) {
        // Retry logic could be added here
        throw error;
      }
    }
  }

  async logAlert(alert, channel) {
    // Already stored in licenseService.alerts, but could store in separate alert log
    const logEntry = {
      id: uuidv4(),
      alertId: alert.id,
      timestamp: new Date().toISOString(),
      severity: alert.severity,
      category: alert.category,
      title: alert.title,
      message: alert.message,
      licenseId: alert.licenseId,
      metadata: alert.metadata
    };

    this.notificationHistory.set(logEntry.id, logEntry);
  }

  // Helper Functions
  async checkSustainedOverage(licenseId, minutes) {
    const usageRecords = this.licenseService.usage.get(licenseId) || [];
    const cutoffTime = moment().subtract(minutes, 'minutes');
    
    const recentRecords = usageRecords.filter(record => 
      moment(record.timestamp).isAfter(cutoffTime)
    );

    // Simplified check - in reality would need more sophisticated analysis
    return recentRecords.length > 0;
  }

  async checkSustainedHighUtilization(licenseId, threshold, hours) {
    // This would typically check historical usage data
    // For now, return true if current usage exceeds threshold
    const currentUsage = this.licenseService.calculateCurrentUsage(licenseId);
    return currentUsage.utilizationRate >= threshold;
  }

  async checkSustainedLowUtilization(licenseId, threshold, days) {
    // This would typically check historical usage data over the specified period
    // For now, return true if current usage is below threshold
    const currentUsage = this.licenseService.calculateLicenseUsage(licenseId);
    return currentUsage.utilizationRate <= threshold;
  }

  calculateUnderutilizationSavings(license, usage) {
    const currentCost = license.cost || 0;
    const utilizationRate = usage.utilizationRate / 100;
    
    // Estimate potential savings
    const optimalQuantity = Math.max(1, Math.ceil(usage.maxUsers * 1.1));
    const currentQuantity = license.quantity || 1;
    
    if (optimalQuantity < currentQuantity) {
      const reductionPercentage = (currentQuantity - optimalQuantity) / currentQuantity;
      return currentCost * reductionPercentage;
    }
    
    return 0;
  }

  calculateCurrentMonthCosts() {
    const currentMonth = moment().format('YYYY-MM');
    let totalCost = 0;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status === 'active') {
        // Convert to monthly cost based on license type
        let monthlyCost = 0;
        
        if (license.type === 'subscription') {
          monthlyCost = license.cost || 0; // Assume already monthly
        } else if (license.type === 'perpetual') {
          monthlyCost = (license.cost || 0) / 36; // Amortize over 3 years
        } else {
          monthlyCost = (license.cost || 0) / 12; // Assume annual
        }
        
        totalCost += monthlyCost;
      }
    }

    return totalCost;
  }

  calculateProjectedAnnualCosts() {
    const currentMonthCosts = this.calculateCurrentMonthCosts();
    return currentMonthCosts * 12;
  }

  getTopCostLicenses(limit) {
    return Array.from(this.licenseService.licenses.values())
      .filter(license => license.status === 'active')
      .sort((a, b) => (b.cost || 0) - (a.cost || 0))
      .slice(0, limit)
      .map(license => ({
        id: license.id,
        name: license.name,
        cost: license.cost || 0,
        vendor: this.licenseService.vendors.get(license.vendorId)?.name || 'Unknown'
      }));
  }

  getEmailTemplate(severity) {
    // Return appropriate email template based on severity
    const templates = {
      critical: 'critical_alert_template',
      high: 'high_alert_template',
      medium: 'medium_alert_template',
      low: 'low_alert_template'
    };

    return templates[severity] || templates.medium;
  }

  generateEmailContent(alert, template) {
    // Generate HTML email content
    return `
      <html>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
          <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="background-color: ${this.getSeverityColor(alert.severity)}; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
              <h2 style="margin: 0; font-size: 18px;">[${alert.severity.toUpperCase()}] ${alert.title}</h2>
            </div>
            
            <div style="margin-bottom: 20px;">
              <p style="font-size: 16px; line-height: 1.5; margin-bottom: 10px;">${alert.message}</p>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
              <h3 style="margin-top: 0; color: #333; font-size: 14px;">Alert Details:</h3>
              <ul style="margin: 0; padding-left: 20px;">
                <li><strong>Category:</strong> ${alert.category}</li>
                <li><strong>Created:</strong> ${moment(alert.createdAt).format('YYYY-MM-DD HH:mm:ss')}</li>
                ${alert.licenseName ? `<li><strong>License:</strong> ${alert.licenseName}</li>` : ''}
                ${Object.entries(alert.details).map(([key, value]) => 
                  `<li><strong>${key}:</strong> ${value}</li>`
                ).join('')}
              </ul>
            </div>
            
            <div style="border-top: 1px solid #eee; padding-top: 15px; font-size: 12px; color: #666;">
              <p>This alert was generated by the OpenDirectory License Management Service.</p>
              <p>Alert ID: ${alert.id}</p>
            </div>
          </div>
        </body>
      </html>
    `;
  }

  getSeverityColor(severity) {
    const colors = {
      critical: '#dc3545',
      high: '#fd7e14',
      medium: '#ffc107',
      low: '#28a745'
    };

    return colors[severity] || colors.medium;
  }

  async cleanupOldAlerts() {
    const retentionDays = 90;
    const cutoffDate = moment().subtract(retentionDays, 'days');

    for (const [alertId, alert] of this.licenseService.alerts) {
      if (moment(alert.createdAt).isBefore(cutoffDate)) {
        this.licenseService.alerts.delete(alertId);
        this.activeAlerts.delete(alertId);
      }
    }

    // Cleanup notification history
    for (const [logId, logEntry] of this.notificationHistory) {
      if (moment(logEntry.timestamp).isBefore(cutoffDate)) {
        this.notificationHistory.delete(logId);
      }
    }
  }

  async generateDailyAlertSummary() {
    const today = moment().startOf('day');
    const todaysAlerts = Array.from(this.licenseService.alerts.values())
      .filter(alert => moment(alert.createdAt).isSameOrAfter(today));

    if (todaysAlerts.length === 0) return;

    const summary = {
      date: today.format('YYYY-MM-DD'),
      totalAlerts: todaysAlerts.length,
      bySeverity: {
        critical: todaysAlerts.filter(a => a.severity === 'critical').length,
        high: todaysAlerts.filter(a => a.severity === 'high').length,
        medium: todaysAlerts.filter(a => a.severity === 'medium').length,
        low: todaysAlerts.filter(a => a.severity === 'low').length
      },
      byCategory: {},
      topAlerts: todaysAlerts.slice(0, 10) // Top 10 alerts
    };

    // Count by category
    todaysAlerts.forEach(alert => {
      summary.byCategory[alert.category] = (summary.byCategory[alert.category] || 0) + 1;
    });

    // Store summary
    this.licenseService.reports.set(`alert_summary_${today.format('YYYY-MM-DD')}`, summary);

    this.licenseService.logger.info('Daily alert summary generated', {
      date: summary.date,
      totalAlerts: summary.totalAlerts
    });
  }

  // Public API methods
  async acknowledgeAlert(alertId, acknowledgedBy) {
    const alert = this.licenseService.alerts.get(alertId);
    if (!alert) {
      throw new Error('Alert not found');
    }

    alert.status = 'acknowledged';
    alert.acknowledgedAt = new Date().toISOString();
    alert.acknowledgedBy = acknowledgedBy;

    this.licenseService.alerts.set(alertId, alert);
    
    // Remove from active alerts if acknowledged
    this.activeAlerts.delete(alertId);

    this.licenseService.logAuditEvent('alert_acknowledged', {
      alertId,
      acknowledgedBy
    });

    return alert;
  }

  async resolveAlert(alertId, resolvedBy, resolution) {
    const alert = this.licenseService.alerts.get(alertId);
    if (!alert) {
      throw new Error('Alert not found');
    }

    alert.status = 'resolved';
    alert.resolvedAt = new Date().toISOString();
    alert.resolvedBy = resolvedBy;
    alert.resolution = resolution;

    this.licenseService.alerts.set(alertId, alert);
    this.activeAlerts.delete(alertId);

    this.licenseService.logAuditEvent('alert_resolved', {
      alertId,
      resolvedBy,
      resolution
    });

    return alert;
  }

  async getAlertMetrics(timeframe = '24h') {
    const cutoffTime = moment().subtract(
      timeframe === '24h' ? 24 : timeframe === '7d' ? 7 * 24 : 30 * 24, 
      'hours'
    );

    const recentAlerts = Array.from(this.licenseService.alerts.values())
      .filter(alert => moment(alert.createdAt).isAfter(cutoffTime));

    return {
      total: recentAlerts.length,
      open: recentAlerts.filter(a => a.status === 'open').length,
      acknowledged: recentAlerts.filter(a => a.status === 'acknowledged').length,
      resolved: recentAlerts.filter(a => a.status === 'resolved').length,
      bySeverity: {
        critical: recentAlerts.filter(a => a.severity === 'critical').length,
        high: recentAlerts.filter(a => a.severity === 'high').length,
        medium: recentAlerts.filter(a => a.severity === 'medium').length,
        low: recentAlerts.filter(a => a.severity === 'low').length
      },
      byCategory: this.groupAlertsByCategory(recentAlerts),
      avgResolutionTime: this.calculateAverageResolutionTime(recentAlerts)
    };
  }

  groupAlertsByCategory(alerts) {
    return alerts.reduce((groups, alert) => {
      groups[alert.category] = (groups[alert.category] || 0) + 1;
      return groups;
    }, {});
  }

  calculateAverageResolutionTime(alerts) {
    const resolvedAlerts = alerts.filter(alert => 
      alert.status === 'resolved' && alert.resolvedAt
    );

    if (resolvedAlerts.length === 0) return 0;

    const totalResolutionTime = resolvedAlerts.reduce((sum, alert) => {
      const resolutionTime = moment(alert.resolvedAt).diff(moment(alert.createdAt), 'minutes');
      return sum + resolutionTime;
    }, 0);

    return Math.round(totalResolutionTime / resolvedAlerts.length);
  }
}

module.exports = AlertService;