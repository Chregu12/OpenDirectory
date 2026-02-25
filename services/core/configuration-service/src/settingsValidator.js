const Joi = require('joi');
const logger = require('./utils/logger');

class SettingsValidator {
  constructor() {
    this.schemas = this.defineSchemas();
  }

  defineSchemas() {
    return {
      // Network Infrastructure Module
      'network-infrastructure': Joi.object({
        dns: Joi.object({
          enabled: Joi.boolean(),
          bind_config_path: Joi.string(),
          default_ttl: Joi.number().min(60).max(86400),
          zones: Joi.array().items(Joi.object({
            name: Joi.string().required(),
            type: Joi.string().valid('master', 'slave', 'forward'),
            records: Joi.array()
          }))
        }),
        dhcp: Joi.object({
          enabled: Joi.boolean(),
          config_path: Joi.string(),
          default_lease_time: Joi.number().min(300).max(604800),
          scopes: Joi.array().items(Joi.object({
            name: Joi.string().required(),
            startIP: Joi.string().ip(),
            endIP: Joi.string().ip(),
            subnet: Joi.string(),
            gateway: Joi.string().ip()
          }))
        }),
        fileShares: Joi.object({
          enabled: Joi.boolean(),
          shares: Joi.array().items(Joi.object({
            name: Joi.string().required(),
            path: Joi.string().required(),
            protocol: Joi.string().valid('SMB', 'NFS', 'AFP'),
            permissions: Joi.string()
          }))
        })
      }),

      // Security Suite Module
      'security-suite': Joi.object({
        threatIntel: Joi.object({
          enabled: Joi.boolean(),
          feeds: Joi.array().items(Joi.string().uri()),
          updateInterval: Joi.number().min(300).max(86400)
        }),
        dlp: Joi.object({
          enabled: Joi.boolean(),
          rules: Joi.array(),
          scanPaths: Joi.array().items(Joi.string())
        }),
        pam: Joi.object({
          enabled: Joi.boolean(),
          sessionTimeout: Joi.number().min(60).max(86400),
          requireApproval: Joi.boolean(),
          approvers: Joi.array().items(Joi.string().email())
        }),
        zeroTrust: Joi.object({
          enabled: Joi.boolean(),
          verificationInterval: Joi.number().min(60).max(3600),
          riskThreshold: Joi.number().min(0).max(100)
        })
      }),

      // Printer Service Module
      'printer-service': Joi.object({
        cups: Joi.object({
          host: Joi.string().hostname(),
          port: Joi.number().port(),
          adminUser: Joi.string(),
          adminPassword: Joi.string()
        }),
        scanning: Joi.object({
          enabled: Joi.boolean(),
          formats: Joi.array().items(Joi.string().valid('pdf', 'jpg', 'png', 'tiff')),
          ocr: Joi.boolean(),
          ocrLanguages: Joi.array().items(Joi.string())
        }),
        quotas: Joi.object({
          enabled: Joi.boolean(),
          defaultQuota: Joi.number().min(0),
          resetPeriod: Joi.string().valid('daily', 'weekly', 'monthly')
        })
      }),

      // Monitoring Analytics Module
      'monitoring-analytics': Joi.object({
        prometheus: Joi.object({
          url: Joi.string().uri(),
          scrapeInterval: Joi.string(),
          retention: Joi.string()
        }),
        alerting: Joi.object({
          enabled: Joi.boolean(),
          email: Joi.object({
            enabled: Joi.boolean(),
            smtpServer: Joi.string().hostname(),
            smtpPort: Joi.number().port(),
            from: Joi.string().email(),
            recipients: Joi.array().items(Joi.string().email())
          }),
          webhook: Joi.object({
            enabled: Joi.boolean(),
            url: Joi.string().uri(),
            headers: Joi.object()
          }),
          slack: Joi.object({
            enabled: Joi.boolean(),
            webhookUrl: Joi.string().uri(),
            channel: Joi.string()
          })
        }),
        aiAnalytics: Joi.object({
          enabled: Joi.boolean(),
          modelPath: Joi.string(),
          trainingInterval: Joi.number().min(3600),
          anomalyThreshold: Joi.number().min(0).max(1)
        })
      }),

      // Device Management Module
      'device-management': Joi.object({
        enrollment: Joi.object({
          autoApprove: Joi.boolean(),
          requireAdminApproval: Joi.boolean(),
          allowedDomains: Joi.array().items(Joi.string()),
          enrollmentUrl: Joi.string().uri()
        }),
        policies: Joi.object({
          enforceEncryption: Joi.boolean(),
          minimumOSVersion: Joi.object(),
          requiredApps: Joi.array().items(Joi.string()),
          blockedApps: Joi.array().items(Joi.string())
        }),
        compliance: Joi.object({
          checkInterval: Joi.number().min(300).max(86400),
          autoRemediate: Joi.boolean(),
          quarantineNonCompliant: Joi.boolean()
        })
      }),

      // Backup Disaster Recovery Module
      'backup-disaster': Joi.object({
        backup: Joi.object({
          enabled: Joi.boolean(),
          schedule: Joi.string(),
          retentionDays: Joi.number().min(1).max(3650),
          compression: Joi.boolean(),
          encryption: Joi.boolean(),
          destinations: Joi.array().items(Joi.object({
            type: Joi.string().valid('local', 's3', 'azure', 'gcs'),
            path: Joi.string().required(),
            credentials: Joi.object()
          }))
        }),
        replication: Joi.object({
          enabled: Joi.boolean(),
          targets: Joi.array().items(Joi.object({
            region: Joi.string().required(),
            endpoint: Joi.string().uri()
          }))
        }),
        disaster: Joi.object({
          autoFailover: Joi.boolean(),
          healthCheckInterval: Joi.number().min(10).max(300),
          failoverThreshold: Joi.number().min(1).max(10)
        })
      }),

      // Global Settings
      global: Joi.object({
        organization: Joi.object({
          name: Joi.string().required(),
          domain: Joi.string().hostname(),
          adminEmail: Joi.string().email()
        }),
        database: Joi.object({
          host: Joi.string().hostname(),
          port: Joi.number().port(),
          name: Joi.string(),
          user: Joi.string(),
          password: Joi.string(),
          ssl: Joi.boolean()
        }),
        redis: Joi.object({
          host: Joi.string().hostname(),
          port: Joi.number().port(),
          password: Joi.string(),
          db: Joi.number().min(0).max(15)
        }),
        logging: Joi.object({
          level: Joi.string().valid('error', 'warn', 'info', 'debug'),
          destination: Joi.string().valid('console', 'file', 'syslog'),
          maxFiles: Joi.number().min(1).max(100),
          maxSize: Joi.string()
        })
      })
    };
  }

  async validateModuleConfig(moduleId, config) {
    const schema = this.schemas[moduleId];
    
    if (!schema) {
      // If no schema defined, accept any config
      return { valid: true };
    }
    
    try {
      const result = schema.validate(config, { 
        abortEarly: false,
        allowUnknown: true 
      });
      
      if (result.error) {
        return {
          valid: false,
          errors: result.error.details.map(detail => ({
            path: detail.path.join('.'),
            message: detail.message,
            type: detail.type
          }))
        };
      }
      
      return { valid: true };
    } catch (error) {
      logger.error('Validation error:', error);
      return {
        valid: false,
        errors: [{ message: error.message }]
      };
    }
  }

  async validateModuleSettings(moduleId, settings) {
    return this.validateModuleConfig(moduleId, settings);
  }

  async validateFullConfiguration(config) {
    const errors = [];
    
    // Validate each module configuration
    for (const [moduleId, moduleConfig] of Object.entries(config.modules || {})) {
      const validation = await this.validateModuleConfig(moduleId, moduleConfig.config);
      if (!validation.valid) {
        errors.push({
          module: moduleId,
          errors: validation.errors
        });
      }
    }
    
    // Validate global settings
    if (config.settings?.global) {
      const validation = await this.validateModuleConfig('global', config.settings.global);
      if (!validation.valid) {
        errors.push({
          module: 'global',
          errors: validation.errors
        });
      }
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Custom validation rules
  validateIPRange(startIP, endIP) {
    const start = this.ipToNumber(startIP);
    const end = this.ipToNumber(endIP);
    return start < end;
  }

  ipToNumber(ip) {
    const parts = ip.split('.');
    return parts.reduce((acc, part, index) => {
      return acc + (parseInt(part) << (8 * (3 - index)));
    }, 0);
  }

  validateCronExpression(expression) {
    // Simple cron validation
    const parts = expression.split(' ');
    return parts.length >= 5 && parts.length <= 6;
  }

  validatePortRange(port) {
    return port >= 1 && port <= 65535;
  }

  validatePath(path) {
    // Check if path is valid and doesn't contain dangerous patterns
    const dangerous = ['../', '\\..', '~/', '${', '$('];
    return !dangerous.some(pattern => path.includes(pattern));
  }
}

module.exports = SettingsValidator;