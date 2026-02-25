const fs = require('fs').promises;
const path = require('path');
const yaml = require('yaml');
const logger = require('./logger');

class ConfigManager {
  constructor() {
    this.configPath = process.env.CONFIG_PATH || '/app/config/modules.yaml';
    this.config = null;
    this.watchers = new Set();
    
    this.loadConfiguration();
    this.watchConfiguration();
  }

  async loadConfiguration() {
    try {
      const configFile = await fs.readFile(this.configPath, 'utf8');
      this.config = yaml.parse(configFile);
      
      logger.info('Configuration loaded successfully');
      this.notifyWatchers('config-loaded', this.config);
    } catch (error) {
      logger.warn('Config file not found, using defaults');
      this.config = this.getDefaultConfiguration();
    }
  }

  async watchConfiguration() {
    try {
      const watcher = fs.watch(this.configPath);
      
      for await (const event of watcher) {
        if (event.eventType === 'change') {
          logger.info('Configuration file changed, reloading...');
          await this.loadConfiguration();
        }
      }
    } catch (error) {
      logger.warn('Could not watch configuration file:', error.message);
    }
  }

  getDefaultConfiguration() {
    return {
      version: '1.0.0',
      modules: {
        'network-infrastructure': {
          enabled: true,
          port: 3007,
          features: {
            dns: true,
            dhcp: true,
            'file-shares': true,
            discovery: true,
            monitoring: true
          },
          config: {
            dns: {
              bind_config_path: '/etc/bind',
              default_ttl: 300,
              zones: []
            },
            dhcp: {
              config_path: '/etc/dhcp',
              default_lease_time: 86400,
              scopes: []
            }
          }
        },
        'security-suite': {
          enabled: false,
          port: 3008,
          features: {
            'threat-intel': true,
            'dlp': false,
            'pam': true,
            'microsegmentation': false,
            'security-orchestration': true,
            'zero-trust': true
          },
          config: {
            threat_intel: {
              feeds: [],
              update_interval: 3600
            },
            pam: {
              session_timeout: 1800,
              require_approval: true
            }
          }
        },
        'printer-service': {
          enabled: true,
          port: 3006,
          features: {
            cups: true,
            scanning: true,
            quotas: true,
            analytics: true
          },
          config: {
            cups: {
              host: 'localhost',
              port: 631
            },
            scanning: {
              formats: ['pdf', 'jpg', 'png'],
              ocr: true
            }
          }
        },
        'monitoring-analytics': {
          enabled: true,
          port: 3009,
          features: {
            'health-monitoring': true,
            'ai-analytics': false,
            'prometheus-integration': true,
            'alerting': true
          },
          config: {
            prometheus: {
              url: 'http://prometheus:9090',
              scrape_interval: '15s'
            },
            alerting: {
              email: {
                enabled: false,
                smtp_server: ''
              },
              webhook: {
                enabled: true,
                url: ''
              }
            }
          }
        },
        'device-management': {
          enabled: true,
          port: 3003,
          features: {
            enrollment: true,
            policies: true,
            compliance: true,
            inventory: true
          },
          config: {
            enrollment: {
              auto_approve: false,
              require_admin_approval: true
            },
            compliance: {
              check_interval: 3600,
              auto_remediate: false
            }
          }
        },
        'policy-compliance': {
          enabled: false,
          port: 3010,
          features: {
            'policy-engine': true,
            'compliance-scanner': true,
            'auto-remediation': false
          },
          config: {
            scanner: {
              scan_interval: 86400,
              compliance_frameworks: ['SOC2', 'GDPR', 'HIPAA']
            }
          }
        },
        'backup-disaster': {
          enabled: false,
          port: 3011,
          features: {
            'automated-backup': true,
            'geo-replication': false,
            'disaster-recovery': true,
            'retention-management': true
          },
          config: {
            backup: {
              schedule: '0 2 * * *',
              retention_days: 30,
              compression: true
            }
          }
        },
        'automation-workflows': {
          enabled: false,
          port: 3012,
          features: {
            'workflow-engine': true,
            'task-scheduler': true,
            'event-automation': true,
            'nlp-interface': false
          },
          config: {
            scheduler: {
              max_concurrent_jobs: 10,
              history_retention_days: 7
            }
          }
        },
        'container-orchestration': {
          enabled: false,
          port: 3013,
          features: {
            'kubernetes': false,
            'docker': true,
            'cost-optimization': false,
            'security-scanning': true
          },
          config: {
            docker: {
              socket_path: '/var/run/docker.sock',
              registry: ''
            }
          }
        },
        'enterprise-integrations': {
          enabled: false,
          port: 3014,
          features: {
            'erp-connector': false,
            'sap-connector': false,
            'o365-connector': false,
            'api-gateway': true
          },
          config: {
            connectors: {
              timeout: 30000,
              retry_attempts: 3
            }
          }
        },
        'ai-intelligence': {
          enabled: false,
          port: 3015,
          features: {
            'predictive-analytics': false,
            'anomaly-detection': false,
            'pattern-recognition': false,
            'recommendations': false
          },
          config: {
            ai: {
              model_path: '/app/models',
              training_interval: 604800
            }
          }
        }
      },
      gateway: {
        port: 8080,
        cors_origin: ['http://localhost:3000'],
        rate_limit: {
          window_ms: 900000,
          max_requests: 1000
        },
        logging: {
          level: 'info',
          format: 'combined'
        },
        health_check: {
          interval: 30000,
          timeout: 5000
        }
      }
    };
  }

  getConfig() {
    return this.config;
  }

  getModuleConfiguration() {
    return this.config?.modules || {};
  }

  getEnabledModules() {
    const modules = this.getModuleConfiguration();
    return Object.keys(modules).filter(moduleId => modules[moduleId]?.enabled === true);
  }

  getModuleConfig(moduleId) {
    return this.config?.modules?.[moduleId];
  }

  isModuleEnabled(moduleId) {
    return this.config?.modules?.[moduleId]?.enabled === true;
  }

  getEnabledFeatures(moduleId) {
    const moduleConfig = this.getModuleConfig(moduleId);
    if (!moduleConfig?.features) return [];
    
    return Object.keys(moduleConfig.features).filter(
      feature => moduleConfig.features[feature] === true
    );
  }

  async updateModuleConfiguration(moduleId, updates) {
    if (!this.config.modules[moduleId]) {
      throw new Error(`Module ${moduleId} not found`);
    }

    // Update module configuration
    if (updates.enabled !== undefined) {
      this.config.modules[moduleId].enabled = updates.enabled;
    }

    if (updates.features) {
      this.config.modules[moduleId].features = {
        ...this.config.modules[moduleId].features,
        ...updates.features
      };
    }

    if (updates.config) {
      this.config.modules[moduleId].config = {
        ...this.config.modules[moduleId].config,
        ...updates.config
      };
    }

    // Save configuration
    await this.saveConfiguration();
    
    // Notify watchers
    this.notifyWatchers('module-updated', { moduleId, config: this.config.modules[moduleId] });

    logger.info(`Module ${moduleId} configuration updated`);
  }

  async updateFeature(moduleId, featureId, enabled) {
    if (!this.config.modules[moduleId]) {
      throw new Error(`Module ${moduleId} not found`);
    }

    this.config.modules[moduleId].features[featureId] = enabled;
    await this.saveConfiguration();

    this.notifyWatchers('feature-updated', { moduleId, featureId, enabled });
    logger.info(`Feature ${featureId} in module ${moduleId} ${enabled ? 'enabled' : 'disabled'}`);
  }

  async saveConfiguration() {
    try {
      const configYaml = yaml.stringify(this.config, { indent: 2 });
      await fs.writeFile(this.configPath, configYaml, 'utf8');
      logger.info('Configuration saved successfully');
    } catch (error) {
      logger.error('Failed to save configuration:', error);
      throw error;
    }
  }

  addWatcher(callback) {
    this.watchers.add(callback);
  }

  removeWatcher(callback) {
    this.watchers.delete(callback);
  }

  notifyWatchers(event, data) {
    this.watchers.forEach(callback => {
      try {
        callback(event, data);
      } catch (error) {
        logger.error('Watcher callback error:', error);
      }
    });
  }

  // Validation methods
  validateModuleConfig(moduleId, config) {
    const moduleConfig = this.getModuleConfig(moduleId);
    if (!moduleConfig) {
      throw new Error(`Module ${moduleId} not found`);
    }

    // Add validation logic based on module requirements
    // This can be extended with JSON schema validation
    return true;
  }

  getServiceUrl(moduleId) {
    const moduleConfig = this.getModuleConfig(moduleId);
    if (!moduleConfig || !moduleConfig.enabled) {
      return null;
    }

    const serviceName = moduleId.replace(/-/g, '-');
    return `http://${serviceName}:${moduleConfig.port}`;
  }

  // Environment-based overrides
  applyEnvironmentOverrides() {
    const envPrefix = 'OD_MODULE_';
    
    Object.keys(process.env).forEach(key => {
      if (key.startsWith(envPrefix)) {
        const parts = key.substring(envPrefix.length).toLowerCase().split('_');
        if (parts.length >= 2) {
          const moduleId = parts[0];
          const property = parts.slice(1).join('_');
          
          if (this.config.modules[moduleId]) {
            if (property === 'enabled') {
              this.config.modules[moduleId].enabled = process.env[key] === 'true';
            } else if (property === 'port') {
              this.config.modules[moduleId].port = parseInt(process.env[key], 10);
            }
          }
        }
      }
    });
  }
}

// Singleton instance
const configManager = new ConfigManager();
module.exports = configManager;