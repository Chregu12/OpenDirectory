const EventEmitter = require('eventemitter3');
const { Pool } = require('pg');
const logger = require('./utils/logger');

class ModuleRegistry extends EventEmitter {
  constructor() {
    super();
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@postgres/configuration'
    });
    
    this.availableModules = this.defineAvailableModules();
  }

  defineAvailableModules() {
    return [
      {
        id: 'network-infrastructure',
        name: 'Network Infrastructure',
        description: 'Complete network management including DNS, DHCP, file shares, and network discovery',
        category: 'infrastructure',
        icon: 'network',
        dependencies: [],
        features: {
          dns: {
            name: 'DNS Management',
            description: 'BIND-compatible DNS server management',
            enabled: true
          },
          dhcp: {
            name: 'DHCP Management',
            description: 'ISC DHCP server management with scopes and reservations',
            enabled: true
          },
          'file-shares': {
            name: 'File Share Management',
            description: 'SMB/CIFS, NFS, and AFP file sharing',
            enabled: true
          },
          discovery: {
            name: 'Network Discovery',
            description: 'Automatic network device detection and topology mapping',
            enabled: true
          },
          monitoring: {
            name: 'Network Monitoring',
            description: 'Real-time network monitoring with SNMP',
            enabled: true
          }
        },
        requirements: {
          ports: [53, 67, 68, 139, 445, 2049],
          privileges: ['NET_ADMIN', 'NET_RAW'],
          memory: '512MB',
          cpu: '0.5'
        }
      },
      {
        id: 'security-suite',
        name: 'Security Suite',
        description: 'Comprehensive security management with threat intelligence, DLP, PAM, and more',
        category: 'security',
        icon: 'shield',
        dependencies: ['authentication-service'],
        features: {
          'threat-intel': {
            name: 'Threat Intelligence',
            description: 'Real-time threat feeds and analysis',
            enabled: true
          },
          dlp: {
            name: 'Data Loss Prevention',
            description: 'Prevent unauthorized data exfiltration',
            enabled: false
          },
          pam: {
            name: 'Privileged Access Management',
            description: 'Manage and audit privileged accounts',
            enabled: true
          },
          microsegmentation: {
            name: 'Microsegmentation',
            description: 'Network segmentation for security',
            enabled: false
          },
          'security-orchestration': {
            name: 'Security Orchestration',
            description: 'Automated security response workflows',
            enabled: true
          },
          'zero-trust': {
            name: 'Zero Trust Authentication',
            description: 'Never trust, always verify approach',
            enabled: true
          }
        },
        requirements: {
          ports: [3008],
          memory: '1GB',
          cpu: '1'
        }
      },
      {
        id: 'printer-service',
        name: 'Printer & Scanner Management',
        description: 'Universal printer and scanner management with CUPS and SANE integration',
        category: 'devices',
        icon: 'printer',
        dependencies: [],
        features: {
          cups: {
            name: 'CUPS Integration',
            description: 'Common UNIX Printing System support',
            enabled: true
          },
          scanning: {
            name: 'Scanner Support',
            description: 'SANE backend for scanner management',
            enabled: true
          },
          quotas: {
            name: 'Print Quotas',
            description: 'User and department print quotas',
            enabled: true
          },
          analytics: {
            name: 'Print Analytics',
            description: 'Usage tracking and reporting',
            enabled: true
          }
        },
        requirements: {
          ports: [631, 3006],
          privileges: ['SYS_ADMIN'],
          memory: '256MB',
          cpu: '0.25'
        }
      },
      {
        id: 'monitoring-analytics',
        name: 'Monitoring & Analytics',
        description: 'System monitoring with AI-powered analytics and alerting',
        category: 'observability',
        icon: 'chart',
        dependencies: [],
        features: {
          'health-monitoring': {
            name: 'Health Monitoring',
            description: 'Real-time system health checks',
            enabled: true
          },
          'ai-analytics': {
            name: 'AI Analytics',
            description: 'Machine learning-based insights',
            enabled: false
          },
          'prometheus-integration': {
            name: 'Prometheus Integration',
            description: 'Metrics collection and storage',
            enabled: true
          },
          alerting: {
            name: 'Alerting',
            description: 'Multi-channel alert notifications',
            enabled: true
          }
        },
        requirements: {
          ports: [3009],
          memory: '512MB',
          cpu: '0.5'
        }
      },
      {
        id: 'device-management',
        name: 'Device Management',
        description: 'MDM for all platforms with enrollment, policies, and compliance',
        category: 'devices',
        icon: 'device',
        dependencies: ['authentication-service'],
        features: {
          enrollment: {
            name: 'Device Enrollment',
            description: 'Zero-touch device enrollment',
            enabled: true
          },
          policies: {
            name: 'Device Policies',
            description: 'Configure and enforce device policies',
            enabled: true
          },
          compliance: {
            name: 'Compliance Checking',
            description: 'Automated compliance verification',
            enabled: true
          },
          inventory: {
            name: 'Asset Inventory',
            description: 'Hardware and software inventory',
            enabled: true
          }
        },
        requirements: {
          ports: [3003],
          memory: '512MB',
          cpu: '0.5'
        }
      },
      {
        id: 'policy-compliance',
        name: 'Policy & Compliance',
        description: 'Policy engine with compliance scanning and auto-remediation',
        category: 'governance',
        icon: 'policy',
        dependencies: [],
        features: {
          'policy-engine': {
            name: 'Policy Engine',
            description: 'Define and enforce organizational policies',
            enabled: true
          },
          'compliance-scanner': {
            name: 'Compliance Scanner',
            description: 'Scan for compliance violations',
            enabled: true
          },
          'auto-remediation': {
            name: 'Auto Remediation',
            description: 'Automatically fix compliance issues',
            enabled: false
          }
        },
        requirements: {
          ports: [3010],
          memory: '256MB',
          cpu: '0.25'
        }
      },
      {
        id: 'backup-disaster',
        name: 'Backup & Disaster Recovery',
        description: 'Automated backup with geo-replication and disaster recovery',
        category: 'infrastructure',
        icon: 'backup',
        dependencies: [],
        features: {
          'automated-backup': {
            name: 'Automated Backup',
            description: 'Scheduled automatic backups',
            enabled: true
          },
          'geo-replication': {
            name: 'Geo-Replication',
            description: 'Multi-region data replication',
            enabled: false
          },
          'disaster-recovery': {
            name: 'Disaster Recovery',
            description: 'Automated failover and recovery',
            enabled: true
          },
          'retention-management': {
            name: 'Retention Management',
            description: 'Backup lifecycle management',
            enabled: true
          }
        },
        requirements: {
          ports: [3011],
          memory: '512MB',
          cpu: '0.5',
          storage: '100GB'
        }
      },
      {
        id: 'automation-workflows',
        name: 'Automation & Workflows',
        description: 'Workflow engine with task scheduling and event automation',
        category: 'automation',
        icon: 'automation',
        dependencies: [],
        features: {
          'workflow-engine': {
            name: 'Workflow Engine',
            description: 'Visual workflow designer and executor',
            enabled: true
          },
          'task-scheduler': {
            name: 'Task Scheduler',
            description: 'Cron-like task scheduling',
            enabled: true
          },
          'event-automation': {
            name: 'Event Automation',
            description: 'Event-driven automation triggers',
            enabled: true
          },
          'nlp-interface': {
            name: 'NLP Interface',
            description: 'Natural language automation commands',
            enabled: false
          }
        },
        requirements: {
          ports: [3012],
          memory: '512MB',
          cpu: '0.5'
        }
      },
      {
        id: 'container-orchestration',
        name: 'Container & Cloud Management',
        description: 'Kubernetes and Docker management with cost optimization',
        category: 'infrastructure',
        icon: 'container',
        dependencies: [],
        features: {
          kubernetes: {
            name: 'Kubernetes Management',
            description: 'K8s cluster management and deployment',
            enabled: false
          },
          docker: {
            name: 'Docker Management',
            description: 'Docker container lifecycle management',
            enabled: true
          },
          'cost-optimization': {
            name: 'Cost Optimization',
            description: 'Cloud resource cost analysis',
            enabled: false
          },
          'security-scanning': {
            name: 'Container Security',
            description: 'Vulnerability scanning for containers',
            enabled: true
          }
        },
        requirements: {
          ports: [3013],
          memory: '1GB',
          cpu: '1',
          privileges: ['SYS_ADMIN']
        }
      },
      {
        id: 'enterprise-integrations',
        name: 'Enterprise Integrations',
        description: 'Connectors for ERP, SAP, Office 365, and other enterprise systems',
        category: 'integration',
        icon: 'integration',
        dependencies: [],
        features: {
          'erp-connector': {
            name: 'ERP Connector',
            description: 'Integration with ERP systems',
            enabled: false
          },
          'sap-connector': {
            name: 'SAP Connector',
            description: 'SAP system integration',
            enabled: false
          },
          'o365-connector': {
            name: 'Office 365 Connector',
            description: 'Microsoft 365 integration',
            enabled: false
          },
          'api-gateway': {
            name: 'API Gateway',
            description: 'Custom API integrations',
            enabled: true
          }
        },
        requirements: {
          ports: [3014],
          memory: '512MB',
          cpu: '0.5'
        }
      },
      {
        id: 'ai-intelligence',
        name: 'AI Intelligence',
        description: 'Advanced AI features with predictive analytics and anomaly detection',
        category: 'intelligence',
        icon: 'ai',
        dependencies: ['monitoring-analytics'],
        features: {
          'predictive-analytics': {
            name: 'Predictive Analytics',
            description: 'ML-based predictions and forecasting',
            enabled: false
          },
          'anomaly-detection': {
            name: 'Anomaly Detection',
            description: 'Automatic anomaly identification',
            enabled: false
          },
          'pattern-recognition': {
            name: 'Pattern Recognition',
            description: 'Identify patterns in data',
            enabled: false
          },
          recommendations: {
            name: 'Smart Recommendations',
            description: 'AI-powered optimization suggestions',
            enabled: false
          }
        },
        requirements: {
          ports: [3015],
          memory: '2GB',
          cpu: '2',
          gpu: 'optional'
        }
      }
    ];
  }

  async getAllModules() {
    const result = await this.db.query('SELECT * FROM modules ORDER BY name');
    return result.rows;
  }

  async getModule(moduleId) {
    const result = await this.db.query('SELECT * FROM modules WHERE id = $1', [moduleId]);
    return result.rows[0];
  }

  async updateModule(moduleId, updates) {
    const module = await this.getModule(moduleId);
    if (!module) {
      throw new Error(`Module ${moduleId} not found`);
    }

    const updatedModule = {
      ...module,
      ...updates,
      updated_at: new Date().toISOString()
    };

    const query = `
      UPDATE modules 
      SET enabled = $2, config = $3, features = $4, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING *
    `;

    const result = await this.db.query(query, [
      moduleId,
      updates.enabled !== undefined ? updates.enabled : module.enabled,
      JSON.stringify(updates.config || module.config),
      JSON.stringify(updates.features || module.features)
    ]);

    const updated = result.rows[0];

    // Emit event
    this.emit('module-changed', {
      moduleId,
      changes: updates,
      module: updated
    });

    logger.info(`Module ${moduleId} updated`);
    return updated;
  }

  async enableModule(moduleId) {
    return this.updateModule(moduleId, { enabled: true });
  }

  async disableModule(moduleId) {
    return this.updateModule(moduleId, { enabled: false });
  }

  async getEnabledModules() {
    const result = await this.db.query('SELECT * FROM modules WHERE enabled = true');
    return result.rows;
  }

  async checkDependencies(moduleId) {
    const availableModule = this.availableModules.find(m => m.id === moduleId);
    if (!availableModule) {
      return { valid: true, missing: [] };
    }

    const missing = [];
    for (const dep of availableModule.dependencies) {
      const depModule = await this.getModule(dep);
      if (!depModule || !depModule.enabled) {
        missing.push(dep);
      }
    }

    return {
      valid: missing.length === 0,
      missing
    };
  }

  async getAvailableModules() {
    // Get current status from database
    const currentModules = await this.getAllModules();
    const currentMap = new Map(currentModules.map(m => [m.id, m]));

    // Merge with available modules definition
    return this.availableModules.map(available => {
      const current = currentMap.get(available.id);
      return {
        ...available,
        enabled: current?.enabled || false,
        config: current?.config || {},
        installedFeatures: current?.features || {}
      };
    });
  }

  async getModulesByCategory(category) {
    const available = await this.getAvailableModules();
    return available.filter(m => m.category === category);
  }

  async getModuleRequirements(moduleId) {
    const availableModule = this.availableModules.find(m => m.id === moduleId);
    return availableModule?.requirements || null;
  }

  async validateModuleConfiguration(moduleId, config) {
    // Basic validation - can be extended with JSON schema
    const availableModule = this.availableModules.find(m => m.id === moduleId);
    if (!availableModule) {
      return { valid: false, errors: ['Module not found'] };
    }

    const errors = [];

    // Check dependencies
    const depCheck = await this.checkDependencies(moduleId);
    if (!depCheck.valid) {
      errors.push(`Missing dependencies: ${depCheck.missing.join(', ')}`);
    }

    // Validate features
    if (config.features) {
      for (const [featureId, enabled] of Object.entries(config.features)) {
        if (!availableModule.features[featureId]) {
          errors.push(`Unknown feature: ${featureId}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

module.exports = ModuleRegistry;