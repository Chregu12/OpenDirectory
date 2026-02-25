const EventEmitter = require('eventemitter3');
const fs = require('fs').promises;
const path = require('path');
const yaml = require('yaml');
const { Pool } = require('pg');
const Redis = require('redis');
const logger = require('./utils/logger');

class ConfigurationManager extends EventEmitter {
  constructor() {
    super();
    
    // Database connection
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@postgres/configuration'
    });
    
    // Redis connection for caching
    this.redis = Redis.createClient({
      url: process.env.REDIS_URL || 'redis://:changeme@redis:6379'
    });
    
    this.redis.connect().catch(err => {
      logger.error('Redis connection error:', err);
    });
    
    this.configPath = process.env.CONFIG_PATH || '/app/config';
    this.defaultConfig = this.loadDefaultConfiguration();
    
    this.initialize();
  }

  async initialize() {
    try {
      // Create database tables if needed
      await this.createTables();
      
      // Load initial configuration
      await this.loadConfiguration();
      
      // Watch for file changes
      this.watchConfigFiles();
      
      logger.info('Configuration Manager initialized');
    } catch (error) {
      logger.error('Failed to initialize Configuration Manager:', error);
    }
  }

  async createTables() {
    const queries = [
      `CREATE TABLE IF NOT EXISTS modules (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        enabled BOOLEAN DEFAULT false,
        config JSONB DEFAULT '{}',
        features JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      
      `CREATE TABLE IF NOT EXISTS settings (
        id VARCHAR(255) PRIMARY KEY,
        module_id VARCHAR(255) REFERENCES modules(id),
        key VARCHAR(255) NOT NULL,
        value JSONB NOT NULL,
        type VARCHAR(50),
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(module_id, key)
      )`,
      
      `CREATE TABLE IF NOT EXISTS configuration_history (
        id SERIAL PRIMARY KEY,
        module_id VARCHAR(255),
        change_type VARCHAR(50),
        old_value JSONB,
        new_value JSONB,
        changed_by VARCHAR(255),
        change_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    for (const query of queries) {
      await this.db.query(query);
    }
  }

  loadDefaultConfiguration() {
    return {
      profiles: {
        minimal: {
          name: 'Minimal',
          description: 'Basic setup with core services only',
          modules: ['authentication-service', 'device-management'],
          settings: {
            monitoring: false,
            backup: false,
            ai: false
          }
        },
        standard: {
          name: 'Standard',
          description: 'Standard setup for most organizations',
          modules: [
            'authentication-service',
            'device-management',
            'network-infrastructure',
            'printer-service',
            'monitoring-analytics'
          ],
          settings: {
            monitoring: true,
            backup: false,
            ai: false
          }
        },
        enterprise: {
          name: 'Enterprise',
          description: 'Full featured enterprise setup',
          modules: [
            'authentication-service',
            'device-management',
            'network-infrastructure',
            'security-suite',
            'printer-service',
            'monitoring-analytics',
            'policy-compliance',
            'backup-disaster',
            'automation-workflows'
          ],
          settings: {
            monitoring: true,
            backup: true,
            ai: true,
            multiTenant: true
          }
        }
      },
      modules: {
        'authentication-service': {
          name: 'Authentication Service',
          category: 'core',
          required: true,
          dependencies: [],
          defaultConfig: {
            providers: ['local', 'lldap'],
            sessionTimeout: 3600,
            mfaEnabled: false
          }
        },
        'network-infrastructure': {
          name: 'Network Infrastructure',
          category: 'infrastructure',
          required: false,
          dependencies: [],
          defaultConfig: {
            dns: { enabled: true },
            dhcp: { enabled: true },
            fileShares: { enabled: false }
          }
        },
        'security-suite': {
          name: 'Security Suite',
          category: 'security',
          required: false,
          dependencies: ['authentication-service'],
          defaultConfig: {
            threatIntel: { enabled: true },
            dlp: { enabled: false },
            pam: { enabled: true }
          }
        }
      }
    };
  }

  async loadConfiguration() {
    try {
      // Try to load from database first
      const result = await this.db.query('SELECT * FROM modules');
      
      if (result.rows.length === 0) {
        // If no configuration in database, load from files
        await this.loadFromFiles();
      } else {
        // Load from database
        for (const row of result.rows) {
          await this.cacheModule(row.id, row);
        }
      }
    } catch (error) {
      logger.error('Failed to load configuration:', error);
      throw error;
    }
  }

  async loadFromFiles() {
    try {
      const configFile = path.join(this.configPath, 'modules.yaml');
      const content = await fs.readFile(configFile, 'utf8');
      const config = yaml.parse(content);
      
      // Import into database
      for (const [moduleId, moduleConfig] of Object.entries(config.modules || {})) {
        await this.saveModule(moduleId, moduleConfig);
      }
      
      logger.info('Configuration loaded from files');
    } catch (error) {
      logger.warn('No configuration files found, using defaults');
      
      // Load default modules
      for (const [moduleId, moduleConfig] of Object.entries(this.defaultConfig.modules)) {
        await this.saveModule(moduleId, {
          ...moduleConfig,
          enabled: moduleConfig.required || false,
          config: moduleConfig.defaultConfig
        });
      }
    }
  }

  async saveModule(moduleId, moduleData) {
    const query = `
      INSERT INTO modules (id, name, enabled, config, features, metadata)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        enabled = EXCLUDED.enabled,
        config = EXCLUDED.config,
        features = EXCLUDED.features,
        metadata = EXCLUDED.metadata,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `;
    
    const values = [
      moduleId,
      moduleData.name || moduleId,
      moduleData.enabled || false,
      JSON.stringify(moduleData.config || {}),
      JSON.stringify(moduleData.features || {}),
      JSON.stringify(moduleData.metadata || {})
    ];
    
    const result = await this.db.query(query, values);
    const module = result.rows[0];
    
    // Cache in Redis
    await this.cacheModule(moduleId, module);
    
    // Record history
    await this.recordHistory(moduleId, 'update', null, module);
    
    // Emit event
    this.emit('config-changed', {
      type: 'module-updated',
      moduleId,
      data: module
    });
    
    return module;
  }

  async cacheModule(moduleId, moduleData) {
    const key = `module:${moduleId}`;
    await this.redis.set(key, JSON.stringify(moduleData), {
      EX: 300 // 5 minutes TTL
    });
  }

  async getCachedModule(moduleId) {
    const key = `module:${moduleId}`;
    const cached = await this.redis.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  async getAllSettings() {
    const result = await this.db.query('SELECT * FROM settings ORDER BY module_id, key');
    
    // Group by module
    const settings = {};
    for (const row of result.rows) {
      if (!settings[row.module_id]) {
        settings[row.module_id] = {};
      }
      settings[row.module_id][row.key] = row.value;
    }
    
    return settings;
  }

  async getModuleSettings(moduleId) {
    const result = await this.db.query(
      'SELECT key, value, type, description FROM settings WHERE module_id = $1',
      [moduleId]
    );
    
    const settings = {};
    for (const row of result.rows) {
      settings[row.key] = row.value;
    }
    
    return settings;
  }

  async updateModuleSettings(moduleId, settings) {
    const client = await this.db.connect();
    
    try {
      await client.query('BEGIN');
      
      for (const [key, value] of Object.entries(settings)) {
        await client.query(
          `INSERT INTO settings (id, module_id, key, value, type)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (module_id, key) DO UPDATE SET
             value = EXCLUDED.value,
             updated_at = CURRENT_TIMESTAMP`,
          [`${moduleId}:${key}`, moduleId, key, JSON.stringify(value), typeof value]
        );
      }
      
      await client.query('COMMIT');
      
      // Clear cache
      await this.redis.del(`settings:${moduleId}`);
      
      // Emit event
      this.emit('config-changed', {
        type: 'settings-updated',
        moduleId,
        settings
      });
      
      return settings;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async exportConfiguration() {
    const modules = await this.db.query('SELECT * FROM modules');
    const settings = await this.db.query('SELECT * FROM settings');
    
    return {
      version: '1.0.0',
      exported: new Date().toISOString(),
      modules: modules.rows.reduce((acc, row) => {
        acc[row.id] = {
          name: row.name,
          enabled: row.enabled,
          config: row.config,
          features: row.features,
          metadata: row.metadata
        };
        return acc;
      }, {}),
      settings: settings.rows.reduce((acc, row) => {
        if (!acc[row.module_id]) {
          acc[row.module_id] = {};
        }
        acc[row.module_id][row.key] = row.value;
        return acc;
      }, {})
    };
  }

  async importConfiguration(config) {
    const client = await this.db.connect();
    
    try {
      await client.query('BEGIN');
      
      // Import modules
      for (const [moduleId, moduleData] of Object.entries(config.modules || {})) {
        await this.saveModule(moduleId, moduleData);
      }
      
      // Import settings
      for (const [moduleId, moduleSettings] of Object.entries(config.settings || {})) {
        await this.updateModuleSettings(moduleId, moduleSettings);
      }
      
      await client.query('COMMIT');
      
      logger.info('Configuration imported successfully');
      
      // Clear all caches
      const keys = await this.redis.keys('module:*');
      if (keys.length > 0) {
        await this.redis.del(keys);
      }
      
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to import configuration:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  async applyMinimalProfile() {
    return this.applyProfile('minimal');
  }

  async applyStandardProfile() {
    return this.applyProfile('standard');
  }

  async applyEnterpriseProfile() {
    return this.applyProfile('enterprise');
  }

  async applyProfile(profileName) {
    const profile = this.defaultConfig.profiles[profileName];
    if (!profile) {
      throw new Error(`Profile ${profileName} not found`);
    }
    
    // Disable all modules first
    await this.db.query('UPDATE modules SET enabled = false');
    
    // Enable modules for this profile
    for (const moduleId of profile.modules) {
      await this.db.query(
        'UPDATE modules SET enabled = true WHERE id = $1',
        [moduleId]
      );
    }
    
    // Apply profile settings
    for (const [key, value] of Object.entries(profile.settings)) {
      await this.updateModuleSettings('global', { [key]: value });
    }
    
    // Clear caches
    const keys = await this.redis.keys('module:*');
    if (keys.length > 0) {
      await this.redis.del(keys);
    }
    
    logger.info(`Applied profile: ${profileName}`);
    
    return {
      profile: profileName,
      modules: profile.modules,
      settings: profile.settings
    };
  }

  async applyCustomProfile(modules, settings) {
    // Disable all modules first
    await this.db.query('UPDATE modules SET enabled = false');
    
    // Enable selected modules
    for (const moduleId of modules) {
      await this.db.query(
        'UPDATE modules SET enabled = true WHERE id = $1',
        [moduleId]
      );
    }
    
    // Apply custom settings
    if (settings) {
      for (const [moduleId, moduleSettings] of Object.entries(settings)) {
        await this.updateModuleSettings(moduleId, moduleSettings);
      }
    }
    
    // Clear caches
    const keys = await this.redis.keys('module:*');
    if (keys.length > 0) {
      await this.redis.del(keys);
    }
    
    logger.info('Applied custom profile');
    
    return {
      profile: 'custom',
      modules,
      settings
    };
  }

  async recordHistory(moduleId, changeType, oldValue, newValue, changedBy = 'system', reason = '') {
    await this.db.query(
      `INSERT INTO configuration_history 
       (module_id, change_type, old_value, new_value, changed_by, change_reason)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        moduleId,
        changeType,
        oldValue ? JSON.stringify(oldValue) : null,
        newValue ? JSON.stringify(newValue) : null,
        changedBy,
        reason
      ]
    );
  }

  watchConfigFiles() {
    // Watch for configuration file changes
    const chokidar = require('chokidar');
    const watcher = chokidar.watch(this.configPath, {
      persistent: true,
      ignoreInitial: true
    });

    watcher.on('change', async (filePath) => {
      logger.info(`Configuration file changed: ${filePath}`);
      await this.loadFromFiles();
    });
  }

  async close() {
    await this.db.end();
    await this.redis.quit();
  }
}

module.exports = ConfigurationManager;