const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const WebSocket = require('ws');
const http = require('http');
const EventEmitter = require('eventemitter3');

const ConfigurationManager = require('./configurationManager');
const ModuleRegistry = require('./moduleRegistry');
const FeatureFlags = require('./featureFlags');
const SettingsValidator = require('./settingsValidator');
const logger = require('./utils/logger');

class ConfigurationService extends EventEmitter {
  constructor() {
    super();
    this.app = express();
    this.server = null;
    this.wsServer = null;
    this.configManager = new ConfigurationManager();
    this.moduleRegistry = new ModuleRegistry();
    this.featureFlags = new FeatureFlags();
    this.validator = new SettingsValidator();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeEventHandlers();
  }

  initializeMiddleware() {
    this.app.use(helmet());
    this.app.use(cors({
      origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
      credentials: true
    }));
    this.app.use(express.json());
    
    // Request logging
    this.app.use((req, res, next) => {
      logger.info(`${req.method} ${req.path}`);
      next();
    });
  }

  initializeWebSocket() {
    this.server = http.createServer(this.app);
    
    this.wsServer = new WebSocket.Server({
      server: this.server,
      path: '/ws/config'
    });

    this.wsServer.on('connection', (ws, req) => {
      logger.info(`WebSocket connection established from ${req.socket.remoteAddress}`);
      
      // Send current configuration
      ws.send(JSON.stringify({
        type: 'config-sync',
        data: {
          modules: this.moduleRegistry.getAllModules(),
          features: this.featureFlags.getAllFlags(),
          timestamp: new Date().toISOString()
        }
      }));

      // Handle configuration changes
      const handleConfigChange = (data) => {
        ws.send(JSON.stringify({
          type: 'config-update',
          data
        }));
      };

      this.on('config-changed', handleConfigChange);

      ws.on('close', () => {
        this.off('config-changed', handleConfigChange);
        logger.info('WebSocket connection closed');
      });

      ws.on('error', (error) => {
        logger.error('WebSocket error:', error);
      });
    });
  }

  initializeRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'configuration-service',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      });
    });

    // Module management
    this.app.get('/api/modules', this.getModules.bind(this));
    this.app.get('/api/modules/:moduleId', this.getModule.bind(this));
    this.app.post('/api/modules/:moduleId', this.updateModule.bind(this));
    this.app.delete('/api/modules/:moduleId', this.disableModule.bind(this));
    
    // Feature flags
    this.app.get('/api/features', this.getFeatures.bind(this));
    this.app.get('/api/features/:featureId', this.getFeature.bind(this));
    this.app.post('/api/features/:featureId', this.updateFeature.bind(this));
    
    // Settings management
    this.app.get('/api/settings', this.getSettings.bind(this));
    this.app.get('/api/settings/:moduleId', this.getModuleSettings.bind(this));
    this.app.put('/api/settings/:moduleId', this.updateModuleSettings.bind(this));
    
    // Validation
    this.app.post('/api/validate', this.validateConfiguration.bind(this));
    
    // Export/Import
    this.app.get('/api/export', this.exportConfiguration.bind(this));
    this.app.post('/api/import', this.importConfiguration.bind(this));
    
    // Setup wizard
    this.app.get('/api/wizard/available-modules', this.getAvailableModules.bind(this));
    this.app.post('/api/wizard/setup', this.runSetupWizard.bind(this));

    // Error handling
    this.app.use((error, req, res, next) => {
      logger.error('Request error:', error);
      res.status(error.status || 500).json({
        error: error.message || 'Internal server error',
        timestamp: new Date().toISOString()
      });
    });
  }

  initializeEventHandlers() {
    // Watch for configuration changes
    this.configManager.on('config-changed', (data) => {
      this.emit('config-changed', data);
      this.broadcastToWebSockets('config-update', data);
    });

    // Watch for module changes
    this.moduleRegistry.on('module-changed', (data) => {
      this.emit('module-changed', data);
      this.broadcastToWebSockets('module-update', data);
    });

    // Watch for feature flag changes
    this.featureFlags.on('flag-changed', (data) => {
      this.emit('feature-changed', data);
      this.broadcastToWebSockets('feature-update', data);
    });
  }

  // API Handlers
  async getModules(req, res) {
    try {
      const modules = await this.moduleRegistry.getAllModules();
      res.json({ modules });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getModule(req, res) {
    try {
      const { moduleId } = req.params;
      const module = await this.moduleRegistry.getModule(moduleId);
      
      if (!module) {
        return res.status(404).json({ error: 'Module not found' });
      }
      
      res.json(module);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async updateModule(req, res) {
    try {
      const { moduleId } = req.params;
      const { enabled, features, config } = req.body;
      
      // Validate configuration
      if (config) {
        const validation = await this.validator.validateModuleConfig(moduleId, config);
        if (!validation.valid) {
          return res.status(400).json({ 
            error: 'Invalid configuration',
            details: validation.errors 
          });
        }
      }
      
      const updated = await this.moduleRegistry.updateModule(moduleId, {
        enabled,
        features,
        config
      });
      
      res.json({
        success: true,
        module: updated
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async disableModule(req, res) {
    try {
      const { moduleId } = req.params;
      await this.moduleRegistry.disableModule(moduleId);
      
      res.json({
        success: true,
        message: `Module ${moduleId} disabled`
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async getFeatures(req, res) {
    try {
      const features = await this.featureFlags.getAllFlags();
      res.json({ features });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getFeature(req, res) {
    try {
      const { featureId } = req.params;
      const feature = await this.featureFlags.getFlag(featureId);
      
      if (!feature) {
        return res.status(404).json({ error: 'Feature not found' });
      }
      
      res.json(feature);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async updateFeature(req, res) {
    try {
      const { featureId } = req.params;
      const { enabled, rollout, conditions } = req.body;
      
      const updated = await this.featureFlags.updateFlag(featureId, {
        enabled,
        rollout,
        conditions
      });
      
      res.json({
        success: true,
        feature: updated
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async getSettings(req, res) {
    try {
      const settings = await this.configManager.getAllSettings();
      res.json({ settings });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getModuleSettings(req, res) {
    try {
      const { moduleId } = req.params;
      const settings = await this.configManager.getModuleSettings(moduleId);
      
      if (!settings) {
        return res.status(404).json({ error: 'Module settings not found' });
      }
      
      res.json(settings);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async updateModuleSettings(req, res) {
    try {
      const { moduleId } = req.params;
      const settings = req.body;
      
      // Validate settings
      const validation = await this.validator.validateModuleSettings(moduleId, settings);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'Invalid settings',
          details: validation.errors
        });
      }
      
      const updated = await this.configManager.updateModuleSettings(moduleId, settings);
      
      res.json({
        success: true,
        settings: updated
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async validateConfiguration(req, res) {
    try {
      const { moduleId, config } = req.body;
      const validation = await this.validator.validateModuleConfig(moduleId, config);
      
      res.json({
        valid: validation.valid,
        errors: validation.errors || []
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async exportConfiguration(req, res) {
    try {
      const config = await this.configManager.exportConfiguration();
      
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="opendirectory-config.json"');
      res.json(config);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async importConfiguration(req, res) {
    try {
      const config = req.body;
      
      // Validate imported configuration
      const validation = await this.validator.validateFullConfiguration(config);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'Invalid configuration',
          details: validation.errors
        });
      }
      
      await this.configManager.importConfiguration(config);
      
      res.json({
        success: true,
        message: 'Configuration imported successfully'
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async getAvailableModules(req, res) {
    try {
      const modules = await this.moduleRegistry.getAvailableModules();
      
      res.json({
        modules: modules.map(m => ({
          id: m.id,
          name: m.name,
          description: m.description,
          category: m.category,
          dependencies: m.dependencies,
          features: m.features,
          requirements: m.requirements
        }))
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async runSetupWizard(req, res) {
    try {
      const { profile, modules, settings } = req.body;
      
      // Apply profile-based configuration
      let config;
      switch (profile) {
        case 'minimal':
          config = await this.configManager.applyMinimalProfile();
          break;
        case 'standard':
          config = await this.configManager.applyStandardProfile();
          break;
        case 'enterprise':
          config = await this.configManager.applyEnterpriseProfile();
          break;
        case 'custom':
          config = await this.configManager.applyCustomProfile(modules, settings);
          break;
        default:
          throw new Error('Invalid profile');
      }
      
      res.json({
        success: true,
        message: `Configuration profile '${profile}' applied successfully`,
        config
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  broadcastToWebSockets(type, data) {
    if (this.wsServer) {
      const message = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
      
      this.wsServer.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(message);
        }
      });
    }
  }

  start(port = process.env.PORT || 3002) {
    this.server.listen(port, () => {
      logger.info(`🔧 Configuration Service started on port ${port}`);
      logger.info(`📊 Health check: http://localhost:${port}/health`);
      logger.info(`🔌 WebSocket: ws://localhost:${port}/ws/config`);
    });
  }

  stop() {
    if (this.server) {
      this.server.close(() => {
        logger.info('Configuration Service stopped');
      });
    }
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully');
  process.exit(0);
});

// Start the service
const service = new ConfigurationService();
service.start();

module.exports = ConfigurationService;