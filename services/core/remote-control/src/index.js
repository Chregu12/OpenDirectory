#!/usr/bin/env node

/**
 * OpenDirectory Remote Control Service
 * Comprehensive remote control solution with desktop, screen sharing, file transfer, and command execution
 */

const cluster = require('cluster');
const os = require('os');
const path = require('path');
const fs = require('fs');
const logger = require('./utils/logger');

// Service configurations
const SERVICES = {
  desktop: {
    name: 'Remote Desktop Service',
    script: path.join(__dirname, 'services', 'remoteDesktopService.js'),
    port: process.env.REMOTE_DESKTOP_PORT || 3019,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      REMOTE_DESKTOP_PORT: process.env.REMOTE_DESKTOP_PORT || 3019,
      VNC_ENABLED: process.env.VNC_ENABLED || 'true',
      RDP_ENABLED: process.env.RDP_ENABLED || 'true',
      WEBRTC_ENABLED: process.env.WEBRTC_ENABLED || 'true',
      SSL_ENABLED: process.env.SSL_ENABLED || 'true'
    }
  },
  screen: {
    name: 'Screen Sharing Service',
    script: path.join(__dirname, 'services', 'screenSharingService.js'),
    port: process.env.SCREEN_SHARING_PORT || 3020,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      SCREEN_SHARING_PORT: process.env.SCREEN_SHARING_PORT || 3020,
      COLLABORATION_ENABLED: process.env.COLLABORATION_ENABLED || 'true',
      RECORDING_ENABLED: process.env.RECORDING_ENABLED || 'true',
      MAX_VIEWERS: process.env.MAX_VIEWERS || '10'
    }
  },
  transfer: {
    name: 'File Transfer Service',
    script: path.join(__dirname, 'services', 'fileTransferService.js'),
    port: process.env.FILE_TRANSFER_PORT || 3021,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      FILE_TRANSFER_PORT: process.env.FILE_TRANSFER_PORT || 3021,
      MAX_FILE_SIZE: process.env.MAX_FILE_SIZE || 1073741824, // 1GB
      ENCRYPTION_ENABLED: process.env.ENCRYPTION_ENABLED || 'true',
      TRANSFER_PATH: process.env.TRANSFER_PATH || '/tmp/remote-transfers'
    }
  },
  command: {
    name: 'Remote Command Execution Service',
    script: path.join(__dirname, 'services', 'commandExecutionService.js'),
    port: process.env.COMMAND_EXECUTION_PORT || 3022,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      COMMAND_EXECUTION_PORT: process.env.COMMAND_EXECUTION_PORT || 3022,
      SSH_ENABLED: process.env.SSH_ENABLED || 'true',
      POWERSHELL_ENABLED: process.env.POWERSHELL_ENABLED || 'true',
      BASH_ENABLED: process.env.BASH_ENABLED || 'true',
      AUDIT_ENABLED: process.env.AUDIT_ENABLED || 'true'
    }
  },
  session: {
    name: 'Session Management Service',
    script: path.join(__dirname, 'services', 'sessionManagementService.js'),
    port: process.env.SESSION_MANAGEMENT_PORT || 3023,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      SESSION_MANAGEMENT_PORT: process.env.SESSION_MANAGEMENT_PORT || 3023,
      RECORDING_ENABLED: process.env.RECORDING_ENABLED || 'true',
      AUDIT_ENABLED: process.env.AUDIT_ENABLED || 'true',
      SESSION_TIMEOUT: process.env.SESSION_TIMEOUT || '3600000' // 1 hour
    }
  }
};

class RemoteControlOrchestrator {
  constructor() {
    this.workers = new Map();
    this.startTime = new Date();
    this.serviceOrder = ['session', 'transfer', 'command', 'screen', 'desktop']; // Start session management first
    this.isShuttingDown = false;
    this.healthCheckInterval = null;
    this.config = this.loadConfiguration();
  }

  loadConfiguration() {
    const configPath = path.join(__dirname, 'config', 'config.json');
    let config = {
      security: {
        encryption: true,
        mfa_required: false,
        session_timeout: 3600000,
        max_concurrent_sessions: 50
      },
      integrations: {
        mobile_management_url: 'http://mobile-management:3013',
        license_management_url: 'http://license-management:3018',
        auth_service_url: 'http://authentication-service:3001'
      },
      performance: {
        compression_enabled: true,
        bandwidth_optimization: true,
        quality_auto_adjust: true
      }
    };

    try {
      if (fs.existsSync(configPath)) {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        config = { ...config, ...fileConfig };
      }
    } catch (error) {
      logger.warn('Failed to load configuration file, using defaults:', error.message);
    }

    return config;
  }

  async start() {
    logger.info('🚀 Starting OpenDirectory Remote Control Service...');
    logger.info(`📅 Started at: ${this.startTime.toISOString()}`);
    logger.info(`💻 Platform: ${os.platform()} ${os.arch()}`);
    logger.info(`🔧 Node.js: ${process.version}`);
    logger.info(`👥 CPU Cores: ${os.cpus().length}`);
    logger.info(`💾 Total Memory: ${Math.round(os.totalmem() / 1024 / 1024 / 1024)}GB`);

    // Create necessary directories
    this.createDirectories();

    if (cluster.isMaster) {
      await this.startMaster();
    } else {
      await this.startWorker();
    }
  }

  createDirectories() {
    const dirs = [
      process.env.TRANSFER_PATH || '/tmp/remote-transfers',
      './logs',
      './certificates',
      './sessions',
      './recordings',
      './data'
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        try {
          fs.mkdirSync(dir, { recursive: true });
          logger.info(`📁 Created directory: ${dir}`);
        } catch (error) {
          logger.error(`❌ Failed to create directory ${dir}:`, error.message);
        }
      }
    });
  }

  async startMaster() {
    logger.info('🎯 Starting as master process...');

    // Initialize shared configuration
    this.initializeSharedConfiguration();

    // Start services in order
    for (const serviceId of this.serviceOrder) {
      await this.startService(serviceId);
      // Wait a bit between service starts
      await this.delay(2000);
    }

    // Start health monitoring
    this.startHealthMonitoring();

    // Setup graceful shutdown
    this.setupGracefulShutdown();

    // Register with API Gateway
    await this.registerWithGateway();

    logger.info('✅ All remote control services started successfully!');
    logger.info('\n📊 Service Status:');
    this.printServiceStatus();
  }

  initializeSharedConfiguration() {
    // Write configuration for worker processes
    const configPath = path.join(__dirname, 'config', 'config.json');
    const configDir = path.dirname(configPath);
    
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    
    fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
    logger.info('📋 Configuration initialized for worker processes');
  }

  async registerWithGateway() {
    try {
      const axios = require('axios');
      
      // Register each service with the API Gateway
      for (const [serviceId, service] of Object.entries(SERVICES)) {
        try {
          await axios.post('http://api-gateway:8080/api/services/register', {
            name: `remote-control-${serviceId}`,
            url: `http://remote-control-${serviceId}:${service.port}`,
            healthPath: '/health',
            version: require('../package.json').version,
            capabilities: this.getServiceCapabilities(serviceId)
          });
          logger.info(`✅ Registered ${service.name} with API Gateway`);
        } catch (error) {
          logger.warn(`⚠️ Failed to register ${service.name} with gateway:`, error.message);
        }
      }
    } catch (error) {
      logger.warn('⚠️ API Gateway registration failed:', error.message);
    }
  }

  getServiceCapabilities(serviceId) {
    const capabilities = {
      desktop: ['vnc', 'rdp', 'webrtc', 'cross-platform'],
      screen: ['collaboration', 'recording', 'multi-viewer', 'real-time'],
      transfer: ['encrypted-transfer', 'large-files', 'resume-support', 'audit'],
      command: ['ssh', 'powershell', 'bash', 'audit', 'secure-execution'],
      session: ['recording', 'audit', 'session-replay', 'compliance']
    };

    return capabilities[serviceId] || [];
  }

  async startService(serviceId) {
    const service = SERVICES[serviceId];
    if (!service) {
      logger.error(`❌ Unknown service: ${serviceId}`);
      return;
    }

    logger.info(`🔄 Starting ${service.name}...`);

    // Set environment variables for the worker
    Object.assign(process.env, service.env);

    const worker = cluster.fork({ 
      SERVICE_ID: serviceId, 
      SERVICE_SCRIPT: service.script,
      SERVICE_CONFIG: JSON.stringify(this.config)
    });
    
    worker.serviceId = serviceId;
    worker.serviceName = service.name;
    worker.startTime = new Date();
    worker.restartCount = 0;

    this.workers.set(serviceId, worker);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Service ${service.name} failed to start within 30 seconds`));
      }, 30000);

      worker.on('message', (message) => {
        if (message.type === 'service_ready') {
          clearTimeout(timeout);
          logger.info(`✅ ${service.name} started successfully on port ${service.port}`);
          resolve();
        }
      });

      worker.on('exit', (code, signal) => {
        clearTimeout(timeout);
        if (code !== 0 && !this.isShuttingDown) {
          logger.error(`❌ ${service.name} exited with code ${code}, signal: ${signal}`);
          // Auto-restart logic
          this.restartService(serviceId);
        }
      });

      worker.on('error', (error) => {
        clearTimeout(timeout);
        logger.error(`❌ ${service.name} error:`, error);
        reject(error);
      });
    });
  }

  async restartService(serviceId) {
    const worker = this.workers.get(serviceId);
    const service = SERVICES[serviceId];
    
    if (!worker || !service) return;

    worker.restartCount = (worker.restartCount || 0) + 1;

    if (worker.restartCount > 5) {
      logger.error(`💀 ${service.name} has failed 5 times. Not restarting.`);
      return;
    }

    logger.info(`🔄 Restarting ${service.name} (attempt ${worker.restartCount})...`);

    // Remove the old worker
    this.workers.delete(serviceId);

    // Wait before restarting
    await this.delay(5000 * worker.restartCount); // Exponential backoff

    // Start the service again
    try {
      await this.startService(serviceId);
    } catch (error) {
      logger.error(`❌ Failed to restart ${service.name}:`, error.message);
    }
  }

  async startWorker() {
    const serviceId = process.env.SERVICE_ID;
    const scriptPath = process.env.SERVICE_SCRIPT;
    
    if (!serviceId || !scriptPath) {
      logger.error('❌ Worker started without service information');
      process.exit(1);
    }

    try {
      // Load and start the specific service
      require(scriptPath);
      
      // Notify master that service is ready
      process.send({ type: 'service_ready', serviceId });
    } catch (error) {
      logger.error(`❌ Failed to start service ${serviceId}:`, error);
      process.exit(1);
    }
  }

  startHealthMonitoring() {
    this.healthCheckInterval = setInterval(() => {
      this.performHealthCheck();
    }, 60000); // Every minute

    logger.info('💗 Health monitoring started');
  }

  async performHealthCheck() {
    const http = require('http');
    const healthResults = {};

    for (const [serviceId, service] of Object.entries(SERVICES)) {
      const worker = this.workers.get(serviceId);
      
      if (!worker || worker.isDead()) {
        healthResults[serviceId] = { status: 'dead', worker: false };
        continue;
      }

      try {
        const health = await this.checkServiceHealth(service.port);
        healthResults[serviceId] = { 
          status: health.status, 
          worker: true,
          uptime: health.uptime,
          memory: health.memory,
          connections: health.connections || 0
        };
      } catch (error) {
        healthResults[serviceId] = { 
          status: 'unhealthy', 
          worker: true, 
          error: error.message 
        };
      }
    }

    // Log summary if any issues
    const unhealthy = Object.entries(healthResults)
      .filter(([id, result]) => result.status !== 'healthy');

    if (unhealthy.length > 0) {
      logger.warn('⚠️  Health check issues:', unhealthy);
    }
  }

  checkServiceHealth(port) {
    const http = require('http');
    
    return new Promise((resolve, reject) => {
      const req = http.request({
        hostname: 'localhost',
        port,
        path: '/health',
        timeout: 5000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const health = JSON.parse(data);
            resolve(health);
          } catch (error) {
            reject(new Error('Invalid health response'));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Health check timeout')));
      req.end();
    });
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      if (this.isShuttingDown) return;
      
      this.isShuttingDown = true;
      logger.info(`\n🛑 Received ${signal}. Starting graceful shutdown...`);

      // Stop health monitoring
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
      }

      // Stop all workers
      const shutdownPromises = Array.from(this.workers.values()).map(worker => {
        return new Promise((resolve) => {
          worker.on('exit', resolve);
          worker.kill('SIGTERM');
          
          // Force kill after 10 seconds
          setTimeout(() => {
            if (!worker.isDead()) {
              worker.kill('SIGKILL');
            }
            resolve();
          }, 10000);
        });
      });

      await Promise.all(shutdownPromises);

      const duration = Date.now() - this.startTime.getTime();
      logger.info(`✅ Graceful shutdown completed in ${Math.round(duration / 1000)}s`);
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    // Handle worker exits
    cluster.on('exit', (worker, code, signal) => {
      if (!this.isShuttingDown && code !== 0) {
        const serviceId = Array.from(this.workers.entries())
          .find(([id, w]) => w === worker)?.[0];
        
        if (serviceId) {
          logger.info(`💀 Worker ${worker.process.pid} (${serviceId}) died`);
          this.restartService(serviceId);
        }
      }
    });
  }

  printServiceStatus() {
    const table = [];
    
    for (const [serviceId, service] of Object.entries(SERVICES)) {
      const worker = this.workers.get(serviceId);
      const status = worker && !worker.isDead() ? '🟢 Running' : '🔴 Stopped';
      const pid = worker ? worker.process.pid : 'N/A';
      const port = service.port;
      
      table.push({
        Service: service.name,
        Status: status,
        Port: port,
        PID: pid
      });
    }

    console.table(table);
    
    logger.info('\n🔗 API Endpoints:');
    logger.info('• Remote Desktop:      http://localhost:3019/health');
    logger.info('• Screen Sharing:      http://localhost:3020/health');
    logger.info('• File Transfer:       http://localhost:3021/health');
    logger.info('• Command Execution:   http://localhost:3022/health');
    logger.info('• Session Management:  http://localhost:3023/health');
    
    logger.info('\n🌐 WebSocket Endpoints:');
    logger.info('• Desktop:             ws://localhost:3019/ws/desktop');
    logger.info('• Screen:              ws://localhost:3020/ws/screen');
    logger.info('• Transfer:            ws://localhost:3021/ws/transfer');
    logger.info('• Command:             ws://localhost:3022/ws/command');
    logger.info('• Session:             ws://localhost:3023/ws/session');
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Start the orchestrator
const orchestrator = new RemoteControlOrchestrator();
orchestrator.start().catch(error => {
  logger.error('💥 Failed to start Remote Control Service:', error);
  process.exit(1);
});

module.exports = RemoteControlOrchestrator;