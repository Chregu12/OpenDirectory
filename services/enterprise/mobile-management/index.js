#!/usr/bin/env node

/**
 * Mobile Management Suite Orchestrator
 * Starts and manages all mobile management services
 */

const cluster = require('cluster');
const os = require('os');
const path = require('path');
const fs = require('fs');

// Service configurations
const SERVICES = {
  ios: {
    name: 'iOS Management Service',
    script: path.join(__dirname, 'ios-management-service.js'),
    port: process.env.IOS_MANAGEMENT_PORT || 3011,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      IOS_MANAGEMENT_PORT: process.env.IOS_MANAGEMENT_PORT || 3011,
      APPLE_DEP_CLIENT_ID: process.env.APPLE_DEP_CLIENT_ID || '',
      APPLE_DEP_CLIENT_SECRET: process.env.APPLE_DEP_CLIENT_SECRET || '',
      APPLE_VPP_CLIENT_ID: process.env.APPLE_VPP_CLIENT_ID || '',
      APPLE_VPP_CLIENT_SECRET: process.env.APPLE_VPP_CLIENT_SECRET || ''
    }
  },
  android: {
    name: 'Android Enterprise Service',
    script: path.join(__dirname, 'android-enterprise-service.js'),
    port: process.env.ANDROID_ENTERPRISE_PORT || 3012,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      ANDROID_ENTERPRISE_PORT: process.env.ANDROID_ENTERPRISE_PORT || 3012,
      GOOGLE_CLIENT_EMAIL: process.env.GOOGLE_CLIENT_EMAIL || '',
      GOOGLE_PRIVATE_KEY: process.env.GOOGLE_PRIVATE_KEY || '',
      GOOGLE_PROJECT_ID: process.env.GOOGLE_PROJECT_ID || '',
      KNOX_CLIENT_ID: process.env.KNOX_CLIENT_ID || '',
      KNOX_CLIENT_SECRET: process.env.KNOX_CLIENT_SECRET || ''
    }
  },
  mam: {
    name: 'Mobile App Management Service',
    script: path.join(__dirname, 'mobile-app-management-service.js'),
    port: process.env.MAM_SERVICE_PORT || 3013,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      MAM_SERVICE_PORT: process.env.MAM_SERVICE_PORT || 3013,
      APP_STORAGE_PATH: process.env.APP_STORAGE_PATH || '/tmp/mam-apps',
      MAX_APP_SIZE: process.env.MAX_APP_SIZE || 524288000,
      APP_WRAPPING_ENABLED: process.env.APP_WRAPPING_ENABLED || 'false'
    }
  },
  mtd: {
    name: 'Mobile Threat Defense Service',
    script: path.join(__dirname, 'mobile-threat-defense-service.js'),
    port: process.env.MTD_SERVICE_PORT || 3014,
    env: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      MTD_SERVICE_PORT: process.env.MTD_SERVICE_PORT || 3014,
      VIRUSTOTAL_ENABLED: process.env.VIRUSTOTAL_ENABLED || 'false',
      VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',
      SIEM_ENABLED: process.env.SIEM_ENABLED || 'false'
    }
  }
};

class MobileManagementOrchestrator {
  constructor() {
    this.workers = new Map();
    this.startTime = new Date();
    this.serviceOrder = ['mtd', 'mam', 'android', 'ios']; // Start MTD first, then MAM, Android, iOS
    this.isShuttingDown = false;
    this.healthCheckInterval = null;
  }

  async start() {
    console.log('🚀 Starting OpenDirectory Mobile Management Suite...');
    console.log(`📅 Started at: ${this.startTime.toISOString()}`);
    console.log(`💻 Platform: ${os.platform()} ${os.arch()}`);
    console.log(`🔧 Node.js: ${process.version}`);
    console.log(`👥 CPU Cores: ${os.cpus().length}`);
    console.log(`💾 Total Memory: ${Math.round(os.totalmem() / 1024 / 1024 / 1024)}GB`);

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
      process.env.APP_STORAGE_PATH || '/tmp/mam-apps',
      './logs',
      './certificates',
      './data'
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        try {
          fs.mkdirSync(dir, { recursive: true });
          console.log(`📁 Created directory: ${dir}`);
        } catch (error) {
          console.error(`❌ Failed to create directory ${dir}:`, error.message);
        }
      }
    });
  }

  async startMaster() {
    console.log('🎯 Starting as master process...');

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

    console.log('✅ All mobile management services started successfully!');
    console.log('\n📊 Service Status:');
    this.printServiceStatus();
  }

  async startService(serviceId) {
    const service = SERVICES[serviceId];
    if (!service) {
      console.error(`❌ Unknown service: ${serviceId}`);
      return;
    }

    console.log(`🔄 Starting ${service.name}...`);

    // Set environment variables for the worker
    Object.assign(process.env, service.env);

    const worker = cluster.fork({ SERVICE_ID: serviceId, SERVICE_SCRIPT: service.script });
    
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
          console.log(`✅ ${service.name} started successfully on port ${service.port}`);
          resolve();
        }
      });

      worker.on('exit', (code, signal) => {
        clearTimeout(timeout);
        if (code !== 0 && !this.isShuttingDown) {
          console.error(`❌ ${service.name} exited with code ${code}, signal: ${signal}`);
          // Auto-restart logic
          this.restartService(serviceId);
        }
      });

      worker.on('error', (error) => {
        clearTimeout(timeout);
        console.error(`❌ ${service.name} error:`, error);
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
      console.error(`💀 ${service.name} has failed 5 times. Not restarting.`);
      return;
    }

    console.log(`🔄 Restarting ${service.name} (attempt ${worker.restartCount})...`);

    // Remove the old worker
    this.workers.delete(serviceId);

    // Wait before restarting
    await this.delay(5000 * worker.restartCount); // Exponential backoff

    // Start the service again
    try {
      await this.startService(serviceId);
    } catch (error) {
      console.error(`❌ Failed to restart ${service.name}:`, error.message);
    }
  }

  async startWorker() {
    const serviceId = process.env.SERVICE_ID;
    const scriptPath = process.env.SERVICE_SCRIPT;
    
    if (!serviceId || !scriptPath) {
      console.error('❌ Worker started without service information');
      process.exit(1);
    }

    try {
      // Load and start the specific service
      require(scriptPath);
      
      // Notify master that service is ready
      process.send({ type: 'service_ready', serviceId });
    } catch (error) {
      console.error(`❌ Failed to start service ${serviceId}:`, error);
      process.exit(1);
    }
  }

  startHealthMonitoring() {
    this.healthCheckInterval = setInterval(() => {
      this.performHealthCheck();
    }, 60000); // Every minute

    console.log('💗 Health monitoring started');
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
          memory: health.memory 
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
      console.warn('⚠️  Health check issues:', unhealthy);
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
      console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);

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
      console.log(`✅ Graceful shutdown completed in ${Math.round(duration / 1000)}s`);
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
          console.log(`💀 Worker ${worker.process.pid} (${serviceId}) died`);
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
    
    console.log('\n🔗 API Endpoints:');
    console.log('• iOS Management:      http://localhost:3011/health');
    console.log('• Android Enterprise:  http://localhost:3012/health');
    console.log('• Mobile App Mgmt:     http://localhost:3013/health');
    console.log('• Mobile Threat Def:   http://localhost:3014/health');
    
    console.log('\n🌐 WebSocket Endpoints:');
    console.log('• iOS:                 ws://localhost:3011/ws/ios');
    console.log('• Android:             ws://localhost:3012/ws/android');
    console.log('• MAM:                 ws://localhost:3013/ws/mam');
    console.log('• MTD:                 ws://localhost:3014/ws/mtd');
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Start the orchestrator
const orchestrator = new MobileManagementOrchestrator();
orchestrator.start().catch(error => {
  console.error('💥 Failed to start Mobile Management Suite:', error);
  process.exit(1);
});

module.exports = MobileManagementOrchestrator;