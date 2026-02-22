#!/usr/bin/env node

/**
 * OpenDirectory MDM Service Orchestrator
 * Master service to coordinate all background services
 * Operates invisibly in the background
 */

const fs = require('fs').promises;
const path = require('path');
const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class ServiceOrchestrator {
    constructor() {
        this.config = {
            services: [
                {
                    name: 'health-monitor',
                    path: '/tmp/opendirectory-health-monitor.js',
                    priority: 1,
                    restartPolicy: 'always',
                    maxRestarts: 5,
                    restartDelay: 10000, // 10 seconds
                    healthCheckInterval: 60000, // 1 minute
                    enabled: true
                },
                {
                    name: 'backup-service',
                    path: '/tmp/opendirectory-backup-service.js',
                    priority: 2,
                    restartPolicy: 'on-failure',
                    maxRestarts: 3,
                    restartDelay: 30000, // 30 seconds
                    healthCheckInterval: 300000, // 5 minutes
                    enabled: true
                },
                {
                    name: 'compliance-scanner',
                    path: '/tmp/opendirectory-compliance-scanner.js',
                    priority: 3,
                    restartPolicy: 'on-failure',
                    maxRestarts: 3,
                    restartDelay: 60000, // 1 minute
                    healthCheckInterval: 600000, // 10 minutes
                    enabled: true
                },
                {
                    name: 'security-service',
                    path: '/tmp/opendirectory-security-service.js',
                    priority: 1,
                    restartPolicy: 'always',
                    maxRestarts: 5,
                    restartDelay: 5000, // 5 seconds
                    healthCheckInterval: 30000, // 30 seconds
                    enabled: true
                },
                {
                    name: 'update-engine',
                    path: '/tmp/opendirectory-update-engine.js',
                    priority: 2,
                    restartPolicy: 'on-failure',
                    maxRestarts: 3,
                    restartDelay: 60000, // 1 minute
                    healthCheckInterval: 300000, // 5 minutes
                    enabled: true
                }
            ],
            orchestratorInterval: 30000, // 30 seconds
            resourceLimits: {
                maxCpuPercent: 80,
                maxMemoryMB: 1024,
                maxDiskUsagePercent: 90
            },
            logging: {
                centralLog: '/tmp/orchestrator.log',
                maxLogSize: 50 * 1024 * 1024, // 50MB
                logRotationCount: 5
            }
        };

        this.services = new Map();
        this.isRunning = false;
        this.systemResources = {
            cpu: { usage: 0, limit: this.config.resourceLimits.maxCpuPercent },
            memory: { usage: 0, limit: this.config.resourceLimits.maxMemoryMB },
            disk: { usage: 0, limit: this.config.resourceLimits.maxDiskUsagePercent }
        };
        this.eventQueue = [];
    }

    async start() {
        this.log('Service Orchestrator starting...');
        this.isRunning = true;

        try {
            // Initialize service tracking
            await this.initializeServices();

            // Start orchestration loop
            this.orchestrationLoop();

            // Set up cleanup on exit
            process.on('SIGTERM', () => this.shutdown());
            process.on('SIGINT', () => this.shutdown());

            // Start all services
            await this.startAllServices();

            this.log('Service Orchestrator started successfully');

        } catch (error) {
            this.log(`Failed to start Service Orchestrator: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async initializeServices() {
        for (const serviceConfig of this.config.services) {
            if (!serviceConfig.enabled) {
                continue;
            }

            const serviceState = {
                config: serviceConfig,
                process: null,
                status: 'stopped',
                restartCount: 0,
                lastRestart: 0,
                lastHealthCheck: 0,
                healthStatus: 'unknown',
                resources: {
                    cpu: 0,
                    memory: 0,
                    pid: null
                },
                events: []
            };

            this.services.set(serviceConfig.name, serviceState);
            this.log(`Initialized service: ${serviceConfig.name}`);
        }
    }

    orchestrationLoop() {
        const orchestrate = async () => {
            if (!this.isRunning) return;

            try {
                // Monitor system resources
                await this.monitorSystemResources();

                // Check service health
                await this.performHealthChecks();

                // Process service events
                await this.processServiceEvents();

                // Manage resource allocation
                await this.manageResourceAllocation();

                // Handle service restarts if needed
                await this.handleServiceRestarts();

                // Generate status reports
                await this.generateStatusReports();

            } catch (error) {
                this.log(`Orchestration loop error: ${error.message}`, 'ERROR');
            }

            setTimeout(orchestrate, this.config.orchestratorInterval);
        };

        orchestrate();
    }

    async startAllServices() {
        this.log('Starting all services...');

        // Sort services by priority (lower number = higher priority)
        const sortedServices = Array.from(this.services.entries())
            .sort(([, a], [, b]) => a.config.priority - b.config.priority);

        for (const [serviceName, serviceState] of sortedServices) {
            try {
                await this.startService(serviceName);
                // Small delay between service starts
                await this.sleep(2000);
            } catch (error) {
                this.log(`Failed to start service ${serviceName}: ${error.message}`, 'ERROR');
            }
        }
    }

    async startService(serviceName) {
        const serviceState = this.services.get(serviceName);
        if (!serviceState || serviceState.status === 'running') {
            return;
        }

        this.log(`Starting service: ${serviceName}`);

        try {
            // Check if service file exists
            await fs.access(serviceState.config.path);

            // Start the service process
            const process = spawn('node', [serviceState.config.path], {
                detached: false,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            serviceState.process = process;
            serviceState.resources.pid = process.pid;
            serviceState.status = 'starting';

            // Handle process events
            process.on('exit', (code, signal) => {
                this.handleServiceExit(serviceName, code, signal);
            });

            process.on('error', (error) => {
                this.log(`Service ${serviceName} error: ${error.message}`, 'ERROR');
                this.recordServiceEvent(serviceName, 'error', error.message);
            });

            // Capture service output
            if (process.stdout) {
                process.stdout.on('data', (data) => {
                    this.logServiceOutput(serviceName, data.toString(), 'INFO');
                });
            }

            if (process.stderr) {
                process.stderr.on('data', (data) => {
                    this.logServiceOutput(serviceName, data.toString(), 'ERROR');
                });
            }

            // Wait a bit for the service to start
            await this.sleep(5000);

            // Verify the service is running
            if (process.pid && !process.killed) {
                serviceState.status = 'running';
                serviceState.lastRestart = Date.now();
                this.recordServiceEvent(serviceName, 'started', 'Service started successfully');
                this.log(`Service ${serviceName} started successfully (PID: ${process.pid})`);
            } else {
                throw new Error('Service failed to start');
            }

        } catch (error) {
            serviceState.status = 'failed';
            this.recordServiceEvent(serviceName, 'start_failed', error.message);
            this.log(`Failed to start service ${serviceName}: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async stopService(serviceName) {
        const serviceState = this.services.get(serviceName);
        if (!serviceState || serviceState.status !== 'running') {
            return;
        }

        this.log(`Stopping service: ${serviceName}`);

        try {
            if (serviceState.process) {
                serviceState.process.kill('SIGTERM');

                // Wait for graceful shutdown
                await this.sleep(10000);

                // Force kill if still running
                if (!serviceState.process.killed) {
                    serviceState.process.kill('SIGKILL');
                }
            }

            serviceState.status = 'stopped';
            serviceState.process = null;
            serviceState.resources.pid = null;
            
            this.recordServiceEvent(serviceName, 'stopped', 'Service stopped');
            this.log(`Service ${serviceName} stopped`);

        } catch (error) {
            this.log(`Error stopping service ${serviceName}: ${error.message}`, 'ERROR');
        }
    }

    async restartService(serviceName) {
        const serviceState = this.services.get(serviceName);
        if (!serviceState) {
            return;
        }

        // Check restart policy and limits
        if (!this.shouldRestartService(serviceState)) {
            this.log(`Service ${serviceName} restart denied by policy`);
            return;
        }

        this.log(`Restarting service: ${serviceName}`);

        try {
            await this.stopService(serviceName);
            await this.sleep(serviceState.config.restartDelay);
            await this.startService(serviceName);

            serviceState.restartCount++;
            this.recordServiceEvent(serviceName, 'restarted', `Service restarted (count: ${serviceState.restartCount})`);

        } catch (error) {
            this.log(`Failed to restart service ${serviceName}: ${error.message}`, 'ERROR');
            this.recordServiceEvent(serviceName, 'restart_failed', error.message);
        }
    }

    shouldRestartService(serviceState) {
        // Check max restart limit
        if (serviceState.restartCount >= serviceState.config.maxRestarts) {
            return false;
        }

        // Check restart policy
        switch (serviceState.config.restartPolicy) {
            case 'never':
                return false;
            case 'always':
                return true;
            case 'on-failure':
                return serviceState.status === 'failed';
            default:
                return false;
        }
    }

    handleServiceExit(serviceName, exitCode, signal) {
        const serviceState = this.services.get(serviceName);
        if (!serviceState) return;

        this.log(`Service ${serviceName} exited with code ${exitCode}, signal ${signal}`);

        serviceState.status = exitCode === 0 ? 'stopped' : 'failed';
        serviceState.process = null;
        serviceState.resources.pid = null;

        const eventType = exitCode === 0 ? 'exited' : 'crashed';
        this.recordServiceEvent(serviceName, eventType, `Exit code: ${exitCode}, Signal: ${signal}`);

        // Schedule restart if needed
        if (this.shouldRestartService(serviceState)) {
            this.log(`Scheduling restart for service: ${serviceName}`);
            setTimeout(() => {
                this.restartService(serviceName);
            }, serviceState.config.restartDelay);
        }
    }

    async performHealthChecks() {
        const now = Date.now();

        for (const [serviceName, serviceState] of this.services.entries()) {
            // Check if health check is due
            if (now - serviceState.lastHealthCheck < serviceState.config.healthCheckInterval) {
                continue;
            }

            serviceState.lastHealthCheck = now;

            try {
                const isHealthy = await this.checkServiceHealth(serviceName, serviceState);
                
                if (isHealthy !== serviceState.healthStatus) {
                    const oldStatus = serviceState.healthStatus;
                    serviceState.healthStatus = isHealthy;
                    
                    this.recordServiceEvent(serviceName, 'health_changed', 
                        `Health status changed from ${oldStatus} to ${isHealthy}`);
                    
                    if (!isHealthy && serviceState.status === 'running') {
                        this.log(`Service ${serviceName} health check failed, considering restart`, 'WARNING');
                        await this.restartService(serviceName);
                    }
                }

            } catch (error) {
                this.log(`Health check failed for ${serviceName}: ${error.message}`, 'WARNING');
                serviceState.healthStatus = 'unknown';
            }
        }
    }

    async checkServiceHealth(serviceName, serviceState) {
        if (serviceState.status !== 'running' || !serviceState.resources.pid) {
            return false;
        }

        try {
            // Check if process is still running
            const { stdout } = await execAsync(`ps -p ${serviceState.resources.pid} -o pid=`);
            if (!stdout.trim()) {
                return false;
            }

            // Update resource usage
            await this.updateServiceResources(serviceName, serviceState);

            // Check resource limits
            if (serviceState.resources.cpu > 90 || serviceState.resources.memory > 500) {
                this.log(`Service ${serviceName} using high resources: CPU ${serviceState.resources.cpu}%, Memory ${serviceState.resources.memory}MB`, 'WARNING');
            }

            return true;

        } catch (error) {
            return false;
        }
    }

    async updateServiceResources(serviceName, serviceState) {
        try {
            const { stdout } = await execAsync(`ps -p ${serviceState.resources.pid} -o %cpu,%mem,vsz --no-headers`);
            const parts = stdout.trim().split(/\s+/);
            
            if (parts.length >= 3) {
                serviceState.resources.cpu = parseFloat(parts[0]);
                serviceState.resources.memory = Math.round(parseFloat(parts[2]) / 1024); // Convert KB to MB
            }

        } catch (error) {
            this.log(`Failed to update resources for ${serviceName}: ${error.message}`, 'WARNING');
        }
    }

    async monitorSystemResources() {
        try {
            // Monitor CPU usage
            const { stdout: cpuInfo } = await execAsync("top -l 1 -n 0 | grep 'CPU usage' | awk '{print $3}' | sed 's/%//'");
            this.systemResources.cpu.usage = parseFloat(cpuInfo.trim()) || 0;

            // Monitor memory usage
            const totalMem = require('os').totalmem();
            const freeMem = require('os').freemem();
            this.systemResources.memory.usage = Math.round((totalMem - freeMem) / 1024 / 1024); // MB

            // Monitor disk usage
            const { stdout: diskInfo } = await execAsync("df -h / | tail -1 | awk '{print $5}' | sed 's/%//'");
            this.systemResources.disk.usage = parseInt(diskInfo.trim()) || 0;

            // Check for resource alerts
            this.checkResourceAlerts();

        } catch (error) {
            this.log(`System resource monitoring failed: ${error.message}`, 'WARNING');
        }
    }

    checkResourceAlerts() {
        const { cpu, memory, disk } = this.systemResources;

        if (cpu.usage > cpu.limit) {
            this.log(`HIGH CPU USAGE: ${cpu.usage}% (limit: ${cpu.limit}%)`, 'CRITICAL');
            this.addEventToQueue('system_resource_alert', 'cpu', cpu.usage);
        }

        if (memory.usage > memory.limit) {
            this.log(`HIGH MEMORY USAGE: ${memory.usage}MB (limit: ${memory.limit}MB)`, 'CRITICAL');
            this.addEventToQueue('system_resource_alert', 'memory', memory.usage);
        }

        if (disk.usage > disk.limit) {
            this.log(`HIGH DISK USAGE: ${disk.usage}% (limit: ${disk.limit}%)`, 'CRITICAL');
            this.addEventToQueue('system_resource_alert', 'disk', disk.usage);
        }
    }

    async processServiceEvents() {
        while (this.eventQueue.length > 0) {
            const event = this.eventQueue.shift();
            
            try {
                await this.handleEvent(event);
            } catch (error) {
                this.log(`Error processing event: ${error.message}`, 'ERROR');
            }
        }
    }

    async handleEvent(event) {
        switch (event.type) {
            case 'system_resource_alert':
                await this.handleResourceAlert(event);
                break;
            case 'service_failure':
                await this.handleServiceFailure(event);
                break;
            default:
                this.log(`Unknown event type: ${event.type}`, 'WARNING');
        }
    }

    async handleResourceAlert(event) {
        this.log(`Handling resource alert: ${event.resource} at ${event.value}`, 'WARNING');

        // Find high resource consuming services and consider throttling
        const highResourceServices = Array.from(this.services.entries())
            .filter(([, state]) => {
                if (event.resource === 'cpu') return state.resources.cpu > 50;
                if (event.resource === 'memory') return state.resources.memory > 200;
                return false;
            })
            .sort((a, b) => {
                const aUsage = event.resource === 'cpu' ? a[1].resources.cpu : a[1].resources.memory;
                const bUsage = event.resource === 'cpu' ? b[1].resources.cpu : b[1].resources.memory;
                return bUsage - aUsage;
            });

        // Consider restarting the highest consuming service
        if (highResourceServices.length > 0) {
            const [serviceName] = highResourceServices[0];
            this.log(`Considering restart of high resource service: ${serviceName}`);
            // Could implement intelligent throttling here
        }
    }

    async handleServiceFailure(event) {
        this.log(`Handling service failure: ${event.serviceName}`, 'ERROR');
        // Service restart is already handled in handleServiceExit
    }

    async manageResourceAllocation() {
        // Implement intelligent resource allocation based on service priorities
        const totalServices = Array.from(this.services.values()).filter(s => s.status === 'running').length;
        
        if (totalServices === 0) return;

        // Calculate resource allocation per service based on priority
        const highPriorityServices = Array.from(this.services.values())
            .filter(s => s.status === 'running' && s.config.priority === 1).length;
        
        const mediumPriorityServices = Array.from(this.services.values())
            .filter(s => s.status === 'running' && s.config.priority === 2).length;

        // Log resource allocation strategy
        if (this.systemResources.cpu.usage > 70 || this.systemResources.memory.usage > 800) {
            this.log(`High system resource usage - managing allocation across ${totalServices} services`);
        }
    }

    async handleServiceRestarts() {
        // Check for services that need immediate restart
        for (const [serviceName, serviceState] of this.services.entries()) {
            if (serviceState.status === 'failed' && this.shouldRestartService(serviceState)) {
                const timeSinceLastRestart = Date.now() - serviceState.lastRestart;
                if (timeSinceLastRestart > serviceState.config.restartDelay) {
                    await this.restartService(serviceName);
                }
            }
        }
    }

    async generateStatusReports() {
        // Generate periodic status reports (every 5 minutes)
        if (!this.lastStatusReport || Date.now() - this.lastStatusReport > 300000) {
            await this.generateServiceStatusReport();
            this.lastStatusReport = Date.now();
        }
    }

    async generateServiceStatusReport() {
        const report = {
            timestamp: new Date().toISOString(),
            orchestrator: {
                status: 'running',
                uptime: process.uptime(),
                services: this.services.size
            },
            systemResources: this.systemResources,
            services: {}
        };

        for (const [serviceName, serviceState] of this.services.entries()) {
            report.services[serviceName] = {
                status: serviceState.status,
                healthStatus: serviceState.healthStatus,
                restartCount: serviceState.restartCount,
                lastRestart: serviceState.lastRestart,
                resources: serviceState.resources,
                recentEvents: serviceState.events.slice(-5) // Last 5 events
            };
        }

        const reportPath = '/tmp/orchestrator-status.json';
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
    }

    recordServiceEvent(serviceName, eventType, message) {
        const serviceState = this.services.get(serviceName);
        if (!serviceState) return;

        const event = {
            timestamp: new Date().toISOString(),
            type: eventType,
            message
        };

        serviceState.events.push(event);

        // Keep only last 100 events per service
        if (serviceState.events.length > 100) {
            serviceState.events = serviceState.events.slice(-100);
        }
    }

    addEventToQueue(type, resource, value) {
        this.eventQueue.push({
            timestamp: new Date().toISOString(),
            type,
            resource,
            value
        });
    }

    logServiceOutput(serviceName, output, level) {
        const lines = output.trim().split('\n');
        for (const line of lines) {
            if (line.trim()) {
                this.log(`[${serviceName}] ${line.trim()}`, level);
            }
        }
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;

        try {
            await fs.appendFile(this.config.logging.centralLog, logEntry);
            console.log(`Orchestrator: ${message}`);

            // Rotate log if needed
            const stats = await fs.stat(this.config.logging.centralLog);
            if (stats.size > this.config.logging.maxLogSize) {
                await this.rotateLog();
            }

        } catch (error) {
            console.error(`Failed to write orchestrator log: ${error.message}`);
        }
    }

    async rotateLog() {
        try {
            const logFile = this.config.logging.centralLog;
            const timestamp = new Date().toISOString().replace(/:/g, '-');
            const rotatedFile = `${logFile}.${timestamp}`;

            await fs.rename(logFile, rotatedFile);
            await fs.writeFile(logFile, ''); // Create new empty log

            // Cleanup old rotated logs
            const logDir = path.dirname(logFile);
            const baseName = path.basename(logFile);
            const files = await fs.readdir(logDir);
            
            const rotatedLogs = files
                .filter(file => file.startsWith(baseName) && file !== baseName)
                .sort()
                .reverse();

            // Keep only the configured number of rotated logs
            if (rotatedLogs.length > this.config.logging.logRotationCount) {
                const filesToDelete = rotatedLogs.slice(this.config.logging.logRotationCount);
                for (const file of filesToDelete) {
                    await fs.unlink(path.join(logDir, file));
                }
            }

            this.log('Log rotated successfully');

        } catch (error) {
            console.error(`Log rotation failed: ${error.message}`);
        }
    }

    async shutdown() {
        this.log('Service Orchestrator shutting down...');
        this.isRunning = false;

        // Stop all services in reverse priority order
        const serviceNames = Array.from(this.services.keys())
            .sort((a, b) => this.services.get(b).config.priority - this.services.get(a).config.priority);

        for (const serviceName of serviceNames) {
            try {
                await this.stopService(serviceName);
                this.log(`Stopped service: ${serviceName}`);
            } catch (error) {
                this.log(`Error stopping service ${serviceName}: ${error.message}`, 'ERROR');
            }
        }

        // Generate final status report
        await this.generateServiceStatusReport();

        this.log('Service Orchestrator shutdown completed');
    }
}

// Start the orchestrator
if (require.main === module) {
    const orchestrator = new ServiceOrchestrator();
    orchestrator.start().catch(error => {
        console.error('Failed to start Service Orchestrator:', error);
        process.exit(1);
    });
}

module.exports = ServiceOrchestrator;