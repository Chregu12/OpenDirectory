#!/usr/bin/env node

/**
 * OpenDirectory MDM Health Check & Auto-Healing Service
 * Continuous monitoring and automatic problem resolution
 * Operates invisibly in the background
 */

const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class HealthMonitorService {
    constructor() {
        this.config = {
            checkInterval: 30000, // 30 seconds
            criticalDiskThreshold: 90, // 90%
            warningDiskThreshold: 80, // 80%
            memoryLeakThreshold: 85, // 85%
            maxLogSize: 100 * 1024 * 1024, // 100MB
            maxLogFiles: 10,
            services: [
                'opendirectory-mdm',
                'opendirectory-backend',
                'opendirectory-policy-engine'
            ],
            networkTargets: [
                '192.168.1.1',
                '8.8.8.8',
                '1.1.1.1'
            ]
        };

        this.logFile = '/tmp/health-monitor.log';
        this.statusFile = '/tmp/health-status.json';
        this.isRunning = false;
        this.healingActions = new Map();
        this.lastMemoryUsage = new Map();
    }

    async start() {
        this.log('Health Monitor Service starting...');
        this.isRunning = true;

        // Initialize healing action tracking
        this.initializeHealingTracking();

        // Start monitoring loop
        this.monitoringLoop();

        // Set up cleanup on exit
        process.on('SIGTERM', () => this.shutdown());
        process.on('SIGINT', () => this.shutdown());

        this.log('Health Monitor Service started successfully');
    }

    async monitoringLoop() {
        while (this.isRunning) {
            try {
                await this.performHealthChecks();
                await this.sleep(this.config.checkInterval);
            } catch (error) {
                this.log(`Error in monitoring loop: ${error.message}`, 'ERROR');
                await this.sleep(5000); // Wait 5 seconds on error
            }
        }
    }

    async performHealthChecks() {
        const status = {
            timestamp: new Date().toISOString(),
            checks: {}
        };

        // System resource checks
        status.checks.disk = await this.checkDiskSpace();
        status.checks.memory = await this.checkMemoryUsage();
        status.checks.cpu = await this.checkCPUUsage();

        // Service checks
        status.checks.services = await this.checkServices();

        // Network connectivity checks
        status.checks.network = await this.checkNetworkConnectivity();

        // Application checks
        status.checks.applications = await this.checkApplications();

        // Log management
        await this.manageLogFiles();

        // Process memory leak detection
        await this.detectMemoryLeaks();

        // Save status
        await this.saveStatus(status);

        // Perform auto-healing if needed
        await this.performAutoHealing(status);
    }

    async checkDiskSpace() {
        try {
            const { stdout } = await execAsync("df -h / | tail -1 | awk '{print $5}' | sed 's/%//'");
            const usage = parseInt(stdout.trim());

            if (usage >= this.config.criticalDiskThreshold) {
                this.log(`Critical disk usage: ${usage}%`, 'CRITICAL');
                await this.healDiskSpace();
                return { status: 'critical', usage, message: 'Critical disk usage detected and healing initiated' };
            } else if (usage >= this.config.warningDiskThreshold) {
                this.log(`High disk usage: ${usage}%`, 'WARNING');
                return { status: 'warning', usage, message: 'High disk usage detected' };
            }

            return { status: 'healthy', usage, message: 'Disk space normal' };
        } catch (error) {
            this.log(`Disk space check failed: ${error.message}`, 'ERROR');
            return { status: 'error', message: error.message };
        }
    }

    async checkMemoryUsage() {
        try {
            const totalMem = os.totalmem();
            const freeMem = os.freemem();
            const usage = ((totalMem - freeMem) / totalMem) * 100;

            if (usage >= this.config.memoryLeakThreshold) {
                this.log(`High memory usage: ${usage.toFixed(2)}%`, 'WARNING');
                await this.healMemoryIssues();
                return { status: 'warning', usage: usage.toFixed(2), message: 'High memory usage detected' };
            }

            return { status: 'healthy', usage: usage.toFixed(2), message: 'Memory usage normal' };
        } catch (error) {
            this.log(`Memory check failed: ${error.message}`, 'ERROR');
            return { status: 'error', message: error.message };
        }
    }

    async checkCPUUsage() {
        try {
            const { stdout } = await execAsync("top -l 1 -n 0 | grep 'CPU usage' | awk '{print $3}' | sed 's/%//'");
            const usage = parseFloat(stdout.trim());

            if (usage >= 90) {
                this.log(`High CPU usage: ${usage}%`, 'WARNING');
                return { status: 'warning', usage, message: 'High CPU usage detected' };
            }

            return { status: 'healthy', usage, message: 'CPU usage normal' };
        } catch (error) {
            return { status: 'healthy', usage: 0, message: 'CPU check not available on this system' };
        }
    }

    async checkServices() {
        const results = {};

        for (const service of this.config.services) {
            try {
                const isRunning = await this.isServiceRunning(service);
                if (!isRunning) {
                    this.log(`Service ${service} is not running`, 'CRITICAL');
                    await this.healService(service);
                    results[service] = { status: 'critical', message: 'Service down, restart initiated' };
                } else {
                    results[service] = { status: 'healthy', message: 'Service running' };
                }
            } catch (error) {
                this.log(`Service check failed for ${service}: ${error.message}`, 'ERROR');
                results[service] = { status: 'error', message: error.message };
            }
        }

        return results;
    }

    async checkNetworkConnectivity() {
        const results = {};

        for (const target of this.config.networkTargets) {
            try {
                const { stdout } = await execAsync(`ping -c 1 -W 5000 ${target}`);
                if (stdout.includes('1 packets transmitted, 1 received')) {
                    results[target] = { status: 'healthy', message: 'Network reachable' };
                } else {
                    results[target] = { status: 'warning', message: 'Network unreachable' };
                }
            } catch (error) {
                this.log(`Network connectivity failed to ${target}`, 'WARNING');
                results[target] = { status: 'warning', message: 'Network unreachable' };
                await this.healNetworkConnectivity();
            }
        }

        return results;
    }

    async checkApplications() {
        const results = {};

        try {
            // Check OpenDirectory MDM UI availability
            const response = await this.checkHttpEndpoint('http://192.168.1.223:30055/health');
            results.mdm_ui = response;

            // Check for application crashes
            const crashes = await this.detectApplicationCrashes();
            results.crashes = crashes;

        } catch (error) {
            this.log(`Application check failed: ${error.message}`, 'ERROR');
            results.error = { status: 'error', message: error.message };
        }

        return results;
    }

    async checkHttpEndpoint(url) {
        return new Promise((resolve) => {
            const http = require('http');
            const request = http.get(url, { timeout: 5000 }, (res) => {
                if (res.statusCode === 200) {
                    resolve({ status: 'healthy', message: 'Endpoint accessible' });
                } else {
                    resolve({ status: 'warning', message: `HTTP ${res.statusCode}` });
                }
            });

            request.on('error', () => {
                resolve({ status: 'critical', message: 'Endpoint unreachable' });
            });

            request.on('timeout', () => {
                resolve({ status: 'warning', message: 'Endpoint timeout' });
                request.destroy();
            });
        });
    }

    async detectApplicationCrashes() {
        try {
            // Check system logs for crashes
            const { stdout } = await execAsync("grep -i 'crash\\|segfault\\|core dump' /var/log/system.log | tail -10");
            const crashes = stdout.trim().split('\n').filter(line => line.length > 0);

            if (crashes.length > 0) {
                this.log(`Application crashes detected: ${crashes.length}`, 'WARNING');
                return { status: 'warning', count: crashes.length, message: 'Application crashes detected' };
            }

            return { status: 'healthy', count: 0, message: 'No crashes detected' };
        } catch (error) {
            return { status: 'healthy', count: 0, message: 'Crash detection not available' };
        }
    }

    async detectMemoryLeaks() {
        try {
            const { stdout } = await execAsync("ps aux | awk '{print $2, $4, $11}' | grep -E '(node|opendirectory)' | sort -nrk 2");
            const processes = stdout.trim().split('\n');

            for (const processLine of processes) {
                const [pid, memUsage, command] = processLine.split(' ', 3);
                const currentUsage = parseFloat(memUsage);
                const lastUsage = this.lastMemoryUsage.get(pid) || 0;

                if (currentUsage > 10 && currentUsage > lastUsage * 1.5) {
                    this.log(`Potential memory leak in PID ${pid} (${command}): ${currentUsage}%`, 'WARNING');
                }

                this.lastMemoryUsage.set(pid, currentUsage);
            }
        } catch (error) {
            this.log(`Memory leak detection failed: ${error.message}`, 'ERROR');
        }
    }

    async manageLogFiles() {
        try {
            const logDirs = ['/var/log', '/tmp', '/Users/christianheusser/Developer/opendirectory/logs'];

            for (const logDir of logDirs) {
                try {
                    const files = await fs.readdir(logDir);
                    const logFiles = files.filter(file => file.endsWith('.log'));

                    for (const logFile of logFiles) {
                        const filePath = path.join(logDir, logFile);
                        const stat = await fs.stat(filePath);

                        if (stat.size > this.config.maxLogSize) {
                            await this.rotateLogFile(filePath);
                            this.log(`Rotated large log file: ${filePath}`);
                        }
                    }
                } catch (error) {
                    // Skip directories we can't access
                }
            }
        } catch (error) {
            this.log(`Log management failed: ${error.message}`, 'ERROR');
        }
    }

    async healDiskSpace() {
        try {
            this.log('Initiating disk space healing...', 'INFO');

            // Clean temporary files
            await execAsync('find /tmp -type f -name "*.tmp" -mtime +7 -delete');
            await execAsync('find /tmp -type f -name "*.log" -mtime +30 -delete');

            // Clean old log files
            await execAsync('find /var/log -type f -name "*.log.*" -mtime +30 -delete');

            // Empty trash
            await execAsync('rm -rf ~/.Trash/*');

            // Clean package caches
            await execAsync('brew cleanup 2>/dev/null || true');
            await execAsync('npm cache clean --force 2>/dev/null || true');

            this.log('Disk space healing completed', 'INFO');
        } catch (error) {
            this.log(`Disk space healing failed: ${error.message}`, 'ERROR');
        }
    }

    async healMemoryIssues() {
        try {
            this.log('Initiating memory healing...', 'INFO');

            // Find and restart high memory usage processes
            const { stdout } = await execAsync("ps aux | sort -nrk 4 | head -5");
            const processes = stdout.trim().split('\n').slice(1);

            for (const processLine of processes) {
                const parts = processLine.split(/\s+/);
                const pid = parts[1];
                const memUsage = parseFloat(parts[3]);

                if (memUsage > 20 && parts[10] && parts[10].includes('node')) {
                    this.log(`Restarting high memory process PID ${pid} (${memUsage}%)`, 'INFO');
                    try {
                        await execAsync(`kill -TERM ${pid}`);
                        await this.sleep(5000);
                    } catch (error) {
                        // Process might have already exited
                    }
                }
            }

            // Force garbage collection in Node.js processes
            await execAsync("kill -USR1 $(pgrep -f 'node.*opendirectory') 2>/dev/null || true");

            this.log('Memory healing completed', 'INFO');
        } catch (error) {
            this.log(`Memory healing failed: ${error.message}`, 'ERROR');
        }
    }

    async healService(serviceName) {
        try {
            this.log(`Healing service: ${serviceName}`, 'INFO');

            // Try to restart the service
            if (serviceName.includes('opendirectory')) {
                // Custom restart logic for OpenDirectory services
                await this.restartOpenDirectoryService(serviceName);
            } else {
                // Standard service restart
                await execAsync(`systemctl restart ${serviceName} 2>/dev/null || launchctl load -w /Library/LaunchDaemons/${serviceName}.plist 2>/dev/null || true`);
            }

            // Wait and verify
            await this.sleep(10000);
            const isRunning = await this.isServiceRunning(serviceName);

            if (isRunning) {
                this.log(`Service ${serviceName} restarted successfully`, 'INFO');
            } else {
                this.log(`Service ${serviceName} restart failed`, 'ERROR');
            }
        } catch (error) {
            this.log(`Service healing failed for ${serviceName}: ${error.message}`, 'ERROR');
        }
    }

    async healNetworkConnectivity() {
        try {
            this.log('Healing network connectivity...', 'INFO');

            // Reset network interface
            await execAsync('sudo route -n flush 2>/dev/null || true');
            await execAsync('sudo dscacheutil -flushcache 2>/dev/null || true');

            // Restart network services
            await execAsync('sudo launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist 2>/dev/null || true');
            await this.sleep(2000);
            await execAsync('sudo launchctl load /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist 2>/dev/null || true');

            this.log('Network healing completed', 'INFO');
        } catch (error) {
            this.log(`Network healing failed: ${error.message}`, 'ERROR');
        }
    }

    async restartOpenDirectoryService(serviceName) {
        try {
            // Find process by name
            const { stdout } = await execAsync(`pgrep -f "${serviceName}"`);
            const pids = stdout.trim().split('\n').filter(pid => pid.length > 0);

            for (const pid of pids) {
                await execAsync(`kill -TERM ${pid}`);
            }

            // Wait for graceful shutdown
            await this.sleep(5000);

            // Force kill if still running
            for (const pid of pids) {
                try {
                    await execAsync(`kill -9 ${pid}`);
                } catch (error) {
                    // Process already exited
                }
            }

            // TODO: Add service restart logic based on how OpenDirectory services are configured
            this.log(`OpenDirectory service ${serviceName} stopped, manual restart may be required`, 'INFO');

        } catch (error) {
            this.log(`Failed to restart OpenDirectory service ${serviceName}: ${error.message}`, 'ERROR');
        }
    }

    async isServiceRunning(serviceName) {
        try {
            const { stdout } = await execAsync(`pgrep -f "${serviceName}"`);
            return stdout.trim().length > 0;
        } catch (error) {
            return false;
        }
    }

    async rotateLogFile(filePath) {
        try {
            const timestamp = new Date().toISOString().replace(/:/g, '-');
            const rotatedPath = `${filePath}.${timestamp}`;

            await fs.rename(filePath, rotatedPath);
            await fs.writeFile(filePath, ''); // Create new empty log file

            // Compress old log
            await execAsync(`gzip "${rotatedPath}" 2>/dev/null || true`);

            // Clean old rotated logs
            const dir = path.dirname(filePath);
            const baseName = path.basename(filePath);
            const files = await fs.readdir(dir);
            const rotatedFiles = files
                .filter(file => file.startsWith(baseName) && file.includes('.20'))
                .sort()
                .reverse();

            // Keep only last N files
            if (rotatedFiles.length > this.config.maxLogFiles) {
                const filesToDelete = rotatedFiles.slice(this.config.maxLogFiles);
                for (const file of filesToDelete) {
                    await fs.unlink(path.join(dir, file));
                }
            }
        } catch (error) {
            this.log(`Log rotation failed for ${filePath}: ${error.message}`, 'ERROR');
        }
    }

    async performAutoHealing(status) {
        const criticalIssues = this.identifyCriticalIssues(status);

        for (const issue of criticalIssues) {
            const actionKey = `${issue.type}-${issue.target}`;
            const lastAction = this.healingActions.get(actionKey);
            const now = Date.now();

            // Prevent too frequent healing actions (min 5 minutes)
            if (lastAction && (now - lastAction) < 300000) {
                continue;
            }

            this.log(`Performing auto-healing for: ${issue.description}`, 'INFO');
            
            try {
                await issue.action();
                this.healingActions.set(actionKey, now);
            } catch (error) {
                this.log(`Auto-healing failed for ${issue.description}: ${error.message}`, 'ERROR');
            }
        }
    }

    identifyCriticalIssues(status) {
        const issues = [];

        // Disk space issues
        if (status.checks.disk && status.checks.disk.status === 'critical') {
            issues.push({
                type: 'disk',
                target: 'system',
                description: 'Critical disk space',
                action: () => this.healDiskSpace()
            });
        }

        // Service issues
        if (status.checks.services) {
            Object.entries(status.checks.services).forEach(([service, check]) => {
                if (check.status === 'critical') {
                    issues.push({
                        type: 'service',
                        target: service,
                        description: `Service ${service} down`,
                        action: () => this.healService(service)
                    });
                }
            });
        }

        // Network issues
        if (status.checks.network) {
            const failedTargets = Object.entries(status.checks.network)
                .filter(([_, check]) => check.status === 'warning')
                .length;
            
            if (failedTargets >= 2) {
                issues.push({
                    type: 'network',
                    target: 'connectivity',
                    description: 'Network connectivity issues',
                    action: () => this.healNetworkConnectivity()
                });
            }
        }

        return issues;
    }

    initializeHealingTracking() {
        this.healingActions.clear();
    }

    async saveStatus(status) {
        try {
            await fs.writeFile(this.statusFile, JSON.stringify(status, null, 2));
        } catch (error) {
            this.log(`Failed to save status: ${error.message}`, 'ERROR');
        }
    }

    async log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;

        try {
            await fs.appendFile(this.logFile, logEntry);
            console.log(`Health Monitor: ${message}`);
        } catch (error) {
            console.error(`Failed to write log: ${error.message}`);
        }
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async shutdown() {
        this.log('Health Monitor Service shutting down...');
        this.isRunning = false;
    }
}

// Start the service
if (require.main === module) {
    const service = new HealthMonitorService();
    service.start().catch(error => {
        console.error('Failed to start Health Monitor Service:', error);
        process.exit(1);
    });
}

module.exports = HealthMonitorService;