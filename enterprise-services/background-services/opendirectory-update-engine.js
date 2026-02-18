#!/usr/bin/env node

/**
 * OpenDirectory MDM Update Distribution Engine
 * Intelligent update distribution with bandwidth optimization
 * Operates invisibly in the background
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class UpdateDistributionEngine {
    constructor() {
        this.config = {
            checkInterval: 2 * 60 * 60 * 1000, // 2 hours
            distributionInterval: 15 * 60 * 1000, // 15 minutes
            maxBandwidthMbps: 10, // 10 Mbps limit
            maxConcurrentDownloads: 3,
            cacheDir: '/tmp/update-cache',
            updateSources: [
                'https://updates.opendirectory.com',
                'https://security-updates.example.com'
            ],
            stagingPolicy: {
                enabled: true,
                stages: [
                    { name: 'canary', percentage: 5, delay: 0 },
                    { name: 'early', percentage: 25, delay: 24 * 60 * 60 * 1000 }, // 24h
                    { name: 'stable', percentage: 70, delay: 72 * 60 * 60 * 1000 }  // 72h
                ]
            },
            peerToPeer: {
                enabled: true,
                maxPeers: 5,
                port: 30056
            },
            rollbackPolicy: {
                enabled: true,
                maxFailureRate: 0.1, // 10%
                monitoringPeriod: 60 * 60 * 1000 // 1 hour
            }
        };

        this.logFile = '/tmp/update-engine.log';
        this.updateQueue = [];
        this.activeDownloads = new Map();
        this.updateCache = new Map();
        this.deviceGroups = new Map();
        this.isRunning = false;
        this.bandwidthMonitor = { used: 0, limit: this.config.maxBandwidthMbps * 1024 * 1024 };
        this.p2pNodes = new Set();
    }

    async start() {
        this.log('Update Distribution Engine starting...');
        this.isRunning = true;

        // Initialize update system
        await this.initializeUpdateSystem();

        // Start update loops
        this.startUpdateLoops();

        // Initialize P2P if enabled
        if (this.config.peerToPeer.enabled) {
            await this.initializePeerToPeer();
        }

        // Set up cleanup on exit
        process.on('SIGTERM', () => this.shutdown());
        process.on('SIGINT', () => this.shutdown());

        // Perform initial update check
        await this.checkForUpdates();

        this.log('Update Distribution Engine started successfully');
    }

    async initializeUpdateSystem() {
        try {
            // Create cache directory
            await fs.mkdir(this.config.cacheDir, { recursive: true });
            await fs.mkdir(path.join(this.config.cacheDir, 'metadata'), { recursive: true });
            await fs.mkdir(path.join(this.config.cacheDir, 'packages'), { recursive: true });
            await fs.mkdir(path.join(this.config.cacheDir, 'staging'), { recursive: true });

            // Load existing update metadata
            await this.loadUpdateMetadata();

            // Initialize device groups
            await this.initializeDeviceGroups();

            this.log('Update system initialized');
        } catch (error) {
            this.log(`Failed to initialize update system: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    startUpdateLoops() {
        // Update checking loop
        setInterval(() => {
            this.checkForUpdates().catch(error => {
                this.log(`Update check failed: ${error.message}`, 'ERROR');
            });
        }, this.config.checkInterval);

        // Update distribution loop
        setInterval(() => {
            this.distributeUpdates().catch(error => {
                this.log(`Update distribution failed: ${error.message}`, 'ERROR');
            });
        }, this.config.distributionInterval);

        // Bandwidth monitoring loop
        setInterval(() => {
            this.monitorBandwidth();
        }, 10000); // Every 10 seconds

        // Cache cleanup loop
        setInterval(() => {
            this.cleanupCache().catch(error => {
                this.log(`Cache cleanup failed: ${error.message}`, 'ERROR');
            });
        }, 6 * 60 * 60 * 1000); // Every 6 hours
    }

    async checkForUpdates() {
        this.log('Checking for updates...');

        try {
            const availableUpdates = [];

            for (const source of this.config.updateSources) {
                try {
                    const updates = await this.fetchUpdatesFromSource(source);
                    availableUpdates.push(...updates);
                } catch (error) {
                    this.log(`Failed to fetch updates from ${source}: ${error.message}`, 'WARNING');
                }
            }

            // Process new updates
            for (const update of availableUpdates) {
                await this.processNewUpdate(update);
            }

            // Check for critical security updates
            const criticalUpdates = availableUpdates.filter(u => u.priority === 'critical');
            if (criticalUpdates.length > 0) {
                this.log(`Found ${criticalUpdates.length} critical security updates`, 'CRITICAL');
                await this.prioritizeCriticalUpdates(criticalUpdates);
            }

            this.log(`Update check completed: ${availableUpdates.length} updates available`);

        } catch (error) {
            this.log(`Update check failed: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async fetchUpdatesFromSource(sourceUrl) {
        // Simulated update source - in real implementation would fetch from actual update servers
        this.log(`Fetching updates from ${sourceUrl}`);

        // Simulate available updates
        const mockUpdates = [
            {
                id: 'opendirectory-core-1.2.3',
                name: 'OpenDirectory Core',
                version: '1.2.3',
                priority: 'normal',
                type: 'security',
                size: 15728640, // 15MB
                checksum: 'sha256:abcd1234...',
                releaseDate: new Date().toISOString(),
                description: 'Security fixes and performance improvements',
                dependencies: [],
                rollbackSupported: true
            },
            {
                id: 'opendirectory-ui-2.1.0',
                name: 'OpenDirectory UI',
                version: '2.1.0',
                priority: 'low',
                type: 'feature',
                size: 5242880, // 5MB
                checksum: 'sha256:efgh5678...',
                releaseDate: new Date().toISOString(),
                description: 'New dashboard features and UI improvements',
                dependencies: ['opendirectory-core-1.2.3'],
                rollbackSupported: true
            }
        ];

        return mockUpdates;
    }

    async processNewUpdate(update) {
        const existingUpdate = this.updateCache.get(update.id);
        
        if (existingUpdate && existingUpdate.version === update.version) {
            return; // Already processed
        }

        this.log(`Processing new update: ${update.name} v${update.version}`);

        // Validate update
        const isValid = await this.validateUpdate(update);
        if (!isValid) {
            this.log(`Update validation failed: ${update.id}`, 'WARNING');
            return;
        }

        // Cache update metadata
        this.updateCache.set(update.id, update);

        // Add to distribution queue
        await this.addToDistributionQueue(update);

        // Save metadata
        await this.saveUpdateMetadata();
    }

    async validateUpdate(update) {
        try {
            // Validate required fields
            const requiredFields = ['id', 'name', 'version', 'size', 'checksum'];
            for (const field of requiredFields) {
                if (!update[field]) {
                    this.log(`Update validation failed: missing ${field}`, 'ERROR');
                    return false;
                }
            }

            // Validate checksum format
            if (!update.checksum.startsWith('sha256:')) {
                this.log(`Update validation failed: invalid checksum format`, 'ERROR');
                return false;
            }

            // Validate size
            if (update.size <= 0 || update.size > 1024 * 1024 * 1024) { // Max 1GB
                this.log(`Update validation failed: invalid size ${update.size}`, 'ERROR');
                return false;
            }

            return true;
        } catch (error) {
            this.log(`Update validation error: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async addToDistributionQueue(update) {
        // Determine staging group based on policy
        const stagingGroup = this.determineUpdateStagingGroup(update);
        
        const queueItem = {
            update,
            stagingGroup,
            addedAt: Date.now(),
            status: 'queued',
            attempts: 0,
            targetDevices: [],
            failedDevices: [],
            successfulDevices: []
        };

        // Select target devices
        queueItem.targetDevices = await this.selectTargetDevices(update, stagingGroup);

        this.updateQueue.push(queueItem);
        this.log(`Update queued: ${update.id} (${queueItem.targetDevices.length} devices)`);
    }

    determineUpdateStagingGroup(update) {
        if (!this.config.stagingPolicy.enabled) {
            return { name: 'immediate', percentage: 100, delay: 0 };
        }

        // Critical security updates go to canary immediately
        if (update.priority === 'critical' && update.type === 'security') {
            return this.config.stagingPolicy.stages[0]; // Canary
        }

        // Normal updates start with canary
        return this.config.stagingPolicy.stages[0];
    }

    async selectTargetDevices(update, stagingGroup) {
        // Simulate device selection - would integrate with actual device management
        const allDevices = Array.from({ length: 100 }, (_, i) => ({
            id: `device-${i + 1}`,
            group: i < 5 ? 'canary' : i < 30 ? 'early' : 'stable',
            online: Math.random() > 0.1, // 90% online
            lastSeen: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000)
        }));

        // Filter by staging group
        let eligibleDevices = allDevices.filter(device => 
            device.online && device.group === stagingGroup.name
        );

        // Apply percentage limit
        const maxDevices = Math.floor(eligibleDevices.length * stagingGroup.percentage / 100);
        eligibleDevices = eligibleDevices.slice(0, maxDevices);

        return eligibleDevices;
    }

    async distributeUpdates() {
        if (this.updateQueue.length === 0) {
            return;
        }

        this.log(`Distributing updates: ${this.updateQueue.length} in queue`);

        const now = Date.now();

        for (const queueItem of this.updateQueue) {
            // Check if ready for distribution based on staging delay
            if (now - queueItem.addedAt < queueItem.stagingGroup.delay) {
                continue;
            }

            // Check bandwidth limits
            if (!this.canStartNewDownload()) {
                this.log('Bandwidth limit reached, postponing distributions');
                break;
            }

            // Process the update
            await this.processUpdateDistribution(queueItem);
        }

        // Clean up completed items
        this.updateQueue = this.updateQueue.filter(item => 
            item.status !== 'completed' && item.status !== 'failed'
        );
    }

    async processUpdateDistribution(queueItem) {
        const { update } = queueItem;

        try {
            queueItem.status = 'distributing';
            this.log(`Starting distribution: ${update.id} to ${queueItem.targetDevices.length} devices`);

            // Download update if not cached
            await this.ensureUpdateCached(update);

            // Distribute to devices
            const results = await this.distributeToDevices(update, queueItem.targetDevices);

            // Process results
            queueItem.successfulDevices = results.successful;
            queueItem.failedDevices = results.failed;

            // Calculate success rate
            const successRate = results.successful.length / queueItem.targetDevices.length;

            if (successRate < (1 - this.config.rollbackPolicy.maxFailureRate)) {
                // High failure rate - initiate rollback
                this.log(`High failure rate (${(1-successRate)*100}%) for ${update.id}, initiating rollback`, 'CRITICAL');
                await this.initiateRollback(update, queueItem);
                queueItem.status = 'rolled_back';
            } else {
                queueItem.status = 'completed';
                this.log(`Update distribution completed: ${update.id} (${results.successful.length}/${queueItem.targetDevices.length} successful)`);

                // If staged deployment, prepare next stage
                if (this.config.stagingPolicy.enabled) {
                    await this.prepareNextStage(update, queueItem);
                }
            }

        } catch (error) {
            this.log(`Update distribution failed: ${update.id} - ${error.message}`, 'ERROR');
            queueItem.status = 'failed';
            queueItem.attempts++;

            // Retry logic
            if (queueItem.attempts < 3) {
                queueItem.status = 'queued';
                this.log(`Retrying update distribution: ${update.id} (attempt ${queueItem.attempts + 1})`);
            }
        }
    }

    async ensureUpdateCached(update) {
        const cachePath = path.join(this.config.cacheDir, 'packages', `${update.id}.pkg`);
        
        try {
            await fs.access(cachePath);
            // Already cached, verify integrity
            const isValid = await this.verifyUpdateIntegrity(cachePath, update.checksum);
            if (isValid) {
                return cachePath;
            }
        } catch (error) {
            // Not cached, need to download
        }

        this.log(`Downloading update: ${update.id}`);
        await this.downloadUpdate(update, cachePath);
        
        return cachePath;
    }

    async downloadUpdate(update, cachePath) {
        // Simulate download - in real implementation would download from update servers
        this.log(`Simulating download: ${update.id} (${this.formatBytes(update.size)})`);

        // Track bandwidth usage
        const downloadId = Date.now().toString();
        this.activeDownloads.set(downloadId, {
            update,
            startTime: Date.now(),
            size: update.size
        });

        try {
            // Simulate download time based on size and bandwidth
            const downloadTimeMs = (update.size / (this.config.maxBandwidthMbps * 1024 * 1024 / 8)) * 1000;
            await this.sleep(Math.min(downloadTimeMs, 5000)); // Max 5 seconds for simulation

            // Create mock update file
            const mockData = Buffer.alloc(Math.min(update.size, 1024), 'update data');
            await fs.writeFile(cachePath, mockData);

            // Update bandwidth tracking
            this.bandwidthMonitor.used += update.size;
            
            this.log(`Download completed: ${update.id}`);

        } finally {
            this.activeDownloads.delete(downloadId);
        }
    }

    async verifyUpdateIntegrity(filePath, expectedChecksum) {
        try {
            const fileData = await fs.readFile(filePath);
            const hash = crypto.createHash('sha256');
            hash.update(fileData);
            const actualChecksum = 'sha256:' + hash.digest('hex');
            
            return actualChecksum === expectedChecksum;
        } catch (error) {
            this.log(`Integrity verification failed: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async distributeToDevices(update, devices) {
        const results = { successful: [], failed: [] };
        const maxConcurrent = Math.min(this.config.maxConcurrentDownloads, devices.length);
        
        // Process devices in batches
        for (let i = 0; i < devices.length; i += maxConcurrent) {
            const batch = devices.slice(i, i + maxConcurrent);
            const batchPromises = batch.map(device => this.distributeToDevice(update, device));
            
            const batchResults = await Promise.allSettled(batchPromises);
            
            batchResults.forEach((result, index) => {
                const device = batch[index];
                if (result.status === 'fulfilled' && result.value) {
                    results.successful.push(device);
                } else {
                    results.failed.push({
                        device,
                        error: result.reason?.message || 'Unknown error'
                    });
                }
            });

            // Rate limiting between batches
            if (i + maxConcurrent < devices.length) {
                await this.sleep(1000); // 1 second between batches
            }
        }

        return results;
    }

    async distributeToDevice(update, device) {
        this.log(`Distributing to device: ${device.id}`);

        try {
            // Check if P2P distribution is possible
            if (this.config.peerToPeer.enabled && this.p2pNodes.size > 0) {
                const success = await this.tryP2PDistribution(update, device);
                if (success) {
                    this.log(`P2P distribution successful: ${device.id}`);
                    return true;
                }
            }

            // Fallback to direct distribution
            return await this.directDistribution(update, device);

        } catch (error) {
            this.log(`Distribution failed for device ${device.id}: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async tryP2PDistribution(update, device) {
        // Simulate P2P distribution attempt
        const peerNodes = Array.from(this.p2pNodes);
        if (peerNodes.length === 0) {
            return false;
        }

        // Select random peer
        const peer = peerNodes[Math.floor(Math.random() * peerNodes.length)];
        
        try {
            // Simulate P2P transfer
            this.log(`Attempting P2P distribution via peer ${peer}`);
            
            // 80% success rate for P2P
            if (Math.random() < 0.8) {
                await this.sleep(500); // Simulate P2P transfer time
                return true;
            }
            
            return false;
        } catch (error) {
            this.log(`P2P distribution failed: ${error.message}`, 'WARNING');
            return false;
        }
    }

    async directDistribution(update, device) {
        // Simulate direct distribution to device
        this.log(`Direct distribution to device: ${device.id}`);
        
        // Simulate network transfer time
        const transferTime = Math.random() * 2000 + 500; // 500ms to 2.5s
        await this.sleep(transferTime);

        // 95% success rate for direct distribution
        if (Math.random() < 0.95) {
            return true;
        }

        throw new Error('Distribution failed');
    }

    async initiateRollback(update, queueItem) {
        this.log(`Initiating rollback for update: ${update.id}`, 'CRITICAL');

        if (!update.rollbackSupported) {
            this.log(`Rollback not supported for update: ${update.id}`, 'ERROR');
            return;
        }

        try {
            // Roll back successful deployments
            for (const device of queueItem.successfulDevices) {
                await this.rollbackDevice(update, device);
            }

            // Record rollback event
            await this.recordRollbackEvent(update, queueItem);

            this.log(`Rollback completed for update: ${update.id}`);

        } catch (error) {
            this.log(`Rollback failed for update ${update.id}: ${error.message}`, 'ERROR');
        }
    }

    async rollbackDevice(update, device) {
        this.log(`Rolling back device: ${device.id}`);
        
        // Simulate rollback process
        await this.sleep(1000);
        
        // 98% rollback success rate
        if (Math.random() < 0.98) {
            this.log(`Rollback successful for device: ${device.id}`);
        } else {
            throw new Error(`Rollback failed for device: ${device.id}`);
        }
    }

    async prepareNextStage(update, completedStage) {
        const currentStageIndex = this.config.stagingPolicy.stages.findIndex(
            stage => stage.name === completedStage.stagingGroup.name
        );

        if (currentStageIndex >= this.config.stagingPolicy.stages.length - 1) {
            this.log(`All staging stages completed for update: ${update.id}`);
            return;
        }

        const nextStage = this.config.stagingPolicy.stages[currentStageIndex + 1];
        this.log(`Preparing next stage for update: ${update.id} -> ${nextStage.name}`);

        // Create new queue item for next stage
        const nextQueueItem = {
            update,
            stagingGroup: nextStage,
            addedAt: Date.now(),
            status: 'queued',
            attempts: 0,
            targetDevices: await this.selectTargetDevices(update, nextStage),
            failedDevices: [],
            successfulDevices: []
        };

        this.updateQueue.push(nextQueueItem);
    }

    async initializePeerToPeer() {
        try {
            this.log(`Initializing P2P network on port ${this.config.peerToPeer.port}`);

            // Simulate P2P node discovery
            const mockPeers = Array.from({ length: 3 }, (_, i) => `peer-${i + 1}`);
            mockPeers.forEach(peer => this.p2pNodes.add(peer));

            this.log(`P2P network initialized with ${this.p2pNodes.size} peers`);

        } catch (error) {
            this.log(`P2P initialization failed: ${error.message}`, 'WARNING');
        }
    }

    canStartNewDownload() {
        // Check concurrent download limit
        if (this.activeDownloads.size >= this.config.maxConcurrentDownloads) {
            return false;
        }

        // Check bandwidth limit (simplified)
        return this.bandwidthMonitor.used < this.bandwidthMonitor.limit;
    }

    monitorBandwidth() {
        // Reset bandwidth counter every minute
        const now = Date.now();
        if (!this.lastBandwidthReset || now - this.lastBandwidthReset > 60000) {
            this.bandwidthMonitor.used = 0;
            this.lastBandwidthReset = now;
        }

        // Log bandwidth usage if high
        const usagePercent = (this.bandwidthMonitor.used / this.bandwidthMonitor.limit) * 100;
        if (usagePercent > 80) {
            this.log(`High bandwidth usage: ${usagePercent.toFixed(1)}%`);
        }
    }

    async cleanupCache() {
        this.log('Cleaning up update cache...');

        try {
            const cacheFiles = await fs.readdir(path.join(this.config.cacheDir, 'packages'));
            const now = Date.now();
            const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days

            let cleanedCount = 0;

            for (const file of cacheFiles) {
                const filePath = path.join(this.config.cacheDir, 'packages', file);
                const stat = await fs.stat(filePath);

                if (now - stat.mtime.getTime() > maxAge) {
                    await fs.unlink(filePath);
                    cleanedCount++;
                }
            }

            this.log(`Cache cleanup completed: ${cleanedCount} files removed`);

        } catch (error) {
            this.log(`Cache cleanup failed: ${error.message}`, 'ERROR');
        }
    }

    async prioritizeCriticalUpdates(criticalUpdates) {
        // Move critical updates to front of queue
        for (const update of criticalUpdates) {
            const existingIndex = this.updateQueue.findIndex(item => item.update.id === update.id);
            
            if (existingIndex > -1) {
                // Move to front
                const item = this.updateQueue.splice(existingIndex, 1)[0];
                this.updateQueue.unshift(item);
            } else {
                // Add as new high priority item
                await this.processNewUpdate(update);
                const newItem = this.updateQueue[this.updateQueue.length - 1];
                this.updateQueue.pop();
                this.updateQueue.unshift(newItem);
            }
        }
    }

    async initializeDeviceGroups() {
        // Initialize device groups for staged deployments
        this.deviceGroups.set('canary', { devices: [], percentage: 5 });
        this.deviceGroups.set('early', { devices: [], percentage: 25 });
        this.deviceGroups.set('stable', { devices: [], percentage: 70 });

        this.log('Device groups initialized');
    }

    async recordRollbackEvent(update, queueItem) {
        const rollbackEvent = {
            timestamp: new Date().toISOString(),
            updateId: update.id,
            reason: 'High failure rate',
            affectedDevices: queueItem.successfulDevices.length,
            failureRate: queueItem.failedDevices.length / queueItem.targetDevices.length
        };

        const rollbackLogPath = '/tmp/update-rollbacks.log';
        await fs.appendFile(rollbackLogPath, JSON.stringify(rollbackEvent) + '\n');
    }

    async loadUpdateMetadata() {
        try {
            const metadataPath = path.join(this.config.cacheDir, 'metadata', 'updates.json');
            const data = await fs.readFile(metadataPath, 'utf8');
            const metadata = JSON.parse(data);

            // Restore update cache
            for (const [id, update] of Object.entries(metadata.updates || {})) {
                this.updateCache.set(id, update);
            }

            this.log(`Loaded metadata for ${this.updateCache.size} updates`);
        } catch (error) {
            this.log('No existing update metadata found');
        }
    }

    async saveUpdateMetadata() {
        try {
            const metadata = {
                timestamp: new Date().toISOString(),
                updates: Object.fromEntries(this.updateCache)
            };

            const metadataPath = path.join(this.config.cacheDir, 'metadata', 'updates.json');
            await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));

        } catch (error) {
            this.log(`Failed to save update metadata: ${error.message}`, 'ERROR');
        }
    }

    formatBytes(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${Math.round(bytes / Math.pow(1024, i) * 100) / 100} ${sizes[i]}`;
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;

        try {
            await fs.appendFile(this.logFile, logEntry);
            console.log(`Update Engine: ${message}`);
        } catch (error) {
            console.error(`Failed to write log: ${error.message}`);
        }
    }

    async shutdown() {
        this.log('Update Distribution Engine shutting down...');
        this.isRunning = false;
        
        // Save current state
        await this.saveUpdateMetadata();
    }
}

// Start the service
if (require.main === module) {
    const service = new UpdateDistributionEngine();
    service.start().catch(error => {
        console.error('Failed to start Update Distribution Engine:', error);
        process.exit(1);
    });
}

module.exports = UpdateDistributionEngine;