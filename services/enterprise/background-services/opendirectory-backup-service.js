#!/usr/bin/env node

/**
 * OpenDirectory MDM Backup & Recovery Service
 * Automated backup and point-in-time recovery capabilities
 * Operates invisibly in the background
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const zlib = require('zlib');

class BackupService {
    constructor() {
        this.config = {
            backupInterval: 24 * 60 * 60 * 1000, // 24 hours
            incrementalInterval: 4 * 60 * 60 * 1000, // 4 hours
            retentionDays: 30,
            maxBackupSize: 1024 * 1024 * 1024, // 1GB
            encryptionKey: this.generateEncryptionKey(),
            backupPaths: [
                '/Users/christianheusser/Developer/opendirectory',
                '/tmp/opendirectory-*',
                '/var/lib/opendirectory',
                '/etc/opendirectory'
            ],
            excludePatterns: [
                '*.tmp',
                '*.log',
                'node_modules',
                '.git',
                'cache',
                'temp'
            ]
        };

        this.backupDir = '/tmp/opendirectory-backups';
        this.metadataFile = path.join(this.backupDir, 'backup-metadata.json');
        this.logFile = '/tmp/backup-service.log';
        this.isRunning = false;
        this.backupHistory = [];
    }

    async start() {
        this.log('Backup Service starting...');
        this.isRunning = true;

        // Initialize backup directory
        await this.initializeBackupDirectory();

        // Load existing metadata
        await this.loadMetadata();

        // Start backup scheduler
        this.scheduleBackups();

        // Set up cleanup on exit
        process.on('SIGTERM', () => this.shutdown());
        process.on('SIGINT', () => this.shutdown());

        // Perform initial backup check
        await this.checkAndPerformBackup();

        this.log('Backup Service started successfully');
    }

    async initializeBackupDirectory() {
        try {
            await fs.mkdir(this.backupDir, { recursive: true });
            await fs.mkdir(path.join(this.backupDir, 'full'), { recursive: true });
            await fs.mkdir(path.join(this.backupDir, 'incremental'), { recursive: true });
            await fs.mkdir(path.join(this.backupDir, 'snapshots'), { recursive: true });
            await fs.mkdir(path.join(this.backupDir, 'configs'), { recursive: true });
            await fs.mkdir(path.join(this.backupDir, 'policies'), { recursive: true });
            await fs.mkdir(path.join(this.backupDir, 'users'), { recursive: true });
        } catch (error) {
            this.log(`Failed to initialize backup directory: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async loadMetadata() {
        try {
            const data = await fs.readFile(this.metadataFile, 'utf8');
            const metadata = JSON.parse(data);
            this.backupHistory = metadata.backupHistory || [];
            this.log(`Loaded ${this.backupHistory.length} backup records`);
        } catch (error) {
            this.log('No existing metadata found, starting fresh');
            this.backupHistory = [];
        }
    }

    async saveMetadata() {
        const metadata = {
            lastUpdate: new Date().toISOString(),
            backupHistory: this.backupHistory,
            config: this.config
        };

        try {
            await fs.writeFile(this.metadataFile, JSON.stringify(metadata, null, 2));
        } catch (error) {
            this.log(`Failed to save metadata: ${error.message}`, 'ERROR');
        }
    }

    scheduleBackups() {
        // Full backup every 24 hours
        setInterval(() => {
            this.performFullBackup().catch(error => {
                this.log(`Scheduled full backup failed: ${error.message}`, 'ERROR');
            });
        }, this.config.backupInterval);

        // Incremental backup every 4 hours
        setInterval(() => {
            this.performIncrementalBackup().catch(error => {
                this.log(`Scheduled incremental backup failed: ${error.message}`, 'ERROR');
            });
        }, this.config.incrementalInterval);

        // Cleanup old backups daily
        setInterval(() => {
            this.cleanupOldBackups().catch(error => {
                this.log(`Backup cleanup failed: ${error.message}`, 'ERROR');
            });
        }, 24 * 60 * 60 * 1000);
    }

    async checkAndPerformBackup() {
        const lastFullBackup = this.backupHistory
            .filter(b => b.type === 'full')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

        if (!lastFullBackup || this.isBackupStale(lastFullBackup, this.config.backupInterval)) {
            this.log('No recent full backup found, performing full backup');
            await this.performFullBackup();
        }

        const lastIncremental = this.backupHistory
            .filter(b => b.type === 'incremental')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

        if (!lastIncremental || this.isBackupStale(lastIncremental, this.config.incrementalInterval)) {
            this.log('No recent incremental backup found, performing incremental backup');
            await this.performIncrementalBackup();
        }
    }

    async performFullBackup() {
        this.log('Starting full backup...');
        const backupId = this.generateBackupId('full');
        const backupPath = path.join(this.backupDir, 'full', `${backupId}.tar.gz.enc`);

        try {
            // Create device state snapshot
            const deviceSnapshot = await this.createDeviceSnapshot();

            // Backup configurations
            const configBackup = await this.backupConfigurations();

            // Backup policies
            const policyBackup = await this.backupPolicies();

            // Backup user data
            const userBackup = await this.backupUserData();

            // Create comprehensive backup archive
            const manifest = {
                id: backupId,
                timestamp: new Date().toISOString(),
                type: 'full',
                deviceSnapshot,
                configBackup,
                policyBackup,
                userBackup,
                files: []
            };

            // Backup application files
            for (const backupPath of this.config.backupPaths) {
                try {
                    const files = await this.backupPath(backupPath, backupId);
                    manifest.files.push(...files);
                } catch (error) {
                    this.log(`Failed to backup path ${backupPath}: ${error.message}`, 'WARNING');
                }
            }

            // Create encrypted archive
            await this.createEncryptedArchive(backupPath, manifest, backupId);

            // Record backup
            const backupRecord = {
                id: backupId,
                type: 'full',
                timestamp: new Date().toISOString(),
                path: backupPath,
                size: (await fs.stat(backupPath)).size,
                manifest: manifest,
                checksum: await this.calculateChecksum(backupPath)
            };

            this.backupHistory.push(backupRecord);
            await this.saveMetadata();

            this.log(`Full backup completed: ${backupId} (${this.formatSize(backupRecord.size)})`);
            return backupRecord;

        } catch (error) {
            this.log(`Full backup failed: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async performIncrementalBackup() {
        this.log('Starting incremental backup...');
        const backupId = this.generateBackupId('incremental');
        const backupPath = path.join(this.backupDir, 'incremental', `${backupId}.tar.gz.enc`);

        try {
            const lastFullBackup = this.backupHistory
                .filter(b => b.type === 'full')
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

            if (!lastFullBackup) {
                this.log('No full backup found, performing full backup instead');
                return await this.performFullBackup();
            }

            // Find changes since last backup
            const changedFiles = await this.findChangedFiles(lastFullBackup.timestamp);

            if (changedFiles.length === 0) {
                this.log('No changes detected, skipping incremental backup');
                return null;
            }

            const manifest = {
                id: backupId,
                timestamp: new Date().toISOString(),
                type: 'incremental',
                baseBackup: lastFullBackup.id,
                changedFiles
            };

            // Create incremental archive
            await this.createIncrementalArchive(backupPath, manifest, changedFiles);

            const backupRecord = {
                id: backupId,
                type: 'incremental',
                timestamp: new Date().toISOString(),
                path: backupPath,
                size: (await fs.stat(backupPath)).size,
                manifest: manifest,
                checksum: await this.calculateChecksum(backupPath),
                baseBackup: lastFullBackup.id
            };

            this.backupHistory.push(backupRecord);
            await this.saveMetadata();

            this.log(`Incremental backup completed: ${backupId} (${changedFiles.length} files, ${this.formatSize(backupRecord.size)})`);
            return backupRecord;

        } catch (error) {
            this.log(`Incremental backup failed: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async createDeviceSnapshot() {
        this.log('Creating device state snapshot...');
        
        const snapshot = {
            timestamp: new Date().toISOString(),
            system: {
                platform: process.platform,
                arch: process.arch,
                nodeVersion: process.version,
                uptime: process.uptime()
            },
            devices: [],
            services: [],
            network: {}
        };

        try {
            // Capture running services
            const { stdout: services } = await execAsync('ps aux | grep -E "(opendirectory|mdm)" | grep -v grep');
            snapshot.services = services.trim().split('\n').map(line => {
                const parts = line.split(/\s+/);
                return {
                    user: parts[0],
                    pid: parts[1],
                    cpu: parts[2],
                    mem: parts[3],
                    command: parts.slice(10).join(' ')
                };
            });

            // Capture network configuration
            try {
                const { stdout: network } = await execAsync('ifconfig -a');
                snapshot.network.interfaces = network;
            } catch (error) {
                snapshot.network.error = error.message;
            }

            // Capture system information
            try {
                const { stdout: sysinfo } = await execAsync('uname -a');
                snapshot.system.uname = sysinfo.trim();
            } catch (error) {
                snapshot.system.unameError = error.message;
            }

        } catch (error) {
            this.log(`Device snapshot creation failed: ${error.message}`, 'WARNING');
        }

        const snapshotPath = path.join(this.backupDir, 'snapshots', `snapshot-${Date.now()}.json`);
        await fs.writeFile(snapshotPath, JSON.stringify(snapshot, null, 2));

        return { path: snapshotPath, snapshot };
    }

    async backupConfigurations() {
        this.log('Backing up configurations...');
        
        const configPaths = [
            '/etc/opendirectory',
            '/usr/local/etc/opendirectory',
            path.join(process.env.HOME || '/tmp', '.opendirectory')
        ];

        const configs = [];

        for (const configPath of configPaths) {
            try {
                const exists = await this.pathExists(configPath);
                if (exists) {
                    const files = await this.copyDirectory(configPath, path.join(this.backupDir, 'configs'));
                    configs.push({ path: configPath, files });
                }
            } catch (error) {
                this.log(`Failed to backup config path ${configPath}: ${error.message}`, 'WARNING');
            }
        }

        return configs;
    }

    async backupPolicies() {
        this.log('Backing up policies...');
        
        // This would integrate with the actual policy storage
        // For now, we'll simulate policy backup
        const policies = {
            timestamp: new Date().toISOString(),
            policies: [],
            deployments: [],
            history: []
        };

        try {
            // Look for policy files in common locations
            const policyPaths = [
                '/var/lib/opendirectory/policies',
                '/tmp/opendirectory-policies',
                path.join(process.cwd(), 'policies')
            ];

            for (const policyPath of policyPaths) {
                try {
                    const exists = await this.pathExists(policyPath);
                    if (exists) {
                        const files = await this.copyDirectory(policyPath, path.join(this.backupDir, 'policies'));
                        policies.policies.push({ path: policyPath, files });
                    }
                } catch (error) {
                    this.log(`Failed to backup policy path ${policyPath}: ${error.message}`, 'WARNING');
                }
            }

        } catch (error) {
            this.log(`Policy backup failed: ${error.message}`, 'WARNING');
        }

        const policyBackupPath = path.join(this.backupDir, 'policies', `policies-${Date.now()}.json`);
        await fs.writeFile(policyBackupPath, JSON.stringify(policies, null, 2));

        return { path: policyBackupPath, policies };
    }

    async backupUserData() {
        this.log('Backing up user and group data...');
        
        const userData = {
            timestamp: new Date().toISOString(),
            users: [],
            groups: [],
            permissions: []
        };

        try {
            // Export user data (simulated - would integrate with actual user management)
            const userDataPath = path.join(this.backupDir, 'users', `users-${Date.now()}.json`);
            await fs.writeFile(userDataPath, JSON.stringify(userData, null, 2));

            return { path: userDataPath, userData };
        } catch (error) {
            this.log(`User data backup failed: ${error.message}`, 'WARNING');
            return { error: error.message };
        }
    }

    async backupPath(sourcePath, backupId) {
        const files = [];
        
        try {
            // Handle glob patterns
            if (sourcePath.includes('*')) {
                const { stdout } = await execAsync(`find ${sourcePath.replace('*', '')} -name "${path.basename(sourcePath)}" 2>/dev/null || true`);
                const matchedPaths = stdout.trim().split('\n').filter(p => p.length > 0);
                
                for (const matchedPath of matchedPaths) {
                    const pathFiles = await this.backupSinglePath(matchedPath, backupId);
                    files.push(...pathFiles);
                }
            } else {
                const pathFiles = await this.backupSinglePath(sourcePath, backupId);
                files.push(...pathFiles);
            }
        } catch (error) {
            this.log(`Failed to backup path ${sourcePath}: ${error.message}`, 'WARNING');
        }

        return files;
    }

    async backupSinglePath(sourcePath, backupId) {
        const files = [];
        
        try {
            const exists = await this.pathExists(sourcePath);
            if (!exists) {
                return files;
            }

            const stat = await fs.stat(sourcePath);
            
            if (stat.isFile()) {
                const relativePath = path.relative('/', sourcePath);
                const backupFilePath = path.join(this.backupDir, 'files', backupId, relativePath);
                
                await fs.mkdir(path.dirname(backupFilePath), { recursive: true });
                await fs.copyFile(sourcePath, backupFilePath);
                
                files.push({
                    original: sourcePath,
                    backup: backupFilePath,
                    size: stat.size,
                    mtime: stat.mtime
                });
            } else if (stat.isDirectory()) {
                const dirFiles = await this.copyDirectory(sourcePath, path.join(this.backupDir, 'files', backupId));
                files.push(...dirFiles);
            }
        } catch (error) {
            this.log(`Failed to backup single path ${sourcePath}: ${error.message}`, 'WARNING');
        }

        return files;
    }

    async copyDirectory(sourceDir, targetDir) {
        const files = [];
        
        try {
            await fs.mkdir(targetDir, { recursive: true });
            
            const entries = await fs.readdir(sourceDir, { withFileTypes: true });
            
            for (const entry of entries) {
                const sourcePath = path.join(sourceDir, entry.name);
                const targetPath = path.join(targetDir, entry.name);
                
                // Skip excluded patterns
                if (this.isExcluded(entry.name)) {
                    continue;
                }
                
                if (entry.isDirectory()) {
                    const dirFiles = await this.copyDirectory(sourcePath, targetPath);
                    files.push(...dirFiles);
                } else if (entry.isFile()) {
                    await fs.copyFile(sourcePath, targetPath);
                    const stat = await fs.stat(sourcePath);
                    files.push({
                        original: sourcePath,
                        backup: targetPath,
                        size: stat.size,
                        mtime: stat.mtime
                    });
                }
            }
        } catch (error) {
            this.log(`Failed to copy directory ${sourceDir}: ${error.message}`, 'WARNING');
        }

        return files;
    }

    async findChangedFiles(sinceTimestamp) {
        const changedFiles = [];
        const sinceDate = new Date(sinceTimestamp);

        for (const backupPath of this.config.backupPaths) {
            try {
                if (backupPath.includes('*')) {
                    const { stdout } = await execAsync(`find ${backupPath.replace('*', '')} -name "${path.basename(backupPath)}" 2>/dev/null || true`);
                    const matchedPaths = stdout.trim().split('\n').filter(p => p.length > 0);
                    
                    for (const matchedPath of matchedPaths) {
                        const files = await this.findChangedFilesInPath(matchedPath, sinceDate);
                        changedFiles.push(...files);
                    }
                } else {
                    const files = await this.findChangedFilesInPath(backupPath, sinceDate);
                    changedFiles.push(...files);
                }
            } catch (error) {
                this.log(`Failed to find changed files in ${backupPath}: ${error.message}`, 'WARNING');
            }
        }

        return changedFiles;
    }

    async findChangedFilesInPath(sourcePath, sinceDate) {
        const changedFiles = [];

        try {
            const exists = await this.pathExists(sourcePath);
            if (!exists) {
                return changedFiles;
            }

            const stat = await fs.stat(sourcePath);
            
            if (stat.isFile()) {
                if (stat.mtime > sinceDate) {
                    changedFiles.push({
                        path: sourcePath,
                        size: stat.size,
                        mtime: stat.mtime,
                        type: 'file'
                    });
                }
            } else if (stat.isDirectory()) {
                const entries = await fs.readdir(sourcePath, { withFileTypes: true });
                
                for (const entry of entries) {
                    if (this.isExcluded(entry.name)) {
                        continue;
                    }
                    
                    const entryPath = path.join(sourcePath, entry.name);
                    const files = await this.findChangedFilesInPath(entryPath, sinceDate);
                    changedFiles.push(...files);
                }
            }
        } catch (error) {
            this.log(`Failed to check changes in ${sourcePath}: ${error.message}`, 'WARNING');
        }

        return changedFiles;
    }

    async createEncryptedArchive(backupPath, manifest, backupId) {
        const tempArchivePath = `${backupPath}.temp`;
        
        try {
            // Create manifest file
            const manifestPath = path.join(this.backupDir, 'temp', `${backupId}-manifest.json`);
            await fs.mkdir(path.dirname(manifestPath), { recursive: true });
            await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));

            // Create tar archive
            const filesToBackup = [manifestPath];
            
            // Add all backup directories
            const backupSubDirs = ['configs', 'policies', 'users', 'snapshots', path.join('files', backupId)];
            for (const subDir of backupSubDirs) {
                const fullPath = path.join(this.backupDir, subDir);
                const exists = await this.pathExists(fullPath);
                if (exists) {
                    filesToBackup.push(fullPath);
                }
            }

            // Create tar.gz archive
            const tarCommand = `tar -czf "${tempArchivePath}" -C "${this.backupDir}" ${filesToBackup.map(f => path.relative(this.backupDir, f)).join(' ')}`;
            await execAsync(tarCommand);

            // Encrypt the archive
            await this.encryptFile(tempArchivePath, backupPath);

            // Cleanup temp files
            await fs.unlink(tempArchivePath);
            await fs.unlink(manifestPath);

        } catch (error) {
            this.log(`Failed to create encrypted archive: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async createIncrementalArchive(backupPath, manifest, changedFiles) {
        const tempArchivePath = `${backupPath}.temp`;
        
        try {
            // Create temporary directory for incremental files
            const incrementalDir = path.join(this.backupDir, 'temp', manifest.id);
            await fs.mkdir(incrementalDir, { recursive: true });

            // Copy changed files
            for (const file of changedFiles) {
                const relativePath = path.relative('/', file.path);
                const targetPath = path.join(incrementalDir, relativePath);
                
                await fs.mkdir(path.dirname(targetPath), { recursive: true });
                
                if (file.type === 'file') {
                    await fs.copyFile(file.path, targetPath);
                }
            }

            // Create manifest file
            const manifestPath = path.join(incrementalDir, 'manifest.json');
            await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));

            // Create tar.gz archive
            const tarCommand = `tar -czf "${tempArchivePath}" -C "${incrementalDir}" .`;
            await execAsync(tarCommand);

            // Encrypt the archive
            await this.encryptFile(tempArchivePath, backupPath);

            // Cleanup
            await fs.unlink(tempArchivePath);
            await execAsync(`rm -rf "${incrementalDir}"`);

        } catch (error) {
            this.log(`Failed to create incremental archive: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async encryptFile(sourcePath, targetPath) {
        return new Promise((resolve, reject) => {
            const cipher = crypto.createCipher('aes-256-cbc', this.config.encryptionKey);
            const input = require('fs').createReadStream(sourcePath);
            const output = require('fs').createWriteStream(targetPath);

            input.pipe(cipher).pipe(output);

            output.on('finish', resolve);
            output.on('error', reject);
            input.on('error', reject);
        });
    }

    async decryptFile(sourcePath, targetPath) {
        return new Promise((resolve, reject) => {
            const decipher = crypto.createDecipher('aes-256-cbc', this.config.encryptionKey);
            const input = require('fs').createReadStream(sourcePath);
            const output = require('fs').createWriteStream(targetPath);

            input.pipe(decipher).pipe(output);

            output.on('finish', resolve);
            output.on('error', reject);
            input.on('error', reject);
        });
    }

    async restoreBackup(backupId, targetPath = null) {
        this.log(`Starting restore of backup: ${backupId}`);

        const backup = this.backupHistory.find(b => b.id === backupId);
        if (!backup) {
            throw new Error(`Backup ${backupId} not found`);
        }

        try {
            // Decrypt backup
            const tempPath = path.join(this.backupDir, 'temp', `restore-${backupId}.tar.gz`);
            await fs.mkdir(path.dirname(tempPath), { recursive: true });
            await this.decryptFile(backup.path, tempPath);

            // Extract archive
            const extractPath = targetPath || path.join(this.backupDir, 'temp', `extract-${backupId}`);
            await fs.mkdir(extractPath, { recursive: true });
            
            const tarCommand = `tar -xzf "${tempPath}" -C "${extractPath}"`;
            await execAsync(tarCommand);

            // If incremental backup, need to restore base backup first
            if (backup.type === 'incremental') {
                await this.restoreBackup(backup.baseBackup, extractPath);
            }

            this.log(`Backup ${backupId} restored to ${extractPath}`);
            
            // Cleanup temp files
            await fs.unlink(tempPath);

            return extractPath;

        } catch (error) {
            this.log(`Restore failed for backup ${backupId}: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async cleanupOldBackups() {
        this.log('Cleaning up old backups...');

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

        const backupsToDelete = this.backupHistory.filter(backup => 
            new Date(backup.timestamp) < cutoffDate
        );

        for (const backup of backupsToDelete) {
            try {
                await fs.unlink(backup.path);
                this.log(`Deleted old backup: ${backup.id}`);
            } catch (error) {
                this.log(`Failed to delete backup ${backup.id}: ${error.message}`, 'WARNING');
            }
        }

        // Remove from history
        this.backupHistory = this.backupHistory.filter(backup => 
            new Date(backup.timestamp) >= cutoffDate
        );

        await this.saveMetadata();
        this.log(`Cleanup completed, removed ${backupsToDelete.length} old backups`);
    }

    async getBackupStatus() {
        const lastFull = this.backupHistory
            .filter(b => b.type === 'full')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

        const lastIncremental = this.backupHistory
            .filter(b => b.type === 'incremental')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

        const totalSize = this.backupHistory.reduce((sum, backup) => sum + backup.size, 0);

        return {
            totalBackups: this.backupHistory.length,
            lastFullBackup: lastFull ? lastFull.timestamp : null,
            lastIncrementalBackup: lastIncremental ? lastIncremental.timestamp : null,
            totalSize: this.formatSize(totalSize),
            retentionDays: this.config.retentionDays,
            isHealthy: this.isBackupHealthy()
        };
    }

    isBackupHealthy() {
        const lastFull = this.backupHistory
            .filter(b => b.type === 'full')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

        if (!lastFull) {
            return false;
        }

        return !this.isBackupStale(lastFull, this.config.backupInterval * 2); // Allow 2x interval
    }

    isBackupStale(backup, maxAge) {
        const backupDate = new Date(backup.timestamp);
        const now = new Date();
        return (now - backupDate) > maxAge;
    }

    async calculateChecksum(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = require('fs').createReadStream(filePath);

            stream.on('data', data => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });
    }

    generateBackupId(type) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        return `${type}-${timestamp}-${Math.random().toString(36).substr(2, 8)}`;
    }

    generateEncryptionKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    isExcluded(filename) {
        return this.config.excludePatterns.some(pattern => {
            if (pattern.includes('*')) {
                const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                return regex.test(filename);
            }
            return filename.includes(pattern);
        });
    }

    async pathExists(path) {
        try {
            await fs.access(path);
            return true;
        } catch {
            return false;
        }
    }

    formatSize(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${Math.round(bytes / Math.pow(1024, i) * 100) / 100} ${sizes[i]}`;
    }

    async log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;

        try {
            await fs.appendFile(this.logFile, logEntry);
            console.log(`Backup Service: ${message}`);
        } catch (error) {
            console.error(`Failed to write log: ${error.message}`);
        }
    }

    async shutdown() {
        this.log('Backup Service shutting down...');
        this.isRunning = false;
        await this.saveMetadata();
    }
}

// Start the service
if (require.main === module) {
    const service = new BackupService();
    service.start().catch(error => {
        console.error('Failed to start Backup Service:', error);
        process.exit(1);
    });
}

module.exports = BackupService;