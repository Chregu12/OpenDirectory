'use strict';

const { v4: uuidv4 } = require('uuid');

// ====================================================================== //
//  QuarantineManager - Quarantine file management
// ====================================================================== //

class QuarantineManager {
    constructor(orchestrator, logger) {
        this.orchestrator = orchestrator;
        this.logger = logger;
        this.quarantinedFiles = new Map();
        this.autoQuarantinePolicies = new Map();

        this._seedData();
        this.logger.info('QuarantineManager initialized', { fileCount: this.quarantinedFiles.size });
    }

    _seedData() {
        // Build quarantine entries from threats that were quarantined
        for (const [threatId, threat] of this.orchestrator.threats) {
            if (threat.action === 'quarantined') {
                const fileId = `qf-${uuidv4().slice(0, 10)}`;
                const device = this.orchestrator.devices.get(threat.deviceId);

                this.quarantinedFiles.set(fileId, {
                    fileId,
                    threatId,
                    deviceId: threat.deviceId,
                    hostname: device ? device.hostname : 'Unknown',
                    originalPath: threat.filePath,
                    quarantinePath: this._buildQuarantinePath(threat.deviceId, fileId),
                    fileName: threat.filePath.split(/[/\\]/).pop(),
                    fileSize: threat.fileSize,
                    sha256: threat.sha256,
                    md5: this._generateMd5(),
                    threatName: threat.name,
                    severity: threat.severity,
                    category: threat.category,
                    quarantinedAt: threat.detectedAt,
                    quarantinedBy: 'clamav-engine',
                    status: 'quarantined',
                    restorable: true,
                    analysisStatus: Math.random() > 0.6 ? 'analyzed' : 'pending',
                    submittedToVT: Math.random() > 0.7,
                    vtDetectionRatio: Math.random() > 0.7 ? `${Math.floor(Math.random() * 40) + 20}/72` : null,
                    notes: null,
                });
            }
        }

        // Seed auto-quarantine policies
        const policies = [
            {
                name: 'Critical Threats Auto-Quarantine',
                description: 'Automatically quarantine all critical severity threats',
                condition: { severity: 'critical' },
                action: 'quarantine',
                enabled: true,
                notifyAdmin: true,
                notifyUser: true,
            },
            {
                name: 'High Threats Auto-Quarantine',
                description: 'Automatically quarantine high severity threats',
                condition: { severity: 'high' },
                action: 'quarantine',
                enabled: true,
                notifyAdmin: true,
                notifyUser: false,
            },
            {
                name: 'Ransomware Immediate Block',
                description: 'Immediately quarantine and isolate any ransomware detection',
                condition: { category: 'Ransomware' },
                action: 'quarantine_and_isolate',
                enabled: true,
                notifyAdmin: true,
                notifyUser: true,
            },
            {
                name: 'PUA Alert Only',
                description: 'Alert but do not quarantine potentially unwanted applications',
                condition: { severity: 'low', category: 'Adware' },
                action: 'alert_only',
                enabled: true,
                notifyAdmin: false,
                notifyUser: true,
            },
            {
                name: 'Trojan Auto-Delete',
                description: 'Automatically delete known trojan samples after quarantine period',
                condition: { category: 'Trojan' },
                action: 'quarantine_then_delete',
                deleteAfterDays: 30,
                enabled: false,
                notifyAdmin: true,
                notifyUser: false,
            },
        ];

        for (const policy of policies) {
            const policyId = `qpol-${uuidv4().slice(0, 8)}`;
            this.autoQuarantinePolicies.set(policyId, {
                policyId,
                ...policy,
                matchCount: Math.floor(Math.random() * 100) + 10,
                createdAt: new Date(Date.now() - Math.floor(Math.random() * 90) * 86400000).toISOString(),
                updatedAt: new Date(Date.now() - Math.floor(Math.random() * 14) * 86400000).toISOString(),
            });
        }
    }

    _buildQuarantinePath(deviceId, fileId) {
        const device = this.orchestrator.devices.get(deviceId);
        if (!device) return `/var/lib/clamav/quarantine/${fileId}`;
        if (device.platform === 'windows') {
            return `C:\\ProgramData\\ClamAV\\Quarantine\\${fileId}`;
        }
        if (device.platform === 'macos') {
            return `/Library/Application Support/ClamAV/Quarantine/${fileId}`;
        }
        return `/var/lib/clamav/quarantine/${fileId}`;
    }

    _generateMd5() {
        const chars = '0123456789abcdef';
        let hash = '';
        for (let i = 0; i < 32; i++) {
            hash += chars[Math.floor(Math.random() * chars.length)];
        }
        return hash;
    }

    // ------------------------------------------------------------------ //
    //  Query operations
    // ------------------------------------------------------------------ //

    listQuarantinedFiles(filters = {}) {
        let files = Array.from(this.quarantinedFiles.values());

        if (filters.deviceId) {
            files = files.filter(f => f.deviceId === filters.deviceId);
        }
        if (filters.severity) {
            files = files.filter(f => f.severity === filters.severity);
        }
        if (filters.status) {
            files = files.filter(f => f.status === filters.status);
        }
        if (filters.category) {
            files = files.filter(f => f.category === filters.category);
        }
        if (filters.sha256) {
            files = files.filter(f => f.sha256 === filters.sha256);
        }

        files.sort((a, b) => new Date(b.quarantinedAt) - new Date(a.quarantinedAt));

        const page = parseInt(filters.page, 10) || 1;
        const limit = parseInt(filters.limit, 10) || 50;
        const offset = (page - 1) * limit;
        const total = files.length;

        return {
            files: files.slice(offset, offset + limit),
            pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
            statistics: this._getQuarantineStatistics(files),
        };
    }

    getQuarantinedFile(fileId) {
        const file = this.quarantinedFiles.get(fileId);
        if (!file) {
            throw Object.assign(new Error(`Quarantined file ${fileId} not found`), { statusCode: 404 });
        }

        // Find related files by hash across fleet
        const relatedFiles = Array.from(this.quarantinedFiles.values())
            .filter(f => f.fileId !== fileId && f.sha256 === file.sha256)
            .map(f => ({
                fileId: f.fileId,
                deviceId: f.deviceId,
                hostname: f.hostname,
                quarantinedAt: f.quarantinedAt,
            }));

        return {
            ...file,
            relatedFiles,
            fleetOccurrences: relatedFiles.length + 1,
        };
    }

    // ------------------------------------------------------------------ //
    //  Actions
    // ------------------------------------------------------------------ //

    restoreFile(fileId) {
        const file = this.quarantinedFiles.get(fileId);
        if (!file) {
            throw Object.assign(new Error(`Quarantined file ${fileId} not found`), { statusCode: 404 });
        }
        if (file.status === 'restored') {
            throw Object.assign(new Error(`File ${fileId} has already been restored`), { statusCode: 409 });
        }
        if (file.status === 'deleted') {
            throw Object.assign(new Error(`File ${fileId} has been permanently deleted and cannot be restored`), { statusCode: 409 });
        }

        file.status = 'restored';
        file.restoredAt = new Date().toISOString();
        file.restoredBy = 'api';

        this.logger.info('Quarantined file restored', { fileId, originalPath: file.originalPath, deviceId: file.deviceId });

        return {
            fileId,
            status: 'restored',
            originalPath: file.originalPath,
            deviceId: file.deviceId,
            hostname: file.hostname,
            restoredAt: file.restoredAt,
            message: `File restored to ${file.originalPath} on ${file.hostname}`,
            warning: 'This file was flagged as malicious. Ensure it has been verified safe before use.',
        };
    }

    deleteFile(fileId) {
        const file = this.quarantinedFiles.get(fileId);
        if (!file) {
            throw Object.assign(new Error(`Quarantined file ${fileId} not found`), { statusCode: 404 });
        }
        if (file.status === 'deleted') {
            throw Object.assign(new Error(`File ${fileId} has already been deleted`), { statusCode: 409 });
        }

        file.status = 'deleted';
        file.deletedAt = new Date().toISOString();
        file.deletedBy = 'api';
        file.restorable = false;

        this.logger.info('Quarantined file permanently deleted', { fileId, deviceId: file.deviceId });

        return {
            fileId,
            status: 'deleted',
            deviceId: file.deviceId,
            hostname: file.hostname,
            deletedAt: file.deletedAt,
            message: 'File has been permanently deleted from quarantine',
        };
    }

    // ------------------------------------------------------------------ //
    //  Statistics
    // ------------------------------------------------------------------ //

    _getQuarantineStatistics(files) {
        if (!files) {
            files = Array.from(this.quarantinedFiles.values());
        }

        const now = new Date();
        const sevenDaysAgo = new Date(now - 7 * 86400000);
        const thirtyDaysAgo = new Date(now - 30 * 86400000);

        return {
            total: files.length,
            byStatus: {
                quarantined: files.filter(f => f.status === 'quarantined').length,
                restored: files.filter(f => f.status === 'restored').length,
                deleted: files.filter(f => f.status === 'deleted').length,
            },
            bySeverity: {
                critical: files.filter(f => f.severity === 'critical').length,
                high: files.filter(f => f.severity === 'high').length,
                medium: files.filter(f => f.severity === 'medium').length,
                low: files.filter(f => f.severity === 'low').length,
            },
            last7Days: files.filter(f => new Date(f.quarantinedAt) >= sevenDaysAgo).length,
            last30Days: files.filter(f => new Date(f.quarantinedAt) >= thirtyDaysAgo).length,
            totalSizeBytes: files.reduce((sum, f) => sum + (f.fileSize || 0), 0),
            uniqueThreats: new Set(files.map(f => f.threatName)).size,
            affectedDevices: new Set(files.map(f => f.deviceId)).size,
        };
    }

    getStatistics() {
        return this._getQuarantineStatistics();
    }

    // ------------------------------------------------------------------ //
    //  Hash correlation
    // ------------------------------------------------------------------ //

    findByHash(sha256) {
        const matches = Array.from(this.quarantinedFiles.values())
            .filter(f => f.sha256 === sha256);

        return {
            sha256,
            occurrences: matches.length,
            files: matches.map(f => ({
                fileId: f.fileId,
                deviceId: f.deviceId,
                hostname: f.hostname,
                originalPath: f.originalPath,
                threatName: f.threatName,
                severity: f.severity,
                status: f.status,
                quarantinedAt: f.quarantinedAt,
            })),
            affectedDevices: [...new Set(matches.map(f => f.deviceId))],
        };
    }

    // ------------------------------------------------------------------ //
    //  Auto-quarantine policies
    // ------------------------------------------------------------------ //

    getAutoQuarantinePolicies() {
        return {
            policies: Array.from(this.autoQuarantinePolicies.values()),
            total: this.autoQuarantinePolicies.size,
        };
    }
}

module.exports = QuarantineManager;
