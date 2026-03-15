'use strict';

const { v4: uuidv4 } = require('uuid');

// ====================================================================== //
//  SignatureManager - ClamAV signature/definition management
// ====================================================================== //

class SignatureManager {
    constructor(orchestrator, logger) {
        this.orchestrator = orchestrator;
        this.logger = logger;

        this.currentSignature = {
            version: '27180',
            fullVersion: 'ClamAV 0.104.3/27180/2026-03-15',
            engineVersion: '0.104.3',
            releaseDate: '2026-03-15T06:00:00.000Z',
            totalSignatures: 8742156,
            mainCvd: { version: 62, signatures: 6543210, buildTime: '2026-03-15T04:00:00.000Z' },
            dailyCvd: { version: 27180, signatures: 2145678, buildTime: '2026-03-15T06:00:00.000Z' },
            bytecodeCvd: { version: 335, signatures: 53268, buildTime: '2026-03-10T12:00:00.000Z' },
        };

        this.updateHistory = [];
        this.customRules = new Map();
        this.deviceSignatureStatus = new Map();
        this.updateJobs = new Map();

        this._seedData();
        this.logger.info('SignatureManager initialized', { signatureVersion: this.currentSignature.version });
    }

    _seedData() {
        // Seed update history
        for (let i = 0; i < 14; i++) {
            const date = new Date(Date.now() - i * 86400000);
            const version = 27180 - i;
            this.updateHistory.push({
                updateId: `upd-${uuidv4().slice(0, 8)}`,
                version: String(version),
                previousVersion: String(version - 1),
                engineVersion: '0.104.3',
                releaseDate: date.toISOString(),
                appliedAt: new Date(date.getTime() + 3600000).toISOString(),
                newSignatures: Math.floor(Math.random() * 500) + 100,
                modifiedSignatures: Math.floor(Math.random() * 200) + 50,
                removedSignatures: Math.floor(Math.random() * 30),
                status: 'applied',
                source: 'database.clamav.net',
            });
        }

        // Seed per-device signature status
        for (const [deviceId, device] of this.orchestrator.devices) {
            const isOutdated = Math.random() < 0.15;
            const version = isOutdated ? String(27180 - Math.floor(Math.random() * 5) - 1) : '27180';
            const lastUpdate = isOutdated
                ? new Date(Date.now() - (Math.floor(Math.random() * 5) + 2) * 86400000).toISOString()
                : new Date(Date.now() - Math.floor(Math.random() * 24) * 3600000).toISOString();

            this.deviceSignatureStatus.set(deviceId, {
                deviceId,
                hostname: device.hostname,
                signatureVersion: version,
                engineVersion: '0.104.3',
                lastUpdate,
                autoUpdateEnabled: Math.random() > 0.1,
                updateFrequency: 'hourly',
                freshclamStatus: isOutdated ? 'outdated' : 'current',
                freshclamLastRun: lastUpdate,
                freshclamNextRun: new Date(new Date(lastUpdate).getTime() + 3600000).toISOString(),
                mirrorSource: 'database.clamav.net',
            });
        }

        // Seed custom signature rules
        const customRules = [
            {
                name: 'Custom.Phishing.InternalBrand',
                description: 'Detects phishing attempts using internal brand assets',
                type: 'ldb',
                pattern: 'MZ;EP+0:4d5a;0/1:436f6d70616e79',
                severity: 'high',
                enabled: true,
                createdBy: 'security-team',
            },
            {
                name: 'Custom.Policy.CryptoMiner',
                description: 'Detects cryptocurrency mining software',
                type: 'ndb',
                pattern: '0:4d5a90000300000004000000ffff',
                severity: 'medium',
                enabled: true,
                createdBy: 'security-team',
            },
            {
                name: 'Custom.PUA.UnauthorizedRemoteAccess',
                description: 'Detects unauthorized remote access tools',
                type: 'ldb',
                pattern: 'MZ;0/1:5465616d566965776572',
                severity: 'medium',
                enabled: true,
                createdBy: 'it-admin',
            },
            {
                name: 'Custom.Dropper.SuspiciousPowerShell',
                description: 'Detects suspicious PowerShell download cradles',
                type: 'ldb',
                pattern: '0/1:496e766f6b652d576562526571756573742d55726920;0/2:446f776e6c6f616446696c65',
                severity: 'high',
                enabled: true,
                createdBy: 'security-team',
            },
            {
                name: 'Custom.Policy.TorBrowser',
                description: 'Detects Tor Browser bundles on managed devices',
                type: 'ndb',
                pattern: '0:746f72627574746f6e2d6275636b6574',
                severity: 'low',
                enabled: false,
                createdBy: 'compliance-team',
            },
        ];

        for (const rule of customRules) {
            const ruleId = `rule-${uuidv4().slice(0, 8)}`;
            this.customRules.set(ruleId, {
                ruleId,
                ...rule,
                hitCount: Math.floor(Math.random() * 50),
                lastHit: Math.random() > 0.5 ? new Date(Date.now() - Math.floor(Math.random() * 7) * 86400000).toISOString() : null,
                createdAt: new Date(Date.now() - Math.floor(Math.random() * 90) * 86400000).toISOString(),
                updatedAt: new Date(Date.now() - Math.floor(Math.random() * 14) * 86400000).toISOString(),
            });
        }
    }

    // ------------------------------------------------------------------ //
    //  Signature status
    // ------------------------------------------------------------------ //

    getSignatureStatus() {
        const deviceStatuses = Array.from(this.deviceSignatureStatus.values());
        const outdatedDevices = deviceStatuses.filter(d => d.freshclamStatus === 'outdated');
        const currentDevices = deviceStatuses.filter(d => d.freshclamStatus === 'current');

        return {
            current: this.currentSignature,
            fleet: {
                totalDevices: deviceStatuses.length,
                upToDate: currentDevices.length,
                outdated: outdatedDevices.length,
                outdatedDevices: outdatedDevices.map(d => ({
                    deviceId: d.deviceId,
                    hostname: d.hostname,
                    signatureVersion: d.signatureVersion,
                    lastUpdate: d.lastUpdate,
                })),
            },
            customRules: {
                total: this.customRules.size,
                enabled: Array.from(this.customRules.values()).filter(r => r.enabled).length,
            },
            updateHistory: this.updateHistory.slice(0, 7),
        };
    }

    getDeviceSignatureStatus(deviceId) {
        const status = this.deviceSignatureStatus.get(deviceId);
        if (!status) {
            throw Object.assign(new Error(`No signature status for device ${deviceId}`), { statusCode: 404 });
        }
        return status;
    }

    // ------------------------------------------------------------------ //
    //  Signature updates
    // ------------------------------------------------------------------ //

    triggerUpdate(deviceIds) {
        const jobId = `updjob-${uuidv4().slice(0, 8)}`;
        const resolvedIds = deviceIds && deviceIds.length > 0
            ? deviceIds.filter(id => this.orchestrator.devices.has(id))
            : Array.from(this.orchestrator.devices.keys());

        if (resolvedIds.length === 0) {
            throw Object.assign(new Error('No valid devices for signature update'), { statusCode: 400 });
        }

        const now = new Date().toISOString();
        const job = {
            jobId,
            status: 'in_progress',
            targetDevices: resolvedIds.length,
            completedDevices: 0,
            failedDevices: 0,
            startedAt: now,
            completedAt: null,
            deviceResults: {},
        };

        this.updateJobs.set(jobId, job);

        // Simulate update completion
        this._simulateUpdate(jobId, resolvedIds);

        this.logger.info('Signature update triggered', { jobId, deviceCount: resolvedIds.length });

        return {
            jobId,
            status: 'in_progress',
            targetDevices: resolvedIds.length,
            startedAt: now,
            message: `Signature update initiated for ${resolvedIds.length} device(s)`,
        };
    }

    _simulateUpdate(jobId, deviceIds) {
        const job = this.updateJobs.get(jobId);
        if (!job) return;

        let completed = 0;
        const timer = setInterval(() => {
            if (completed >= deviceIds.length) {
                clearInterval(timer);
                job.status = 'completed';
                job.completedAt = new Date().toISOString();
                this.logger.info('Signature update job completed', { jobId });
                return;
            }

            const deviceId = deviceIds[completed];
            const success = Math.random() > 0.05;

            if (success) {
                const devStatus = this.deviceSignatureStatus.get(deviceId);
                if (devStatus) {
                    devStatus.signatureVersion = this.currentSignature.version;
                    devStatus.lastUpdate = new Date().toISOString();
                    devStatus.freshclamStatus = 'current';
                    devStatus.freshclamLastRun = new Date().toISOString();
                }
                job.completedDevices++;
                job.deviceResults[deviceId] = { status: 'success', updatedTo: this.currentSignature.version };
            } else {
                job.failedDevices++;
                job.deviceResults[deviceId] = { status: 'failed', error: 'Connection timeout to mirror' };
            }

            completed++;
        }, 500);
    }

    // ------------------------------------------------------------------ //
    //  Custom rules
    // ------------------------------------------------------------------ //

    getCustomRules() {
        return {
            rules: Array.from(this.customRules.values()),
            total: this.customRules.size,
        };
    }

    getCustomRule(ruleId) {
        const rule = this.customRules.get(ruleId);
        if (!rule) {
            throw Object.assign(new Error(`Custom rule ${ruleId} not found`), { statusCode: 404 });
        }
        return rule;
    }

    // ------------------------------------------------------------------ //
    //  Version comparison
    // ------------------------------------------------------------------ //

    compareVersions(deviceVersion) {
        const current = parseInt(this.currentSignature.version, 10);
        const device = parseInt(deviceVersion, 10);
        const behind = current - device;

        return {
            currentVersion: this.currentSignature.version,
            deviceVersion,
            isUpToDate: behind === 0,
            versionsBehind: behind,
            updateRequired: behind > 0,
            urgency: behind === 0 ? 'none' : behind <= 2 ? 'low' : behind <= 5 ? 'medium' : 'high',
        };
    }
}

module.exports = SignatureManager;
