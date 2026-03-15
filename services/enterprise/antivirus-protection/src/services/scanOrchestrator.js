'use strict';

const { v4: uuidv4 } = require('uuid');

// ====================================================================== //
//  Demo data helpers
// ====================================================================== //

const PLATFORMS = ['windows', 'macos', 'linux'];
const DEPARTMENTS = ['Engineering', 'Finance', 'Marketing', 'HR', 'Sales', 'IT', 'Legal', 'Operations'];
const SCAN_TYPES = ['quick', 'full', 'custom', 'memory'];

const THREAT_NAMES = [
    'Win.Trojan.Agent-798345',
    'Win.Ransomware.Locky-9876',
    'Unix.Trojan.Mirai-456',
    'Osx.Adware.Genieo-123',
    'Win.Exploit.CVE_2024_1234-567',
    'PUA.Win.Packer.UPX-89',
    'Win.Malware.Emotet-345',
    'Doc.Dropper.Macro-234',
    'Win.Worm.Conficker-101',
    'Php.Webshell.Backdoor-777',
    'Win.Keylogger.HawkEye-555',
    'Linux.Rootkit.Beurk-333',
    'Win.Infostealer.Raccoon-222',
    'Osx.Backdoor.OceanLotus-111',
    'Android.Banker.Cerberus-999',
];

const THREAT_PATHS_WINDOWS = [
    'C:\\Users\\jsmith\\Downloads\\invoice_2026.pdf.exe',
    'C:\\Users\\agarcia\\AppData\\Local\\Temp\\svchost.exe',
    'C:\\Windows\\Temp\\update.bat',
    'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.exe',
    'C:\\Users\\mchen\\Documents\\macro_enabled.docm',
    'C:\\Users\\Public\\Desktop\\free_tool.exe',
];

const THREAT_PATHS_MACOS = [
    '/Users/shared/.hidden/agent',
    '/tmp/.com.apple.launchd.xyz',
    '/Users/jdoe/Downloads/Adobe_Flash_Installer.dmg',
    '/Library/LaunchDaemons/com.fake.plist',
];

const THREAT_PATHS_LINUX = [
    '/tmp/.ICE-unix/rootkit',
    '/var/tmp/.session-helper',
    '/home/deploy/.ssh/authorized_keys2',
    '/usr/local/bin/.update-notifier',
];

function randomItem(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function randomBetween(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function hoursAgo(h) {
    return new Date(Date.now() - h * 3600000).toISOString();
}

function daysAgo(d) {
    return new Date(Date.now() - d * 86400000).toISOString();
}

function generateSha256() {
    const chars = '0123456789abcdef';
    let hash = '';
    for (let i = 0; i < 64; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
    }
    return hash;
}

// ====================================================================== //
//  ScanOrchestrator
// ====================================================================== //

class ScanOrchestrator {
    constructor(logger) {
        this.logger = logger;
        this.devices = new Map();
        this.scans = new Map();
        this.threats = new Map();
        this.schedules = new Map();
        this.scanListeners = [];

        this._seedDemoData();
        this.logger.info('ScanOrchestrator initialized', { deviceCount: this.devices.size, scanCount: this.scans.size });
    }

    // ------------------------------------------------------------------ //
    //  Seed demo data
    // ------------------------------------------------------------------ //

    _seedDemoData() {
        const deviceDefs = [
            { name: 'ENG-WS-001', platform: 'windows', department: 'Engineering', user: 'jsmith' },
            { name: 'ENG-WS-002', platform: 'windows', department: 'Engineering', user: 'agarcia' },
            { name: 'ENG-MAC-003', platform: 'macos', department: 'Engineering', user: 'mchen' },
            { name: 'ENG-LNX-004', platform: 'linux', department: 'Engineering', user: 'kpatel' },
            { name: 'FIN-WS-001', platform: 'windows', department: 'Finance', user: 'ljohnson' },
            { name: 'FIN-WS-002', platform: 'windows', department: 'Finance', user: 'rwilliams' },
            { name: 'MKT-MAC-001', platform: 'macos', department: 'Marketing', user: 'sbrown' },
            { name: 'MKT-MAC-002', platform: 'macos', department: 'Marketing', user: 'jdoe' },
            { name: 'HR-WS-001', platform: 'windows', department: 'HR', user: 'tdavis' },
            { name: 'SALES-WS-001', platform: 'windows', department: 'Sales', user: 'nwilson' },
            { name: 'SALES-WS-002', platform: 'windows', department: 'Sales', user: 'pmartin' },
            { name: 'IT-LNX-001', platform: 'linux', department: 'IT', user: 'admin' },
            { name: 'IT-LNX-002', platform: 'linux', department: 'IT', user: 'deploy' },
            { name: 'LEGAL-WS-001', platform: 'windows', department: 'Legal', user: 'amiller' },
            { name: 'OPS-MAC-001', platform: 'macos', department: 'Operations', user: 'cthompson' },
            { name: 'OPS-WS-001', platform: 'windows', department: 'Operations', user: 'dlee' },
        ];

        for (const def of deviceDefs) {
            const deviceId = `dev-${uuidv4().slice(0, 8)}`;
            const lastScanHoursAgo = randomBetween(1, 72);
            const threatsFound = Math.random() < 0.35 ? randomBetween(1, 4) : 0;

            this.devices.set(deviceId, {
                deviceId,
                hostname: def.name,
                platform: def.platform,
                department: def.department,
                assignedUser: def.user,
                clamavVersion: 'ClamAV 0.104.3',
                signatureVersion: '27180',
                signatureDate: '2026-03-15',
                engineVersion: '0.104.3',
                realtimeProtection: Math.random() > 0.1,
                lastScanTime: hoursAgo(lastScanHoursAgo),
                lastScanType: randomItem(SCAN_TYPES),
                lastScanResult: threatsFound > 0 ? 'threats_found' : 'clean',
                threatsFoundTotal: threatsFound,
                totalScansRun: randomBetween(15, 120),
                status: Math.random() > 0.05 ? 'online' : 'offline',
                registeredAt: daysAgo(randomBetween(30, 365)),
                lastCheckin: hoursAgo(randomBetween(0, 4)),
            });

            // Generate historical scans for this device
            this._generateDeviceScans(deviceId, def.platform, randomBetween(3, 8));
        }

        // Generate some scheduled scans
        this._seedSchedules();
    }

    _generateDeviceScans(deviceId, platform, count) {
        for (let i = 0; i < count; i++) {
            const scanId = `scan-${uuidv4().slice(0, 12)}`;
            const scanType = randomItem(SCAN_TYPES);
            const startedAt = daysAgo(randomBetween(0, 14));
            const durationSec = scanType === 'quick' ? randomBetween(30, 300) :
                scanType === 'full' ? randomBetween(1800, 7200) :
                    scanType === 'memory' ? randomBetween(60, 600) :
                        randomBetween(120, 1800);

            const endedAt = new Date(new Date(startedAt).getTime() + durationSec * 1000).toISOString();
            const filesScanned = scanType === 'quick' ? randomBetween(5000, 25000) :
                scanType === 'full' ? randomBetween(100000, 500000) :
                    scanType === 'memory' ? randomBetween(200, 2000) :
                        randomBetween(1000, 50000);

            const hasThreats = Math.random() < 0.2;
            const threatCount = hasThreats ? randomBetween(1, 3) : 0;
            const scanThreats = [];

            for (let t = 0; t < threatCount; t++) {
                const threatId = `threat-${uuidv4().slice(0, 12)}`;
                const threatName = randomItem(THREAT_NAMES);
                const pathPool = platform === 'windows' ? THREAT_PATHS_WINDOWS :
                    platform === 'macos' ? THREAT_PATHS_MACOS : THREAT_PATHS_LINUX;
                const filePath = randomItem(pathPool);
                const sha256 = generateSha256();
                const severity = threatName.includes('Ransomware') || threatName.includes('Rootkit') ? 'critical' :
                    threatName.includes('Trojan') || threatName.includes('Exploit') || threatName.includes('Backdoor') ? 'high' :
                        threatName.includes('Worm') || threatName.includes('Keylogger') || threatName.includes('Infostealer') ? 'high' :
                            threatName.includes('PUA') || threatName.includes('Adware') ? 'low' : 'medium';

                const threat = {
                    threatId,
                    scanId,
                    deviceId,
                    name: threatName,
                    filePath,
                    fileSize: randomBetween(1024, 52428800),
                    sha256,
                    severity,
                    category: threatName.split('.')[1] || 'Malware',
                    action: randomItem(['quarantined', 'quarantined', 'quarantined', 'deleted', 'blocked']),
                    detectedAt: endedAt,
                    engineVersion: '0.104.3',
                    signatureMatch: threatName,
                };

                scanThreats.push(threat);
                this.threats.set(threatId, threat);
            }

            const scan = {
                scanId,
                deviceId,
                scanType,
                status: 'completed',
                progress: 100,
                startedAt,
                completedAt: endedAt,
                durationSeconds: durationSec,
                filesScanned,
                filesInfected: threatCount,
                dataScanned: `${(filesScanned * randomBetween(5, 50) / 1024).toFixed(1)} MB`,
                threats: scanThreats.map(t => t.threatId),
                engineVersion: '0.104.3',
                signatureVersion: '27180',
                initiatedBy: Math.random() > 0.5 ? 'scheduled' : 'manual',
                paths: scanType === 'custom' ? ['/home', '/var/www'] : null,
            };

            this.scans.set(scanId, scan);
        }
    }

    _seedSchedules() {
        const schedules = [
            {
                name: 'Daily Quick Scan - All Devices',
                scanType: 'quick',
                cronExpression: '0 12 * * *',
                deviceSelector: { all: true },
                enabled: true,
                createdBy: 'admin',
            },
            {
                name: 'Weekly Full Scan - Engineering',
                scanType: 'full',
                cronExpression: '0 2 * * 0',
                deviceSelector: { department: 'Engineering' },
                enabled: true,
                createdBy: 'admin',
            },
            {
                name: 'Nightly Full Scan - Finance',
                scanType: 'full',
                cronExpression: '0 1 * * *',
                deviceSelector: { department: 'Finance' },
                enabled: true,
                createdBy: 'admin',
            },
            {
                name: 'Bi-weekly Memory Scan - Servers',
                scanType: 'memory',
                cronExpression: '0 3 1,15 * *',
                deviceSelector: { platform: 'linux' },
                enabled: false,
                createdBy: 'admin',
            },
        ];

        for (const sched of schedules) {
            const scheduleId = `sched-${uuidv4().slice(0, 8)}`;
            this.schedules.set(scheduleId, {
                scheduleId,
                ...sched,
                lastRun: daysAgo(randomBetween(0, 3)),
                nextRun: new Date(Date.now() + randomBetween(3600000, 86400000)).toISOString(),
                runCount: randomBetween(5, 50),
                createdAt: daysAgo(randomBetween(30, 90)),
                updatedAt: daysAgo(randomBetween(0, 7)),
            });
        }
    }

    // ------------------------------------------------------------------ //
    //  Scan operations
    // ------------------------------------------------------------------ //

    initiateScan(deviceIds, scanType, paths) {
        const scanId = `scan-${uuidv4().slice(0, 12)}`;
        const resolvedDeviceIds = this._resolveDeviceIds(deviceIds);

        if (resolvedDeviceIds.length === 0) {
            throw Object.assign(new Error('No valid devices found for the provided device IDs'), { statusCode: 400 });
        }

        const now = new Date().toISOString();
        const scan = {
            scanId,
            deviceId: resolvedDeviceIds.length === 1 ? resolvedDeviceIds[0] : null,
            deviceIds: resolvedDeviceIds,
            scanType: scanType || 'quick',
            status: 'queued',
            progress: 0,
            startedAt: now,
            completedAt: null,
            durationSeconds: null,
            filesScanned: 0,
            filesInfected: 0,
            dataScanned: '0 MB',
            threats: [],
            engineVersion: '0.104.3',
            signatureVersion: '27180',
            initiatedBy: 'manual',
            paths: paths || null,
        };

        this.scans.set(scanId, scan);

        // Simulate scan progression
        this._simulateScanProgress(scanId, resolvedDeviceIds, scanType);

        this.logger.info('Scan initiated', { scanId, deviceCount: resolvedDeviceIds.length, scanType });

        return {
            scanId,
            status: 'queued',
            deviceCount: resolvedDeviceIds.length,
            scanType: scanType || 'quick',
            startedAt: now,
            message: `Scan queued for ${resolvedDeviceIds.length} device(s)`,
        };
    }

    _resolveDeviceIds(deviceIds) {
        if (!deviceIds || deviceIds.length === 0) {
            return Array.from(this.devices.keys());
        }
        return deviceIds.filter(id => this.devices.has(id));
    }

    _simulateScanProgress(scanId, deviceIds, scanType) {
        const scan = this.scans.get(scanId);
        if (!scan) return;

        const totalDuration = scanType === 'quick' ? 8000 : scanType === 'full' ? 20000 : scanType === 'memory' ? 10000 : 12000;
        const steps = 10;
        const interval = totalDuration / steps;

        let step = 0;
        const timer = setInterval(() => {
            step++;
            const progress = Math.min(Math.round((step / steps) * 100), 100);
            scan.status = 'scanning';
            scan.progress = progress;
            scan.filesScanned = Math.round(progress * randomBetween(100, 5000) / 10);
            scan.dataScanned = `${(scan.filesScanned * randomBetween(5, 30) / 1024).toFixed(1)} MB`;

            this._notifyListeners({
                type: 'scan_progress',
                scanId,
                progress,
                filesScanned: scan.filesScanned,
                status: 'scanning',
            });

            if (step >= steps) {
                clearInterval(timer);
                const hasThreats = Math.random() < 0.25;
                const threatCount = hasThreats ? randomBetween(1, 3) : 0;
                const foundThreats = [];

                for (let t = 0; t < threatCount; t++) {
                    const deviceId = randomItem(deviceIds);
                    const device = this.devices.get(deviceId);
                    const platform = device ? device.platform : 'windows';
                    const threatId = `threat-${uuidv4().slice(0, 12)}`;
                    const threatName = randomItem(THREAT_NAMES);
                    const pathPool = platform === 'windows' ? THREAT_PATHS_WINDOWS :
                        platform === 'macos' ? THREAT_PATHS_MACOS : THREAT_PATHS_LINUX;

                    const threat = {
                        threatId,
                        scanId,
                        deviceId,
                        name: threatName,
                        filePath: randomItem(pathPool),
                        fileSize: randomBetween(1024, 52428800),
                        sha256: generateSha256(),
                        severity: threatName.includes('Ransomware') || threatName.includes('Rootkit') ? 'critical' :
                            threatName.includes('Trojan') || threatName.includes('Exploit') || threatName.includes('Backdoor') ? 'high' :
                                threatName.includes('PUA') || threatName.includes('Adware') ? 'low' : 'medium',
                        category: threatName.split('.')[1] || 'Malware',
                        action: 'quarantined',
                        detectedAt: new Date().toISOString(),
                        engineVersion: '0.104.3',
                        signatureMatch: threatName,
                    };

                    foundThreats.push(threat);
                    this.threats.set(threatId, threat);

                    if (device) {
                        device.threatsFoundTotal = (device.threatsFoundTotal || 0) + 1;
                    }
                }

                scan.status = 'completed';
                scan.progress = 100;
                scan.completedAt = new Date().toISOString();
                scan.durationSeconds = Math.round(totalDuration / 1000);
                scan.filesInfected = threatCount;
                scan.threats = foundThreats.map(t => t.threatId);

                for (const did of deviceIds) {
                    const device = this.devices.get(did);
                    if (device) {
                        device.lastScanTime = scan.completedAt;
                        device.lastScanType = scanType;
                        device.lastScanResult = threatCount > 0 ? 'threats_found' : 'clean';
                        device.totalScansRun = (device.totalScansRun || 0) + 1;
                    }
                }

                this._notifyListeners({
                    type: 'scan_completed',
                    scanId,
                    status: 'completed',
                    filesScanned: scan.filesScanned,
                    threatsFound: threatCount,
                    threats: foundThreats,
                    durationSeconds: scan.durationSeconds,
                });

                this.logger.info('Scan completed', { scanId, threatsFound: threatCount });
            }
        }, interval);
    }

    _notifyListeners(message) {
        for (const listener of this.scanListeners) {
            try {
                listener(message);
            } catch (err) {
                this.logger.error('Error notifying scan listener', { error: err.message });
            }
        }
    }

    addScanListener(listener) {
        this.scanListeners.push(listener);
    }

    removeScanListener(listener) {
        this.scanListeners = this.scanListeners.filter(l => l !== listener);
    }

    // ------------------------------------------------------------------ //
    //  Query operations
    // ------------------------------------------------------------------ //

    getScan(scanId) {
        const scan = this.scans.get(scanId);
        if (!scan) {
            throw Object.assign(new Error(`Scan ${scanId} not found`), { statusCode: 404 });
        }

        const threats = (scan.threats || []).map(tid => this.threats.get(tid)).filter(Boolean);
        return { ...scan, threatDetails: threats };
    }

    listScans(filters = {}) {
        let scans = Array.from(this.scans.values());

        if (filters.status) {
            scans = scans.filter(s => s.status === filters.status);
        }
        if (filters.deviceId) {
            scans = scans.filter(s => s.deviceId === filters.deviceId || (s.deviceIds && s.deviceIds.includes(filters.deviceId)));
        }
        if (filters.scanType) {
            scans = scans.filter(s => s.scanType === filters.scanType);
        }
        if (filters.dateFrom) {
            const from = new Date(filters.dateFrom);
            scans = scans.filter(s => new Date(s.startedAt) >= from);
        }
        if (filters.dateTo) {
            const to = new Date(filters.dateTo);
            scans = scans.filter(s => new Date(s.startedAt) <= to);
        }

        scans.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));

        const page = parseInt(filters.page, 10) || 1;
        const limit = parseInt(filters.limit, 10) || 50;
        const offset = (page - 1) * limit;
        const total = scans.length;

        return {
            scans: scans.slice(offset, offset + limit),
            pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
        };
    }

    // ------------------------------------------------------------------ //
    //  Device operations
    // ------------------------------------------------------------------ //

    getDevices(filters = {}) {
        let devices = Array.from(this.devices.values());

        if (filters.platform) {
            devices = devices.filter(d => d.platform === filters.platform);
        }
        if (filters.department) {
            devices = devices.filter(d => d.department === filters.department);
        }
        if (filters.status) {
            devices = devices.filter(d => d.status === filters.status);
        }

        return {
            devices,
            total: devices.length,
            summary: {
                online: devices.filter(d => d.status === 'online').length,
                offline: devices.filter(d => d.status === 'offline').length,
                protectionEnabled: devices.filter(d => d.realtimeProtection).length,
                protectionDisabled: devices.filter(d => !d.realtimeProtection).length,
                withThreats: devices.filter(d => d.threatsFoundTotal > 0).length,
                clean: devices.filter(d => d.threatsFoundTotal === 0).length,
            },
        };
    }

    getDevice(deviceId) {
        const device = this.devices.get(deviceId);
        if (!device) {
            throw Object.assign(new Error(`Device ${deviceId} not found`), { statusCode: 404 });
        }

        const deviceScans = Array.from(this.scans.values())
            .filter(s => s.deviceId === deviceId || (s.deviceIds && s.deviceIds.includes(deviceId)))
            .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
            .slice(0, 20);

        const deviceThreats = Array.from(this.threats.values())
            .filter(t => t.deviceId === deviceId)
            .sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));

        return {
            ...device,
            recentScans: deviceScans,
            threats: deviceThreats,
            threatSummary: {
                total: deviceThreats.length,
                critical: deviceThreats.filter(t => t.severity === 'critical').length,
                high: deviceThreats.filter(t => t.severity === 'high').length,
                medium: deviceThreats.filter(t => t.severity === 'medium').length,
                low: deviceThreats.filter(t => t.severity === 'low').length,
            },
        };
    }

    // ------------------------------------------------------------------ //
    //  Threat operations
    // ------------------------------------------------------------------ //

    getThreats(filters = {}) {
        let threats = Array.from(this.threats.values());

        if (filters.severity) {
            threats = threats.filter(t => t.severity === filters.severity);
        }
        if (filters.deviceId) {
            threats = threats.filter(t => t.deviceId === filters.deviceId);
        }
        if (filters.category) {
            threats = threats.filter(t => t.category === filters.category);
        }
        if (filters.action) {
            threats = threats.filter(t => t.action === filters.action);
        }

        threats.sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));

        const page = parseInt(filters.page, 10) || 1;
        const limit = parseInt(filters.limit, 10) || 50;
        const offset = (page - 1) * limit;

        return {
            threats: threats.slice(offset, offset + limit),
            pagination: { page, limit, total: threats.length, totalPages: Math.ceil(threats.length / limit) },
            summary: {
                total: threats.length,
                critical: threats.filter(t => t.severity === 'critical').length,
                high: threats.filter(t => t.severity === 'high').length,
                medium: threats.filter(t => t.severity === 'medium').length,
                low: threats.filter(t => t.severity === 'low').length,
            },
        };
    }

    getThreat(threatId) {
        const threat = this.threats.get(threatId);
        if (!threat) {
            throw Object.assign(new Error(`Threat ${threatId} not found`), { statusCode: 404 });
        }

        const device = this.devices.get(threat.deviceId);
        const scan = this.scans.get(threat.scanId);

        return {
            ...threat,
            device: device ? { deviceId: device.deviceId, hostname: device.hostname, platform: device.platform, department: device.department } : null,
            scan: scan ? { scanId: scan.scanId, scanType: scan.scanType, startedAt: scan.startedAt } : null,
            relatedThreats: Array.from(this.threats.values())
                .filter(t => t.threatId !== threatId && (t.name === threat.name || t.sha256 === threat.sha256))
                .map(t => ({ threatId: t.threatId, deviceId: t.deviceId, detectedAt: t.detectedAt })),
        };
    }

    // ------------------------------------------------------------------ //
    //  Schedule operations
    // ------------------------------------------------------------------ //

    createSchedule(schedule) {
        const scheduleId = `sched-${uuidv4().slice(0, 8)}`;
        const now = new Date().toISOString();

        const entry = {
            scheduleId,
            name: schedule.name,
            scanType: schedule.scanType || 'quick',
            cronExpression: schedule.cronExpression,
            deviceSelector: schedule.deviceSelector || { all: true },
            paths: schedule.paths || null,
            enabled: schedule.enabled !== false,
            createdBy: schedule.createdBy || 'api',
            lastRun: null,
            nextRun: this._computeNextRun(schedule.cronExpression),
            runCount: 0,
            createdAt: now,
            updatedAt: now,
        };

        this.schedules.set(scheduleId, entry);
        this.logger.info('Scheduled scan created', { scheduleId, name: schedule.name });

        return entry;
    }

    _computeNextRun(cronExpression) {
        // Simplified next-run computation for demo purposes
        const parts = cronExpression.split(' ');
        const now = new Date();
        const hour = parseInt(parts[1], 10) || 0;
        const next = new Date(now);
        next.setHours(hour, parseInt(parts[0], 10) || 0, 0, 0);
        if (next <= now) {
            next.setDate(next.getDate() + 1);
        }
        return next.toISOString();
    }

    getSchedules() {
        return {
            schedules: Array.from(this.schedules.values()),
            total: this.schedules.size,
        };
    }

    // ------------------------------------------------------------------ //
    //  Statistics
    // ------------------------------------------------------------------ //

    getStatistics() {
        const devices = Array.from(this.devices.values());
        const scans = Array.from(this.scans.values());
        const threats = Array.from(this.threats.values());

        const now = new Date();
        const oneDayAgo = new Date(now - 86400000);
        const sevenDaysAgo = new Date(now - 7 * 86400000);
        const thirtyDaysAgo = new Date(now - 30 * 86400000);

        const scansLast24h = scans.filter(s => new Date(s.startedAt) >= oneDayAgo);
        const scansLast7d = scans.filter(s => new Date(s.startedAt) >= sevenDaysAgo);
        const threatsLast7d = threats.filter(t => new Date(t.detectedAt) >= sevenDaysAgo);
        const threatsLast30d = threats.filter(t => new Date(t.detectedAt) >= thirtyDaysAgo);

        return {
            timestamp: now.toISOString(),
            fleet: {
                totalDevices: devices.length,
                onlineDevices: devices.filter(d => d.status === 'online').length,
                protectedDevices: devices.filter(d => d.realtimeProtection).length,
                unprotectedDevices: devices.filter(d => !d.realtimeProtection).length,
            },
            scans: {
                totalScans: scans.length,
                scansLast24h: scansLast24h.length,
                scansLast7d: scansLast7d.length,
                activeScans: scans.filter(s => s.status === 'scanning' || s.status === 'queued').length,
                completedScans: scans.filter(s => s.status === 'completed').length,
                failedScans: scans.filter(s => s.status === 'failed').length,
                byType: {
                    quick: scans.filter(s => s.scanType === 'quick').length,
                    full: scans.filter(s => s.scanType === 'full').length,
                    custom: scans.filter(s => s.scanType === 'custom').length,
                    memory: scans.filter(s => s.scanType === 'memory').length,
                },
            },
            threats: {
                totalThreats: threats.length,
                threatsLast7d: threatsLast7d.length,
                threatsLast30d: threatsLast30d.length,
                bySeverity: {
                    critical: threats.filter(t => t.severity === 'critical').length,
                    high: threats.filter(t => t.severity === 'high').length,
                    medium: threats.filter(t => t.severity === 'medium').length,
                    low: threats.filter(t => t.severity === 'low').length,
                },
                byAction: {
                    quarantined: threats.filter(t => t.action === 'quarantined').length,
                    deleted: threats.filter(t => t.action === 'deleted').length,
                    blocked: threats.filter(t => t.action === 'blocked').length,
                },
                topThreats: this._getTopThreats(threats, 10),
                mostTargetedDevices: this._getMostTargetedDevices(threats, 5),
            },
            signatures: {
                currentVersion: '27180',
                lastUpdated: '2026-03-15T06:00:00.000Z',
                engineVersion: '0.104.3',
            },
            schedules: {
                total: this.schedules.size,
                enabled: Array.from(this.schedules.values()).filter(s => s.enabled).length,
            },
        };
    }

    _getTopThreats(threats, limit) {
        const counts = {};
        for (const t of threats) {
            counts[t.name] = (counts[t.name] || 0) + 1;
        }
        return Object.entries(counts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, limit)
            .map(([name, count]) => ({ name, count, severity: threats.find(t => t.name === name).severity }));
    }

    _getMostTargetedDevices(threats, limit) {
        const counts = {};
        for (const t of threats) {
            counts[t.deviceId] = (counts[t.deviceId] || 0) + 1;
        }
        return Object.entries(counts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, limit)
            .map(([deviceId, count]) => {
                const device = this.devices.get(deviceId);
                return {
                    deviceId,
                    hostname: device ? device.hostname : 'Unknown',
                    department: device ? device.department : 'Unknown',
                    threatCount: count,
                };
            });
    }

    getDashboard() {
        const stats = this.getStatistics();
        const recentThreats = Array.from(this.threats.values())
            .sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt))
            .slice(0, 10)
            .map(t => {
                const device = this.devices.get(t.deviceId);
                return {
                    ...t,
                    hostname: device ? device.hostname : 'Unknown',
                };
            });

        const recentScans = Array.from(this.scans.values())
            .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
            .slice(0, 10);

        const devicesNeedingAttention = Array.from(this.devices.values())
            .filter(d => !d.realtimeProtection || d.threatsFoundTotal > 2 || d.status === 'offline')
            .map(d => ({
                deviceId: d.deviceId,
                hostname: d.hostname,
                issues: [
                    ...(!d.realtimeProtection ? ['Realtime protection disabled'] : []),
                    ...(d.threatsFoundTotal > 2 ? [`${d.threatsFoundTotal} threats detected`] : []),
                    ...(d.status === 'offline' ? ['Device offline'] : []),
                ],
            }));

        return {
            timestamp: new Date().toISOString(),
            summary: {
                fleetHealth: stats.fleet,
                scanActivity: {
                    activeScans: stats.scans.activeScans,
                    scansToday: stats.scans.scansLast24h,
                    scansThisWeek: stats.scans.scansLast7d,
                },
                threatOverview: {
                    total: stats.threats.totalThreats,
                    thisWeek: stats.threats.threatsLast7d,
                    bySeverity: stats.threats.bySeverity,
                },
            },
            recentThreats,
            recentScans,
            devicesNeedingAttention,
            topThreats: stats.threats.topThreats,
            signatureStatus: stats.signatures,
        };
    }
}

module.exports = ScanOrchestrator;
