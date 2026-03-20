'use strict';

const { v4: uuidv4 } = require('uuid');

// ====================================================================== //
//  ThreatIntelligence - Fleet-wide threat analysis and IoC tracking
// ====================================================================== //

class ThreatIntelligence {
    constructor(orchestrator, logger) {
        this.orchestrator = orchestrator;
        this.logger = logger;
        this.iocs = new Map();
        this.externalFeeds = [];
        this.threatTrends = [];

        this._seedData();
        this.logger.info('ThreatIntelligence initialized', { iocCount: this.iocs.size });
    }

    _seedData() {
        this._seedIoCs();
        this._seedExternalFeeds();
        this._buildThreatTrends();
    }

    _seedIoCs() {
        const iocDefs = [
            {
                type: 'sha256',
                value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                threatName: 'Win.Trojan.Agent-798345',
                severity: 'high',
                source: 'internal_scan',
                confidence: 95,
                tags: ['trojan', 'agent', 'persistence'],
            },
            {
                type: 'sha256',
                value: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
                threatName: 'Win.Ransomware.Locky-9876',
                severity: 'critical',
                source: 'internal_scan',
                confidence: 99,
                tags: ['ransomware', 'locky', 'encryption'],
            },
            {
                type: 'domain',
                value: 'malware-c2.evil-domain.com',
                threatName: 'Win.Trojan.Agent-798345',
                severity: 'high',
                source: 'threat_feed',
                confidence: 90,
                tags: ['c2', 'command-and-control', 'trojan'],
            },
            {
                type: 'ip',
                value: '185.220.101.45',
                threatName: 'Generic.C2.Communication',
                severity: 'high',
                source: 'threat_feed',
                confidence: 85,
                tags: ['c2', 'tor-exit', 'suspicious'],
            },
            {
                type: 'ip',
                value: '91.219.236.174',
                threatName: 'Linux.Rootkit.Beurk-333',
                severity: 'critical',
                source: 'incident_response',
                confidence: 92,
                tags: ['rootkit', 'backdoor', 'linux'],
            },
            {
                type: 'domain',
                value: 'update-checker.malicious-cdn.net',
                threatName: 'Win.Malware.Emotet-345',
                severity: 'high',
                source: 'threat_feed',
                confidence: 88,
                tags: ['emotet', 'dropper', 'banking'],
            },
            {
                type: 'url',
                value: 'https://phishing-portal.com/login/office365',
                threatName: 'Phishing.Office365.Credential',
                severity: 'high',
                source: 'user_report',
                confidence: 95,
                tags: ['phishing', 'credential-theft', 'office365'],
            },
            {
                type: 'sha256',
                value: '5d41402abc4b2a76b9719d911017c592f35f15b3e61b1a15dc3eaf6d4a3a5c01',
                threatName: 'Doc.Dropper.Macro-234',
                severity: 'medium',
                source: 'internal_scan',
                confidence: 87,
                tags: ['macro', 'dropper', 'document'],
            },
            {
                type: 'email',
                value: 'invoice-department@spoofed-company.com',
                threatName: 'Phishing.Invoice.BEC',
                severity: 'medium',
                source: 'user_report',
                confidence: 80,
                tags: ['phishing', 'bec', 'social-engineering'],
            },
            {
                type: 'registry_key',
                value: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHelper',
                threatName: 'Win.Trojan.Agent-798345',
                severity: 'high',
                source: 'internal_scan',
                confidence: 93,
                tags: ['persistence', 'autorun', 'trojan'],
            },
            {
                type: 'file_path',
                value: '/tmp/.ICE-unix/rootkit',
                threatName: 'Linux.Rootkit.Beurk-333',
                severity: 'critical',
                source: 'internal_scan',
                confidence: 97,
                tags: ['rootkit', 'hidden', 'linux'],
            },
            {
                type: 'mutex',
                value: 'Global\\EmotetMutex_v4',
                threatName: 'Win.Malware.Emotet-345',
                severity: 'high',
                source: 'threat_feed',
                confidence: 91,
                tags: ['emotet', 'mutex', 'persistence'],
            },
        ];

        for (const ioc of iocDefs) {
            const iocId = `ioc-${uuidv4().slice(0, 10)}`;
            const firstSeen = new Date(Date.now() - Math.floor(Math.random() * 30) * 86400000);
            const lastSeen = new Date(Date.now() - Math.floor(Math.random() * 3) * 86400000);

            this.iocs.set(iocId, {
                iocId,
                ...ioc,
                firstSeen: firstSeen.toISOString(),
                lastSeen: lastSeen.toISOString(),
                sightings: Math.floor(Math.random() * 20) + 1,
                affectedDevices: this._randomDeviceIds(Math.floor(Math.random() * 4) + 1),
                status: 'active',
                createdAt: firstSeen.toISOString(),
                updatedAt: lastSeen.toISOString(),
            });
        }
    }

    _randomDeviceIds(count) {
        const allIds = Array.from(this.orchestrator.devices.keys());
        const shuffled = allIds.sort(() => Math.random() - 0.5);
        return shuffled.slice(0, Math.min(count, allIds.length));
    }

    _seedExternalFeeds() {
        this.externalFeeds = [
            {
                feedId: 'feed-clamav-official',
                name: 'ClamAV Official Signatures',
                type: 'signature',
                url: 'https://database.clamav.net',
                enabled: true,
                lastSync: new Date(Date.now() - 3600000).toISOString(),
                nextSync: new Date(Date.now() + 3600000).toISOString(),
                syncFrequency: 'hourly',
                indicatorCount: 8742156,
                status: 'active',
            },
            {
                feedId: 'feed-abuse-ch',
                name: 'abuse.ch MalwareBazaar',
                type: 'hash',
                url: 'https://bazaar.abuse.ch/export/csv/recent/',
                enabled: true,
                lastSync: new Date(Date.now() - 7200000).toISOString(),
                nextSync: new Date(Date.now() + 7200000).toISOString(),
                syncFrequency: 'every_2_hours',
                indicatorCount: 245678,
                status: 'active',
            },
            {
                feedId: 'feed-alienvault-otx',
                name: 'AlienVault OTX',
                type: 'mixed',
                url: 'https://otx.alienvault.com/api/v1/indicators',
                enabled: true,
                lastSync: new Date(Date.now() - 14400000).toISOString(),
                nextSync: new Date(Date.now() + 14400000).toISOString(),
                syncFrequency: 'every_4_hours',
                indicatorCount: 1567890,
                status: 'active',
            },
            {
                feedId: 'feed-virustotal',
                name: 'VirusTotal Intelligence',
                type: 'hash',
                url: 'https://www.virustotal.com/api/v3/intelligence',
                enabled: false,
                lastSync: new Date(Date.now() - 86400000).toISOString(),
                nextSync: null,
                syncFrequency: 'daily',
                indicatorCount: 0,
                status: 'disabled',
                note: 'Requires premium API key',
            },
            {
                feedId: 'feed-emerging-threats',
                name: 'Emerging Threats Ruleset',
                type: 'rules',
                url: 'https://rules.emergingthreats.net',
                enabled: true,
                lastSync: new Date(Date.now() - 43200000).toISOString(),
                nextSync: new Date(Date.now() + 43200000).toISOString(),
                syncFrequency: 'every_12_hours',
                indicatorCount: 35678,
                status: 'active',
            },
        ];
    }

    _buildThreatTrends() {
        const threats = Array.from(this.orchestrator.threats.values());

        // Daily trend for last 14 days
        for (let i = 13; i >= 0; i--) {
            const date = new Date(Date.now() - i * 86400000);
            const dateStr = date.toISOString().split('T')[0];
            const dayStart = new Date(dateStr);
            const dayEnd = new Date(dayStart.getTime() + 86400000);

            const dayThreats = threats.filter(t => {
                const d = new Date(t.detectedAt);
                return d >= dayStart && d < dayEnd;
            });

            this.threatTrends.push({
                date: dateStr,
                total: dayThreats.length,
                critical: dayThreats.filter(t => t.severity === 'critical').length,
                high: dayThreats.filter(t => t.severity === 'high').length,
                medium: dayThreats.filter(t => t.severity === 'medium').length,
                low: dayThreats.filter(t => t.severity === 'low').length,
                uniqueThreats: new Set(dayThreats.map(t => t.name)).size,
                affectedDevices: new Set(dayThreats.map(t => t.deviceId)).size,
            });
        }
    }

    // ------------------------------------------------------------------ //
    //  Threat aggregation
    // ------------------------------------------------------------------ //

    getFleetThreatSummary() {
        const threats = Array.from(this.orchestrator.threats.values());
        const devices = Array.from(this.orchestrator.devices.values());

        const now = new Date();
        const oneDayAgo = new Date(now - 86400000);
        const sevenDaysAgo = new Date(now - 7 * 86400000);

        const threatsByName = {};
        for (const t of threats) {
            if (!threatsByName[t.name]) {
                threatsByName[t.name] = { name: t.name, severity: t.severity, category: t.category, count: 0, devices: new Set() };
            }
            threatsByName[t.name].count++;
            threatsByName[t.name].devices.add(t.deviceId);
        }

        const topThreats = Object.values(threatsByName)
            .map(t => ({ ...t, affectedDevices: t.devices.size, devices: undefined }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);

        const threatsByCategory = {};
        for (const t of threats) {
            threatsByCategory[t.category] = (threatsByCategory[t.category] || 0) + 1;
        }

        const threatsByPlatform = {};
        for (const t of threats) {
            const device = this.orchestrator.devices.get(t.deviceId);
            const platform = device ? device.platform : 'unknown';
            threatsByPlatform[platform] = (threatsByPlatform[platform] || 0) + 1;
        }

        const threatsByDepartment = {};
        for (const t of threats) {
            const device = this.orchestrator.devices.get(t.deviceId);
            const dept = device ? device.department : 'Unknown';
            threatsByDepartment[dept] = (threatsByDepartment[dept] || 0) + 1;
        }

        return {
            timestamp: now.toISOString(),
            overview: {
                totalThreats: threats.length,
                threatsLast24h: threats.filter(t => new Date(t.detectedAt) >= oneDayAgo).length,
                threatsLast7d: threats.filter(t => new Date(t.detectedAt) >= sevenDaysAgo).length,
                uniqueThreatNames: new Set(threats.map(t => t.name)).size,
                affectedDevices: new Set(threats.map(t => t.deviceId)).size,
                totalDevices: devices.length,
            },
            bySeverity: {
                critical: threats.filter(t => t.severity === 'critical').length,
                high: threats.filter(t => t.severity === 'high').length,
                medium: threats.filter(t => t.severity === 'medium').length,
                low: threats.filter(t => t.severity === 'low').length,
            },
            byCategory: threatsByCategory,
            byPlatform: threatsByPlatform,
            byDepartment: threatsByDepartment,
            topThreats,
            trends: this.threatTrends,
        };
    }

    // ------------------------------------------------------------------ //
    //  Severity classification
    // ------------------------------------------------------------------ //

    classifyThreat(threatName) {
        if (/Ransomware|Rootkit/i.test(threatName)) return 'critical';
        if (/Trojan|Exploit|Backdoor|Worm|Keylogger|Infostealer|Banker/i.test(threatName)) return 'high';
        if (/Dropper|Webshell|Miner/i.test(threatName)) return 'medium';
        if (/PUA|Adware|Packer/i.test(threatName)) return 'low';
        return 'medium';
    }

    // ------------------------------------------------------------------ //
    //  IoC operations
    // ------------------------------------------------------------------ //

    getIoCs(filters = {}) {
        let iocs = Array.from(this.iocs.values());

        if (filters.type) {
            iocs = iocs.filter(i => i.type === filters.type);
        }
        if (filters.severity) {
            iocs = iocs.filter(i => i.severity === filters.severity);
        }
        if (filters.source) {
            iocs = iocs.filter(i => i.source === filters.source);
        }
        if (filters.status) {
            iocs = iocs.filter(i => i.status === filters.status);
        }
        if (filters.tag) {
            iocs = iocs.filter(i => i.tags.includes(filters.tag));
        }

        iocs.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));

        const page = parseInt(filters.page, 10) || 1;
        const limit = parseInt(filters.limit, 10) || 50;
        const offset = (page - 1) * limit;

        return {
            iocs: iocs.slice(offset, offset + limit),
            pagination: { page, limit, total: iocs.length, totalPages: Math.ceil(iocs.length / limit) },
            summary: {
                total: iocs.length,
                byType: {
                    sha256: iocs.filter(i => i.type === 'sha256').length,
                    domain: iocs.filter(i => i.type === 'domain').length,
                    ip: iocs.filter(i => i.type === 'ip').length,
                    url: iocs.filter(i => i.type === 'url').length,
                    email: iocs.filter(i => i.type === 'email').length,
                    file_path: iocs.filter(i => i.type === 'file_path').length,
                    registry_key: iocs.filter(i => i.type === 'registry_key').length,
                    mutex: iocs.filter(i => i.type === 'mutex').length,
                },
                bySeverity: {
                    critical: iocs.filter(i => i.severity === 'critical').length,
                    high: iocs.filter(i => i.severity === 'high').length,
                    medium: iocs.filter(i => i.severity === 'medium').length,
                    low: iocs.filter(i => i.severity === 'low').length,
                },
            },
        };
    }

    getIoC(iocId) {
        const ioc = this.iocs.get(iocId);
        if (!ioc) {
            throw Object.assign(new Error(`IoC ${iocId} not found`), { statusCode: 404 });
        }

        const affectedDeviceDetails = ioc.affectedDevices.map(did => {
            const device = this.orchestrator.devices.get(did);
            return device
                ? { deviceId: did, hostname: device.hostname, platform: device.platform, department: device.department }
                : { deviceId: did, hostname: 'Unknown' };
        });

        return {
            ...ioc,
            affectedDeviceDetails,
        };
    }

    // ------------------------------------------------------------------ //
    //  External feeds
    // ------------------------------------------------------------------ //

    getExternalFeeds() {
        return {
            feeds: this.externalFeeds,
            total: this.externalFeeds.length,
            active: this.externalFeeds.filter(f => f.status === 'active').length,
            totalIndicators: this.externalFeeds.reduce((sum, f) => sum + f.indicatorCount, 0),
        };
    }

    // ------------------------------------------------------------------ //
    //  Trend analysis
    // ------------------------------------------------------------------ //

    getTrends(period) {
        if (period === 'weekly') {
            // Aggregate daily trends into weekly
            const weeks = [];
            for (let i = 0; i < this.threatTrends.length; i += 7) {
                const weekData = this.threatTrends.slice(i, i + 7);
                if (weekData.length === 0) continue;
                weeks.push({
                    weekStart: weekData[0].date,
                    weekEnd: weekData[weekData.length - 1].date,
                    total: weekData.reduce((sum, d) => sum + d.total, 0),
                    critical: weekData.reduce((sum, d) => sum + d.critical, 0),
                    high: weekData.reduce((sum, d) => sum + d.high, 0),
                    medium: weekData.reduce((sum, d) => sum + d.medium, 0),
                    low: weekData.reduce((sum, d) => sum + d.low, 0),
                });
            }
            return { period: 'weekly', data: weeks };
        }

        return { period: 'daily', data: this.threatTrends };
    }
}

module.exports = ThreatIntelligence;
