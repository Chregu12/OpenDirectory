const { EventEmitter } = require('events');

/**
 * Risk scoring weights and thresholds
 */
const RISK_CATEGORIES = {
    OS_VERSION: { weight: 15, name: 'OS Version' },
    UPDATE_STATUS: { weight: 15, name: 'Update Status' },
    DISK_ENCRYPTION: { weight: 15, name: 'Disk Encryption' },
    EDR_STATUS: { weight: 15, name: 'EDR / Endpoint Protection' },
    COMPLIANCE_STATE: { weight: 15, name: 'Compliance State' },
    LOGIN_ANOMALIES: { weight: 10, name: 'Login Anomalies' },
    APP_VULNERABILITIES: { weight: 15, name: 'Application Vulnerabilities' }
};

const RISK_LEVELS = {
    LOW: { label: 'Low', min: 0, max: 30 },
    MEDIUM: { label: 'Medium', min: 31, max: 60 },
    HIGH: { label: 'High', min: 61, max: 80 },
    CRITICAL: { label: 'Critical', min: 81, max: 100 }
};

/**
 * Known current OS versions for scoring purposes
 */
const CURRENT_OS_VERSIONS = {
    windows: ['Windows 11 23H2', 'Windows 11 24H2'],
    macos: ['macOS 14.3 Sonoma', 'macOS 14.4 Sonoma', 'macOS 15.0 Sequoia'],
    linux: ['Ubuntu 24.04', 'Ubuntu 22.04.4 LTS', 'Ubuntu 22.04.3 LTS'],
    ios: ['iPadOS 17.3', 'iPadOS 17.4', 'iOS 17.3', 'iOS 17.4']
};

class RiskScorer extends EventEmitter {
    constructor() {
        super();
        this.scoreHistory = new Map();
        this.anomalyData = new Map();

        // Seed some anomaly data for demo devices
        this._seedAnomalyData();
    }

    /**
     * Seed demo anomaly data
     */
    _seedAnomalyData() {
        this.anomalyData.set('dev-001', { failedLogins: 0, unusualLocations: 0, offHoursLogins: 1 });
        this.anomalyData.set('dev-002', { failedLogins: 1, unusualLocations: 0, offHoursLogins: 2 });
        this.anomalyData.set('dev-003', { failedLogins: 5, unusualLocations: 2, offHoursLogins: 8 });
        this.anomalyData.set('dev-004', { failedLogins: 0, unusualLocations: 0, offHoursLogins: 15 });
        this.anomalyData.set('dev-005', { failedLogins: 0, unusualLocations: 0, offHoursLogins: 0 });
        this.anomalyData.set('dev-006', { failedLogins: 2, unusualLocations: 1, offHoursLogins: 3 });
        this.anomalyData.set('dev-007', { failedLogins: 12, unusualLocations: 3, offHoursLogins: 5 });
        this.anomalyData.set('dev-008', { failedLogins: 0, unusualLocations: 1, offHoursLogins: 0 });
    }

    /**
     * Calculate the complete risk score for a device
     */
    calculateRiskScore(device) {
        const breakdown = {};
        let totalRiskPoints = 0;

        // 1. OS Version scoring
        const osScore = this._scoreOsVersion(device);
        breakdown.osVersion = {
            category: RISK_CATEGORIES.OS_VERSION.name,
            weight: RISK_CATEGORIES.OS_VERSION.weight,
            rawScore: osScore.score,
            weightedScore: Math.round(osScore.score * (RISK_CATEGORIES.OS_VERSION.weight / 100) * 100) / 100,
            details: osScore.details
        };
        totalRiskPoints += breakdown.osVersion.weightedScore;

        // 2. Update Status scoring
        const updateScore = this._scoreUpdateStatus(device);
        breakdown.updateStatus = {
            category: RISK_CATEGORIES.UPDATE_STATUS.name,
            weight: RISK_CATEGORIES.UPDATE_STATUS.weight,
            rawScore: updateScore.score,
            weightedScore: Math.round(updateScore.score * (RISK_CATEGORIES.UPDATE_STATUS.weight / 100) * 100) / 100,
            details: updateScore.details
        };
        totalRiskPoints += breakdown.updateStatus.weightedScore;

        // 3. Disk Encryption scoring
        const encryptionScore = this._scoreDiskEncryption(device);
        breakdown.diskEncryption = {
            category: RISK_CATEGORIES.DISK_ENCRYPTION.name,
            weight: RISK_CATEGORIES.DISK_ENCRYPTION.weight,
            rawScore: encryptionScore.score,
            weightedScore: Math.round(encryptionScore.score * (RISK_CATEGORIES.DISK_ENCRYPTION.weight / 100) * 100) / 100,
            details: encryptionScore.details
        };
        totalRiskPoints += breakdown.diskEncryption.weightedScore;

        // 4. EDR Status scoring
        const edrScore = this._scoreEdrStatus(device);
        breakdown.edrStatus = {
            category: RISK_CATEGORIES.EDR_STATUS.name,
            weight: RISK_CATEGORIES.EDR_STATUS.weight,
            rawScore: edrScore.score,
            weightedScore: Math.round(edrScore.score * (RISK_CATEGORIES.EDR_STATUS.weight / 100) * 100) / 100,
            details: edrScore.details
        };
        totalRiskPoints += breakdown.edrStatus.weightedScore;

        // 5. Compliance State scoring
        const complianceScore = this._scoreComplianceState(device);
        breakdown.complianceState = {
            category: RISK_CATEGORIES.COMPLIANCE_STATE.name,
            weight: RISK_CATEGORIES.COMPLIANCE_STATE.weight,
            rawScore: complianceScore.score,
            weightedScore: Math.round(complianceScore.score * (RISK_CATEGORIES.COMPLIANCE_STATE.weight / 100) * 100) / 100,
            details: complianceScore.details
        };
        totalRiskPoints += breakdown.complianceState.weightedScore;

        // 6. Login Anomalies scoring
        const loginScore = this._scoreLoginAnomalies(device);
        breakdown.loginAnomalies = {
            category: RISK_CATEGORIES.LOGIN_ANOMALIES.name,
            weight: RISK_CATEGORIES.LOGIN_ANOMALIES.weight,
            rawScore: loginScore.score,
            weightedScore: Math.round(loginScore.score * (RISK_CATEGORIES.LOGIN_ANOMALIES.weight / 100) * 100) / 100,
            details: loginScore.details
        };
        totalRiskPoints += breakdown.loginAnomalies.weightedScore;

        // 7. App Vulnerabilities scoring
        const appScore = this._scoreAppVulnerabilities(device);
        breakdown.appVulnerabilities = {
            category: RISK_CATEGORIES.APP_VULNERABILITIES.name,
            weight: RISK_CATEGORIES.APP_VULNERABILITIES.weight,
            rawScore: appScore.score,
            weightedScore: Math.round(appScore.score * (RISK_CATEGORIES.APP_VULNERABILITIES.weight / 100) * 100) / 100,
            details: appScore.details
        };
        totalRiskPoints += breakdown.appVulnerabilities.weightedScore;

        // Calculate final score (0-100)
        const finalScore = Math.min(100, Math.round(totalRiskPoints));
        const riskLevel = this._getRiskLevel(finalScore);

        const result = {
            deviceId: device.id,
            hostname: device.hostname,
            overallScore: finalScore,
            riskLevel: riskLevel.label,
            breakdown,
            recommendations: this._generateRecommendations(breakdown, device),
            calculatedAt: new Date().toISOString()
        };

        // Store in history
        if (!this.scoreHistory.has(device.id)) {
            this.scoreHistory.set(device.id, []);
        }
        this.scoreHistory.get(device.id).push({
            score: finalScore,
            riskLevel: riskLevel.label,
            timestamp: result.calculatedAt
        });

        // Keep only last 100 scores per device
        const history = this.scoreHistory.get(device.id);
        if (history.length > 100) {
            history.splice(0, history.length - 100);
        }

        this.emit('riskScoreCalculated', result);

        return result;
    }

    /**
     * Score OS version risk
     */
    _scoreOsVersion(device) {
        const osVersion = device.osVersion || '';
        const platform = (device.platform || '').toLowerCase();

        let platformVersions;
        if (platform === 'windows') {
            platformVersions = CURRENT_OS_VERSIONS.windows;
        } else if (platform === 'macos') {
            platformVersions = CURRENT_OS_VERSIONS.macos;
        } else if (platform === 'linux') {
            platformVersions = CURRENT_OS_VERSIONS.linux;
        } else if (platform === 'ios' || platform === 'ipados') {
            platformVersions = CURRENT_OS_VERSIONS.ios;
        } else {
            return { score: 50, details: `Unknown platform: ${platform}` };
        }

        const isCurrent = platformVersions.some(v => osVersion.includes(v) || v.includes(osVersion));
        if (isCurrent) {
            return { score: 0, details: `OS version ${osVersion} is current` };
        }

        // Check if it's one major version behind
        if (platform === 'windows' && osVersion.includes('Windows 11')) {
            return { score: 30, details: `OS version ${osVersion} is slightly outdated` };
        }
        if (platform === 'windows' && osVersion.includes('Windows 10')) {
            return { score: 70, details: `OS version ${osVersion} is nearing end of life` };
        }

        return { score: 60, details: `OS version ${osVersion} may be outdated` };
    }

    /**
     * Score update status risk
     */
    _scoreUpdateStatus(device) {
        const pendingUpdates = device.pendingUpdates || 0;

        if (pendingUpdates === 0) {
            return { score: 0, details: 'All updates are installed' };
        } else if (pendingUpdates <= 2) {
            return { score: 20, details: `${pendingUpdates} pending update(s)` };
        } else if (pendingUpdates <= 5) {
            return { score: 50, details: `${pendingUpdates} pending updates` };
        } else if (pendingUpdates <= 10) {
            return { score: 75, details: `${pendingUpdates} pending updates - significant risk` };
        }
        return { score: 100, details: `${pendingUpdates} pending updates - critical risk` };
    }

    /**
     * Score disk encryption risk
     */
    _scoreDiskEncryption(device) {
        const platform = (device.platform || '').toLowerCase();

        if (platform === 'windows') {
            if (device.bitlockerEnabled) {
                return { score: 0, details: 'BitLocker is enabled' };
            }
            return { score: 100, details: 'BitLocker is not enabled' };
        }
        if (platform === 'macos') {
            if (device.filevaultEnabled) {
                return { score: 0, details: 'FileVault is enabled' };
            }
            return { score: 100, details: 'FileVault is not enabled' };
        }
        if (platform === 'linux') {
            if (device.luksEnabled) {
                return { score: 0, details: 'LUKS encryption is enabled' };
            }
            return { score: 100, details: 'Disk encryption is not enabled' };
        }
        if (platform === 'ios' || platform === 'ipados') {
            // iOS devices are encrypted by default
            return { score: 0, details: 'Device encryption is enabled by default' };
        }

        return { score: 50, details: 'Encryption status unknown' };
    }

    /**
     * Score EDR / endpoint protection status
     */
    _scoreEdrStatus(device) {
        if (device.edrInstalled) {
            return { score: 0, details: 'EDR agent is installed and active' };
        }

        const platform = (device.platform || '').toLowerCase();
        if (platform === 'ios' || platform === 'ipados') {
            return { score: 30, details: 'Mobile EDR not installed (lower risk for managed iOS devices)' };
        }

        return { score: 100, details: 'EDR agent is not installed' };
    }

    /**
     * Score compliance state risk
     */
    _scoreComplianceState(device) {
        const state = device.state;

        switch (state) {
            case 'Compliant':
                return { score: 0, details: 'Device is fully compliant' };
            case 'Configured':
                return { score: 20, details: 'Device is configured but compliance not yet verified' };
            case 'Enrolled':
                return { score: 40, details: 'Device is enrolled but not yet configured' };
            case 'Provisioned':
                return { score: 50, details: 'Device is provisioned but not enrolled' };
            case 'Non-Compliant':
                return { score: 80, details: 'Device is non-compliant' };
            case 'Retiring':
                return { score: 60, details: 'Device is being retired' };
            case 'Retired':
                return { score: 30, details: 'Device is retired' };
            default:
                return { score: 50, details: `Unknown state: ${state}` };
        }
    }

    /**
     * Score login anomalies
     */
    _scoreLoginAnomalies(device) {
        const anomalyInfo = this.anomalyData.get(device.id) || {
            failedLogins: 0,
            unusualLocations: 0,
            offHoursLogins: 0
        };

        let score = 0;
        const details = [];

        // Failed logins (each adds 8 points, max contribution 40)
        if (anomalyInfo.failedLogins > 0) {
            const failedScore = Math.min(40, anomalyInfo.failedLogins * 8);
            score += failedScore;
            details.push(`${anomalyInfo.failedLogins} failed login attempt(s)`);
        }

        // Unusual locations (each adds 15 points, max 30)
        if (anomalyInfo.unusualLocations > 0) {
            const locationScore = Math.min(30, anomalyInfo.unusualLocations * 15);
            score += locationScore;
            details.push(`${anomalyInfo.unusualLocations} login(s) from unusual location(s)`);
        }

        // Off-hours logins (each adds 3 points, max 30)
        if (anomalyInfo.offHoursLogins > 0) {
            const offHoursScore = Math.min(30, anomalyInfo.offHoursLogins * 3);
            score += offHoursScore;
            details.push(`${anomalyInfo.offHoursLogins} off-hours login(s)`);
        }

        score = Math.min(100, score);

        return {
            score,
            details: details.length > 0 ? details.join('; ') : 'No login anomalies detected'
        };
    }

    /**
     * Score application vulnerabilities
     */
    _scoreAppVulnerabilities(device) {
        const apps = device.apps || [];

        // Simulated vulnerability data for common apps
        const knownVulnerableVersions = {
            'Chrome': { vulnerable: false, score: 0 },
            'Firefox': { vulnerable: false, score: 0 },
            'Zoom': { vulnerable: true, score: 15 },
            'Slack': { vulnerable: false, score: 0 },
            'Docker': { vulnerable: false, score: 0 },
            'VS Code': { vulnerable: false, score: 0 },
            'Microsoft 365': { vulnerable: false, score: 0 }
        };

        let totalVulnScore = 0;
        const vulnerableApps = [];

        for (const app of apps) {
            const vulnInfo = knownVulnerableVersions[app];
            if (vulnInfo && vulnInfo.vulnerable) {
                totalVulnScore += vulnInfo.score;
                vulnerableApps.push(app);
            }
        }

        // Additional scoring based on number of installed apps (more apps = larger attack surface)
        if (apps.length > 10) {
            totalVulnScore += 10;
        }

        totalVulnScore = Math.min(100, totalVulnScore);

        return {
            score: totalVulnScore,
            details: vulnerableApps.length > 0
                ? `Vulnerable apps detected: ${vulnerableApps.join(', ')}`
                : 'No known application vulnerabilities detected'
        };
    }

    /**
     * Determine risk level from numeric score
     */
    _getRiskLevel(score) {
        for (const level of Object.values(RISK_LEVELS)) {
            if (score >= level.min && score <= level.max) {
                return level;
            }
        }
        return RISK_LEVELS.CRITICAL;
    }

    /**
     * Generate remediation recommendations based on risk breakdown
     */
    _generateRecommendations(breakdown, device) {
        const recommendations = [];

        if (breakdown.osVersion.rawScore >= 50) {
            recommendations.push({
                priority: 'high',
                category: 'OS Version',
                action: `Upgrade ${device.platform} to the latest supported version`,
                impact: 'Reduces OS vulnerability exposure'
            });
        }

        if (breakdown.updateStatus.rawScore >= 30) {
            recommendations.push({
                priority: breakdown.updateStatus.rawScore >= 70 ? 'critical' : 'medium',
                category: 'Updates',
                action: `Install ${device.pendingUpdates} pending update(s)`,
                impact: 'Patches known security vulnerabilities'
            });
        }

        if (breakdown.diskEncryption.rawScore >= 50) {
            const encryptionType = device.platform === 'Windows' ? 'BitLocker' :
                device.platform === 'macOS' ? 'FileVault' : 'disk encryption';
            recommendations.push({
                priority: 'critical',
                category: 'Disk Encryption',
                action: `Enable ${encryptionType} on this device`,
                impact: 'Protects data at rest from unauthorized access'
            });
        }

        if (breakdown.edrStatus.rawScore >= 50) {
            recommendations.push({
                priority: 'critical',
                category: 'Endpoint Protection',
                action: 'Install and activate EDR agent',
                impact: 'Provides real-time threat detection and response'
            });
        }

        if (breakdown.complianceState.rawScore >= 50) {
            recommendations.push({
                priority: 'high',
                category: 'Compliance',
                action: 'Review and remediate compliance violations',
                impact: 'Brings device into policy compliance'
            });
        }

        if (breakdown.loginAnomalies.rawScore >= 30) {
            recommendations.push({
                priority: breakdown.loginAnomalies.rawScore >= 60 ? 'high' : 'medium',
                category: 'Login Security',
                action: 'Investigate login anomalies and consider enforcing MFA',
                impact: 'Reduces risk of unauthorized access'
            });
        }

        if (breakdown.appVulnerabilities.rawScore >= 20) {
            recommendations.push({
                priority: 'medium',
                category: 'Application Security',
                action: 'Update vulnerable applications to latest versions',
                impact: 'Reduces application-level attack surface'
            });
        }

        // Sort by priority
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        recommendations.sort((a, b) => (priorityOrder[a.priority] || 99) - (priorityOrder[b.priority] || 99));

        return recommendations;
    }

    /**
     * Get risk score history for a device
     */
    getScoreHistory(deviceId) {
        return this.scoreHistory.get(deviceId) || [];
    }
}

module.exports = RiskScorer;
