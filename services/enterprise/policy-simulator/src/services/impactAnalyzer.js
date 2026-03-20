'use strict';

const { v4: uuidv4 } = require('uuid');

/**
 * ImpactAnalyzer - Analyzes the impact of a policy on devices, users,
 * compliance posture, and operational cost.
 *
 * Works alongside SimulationEngine but focuses on higher-level aggregation
 * and reporting rather than per-device evaluation.
 */
class ImpactAnalyzer {
    constructor(simulationEngine, logger) {
        this.engine = simulationEngine;
        this.logger = logger;
    }

    /**
     * Generate a full impact report for a given policy.
     *
     * @param {string} policyId
     * @returns {Object} Impact report
     */
    analyze(policyId) {
        this.logger.info('Starting impact analysis', { policyId });

        const policy = this.engine.getPolicy(policyId);
        if (!policy) {
            const err = new Error(`Policy not found: ${policyId}`);
            err.statusCode = 404;
            throw err;
        }

        const affectedDevices = this.engine.getAssignedDevices(policyId);

        const report = {
            reportId: uuidv4(),
            policyId,
            policyName: policy.name,
            policyType: policy.type,
            generatedAt: new Date().toISOString(),
            scope: this._buildScopeBreakdown(affectedDevices),
            compliance: this._buildComplianceAnalysis(affectedDevices, policy),
            userImpact: this._buildUserImpact(affectedDevices, policy),
            operationalImpact: this._buildOperationalImpact(affectedDevices, policy),
            settingCoverage: this._buildSettingCoverage(affectedDevices, policy),
            riskMatrix: this._buildRiskMatrix(affectedDevices, policy),
        };

        this.logger.info('Impact analysis completed', {
            reportId: report.reportId,
            policyId,
            devicesAnalyzed: affectedDevices.length,
        });

        return report;
    }

    // ------------------------------------------------------------------ //
    //  Report section builders
    // ------------------------------------------------------------------ //

    /**
     * Break down affected devices by platform, department, and remote status.
     */
    _buildScopeBreakdown(devices) {
        const byPlatform = {};
        const byDepartment = {};
        let remoteCount = 0;
        let onPremCount = 0;

        for (const device of devices) {
            byPlatform[device.platform] = (byPlatform[device.platform] || 0) + 1;
            byDepartment[device.department] = (byDepartment[device.department] || 0) + 1;
            if (device.isRemote) remoteCount++;
            else onPremCount++;
        }

        return {
            totalDevices: devices.length,
            byPlatform,
            byDepartment,
            byLocation: { remote: remoteCount, onPremise: onPremCount },
            uniqueUsers: new Set(devices.map(d => d.owner)).size,
        };
    }

    /**
     * Evaluate current compliance rates against the policy.
     */
    _buildComplianceAnalysis(devices, policy) {
        let compliant = 0;
        let nonCompliant = 0;
        const nonCompliantSettings = {};

        for (const device of devices) {
            let deviceCompliant = true;

            for (const [key, required] of Object.entries(policy.settings)) {
                const actual = device.currentState[key];
                if (actual === undefined) continue;

                let settingOk = true;
                if (typeof required === 'number' && typeof actual === 'number') {
                    settingOk = actual >= required;
                } else if (typeof required === 'boolean') {
                    settingOk = actual === required;
                } else if (typeof required === 'string') {
                    settingOk = actual === required;
                }

                if (!settingOk) {
                    deviceCompliant = false;
                    nonCompliantSettings[key] = (nonCompliantSettings[key] || 0) + 1;
                }
            }

            if (deviceCompliant) compliant++;
            else nonCompliant++;
        }

        const total = devices.length;

        return {
            compliant,
            nonCompliant,
            complianceRate: total > 0 ? Math.round((compliant / total) * 10000) / 100 : 0,
            nonCompliantSettingsBreakdown: Object.entries(nonCompliantSettings)
                .map(([setting, count]) => ({
                    setting,
                    nonCompliantDevices: count,
                    percentNonCompliant: total > 0 ? Math.round((count / total) * 10000) / 100 : 0,
                }))
                .sort((a, b) => b.nonCompliantDevices - a.nonCompliantDevices),
        };
    }

    /**
     * Aggregate impact at the user level.
     */
    _buildUserImpact(devices, policy) {
        const userMap = new Map();

        for (const device of devices) {
            if (!userMap.has(device.owner)) {
                userMap.set(device.owner, {
                    userId: device.owner,
                    devices: [],
                    departments: new Set(),
                    platforms: new Set(),
                    isRemote: false,
                });
            }
            const entry = userMap.get(device.owner);
            entry.devices.push(device.id);
            entry.departments.add(device.department);
            entry.platforms.add(device.platform);
            if (device.isRemote) entry.isRemote = true;
        }

        const users = [...userMap.values()].map(u => ({
            userId: u.userId,
            deviceCount: u.devices.length,
            departments: [...u.departments],
            platforms: [...u.platforms],
            isRemote: u.isRemote,
        }));

        return {
            totalUsersAffected: users.length,
            usersWithMultipleDevices: users.filter(u => u.deviceCount > 1).length,
            remoteUsersAffected: users.filter(u => u.isRemote).length,
            users: users.slice(0, 50), // cap to 50 for response size
        };
    }

    /**
     * Estimate operational cost of enforcing / remediating the policy.
     */
    _buildOperationalImpact(devices, policy) {
        let rebootsRequired = 0;
        let totalRemediationMinutes = 0;
        const remediationByType = {};

        const rebootSettings = new Set([
            'encryptionRequired', 'firewallEnabled', 'osUpdateChannel',
            'kernelProtection', 'secureBootRequired',
        ]);

        const applyTimes = {
            passwordMinLength: 1,
            passwordRequireComplexity: 1,
            screenLockTimeoutMinutes: 1,
            firewallEnabled: 5,
            encryptionRequired: 30,
            autoUpdateEnabled: 2,
            osUpdateChannel: 15,
            vpnRequired: 3,
            antivirusRequired: 10,
        };

        for (const device of devices) {
            let deviceNeedsReboot = false;

            for (const [key, required] of Object.entries(policy.settings)) {
                const actual = device.currentState[key];
                if (actual === undefined) continue;

                let settingOk;
                if (typeof required === 'number' && typeof actual === 'number') {
                    settingOk = actual >= required;
                } else {
                    settingOk = JSON.stringify(actual) === JSON.stringify(required);
                }

                if (!settingOk) {
                    const time = applyTimes[key] || 2;
                    totalRemediationMinutes += time;
                    remediationByType[key] = (remediationByType[key] || 0) + time;

                    if (rebootSettings.has(key)) deviceNeedsReboot = true;
                }
            }

            if (deviceNeedsReboot) rebootsRequired++;
        }

        return {
            estimatedRemediationMinutes: totalRemediationMinutes,
            estimatedRemediationHours: Math.round(totalRemediationMinutes / 60 * 100) / 100,
            devicesRequiringReboot: rebootsRequired,
            rebootPercentage: devices.length > 0
                ? Math.round((rebootsRequired / devices.length) * 10000) / 100
                : 0,
            remediationBySettingMinutes: remediationByType,
            recommendedMaintenanceWindow: rebootsRequired > 50
                ? 'weekend'
                : rebootsRequired > 10
                    ? 'overnight'
                    : 'anytime',
        };
    }

    /**
     * Show which settings the policy controls and their current distribution.
     */
    _buildSettingCoverage(devices, policy) {
        const coverage = [];

        for (const [key, required] of Object.entries(policy.settings)) {
            const distribution = {};
            let matchCount = 0;

            for (const device of devices) {
                const val = device.currentState[key];
                const valStr = String(val);
                distribution[valStr] = (distribution[valStr] || 0) + 1;

                let matches;
                if (typeof required === 'number' && typeof val === 'number') {
                    matches = val >= required;
                } else {
                    matches = JSON.stringify(val) === JSON.stringify(required);
                }
                if (matches) matchCount++;
            }

            coverage.push({
                setting: key,
                requiredValue: required,
                matchingDevices: matchCount,
                matchRate: devices.length > 0
                    ? Math.round((matchCount / devices.length) * 10000) / 100
                    : 0,
                valueDistribution: distribution,
            });
        }

        return coverage.sort((a, b) => a.matchRate - b.matchRate);
    }

    /**
     * Build a risk matrix (likelihood vs impact) for the policy.
     */
    _buildRiskMatrix(devices, policy) {
        const risks = [];

        const securitySettings = ['firewallEnabled', 'encryptionRequired', 'antivirusRequired', 'vpnRequired'];
        const operationalSettings = ['autoUpdateEnabled', 'osUpdateChannel', 'deferFeatureUpdateDays'];

        for (const [key, required] of Object.entries(policy.settings)) {
            let nonCompliant = 0;
            for (const device of devices) {
                const val = device.currentState[key];
                if (val === undefined) continue;
                let ok;
                if (typeof required === 'number' && typeof val === 'number') ok = val >= required;
                else ok = JSON.stringify(val) === JSON.stringify(required);
                if (!ok) nonCompliant++;
            }

            if (nonCompliant === 0) continue;

            const likelihood = devices.length > 0 ? nonCompliant / devices.length : 0;
            const isSecurity = securitySettings.includes(key);
            const impactScore = isSecurity ? 0.9 : operationalSettings.includes(key) ? 0.5 : 0.3;

            risks.push({
                setting: key,
                category: isSecurity ? 'security' : operationalSettings.includes(key) ? 'operational' : 'configuration',
                nonCompliantDevices: nonCompliant,
                likelihood: Math.round(likelihood * 100) / 100,
                impactScore,
                riskScore: Math.round(likelihood * impactScore * 100) / 100,
                riskLevel: likelihood * impactScore > 0.3 ? 'high'
                    : likelihood * impactScore > 0.1 ? 'medium'
                        : 'low',
            });
        }

        return risks.sort((a, b) => b.riskScore - a.riskScore);
    }
}

module.exports = ImpactAnalyzer;
