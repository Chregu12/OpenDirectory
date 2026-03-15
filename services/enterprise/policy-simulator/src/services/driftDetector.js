'use strict';

const { v4: uuidv4 } = require('uuid');

/**
 * DriftDetector - Compares the expected policy state of each device against
 * its actual reported state to surface configuration drift.
 *
 * Drift occurs when a device's current configuration no longer matches what
 * the assigned policies require -- for example, a user disabling the firewall
 * or a failed update leaving a setting in an unexpected state.
 */
class DriftDetector {
    constructor(simulationEngine, logger) {
        this.engine = simulationEngine;
        this.logger = logger;
    }

    /**
     * Detect drift across all devices.
     *
     * @param {Object} [filters] - Optional filters { platform, department, severity }
     * @returns {Object} Drift report
     */
    detectAll(filters = {}) {
        this.logger.info('Running full drift detection', { filters });

        const allDevices = this.engine.getAllDevices();
        const policies = [...this.engine.policies.values()];
        const driftItems = [];

        for (const device of allDevices) {
            const deviceDrift = this._detectForDevice(device, policies);
            if (deviceDrift.driftedSettings.length > 0) {
                driftItems.push(deviceDrift);
            }
        }

        // Apply optional filters
        let filtered = driftItems;
        if (filters.platform) {
            filtered = filtered.filter(d => d.platform.toLowerCase() === filters.platform.toLowerCase());
        }
        if (filters.department) {
            filtered = filtered.filter(d => d.department.toLowerCase() === filters.department.toLowerCase());
        }
        if (filters.severity) {
            filtered = filtered.filter(d => d.overallSeverity === filters.severity.toLowerCase());
        }

        const summary = this._buildSummary(filtered, allDevices.length);

        this.logger.info('Drift detection completed', {
            totalDevices: allDevices.length,
            devicesWithDrift: filtered.length,
        });

        return {
            reportId: uuidv4(),
            timestamp: new Date().toISOString(),
            summary,
            devices: filtered,
        };
    }

    /**
     * Detect drift for a specific device.
     *
     * @param {string} deviceId
     * @returns {Object} Device drift report
     */
    detectForDevice(deviceId) {
        const device = this.engine.getDevice(deviceId);
        if (!device) {
            const err = new Error(`Device not found: ${deviceId}`);
            err.statusCode = 404;
            throw err;
        }

        const policies = [...this.engine.policies.values()];
        const drift = this._detectForDevice(device, policies);

        this.logger.info('Device drift detection completed', {
            deviceId,
            driftedSettings: drift.driftedSettings.length,
        });

        return {
            reportId: uuidv4(),
            timestamp: new Date().toISOString(),
            ...drift,
        };
    }

    // ------------------------------------------------------------------ //
    //  Internal logic
    // ------------------------------------------------------------------ //

    /**
     * Compute drift for a single device across all applicable policies.
     */
    _detectForDevice(device, policies) {
        // Resolve which policies apply to this device
        const applicablePolicies = this._getApplicablePolicies(device, policies);

        // Merge all policy requirements (highest-priority / strictest wins)
        const expectedState = this._mergeExpectedState(applicablePolicies);

        // Compare each expected setting with the device's actual state
        const driftedSettings = [];

        for (const [key, expected] of Object.entries(expectedState)) {
            const actual = device.currentState[key];
            if (actual === undefined) {
                driftedSettings.push({
                    setting: key,
                    expectedValue: expected.value,
                    actualValue: null,
                    sourcePolicy: expected.sourcePolicy,
                    driftType: 'missing',
                    severity: this._settingSeverity(key),
                    detectedAt: new Date().toISOString(),
                    possibleCauses: this._guessCauses('missing', key),
                    remediation: this._suggestRemediation('missing', key, expected.value),
                });
                continue;
            }

            let isDrifted = false;
            if (typeof expected.value === 'number' && typeof actual === 'number') {
                isDrifted = actual < expected.value;
            } else if (typeof expected.value === 'boolean') {
                isDrifted = actual !== expected.value;
            } else if (typeof expected.value === 'string') {
                isDrifted = actual !== expected.value;
            }

            if (isDrifted) {
                const driftType = typeof expected.value === 'number'
                    ? (actual < expected.value ? 'below_threshold' : 'above_threshold')
                    : 'value_mismatch';

                driftedSettings.push({
                    setting: key,
                    expectedValue: expected.value,
                    actualValue: actual,
                    sourcePolicy: expected.sourcePolicy,
                    driftType,
                    severity: this._settingSeverity(key),
                    detectedAt: new Date().toISOString(),
                    possibleCauses: this._guessCauses(driftType, key),
                    remediation: this._suggestRemediation(driftType, key, expected.value),
                });
            }
        }

        return {
            deviceId: device.id,
            deviceName: device.name,
            platform: device.platform,
            department: device.department,
            owner: device.owner,
            lastCheckIn: device.lastCheckIn,
            applicablePolicies: applicablePolicies.map(p => ({ id: p.id, name: p.name })),
            driftedSettings,
            overallSeverity: this._worstSeverity(driftedSettings),
            totalExpectedSettings: Object.keys(expectedState).length,
            compliantSettings: Object.keys(expectedState).length - driftedSettings.length,
            driftPercentage: Object.keys(expectedState).length > 0
                ? Math.round((driftedSettings.length / Object.keys(expectedState).length) * 10000) / 100
                : 0,
        };
    }

    /**
     * Determine which policies target groups that contain this device.
     */
    _getApplicablePolicies(device, policies) {
        const applicable = [];

        for (const policy of policies) {
            const assignedGroups = this.engine.assignments.get(policy.id) || new Set();
            for (const groupId of assignedGroups) {
                const group = this.engine.groups.get(groupId);
                if (group && group.members.includes(device.id)) {
                    applicable.push(policy);
                    break; // no need to check other groups for this policy
                }
            }
        }

        // Sort by priority (lower number = higher priority)
        return applicable.sort((a, b) => a.priority - b.priority);
    }

    /**
     * Merge settings from multiple policies.  If two policies define the same
     * setting, the higher-priority (lower priority number) policy wins.
     * For numeric thresholds the stricter (higher) value wins.
     */
    _mergeExpectedState(policies) {
        const merged = {};

        for (const policy of policies) {
            for (const [key, value] of Object.entries(policy.settings)) {
                if (!(key in merged)) {
                    merged[key] = { value, sourcePolicy: policy.name };
                } else {
                    // For numeric settings, take the stricter (larger) value
                    if (typeof value === 'number' && typeof merged[key].value === 'number') {
                        if (value > merged[key].value) {
                            merged[key] = { value, sourcePolicy: policy.name };
                        }
                    }
                    // For booleans that require something to be enabled, true wins
                    if (typeof value === 'boolean' && value === true && merged[key].value === false) {
                        merged[key] = { value, sourcePolicy: policy.name };
                    }
                    // Otherwise the first (highest priority) policy keeps its value
                }
            }
        }

        return merged;
    }

    _settingSeverity(key) {
        const critical = new Set(['firewallEnabled', 'encryptionRequired', 'antivirusRequired']);
        const high = new Set(['vpnRequired', 'passwordMinLength', 'passwordRequireComplexity', 'secureBootRequired']);
        const medium = new Set(['screenLockTimeoutMinutes', 'autoUpdateEnabled', 'osUpdateChannel']);

        if (critical.has(key)) return 'critical';
        if (high.has(key)) return 'high';
        if (medium.has(key)) return 'medium';
        return 'low';
    }

    _worstSeverity(driftedSettings) {
        if (driftedSettings.length === 0) return 'none';
        const order = ['critical', 'high', 'medium', 'low'];
        for (const level of order) {
            if (driftedSettings.some(s => s.severity === level)) return level;
        }
        return 'low';
    }

    _guessCauses(driftType, setting) {
        const causes = [];

        if (driftType === 'missing') {
            causes.push('Policy has not been applied to the device yet');
            causes.push('Device agent may not support this setting');
            causes.push('Recent re-enrollment may have reset the configuration');
        } else if (driftType === 'value_mismatch') {
            causes.push('User or local administrator changed the setting');
            causes.push('Third-party software overrode the configuration');
            causes.push('A conflicting group policy was applied');
        } else if (driftType === 'below_threshold') {
            causes.push('Setting was changed locally to a less restrictive value');
            causes.push('Policy update failed to apply');
        }

        if (['firewallEnabled', 'antivirusRequired'].includes(setting)) {
            causes.push('Security software may have been uninstalled or disabled');
        }
        if (setting === 'encryptionRequired') {
            causes.push('Encryption may still be in progress');
            causes.push('Drive was recently replaced or reformatted');
        }

        return causes;
    }

    _suggestRemediation(driftType, setting, expectedValue) {
        const actions = [];

        actions.push(`Re-apply the policy to force the setting "${setting}" to the expected value (${JSON.stringify(expectedValue)})`);

        if (['firewallEnabled', 'encryptionRequired', 'antivirusRequired'].includes(setting)) {
            actions.push('Trigger a remote remediation action on the device');
            actions.push('Escalate to the security team if the setting cannot be re-applied');
        }

        if (driftType === 'missing') {
            actions.push('Verify the device agent is running and connected');
            actions.push('Check if the device is still enrolled in management');
        }

        actions.push('Schedule a compliance review with the device owner');

        return actions;
    }

    /**
     * Aggregate drift statistics for a summary section.
     */
    _buildSummary(driftItems, totalDeviceCount) {
        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
        const byPlatform = {};
        const byDepartment = {};
        const topDriftedSettings = {};

        for (const item of driftItems) {
            bySeverity[item.overallSeverity] = (bySeverity[item.overallSeverity] || 0) + 1;
            byPlatform[item.platform] = (byPlatform[item.platform] || 0) + 1;
            byDepartment[item.department] = (byDepartment[item.department] || 0) + 1;

            for (const ds of item.driftedSettings) {
                topDriftedSettings[ds.setting] = (topDriftedSettings[ds.setting] || 0) + 1;
            }
        }

        return {
            totalDevices: totalDeviceCount,
            devicesWithDrift: driftItems.length,
            driftRate: totalDeviceCount > 0
                ? Math.round((driftItems.length / totalDeviceCount) * 10000) / 100
                : 0,
            bySeverity,
            byPlatform,
            byDepartment,
            topDriftedSettings: Object.entries(topDriftedSettings)
                .map(([setting, count]) => ({ setting, count }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 10),
        };
    }
}

module.exports = DriftDetector;
