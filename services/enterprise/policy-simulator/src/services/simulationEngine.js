'use strict';

const { v4: uuidv4 } = require('uuid');
const { EventEmitter } = require('events');

/**
 * SimulationEngine - Core simulation logic for policy what-if analysis.
 *
 * Maintains an in-memory representation of policies, devices, and assignments.
 * Runs deterministic simulations to predict the outcome of proposed policy
 * changes before they are applied to production.
 */
class SimulationEngine extends EventEmitter {
    constructor(logger) {
        super();
        this.logger = logger;

        // In-memory stores (would be backed by a database in production)
        this.policies = new Map();
        this.devices = new Map();
        this.groups = new Map();
        this.assignments = new Map(); // policyId -> Set<groupId>
        this.simulationHistory = [];

        this._seedDemoData();
    }

    // ------------------------------------------------------------------ //
    //  Public API
    // ------------------------------------------------------------------ //

    /**
     * Simulate a proposed policy change and return the predicted outcome.
     *
     * @param {string}   policyId  - ID of the policy to modify
     * @param {Object}   changes   - Key/value map of settings to change
     * @param {Object}   [scope]   - Optional scope filter ({ groups, platforms })
     * @returns {Object} Simulation result
     */
    simulate(policyId, changes, scope = {}) {
        const simulationId = uuidv4();
        const startTime = Date.now();

        this.logger.info('Starting simulation', { simulationId, policyId, changes });

        const policy = this.policies.get(policyId);
        if (!policy) {
            const err = new Error(`Policy not found: ${policyId}`);
            err.statusCode = 404;
            throw err;
        }

        // Build the proposed policy state
        const proposedPolicy = this._applyChanges(policy, changes);

        // Determine which devices are in scope
        const affectedDevices = this._resolveAffectedDevices(policyId, scope);

        // Evaluate each device against the proposed policy
        const deviceResults = affectedDevices.map(device =>
            this._evaluateDeviceImpact(device, policy, proposedPolicy)
        );

        // Aggregate results
        const complianceBefore = deviceResults.filter(d => d.complianceBefore).length;
        const complianceAfter = deviceResults.filter(d => d.complianceAfter).length;

        const result = {
            simulationId,
            policyId,
            policyName: policy.name,
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            changes,
            scope,
            summary: {
                totalDevicesAffected: affectedDevices.length,
                complianceBefore: {
                    compliant: complianceBefore,
                    nonCompliant: affectedDevices.length - complianceBefore,
                    rate: affectedDevices.length > 0
                        ? Math.round((complianceBefore / affectedDevices.length) * 10000) / 100
                        : 0,
                },
                complianceAfter: {
                    compliant: complianceAfter,
                    nonCompliant: affectedDevices.length - complianceAfter,
                    rate: affectedDevices.length > 0
                        ? Math.round((complianceAfter / affectedDevices.length) * 10000) / 100
                        : 0,
                },
                complianceDelta: complianceAfter - complianceBefore,
                riskLevel: this._assessRiskLevel(deviceResults, affectedDevices.length),
            },
            deviceResults,
            conflicts: this._detectConflictsForPolicy(proposedPolicy),
            recommendations: this._generateRecommendations(deviceResults, changes),
        };

        // Persist to history
        this.simulationHistory.push({
            simulationId,
            policyId,
            policyName: policy.name,
            timestamp: result.timestamp,
            summary: result.summary,
            changes,
        });

        this.emit('simulationCompleted', result);
        this.logger.info('Simulation completed', {
            simulationId,
            devicesAffected: result.summary.totalDevicesAffected,
            riskLevel: result.summary.riskLevel,
        });

        return result;
    }

    /**
     * Return the full simulation history (most recent first).
     */
    getHistory(limit = 50, offset = 0) {
        const sorted = [...this.simulationHistory].reverse();
        return {
            total: sorted.length,
            limit,
            offset,
            results: sorted.slice(offset, offset + limit),
        };
    }

    /**
     * Detect conflicts across all registered policies.
     */
    detectAllConflicts() {
        const conflicts = [];
        const policyList = [...this.policies.values()];

        for (let i = 0; i < policyList.length; i++) {
            for (let j = i + 1; j < policyList.length; j++) {
                const c = this._comparePolicies(policyList[i], policyList[j]);
                if (c.length > 0) {
                    conflicts.push({
                        policyA: { id: policyList[i].id, name: policyList[i].name },
                        policyB: { id: policyList[j].id, name: policyList[j].name },
                        conflicts: c,
                        severity: this._conflictSeverity(c),
                    });
                }
            }
        }

        return {
            timestamp: new Date().toISOString(),
            totalConflicts: conflicts.length,
            conflicts,
        };
    }

    /**
     * Create a rollback plan for a proposed set of changes.
     */
    createRollbackPlan(policyId, changes) {
        const policy = this.policies.get(policyId);
        if (!policy) {
            const err = new Error(`Policy not found: ${policyId}`);
            err.statusCode = 404;
            throw err;
        }

        const affectedDevices = this._resolveAffectedDevices(policyId);
        const proposedPolicy = this._applyChanges(policy, changes);

        // Determine rollback steps (revert each changed setting)
        const rollbackSteps = Object.keys(changes).map(key => ({
            setting: key,
            currentValue: policy.settings[key],
            proposedValue: changes[key],
            rollbackValue: policy.settings[key],
        }));

        // Estimate rollback timing based on device count
        const estimatedRollbackMinutes = Math.max(5, Math.ceil(affectedDevices.length / 100) * 5);

        const plan = {
            planId: uuidv4(),
            policyId,
            policyName: policy.name,
            createdAt: new Date().toISOString(),
            rollbackSteps,
            affectedDeviceCount: affectedDevices.length,
            estimatedRollbackTimeMinutes: estimatedRollbackMinutes,
            riskAssessment: {
                rollbackRisk: affectedDevices.length > 500 ? 'high' : affectedDevices.length > 100 ? 'medium' : 'low',
                dataLossRisk: 'none',
                serviceInterruption: this._estimateServiceInterruption(changes),
            },
            preRollbackChecks: [
                'Verify current policy state matches expected baseline',
                'Confirm all target devices are reachable',
                'Ensure rollback window does not overlap with maintenance',
                'Notify affected users before rollback',
            ],
            postRollbackValidation: [
                'Verify policy settings reverted on all devices',
                'Run compliance check on affected device group',
                'Monitor error rates for 30 minutes post-rollback',
                'Confirm user-reported issues are resolved',
            ],
        };

        this.logger.info('Rollback plan created', { planId: plan.planId, policyId });
        return plan;
    }

    // ------------------------------------------------------------------ //
    //  Policy & device accessors (for other services)
    // ------------------------------------------------------------------ //

    getPolicy(policyId) {
        return this.policies.get(policyId) || null;
    }

    getDevice(deviceId) {
        return this.devices.get(deviceId) || null;
    }

    getAllDevices() {
        return [...this.devices.values()];
    }

    getAssignedDevices(policyId) {
        return this._resolveAffectedDevices(policyId);
    }

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    _applyChanges(policy, changes) {
        return {
            ...policy,
            settings: { ...policy.settings, ...changes },
            _proposed: true,
        };
    }

    _resolveAffectedDevices(policyId, scope = {}) {
        const assignedGroups = this.assignments.get(policyId) || new Set();
        let devices = [];

        for (const groupId of assignedGroups) {
            const group = this.groups.get(groupId);
            if (!group) continue;
            for (const deviceId of group.members) {
                const device = this.devices.get(deviceId);
                if (device) devices.push(device);
            }
        }

        // De-duplicate
        const seen = new Set();
        devices = devices.filter(d => {
            if (seen.has(d.id)) return false;
            seen.add(d.id);
            return true;
        });

        // Apply scope filters
        if (scope.groups && scope.groups.length > 0) {
            const scopeGroupMembers = new Set();
            for (const gId of scope.groups) {
                const g = this.groups.get(gId);
                if (g) g.members.forEach(m => scopeGroupMembers.add(m));
            }
            devices = devices.filter(d => scopeGroupMembers.has(d.id));
        }

        if (scope.platforms && scope.platforms.length > 0) {
            const platforms = new Set(scope.platforms.map(p => p.toLowerCase()));
            devices = devices.filter(d => platforms.has(d.platform.toLowerCase()));
        }

        return devices;
    }

    _evaluateDeviceImpact(device, currentPolicy, proposedPolicy) {
        const complianceBefore = this._isDeviceCompliant(device, currentPolicy);
        const complianceAfter = this._isDeviceCompliant(device, proposedPolicy);
        const settingChanges = [];

        for (const [key, proposedValue] of Object.entries(proposedPolicy.settings)) {
            const currentValue = currentPolicy.settings[key];
            if (JSON.stringify(currentValue) !== JSON.stringify(proposedValue)) {
                const deviceCurrentValue = device.currentState[key];
                const needsAction = JSON.stringify(deviceCurrentValue) !== JSON.stringify(proposedValue);
                settingChanges.push({
                    setting: key,
                    policyCurrentValue: currentValue,
                    policyProposedValue: proposedValue,
                    deviceCurrentValue,
                    requiresAction: needsAction,
                    estimatedApplyTimeMinutes: needsAction ? this._estimateApplyTime(key) : 0,
                });
            }
        }

        return {
            deviceId: device.id,
            deviceName: device.name,
            platform: device.platform,
            owner: device.owner,
            complianceBefore,
            complianceAfter,
            complianceChanged: complianceBefore !== complianceAfter,
            settingChanges,
            requiresReboot: settingChanges.some(c => this._requiresReboot(c.setting)),
            estimatedTotalApplyTimeMinutes: settingChanges.reduce(
                (sum, c) => sum + c.estimatedApplyTimeMinutes, 0
            ),
        };
    }

    _isDeviceCompliant(device, policy) {
        for (const [key, requiredValue] of Object.entries(policy.settings)) {
            const deviceValue = device.currentState[key];
            if (deviceValue === undefined) continue;

            if (typeof requiredValue === 'number') {
                // Numeric comparison: device value must meet or exceed the policy requirement
                if (typeof deviceValue === 'number' && deviceValue < requiredValue) return false;
            } else if (typeof requiredValue === 'boolean') {
                if (deviceValue !== requiredValue) return false;
            } else if (typeof requiredValue === 'string') {
                if (deviceValue !== requiredValue) return false;
            }
        }
        return true;
    }

    _assessRiskLevel(deviceResults, totalDevices) {
        if (totalDevices === 0) return 'none';

        const complianceLoss = deviceResults.filter(
            d => d.complianceBefore && !d.complianceAfter
        ).length;

        const complianceLossRate = complianceLoss / totalDevices;
        const rebootCount = deviceResults.filter(d => d.requiresReboot).length;
        const rebootRate = rebootCount / totalDevices;

        if (complianceLossRate > 0.3 || rebootRate > 0.5) return 'critical';
        if (complianceLossRate > 0.1 || rebootRate > 0.3) return 'high';
        if (complianceLossRate > 0.05 || rebootRate > 0.1) return 'medium';
        if (complianceLossRate > 0 || rebootRate > 0) return 'low';
        return 'none';
    }

    _generateRecommendations(deviceResults, changes) {
        const recommendations = [];
        const rebootDevices = deviceResults.filter(d => d.requiresReboot);

        if (rebootDevices.length > 0) {
            recommendations.push({
                type: 'warning',
                message: `${rebootDevices.length} device(s) will require a reboot. Consider scheduling during a maintenance window.`,
            });
        }

        const lostCompliance = deviceResults.filter(d => d.complianceBefore && !d.complianceAfter);
        if (lostCompliance.length > 0) {
            recommendations.push({
                type: 'critical',
                message: `${lostCompliance.length} device(s) will lose compliance. Review the changes before applying.`,
            });
        }

        const gainedCompliance = deviceResults.filter(d => !d.complianceBefore && d.complianceAfter);
        if (gainedCompliance.length > 0) {
            recommendations.push({
                type: 'info',
                message: `${gainedCompliance.length} device(s) will become compliant after this change.`,
            });
        }

        if (deviceResults.length > 200) {
            recommendations.push({
                type: 'suggestion',
                message: 'Large number of affected devices. Consider a phased rollout using deployment rings.',
            });
        }

        if (Object.keys(changes).length > 5) {
            recommendations.push({
                type: 'suggestion',
                message: 'Multiple settings changed simultaneously. Consider applying changes incrementally.',
            });
        }

        return recommendations;
    }

    _detectConflictsForPolicy(policy) {
        const conflicts = [];
        for (const [otherId, otherPolicy] of this.policies) {
            if (otherId === policy.id) continue;
            const c = this._comparePolicies(policy, otherPolicy);
            if (c.length > 0) {
                conflicts.push({
                    conflictingPolicyId: otherId,
                    conflictingPolicyName: otherPolicy.name,
                    settings: c,
                });
            }
        }
        return conflicts;
    }

    _comparePolicies(policyA, policyB) {
        // Two policies conflict if they target overlapping groups and set the
        // same setting to different values.
        const groupsA = this.assignments.get(policyA.id) || new Set();
        const groupsB = this.assignments.get(policyB.id) || new Set();

        let overlaps = false;
        for (const g of groupsA) {
            if (groupsB.has(g)) { overlaps = true; break; }
        }
        if (!overlaps) return [];

        const conflicts = [];
        for (const [key, valueA] of Object.entries(policyA.settings)) {
            if (key in policyB.settings) {
                const valueB = policyB.settings[key];
                if (JSON.stringify(valueA) !== JSON.stringify(valueB)) {
                    conflicts.push({
                        setting: key,
                        valueInA: valueA,
                        valueInB: valueB,
                    });
                }
            }
        }
        return conflicts;
    }

    _conflictSeverity(conflicts) {
        if (conflicts.some(c => ['firewallEnabled', 'encryptionRequired', 'passwordMinLength'].includes(c.setting))) {
            return 'high';
        }
        if (conflicts.length > 3) return 'medium';
        return 'low';
    }

    _requiresReboot(settingKey) {
        const rebootSettings = new Set([
            'encryptionRequired',
            'firewallEnabled',
            'osUpdateChannel',
            'kernelProtection',
            'secureBootRequired',
        ]);
        return rebootSettings.has(settingKey);
    }

    _estimateApplyTime(settingKey) {
        const timings = {
            passwordMinLength: 1,
            passwordRequireComplexity: 1,
            screenLockTimeoutMinutes: 1,
            firewallEnabled: 5,
            encryptionRequired: 30,
            autoUpdateEnabled: 2,
            osUpdateChannel: 15,
            vpnRequired: 3,
            antivirusRequired: 10,
            kernelProtection: 10,
            secureBootRequired: 15,
        };
        return timings[settingKey] || 2;
    }

    _estimateServiceInterruption(changes) {
        const disruptiveKeys = ['encryptionRequired', 'firewallEnabled', 'osUpdateChannel', 'secureBootRequired'];
        const hasDisruptive = Object.keys(changes).some(k => disruptiveKeys.includes(k));
        if (hasDisruptive) return 'possible - some changes may require reboot';
        return 'unlikely';
    }

    // ------------------------------------------------------------------ //
    //  Demo / seed data
    // ------------------------------------------------------------------ //

    _seedDemoData() {
        // ----- Policies -----
        const policies = [
            {
                id: 'policy-security-baseline',
                name: 'Security Baseline',
                type: 'security',
                priority: 1,
                settings: {
                    passwordMinLength: 8,
                    passwordRequireComplexity: true,
                    screenLockTimeoutMinutes: 5,
                    firewallEnabled: true,
                    encryptionRequired: true,
                    autoUpdateEnabled: true,
                },
                createdAt: '2025-01-15T10:00:00Z',
                updatedAt: '2025-06-01T14:30:00Z',
            },
            {
                id: 'policy-update-ring-a',
                name: 'Update Ring A - Early Adopters',
                type: 'update',
                priority: 2,
                settings: {
                    osUpdateChannel: 'fast',
                    autoUpdateEnabled: true,
                    deferFeatureUpdateDays: 0,
                    deferQualityUpdateDays: 0,
                    maintenanceWindowStart: '02:00',
                    maintenanceWindowEnd: '06:00',
                },
                createdAt: '2025-02-01T09:00:00Z',
                updatedAt: '2025-07-15T11:00:00Z',
            },
            {
                id: 'policy-update-ring-b',
                name: 'Update Ring B - Broad Deployment',
                type: 'update',
                priority: 3,
                settings: {
                    osUpdateChannel: 'slow',
                    autoUpdateEnabled: true,
                    deferFeatureUpdateDays: 14,
                    deferQualityUpdateDays: 7,
                    maintenanceWindowStart: '00:00',
                    maintenanceWindowEnd: '06:00',
                },
                createdAt: '2025-02-01T09:00:00Z',
                updatedAt: '2025-07-15T11:00:00Z',
            },
            {
                id: 'policy-compliance-strict',
                name: 'Strict Compliance',
                type: 'compliance',
                priority: 1,
                settings: {
                    passwordMinLength: 12,
                    passwordRequireComplexity: true,
                    screenLockTimeoutMinutes: 3,
                    firewallEnabled: true,
                    encryptionRequired: true,
                    vpnRequired: true,
                    antivirusRequired: true,
                },
                createdAt: '2025-03-10T08:00:00Z',
                updatedAt: '2025-08-20T16:45:00Z',
            },
            {
                id: 'policy-remote-workers',
                name: 'Remote Workers Policy',
                type: 'security',
                priority: 2,
                settings: {
                    passwordMinLength: 10,
                    passwordRequireComplexity: true,
                    screenLockTimeoutMinutes: 3,
                    firewallEnabled: true,
                    encryptionRequired: true,
                    vpnRequired: true,
                    autoUpdateEnabled: true,
                },
                createdAt: '2025-04-05T12:00:00Z',
                updatedAt: '2025-09-10T09:30:00Z',
            },
        ];

        for (const p of policies) this.policies.set(p.id, p);

        // ----- Groups -----
        const groups = [
            { id: 'group-it-early-adopters', name: 'IT Early Adopters', members: [] },
            { id: 'group-engineering', name: 'Engineering', members: [] },
            { id: 'group-sales', name: 'Sales', members: [] },
            { id: 'group-executives', name: 'Executives', members: [] },
            { id: 'group-remote', name: 'Remote Workers', members: [] },
            { id: 'group-all-devices', name: 'All Devices', members: [] },
        ];
        for (const g of groups) this.groups.set(g.id, g);

        // ----- Devices -----
        const platforms = ['Windows', 'macOS', 'Linux'];
        const departments = ['Engineering', 'Sales', 'IT', 'HR', 'Finance', 'Marketing', 'Executive'];
        const owners = [
            'alice.johnson', 'bob.smith', 'carol.williams', 'dave.brown',
            'eve.davis', 'frank.miller', 'grace.wilson', 'hank.moore',
            'irene.taylor', 'jack.anderson', 'kate.thomas', 'leo.jackson',
            'mia.white', 'nate.harris', 'olivia.martin', 'pete.garcia',
            'quinn.martinez', 'rachel.robinson', 'sam.clark', 'tina.rodriguez',
        ];

        for (let i = 0; i < 150; i++) {
            const platform = platforms[i % platforms.length];
            const owner = owners[i % owners.length];
            const department = departments[i % departments.length];
            const isRemote = i % 4 === 0;
            const isCompliant = i % 7 !== 0; // ~85 % compliant

            const device = {
                id: `device-${String(i + 1).padStart(4, '0')}`,
                name: `${owner.split('.')[0].toUpperCase()}-${platform.toUpperCase().slice(0, 3)}-${String(i + 1).padStart(4, '0')}`,
                platform,
                owner,
                department,
                isRemote,
                enrolledAt: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
                lastCheckIn: new Date(Date.now() - Math.random() * 48 * 60 * 60 * 1000).toISOString(),
                currentState: {
                    passwordMinLength: isCompliant ? 10 : 6,
                    passwordRequireComplexity: isCompliant,
                    screenLockTimeoutMinutes: isCompliant ? 5 : 15,
                    firewallEnabled: isCompliant,
                    encryptionRequired: isCompliant,
                    autoUpdateEnabled: isCompliant || i % 3 === 0,
                    osUpdateChannel: i % 5 === 0 ? 'fast' : 'slow',
                    vpnRequired: isRemote,
                    antivirusRequired: isCompliant,
                    deferFeatureUpdateDays: i % 5 === 0 ? 0 : 14,
                    deferQualityUpdateDays: i % 5 === 0 ? 0 : 7,
                },
                osVersion: platform === 'Windows' ? '11.23H2' : platform === 'macOS' ? '14.3' : '22.04 LTS',
            };

            this.devices.set(device.id, device);

            // Add to All Devices group
            this.groups.get('group-all-devices').members.push(device.id);

            // Assign to department-relevant groups
            if (i % 5 === 0) this.groups.get('group-it-early-adopters').members.push(device.id);
            if (department === 'Engineering') this.groups.get('group-engineering').members.push(device.id);
            if (department === 'Sales') this.groups.get('group-sales').members.push(device.id);
            if (department === 'Executive') this.groups.get('group-executives').members.push(device.id);
            if (isRemote) this.groups.get('group-remote').members.push(device.id);
        }

        // ----- Assignments (policy -> groups) -----
        this.assignments.set('policy-security-baseline', new Set(['group-all-devices']));
        this.assignments.set('policy-update-ring-a', new Set(['group-it-early-adopters']));
        this.assignments.set('policy-update-ring-b', new Set(['group-engineering', 'group-sales']));
        this.assignments.set('policy-compliance-strict', new Set(['group-executives', 'group-remote']));
        this.assignments.set('policy-remote-workers', new Set(['group-remote']));

        this.logger.info('Demo data seeded', {
            policies: this.policies.size,
            devices: this.devices.size,
            groups: this.groups.size,
        });
    }
}

module.exports = SimulationEngine;
