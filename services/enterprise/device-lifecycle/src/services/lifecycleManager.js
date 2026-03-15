const { EventEmitter } = require('events');
const { v4: uuidv4 } = require('uuid');

/**
 * Valid lifecycle states and their allowed transitions
 */
const LIFECYCLE_STATES = {
    PROVISIONED: 'Provisioned',
    ENROLLED: 'Enrolled',
    CONFIGURED: 'Configured',
    COMPLIANT: 'Compliant',
    NON_COMPLIANT: 'Non-Compliant',
    RETIRING: 'Retiring',
    RETIRED: 'Retired'
};

const VALID_TRANSITIONS = {
    [LIFECYCLE_STATES.PROVISIONED]: [LIFECYCLE_STATES.ENROLLED, LIFECYCLE_STATES.RETIRED],
    [LIFECYCLE_STATES.ENROLLED]: [LIFECYCLE_STATES.CONFIGURED, LIFECYCLE_STATES.RETIRING],
    [LIFECYCLE_STATES.CONFIGURED]: [LIFECYCLE_STATES.COMPLIANT, LIFECYCLE_STATES.NON_COMPLIANT, LIFECYCLE_STATES.RETIRING],
    [LIFECYCLE_STATES.COMPLIANT]: [LIFECYCLE_STATES.NON_COMPLIANT, LIFECYCLE_STATES.RETIRING],
    [LIFECYCLE_STATES.NON_COMPLIANT]: [LIFECYCLE_STATES.COMPLIANT, LIFECYCLE_STATES.CONFIGURED, LIFECYCLE_STATES.RETIRING],
    [LIFECYCLE_STATES.RETIRING]: [LIFECYCLE_STATES.RETIRED],
    [LIFECYCLE_STATES.RETIRED]: []
};

class LifecycleManager extends EventEmitter {
    constructor() {
        super();
        this.devices = new Map();
        this.auditTrail = [];
        this.transitionHistory = [];

        this._seedDemoDevices();
    }

    /**
     * Seed demo devices for demonstration purposes
     */
    _seedDemoDevices() {
        const demoDevices = [
            {
                id: 'dev-001',
                hostname: 'DESKTOP-PROD-01',
                serialNumber: 'SN-2024-00101',
                owner: 'alice.johnson@company.com',
                platform: 'Windows',
                osVersion: 'Windows 11 23H2',
                model: 'Dell Latitude 5540',
                hardwareSpecs: { cpu: 'Intel i7-1365U', ram: '16GB', storage: '512GB NVMe' },
                enrolledAt: '2024-01-15T10:30:00Z',
                apps: ['Microsoft 365', 'Slack', 'Zoom', 'Chrome', 'VS Code'],
                lastCheckIn: '2024-03-10T14:22:00Z',
                bitlockerEnabled: true,
                edrInstalled: true,
                firewallEnabled: true,
                pendingUpdates: 0,
                state: LIFECYCLE_STATES.COMPLIANT
            },
            {
                id: 'dev-002',
                hostname: 'MACBOOK-ENG-07',
                serialNumber: 'SN-2024-00202',
                owner: 'bob.smith@company.com',
                platform: 'macOS',
                osVersion: 'macOS 14.3 Sonoma',
                model: 'MacBook Pro 14" M3 Pro',
                hardwareSpecs: { cpu: 'Apple M3 Pro', ram: '18GB', storage: '512GB SSD' },
                enrolledAt: '2024-02-01T09:00:00Z',
                apps: ['Xcode', 'Slack', 'Docker', 'iTerm2', 'Chrome'],
                lastCheckIn: '2024-03-10T16:45:00Z',
                bitlockerEnabled: false,
                filevaultEnabled: true,
                edrInstalled: true,
                firewallEnabled: true,
                pendingUpdates: 2,
                state: LIFECYCLE_STATES.COMPLIANT
            },
            {
                id: 'dev-003',
                hostname: 'LAPTOP-SALES-12',
                serialNumber: 'SN-2023-00389',
                owner: 'carol.davis@company.com',
                platform: 'Windows',
                osVersion: 'Windows 10 22H2',
                model: 'Lenovo ThinkPad X1 Carbon Gen 11',
                hardwareSpecs: { cpu: 'Intel i5-1345U', ram: '8GB', storage: '256GB NVMe' },
                enrolledAt: '2023-06-20T11:15:00Z',
                apps: ['Microsoft 365', 'Salesforce', 'Chrome', 'Teams'],
                lastCheckIn: '2024-03-08T09:30:00Z',
                bitlockerEnabled: false,
                edrInstalled: true,
                firewallEnabled: true,
                pendingUpdates: 5,
                state: LIFECYCLE_STATES.NON_COMPLIANT
            },
            {
                id: 'dev-004',
                hostname: 'UBUNTU-DEV-03',
                serialNumber: 'SN-2024-00450',
                owner: 'dave.wilson@company.com',
                platform: 'Linux',
                osVersion: 'Ubuntu 22.04.4 LTS',
                model: 'System76 Pangolin',
                hardwareSpecs: { cpu: 'AMD Ryzen 7 7840U', ram: '32GB', storage: '1TB NVMe' },
                enrolledAt: '2024-01-28T13:00:00Z',
                apps: ['VS Code', 'Docker', 'Firefox', 'Slack', 'Git'],
                lastCheckIn: '2024-03-10T18:00:00Z',
                bitlockerEnabled: false,
                luksEnabled: true,
                edrInstalled: false,
                firewallEnabled: true,
                pendingUpdates: 0,
                state: LIFECYCLE_STATES.NON_COMPLIANT
            },
            {
                id: 'dev-005',
                hostname: 'DESKTOP-FIN-09',
                serialNumber: 'SN-2022-00156',
                owner: 'eve.martinez@company.com',
                platform: 'Windows',
                osVersion: 'Windows 11 22H2',
                model: 'HP EliteDesk 800 G9',
                hardwareSpecs: { cpu: 'Intel i7-12700', ram: '32GB', storage: '1TB NVMe' },
                enrolledAt: '2022-11-05T08:45:00Z',
                apps: ['Microsoft 365', 'SAP', 'QuickBooks', 'Chrome'],
                lastCheckIn: '2024-03-10T17:30:00Z',
                bitlockerEnabled: true,
                edrInstalled: true,
                firewallEnabled: true,
                pendingUpdates: 1,
                state: LIFECYCLE_STATES.COMPLIANT
            },
            {
                id: 'dev-006',
                hostname: 'SURFACE-EXEC-01',
                serialNumber: 'SN-2024-00601',
                owner: 'frank.chen@company.com',
                platform: 'Windows',
                osVersion: 'Windows 11 23H2',
                model: 'Microsoft Surface Pro 10',
                hardwareSpecs: { cpu: 'Intel Ultra 7 165U', ram: '16GB', storage: '256GB SSD' },
                enrolledAt: '2024-03-01T10:00:00Z',
                apps: ['Microsoft 365'],
                lastCheckIn: '2024-03-10T12:00:00Z',
                bitlockerEnabled: true,
                edrInstalled: false,
                firewallEnabled: true,
                pendingUpdates: 0,
                state: LIFECYCLE_STATES.CONFIGURED
            },
            {
                id: 'dev-007',
                hostname: 'LAPTOP-HR-04',
                serialNumber: 'SN-2021-00078',
                owner: 'grace.lee@company.com',
                platform: 'Windows',
                osVersion: 'Windows 10 21H2',
                model: 'Dell Latitude 7420',
                hardwareSpecs: { cpu: 'Intel i5-1145G7', ram: '8GB', storage: '256GB SSD' },
                enrolledAt: '2021-09-15T14:30:00Z',
                apps: ['Microsoft 365', 'Workday', 'Chrome'],
                lastCheckIn: '2024-02-20T10:00:00Z',
                bitlockerEnabled: true,
                edrInstalled: true,
                firewallEnabled: false,
                pendingUpdates: 12,
                state: LIFECYCLE_STATES.RETIRING
            },
            {
                id: 'dev-008',
                hostname: 'IPAD-FIELD-22',
                serialNumber: 'SN-2023-00822',
                owner: 'henry.brown@company.com',
                platform: 'iOS',
                osVersion: 'iPadOS 17.3',
                model: 'iPad Air 5th Gen',
                hardwareSpecs: { cpu: 'Apple M1', ram: '8GB', storage: '64GB' },
                enrolledAt: '2023-08-10T09:30:00Z',
                apps: ['Microsoft Teams', 'Salesforce', 'ServiceNow'],
                lastCheckIn: '2024-03-10T08:15:00Z',
                bitlockerEnabled: false,
                edrInstalled: false,
                firewallEnabled: false,
                pendingUpdates: 1,
                state: LIFECYCLE_STATES.COMPLIANT
            }
        ];

        for (const device of demoDevices) {
            const fullDevice = {
                ...device,
                createdAt: device.enrolledAt,
                updatedAt: new Date().toISOString(),
                lifecycleHistory: [
                    {
                        id: uuidv4(),
                        fromState: null,
                        toState: LIFECYCLE_STATES.PROVISIONED,
                        timestamp: new Date(new Date(device.enrolledAt).getTime() - 86400000).toISOString(),
                        performedBy: 'system',
                        reason: 'Device provisioned in inventory'
                    },
                    {
                        id: uuidv4(),
                        fromState: LIFECYCLE_STATES.PROVISIONED,
                        toState: LIFECYCLE_STATES.ENROLLED,
                        timestamp: device.enrolledAt,
                        performedBy: device.owner,
                        reason: 'Device enrolled by user'
                    },
                    {
                        id: uuidv4(),
                        fromState: LIFECYCLE_STATES.ENROLLED,
                        toState: LIFECYCLE_STATES.CONFIGURED,
                        timestamp: new Date(new Date(device.enrolledAt).getTime() + 3600000).toISOString(),
                        performedBy: 'system',
                        reason: 'Configuration profiles applied'
                    },
                    {
                        id: uuidv4(),
                        fromState: LIFECYCLE_STATES.CONFIGURED,
                        toState: device.state,
                        timestamp: new Date(new Date(device.enrolledAt).getTime() + 7200000).toISOString(),
                        performedBy: 'compliance-engine',
                        reason: device.state === LIFECYCLE_STATES.COMPLIANT
                            ? 'Device met all compliance requirements'
                            : device.state === LIFECYCLE_STATES.NON_COMPLIANT
                                ? 'Device failed compliance check'
                                : `Device transitioned to ${device.state}`
                    }
                ],
                tags: [],
                notes: []
            };
            this.devices.set(device.id, fullDevice);
        }
    }

    /**
     * Get all devices with optional filtering
     */
    getAllDevices(filters = {}) {
        let devices = Array.from(this.devices.values());

        if (filters.state) {
            devices = devices.filter(d => d.state === filters.state);
        }
        if (filters.platform) {
            devices = devices.filter(d => d.platform.toLowerCase() === filters.platform.toLowerCase());
        }
        if (filters.owner) {
            devices = devices.filter(d => d.owner.toLowerCase().includes(filters.owner.toLowerCase()));
        }
        if (filters.search) {
            const term = filters.search.toLowerCase();
            devices = devices.filter(d =>
                d.hostname.toLowerCase().includes(term) ||
                d.serialNumber.toLowerCase().includes(term) ||
                d.owner.toLowerCase().includes(term) ||
                d.model.toLowerCase().includes(term)
            );
        }

        // Pagination
        const page = parseInt(filters.page) || 1;
        const limit = parseInt(filters.limit) || 50;
        const startIndex = (page - 1) * limit;
        const total = devices.length;
        const paginatedDevices = devices.slice(startIndex, startIndex + limit);

        return {
            devices: paginatedDevices.map(d => ({
                id: d.id,
                hostname: d.hostname,
                serialNumber: d.serialNumber,
                owner: d.owner,
                platform: d.platform,
                osVersion: d.osVersion,
                model: d.model,
                state: d.state,
                lastCheckIn: d.lastCheckIn,
                enrolledAt: d.enrolledAt,
                pendingUpdates: d.pendingUpdates
            })),
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            }
        };
    }

    /**
     * Get device by ID with full detail
     */
    getDeviceById(deviceId) {
        const device = this.devices.get(deviceId);
        if (!device) {
            return null;
        }
        return { ...device };
    }

    /**
     * Transition a device to a new state
     */
    transitionDevice(deviceId, targetState, { performedBy = 'system', reason = '' } = {}) {
        const device = this.devices.get(deviceId);
        if (!device) {
            throw new Error(`Device ${deviceId} not found`);
        }

        const currentState = device.state;

        // Validate state name
        const validStates = Object.values(LIFECYCLE_STATES);
        if (!validStates.includes(targetState)) {
            throw new Error(`Invalid target state: ${targetState}. Valid states: ${validStates.join(', ')}`);
        }

        // Validate transition
        const allowedTransitions = VALID_TRANSITIONS[currentState];
        if (!allowedTransitions || !allowedTransitions.includes(targetState)) {
            throw new Error(
                `Invalid transition from ${currentState} to ${targetState}. ` +
                `Allowed transitions from ${currentState}: ${(allowedTransitions || []).join(', ') || 'none'}`
            );
        }

        const transitionRecord = {
            id: uuidv4(),
            deviceId,
            fromState: currentState,
            toState: targetState,
            timestamp: new Date().toISOString(),
            performedBy,
            reason
        };

        // Update device state
        device.state = targetState;
        device.updatedAt = new Date().toISOString();
        device.lifecycleHistory.push(transitionRecord);

        // Store in global history
        this.transitionHistory.push(transitionRecord);

        // Audit trail
        this.auditTrail.push({
            id: uuidv4(),
            action: 'state_transition',
            deviceId,
            details: transitionRecord,
            timestamp: transitionRecord.timestamp
        });

        this.emit('stateTransition', transitionRecord);

        return {
            success: true,
            transition: transitionRecord,
            device: {
                id: device.id,
                hostname: device.hostname,
                previousState: currentState,
                currentState: targetState
            }
        };
    }

    /**
     * Bulk transition multiple devices
     */
    bulkTransition(deviceIds, targetState, { performedBy = 'system', reason = '' } = {}) {
        const results = {
            successful: [],
            failed: [],
            timestamp: new Date().toISOString()
        };

        for (const deviceId of deviceIds) {
            try {
                const result = this.transitionDevice(deviceId, targetState, { performedBy, reason });
                results.successful.push({
                    deviceId,
                    transition: result.transition
                });
            } catch (error) {
                results.failed.push({
                    deviceId,
                    error: error.message
                });
            }
        }

        results.summary = {
            total: deviceIds.length,
            succeeded: results.successful.length,
            failed: results.failed.length
        };

        this.emit('bulkTransition', results);

        return results;
    }

    /**
     * Get the complete timeline for a device
     */
    getDeviceTimeline(deviceId) {
        const device = this.devices.get(deviceId);
        if (!device) {
            return null;
        }

        const timeline = [];

        // Add lifecycle events
        for (const entry of device.lifecycleHistory) {
            timeline.push({
                type: 'state_transition',
                timestamp: entry.timestamp,
                details: {
                    fromState: entry.fromState,
                    toState: entry.toState,
                    performedBy: entry.performedBy,
                    reason: entry.reason
                }
            });
        }

        // Add audit trail events for this device
        const deviceAuditEvents = this.auditTrail.filter(a => a.deviceId === deviceId && a.action !== 'state_transition');
        for (const event of deviceAuditEvents) {
            timeline.push({
                type: event.action,
                timestamp: event.timestamp,
                details: event.details
            });
        }

        // Sort by timestamp descending (newest first)
        timeline.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return {
            deviceId,
            hostname: device.hostname,
            currentState: device.state,
            totalEvents: timeline.length,
            timeline
        };
    }

    /**
     * Compute lifecycle analytics
     */
    getAnalytics() {
        const devices = Array.from(this.devices.values());
        const totalDevices = devices.length;

        // State distribution
        const stateDistribution = {};
        for (const state of Object.values(LIFECYCLE_STATES)) {
            stateDistribution[state] = devices.filter(d => d.state === state).length;
        }

        // Platform distribution
        const platformDistribution = {};
        for (const device of devices) {
            platformDistribution[device.platform] = (platformDistribution[device.platform] || 0) + 1;
        }

        // Average time in each state (in hours)
        const stateTimings = {};
        for (const device of devices) {
            const history = device.lifecycleHistory;
            for (let i = 0; i < history.length; i++) {
                const entry = history[i];
                const nextEntry = history[i + 1];
                const state = entry.toState;
                const startTime = new Date(entry.timestamp);
                const endTime = nextEntry ? new Date(nextEntry.timestamp) : new Date();
                const durationHours = (endTime - startTime) / (1000 * 60 * 60);

                if (!stateTimings[state]) {
                    stateTimings[state] = { totalHours: 0, count: 0 };
                }
                stateTimings[state].totalHours += durationHours;
                stateTimings[state].count += 1;
            }
        }

        const averageTimeInState = {};
        for (const [state, data] of Object.entries(stateTimings)) {
            averageTimeInState[state] = {
                averageHours: Math.round((data.totalHours / data.count) * 100) / 100,
                sampleSize: data.count
            };
        }

        // Transition failure rates
        const totalTransitions = this.transitionHistory.length;

        // Compliance rate
        const compliantCount = stateDistribution[LIFECYCLE_STATES.COMPLIANT] || 0;
        const activeDevices = totalDevices - (stateDistribution[LIFECYCLE_STATES.RETIRED] || 0) - (stateDistribution[LIFECYCLE_STATES.RETIRING] || 0);
        const complianceRate = activeDevices > 0 ? Math.round((compliantCount / activeDevices) * 10000) / 100 : 0;

        // Devices needing attention
        const devicesNeedingAttention = devices.filter(d =>
            d.state === LIFECYCLE_STATES.NON_COMPLIANT ||
            d.pendingUpdates > 3 ||
            (d.lastCheckIn && (new Date() - new Date(d.lastCheckIn)) > 7 * 24 * 60 * 60 * 1000)
        ).map(d => ({
            id: d.id,
            hostname: d.hostname,
            state: d.state,
            reason: d.state === LIFECYCLE_STATES.NON_COMPLIANT
                ? 'Non-compliant'
                : d.pendingUpdates > 3
                    ? `${d.pendingUpdates} pending updates`
                    : 'No recent check-in'
        }));

        return {
            summary: {
                totalDevices,
                activeDevices,
                complianceRate: `${complianceRate}%`,
                totalTransitions,
                devicesNeedingAttention: devicesNeedingAttention.length
            },
            stateDistribution,
            platformDistribution,
            averageTimeInState,
            devicesNeedingAttention,
            generatedAt: new Date().toISOString()
        };
    }

    /**
     * Get valid lifecycle states
     */
    getStates() {
        return LIFECYCLE_STATES;
    }

    /**
     * Get valid transitions for a given state
     */
    getValidTransitions(state) {
        return VALID_TRANSITIONS[state] || [];
    }
}

module.exports = LifecycleManager;
module.exports.LIFECYCLE_STATES = LIFECYCLE_STATES;
module.exports.VALID_TRANSITIONS = VALID_TRANSITIONS;
