'use strict';

const { v4: uuidv4 } = require('uuid');

/**
 * ComplianceTimeline - Tracks historical compliance events per device.
 *
 * Each device moves through a lifecycle:
 *   enrolled -> policy assigned -> policy applied -> compliant
 *   -> (optional) compliance lost -> remediated -> compliant
 *
 * The timeline stores discrete events so administrators can see exactly when
 * and why a device gained or lost compliance.
 */
class ComplianceTimeline {
    constructor(simulationEngine, logger) {
        this.engine = simulationEngine;
        this.logger = logger;

        // deviceId -> Array<TimelineEvent>
        this.timelines = new Map();

        this._seedTimelineData();
    }

    /**
     * Retrieve the compliance timeline for a given device.
     *
     * @param {string}  deviceId
     * @param {Object}  [options]          - { from, to, eventTypes, limit }
     * @returns {Object} Timeline report
     */
    getTimeline(deviceId, options = {}) {
        const device = this.engine.getDevice(deviceId);
        if (!device) {
            const err = new Error(`Device not found: ${deviceId}`);
            err.statusCode = 404;
            throw err;
        }

        let events = this.timelines.get(deviceId) || [];

        // Filter by date range
        if (options.from) {
            const from = new Date(options.from).getTime();
            events = events.filter(e => new Date(e.timestamp).getTime() >= from);
        }
        if (options.to) {
            const to = new Date(options.to).getTime();
            events = events.filter(e => new Date(e.timestamp).getTime() <= to);
        }

        // Filter by event type
        if (options.eventTypes && options.eventTypes.length > 0) {
            const types = new Set(options.eventTypes);
            events = events.filter(e => types.has(e.type));
        }

        // Sort chronologically (oldest first)
        events = events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        // Apply limit
        const limit = options.limit || 200;
        const total = events.length;
        events = events.slice(0, limit);

        // Derive current compliance state
        const currentState = this._deriveCurrentState(events);

        // Compute statistics
        const stats = this._computeStats(this.timelines.get(deviceId) || []);

        return {
            deviceId,
            deviceName: device.name,
            platform: device.platform,
            owner: device.owner,
            department: device.department,
            enrolledAt: device.enrolledAt,
            currentComplianceState: currentState,
            statistics: stats,
            events,
            total,
            limit,
        };
    }

    /**
     * Record a new timeline event for a device.
     */
    recordEvent(deviceId, type, details = {}) {
        if (!this.timelines.has(deviceId)) {
            this.timelines.set(deviceId, []);
        }

        const event = {
            eventId: uuidv4(),
            deviceId,
            type,
            timestamp: new Date().toISOString(),
            details,
        };

        this.timelines.get(deviceId).push(event);
        this.logger.info('Timeline event recorded', { deviceId, type });

        return event;
    }

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    /**
     * Walk the event list and derive the device's current compliance state.
     */
    _deriveCurrentState(events) {
        if (events.length === 0) return 'unknown';

        // Walk backwards to find the most recent state-changing event
        for (let i = events.length - 1; i >= 0; i--) {
            const e = events[i];
            switch (e.type) {
                case 'compliance_achieved':
                case 'remediation_completed':
                    return 'compliant';
                case 'compliance_lost':
                case 'compliance_violation':
                    return 'non_compliant';
                case 'policy_applied':
                    return 'pending_evaluation';
                case 'policy_assigned':
                    return 'pending_application';
                case 'device_enrolled':
                    return 'enrolled_pending_policy';
                case 'device_unenrolled':
                    return 'unenrolled';
            }
        }

        return 'unknown';
    }

    /**
     * Compute statistics from the full event list.
     */
    _computeStats(events) {
        if (events.length === 0) {
            return {
                totalEvents: 0,
                complianceLostCount: 0,
                averageTimeToRemediate: null,
                longestNonCompliantPeriodMinutes: null,
                currentStreakDays: 0,
            };
        }

        const sorted = [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        let complianceLostCount = 0;
        let remediationDurations = [];
        let lastLostTimestamp = null;
        let longestNonCompliant = 0;

        for (const event of sorted) {
            if (event.type === 'compliance_lost' || event.type === 'compliance_violation') {
                complianceLostCount++;
                lastLostTimestamp = new Date(event.timestamp);
            }
            if ((event.type === 'compliance_achieved' || event.type === 'remediation_completed') && lastLostTimestamp) {
                const duration = new Date(event.timestamp) - lastLostTimestamp;
                const minutes = duration / (1000 * 60);
                remediationDurations.push(minutes);
                if (minutes > longestNonCompliant) longestNonCompliant = minutes;
                lastLostTimestamp = null;
            }
        }

        // Current streak (days since last compliance_lost without a subsequent loss)
        let currentStreakDays = 0;
        const lastComplianceEvent = [...sorted].reverse().find(
            e => e.type === 'compliance_achieved' || e.type === 'remediation_completed'
        );
        if (lastComplianceEvent && !lastLostTimestamp) {
            currentStreakDays = Math.floor(
                (Date.now() - new Date(lastComplianceEvent.timestamp)) / (1000 * 60 * 60 * 24)
            );
        }

        const avgRemediation = remediationDurations.length > 0
            ? Math.round(remediationDurations.reduce((a, b) => a + b, 0) / remediationDurations.length)
            : null;

        return {
            totalEvents: sorted.length,
            complianceLostCount,
            remediationCount: remediationDurations.length,
            averageTimeToRemediateMinutes: avgRemediation,
            longestNonCompliantPeriodMinutes: longestNonCompliant > 0 ? Math.round(longestNonCompliant) : null,
            currentComplianceStreakDays: currentStreakDays,
        };
    }

    // ------------------------------------------------------------------ //
    //  Seed demo data
    // ------------------------------------------------------------------ //

    _seedTimelineData() {
        const devices = this.engine.getAllDevices();

        for (const device of devices) {
            const events = [];
            const enrollDate = new Date(device.enrolledAt);

            // 1. Device enrolled
            events.push({
                eventId: uuidv4(),
                deviceId: device.id,
                type: 'device_enrolled',
                timestamp: enrollDate.toISOString(),
                details: {
                    platform: device.platform,
                    osVersion: device.osVersion,
                    enrolledBy: device.owner,
                },
            });

            // 2. Policy assigned (shortly after enrollment)
            const assignDate = new Date(enrollDate.getTime() + this._randomMinutes(5, 30) * 60000);
            events.push({
                eventId: uuidv4(),
                deviceId: device.id,
                type: 'policy_assigned',
                timestamp: assignDate.toISOString(),
                details: {
                    policyId: 'policy-security-baseline',
                    policyName: 'Security Baseline',
                    assignedVia: 'group-all-devices',
                },
            });

            // 3. Policy applied
            const applyDate = new Date(assignDate.getTime() + this._randomMinutes(10, 120) * 60000);
            events.push({
                eventId: uuidv4(),
                deviceId: device.id,
                type: 'policy_applied',
                timestamp: applyDate.toISOString(),
                details: {
                    policyId: 'policy-security-baseline',
                    policyName: 'Security Baseline',
                    settingsApplied: 6,
                    settingsSkipped: 0,
                },
            });

            // 4. Compliance achieved
            const compliantDate = new Date(applyDate.getTime() + this._randomMinutes(5, 60) * 60000);
            events.push({
                eventId: uuidv4(),
                deviceId: device.id,
                type: 'compliance_achieved',
                timestamp: compliantDate.toISOString(),
                details: {
                    evaluationResult: 'all_settings_compliant',
                },
            });

            // 5. For ~30% of devices, simulate compliance loss and remediation
            const deviceIndex = parseInt(device.id.split('-')[1], 10);
            if (deviceIndex % 3 === 0) {
                const lostDate = new Date(compliantDate.getTime() + this._randomMinutes(1440, 10080) * 60000);
                if (lostDate < new Date()) {
                    events.push({
                        eventId: uuidv4(),
                        deviceId: device.id,
                        type: 'compliance_lost',
                        timestamp: lostDate.toISOString(),
                        details: {
                            reason: 'setting_changed_locally',
                            setting: 'firewallEnabled',
                            expectedValue: true,
                            actualValue: false,
                        },
                    });

                    // Remediation
                    const remediateDate = new Date(lostDate.getTime() + this._randomMinutes(30, 480) * 60000);
                    if (remediateDate < new Date()) {
                        events.push({
                            eventId: uuidv4(),
                            deviceId: device.id,
                            type: 'remediation_completed',
                            timestamp: remediateDate.toISOString(),
                            details: {
                                action: 'policy_reapplied',
                                setting: 'firewallEnabled',
                                newValue: true,
                                initiatedBy: 'system_auto_remediation',
                            },
                        });
                    }
                }
            }

            // 6. For ~15% of devices, add an update event
            if (deviceIndex % 7 === 0) {
                const updateDate = new Date(compliantDate.getTime() + this._randomMinutes(2880, 20160) * 60000);
                if (updateDate < new Date()) {
                    events.push({
                        eventId: uuidv4(),
                        deviceId: device.id,
                        type: 'update_installed',
                        timestamp: updateDate.toISOString(),
                        details: {
                            updateId: `KB${5000000 + deviceIndex}`,
                            updateType: 'quality',
                            previousVersion: device.osVersion,
                            newVersion: device.platform === 'Windows' ? '11.24H1' : device.platform === 'macOS' ? '14.4' : '24.04 LTS',
                            rebootRequired: true,
                        },
                    });
                }
            }

            this.timelines.set(device.id, events);
        }

        this.logger.info('Timeline demo data seeded', {
            devicesWithTimelines: this.timelines.size,
        });
    }

    _randomMinutes(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
}

module.exports = ComplianceTimeline;
