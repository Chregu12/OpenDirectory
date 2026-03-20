'use strict';

const { EventEmitter } = require('events');
const { v4: uuidv4 } = require('uuid');

/**
 * Risk thresholds for auto-approval
 */
const RISK_THRESHOLDS = {
    AUTO_APPROVE: 'low',       // Auto-execute low-risk remediations
    REQUIRE_APPROVAL: 'high'   // Require manual approval for high/critical
};

const ISSUE_SEVERITY = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
};

const EXECUTION_STATUS = {
    PENDING: 'pending',
    APPROVED: 'approved',
    EXECUTING: 'executing',
    COMPLETED: 'completed',
    FAILED: 'failed',
    AWAITING_APPROVAL: 'awaiting_approval',
    REJECTED: 'rejected',
    CANCELLED: 'cancelled'
};

/**
 * Orchestrates the full remediation lifecycle: detect issues, generate fixes,
 * enforce approval workflows, execute remediations, and track history / metrics.
 */
class RemediationEngine extends EventEmitter {
    constructor(scriptGenerator, playbookManager) {
        super();
        this.scriptGenerator = scriptGenerator;
        this.playbookManager = playbookManager;

        this.issues = new Map();
        this.executionHistory = [];

        this._seedDemoIssues();
    }

    // ------------------------------------------------------------------ //
    //  Issue Detection
    // ------------------------------------------------------------------ //

    /**
     * Detect compliance / security issues across managed devices.
     * In production this would query device inventories and compliance feeds;
     * here it simulates a scan and returns newly-detected issues.
     */
    detectIssues(options = {}) {
        const { platform, deviceId, rescan = false } = options;
        const scanId = uuidv4();
        const scanStarted = new Date().toISOString();

        // If rescan is requested, clear non-executing issues so they can be re-detected
        if (rescan) {
            for (const [id, issue] of this.issues.entries()) {
                if (issue.status === EXECUTION_STATUS.PENDING) {
                    this.issues.delete(id);
                }
            }
        }

        // Simulated detection results (in production, replaced by real telemetry)
        const detectedIssues = this._simulateDetection(platform, deviceId);

        const newIssues = [];
        for (const issue of detectedIssues) {
            if (!this.issues.has(issue.id)) {
                this.issues.set(issue.id, issue);
                newIssues.push(issue);
            }
        }

        const scanResult = {
            scanId,
            scanStarted,
            scanCompleted: new Date().toISOString(),
            totalDetected: detectedIssues.length,
            newIssues: newIssues.length,
            existingIssues: detectedIssues.length - newIssues.length,
            issues: newIssues,
            filters: { platform: platform || 'all', deviceId: deviceId || 'all' }
        };

        this.emit('issuesDetected', scanResult);
        return scanResult;
    }

    // ------------------------------------------------------------------ //
    //  Issue Queries
    // ------------------------------------------------------------------ //

    /**
     * Get all detected issues with optional filtering and pagination.
     */
    getIssues(filters = {}) {
        let issues = Array.from(this.issues.values());

        if (filters.status) {
            issues = issues.filter(i => i.status === filters.status);
        }
        if (filters.severity) {
            issues = issues.filter(i => i.severity === filters.severity);
        }
        if (filters.type) {
            issues = issues.filter(i => i.type === filters.type);
        }
        if (filters.deviceId) {
            issues = issues.filter(i => i.deviceId === filters.deviceId);
        }
        if (filters.platform) {
            issues = issues.filter(i => i.platform.toLowerCase() === filters.platform.toLowerCase());
        }

        // Pagination
        const page = parseInt(filters.page) || 1;
        const limit = parseInt(filters.limit) || 50;
        const startIndex = (page - 1) * limit;
        const total = issues.length;

        // Sort by severity (critical first) then detection date (newest first)
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        issues.sort((a, b) => {
            const sevDiff = (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99);
            if (sevDiff !== 0) return sevDiff;
            return new Date(b.detectedAt) - new Date(a.detectedAt);
        });

        const paginatedIssues = issues.slice(startIndex, startIndex + limit);

        return {
            issues: paginatedIssues,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            }
        };
    }

    /**
     * Get a single issue by ID, enriched with its generated remediation script.
     */
    getIssueById(issueId) {
        const issue = this.issues.get(issueId);
        if (!issue) return null;

        const script = this.scriptGenerator.generateScript(issue);

        return {
            ...issue,
            remediation: {
                script: script.script,
                language: script.language,
                description: script.description,
                requiresReboot: script.requiresReboot,
                estimatedDuration: script.estimatedDuration,
                generatedAt: script.generatedAt
            },
            autoApproveEligible: this._isAutoApproveEligible(issue)
        };
    }

    // ------------------------------------------------------------------ //
    //  Execution
    // ------------------------------------------------------------------ //

    /**
     * Execute remediation for a single issue.
     * Low/medium-risk issues are auto-approved; high/critical require explicit
     * approval or the `force` flag.
     */
    executeRemediation(issueId, { executedBy = 'api-user', force = false } = {}) {
        const issue = this.issues.get(issueId);
        if (!issue) {
            throw new Error(`Issue ${issueId} not found`);
        }

        if (issue.status === EXECUTION_STATUS.COMPLETED) {
            throw new Error(`Issue ${issueId} has already been remediated`);
        }

        if (issue.status === EXECUTION_STATUS.EXECUTING) {
            throw new Error(`Issue ${issueId} is currently being remediated`);
        }

        // Approval workflow
        const needsApproval = !this._isAutoApproveEligible(issue);
        if (needsApproval && !force) {
            if (issue.status !== EXECUTION_STATUS.APPROVED) {
                issue.status = EXECUTION_STATUS.AWAITING_APPROVAL;
                issue.approvalRequestedAt = new Date().toISOString();
                issue.approvalRequestedBy = executedBy;

                return {
                    success: false,
                    requiresApproval: true,
                    issueId,
                    message: `Issue severity is "${issue.severity}". Manual approval required before execution. Use force=true to override.`,
                    status: EXECUTION_STATUS.AWAITING_APPROVAL
                };
            }
        }

        // Generate the script
        const scriptResult = this.scriptGenerator.generateScript(issue);

        // Mark as executing
        issue.status = EXECUTION_STATUS.EXECUTING;
        issue.executionStartedAt = new Date().toISOString();

        // Simulate execution outcome (90 % success in demo mode)
        const success = Math.random() > 0.1;

        const executionRecord = {
            id: uuidv4(),
            issueId,
            issueType: issue.type,
            deviceId: issue.deviceId,
            deviceHostname: issue.deviceHostname,
            platform: issue.platform,
            status: success ? EXECUTION_STATUS.COMPLETED : EXECUTION_STATUS.FAILED,
            executedAt: issue.executionStartedAt,
            completedAt: new Date().toISOString(),
            duration: scriptResult.estimatedDuration,
            executedBy,
            scriptLanguage: scriptResult.language,
            result: success
                ? { message: 'Remediation completed successfully', requiresReboot: scriptResult.requiresReboot }
                : { error: 'Remediation execution failed. Check device agent logs for details.' },
            success
        };

        // Update issue
        issue.status = success ? EXECUTION_STATUS.COMPLETED : EXECUTION_STATUS.FAILED;
        issue.completedAt = executionRecord.completedAt;
        issue.executionResult = executionRecord;

        this.executionHistory.push(executionRecord);
        this.emit('remediationExecuted', executionRecord);

        return {
            success,
            execution: executionRecord,
            message: success
                ? 'Remediation executed successfully'
                : 'Remediation execution failed. Manual intervention may be required.'
        };
    }

    /**
     * Bulk-execute remediation for an array of issue IDs.
     */
    bulkExecute(issueIds, { executedBy = 'api-user', force = false } = {}) {
        const results = {
            successful: [],
            failed: [],
            awaitingApproval: [],
            timestamp: new Date().toISOString()
        };

        for (const issueId of issueIds) {
            try {
                const result = this.executeRemediation(issueId, { executedBy, force });
                if (result.requiresApproval) {
                    results.awaitingApproval.push({ issueId, message: result.message });
                } else if (result.success) {
                    results.successful.push({ issueId, execution: result.execution });
                } else {
                    results.failed.push({ issueId, error: result.message });
                }
            } catch (error) {
                results.failed.push({ issueId, error: error.message });
            }
        }

        results.summary = {
            total: issueIds.length,
            succeeded: results.successful.length,
            failed: results.failed.length,
            awaitingApproval: results.awaitingApproval.length
        };

        this.emit('bulkRemediationExecuted', results);
        return results;
    }

    // ------------------------------------------------------------------ //
    //  Scripts
    // ------------------------------------------------------------------ //

    /**
     * Return the generated remediation script for an issue without executing it.
     */
    getScript(issueId) {
        const issue = this.issues.get(issueId);
        if (!issue) return null;

        return this.scriptGenerator.generateScript(issue);
    }

    // ------------------------------------------------------------------ //
    //  History & Statistics
    // ------------------------------------------------------------------ //

    /**
     * Get execution history with optional filtering and pagination.
     */
    getHistory(filters = {}) {
        let history = [...this.executionHistory];

        if (filters.status) {
            history = history.filter(h => h.status === filters.status);
        }
        if (filters.deviceId) {
            history = history.filter(h => h.deviceId === filters.deviceId);
        }
        if (filters.issueType) {
            history = history.filter(h => h.issueType === filters.issueType);
        }
        if (filters.success !== undefined) {
            const successBool = filters.success === 'true' || filters.success === true;
            history = history.filter(h => h.success === successBool);
        }

        // Sort newest first
        history.sort((a, b) => new Date(b.executedAt) - new Date(a.executedAt));

        const page = parseInt(filters.page) || 1;
        const limit = parseInt(filters.limit) || 50;
        const startIndex = (page - 1) * limit;
        const total = history.length;
        const paginatedHistory = history.slice(startIndex, startIndex + limit);

        return {
            history: paginatedHistory,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            }
        };
    }

    /**
     * Compute aggregate remediation statistics.
     */
    getStatistics() {
        const allHistory = this.executionHistory;
        const totalExecutions = allHistory.length;
        const successfulExecutions = allHistory.filter(h => h.success).length;
        const failedExecutions = allHistory.filter(h => !h.success).length;
        const successRate = totalExecutions > 0
            ? Math.round((successfulExecutions / totalExecutions) * 10000) / 100
            : 0;

        // By issue type
        const byType = {};
        for (const execution of allHistory) {
            if (!byType[execution.issueType]) {
                byType[execution.issueType] = { total: 0, successful: 0, failed: 0 };
            }
            byType[execution.issueType].total += 1;
            if (execution.success) {
                byType[execution.issueType].successful += 1;
            } else {
                byType[execution.issueType].failed += 1;
            }
        }

        for (const type of Object.keys(byType)) {
            const data = byType[type];
            data.successRate = data.total > 0
                ? Math.round((data.successful / data.total) * 10000) / 100
                : 0;
        }

        // By platform
        const byPlatform = {};
        for (const execution of allHistory) {
            if (!byPlatform[execution.platform]) {
                byPlatform[execution.platform] = { total: 0, successful: 0, failed: 0 };
            }
            byPlatform[execution.platform].total += 1;
            if (execution.success) {
                byPlatform[execution.platform].successful += 1;
            } else {
                byPlatform[execution.platform].failed += 1;
            }
        }

        // Current open issues
        const openIssues = Array.from(this.issues.values()).filter(
            i => i.status === EXECUTION_STATUS.PENDING || i.status === EXECUTION_STATUS.AWAITING_APPROVAL
        );

        const openBySeverity = {};
        for (const issue of openIssues) {
            openBySeverity[issue.severity] = (openBySeverity[issue.severity] || 0) + 1;
        }

        return {
            summary: {
                totalExecutions,
                successfulExecutions,
                failedExecutions,
                successRate: `${successRate}%`,
                openIssues: openIssues.length,
                awaitingApproval: Array.from(this.issues.values()).filter(
                    i => i.status === EXECUTION_STATUS.AWAITING_APPROVAL
                ).length
            },
            byIssueType: byType,
            byPlatform,
            openIssuesBySeverity: openBySeverity,
            generatedAt: new Date().toISOString()
        };
    }

    // ------------------------------------------------------------------ //
    //  Private helpers
    // ------------------------------------------------------------------ //

    /**
     * Determine if an issue qualifies for automatic approval.
     * Low-severity issues are always auto-approved; medium-severity issues
     * are auto-approved only for certain non-destructive remediation types.
     */
    _isAutoApproveEligible(issue) {
        if (issue.severity === ISSUE_SEVERITY.LOW) {
            return true;
        }
        if (issue.severity === ISSUE_SEVERITY.MEDIUM) {
            const safeTypes = ['missing-updates', 'firewall-disabled'];
            return safeTypes.includes(issue.type);
        }
        return false;
    }

    /**
     * Simulate a detection scan returning issue objects.
     * Filters results by platform / deviceId when provided.
     */
    _simulateDetection(platform, deviceId) {
        const allIssues = this._getDemoIssues();

        let filtered = allIssues;
        if (platform) {
            filtered = filtered.filter(i => i.platform.toLowerCase() === platform.toLowerCase());
        }
        if (deviceId) {
            filtered = filtered.filter(i => i.deviceId === deviceId);
        }
        return filtered;
    }

    /**
     * Seed the in-memory stores with demo issues and historical executions.
     */
    _seedDemoIssues() {
        const demoIssues = this._getDemoIssues();

        const historicalExecutions = [
            {
                id: uuidv4(),
                issueId: 'issue-hist-001',
                issueType: 'missing-updates',
                deviceId: 'dev-001',
                deviceHostname: 'DESKTOP-PROD-01',
                platform: 'windows',
                status: EXECUTION_STATUS.COMPLETED,
                executedAt: '2024-03-05T14:00:00Z',
                completedAt: '2024-03-05T14:35:00Z',
                duration: '35 minutes',
                executedBy: 'auto-remediation',
                result: { updatesInstalled: 3, rebootRequired: true },
                success: true
            },
            {
                id: uuidv4(),
                issueId: 'issue-hist-002',
                issueType: 'bitlocker-disabled',
                deviceId: 'dev-005',
                deviceHostname: 'DESKTOP-FIN-09',
                platform: 'windows',
                status: EXECUTION_STATUS.COMPLETED,
                executedAt: '2024-02-28T10:00:00Z',
                completedAt: '2024-02-28T10:40:00Z',
                duration: '40 minutes',
                executedBy: 'admin@company.com',
                result: { encryptionStarted: true, recoveryKeyBackedUp: true },
                success: true
            },
            {
                id: uuidv4(),
                issueId: 'issue-hist-003',
                issueType: 'firewall-disabled',
                deviceId: 'dev-001',
                deviceHostname: 'DESKTOP-PROD-01',
                platform: 'windows',
                status: EXECUTION_STATUS.COMPLETED,
                executedAt: '2024-03-01T09:00:00Z',
                completedAt: '2024-03-01T09:02:00Z',
                duration: '2 minutes',
                executedBy: 'auto-remediation',
                result: { firewallEnabled: true, profiles: ['Domain', 'Public', 'Private'] },
                success: true
            },
            {
                id: uuidv4(),
                issueId: 'issue-hist-004',
                issueType: 'edr-missing',
                deviceId: 'dev-002',
                deviceHostname: 'MACBOOK-ENG-07',
                platform: 'macos',
                status: EXECUTION_STATUS.COMPLETED,
                executedAt: '2024-02-20T15:00:00Z',
                completedAt: '2024-02-20T15:12:00Z',
                duration: '12 minutes',
                executedBy: 'admin@company.com',
                result: { agentInstalled: true, agentVersion: '7.04.17605' },
                success: true
            },
            {
                id: uuidv4(),
                issueId: 'issue-hist-005',
                issueType: 'missing-updates',
                deviceId: 'dev-003',
                deviceHostname: 'LAPTOP-SALES-12',
                platform: 'windows',
                status: EXECUTION_STATUS.FAILED,
                executedAt: '2024-03-01T11:00:00Z',
                completedAt: '2024-03-01T11:45:00Z',
                duration: '45 minutes',
                executedBy: 'auto-remediation',
                result: { error: 'Insufficient disk space (2.1 GB available, 4.5 GB required)' },
                success: false
            },
            {
                id: uuidv4(),
                issueId: 'issue-hist-006',
                issueType: 'password-expired',
                deviceId: 'dev-005',
                deviceHostname: 'DESKTOP-FIN-09',
                platform: 'windows',
                status: EXECUTION_STATUS.COMPLETED,
                executedAt: '2024-03-08T08:30:00Z',
                completedAt: '2024-03-08T08:31:00Z',
                duration: '1 minute',
                executedBy: 'auto-remediation',
                result: { passwordExpired: true, nextLoginForceChange: true },
                success: true
            }
        ];

        for (const issue of demoIssues) {
            this.issues.set(issue.id, issue);
        }

        this.executionHistory = historicalExecutions;
    }

    /**
     * Return the canonical set of demo issues (used by both seeding and detection).
     */
    _getDemoIssues() {
        return [
            {
                id: 'issue-001',
                type: 'bitlocker-disabled',
                title: 'BitLocker not enabled',
                description: 'BitLocker drive encryption is disabled on system drive C:',
                deviceId: 'dev-003',
                deviceHostname: 'LAPTOP-SALES-12',
                platform: 'windows',
                owner: 'carol.davis@company.com',
                severity: ISSUE_SEVERITY.CRITICAL,
                detectedAt: '2024-03-08T14:30:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    drive: 'C:',
                    currentStatus: 'Off'
                }
            },
            {
                id: 'issue-002',
                type: 'missing-updates',
                title: '5 pending security updates',
                description: 'Device has 5 pending security updates including 2 critical patches',
                deviceId: 'dev-003',
                deviceHostname: 'LAPTOP-SALES-12',
                platform: 'windows',
                owner: 'carol.davis@company.com',
                severity: ISSUE_SEVERITY.HIGH,
                detectedAt: '2024-03-09T08:00:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    pendingCount: 5,
                    criticalCount: 2,
                    updateNames: ['KB5034763', 'KB5034441', 'KB5034122', 'KB5033918', 'KB5033372']
                }
            },
            {
                id: 'issue-003',
                type: 'edr-missing',
                title: 'EDR agent not installed',
                description: 'No endpoint detection and response agent found on this Linux workstation',
                deviceId: 'dev-004',
                deviceHostname: 'UBUNTU-DEV-03',
                platform: 'linux',
                owner: 'dave.wilson@company.com',
                severity: ISSUE_SEVERITY.CRITICAL,
                detectedAt: '2024-03-07T10:15:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    expectedAgent: 'CrowdStrike Falcon',
                    lastSeen: null
                }
            },
            {
                id: 'issue-004',
                type: 'edr-missing',
                title: 'EDR agent not installed',
                description: 'Endpoint detection agent not installed on newly configured Surface device',
                deviceId: 'dev-006',
                deviceHostname: 'SURFACE-EXEC-01',
                platform: 'windows',
                owner: 'frank.chen@company.com',
                severity: ISSUE_SEVERITY.HIGH,
                detectedAt: '2024-03-02T11:00:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    expectedAgent: 'Microsoft Defender for Endpoint',
                    lastSeen: null
                }
            },
            {
                id: 'issue-005',
                type: 'firewall-disabled',
                title: 'Windows Firewall disabled',
                description: 'Windows Firewall is disabled on all profiles for this retiring device',
                deviceId: 'dev-007',
                deviceHostname: 'LAPTOP-HR-04',
                platform: 'windows',
                owner: 'grace.lee@company.com',
                severity: ISSUE_SEVERITY.HIGH,
                detectedAt: '2024-02-22T09:45:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    domainProfile: 'disabled',
                    privateProfile: 'disabled',
                    publicProfile: 'disabled'
                }
            },
            {
                id: 'issue-006',
                type: 'missing-updates',
                title: '12 pending updates including critical security patches',
                description: 'Device has 12 pending updates and has not been updated in over 30 days',
                deviceId: 'dev-007',
                deviceHostname: 'LAPTOP-HR-04',
                platform: 'windows',
                owner: 'grace.lee@company.com',
                severity: ISSUE_SEVERITY.CRITICAL,
                detectedAt: '2024-02-22T09:45:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    pendingCount: 12,
                    criticalCount: 5,
                    daysSinceLastUpdate: 35
                }
            },
            {
                id: 'issue-007',
                type: 'missing-updates',
                title: '2 pending macOS updates',
                description: 'macOS Sonoma 14.3.1 and Safari 17.3.1 updates available',
                deviceId: 'dev-002',
                deviceHostname: 'MACBOOK-ENG-07',
                platform: 'macos',
                owner: 'bob.smith@company.com',
                severity: ISSUE_SEVERITY.LOW,
                detectedAt: '2024-03-10T12:00:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    pendingCount: 2,
                    criticalCount: 0,
                    updateNames: ['macOS Sonoma 14.3.1', 'Safari 17.3.1']
                }
            },
            {
                id: 'issue-008',
                type: 'required-app-missing',
                title: 'Required application missing: CrowdStrike Falcon',
                description: 'CrowdStrike Falcon agent is required for all corporate devices but is not installed',
                deviceId: 'dev-004',
                deviceHostname: 'UBUNTU-DEV-03',
                platform: 'linux',
                owner: 'dave.wilson@company.com',
                severity: ISSUE_SEVERITY.HIGH,
                detectedAt: '2024-03-07T10:15:00Z',
                status: EXECUTION_STATUS.PENDING,
                details: {
                    appName: 'CrowdStrike Falcon',
                    packageName: 'falcon-sensor',
                    required: true
                }
            }
        ];
    }
}

module.exports = RemediationEngine;
module.exports.ISSUE_SEVERITY = ISSUE_SEVERITY;
module.exports.EXECUTION_STATUS = EXECUTION_STATUS;
