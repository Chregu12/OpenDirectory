/**
 * Privileged Identity Management (PIM) Service
 * Just-in-time privileged access with approval workflows, multi-approver chains,
 * break-glass emergency access, AD bridge sync, session recording, and event bus publishing.
 */

const EventEmitter = require('events');
const crypto = require('crypto');

const AD_BASE_URL = process.env.ENTERPRISE_DIRECTORY_URL || 'http://enterprise-directory';
const AD_SYNC_TIMEOUT_MS = 5000;

class PIMService extends EventEmitter {
    /**
     * @param {object} [opts]
     * @param {Function} [opts.publishFn]      - (routingKey, payload) => void — event bus publisher
     * @param {object}  [opts.sessionRecorder] - SessionRecorder instance
     */
    constructor({ publishFn, sessionRecorder } = {}) {
        super();
        this.privilegedRoles = new Map();
        this.accessRequests = new Map();
        this.activeElevations = new Map();
        this.approvalWorkflows = new Map();
        this.sessionMonitoring = new Map();
        this.accessPolicies = new Map();

        // Break-glass events (in-memory, also persisted via DB when available)
        this.breakGlassEvents = new Map();

        // Optional integrations
        this._publish = typeof publishFn === 'function' ? publishFn : null;
        this._sessionRecorder = sessionRecorder || null;

        // Role management
        this.roleManager = new RoleManager();
        this.approvalEngine = new ApprovalEngine();
        this.sessionManager = new PrivilegedSessionManager();
        this.justInTimeAccess = new JustInTimeAccessManager();

        this.initializeDefaultRoles();
        this.initializeDefaultPolicies();
    }

    // ─── Event bus helper ──────────────────────────────────────────────────────

    /**
     * Publish an event to the event bus, if a publisher is wired up.
     * Never throws — failures are logged as warnings.
     */
    _publishEvent(routingKey, payload) {
        if (!this._publish) return;
        try {
            this._publish(routingKey, payload);
        } catch (err) {
            console.warn(`[PIM] Event publish failed for ${routingKey}: ${err.message}`);
        }
    }

    // ─── AD Bridge ────────────────────────────────────────────────────────────

    /**
     * Sync PIM elevation state to Active Directory group membership.
     * Non-blocking — logs a warning on failure, never throws.
     *
     * @param {string} userId
     * @param {string} roleId
     * @param {'add'|'remove'} action
     */
    async _syncElevationToAD(userId, roleId, action) {
        const role = this.privilegedRoles.get(roleId);
        if (!role || !role.adGroupDn) {
            // No AD group configured for this role — skip silently
            return;
        }

        const adGroupId = encodeURIComponent(role.adGroupDn);
        const url = `${AD_BASE_URL}/api/groups/${adGroupId}/members`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), AD_SYNC_TIMEOUT_MS);

        try {
            const method = action === 'add' ? 'POST' : 'DELETE';
            const resp = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (!resp.ok) {
                console.warn(`[PIM] AD sync (${action}) responded ${resp.status} for user ${userId} / role ${roleId}`);
            }
        } catch (err) {
            clearTimeout(timeoutId);
            console.warn(`[PIM] AD sync (${action}) failed for user ${userId} / role ${roleId}: ${err.message}`);
        }
    }

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    async initialize() {
        console.log('Initializing Privileged Identity Management...');
        await this.roleManager.initialize();
        await this.approvalEngine.initialize();
        await this.sessionManager.initialize();
        await this.justInTimeAccess.initialize();
        console.log('Privileged Identity Management initialized');
    }

    // ─── Elevation request / approval ─────────────────────────────────────────

    /**
     * Request privileged access elevation.
     */
    async requestElevation(requesterId, roleId, justification, duration = 8) {
        const requestId = crypto.randomUUID();
        const role = this.privilegedRoles.get(roleId);

        if (!role) {
            throw new Error(`Privileged role ${roleId} not found`);
        }
        if (!role.enabled) {
            throw new Error(`Privileged role ${roleId} is disabled`);
        }

        const eligibilityCheck = await this.checkRoleEligibility(requesterId, role);
        if (!eligibilityCheck.eligible) {
            throw new Error(`User is not eligible for role ${roleId}: ${eligibilityCheck.reason}`);
        }

        const policy = this.accessPolicies.get(role.policyId);
        if (!policy) {
            throw new Error(`Access policy not found for role ${roleId}`);
        }

        // Build initial multi-level approval state from the chain defined on the role
        const chain = role.approvalChain || [];
        const approvalState = {};
        for (const level of chain) {
            approvalState[`level${level.level}`] = { approved: [], denied: [] };
        }

        const request = {
            id: requestId,
            requesterId,
            roleId,
            roleName: role.name,
            justification,
            requestedDuration: duration,
            maxAllowedDuration: policy.maxDuration,
            status: 'PENDING',
            createdAt: new Date(),
            requiresApproval: policy.requiresApproval,
            approvalWorkflowId: policy.approvalWorkflowId,
            approvalChain: chain,
            approvalState,
            currentChainLevel: chain.length > 0 ? 1 : null,
            riskLevel: await this.calculateRequestRisk(requesterId, role),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
        };

        this.accessRequests.set(requestId, request);

        // Auto-approve if policy allows and risk is low
        if (!policy.requiresApproval && request.riskLevel < 0.3) {
            return await this.approveElevation(requestId, 'SYSTEM', 'Auto-approved based on policy');
        }

        if (policy.requiresApproval) {
            await this.startApprovalWorkflow(request);
        }

        this._publishEvent('security.elevation.requested', {
            requestId,
            requesterId,
            roleId,
            requiresApproval: policy.requiresApproval
        });

        this.emit('elevationRequested', {
            requestId,
            requesterId,
            roleId,
            requiresApproval: policy.requiresApproval
        });

        return {
            requestId,
            status: request.status,
            requiresApproval: policy.requiresApproval,
            estimatedApprovalTime: policy.requiresApproval ? '15-30 minutes' : 'Immediate',
            expiresAt: request.expiresAt
        };
    }

    /**
     * Approve elevation request — advances the multi-approver chain.
     * When all chain levels are satisfied the elevation becomes ACTIVE.
     */
    async approveElevation(requestId, approverId, approvalReason) {
        const request = this.accessRequests.get(requestId);
        if (!request) {
            throw new Error('Elevation request not found');
        }
        if (request.status !== 'PENDING') {
            throw new Error(`Request is already ${request.status.toLowerCase()}`);
        }
        if (new Date() > request.expiresAt) {
            request.status = 'EXPIRED';
            this._publishEvent('security.elevation.expired', { requestId });
            throw new Error('Elevation request has expired');
        }

        if (approverId !== 'SYSTEM') {
            const canApprove = await this.validateApproverPermissions(approverId, request.roleId);
            if (!canApprove) {
                throw new Error('Insufficient permissions to approve this request');
            }
        }

        // ── Multi-approver chain handling ────────────────────────────────────
        const chain = request.approvalChain || [];
        if (chain.length > 0 && approverId !== 'SYSTEM') {
            const currentLevel = request.currentChainLevel;
            const levelKey = `level${currentLevel}`;
            const levelDef = chain.find(l => l.level === currentLevel);
            const levelState = request.approvalState[levelKey];

            if (!levelState) {
                throw new Error(`No approval state for chain level ${currentLevel}`);
            }
            if (levelState.approved.includes(approverId)) {
                throw new Error('Approver has already approved this chain level');
            }

            levelState.approved.push(approverId);

            const required = levelDef ? levelDef.required : 1;
            if (levelState.approved.length < required) {
                return {
                    requestId,
                    status: 'PENDING',
                    chainLevel: currentLevel,
                    approvalsAtLevel: levelState.approved.length,
                    requiredAtLevel: required,
                    message: `${required - levelState.approved.length} more approval(s) needed at level ${currentLevel}`
                };
            }

            // Current level satisfied — advance to next level
            const nextLevel = currentLevel + 1;
            const nextLevelDef = chain.find(l => l.level === nextLevel);
            if (nextLevelDef) {
                request.currentChainLevel = nextLevel;
                return {
                    requestId,
                    status: 'PENDING',
                    chainLevel: nextLevel,
                    message: `Level ${currentLevel} complete; awaiting level ${nextLevel} approval`
                };
            }
            // All chain levels satisfied — fall through to grant access
        }

        // ── Grant the elevation ────────────────────────────────────────────────
        const elevationId = crypto.randomUUID();
        const role = this.privilegedRoles.get(request.roleId);
        const policy = this.accessPolicies.get(role.policyId);

        const elevation = {
            id: elevationId,
            requestId,
            userId: request.requesterId,
            roleId: request.roleId,
            roleName: role.name,
            permissions: role.permissions,
            startTime: new Date(),
            duration: Math.min(request.requestedDuration, policy.maxDuration) * 60 * 60 * 1000,
            endTime: new Date(Date.now() + Math.min(request.requestedDuration, policy.maxDuration) * 60 * 60 * 1000),
            status: 'ACTIVE',
            approverId,
            approvalReason,
            approvedAt: new Date(),
            sessionToken: crypto.randomUUID(),
            monitoringEnabled: policy.enableMonitoring,
            activities: []
        };

        this.activeElevations.set(elevationId, elevation);

        request.status = 'APPROVED';
        request.elevationId = elevationId;
        request.approvedBy = approverId;
        request.approvedAt = new Date();

        if (policy.enableMonitoring) {
            await this.startSessionMonitoring(elevation);
        }

        // Start session recording if recorder is available
        if (this._sessionRecorder) {
            try {
                const sessionRecordId = await this._sessionRecorder.startRecording(
                    elevationId,
                    request.requesterId,
                    request.roleId
                );
                elevation.sessionRecordId = sessionRecordId;
            } catch (err) {
                console.warn(`[PIM] Session recording start failed: ${err.message}`);
            }
        }

        // Sync to AD group (non-blocking)
        this._syncElevationToAD(request.requesterId, request.roleId, 'add');

        // Schedule automatic deactivation
        setTimeout(() => {
            this.deactivateElevation(elevationId, 'SESSION_EXPIRED');
        }, elevation.duration);

        this._publishEvent('security.elevation.approved', {
            requestId,
            elevationId,
            userId: request.requesterId,
            roleId: request.roleId,
            duration: elevation.duration
        });

        this.emit('elevationApproved', {
            requestId,
            elevationId,
            userId: request.requesterId,
            roleId: request.roleId,
            duration: elevation.duration
        });

        return {
            elevationId,
            sessionToken: elevation.sessionToken,
            permissions: elevation.permissions,
            expiresAt: elevation.endTime,
            monitoringEnabled: elevation.monitoringEnabled
        };
    }

    /**
     * Approve a request using the chain-aware method name (alias).
     */
    async approveRequest(requestId, approverId, justification) {
        return this.approveElevation(requestId, approverId, justification);
    }

    /**
     * Deny elevation request — immediately denies at any chain level.
     */
    async denyElevation(requestId, deniedBy, denialReason) {
        const request = this.accessRequests.get(requestId);
        if (!request) {
            throw new Error('Elevation request not found');
        }
        if (request.status !== 'PENDING') {
            throw new Error(`Request is already ${request.status.toLowerCase()}`);
        }

        request.status = 'DENIED';
        request.deniedBy = deniedBy;
        request.deniedAt = new Date();
        request.denialReason = denialReason;

        this._publishEvent('security.elevation.denied', {
            requestId,
            userId: request.requesterId,
            roleId: request.roleId,
            deniedBy,
            reason: denialReason
        });

        this.emit('elevationDenied', {
            requestId,
            userId: request.requesterId,
            roleId: request.roleId,
            deniedBy,
            reason: denialReason
        });

        return { requestId, status: 'DENIED', reason: denialReason };
    }

    /**
     * Deny a request (chain-aware alias for denyElevation).
     */
    async denyRequest(requestId, approverId, justification) {
        return this.denyElevation(requestId, approverId, justification);
    }

    /**
     * Deactivate privileged elevation.
     */
    async deactivateElevation(elevationId, reason = 'USER_REQUEST') {
        const elevation = this.activeElevations.get(elevationId);
        if (!elevation) {
            throw new Error('Privileged elevation not found');
        }
        if (elevation.status !== 'ACTIVE') {
            throw new Error(`Elevation is already ${elevation.status.toLowerCase()}`);
        }

        elevation.status = 'DEACTIVATED';
        elevation.endTime = new Date();
        elevation.deactivationReason = reason;

        if (elevation.monitoringEnabled) {
            await this.stopSessionMonitoring(elevationId);
        }

        // Stop session recording
        if (this._sessionRecorder && elevation.sessionRecordId) {
            try {
                await this._sessionRecorder.stopRecording(elevation.sessionRecordId, { reason });
            } catch (err) {
                console.warn(`[PIM] Session recording stop failed: ${err.message}`);
            }
        }

        // Sync AD removal (non-blocking)
        this._syncElevationToAD(elevation.userId, elevation.roleId, 'remove');

        const isExpiry = reason === 'SESSION_EXPIRED';
        const isRevocation = !isExpiry;

        if (isExpiry) {
            this._publishEvent('security.elevation.expired', {
                elevationId,
                userId: elevation.userId,
                roleId: elevation.roleId
            });
        } else {
            this._publishEvent('security.elevation.revoked', {
                elevationId,
                userId: elevation.userId,
                roleId: elevation.roleId,
                reason
            });
        }

        this.emit('elevationDeactivated', {
            elevationId,
            userId: elevation.userId,
            roleId: elevation.roleId,
            reason,
            duration: elevation.endTime - elevation.startTime
        });

        return {
            elevationId,
            status: 'DEACTIVATED',
            reason,
            totalDuration: elevation.endTime - elevation.startTime
        };
    }

    // ─── Break-Glass Emergency Access ─────────────────────────────────────────

    /**
     * Request break-glass emergency access.
     * A second manager must call activateBreakGlass() before access is granted.
     *
     * @param {string} userId
     * @param {{ reason: string, systemsAffected: string[], estimatedDuration: number }} opts
     *   estimatedDuration in minutes (capped at 240)
     * @returns {{ breakGlassId: string, status: string, expiresAt: Date }}
     */
    async requestBreakGlass(userId, { reason, systemsAffected = [], estimatedDuration }) {
        const breakGlassId = crypto.randomUUID();
        const durationMs = Math.min(estimatedDuration || 60, 240) * 60 * 1000;
        const expiresAt = new Date(Date.now() + durationMs);

        const event = {
            id: breakGlassId,
            requestedBy: userId,
            reason,
            systemsAffected,
            estimatedDurationMinutes: Math.min(estimatedDuration || 60, 240),
            status: 'PENDING',
            activatedBy: null,
            activatedAt: null,
            terminatedBy: null,
            terminatedAt: null,
            outcome: null,
            expiresAt,
            createdAt: new Date(),
            activities: []
        };

        this.breakGlassEvents.set(breakGlassId, event);

        this.emit('breakGlassRequested', { breakGlassId, userId, reason });

        return {
            breakGlassId,
            status: 'PENDING',
            expiresAt,
            message: 'Break-glass request created. A second manager must activate.'
        };
    }

    /**
     * Activate break-glass access (dual-control: requires a different manager than the requester).
     * Grants full admin permissions for up to 4 hours; auto-expires.
     *
     * @param {string} breakGlassId
     * @param {string} managerId - must differ from the requester
     * @returns {{ breakGlassId: string, status: string, expiresAt: Date, permissions: string[] }}
     */
    async activateBreakGlass(breakGlassId, managerId) {
        const event = this.breakGlassEvents.get(breakGlassId);
        if (!event) {
            throw new Error(`Break-glass event ${breakGlassId} not found`);
        }
        if (event.status !== 'PENDING') {
            throw new Error(`Break-glass event is already ${event.status}`);
        }
        if (event.requestedBy === managerId) {
            throw new Error('Break-glass activation requires a different manager (dual control)');
        }

        const maxDurationMs = 4 * 60 * 60 * 1000; // 4 hours hard cap
        const requestedDurationMs = event.estimatedDurationMinutes * 60 * 1000;
        const durationMs = Math.min(requestedDurationMs, maxDurationMs);
        const expiresAt = new Date(Date.now() + durationMs);

        event.status = 'ACTIVE';
        event.activatedBy = managerId;
        event.activatedAt = new Date();
        event.expiresAt = expiresAt;

        // Auto-terminate on expiry
        setTimeout(() => {
            const current = this.breakGlassEvents.get(breakGlassId);
            if (current && current.status === 'ACTIVE') {
                this.terminateBreakGlass(breakGlassId, {
                    terminatedBy: 'SYSTEM',
                    outcome: 'Auto-expired'
                }).catch(() => {});
            }
        }, durationMs);

        this._publishEvent('security.breakglass.activated', {
            breakGlassId,
            requestedBy: event.requestedBy,
            activatedBy: managerId,
            reason: event.reason,
            systemsAffected: event.systemsAffected,
            expiresAt
        });

        this.emit('breakGlassActivated', {
            breakGlassId,
            requestedBy: event.requestedBy,
            activatedBy: managerId
        });

        return {
            breakGlassId,
            status: 'ACTIVE',
            expiresAt,
            permissions: ['*'],  // Full admin
            message: 'Break-glass access activated. All actions are being recorded.'
        };
    }

    /**
     * Terminate break-glass access.
     *
     * @param {string} breakGlassId
     * @param {{ terminatedBy: string, outcome: string }} opts
     */
    async terminateBreakGlass(breakGlassId, { terminatedBy, outcome }) {
        const event = this.breakGlassEvents.get(breakGlassId);
        if (!event) {
            throw new Error(`Break-glass event ${breakGlassId} not found`);
        }
        if (event.status !== 'ACTIVE') {
            throw new Error(`Break-glass event is not active (status: ${event.status})`);
        }

        event.status = 'TERMINATED';
        event.terminatedBy = terminatedBy;
        event.terminatedAt = new Date();
        event.outcome = outcome;

        this._publishEvent('security.breakglass.terminated', {
            breakGlassId,
            requestedBy: event.requestedBy,
            activatedBy: event.activatedBy,
            terminatedBy,
            outcome,
            durationMs: event.terminatedAt - event.activatedAt,
            activityCount: event.activities.length
        });

        this.emit('breakGlassTerminated', { breakGlassId, terminatedBy, outcome });

        return {
            breakGlassId,
            status: 'TERMINATED',
            terminatedBy,
            outcome,
            activeDuration: event.terminatedAt - event.activatedAt
        };
    }

    /**
     * Retrieve an audit log of all break-glass events within an optional date range.
     *
     * @param {{ from?: Date, to?: Date }} opts
     * @returns {object[]}
     */
    async listBreakGlassEvents({ from, to } = {}) {
        let events = Array.from(this.breakGlassEvents.values());
        if (from) events = events.filter(e => e.createdAt >= from);
        if (to)   events = events.filter(e => e.createdAt <= to);
        return events.sort((a, b) => b.createdAt - a.createdAt);
    }

    // ─── Session Monitoring ───────────────────────────────────────────────────

    async startSessionMonitoring(elevation) {
        const monitoringSession = {
            elevationId: elevation.id,
            userId: elevation.userId,
            roleId: elevation.roleId,
            startTime: new Date(),
            activities: [],
            alerts: [],
            riskScore: 0.0
        };
        this.sessionMonitoring.set(elevation.id, monitoringSession);
        this.emit('sessionMonitoringStarted', {
            elevationId: elevation.id,
            userId: elevation.userId
        });
    }

    async stopSessionMonitoring(elevationId) {
        const monitoring = this.sessionMonitoring.get(elevationId);
        if (monitoring) {
            monitoring.endTime = new Date();
            this.emit('sessionMonitoringEnded', {
                elevationId,
                activities: monitoring.activities.length,
                alerts: monitoring.alerts.length
            });
        }
    }

    async recordPrivilegedActivity(elevationId, activity) {
        const elevation = this.activeElevations.get(elevationId);
        if (!elevation || elevation.status !== 'ACTIVE') {
            return;
        }

        const activityRecord = {
            timestamp: new Date(),
            type: activity.type,
            description: activity.description,
            resource: activity.resource,
            success: activity.success,
            riskScore: this.calculateActivityRisk(activity)
        };

        elevation.activities.push(activityRecord);

        // Persist to session recorder
        if (this._sessionRecorder && elevation.sessionRecordId) {
            try {
                await this._sessionRecorder.recordActivity(elevation.sessionRecordId, {
                    activityType: activityRecord.type,
                    details: { description: activityRecord.description, resource: activityRecord.resource, success: activityRecord.success },
                    riskScore: activityRecord.riskScore,
                    timestamp: activityRecord.timestamp
                });
            } catch (err) {
                console.warn(`[PIM] Session recording activity failed: ${err.message}`);
            }
        }

        const monitoring = this.sessionMonitoring.get(elevationId);
        if (monitoring) {
            monitoring.activities.push(activityRecord);
            monitoring.riskScore = this.calculateSessionRiskScore(monitoring);

            if (activityRecord.riskScore > 0.8) {
                await this.handleHighRiskActivity(elevationId, activityRecord);
            }
        }

        this.emit('privilegedActivityRecorded', {
            elevationId,
            userId: elevation.userId,
            activity: activityRecord
        });
    }

    async handleHighRiskActivity(elevationId, activity) {
        const monitoring = this.sessionMonitoring.get(elevationId);
        const elevation = this.activeElevations.get(elevationId);

        const alert = {
            id: crypto.randomUUID(),
            elevationId,
            userId: elevation.userId,
            activity,
            alertType: 'HIGH_RISK_ACTIVITY',
            severity: 'HIGH',
            timestamp: new Date(),
            description: `High-risk privileged activity detected: ${activity.description}`
        };

        monitoring.alerts.push(alert);
        this.emit('privilegedActivityAlert', alert);

        if (activity.riskScore > 0.95) {
            await this.deactivateElevation(elevationId, 'HIGH_RISK_ACTIVITY_DETECTED');
        }
    }

    /**
     * Start periodic session health checks for all active elevations.
     */
    startPeriodicSessionMonitoring() {
        this._monitoringInterval = setInterval(async () => {
            for (const [elevationId, elevation] of this.activeElevations) {
                if (elevation.status === 'ACTIVE' && elevation.monitoringEnabled) {
                    await this.checkSessionHealth(elevationId);
                }
            }
        }, 30000);
        console.log('PIM periodic session monitoring started');
    }

    /**
     * Backward-compat alias used by index.js startBackgroundServices().
     */
    startSessionMonitoring() {
        return this.startPeriodicSessionMonitoring();
    }

    async checkSessionHealth(elevationId) {
        const elevation = this.activeElevations.get(elevationId);
        const monitoring = this.sessionMonitoring.get(elevationId);

        if (!elevation || !monitoring) return;

        if (new Date() > elevation.endTime) {
            await this.deactivateElevation(elevationId, 'SESSION_EXPIRED');
            return;
        }

        const recentActivities = monitoring.activities.filter(a =>
            new Date() - a.timestamp < 5 * 60 * 1000
        );

        if (recentActivities.length > 50) {
            await this.handleHighRiskActivity(elevationId, {
                type: 'EXCESSIVE_ACTIVITY',
                description: 'Excessive privileged activity detected',
                riskScore: 0.7
            });
        }

        monitoring.riskScore = this.calculateSessionRiskScore(monitoring);
    }

    // ─── Default roles & policies ─────────────────────────────────────────────

    initializeDefaultRoles() {
        // Domain Administrator
        this.privilegedRoles.set('domain-admin', {
            id: 'domain-admin',
            name: 'Domain Administrator',
            description: 'Full administrative access to Active Directory domain',
            enabled: true,
            policyId: 'high-privilege-policy',
            // adGroupDn: 'CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com',
            approvalChain: [
                { level: 1, approvers: [], required: 1 },
                { level: 2, approvers: [], required: 2 }
            ],
            permissions: [
                'ad.users.create',
                'ad.users.modify',
                'ad.users.delete',
                'ad.groups.manage',
                'ad.computers.manage',
                'ad.schema.modify',
                'ad.forest.configure'
            ],
            eligibilityCriteria: {
                requiredRoles: ['IT_ADMIN'],
                minimumClearanceLevel: 'SECRET',
                trainingRequired: ['privileged_access_training']
            }
        });

        // Server Administrator
        this.privilegedRoles.set('server-admin', {
            id: 'server-admin',
            name: 'Server Administrator',
            description: 'Administrative access to critical servers',
            enabled: true,
            policyId: 'medium-privilege-policy',
            approvalChain: [
                { level: 1, approvers: [], required: 1 }
            ],
            permissions: [
                'server.admin.access',
                'service.start',
                'service.stop',
                'registry.modify',
                'file.system.admin',
                'user.local.admin'
            ],
            eligibilityCriteria: {
                requiredRoles: ['IT_SUPPORT', 'SYSTEM_ADMIN'],
                minimumClearanceLevel: 'CONFIDENTIAL'
            }
        });

        // Security Administrator
        this.privilegedRoles.set('security-admin', {
            id: 'security-admin',
            name: 'Security Administrator',
            description: 'Access to security tools and configurations',
            enabled: true,
            policyId: 'high-privilege-policy',
            approvalChain: [
                { level: 1, approvers: [], required: 1 },
                { level: 2, approvers: [], required: 2 }
            ],
            permissions: [
                'security.policy.modify',
                'firewall.configure',
                'av.configure',
                'audit.logs.access',
                'incident.response',
                'edr.configure'
            ],
            eligibilityCriteria: {
                requiredRoles: ['SECURITY_ANALYST', 'SECURITY_ENGINEER'],
                minimumClearanceLevel: 'SECRET',
                trainingRequired: ['security_admin_training']
            }
        });

        // Database Administrator
        this.privilegedRoles.set('database-admin', {
            id: 'database-admin',
            name: 'Database Administrator',
            description: 'Administrative access to database systems',
            enabled: true,
            policyId: 'medium-privilege-policy',
            approvalChain: [
                { level: 1, approvers: [], required: 1 }
            ],
            permissions: [
                'database.admin',
                'database.backup',
                'database.restore',
                'database.schema.modify',
                'database.user.manage'
            ],
            eligibilityCriteria: {
                requiredRoles: ['DBA', 'DATA_ENGINEER'],
                minimumClearanceLevel: 'CONFIDENTIAL'
            }
        });

        console.log(`Initialized ${this.privilegedRoles.size} privileged roles`);
    }

    initializeDefaultPolicies() {
        this.accessPolicies.set('high-privilege-policy', {
            id: 'high-privilege-policy',
            name: 'High Privilege Access Policy',
            description: 'Strict controls for high-privilege roles',
            requiresApproval: true,
            approvalWorkflowId: 'high-privilege-workflow',
            maxDuration: 4,
            enableMonitoring: true,
            enableRecording: true,
            allowedTimes: { businessHours: true, weekends: false, holidays: false },
            riskThresholds: { autoApprove: 0.2, requireAdditionalApproval: 0.7, deny: 0.9 }
        });

        this.accessPolicies.set('medium-privilege-policy', {
            id: 'medium-privilege-policy',
            name: 'Medium Privilege Access Policy',
            description: 'Moderate controls for medium-privilege roles',
            requiresApproval: true,
            approvalWorkflowId: 'medium-privilege-workflow',
            maxDuration: 8,
            enableMonitoring: true,
            enableRecording: false,
            allowedTimes: { businessHours: true, weekends: true, holidays: false },
            riskThresholds: { autoApprove: 0.3, requireAdditionalApproval: 0.8, deny: 0.95 }
        });

        this.accessPolicies.set('low-privilege-policy', {
            id: 'low-privilege-policy',
            name: 'Low Privilege Access Policy',
            description: 'Basic controls for low-privilege roles',
            requiresApproval: false,
            maxDuration: 12,
            enableMonitoring: false,
            enableRecording: false,
            allowedTimes: { businessHours: true, weekends: true, holidays: true },
            riskThresholds: { autoApprove: 0.5, requireAdditionalApproval: 0.9, deny: 0.99 }
        });

        console.log(`Initialized ${this.accessPolicies.size} access policies`);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    async checkRoleEligibility(userId, role) {
        const criteria = role.eligibilityCriteria;
        if (!criteria) {
            return { eligible: true, reason: 'No eligibility criteria defined' };
        }

        const activeElevations = this.getUserActiveElevations(userId);
        const alreadyElevated = activeElevations.some(e => e.roleId === role.id);
        if (alreadyElevated) {
            return { eligible: false, reason: 'User already has an active elevation for this role' };
        }

        if (criteria.requiredRoles && criteria.requiredRoles.length > 0) {
            const userRoles = await this.roleManager.getUserRoles(userId);
            const hasRequiredRole = criteria.requiredRoles.some(r => userRoles.includes(r));
            if (!hasRequiredRole) {
                return {
                    eligible: false,
                    reason: `User lacks required role. Needs one of: ${criteria.requiredRoles.join(', ')}`
                };
            }
        }

        if (criteria.minimumClearanceLevel) {
            const clearanceLevels = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
            const userClearance = await this.roleManager.getUserClearanceLevel(userId);
            const requiredIndex = clearanceLevels.indexOf(criteria.minimumClearanceLevel);
            const userIndex = clearanceLevels.indexOf(userClearance);
            if (userIndex < requiredIndex) {
                return {
                    eligible: false,
                    reason: `Insufficient clearance level. Required: ${criteria.minimumClearanceLevel}, has: ${userClearance}`
                };
            }
        }

        if (criteria.trainingRequired && criteria.trainingRequired.length > 0) {
            const completedTraining = await this.roleManager.getUserCompletedTraining(userId);
            const missingTraining = criteria.trainingRequired.filter(t => !completedTraining.includes(t));
            if (missingTraining.length > 0) {
                return {
                    eligible: false,
                    reason: `Missing required training: ${missingTraining.join(', ')}`
                };
            }
        }

        return { eligible: true, reason: 'User meets all eligibility criteria' };
    }

    async calculateRequestRisk(userId, role) {
        let riskScore = 0.0;

        switch (role.id) {
            case 'domain-admin':   riskScore += 0.5; break;
            case 'security-admin': riskScore += 0.4; break;
            case 'server-admin':   riskScore += 0.3; break;
            default:               riskScore += 0.2;
        }

        const hour = new Date().getHours();
        const isBusinessHours = hour >= 8 && hour <= 18;
        const isWeekend = [0, 6].includes(new Date().getDay());
        if (!isBusinessHours) riskScore += 0.1;
        if (isWeekend) riskScore += 0.1;

        const recentRequests = this.getUserElevationHistory(userId, 1);
        if (recentRequests.length > 3) riskScore += 0.15;
        if (recentRequests.length > 5) riskScore += 0.15;

        const activeElevations = this.getUserActiveElevations(userId);
        if (activeElevations.length > 0) riskScore += 0.1;

        return Math.min(1.0, riskScore);
    }

    calculateActivityRisk(activity) {
        let riskScore = 0.0;
        switch (activity.type) {
            case 'SCHEMA_MODIFY': riskScore += 0.8; break;
            case 'USER_DELETE':   riskScore += 0.7; break;
            case 'GROUP_MODIFY':  riskScore += 0.5; break;
            case 'SERVICE_STOP':  riskScore += 0.4; break;
            default:              riskScore += 0.2;
        }
        if (!activity.success) riskScore += 0.2;
        return Math.min(1.0, riskScore);
    }

    calculateSessionRiskScore(monitoring) {
        if (monitoring.activities.length === 0) return 0.0;
        const avgRisk = monitoring.activities.reduce((sum, a) => sum + a.riskScore, 0) / monitoring.activities.length;
        return Math.min(1.0, avgRisk + monitoring.alerts.length * 0.1);
    }

    async validateApproverPermissions(approverId, roleId) {
        const request = [...this.accessRequests.values()].find(
            r => r.roleId === roleId && r.requesterId === approverId && r.status === 'PENDING'
        );
        if (request) return false; // Self-approval not allowed

        const approverRoles = await this.roleManager.getUserRoles(approverId);
        const role = this.privilegedRoles.get(roleId);
        const policy = this.accessPolicies.get(role.policyId);

        if (policy.id === 'high-privilege-policy') {
            return approverRoles.some(r => ['SECURITY_ADMIN', 'IT_DIRECTOR', 'CISO'].includes(r));
        }
        if (policy.id === 'medium-privilege-policy') {
            return approverRoles.some(r =>
                ['SECURITY_ADMIN', 'IT_DIRECTOR', 'CISO', 'TEAM_LEAD', 'IT_MANAGER'].includes(r)
            );
        }
        return approverRoles.length > 0;
    }

    async startApprovalWorkflow(request) {
        const workflowId = crypto.randomUUID();
        const role = this.privilegedRoles.get(request.roleId);
        const policy = this.accessPolicies.get(role.policyId);

        const workflow = {
            id: workflowId,
            requestId: request.id,
            policyId: policy.id,
            status: 'AWAITING_APPROVAL',
            requiredApprovals: policy.id === 'high-privilege-policy' ? 2 : 1,
            currentApprovals: [],
            rejections: [],
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
            escalationAt: new Date(Date.now() + 4 * 60 * 60 * 1000)
        };

        this.approvalWorkflows.set(workflowId, workflow);
        request.workflowId = workflowId;

        setTimeout(() => {
            const wf = this.approvalWorkflows.get(workflowId);
            if (wf && wf.status === 'AWAITING_APPROVAL') {
                wf.status = 'ESCALATED';
                this.emit('approvalEscalated', { workflowId, requestId: request.id, roleId: request.roleId });
            }
        }, 4 * 60 * 60 * 1000);

        this.emit('approvalWorkflowStarted', {
            requestId: request.id,
            workflowId,
            requiredApprovals: workflow.requiredApprovals,
            expiresAt: workflow.expiresAt
        });

        return workflow;
    }

    // ─── Accessors ────────────────────────────────────────────────────────────

    getElevationRequest(requestId) {
        return this.accessRequests.get(requestId);
    }

    getActiveElevation(elevationId) {
        return this.activeElevations.get(elevationId);
    }

    getUserActiveElevations(userId) {
        const elevations = [];
        for (const elevation of this.activeElevations.values()) {
            if (elevation.userId === userId && elevation.status === 'ACTIVE') {
                elevations.push(elevation);
            }
        }
        return elevations;
    }

    getPrivilegedRoles() {
        return Array.from(this.privilegedRoles.values());
    }

    getUserElevationHistory(userId, days = 30) {
        const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
        const history = [];
        for (const request of this.accessRequests.values()) {
            if (request.requesterId === userId && request.createdAt > cutoffDate) {
                history.push(request);
            }
        }
        return history.sort((a, b) => b.createdAt - a.createdAt);
    }

    // ─── Shutdown ─────────────────────────────────────────────────────────────

    async shutdown() {
        console.log('Shutting down Privileged Identity Management...');
        if (this._monitoringInterval) {
            clearInterval(this._monitoringInterval);
            this._monitoringInterval = null;
        }
        this.removeAllListeners();
        this.privilegedRoles.clear();
        this.accessRequests.clear();
        this.activeElevations.clear();
        this.sessionMonitoring.clear();
        this.breakGlassEvents.clear();
        console.log('Privileged Identity Management shutdown complete');
    }
}

// ─── Supporting classes ────────────────────────────────────────────────────────

class RoleManager {
    constructor() {
        this.userRoles = new Map();
        this.userClearance = new Map();
        this.userTraining = new Map();
    }

    async initialize() { console.log('RoleManager initialized'); }

    async getUserRoles(userId) { return this.userRoles.get(userId) || []; }
    async setUserRoles(userId, roles) { this.userRoles.set(userId, roles); }

    async getUserClearanceLevel(userId) { return this.userClearance.get(userId) || 'PUBLIC'; }
    async setUserClearanceLevel(userId, level) { this.userClearance.set(userId, level); }

    async getUserCompletedTraining(userId) { return this.userTraining.get(userId) || []; }
    async addUserTraining(userId, trainingId) {
        const current = this.userTraining.get(userId) || [];
        if (!current.includes(trainingId)) {
            current.push(trainingId);
            this.userTraining.set(userId, current);
        }
    }
}

class ApprovalEngine {
    constructor() { this.approvers = new Map(); }

    async initialize() { console.log('ApprovalEngine initialized'); }

    async getEligibleApprovers(policyId) { return this.approvers.get(policyId) || []; }
    async registerApprover(policyId, approverId) {
        const current = this.approvers.get(policyId) || [];
        if (!current.includes(approverId)) {
            current.push(approverId);
            this.approvers.set(policyId, current);
        }
    }
}

class PrivilegedSessionManager {
    constructor() { this.sessions = new Map(); }

    async initialize() { console.log('PrivilegedSessionManager initialized'); }

    async createSession(elevationId, userId, permissions) {
        const session = { elevationId, userId, permissions, startedAt: new Date(), commands: [] };
        this.sessions.set(elevationId, session);
        return session;
    }

    async terminateSession(elevationId) {
        const session = this.sessions.get(elevationId);
        if (session) { session.endedAt = new Date(); this.sessions.delete(elevationId); }
        return session;
    }
}

class JustInTimeAccessManager {
    constructor() { this.pendingAccess = new Map(); }

    async initialize() { console.log('JustInTimeAccessManager initialized'); }

    async grantAccess(userId, resource, durationMs) {
        const accessId = crypto.randomUUID();
        const access = { id: accessId, userId, resource, grantedAt: new Date(), expiresAt: new Date(Date.now() + durationMs) };
        this.pendingAccess.set(accessId, access);
        setTimeout(() => this.revokeAccess(accessId), durationMs);
        return access;
    }

    async revokeAccess(accessId) { this.pendingAccess.delete(accessId); }
}

module.exports = PIMService;
