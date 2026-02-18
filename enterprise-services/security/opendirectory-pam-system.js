/**
 * OpenDirectory Privilege Access Management (PAM) System
 * Provides just-in-time access provisioning, credential vaulting, and privileged session management
 */

const crypto = require('crypto');
const EventEmitter = require('events');
const express = require('express');

class PrivilegeAccessManager extends EventEmitter {
    constructor() {
        super();
        this.privilegedSessions = new Map();
        this.credentialVault = new Map();
        this.accessRequests = new Map();
        this.approvalWorkflows = new Map();
        this.sessionRecordings = new Map();
        this.privilegeEscalations = new Map();
        this.emergencyAccess = new Map();
        this.passwordRotationJobs = new Map();
        
        this.initializePAM();
        this.startSessionMonitoring();
        this.startPasswordRotation();
    }

    /**
     * Initialize the PAM system
     */
    initializePAM() {
        console.log('🔑 Initializing Privilege Access Management System...');
        
        // Initialize JIT access provisioner
        this.jitProvisioner = new JITAccessProvisioner();
        
        // Initialize credential manager
        this.credentialManager = new CredentialManager();
        
        // Initialize session manager
        this.sessionManager = new PrivilegedSessionManager();
        
        // Initialize approval engine
        this.approvalEngine = new ApprovalWorkflowEngine();
        
        // Initialize session recorder
        this.sessionRecorder = new SessionRecorder();
        
        // Initialize command filter
        this.commandFilter = new CommandFilter();
        
        console.log('✅ Privilege Access Management System initialized');
    }

    /**
     * Just-in-time (JIT) access provisioning
     */
    async requestJITAccess(requestConfig) {
        try {
            const accessRequest = {
                id: crypto.randomUUID(),
                userId: requestConfig.userId,
                targetResource: requestConfig.targetResource,
                requestedPrivileges: requestConfig.requestedPrivileges,
                justification: requestConfig.justification,
                duration: requestConfig.duration || 3600000, // 1 hour default
                urgency: requestConfig.urgency || 'normal',
                businessContext: requestConfig.businessContext || '',
                requestedAt: new Date(),
                expiresAt: new Date(Date.now() + (requestConfig.duration || 3600000)),
                status: 'pending_approval',
                approvals: [],
                rejections: [],
                metadata: requestConfig.metadata || {}
            };

            // Determine required approvers
            const requiredApprovers = await this.determineRequiredApprovers(accessRequest);
            accessRequest.requiredApprovers = requiredApprovers;

            // Store access request
            this.accessRequests.set(accessRequest.id, accessRequest);

            // Initiate approval workflow
            await this.initiateApprovalWorkflow(accessRequest);

            this.emit('jitAccessRequested', {
                requestId: accessRequest.id,
                userId: accessRequest.userId,
                targetResource: accessRequest.targetResource,
                requiredApprovers: requiredApprovers.length,
                urgency: accessRequest.urgency,
                timestamp: new Date()
            });

            return {
                requestId: accessRequest.id,
                status: 'pending_approval',
                requiredApprovers: requiredApprovers.length,
                estimatedApprovalTime: this.estimateApprovalTime(accessRequest),
                expiresAt: accessRequest.expiresAt
            };

        } catch (error) {
            console.error('JIT access request error:', error);
            throw error;
        }
    }

    /**
     * Approve or reject JIT access requests
     */
    async processAccessApproval(requestId, approverId, decision, comments = '') {
        try {
            const accessRequest = this.accessRequests.get(requestId);
            if (!accessRequest) {
                throw new Error('Access request not found');
            }

            if (accessRequest.status !== 'pending_approval') {
                throw new Error('Request is not in pending approval state');
            }

            const approval = {
                approverId,
                decision, // 'approved' or 'rejected'
                comments,
                timestamp: new Date()
            };

            if (decision === 'approved') {
                accessRequest.approvals.push(approval);
            } else {
                accessRequest.rejections.push(approval);
                accessRequest.status = 'rejected';
                accessRequest.rejectedAt = new Date();
            }

            // Check if all required approvals are received
            const approvedBy = new Set(accessRequest.approvals.map(a => a.approverId));
            const allRequired = accessRequest.requiredApprovers.every(approver => 
                approvedBy.has(approver.id)
            );

            if (allRequired && decision === 'approved') {
                // All approvals received - provision access
                await this.provisionJITAccess(accessRequest);
                accessRequest.status = 'approved';
                accessRequest.approvedAt = new Date();
            }

            this.emit('accessApprovalProcessed', {
                requestId,
                approverId,
                decision,
                status: accessRequest.status,
                timestamp: new Date()
            });

            return {
                requestId,
                status: accessRequest.status,
                decision,
                remainingApprovers: accessRequest.requiredApprovers.length - accessRequest.approvals.length
            };

        } catch (error) {
            console.error('Access approval processing error:', error);
            throw error;
        }
    }

    /**
     * Provision JIT access after approval
     */
    async provisionJITAccess(accessRequest) {
        try {
            // Create temporary privileged account
            const tempAccount = await this.createTemporaryAccount(accessRequest);
            
            // Generate temporary credentials
            const credentials = await this.generateTemporaryCredentials(tempAccount);
            
            // Configure access permissions
            await this.configureAccessPermissions(tempAccount, accessRequest.requestedPrivileges);
            
            // Set up access monitoring
            await this.setupAccessMonitoring(tempAccount, accessRequest);
            
            // Schedule access revocation
            await this.scheduleAccessRevocation(tempAccount, accessRequest.expiresAt);

            // Store provisioned access
            const provisionedAccess = {
                requestId: accessRequest.id,
                accountId: tempAccount.id,
                userId: accessRequest.userId,
                credentials,
                provisionedAt: new Date(),
                expiresAt: accessRequest.expiresAt,
                status: 'active',
                monitoringEnabled: true
            };

            this.jitProvisioner.activeAccess.set(accessRequest.id, provisionedAccess);

            this.emit('jitAccessProvisioned', {
                requestId: accessRequest.id,
                userId: accessRequest.userId,
                accountId: tempAccount.id,
                expiresAt: accessRequest.expiresAt,
                timestamp: new Date()
            });

            return {
                success: true,
                accountId: tempAccount.id,
                credentials: {
                    username: credentials.username,
                    // Don't return password in response for security
                    connectionInfo: credentials.connectionInfo
                },
                expiresAt: accessRequest.expiresAt,
                instructions: tempAccount.instructions
            };

        } catch (error) {
            console.error('JIT access provisioning error:', error);
            throw error;
        }
    }

    /**
     * Privileged session management
     */
    async startPrivilegedSession(sessionConfig) {
        try {
            const session = {
                id: crypto.randomUUID(),
                userId: sessionConfig.userId,
                accountId: sessionConfig.accountId,
                targetResource: sessionConfig.targetResource,
                sessionType: sessionConfig.sessionType || 'ssh',
                startedAt: new Date(),
                lastActivity: new Date(),
                status: 'active',
                commands: [],
                recordings: {
                    enabled: true,
                    videoPath: null,
                    logPath: null
                },
                monitoring: {
                    keystrokes: true,
                    screenshots: true,
                    networkActivity: true
                },
                metadata: sessionConfig.metadata || {}
            };

            // Start session recording
            await this.startSessionRecording(session);
            
            // Enable command monitoring
            await this.enableCommandMonitoring(session);
            
            // Set up session timeout
            this.setSessionTimeout(session);

            this.privilegedSessions.set(session.id, session);

            this.emit('privilegedSessionStarted', {
                sessionId: session.id,
                userId: session.userId,
                targetResource: session.targetResource,
                sessionType: session.sessionType,
                timestamp: new Date()
            });

            return {
                sessionId: session.id,
                status: 'active',
                recordingEnabled: session.recordings.enabled,
                monitoringEnabled: true,
                startedAt: session.startedAt
            };

        } catch (error) {
            console.error('Privileged session start error:', error);
            throw error;
        }
    }

    /**
     * Session recording and playback
     */
    async recordSessionActivity(sessionId, activityData) {
        try {
            const session = this.privilegedSessions.get(sessionId);
            if (!session) {
                throw new Error('Session not found');
            }

            const activity = {
                timestamp: new Date(),
                type: activityData.type, // 'command', 'keystroke', 'screenshot', 'network'
                data: activityData.data,
                metadata: activityData.metadata || {}
            };

            // Store activity
            session.commands.push(activity);
            session.lastActivity = new Date();

            // Check for suspicious commands
            if (activity.type === 'command') {
                const riskScore = await this.assessCommandRisk(activity.data, session);
                if (riskScore > 0.8) {
                    await this.handleHighRiskCommand(session, activity, riskScore);
                }
            }

            // Update session recording
            await this.updateSessionRecording(session, activity);

            this.emit('sessionActivityRecorded', {
                sessionId,
                activityType: activity.type,
                timestamp: activity.timestamp
            });

            return {
                recorded: true,
                activityCount: session.commands.length
            };

        } catch (error) {
            console.error('Session recording error:', error);
            throw error;
        }
    }

    /**
     * Command filtering and control
     */
    async filterCommand(sessionId, command) {
        try {
            const session = this.privilegedSessions.get(sessionId);
            if (!session) {
                throw new Error('Session not found');
            }

            const filterResult = {
                command,
                sessionId,
                userId: session.userId,
                timestamp: new Date(),
                allowed: true,
                modifiedCommand: null,
                riskScore: 0,
                reasons: []
            };

            // Check command against blacklist
            const blacklistCheck = await this.checkCommandBlacklist(command, session);
            if (!blacklistCheck.allowed) {
                filterResult.allowed = false;
                filterResult.reasons.push('Command blacklisted');
                filterResult.riskScore = 1.0;
            }

            // Check for dangerous patterns
            const patternCheck = await this.checkDangerousPatterns(command);
            if (patternCheck.dangerous) {
                if (patternCheck.severity === 'high') {
                    filterResult.allowed = false;
                    filterResult.reasons.push('Dangerous command pattern detected');
                    filterResult.riskScore = Math.max(filterResult.riskScore, 0.9);
                } else {
                    // Require approval for medium risk commands
                    const approval = await this.requestCommandApproval(sessionId, command, patternCheck);
                    filterResult.allowed = approval.approved;
                    if (!approval.approved) {
                        filterResult.reasons.push('Command approval required but not granted');
                    }
                }
            }

            // Apply command modifications if needed
            if (filterResult.allowed && patternCheck.suggestModification) {
                filterResult.modifiedCommand = patternCheck.modifiedCommand;
                filterResult.reasons.push('Command modified for safety');
            }

            // Log command filtering decision
            await this.logCommandFilter(filterResult);

            if (!filterResult.allowed) {
                this.emit('commandBlocked', {
                    sessionId,
                    userId: session.userId,
                    command,
                    reasons: filterResult.reasons,
                    riskScore: filterResult.riskScore,
                    timestamp: new Date()
                });
            }

            return filterResult;

        } catch (error) {
            console.error('Command filtering error:', error);
            // Fail secure - block command on error
            return {
                command,
                sessionId,
                allowed: false,
                reasons: ['Command filtering system error'],
                riskScore: 1.0,
                timestamp: new Date()
            };
        }
    }

    /**
     * Credential vaulting and management
     */
    async storeCredentials(credentialConfig) {
        try {
            // Encrypt credentials
            const encryptedCredentials = await this.encryptCredentials(credentialConfig.credentials);
            
            const vaultEntry = {
                id: crypto.randomUUID(),
                name: credentialConfig.name,
                type: credentialConfig.type, // 'password', 'key', 'certificate'
                targetSystem: credentialConfig.targetSystem,
                username: credentialConfig.username,
                encryptedCredentials,
                tags: new Set(credentialConfig.tags || []),
                accessPolicy: credentialConfig.accessPolicy || 'default',
                rotationPolicy: credentialConfig.rotationPolicy || 'manual',
                lastRotated: null,
                nextRotation: null,
                createdAt: new Date(),
                updatedAt: new Date(),
                metadata: credentialConfig.metadata || {}
            };

            // Set up rotation schedule if automated
            if (vaultEntry.rotationPolicy !== 'manual') {
                await this.schedulePasswordRotation(vaultEntry);
            }

            this.credentialVault.set(vaultEntry.id, vaultEntry);

            this.emit('credentialsStored', {
                credentialId: vaultEntry.id,
                name: vaultEntry.name,
                targetSystem: vaultEntry.targetSystem,
                rotationPolicy: vaultEntry.rotationPolicy,
                timestamp: new Date()
            });

            return {
                credentialId: vaultEntry.id,
                success: true,
                rotationScheduled: vaultEntry.rotationPolicy !== 'manual'
            };

        } catch (error) {
            console.error('Credential storage error:', error);
            throw error;
        }
    }

    /**
     * Password rotation automation
     */
    async rotatePassword(credentialId, options = {}) {
        try {
            const credential = this.credentialVault.get(credentialId);
            if (!credential) {
                throw new Error('Credential not found');
            }

            // Generate new password
            const newPassword = this.generateSecurePassword(options.passwordPolicy);
            
            // Test connectivity to target system
            const connectivityTest = await this.testSystemConnectivity(credential.targetSystem);
            if (!connectivityTest.success) {
                throw new Error(`Cannot connect to target system: ${connectivityTest.error}`);
            }

            // Change password on target system
            const rotationResult = await this.performPasswordRotation(credential, newPassword);
            
            if (rotationResult.success) {
                // Update vault with new password
                const encryptedNewPassword = await this.encryptCredentials({ password: newPassword });
                credential.encryptedCredentials = encryptedNewPassword;
                credential.lastRotated = new Date();
                credential.updatedAt = new Date();
                
                // Schedule next rotation
                if (credential.rotationPolicy !== 'manual') {
                    await this.scheduleNextRotation(credential);
                }

                this.emit('passwordRotated', {
                    credentialId,
                    targetSystem: credential.targetSystem,
                    rotationMethod: rotationResult.method,
                    timestamp: new Date()
                });

                return {
                    success: true,
                    rotatedAt: credential.lastRotated,
                    nextRotation: credential.nextRotation
                };
            } else {
                throw new Error(`Password rotation failed: ${rotationResult.error}`);
            }

        } catch (error) {
            console.error('Password rotation error:', error);
            
            // Log rotation failure
            this.emit('passwordRotationFailed', {
                credentialId,
                error: error.message,
                timestamp: new Date()
            });
            
            throw error;
        }
    }

    /**
     * Emergency access procedures
     */
    async requestEmergencyAccess(emergencyConfig) {
        try {
            const emergencyRequest = {
                id: crypto.randomUUID(),
                userId: emergencyConfig.userId,
                targetResource: emergencyConfig.targetResource,
                emergencyJustification: emergencyConfig.emergencyJustification,
                incidentTicket: emergencyConfig.incidentTicket,
                urgencyLevel: emergencyConfig.urgencyLevel || 'high',
                requestedAt: new Date(),
                status: 'pending',
                approverNotified: false,
                escalationLevel: 0,
                metadata: emergencyConfig.metadata || {}
            };

            // Notify emergency approvers immediately
            await this.notifyEmergencyApprovers(emergencyRequest);
            emergencyRequest.approverNotified = true;

            // Start escalation timer
            this.startEmergencyEscalation(emergencyRequest);

            this.emergencyAccess.set(emergencyRequest.id, emergencyRequest);

            this.emit('emergencyAccessRequested', {
                requestId: emergencyRequest.id,
                userId: emergencyRequest.userId,
                targetResource: emergencyRequest.targetResource,
                urgencyLevel: emergencyRequest.urgencyLevel,
                incidentTicket: emergencyRequest.incidentTicket,
                timestamp: new Date()
            });

            return {
                requestId: emergencyRequest.id,
                status: 'pending',
                estimatedResponseTime: this.getEmergencyResponseTime(emergencyRequest.urgencyLevel),
                escalationSchedule: this.getEscalationSchedule(emergencyRequest.urgencyLevel)
            };

        } catch (error) {
            console.error('Emergency access request error:', error);
            throw error;
        }
    }

    /**
     * Approval workflow management
     */
    async createApprovalWorkflow(workflowConfig) {
        try {
            const workflow = {
                id: crypto.randomUUID(),
                name: workflowConfig.name,
                resourceType: workflowConfig.resourceType,
                privilegeLevel: workflowConfig.privilegeLevel,
                approvers: workflowConfig.approvers.map(approver => ({
                    id: approver.id,
                    type: approver.type, // 'user', 'role', 'group'
                    required: approver.required || true,
                    order: approver.order || 1
                })),
                conditions: workflowConfig.conditions || [],
                timeouts: {
                    approverTimeout: workflowConfig.approverTimeout || 3600000, // 1 hour
                    workflowTimeout: workflowConfig.workflowTimeout || 86400000 // 24 hours
                },
                escalation: workflowConfig.escalation || null,
                createdAt: new Date(),
                enabled: true,
                metadata: workflowConfig.metadata || {}
            };

            this.approvalWorkflows.set(workflow.id, workflow);

            this.emit('approvalWorkflowCreated', {
                workflowId: workflow.id,
                name: workflow.name,
                approverCount: workflow.approvers.length,
                timestamp: new Date()
            });

            return workflow;

        } catch (error) {
            console.error('Approval workflow creation error:', error);
            throw error;
        }
    }

    /**
     * Session monitoring and analytics
     */
    startSessionMonitoring() {
        // Monitor active sessions every 30 seconds
        setInterval(async () => {
            for (const [sessionId, session] of this.privilegedSessions.entries()) {
                if (session.status === 'active') {
                    try {
                        await this.analyzeSessionBehavior(sessionId);
                        await this.checkSessionTimeout(sessionId);
                        await this.updateSessionMetrics(sessionId);
                    } catch (error) {
                        console.error(`Session monitoring error for ${sessionId}:`, error);
                    }
                }
            }
        }, 30000);

        console.log('✅ Session monitoring started');
    }

    /**
     * Password rotation scheduler
     */
    startPasswordRotation() {
        // Check for passwords due for rotation every hour
        setInterval(async () => {
            const now = new Date();
            for (const [credentialId, credential] of this.credentialVault.entries()) {
                if (credential.nextRotation && credential.nextRotation <= now) {
                    try {
                        await this.rotatePassword(credentialId);
                    } catch (error) {
                        console.error(`Automated password rotation failed for ${credentialId}:`, error);
                    }
                }
            }
        }, 3600000); // Every hour

        console.log('✅ Password rotation scheduler started');
    }

    /**
     * Helper methods
     */
    
    generateSecurePassword(policy = {}) {
        const length = policy.length || 16;
        const charset = policy.charset || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let password = '';
        
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        
        return password;
    }

    async encryptCredentials(credentials) {
        // Use AES-256 encryption (simplified implementation)
        const algorithm = 'aes-256-gcm';
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipher(algorithm, key);
        let encrypted = cipher.update(JSON.stringify(credentials), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return {
            encrypted,
            key: key.toString('hex'),
            iv: iv.toString('hex'),
            algorithm
        };
    }

    estimateApprovalTime(accessRequest) {
        // Estimate approval time based on urgency and approver count
        const baseTime = {
            low: 3600000,    // 1 hour
            normal: 1800000, // 30 minutes
            high: 900000,    // 15 minutes
            critical: 300000 // 5 minutes
        };
        
        return baseTime[accessRequest.urgency] * accessRequest.requiredApprovers.length;
    }

    /**
     * REST API endpoints
     */
    createAPIRoutes() {
        const router = express.Router();

        // JIT access request endpoint
        router.post('/access/request', async (req, res) => {
            try {
                const request = await this.requestJITAccess(req.body);
                res.json(request);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Access approval endpoint
        router.post('/access/approve/:requestId', async (req, res) => {
            try {
                const { approverId, decision, comments } = req.body;
                const result = await this.processAccessApproval(req.params.requestId, approverId, decision, comments);
                res.json(result);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Privileged session endpoint
        router.post('/sessions/start', async (req, res) => {
            try {
                const session = await this.startPrivilegedSession(req.body);
                res.json(session);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Command filter endpoint
        router.post('/sessions/:sessionId/filter-command', async (req, res) => {
            try {
                const { command } = req.body;
                const result = await this.filterCommand(req.params.sessionId, command);
                res.json(result);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Credential vault endpoint
        router.post('/vault/credentials', async (req, res) => {
            try {
                const result = await this.storeCredentials(req.body);
                res.json(result);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Password rotation endpoint
        router.post('/vault/rotate/:credentialId', async (req, res) => {
            try {
                const result = await this.rotatePassword(req.params.credentialId, req.body);
                res.json(result);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Emergency access endpoint
        router.post('/access/emergency', async (req, res) => {
            try {
                const request = await this.requestEmergencyAccess(req.body);
                res.json(request);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        return router;
    }
}

/**
 * Supporting classes
 */

class JITAccessProvisioner {
    constructor() {
        this.activeAccess = new Map();
    }
}

class CredentialManager {
    constructor() {
        this.encryptionKeys = new Map();
    }
}

class PrivilegedSessionManager {
    constructor() {
        this.activeSessions = new Map();
    }
}

class ApprovalWorkflowEngine {
    constructor() {
        this.workflows = new Map();
    }
}

class SessionRecorder {
    constructor() {
        this.recordings = new Map();
    }
}

class CommandFilter {
    constructor() {
        this.blacklist = new Set([
            'rm -rf /',
            'dd if=/dev/zero',
            'mkfs',
            'fdisk',
            'cfdisk'
        ]);
    }
}

module.exports = PrivilegeAccessManager;

// Example usage and initialization
if (require.main === module) {
    const pamSystem = new PrivilegeAccessManager();
    
    // Set up event listeners
    pamSystem.on('jitAccessRequested', (data) => {
        console.log('JIT access requested:', data.userId, 'for', data.targetResource);
    });
    
    pamSystem.on('jitAccessProvisioned', (data) => {
        console.log('JIT access provisioned:', data.userId, 'account:', data.accountId);
    });
    
    pamSystem.on('privilegedSessionStarted', (data) => {
        console.log('Privileged session started:', data.sessionId, 'user:', data.userId);
    });
    
    pamSystem.on('commandBlocked', (data) => {
        console.log('COMMAND BLOCKED in session:', data.sessionId, 'command:', data.command);
    });
    
    pamSystem.on('passwordRotated', (data) => {
        console.log('Password rotated for:', data.targetSystem);
    });
    
    console.log('🚀 Privilege Access Management System started successfully');
}