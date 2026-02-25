/**
 * Conditional Access Controller
 * REST API endpoints for conditional access operations
 */

const express = require('express');

class ConditionalAccessController {
    constructor(conditionalAccessEngine, auditLogger) {
        this.conditionalAccessEngine = conditionalAccessEngine;
        this.auditLogger = auditLogger;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Evaluate access request
        this.router.post('/evaluate', this.evaluateAccess.bind(this));
        
        // Get access policies
        this.router.get('/policies', this.getPolicies.bind(this));
        
        // Create/update policy
        this.router.post('/policies', this.createPolicy.bind(this));
        this.router.put('/policies/:policyId', this.updatePolicy.bind(this));
        
        // Delete policy
        this.router.delete('/policies/:policyId', this.deletePolicy.bind(this));
        
        // Get session information
        this.router.get('/sessions/:sessionId', this.getSessionInfo.bind(this));
        
        // Terminate session
        this.router.delete('/sessions/:sessionId', this.terminateSession.bind(this));
        
        // Get risk assessment
        this.router.post('/risk-assessment', this.getRiskAssessment.bind(this));
        
        // Update device context
        this.router.post('/device-context', this.updateDeviceContext.bind(this));
    }

    async evaluateAccess(req, res) {
        try {
            await this.auditLogger.logEvent(
                'conditional_access',
                'ACCESS_EVALUATION_REQUESTED',
                {
                    userId: req.user?.id,
                    deviceId: req.headers['x-device-id'],
                    application: req.headers['x-app-id'],
                    ip: req.ip
                }
            );

            const accessRequest = {
                user: req.user,
                headers: req.headers,
                ip: req.ip,
                path: req.body.resource || req.path,
                method: req.method
            };

            const result = await this.conditionalAccessEngine.evaluateAccess(accessRequest);

            await this.auditLogger.logEvent(
                'conditional_access',
                result.decision === 'ALLOW' ? 'ACCESS_GRANTED' : 'ACCESS_DENIED',
                {
                    evaluationId: result.evaluationId,
                    userId: req.user?.id,
                    decision: result.decision,
                    riskScore: result.riskScore,
                    reasons: result.reasons
                }
            );

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'conditional_access',
                'ACCESS_EVALUATION_ERROR',
                {
                    userId: req.user?.id,
                    error: error.message
                }
            );

            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getPolicies(req, res) {
        try {
            const policies = Array.from(this.conditionalAccessEngine.policies.values());
            
            res.json({
                success: true,
                data: policies
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async createPolicy(req, res) {
        try {
            const policyData = req.body;
            
            // Validate policy data
            this.validatePolicyData(policyData);
            
            const policyId = crypto.randomUUID();
            const policy = {
                id: policyId,
                ...policyData,
                createdAt: new Date(),
                createdBy: req.user.id
            };
            
            this.conditionalAccessEngine.policies.set(policyId, policy);
            
            await this.auditLogger.logEvent(
                'conditional_access',
                'POLICY_CREATED',
                {
                    policyId,
                    policyName: policy.name,
                    createdBy: req.user.id
                }
            );
            
            res.status(201).json({
                success: true,
                data: { policyId, policy }
            });

        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    async updatePolicy(req, res) {
        try {
            const { policyId } = req.params;
            const updates = req.body;
            
            const policy = this.conditionalAccessEngine.policies.get(policyId);
            if (!policy) {
                return res.status(404).json({
                    success: false,
                    error: 'Policy not found'
                });
            }
            
            const updatedPolicy = {
                ...policy,
                ...updates,
                updatedAt: new Date(),
                updatedBy: req.user.id
            };
            
            this.conditionalAccessEngine.policies.set(policyId, updatedPolicy);
            
            await this.auditLogger.logEvent(
                'conditional_access',
                'POLICY_UPDATED',
                {
                    policyId,
                    policyName: updatedPolicy.name,
                    updatedBy: req.user.id,
                    changes: Object.keys(updates)
                }
            );
            
            res.json({
                success: true,
                data: updatedPolicy
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async deletePolicy(req, res) {
        try {
            const { policyId } = req.params;
            
            const policy = this.conditionalAccessEngine.policies.get(policyId);
            if (!policy) {
                return res.status(404).json({
                    success: false,
                    error: 'Policy not found'
                });
            }
            
            this.conditionalAccessEngine.policies.delete(policyId);
            
            await this.auditLogger.logEvent(
                'conditional_access',
                'POLICY_DELETED',
                {
                    policyId,
                    policyName: policy.name,
                    deletedBy: req.user.id
                }
            );
            
            res.json({
                success: true,
                message: 'Policy deleted successfully'
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getSessionInfo(req, res) {
        try {
            const { sessionId } = req.params;
            const session = this.conditionalAccessEngine.activeSessions.get(sessionId);
            
            if (!session) {
                return res.status(404).json({
                    success: false,
                    error: 'Session not found'
                });
            }
            
            res.json({
                success: true,
                data: session
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async terminateSession(req, res) {
        try {
            const { sessionId } = req.params;
            const reason = req.body.reason || 'Administrative termination';
            
            const session = this.conditionalAccessEngine.activeSessions.get(sessionId);
            if (!session) {
                return res.status(404).json({
                    success: false,
                    error: 'Session not found'
                });
            }
            
            this.conditionalAccessEngine.activeSessions.delete(sessionId);
            
            await this.auditLogger.logEvent(
                'conditional_access',
                'SESSION_TERMINATED',
                {
                    sessionId,
                    userId: session.userId,
                    reason,
                    terminatedBy: req.user.id
                }
            );
            
            res.json({
                success: true,
                message: 'Session terminated successfully'
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getRiskAssessment(req, res) {
        try {
            const context = req.body;
            const riskAssessment = await this.conditionalAccessEngine.calculateRiskScore(context);
            
            res.json({
                success: true,
                data: riskAssessment
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async updateDeviceContext(req, res) {
        try {
            const deviceContext = req.body;
            
            // Update device profile
            this.conditionalAccessEngine.deviceProfiles.set(
                deviceContext.deviceId,
                {
                    ...deviceContext,
                    lastUpdated: new Date()
                }
            );
            
            res.json({
                success: true,
                message: 'Device context updated successfully'
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    validatePolicyData(policyData) {
        if (!policyData.name) {
            throw new Error('Policy name is required');
        }
        
        if (!policyData.conditions) {
            throw new Error('Policy conditions are required');
        }
        
        if (!policyData.action) {
            throw new Error('Policy action is required');
        }
        
        const validActions = ['ALLOW', 'BLOCK', 'REQUIRE_MFA', 'REQUIRE_STEP_UP', 'CONDITIONAL'];
        if (!validActions.includes(policyData.action)) {
            throw new Error('Invalid policy action');
        }
    }

    getRouter() {
        return this.router;
    }
}

module.exports = ConditionalAccessController;