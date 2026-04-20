/**
 * Zero Trust Conditional Access Engine
 * Implements comprehensive rule-based access control with real-time evaluation
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const RiskCalculator = require('./RiskCalculator');
const ConditionEvaluator = require('./ConditionEvaluator');

class ConditionalAccessEngine extends EventEmitter {
    constructor() {
        super();
        this.policies = new Map();
        this.activeSessions = new Map();
        this.riskAssessments = new Map();
        this.deviceProfiles = new Map();
        this.userContexts = new Map();

        this.riskCalculator = new RiskCalculator();
        this.conditionEvaluator = new ConditionEvaluator();

        // Risk thresholds
        this.riskThresholds = {
            ALLOW: 0.3,
            REQUIRE_MFA: 0.5,
            REQUIRE_STEP_UP: 0.7,
            BLOCK: 0.9
        };

        // Initialize default policies
        this.initializeDefaultPolicies();
    }

    async initialize() {
        console.log('🔐 Initializing Conditional Access Engine...');
        
        // Start continuous evaluation
        this.startContinuousEvaluation();
        
        // Initialize risk analytics
        this.initializeRiskAnalytics();
        
        console.log('✅ Conditional Access Engine initialized');
    }

    /**
     * Evaluate access request against all conditional access policies
     */
    async evaluateAccess(request) {
        const evaluationId = crypto.randomUUID();
        const startTime = Date.now();
        
        try {
            // Extract context from request
            const context = await this.extractRequestContext(request);
            
            // Calculate risk score
            const riskAssessment = await this.calculateRiskScore(context);
            
            // Evaluate against all policies
            const policyResults = await this.evaluatePolicies(context, riskAssessment);
            
            // Make final access decision
            const accessDecision = this.makeAccessDecision(policyResults, riskAssessment);
            
            // Log evaluation
            const evaluation = {
                id: evaluationId,
                timestamp: new Date(),
                userId: context.user.id,
                deviceId: context.device.id,
                application: context.application,
                context,
                riskAssessment,
                policyResults,
                accessDecision,
                evaluationTime: Date.now() - startTime
            };
            
            this.emit('accessEvaluated', evaluation);
            
            return {
                evaluationId,
                decision: accessDecision.action,
                requirements: accessDecision.requirements,
                riskScore: riskAssessment.totalRisk,
                reasons: accessDecision.reasons,
                sessionToken: accessDecision.sessionToken,
                expiresAt: accessDecision.expiresAt
            };
            
        } catch (error) {
            console.error('Access evaluation error:', error);
            this.emit('evaluationError', { evaluationId, error: error.message });
            
            // Fail secure - deny access on error
            return {
                evaluationId,
                decision: 'DENY',
                requirements: [],
                riskScore: 1.0,
                reasons: ['System error during evaluation'],
                sessionToken: null,
                expiresAt: null
            };
        }
    }

    /**
     * Extract comprehensive context from access request
     */
    async extractRequestContext(request) {
        const userAgent = new UAParser(request.headers['user-agent']);
        const geoData = geoip.lookup(request.ip) || {};
        
        return {
            user: {
                id: request.user.id,
                username: request.user.username,
                groups: request.user.groups || [],
                roles: request.user.roles || [],
                lastLogin: request.user.lastLogin,
                accountStatus: request.user.status,
                mfaEnabled: request.user.mfaEnabled,
                riskProfile: await this.getUserRiskProfile(request.user.id)
            },
            device: {
                id: request.headers['x-device-id'] || 'unknown',
                type: userAgent.device.type || 'unknown',
                os: {
                    name: userAgent.os.name,
                    version: userAgent.os.version
                },
                browser: {
                    name: userAgent.browser.name,
                    version: userAgent.browser.version
                },
                compliance: await this.getDeviceCompliance(request.headers['x-device-id']),
                trust: await this.getDeviceTrust(request.headers['x-device-id']),
                encryption: await this.getDeviceEncryption(request.headers['x-device-id']),
                lastSeen: await this.getDeviceLastSeen(request.headers['x-device-id'])
            },
            network: {
                ip: request.ip,
                country: geoData.country,
                region: geoData.region,
                city: geoData.city,
                timezone: geoData.timezone,
                coordinates: geoData.ll,
                isp: await this.getISPInfo(request.ip),
                vpn: await this.isVPN(request.ip),
                tor: await this.isTor(request.ip),
                proxy: await this.isProxy(request.ip),
                reputation: await this.getIPReputation(request.ip)
            },
            application: {
                id: request.headers['x-app-id'] || 'unknown',
                name: request.headers['x-app-name'] || 'unknown',
                sensitivity: await this.getApplicationSensitivity(request.headers['x-app-id']),
                requiresCompliance: await this.getApplicationComplianceRequirement(request.headers['x-app-id'])
            },
            session: {
                existing: await this.getExistingSession(request.user.id, request.headers['x-device-id']),
                concurrent: await this.getConcurrentSessions(request.user.id),
                duration: 0 // Will be calculated if existing session
            },
            request: {
                timestamp: new Date(),
                path: request.path,
                method: request.method,
                headers: this.sanitizeHeaders(request.headers),
                userAgent: request.headers['user-agent']
            }
        };
    }

    /**
     * Calculate comprehensive risk score
     */
    async calculateRiskScore(context) {
        return this.riskCalculator.calculateRiskScore(context);
    }

    /**
     * Evaluate all applicable conditional access policies
     */
    async evaluatePolicies(context, riskAssessment) {
        const results = [];
        
        for (const [policyId, policy] of this.policies) {
            if (this.isPolicyApplicable(policy, context)) {
                const result = await this.evaluatePolicy(policy, context, riskAssessment);
                results.push({
                    policyId,
                    policyName: policy.name,
                    applicable: true,
                    result,
                    evaluatedAt: new Date()
                });
            } else {
                results.push({
                    policyId,
                    policyName: policy.name,
                    applicable: false,
                    result: { action: 'NOT_APPLICABLE', requirements: [] },
                    evaluatedAt: new Date()
                });
            }
        }
        
        return results;
    }

    /**
     * Evaluate individual policy
     */
    async evaluatePolicy(policy, context, riskAssessment) {
        const conditions = policy.conditions;
        let conditionsMet = true;
        const failedConditions = [];

        // Evaluate user conditions
        if (conditions.users) {
            const userConditionMet = this.evaluateUserConditions(conditions.users, context.user);
            if (!userConditionMet.met) {
                conditionsMet = false;
                failedConditions.push(...userConditionMet.failed);
            }
        }

        // Evaluate device conditions
        if (conditions.devices) {
            const deviceConditionMet = this.evaluateDeviceConditions(conditions.devices, context.device);
            if (!deviceConditionMet.met) {
                conditionsMet = false;
                failedConditions.push(...deviceConditionMet.failed);
            }
        }

        // Evaluate location conditions
        if (conditions.locations) {
            const locationConditionMet = this.evaluateLocationConditions(conditions.locations, context.network);
            if (!locationConditionMet.met) {
                conditionsMet = false;
                failedConditions.push(...locationConditionMet.failed);
            }
        }

        // Evaluate application conditions
        if (conditions.applications) {
            const appConditionMet = this.evaluateApplicationConditions(conditions.applications, context.application);
            if (!appConditionMet.met) {
                conditionsMet = false;
                failedConditions.push(...appConditionMet.failed);
            }
        }

        // Evaluate risk conditions
        if (conditions.risk) {
            const riskConditionMet = this.evaluateRiskConditions(conditions.risk, riskAssessment);
            if (!riskConditionMet.met) {
                conditionsMet = false;
                failedConditions.push(...riskConditionMet.failed);
            }
        }

        // Evaluate time conditions
        if (conditions.time) {
            const timeConditionMet = this.evaluateTimeConditions(conditions.time, context.request.timestamp);
            if (!timeConditionMet.met) {
                conditionsMet = false;
                failedConditions.push(...timeConditionMet.failed);
            }
        }

        // Return policy result
        if (conditionsMet) {
            return {
                action: policy.action,
                requirements: policy.requirements || [],
                conditions: 'ALL_MET',
                message: policy.description
            };
        } else {
            return {
                action: 'NOT_APPLICABLE',
                requirements: [],
                conditions: 'FAILED',
                failedConditions,
                message: `Policy conditions not met: ${failedConditions.join(', ')}`
            };
        }
    }

    /**
     * Make final access decision based on policy results
     */
    makeAccessDecision(policyResults, riskAssessment) {
        const applicablePolicies = policyResults.filter(p => p.applicable && p.result.action !== 'NOT_APPLICABLE');
        
        if (applicablePolicies.length === 0) {
            // No applicable policies - use risk-based decision
            return this.makeRiskBasedDecision(riskAssessment);
        }

        // Find the most restrictive action
        const actions = applicablePolicies.map(p => p.result.action);
        const requirements = [];
        const reasons = [];

        // Priority order: BLOCK > REQUIRE_STEP_UP > REQUIRE_MFA > ALLOW
        if (actions.includes('BLOCK')) {
            return {
                action: 'BLOCK',
                requirements: [],
                reasons: applicablePolicies
                    .filter(p => p.result.action === 'BLOCK')
                    .map(p => p.result.message),
                sessionToken: null,
                expiresAt: null
            };
        }

        if (actions.includes('REQUIRE_STEP_UP')) {
            const stepUpPolicies = applicablePolicies.filter(p => p.result.action === 'REQUIRE_STEP_UP');
            stepUpPolicies.forEach(p => {
                requirements.push(...(p.result.requirements || []));
                reasons.push(p.result.message);
            });
        }

        if (actions.includes('REQUIRE_MFA')) {
            const mfaPolicies = applicablePolicies.filter(p => p.result.action === 'REQUIRE_MFA');
            mfaPolicies.forEach(p => {
                requirements.push(...(p.result.requirements || []));
                reasons.push(p.result.message);
            });
        }

        // If we have requirements, return conditional access
        if (requirements.length > 0) {
            return {
                action: 'CONDITIONAL',
                requirements: [...new Set(requirements)], // Remove duplicates
                reasons,
                sessionToken: null,
                expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes to complete
            };
        }

        // Otherwise, allow access
        const sessionToken = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

        return {
            action: 'ALLOW',
            requirements: [],
            reasons: ['Access granted by conditional access policies'],
            sessionToken,
            expiresAt
        };
    }

    /**
     * Risk-based decision when no policies apply
     */
    makeRiskBasedDecision(riskAssessment) {
        const risk = riskAssessment.totalRisk;

        if (risk >= this.riskThresholds.BLOCK) {
            return {
                action: 'BLOCK',
                requirements: [],
                reasons: [`High risk score: ${Math.round(risk * 100)}%`],
                sessionToken: null,
                expiresAt: null
            };
        }

        if (risk >= this.riskThresholds.REQUIRE_STEP_UP) {
            return {
                action: 'CONDITIONAL',
                requirements: ['step_up_authentication'],
                reasons: [`Elevated risk score: ${Math.round(risk * 100)}%`],
                sessionToken: null,
                expiresAt: new Date(Date.now() + 5 * 60 * 1000)
            };
        }

        if (risk >= this.riskThresholds.REQUIRE_MFA) {
            return {
                action: 'CONDITIONAL',
                requirements: ['mfa_authentication'],
                reasons: [`Medium risk score: ${Math.round(risk * 100)}%`],
                sessionToken: null,
                expiresAt: new Date(Date.now() + 5 * 60 * 1000)
            };
        }

        // Low risk - allow access
        const sessionToken = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

        return {
            action: 'ALLOW',
            requirements: [],
            reasons: [`Low risk score: ${Math.round(risk * 100)}%`],
            sessionToken,
            expiresAt
        };
    }

    /**
     * Initialize default conditional access policies
     */
    initializeDefaultPolicies() {
        // High-risk user policy
        this.policies.set('high-risk-users', {
            id: 'high-risk-users',
            name: 'High Risk Users Policy',
            description: 'Blocks access for high-risk users',
            enabled: true,
            priority: 1,
            conditions: {
                users: {
                    riskLevel: ['HIGH', 'CRITICAL']
                }
            },
            action: 'BLOCK'
        });

        // Non-compliant device policy
        this.policies.set('non-compliant-devices', {
            id: 'non-compliant-devices',
            name: 'Non-Compliant Devices Policy',
            description: 'Blocks access from non-compliant devices',
            enabled: true,
            priority: 2,
            conditions: {
                devices: {
                    compliance: ['NON_COMPLIANT']
                }
            },
            action: 'BLOCK'
        });

        // High-value application policy
        this.policies.set('high-value-apps', {
            id: 'high-value-apps',
            name: 'High-Value Applications Policy',
            description: 'Requires MFA for high-value applications',
            enabled: true,
            priority: 3,
            conditions: {
                applications: {
                    sensitivity: ['HIGH', 'CRITICAL']
                }
            },
            action: 'REQUIRE_MFA',
            requirements: ['mfa_authentication']
        });

        // Anonymous network policy
        this.policies.set('anonymous-networks', {
            id: 'anonymous-networks',
            name: 'Anonymous Networks Policy',
            description: 'Blocks access from Tor/VPN networks',
            enabled: true,
            priority: 4,
            conditions: {
                locations: {
                    anonymousNetworks: true
                }
            },
            action: 'BLOCK'
        });

        // Administrative access policy
        this.policies.set('admin-access', {
            id: 'admin-access',
            name: 'Administrative Access Policy',
            description: 'Requires step-up authentication for admin access',
            enabled: true,
            priority: 5,
            conditions: {
                users: {
                    roles: ['ADMIN', 'SUPER_ADMIN']
                }
            },
            action: 'REQUIRE_STEP_UP',
            requirements: ['privileged_authentication', 'device_compliance']
        });

        console.log(`✅ Initialized ${this.policies.size} default conditional access policies`);
    }

    // Condition evaluation — delegated to ConditionEvaluator
    evaluateUserConditions(c, u)       { return this.conditionEvaluator.evaluateUserConditions(c, u); }
    evaluateDeviceConditions(c, d)     { return this.conditionEvaluator.evaluateDeviceConditions(c, d); }
    evaluateLocationConditions(c, n)   { return this.conditionEvaluator.evaluateLocationConditions(c, n); }
    evaluateApplicationConditions(c, a){ return this.conditionEvaluator.evaluateApplicationConditions(c, a); }
    evaluateRiskConditions(c, r)       { return this.conditionEvaluator.evaluateRiskConditions(c, r); }
    evaluateTimeConditions(c, t)       { return this.conditionEvaluator.evaluateTimeConditions(c, t); }

    // Risk calculation — delegated to RiskCalculator
    async calculateUserRisk(u)         { return this.riskCalculator.calculateUserRisk(u); }
    async calculateDeviceRisk(d)       { return this.riskCalculator.calculateDeviceRisk(d); }
    async calculateNetworkRisk(n)      { return this.riskCalculator.calculateNetworkRisk(n); }
    async calculateApplicationRisk(a)  { return this.riskCalculator.calculateApplicationRisk(a); }
    async calculateBehavioralRisk(ctx) { return this.riskCalculator.calculateBehavioralRisk(ctx); }
    async calculateTemporalRisk(ctx)   { return this.riskCalculator.calculateTemporalRisk(ctx); }

    // External data stubs — delegated to RiskCalculator (replace with real integrations)
    async getUserRiskProfile(id)                { return this.riskCalculator.getUserRiskProfile(id); }
    async getDeviceCompliance(id)               { return this.riskCalculator.getDeviceCompliance(id); }
    async getDeviceTrust(id)                    { return this.riskCalculator.getDeviceTrust(id); }
    async getDeviceEncryption(id)               { return this.riskCalculator.getDeviceEncryption(id); }
    async getDeviceLastSeen(id)                 { return this.riskCalculator.getDeviceLastSeen(id); }
    async getISPInfo(ip)                        { return this.riskCalculator.getISPInfo(ip); }
    async isVPN(ip)                             { return this.riskCalculator.isVPN(ip); }
    async isTor(ip)                             { return this.riskCalculator.isTor(ip); }
    async isProxy(ip)                           { return this.riskCalculator.isProxy(ip); }
    async getIPReputation(ip)                   { return this.riskCalculator.getIPReputation(ip); }
    async getApplicationSensitivity(id)         { return this.riskCalculator.getApplicationSensitivity(id); }
    async getApplicationComplianceRequirement(id){ return this.riskCalculator.getApplicationComplianceRequirement(id); }

    async getExistingSession(userId, deviceId) {
        return this.activeSessions.get(`${userId}:${deviceId}`);
    }

    async getConcurrentSessions(userId) {
        let count = 0;
        for (const [sessionKey, session] of this.activeSessions) {
            if (session.userId === userId) {
                count++;
            }
        }
        return count;
    }

    sanitizeHeaders(headers) {
        // Remove sensitive headers from logs
        const sanitized = { ...headers };
        delete sanitized.authorization;
        delete sanitized.cookie;
        delete sanitized['x-api-key'];
        return sanitized;
    }

    /**
     * Check if policy is applicable to the current context
     */
    isPolicyApplicable(policy, context) {
        if (!policy.enabled) {
            return false;
        }

        // Check if policy has any conditions that match the context
        const conditions = policy.conditions;
        
        // If no conditions specified, policy applies to all
        if (!conditions || Object.keys(conditions).length === 0) {
            return true;
        }

        // Policy is applicable if it has conditions for any aspect of the context
        return !!(conditions.users || conditions.devices || conditions.locations || 
                 conditions.applications || conditions.risk || conditions.time);
    }

    /**
     * Start continuous evaluation of active sessions
     */
    startContinuousEvaluation() {
        const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
        const MAX_SESSIONS = parseInt(process.env.MAX_ACTIVE_SESSIONS) || 10000;

        this._evaluationInterval = setInterval(async () => {
            const now = Date.now();

            // Evict expired sessions before evaluation
            for (const [sessionKey, session] of this.activeSessions) {
                const age = now - new Date(session.createdAt || 0).getTime();
                if (age > SESSION_TTL_MS) {
                    this.activeSessions.delete(sessionKey);
                    this.emit('sessionExpired', { sessionId: session.id, userId: session.userId });
                }
            }

            // Safety valve: if session count exceeds limit, skip evaluation this tick and warn
            if (this.activeSessions.size > MAX_SESSIONS) {
                console.warn(`Active session count (${this.activeSessions.size}) exceeds MAX_ACTIVE_SESSIONS (${MAX_SESSIONS}), skipping evaluation tick`);
                return;
            }

            for (const [sessionKey, session] of this.activeSessions) {
                try {
                    await this.reevaluateSession(session);
                } catch (error) {
                    console.error(`Error reevaluating session ${sessionKey}:`, error);
                }
            }
        }, 30000); // Every 30 seconds

        console.log('📊 Continuous session evaluation started');
    }

    stopContinuousEvaluation() {
        if (this._evaluationInterval) {
            clearInterval(this._evaluationInterval);
            this._evaluationInterval = null;
        }
    }

    /**
     * Re-evaluate an active session
     */
    async reevaluateSession(session) {
        const context = session.context;
        context.request.timestamp = new Date(); // Update timestamp

        const riskAssessment = await this.calculateRiskScore(context);
        const policyResults = await this.evaluatePolicies(context, riskAssessment);
        const accessDecision = this.makeAccessDecision(policyResults, riskAssessment);

        if (accessDecision.action === 'BLOCK') {
            // Terminate session
            this.activeSessions.delete(session.id);
            this.emit('sessionTerminated', {
                sessionId: session.id,
                userId: session.userId,
                reason: 'Blocked by conditional access policy',
                riskScore: riskAssessment.totalRisk
            });
        } else if (accessDecision.action === 'CONDITIONAL') {
            // Mark session as requiring additional authentication
            session.requiresAuth = true;
            session.authRequirements = accessDecision.requirements;
            this.emit('sessionRequiresAuth', {
                sessionId: session.id,
                userId: session.userId,
                requirements: accessDecision.requirements
            });
        }

        // Update session risk
        session.riskAssessment = riskAssessment;
        session.lastEvaluation = new Date();
    }

    /**
     * Initialize risk analytics
     */
    initializeRiskAnalytics() {
        // TODO: Initialize machine learning models for risk prediction
        console.log('📈 Risk analytics initialized');
    }

    /**
     * Shutdown the engine
     */
    async shutdown() {
        console.log('🔐 Shutting down Conditional Access Engine...');
        this.stopContinuousEvaluation();
        this.removeAllListeners();
        this.policies.clear();
        this.activeSessions.clear();
        this.riskAssessments.clear();
        console.log('✅ Conditional Access Engine shutdown complete');
    }
}

module.exports = ConditionalAccessEngine;