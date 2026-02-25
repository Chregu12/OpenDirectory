/**
 * Zero Trust Conditional Access Engine
 * Implements comprehensive rule-based access control with real-time evaluation
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

class ConditionalAccessEngine extends EventEmitter {
    constructor() {
        super();
        this.policies = new Map();
        this.activeSessions = new Map();
        this.riskAssessments = new Map();
        this.deviceProfiles = new Map();
        this.userContexts = new Map();
        
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
        const riskFactors = {
            user: await this.calculateUserRisk(context.user),
            device: await this.calculateDeviceRisk(context.device),
            network: await this.calculateNetworkRisk(context.network),
            application: await this.calculateApplicationRisk(context.application),
            behavioral: await this.calculateBehavioralRisk(context),
            temporal: await this.calculateTemporalRisk(context)
        };

        // Calculate weighted risk score
        const weights = {
            user: 0.2,
            device: 0.25,
            network: 0.2,
            application: 0.15,
            behavioral: 0.15,
            temporal: 0.05
        };

        let totalRisk = 0;
        for (const [factor, risk] of Object.entries(riskFactors)) {
            totalRisk += risk.score * weights[factor];
        }

        return {
            totalRisk: Math.min(1.0, Math.max(0.0, totalRisk)),
            factors: riskFactors,
            weights,
            calculatedAt: new Date()
        };
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

    /**
     * Helper methods for condition evaluation
     */
    evaluateUserConditions(conditions, user) {
        const failed = [];
        let met = true;

        if (conditions.riskLevel) {
            if (!conditions.riskLevel.includes(user.riskProfile?.level)) {
                met = false;
                failed.push('user_risk_level');
            }
        }

        if (conditions.roles) {
            const hasRequiredRole = conditions.roles.some(role => user.roles.includes(role));
            if (!hasRequiredRole) {
                met = false;
                failed.push('user_roles');
            }
        }

        if (conditions.groups) {
            const hasRequiredGroup = conditions.groups.some(group => user.groups.includes(group));
            if (!hasRequiredGroup) {
                met = false;
                failed.push('user_groups');
            }
        }

        return { met, failed };
    }

    evaluateDeviceConditions(conditions, device) {
        const failed = [];
        let met = true;

        if (conditions.compliance) {
            if (!conditions.compliance.includes(device.compliance?.status)) {
                met = false;
                failed.push('device_compliance');
            }
        }

        if (conditions.trust) {
            if (device.trust?.score < conditions.trust.minimum) {
                met = false;
                failed.push('device_trust');
            }
        }

        if (conditions.encryption) {
            if (!conditions.encryption.includes(device.encryption?.status)) {
                met = false;
                failed.push('device_encryption');
            }
        }

        return { met, failed };
    }

    evaluateLocationConditions(conditions, network) {
        const failed = [];
        let met = true;

        if (conditions.countries) {
            if (conditions.countries.blocked?.includes(network.country)) {
                met = false;
                failed.push('blocked_country');
            }
            if (conditions.countries.allowed && !conditions.countries.allowed.includes(network.country)) {
                met = false;
                failed.push('country_not_allowed');
            }
        }

        if (conditions.anonymousNetworks === true) {
            if (network.vpn || network.tor || network.proxy) {
                met = false;
                failed.push('anonymous_network');
            }
        }

        if (conditions.ipReputation) {
            if (network.reputation?.score < conditions.ipReputation.minimum) {
                met = false;
                failed.push('poor_ip_reputation');
            }
        }

        return { met, failed };
    }

    evaluateApplicationConditions(conditions, application) {
        const failed = [];
        let met = true;

        if (conditions.sensitivity) {
            if (!conditions.sensitivity.includes(application.sensitivity)) {
                met = false;
                failed.push('application_sensitivity');
            }
        }

        if (conditions.requiresCompliance && application.requiresCompliance) {
            met = false;
            failed.push('application_compliance_required');
        }

        return { met, failed };
    }

    evaluateRiskConditions(conditions, riskAssessment) {
        const failed = [];
        let met = true;

        if (conditions.maximum && riskAssessment.totalRisk > conditions.maximum) {
            met = false;
            failed.push('risk_too_high');
        }

        if (conditions.minimum && riskAssessment.totalRisk < conditions.minimum) {
            met = false;
            failed.push('risk_too_low');
        }

        return { met, failed };
    }

    evaluateTimeConditions(conditions, timestamp) {
        const failed = [];
        let met = true;
        const now = new Date(timestamp);
        const hour = now.getHours();
        const day = now.getDay(); // 0 = Sunday

        if (conditions.allowedHours) {
            if (!conditions.allowedHours.includes(hour)) {
                met = false;
                failed.push('outside_allowed_hours');
            }
        }

        if (conditions.allowedDays) {
            if (!conditions.allowedDays.includes(day)) {
                met = false;
                failed.push('outside_allowed_days');
            }
        }

        return { met, failed };
    }

    /**
     * Risk calculation methods
     */
    async calculateUserRisk(user) {
        let risk = 0.0;
        const factors = [];

        // Account status risk
        if (user.accountStatus === 'SUSPENDED') {
            risk += 1.0;
            factors.push('account_suspended');
        } else if (user.accountStatus === 'LOCKED') {
            risk += 0.8;
            factors.push('account_locked');
        }

        // MFA risk
        if (!user.mfaEnabled) {
            risk += 0.3;
            factors.push('no_mfa');
        }

        // Risk profile
        if (user.riskProfile) {
            switch (user.riskProfile.level) {
                case 'CRITICAL':
                    risk += 1.0;
                    factors.push('critical_risk_profile');
                    break;
                case 'HIGH':
                    risk += 0.8;
                    factors.push('high_risk_profile');
                    break;
                case 'MEDIUM':
                    risk += 0.4;
                    factors.push('medium_risk_profile');
                    break;
            }
        }

        // Last login time
        if (user.lastLogin) {
            const daysSinceLogin = (Date.now() - new Date(user.lastLogin).getTime()) / (1000 * 60 * 60 * 24);
            if (daysSinceLogin > 30) {
                risk += 0.2;
                factors.push('inactive_account');
            }
        }

        return {
            score: Math.min(1.0, risk),
            factors
        };
    }

    async calculateDeviceRisk(device) {
        let risk = 0.0;
        const factors = [];

        // Device compliance
        if (device.compliance?.status === 'NON_COMPLIANT') {
            risk += 0.8;
            factors.push('non_compliant_device');
        } else if (device.compliance?.status === 'UNKNOWN') {
            risk += 0.4;
            factors.push('unknown_compliance');
        }

        // Device trust
        if (device.trust?.score < 0.5) {
            risk += 0.6;
            factors.push('low_device_trust');
        }

        // Encryption status
        if (device.encryption?.status === 'NOT_ENCRYPTED') {
            risk += 0.4;
            factors.push('device_not_encrypted');
        }

        // Unknown device
        if (device.id === 'unknown') {
            risk += 0.5;
            factors.push('unknown_device');
        }

        // Last seen
        if (device.lastSeen) {
            const daysSinceLastSeen = (Date.now() - new Date(device.lastSeen).getTime()) / (1000 * 60 * 60 * 24);
            if (daysSinceLastSeen > 90) {
                risk += 0.3;
                factors.push('device_inactive');
            }
        }

        return {
            score: Math.min(1.0, risk),
            factors
        };
    }

    async calculateNetworkRisk(network) {
        let risk = 0.0;
        const factors = [];

        // VPN/Tor/Proxy
        if (network.tor) {
            risk += 0.9;
            factors.push('tor_network');
        } else if (network.vpn) {
            risk += 0.3;
            factors.push('vpn_network');
        } else if (network.proxy) {
            risk += 0.2;
            factors.push('proxy_network');
        }

        // IP reputation
        if (network.reputation?.score < 50) {
            risk += 0.6;
            factors.push('poor_ip_reputation');
        }

        // Geographic risk (example: high-risk countries)
        const highRiskCountries = ['CN', 'RU', 'IR', 'KP'];
        if (highRiskCountries.includes(network.country)) {
            risk += 0.4;
            factors.push('high_risk_country');
        }

        return {
            score: Math.min(1.0, risk),
            factors
        };
    }

    async calculateApplicationRisk(application) {
        let risk = 0.0;
        const factors = [];

        // Application sensitivity
        switch (application.sensitivity) {
            case 'CRITICAL':
                risk += 0.8;
                factors.push('critical_application');
                break;
            case 'HIGH':
                risk += 0.6;
                factors.push('high_value_application');
                break;
            case 'MEDIUM':
                risk += 0.3;
                factors.push('medium_value_application');
                break;
        }

        // Compliance requirements
        if (application.requiresCompliance) {
            risk += 0.2;
            factors.push('compliance_required');
        }

        return {
            score: Math.min(1.0, risk),
            factors
        };
    }

    async calculateBehavioralRisk(context) {
        let risk = 0.0;
        const factors = [];

        // Multiple concurrent sessions
        if (context.session.concurrent > 3) {
            risk += 0.3;
            factors.push('multiple_sessions');
        }

        // Unusual time access
        const hour = context.request.timestamp.getHours();
        if (hour < 6 || hour > 22) {
            risk += 0.2;
            factors.push('unusual_time');
        }

        // TODO: Add more behavioral analysis
        // - Typing patterns
        // - Mouse movement patterns
        // - Navigation patterns

        return {
            score: Math.min(1.0, risk),
            factors
        };
    }

    async calculateTemporalRisk(context) {
        let risk = 0.0;
        const factors = [];

        // Weekend access
        const day = context.request.timestamp.getDay();
        if (day === 0 || day === 6) {
            risk += 0.1;
            factors.push('weekend_access');
        }

        // Holiday access (simplified)
        // TODO: Implement proper holiday detection

        return {
            score: Math.min(1.0, risk),
            factors
        };
    }

    /**
     * Helper methods for external data
     */
    async getUserRiskProfile(userId) {
        // TODO: Integrate with user risk service
        return { level: 'LOW', score: 0.1 };
    }

    async getDeviceCompliance(deviceId) {
        // TODO: Integrate with device compliance service
        return { status: 'COMPLIANT', lastChecked: new Date() };
    }

    async getDeviceTrust(deviceId) {
        // TODO: Integrate with device trust service
        return { score: 0.8, lastUpdated: new Date() };
    }

    async getDeviceEncryption(deviceId) {
        // TODO: Integrate with encryption service
        return { status: 'ENCRYPTED', type: 'BitLocker' };
    }

    async getDeviceLastSeen(deviceId) {
        // TODO: Integrate with device service
        return new Date();
    }

    async getISPInfo(ip) {
        // TODO: Integrate with ISP lookup service
        return 'Unknown ISP';
    }

    async isVPN(ip) {
        // TODO: Integrate with VPN detection service
        return false;
    }

    async isTor(ip) {
        // TODO: Integrate with Tor detection service
        return false;
    }

    async isProxy(ip) {
        // TODO: Integrate with proxy detection service
        return false;
    }

    async getIPReputation(ip) {
        // TODO: Integrate with IP reputation service
        return { score: 80 };
    }

    async getApplicationSensitivity(appId) {
        // TODO: Integrate with application catalog
        return 'MEDIUM';
    }

    async getApplicationComplianceRequirement(appId) {
        // TODO: Integrate with application catalog
        return false;
    }

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
        setInterval(async () => {
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
        this.removeAllListeners();
        this.policies.clear();
        this.activeSessions.clear();
        this.riskAssessments.clear();
        console.log('✅ Conditional Access Engine shutdown complete');
    }
}

module.exports = ConditionalAccessEngine;