const Joi = require('joi');
const logger = require('../utils/logger').logger;

/**
 * Request validation middleware using Joi schemas
 */
const validateRequest = (schema, target = 'body') => {
    return (req, res, next) => {
        try {
            const dataToValidate = getValidationTarget(req, target);
            const { error, value } = schema.validate(dataToValidate, {
                abortEarly: false, // Return all validation errors
                stripUnknown: true, // Remove unknown fields
                convert: true // Convert types when possible
            });

            if (error) {
                const validationErrors = error.details.map(detail => ({
                    field: detail.path.join('.'),
                    message: detail.message,
                    value: detail.context?.value
                }));

                logger.warn('Request validation failed', {
                    path: req.path,
                    method: req.method,
                    target,
                    errors: validationErrors,
                    userId: req.user?.id,
                    tenantId: req.tenantId
                });

                return res.status(400).json({
                    error: 'Validation failed',
                    message: 'The request data is invalid',
                    details: validationErrors,
                    timestamp: new Date().toISOString()
                });
            }

            // Replace the validated data with the sanitized version
            setValidationTarget(req, target, value);
            next();

        } catch (validationError) {
            logger.error('Validation middleware error:', validationError);
            return res.status(500).json({
                error: 'Validation error',
                message: 'An error occurred during request validation',
                timestamp: new Date().toISOString()
            });
        }
    };
};

/**
 * Get validation target from request
 */
const getValidationTarget = (req, target) => {
    switch (target) {
        case 'body':
            return req.body;
        case 'query':
            return req.query;
        case 'params':
            return req.params;
        case 'headers':
            return req.headers;
        default:
            return req.body;
    }
};

/**
 * Set validation target on request
 */
const setValidationTarget = (req, target, value) => {
    switch (target) {
        case 'body':
            req.body = value;
            break;
        case 'query':
            req.query = value;
            break;
        case 'params':
            req.params = value;
            break;
        case 'headers':
            req.headers = value;
            break;
    }
};

/**
 * Common validation schemas
 */
const commonSchemas = {
    // Basic types
    id: Joi.string().uuid().required(),
    optionalId: Joi.string().uuid().optional(),
    name: Joi.string().min(1).max(255).trim().required(),
    description: Joi.string().max(1000).trim().optional(),
    email: Joi.string().email().lowercase().required(),
    url: Joi.string().uri().optional(),
    
    // Pagination
    pagination: Joi.object({
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.number().integer().min(1).max(1000).default(20),
        sort: Joi.string().optional(),
        order: Joi.string().valid('asc', 'desc').default('asc')
    }),

    // Tenant validation
    tenantId: Joi.string().pattern(/^tenant-[a-zA-Z0-9-]+$/).required(),

    // Date range
    dateRange: Joi.object({
        startDate: Joi.date().iso().optional(),
        endDate: Joi.date().iso().min(Joi.ref('startDate')).optional()
    })
};

/**
 * Update management validation schemas
 */
const updateSchemas = {
    // Windows Update Policy
    windowsUpdatePolicy: Joi.object({
        name: commonSchemas.name,
        description: commonSchemas.description,
        platform: Joi.string().valid('windows').required(),
        featureUpdateDeferralDays: Joi.number().integer().min(0).max(365).default(0),
        qualityUpdateDeferralDays: Joi.number().integer().min(0).max(30).default(0),
        deferDriverUpdates: Joi.boolean().default(false),
        automaticMaintenance: Joi.boolean().default(true),
        wsusUrl: Joi.string().uri().optional(),
        targetVersion: Joi.string().optional(),
        pauseUpdates: Joi.boolean().default(false),
        pauseFeatureUpdates: Joi.boolean().default(false),
        pauseQualityUpdates: Joi.boolean().default(false),
        activeHoursStart: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).default('08:00'),
        activeHoursEnd: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).default('17:00'),
        restartGracePeriod: Joi.number().integer().min(1).max(60).default(15),
        updateRing: Joi.string().valid('Pilot', 'Early Adopters', 'Broad Deployment', 'Critical Systems').default('Production'),
        targetDevices: Joi.array().items(Joi.string().uuid()).optional()
    }),

    // macOS Update Policy
    macosUpdatePolicy: Joi.object({
        name: commonSchemas.name,
        description: commonSchemas.description,
        platform: Joi.string().valid('macos').required(),
        automaticDownload: Joi.boolean().default(true),
        automaticInstallOSUpdates: Joi.boolean().default(false),
        automaticInstallAppUpdates: Joi.boolean().default(true),
        automaticInstallSecurityUpdates: Joi.boolean().default(true),
        automaticCheckEnabled: Joi.boolean().default(true),
        criticalUpdateDelay: Joi.number().integer().min(0).max(90).default(0),
        nonCriticalUpdateDelay: Joi.number().integer().min(0).max(90).default(7),
        majorOSUpdateDelay: Joi.number().integer().min(0).max(365).default(90),
        catalogURL: Joi.string().uri().optional(),
        allowPrereleaseInstallation: Joi.boolean().default(false),
        requireAdminToInstall: Joi.boolean().default(true),
        updateRing: Joi.string().valid('Pilot', 'Early Adopters', 'Broad Deployment', 'Critical Systems').default('Production'),
        targetDevices: Joi.array().items(Joi.string().uuid()).optional()
    }),

    // Linux Update Policy
    linuxUpdatePolicy: Joi.object({
        name: commonSchemas.name,
        description: commonSchemas.description,
        platform: Joi.string().valid('linux').required(),
        automaticUpdates: Joi.boolean().default(true),
        securityUpdatesOnly: Joi.boolean().default(false),
        unattendedUpgradesEnabled: Joi.boolean().default(true),
        autoRemoveUnused: Joi.boolean().default(true),
        downloadUpgradesOnly: Joi.boolean().default(false),
        installOnShutdown: Joi.boolean().default(false),
        rebootTime: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).default('02:00'),
        updateFrequency: Joi.string().valid('daily', 'weekly', 'monthly').default('daily'),
        packageManagers: Joi.object({
            apt: Joi.object({
                enabled: Joi.boolean().default(true),
                autoUpdate: Joi.boolean().default(true),
                autoUpgrade: Joi.boolean().default(true)
            }).optional(),
            yum: Joi.object({
                enabled: Joi.boolean().default(true),
                autoUpdate: Joi.boolean().default(true),
                autoUpgrade: Joi.boolean().default(true)
            }).optional(),
            dnf: Joi.object({
                enabled: Joi.boolean().default(true),
                autoUpdate: Joi.boolean().default(true),
                autoUpgrade: Joi.boolean().default(true)
            }).optional(),
            snap: Joi.object({
                enabled: Joi.boolean().default(true),
                autoRefresh: Joi.boolean().default(true)
            }).optional(),
            flatpak: Joi.object({
                enabled: Joi.boolean().default(true),
                autoUpdate: Joi.boolean().default(true)
            }).optional()
        }).optional(),
        updateRing: Joi.string().valid('Pilot', 'Early Adopters', 'Broad Deployment', 'Critical Systems').default('Production'),
        targetDevices: Joi.array().items(Joi.string().uuid()).optional()
    })
};

/**
 * Remote actions validation schemas
 */
const remoteActionSchemas = {
    // Device Lock
    deviceLock: Joi.object({
        deviceId: commonSchemas.id,
        message: Joi.string().max(500).default('This device has been locked by your IT administrator'),
        phoneNumber: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).optional(),
        passcode: Joi.string().length(6).pattern(/^\d+$/).optional(),
        requireAdminUnlock: Joi.boolean().default(true),
        allowBiometricUnlock: Joi.boolean().default(false),
        allowPasscodeReset: Joi.boolean().default(false),
        reason: Joi.string().max(255).required(),
        executor: Joi.string().max(255).optional()
    }),

    // Device Wipe
    deviceWipe: Joi.object({
        deviceId: commonSchemas.id,
        wipeType: Joi.string().valid('full', 'selective', 'enterprise').required(),
        preserveEnrollment: Joi.boolean().default(true),
        wipeExternalStorage: Joi.boolean().default(false),
        wipeMethod: Joi.string().valid('secure', 'quick').default('secure'),
        confirmation: Joi.boolean().valid(true).required(),
        dataRetentionPeriod: Joi.number().integer().min(0).max(365).default(0),
        selectiveWipeApps: Joi.array().items(Joi.string()).when('wipeType', {
            is: 'selective',
            then: Joi.required(),
            otherwise: Joi.optional()
        }),
        reason: Joi.string().max(255).required(),
        executor: Joi.string().max(255).optional()
    }),

    // Device Restart
    deviceRestart: Joi.object({
        deviceId: commonSchemas.id,
        delay: Joi.number().integer().min(0).max(3600).default(60),
        message: Joi.string().max(500).default('This device will restart in {delay} seconds for maintenance'),
        forceRestart: Joi.boolean().default(false),
        scheduledTime: Joi.date().iso().optional(),
        reason: Joi.string().max(255).required(),
        executor: Joi.string().max(255).optional()
    }),

    // Device Locate
    deviceLocate: Joi.object({
        deviceId: commonSchemas.id,
        accuracy: Joi.string().valid('best', 'navigation', 'significant').default('best'),
        timeout: Joi.number().integer().min(30).max(600).default(300),
        playSound: Joi.boolean().default(true),
        displayMessage: Joi.boolean().default(true),
        message: Joi.string().max(500).default('This device is being located by your IT administrator'),
        reason: Joi.string().max(255).required(),
        executor: Joi.string().max(255).optional()
    })
};

/**
 * Update rings validation schemas
 */
const updateRingSchemas = {
    // Create Update Ring
    createUpdateRing: Joi.object({
        name: commonSchemas.name,
        description: commonSchemas.description,
        type: Joi.string().valid('gradual', 'immediate', 'scheduled').default('gradual'),
        priority: Joi.number().integer().min(1).max(10).default(1),
        rolloutPercentage: Joi.number().integer().min(1).max(100).default(100),
        rolloutStrategy: Joi.string().valid('percentage', 'device-count', 'time-based').default('percentage'),
        rolloutSchedule: Joi.object({
            startTime: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).default('09:00'),
            endTime: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).default('17:00'),
            timeZone: Joi.string().default('UTC'),
            daysOfWeek: Joi.array().items(
                Joi.string().valid('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday')
            ).min(1).default(['monday', 'tuesday', 'wednesday', 'thursday', 'friday']),
            exclusionDates: Joi.array().items(Joi.date().iso()).optional()
        }).optional(),
        allowUserDeferral: Joi.boolean().default(true),
        maxDeferrals: Joi.number().integer().min(0).max(10).default(3),
        deferralPeriod: Joi.number().integer().min(1).max(90).default(7),
        forcedInstallDeadline: Joi.number().integer().min(1).max(365).default(30),
        requireApproval: Joi.boolean().default(false),
        approvers: Joi.array().items(Joi.string().email()).optional(),
        approvalThreshold: Joi.number().integer().min(1).default(1),
        enableHealthChecks: Joi.boolean().default(true),
        successThreshold: Joi.number().integer().min(50).max(100).default(95),
        failureThreshold: Joi.number().integer().min(0).max(50).default(5),
        pauseOnFailure: Joi.boolean().default(true),
        enableRollback: Joi.boolean().default(true),
        automaticRollback: Joi.boolean().default(false),
        targetOS: Joi.array().items(Joi.string().valid('windows', 'macos', 'linux')).default(['windows', 'macos', 'linux']),
        deviceTypes: Joi.array().items(Joi.string().valid('desktop', 'laptop', 'server')).default(['desktop', 'laptop', 'server']),
        businessUnits: Joi.array().items(Joi.string()).optional(),
        locations: Joi.array().items(Joi.string()).optional(),
        tags: Joi.array().items(Joi.string()).optional(),
        customFilters: Joi.array().items(Joi.object()).optional()
    }),

    // Assign Devices to Ring
    assignDevicesToRing: Joi.object({
        deviceIds: Joi.array().items(commonSchemas.id).min(1).required(),
        criteria: Joi.object({
            assignedBy: Joi.string().optional(),
            reason: Joi.string().max(255).optional(),
            effectiveDate: Joi.date().iso().optional()
        }).optional()
    })
};

/**
 * MAM (Mobile Application Management) validation schemas
 */
const mamSchemas = {
    // Create MAM Policy
    createMAMPolicy: Joi.object({
        name: commonSchemas.name,
        description: commonSchemas.description,
        type: Joi.string().valid('data-protection', 'app-protection', 'conditional-access').default('data-protection'),
        platform: Joi.string().valid('ios', 'android', 'windows', 'all').default('all'),
        targetApplications: Joi.array().items(Joi.object({
            id: Joi.string().required(),
            name: Joi.string().required(),
            platform: Joi.string().valid('ios', 'android', 'windows').required()
        })).optional(),
        preventDataLoss: Joi.boolean().default(true),
        encryptAppData: Joi.boolean().default(true),
        allowDataTransferTo: Joi.string().valid('all-apps', 'managed-apps-only', 'none').default('managed-apps-only'),
        allowDataTransferFrom: Joi.string().valid('all-apps', 'managed-apps-only', 'none').default('managed-apps-only'),
        preventBackup: Joi.boolean().default(true),
        preventScreenCapture: Joi.boolean().default(true),
        allowPrintFromManagedApps: Joi.boolean().default(false),
        allowCopyPaste: Joi.boolean().default(false),
        requirePinForAccess: Joi.boolean().default(true),
        pinComplexity: Joi.string().valid('numeric', 'alphanumeric', 'complex').default('numeric'),
        pinMinLength: Joi.number().integer().min(4).max(16).default(6),
        pinMaxRetries: Joi.number().integer().min(3).max(10).default(5),
        biometricAuthentication: Joi.boolean().default(true),
        sessionTimeout: Joi.number().integer().min(5).max(1440).default(30),
        offlineGracePeriod: Joi.number().integer().min(60).max(10080).default(720),
        wipeAfterFailedAttempts: Joi.number().integer().min(5).max(20).default(10),
        requireDeviceCompliance: Joi.boolean().default(true),
        requireManagedBrowser: Joi.boolean().default(true),
        blockJailbrokenDevices: Joi.boolean().default(true),
        minimumOSVersion: Joi.string().optional(),
        allowedCountries: Joi.array().items(Joi.string().length(2)).optional(),
        blockedCountries: Joi.array().items(Joi.string().length(2)).optional(),
        requireVPN: Joi.boolean().default(false),
        riskLevelThreshold: Joi.string().valid('low', 'medium', 'high').default('medium'),
        targetUsers: Joi.array().items(commonSchemas.id).optional(),
        targetGroups: Joi.array().items(commonSchemas.id).optional(),
        targetDevices: Joi.array().items(commonSchemas.id).optional(),
        excludedUsers: Joi.array().items(commonSchemas.id).optional(),
        excludedGroups: Joi.array().items(commonSchemas.id).optional(),
        deploymentPhase: Joi.string().valid('pilot', 'production', 'all').default('pilot'),
        rolloutPercentage: Joi.number().integer().min(1).max(100).default(100)
    })
};

/**
 * Terms of Use validation schemas
 */
const termsSchemas = {
    // Create Terms of Use
    createTermsOfUse: Joi.object({
        title: Joi.string().min(1).max(200).required(),
        version: Joi.string().pattern(/^\d+\.\d+(\.\d+)?$/).default('1.0'),
        description: commonSchemas.description,
        type: Joi.string().valid('general', 'privacy', 'security', 'usage', 'compliance').default('general'),
        language: Joi.string().length(5).pattern(/^[a-z]{2}-[A-Z]{2}$/).default('en-US'),
        introduction: Joi.string().max(5000).optional(),
        mainContent: Joi.string().min(1).max(50000).required(),
        conclusion: Joi.string().max(5000).optional(),
        lastUpdated: Joi.date().iso().optional(),
        effectiveDate: Joi.date().iso().optional(),
        expirationDate: Joi.date().iso().min(Joi.ref('effectiveDate')).optional(),
        displayType: Joi.string().valid('modal', 'fullscreen', 'inline', 'redirect').default('modal'),
        allowScrolling: Joi.boolean().default(true),
        requireFullRead: Joi.boolean().default(true),
        minimumReadTime: Joi.number().integer().min(5).max(300).default(30),
        fontSize: Joi.string().valid('small', 'normal', 'large').default('normal'),
        theme: Joi.string().default('default'),
        acceptanceRequired: Joi.boolean().default(true),
        acceptanceMethod: Joi.string().valid('checkbox', 'signature', 'both').default('checkbox'),
        requireSignature: Joi.boolean().default(false),
        signatureType: Joi.string().valid('electronic', 'digital', 'wet').default('electronic'),
        reacceptanceRequired: Joi.boolean().default(true),
        reacceptancePeriod: Joi.number().integer().min(30).max(1095).default(365),
        gracePeriod: Joi.number().integer().min(1).max(30).default(7),
        acceptanceText: Joi.string().max(200).default('I have read and agree to these Terms of Use'),
        targetAllUsers: Joi.boolean().default(true),
        targetUsers: Joi.array().items(commonSchemas.id).optional(),
        targetGroups: Joi.array().items(commonSchemas.id).optional(),
        targetRoles: Joi.array().items(Joi.string()).optional(),
        excludeUsers: Joi.array().items(commonSchemas.id).optional(),
        excludeGroups: Joi.array().items(commonSchemas.id).optional(),
        blockOnDecline: Joi.boolean().default(true),
        blockOnNonCompliance: Joi.boolean().default(true),
        allowTemporaryAccess: Joi.boolean().default(false),
        temporaryAccessDuration: Joi.number().integer().min(1).max(168).default(24),
        trackingEnabled: Joi.boolean().default(true),
        ipAddressTracking: Joi.boolean().default(true),
        deviceTracking: Joi.boolean().default(true),
        locationTracking: Joi.boolean().default(false),
        auditLogRetention: Joi.number().integer().min(365).max(3650).default(2555)
    }),

    // Record Acceptance
    recordAcceptance: Joi.object({
        termsId: commonSchemas.id,
        userId: commonSchemas.id,
        accepted: Joi.boolean().required(),
        signature: Joi.string().max(10000).optional(),
        witnessedBy: commonSchemas.optionalId,
        ipAddress: Joi.string().ip().optional(),
        userAgent: Joi.string().max(500).optional(),
        deviceId: Joi.string().optional(),
        sessionId: Joi.string().optional(),
        location: Joi.object({
            latitude: Joi.number().min(-90).max(90).optional(),
            longitude: Joi.number().min(-180).max(180).optional(),
            accuracy: Joi.number().positive().optional()
        }).optional(),
        platform: Joi.string().valid('web', 'mobile', 'desktop', 'unknown').default('unknown'),
        readTime: Joi.number().integer().min(0).optional(),
        fullContentViewed: Joi.boolean().optional(),
        verificationMethod: Joi.string().default('standard'),
        browserFingerprint: Joi.string().optional(),
        deviceFingerprint: Joi.string().optional(),
        metadata: Joi.object().optional()
    })
};

/**
 * Multi-tenant validation schemas
 */
const tenantSchemas = {
    // Create Tenant
    createTenant: Joi.object({
        name: Joi.string().min(2).max(100).pattern(/^[a-zA-Z0-9-_]+$/).required(),
        displayName: Joi.string().min(2).max(100).optional(),
        description: Joi.string().max(500).optional(),
        type: Joi.string().valid('enterprise', 'subsidiary', 'partner', 'customer').default('enterprise'),
        legalName: Joi.string().max(200).optional(),
        registrationNumber: Joi.string().max(50).optional(),
        taxId: Joi.string().max(50).optional(),
        address: Joi.object({
            street: Joi.string().max(200).optional(),
            city: Joi.string().max(100).optional(),
            state: Joi.string().max(100).optional(),
            postalCode: Joi.string().max(20).optional(),
            country: Joi.string().length(2).optional()
        }).optional(),
        industry: Joi.string().max(100).optional(),
        organizationSize: Joi.string().valid('small', 'medium', 'large', 'enterprise').default('medium'),
        parentTenant: commonSchemas.optionalId,
        primaryContact: Joi.object({
            name: Joi.string().max(100).optional(),
            email: Joi.string().email().optional(),
            phone: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).optional(),
            title: Joi.string().max(100).optional()
        }).optional(),
        technicalContact: Joi.object({
            name: Joi.string().max(100).optional(),
            email: Joi.string().email().optional(),
            phone: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).optional()
        }).optional(),
        billingContact: Joi.object({
            name: Joi.string().max(100).optional(),
            email: Joi.string().email().optional(),
            phone: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).optional()
        }).optional(),
        timeZone: Joi.string().default('UTC'),
        locale: Joi.string().pattern(/^[a-z]{2}-[A-Z]{2}$/).default('en-US'),
        currency: Joi.string().length(3).default('USD'),
        customDomain: Joi.string().hostname().optional(),
        allowCustomBranding: Joi.boolean().default(true),
        logoUrl: Joi.string().uri().optional(),
        primaryColor: Joi.string().pattern(/^#[0-9A-Fa-f]{6}$/).default('#007bff'),
        secondaryColor: Joi.string().pattern(/^#[0-9A-Fa-f]{6}$/).default('#6c757d'),
        isolationLevel: Joi.string().valid('basic', 'standard', 'strict', 'complete').default('standard'),
        networkIsolation: Joi.boolean().default(true),
        dataIsolation: Joi.boolean().default(true),
        computeIsolation: Joi.boolean().default(false),
        storageIsolation: Joi.boolean().default(true),
        allowCrossTenantAccess: Joi.boolean().default(false),
        trustedTenants: Joi.array().items(commonSchemas.id).optional(),
        encryptionRequired: Joi.boolean().default(true),
        complianceFrameworks: Joi.array().items(Joi.string()).optional(),
        maxUsers: Joi.number().integer().min(1).max(100000).default(1000),
        maxDevices: Joi.number().integer().min(1).max(500000).default(5000),
        maxApplications: Joi.number().integer().min(1).max(1000).default(100),
        maxPolicies: Joi.number().integer().min(1).max(500).default(50),
        storageQuota: Joi.string().pattern(/^\d+\s*(GB|TB)$/i).default('100GB'),
        bandwidthQuota: Joi.string().pattern(/^\d+\s*(GB|TB)$/i).default('1TB'),
        apiCallsQuota: Joi.number().integer().min(1000).max(10000000).default(100000),
        maxConcurrentSessions: Joi.number().integer().min(10).max(10000).default(500),
        dataRetentionPeriod: Joi.number().integer().min(365).max(3650).default(2555),
        subscriptionType: Joi.string().valid('trial', 'basic', 'standard', 'premium', 'enterprise').default('standard'),
        billingCycle: Joi.string().valid('monthly', 'quarterly', 'yearly').default('monthly'),
        autoRenewal: Joi.boolean().default(true),
        trialEndDate: Joi.date().iso().optional(),
        subscriptionStartDate: Joi.date().iso().optional(),
        subscriptionEndDate: Joi.date().iso().min(Joi.ref('subscriptionStartDate')).optional(),
        usageTracking: Joi.boolean().default(true),
        updateManagementEnabled: Joi.boolean().default(true),
        updateManagementFeatures: Joi.array().items(
            Joi.string().valid('windows', 'macos', 'linux', 'mobile')
        ).default(['windows', 'macos', 'linux', 'mobile']),
        enableUpdateRings: Joi.boolean().default(true),
        enableRemoteActions: Joi.boolean().default(true),
        mamEnabled: Joi.boolean().default(true),
        appProtectionEnabled: Joi.boolean().default(true),
        dlpEnabled: Joi.boolean().default(true),
        conditionalAccessEnabled: Joi.boolean().default(true),
        termsOfUseEnabled: Joi.boolean().default(true),
        allowCustomTerms: Joi.boolean().default(true),
        multiLanguageTerms: Joi.boolean().default(false),
        complianceEnabled: Joi.boolean().default(true),
        auditLogsEnabled: Joi.boolean().default(true),
        reportingEnabled: Joi.boolean().default(true),
        realTimeMonitoringEnabled: Joi.boolean().default(true),
        metadata: Joi.object().optional()
    })
};

/**
 * Export validation schemas and middleware
 */
module.exports = {
    // Middleware
    validateRequest,
    
    // Common schemas
    commonSchemas,
    
    // Feature-specific schemas
    updateSchemas,
    remoteActionSchemas,
    updateRingSchemas,
    mamSchemas,
    termsSchemas,
    tenantSchemas,
    
    // Custom validators
    validators: {
        uuid: (value, helpers) => {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(value)) {
                return helpers.error('any.invalid');
            }
            return value;
        },
        
        platform: (value, helpers) => {
            const validPlatforms = ['windows', 'macos', 'linux', 'ios', 'android'];
            if (!validPlatforms.includes(value.toLowerCase())) {
                return helpers.error('any.invalid');
            }
            return value.toLowerCase();
        },
        
        semver: (value, helpers) => {
            const semverRegex = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
            if (!semverRegex.test(value)) {
                return helpers.error('any.invalid');
            }
            return value;
        }
    }
};