const logger = require('../utils/logger').logger;

/**
 * Tenant context middleware
 * Sets up tenant-specific context for multi-tenant operations
 */
const tenantMiddleware = (multiTenantService) => {
    return async (req, res, next) => {
        try {
            // Skip tenant processing for public endpoints
            const publicEndpoints = ['/health', '/metrics', '/api/v1/docs', '/'];
            if (publicEndpoints.some(endpoint => req.path === endpoint || req.path.startsWith(endpoint))) {
                return next();
            }

            // Extract tenant ID from various sources
            const tenantId = extractTenantId(req);
            
            if (!tenantId) {
                // If no tenant ID found, this might be a system-level operation
                logger.debug('No tenant ID found in request', {
                    path: req.path,
                    method: req.method,
                    user: req.user?.id
                });
                return next();
            }

            // Validate tenant exists and is active
            const tenantInfo = await multiTenantService.getTenantInfo(tenantId);
            
            if (!tenantInfo.success) {
                logger.warn('Invalid tenant ID in request', {
                    tenantId,
                    path: req.path,
                    method: req.method,
                    user: req.user?.id
                });
                
                return res.status(404).json({
                    error: 'Tenant not found',
                    message: 'The specified tenant does not exist or is not accessible',
                    timestamp: new Date().toISOString()
                });
            }

            const tenant = tenantInfo.tenant;

            // Check if tenant is active
            if (tenant.status !== 'active') {
                logger.warn('Access attempt to inactive tenant', {
                    tenantId,
                    tenantStatus: tenant.status,
                    path: req.path,
                    method: req.method,
                    user: req.user?.id
                });

                return res.status(403).json({
                    error: 'Tenant unavailable',
                    message: `Tenant is currently ${tenant.status}`,
                    timestamp: new Date().toISOString()
                });
            }

            // Set tenant context on request
            req.tenant = {
                id: tenant.id,
                name: tenant.name,
                displayName: tenant.displayName,
                type: tenant.type,
                status: tenant.status,
                configuration: tenant.configuration,
                isolation: tenant.isolation,
                quotas: tenant.quotas,
                services: tenant.services,
                metadata: tenant.metadata
            };

            // Set database context for tenant isolation
            if (tenant.isolation.dataIsolation) {
                req.dbContext = {
                    schema: `tenant_${tenantId}`,
                    tenantId: tenantId,
                    isolationLevel: tenant.isolation.level
                };
            }

            // Set storage context for tenant isolation
            if (tenant.isolation.storageIsolation) {
                req.storageContext = {
                    bucket: `tenant-${tenantId}-storage`,
                    path: `/tenants/${tenantId}`,
                    encryptionRequired: tenant.isolation.encryptionRequired
                };
            }

            // Check resource quotas
            const quotaCheck = await checkResourceQuotas(req, tenant);
            if (!quotaCheck.allowed) {
                logger.warn('Resource quota exceeded', {
                    tenantId,
                    quotaType: quotaCheck.quotaType,
                    current: quotaCheck.current,
                    limit: quotaCheck.limit,
                    user: req.user?.id
                });

                return res.status(429).json({
                    error: 'Resource quota exceeded',
                    message: `${quotaCheck.quotaType} limit exceeded`,
                    details: {
                        current: quotaCheck.current,
                        limit: quotaCheck.limit
                    },
                    timestamp: new Date().toISOString()
                });
            }

            // Set response headers for tenant context
            res.set('X-Tenant-ID', tenantId);
            res.set('X-Tenant-Name', tenant.name);
            res.set('X-Isolation-Level', tenant.isolation.level);

            logger.debug('Tenant context established', {
                tenantId,
                tenantName: tenant.name,
                isolationLevel: tenant.isolation.level,
                path: req.path,
                method: req.method,
                user: req.user?.id
            });

            next();

        } catch (error) {
            logger.error('Error in tenant middleware:', error);
            
            return res.status(500).json({
                error: 'Tenant processing error',
                message: 'An error occurred while processing tenant context',
                timestamp: new Date().toISOString()
            });
        }
    };
};

/**
 * Extract tenant ID from request
 */
const extractTenantId = (req) => {
    // Priority order for tenant ID extraction:
    // 1. URL parameter (/tenants/:tenantId/...)
    // 2. X-Tenant-ID header
    // 3. Request body tenantId field
    // 4. Query parameter tenantId
    // 5. User's tenant ID from JWT token
    
    return req.params.tenantId ||
           req.headers['x-tenant-id'] ||
           req.body?.tenantId ||
           req.query?.tenantId ||
           req.user?.tenantId;
};

/**
 * Check resource quotas for tenant
 */
const checkResourceQuotas = async (req, tenant) => {
    try {
        const quotas = tenant.quotas;
        const method = req.method;
        const path = req.path;

        // Check API call quota
        const apiQuota = await checkApiCallQuota(tenant.id, quotas.apiCalls);
        if (!apiQuota.allowed) {
            return { allowed: false, quotaType: 'API calls', ...apiQuota };
        }

        // Check storage quota for file uploads
        if (isFileUploadRequest(req)) {
            const storageQuota = await checkStorageQuota(tenant.id, quotas.storage);
            if (!storageQuota.allowed) {
                return { allowed: false, quotaType: 'Storage', ...storageQuota };
            }
        }

        // Check concurrent sessions quota
        if (isSessionCreationRequest(req)) {
            const sessionQuota = await checkConcurrentSessionsQuota(tenant.id, quotas.concurrentSessions);
            if (!sessionQuota.allowed) {
                return { allowed: false, quotaType: 'Concurrent sessions', ...sessionQuota };
            }
        }

        return { allowed: true };

    } catch (error) {
        logger.error('Error checking resource quotas:', error);
        // Allow request to proceed if quota check fails to avoid service disruption
        return { allowed: true };
    }
};

/**
 * Check API call quota
 */
const checkApiCallQuota = async (tenantId, limit) => {
    // This would check against a rate limiting store (Redis, etc.)
    // For now, return a placeholder allowing the request
    const current = 0; // Would be retrieved from rate limiting store
    const allowed = current < limit;
    
    return { allowed, current, limit };
};

/**
 * Check storage quota
 */
const checkStorageQuota = async (tenantId, limit) => {
    // This would check actual storage usage
    // For now, return a placeholder allowing the request
    const current = 0; // Would be retrieved from storage metrics
    const limitBytes = parseStorageLimit(limit);
    const allowed = current < limitBytes;
    
    return { allowed, current, limit: limitBytes };
};

/**
 * Check concurrent sessions quota
 */
const checkConcurrentSessionsQuota = async (tenantId, limit) => {
    // This would check active session count
    // For now, return a placeholder allowing the request
    const current = 0; // Would be retrieved from session store
    const allowed = current < limit;
    
    return { allowed, current, limit };
};

/**
 * Parse storage limit string (e.g., "100GB") to bytes
 */
const parseStorageLimit = (limitStr) => {
    if (typeof limitStr === 'number') {
        return limitStr;
    }
    
    const match = limitStr.match(/^(\d+)\s*(GB|MB|KB|TB)?$/i);
    if (!match) {
        return 0;
    }
    
    const value = parseInt(match[1]);
    const unit = (match[2] || 'B').toLowerCase();
    
    const multipliers = {
        'b': 1,
        'kb': 1024,
        'mb': 1024 * 1024,
        'gb': 1024 * 1024 * 1024,
        'tb': 1024 * 1024 * 1024 * 1024
    };
    
    return value * (multipliers[unit] || 1);
};

/**
 * Check if request is a file upload
 */
const isFileUploadRequest = (req) => {
    const contentType = req.get('Content-Type') || '';
    return contentType.includes('multipart/form-data') || 
           contentType.includes('application/octet-stream') ||
           req.files || 
           (req.body && req.body.file);
};

/**
 * Check if request creates a new session
 */
const isSessionCreationRequest = (req) => {
    return req.method === 'POST' && 
           (req.path.includes('/login') || 
            req.path.includes('/session') ||
            req.path.includes('/auth'));
};

/**
 * Middleware to enforce tenant feature availability
 */
const requireTenantFeature = (feature) => {
    return (req, res, next) => {
        if (!req.tenant) {
            return res.status(400).json({
                error: 'Tenant context required',
                message: 'This operation requires tenant context',
                timestamp: new Date().toISOString()
            });
        }

        const services = req.tenant.services;
        const featureEnabled = getFeatureStatus(services, feature);

        if (!featureEnabled) {
            logger.warn('Feature not available for tenant', {
                tenantId: req.tenant.id,
                feature,
                path: req.path,
                method: req.method,
                user: req.user?.id
            });

            return res.status(403).json({
                error: 'Feature not available',
                message: `The ${feature} feature is not available for this tenant`,
                timestamp: new Date().toISOString()
            });
        }

        next();
    };
};

/**
 * Get feature status from tenant services configuration
 */
const getFeatureStatus = (services, feature) => {
    const featureMap = {
        'windows-updates': services.updateManagement?.enabled && services.updateManagement.features?.includes('windows'),
        'macos-updates': services.updateManagement?.enabled && services.updateManagement.features?.includes('macos'),
        'linux-updates': services.updateManagement?.enabled && services.updateManagement.features?.includes('linux'),
        'remote-actions': services.updateManagement?.enabled && services.updateManagement.remoteActions,
        'update-rings': services.updateManagement?.enabled && services.updateManagement.updateRings,
        'mam': services.mobileApplicationManagement?.enabled,
        'app-protection': services.mobileApplicationManagement?.appProtection,
        'dlp': services.mobileApplicationManagement?.dataLossPrevention,
        'conditional-access': services.mobileApplicationManagement?.conditionalAccess,
        'terms-of-use': services.termsOfUse?.enabled,
        'compliance': services.compliance?.enabled,
        'audit-logs': services.compliance?.auditLogs,
        'reporting': services.compliance?.reporting
    };

    return featureMap[feature] || false;
};

/**
 * Middleware to set tenant-specific database connection
 */
const setTenantDatabase = (req, res, next) => {
    if (req.tenant && req.tenant.isolation.dataIsolation) {
        // Set database context for ORM/query builder
        req.dbConfig = {
            schema: `tenant_${req.tenant.id}`,
            tenantId: req.tenant.id,
            connectionString: generateTenantConnectionString(req.tenant.id)
        };
    }
    next();
};

/**
 * Generate tenant-specific database connection string
 */
const generateTenantConnectionString = (tenantId) => {
    // This would generate tenant-specific connection string
    // For now, return a placeholder
    return `postgresql://tenant_${tenantId}:password@localhost:5432/tenant_${tenantId}`;
};

module.exports = {
    tenantMiddleware,
    requireTenantFeature,
    setTenantDatabase
};