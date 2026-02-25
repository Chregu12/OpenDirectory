const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

/**
 * Specialized audit logger for security and compliance events
 * Provides tamper-evident logging with integrity checks
 */
class AuditLogger {
    constructor(options = {}) {
        this.serviceName = options.serviceName || 'update-management';
        this.version = options.version || '1.0.0';
        this.nodeId = options.nodeId || os.hostname();
        this.secretKey = options.secretKey || process.env.AUDIT_SECRET_KEY || 'audit-secret-key-change-this';
        
        // Initialize sequence counter for log integrity
        this.sequenceNumber = 0;
        this.previousHash = null;

        // Create audit logs directory
        this.logsDir = path.join(__dirname, '../../logs/audit');
        this.ensureLogDirectory();

        // Initialize Winston logger for audit events
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp({
                    format: 'YYYY-MM-DD HH:mm:ss.SSS'
                }),
                winston.format.json()
            ),
            defaultMeta: {
                service: this.serviceName,
                version: this.version,
                nodeId: this.nodeId
            },
            transports: [
                // Primary audit log with daily rotation
                new DailyRotateFile({
                    filename: path.join(this.logsDir, 'audit-%DATE%.log'),
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '100m',
                    maxFiles: '2555d', // Keep for 7 years for compliance
                    zippedArchive: true,
                    auditFile: path.join(this.logsDir, 'audit-rotation.json')
                }),

                // Security events log
                new DailyRotateFile({
                    filename: path.join(this.logsDir, 'security-%DATE%.log'),
                    datePattern: 'YYYY-MM-DD',
                    level: 'warn',
                    maxSize: '50m',
                    maxFiles: '2555d',
                    zippedArchive: true
                }),

                // Compliance events log
                new DailyRotateFile({
                    filename: path.join(this.logsDir, 'compliance-%DATE%.log'),
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '50m',
                    maxFiles: '2555d',
                    zippedArchive: true
                })
            ]
        });

        // Initialize integrity chain
        this.initializeIntegrityChain();
    }

    /**
     * Ensure audit log directory exists
     */
    ensureLogDirectory() {
        const fs = require('fs');
        if (!fs.existsSync(this.logsDir)) {
            fs.mkdirSync(this.logsDir, { recursive: true });
        }
    }

    /**
     * Initialize integrity chain for tamper detection
     */
    initializeIntegrityChain() {
        this.previousHash = this.generateHash('AUDIT_CHAIN_GENESIS_' + new Date().toISOString());
    }

    /**
     * Generate SHA-256 hash for integrity checking
     */
    generateHash(data) {
        return crypto
            .createHash('sha256')
            .update(data)
            .digest('hex');
    }

    /**
     * Generate HMAC for data authenticity
     */
    generateHMAC(data) {
        return crypto
            .createHmac('sha256', this.secretKey)
            .update(JSON.stringify(data))
            .digest('hex');
    }

    /**
     * Create tamper-evident audit log entry
     */
    createAuditEntry(event, data, metadata = {}) {
        this.sequenceNumber++;

        const baseEntry = {
            sequenceNumber: this.sequenceNumber,
            timestamp: new Date().toISOString(),
            event,
            data,
            metadata: {
                ...metadata,
                nodeId: this.nodeId,
                pid: process.pid,
                sessionId: metadata.sessionId || null,
                requestId: metadata.requestId || null,
                userAgent: metadata.userAgent || null,
                ipAddress: metadata.ipAddress || null
            }
        };

        // Calculate content hash
        const contentHash = this.generateHash(JSON.stringify(baseEntry));
        
        // Create chain hash (previous hash + current content)
        const chainData = this.previousHash + contentHash;
        const chainHash = this.generateHash(chainData);

        // Generate HMAC for authenticity
        const hmac = this.generateHMAC(baseEntry);

        const auditEntry = {
            ...baseEntry,
            integrity: {
                contentHash,
                chainHash,
                previousHash: this.previousHash,
                hmac
            }
        };

        // Update previous hash for next entry
        this.previousHash = chainHash;

        return auditEntry;
    }

    /**
     * Log audit event
     */
    async log(event, data, metadata = {}) {
        try {
            const auditEntry = this.createAuditEntry(event, data, metadata);
            
            // Determine log level based on event type
            const level = this.getLogLevel(event);
            
            // Log to appropriate transport
            this.logger.log(level, 'Audit Event', auditEntry);

            // For critical security events, also log to security transport
            if (this.isSecurityEvent(event)) {
                this.logger.warn('Security Event', auditEntry);
            }

            // For compliance events, also log to compliance transport
            if (this.isComplianceEvent(event)) {
                this.logger.info('Compliance Event', auditEntry);
            }

            return auditEntry;

        } catch (error) {
            // Fallback logging to prevent audit log failures from breaking the application
            console.error('Audit logging failed:', error);
            this.logger.error('Audit logging failure', {
                event,
                error: error.message,
                timestamp: new Date().toISOString()
            });
            throw error;
        }
    }

    /**
     * Determine log level based on event type
     */
    getLogLevel(event) {
        const criticalEvents = [
            'authentication_failure',
            'authorization_failure',
            'security_breach',
            'data_breach',
            'privilege_escalation',
            'system_compromise',
            'malicious_activity'
        ];

        const warningEvents = [
            'login_failure',
            'access_denied',
            'policy_violation',
            'suspicious_activity',
            'configuration_change',
            'admin_action'
        ];

        if (criticalEvents.includes(event)) {
            return 'error';
        } else if (warningEvents.includes(event)) {
            return 'warn';
        } else {
            return 'info';
        }
    }

    /**
     * Check if event is a security event
     */
    isSecurityEvent(event) {
        const securityEvents = [
            'authentication_success',
            'authentication_failure',
            'authorization_failure',
            'login_success',
            'login_failure',
            'logout',
            'password_change',
            'account_locked',
            'account_unlocked',
            'privilege_escalation',
            'access_denied',
            'security_policy_change',
            'encryption_key_rotation',
            'certificate_issued',
            'certificate_revoked',
            'security_breach',
            'malicious_activity',
            'suspicious_activity'
        ];

        return securityEvents.some(secEvent => event.includes(secEvent));
    }

    /**
     * Check if event is a compliance event
     */
    isComplianceEvent(event) {
        const complianceEvents = [
            'data_access',
            'data_export',
            'data_deletion',
            'privacy_setting_change',
            'consent_given',
            'consent_withdrawn',
            'terms_acceptance',
            'terms_decline',
            'policy_application',
            'compliance_check',
            'audit_report_generated',
            'retention_policy_applied',
            'gdpr_request',
            'data_subject_request'
        ];

        return complianceEvents.some(compEvent => event.includes(compEvent));
    }

    /**
     * Log authentication event
     */
    async logAuthentication(type, userId, metadata = {}) {
        const events = {
            success: 'authentication_success',
            failure: 'authentication_failure',
            logout: 'logout'
        };

        return this.log(events[type] || 'authentication_event', {
            userId,
            authenticationType: metadata.type || 'unknown',
            result: type,
            details: metadata.details || null
        }, metadata);
    }

    /**
     * Log authorization event
     */
    async logAuthorization(type, userId, resource, action, metadata = {}) {
        return this.log(`authorization_${type}`, {
            userId,
            resource,
            action,
            result: type,
            reason: metadata.reason || null
        }, metadata);
    }

    /**
     * Log data access event
     */
    async logDataAccess(userId, resourceType, resourceId, action, metadata = {}) {
        return this.log('data_access', {
            userId,
            resourceType,
            resourceId,
            action,
            dataClassification: metadata.classification || 'unknown',
            purpose: metadata.purpose || null
        }, metadata);
    }

    /**
     * Log configuration change
     */
    async logConfigurationChange(userId, component, changes, metadata = {}) {
        return this.log('configuration_change', {
            userId,
            component,
            changes: this.sanitizeChanges(changes),
            reason: metadata.reason || null
        }, metadata);
    }

    /**
     * Log policy enforcement
     */
    async logPolicyEnforcement(policyId, userId, action, result, metadata = {}) {
        return this.log('policy_enforcement', {
            policyId,
            userId,
            action,
            result,
            violations: metadata.violations || [],
            remediationActions: metadata.remediationActions || []
        }, metadata);
    }

    /**
     * Log update deployment
     */
    async logUpdateDeployment(deploymentId, deviceId, status, metadata = {}) {
        return this.log('update_deployment', {
            deploymentId,
            deviceId,
            status,
            updateType: metadata.updateType || null,
            version: metadata.version || null,
            duration: metadata.duration || null,
            errors: metadata.errors || []
        }, metadata);
    }

    /**
     * Log remote action execution
     */
    async logRemoteAction(actionType, deviceId, userId, result, metadata = {}) {
        return this.log('remote_action_executed', {
            actionType,
            deviceId,
            userId,
            result,
            reason: metadata.reason || null,
            additionalData: metadata.additionalData || null
        }, metadata);
    }

    /**
     * Log terms of use event
     */
    async logTermsOfUse(event, userId, termsId, metadata = {}) {
        return this.log(`terms_of_use_${event}`, {
            userId,
            termsId,
            version: metadata.version || null,
            ipAddress: metadata.ipAddress || null,
            signature: metadata.signature ? 'present' : 'not_present'
        }, metadata);
    }

    /**
     * Log tenant operation
     */
    async logTenantOperation(operation, tenantId, userId, metadata = {}) {
        return this.log(`tenant_${operation}`, {
            tenantId,
            userId,
            changes: metadata.changes ? this.sanitizeChanges(metadata.changes) : null,
            reason: metadata.reason || null
        }, metadata);
    }

    /**
     * Sanitize sensitive data from changes object
     */
    sanitizeChanges(changes) {
        if (!changes || typeof changes !== 'object') {
            return changes;
        }

        const sensitiveFields = [
            'password',
            'secret',
            'key',
            'token',
            'credential',
            'api_key',
            'private_key',
            'certificate'
        ];

        const sanitized = { ...changes };

        for (const [key, value] of Object.entries(sanitized)) {
            const lowerKey = key.toLowerCase();
            if (sensitiveFields.some(field => lowerKey.includes(field))) {
                sanitized[key] = '[REDACTED]';
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = this.sanitizeChanges(value);
            }
        }

        return sanitized;
    }

    /**
     * Verify audit log integrity
     */
    async verifyIntegrity(entries) {
        if (!Array.isArray(entries) || entries.length === 0) {
            return { valid: true, errors: [] };
        }

        const errors = [];
        let expectedPreviousHash = this.generateHash('AUDIT_CHAIN_GENESIS_' + new Date().toISOString());

        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i];

            // Verify sequence number
            if (entry.sequenceNumber !== i + 1) {
                errors.push(`Entry ${i}: Invalid sequence number. Expected ${i + 1}, got ${entry.sequenceNumber}`);
            }

            // Verify content hash
            const entryWithoutIntegrity = { ...entry };
            delete entryWithoutIntegrity.integrity;
            const calculatedContentHash = this.generateHash(JSON.stringify(entryWithoutIntegrity));
            
            if (calculatedContentHash !== entry.integrity.contentHash) {
                errors.push(`Entry ${i}: Content hash mismatch. Entry may have been tampered with.`);
            }

            // Verify chain hash
            const chainData = entry.integrity.previousHash + entry.integrity.contentHash;
            const calculatedChainHash = this.generateHash(chainData);
            
            if (calculatedChainHash !== entry.integrity.chainHash) {
                errors.push(`Entry ${i}: Chain hash mismatch. Chain integrity compromised.`);
            }

            // Verify previous hash linkage
            if (entry.integrity.previousHash !== expectedPreviousHash) {
                errors.push(`Entry ${i}: Previous hash linkage broken. Expected ${expectedPreviousHash}, got ${entry.integrity.previousHash}`);
            }

            // Verify HMAC
            const calculatedHMAC = this.generateHMAC(entryWithoutIntegrity);
            if (calculatedHMAC !== entry.integrity.hmac) {
                errors.push(`Entry ${i}: HMAC verification failed. Entry authenticity compromised.`);
            }

            expectedPreviousHash = entry.integrity.chainHash;
        }

        return {
            valid: errors.length === 0,
            errors,
            verifiedEntries: entries.length,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Export audit logs for external analysis or compliance reporting
     */
    async exportLogs(startDate, endDate, format = 'json') {
        // This would implement log export functionality
        // For now, return a placeholder
        return {
            format,
            startDate,
            endDate,
            exportTimestamp: new Date().toISOString(),
            status: 'placeholder - implementation needed'
        };
    }

    /**
     * Generate audit report
     */
    async generateAuditReport(startDate, endDate, options = {}) {
        // This would implement audit report generation
        // For now, return a placeholder structure
        return {
            reportId: crypto.randomUUID(),
            startDate,
            endDate,
            generatedAt: new Date().toISOString(),
            summary: {
                totalEvents: 0,
                securityEvents: 0,
                complianceEvents: 0,
                criticalEvents: 0
            },
            eventBreakdown: {},
            integrityStatus: 'verified',
            recommendations: [],
            status: 'placeholder - implementation needed'
        };
    }

    /**
     * Close logger and flush any pending writes
     */
    async close() {
        return new Promise((resolve) => {
            this.logger.on('finish', resolve);
            this.logger.end();
        });
    }
}

module.exports = AuditLogger;