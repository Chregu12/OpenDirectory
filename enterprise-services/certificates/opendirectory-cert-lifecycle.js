/**
 * OpenDirectory Certificate Lifecycle Manager
 * Comprehensive certificate lifecycle management system
 * 
 * Features:
 * - Automated certificate enrollment
 * - Certificate renewal automation
 * - Expiration monitoring and alerts
 * - Certificate deployment to devices
 * - Certificate inventory management
 * - Bulk certificate operations
 * - Certificate template management
 * - Approval workflows
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const cron = require('node-cron');
const EventEmitter = require('events');
const winston = require('winston');
const nodemailer = require('nodemailer');

class CertificateLifecycleManager extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            storagePath: config.storagePath || '/var/lib/opendirectory/certificates',
            templatesPath: config.templatesPath || '/var/lib/opendirectory/templates',
            renewalThreshold: config.renewalThreshold || 30, // days before expiration
            monitoringInterval: config.monitoringInterval || '0 0 * * *', // daily at midnight
            maxRetries: config.maxRetries || 3,
            retryDelay: config.retryDelay || 60000, // 1 minute
            bulkOperationBatchSize: config.bulkOperationBatchSize || 100,
            approvalRequired: config.approvalRequired || true,
            autoDeployment: config.autoDeployment || false,
            ...config
        };

        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ filename: '/var/log/opendirectory-lifecycle.log' }),
                new winston.transports.Console()
            ]
        });

        // Email configuration for notifications
        this.emailTransporter = config.emailConfig ? nodemailer.createTransporter(config.emailConfig) : null;

        // Core data stores
        this.certificates = new Map(); // certificate inventory
        this.templates = new Map(); // certificate templates
        this.enrollmentRequests = new Map(); // pending enrollment requests
        this.renewalQueue = new Map(); // certificates pending renewal
        this.deploymentQueue = new Map(); // certificates pending deployment
        this.workflows = new Map(); // approval workflows
        this.bulkOperations = new Map(); // bulk operation tracking
        
        // Monitoring and metrics
        this.metrics = {
            totalCertificates: 0,
            activeCertificates: 0,
            expiringSoon: 0,
            expired: 0,
            renewalSuccess: 0,
            renewalFailures: 0,
            deploymentSuccess: 0,
            deploymentFailures: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadCertificateTemplates();
            await this.loadCertificateInventory();
            this.scheduleMonitoring();
            this.setupEventHandlers();
            
            this.logger.info('Certificate Lifecycle Manager initialized successfully');
        } catch (error) {
            this.logger.error('Failed to initialize Certificate Lifecycle Manager:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            this.config.storagePath,
            this.config.templatesPath,
            path.join(this.config.storagePath, 'inventory'),
            path.join(this.config.storagePath, 'enrollment'),
            path.join(this.config.storagePath, 'deployment'),
            path.join(this.config.storagePath, 'workflows'),
            path.join(this.config.storagePath, 'bulk-operations'),
            path.join(this.config.storagePath, 'backups')
        ];

        for (const dir of directories) {
            try {
                await fs.mkdir(dir, { recursive: true });
            } catch (error) {
                if (error.code !== 'EEXIST') throw error;
            }
        }
    }

    /**
     * Certificate Template Management
     */
    async createCertificateTemplate(templateData) {
        try {
            const templateId = this.generateTemplateId(templateData.name);
            const template = {
                id: templateId,
                name: templateData.name,
                description: templateData.description || '',
                version: templateData.version || '1.0',
                validityPeriod: templateData.validityPeriod || 365, // days
                keySize: templateData.keySize || 2048,
                keyAlgorithm: templateData.keyAlgorithm || 'RSA',
                hashAlgorithm: templateData.hashAlgorithm || 'SHA-256',
                
                // Certificate attributes
                subject: templateData.subject || {},
                subjectAltName: templateData.subjectAltName || [],
                keyUsage: templateData.keyUsage || ['digitalSignature', 'keyEncipherment'],
                extendedKeyUsage: templateData.extendedKeyUsage || [],
                
                // Enrollment settings
                enrollmentType: templateData.enrollmentType || 'manual', // manual, automatic, scep
                requireApproval: templateData.requireApproval !== undefined ? templateData.requireApproval : this.config.approvalRequired,
                approvers: templateData.approvers || [],
                
                // Renewal settings
                autoRenewal: templateData.autoRenewal !== undefined ? templateData.autoRenewal : true,
                renewalThreshold: templateData.renewalThreshold || this.config.renewalThreshold,
                
                // Deployment settings
                autoDeployment: templateData.autoDeployment !== undefined ? templateData.autoDeployment : this.config.autoDeployment,
                deploymentTargets: templateData.deploymentTargets || [],
                
                // Security settings
                exportable: templateData.exportable !== undefined ? templateData.exportable : false,
                strongKeyProtection: templateData.strongKeyProtection !== undefined ? templateData.strongKeyProtection : true,
                
                createdAt: new Date(),
                updatedAt: new Date(),
                status: 'active'
            };

            this.templates.set(templateId, template);
            await this.saveTemplate(template);
            
            this.logger.info(`Certificate template created: ${templateId}`);
            this.emit('templateCreated', template);
            
            return template;

        } catch (error) {
            this.logger.error('Failed to create certificate template:', error);
            throw error;
        }
    }

    async updateCertificateTemplate(templateId, updates) {
        try {
            const template = this.templates.get(templateId);
            if (!template) throw new Error(`Template not found: ${templateId}`);

            // Create new version
            const updatedTemplate = {
                ...template,
                ...updates,
                version: this.incrementVersion(template.version),
                updatedAt: new Date()
            };

            this.templates.set(templateId, updatedTemplate);
            await this.saveTemplate(updatedTemplate);
            
            this.logger.info(`Certificate template updated: ${templateId}`);
            this.emit('templateUpdated', updatedTemplate);
            
            return updatedTemplate;

        } catch (error) {
            this.logger.error('Failed to update certificate template:', error);
            throw error;
        }
    }

    /**
     * Automated Certificate Enrollment
     */
    async enrollCertificate(enrollmentRequest) {
        try {
            const requestId = this.generateRequestId();
            const request = {
                id: requestId,
                templateId: enrollmentRequest.templateId,
                subject: enrollmentRequest.subject,
                subjectAltName: enrollmentRequest.subjectAltName || [],
                requester: enrollmentRequest.requester,
                deviceId: enrollmentRequest.deviceId,
                status: 'pending',
                submittedAt: new Date(),
                metadata: enrollmentRequest.metadata || {}
            };

            const template = this.templates.get(enrollmentRequest.templateId);
            if (!template) throw new Error(`Template not found: ${enrollmentRequest.templateId}`);

            if (template.requireApproval) {
                request.status = 'pending_approval';
                await this.initiateApprovalWorkflow(request, template);
            } else {
                request.status = 'approved';
                await this.processEnrollment(request);
            }

            this.enrollmentRequests.set(requestId, request);
            await this.saveEnrollmentRequest(request);
            
            this.logger.info(`Certificate enrollment request submitted: ${requestId}`);
            this.emit('enrollmentRequested', request);
            
            return request;

        } catch (error) {
            this.logger.error('Failed to enroll certificate:', error);
            throw error;
        }
    }

    async processEnrollment(request) {
        try {
            const template = this.templates.get(request.templateId);
            
            // Generate key pair
            const keyPair = await this.generateKeyPair(template.keySize, template.keyAlgorithm);
            
            // Create CSR
            const csr = await this.createCSR(request, keyPair, template);
            
            // Submit to CA for signing
            const signedCertificate = await this.submitToCA(csr, template);
            
            // Create certificate record
            const certificate = {
                id: this.generateCertificateId(),
                serialNumber: this.extractSerialNumber(signedCertificate),
                templateId: template.id,
                subject: request.subject,
                subjectAltName: request.subjectAltName,
                certificate: signedCertificate,
                privateKey: this.config.storePrivateKeys ? keyPair.privateKey : null,
                publicKey: keyPair.publicKey,
                issuer: this.extractIssuer(signedCertificate),
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                keyUsage: template.keyUsage,
                extendedKeyUsage: template.extendedKeyUsage,
                enrollmentRequestId: request.id,
                deviceId: request.deviceId,
                requester: request.requester,
                status: 'active',
                createdAt: new Date(),
                lastRenewalCheck: new Date(),
                deploymentStatus: 'pending',
                metadata: request.metadata
            };

            this.certificates.set(certificate.id, certificate);
            await this.saveCertificate(certificate);
            
            // Update enrollment request
            request.status = 'completed';
            request.certificateId = certificate.id;
            request.completedAt = new Date();
            
            // Queue for deployment if auto-deployment enabled
            if (template.autoDeployment) {
                await this.queueForDeployment(certificate);
            }
            
            this.updateMetrics();
            this.logger.info(`Certificate enrollment completed: ${certificate.id}`);
            this.emit('certificateEnrolled', certificate);
            
            return certificate;

        } catch (error) {
            request.status = 'failed';
            request.error = error.message;
            request.failedAt = new Date();
            
            this.logger.error('Certificate enrollment failed:', error);
            this.emit('enrollmentFailed', request, error);
            throw error;
        }
    }

    /**
     * Certificate Renewal Automation
     */
    async checkRenewals() {
        try {
            const certificatesToRenew = [];
            const now = new Date();
            
            for (const [certId, certificate] of this.certificates) {
                if (certificate.status !== 'active') continue;
                
                const template = this.templates.get(certificate.templateId);
                if (!template || !template.autoRenewal) continue;
                
                const renewalThreshold = template.renewalThreshold;
                const daysUntilExpiration = this.calculateDaysUntilExpiration(certificate.notAfter);
                
                if (daysUntilExpiration <= renewalThreshold && daysUntilExpiration > 0) {
                    certificatesToRenew.push(certificate);
                }
            }
            
            this.logger.info(`Found ${certificatesToRenew.length} certificates for renewal`);
            
            for (const certificate of certificatesToRenew) {
                await this.renewCertificate(certificate.id);
            }
            
            return certificatesToRenew.length;

        } catch (error) {
            this.logger.error('Failed to check renewals:', error);
            throw error;
        }
    }

    async renewCertificate(certificateId, options = {}) {
        try {
            const certificate = this.certificates.get(certificateId);
            if (!certificate) throw new Error(`Certificate not found: ${certificateId}`);

            const template = this.templates.get(certificate.templateId);
            if (!template) throw new Error(`Template not found: ${certificate.templateId}`);

            const renewalId = this.generateRequestId();
            const renewalRequest = {
                id: renewalId,
                type: 'renewal',
                originalCertificateId: certificateId,
                templateId: certificate.templateId,
                subject: certificate.subject,
                subjectAltName: certificate.subjectAltName,
                deviceId: certificate.deviceId,
                requester: options.requester || 'system',
                status: 'processing',
                submittedAt: new Date(),
                reuseKey: options.reuseKey !== undefined ? options.reuseKey : false
            };

            // Generate new key pair or reuse existing
            let keyPair;
            if (renewalRequest.reuseKey && certificate.privateKey) {
                keyPair = {
                    privateKey: certificate.privateKey,
                    publicKey: certificate.publicKey
                };
            } else {
                keyPair = await this.generateKeyPair(template.keySize, template.keyAlgorithm);
            }

            // Create CSR
            const csr = await this.createCSR(renewalRequest, keyPair, template);
            
            // Submit to CA for signing
            const signedCertificate = await this.submitToCA(csr, template);
            
            // Create new certificate record
            const newCertificate = {
                ...certificate,
                id: this.generateCertificateId(),
                serialNumber: this.extractSerialNumber(signedCertificate),
                certificate: signedCertificate,
                privateKey: this.config.storePrivateKeys ? keyPair.privateKey : null,
                publicKey: keyPair.publicKey,
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                renewalRequestId: renewalId,
                parentCertificateId: certificateId,
                createdAt: new Date(),
                lastRenewalCheck: new Date(),
                deploymentStatus: 'pending'
            };

            // Store new certificate
            this.certificates.set(newCertificate.id, newCertificate);
            await this.saveCertificate(newCertificate);
            
            // Update original certificate status
            certificate.status = 'renewed';
            certificate.renewedAt = new Date();
            certificate.newCertificateId = newCertificate.id;
            
            // Update renewal request
            renewalRequest.status = 'completed';
            renewalRequest.newCertificateId = newCertificate.id;
            renewalRequest.completedAt = new Date();
            
            // Queue for deployment
            if (template.autoDeployment) {
                await this.queueForDeployment(newCertificate);
            }
            
            this.updateMetrics();
            this.logger.info(`Certificate renewed successfully: ${certificateId} -> ${newCertificate.id}`);
            this.emit('certificateRenewed', certificate, newCertificate);
            
            return newCertificate;

        } catch (error) {
            this.metrics.renewalFailures++;
            this.logger.error('Certificate renewal failed:', error);
            this.emit('renewalFailed', certificateId, error);
            throw error;
        }
    }

    /**
     * Expiration Monitoring and Alerts
     */
    async monitorExpirations() {
        try {
            const now = new Date();
            const alerts = [];
            
            for (const [certId, certificate] of this.certificates) {
                if (certificate.status !== 'active') continue;
                
                const daysUntilExpiration = this.calculateDaysUntilExpiration(certificate.notAfter);
                
                let alertLevel = null;
                if (daysUntilExpiration <= 0) {
                    alertLevel = 'critical';
                } else if (daysUntilExpiration <= 7) {
                    alertLevel = 'high';
                } else if (daysUntilExpiration <= 30) {
                    alertLevel = 'medium';
                } else if (daysUntilExpiration <= 60) {
                    alertLevel = 'low';
                }
                
                if (alertLevel) {
                    const alert = {
                        certificateId: certId,
                        certificate,
                        alertLevel,
                        daysUntilExpiration,
                        message: this.generateExpirationMessage(certificate, daysUntilExpiration),
                        timestamp: now
                    };
                    
                    alerts.push(alert);
                    await this.sendExpirationAlert(alert);
                }
            }
            
            this.updateExpirationMetrics();
            this.logger.info(`Expiration monitoring completed: ${alerts.length} alerts generated`);
            
            return alerts;

        } catch (error) {
            this.logger.error('Expiration monitoring failed:', error);
            throw error;
        }
    }

    async sendExpirationAlert(alert) {
        try {
            const template = this.templates.get(alert.certificate.templateId);
            const recipients = this.getAlertRecipients(alert, template);
            
            if (this.emailTransporter && recipients.length > 0) {
                const mailOptions = {
                    from: this.config.emailFrom || 'noreply@opendirectory.com',
                    to: recipients.join(','),
                    subject: `Certificate Expiration Alert - ${alert.alertLevel.toUpperCase()}`,
                    html: this.generateExpirationEmailHtml(alert)
                };
                
                await this.emailTransporter.sendMail(mailOptions);
                this.logger.info(`Expiration alert sent for certificate: ${alert.certificateId}`);
            }
            
            // Emit event for custom handlers
            this.emit('expirationAlert', alert);
            
        } catch (error) {
            this.logger.error('Failed to send expiration alert:', error);
        }
    }

    /**
     * Certificate Deployment to Devices
     */
    async queueForDeployment(certificate) {
        try {
            const template = this.templates.get(certificate.templateId);
            if (!template || !template.deploymentTargets || template.deploymentTargets.length === 0) {
                return;
            }
            
            const deploymentId = this.generateRequestId();
            const deployment = {
                id: deploymentId,
                certificateId: certificate.id,
                targets: template.deploymentTargets,
                status: 'queued',
                attempts: 0,
                maxAttempts: this.config.maxRetries,
                queuedAt: new Date(),
                metadata: {}
            };
            
            this.deploymentQueue.set(deploymentId, deployment);
            await this.saveDeployment(deployment);
            
            // Start deployment process
            await this.processDeployment(deploymentId);
            
            this.logger.info(`Certificate queued for deployment: ${certificate.id}`);
            
        } catch (error) {
            this.logger.error('Failed to queue certificate for deployment:', error);
            throw error;
        }
    }

    async processDeployment(deploymentId) {
        try {
            const deployment = this.deploymentQueue.get(deploymentId);
            if (!deployment) throw new Error(`Deployment not found: ${deploymentId}`);

            const certificate = this.certificates.get(deployment.certificateId);
            if (!certificate) throw new Error(`Certificate not found: ${deployment.certificateId}`);

            deployment.status = 'processing';
            deployment.startedAt = new Date();
            deployment.attempts++;

            const results = [];
            
            for (const target of deployment.targets) {
                try {
                    const result = await this.deployToTarget(certificate, target);
                    results.push({ target, success: true, result });
                    this.logger.info(`Certificate deployed successfully to ${target.type}:${target.id}`);
                } catch (error) {
                    results.push({ target, success: false, error: error.message });
                    this.logger.error(`Certificate deployment failed to ${target.type}:${target.id}:`, error);
                }
            }
            
            const successCount = results.filter(r => r.success).length;
            const totalTargets = deployment.targets.length;
            
            if (successCount === totalTargets) {
                deployment.status = 'completed';
                certificate.deploymentStatus = 'deployed';
                this.metrics.deploymentSuccess++;
            } else if (successCount > 0) {
                deployment.status = 'partial';
                certificate.deploymentStatus = 'partial';
            } else {
                deployment.status = 'failed';
                certificate.deploymentStatus = 'failed';
                this.metrics.deploymentFailures++;
            }
            
            deployment.completedAt = new Date();
            deployment.results = results;
            
            await this.saveCertificate(certificate);
            await this.saveDeployment(deployment);
            
            this.emit('deploymentCompleted', deployment, certificate);
            
        } catch (error) {
            const deployment = this.deploymentQueue.get(deploymentId);
            if (deployment) {
                deployment.status = 'error';
                deployment.error = error.message;
                this.metrics.deploymentFailures++;
            }
            
            this.logger.error('Deployment processing failed:', error);
            throw error;
        }
    }

    async deployToTarget(certificate, target) {
        // Implementation would depend on target type (MDM, SCEP, manual, etc.)
        switch (target.type) {
            case 'mdm':
                return await this.deployToMDM(certificate, target);
            case 'scep':
                return await this.deployToSCEP(certificate, target);
            case 'api':
                return await this.deployToAPI(certificate, target);
            case 'file':
                return await this.deployToFile(certificate, target);
            default:
                throw new Error(`Unsupported deployment target type: ${target.type}`);
        }
    }

    /**
     * Certificate Inventory Management
     */
    async getCertificateInventory(filters = {}) {
        const inventory = [];
        
        for (const [certId, certificate] of this.certificates) {
            // Apply filters
            if (filters.status && certificate.status !== filters.status) continue;
            if (filters.templateId && certificate.templateId !== filters.templateId) continue;
            if (filters.deviceId && certificate.deviceId !== filters.deviceId) continue;
            if (filters.requester && certificate.requester !== filters.requester) continue;
            
            // Date range filters
            if (filters.issuedAfter && certificate.createdAt < new Date(filters.issuedAfter)) continue;
            if (filters.issuedBefore && certificate.createdAt > new Date(filters.issuedBefore)) continue;
            if (filters.expiresAfter && certificate.notAfter < new Date(filters.expiresAfter)) continue;
            if (filters.expiresBefore && certificate.notAfter > new Date(filters.expiresBefore)) continue;
            
            const daysUntilExpiration = this.calculateDaysUntilExpiration(certificate.notAfter);
            const template = this.templates.get(certificate.templateId);
            
            inventory.push({
                id: certificate.id,
                serialNumber: certificate.serialNumber,
                subject: certificate.subject,
                issuer: certificate.issuer,
                notBefore: certificate.notBefore,
                notAfter: certificate.notAfter,
                daysUntilExpiration,
                status: certificate.status,
                template: template ? template.name : 'Unknown',
                deviceId: certificate.deviceId,
                requester: certificate.requester,
                deploymentStatus: certificate.deploymentStatus,
                createdAt: certificate.createdAt
            });
        }
        
        // Sort by expiration date by default
        inventory.sort((a, b) => new Date(a.notAfter) - new Date(b.notAfter));
        
        return inventory;
    }

    async revokeCertificate(certificateId, reason = 'unspecified', requester = 'system') {
        try {
            const certificate = this.certificates.get(certificateId);
            if (!certificate) throw new Error(`Certificate not found: ${certificateId}`);

            // Update certificate status
            certificate.status = 'revoked';
            certificate.revokedAt = new Date();
            certificate.revocationReason = reason;
            certificate.revokedBy = requester;
            
            // Notify CA for CRL update
            await this.notifyCARevocation(certificate, reason);
            
            // Remove from devices if deployed
            if (certificate.deploymentStatus === 'deployed') {
                await this.removeFromDevices(certificate);
            }
            
            await this.saveCertificate(certificate);
            
            this.updateMetrics();
            this.logger.info(`Certificate revoked: ${certificateId}, reason: ${reason}`);
            this.emit('certificateRevoked', certificate);
            
            return certificate;

        } catch (error) {
            this.logger.error('Failed to revoke certificate:', error);
            throw error;
        }
    }

    /**
     * Bulk Certificate Operations
     */
    async createBulkOperation(operation) {
        try {
            const operationId = this.generateRequestId();
            const bulkOp = {
                id: operationId,
                type: operation.type, // enroll, renew, revoke, deploy
                parameters: operation.parameters,
                targets: operation.targets || [],
                status: 'queued',
                progress: {
                    total: operation.targets ? operation.targets.length : 0,
                    completed: 0,
                    failed: 0,
                    results: []
                },
                createdAt: new Date(),
                createdBy: operation.requester || 'system'
            };

            this.bulkOperations.set(operationId, bulkOp);
            await this.saveBulkOperation(bulkOp);
            
            // Start processing
            setImmediate(() => this.processBulkOperation(operationId));
            
            this.logger.info(`Bulk operation created: ${operationId}, type: ${operation.type}`);
            return bulkOp;

        } catch (error) {
            this.logger.error('Failed to create bulk operation:', error);
            throw error;
        }
    }

    async processBulkOperation(operationId) {
        try {
            const operation = this.bulkOperations.get(operationId);
            if (!operation) throw new Error(`Bulk operation not found: ${operationId}`);

            operation.status = 'processing';
            operation.startedAt = new Date();

            const batchSize = this.config.bulkOperationBatchSize;
            const targets = operation.targets;
            
            for (let i = 0; i < targets.length; i += batchSize) {
                const batch = targets.slice(i, i + batchSize);
                const batchPromises = [];
                
                for (const target of batch) {
                    batchPromises.push(this.processBulkTarget(operation, target));
                }
                
                const batchResults = await Promise.allSettled(batchPromises);
                
                for (let j = 0; j < batchResults.length; j++) {
                    const result = batchResults[j];
                    const target = batch[j];
                    
                    if (result.status === 'fulfilled') {
                        operation.progress.completed++;
                        operation.progress.results.push({
                            target,
                            success: true,
                            result: result.value
                        });
                    } else {
                        operation.progress.failed++;
                        operation.progress.results.push({
                            target,
                            success: false,
                            error: result.reason.message
                        });
                    }
                }
                
                // Save progress
                await this.saveBulkOperation(operation);
                this.emit('bulkOperationProgress', operation);
                
                // Small delay between batches
                if (i + batchSize < targets.length) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }
            
            operation.status = 'completed';
            operation.completedAt = new Date();
            
            await this.saveBulkOperation(operation);
            
            this.logger.info(`Bulk operation completed: ${operationId}, ` +
                `success: ${operation.progress.completed}, failed: ${operation.progress.failed}`);
            this.emit('bulkOperationCompleted', operation);

        } catch (error) {
            const operation = this.bulkOperations.get(operationId);
            if (operation) {
                operation.status = 'failed';
                operation.error = error.message;
                operation.completedAt = new Date();
                await this.saveBulkOperation(operation);
            }
            
            this.logger.error('Bulk operation failed:', error);
            throw error;
        }
    }

    async processBulkTarget(operation, target) {
        switch (operation.type) {
            case 'enroll':
                return await this.enrollCertificate({
                    ...operation.parameters,
                    ...target
                });
            case 'renew':
                return await this.renewCertificate(target.certificateId, operation.parameters);
            case 'revoke':
                return await this.revokeCertificate(target.certificateId, 
                    operation.parameters.reason, operation.createdBy);
            case 'deploy':
                return await this.queueForDeployment(this.certificates.get(target.certificateId));
            default:
                throw new Error(`Unsupported bulk operation type: ${operation.type}`);
        }
    }

    /**
     * Approval Workflows
     */
    async initiateApprovalWorkflow(request, template) {
        try {
            const workflowId = this.generateRequestId();
            const workflow = {
                id: workflowId,
                requestId: request.id,
                templateId: template.id,
                approvers: template.approvers.slice(),
                requiredApprovals: template.approvers.length,
                approvals: [],
                rejections: [],
                status: 'pending',
                createdAt: new Date()
            };

            this.workflows.set(workflowId, workflow);
            await this.saveWorkflow(workflow);
            
            // Send approval notifications
            for (const approver of template.approvers) {
                await this.sendApprovalNotification(workflow, approver, request);
            }
            
            this.logger.info(`Approval workflow initiated: ${workflowId}`);
            this.emit('approvalWorkflowStarted', workflow);

        } catch (error) {
            this.logger.error('Failed to initiate approval workflow:', error);
            throw error;
        }
    }

    async processApproval(workflowId, approver, decision, comments = '') {
        try {
            const workflow = this.workflows.get(workflowId);
            if (!workflow) throw new Error(`Workflow not found: ${workflowId}`);

            if (workflow.status !== 'pending') {
                throw new Error(`Workflow is not pending: ${workflowId}`);
            }

            const approval = {
                approver,
                decision, // 'approved' or 'rejected'
                comments,
                timestamp: new Date()
            };

            if (decision === 'approved') {
                workflow.approvals.push(approval);
            } else {
                workflow.rejections.push(approval);
                workflow.status = 'rejected';
                workflow.completedAt = new Date();
            }

            // Check if all approvals received
            if (workflow.approvals.length >= workflow.requiredApprovals) {
                workflow.status = 'approved';
                workflow.completedAt = new Date();
                
                // Process the original enrollment request
                const request = this.enrollmentRequests.get(workflow.requestId);
                if (request) {
                    request.status = 'approved';
                    await this.processEnrollment(request);
                }
            }

            await this.saveWorkflow(workflow);
            
            this.logger.info(`Approval processed: ${workflowId}, decision: ${decision}`);
            this.emit('approvalProcessed', workflow, approval);

        } catch (error) {
            this.logger.error('Failed to process approval:', error);
            throw error;
        }
    }

    /**
     * Utility Methods
     */
    generateTemplateId(name) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(name + timestamp)
            .digest('hex')
            .substring(0, 8);
        return `tpl-${hash}`;
    }

    generateRequestId() {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `req-${timestamp}-${random.toString(16)}`;
    }

    generateCertificateId() {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `cert-${timestamp}-${random.toString(16)}`;
    }

    incrementVersion(version) {
        const parts = version.split('.');
        parts[parts.length - 1] = (parseInt(parts[parts.length - 1]) + 1).toString();
        return parts.join('.');
    }

    calculateDaysUntilExpiration(notAfter) {
        const now = new Date();
        const expiration = new Date(notAfter);
        const diffTime = expiration - now;
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }

    generateExpirationMessage(certificate, daysUntilExpiration) {
        const subject = this.formatSubject(certificate.subject);
        
        if (daysUntilExpiration <= 0) {
            return `Certificate has EXPIRED: ${subject}`;
        } else if (daysUntilExpiration === 1) {
            return `Certificate expires tomorrow: ${subject}`;
        } else {
            return `Certificate expires in ${daysUntilExpiration} days: ${subject}`;
        }
    }

    formatSubject(subject) {
        if (typeof subject === 'object' && subject.commonName) {
            return subject.commonName;
        }
        return JSON.stringify(subject);
    }

    getAlertRecipients(alert, template) {
        const recipients = [];
        
        if (template && template.approvers) {
            recipients.push(...template.approvers);
        }
        
        if (alert.certificate.requester && !recipients.includes(alert.certificate.requester)) {
            recipients.push(alert.certificate.requester);
        }
        
        return recipients.filter(r => r.includes('@')); // Basic email validation
    }

    generateExpirationEmailHtml(alert) {
        return `
            <h2>Certificate Expiration Alert</h2>
            <p><strong>Alert Level:</strong> ${alert.alertLevel.toUpperCase()}</p>
            <p><strong>Certificate ID:</strong> ${alert.certificateId}</p>
            <p><strong>Subject:</strong> ${this.formatSubject(alert.certificate.subject)}</p>
            <p><strong>Serial Number:</strong> ${alert.certificate.serialNumber}</p>
            <p><strong>Expires:</strong> ${alert.certificate.notAfter}</p>
            <p><strong>Days Until Expiration:</strong> ${alert.daysUntilExpiration}</p>
            <p><strong>Device ID:</strong> ${alert.certificate.deviceId || 'N/A'}</p>
            <p><strong>Requester:</strong> ${alert.certificate.requester}</p>
            
            <h3>Next Steps</h3>
            <p>Please review this certificate and take appropriate action to renew or replace it before expiration.</p>
        `;
    }

    updateMetrics() {
        this.metrics.totalCertificates = this.certificates.size;
        this.metrics.activeCertificates = 0;
        this.metrics.expiringSoon = 0;
        this.metrics.expired = 0;

        const now = new Date();
        
        for (const [certId, certificate] of this.certificates) {
            if (certificate.status === 'active') {
                this.metrics.activeCertificates++;
                
                const daysUntilExpiration = this.calculateDaysUntilExpiration(certificate.notAfter);
                
                if (daysUntilExpiration <= 0) {
                    this.metrics.expired++;
                } else if (daysUntilExpiration <= 30) {
                    this.metrics.expiringSoon++;
                }
            }
        }
    }

    updateExpirationMetrics() {
        this.updateMetrics(); // Reuse existing logic
    }

    scheduleMonitoring() {
        // Schedule daily monitoring
        cron.schedule(this.config.monitoringInterval, async () => {
            try {
                await this.monitorExpirations();
                await this.checkRenewals();
                this.logger.info('Scheduled monitoring completed');
            } catch (error) {
                this.logger.error('Scheduled monitoring failed:', error);
            }
        });
    }

    setupEventHandlers() {
        this.on('certificateEnrolled', (certificate) => {
            this.metrics.renewalSuccess++; // Count successful enrollments
        });
        
        this.on('certificateRenewed', (oldCert, newCert) => {
            this.metrics.renewalSuccess++;
        });
        
        this.on('enrollmentFailed', (request, error) => {
            this.metrics.renewalFailures++;
        });
    }

    /**
     * Storage Methods (placeholder implementations)
     */
    async saveTemplate(template) {
        const templatePath = path.join(this.config.templatesPath, `${template.id}.json`);
        await fs.writeFile(templatePath, JSON.stringify(template, null, 2));
    }

    async loadCertificateTemplates() {
        try {
            const files = await fs.readdir(this.config.templatesPath);
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const templatePath = path.join(this.config.templatesPath, file);
                    const templateData = JSON.parse(await fs.readFile(templatePath, 'utf8'));
                    this.templates.set(templateData.id, templateData);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load certificate templates:', error);
            }
        }
    }

    async saveCertificate(certificate) {
        const certPath = path.join(this.config.storagePath, 'inventory', `${certificate.id}.json`);
        await fs.writeFile(certPath, JSON.stringify(certificate, null, 2));
    }

    async loadCertificateInventory() {
        try {
            const inventoryPath = path.join(this.config.storagePath, 'inventory');
            const files = await fs.readdir(inventoryPath);
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const certPath = path.join(inventoryPath, file);
                    const certData = JSON.parse(await fs.readFile(certPath, 'utf8'));
                    this.certificates.set(certData.id, certData);
                }
            }
            this.updateMetrics();
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load certificate inventory:', error);
            }
        }
    }

    async saveEnrollmentRequest(request) {
        const requestPath = path.join(this.config.storagePath, 'enrollment', `${request.id}.json`);
        await fs.writeFile(requestPath, JSON.stringify(request, null, 2));
    }

    async saveDeployment(deployment) {
        const deploymentPath = path.join(this.config.storagePath, 'deployment', `${deployment.id}.json`);
        await fs.writeFile(deploymentPath, JSON.stringify(deployment, null, 2));
    }

    async saveWorkflow(workflow) {
        const workflowPath = path.join(this.config.storagePath, 'workflows', `${workflow.id}.json`);
        await fs.writeFile(workflowPath, JSON.stringify(workflow, null, 2));
    }

    async saveBulkOperation(operation) {
        const opPath = path.join(this.config.storagePath, 'bulk-operations', `${operation.id}.json`);
        await fs.writeFile(opPath, JSON.stringify(operation, null, 2));
    }

    /**
     * Integration Methods (placeholders)
     */
    async generateKeyPair(keySize, algorithm) {
        // Implementation would generate actual key pairs
        return { privateKey: 'private-key-pem', publicKey: 'public-key-pem' };
    }

    async createCSR(request, keyPair, template) {
        // Implementation would create actual CSR
        return 'csr-pem-data';
    }

    async submitToCA(csr, template) {
        // Implementation would submit to actual CA
        return 'signed-certificate-pem';
    }

    async deployToMDM(certificate, target) {
        // Implementation for MDM deployment
        return { deployed: true, mdmCommandId: 'cmd-123' };
    }

    async deployToSCEP(certificate, target) {
        // Implementation for SCEP deployment
        return { deployed: true, scepUrl: target.url };
    }

    async deployToAPI(certificate, target) {
        // Implementation for API deployment
        return { deployed: true, apiResponse: 'success' };
    }

    async deployToFile(certificate, target) {
        // Implementation for file deployment
        const filePath = path.join(target.path, `${certificate.id}.pem`);
        await fs.writeFile(filePath, certificate.certificate);
        return { deployed: true, filePath };
    }

    async notifyCARevocation(certificate, reason) {
        // Implementation would notify CA system
        this.logger.info(`Notifying CA of revocation: ${certificate.serialNumber}`);
    }

    async removeFromDevices(certificate) {
        // Implementation would remove certificate from deployed devices
        this.logger.info(`Removing certificate from devices: ${certificate.id}`);
    }

    async sendApprovalNotification(workflow, approver, request) {
        // Implementation would send approval notification
        this.logger.info(`Approval notification sent to: ${approver}`);
    }

    // Extraction methods (placeholders)
    extractSerialNumber(certificate) {
        return 'serial-number';
    }

    extractIssuer(certificate) {
        return 'issuer-dn';
    }

    extractNotBefore(certificate) {
        return new Date();
    }

    extractNotAfter(certificate) {
        const future = new Date();
        future.setFullYear(future.getFullYear() + 1);
        return future;
    }

    /**
     * Public API Methods
     */
    async getMetrics() {
        return { ...this.metrics };
    }

    async getTemplates() {
        return Array.from(this.templates.values());
    }

    async getTemplate(templateId) {
        return this.templates.get(templateId);
    }

    async getBulkOperationStatus(operationId) {
        return this.bulkOperations.get(operationId);
    }

    async getWorkflowStatus(workflowId) {
        return this.workflows.get(workflowId);
    }
}

module.exports = CertificateLifecycleManager;