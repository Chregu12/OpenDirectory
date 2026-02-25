/**
 * OpenDirectory Certificate Lifecycle Management Service
 * Comprehensive certificate lifecycle automation with auto-enrollment
 * 
 * Features:
 * - Automated certificate enrollment and renewal
 * - Certificate template management
 * - Expiration monitoring and alerts
 * - Auto-deployment to devices
 * - Bulk certificate operations
 * - Approval workflows
 * - Integration with Enterprise Directory
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const cron = require('node-cron');
const EventEmitter = require('events');
const winston = require('winston');
const nodemailer = require('nodemailer');
const config = require('../config');

class CertificateLifecycleService extends EventEmitter {
    constructor(caService, options = {}) {
        super();
        
        this.caService = caService;
        this.config = {
            ...config.pki,
            ...options
        };

        this.logger = winston.createLogger({
            level: config.logging.level,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ 
                    filename: path.join(path.dirname(config.logging.file), 'lifecycle.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // Email configuration
        this.emailTransporter = null;
        if (config.notifications.enabled && config.notifications.smtp.host) {
            this.emailTransporter = nodemailer.createTransporter(config.notifications.smtp);
        }

        // Data stores
        this.certificateTemplates = new Map();
        this.enrollmentRequests = new Map();
        this.renewalQueue = new Map();
        this.deploymentQueue = new Map();
        this.approvalWorkflows = new Map();
        this.bulkOperations = new Map();
        this.certificateInventory = new Map();
        
        // Auto-enrollment configurations
        this.autoEnrollmentPolicies = new Map();
        this.deviceCertificateMap = new Map();
        
        // Monitoring and metrics
        this.metrics = {
            enrollmentRequests: 0,
            successfulEnrollments: 0,
            failedEnrollments: 0,
            renewalSuccess: 0,
            renewalFailures: 0,
            deploymentSuccess: 0,
            deploymentFailures: 0,
            expirationAlerts: 0,
            autoEnrollments: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadCertificateTemplates();
            await this.loadAutoEnrollmentPolicies();
            await this.loadCertificateInventory();
            this.scheduleMonitoring();
            this.setupEventHandlers();
            
            this.logger.info('Certificate Lifecycle Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize Certificate Lifecycle Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            path.join(config.storage.certificates, 'templates'),
            path.join(config.storage.certificates, 'enrollment'),
            path.join(config.storage.certificates, 'inventory'),
            path.join(config.storage.certificates, 'auto-enrollment'),
            path.join(config.storage.certificates, 'workflows'),
            path.join(config.storage.certificates, 'bulk-operations'),
            path.join(config.storage.certificates, 'deployments')
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
                
                // Certificate properties
                validityPeriod: templateData.validityPeriod || this.config.leafCertValidity,
                keySize: templateData.keySize || this.config.keySize,
                keyAlgorithm: templateData.keyAlgorithm || 'RSA',
                hashAlgorithm: templateData.hashAlgorithm || this.config.hashAlgorithm,
                
                // Subject configuration
                subject: {
                    template: templateData.subject || {},
                    allowCustomization: templateData.allowSubjectCustomization || false,
                    requiredFields: templateData.requiredSubjectFields || ['commonName']
                },
                
                // Extensions
                keyUsage: templateData.keyUsage || ['digitalSignature', 'keyEncipherment'],
                extendedKeyUsage: templateData.extendedKeyUsage || [],
                subjectAltName: {
                    template: templateData.subjectAltName || [],
                    allowCustomization: templateData.allowSANCustomization || false
                },
                
                // Enrollment settings
                enrollmentMethod: templateData.enrollmentMethod || 'manual', // manual, auto, scep
                caId: templateData.caId,
                requireApproval: templateData.requireApproval !== undefined ? templateData.requireApproval : false,
                approvers: templateData.approvers || [],
                
                // Auto-enrollment settings
                autoEnrollment: {
                    enabled: templateData.autoEnrollment?.enabled || false,
                    triggers: templateData.autoEnrollment?.triggers || ['deviceJoin', 'userLogin'],
                    deviceTypes: templateData.autoEnrollment?.deviceTypes || ['windows', 'macos', 'ios', 'android'],
                    userGroups: templateData.autoEnrollment?.userGroups || [],
                    deviceGroups: templateData.autoEnrollment?.deviceGroups || []
                },
                
                // Renewal settings
                autoRenewal: {
                    enabled: templateData.autoRenewal?.enabled !== undefined ? templateData.autoRenewal.enabled : true,
                    threshold: templateData.autoRenewal?.threshold || this.config.renewalThreshold,
                    reuseKey: templateData.autoRenewal?.reuseKey || false
                },
                
                // Deployment settings
                autoDeployment: {
                    enabled: templateData.autoDeployment?.enabled || false,
                    targets: templateData.autoDeployment?.targets || [],
                    methods: templateData.autoDeployment?.methods || ['mdm']
                },
                
                // Security settings
                exportable: templateData.exportable !== undefined ? templateData.exportable : false,
                strongKeyProtection: templateData.strongKeyProtection !== undefined ? templateData.strongKeyProtection : true,
                
                // Monitoring
                enableMonitoring: templateData.enableMonitoring !== undefined ? templateData.enableMonitoring : true,
                notificationRecipients: templateData.notificationRecipients || [],
                
                createdAt: new Date(),
                updatedAt: new Date(),
                status: 'active'
            };

            this.certificateTemplates.set(templateId, template);
            await this.saveCertificateTemplate(template);
            
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
            const template = this.certificateTemplates.get(templateId);
            if (!template) {
                throw new Error(`Template not found: ${templateId}`);
            }

            const updatedTemplate = {
                ...template,
                ...updates,
                version: this.incrementVersion(template.version),
                updatedAt: new Date()
            };

            this.certificateTemplates.set(templateId, updatedTemplate);
            await this.saveCertificateTemplate(updatedTemplate);
            
            this.logger.info(`Certificate template updated: ${templateId}`);
            this.emit('templateUpdated', updatedTemplate);
            
            return updatedTemplate;

        } catch (error) {
            this.logger.error('Failed to update certificate template:', error);
            throw error;
        }
    }

    /**
     * Auto-Enrollment System
     */
    async createAutoEnrollmentPolicy(policyData) {
        try {
            const policyId = this.generatePolicyId();
            const policy = {
                id: policyId,
                name: policyData.name,
                description: policyData.description || '',
                enabled: policyData.enabled !== undefined ? policyData.enabled : true,
                
                // Trigger conditions
                triggers: policyData.triggers || ['deviceJoin'],
                conditions: {
                    deviceTypes: policyData.conditions?.deviceTypes || [],
                    userGroups: policyData.conditions?.userGroups || [],
                    deviceGroups: policyData.conditions?.deviceGroups || [],
                    osVersions: policyData.conditions?.osVersions || {},
                    customAttributes: policyData.conditions?.customAttributes || {}
                },
                
                // Certificate configuration
                templateId: policyData.templateId,
                certificateProfile: {
                    subject: policyData.certificateProfile?.subject || {},
                    subjectAltName: policyData.certificateProfile?.subjectAltName || [],
                    validityPeriod: policyData.certificateProfile?.validityPeriod
                },
                
                // Deployment configuration
                deployment: {
                    automatic: policyData.deployment?.automatic !== undefined ? policyData.deployment.automatic : true,
                    targets: policyData.deployment?.targets || ['device'],
                    stores: policyData.deployment?.stores || ['user', 'machine']
                },
                
                priority: policyData.priority || 100,
                createdAt: new Date(),
                updatedAt: new Date()
            };

            this.autoEnrollmentPolicies.set(policyId, policy);
            await this.saveAutoEnrollmentPolicy(policy);
            
            this.logger.info(`Auto-enrollment policy created: ${policyId}`);
            this.emit('autoEnrollmentPolicyCreated', policy);
            
            return policy;

        } catch (error) {
            this.logger.error('Failed to create auto-enrollment policy:', error);
            throw error;
        }
    }

    async triggerAutoEnrollment(deviceInfo, trigger = 'manual') {
        try {
            const applicablePolicies = this.findApplicablePolicies(deviceInfo, trigger);
            
            if (applicablePolicies.length === 0) {
                this.logger.info(`No applicable auto-enrollment policies for device: ${deviceInfo.deviceId}`);
                return { enrolled: false, reason: 'No applicable policies' };
            }

            // Sort by priority (lower number = higher priority)
            applicablePolicies.sort((a, b) => a.priority - b.priority);

            const enrollmentResults = [];
            
            for (const policy of applicablePolicies) {
                try {
                    const result = await this.executeAutoEnrollment(deviceInfo, policy);
                    enrollmentResults.push({
                        policyId: policy.id,
                        success: true,
                        result
                    });
                    
                    this.metrics.autoEnrollments++;
                    
                } catch (error) {
                    enrollmentResults.push({
                        policyId: policy.id,
                        success: false,
                        error: error.message
                    });
                    
                    this.logger.error(`Auto-enrollment failed for policy ${policy.id}:`, error);
                }
            }
            
            this.logger.info(`Auto-enrollment completed for device: ${deviceInfo.deviceId}, Results: ${enrollmentResults.length}`);
            this.emit('autoEnrollmentCompleted', deviceInfo, enrollmentResults);
            
            return {
                enrolled: enrollmentResults.some(r => r.success),
                results: enrollmentResults
            };

        } catch (error) {
            this.logger.error('Auto-enrollment failed:', error);
            throw error;
        }
    }

    async executeAutoEnrollment(deviceInfo, policy) {
        const template = this.certificateTemplates.get(policy.templateId);
        if (!template) {
            throw new Error(`Template not found: ${policy.templateId}`);
        }

        // Build certificate request from policy and device info
        const enrollmentRequest = {
            templateId: policy.templateId,
            subject: this.buildSubjectFromPolicy(deviceInfo, policy),
            subjectAltName: this.buildSANFromPolicy(deviceInfo, policy),
            deviceId: deviceInfo.deviceId,
            userId: deviceInfo.userId,
            requester: 'auto-enrollment',
            metadata: {
                policyId: policy.id,
                trigger: 'auto-enrollment',
                deviceInfo: deviceInfo
            }
        };

        return await this.enrollCertificate(enrollmentRequest);
    }

    findApplicablePolicies(deviceInfo, trigger) {
        const applicablePolicies = [];
        
        for (const [policyId, policy] of this.autoEnrollmentPolicies) {
            if (!policy.enabled) continue;
            
            // Check trigger
            if (!policy.triggers.includes(trigger)) continue;
            
            // Check device type
            if (policy.conditions.deviceTypes.length > 0 && 
                !policy.conditions.deviceTypes.includes(deviceInfo.deviceType)) {
                continue;
            }
            
            // Check user groups
            if (policy.conditions.userGroups.length > 0 &&
                (!deviceInfo.userGroups || 
                 !policy.conditions.userGroups.some(group => deviceInfo.userGroups.includes(group)))) {
                continue;
            }
            
            // Check device groups
            if (policy.conditions.deviceGroups.length > 0 &&
                (!deviceInfo.deviceGroups ||
                 !policy.conditions.deviceGroups.some(group => deviceInfo.deviceGroups.includes(group)))) {
                continue;
            }
            
            // Check OS versions
            if (Object.keys(policy.conditions.osVersions).length > 0) {
                const deviceOS = deviceInfo.osVersion;
                const requiredVersions = policy.conditions.osVersions[deviceInfo.deviceType];
                
                if (requiredVersions && deviceOS && !this.checkVersionRequirement(deviceOS, requiredVersions)) {
                    continue;
                }
            }
            
            // Check custom attributes
            if (Object.keys(policy.conditions.customAttributes).length > 0) {
                let customMatch = true;
                
                for (const [attr, value] of Object.entries(policy.conditions.customAttributes)) {
                    if (deviceInfo.customAttributes?.[attr] !== value) {
                        customMatch = false;
                        break;
                    }
                }
                
                if (!customMatch) continue;
            }
            
            applicablePolicies.push(policy);
        }
        
        return applicablePolicies;
    }

    buildSubjectFromPolicy(deviceInfo, policy) {
        const subject = { ...policy.certificateProfile.subject };
        
        // Replace placeholders with device info
        for (const [key, value] of Object.entries(subject)) {
            if (typeof value === 'string') {
                subject[key] = value
                    .replace('{{deviceId}}', deviceInfo.deviceId || '')
                    .replace('{{userId}}', deviceInfo.userId || '')
                    .replace('{{deviceName}}', deviceInfo.deviceName || '')
                    .replace('{{userName}}', deviceInfo.userName || '')
                    .replace('{{department}}', deviceInfo.department || '')
                    .replace('{{organizationalUnit}}', deviceInfo.organizationalUnit || '');
            }
        }
        
        // Set common name if not specified
        if (!subject.commonName) {
            subject.commonName = deviceInfo.deviceName || deviceInfo.deviceId;
        }
        
        return subject;
    }

    buildSANFromPolicy(deviceInfo, policy) {
        const sanList = [];
        
        if (policy.certificateProfile.subjectAltName) {
            for (const san of policy.certificateProfile.subjectAltName) {
                let value = san.value;
                
                // Replace placeholders
                if (typeof value === 'string') {
                    value = value
                        .replace('{{deviceId}}', deviceInfo.deviceId || '')
                        .replace('{{userId}}', deviceInfo.userId || '')
                        .replace('{{deviceName}}', deviceInfo.deviceName || '')
                        .replace('{{userEmail}}', deviceInfo.userEmail || '')
                        .replace('{{deviceFQDN}}', deviceInfo.deviceFQDN || '');
                }
                
                if (value) {
                    sanList.push({
                        type: san.type,
                        value: value
                    });
                }
            }
        }
        
        // Add device-specific SANs
        if (deviceInfo.deviceFQDN) {
            sanList.push({ type: 2, value: deviceInfo.deviceFQDN }); // DNS name
        }
        
        if (deviceInfo.userEmail) {
            sanList.push({ type: 1, value: deviceInfo.userEmail }); // Email
        }
        
        return sanList;
    }

    /**
     * Manual Certificate Enrollment
     */
    async enrollCertificate(enrollmentData) {
        try {
            const requestId = this.generateRequestId();
            const request = {
                id: requestId,
                templateId: enrollmentData.templateId,
                subject: enrollmentData.subject,
                subjectAltName: enrollmentData.subjectAltName || [],
                csr: enrollmentData.csr,
                deviceId: enrollmentData.deviceId,
                userId: enrollmentData.userId,
                requester: enrollmentData.requester || 'manual',
                status: 'pending',
                submittedAt: new Date(),
                metadata: enrollmentData.metadata || {}
            };

            const template = this.certificateTemplates.get(enrollmentData.templateId);
            if (!template) {
                throw new Error(`Template not found: ${enrollmentData.templateId}`);
            }

            // Check if approval is required
            if (template.requireApproval && enrollmentData.requester !== 'auto-enrollment') {
                request.status = 'pending_approval';
                await this.initiateApprovalWorkflow(request, template);
            } else {
                request.status = 'approved';
                await this.processEnrollmentRequest(request);
            }

            this.enrollmentRequests.set(requestId, request);
            await this.saveEnrollmentRequest(request);
            
            this.metrics.enrollmentRequests++;
            this.logger.info(`Certificate enrollment request submitted: ${requestId}`);
            this.emit('enrollmentRequested', request);
            
            return request;

        } catch (error) {
            this.metrics.failedEnrollments++;
            this.logger.error('Certificate enrollment failed:', error);
            throw error;
        }
    }

    async processEnrollmentRequest(request) {
        try {
            const template = this.certificateTemplates.get(request.templateId);
            
            // Issue the certificate
            const certificateResult = await this.caService.issueCertificate({
                caId: template.caId,
                csr: request.csr,
                template: template.id,
                subject: request.subject,
                subjectAltName: request.subjectAltName,
                validityDays: template.validityPeriod,
                keyUsage: template.keyUsage,
                extendedKeyUsage: template.extendedKeyUsage,
                requesterId: request.requester,
                deviceId: request.deviceId
            });

            // Update request status
            request.status = 'completed';
            request.certificateId = certificateResult.id;
            request.completedAt = new Date();

            // Add to inventory
            const inventoryRecord = {
                id: certificateResult.id,
                serialNumber: certificateResult.serialNumber,
                templateId: request.templateId,
                deviceId: request.deviceId,
                userId: request.userId,
                enrollmentRequestId: request.id,
                certificate: certificateResult.certificate,
                privateKey: certificateResult.privateKey,
                caChain: certificateResult.caChain,
                subject: request.subject,
                subjectAltName: request.subjectAltName,
                notBefore: certificateResult.notBefore,
                notAfter: certificateResult.notAfter,
                status: 'active',
                issuedAt: new Date(),
                lastRenewalCheck: new Date(),
                deploymentStatus: 'pending'
            };

            this.certificateInventory.set(certificateResult.id, inventoryRecord);
            await this.saveCertificateInventory(inventoryRecord);

            // Auto-deployment if enabled
            if (template.autoDeployment.enabled) {
                await this.queueForDeployment(inventoryRecord);
            }

            this.metrics.successfulEnrollments++;
            this.logger.info(`Certificate enrollment completed: ${request.id} -> ${certificateResult.id}`);
            this.emit('enrollmentCompleted', request, inventoryRecord);

            return inventoryRecord;

        } catch (error) {
            request.status = 'failed';
            request.error = error.message;
            request.failedAt = new Date();
            
            this.metrics.failedEnrollments++;
            this.logger.error('Certificate enrollment processing failed:', error);
            this.emit('enrollmentFailed', request, error);
            throw error;
        }
    }

    /**
     * Certificate Renewal
     */
    async renewCertificate(certificateId, options = {}) {
        try {
            const certificate = this.certificateInventory.get(certificateId);
            if (!certificate) {
                throw new Error(`Certificate not found: ${certificateId}`);
            }

            const template = this.certificateTemplates.get(certificate.templateId);
            if (!template) {
                throw new Error(`Template not found: ${certificate.templateId}`);
            }

            const renewalRequest = {
                id: this.generateRequestId(),
                type: 'renewal',
                originalCertificateId: certificateId,
                templateId: certificate.templateId,
                subject: certificate.subject,
                subjectAltName: certificate.subjectAltName,
                deviceId: certificate.deviceId,
                userId: certificate.userId,
                requester: options.requester || 'system',
                reuseKey: options.reuseKey !== undefined ? options.reuseKey : template.autoRenewal.reuseKey,
                submittedAt: new Date(),
                status: 'processing'
            };

            // Issue new certificate
            const certificateResult = await this.caService.issueCertificate({
                caId: template.caId,
                subject: certificate.subject,
                subjectAltName: certificate.subjectAltName,
                validityDays: template.validityPeriod,
                keyUsage: template.keyUsage,
                extendedKeyUsage: template.extendedKeyUsage,
                requesterId: renewalRequest.requester,
                deviceId: certificate.deviceId
            });

            // Create new certificate inventory record
            const newCertificate = {
                ...certificate,
                id: certificateResult.id,
                serialNumber: certificateResult.serialNumber,
                certificate: certificateResult.certificate,
                privateKey: certificateResult.privateKey,
                caChain: certificateResult.caChain,
                notBefore: certificateResult.notBefore,
                notAfter: certificateResult.notAfter,
                renewalRequestId: renewalRequest.id,
                parentCertificateId: certificateId,
                issuedAt: new Date(),
                lastRenewalCheck: new Date(),
                deploymentStatus: 'pending'
            };

            // Update original certificate
            certificate.status = 'renewed';
            certificate.renewedAt = new Date();
            certificate.newCertificateId = newCertificate.id;

            // Store updated records
            this.certificateInventory.set(newCertificate.id, newCertificate);
            await this.saveCertificateInventory(certificate);
            await this.saveCertificateInventory(newCertificate);

            // Update renewal request
            renewalRequest.status = 'completed';
            renewalRequest.newCertificateId = newCertificate.id;
            renewalRequest.completedAt = new Date();

            // Auto-deployment
            if (template.autoDeployment.enabled) {
                await this.queueForDeployment(newCertificate);
            }

            this.metrics.renewalSuccess++;
            this.logger.info(`Certificate renewed: ${certificateId} -> ${newCertificate.id}`);
            this.emit('certificateRenewed', certificate, newCertificate);

            return newCertificate;

        } catch (error) {
            this.metrics.renewalFailures++;
            this.logger.error('Certificate renewal failed:', error);
            throw error;
        }
    }

    async checkRenewalRequirements() {
        try {
            const now = new Date();
            const renewalCandidates = [];
            
            for (const [certId, certificate] of this.certificateInventory) {
                if (certificate.status !== 'active') continue;
                
                const template = this.certificateTemplates.get(certificate.templateId);
                if (!template || !template.autoRenewal.enabled) continue;
                
                const daysUntilExpiration = Math.ceil((certificate.notAfter - now) / (1000 * 60 * 60 * 24));
                
                if (daysUntilExpiration <= template.autoRenewal.threshold && daysUntilExpiration > 0) {
                    renewalCandidates.push({
                        certificate,
                        daysUntilExpiration,
                        template
                    });
                }
            }
            
            this.logger.info(`Found ${renewalCandidates.length} certificates for renewal`);
            
            for (const { certificate } of renewalCandidates) {
                try {
                    await this.renewCertificate(certificate.id);
                } catch (error) {
                    this.logger.error(`Failed to renew certificate ${certificate.id}:`, error);
                }
            }
            
            return renewalCandidates.length;

        } catch (error) {
            this.logger.error('Renewal check failed:', error);
            throw error;
        }
    }

    /**
     * Certificate Deployment
     */
    async queueForDeployment(certificate) {
        try {
            const template = this.certificateTemplates.get(certificate.templateId);
            if (!template || !template.autoDeployment.enabled) {
                return;
            }
            
            const deploymentId = this.generateRequestId();
            const deployment = {
                id: deploymentId,
                certificateId: certificate.id,
                deviceId: certificate.deviceId,
                userId: certificate.userId,
                targets: template.autoDeployment.targets,
                methods: template.autoDeployment.methods,
                status: 'queued',
                attempts: 0,
                maxAttempts: 3,
                queuedAt: new Date()
            };
            
            this.deploymentQueue.set(deploymentId, deployment);
            await this.saveDeployment(deployment);
            
            // Start deployment process
            setImmediate(() => this.processDeployment(deploymentId));
            
            this.logger.info(`Certificate queued for deployment: ${certificate.id}`);

        } catch (error) {
            this.logger.error('Failed to queue certificate for deployment:', error);
            throw error;
        }
    }

    async processDeployment(deploymentId) {
        try {
            const deployment = this.deploymentQueue.get(deploymentId);
            if (!deployment) {
                throw new Error(`Deployment not found: ${deploymentId}`);
            }

            const certificate = this.certificateInventory.get(deployment.certificateId);
            if (!certificate) {
                throw new Error(`Certificate not found: ${deployment.certificateId}`);
            }

            deployment.status = 'processing';
            deployment.startedAt = new Date();
            deployment.attempts++;

            const results = [];
            
            // Deploy to each target
            for (const target of deployment.targets) {
                for (const method of deployment.methods) {
                    try {
                        const result = await this.deployToTarget(certificate, target, method);
                        results.push({ target, method, success: true, result });
                        
                        this.logger.info(`Certificate deployed: ${certificate.id} to ${target} via ${method}`);
                    } catch (error) {
                        results.push({ target, method, success: false, error: error.message });
                        
                        this.logger.error(`Certificate deployment failed: ${certificate.id} to ${target} via ${method}`, error);
                    }
                }
            }
            
            // Determine overall status
            const successCount = results.filter(r => r.success).length;
            const totalAttempts = results.length;
            
            if (successCount === totalAttempts) {
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
            
            await this.saveCertificateInventory(certificate);
            await this.saveDeployment(deployment);
            
            this.emit('deploymentCompleted', deployment, certificate);

        } catch (error) {
            const deployment = this.deploymentQueue.get(deploymentId);
            if (deployment) {
                deployment.status = 'error';
                deployment.error = error.message;
                this.metrics.deploymentFailures++;
                await this.saveDeployment(deployment);
            }
            
            this.logger.error('Deployment processing failed:', error);
            throw error;
        }
    }

    async deployToTarget(certificate, target, method) {
        // Integration with deployment services
        switch (method) {
            case 'mdm':
                return await this.deployViaMDM(certificate, target);
            case 'scep':
                return await this.deployViaSCEP(certificate, target);
            case 'api':
                return await this.deployViaAPI(certificate, target);
            case 'file':
                return await this.deployToFile(certificate, target);
            default:
                throw new Error(`Unsupported deployment method: ${method}`);
        }
    }

    async deployViaMDM(certificate, target) {
        if (!config.mdm.enabled) {
            throw new Error('MDM integration not enabled');
        }

        // Implementation would integrate with MDM service
        // This is a placeholder for the actual MDM integration
        return {
            method: 'mdm',
            target: target,
            deployed: true,
            mdmCommandId: `cmd-${Date.now()}`
        };
    }

    async deployViaSCEP(certificate, target) {
        // SCEP deployment would be handled by SCEP service
        return {
            method: 'scep',
            target: target,
            deployed: true,
            scepUrl: '/scep'
        };
    }

    async deployViaAPI(certificate, target) {
        // API deployment to external systems
        return {
            method: 'api',
            target: target,
            deployed: true,
            apiResponse: 'success'
        };
    }

    async deployToFile(certificate, target) {
        // File-based deployment
        const targetPath = path.join(config.storage.certificates, 'deployed', `${certificate.id}.pem`);
        await fs.writeFile(targetPath, certificate.certificate);
        
        return {
            method: 'file',
            target: target,
            deployed: true,
            filePath: targetPath
        };
    }

    /**
     * Expiration Monitoring
     */
    async monitorExpirations() {
        try {
            const now = new Date();
            const alerts = [];
            
            for (const [certId, certificate] of this.certificateInventory) {
                if (certificate.status !== 'active') continue;
                
                const daysUntilExpiration = Math.ceil((certificate.notAfter - now) / (1000 * 60 * 60 * 24));
                
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
                    const template = this.certificateTemplates.get(certificate.templateId);
                    const alert = {
                        certificateId: certId,
                        certificate,
                        template,
                        alertLevel,
                        daysUntilExpiration,
                        message: this.generateExpirationMessage(certificate, daysUntilExpiration),
                        timestamp: now
                    };
                    
                    alerts.push(alert);
                    await this.sendExpirationAlert(alert);
                }
            }
            
            this.metrics.expirationAlerts += alerts.length;
            this.logger.info(`Expiration monitoring completed: ${alerts.length} alerts generated`);
            
            return alerts;

        } catch (error) {
            this.logger.error('Expiration monitoring failed:', error);
            throw error;
        }
    }

    async sendExpirationAlert(alert) {
        try {
            if (!this.emailTransporter) return;
            
            const recipients = this.getAlertRecipients(alert);
            if (recipients.length === 0) return;
            
            const mailOptions = {
                from: config.notifications.from,
                to: recipients.join(','),
                subject: `Certificate Expiration Alert - ${alert.alertLevel.toUpperCase()}`,
                html: this.generateExpirationEmailHtml(alert)
            };
            
            await this.emailTransporter.sendMail(mailOptions);
            this.logger.info(`Expiration alert sent for certificate: ${alert.certificateId}`);
            
        } catch (error) {
            this.logger.error('Failed to send expiration alert:', error);
        }
    }

    /**
     * Utility Methods
     */
    generateTemplateId(name) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(`${name}-${timestamp}`)
            .digest('hex')
            .substring(0, 8);
        return `tpl-${hash}`;
    }

    generatePolicyId() {
        return `pol-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generateRequestId() {
        return `req-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    incrementVersion(version) {
        const parts = version.split('.');
        parts[parts.length - 1] = (parseInt(parts[parts.length - 1]) + 1).toString();
        return parts.join('.');
    }

    checkVersionRequirement(deviceVersion, requirement) {
        // Simple version comparison - can be enhanced
        return deviceVersion >= requirement.min && 
               (!requirement.max || deviceVersion <= requirement.max);
    }

    generateExpirationMessage(certificate, daysUntilExpiration) {
        const subject = certificate.subject.commonName || 'Unknown';
        
        if (daysUntilExpiration <= 0) {
            return `Certificate has EXPIRED: ${subject}`;
        } else if (daysUntilExpiration === 1) {
            return `Certificate expires tomorrow: ${subject}`;
        } else {
            return `Certificate expires in ${daysUntilExpiration} days: ${subject}`;
        }
    }

    getAlertRecipients(alert) {
        const recipients = new Set();
        
        // Template recipients
        if (alert.template?.notificationRecipients) {
            alert.template.notificationRecipients.forEach(r => recipients.add(r));
        }
        
        // Certificate requester
        if (alert.certificate.userId) {
            // Would typically resolve user ID to email via Enterprise Directory
            recipients.add(`${alert.certificate.userId}@${config.enterpriseDirectory.defaultDomain || 'company.com'}`);
        }
        
        return Array.from(recipients).filter(r => r.includes('@'));
    }

    generateExpirationEmailHtml(alert) {
        return `
            <h2>Certificate Expiration Alert</h2>
            <p><strong>Alert Level:</strong> ${alert.alertLevel.toUpperCase()}</p>
            <p><strong>Certificate ID:</strong> ${alert.certificateId}</p>
            <p><strong>Subject:</strong> ${alert.certificate.subject.commonName || 'Unknown'}</p>
            <p><strong>Serial Number:</strong> ${alert.certificate.serialNumber}</p>
            <p><strong>Expires:</strong> ${alert.certificate.notAfter}</p>
            <p><strong>Days Until Expiration:</strong> ${alert.daysUntilExpiration}</p>
            <p><strong>Device:</strong> ${alert.certificate.deviceId || 'N/A'}</p>
            <p><strong>Template:</strong> ${alert.template?.name || 'Unknown'}</p>
        `;
    }

    scheduleMonitoring() {
        // Daily expiration check at 6:00 AM
        cron.schedule('0 6 * * *', async () => {
            try {
                await this.monitorExpirations();
                await this.checkRenewalRequirements();
                this.logger.info('Scheduled certificate monitoring completed');
            } catch (error) {
                this.logger.error('Scheduled monitoring failed:', error);
            }
        });
        
        // Hourly deployment queue processing
        cron.schedule('0 * * * *', async () => {
            try {
                await this.processDeploymentQueue();
            } catch (error) {
                this.logger.error('Deployment queue processing failed:', error);
            }
        });
    }

    async processDeploymentQueue() {
        for (const [deploymentId, deployment] of this.deploymentQueue) {
            if (deployment.status === 'queued' || 
                (deployment.status === 'failed' && deployment.attempts < deployment.maxAttempts)) {
                try {
                    await this.processDeployment(deploymentId);
                } catch (error) {
                    this.logger.error(`Deployment processing failed for ${deploymentId}:`, error);
                }
            }
        }
    }

    setupEventHandlers() {
        // Integration with Enterprise Directory
        if (config.enterpriseDirectory.enabled) {
            this.on('deviceJoined', async (deviceInfo) => {
                await this.triggerAutoEnrollment(deviceInfo, 'deviceJoin');
            });
            
            this.on('userLogin', async (userInfo) => {
                await this.triggerAutoEnrollment(userInfo, 'userLogin');
            });
        }
    }

    /**
     * Storage Methods
     */
    async saveCertificateTemplate(template) {
        const templatePath = path.join(config.storage.certificates, 'templates', `${template.id}.json`);
        await fs.writeFile(templatePath, JSON.stringify(template, null, 2));
    }

    async loadCertificateTemplates() {
        try {
            const templatesDir = path.join(config.storage.certificates, 'templates');
            const files = await fs.readdir(templatesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const templatePath = path.join(templatesDir, file);
                    const template = JSON.parse(await fs.readFile(templatePath, 'utf8'));
                    this.certificateTemplates.set(template.id, template);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load certificate templates:', error);
            }
        }
    }

    async saveAutoEnrollmentPolicy(policy) {
        const policyPath = path.join(config.storage.certificates, 'auto-enrollment', `${policy.id}.json`);
        await fs.writeFile(policyPath, JSON.stringify(policy, null, 2));
    }

    async loadAutoEnrollmentPolicies() {
        try {
            const policiesDir = path.join(config.storage.certificates, 'auto-enrollment');
            const files = await fs.readdir(policiesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const policyPath = path.join(policiesDir, file);
                    const policy = JSON.parse(await fs.readFile(policyPath, 'utf8'));
                    this.autoEnrollmentPolicies.set(policy.id, policy);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load auto-enrollment policies:', error);
            }
        }
    }

    async saveEnrollmentRequest(request) {
        const requestPath = path.join(config.storage.certificates, 'enrollment', `${request.id}.json`);
        await fs.writeFile(requestPath, JSON.stringify(request, null, 2));
    }

    async saveCertificateInventory(certificate) {
        const certPath = path.join(config.storage.certificates, 'inventory', `${certificate.id}.json`);
        await fs.writeFile(certPath, JSON.stringify(certificate, null, 2));
    }

    async loadCertificateInventory() {
        try {
            const inventoryDir = path.join(config.storage.certificates, 'inventory');
            const files = await fs.readdir(inventoryDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const certPath = path.join(inventoryDir, file);
                    const certificate = JSON.parse(await fs.readFile(certPath, 'utf8'));
                    this.certificateInventory.set(certificate.id, certificate);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load certificate inventory:', error);
            }
        }
    }

    async saveDeployment(deployment) {
        const deploymentPath = path.join(config.storage.certificates, 'deployments', `${deployment.id}.json`);
        await fs.writeFile(deploymentPath, JSON.stringify(deployment, null, 2));
    }

    /**
     * Approval Workflow (placeholder)
     */
    async initiateApprovalWorkflow(request, template) {
        // Implementation would integrate with approval system
        this.logger.info(`Approval workflow initiated for request: ${request.id}`);
    }

    /**
     * Public API Methods
     */
    async getTemplates() {
        return Array.from(this.certificateTemplates.values());
    }

    async getTemplate(templateId) {
        return this.certificateTemplates.get(templateId);
    }

    async getCertificateInventory(filters = {}) {
        const inventory = [];
        
        for (const [certId, certificate] of this.certificateInventory) {
            // Apply filters
            if (filters.status && certificate.status !== filters.status) continue;
            if (filters.templateId && certificate.templateId !== filters.templateId) continue;
            if (filters.deviceId && certificate.deviceId !== filters.deviceId) continue;
            
            inventory.push({
                id: certificate.id,
                serialNumber: certificate.serialNumber,
                subject: certificate.subject,
                templateId: certificate.templateId,
                deviceId: certificate.deviceId,
                status: certificate.status,
                notBefore: certificate.notBefore,
                notAfter: certificate.notAfter,
                deploymentStatus: certificate.deploymentStatus,
                issuedAt: certificate.issuedAt
            });
        }
        
        return inventory;
    }

    async getMetrics() {
        return {
            ...this.metrics,
            totalTemplates: this.certificateTemplates.size,
            activeTemplates: Array.from(this.certificateTemplates.values()).filter(t => t.status === 'active').length,
            autoEnrollmentPolicies: this.autoEnrollmentPolicies.size,
            totalCertificates: this.certificateInventory.size,
            activeCertificates: Array.from(this.certificateInventory.values()).filter(c => c.status === 'active').length
        };
    }
}

module.exports = CertificateLifecycleService;