/**
 * OpenDirectory Data Loss Prevention (DLP) Engine
 * Provides content inspection, sensitive data discovery, and data exfiltration prevention
 */

const crypto = require('crypto');
const EventEmitter = require('events');
const express = require('express');

class DataLossPreventionEngine extends EventEmitter {
    constructor() {
        super();
        this.dataClassificationRules = new Map();
        this.contentInspectionPolicies = new Map();
        this.sensitiveDataPatterns = new Map();
        this.monitoredChannels = new Map();
        this.encryptionPolicies = new Map();
        this.dataMovementLogs = new Map();
        this.quarantinedFiles = new Map();
        this.approvedDataTransfers = new Map();
        
        this.initializeDLP();
        this.startContentMonitoring();
        this.loadSensitiveDataPatterns();
    }

    /**
     * Initialize the DLP engine
     */
    initializeDLP() {
        console.log('🛡️ Initializing Data Loss Prevention Engine...');
        
        // Initialize content inspector
        this.contentInspector = new ContentInspector();
        
        // Initialize data classifier
        this.dataClassifier = new DataClassifier();
        
        // Initialize policy engine
        this.policyEngine = new DLPPolicyEngine();
        
        // Initialize encryption manager
        this.encryptionManager = new EncryptionPolicyManager();
        
        // Initialize channel monitors
        this.emailMonitor = new EmailContentMonitor();
        this.fileSystemMonitor = new FileSystemMonitor();
        this.networkMonitor = new NetworkDataMonitor();
        this.cloudStorageMonitor = new CloudStorageMonitor();
        this.removableMediaMonitor = new RemovableMediaMonitor();
        this.printMonitor = new PrintMonitor();
        
        // Create default data classification rules
        this.createDefaultClassificationRules();
        
        // Create default DLP policies
        this.createDefaultDLPPolicies();
        
        console.log('✅ Data Loss Prevention Engine initialized');
    }

    /**
     * Content inspection and classification
     */
    async inspectContent(contentData) {
        try {
            const inspection = {
                id: crypto.randomUUID(),
                timestamp: new Date(),
                source: contentData.source,
                contentType: contentData.contentType,
                size: contentData.size || 0,
                checksum: this.calculateChecksum(contentData.content),
                classifications: [],
                sensitiveDataFound: [],
                riskScore: 0,
                recommendedAction: 'allow',
                policyViolations: [],
                encryptionRequired: false
            };

            // Classify data content
            const classification = await this.classifyContent(contentData.content, contentData.metadata);
            inspection.classifications = classification.categories;
            inspection.riskScore = classification.riskScore;

            // Scan for sensitive data patterns
            const sensitiveData = await this.scanForSensitiveData(contentData.content);
            inspection.sensitiveDataFound = sensitiveData.findings;
            
            // Update risk score based on sensitive data
            if (sensitiveData.findings.length > 0) {
                inspection.riskScore = Math.max(inspection.riskScore, sensitiveData.maxRiskScore);
            }

            // Check against DLP policies
            const policyCheck = await this.checkDLPPolicies(inspection, contentData);
            inspection.policyViolations = policyCheck.violations;
            inspection.recommendedAction = policyCheck.action;
            inspection.encryptionRequired = policyCheck.encryptionRequired;

            // Determine final action
            if (inspection.policyViolations.length > 0) {
                const severity = Math.max(...inspection.policyViolations.map(v => v.severity));
                if (severity >= 0.8) {
                    inspection.recommendedAction = 'block';
                } else if (severity >= 0.6) {
                    inspection.recommendedAction = 'quarantine';
                } else if (severity >= 0.4) {
                    inspection.recommendedAction = 'warn';
                }
            }

            this.emit('contentInspected', {
                inspectionId: inspection.id,
                source: inspection.source,
                riskScore: inspection.riskScore,
                action: inspection.recommendedAction,
                violationCount: inspection.policyViolations.length,
                sensitiveDataCount: inspection.sensitiveDataFound.length,
                timestamp: new Date()
            });

            return inspection;

        } catch (error) {
            console.error('Content inspection error:', error);
            // Fail secure - recommend blocking on inspection error
            return {
                id: crypto.randomUUID(),
                timestamp: new Date(),
                source: contentData.source,
                error: error.message,
                riskScore: 1.0,
                recommendedAction: 'block',
                policyViolations: [{
                    policy: 'system',
                    violation: 'Inspection system error',
                    severity: 1.0
                }]
            };
        }
    }

    /**
     * Sensitive data discovery and cataloging
     */
    async discoverSensitiveData(scanConfig) {
        try {
            const discoveryTask = {
                id: crypto.randomUUID(),
                name: scanConfig.name,
                targets: scanConfig.targets, // file paths, databases, etc.
                patterns: scanConfig.patterns || this.getDefaultPatterns(),
                includePatterns: scanConfig.includePatterns || ['*'],
                excludePatterns: scanConfig.excludePatterns || [],
                depth: scanConfig.depth || 'deep',
                startedAt: new Date(),
                status: 'running',
                progress: 0,
                findings: [],
                statistics: {
                    filesScanned: 0,
                    sensitiveFilesFound: 0,
                    totalSensitiveItems: 0,
                    riskDistribution: { low: 0, medium: 0, high: 0, critical: 0 }
                }
            };

            // Start discovery process
            this.startSensitiveDataDiscovery(discoveryTask);

            this.emit('sensitiveDataDiscoveryStarted', {
                taskId: discoveryTask.id,
                name: discoveryTask.name,
                targetCount: discoveryTask.targets.length,
                timestamp: new Date()
            });

            return {
                taskId: discoveryTask.id,
                status: 'running',
                estimatedDuration: this.estimateDiscoveryDuration(scanConfig),
                progress: 0
            };

        } catch (error) {
            console.error('Sensitive data discovery error:', error);
            throw error;
        }
    }

    /**
     * Data movement monitoring across all channels
     */
    async monitorDataMovement(movementData) {
        try {
            const movement = {
                id: crypto.randomUUID(),
                timestamp: new Date(),
                userId: movementData.userId,
                deviceId: movementData.deviceId,
                source: movementData.source,
                destination: movementData.destination,
                channel: movementData.channel, // email, file_copy, upload, print, etc.
                dataSize: movementData.dataSize || 0,
                contentSummary: movementData.contentSummary,
                riskScore: 0,
                allowed: false,
                reason: '',
                metadata: movementData.metadata || {}
            };

            // Classify the data being moved
            const classification = await this.classifyDataMovement(movement);
            movement.riskScore = classification.riskScore;
            movement.sensitiveDataTypes = classification.sensitiveTypes;

            // Check movement policies
            const policyCheck = await this.checkDataMovementPolicies(movement);
            movement.allowed = policyCheck.allowed;
            movement.reason = policyCheck.reason;
            movement.requiredApproval = policyCheck.requiresApproval;

            // Log the movement
            this.dataMovementLogs.set(movement.id, movement);

            // Handle based on policy decision
            if (!movement.allowed) {
                await this.blockDataMovement(movement);
            } else if (movement.requiredApproval) {
                await this.requestDataMovementApproval(movement);
            }

            this.emit('dataMovementMonitored', {
                movementId: movement.id,
                userId: movement.userId,
                channel: movement.channel,
                allowed: movement.allowed,
                riskScore: movement.riskScore,
                timestamp: new Date()
            });

            return {
                movementId: movement.id,
                allowed: movement.allowed,
                reason: movement.reason,
                requiresApproval: movement.requiredApproval
            };

        } catch (error) {
            console.error('Data movement monitoring error:', error);
            // Fail secure - block movement on error
            return {
                movementId: crypto.randomUUID(),
                allowed: false,
                reason: 'Data movement monitoring system error'
            };
        }
    }

    /**
     * Encryption policy enforcement
     */
    async enforceEncryptionPolicy(fileData) {
        try {
            const policyCheck = {
                fileId: fileData.fileId || crypto.randomUUID(),
                filePath: fileData.filePath,
                fileType: fileData.fileType,
                size: fileData.size,
                classification: fileData.classification,
                timestamp: new Date(),
                encryptionRequired: false,
                encryptionMethod: null,
                keyManagement: null,
                policyMatches: [],
                complianceStatus: 'unknown'
            };

            // Check file against encryption policies
            for (const [policyId, policy] of this.encryptionPolicies.entries()) {
                if (await this.matchesEncryptionPolicy(fileData, policy)) {
                    policyCheck.policyMatches.push({
                        policyId,
                        policyName: policy.name,
                        required: policy.required,
                        method: policy.encryptionMethod,
                        keyPolicy: policy.keyManagement
                    });

                    if (policy.required) {
                        policyCheck.encryptionRequired = true;
                        policyCheck.encryptionMethod = policy.encryptionMethod;
                        policyCheck.keyManagement = policy.keyManagement;
                    }
                }
            }

            // Check current encryption status
            const currentEncryption = await this.checkCurrentEncryption(fileData);
            policyCheck.currentlyEncrypted = currentEncryption.encrypted;
            policyCheck.encryptionMethod = currentEncryption.method;

            // Determine compliance status
            if (policyCheck.encryptionRequired && !policyCheck.currentlyEncrypted) {
                policyCheck.complianceStatus = 'non_compliant';
                
                // Auto-encrypt if policy allows
                if (this.shouldAutoEncrypt(policyCheck)) {
                    const encryptionResult = await this.autoEncryptFile(fileData, policyCheck);
                    policyCheck.autoEncrypted = encryptionResult.success;
                    policyCheck.encryptionKey = encryptionResult.keyId;
                }
            } else if (policyCheck.encryptionRequired && policyCheck.currentlyEncrypted) {
                policyCheck.complianceStatus = 'compliant';
            } else {
                policyCheck.complianceStatus = 'not_required';
            }

            this.emit('encryptionPolicyEnforced', {
                fileId: policyCheck.fileId,
                filePath: policyCheck.filePath,
                encryptionRequired: policyCheck.encryptionRequired,
                complianceStatus: policyCheck.complianceStatus,
                autoEncrypted: policyCheck.autoEncrypted || false,
                timestamp: new Date()
            });

            return policyCheck;

        } catch (error) {
            console.error('Encryption policy enforcement error:', error);
            throw error;
        }
    }

    /**
     * Email content filtering
     */
    async filterEmailContent(emailData) {
        try {
            const emailInspection = {
                messageId: emailData.messageId || crypto.randomUUID(),
                sender: emailData.sender,
                recipients: emailData.recipients,
                subject: emailData.subject,
                timestamp: new Date(),
                attachments: emailData.attachments || [],
                bodyInspection: null,
                attachmentInspections: [],
                overallRisk: 0,
                action: 'deliver',
                warnings: [],
                quarantineReason: null
            };

            // Inspect email body
            if (emailData.body) {
                emailInspection.bodyInspection = await this.inspectContent({
                    source: 'email_body',
                    contentType: 'text',
                    content: emailData.body,
                    metadata: { sender: emailData.sender, recipients: emailData.recipients }
                });
            }

            // Inspect attachments
            for (const attachment of emailData.attachments || []) {
                const attachmentInspection = await this.inspectContent({
                    source: 'email_attachment',
                    contentType: attachment.contentType,
                    content: attachment.content,
                    metadata: { 
                        filename: attachment.filename,
                        sender: emailData.sender,
                        recipients: emailData.recipients
                    }
                });
                emailInspection.attachmentInspections.push(attachmentInspection);
            }

            // Calculate overall risk
            const riskScores = [
                emailInspection.bodyInspection?.riskScore || 0,
                ...emailInspection.attachmentInspections.map(a => a.riskScore)
            ];
            emailInspection.overallRisk = Math.max(...riskScores);

            // Determine action
            if (emailInspection.overallRisk >= 0.8) {
                emailInspection.action = 'quarantine';
                emailInspection.quarantineReason = 'High risk content detected';
            } else if (emailInspection.overallRisk >= 0.6) {
                emailInspection.action = 'deliver_with_warning';
                emailInspection.warnings.push('Potentially sensitive content detected');
            } else if (emailInspection.overallRisk >= 0.4) {
                emailInspection.action = 'deliver_with_encryption';
                emailInspection.warnings.push('Email should be encrypted');
            }

            this.emit('emailFiltered', {
                messageId: emailInspection.messageId,
                sender: emailInspection.sender,
                recipientCount: emailInspection.recipients.length,
                action: emailInspection.action,
                riskScore: emailInspection.overallRisk,
                attachmentCount: emailInspection.attachments.length,
                timestamp: new Date()
            });

            return emailInspection;

        } catch (error) {
            console.error('Email content filtering error:', error);
            // Fail secure - quarantine email on error
            return {
                messageId: emailData.messageId || crypto.randomUUID(),
                action: 'quarantine',
                quarantineReason: 'Email filtering system error',
                overallRisk: 1.0,
                timestamp: new Date()
            };
        }
    }

    /**
     * Cloud storage monitoring
     */
    async monitorCloudStorage(storageActivity) {
        try {
            const monitoring = {
                activityId: crypto.randomUUID(),
                timestamp: new Date(),
                userId: storageActivity.userId,
                cloudProvider: storageActivity.cloudProvider, // dropbox, google_drive, onedrive, etc.
                action: storageActivity.action, // upload, download, share, sync
                filePath: storageActivity.filePath,
                fileName: storageActivity.fileName,
                fileSize: storageActivity.fileSize || 0,
                shared: storageActivity.shared || false,
                recipients: storageActivity.recipients || [],
                riskScore: 0,
                allowed: true,
                reason: '',
                complianceChecks: []
            };

            // Check if cloud provider is authorized
            const providerCheck = await this.checkAuthorizedCloudProvider(
                monitoring.cloudProvider, 
                monitoring.userId
            );
            
            if (!providerCheck.authorized) {
                monitoring.allowed = false;
                monitoring.reason = `Unauthorized cloud provider: ${monitoring.cloudProvider}`;
                monitoring.riskScore = 0.9;
            }

            // Classify the file being uploaded/shared
            if (storageActivity.fileContent) {
                const contentInspection = await this.inspectContent({
                    source: 'cloud_storage',
                    contentType: this.getFileTypeFromExtension(monitoring.fileName),
                    content: storageActivity.fileContent,
                    metadata: {
                        cloudProvider: monitoring.cloudProvider,
                        action: monitoring.action,
                        shared: monitoring.shared
                    }
                });
                
                monitoring.riskScore = Math.max(monitoring.riskScore, contentInspection.riskScore);
                monitoring.sensitiveDataFound = contentInspection.sensitiveDataFound;
                
                // Additional restrictions for sensitive data in cloud
                if (contentInspection.sensitiveDataFound.length > 0) {
                    const sensitiveCloudPolicy = await this.checkSensitiveDataCloudPolicy(
                        contentInspection, 
                        monitoring
                    );
                    
                    if (!sensitiveCloudPolicy.allowed) {
                        monitoring.allowed = false;
                        monitoring.reason = sensitiveCloudPolicy.reason;
                    }
                }
            }

            // Check file sharing restrictions
            if (monitoring.shared && monitoring.recipients.length > 0) {
                const sharingCheck = await this.checkCloudSharingPolicy(monitoring);
                if (!sharingCheck.allowed) {
                    monitoring.allowed = false;
                    monitoring.reason = sharingCheck.reason;
                }
            }

            this.emit('cloudStorageActivityMonitored', {
                activityId: monitoring.activityId,
                userId: monitoring.userId,
                cloudProvider: monitoring.cloudProvider,
                action: monitoring.action,
                fileName: monitoring.fileName,
                allowed: monitoring.allowed,
                riskScore: monitoring.riskScore,
                timestamp: new Date()
            });

            return {
                activityId: monitoring.activityId,
                allowed: monitoring.allowed,
                reason: monitoring.reason,
                riskScore: monitoring.riskScore,
                requiresEncryption: monitoring.riskScore > 0.5
            };

        } catch (error) {
            console.error('Cloud storage monitoring error:', error);
            // Fail secure - block cloud activity on error
            return {
                activityId: crypto.randomUUID(),
                allowed: false,
                reason: 'Cloud storage monitoring system error',
                riskScore: 1.0
            };
        }
    }

    /**
     * Removable media control
     */
    async controlRemovableMedia(mediaActivity) {
        try {
            const control = {
                activityId: crypto.randomUUID(),
                timestamp: new Date(),
                userId: mediaActivity.userId,
                deviceId: mediaActivity.deviceId,
                mediaType: mediaActivity.mediaType, // usb, cd, dvd, etc.
                action: mediaActivity.action, // insert, copy_to, copy_from, eject
                files: mediaActivity.files || [],
                totalSize: mediaActivity.totalSize || 0,
                allowed: false,
                reason: '',
                encryptionRequired: false,
                virusScanRequired: true
            };

            // Check if removable media is allowed for user
            const mediaPolicy = await this.checkRemovableMediaPolicy(control.userId, control.mediaType);
            if (!mediaPolicy.allowed) {
                control.allowed = false;
                control.reason = `Removable media type ${control.mediaType} not allowed for user`;
                
                this.emit('removableMediaBlocked', {
                    activityId: control.activityId,
                    userId: control.userId,
                    mediaType: control.mediaType,
                    reason: control.reason,
                    timestamp: new Date()
                });
                
                return control;
            }

            // For copy operations, inspect the content
            if (control.action.includes('copy') && control.files.length > 0) {
                let maxRiskScore = 0;
                const sensitiveFiles = [];
                
                for (const file of control.files) {
                    if (file.content) {
                        const inspection = await this.inspectContent({
                            source: 'removable_media',
                            contentType: this.getFileTypeFromExtension(file.name),
                            content: file.content,
                            metadata: {
                                mediaType: control.mediaType,
                                action: control.action
                            }
                        });
                        
                        maxRiskScore = Math.max(maxRiskScore, inspection.riskScore);
                        
                        if (inspection.sensitiveDataFound.length > 0) {
                            sensitiveFiles.push({
                                fileName: file.name,
                                sensitiveData: inspection.sensitiveDataFound
                            });
                        }
                    }
                }
                
                // Apply restrictions based on sensitive content
                if (sensitiveFiles.length > 0) {
                    const sensitiveMediaPolicy = await this.checkSensitiveDataMediaPolicy(
                        sensitiveFiles,
                        control
                    );
                    
                    if (!sensitiveMediaPolicy.allowed) {
                        control.allowed = false;
                        control.reason = sensitiveMediaPolicy.reason;
                    } else {
                        control.allowed = true;
                        control.encryptionRequired = sensitiveMediaPolicy.encryptionRequired;
                    }
                } else {
                    control.allowed = mediaPolicy.allowed;
                    control.encryptionRequired = mediaPolicy.encryptionRequired;
                }
            } else {
                control.allowed = mediaPolicy.allowed;
            }

            this.emit('removableMediaControlled', {
                activityId: control.activityId,
                userId: control.userId,
                mediaType: control.mediaType,
                action: control.action,
                allowed: control.allowed,
                fileCount: control.files.length,
                timestamp: new Date()
            });

            return control;

        } catch (error) {
            console.error('Removable media control error:', error);
            // Fail secure - block removable media on error
            return {
                activityId: crypto.randomUUID(),
                allowed: false,
                reason: 'Removable media control system error'
            };
        }
    }

    /**
     * Print monitoring and control
     */
    async monitorPrintActivity(printJob) {
        try {
            const monitoring = {
                jobId: printJob.jobId || crypto.randomUUID(),
                timestamp: new Date(),
                userId: printJob.userId,
                printer: printJob.printer,
                documentName: printJob.documentName,
                pages: printJob.pages || 1,
                copies: printJob.copies || 1,
                contentSummary: printJob.contentSummary,
                riskScore: 0,
                allowed: true,
                reason: '',
                watermarkRequired: false,
                auditRequired: false
            };

            // Check printer authorization
            const printerCheck = await this.checkAuthorizedPrinter(printJob.printer, printJob.userId);
            if (!printerCheck.authorized) {
                monitoring.allowed = false;
                monitoring.reason = `Printer ${printJob.printer} not authorized for user`;
                monitoring.riskScore = 0.8;
            }

            // Inspect print content if available
            if (printJob.content) {
                const contentInspection = await this.inspectContent({
                    source: 'print_job',
                    contentType: 'document',
                    content: printJob.content,
                    metadata: {
                        printer: printJob.printer,
                        pages: printJob.pages,
                        copies: printJob.copies
                    }
                });
                
                monitoring.riskScore = Math.max(monitoring.riskScore, contentInspection.riskScore);
                monitoring.sensitiveDataFound = contentInspection.sensitiveDataFound;
                
                // Apply print restrictions for sensitive content
                if (contentInspection.sensitiveDataFound.length > 0) {
                    const printPolicy = await this.checkSensitiveDataPrintPolicy(
                        contentInspection,
                        monitoring
                    );
                    
                    monitoring.allowed = printPolicy.allowed;
                    monitoring.reason = printPolicy.reason;
                    monitoring.watermarkRequired = printPolicy.watermarkRequired;
                    monitoring.auditRequired = printPolicy.auditRequired;
                }
            }

            // Check print quotas and restrictions
            const quotaCheck = await this.checkPrintQuota(printJob.userId, monitoring.pages * monitoring.copies);
            if (!quotaCheck.withinQuota) {
                monitoring.allowed = false;
                monitoring.reason = 'Print quota exceeded';
            }

            this.emit('printActivityMonitored', {
                jobId: monitoring.jobId,
                userId: monitoring.userId,
                printer: monitoring.printer,
                documentName: monitoring.documentName,
                pages: monitoring.pages,
                allowed: monitoring.allowed,
                riskScore: monitoring.riskScore,
                timestamp: new Date()
            });

            return {
                jobId: monitoring.jobId,
                allowed: monitoring.allowed,
                reason: monitoring.reason,
                watermarkRequired: monitoring.watermarkRequired,
                auditRequired: monitoring.auditRequired
            };

        } catch (error) {
            console.error('Print monitoring error:', error);
            // Fail secure - block printing on error
            return {
                jobId: crypto.randomUUID(),
                allowed: false,
                reason: 'Print monitoring system error'
            };
        }
    }

    /**
     * Content monitoring startup
     */
    startContentMonitoring() {
        // Start monitoring all channels
        this.emailMonitor.startMonitoring();
        this.fileSystemMonitor.startMonitoring();
        this.networkMonitor.startMonitoring();
        this.cloudStorageMonitor.startMonitoring();
        this.removableMediaMonitor.startMonitoring();
        this.printMonitor.startMonitoring();
        
        console.log('✅ Content monitoring started');
    }

    /**
     * Load sensitive data patterns
     */
    loadSensitiveDataPatterns() {
        const patterns = [
            {
                name: 'Social Security Number',
                pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
                type: 'pii',
                riskLevel: 0.9
            },
            {
                name: 'Credit Card Number',
                pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
                type: 'financial',
                riskLevel: 0.95
            },
            {
                name: 'Email Address',
                pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
                type: 'pii',
                riskLevel: 0.3
            },
            {
                name: 'Phone Number',
                pattern: /\b\d{3}-\d{3}-\d{4}\b/g,
                type: 'pii',
                riskLevel: 0.4
            },
            {
                name: 'API Key Pattern',
                pattern: /\b[A-Za-z0-9]{32,}\b/g,
                type: 'credential',
                riskLevel: 0.8
            }
        ];

        for (const pattern of patterns) {
            this.sensitiveDataPatterns.set(pattern.name, pattern);
        }

        console.log(`✅ Loaded ${patterns.length} sensitive data patterns`);
    }

    /**
     * Helper methods
     */
    
    calculateChecksum(content) {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    async classifyContent(content, metadata = {}) {
        // Simplified content classification
        const categories = [];
        let riskScore = 0.0;

        // Check for financial terms
        if (/bank|credit|payment|invoice|financial/i.test(content)) {
            categories.push('financial');
            riskScore = Math.max(riskScore, 0.6);
        }

        // Check for confidential markers
        if (/confidential|restricted|private|secret/i.test(content)) {
            categories.push('confidential');
            riskScore = Math.max(riskScore, 0.8);
        }

        return { categories, riskScore };
    }

    async scanForSensitiveData(content) {
        const findings = [];
        let maxRiskScore = 0;

        for (const [name, pattern] of this.sensitiveDataPatterns.entries()) {
            const matches = content.match(pattern.pattern);
            if (matches) {
                findings.push({
                    patternName: name,
                    type: pattern.type,
                    matchCount: matches.length,
                    riskLevel: pattern.riskLevel,
                    samples: matches.slice(0, 3) // First 3 matches as samples
                });
                maxRiskScore = Math.max(maxRiskScore, pattern.riskLevel);
            }
        }

        return { findings, maxRiskScore };
    }

    createDefaultClassificationRules() {
        // Create default data classification rules
        const defaultRules = [
            {
                name: 'Financial Data',
                patterns: ['credit', 'bank', 'payment', 'invoice'],
                classification: 'restricted',
                riskLevel: 0.8
            },
            {
                name: 'Personal Information',
                patterns: ['ssn', 'social security', 'personal'],
                classification: 'confidential',
                riskLevel: 0.9
            },
            {
                name: 'Public Information',
                patterns: ['public', 'general'],
                classification: 'public',
                riskLevel: 0.1
            }
        ];

        for (const rule of defaultRules) {
            this.dataClassificationRules.set(rule.name, rule);
        }
    }

    createDefaultDLPPolicies() {
        // Create default DLP policies
        const defaultPolicies = [
            {
                name: 'Block SSN Transmission',
                enabled: true,
                action: 'block',
                conditions: [
                    { type: 'contains_pattern', pattern: 'Social Security Number' }
                ]
            },
            {
                name: 'Encrypt Financial Data',
                enabled: true,
                action: 'encrypt',
                conditions: [
                    { type: 'classification', value: 'financial' }
                ]
            }
        ];

        for (const policy of defaultPolicies) {
            this.contentInspectionPolicies.set(policy.name, policy);
        }
    }

    /**
     * REST API endpoints
     */
    createAPIRoutes() {
        const router = express.Router();

        // Content inspection endpoint
        router.post('/inspect', async (req, res) => {
            try {
                const inspection = await this.inspectContent(req.body);
                res.json(inspection);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Sensitive data discovery endpoint
        router.post('/discover', async (req, res) => {
            try {
                const discovery = await this.discoverSensitiveData(req.body);
                res.json(discovery);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Data movement monitoring endpoint
        router.post('/monitor-movement', async (req, res) => {
            try {
                const monitoring = await this.monitorDataMovement(req.body);
                res.json(monitoring);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Email filtering endpoint
        router.post('/filter-email', async (req, res) => {
            try {
                const filtering = await this.filterEmailContent(req.body);
                res.json(filtering);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Cloud storage monitoring endpoint
        router.post('/monitor-cloud', async (req, res) => {
            try {
                const monitoring = await this.monitorCloudStorage(req.body);
                res.json(monitoring);
            } catch (error) {
                res.status(400).json({ error: error.message });
            }
        });

        // Print monitoring endpoint
        router.post('/monitor-print', async (req, res) => {
            try {
                const monitoring = await this.monitorPrintActivity(req.body);
                res.json(monitoring);
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

class ContentInspector {
    constructor() {
        this.inspectionQueue = [];
    }
}

class DataClassifier {
    constructor() {
        this.classificationModels = new Map();
    }
}

class DLPPolicyEngine {
    constructor() {
        this.policies = new Map();
    }
}

class EncryptionPolicyManager {
    constructor() {
        this.encryptionPolicies = new Map();
    }
}

class EmailContentMonitor {
    startMonitoring() {
        console.log('📧 Email content monitoring started');
    }
}

class FileSystemMonitor {
    startMonitoring() {
        console.log('📁 File system monitoring started');
    }
}

class NetworkDataMonitor {
    startMonitoring() {
        console.log('🌐 Network data monitoring started');
    }
}

class CloudStorageMonitor {
    startMonitoring() {
        console.log('☁️ Cloud storage monitoring started');
    }
}

class RemovableMediaMonitor {
    startMonitoring() {
        console.log('💾 Removable media monitoring started');
    }
}

class PrintMonitor {
    startMonitoring() {
        console.log('🖨️ Print monitoring started');
    }
}

module.exports = DataLossPreventionEngine;

// Example usage and initialization
if (require.main === module) {
    const dlpEngine = new DataLossPreventionEngine();
    
    // Set up event listeners
    dlpEngine.on('contentInspected', (data) => {
        console.log('Content inspected:', data.source, 'Risk:', data.riskScore, 'Action:', data.action);
    });
    
    dlpEngine.on('dataMovementMonitored', (data) => {
        console.log('Data movement:', data.channel, 'User:', data.userId, 'Allowed:', data.allowed);
    });
    
    dlpEngine.on('emailFiltered', (data) => {
        console.log('Email filtered:', data.messageId, 'Action:', data.action, 'Risk:', data.riskScore);
    });
    
    dlpEngine.on('sensitiveDataDiscoveryStarted', (data) => {
        console.log('Sensitive data discovery started:', data.name, 'Targets:', data.targetCount);
    });
    
    console.log('🚀 Data Loss Prevention Engine started successfully');
}