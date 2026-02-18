/**
 * OpenDirectory Self-Service Automation Portal Backend
 * Automated self-service workflows for common user tasks
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class SelfServiceBackend extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            requestTimeout: 300000, // 5 minutes
            maxPendingRequests: 1000,
            approvalTimeout: 86400000, // 24 hours
            passwordComplexity: {
                minLength: 8,
                requireUppercase: true,
                requireLowercase: true,
                requireNumbers: true,
                requireSpecialChars: true
            },
            storageDir: config.storageDir || '/tmp/self-service',
            ...config
        };
        
        this.pendingRequests = new Map();
        this.approvalChains = new Map();
        this.requestTemplates = new Map();
        this.automationRules = new Map();
        this.certificateRequests = new Map();
        this.deviceEnrollments = new Map();
        this.requestStats = {
            total: 0,
            approved: 0,
            rejected: 0,
            automated: 0,
            pending: 0
        };
        
        this.init();
    }
    
    async init() {
        await this.ensureStorageDir();
        await this.loadRequestTemplates();
        this.setupBuiltinTemplates();
        this.startRequestProcessor();
        this.startApprovalTimeoutChecker();
        
        this.emit('backend:ready');
        console.log('Self-Service Backend initialized successfully');
    }
    
    async ensureStorageDir() {
        try {
            await fs.mkdir(this.config.storageDir, { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'requests'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'approvals'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'templates'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'certificates'), { recursive: true });
        } catch (error) {
            console.error('Failed to create storage directories:', error);
        }
    }
    
    setupBuiltinTemplates() {
        // Password Reset Template
        this.requestTemplates.set('password_reset', {
            id: 'password_reset',
            name: 'Password Reset Request',
            description: 'Automated password reset workflow',
            category: 'security',
            requiresApproval: false,
            autoApprove: true,
            steps: [
                {
                    id: 'validate_user',
                    type: 'validation',
                    action: 'verify_user_exists'
                },
                {
                    id: 'security_check',
                    type: 'security',
                    action: 'check_recent_resets'
                },
                {
                    id: 'generate_password',
                    type: 'password',
                    action: 'generate_secure_password'
                },
                {
                    id: 'update_ldap',
                    type: 'ldap',
                    action: 'update_user_password'
                },
                {
                    id: 'notify_user',
                    type: 'notification',
                    action: 'send_password_notification'
                }
            ]
        });
        
        // Application Access Template
        this.requestTemplates.set('application_access', {
            id: 'application_access',
            name: 'Application Access Request',
            description: 'Request access to applications',
            category: 'access',
            requiresApproval: true,
            approvalChain: ['manager', 'application_owner'],
            steps: [
                {
                    id: 'validate_request',
                    type: 'validation',
                    action: 'validate_access_request'
                },
                {
                    id: 'check_entitlements',
                    type: 'authorization',
                    action: 'check_existing_access'
                },
                {
                    id: 'create_access',
                    type: 'provisioning',
                    action: 'grant_application_access'
                },
                {
                    id: 'notify_completion',
                    type: 'notification',
                    action: 'notify_access_granted'
                }
            ]
        });
        
        // Device Enrollment Template
        this.requestTemplates.set('device_enrollment', {
            id: 'device_enrollment',
            name: 'Device Enrollment Request',
            description: 'Enroll new device in MDM',
            category: 'device',
            requiresApproval: false,
            autoApprove: true,
            steps: [
                {
                    id: 'validate_device',
                    type: 'validation',
                    action: 'validate_device_info'
                },
                {
                    id: 'generate_profile',
                    type: 'mdm',
                    action: 'generate_enrollment_profile'
                },
                {
                    id: 'send_profile',
                    type: 'delivery',
                    action: 'deliver_enrollment_profile'
                }
            ]
        });
    }
    
    // Password Reset Automation
    async requestPasswordReset(userId, requestedBy, options = {}) {
        const requestId = this.generateId();
        const request = {
            id: requestId,
            type: 'password_reset',
            userId,
            requestedBy,
            status: 'pending',
            data: {
                reason: options.reason || 'Self-service password reset',
                deliveryMethod: options.deliveryMethod || 'email',
                temporaryPassword: options.temporaryPassword || false
            },
            timestamp: new Date().toISOString(),
            metadata: {
                ipAddress: options.ipAddress,
                userAgent: options.userAgent,
                source: 'self_service'
            }
        };
        
        this.pendingRequests.set(requestId, request);
        this.requestStats.total++;
        this.requestStats.pending++;
        
        // Start processing
        await this.processPasswordReset(request);
        
        return { requestId, status: request.status };
    }
    
    async processPasswordReset(request) {
        try {
            // Step 1: Validate user exists
            const userExists = await this.validateUserExists(request.userId);
            if (!userExists) {
                return await this.rejectRequest(request.id, 'User not found');
            }
            
            // Step 2: Security checks
            const securityCheck = await this.performSecurityChecks(request);
            if (!securityCheck.passed) {
                return await this.rejectRequest(request.id, securityCheck.reason);
            }
            
            // Step 3: Generate new password
            const newPassword = this.generateSecurePassword();
            request.data.newPassword = newPassword;
            
            // Step 4: Update password in LDAP
            await this.updateUserPassword(request.userId, newPassword);
            
            // Step 5: Send notification
            await this.sendPasswordNotification(request);
            
            // Mark as completed
            request.status = 'completed';
            request.completedAt = new Date().toISOString();
            
            this.requestStats.pending--;
            this.requestStats.automated++;
            
            this.emit('password_reset:completed', {
                requestId: request.id,
                userId: request.userId,
                requestedBy: request.requestedBy
            });
            
            await this.saveRequest(request);
            
        } catch (error) {
            await this.failRequest(request.id, error.message);
        }
    }
    
    async validateUserExists(userId) {
        // Mock LDAP user validation
        this.emit('ldap:search', {
            filter: `(uid=${userId})`,
            scope: 'subtree'
        });
        
        // Simulate validation result
        return true; // In real implementation, this would query LDAP
    }
    
    async performSecurityChecks(request) {
        const checks = [];
        
        // Check for recent password resets
        const recentReset = await this.checkRecentPasswordReset(request.userId);
        if (recentReset) {
            return { passed: false, reason: 'Password was reset recently. Please wait 24 hours.' };
        }
        
        // Check for suspicious activity
        const suspiciousActivity = await this.checkSuspiciousActivity(request);
        if (suspiciousActivity) {
            return { passed: false, reason: 'Suspicious activity detected. Please contact IT support.' };
        }
        
        // Check rate limiting
        const rateLimited = await this.checkRateLimit(request.requestedBy);
        if (rateLimited) {
            return { passed: false, reason: 'Too many password reset requests. Please try again later.' };
        }
        
        return { passed: true };
    }
    
    async checkRecentPasswordReset(userId) {
        // Check if password was reset in the last 24 hours
        // This would query audit logs or database
        return false;
    }
    
    async checkSuspiciousActivity(request) {
        // Check for suspicious patterns
        const indicators = [];
        
        // Multiple requests from same IP
        if (request.metadata.ipAddress) {
            // Check recent requests from this IP
        }
        
        // Unusual request timing
        const hour = new Date().getHours();
        if (hour < 6 || hour > 22) {
            indicators.push('off_hours_request');
        }
        
        return indicators.length > 2;
    }
    
    async checkRateLimit(requestedBy) {
        // Implementation would check request frequency
        return false;
    }
    
    generateSecurePassword() {
        const config = this.config.passwordComplexity;
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const special = '!@#$%^&*';
        
        let chars = '';
        let password = '';
        
        if (config.requireLowercase) {
            chars += lowercase;
            password += lowercase[Math.floor(Math.random() * lowercase.length)];
        }
        if (config.requireUppercase) {
            chars += uppercase;
            password += uppercase[Math.floor(Math.random() * uppercase.length)];
        }
        if (config.requireNumbers) {
            chars += numbers;
            password += numbers[Math.floor(Math.random() * numbers.length)];
        }
        if (config.requireSpecialChars) {
            chars += special;
            password += special[Math.floor(Math.random() * special.length)];
        }
        
        // Fill remaining length
        const remainingLength = Math.max(config.minLength - password.length, 0);
        for (let i = 0; i < remainingLength; i++) {
            password += chars[Math.floor(Math.random() * chars.length)];
        }
        
        // Shuffle password
        return password.split('').sort(() => Math.random() - 0.5).join('');
    }
    
    async updateUserPassword(userId, newPassword) {
        this.emit('ldap:modify', {
            dn: `uid=${userId},ou=users,dc=example,dc=com`,
            changes: [{
                operation: 'replace',
                modification: {
                    userPassword: newPassword
                }
            }]
        });
        
        // Mock successful update
        return { success: true };
    }
    
    async sendPasswordNotification(request) {
        const notification = {
            to: request.userId,
            type: 'password_reset',
            subject: 'Password Reset Completed',
            body: `Your password has been reset successfully. Your temporary password is: ${request.data.newPassword}`,
            deliveryMethod: request.data.deliveryMethod
        };
        
        this.emit('notification:send', notification);
        return { sent: true };
    }
    
    // Application Access Request
    async requestApplicationAccess(userId, applicationId, requestedBy, options = {}) {
        const requestId = this.generateId();
        const request = {
            id: requestId,
            type: 'application_access',
            userId,
            applicationId,
            requestedBy,
            status: 'pending',
            data: {
                accessLevel: options.accessLevel || 'read',
                businessJustification: options.businessJustification || '',
                requestedDuration: options.requestedDuration || 'permanent',
                urgency: options.urgency || 'normal'
            },
            timestamp: new Date().toISOString(),
            approvals: [],
            metadata: {
                requestorRole: options.requestorRole,
                department: options.department,
                manager: options.manager
            }
        };
        
        this.pendingRequests.set(requestId, request);
        this.requestStats.total++;
        this.requestStats.pending++;
        
        // Check if auto-approval is possible
        if (await this.canAutoApprove(request)) {
            await this.processApplicationAccess(request);
        } else {
            await this.initiateApprovalProcess(request);
        }
        
        return { requestId, status: request.status };
    }
    
    async canAutoApprove(request) {
        // Check auto-approval rules
        const rules = [
            // User already has similar access
            await this.checkExistingSimilarAccess(request),
            // Low-risk application
            await this.isLowRiskApplication(request.applicationId),
            // Standard access level
            request.data.accessLevel === 'read'
        ];
        
        return rules.every(rule => rule === true);
    }
    
    async checkExistingSimilarAccess(request) {
        // Check if user already has access to similar applications
        this.emit('access:check', {
            userId: request.userId,
            applicationCategory: 'productivity' // Mock category
        });
        
        return false; // Mock result
    }
    
    async isLowRiskApplication(applicationId) {
        // Check application risk level
        const lowRiskApps = ['office365', 'slack', 'zoom', 'confluence'];
        return lowRiskApps.includes(applicationId);
    }
    
    async initiateApprovalProcess(request) {
        const template = this.requestTemplates.get(request.type);
        const approvalChain = template.approvalChain || ['manager'];
        
        const approvalProcess = {
            requestId: request.id,
            chain: approvalChain.map((role, index) => ({
                step: index + 1,
                role,
                approver: null,
                status: 'pending',
                timestamp: null,
                comments: null
            })),
            currentStep: 1,
            status: 'pending'
        };
        
        this.approvalChains.set(request.id, approvalProcess);
        
        // Notify first approver
        await this.notifyApprover(request, approvalProcess.chain[0]);
        
        request.status = 'pending_approval';
        await this.saveRequest(request);
        
        this.emit('approval:initiated', {
            requestId: request.id,
            approvalChain: approvalProcess.chain
        });
    }
    
    async notifyApprover(request, approvalStep) {
        const approver = await this.getApprover(request, approvalStep.role);
        
        if (approver) {
            approvalStep.approver = approver.id;
            
            const notification = {
                to: approver.email,
                type: 'approval_request',
                subject: `Approval Required: ${request.type}`,
                body: this.buildApprovalNotification(request),
                data: {
                    requestId: request.id,
                    approver: approver.id,
                    role: approvalStep.role
                }
            };
            
            this.emit('notification:send', notification);
        }
    }
    
    async getApprover(request, role) {
        switch (role) {
            case 'manager':
                return await this.getUserManager(request.userId);
            case 'application_owner':
                return await this.getApplicationOwner(request.applicationId);
            case 'security_team':
                return await this.getSecurityTeamContact();
            default:
                return null;
        }
    }
    
    async getUserManager(userId) {
        // Mock manager lookup
        return {
            id: 'manager_' + userId,
            email: `manager.${userId}@example.com`,
            name: `Manager of ${userId}`
        };
    }
    
    async getApplicationOwner(applicationId) {
        // Mock application owner lookup
        return {
            id: 'owner_' + applicationId,
            email: `owner.${applicationId}@example.com`,
            name: `Owner of ${applicationId}`
        };
    }
    
    async getSecurityTeamContact() {
        return {
            id: 'security_team',
            email: 'security@example.com',
            name: 'Security Team'
        };
    }
    
    buildApprovalNotification(request) {
        return `
A new access request requires your approval:

Request Type: ${request.type}
User: ${request.userId}
Application: ${request.applicationId || 'N/A'}
Access Level: ${request.data.accessLevel || 'N/A'}
Business Justification: ${request.data.businessJustification || 'Not provided'}

Please review and approve or reject this request.
        `.trim();
    }
    
    async approveRequest(requestId, approverId, comments = '') {
        const request = this.pendingRequests.get(requestId);
        if (!request) {
            throw new Error('Request not found');
        }
        
        const approvalProcess = this.approvalChains.get(requestId);
        if (!approvalProcess) {
            throw new Error('Approval process not found');
        }
        
        const currentStep = approvalProcess.chain[approvalProcess.currentStep - 1];
        
        if (currentStep.approver !== approverId) {
            throw new Error('Unauthorized approver');
        }
        
        // Record approval
        currentStep.status = 'approved';
        currentStep.timestamp = new Date().toISOString();
        currentStep.comments = comments;
        
        request.approvals.push({
            step: approvalProcess.currentStep,
            approverId,
            action: 'approved',
            timestamp: new Date().toISOString(),
            comments
        });
        
        // Check if more approvals needed
        if (approvalProcess.currentStep < approvalProcess.chain.length) {
            approvalProcess.currentStep++;
            const nextStep = approvalProcess.chain[approvalProcess.currentStep - 1];
            await this.notifyApprover(request, nextStep);
        } else {
            // All approvals complete
            approvalProcess.status = 'approved';
            request.status = 'approved';
            
            // Process the request
            await this.processApprovedRequest(request);
        }
        
        await this.saveRequest(request);
        await this.saveApproval(approvalProcess);
        
        this.emit('request:approved', {
            requestId,
            approverId,
            step: approvalProcess.currentStep
        });
        
        return { status: request.status };
    }
    
    async rejectRequest(requestId, reason, rejectedBy = null) {
        const request = this.pendingRequests.get(requestId);
        if (!request) return;
        
        request.status = 'rejected';
        request.rejectionReason = reason;
        request.rejectedBy = rejectedBy;
        request.rejectedAt = new Date().toISOString();
        
        this.requestStats.pending--;
        this.requestStats.rejected++;
        
        // Notify requestor
        await this.notifyRequestRejection(request);
        
        this.emit('request:rejected', {
            requestId,
            reason,
            rejectedBy
        });
        
        await this.saveRequest(request);
        this.pendingRequests.delete(requestId);
    }
    
    async processApprovedRequest(request) {
        try {
            switch (request.type) {
                case 'application_access':
                    await this.processApplicationAccess(request);
                    break;
                case 'device_enrollment':
                    await this.processDeviceEnrollment(request);
                    break;
                case 'certificate_request':
                    await this.processCertificateRequest(request);
                    break;
                default:
                    throw new Error(`Unknown request type: ${request.type}`);
            }
            
            request.status = 'completed';
            request.completedAt = new Date().toISOString();
            
            this.requestStats.pending--;
            this.requestStats.approved++;
            
        } catch (error) {
            await this.failRequest(request.id, error.message);
        }
    }
    
    async processApplicationAccess(request) {
        // Grant access to application
        this.emit('access:grant', {
            userId: request.userId,
            applicationId: request.applicationId,
            accessLevel: request.data.accessLevel,
            requestId: request.id
        });
        
        // Send confirmation notification
        const notification = {
            to: request.userId,
            type: 'access_granted',
            subject: `Access Granted: ${request.applicationId}`,
            body: `Your access request for ${request.applicationId} has been approved and granted.`
        };
        
        this.emit('notification:send', notification);
        
        // Log access grant
        this.emit('audit:log', {
            action: 'access_granted',
            userId: request.userId,
            applicationId: request.applicationId,
            requestId: request.id,
            timestamp: new Date().toISOString()
        });
    }
    
    // Device Enrollment
    async requestDeviceEnrollment(deviceInfo, requestedBy, options = {}) {
        const requestId = this.generateId();
        const request = {
            id: requestId,
            type: 'device_enrollment',
            requestedBy,
            status: 'pending',
            data: {
                deviceType: deviceInfo.deviceType,
                deviceModel: deviceInfo.deviceModel,
                serialNumber: deviceInfo.serialNumber,
                ownerEmail: deviceInfo.ownerEmail,
                platform: deviceInfo.platform,
                enrollmentType: options.enrollmentType || 'byod'
            },
            timestamp: new Date().toISOString(),
            metadata: {
                department: options.department,
                manager: options.manager
            }
        };
        
        this.pendingRequests.set(requestId, request);
        this.deviceEnrollments.set(requestId, {
            ...request.data,
            status: 'pending'
        });
        
        this.requestStats.total++;
        this.requestStats.pending++;
        
        // Auto-approve device enrollment
        await this.processDeviceEnrollment(request);
        
        return { requestId, status: request.status };
    }
    
    async processDeviceEnrollment(request) {
        try {
            // Generate enrollment profile
            const enrollmentProfile = await this.generateEnrollmentProfile(request.data);
            
            // Send enrollment profile to user
            await this.deliverEnrollmentProfile(request, enrollmentProfile);
            
            request.status = 'completed';
            request.completedAt = new Date().toISOString();
            request.data.enrollmentProfile = enrollmentProfile;
            
            this.requestStats.pending--;
            this.requestStats.automated++;
            
            this.emit('device:enrollment_completed', {
                requestId: request.id,
                deviceInfo: request.data
            });
            
            await this.saveRequest(request);
            
        } catch (error) {
            await this.failRequest(request.id, error.message);
        }
    }
    
    async generateEnrollmentProfile(deviceInfo) {
        const profile = {
            profileId: this.generateId(),
            deviceType: deviceInfo.deviceType,
            platform: deviceInfo.platform,
            enrollmentUrl: `https://mdm.example.com/enroll/${this.generateId()}`,
            configurationProfile: {
                mdmServerUrl: 'https://mdm.example.com',
                organizationName: 'Example Organization',
                settings: {
                    passcodeRequired: true,
                    encryptionRequired: true,
                    wifiConfiguration: {
                        ssid: 'CorporateWiFi',
                        security: 'WPA2'
                    }
                }
            },
            expiresAt: new Date(Date.now() + 86400000).toISOString() // 24 hours
        };
        
        return profile;
    }
    
    async deliverEnrollmentProfile(request, profile) {
        const notification = {
            to: request.data.ownerEmail,
            type: 'device_enrollment',
            subject: 'Device Enrollment Profile Ready',
            body: `Your device enrollment profile is ready. Please visit: ${profile.enrollmentUrl}`,
            attachments: [{
                name: 'enrollment_profile.mobileconfig',
                content: JSON.stringify(profile.configurationProfile, null, 2),
                contentType: 'application/x-apple-aspen-config'
            }]
        };
        
        this.emit('notification:send', notification);
        return { delivered: true };
    }
    
    // Certificate Management
    async requestCertificate(certificateRequest, requestedBy, options = {}) {
        const requestId = this.generateId();
        const request = {
            id: requestId,
            type: 'certificate_request',
            requestedBy,
            status: 'pending',
            data: {
                certificateType: certificateRequest.type,
                commonName: certificateRequest.commonName,
                subjectAlternativeNames: certificateRequest.sans || [],
                keySize: certificateRequest.keySize || 2048,
                validityPeriod: certificateRequest.validityPeriod || '1y',
                usage: certificateRequest.usage || 'client',
                autoRenewal: options.autoRenewal || false
            },
            timestamp: new Date().toISOString(),
            metadata: {
                department: options.department,
                purpose: options.purpose
            }
        };
        
        this.pendingRequests.set(requestId, request);
        this.certificateRequests.set(requestId, {
            ...request.data,
            status: 'pending'
        });
        
        this.requestStats.total++;
        this.requestStats.pending++;
        
        // Process certificate request
        await this.processCertificateRequest(request);
        
        return { requestId, status: request.status };
    }
    
    async processCertificateRequest(request) {
        try {
            // Generate certificate
            const certificate = await this.generateCertificate(request.data);
            
            // Store certificate securely
            await this.storeCertificate(request.id, certificate);
            
            // Schedule renewal if enabled
            if (request.data.autoRenewal) {
                await this.scheduleRenewal(request.id, certificate.expiresAt);
            }
            
            // Notify user
            await this.deliverCertificate(request, certificate);
            
            request.status = 'completed';
            request.completedAt = new Date().toISOString();
            request.data.certificateId = certificate.id;
            
            this.requestStats.pending--;
            this.requestStats.automated++;
            
            this.emit('certificate:issued', {
                requestId: request.id,
                certificateId: certificate.id,
                commonName: certificate.commonName
            });
            
            await this.saveRequest(request);
            
        } catch (error) {
            await this.failRequest(request.id, error.message);
        }
    }
    
    async generateCertificate(certificateData) {
        // Mock certificate generation
        const certificate = {
            id: this.generateId(),
            commonName: certificateData.commonName,
            subjectAlternativeNames: certificateData.subjectAlternativeNames,
            keySize: certificateData.keySize,
            serialNumber: this.generateSerialNumber(),
            issuedAt: new Date().toISOString(),
            expiresAt: this.calculateExpiration(certificateData.validityPeriod),
            usage: certificateData.usage,
            certificate: '-----BEGIN CERTIFICATE-----\n[MOCK CERTIFICATE DATA]\n-----END CERTIFICATE-----',
            privateKey: '-----BEGIN PRIVATE KEY-----\n[MOCK PRIVATE KEY DATA]\n-----END PRIVATE KEY-----'
        };
        
        return certificate;
    }
    
    generateSerialNumber() {
        return crypto.randomBytes(8).toString('hex').toUpperCase();
    }
    
    calculateExpiration(validityPeriod) {
        const now = new Date();
        const match = validityPeriod.match(/^(\d+)([ymwd])$/);
        
        if (!match) return new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString();
        
        const [, amount, unit] = match;
        const value = parseInt(amount);
        
        switch (unit) {
            case 'y':
                now.setFullYear(now.getFullYear() + value);
                break;
            case 'm':
                now.setMonth(now.getMonth() + value);
                break;
            case 'w':
                now.setDate(now.getDate() + value * 7);
                break;
            case 'd':
                now.setDate(now.getDate() + value);
                break;
        }
        
        return now.toISOString();
    }
    
    async storeCertificate(requestId, certificate) {
        const certPath = path.join(this.config.storageDir, 'certificates', `${certificate.id}.json`);
        await fs.writeFile(certPath, JSON.stringify({
            ...certificate,
            requestId
        }, null, 2));
        
        return { stored: true, path: certPath };
    }
    
    async scheduleRenewal(requestId, expirationDate) {
        const renewalDate = new Date(expirationDate);
        renewalDate.setDate(renewalDate.getDate() - 30); // Renew 30 days before expiration
        
        this.emit('scheduler:schedule', {
            id: `cert_renewal_${requestId}`,
            executeAt: renewalDate.toISOString(),
            action: 'renew_certificate',
            data: { requestId }
        });
        
        return { scheduled: true, renewalDate: renewalDate.toISOString() };
    }
    
    async deliverCertificate(request, certificate) {
        const notification = {
            to: request.requestedBy,
            type: 'certificate_ready',
            subject: `Certificate Ready: ${certificate.commonName}`,
            body: `Your certificate for ${certificate.commonName} has been generated and is ready for download.`,
            attachments: [{
                name: `${certificate.commonName}.p12`,
                content: '[MOCK P12 CERTIFICATE DATA]',
                contentType: 'application/x-pkcs12'
            }]
        };
        
        this.emit('notification:send', notification);
        return { delivered: true };
    }
    
    // Approval Chain Management
    async getApprovalChain(requestId) {
        return this.approvalChains.get(requestId);
    }
    
    async updateApprovalChain(requestId, newChain) {
        const approvalProcess = this.approvalChains.get(requestId);
        if (!approvalProcess) {
            throw new Error('Approval process not found');
        }
        
        approvalProcess.chain = newChain;
        await this.saveApproval(approvalProcess);
        
        this.emit('approval:chain_updated', { requestId, newChain });
        return approvalProcess;
    }
    
    // Request Management
    async getRequest(requestId) {
        return this.pendingRequests.get(requestId) || await this.loadRequest(requestId);
    }
    
    async getPendingRequests(filters = {}) {
        let requests = Array.from(this.pendingRequests.values());
        
        if (filters.type) {
            requests = requests.filter(r => r.type === filters.type);
        }
        
        if (filters.status) {
            requests = requests.filter(r => r.status === filters.status);
        }
        
        if (filters.requestedBy) {
            requests = requests.filter(r => r.requestedBy === filters.requestedBy);
        }
        
        return requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }
    
    async cancelRequest(requestId, cancelledBy, reason = '') {
        const request = this.pendingRequests.get(requestId);
        if (!request) {
            throw new Error('Request not found');
        }
        
        if (request.status === 'completed') {
            throw new Error('Cannot cancel completed request');
        }
        
        request.status = 'cancelled';
        request.cancelledBy = cancelledBy;
        request.cancellationReason = reason;
        request.cancelledAt = new Date().toISOString();
        
        this.requestStats.pending--;
        
        // Clean up approval process
        this.approvalChains.delete(requestId);
        
        this.emit('request:cancelled', {
            requestId,
            cancelledBy,
            reason
        });
        
        await this.saveRequest(request);
        this.pendingRequests.delete(requestId);
        
        return { cancelled: true };
    }
    
    async failRequest(requestId, error) {
        const request = this.pendingRequests.get(requestId);
        if (!request) return;
        
        request.status = 'failed';
        request.error = error;
        request.failedAt = new Date().toISOString();
        
        this.requestStats.pending--;
        this.requestStats.errors = (this.requestStats.errors || 0) + 1;
        
        this.emit('request:failed', {
            requestId,
            error
        });
        
        await this.saveRequest(request);
        this.pendingRequests.delete(requestId);
    }
    
    // Notification helpers
    async notifyRequestRejection(request) {
        const notification = {
            to: request.requestedBy,
            type: 'request_rejected',
            subject: `Request Rejected: ${request.type}`,
            body: `Your request has been rejected. Reason: ${request.rejectionReason}`
        };
        
        this.emit('notification:send', notification);
    }
    
    // Storage
    async saveRequest(request) {
        const filePath = path.join(this.config.storageDir, 'requests', `${request.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(request, null, 2));
    }
    
    async loadRequest(requestId) {
        try {
            const filePath = path.join(this.config.storageDir, 'requests', `${requestId}.json`);
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return null;
        }
    }
    
    async saveApproval(approvalProcess) {
        const filePath = path.join(this.config.storageDir, 'approvals', `${approvalProcess.requestId}.json`);
        await fs.writeFile(filePath, JSON.stringify(approvalProcess, null, 2));
    }
    
    async loadRequestTemplates() {
        // Load custom request templates from storage
        try {
            const templatesDir = path.join(this.config.storageDir, 'templates');
            const files = await fs.readdir(templatesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const filePath = path.join(templatesDir, file);
                    const data = await fs.readFile(filePath, 'utf8');
                    const template = JSON.parse(data);
                    this.requestTemplates.set(template.id, template);
                }
            }
            
            console.log(`Loaded ${this.requestTemplates.size} request templates`);
        } catch (error) {
            console.error('Failed to load request templates:', error);
        }
    }
    
    // Background processing
    startRequestProcessor() {
        setInterval(() => {
            this.processTimeoutRequests();
        }, 60000); // Check every minute
        
        console.log('Request processor started');
    }
    
    startApprovalTimeoutChecker() {
        setInterval(() => {
            this.checkApprovalTimeouts();
        }, 3600000); // Check every hour
        
        console.log('Approval timeout checker started');
    }
    
    async processTimeoutRequests() {
        const now = Date.now();
        
        for (const [requestId, request] of this.pendingRequests) {
            const requestTime = Date.parse(request.timestamp);
            
            if (now - requestTime > this.config.requestTimeout) {
                await this.failRequest(requestId, 'Request timeout');
            }
        }
    }
    
    async checkApprovalTimeouts() {
        const now = Date.now();
        
        for (const [requestId, approvalProcess] of this.approvalChains) {
            const request = this.pendingRequests.get(requestId);
            if (!request) continue;
            
            const requestTime = Date.parse(request.timestamp);
            
            if (now - requestTime > this.config.approvalTimeout) {
                await this.rejectRequest(requestId, 'Approval timeout - no response from approvers');
            }
        }
    }
    
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }
    
    // Statistics and reporting
    getRequestStats() {
        return {
            ...this.requestStats,
            pendingRequests: this.pendingRequests.size,
            pendingApprovals: this.approvalChains.size,
            certificateRequests: this.certificateRequests.size,
            deviceEnrollments: this.deviceEnrollments.size,
            templates: this.requestTemplates.size,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        };
    }
    
    // API Methods
    async createRequestTemplate(template) {
        const templateId = template.id || this.generateId();
        template.id = templateId;
        template.created = new Date().toISOString();
        
        this.requestTemplates.set(templateId, template);
        
        const templatePath = path.join(this.config.storageDir, 'templates', `${templateId}.json`);
        await fs.writeFile(templatePath, JSON.stringify(template, null, 2));
        
        this.emit('template:created', { templateId });
        return templateId;
    }
    
    async getRequestTemplates() {
        return Array.from(this.requestTemplates.values());
    }
    
    async deleteRequestTemplate(templateId) {
        const deleted = this.requestTemplates.delete(templateId);
        
        if (deleted) {
            const templatePath = path.join(this.config.storageDir, 'templates', `${templateId}.json`);
            try {
                await fs.unlink(templatePath);
            } catch (error) {
                console.error('Failed to delete template file:', error);
            }
            
            this.emit('template:deleted', { templateId });
        }
        
        return deleted;
    }
}

module.exports = { SelfServiceBackend };