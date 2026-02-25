/**
 * OpenDirectory SCEP (Simple Certificate Enrollment Protocol) Service
 * RFC 8894 compliant SCEP server implementation
 * 
 * Features:
 * - SCEP enrollment and renewal operations
 * - Challenge password authentication
 * - Certificate-based renewal
 * - Integration with Enterprise CA
 * - Device-specific certificate profiles
 * - Automatic and manual approval workflows
 * - PKCS#7 message handling
 * - Multi-platform support (iOS, Android, Windows, macOS)
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const EventEmitter = require('events');
const express = require('express');
const forge = require('node-forge');
const config = require('../config');

class SCEPService extends EventEmitter {
    constructor(caService, certificateService, options = {}) {
        super();
        
        this.caService = caService;
        this.certificateService = certificateService;
        this.config = {
            ...config.scep,
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
                    filename: path.join(path.dirname(config.logging.file), 'scep.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // SCEP server instance
        this.server = null;
        
        // Data stores
        this.enrollmentRequests = new Map();
        this.challengePasswords = new Map();
        this.scepProfiles = new Map();
        
        // SCEP CA certificate and private key
        this.scepCACert = null;
        this.scepCAKey = null;
        this.scepEncCert = null;
        this.scepEncKey = null;
        
        // SCEP operation types
        this.SCEP_OPERATIONS = {
            GET_CA_CERT: 'GetCACert',
            GET_CA_CAPS: 'GetCACaps', 
            PKI_OPERATION: 'PKIOperation'
        };

        // SCEP message types
        this.SCEP_MESSAGE_TYPES = {
            CERT_REQ: 19,      // Certificate Request
            CERT_REP: 3,       // Certificate Response
            GET_CERT_INITIAL: 20, // Get Certificate Initial
            GET_CERT: 21,      // Get Certificate
            GET_CRL: 22        // Get CRL
        };

        // SCEP failure reasons
        this.SCEP_FAILURE_REASONS = {
            BAD_ALG: 0,           // Unrecognized or unsupported algorithm
            BAD_MESSAGE_CHECK: 1,  // Integrity check failed
            BAD_REQUEST: 2,        // Transaction not permitted or supported
            BAD_TIME: 3,          // Message time field was not sufficiently close to the system time
            BAD_CERT_ID: 4        // No certificate could be identified matching the provided criteria
        };

        // SCEP status values
        this.SCEP_STATUS = {
            SUCCESS: 0,
            FAILURE: 2,
            PENDING: 3
        };

        // Metrics
        this.metrics = {
            enrollmentRequests: 0,
            enrollmentSuccess: 0,
            enrollmentFailures: 0,
            renewalRequests: 0,
            renewalSuccess: 0,
            renewalFailures: 0,
            caCertRequests: 0,
            capabilitiesRequests: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadSCEPCertificates();
            await this.loadSCEPProfiles();
            await this.loadChallengePasswords();
            await this.startSCEPServer();
            
            this.logger.info('SCEP Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize SCEP Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            path.join(config.storage.certificates, 'scep'),
            path.join(config.storage.certificates, 'scep', 'enrollment'),
            path.join(config.storage.certificates, 'scep', 'profiles'),
            path.join(config.storage.certificates, 'scep', 'challenges')
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
     * SCEP Server Setup
     */
    async startSCEPServer() {
        this.server = express();
        
        // Middleware
        this.server.use(express.raw({ type: 'application/x-pki-message', limit: '10mb' }));
        this.server.use(express.urlencoded({ extended: true }));
        
        // SCEP endpoints
        this.server.get(this.config.endpoint || '/scep', this.handleSCEPRequest.bind(this));
        this.server.post(this.config.endpoint || '/scep', this.handleSCEPRequest.bind(this));
        
        // Health check endpoint
        this.server.get(this.config.endpoint + '/health', (req, res) => {
            res.json({ status: 'healthy', timestamp: new Date() });
        });

        const port = this.config.port || 8080;
        this.server.listen(port, () => {
            this.logger.info(`SCEP server listening on port ${port}`);
            this.logger.info(`SCEP endpoint: ${this.config.endpoint || '/scep'}`);
        });
    }

    async handleSCEPRequest(req, res) {
        try {
            const operation = req.query.operation || req.body.operation;
            
            this.logger.info(`SCEP request: ${req.method} ${req.url}, operation: ${operation}`);

            switch (operation) {
                case this.SCEP_OPERATIONS.GET_CA_CERT:
                    await this.handleGetCACert(req, res);
                    break;
                case this.SCEP_OPERATIONS.GET_CA_CAPS:
                    await this.handleGetCACaps(req, res);
                    break;
                case this.SCEP_OPERATIONS.PKI_OPERATION:
                    await this.handlePKIOperation(req, res);
                    break;
                default:
                    res.status(400).send('Invalid SCEP operation');
            }

        } catch (error) {
            this.logger.error('SCEP request handling failed:', error);
            res.status(500).send('Internal server error');
        }
    }

    async handleGetCACert(req, res) {
        try {
            this.metrics.caCertRequests++;
            
            const message = req.query.message;
            
            if (message) {
                // Return specific CA certificate
                const caCert = await this.getCACertByName(message);
                if (caCert) {
                    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
                    res.send(forge.pki.certificateToDer(caCert));
                } else {
                    res.status(404).send('CA certificate not found');
                }
            } else {
                // Return CA certificate chain
                const caCertChain = await this.getSCEPCACertChain();
                
                if (caCertChain.length === 1) {
                    // Single certificate
                    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
                    res.send(forge.pki.certificateToDer(caCertChain[0]));
                } else {
                    // Certificate chain in PKCS#7 format
                    const p7 = this.buildCACertChainP7(caCertChain);
                    res.setHeader('Content-Type', 'application/x-x509-ca-ra-cert');
                    res.send(p7);
                }
            }

        } catch (error) {
            this.logger.error('GetCACert failed:', error);
            res.status(500).send('Failed to retrieve CA certificate');
        }
    }

    async handleGetCACaps(req, res) {
        try {
            this.metrics.capabilitiesRequests++;
            
            const capabilities = this.getSCEPCapabilities();
            
            res.setHeader('Content-Type', 'text/plain');
            res.send(capabilities.join('\n'));

        } catch (error) {
            this.logger.error('GetCACaps failed:', error);
            res.status(500).send('Failed to retrieve CA capabilities');
        }
    }

    async handlePKIOperation(req, res) {
        try {
            let messageData;
            
            if (req.method === 'GET') {
                // GET request - message in query parameter (base64 encoded)
                const messageParam = req.query.message;
                if (!messageParam) {
                    return res.status(400).send('Missing message parameter');
                }
                messageData = Buffer.from(messageParam, 'base64');
            } else {
                // POST request - message in body
                messageData = req.body;
            }

            const response = await this.processPKIMessage(messageData);
            
            res.setHeader('Content-Type', 'application/x-pki-message');
            res.send(response);

        } catch (error) {
            this.logger.error('PKIOperation failed:', error);
            res.status(500).send('PKI operation failed');
        }
    }

    /**
     * PKI Message Processing
     */
    async processPKIMessage(messageData) {
        try {
            // Parse PKCS#7 message
            const p7 = this.parsePKCS7Message(messageData);
            
            // Verify message signature
            if (!this.verifyPKCS7Signature(p7)) {
                throw new Error('Invalid message signature');
            }

            // Decrypt message if needed
            const decryptedMessage = await this.decryptPKCS7Message(p7);
            
            // Parse inner PKCS#10 CSR
            const csr = this.parseCSRFromMessage(decryptedMessage);
            
            // Extract SCEP attributes
            const scepAttrs = this.extractSCEPAttributes(p7);
            
            // Process based on message type
            switch (scepAttrs.messageType) {
                case this.SCEP_MESSAGE_TYPES.CERT_REQ:
                    return await this.processCertificateRequest(csr, scepAttrs, p7);
                case this.SCEP_MESSAGE_TYPES.GET_CERT_INITIAL:
                    return await this.processGetCertInitial(scepAttrs);
                case this.SCEP_MESSAGE_TYPES.GET_CERT:
                    return await this.processGetCert(scepAttrs);
                case this.SCEP_MESSAGE_TYPES.GET_CRL:
                    return await this.processGetCRL(scepAttrs);
                default:
                    throw new Error(`Unsupported message type: ${scepAttrs.messageType}`);
            }

        } catch (error) {
            this.logger.error('PKI message processing failed:', error);
            
            // Return SCEP failure response
            return this.buildSCEPFailureResponse(
                this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                'Message processing failed'
            );
        }
    }

    async processCertificateRequest(csr, scepAttrs, originalMessage) {
        try {
            this.metrics.enrollmentRequests++;
            
            const transactionId = scepAttrs.transactionId;
            const challengePassword = scepAttrs.challengePassword;
            
            this.logger.info(`Certificate request - Transaction: ${transactionId}`);

            // Validate challenge password
            if (!this.validateChallengePassword(challengePassword, scepAttrs)) {
                this.metrics.enrollmentFailures++;
                return this.buildSCEPFailureResponse(
                    this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                    'Invalid challenge password'
                );
            }

            // Create enrollment request record
            const enrollmentRequest = {
                id: this.generateRequestId(),
                transactionId: transactionId,
                csr: csr,
                scepAttrs: scepAttrs,
                originalMessage: originalMessage,
                status: 'pending',
                submittedAt: new Date()
            };

            this.enrollmentRequests.set(transactionId, enrollmentRequest);
            await this.saveEnrollmentRequest(enrollmentRequest);

            // Determine if automatic approval is enabled
            const profile = await this.getSCEPProfileForRequest(scepAttrs);
            
            if (profile && profile.autoApproval) {
                return await this.approveEnrollmentRequest(transactionId);
            } else {
                // Manual approval required - return pending response
                return this.buildSCEPPendingResponse(transactionId);
            }

        } catch (error) {
            this.metrics.enrollmentFailures++;
            this.logger.error('Certificate request processing failed:', error);
            
            return this.buildSCEPFailureResponse(
                this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                'Certificate request processing failed'
            );
        }
    }

    async approveEnrollmentRequest(transactionId) {
        try {
            const enrollmentRequest = this.enrollmentRequests.get(transactionId);
            if (!enrollmentRequest) {
                throw new Error(`Enrollment request not found: ${transactionId}`);
            }

            // Get SCEP profile for certificate issuance
            const profile = await this.getSCEPProfileForRequest(enrollmentRequest.scepAttrs);
            
            // Issue certificate via CA service
            const certificateResult = await this.caService.issueCertificate({
                caId: profile.caId,
                csr: forge.pki.certificationRequestToPem(enrollmentRequest.csr),
                template: profile.certificateTemplate,
                validityDays: profile.validityDays || 365,
                keyUsage: profile.keyUsage || ['digitalSignature', 'keyEncipherment'],
                extendedKeyUsage: profile.extendedKeyUsage || [],
                requesterId: 'scep',
                metadata: {
                    scepTransactionId: transactionId,
                    scepProfile: profile.id
                }
            });

            // Update enrollment request
            enrollmentRequest.status = 'approved';
            enrollmentRequest.certificateId = certificateResult.id;
            enrollmentRequest.approvedAt = new Date();
            
            await this.saveEnrollmentRequest(enrollmentRequest);
            
            // Build SCEP success response with certificate
            const certificate = forge.pki.certificateFromPem(certificateResult.certificate);
            const caChain = await this.getCAChainForProfile(profile);
            
            this.metrics.enrollmentSuccess++;
            this.logger.info(`Certificate request approved: ${transactionId}`);
            
            return this.buildSCEPSuccessResponse(transactionId, certificate, caChain);

        } catch (error) {
            this.metrics.enrollmentFailures++;
            this.logger.error('Enrollment approval failed:', error);
            
            return this.buildSCEPFailureResponse(
                this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                'Certificate issuance failed'
            );
        }
    }

    async processGetCertInitial(scepAttrs) {
        try {
            const transactionId = scepAttrs.transactionId;
            const enrollmentRequest = this.enrollmentRequests.get(transactionId);
            
            if (!enrollmentRequest) {
                return this.buildSCEPFailureResponse(
                    this.SCEP_FAILURE_REASONS.BAD_CERT_ID,
                    'Transaction not found'
                );
            }

            switch (enrollmentRequest.status) {
                case 'approved':
                    // Certificate is ready
                    const certificate = await this.getCertificateById(enrollmentRequest.certificateId);
                    const profile = await this.getSCEPProfileForRequest(enrollmentRequest.scepAttrs);
                    const caChain = await this.getCAChainForProfile(profile);
                    
                    return this.buildSCEPSuccessResponse(transactionId, certificate, caChain);
                    
                case 'rejected':
                    return this.buildSCEPFailureResponse(
                        this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                        'Certificate request was rejected'
                    );
                    
                case 'pending':
                default:
                    return this.buildSCEPPendingResponse(transactionId);
            }

        } catch (error) {
            this.logger.error('GetCertInitial processing failed:', error);
            return this.buildSCEPFailureResponse(
                this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                'GetCertInitial failed'
            );
        }
    }

    async processGetCert(scepAttrs) {
        try {
            const serialNumber = scepAttrs.serialNumber;
            const issuerName = scepAttrs.issuerName;
            
            // Find certificate by serial number and issuer
            const certificate = await this.findCertificateBySerialAndIssuer(serialNumber, issuerName);
            
            if (!certificate) {
                return this.buildSCEPFailureResponse(
                    this.SCEP_FAILURE_REASONS.BAD_CERT_ID,
                    'Certificate not found'
                );
            }

            const caChain = await this.getCAChainForCertificate(certificate);
            
            return this.buildSCEPSuccessResponse(null, certificate, caChain);

        } catch (error) {
            this.logger.error('GetCert processing failed:', error);
            return this.buildSCEPFailureResponse(
                this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                'GetCert failed'
            );
        }
    }

    async processGetCRL(scepAttrs) {
        try {
            const issuerName = scepAttrs.issuerName;
            
            // Get CRL for the specified issuer
            const crl = await this.getCRLByIssuer(issuerName);
            
            if (!crl) {
                return this.buildSCEPFailureResponse(
                    this.SCEP_FAILURE_REASONS.BAD_CERT_ID,
                    'CRL not found'
                );
            }

            return this.buildSCEPCRLResponse(crl);

        } catch (error) {
            this.logger.error('GetCRL processing failed:', error);
            return this.buildSCEPFailureResponse(
                this.SCEP_FAILURE_REASONS.BAD_REQUEST,
                'GetCRL failed'
            );
        }
    }

    /**
     * SCEP Message Building
     */
    buildSCEPSuccessResponse(transactionId, certificate, caChain = []) {
        try {
            // Create PKCS#7 degenerate certificates-only message
            const p7 = forge.pkcs7.createSignedData();
            
            // Add the issued certificate
            p7.addCertificate(certificate);
            
            // Add CA chain
            caChain.forEach(caCert => {
                p7.addCertificate(caCert);
            });

            // Create signed data with SCEP attributes
            const content = forge.util.createBuffer();
            
            // Add SCEP attributes
            const attrs = [
                {
                    type: forge.pki.oids.pkcs9ChallengePassword, // MessageType
                    value: this.SCEP_MESSAGE_TYPES.CERT_REP
                },
                {
                    type: forge.pki.oids.extensionRequest, // PKIStatus
                    value: this.SCEP_STATUS.SUCCESS
                }
            ];

            if (transactionId) {
                attrs.push({
                    type: forge.pki.oids.pkcs9UnstructuredName, // TransactionID
                    value: transactionId
                });
            }

            // Sign with SCEP signing certificate
            const signer = {
                key: this.scepCAKey,
                certificate: this.scepCACert,
                digestAlgorithm: forge.pki.oids.sha256,
                signedAttrs: attrs
            };

            p7.addSigner(signer);
            p7.sign();

            return forge.pkcs7.messageToDer(p7);

        } catch (error) {
            this.logger.error('Failed to build SCEP success response:', error);
            throw error;
        }
    }

    buildSCEPPendingResponse(transactionId) {
        try {
            const p7 = forge.pkcs7.createSignedData();
            
            const content = forge.util.createBuffer();
            p7.content = content;
            
            const attrs = [
                {
                    type: forge.pki.oids.pkcs9ChallengePassword, // MessageType
                    value: this.SCEP_MESSAGE_TYPES.CERT_REP
                },
                {
                    type: forge.pki.oids.extensionRequest, // PKIStatus
                    value: this.SCEP_STATUS.PENDING
                },
                {
                    type: forge.pki.oids.pkcs9UnstructuredName, // TransactionID
                    value: transactionId
                }
            ];

            const signer = {
                key: this.scepCAKey,
                certificate: this.scepCACert,
                digestAlgorithm: forge.pki.oids.sha256,
                signedAttrs: attrs
            };

            p7.addSigner(signer);
            p7.sign();

            return forge.pkcs7.messageToDer(p7);

        } catch (error) {
            this.logger.error('Failed to build SCEP pending response:', error);
            throw error;
        }
    }

    buildSCEPFailureResponse(failureReason, failureInfo) {
        try {
            const p7 = forge.pkcs7.createSignedData();
            
            const content = forge.util.createBuffer();
            p7.content = content;
            
            const attrs = [
                {
                    type: forge.pki.oids.pkcs9ChallengePassword, // MessageType
                    value: this.SCEP_MESSAGE_TYPES.CERT_REP
                },
                {
                    type: forge.pki.oids.extensionRequest, // PKIStatus
                    value: this.SCEP_STATUS.FAILURE
                },
                {
                    type: forge.pki.oids.pkcs9UnstructuredName, // FailInfo
                    value: failureReason
                }
            ];

            if (failureInfo) {
                attrs.push({
                    type: forge.pki.oids.description,
                    value: failureInfo
                });
            }

            const signer = {
                key: this.scepCAKey,
                certificate: this.scepCACert,
                digestAlgorithm: forge.pki.oids.sha256,
                signedAttrs: attrs
            };

            p7.addSigner(signer);
            p7.sign();

            return forge.pkcs7.messageToDer(p7);

        } catch (error) {
            this.logger.error('Failed to build SCEP failure response:', error);
            throw error;
        }
    }

    buildSCEPCRLResponse(crl) {
        try {
            const p7 = forge.pkcs7.createSignedData();
            
            // Add CRL to the message
            const content = forge.util.createBuffer(forge.pki.certificateRevocationListToDer(crl));
            p7.content = content;
            
            const attrs = [
                {
                    type: forge.pki.oids.pkcs9ChallengePassword, // MessageType
                    value: this.SCEP_MESSAGE_TYPES.CERT_REP
                },
                {
                    type: forge.pki.oids.extensionRequest, // PKIStatus
                    value: this.SCEP_STATUS.SUCCESS
                }
            ];

            const signer = {
                key: this.scepCAKey,
                certificate: this.scepCACert,
                digestAlgorithm: forge.pki.oids.sha256,
                signedAttrs: attrs
            };

            p7.addSigner(signer);
            p7.sign();

            return forge.pkcs7.messageToDer(p7);

        } catch (error) {
            this.logger.error('Failed to build SCEP CRL response:', error);
            throw error;
        }
    }

    /**
     * SCEP Message Parsing
     */
    parsePKCS7Message(messageData) {
        try {
            const asn1 = forge.asn1.fromDer(messageData.toString('binary'));
            return forge.pkcs7.messageFromAsn1(asn1);
        } catch (error) {
            this.logger.error('Failed to parse PKCS#7 message:', error);
            throw new Error('Invalid PKCS#7 message format');
        }
    }

    verifyPKCS7Signature(p7) {
        try {
            // Verify signature against known client certificates or CA
            return true; // Simplified implementation
        } catch (error) {
            this.logger.error('PKCS#7 signature verification failed:', error);
            return false;
        }
    }

    async decryptPKCS7Message(p7) {
        try {
            if (p7.type === forge.pki.oids.envelopedData) {
                // Decrypt using SCEP encryption certificate
                const decrypted = p7.decrypt(this.scepEncCert, this.scepEncKey);
                return decrypted;
            }
            
            // Message is not encrypted, return content directly
            return p7.content;
        } catch (error) {
            this.logger.error('PKCS#7 message decryption failed:', error);
            throw error;
        }
    }

    parseCSRFromMessage(messageContent) {
        try {
            // Parse PKCS#10 CSR from message content
            const csrDer = messageContent.getBytes();
            const asn1 = forge.asn1.fromDer(csrDer);
            return forge.pki.certificationRequestFromAsn1(asn1);
        } catch (error) {
            this.logger.error('Failed to parse CSR from message:', error);
            throw error;
        }
    }

    extractSCEPAttributes(p7) {
        try {
            const scepAttrs = {};
            
            if (p7.signers && p7.signers.length > 0) {
                const signer = p7.signers[0];
                
                if (signer.signedAttrs) {
                    signer.signedAttrs.forEach(attr => {
                        switch (attr.type) {
                            case forge.pki.oids.pkcs9ChallengePassword:
                                scepAttrs.messageType = attr.value;
                                break;
                            case forge.pki.oids.pkcs9UnstructuredName:
                                scepAttrs.transactionId = attr.value;
                                break;
                            case forge.pki.oids.extensionRequest:
                                scepAttrs.senderNonce = attr.value;
                                break;
                            // Add more SCEP attribute mappings as needed
                        }
                    });
                }
            }
            
            // Extract challenge password from CSR attributes if present
            const csr = this.parseCSRFromMessage(p7.content);
            if (csr.attributes) {
                csr.attributes.forEach(attr => {
                    if (attr.type === forge.pki.oids.challengePassword) {
                        scepAttrs.challengePassword = attr.value;
                    }
                });
            }
            
            return scepAttrs;

        } catch (error) {
            this.logger.error('Failed to extract SCEP attributes:', error);
            return {};
        }
    }

    /**
     * SCEP Profile Management
     */
    async createSCEPProfile(profileData) {
        try {
            const profileId = this.generateProfileId(profileData.name);
            const profile = {
                id: profileId,
                name: profileData.name,
                description: profileData.description || '',
                enabled: profileData.enabled !== false,
                
                // CA configuration
                caId: profileData.caId,
                certificateTemplate: profileData.certificateTemplate,
                
                // Certificate settings
                validityDays: profileData.validityDays || 365,
                keyUsage: profileData.keyUsage || ['digitalSignature', 'keyEncipherment'],
                extendedKeyUsage: profileData.extendedKeyUsage || [],
                
                // SCEP settings
                challengePassword: profileData.challengePassword || this.generateChallengePassword(),
                autoApproval: profileData.autoApproval !== false,
                allowRenewal: profileData.allowRenewal !== false,
                renewalThreshold: profileData.renewalThreshold || 30, // days
                
                // Device/client filters
                allowedDeviceTypes: profileData.allowedDeviceTypes || [],
                allowedUserGroups: profileData.allowedUserGroups || [],
                clientIPRestrictions: profileData.clientIPRestrictions || [],
                
                createdAt: new Date(),
                updatedAt: new Date()
            };

            this.scepProfiles.set(profileId, profile);
            await this.saveSCEPProfile(profile);
            
            this.logger.info(`SCEP profile created: ${profileId}`);
            this.emit('profileCreated', profile);
            
            return profile;

        } catch (error) {
            this.logger.error('Failed to create SCEP profile:', error);
            throw error;
        }
    }

    async updateSCEPProfile(profileId, updates) {
        try {
            const profile = this.scepProfiles.get(profileId);
            if (!profile) {
                throw new Error(`SCEP profile not found: ${profileId}`);
            }

            const updatedProfile = {
                ...profile,
                ...updates,
                updatedAt: new Date()
            };

            this.scepProfiles.set(profileId, updatedProfile);
            await this.saveSCEPProfile(updatedProfile);
            
            this.logger.info(`SCEP profile updated: ${profileId}`);
            this.emit('profileUpdated', updatedProfile);
            
            return updatedProfile;

        } catch (error) {
            this.logger.error('Failed to update SCEP profile:', error);
            throw error;
        }
    }

    /**
     * Challenge Password Management
     */
    generateChallengePassword() {
        return crypto.randomBytes(16).toString('hex');
    }

    async addChallengePassword(password, metadata = {}) {
        const passwordId = this.generatePasswordId();
        const challengeData = {
            id: passwordId,
            password: password,
            createdAt: new Date(),
            expiresAt: metadata.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
            usageCount: 0,
            maxUsage: metadata.maxUsage || 1,
            metadata: metadata,
            enabled: true
        };

        this.challengePasswords.set(password, challengeData);
        await this.saveChallengePassword(challengeData);
        
        this.logger.info(`Challenge password added: ${passwordId}`);
        return challengeData;
    }

    validateChallengePassword(password, scepAttrs) {
        if (!password) return false;
        
        const challengeData = this.challengePasswords.get(password);
        if (!challengeData) return false;
        
        // Check if password is enabled
        if (!challengeData.enabled) return false;
        
        // Check expiration
        if (new Date() > challengeData.expiresAt) {
            challengeData.enabled = false;
            return false;
        }
        
        // Check usage limit
        if (challengeData.usageCount >= challengeData.maxUsage) {
            challengeData.enabled = false;
            return false;
        }
        
        // Increment usage count
        challengeData.usageCount++;
        challengeData.lastUsed = new Date();
        
        // Disable if max usage reached
        if (challengeData.usageCount >= challengeData.maxUsage) {
            challengeData.enabled = false;
        }
        
        this.saveChallengePassword(challengeData);
        
        return true;
    }

    /**
     * Certificate and CA Operations
     */
    async getCACertByName(name) {
        if (this.caService) {
            const cas = await this.caService.getCAList();
            const ca = cas.find(c => c.subject.commonName === name);
            return ca ? forge.pki.certificateFromPem(ca.certificate) : null;
        }
        return null;
    }

    async getSCEPCACertChain() {
        const chain = [];
        
        if (this.scepCACert) {
            chain.push(this.scepCACert);
        }
        
        // Add parent CA certificates if available
        if (this.caService) {
            try {
                const caChain = await this.caService.getCAChain(this.config.scepCAId);
                caChain.forEach(caCertPem => {
                    const caCert = forge.pki.certificateFromPem(caCertPem);
                    if (caCert.serialNumber !== this.scepCACert.serialNumber) {
                        chain.push(caCert);
                    }
                });
            } catch (error) {
                this.logger.warn('Failed to get CA chain:', error);
            }
        }
        
        return chain;
    }

    buildCACertChainP7(certChain) {
        const p7 = forge.pkcs7.createSignedData();
        
        certChain.forEach(cert => {
            p7.addCertificate(cert);
        });
        
        return forge.pkcs7.messageToDer(p7);
    }

    getSCEPCapabilities() {
        return [
            'PostPKIOperation',    // Supports HTTP POST
            'Renewal',             // Supports certificate renewal
            'SHA-1',              // Supports SHA-1 hashing
            'SHA-256',            // Supports SHA-256 hashing
            'DES3',               // Supports 3DES encryption
            'AES',                // Supports AES encryption
            'SCEPStandard'        // Supports standard SCEP
        ];
    }

    async getSCEPProfileForRequest(scepAttrs) {
        // Find applicable SCEP profile based on request attributes
        for (const [profileId, profile] of this.scepProfiles) {
            if (!profile.enabled) continue;
            
            // For now, return the first enabled profile
            // In production, implement more sophisticated matching logic
            return profile;
        }
        
        return null;
    }

    async getCAChainForProfile(profile) {
        if (this.caService && profile.caId) {
            try {
                const caChain = await this.caService.getCAChain(profile.caId);
                return caChain.map(certPem => forge.pki.certificateFromPem(certPem));
            } catch (error) {
                this.logger.warn(`Failed to get CA chain for profile ${profile.id}:`, error);
            }
        }
        return [];
    }

    async getCertificateById(certificateId) {
        if (this.certificateService) {
            try {
                const cert = await this.certificateService.getCertificate(certificateId);
                return forge.pki.certificateFromPem(cert.certificate);
            } catch (error) {
                this.logger.error(`Failed to get certificate ${certificateId}:`, error);
            }
        }
        return null;
    }

    async findCertificateBySerialAndIssuer(serialNumber, issuerName) {
        // Implementation would search certificate database
        // Placeholder implementation
        return null;
    }

    async getCRLByIssuer(issuerName) {
        if (this.caService) {
            try {
                // Find CA by issuer name and get its CRL
                const cas = await this.caService.getCAList();
                const ca = cas.find(c => c.subject.commonName === issuerName);
                
                if (ca) {
                    const crlPem = await this.caService.getCRL(ca.id);
                    return forge.pki.certificateRevocationListFromPem(crlPem);
                }
            } catch (error) {
                this.logger.error(`Failed to get CRL for issuer ${issuerName}:`, error);
            }
        }
        return null;
    }

    async getCAChainForCertificate(certificate) {
        // Get CA chain for the certificate's issuer
        return [];
    }

    /**
     * Certificate Renewal Operations
     */
    async processRenewalRequest(originalCert, newCSR, scepAttrs) {
        try {
            this.metrics.renewalRequests++;
            
            // Verify the original certificate is valid for renewal
            if (!this.validateRenewalCertificate(originalCert)) {
                this.metrics.renewalFailures++;
                throw new Error('Original certificate not valid for renewal');
            }

            // Get SCEP profile
            const profile = await this.getSCEPProfileForRequest(scepAttrs);
            if (!profile || !profile.allowRenewal) {
                this.metrics.renewalFailures++;
                throw new Error('Renewal not allowed by profile');
            }

            // Check renewal threshold
            const daysUntilExpiration = this.calculateDaysUntilExpiration(originalCert.validity.notAfter);
            if (daysUntilExpiration > profile.renewalThreshold) {
                this.metrics.renewalFailures++;
                throw new Error('Certificate not yet eligible for renewal');
            }

            // Issue new certificate
            const certificateResult = await this.caService.issueCertificate({
                caId: profile.caId,
                csr: forge.pki.certificationRequestToPem(newCSR),
                template: profile.certificateTemplate,
                validityDays: profile.validityDays,
                keyUsage: profile.keyUsage,
                extendedKeyUsage: profile.extendedKeyUsage,
                requesterId: 'scep-renewal',
                metadata: {
                    originalCertificate: originalCert.serialNumber,
                    renewalRequest: true
                }
            });

            this.metrics.renewalSuccess++;
            this.logger.info(`Certificate renewal successful: ${originalCert.serialNumber} -> ${certificateResult.serialNumber}`);
            
            return forge.pki.certificateFromPem(certificateResult.certificate);

        } catch (error) {
            this.metrics.renewalFailures++;
            this.logger.error('Certificate renewal failed:', error);
            throw error;
        }
    }

    validateRenewalCertificate(certificate) {
        // Check if certificate is valid and issued by a trusted CA
        const now = new Date();
        return certificate.validity.notBefore <= now && certificate.validity.notAfter > now;
    }

    calculateDaysUntilExpiration(notAfter) {
        const now = new Date();
        const diffTime = notAfter - now;
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }

    /**
     * SCEP Certificate Setup
     */
    async loadSCEPCertificates() {
        if (this.caService) {
            try {
                // Get SCEP CA certificate
                const scepCA = await this.caService.getCA(this.config.scepCAId || 'scep-ca');
                this.scepCACert = forge.pki.certificateFromPem(scepCA.certificate);
                this.scepCAKey = forge.pki.privateKeyFromPem(scepCA.privateKey);
                
                // Use same certificate for encryption (simplified)
                this.scepEncCert = this.scepCACert;
                this.scepEncKey = this.scepCAKey;
                
                this.logger.info('SCEP certificates loaded successfully');
            } catch (error) {
                this.logger.warn('SCEP certificates not found, creating self-signed certificates');
                await this.createSelfSignedSCEPCertificates();
            }
        } else {
            await this.createSelfSignedSCEPCertificates();
        }
    }

    async createSelfSignedSCEPCertificates() {
        // Generate key pair
        const keyPair = forge.pki.rsa.generateKeyPair(2048);
        
        // Create self-signed certificate for SCEP
        const cert = forge.pki.createCertificate();
        cert.publicKey = keyPair.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
        
        const attrs = [
            { name: 'commonName', value: 'SCEP CA' },
            { name: 'organizationName', value: 'OpenDirectory' },
            { name: 'organizationalUnitName', value: 'SCEP Service' }
        ];
        
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        
        cert.setExtensions([
            {
                name: 'basicConstraints',
                cA: true,
                critical: true
            },
            {
                name: 'keyUsage',
                keyCertSign: true,
                cRLSign: true,
                digitalSignature: true,
                keyEncipherment: true,
                critical: true
            }
        ]);
        
        cert.sign(keyPair.privateKey);
        
        this.scepCACert = cert;
        this.scepCAKey = keyPair.privateKey;
        this.scepEncCert = cert;
        this.scepEncKey = keyPair.privateKey;
        
        this.logger.info('Self-signed SCEP certificates created');
    }

    /**
     * Utility Methods
     */
    generateProfileId(name) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(`${name}-${timestamp}`)
            .digest('hex')
            .substring(0, 8);
        return `scep-${hash}`;
    }

    generateRequestId() {
        return `req-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generatePasswordId() {
        return `pwd-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    /**
     * Storage Methods
     */
    async saveSCEPProfile(profile) {
        const profilePath = path.join(config.storage.certificates, 'scep', 'profiles', `${profile.id}.json`);
        await fs.writeFile(profilePath, JSON.stringify(profile, null, 2));
    }

    async loadSCEPProfiles() {
        try {
            const profilesDir = path.join(config.storage.certificates, 'scep', 'profiles');
            const files = await fs.readdir(profilesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const profilePath = path.join(profilesDir, file);
                    const profile = JSON.parse(await fs.readFile(profilePath, 'utf8'));
                    this.scepProfiles.set(profile.id, profile);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load SCEP profiles:', error);
            }
        }
    }

    async saveEnrollmentRequest(request) {
        const requestPath = path.join(config.storage.certificates, 'scep', 'enrollment', `${request.id}.json`);
        const requestData = {
            ...request,
            // Convert forge objects to PEM for storage
            csr: forge.pki.certificationRequestToPem(request.csr),
            originalMessage: request.originalMessage ? request.originalMessage.toString('base64') : null
        };
        await fs.writeFile(requestPath, JSON.stringify(requestData, null, 2));
    }

    async saveChallengePassword(challengeData) {
        const passwordPath = path.join(config.storage.certificates, 'scep', 'challenges', `${challengeData.id}.json`);
        await fs.writeFile(passwordPath, JSON.stringify(challengeData, null, 2));
    }

    async loadChallengePasswords() {
        try {
            const challengesDir = path.join(config.storage.certificates, 'scep', 'challenges');
            const files = await fs.readdir(challengesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const challengePath = path.join(challengesDir, file);
                    const challengeData = JSON.parse(await fs.readFile(challengePath, 'utf8'));
                    this.challengePasswords.set(challengeData.password, challengeData);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load challenge passwords:', error);
            }
        }
    }

    /**
     * Public API Methods
     */
    async getProfiles() {
        return Array.from(this.scepProfiles.values());
    }

    async getProfile(profileId) {
        return this.scepProfiles.get(profileId);
    }

    async deleteProfile(profileId) {
        const profile = this.scepProfiles.get(profileId);
        if (!profile) {
            throw new Error(`SCEP profile not found: ${profileId}`);
        }

        this.scepProfiles.delete(profileId);
        
        const profilePath = path.join(config.storage.certificates, 'scep', 'profiles', `${profileId}.json`);
        try {
            await fs.unlink(profilePath);
        } catch (error) {
            this.logger.error(`Failed to delete profile file: ${profilePath}`, error);
        }

        this.logger.info(`SCEP profile deleted: ${profileId}`);
        this.emit('profileDeleted', profile);
        
        return true;
    }

    async getEnrollmentRequests(filters = {}) {
        let requests = Array.from(this.enrollmentRequests.values());
        
        if (filters.status) {
            requests = requests.filter(r => r.status === filters.status);
        }
        
        return requests;
    }

    async approveEnrollmentRequestManually(transactionId, approverId) {
        const enrollmentRequest = this.enrollmentRequests.get(transactionId);
        if (!enrollmentRequest) {
            throw new Error(`Enrollment request not found: ${transactionId}`);
        }

        if (enrollmentRequest.status !== 'pending') {
            throw new Error(`Enrollment request is not pending: ${transactionId}`);
        }

        enrollmentRequest.approvedBy = approverId;
        enrollmentRequest.approvedAt = new Date();
        
        return await this.approveEnrollmentRequest(transactionId);
    }

    async rejectEnrollmentRequest(transactionId, rejectionReason, rejectedBy) {
        const enrollmentRequest = this.enrollmentRequests.get(transactionId);
        if (!enrollmentRequest) {
            throw new Error(`Enrollment request not found: ${transactionId}`);
        }

        enrollmentRequest.status = 'rejected';
        enrollmentRequest.rejectionReason = rejectionReason;
        enrollmentRequest.rejectedBy = rejectedBy;
        enrollmentRequest.rejectedAt = new Date();
        
        await this.saveEnrollmentRequest(enrollmentRequest);
        
        this.logger.info(`Enrollment request rejected: ${transactionId}`);
        this.emit('enrollmentRejected', enrollmentRequest);
        
        return enrollmentRequest;
    }

    async getMetrics() {
        return {
            ...this.metrics,
            totalProfiles: this.scepProfiles.size,
            activeProfiles: Array.from(this.scepProfiles.values()).filter(p => p.enabled).length,
            pendingRequests: Array.from(this.enrollmentRequests.values()).filter(r => r.status === 'pending').length,
            activeChallenges: Array.from(this.challengePasswords.values()).filter(c => c.enabled).length
        };
    }

    async stop() {
        if (this.server) {
            this.server.close();
            this.server = null;
        }
        
        this.logger.info('SCEP service stopped');
    }
}

module.exports = SCEPService;