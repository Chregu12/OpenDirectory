/**
 * OpenDirectory PKI Security Engine
 * Advanced PKI security management and certificate handling
 * 
 * Features:
 * - Code signing certificates
 * - SSL/TLS certificate management
 * - S/MIME certificates for email
 * - Client authentication certificates
 * - Device certificates (IoT/mobile)
 * - Certificate transparency monitoring
 * - Key escrow and recovery
 * - HSM (Hardware Security Module) integration
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');
const winston = require('winston');
const axios = require('axios');
const EventEmitter = require('events');

class PKISecurityEngine extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            storagePath: config.storagePath || '/var/lib/opendirectory/pki-security',
            hsmConfig: config.hsmConfig || null,
            keyEscrowConfig: config.keyEscrowConfig || null,
            certificateTransparencyLogs: config.certificateTransparencyLogs || [
                'https://ct.googleapis.com/logs/argon2024/',
                'https://ct.googleapis.com/logs/xenon2024/'
            ],
            timestampingService: config.timestampingService || 'https://freetsa.org/tsr',
            ocspResponderUrl: config.ocspResponderUrl || 'http://localhost:8080/ocsp',
            codeSigningPolicy: config.codeSigningPolicy || {},
            sslTlsPolicy: config.sslTlsPolicy || {},
            smimePolicy: config.smimePolicy || {},
            clientAuthPolicy: config.clientAuthPolicy || {},
            deviceCertPolicy: config.deviceCertPolicy || {},
            ...config
        };

        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ filename: '/var/log/opendirectory-pki-security.log' }),
                new winston.transports.Console()
            ]
        });

        // Core stores
        this.codeSigningCertificates = new Map();
        this.sslTlsCertificates = new Map();
        this.smimeCertificates = new Map();
        this.clientAuthCertificates = new Map();
        this.deviceCertificates = new Map();
        this.keyEscrowRecords = new Map();
        this.certificateTransparencyRecords = new Map();
        this.timestampTokens = new Map();
        this.trustedRoots = new Map();
        this.certificatePolicies = new Map();

        // HSM integration
        this.hsmProvider = null;
        this.hsmSessions = new Map();

        // Security metrics
        this.securityMetrics = {
            totalCodeSigningCerts: 0,
            activeSslTlsCerts: 0,
            smimeCertsIssued: 0,
            clientAuthCertsActive: 0,
            deviceCertsDeployed: 0,
            keyEscrowRecords: 0,
            ctLogEntries: 0,
            securityViolations: 0,
            hsmOperations: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.initializeHSM();
            await this.loadTrustedRoots();
            await this.loadCertificatePolicies();
            await this.startSecurityMonitoring();
            
            this.logger.info('PKI Security Engine initialized successfully');
        } catch (error) {
            this.logger.error('Failed to initialize PKI Security Engine:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            this.config.storagePath,
            path.join(this.config.storagePath, 'code-signing'),
            path.join(this.config.storagePath, 'ssl-tls'),
            path.join(this.config.storagePath, 'smime'),
            path.join(this.config.storagePath, 'client-auth'),
            path.join(this.config.storagePath, 'device-certs'),
            path.join(this.config.storagePath, 'key-escrow'),
            path.join(this.config.storagePath, 'ct-logs'),
            path.join(this.config.storagePath, 'trusted-roots'),
            path.join(this.config.storagePath, 'policies'),
            path.join(this.config.storagePath, 'hsm-keys')
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
     * Code Signing Certificate Management
     */
    async createCodeSigningCertificate(request) {
        try {
            this.validateCodeSigningRequest(request);

            const keyPair = await this.generateKeyPair(request.keySize || 3072, 'RSA');
            const csr = await this.createCodeSigningCSR(request, keyPair);

            // Enhanced security for code signing
            let privateKey = keyPair.privateKey;
            if (this.hsmProvider && request.useHSM) {
                privateKey = await this.storeKeyInHSM(keyPair.privateKey, `codesign-${request.subject.commonName}`);
            } else if (request.keyEscrow) {
                await this.escrowKey(keyPair.privateKey, request.subject.commonName, 'code-signing');
            }

            const signedCertificate = await this.signCertificate(csr, 'code-signing');

            const certificate = {
                id: this.generateCertificateId('cs'),
                type: 'code-signing',
                subject: request.subject,
                serialNumber: this.extractSerialNumber(signedCertificate),
                certificate: signedCertificate,
                privateKey: request.useHSM ? null : privateKey,
                publicKey: keyPair.publicKey,
                hsmKeyId: request.useHSM ? privateKey.keyId : null,
                keyUsage: ['digitalSignature', 'nonRepudiation'],
                extendedKeyUsage: ['codeSigning'],
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                signingPolicy: request.signingPolicy || this.config.codeSigningPolicy,
                timestampingRequired: request.timestampingRequired !== false,
                createdAt: new Date(),
                status: 'active',
                metadata: request.metadata || {}
            };

            this.codeSigningCertificates.set(certificate.id, certificate);
            await this.saveCertificate(certificate, 'code-signing');

            // Submit to Certificate Transparency logs
            if (request.submitToCT !== false) {
                await this.submitToCertificateTransparency(certificate);
            }

            this.securityMetrics.totalCodeSigningCerts++;
            this.logger.info(`Code signing certificate created: ${certificate.id}`);
            this.emit('codeSigningCertificateCreated', certificate);

            return certificate;

        } catch (error) {
            this.logger.error('Failed to create code signing certificate:', error);
            throw error;
        }
    }

    async signCode(certificateId, codeData, options = {}) {
        try {
            const certificate = this.codeSigningCertificates.get(certificateId);
            if (!certificate) throw new Error(`Code signing certificate not found: ${certificateId}`);

            if (certificate.status !== 'active') {
                throw new Error(`Certificate is not active: ${certificateId}`);
            }

            // Validate signing policy
            await this.validateSigningPolicy(certificate, codeData, options);

            // Get private key (from HSM or local storage)
            const privateKey = certificate.hsmKeyId 
                ? await this.getHSMKey(certificate.hsmKeyId)
                : certificate.privateKey;

            // Create signature
            const signature = this.createCodeSignature(codeData, privateKey, certificate);

            // Generate timestamp token if required
            let timestampToken = null;
            if (certificate.timestampingRequired || options.timestamp) {
                timestampToken = await this.getTimestampToken(signature);
            }

            const signedCode = {
                id: this.generateOperationId(),
                certificateId,
                originalHash: crypto.createHash('sha256').update(codeData).digest('hex'),
                signature,
                timestampToken,
                signedAt: new Date(),
                signingOptions: options,
                metadata: {
                    algorithm: certificate.signingPolicy.algorithm || 'SHA-256withRSA',
                    certificateChain: await this.getCertificateChain(certificateId)
                }
            };

            await this.saveSignedCodeRecord(signedCode);

            this.logger.info(`Code signed successfully: ${signedCode.id}`);
            this.emit('codeSigned', signedCode);

            return signedCode;

        } catch (error) {
            this.securityMetrics.securityViolations++;
            this.logger.error('Code signing failed:', error);
            throw error;
        }
    }

    /**
     * SSL/TLS Certificate Management
     */
    async createSSLTLSCertificate(request) {
        try {
            this.validateSSLTLSRequest(request);

            const keyPair = await this.generateKeyPair(request.keySize || 2048, 'RSA');
            const csr = await this.createSSLTLSCSR(request, keyPair);
            const signedCertificate = await this.signCertificate(csr, 'ssl-tls');

            const certificate = {
                id: this.generateCertificateId('ssl'),
                type: 'ssl-tls',
                subject: request.subject,
                subjectAltName: request.subjectAltName || [],
                serialNumber: this.extractSerialNumber(signedCertificate),
                certificate: signedCertificate,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                keyUsage: ['digitalSignature', 'keyEncipherment'],
                extendedKeyUsage: ['serverAuth', 'clientAuth'],
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                domains: this.extractDomains(request.subjectAltName),
                sslPolicy: request.sslPolicy || this.config.sslTlsPolicy,
                ocspMustStaple: request.ocspMustStaple !== false,
                createdAt: new Date(),
                status: 'active',
                deploymentTargets: request.deploymentTargets || [],
                metadata: request.metadata || {}
            };

            this.sslTlsCertificates.set(certificate.id, certificate);
            await this.saveCertificate(certificate, 'ssl-tls');

            // Auto-deploy to specified targets
            if (certificate.deploymentTargets.length > 0) {
                await this.deploySSLCertificate(certificate);
            }

            // Submit to Certificate Transparency
            await this.submitToCertificateTransparency(certificate);

            this.securityMetrics.activeSslTlsCerts++;
            this.logger.info(`SSL/TLS certificate created: ${certificate.id}`);
            this.emit('sslTlsCertificateCreated', certificate);

            return certificate;

        } catch (error) {
            this.logger.error('Failed to create SSL/TLS certificate:', error);
            throw error;
        }
    }

    async validateSSLConnection(certificateId, hostname, port = 443) {
        try {
            const certificate = this.sslTlsCertificates.get(certificateId);
            if (!certificate) throw new Error(`SSL certificate not found: ${certificateId}`);

            const validation = {
                certificateId,
                hostname,
                port,
                validationTime: new Date(),
                status: 'unknown',
                details: {}
            };

            // Perform SSL handshake validation
            const sslValidation = await this.performSSLHandshake(hostname, port);
            validation.details.handshake = sslValidation;

            // Certificate chain validation
            const chainValidation = await this.validateCertificateChain(sslValidation.certificateChain);
            validation.details.chainValidation = chainValidation;

            // OCSP validation
            const ocspValidation = await this.validateOCSP(certificate);
            validation.details.ocspValidation = ocspValidation;

            // Policy compliance
            const policyCompliance = await this.validateSSLPolicy(certificate, sslValidation);
            validation.details.policyCompliance = policyCompliance;

            validation.status = this.calculateSSLValidationStatus(validation.details);

            this.logger.info(`SSL validation completed: ${certificateId}, status: ${validation.status}`);
            return validation;

        } catch (error) {
            this.logger.error('SSL validation failed:', error);
            throw error;
        }
    }

    /**
     * S/MIME Certificate Management
     */
    async createSMIMECertificate(request) {
        try {
            this.validateSMIMERequest(request);

            const keyPair = await this.generateKeyPair(request.keySize || 2048, 'RSA');
            const csr = await this.createSMIMECSR(request, keyPair);
            const signedCertificate = await this.signCertificate(csr, 'smime');

            const certificate = {
                id: this.generateCertificateId('smime'),
                type: 's-mime',
                subject: request.subject,
                emailAddress: request.emailAddress,
                serialNumber: this.extractSerialNumber(signedCertificate),
                certificate: signedCertificate,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                keyUsage: ['digitalSignature', 'keyEncipherment', 'nonRepudiation'],
                extendedKeyUsage: ['emailProtection'],
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                smimePolicy: request.smimePolicy || this.config.smimePolicy,
                encryptionAlgorithms: request.encryptionAlgorithms || ['AES-256', 'AES-128'],
                createdAt: new Date(),
                status: 'active',
                metadata: request.metadata || {}
            };

            this.smimeCertificates.set(certificate.id, certificate);
            await this.saveCertificate(certificate, 'smime');

            // Export for email client installation
            const p12Bundle = await this.createP12Bundle(certificate, request.p12Password);
            certificate.p12Bundle = p12Bundle;

            this.securityMetrics.smimeCertsIssued++;
            this.logger.info(`S/MIME certificate created: ${certificate.id}`);
            this.emit('smimeCertificateCreated', certificate);

            return certificate;

        } catch (error) {
            this.logger.error('Failed to create S/MIME certificate:', error);
            throw error;
        }
    }

    async signEmail(certificateId, emailData, options = {}) {
        try {
            const certificate = this.smimeCertificates.get(certificateId);
            if (!certificate) throw new Error(`S/MIME certificate not found: ${certificateId}`);

            if (certificate.status !== 'active') {
                throw new Error(`Certificate is not active: ${certificateId}`);
            }

            // Create S/MIME signed message
            const signedMessage = await this.createSMIMESignature(emailData, certificate, options);

            const signedEmail = {
                id: this.generateOperationId(),
                certificateId,
                originalMessageHash: crypto.createHash('sha256').update(emailData.content).digest('hex'),
                signedMessage,
                signedAt: new Date(),
                recipients: emailData.recipients,
                subject: emailData.subject,
                signingOptions: options
            };

            await this.saveSignedEmailRecord(signedEmail);

            this.logger.info(`Email signed successfully: ${signedEmail.id}`);
            this.emit('emailSigned', signedEmail);

            return signedEmail;

        } catch (error) {
            this.logger.error('Email signing failed:', error);
            throw error;
        }
    }

    async encryptEmail(certificateId, emailData, recipientCertificates) {
        try {
            const certificate = this.smimeCertificates.get(certificateId);
            if (!certificate) throw new Error(`S/MIME certificate not found: ${certificateId}`);

            // Create S/MIME encrypted message
            const encryptedMessage = await this.createSMIMEEncryption(
                emailData, 
                certificate, 
                recipientCertificates
            );

            const encryptedEmail = {
                id: this.generateOperationId(),
                certificateId,
                originalMessageHash: crypto.createHash('sha256').update(emailData.content).digest('hex'),
                encryptedMessage,
                encryptedAt: new Date(),
                recipients: emailData.recipients,
                subject: emailData.subject,
                encryptionAlgorithm: certificate.encryptionAlgorithms[0]
            };

            await this.saveEncryptedEmailRecord(encryptedEmail);

            this.logger.info(`Email encrypted successfully: ${encryptedEmail.id}`);
            this.emit('emailEncrypted', encryptedEmail);

            return encryptedEmail;

        } catch (error) {
            this.logger.error('Email encryption failed:', error);
            throw error;
        }
    }

    /**
     * Client Authentication Certificate Management
     */
    async createClientAuthCertificate(request) {
        try {
            this.validateClientAuthRequest(request);

            const keyPair = await this.generateKeyPair(request.keySize || 2048, 'RSA');
            const csr = await this.createClientAuthCSR(request, keyPair);
            const signedCertificate = await this.signCertificate(csr, 'client-auth');

            const certificate = {
                id: this.generateCertificateId('client'),
                type: 'client-auth',
                subject: request.subject,
                serialNumber: this.extractSerialNumber(signedCertificate),
                certificate: signedCertificate,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                keyUsage: ['digitalSignature', 'keyAgreement'],
                extendedKeyUsage: ['clientAuth'],
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                clientAuthPolicy: request.clientAuthPolicy || this.config.clientAuthPolicy,
                allowedServices: request.allowedServices || [],
                accessLevel: request.accessLevel || 'standard',
                createdAt: new Date(),
                status: 'active',
                userId: request.userId,
                deviceId: request.deviceId,
                metadata: request.metadata || {}
            };

            this.clientAuthCertificates.set(certificate.id, certificate);
            await this.saveCertificate(certificate, 'client-auth');

            this.securityMetrics.clientAuthCertsActive++;
            this.logger.info(`Client authentication certificate created: ${certificate.id}`);
            this.emit('clientAuthCertificateCreated', certificate);

            return certificate;

        } catch (error) {
            this.logger.error('Failed to create client authentication certificate:', error);
            throw error;
        }
    }

    async authenticateClient(certificateData, serviceId) {
        try {
            // Parse and validate client certificate
            const clientCert = forge.pki.certificateFromPem(certificateData);
            const serialNumber = clientCert.serialNumber;

            // Find matching certificate in our store
            let certificate = null;
            for (const [certId, cert] of this.clientAuthCertificates) {
                if (cert.serialNumber === serialNumber) {
                    certificate = cert;
                    break;
                }
            }

            if (!certificate) {
                throw new Error(`Client certificate not found: ${serialNumber}`);
            }

            if (certificate.status !== 'active') {
                throw new Error(`Certificate is not active: ${certificate.id}`);
            }

            // Validate certificate chain and revocation status
            const validation = await this.validateClientCertificate(clientCert);
            if (!validation.valid) {
                throw new Error(`Certificate validation failed: ${validation.error}`);
            }

            // Check service access permissions
            if (certificate.allowedServices.length > 0 && 
                !certificate.allowedServices.includes(serviceId)) {
                throw new Error(`Access denied to service: ${serviceId}`);
            }

            const authResult = {
                certificateId: certificate.id,
                userId: certificate.userId,
                deviceId: certificate.deviceId,
                accessLevel: certificate.accessLevel,
                serviceId,
                authenticatedAt: new Date(),
                clientCertificate: certificate,
                valid: true
            };

            await this.saveAuthenticationRecord(authResult);

            this.logger.info(`Client authenticated successfully: ${certificate.id}, service: ${serviceId}`);
            this.emit('clientAuthenticated', authResult);

            return authResult;

        } catch (error) {
            this.securityMetrics.securityViolations++;
            this.logger.error('Client authentication failed:', error);
            throw error;
        }
    }

    /**
     * Device Certificate Management (IoT/Mobile)
     */
    async createDeviceCertificate(request) {
        try {
            this.validateDeviceCertRequest(request);

            const keyPair = await this.generateKeyPair(request.keySize || 2048, request.keyAlgorithm || 'EC');
            const csr = await this.createDeviceCSR(request, keyPair);
            const signedCertificate = await this.signCertificate(csr, 'device');

            const certificate = {
                id: this.generateCertificateId('device'),
                type: 'device',
                subject: request.subject,
                serialNumber: this.extractSerialNumber(signedCertificate),
                certificate: signedCertificate,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                keyUsage: ['digitalSignature', 'keyAgreement'],
                extendedKeyUsage: ['clientAuth', 'serverAuth'],
                notBefore: this.extractNotBefore(signedCertificate),
                notAfter: this.extractNotAfter(signedCertificate),
                deviceType: request.deviceType, // 'mobile', 'iot', 'server', etc.
                deviceId: request.deviceId,
                deviceInfo: request.deviceInfo || {},
                devicePolicy: request.devicePolicy || this.config.deviceCertPolicy,
                attestationData: request.attestationData,
                createdAt: new Date(),
                status: 'active',
                metadata: request.metadata || {}
            };

            this.deviceCertificates.set(certificate.id, certificate);
            await this.saveCertificate(certificate, 'device-certs');

            // Device-specific deployment
            if (request.autoInstall) {
                await this.installDeviceCertificate(certificate);
            }

            this.securityMetrics.deviceCertsDeployed++;
            this.logger.info(`Device certificate created: ${certificate.id}, type: ${request.deviceType}`);
            this.emit('deviceCertificateCreated', certificate);

            return certificate;

        } catch (error) {
            this.logger.error('Failed to create device certificate:', error);
            throw error;
        }
    }

    async attestDevice(certificateId, challengeData) {
        try {
            const certificate = this.deviceCertificates.get(certificateId);
            if (!certificate) throw new Error(`Device certificate not found: ${certificateId}`);

            // Verify device attestation
            const attestation = await this.verifyDeviceAttestation(
                certificate,
                challengeData,
                certificate.attestationData
            );

            const attestationResult = {
                certificateId,
                challenge: challengeData,
                attestationVerified: attestation.verified,
                deviceIntegrityStatus: attestation.integrityStatus,
                attestedAt: new Date(),
                attestationDetails: attestation.details
            };

            await this.saveDeviceAttestationRecord(attestationResult);

            this.logger.info(`Device attestation completed: ${certificateId}, ` +
                `verified: ${attestation.verified}`);
            this.emit('deviceAttested', attestationResult);

            return attestationResult;

        } catch (error) {
            this.logger.error('Device attestation failed:', error);
            throw error;
        }
    }

    /**
     * Certificate Transparency Monitoring
     */
    async submitToCertificateTransparency(certificate) {
        try {
            const submissions = [];

            for (const ctLogUrl of this.config.certificateTransparencyLogs) {
                try {
                    const submission = await this.submitToCTLog(certificate, ctLogUrl);
                    submissions.push({
                        logUrl: ctLogUrl,
                        success: true,
                        sct: submission.sct,
                        timestamp: submission.timestamp
                    });
                } catch (error) {
                    submissions.push({
                        logUrl: ctLogUrl,
                        success: false,
                        error: error.message
                    });
                }
            }

            const ctRecord = {
                certificateId: certificate.id,
                certificateType: certificate.type,
                submissions,
                submittedAt: new Date(),
                totalLogs: this.config.certificateTransparencyLogs.length,
                successfulSubmissions: submissions.filter(s => s.success).length
            };

            this.certificateTransparencyRecords.set(certificate.id, ctRecord);
            await this.saveCTRecord(ctRecord);

            this.securityMetrics.ctLogEntries++;
            this.logger.info(`Certificate submitted to CT logs: ${certificate.id}, ` +
                `successful: ${ctRecord.successfulSubmissions}/${ctRecord.totalLogs}`);

            return ctRecord;

        } catch (error) {
            this.logger.error('CT submission failed:', error);
            throw error;
        }
    }

    async monitorCertificateTransparency() {
        try {
            const monitoringResults = [];

            for (const [certId, ctRecord] of this.certificateTransparencyRecords) {
                const certificate = this.getCertificateById(certId);
                if (!certificate) continue;

                for (const submission of ctRecord.submissions) {
                    if (!submission.success) continue;

                    try {
                        const logEntries = await this.searchCTLog(submission.logUrl, certificate.serialNumber);
                        const monitoring = {
                            certificateId: certId,
                            logUrl: submission.logUrl,
                            entriesFound: logEntries.length,
                            entries: logEntries,
                            monitoredAt: new Date()
                        };
                        monitoringResults.push(monitoring);

                        // Check for suspicious entries
                        await this.analyzeCTEntries(certificate, logEntries);

                    } catch (error) {
                        this.logger.warn(`CT monitoring failed for ${submission.logUrl}:`, error);
                    }
                }
            }

            this.logger.info(`CT monitoring completed: ${monitoringResults.length} logs checked`);
            return monitoringResults;

        } catch (error) {
            this.logger.error('CT monitoring failed:', error);
            throw error;
        }
    }

    /**
     * Key Escrow and Recovery
     */
    async escrowKey(privateKey, keyOwner, keyType, metadata = {}) {
        try {
            const escrowId = this.generateEscrowId();
            
            // Encrypt private key for escrow storage
            const encryptedKey = await this.encryptForEscrow(privateKey);
            
            const escrowRecord = {
                id: escrowId,
                keyOwner,
                keyType, // 'code-signing', 'ssl-tls', 's-mime', etc.
                encryptedPrivateKey: encryptedKey.encryptedData,
                keyFingerprint: this.calculateKeyFingerprint(privateKey),
                escrowMetadata: metadata,
                escrowAgents: this.config.keyEscrowConfig?.agents || [],
                recoveryPolicy: this.config.keyEscrowConfig?.recoveryPolicy || {},
                escrowedAt: new Date(),
                status: 'active',
                accessLog: []
            };

            this.keyEscrowRecords.set(escrowId, escrowRecord);
            await this.saveEscrowRecord(escrowRecord);

            this.securityMetrics.keyEscrowRecords++;
            this.logger.info(`Key escrowed: ${escrowId}, owner: ${keyOwner}, type: ${keyType}`);
            this.emit('keyEscrowed', escrowRecord);

            return escrowId;

        } catch (error) {
            this.logger.error('Key escrow failed:', error);
            throw error;
        }
    }

    async recoverKey(escrowId, requester, justification) {
        try {
            const escrowRecord = this.keyEscrowRecords.get(escrowId);
            if (!escrowRecord) throw new Error(`Escrow record not found: ${escrowId}`);

            if (escrowRecord.status !== 'active') {
                throw new Error(`Escrow record is not active: ${escrowId}`);
            }

            // Validate recovery authorization
            await this.validateKeyRecoveryAuthorization(escrowRecord, requester, justification);

            // Decrypt escrowed key
            const recoveredKey = await this.decryptFromEscrow(escrowRecord.encryptedPrivateKey);

            // Log recovery access
            const accessLogEntry = {
                requester,
                justification,
                recoveredAt: new Date(),
                ipAddress: this.getRequesterIP(),
                success: true
            };

            escrowRecord.accessLog.push(accessLogEntry);
            await this.saveEscrowRecord(escrowRecord);

            this.logger.info(`Key recovered: ${escrowId}, requester: ${requester}`);
            this.emit('keyRecovered', escrowRecord, accessLogEntry);

            return {
                escrowId,
                privateKey: recoveredKey,
                keyFingerprint: escrowRecord.keyFingerprint,
                recoveryInfo: accessLogEntry
            };

        } catch (error) {
            const escrowRecord = this.keyEscrowRecords.get(escrowId);
            if (escrowRecord) {
                escrowRecord.accessLog.push({
                    requester,
                    justification,
                    recoveredAt: new Date(),
                    success: false,
                    error: error.message
                });
                await this.saveEscrowRecord(escrowRecord);
            }

            this.securityMetrics.securityViolations++;
            this.logger.error('Key recovery failed:', error);
            throw error;
        }
    }

    /**
     * HSM (Hardware Security Module) Integration
     */
    async initializeHSM() {
        if (!this.config.hsmConfig) return;

        try {
            // Initialize HSM provider based on configuration
            switch (this.config.hsmConfig.provider) {
                case 'pkcs11':
                    this.hsmProvider = await this.initializePKCS11HSM(this.config.hsmConfig);
                    break;
                case 'aws-kms':
                    this.hsmProvider = await this.initializeAWSKMS(this.config.hsmConfig);
                    break;
                case 'azure-keyvault':
                    this.hsmProvider = await this.initializeAzureKeyVault(this.config.hsmConfig);
                    break;
                default:
                    throw new Error(`Unsupported HSM provider: ${this.config.hsmConfig.provider}`);
            }

            this.logger.info(`HSM initialized: ${this.config.hsmConfig.provider}`);

        } catch (error) {
            this.logger.error('HSM initialization failed:', error);
            throw error;
        }
    }

    async storeKeyInHSM(privateKey, keyLabel) {
        if (!this.hsmProvider) throw new Error('HSM not initialized');

        try {
            const keyId = await this.hsmProvider.importKey(privateKey, keyLabel, {
                extractable: false,
                keyUsage: ['sign'],
                algorithm: 'RSA'
            });

            this.securityMetrics.hsmOperations++;
            this.logger.info(`Key stored in HSM: ${keyLabel}, ID: ${keyId}`);

            return { keyId, label: keyLabel, provider: this.config.hsmConfig.provider };

        } catch (error) {
            this.logger.error('HSM key storage failed:', error);
            throw error;
        }
    }

    async getHSMKey(keyId) {
        if (!this.hsmProvider) throw new Error('HSM not initialized');

        try {
            const hsmKey = await this.hsmProvider.getKey(keyId);
            this.securityMetrics.hsmOperations++;
            return hsmKey;

        } catch (error) {
            this.logger.error('HSM key retrieval failed:', error);
            throw error;
        }
    }

    async signWithHSM(keyId, data, algorithm = 'SHA-256withRSA') {
        if (!this.hsmProvider) throw new Error('HSM not initialized');

        try {
            const signature = await this.hsmProvider.sign(keyId, data, algorithm);
            this.securityMetrics.hsmOperations++;
            return signature;

        } catch (error) {
            this.logger.error('HSM signing failed:', error);
            throw error;
        }
    }

    /**
     * Security Monitoring and Analytics
     */
    async startSecurityMonitoring() {
        // Monitor certificate usage patterns
        setInterval(async () => {
            await this.analyzeSecurityMetrics();
        }, 60000); // Every minute

        // Daily security report
        setInterval(async () => {
            await this.generateSecurityReport();
        }, 24 * 60 * 60 * 1000); // Daily

        this.logger.info('Security monitoring started');
    }

    async analyzeSecurityMetrics() {
        try {
            const analysis = {
                timestamp: new Date(),
                metrics: { ...this.securityMetrics },
                alerts: []
            };

            // Check for security violations spike
            if (this.securityMetrics.securityViolations > this.getViolationThreshold()) {
                analysis.alerts.push({
                    type: 'security_violations_spike',
                    severity: 'high',
                    message: 'Unusual number of security violations detected',
                    count: this.securityMetrics.securityViolations
                });
            }

            // Check certificate expiration patterns
            const expiringCerts = await this.getExpiringCertificates(30); // 30 days
            if (expiringCerts.length > 10) {
                analysis.alerts.push({
                    type: 'mass_expiration',
                    severity: 'medium',
                    message: 'Large number of certificates expiring soon',
                    count: expiringCerts.length
                });
            }

            // HSM health check
            if (this.hsmProvider) {
                const hsmHealth = await this.checkHSMHealth();
                if (!hsmHealth.healthy) {
                    analysis.alerts.push({
                        type: 'hsm_unhealthy',
                        severity: 'critical',
                        message: 'HSM health check failed',
                        details: hsmHealth.details
                    });
                }
            }

            // Process alerts
            for (const alert of analysis.alerts) {
                await this.processSecurityAlert(alert);
            }

            return analysis;

        } catch (error) {
            this.logger.error('Security metrics analysis failed:', error);
        }
    }

    async generateSecurityReport() {
        try {
            const report = {
                reportDate: new Date(),
                period: '24h',
                summary: {
                    ...this.securityMetrics,
                    certificatesIssued: this.calculateCertificatesIssuedToday(),
                    certificatesRevoked: this.calculateCertificatesRevokedToday(),
                    securityAlerts: this.getSecurityAlertsToday()
                },
                certificateBreakdown: {
                    codeSigningActive: this.getActiveCertificateCount('code-signing'),
                    sslTlsActive: this.getActiveCertificateCount('ssl-tls'),
                    smimeActive: this.getActiveCertificateCount('s-mime'),
                    clientAuthActive: this.getActiveCertificateCount('client-auth'),
                    deviceActive: this.getActiveCertificateCount('device')
                },
                securityEvents: await this.getRecentSecurityEvents(),
                recommendations: await this.generateSecurityRecommendations()
            };

            await this.saveSecurityReport(report);

            this.logger.info('Security report generated');
            this.emit('securityReportGenerated', report);

            return report;

        } catch (error) {
            this.logger.error('Security report generation failed:', error);
            throw error;
        }
    }

    /**
     * Utility Methods
     */
    generateCertificateId(type) {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `${type}-${timestamp}-${random.toString(16)}`;
    }

    generateOperationId() {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `op-${timestamp}-${random.toString(16)}`;
    }

    generateEscrowId() {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFFFF);
        return `escrow-${timestamp}-${random.toString(16)}`;
    }

    async generateKeyPair(keySize, algorithm = 'RSA') {
        return new Promise((resolve, reject) => {
            if (algorithm === 'RSA') {
                forge.pki.rsa.generateKeyPair(keySize, (err, keyPair) => {
                    if (err) reject(err);
                    else resolve(keyPair);
                });
            } else if (algorithm === 'EC') {
                // Elliptic curve key generation
                const keys = forge.pki.ed25519.generateKeyPair();
                resolve(keys);
            } else {
                reject(new Error(`Unsupported algorithm: ${algorithm}`));
            }
        });
    }

    getCertificateById(certificateId) {
        return this.codeSigningCertificates.get(certificateId) ||
               this.sslTlsCertificates.get(certificateId) ||
               this.smimeCertificates.get(certificateId) ||
               this.clientAuthCertificates.get(certificateId) ||
               this.deviceCertificates.get(certificateId);
    }

    calculateKeyFingerprint(privateKey) {
        // Generate SHA-256 fingerprint of the private key
        const keyDer = forge.pki.privateKeyToAsn1(privateKey);
        const keyBytes = forge.asn1.toDer(keyDer).getBytes();
        return crypto.createHash('sha256').update(keyBytes).digest('hex');
    }

    /**
     * Validation Methods (placeholder implementations)
     */
    validateCodeSigningRequest(request) {
        if (!request.subject || !request.subject.commonName) {
            throw new Error('Code signing certificate requires subject.commonName');
        }
    }

    validateSSLTLSRequest(request) {
        if (!request.subject || !request.subjectAltName || request.subjectAltName.length === 0) {
            throw new Error('SSL/TLS certificate requires subject and subjectAltName');
        }
    }

    validateSMIMERequest(request) {
        if (!request.emailAddress) {
            throw new Error('S/MIME certificate requires emailAddress');
        }
    }

    validateClientAuthRequest(request) {
        if (!request.subject || !request.userId) {
            throw new Error('Client auth certificate requires subject and userId');
        }
    }

    validateDeviceCertRequest(request) {
        if (!request.deviceId || !request.deviceType) {
            throw new Error('Device certificate requires deviceId and deviceType');
        }
    }

    /**
     * Storage Methods (placeholder implementations)
     */
    async saveCertificate(certificate, type) {
        const certPath = path.join(this.config.storagePath, type, `${certificate.id}.json`);
        await fs.writeFile(certPath, JSON.stringify(certificate, null, 2));
    }

    async saveCTRecord(ctRecord) {
        const ctPath = path.join(this.config.storagePath, 'ct-logs', `${ctRecord.certificateId}.json`);
        await fs.writeFile(ctPath, JSON.stringify(ctRecord, null, 2));
    }

    async saveEscrowRecord(escrowRecord) {
        const escrowPath = path.join(this.config.storagePath, 'key-escrow', `${escrowRecord.id}.json`);
        await fs.writeFile(escrowPath, JSON.stringify(escrowRecord, null, 2));
    }

    async saveSecurityReport(report) {
        const reportPath = path.join(this.config.storagePath, `security-report-${Date.now()}.json`);
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
    }

    // ... Additional placeholder methods for integration
    async loadTrustedRoots() { /* Implementation */ }
    async loadCertificatePolicies() { /* Implementation */ }
    async createCodeSigningCSR(request, keyPair) { /* Implementation */ return 'csr-pem'; }
    async createSSLTLSCSR(request, keyPair) { /* Implementation */ return 'csr-pem'; }
    async createSMIMECSR(request, keyPair) { /* Implementation */ return 'csr-pem'; }
    async createClientAuthCSR(request, keyPair) { /* Implementation */ return 'csr-pem'; }
    async createDeviceCSR(request, keyPair) { /* Implementation */ return 'csr-pem'; }
    async signCertificate(csr, type) { /* Implementation */ return 'signed-cert-pem'; }
    async submitToCTLog(certificate, logUrl) { /* Implementation */ return { sct: 'sct-data', timestamp: Date.now() }; }
    async searchCTLog(logUrl, serialNumber) { /* Implementation */ return []; }
    async analyzeCTEntries(certificate, entries) { /* Implementation */ }
    async encryptForEscrow(privateKey) { /* Implementation */ return { encryptedData: 'encrypted' }; }
    async decryptFromEscrow(encryptedData) { /* Implementation */ return 'decrypted-key'; }
    async validateKeyRecoveryAuthorization(escrowRecord, requester, justification) { /* Implementation */ }
    async getTimestampToken(signature) { /* Implementation */ return 'timestamp-token'; }
    async createCodeSignature(codeData, privateKey, certificate) { /* Implementation */ return 'signature'; }
    async createSMIMESignature(emailData, certificate, options) { /* Implementation */ return 'signed-message'; }
    async createSMIMEEncryption(emailData, certificate, recipientCerts) { /* Implementation */ return 'encrypted-message'; }
    async createP12Bundle(certificate, password) { /* Implementation */ return 'p12-bundle'; }
    async deploySSLCertificate(certificate) { /* Implementation */ }
    async installDeviceCertificate(certificate) { /* Implementation */ }
    async verifyDeviceAttestation(certificate, challenge, attestationData) { /* Implementation */ return { verified: true, integrityStatus: 'intact', details: {} }; }

    extractSerialNumber(certificate) { return 'serial-number'; }
    extractNotBefore(certificate) { return new Date(); }
    extractNotAfter(certificate) { return new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); }
    extractDomains(subjectAltName) { return subjectAltName.map(san => san.value); }
    getRequesterIP() { return '127.0.0.1'; }
    getViolationThreshold() { return 10; }
    getExpiringCertificates(days) { return Promise.resolve([]); }
    checkHSMHealth() { return Promise.resolve({ healthy: true, details: {} }); }
    processSecurityAlert(alert) { /* Implementation */ }
    calculateCertificatesIssuedToday() { return 0; }
    calculateCertificatesRevokedToday() { return 0; }
    getSecurityAlertsToday() { return []; }
    getActiveCertificateCount(type) { return 0; }
    getRecentSecurityEvents() { return Promise.resolve([]); }
    generateSecurityRecommendations() { return Promise.resolve([]); }

    /**
     * Public API Methods
     */
    async getMetrics() {
        return { ...this.securityMetrics };
    }

    async getCertificates(type = null) {
        const allCerts = [
            ...Array.from(this.codeSigningCertificates.values()),
            ...Array.from(this.sslTlsCertificates.values()),
            ...Array.from(this.smimeCertificates.values()),
            ...Array.from(this.clientAuthCertificates.values()),
            ...Array.from(this.deviceCertificates.values())
        ];

        return type ? allCerts.filter(cert => cert.type === type) : allCerts;
    }

    async getCertificate(certificateId) {
        return this.getCertificateById(certificateId);
    }

    async getKeyEscrowRecords() {
        return Array.from(this.keyEscrowRecords.values());
    }

    async getCertificateTransparencyRecords() {
        return Array.from(this.certificateTransparencyRecords.values());
    }
}

module.exports = PKISecurityEngine;