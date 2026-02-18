/**
 * OpenDirectory Smart Card & Token Manager
 * Advanced smart card and hardware token management system
 * 
 * Features:
 * - Smart card provisioning
 * - PIV/CAC card support
 * - FIDO2/WebAuthn integration
 * - Token lifecycle management
 * - Card reader management
 * - PIN policy enforcement
 * - Certificate-to-card binding
 * - Mobile device certificate storage
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');
const winston = require('winston');
const forge = require('node-forge');

class SmartCardTokenManager extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            storagePath: config.storagePath || '/var/lib/opendirectory/smartcard',
            cardReadersPath: config.cardReadersPath || '/var/lib/opendirectory/readers',
            pivSupport: config.pivSupport !== false,
            cacSupport: config.cacSupport !== false,
            fido2Support: config.fido2Support !== false,
            webAuthnSupport: config.webAuthnSupport !== false,
            mobileSupport: config.mobileSupport !== false,
            pinPolicyEnforcement: config.pinPolicyEnforcement !== false,
            maxPinAttempts: config.maxPinAttempts || 3,
            pinComplexityRequirements: config.pinComplexityRequirements || {
                minLength: 6,
                maxLength: 8,
                requireNumbers: true,
                requireMixedCase: false,
                requireSpecialChars: false,
                preventSequential: true,
                preventRepeating: true
            },
            cardLockoutDuration: config.cardLockoutDuration || 30 * 60 * 1000, // 30 minutes
            certificateSlots: config.certificateSlots || {
                piv: {
                    '9a': 'authentication',
                    '9c': 'digital-signature',
                    '9d': 'key-management',
                    '9e': 'card-authentication'
                },
                cac: {
                    '01': 'id-certificate',
                    '02': 'email-certificate',
                    '03': 'encryption-certificate',
                    '04': 'signature-certificate'
                }
            },
            ...config
        };

        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ filename: '/var/log/opendirectory-smartcard.log' }),
                new winston.transports.Console()
            ]
        });

        // Core data stores
        this.smartCards = new Map(); // Issued smart cards
        this.cardReaders = new Map(); // Available card readers
        this.tokenRegistry = new Map(); // Hardware tokens
        this.fido2Devices = new Map(); // FIDO2/WebAuthn devices
        this.mobileTokens = new Map(); // Mobile device certificates
        this.pinPolicies = new Map(); // PIN policies per card type
        this.provisioningTemplates = new Map(); // Card provisioning templates
        this.cardSessions = new Map(); // Active card sessions
        this.auditLog = []; // Security audit log

        // PIN management
        this.pinAttempts = new Map(); // Track failed PIN attempts
        this.lockedCards = new Map(); // Temporarily locked cards
        this.pinHistories = new Map(); // PIN change history

        // FIDO2/WebAuthn components
        this.webAuthnCredentials = new Map();
        this.attestationRecords = new Map();

        // Metrics and monitoring
        this.metrics = {
            totalCards: 0,
            activeCards: 0,
            pivCards: 0,
            cacCards: 0,
            fido2Devices: 0,
            mobileTokens: 0,
            cardReaders: 0,
            successfulAuthentications: 0,
            failedAuthentications: 0,
            pinViolations: 0,
            securityEvents: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.initializeCardReaders();
            await this.loadProvisioningTemplates();
            await this.loadPinPolicies();
            await this.loadExistingCards();
            await this.initializeFIDO2Support();
            await this.startMonitoring();
            
            this.logger.info('Smart Card & Token Manager initialized successfully');
        } catch (error) {
            this.logger.error('Failed to initialize Smart Card & Token Manager:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            this.config.storagePath,
            this.config.cardReadersPath,
            path.join(this.config.storagePath, 'piv-cards'),
            path.join(this.config.storagePath, 'cac-cards'),
            path.join(this.config.storagePath, 'fido2-devices'),
            path.join(this.config.storagePath, 'mobile-tokens'),
            path.join(this.config.storagePath, 'templates'),
            path.join(this.config.storagePath, 'pin-policies'),
            path.join(this.config.storagePath, 'audit-logs'),
            path.join(this.config.storagePath, 'reader-configs')
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
     * Smart Card Provisioning
     */
    async provisionSmartCard(provisioningRequest) {
        try {
            const { cardType, holderInfo, template, certificates, pinPolicy } = provisioningRequest;
            
            this.validateProvisioningRequest(provisioningRequest);

            const cardId = this.generateCardId(cardType);
            const card = {
                id: cardId,
                type: cardType, // 'piv', 'cac', 'generic'
                holderInfo: {
                    firstName: holderInfo.firstName,
                    lastName: holderInfo.lastName,
                    employeeId: holderInfo.employeeId,
                    organization: holderInfo.organization,
                    department: holderInfo.department,
                    email: holderInfo.email
                },
                templateId: template,
                serialNumber: this.generateSerialNumber(),
                issueDate: new Date(),
                expirationDate: this.calculateExpirationDate(template),
                status: 'provisioning',
                certificates: new Map(),
                pinPolicy: pinPolicy || this.getDefaultPinPolicy(cardType),
                pinHistory: [],
                failedPinAttempts: 0,
                lastPinChange: new Date(),
                securityDomain: this.getSecurityDomain(template),
                provisioningLog: [],
                metadata: provisioningRequest.metadata || {}
            };

            // Initialize card applets based on type
            if (cardType === 'piv') {
                await this.initializePIVCard(card);
            } else if (cardType === 'cac') {
                await this.initializeCACCard(card);
            }

            // Load certificates onto card
            for (const certRequest of certificates) {
                await this.loadCertificateToCard(card, certRequest);
            }

            // Set initial PIN
            await this.setCardPIN(card, provisioningRequest.initialPIN);

            // Finalize provisioning
            card.status = 'active';
            card.provisionedAt = new Date();

            this.smartCards.set(cardId, card);
            await this.saveCard(card);

            this.updateMetrics();
            this.logger.info(`Smart card provisioned: ${cardId}, type: ${cardType}, holder: ${holderInfo.employeeId}`);
            this.emit('cardProvisioned', card);

            return card;

        } catch (error) {
            this.logger.error('Smart card provisioning failed:', error);
            throw error;
        }
    }

    async initializePIVCard(card) {
        try {
            // PIV card initialization according to NIST SP 800-73
            card.pivData = {
                cardCapabilityContainer: this.createCCC(),
                cardHolderUniqueIdentifier: this.generateCHUID(),
                cardAuthentication: null, // Will be set when certificate is loaded
                fingerprints: [], // Biometric data if required
                facialImage: null, // Photo if required
                printedInformation: this.createPrintedInfo(card.holderInfo),
                discoveryObject: this.createDiscoveryObject(),
                keyHistoryObject: this.createKeyHistory(),
                retiredCertificates: new Map(),
                securityObject: null // Will be generated after all data is loaded
            };

            // Create default PIN policy for PIV
            if (!card.pinPolicy) {
                card.pinPolicy = {
                    type: 'piv',
                    minLength: 6,
                    maxLength: 8,
                    pinType: 'numeric',
                    maxAttempts: 3,
                    lockoutDuration: 30 * 60 * 1000
                };
            }

            this.logger.info(`PIV card initialized: ${card.id}`);

        } catch (error) {
            this.logger.error('PIV card initialization failed:', error);
            throw error;
        }
    }

    async initializeCACCard(card) {
        try {
            // CAC card initialization according to DoD standards
            card.cacData = {
                gscIsCard: this.createGSCISCard(),
                cardCapabilityContainer: this.createCCC(),
                cardHolderUniqueIdentifier: this.generateCHUID(),
                personInstanceIdentifier: this.generatePII(card.holderInfo),
                personnelData: this.createPersonnelData(card.holderInfo),
                organizationalData: this.createOrgData(card.holderInfo),
                accessControlRules: this.createAccessControlRules(),
                certificateSlots: new Map(),
                biometricData: null // Optional biometric template
            };

            // Create default PIN policy for CAC
            if (!card.pinPolicy) {
                card.pinPolicy = {
                    type: 'cac',
                    minLength: 6,
                    maxLength: 8,
                    pinType: 'numeric',
                    maxAttempts: 3,
                    lockoutDuration: 30 * 60 * 1000
                };
            }

            this.logger.info(`CAC card initialized: ${card.id}`);

        } catch (error) {
            this.logger.error('CAC card initialization failed:', error);
            throw error;
        }
    }

    async loadCertificateToCard(card, certificateRequest) {
        try {
            const { certificate, privateKey, slot, keyUsage } = certificateRequest;
            
            // Validate certificate and slot
            this.validateCertificateForCard(card, certificate, slot);

            // Generate key pair if not provided
            let keyPair = { certificate, privateKey };
            if (!privateKey) {
                keyPair = await this.generateKeyPairForCard(card, keyUsage);
                // Get certificate signed by CA
                keyPair.certificate = await this.requestCertificateForCard(card, keyPair.publicKey, keyUsage);
            }

            // Store certificate and key in appropriate slot
            const certData = {
                slot,
                certificate: keyPair.certificate,
                privateKey: keyPair.privateKey,
                keyUsage,
                loadedAt: new Date(),
                status: 'active'
            };

            card.certificates.set(slot, certData);

            // Update card-specific data structures
            if (card.type === 'piv') {
                await this.updatePIVCertificateSlot(card, slot, certData);
            } else if (card.type === 'cac') {
                await this.updateCACCertificateSlot(card, slot, certData);
            }

            this.logger.info(`Certificate loaded to card: ${card.id}, slot: ${slot}, usage: ${keyUsage}`);

        } catch (error) {
            this.logger.error('Certificate loading to card failed:', error);
            throw error;
        }
    }

    /**
     * PIV/CAC Card Support
     */
    async authenticateWithPIVCard(cardId, pin, readerName) {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`PIV card not found: ${cardId}`);

            if (card.type !== 'piv') throw new Error(`Card is not PIV type: ${cardId}`);
            if (card.status !== 'active') throw new Error(`PIV card is not active: ${cardId}`);

            // Check if card is locked
            if (this.isCardLocked(cardId)) {
                throw new Error(`PIV card is locked due to PIN violations: ${cardId}`);
            }

            // Verify PIN
            const pinValid = await this.verifyCardPIN(card, pin);
            if (!pinValid) {
                await this.handleFailedPINAttempt(card);
                throw new Error('Invalid PIN');
            }

            // Reset failed attempts on successful authentication
            card.failedPinAttempts = 0;
            this.pinAttempts.delete(cardId);

            // Create authentication session
            const session = await this.createCardSession(card, readerName);

            // Perform PIV authentication challenge
            const authCert = card.certificates.get('9a'); // PIV authentication certificate
            if (!authCert) throw new Error('PIV authentication certificate not found');

            const challenge = crypto.randomBytes(32);
            const signature = await this.signWithCardCertificate(card, '9a', challenge);

            const authResult = {
                cardId,
                sessionId: session.id,
                holderInfo: card.holderInfo,
                authenticatedAt: new Date(),
                readerName,
                certificate: authCert.certificate,
                challenge: challenge.toString('hex'),
                signature: signature.toString('hex'),
                valid: true
            };

            await this.recordAuthenticationEvent(authResult);
            this.metrics.successfulAuthentications++;

            this.logger.info(`PIV authentication successful: ${cardId}, holder: ${card.holderInfo.employeeId}`);
            this.emit('pivAuthenticated', authResult);

            return authResult;

        } catch (error) {
            this.metrics.failedAuthentications++;
            this.metrics.securityEvents++;
            this.logger.error('PIV authentication failed:', error);
            throw error;
        }
    }

    async authenticateWithCACCard(cardId, pin, readerName) {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`CAC card not found: ${cardId}`);

            if (card.type !== 'cac') throw new Error(`Card is not CAC type: ${cardId}`);
            if (card.status !== 'active') throw new Error(`CAC card is not active: ${cardId}`);

            // Check if card is locked
            if (this.isCardLocked(cardId)) {
                throw new Error(`CAC card is locked due to PIN violations: ${cardId}`);
            }

            // Verify PIN
            const pinValid = await this.verifyCardPIN(card, pin);
            if (!pinValid) {
                await this.handleFailedPINAttempt(card);
                throw new Error('Invalid PIN');
            }

            // Reset failed attempts
            card.failedPinAttempts = 0;
            this.pinAttempts.delete(cardId);

            // Create authentication session
            const session = await this.createCardSession(card, readerName);

            // Get ID certificate for authentication
            const idCert = card.certificates.get('01'); // CAC ID certificate
            if (!idCert) throw new Error('CAC ID certificate not found');

            const authResult = {
                cardId,
                sessionId: session.id,
                holderInfo: card.holderInfo,
                personnelData: card.cacData?.personnelData,
                authenticatedAt: new Date(),
                readerName,
                certificate: idCert.certificate,
                accessLevel: this.determineAccessLevel(card),
                valid: true
            };

            await this.recordAuthenticationEvent(authResult);
            this.metrics.successfulAuthentications++;

            this.logger.info(`CAC authentication successful: ${cardId}, holder: ${card.holderInfo.employeeId}`);
            this.emit('cacAuthenticated', authResult);

            return authResult;

        } catch (error) {
            this.metrics.failedAuthentications++;
            this.metrics.securityEvents++;
            this.logger.error('CAC authentication failed:', error);
            throw error;
        }
    }

    /**
     * FIDO2/WebAuthn Integration
     */
    async registerFIDO2Device(registrationRequest) {
        try {
            const { userId, userName, displayName, deviceInfo, attestationObject, clientDataJSON } = registrationRequest;

            this.validateFIDO2Registration(registrationRequest);

            // Parse attestation object
            const attestation = this.parseAttestationObject(attestationObject);
            const authData = this.parseAuthenticatorData(attestation.authData);
            
            // Verify attestation
            const attestationValid = await this.verifyAttestation(attestation, clientDataJSON);
            if (!attestationValid) {
                throw new Error('FIDO2 attestation verification failed');
            }

            const deviceId = this.generateDeviceId('fido2');
            const device = {
                id: deviceId,
                type: 'fido2',
                userId,
                userName,
                displayName,
                credentialId: authData.credentialId,
                publicKey: authData.publicKey,
                signCounter: authData.signCounter,
                deviceInfo: {
                    aaguid: authData.aaguid,
                    ...deviceInfo
                },
                attestationObject,
                attestationFormat: attestation.fmt,
                attestationStatement: attestation.attStmt,
                registeredAt: new Date(),
                lastUsed: new Date(),
                useCount: 0,
                status: 'active',
                metadata: registrationRequest.metadata || {}
            };

            this.fido2Devices.set(deviceId, device);
            await this.saveFIDO2Device(device);

            // Store WebAuthn credential
            const webauthnCred = {
                id: authData.credentialId.toString('base64url'),
                publicKey: authData.publicKey.toString('base64'),
                deviceId,
                userId,
                createdAt: new Date()
            };
            this.webAuthnCredentials.set(webauthnCred.id, webauthnCred);

            this.metrics.fido2Devices++;
            this.logger.info(`FIDO2 device registered: ${deviceId}, user: ${userId}`);
            this.emit('fido2DeviceRegistered', device);

            return device;

        } catch (error) {
            this.logger.error('FIDO2 device registration failed:', error);
            throw error;
        }
    }

    async authenticateWithFIDO2(authenticationRequest) {
        try {
            const { credentialId, authenticatorData, signature, userHandle, clientDataJSON } = authenticationRequest;

            // Find device by credential ID
            const credential = this.webAuthnCredentials.get(credentialId);
            if (!credential) throw new Error(`FIDO2 credential not found: ${credentialId}`);

            const device = this.fido2Devices.get(credential.deviceId);
            if (!device || device.status !== 'active') {
                throw new Error(`FIDO2 device not active: ${credential.deviceId}`);
            }

            // Parse authenticator data
            const authData = this.parseAuthenticatorData(Buffer.from(authenticatorData, 'base64'));
            
            // Verify signature counter (replay protection)
            if (authData.signCounter <= device.signCounter) {
                throw new Error('FIDO2 signature counter regression detected');
            }

            // Verify signature
            const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64').toString());
            const signatureValid = await this.verifyFIDO2Signature(
                device.publicKey,
                authenticatorData,
                clientDataJSON,
                signature
            );

            if (!signatureValid) {
                throw new Error('FIDO2 signature verification failed');
            }

            // Update device usage statistics
            device.lastUsed = new Date();
            device.useCount++;
            device.signCounter = authData.signCounter;

            const authResult = {
                deviceId: device.id,
                credentialId,
                userId: device.userId,
                userName: device.userName,
                authenticatedAt: new Date(),
                userPresent: authData.userPresent,
                userVerified: authData.userVerified,
                signCounter: authData.signCounter,
                valid: true
            };

            await this.recordFIDO2AuthenticationEvent(authResult);
            this.metrics.successfulAuthentications++;

            this.logger.info(`FIDO2 authentication successful: ${device.id}, user: ${device.userId}`);
            this.emit('fido2Authenticated', authResult);

            return authResult;

        } catch (error) {
            this.metrics.failedAuthentications++;
            this.metrics.securityEvents++;
            this.logger.error('FIDO2 authentication failed:', error);
            throw error;
        }
    }

    /**
     * Token Lifecycle Management
     */
    async updateCardStatus(cardId, newStatus, reason = '') {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`Card not found: ${cardId}`);

            const previousStatus = card.status;
            card.status = newStatus;
            card.lastStatusChange = new Date();
            
            if (reason) {
                card.statusChangeReason = reason;
            }

            // Handle status-specific actions
            switch (newStatus) {
                case 'suspended':
                    await this.suspendCard(card);
                    break;
                case 'revoked':
                    await this.revokeCard(card);
                    break;
                case 'expired':
                    await this.expireCard(card);
                    break;
                case 'lost':
                    await this.reportCardLost(card);
                    break;
                case 'damaged':
                    await this.reportCardDamaged(card);
                    break;
            }

            await this.saveCard(card);

            const statusChangeEvent = {
                cardId,
                previousStatus,
                newStatus,
                reason,
                changedAt: new Date(),
                metadata: { cardType: card.type, holderEmployeeId: card.holderInfo.employeeId }
            };

            await this.recordStatusChangeEvent(statusChangeEvent);
            this.updateMetrics();

            this.logger.info(`Card status updated: ${cardId}, ${previousStatus} -> ${newStatus}, reason: ${reason}`);
            this.emit('cardStatusChanged', statusChangeEvent);

            return card;

        } catch (error) {
            this.logger.error('Card status update failed:', error);
            throw error;
        }
    }

    async renewCard(cardId, extensionPeriod = null) {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`Card not found: ${cardId}`);

            const template = this.provisioningTemplates.get(card.templateId);
            if (!template) throw new Error(`Provisioning template not found: ${card.templateId}`);

            const newExpirationDate = extensionPeriod 
                ? new Date(Date.now() + extensionPeriod * 24 * 60 * 60 * 1000)
                : this.calculateExpirationDate(template);

            // Create renewal record
            const renewalRecord = {
                cardId,
                previousExpiration: card.expirationDate,
                newExpiration: newExpirationDate,
                renewedAt: new Date(),
                extensionPeriod,
                renewalReason: 'lifecycle_renewal'
            };

            card.expirationDate = newExpirationDate;
            card.renewalHistory = card.renewalHistory || [];
            card.renewalHistory.push(renewalRecord);

            await this.saveCard(card);

            this.logger.info(`Card renewed: ${cardId}, new expiration: ${newExpirationDate}`);
            this.emit('cardRenewed', renewalRecord);

            return renewalRecord;

        } catch (error) {
            this.logger.error('Card renewal failed:', error);
            throw error;
        }
    }

    /**
     * Card Reader Management
     */
    async initializeCardReaders() {
        try {
            // Detect available card readers
            const readers = await this.detectCardReaders();
            
            for (const readerInfo of readers) {
                const reader = {
                    id: this.generateReaderId(),
                    name: readerInfo.name,
                    type: readerInfo.type || 'pcsc',
                    driver: readerInfo.driver,
                    status: 'available',
                    capabilities: readerInfo.capabilities || [],
                    supportedProtocols: readerInfo.protocols || ['T=0', 'T=1'],
                    connectedCard: null,
                    lastActivity: null,
                    configuration: this.getReaderConfiguration(readerInfo.name),
                    metadata: readerInfo.metadata || {}
                };

                this.cardReaders.set(reader.id, reader);
                await this.saveReaderConfiguration(reader);
            }

            this.metrics.cardReaders = this.cardReaders.size;
            this.logger.info(`Initialized ${this.cardReaders.size} card readers`);

        } catch (error) {
            this.logger.error('Card reader initialization failed:', error);
            throw error;
        }
    }

    async connectToCard(readerId) {
        try {
            const reader = this.cardReaders.get(readerId);
            if (!reader) throw new Error(`Card reader not found: ${readerId}`);

            if (reader.status !== 'available') {
                throw new Error(`Card reader not available: ${readerId}`);
            }

            // Establish connection to card
            const cardConnection = await this.establishCardConnection(reader);
            
            // Read card information
            const cardInfo = await this.readCardInformation(cardConnection);
            
            reader.connectedCard = cardInfo;
            reader.status = 'connected';
            reader.lastActivity = new Date();

            this.logger.info(`Connected to card: ${readerId}, type: ${cardInfo.type}`);
            this.emit('cardConnected', { readerId, cardInfo });

            return { reader, cardInfo };

        } catch (error) {
            this.logger.error('Card connection failed:', error);
            throw error;
        }
    }

    async disconnectFromCard(readerId) {
        try {
            const reader = this.cardReaders.get(readerId);
            if (!reader) throw new Error(`Card reader not found: ${readerId}`);

            if (reader.connectedCard) {
                await this.closeCardConnection(reader);
                
                const cardInfo = reader.connectedCard;
                reader.connectedCard = null;
                reader.status = 'available';
                reader.lastActivity = new Date();

                this.logger.info(`Disconnected from card: ${readerId}`);
                this.emit('cardDisconnected', { readerId, cardInfo });
            }

        } catch (error) {
            this.logger.error('Card disconnection failed:', error);
            throw error;
        }
    }

    /**
     * PIN Policy Enforcement
     */
    async validatePIN(cardId, pin) {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`Card not found: ${cardId}`);

            const policy = card.pinPolicy;
            const violations = [];

            // Length validation
            if (pin.length < policy.minLength) {
                violations.push(`PIN too short (minimum ${policy.minLength} characters)`);
            }
            if (pin.length > policy.maxLength) {
                violations.push(`PIN too long (maximum ${policy.maxLength} characters)`);
            }

            // Type validation
            if (policy.pinType === 'numeric' && !/^\d+$/.test(pin)) {
                violations.push('PIN must contain only numeric characters');
            }

            // Complexity requirements
            if (this.config.pinComplexityRequirements.requireNumbers && !/\d/.test(pin)) {
                violations.push('PIN must contain at least one number');
            }

            if (this.config.pinComplexityRequirements.requireMixedCase) {
                if (!/[a-z]/.test(pin) || !/[A-Z]/.test(pin)) {
                    violations.push('PIN must contain both uppercase and lowercase letters');
                }
            }

            if (this.config.pinComplexityRequirements.requireSpecialChars) {
                if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pin)) {
                    violations.push('PIN must contain at least one special character');
                }
            }

            // Sequential/repeating character validation
            if (this.config.pinComplexityRequirements.preventSequential && this.hasSequentialChars(pin)) {
                violations.push('PIN must not contain sequential characters');
            }

            if (this.config.pinComplexityRequirements.preventRepeating && this.hasRepeatingChars(pin)) {
                violations.push('PIN must not contain repeating characters');
            }

            // PIN history validation
            if (card.pinHistory && card.pinHistory.length > 0) {
                const pinHash = this.hashPIN(pin);
                if (card.pinHistory.includes(pinHash)) {
                    violations.push('PIN has been used recently and cannot be reused');
                }
            }

            return {
                valid: violations.length === 0,
                violations
            };

        } catch (error) {
            this.logger.error('PIN validation failed:', error);
            throw error;
        }
    }

    async changePIN(cardId, currentPin, newPin) {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`Card not found: ${cardId}`);

            // Verify current PIN
            const currentPinValid = await this.verifyCardPIN(card, currentPin);
            if (!currentPinValid) {
                throw new Error('Current PIN is incorrect');
            }

            // Validate new PIN
            const validation = await this.validatePIN(cardId, newPin);
            if (!validation.valid) {
                throw new Error(`PIN validation failed: ${validation.violations.join(', ')}`);
            }

            // Update PIN on card
            await this.setCardPIN(card, newPin);

            // Update PIN history
            const newPinHash = this.hashPIN(newPin);
            card.pinHistory = card.pinHistory || [];
            card.pinHistory.push(newPinHash);
            
            // Keep only last 5 PINs in history
            if (card.pinHistory.length > 5) {
                card.pinHistory = card.pinHistory.slice(-5);
            }

            card.lastPinChange = new Date();
            card.failedPinAttempts = 0;

            await this.saveCard(card);

            const pinChangeEvent = {
                cardId,
                changedAt: new Date(),
                holderEmployeeId: card.holderInfo.employeeId
            };

            await this.recordPINChangeEvent(pinChangeEvent);

            this.logger.info(`PIN changed successfully: ${cardId}`);
            this.emit('pinChanged', pinChangeEvent);

        } catch (error) {
            this.metrics.pinViolations++;
            this.logger.error('PIN change failed:', error);
            throw error;
        }
    }

    /**
     * Certificate-to-Card Binding
     */
    async bindCertificateToCard(certificateId, cardId, slot) {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`Card not found: ${cardId}`);

            // Validate slot availability
            if (card.certificates.has(slot)) {
                throw new Error(`Certificate slot already occupied: ${slot}`);
            }

            // Get certificate from PKI system
            const certificate = await this.getCertificateFromPKI(certificateId);
            if (!certificate) throw new Error(`Certificate not found: ${certificateId}`);

            // Generate key pair for card
            const keyPair = await this.generateKeyPairForCard(card, certificate.keyUsage);

            // Create CSR and get certificate signed
            const csr = await this.createCSRForCertificate(certificate, keyPair.publicKey);
            const signedCertificate = await this.requestCertificateSigning(csr);

            // Load certificate and private key to card
            await this.loadCertificateToCard(card, {
                certificate: signedCertificate,
                privateKey: keyPair.privateKey,
                slot,
                keyUsage: certificate.keyUsage
            });

            const binding = {
                certificateId,
                cardId,
                slot,
                boundAt: new Date(),
                certificate: signedCertificate,
                status: 'active'
            };

            this.logger.info(`Certificate bound to card: ${certificateId} -> ${cardId}:${slot}`);
            this.emit('certificateBoundToCard', binding);

            return binding;

        } catch (error) {
            this.logger.error('Certificate-to-card binding failed:', error);
            throw error;
        }
    }

    async unbindCertificateFromCard(cardId, slot, reason = 'manual') {
        try {
            const card = this.smartCards.get(cardId);
            if (!card) throw new Error(`Card not found: ${cardId}`);

            const certData = card.certificates.get(slot);
            if (!certData) throw new Error(`No certificate in slot: ${slot}`);

            // Remove certificate from card
            card.certificates.delete(slot);

            // Update card data structures
            if (card.type === 'piv') {
                await this.removePIVCertificateSlot(card, slot);
            } else if (card.type === 'cac') {
                await this.removeCACCertificateSlot(card, slot);
            }

            await this.saveCard(card);

            const unbinding = {
                cardId,
                slot,
                certificateId: certData.certificateId,
                unboundAt: new Date(),
                reason
            };

            this.logger.info(`Certificate unbound from card: ${cardId}:${slot}, reason: ${reason}`);
            this.emit('certificateUnboundFromCard', unbinding);

            return unbinding;

        } catch (error) {
            this.logger.error('Certificate unbinding failed:', error);
            throw error;
        }
    }

    /**
     * Mobile Device Certificate Storage
     */
    async provisionMobileToken(provisioningRequest) {
        try {
            const { deviceId, deviceInfo, holderInfo, certificates, securityPolicy } = provisioningRequest;

            this.validateMobileProvisioningRequest(provisioningRequest);

            const tokenId = this.generateTokenId('mobile');
            const mobileToken = {
                id: tokenId,
                type: 'mobile',
                deviceId,
                deviceInfo: {
                    platform: deviceInfo.platform, // 'ios', 'android'
                    osVersion: deviceInfo.osVersion,
                    model: deviceInfo.model,
                    udid: deviceInfo.udid,
                    attestationData: deviceInfo.attestationData
                },
                holderInfo,
                certificates: new Map(),
                securityPolicy: securityPolicy || this.getDefaultMobileSecurityPolicy(),
                keystore: this.createMobileKeystore(deviceInfo.platform),
                biometricPolicy: securityPolicy?.biometricPolicy || {},
                enrollmentProfile: this.createEnrollmentProfile(provisioningRequest),
                provisionedAt: new Date(),
                lastSync: new Date(),
                status: 'active',
                metadata: provisioningRequest.metadata || {}
            };

            // Install certificates
            for (const certRequest of certificates) {
                await this.installCertificateOnMobile(mobileToken, certRequest);
            }

            this.mobileTokens.set(tokenId, mobileToken);
            await this.saveMobileToken(mobileToken);

            this.metrics.mobileTokens++;
            this.logger.info(`Mobile token provisioned: ${tokenId}, device: ${deviceId}`);
            this.emit('mobileTokenProvisioned', mobileToken);

            return mobileToken;

        } catch (error) {
            this.logger.error('Mobile token provisioning failed:', error);
            throw error;
        }
    }

    async authenticateWithMobileToken(tokenId, biometricData, deviceAttestation) {
        try {
            const token = this.mobileTokens.get(tokenId);
            if (!token) throw new Error(`Mobile token not found: ${tokenId}`);

            if (token.status !== 'active') {
                throw new Error(`Mobile token is not active: ${tokenId}`);
            }

            // Verify device attestation
            const attestationValid = await this.verifyMobileDeviceAttestation(token, deviceAttestation);
            if (!attestationValid) {
                throw new Error('Mobile device attestation failed');
            }

            // Verify biometric authentication if required
            if (token.biometricPolicy.required) {
                const biometricValid = await this.verifyBiometricAuthentication(token, biometricData);
                if (!biometricValid) {
                    throw new Error('Biometric authentication failed');
                }
            }

            const authResult = {
                tokenId,
                deviceId: token.deviceId,
                holderInfo: token.holderInfo,
                authenticatedAt: new Date(),
                authenticationMethod: biometricData ? 'biometric' : 'device_attestation',
                deviceInfo: token.deviceInfo,
                valid: true
            };

            await this.recordMobileAuthenticationEvent(authResult);
            this.metrics.successfulAuthentications++;

            this.logger.info(`Mobile token authentication successful: ${tokenId}, device: ${token.deviceId}`);
            this.emit('mobileTokenAuthenticated', authResult);

            return authResult;

        } catch (error) {
            this.metrics.failedAuthentications++;
            this.metrics.securityEvents++;
            this.logger.error('Mobile token authentication failed:', error);
            throw error;
        }
    }

    /**
     * Monitoring and Metrics
     */
    async startMonitoring() {
        // Check card expirations daily
        setInterval(async () => {
            await this.checkCardExpirations();
        }, 24 * 60 * 60 * 1000); // 24 hours

        // Monitor failed PIN attempts
        setInterval(() => {
            this.monitorFailedPINAttempts();
        }, 5 * 60 * 1000); // 5 minutes

        // Clean up expired sessions
        setInterval(() => {
            this.cleanupExpiredSessions();
        }, 60 * 60 * 1000); // 1 hour

        // Update metrics
        setInterval(() => {
            this.updateMetrics();
        }, 5 * 60 * 1000); // 5 minutes

        this.logger.info('Smart card monitoring started');
    }

    async checkCardExpirations() {
        try {
            const now = new Date();
            const expirationThreshold = 30 * 24 * 60 * 60 * 1000; // 30 days
            const expiringCards = [];

            for (const [cardId, card] of this.smartCards) {
                if (card.status !== 'active') continue;

                const timeToExpiration = card.expirationDate - now;
                if (timeToExpiration <= expirationThreshold && timeToExpiration > 0) {
                    expiringCards.push(card);
                } else if (timeToExpiration <= 0) {
                    // Card has expired
                    await this.updateCardStatus(cardId, 'expired', 'automatic_expiration');
                }
            }

            if (expiringCards.length > 0) {
                await this.sendExpirationNotifications(expiringCards);
            }

            this.logger.info(`Card expiration check completed: ${expiringCards.length} cards expiring soon`);

        } catch (error) {
            this.logger.error('Card expiration check failed:', error);
        }
    }

    /**
     * Utility Methods
     */
    generateCardId(cardType) {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `${cardType}-${timestamp}-${random.toString(16)}`;
    }

    generateSerialNumber() {
        return crypto.randomBytes(8).toString('hex').toUpperCase();
    }

    generateDeviceId(type) {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `${type}-${timestamp}-${random.toString(16)}`;
    }

    generateTokenId(type) {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `${type}-${timestamp}-${random.toString(16)}`;
    }

    generateReaderId() {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFF);
        return `reader-${timestamp}-${random.toString(16)}`;
    }

    hashPIN(pin) {
        return crypto.createHash('sha256').update(pin).digest('hex');
    }

    hasSequentialChars(pin) {
        for (let i = 0; i < pin.length - 2; i++) {
            const charCode = pin.charCodeAt(i);
            if (pin.charCodeAt(i + 1) === charCode + 1 && pin.charCodeAt(i + 2) === charCode + 2) {
                return true;
            }
        }
        return false;
    }

    hasRepeatingChars(pin) {
        for (let i = 0; i < pin.length - 2; i++) {
            if (pin[i] === pin[i + 1] && pin[i + 1] === pin[i + 2]) {
                return true;
            }
        }
        return false;
    }

    calculateExpirationDate(template) {
        const validityPeriod = template.validityPeriod || 365; // days
        return new Date(Date.now() + validityPeriod * 24 * 60 * 60 * 1000);
    }

    updateMetrics() {
        this.metrics.totalCards = this.smartCards.size;
        this.metrics.activeCards = Array.from(this.smartCards.values()).filter(c => c.status === 'active').length;
        this.metrics.pivCards = Array.from(this.smartCards.values()).filter(c => c.type === 'piv').length;
        this.metrics.cacCards = Array.from(this.smartCards.values()).filter(c => c.type === 'cac').length;
        this.metrics.fido2Devices = this.fido2Devices.size;
        this.metrics.mobileTokens = this.mobileTokens.size;
        this.metrics.cardReaders = this.cardReaders.size;
    }

    /**
     * Placeholder implementations for integration methods
     */
    validateProvisioningRequest(request) { /* Implementation */ }
    validateFIDO2Registration(request) { /* Implementation */ }
    validateMobileProvisioningRequest(request) { /* Implementation */ }
    getDefaultPinPolicy(cardType) { return this.config.pinPolicyEnforcement ? {} : null; }
    getSecurityDomain(template) { return 'default'; }
    createCCC() { return {}; }
    generateCHUID() { return crypto.randomBytes(16).toString('hex'); }
    createPrintedInfo(holderInfo) { return {}; }
    createDiscoveryObject() { return {}; }
    createKeyHistory() { return {}; }
    createGSCISCard() { return {}; }
    generatePII(holderInfo) { return crypto.randomBytes(8).toString('hex'); }
    createPersonnelData(holderInfo) { return {}; }
    createOrgData(holderInfo) { return {}; }
    createAccessControlRules() { return {}; }
    detectCardReaders() { return Promise.resolve([]); }
    getReaderConfiguration(name) { return {}; }
    parseAttestationObject(obj) { return {}; }
    parseAuthenticatorData(data) { return {}; }
    verifyAttestation(attestation, clientData) { return Promise.resolve(true); }
    verifyFIDO2Signature(publicKey, authData, clientData, signature) { return Promise.resolve(true); }
    createMobileKeystore(platform) { return {}; }
    createEnrollmentProfile(request) { return {}; }
    getDefaultMobileSecurityPolicy() { return {}; }
    verifyMobileDeviceAttestation(token, attestation) { return Promise.resolve(true); }
    verifyBiometricAuthentication(token, biometricData) { return Promise.resolve(true); }

    // Storage methods
    async saveCard(card) { /* Implementation */ }
    async saveFIDO2Device(device) { /* Implementation */ }
    async saveMobileToken(token) { /* Implementation */ }
    async saveReaderConfiguration(reader) { /* Implementation */ }

    // Event recording methods
    async recordAuthenticationEvent(event) { /* Implementation */ }
    async recordFIDO2AuthenticationEvent(event) { /* Implementation */ }
    async recordMobileAuthenticationEvent(event) { /* Implementation */ }
    async recordStatusChangeEvent(event) { /* Implementation */ }
    async recordPINChangeEvent(event) { /* Implementation */ }

    /**
     * Public API Methods
     */
    async getMetrics() {
        return { ...this.metrics };
    }

    async getCards(filters = {}) {
        const cards = Array.from(this.smartCards.values());
        // Apply filters as needed
        return cards;
    }

    async getCard(cardId) {
        return this.smartCards.get(cardId);
    }

    async getFIDO2Devices() {
        return Array.from(this.fido2Devices.values());
    }

    async getMobileTokens() {
        return Array.from(this.mobileTokens.values());
    }

    async getCardReaders() {
        return Array.from(this.cardReaders.values());
    }

    async getAuditLog() {
        return this.auditLog;
    }
}

module.exports = SmartCardTokenManager;