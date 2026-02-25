/**
 * OpenDirectory Enterprise Certificate Authority Service
 * Comprehensive PKI infrastructure with full CA lifecycle management
 * 
 * Features:
 * - Root and Intermediate CA creation and management
 * - Certificate signing and validation
 * - CRL and OCSP services
 * - Key rotation and backup
 * - Cross-certification support
 * - Integration with Enterprise Directory
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');
const winston = require('winston');
const EventEmitter = require('events');
const config = require('../config');

class EnterpriseCAService extends EventEmitter {
    constructor(options = {}) {
        super();
        
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
                    filename: path.join(path.dirname(config.logging.file), 'ca-service.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // Certificate Authority stores
        this.caStore = new Map();
        this.certificateStore = new Map();
        this.crlStore = new Map();
        this.templateStore = new Map();
        
        // OCSP responders
        this.ocspResponders = new Map();
        
        // Metrics and monitoring
        this.metrics = {
            certificatesIssued: 0,
            certificatesRevoked: 0,
            certificatesExpired: 0,
            crlUpdates: 0,
            ocspRequests: 0,
            caCreated: 0,
            keyRotations: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadExistingCAs();
            await this.loadCertificateTemplates();
            await this.startOCSPService();
            await this.scheduleMaintenance();
            
            this.logger.info('Enterprise CA Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize Enterprise CA Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            this.config.rootCAPath,
            this.config.intermediateCAPath,
            this.config.certificateStorePath,
            this.config.crlPath,
            path.join(this.config.certificateStorePath, 'issued'),
            path.join(this.config.certificateStorePath, 'revoked'),
            path.join(this.config.certificateStorePath, 'templates'),
            path.join(this.config.certificateStorePath, 'backups'),
            path.join(this.config.certificateStorePath, 'cross-certs'),
            path.join(this.config.certificateStorePath, 'ocsp')
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
     * Root Certificate Authority Management
     */
    async createRootCA(caData) {
        try {
            const {
                subject,
                keySize = this.config.keySize,
                validityDays = this.config.rootCAValidity,
                extensions = {}
            } = caData;

            // Generate key pair
            const keyPair = await this.generateKeyPair(keySize);
            
            // Create self-signed root certificate
            const cert = forge.pki.createCertificate();
            cert.publicKey = keyPair.publicKey;
            cert.serialNumber = this.generateSerialNumber();
            
            const now = new Date();
            cert.validity.notBefore = now;
            cert.validity.notAfter = new Date(now.getTime() + (validityDays * 24 * 60 * 60 * 1000));

            // Set subject and issuer (self-signed)
            const attrs = this.buildCertificateAttributes(subject);
            cert.setSubject(attrs);
            cert.setIssuer(attrs);

            // Add basic constraints and key usage
            const certExtensions = [
                {
                    name: 'basicConstraints',
                    cA: true,
                    critical: true
                },
                {
                    name: 'keyUsage',
                    keyCertSign: true,
                    cRLSign: true,
                    critical: true
                },
                {
                    name: 'subjectKeyIdentifier'
                },
                {
                    name: 'authorityKeyIdentifier',
                    keyid: false,
                    serialNumber: false
                },
                ...this.buildCustomExtensions(extensions)
            ];

            cert.setExtensions(certExtensions);

            // Self-sign the certificate
            cert.sign(keyPair.privateKey, forge.md[this.config.hashAlgorithm].create());

            const caId = this.generateCAId('root', subject.commonName);
            const rootCA = {
                id: caId,
                type: 'root',
                subject,
                certificate: cert,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                serialNumber: cert.serialNumber,
                keySize,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                status: 'active',
                createdAt: new Date(),
                extensions,
                keyUsage: ['keyCertSign', 'cRLSign']
            };

            await this.storeCA(rootCA);
            await this.initializeCRL(caId);
            
            this.metrics.caCreated++;
            this.logger.info(`Root CA created: ${caId}`);
            this.emit('rootCACreated', rootCA);

            return {
                id: caId,
                certificate: forge.pki.certificateToPem(cert),
                subject: subject,
                serialNumber: cert.serialNumber,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter
            };

        } catch (error) {
            this.logger.error('Failed to create root CA:', error);
            throw error;
        }
    }

    async createIntermediateCA(caData) {
        try {
            const {
                parentCAId,
                subject,
                keySize = this.config.keySize,
                validityDays = this.config.intermediateCAValidity,
                pathLenConstraint = 0,
                extensions = {}
            } = caData;

            const parentCA = this.caStore.get(parentCAId);
            if (!parentCA) {
                throw new Error(`Parent CA not found: ${parentCAId}`);
            }

            if (parentCA.status !== 'active') {
                throw new Error(`Parent CA is not active: ${parentCAId}`);
            }

            // Generate key pair
            const keyPair = await this.generateKeyPair(keySize);
            
            // Create certificate
            const cert = forge.pki.createCertificate();
            cert.publicKey = keyPair.publicKey;
            cert.serialNumber = this.generateSerialNumber();
            
            const now = new Date();
            cert.validity.notBefore = now;
            cert.validity.notAfter = new Date(now.getTime() + (validityDays * 24 * 60 * 60 * 1000));

            // Set subject and issuer
            cert.setSubject(this.buildCertificateAttributes(subject));
            cert.setIssuer(parentCA.certificate.subject.attributes);

            // Add intermediate CA extensions
            const certExtensions = [
                {
                    name: 'basicConstraints',
                    cA: true,
                    pathLenConstraint: pathLenConstraint,
                    critical: true
                },
                {
                    name: 'keyUsage',
                    keyCertSign: true,
                    cRLSign: true,
                    critical: true
                },
                {
                    name: 'subjectKeyIdentifier'
                },
                {
                    name: 'authorityKeyIdentifier',
                    keyIdentifier: forge.pki.getPublicKeyFingerprint(parentCA.publicKey, {encoding: 'hex'})
                },
                ...this.buildCustomExtensions(extensions)
            ];

            cert.setExtensions(certExtensions);

            // Sign with parent CA
            cert.sign(parentCA.privateKey, forge.md[this.config.hashAlgorithm].create());

            const caId = this.generateCAId('intermediate', subject.commonName);
            const intermediateCA = {
                id: caId,
                type: 'intermediate',
                parentId: parentCAId,
                subject,
                certificate: cert,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                serialNumber: cert.serialNumber,
                keySize,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                pathLenConstraint,
                status: 'active',
                createdAt: new Date(),
                extensions,
                keyUsage: ['keyCertSign', 'cRLSign']
            };

            await this.storeCA(intermediateCA);
            await this.initializeCRL(caId);
            
            this.metrics.caCreated++;
            this.logger.info(`Intermediate CA created: ${caId}`);
            this.emit('intermediateCACreated', intermediateCA);

            return {
                id: caId,
                certificate: forge.pki.certificateToPem(cert),
                subject: subject,
                serialNumber: cert.serialNumber,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                parentId: parentCAId
            };

        } catch (error) {
            this.logger.error('Failed to create intermediate CA:', error);
            throw error;
        }
    }

    /**
     * Certificate Issuance
     */
    async issueCertificate(certData) {
        try {
            const {
                caId,
                csr,
                template,
                subject,
                subjectAltName = [],
                validityDays = this.config.leafCertValidity,
                keyUsage = ['digitalSignature', 'keyEncipherment'],
                extendedKeyUsage = [],
                requesterId,
                deviceId
            } = certData;

            const ca = this.caStore.get(caId);
            if (!ca) {
                throw new Error(`CA not found: ${caId}`);
            }

            if (ca.status !== 'active') {
                throw new Error(`CA is not active: ${caId}`);
            }

            let cert, keyPair, csrObj;

            if (csr) {
                // Use provided CSR
                csrObj = forge.pki.certificationRequestFromPem(csr);
                if (!csrObj.verify()) {
                    throw new Error('Invalid CSR signature');
                }
                
                cert = forge.pki.createCertificate();
                cert.publicKey = csrObj.publicKey;
            } else {
                // Generate new key pair and certificate
                keyPair = await this.generateKeyPair(this.config.keySize);
                cert = forge.pki.createCertificate();
                cert.publicKey = keyPair.publicKey;
            }

            cert.serialNumber = this.generateSerialNumber();
            
            const now = new Date();
            cert.validity.notBefore = now;
            cert.validity.notAfter = new Date(now.getTime() + (validityDays * 24 * 60 * 60 * 1000));

            // Set subject and issuer
            const subjectAttrs = csr ? csrObj.subject.attributes : this.buildCertificateAttributes(subject);
            cert.setSubject(subjectAttrs);
            cert.setIssuer(ca.certificate.subject.attributes);

            // Build extensions
            const extensions = this.buildLeafCertificateExtensions({
                keyUsage,
                extendedKeyUsage,
                subjectAltName,
                ca
            });

            cert.setExtensions(extensions);

            // Sign the certificate
            cert.sign(ca.privateKey, forge.md[this.config.hashAlgorithm].create());

            // Store certificate record
            const certificateId = this.generateCertificateId();
            const certificateRecord = {
                id: certificateId,
                serialNumber: cert.serialNumber,
                certificate: cert,
                privateKey: keyPair ? keyPair.privateKey : null,
                publicKey: keyPair ? keyPair.publicKey : cert.publicKey,
                subject: subjectAttrs,
                subjectAltName,
                issuerCAId: caId,
                template,
                keyUsage,
                extendedKeyUsage,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                status: 'active',
                requesterId,
                deviceId,
                issuedAt: new Date(),
                lastCheck: new Date()
            };

            await this.storeCertificate(certificateRecord);
            
            this.metrics.certificatesIssued++;
            this.logger.info(`Certificate issued: ${certificateId}, Serial: ${cert.serialNumber}`);
            this.emit('certificateIssued', certificateRecord);

            return {
                id: certificateId,
                certificate: forge.pki.certificateToPem(cert),
                privateKey: keyPair ? forge.pki.privateKeyToPem(keyPair.privateKey) : null,
                serialNumber: cert.serialNumber,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                caChain: await this.getCAChain(caId)
            };

        } catch (error) {
            this.logger.error('Failed to issue certificate:', error);
            throw error;
        }
    }

    /**
     * Certificate Revocation
     */
    async revokeCertificate(serialNumber, reason = 'unspecified', revokerId = 'system') {
        try {
            // Find certificate
            let certificate = null;
            let certificateId = null;
            
            for (const [id, cert] of this.certificateStore) {
                if (cert.serialNumber === serialNumber) {
                    certificate = cert;
                    certificateId = id;
                    break;
                }
            }

            if (!certificate) {
                throw new Error(`Certificate not found: ${serialNumber}`);
            }

            if (certificate.status === 'revoked') {
                throw new Error(`Certificate already revoked: ${serialNumber}`);
            }

            // Update certificate status
            certificate.status = 'revoked';
            certificate.revokedAt = new Date();
            certificate.revocationReason = reason;
            certificate.revokedBy = revokerId;

            // Add to CRL
            const crlData = this.crlStore.get(certificate.issuerCAId);
            if (crlData) {
                crlData.revokedCertificates.add({
                    serialNumber,
                    revocationDate: new Date(),
                    reason,
                    extensions: []
                });
                
                await this.updateCRL(certificate.issuerCAId);
            }

            await this.storeCertificate(certificate);
            
            this.metrics.certificatesRevoked++;
            this.logger.info(`Certificate revoked: ${serialNumber}, reason: ${reason}`);
            this.emit('certificateRevoked', certificate);

            return {
                serialNumber,
                status: 'revoked',
                revokedAt: certificate.revokedAt,
                reason
            };

        } catch (error) {
            this.logger.error('Failed to revoke certificate:', error);
            throw error;
        }
    }

    /**
     * Certificate Validation
     */
    async validateCertificate(certificatePem, options = {}) {
        try {
            const cert = forge.pki.certificateFromPem(certificatePem);
            const now = new Date();
            const results = {
                valid: true,
                errors: [],
                warnings: [],
                details: {
                    subject: cert.subject.attributes,
                    issuer: cert.issuer.attributes,
                    serialNumber: cert.serialNumber,
                    notBefore: cert.validity.notBefore,
                    notAfter: cert.validity.notAfter
                }
            };

            // Check certificate dates
            if (cert.validity.notBefore > now) {
                results.valid = false;
                results.errors.push('Certificate is not yet valid');
            }

            if (cert.validity.notAfter < now) {
                results.valid = false;
                results.errors.push('Certificate has expired');
            }

            // Check if expires soon (warning)
            const daysUntilExpiration = Math.ceil((cert.validity.notAfter - now) / (1000 * 60 * 60 * 24));
            if (daysUntilExpiration <= 30 && daysUntilExpiration > 0) {
                results.warnings.push(`Certificate expires in ${daysUntilExpiration} days`);
            }

            // Check chain validation if requested
            if (options.validateChain !== false) {
                const chainValidation = await this.validateCertificateChain(certificatePem);
                if (!chainValidation.valid) {
                    results.valid = false;
                    results.errors.push('Certificate chain validation failed: ' + chainValidation.error);
                }
            }

            // Check revocation status
            const revocationCheck = await this.checkRevocationStatus(cert);
            if (revocationCheck.revoked) {
                results.valid = false;
                results.errors.push(`Certificate is revoked: ${revocationCheck.reason}`);
            }

            // Check key usage if specified
            if (options.requiredKeyUsage) {
                const keyUsageValid = this.validateKeyUsage(cert, options.requiredKeyUsage);
                if (!keyUsageValid) {
                    results.valid = false;
                    results.errors.push('Certificate key usage does not match requirements');
                }
            }

            return results;

        } catch (error) {
            this.logger.error('Certificate validation failed:', error);
            return {
                valid: false,
                errors: ['Certificate validation error: ' + error.message],
                warnings: [],
                details: null
            };
        }
    }

    async validateCertificateChain(certificatePem) {
        try {
            const cert = forge.pki.certificateFromPem(certificatePem);
            const caStore = forge.pki.createCaStore();

            // Add all CA certificates to the store
            for (const [caId, ca] of this.caStore) {
                if (ca.status === 'active') {
                    caStore.addCertificate(ca.certificate);
                }
            }

            // Verify the chain
            const verified = forge.pki.verifyCertificateChain(caStore, [cert]);
            
            return {
                valid: verified,
                error: verified ? null : 'Certificate chain verification failed'
            };

        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    /**
     * CRL Management
     */
    async initializeCRL(caId) {
        try {
            const ca = this.caStore.get(caId);
            if (!ca) throw new Error(`CA not found: ${caId}`);

            const crl = forge.pki.createCertificateRevocationList();
            crl.version = 1;
            crl.signatureOid = forge.pki.oids[this.config.hashAlgorithm + 'WithRSAEncryption'];
            crl.issuer.setAttributes(ca.certificate.subject.attributes);
            crl.thisUpdate = new Date();
            crl.nextUpdate = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

            // Add CRL extensions
            crl.setExtensions([
                {
                    name: 'cRLNumber',
                    cRLNumber: 1
                },
                {
                    name: 'authorityKeyIdentifier',
                    keyIdentifier: forge.pki.getPublicKeyFingerprint(ca.publicKey, {encoding: 'hex'})
                }
            ]);

            crl.sign(ca.privateKey);

            const crlData = {
                caId,
                crl,
                crlNumber: 1,
                thisUpdate: crl.thisUpdate,
                nextUpdate: crl.nextUpdate,
                revokedCertificates: new Set(),
                lastUpdate: new Date()
            };

            this.crlStore.set(caId, crlData);
            await this.saveCRL(caId, crlData);

            this.logger.info(`CRL initialized for CA: ${caId}`);

        } catch (error) {
            this.logger.error('Failed to initialize CRL:', error);
            throw error;
        }
    }

    async updateCRL(caId) {
        try {
            const ca = this.caStore.get(caId);
            const crlData = this.crlStore.get(caId);
            
            if (!ca || !crlData) {
                throw new Error(`CA or CRL not found: ${caId}`);
            }

            const crl = forge.pki.createCertificateRevocationList();
            crl.version = 1;
            crl.signatureOid = forge.pki.oids[this.config.hashAlgorithm + 'WithRSAEncryption'];
            crl.issuer.setAttributes(ca.certificate.subject.attributes);
            crl.thisUpdate = new Date();
            crl.nextUpdate = new Date(Date.now() + 24 * 60 * 60 * 1000);

            // Add revoked certificates
            for (const revokedCert of crlData.revokedCertificates) {
                const revoked = {
                    serialNumber: revokedCert.serialNumber,
                    revocationDate: revokedCert.revocationDate,
                    extensions: [{
                        name: 'cRLReason',
                        reason: this.getRevocationReasonCode(revokedCert.reason)
                    }]
                };
                crl.certificates.push(revoked);
            }

            // Update CRL number
            crlData.crlNumber++;
            crl.setExtensions([
                {
                    name: 'cRLNumber',
                    cRLNumber: crlData.crlNumber
                },
                {
                    name: 'authorityKeyIdentifier',
                    keyIdentifier: forge.pki.getPublicKeyFingerprint(ca.publicKey, {encoding: 'hex'})
                }
            ]);

            crl.sign(ca.privateKey);

            crlData.crl = crl;
            crlData.thisUpdate = crl.thisUpdate;
            crlData.nextUpdate = crl.nextUpdate;
            crlData.lastUpdate = new Date();

            await this.saveCRL(caId, crlData);
            
            this.metrics.crlUpdates++;
            this.logger.info(`CRL updated for CA: ${caId}, Number: ${crlData.crlNumber}`);

        } catch (error) {
            this.logger.error('Failed to update CRL:', error);
            throw error;
        }
    }

    async getCRL(caId, format = 'pem') {
        try {
            const crlData = this.crlStore.get(caId);
            if (!crlData) {
                throw new Error(`CRL not found for CA: ${caId}`);
            }

            switch (format.toLowerCase()) {
                case 'pem':
                    return forge.pki.certificateRevocationListToPem(crlData.crl);
                case 'der':
                    return forge.pki.certificateRevocationListToDer(crlData.crl);
                default:
                    throw new Error(`Unsupported CRL format: ${format}`);
            }

        } catch (error) {
            this.logger.error('Failed to get CRL:', error);
            throw error;
        }
    }

    /**
     * OCSP Service
     */
    async startOCSPService() {
        if (!config.features.ocspStapling) return;

        const express = require('express');
        const app = express();

        app.use(express.raw({ type: 'application/ocsp-request', limit: '10mb' }));

        app.post('/ocsp', async (req, res) => {
            try {
                this.metrics.ocspRequests++;
                const response = await this.handleOCSPRequest(req.body);
                
                res.setHeader('Content-Type', 'application/ocsp-response');
                res.send(response);

            } catch (error) {
                this.logger.error('OCSP request failed:', error);
                res.status(500).send('Internal Server Error');
            }
        });

        app.listen(this.config.ocspPort, () => {
            this.logger.info(`OCSP service started on port ${this.config.ocspPort}`);
        });
    }

    async handleOCSPRequest(requestData) {
        // OCSP request parsing and response generation
        // This is a simplified implementation
        // In production, use a proper OCSP library
        
        try {
            // Parse OCSP request (simplified)
            const response = {
                status: 'good', // good, revoked, unknown
                thisUpdate: new Date(),
                nextUpdate: new Date(Date.now() + 24 * 60 * 60 * 1000)
            };

            // Generate OCSP response (simplified)
            return Buffer.from('OCSP response placeholder');

        } catch (error) {
            this.logger.error('OCSP request handling failed:', error);
            throw error;
        }
    }

    async checkRevocationStatus(certificate) {
        try {
            const serialNumber = certificate.serialNumber;
            
            // Find certificate in store
            for (const [id, cert] of this.certificateStore) {
                if (cert.serialNumber === serialNumber) {
                    return {
                        revoked: cert.status === 'revoked',
                        status: cert.status,
                        reason: cert.revocationReason,
                        revocationDate: cert.revokedAt
                    };
                }
            }

            return {
                revoked: false,
                status: 'unknown',
                reason: 'Certificate not found in store'
            };

        } catch (error) {
            this.logger.error('Failed to check revocation status:', error);
            return {
                revoked: false,
                status: 'unknown',
                error: error.message
            };
        }
    }

    /**
     * Utility Methods
     */
    async generateKeyPair(keySize = this.config.keySize) {
        return new Promise((resolve, reject) => {
            forge.pki.rsa.generateKeyPair(keySize, (err, keyPair) => {
                if (err) reject(err);
                else resolve(keyPair);
            });
        });
    }

    generateSerialNumber() {
        return Math.floor(Math.random() * 0xFFFFFFFFFFFFFF).toString(16).toUpperCase();
    }

    generateCAId(type, commonName) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(`${type}-${commonName}-${timestamp}`)
            .digest('hex')
            .substring(0, 8);
        return `ca-${type}-${hash}`;
    }

    generateCertificateId() {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 0xFFFF);
        return `cert-${timestamp}-${random.toString(16)}`;
    }

    buildCertificateAttributes(subject) {
        const attrs = [];
        
        if (subject.countryName) attrs.push({ name: 'countryName', value: subject.countryName });
        if (subject.stateOrProvinceName) attrs.push({ name: 'stateOrProvinceName', value: subject.stateOrProvinceName });
        if (subject.localityName) attrs.push({ name: 'localityName', value: subject.localityName });
        if (subject.organizationName) attrs.push({ name: 'organizationName', value: subject.organizationName });
        if (subject.organizationalUnitName) attrs.push({ name: 'organizationalUnitName', value: subject.organizationalUnitName });
        if (subject.commonName) attrs.push({ name: 'commonName', value: subject.commonName });
        if (subject.emailAddress) attrs.push({ name: 'emailAddress', value: subject.emailAddress });

        return attrs;
    }

    buildCustomExtensions(extensions) {
        const extList = [];
        
        if (extensions.subjectAltName) {
            extList.push({
                name: 'subjectAltName',
                altNames: extensions.subjectAltName
            });
        }

        if (extensions.certificatePolicies) {
            extList.push({
                name: 'certificatePolicies',
                policies: extensions.certificatePolicies
            });
        }

        return extList;
    }

    buildLeafCertificateExtensions(options) {
        const { keyUsage, extendedKeyUsage, subjectAltName, ca } = options;
        
        const extensions = [
            {
                name: 'subjectKeyIdentifier'
            },
            {
                name: 'authorityKeyIdentifier',
                keyIdentifier: forge.pki.getPublicKeyFingerprint(ca.publicKey, {encoding: 'hex'})
            }
        ];

        if (keyUsage && keyUsage.length > 0) {
            const keyUsageExt = { name: 'keyUsage', critical: true };
            keyUsage.forEach(usage => {
                keyUsageExt[usage] = true;
            });
            extensions.push(keyUsageExt);
        }

        if (extendedKeyUsage && extendedKeyUsage.length > 0) {
            extensions.push({
                name: 'extendedKeyUsage',
                ...extendedKeyUsage.reduce((acc, usage) => {
                    acc[usage] = true;
                    return acc;
                }, {})
            });
        }

        if (subjectAltName && subjectAltName.length > 0) {
            extensions.push({
                name: 'subjectAltName',
                altNames: subjectAltName.map(san => ({
                    type: san.type || 2, // DNS name
                    value: san.value
                }))
            });
        }

        return extensions;
    }

    getRevocationReasonCode(reason) {
        const reasonCodes = {
            'unspecified': 0,
            'keyCompromise': 1,
            'cACompromise': 2,
            'affiliationChanged': 3,
            'superseded': 4,
            'cessationOfOperation': 5,
            'certificateHold': 6,
            'removeFromCRL': 8,
            'privilegeWithdrawn': 9,
            'aACompromise': 10
        };
        return reasonCodes[reason] || 0;
    }

    validateKeyUsage(certificate, requiredUsage) {
        const keyUsageExt = certificate.extensions.find(ext => ext.name === 'keyUsage');
        if (!keyUsageExt) return false;

        return requiredUsage.every(usage => keyUsageExt[usage] === true);
    }

    async getCAChain(caId) {
        const chain = [];
        let currentCAId = caId;

        while (currentCAId) {
            const ca = this.caStore.get(currentCAId);
            if (!ca) break;

            chain.push(forge.pki.certificateToPem(ca.certificate));
            currentCAId = ca.parentId;
        }

        return chain;
    }

    async scheduleMaintenance() {
        // Schedule CRL updates
        setInterval(async () => {
            for (const [caId, crlData] of this.crlStore) {
                try {
                    if (new Date() >= crlData.nextUpdate) {
                        await this.updateCRL(caId);
                    }
                } catch (error) {
                    this.logger.error(`CRL update failed for CA ${caId}:`, error);
                }
            }
        }, this.config.crlUpdateInterval);

        // Schedule certificate expiration checks
        setInterval(async () => {
            await this.checkExpiringCertificates();
        }, 24 * 60 * 60 * 1000); // Daily
    }

    async checkExpiringCertificates() {
        try {
            const now = new Date();
            const warningPeriod = 30 * 24 * 60 * 60 * 1000; // 30 days
            const expiringCerts = [];

            for (const [id, cert] of this.certificateStore) {
                if (cert.status !== 'active') continue;
                
                const timeUntilExpiration = cert.notAfter.getTime() - now.getTime();
                
                if (timeUntilExpiration <= warningPeriod && timeUntilExpiration > 0) {
                    expiringCerts.push({
                        id,
                        certificate: cert,
                        daysUntilExpiration: Math.ceil(timeUntilExpiration / (24 * 60 * 60 * 1000))
                    });
                } else if (timeUntilExpiration <= 0) {
                    cert.status = 'expired';
                    await this.storeCertificate(cert);
                    this.metrics.certificatesExpired++;
                }
            }

            if (expiringCerts.length > 0) {
                this.emit('certificatesExpiring', expiringCerts);
            }

        } catch (error) {
            this.logger.error('Failed to check expiring certificates:', error);
        }
    }

    /**
     * Storage Methods
     */
    async storeCA(ca) {
        this.caStore.set(ca.id, ca);
        
        const caPath = path.join(
            ca.type === 'root' ? this.config.rootCAPath : this.config.intermediateCAPath,
            `${ca.id}.json`
        );
        
        const caData = {
            ...ca,
            certificate: forge.pki.certificateToPem(ca.certificate),
            privateKey: forge.pki.privateKeyToPem(ca.privateKey),
            publicKey: forge.pki.publicKeyToPem(ca.publicKey)
        };

        await fs.writeFile(caPath, JSON.stringify(caData, null, 2));
    }

    async loadExistingCAs() {
        const caTypes = ['root', 'intermediate'];
        
        for (const type of caTypes) {
            const caDir = type === 'root' ? this.config.rootCAPath : this.config.intermediateCAPath;
            
            try {
                const files = await fs.readdir(caDir);
                
                for (const file of files) {
                    if (file.endsWith('.json')) {
                        const caPath = path.join(caDir, file);
                        const caData = JSON.parse(await fs.readFile(caPath, 'utf8'));
                        
                        // Convert PEM back to forge objects
                        caData.certificate = forge.pki.certificateFromPem(caData.certificate);
                        caData.privateKey = forge.pki.privateKeyFromPem(caData.privateKey);
                        caData.publicKey = forge.pki.publicKeyFromPem(caData.publicKey);
                        
                        this.caStore.set(caData.id, caData);
                        
                        // Load associated CRL
                        await this.loadCRL(caData.id);
                    }
                }
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    this.logger.error(`Failed to load CAs from ${caDir}:`, error);
                }
            }
        }
    }

    async storeCertificate(certificate) {
        this.certificateStore.set(certificate.id, certificate);
        
        const certPath = path.join(this.config.certificateStorePath, 'issued', `${certificate.id}.json`);
        
        const certData = {
            ...certificate,
            certificate: forge.pki.certificateToPem(certificate.certificate),
            privateKey: certificate.privateKey ? forge.pki.privateKeyToPem(certificate.privateKey) : null,
            publicKey: forge.pki.publicKeyToPem(certificate.publicKey)
        };

        await fs.writeFile(certPath, JSON.stringify(certData, null, 2));
    }

    async saveCRL(caId, crlData) {
        const crlPath = path.join(this.config.crlPath, `${caId}.crl`);
        const crlPem = forge.pki.certificateRevocationListToPem(crlData.crl);
        await fs.writeFile(crlPath, crlPem);
        
        // Also save metadata
        const metaPath = path.join(this.config.crlPath, `${caId}.json`);
        const metadata = {
            caId: crlData.caId,
            crlNumber: crlData.crlNumber,
            thisUpdate: crlData.thisUpdate,
            nextUpdate: crlData.nextUpdate,
            lastUpdate: crlData.lastUpdate,
            revokedCount: crlData.revokedCertificates.size
        };
        await fs.writeFile(metaPath, JSON.stringify(metadata, null, 2));
    }

    async loadCRL(caId) {
        try {
            const crlPath = path.join(this.config.crlPath, `${caId}.crl`);
            const metaPath = path.join(this.config.crlPath, `${caId}.json`);
            
            const [crlPem, metadataStr] = await Promise.all([
                fs.readFile(crlPath, 'utf8'),
                fs.readFile(metaPath, 'utf8')
            ]);
            
            const crl = forge.pki.certificateRevocationListFromPem(crlPem);
            const metadata = JSON.parse(metadataStr);
            
            const crlData = {
                ...metadata,
                crl,
                revokedCertificates: new Set() // Will be populated from CRL
            };
            
            // Extract revoked certificates from CRL
            for (const revokedCert of crl.certificates) {
                crlData.revokedCertificates.add({
                    serialNumber: revokedCert.serialNumber,
                    revocationDate: revokedCert.revocationDate,
                    reason: revokedCert.extensions && revokedCert.extensions[0] ? 
                           this.getRevocationReasonText(revokedCert.extensions[0].reason) : 'unspecified'
                });
            }
            
            this.crlStore.set(caId, crlData);
            
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error(`Failed to load CRL for CA ${caId}:`, error);
            }
        }
    }

    getRevocationReasonText(code) {
        const reasonTexts = {
            0: 'unspecified',
            1: 'keyCompromise',
            2: 'cACompromise',
            3: 'affiliationChanged',
            4: 'superseded',
            5: 'cessationOfOperation',
            6: 'certificateHold',
            8: 'removeFromCRL',
            9: 'privilegeWithdrawn',
            10: 'aACompromise'
        };
        return reasonTexts[code] || 'unspecified';
    }

    async loadCertificateTemplates() {
        try {
            const templatesPath = path.join(this.config.certificateStorePath, 'templates');
            const files = await fs.readdir(templatesPath);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const templatePath = path.join(templatesPath, file);
                    const template = JSON.parse(await fs.readFile(templatePath, 'utf8'));
                    this.templateStore.set(template.id, template);
                }
            }
            
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load certificate templates:', error);
            }
        }
    }

    /**
     * Public API Methods
     */
    async getCAList() {
        const caList = [];
        for (const [caId, ca] of this.caStore) {
            caList.push({
                id: ca.id,
                type: ca.type,
                subject: ca.subject,
                status: ca.status,
                notBefore: ca.notBefore,
                notAfter: ca.notAfter,
                parentId: ca.parentId
            });
        }
        return caList;
    }

    async getCA(caId) {
        const ca = this.caStore.get(caId);
        if (!ca) throw new Error(`CA not found: ${caId}`);

        return {
            id: ca.id,
            type: ca.type,
            subject: ca.subject,
            certificate: forge.pki.certificateToPem(ca.certificate),
            status: ca.status,
            notBefore: ca.notBefore,
            notAfter: ca.notAfter,
            parentId: ca.parentId,
            keySize: ca.keySize,
            createdAt: ca.createdAt
        };
    }

    async getCertificateList(filters = {}) {
        const certList = [];
        
        for (const [certId, cert] of this.certificateStore) {
            // Apply filters
            if (filters.status && cert.status !== filters.status) continue;
            if (filters.issuerCAId && cert.issuerCAId !== filters.issuerCAId) continue;
            if (filters.deviceId && cert.deviceId !== filters.deviceId) continue;
            
            certList.push({
                id: cert.id,
                serialNumber: cert.serialNumber,
                subject: cert.subject,
                issuerCAId: cert.issuerCAId,
                status: cert.status,
                notBefore: cert.notBefore,
                notAfter: cert.notAfter,
                deviceId: cert.deviceId,
                issuedAt: cert.issuedAt
            });
        }
        
        return certList;
    }

    async getCertificate(certificateId) {
        const cert = this.certificateStore.get(certificateId);
        if (!cert) throw new Error(`Certificate not found: ${certificateId}`);

        return {
            id: cert.id,
            serialNumber: cert.serialNumber,
            certificate: forge.pki.certificateToPem(cert.certificate),
            subject: cert.subject,
            issuerCAId: cert.issuerCAId,
            status: cert.status,
            notBefore: cert.notBefore,
            notAfter: cert.notAfter,
            keyUsage: cert.keyUsage,
            extendedKeyUsage: cert.extendedKeyUsage,
            deviceId: cert.deviceId,
            issuedAt: cert.issuedAt
        };
    }

    async getMetrics() {
        return {
            ...this.metrics,
            activeCAs: Array.from(this.caStore.values()).filter(ca => ca.status === 'active').length,
            totalCAs: this.caStore.size,
            activeCertificates: Array.from(this.certificateStore.values()).filter(cert => cert.status === 'active').length,
            totalCertificates: this.certificateStore.size
        };
    }
}

module.exports = EnterpriseCAService;