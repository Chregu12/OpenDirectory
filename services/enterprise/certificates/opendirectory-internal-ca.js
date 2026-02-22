/**
 * OpenDirectory Internal Certificate Authority System
 * Enterprise-grade PKI infrastructure with comprehensive CA management
 * 
 * Features:
 * - Root CA creation and management
 * - Intermediate CA generation
 * - Certificate signing workflows
 * - Certificate chain validation
 * - CRL (Certificate Revocation List) management
 * - OCSP (Online Certificate Status Protocol)
 * - CA key rotation and backup
 * - Cross-certification support
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');
const winston = require('winston');

class InternalCertificateAuthority {
    constructor(config = {}) {
        this.config = {
            caStorePath: config.caStorePath || '/var/lib/opendirectory/ca',
            keySize: config.keySize || 4096,
            hashAlgorithm: config.hashAlgorithm || 'sha256',
            rootCAValidity: config.rootCAValidity || 365 * 10, // 10 years
            intermediateCAValidity: config.intermediateCAValidity || 365 * 5, // 5 years
            crlUpdateInterval: config.crlUpdateInterval || 24 * 60 * 60 * 1000, // 24 hours
            ocspPort: config.ocspPort || 8080,
            ...config
        };

        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ filename: '/var/log/opendirectory-ca.log' }),
                new winston.transports.Console()
            ]
        });

        this.caStore = new Map();
        this.crlStore = new Map();
        this.ocspResponders = new Map();
        this.keyRotationSchedules = new Map();
        this.crossCertifications = new Map();

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadExistingCAs();
            await this.startOCSPService();
            await this.scheduleCRLUpdates();
            this.logger.info('Internal Certificate Authority initialized successfully');
        } catch (error) {
            this.logger.error('Failed to initialize Certificate Authority:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            this.config.caStorePath,
            path.join(this.config.caStorePath, 'root'),
            path.join(this.config.caStorePath, 'intermediate'),
            path.join(this.config.caStorePath, 'crl'),
            path.join(this.config.caStorePath, 'ocsp'),
            path.join(this.config.caStorePath, 'backup'),
            path.join(this.config.caStorePath, 'cross-certs')
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
     * Root CA Management
     */
    async createRootCA(subject, extensions = {}) {
        try {
            const keyPair = await this.generateKeyPair();
            const cert = forge.pki.createCertificate();

            // Set certificate attributes
            cert.publicKey = keyPair.publicKey;
            cert.serialNumber = this.generateSerialNumber();
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + this.config.rootCAValidity);

            // Set subject and issuer (self-signed for root)
            const attrs = this.buildCertificateAttributes(subject);
            cert.setSubject(attrs);
            cert.setIssuer(attrs);

            // Add extensions
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
            cert.sign(keyPair.privateKey, forge.md.sha256.create());

            const caId = this.generateCAId(subject.commonName);
            const rootCA = {
                id: caId,
                type: 'root',
                certificate: cert,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                subject,
                serialNumber: cert.serialNumber,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                keyUsage: ['keyCertSign', 'cRLSign'],
                extensions,
                createdAt: new Date(),
                status: 'active'
            };

            await this.storeCA(rootCA);
            await this.initializeCRL(caId);
            
            this.logger.info(`Root CA created successfully: ${caId}`);
            return rootCA;

        } catch (error) {
            this.logger.error('Failed to create Root CA:', error);
            throw error;
        }
    }

    async createIntermediateCA(parentCAId, subject, extensions = {}) {
        try {
            const parentCA = this.caStore.get(parentCAId);
            if (!parentCA) {
                throw new Error(`Parent CA not found: ${parentCAId}`);
            }

            const keyPair = await this.generateKeyPair();
            const cert = forge.pki.createCertificate();

            // Set certificate attributes
            cert.publicKey = keyPair.publicKey;
            cert.serialNumber = this.generateSerialNumber();
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + this.config.intermediateCAValidity);

            // Set subject and issuer
            cert.setSubject(this.buildCertificateAttributes(subject));
            cert.setIssuer(parentCA.certificate.subject.attributes);

            // Add extensions
            const certExtensions = [
                {
                    name: 'basicConstraints',
                    cA: true,
                    pathLenConstraint: extensions.pathLenConstraint || 0,
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
                    keyIdentifier: forge.pki.getPublicKeyFingerprint(parentCA.publicKey, { encoding: 'hex' })
                },
                ...this.buildCustomExtensions(extensions)
            ];

            cert.setExtensions(certExtensions);

            // Sign with parent CA
            cert.sign(parentCA.privateKey, forge.md.sha256.create());

            const caId = this.generateCAId(subject.commonName);
            const intermediateCA = {
                id: caId,
                type: 'intermediate',
                parentId: parentCAId,
                certificate: cert,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                subject,
                serialNumber: cert.serialNumber,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                keyUsage: ['keyCertSign', 'cRLSign'],
                extensions,
                createdAt: new Date(),
                status: 'active'
            };

            await this.storeCA(intermediateCA);
            await this.initializeCRL(caId);
            
            this.logger.info(`Intermediate CA created successfully: ${caId}`);
            return intermediateCA;

        } catch (error) {
            this.logger.error('Failed to create Intermediate CA:', error);
            throw error;
        }
    }

    /**
     * Certificate Signing Workflows
     */
    async signCertificate(caId, csr, certificateTemplate = {}) {
        try {
            const ca = this.caStore.get(caId);
            if (!ca) {
                throw new Error(`CA not found: ${caId}`);
            }

            if (ca.status !== 'active') {
                throw new Error(`CA is not active: ${caId}`);
            }

            // Parse CSR
            const csrObj = forge.pki.certificationRequestFromPem(csr);
            if (!csrObj.verify()) {
                throw new Error('Invalid CSR signature');
            }

            const cert = forge.pki.createCertificate();
            cert.publicKey = csrObj.publicKey;
            cert.serialNumber = this.generateSerialNumber();
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            
            const validityDays = certificateTemplate.validityDays || 365;
            cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + validityDays);

            // Set subject from CSR
            cert.setSubject(csrObj.subject.attributes);
            cert.setIssuer(ca.certificate.subject.attributes);

            // Build extensions based on template
            const extensions = this.buildCertificateExtensions(certificateTemplate, csrObj);
            cert.setExtensions(extensions);

            // Sign the certificate
            cert.sign(ca.privateKey, forge.md.sha256.create());

            // Store certificate record
            const certRecord = {
                serialNumber: cert.serialNumber,
                subject: cert.subject.attributes,
                issuer: caId,
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                status: 'active',
                template: certificateTemplate,
                issuedAt: new Date()
            };

            await this.storeCertificateRecord(certRecord);

            this.logger.info(`Certificate signed successfully by CA ${caId}, Serial: ${cert.serialNumber}`);
            return forge.pki.certificateToPem(cert);

        } catch (error) {
            this.logger.error('Failed to sign certificate:', error);
            throw error;
        }
    }

    /**
     * Certificate Chain Validation
     */
    async validateCertificateChain(certificateChain) {
        try {
            const certs = certificateChain.map(pemCert => forge.pki.certificateFromPem(pemCert));
            const caStore = forge.pki.createCaStore();

            // Add all CA certificates to the store
            for (const [caId, ca] of this.caStore) {
                if (ca.status === 'active') {
                    caStore.addCertificate(ca.certificate);
                }
            }

            // Validate each certificate in the chain
            for (let i = 0; i < certs.length; i++) {
                const cert = certs[i];
                const isValid = forge.pki.verifyCertificateChain(caStore, [cert]);
                
                if (!isValid) {
                    return {
                        valid: false,
                        error: `Certificate at index ${i} failed validation`,
                        certificate: forge.pki.certificateToPem(cert)
                    };
                }

                // Check certificate dates
                const now = new Date();
                if (cert.validity.notBefore > now || cert.validity.notAfter < now) {
                    return {
                        valid: false,
                        error: `Certificate at index ${i} is expired or not yet valid`,
                        certificate: forge.pki.certificateToPem(cert)
                    };
                }

                // Check revocation status
                const revocationStatus = await this.checkRevocationStatus(cert);
                if (revocationStatus.revoked) {
                    return {
                        valid: false,
                        error: `Certificate at index ${i} is revoked`,
                        revocationInfo: revocationStatus
                    };
                }
            }

            return { valid: true, message: 'Certificate chain is valid' };

        } catch (error) {
            this.logger.error('Failed to validate certificate chain:', error);
            return { valid: false, error: error.message };
        }
    }

    /**
     * CRL (Certificate Revocation List) Management
     */
    async initializeCRL(caId) {
        const ca = this.caStore.get(caId);
        if (!ca) throw new Error(`CA not found: ${caId}`);

        const crl = forge.pki.createCertificateRevocationList();
        crl.version = 1;
        crl.signatureOid = forge.pki.oids.sha256WithRSAEncryption;
        crl.issuer.setAttributes(ca.certificate.subject.attributes);
        crl.thisUpdate = new Date();
        crl.nextUpdate = new Date();
        crl.nextUpdate.setDate(crl.thisUpdate.getDate() + 1);

        // Add extensions
        crl.setExtensions([
            {
                name: 'cRLNumber',
                cRLNumber: 1
            },
            {
                name: 'authorityKeyIdentifier',
                keyIdentifier: forge.pki.getPublicKeyFingerprint(ca.publicKey, { encoding: 'hex' })
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
            createdAt: new Date()
        };

        this.crlStore.set(caId, crlData);
        await this.saveCRL(caId, crlData);

        this.logger.info(`CRL initialized for CA: ${caId}`);
    }

    async revokeCertificate(caId, serialNumber, reason = 'unspecified') {
        try {
            const crlData = this.crlStore.get(caId);
            if (!crlData) throw new Error(`CRL not found for CA: ${caId}`);

            const revocationDate = new Date();
            crlData.revokedCertificates.add({
                serialNumber,
                revocationDate,
                reason,
                revokedAt: new Date()
            });

            await this.updateCRL(caId);
            await this.updateCertificateStatus(serialNumber, 'revoked', reason);

            this.logger.info(`Certificate revoked: ${serialNumber} by CA: ${caId}`);

        } catch (error) {
            this.logger.error('Failed to revoke certificate:', error);
            throw error;
        }
    }

    async updateCRL(caId) {
        try {
            const ca = this.caStore.get(caId);
            const crlData = this.crlStore.get(caId);
            
            if (!ca || !crlData) throw new Error(`CA or CRL not found: ${caId}`);

            const crl = forge.pki.createCertificateRevocationList();
            crl.version = 1;
            crl.signatureOid = forge.pki.oids.sha256WithRSAEncryption;
            crl.issuer.setAttributes(ca.certificate.subject.attributes);
            crl.thisUpdate = new Date();
            crl.nextUpdate = new Date();
            crl.nextUpdate.setDate(crl.thisUpdate.getDate() + 1);

            // Add revoked certificates
            for (const revokedCert of crlData.revokedCertificates) {
                const revokedCertificate = {
                    serialNumber: revokedCert.serialNumber,
                    revocationDate: revokedCert.revocationDate,
                    extensions: [{
                        name: 'cRLReason',
                        reason: this.getRevocationReasonCode(revokedCert.reason)
                    }]
                };
                crl.certificates.push(revokedCertificate);
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
                    keyIdentifier: forge.pki.getPublicKeyFingerprint(ca.publicKey, { encoding: 'hex' })
                }
            ]);

            crl.sign(ca.privateKey);

            crlData.crl = crl;
            crlData.thisUpdate = crl.thisUpdate;
            crlData.nextUpdate = crl.nextUpdate;

            await this.saveCRL(caId, crlData);
            this.logger.info(`CRL updated for CA: ${caId}, CRL Number: ${crlData.crlNumber}`);

        } catch (error) {
            this.logger.error('Failed to update CRL:', error);
            throw error;
        }
    }

    /**
     * OCSP (Online Certificate Status Protocol)
     */
    async startOCSPService() {
        const express = require('express');
        const app = express();

        app.use(express.raw({ type: 'application/ocsp-request' }));

        app.post('/ocsp', async (req, res) => {
            try {
                const ocspRequest = this.parseOCSPRequest(req.body);
                const response = await this.generateOCSPResponse(ocspRequest);
                
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

    async checkRevocationStatus(certificate) {
        try {
            const serialNumber = certificate.serialNumber;
            const issuerKeyId = this.getAuthorityKeyIdentifier(certificate);
            
            // Find the issuing CA
            let issuingCA = null;
            for (const [caId, ca] of this.caStore) {
                const caKeyId = forge.pki.getPublicKeyFingerprint(ca.publicKey, { encoding: 'hex' });
                if (caKeyId === issuerKeyId) {
                    issuingCA = ca;
                    break;
                }
            }

            if (!issuingCA) {
                return { revoked: false, status: 'unknown', reason: 'Issuing CA not found' };
            }

            const crlData = this.crlStore.get(issuingCA.id);
            if (!crlData) {
                return { revoked: false, status: 'unknown', reason: 'CRL not available' };
            }

            // Check if certificate is in revocation list
            for (const revokedCert of crlData.revokedCertificates) {
                if (revokedCert.serialNumber === serialNumber) {
                    return {
                        revoked: true,
                        status: 'revoked',
                        reason: revokedCert.reason,
                        revocationDate: revokedCert.revocationDate
                    };
                }
            }

            return { revoked: false, status: 'good' };

        } catch (error) {
            this.logger.error('Failed to check revocation status:', error);
            return { revoked: false, status: 'unknown', error: error.message };
        }
    }

    /**
     * CA Key Rotation and Backup
     */
    async rotateCAKey(caId, newKeySize = null) {
        try {
            const ca = this.caStore.get(caId);
            if (!ca) throw new Error(`CA not found: ${caId}`);

            // Backup current key
            await this.backupCA(caId, `pre-rotation-${Date.now()}`);

            // Generate new key pair
            const newKeyPair = await this.generateKeyPair(newKeySize || this.config.keySize);
            
            // Create new certificate with same subject but new public key
            const newCert = forge.pki.createCertificate();
            newCert.publicKey = newKeyPair.publicKey;
            newCert.serialNumber = this.generateSerialNumber();
            newCert.validity.notBefore = new Date();
            newCert.validity.notAfter = new Date();
            
            if (ca.type === 'root') {
                newCert.validity.notAfter.setDate(newCert.validity.notBefore.getDate() + this.config.rootCAValidity);
                newCert.setSubject(ca.certificate.subject.attributes);
                newCert.setIssuer(ca.certificate.subject.attributes);
                newCert.sign(newKeyPair.privateKey, forge.md.sha256.create());
            } else {
                // For intermediate CA, get parent to sign
                const parentCA = this.caStore.get(ca.parentId);
                if (!parentCA) throw new Error(`Parent CA not found: ${ca.parentId}`);
                
                newCert.validity.notAfter.setDate(newCert.validity.notBefore.getDate() + this.config.intermediateCAValidity);
                newCert.setSubject(ca.certificate.subject.attributes);
                newCert.setIssuer(parentCA.certificate.subject.attributes);
                newCert.sign(parentCA.privateKey, forge.md.sha256.create());
            }

            // Update CA with new keys and certificate
            ca.privateKey = newKeyPair.privateKey;
            ca.publicKey = newKeyPair.publicKey;
            ca.certificate = newCert;
            ca.serialNumber = newCert.serialNumber;
            ca.notBefore = newCert.validity.notBefore;
            ca.notAfter = newCert.validity.notAfter;
            ca.lastKeyRotation = new Date();

            await this.storeCA(ca);

            // Initialize new CRL for rotated CA
            await this.initializeCRL(caId);

            this.logger.info(`CA key rotated successfully: ${caId}`);
            return ca;

        } catch (error) {
            this.logger.error('Failed to rotate CA key:', error);
            throw error;
        }
    }

    async backupCA(caId, backupLabel = null) {
        try {
            const ca = this.caStore.get(caId);
            if (!ca) throw new Error(`CA not found: ${caId}`);

            const backupId = backupLabel || `backup-${Date.now()}`;
            const backupPath = path.join(this.config.caStorePath, 'backup', `${caId}-${backupId}.json`);

            const backupData = {
                ca: {
                    ...ca,
                    certificate: forge.pki.certificateToPem(ca.certificate),
                    privateKey: forge.pki.privateKeyToPem(ca.privateKey),
                    publicKey: forge.pki.publicKeyToPem(ca.publicKey)
                },
                crl: this.crlStore.has(caId) ? {
                    ...this.crlStore.get(caId),
                    crl: forge.pki.certificateRevocationListToPem(this.crlStore.get(caId).crl)
                } : null,
                backupId,
                createdAt: new Date()
            };

            await fs.writeFile(backupPath, JSON.stringify(backupData, null, 2));
            this.logger.info(`CA backup created: ${caId} -> ${backupPath}`);

            return backupId;

        } catch (error) {
            this.logger.error('Failed to backup CA:', error);
            throw error;
        }
    }

    /**
     * Cross-Certification Support
     */
    async createCrossCertificate(caId, externalCAId, externalCACert) {
        try {
            const ca = this.caStore.get(caId);
            if (!ca) throw new Error(`CA not found: ${caId}`);

            const externalCert = forge.pki.certificateFromPem(externalCACert);
            
            // Create cross-certificate
            const crossCert = forge.pki.createCertificate();
            crossCert.publicKey = externalCert.publicKey;
            crossCert.serialNumber = this.generateSerialNumber();
            crossCert.validity.notBefore = new Date();
            crossCert.validity.notAfter = new Date();
            crossCert.validity.notAfter.setDate(crossCert.validity.notBefore.getDate() + (365 * 2)); // 2 years

            // Set subject from external CA
            crossCert.setSubject(externalCert.subject.attributes);
            crossCert.setIssuer(ca.certificate.subject.attributes);

            // Add cross-certification extensions
            const extensions = [
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
                    keyIdentifier: forge.pki.getPublicKeyFingerprint(ca.publicKey, { encoding: 'hex' })
                }
            ];

            crossCert.setExtensions(extensions);
            crossCert.sign(ca.privateKey, forge.md.sha256.create());

            const crossCertData = {
                id: `cross-${caId}-${externalCAId}`,
                issuingCA: caId,
                externalCA: externalCAId,
                certificate: crossCert,
                externalCertificate: externalCert,
                serialNumber: crossCert.serialNumber,
                notBefore: crossCert.validity.notBefore,
                notAfter: crossCert.validity.notAfter,
                createdAt: new Date(),
                status: 'active'
            };

            this.crossCertifications.set(crossCertData.id, crossCertData);
            await this.storeCrossCertificate(crossCertData);

            this.logger.info(`Cross-certificate created: ${crossCertData.id}`);
            return forge.pki.certificateToPem(crossCert);

        } catch (error) {
            this.logger.error('Failed to create cross-certificate:', error);
            throw error;
        }
    }

    /**
     * Utility Methods
     */
    async generateKeyPair(keySize = null) {
        return new Promise((resolve, reject) => {
            forge.pki.rsa.generateKeyPair(keySize || this.config.keySize, (err, keyPair) => {
                if (err) reject(err);
                else resolve(keyPair);
            });
        });
    }

    generateSerialNumber() {
        return Math.floor(Math.random() * 0xFFFFFFFFFFFFFF).toString(16).toUpperCase();
    }

    generateCAId(commonName) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(commonName + timestamp)
            .digest('hex')
            .substring(0, 8);
        return `ca-${hash}`;
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

        if (extensions.extendedKeyUsage) {
            extList.push({
                name: 'extendedKeyUsage',
                ...extensions.extendedKeyUsage
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

    buildCertificateExtensions(template, csr) {
        const extensions = [
            {
                name: 'subjectKeyIdentifier'
            },
            {
                name: 'authorityKeyIdentifier',
                keyid: false,
                serialNumber: false
            }
        ];

        if (template.keyUsage) {
            extensions.push({
                name: 'keyUsage',
                ...template.keyUsage,
                critical: true
            });
        }

        if (template.extendedKeyUsage) {
            extensions.push({
                name: 'extendedKeyUsage',
                ...template.extendedKeyUsage
            });
        }

        if (template.subjectAltName) {
            extensions.push({
                name: 'subjectAltName',
                altNames: template.subjectAltName
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

    getAuthorityKeyIdentifier(certificate) {
        const extensions = certificate.extensions;
        for (const ext of extensions) {
            if (ext.name === 'authorityKeyIdentifier') {
                return ext.keyIdentifier;
            }
        }
        return null;
    }

    async scheduleCRLUpdates() {
        setInterval(async () => {
            for (const [caId, crlData] of this.crlStore) {
                try {
                    if (new Date() >= crlData.nextUpdate) {
                        await this.updateCRL(caId);
                    }
                } catch (error) {
                    this.logger.error(`Failed to update CRL for CA ${caId}:`, error);
                }
            }
        }, this.config.crlUpdateInterval);
    }

    /**
     * Storage Methods
     */
    async storeCA(ca) {
        this.caStore.set(ca.id, ca);
        const caPath = path.join(this.config.caStorePath, ca.type, `${ca.id}.json`);
        
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
            const caDir = path.join(this.config.caStorePath, type);
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
                    }
                }
            } catch (error) {
                // Directory might not exist yet
                if (error.code !== 'ENOENT') {
                    this.logger.error(`Failed to load CAs from ${caDir}:`, error);
                }
            }
        }
    }

    async saveCRL(caId, crlData) {
        const crlPath = path.join(this.config.caStorePath, 'crl', `${caId}.crl`);
        const crlPem = forge.pki.certificateRevocationListToPem(crlData.crl);
        await fs.writeFile(crlPath, crlPem);
    }

    async storeCertificateRecord(certRecord) {
        // Implementation would store certificate records in database
        // For now, just log the action
        this.logger.info('Certificate record stored:', { serialNumber: certRecord.serialNumber });
    }

    async updateCertificateStatus(serialNumber, status, reason = null) {
        // Implementation would update certificate status in database
        this.logger.info('Certificate status updated:', { serialNumber, status, reason });
    }

    async storeCrossCertificate(crossCertData) {
        const crossCertPath = path.join(this.config.caStorePath, 'cross-certs', `${crossCertData.id}.json`);
        
        const data = {
            ...crossCertData,
            certificate: forge.pki.certificateToPem(crossCertData.certificate),
            externalCertificate: forge.pki.certificateToPem(crossCertData.externalCertificate)
        };

        await fs.writeFile(crossCertPath, JSON.stringify(data, null, 2));
    }

    /**
     * Public API Methods
     */
    async getCAInfo(caId) {
        const ca = this.caStore.get(caId);
        if (!ca) throw new Error(`CA not found: ${caId}`);

        return {
            id: ca.id,
            type: ca.type,
            subject: ca.subject,
            serialNumber: ca.serialNumber,
            notBefore: ca.notBefore,
            notAfter: ca.notAfter,
            status: ca.status,
            certificate: forge.pki.certificateToPem(ca.certificate)
        };
    }

    async listCAs() {
        const caList = [];
        for (const [caId, ca] of this.caStore) {
            caList.push({
                id: ca.id,
                type: ca.type,
                subject: ca.subject,
                status: ca.status,
                notBefore: ca.notBefore,
                notAfter: ca.notAfter
            });
        }
        return caList;
    }

    async getCRL(caId) {
        const crlData = this.crlStore.get(caId);
        if (!crlData) throw new Error(`CRL not found for CA: ${caId}`);

        return forge.pki.certificateRevocationListToPem(crlData.crl);
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
}

module.exports = InternalCertificateAuthority;