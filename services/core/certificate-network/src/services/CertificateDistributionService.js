/**
 * OpenDirectory Certificate Distribution Service
 * Comprehensive certificate distribution system for all platforms
 * 
 * Features:
 * - Multi-platform certificate deployment (Windows, macOS, iOS, Android, Linux)
 * - Multiple distribution methods (MDM, SCEP, manual, API)
 * - Platform-specific certificate stores and formats
 * - Automated deployment workflows
 * - Certificate revocation and removal
 * - Distribution tracking and compliance reporting
 * - Bulk distribution operations
 * - Integration with existing device management systems
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const EventEmitter = require('events');
const archiver = require('archiver');
const config = require('../config');

class CertificateDistributionService extends EventEmitter {
    constructor(certificateService, mdmService, options = {}) {
        super();
        
        this.certificateService = certificateService;
        this.mdmService = mdmService;
        this.config = {
            ...config,
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
                    filename: path.join(path.dirname(config.logging.file), 'cert-distribution.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // Distribution stores
        this.distributionJobs = new Map();
        this.distributionPolicies = new Map();
        this.deviceCertificates = new Map(); // Track certificates per device
        this.complianceReports = new Map();
        
        // Platform-specific handlers
        this.platformHandlers = {
            windows: this.createWindowsHandler(),
            macos: this.createMacOSHandler(),
            ios: this.createIOSHandler(),
            android: this.createAndroidHandler(),
            linux: this.createLinuxHandler()
        };

        // Distribution methods
        this.distributionMethods = {
            mdm: this.distributeMDM.bind(this),
            scep: this.distributeSCEP.bind(this),
            api: this.distributeAPI.bind(this),
            manual: this.distributeManual.bind(this),
            email: this.distributeEmail.bind(this),
            download: this.distributeDownload.bind(this)
        };

        // Metrics
        this.metrics = {
            totalDistributions: 0,
            successfulDistributions: 0,
            failedDistributions: 0,
            certificatesDeployed: 0,
            certificatesRevoked: 0,
            devicesCertified: 0,
            complianceRate: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadDistributionPolicies();
            await this.loadDeviceCertificateMapping();
            this.scheduleComplianceChecks();
            
            this.logger.info('Certificate Distribution Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize Certificate Distribution Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            path.join(config.storage.certificates, 'distribution'),
            path.join(config.storage.certificates, 'distribution', 'jobs'),
            path.join(config.storage.certificates, 'distribution', 'policies'),
            path.join(config.storage.certificates, 'distribution', 'packages'),
            path.join(config.storage.certificates, 'distribution', 'compliance'),
            path.join(config.storage.certificates, 'distribution', 'device-mapping')
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
     * Distribution Policy Management
     */
    async createDistributionPolicy(policyData) {
        try {
            const policyId = this.generatePolicyId(policyData.name);
            const policy = {
                id: policyId,
                name: policyData.name,
                description: policyData.description || '',
                enabled: policyData.enabled !== false,
                priority: policyData.priority || 100,
                
                // Certificate selection
                certificateFilters: {
                    templateIds: policyData.certificateFilters?.templateIds || [],
                    certificateTypes: policyData.certificateFilters?.certificateTypes || [],
                    keyUsage: policyData.certificateFilters?.keyUsage || [],
                    expiryThreshold: policyData.certificateFilters?.expiryThreshold || 30 // days
                },
                
                // Target selection
                targets: {
                    deviceTypes: policyData.targets?.deviceTypes || [],
                    deviceGroups: policyData.targets?.deviceGroups || [],
                    userGroups: policyData.targets?.userGroups || [],
                    deviceTags: policyData.targets?.deviceTags || [],
                    excludeDevices: policyData.targets?.excludeDevices || []
                },
                
                // Distribution settings
                distribution: {
                    methods: policyData.distribution?.methods || ['mdm'],
                    primaryMethod: policyData.distribution?.primaryMethod || 'mdm',
                    fallbackMethods: policyData.distribution?.fallbackMethods || ['manual'],
                    retryAttempts: policyData.distribution?.retryAttempts || 3,
                    retryInterval: policyData.distribution?.retryInterval || 60000 // ms
                },
                
                // Platform-specific settings
                platforms: {
                    windows: {
                        stores: policyData.platforms?.windows?.stores || ['My', 'TrustedPeople'],
                        installLocation: policyData.platforms?.windows?.installLocation || 'CurrentUser',
                        exportable: policyData.platforms?.windows?.exportable || false
                    },
                    macos: {
                        keychain: policyData.platforms?.macos?.keychain || 'login',
                        trustSettings: policyData.platforms?.macos?.trustSettings || 'user',
                        allowRoot: policyData.platforms?.macos?.allowRoot || false
                    },
                    ios: {
                        profileScope: policyData.platforms?.ios?.profileScope || 'User',
                        removeOnDisenroll: policyData.platforms?.ios?.removeOnDisenroll !== false,
                        allowOverNetwork: policyData.platforms?.ios?.allowOverNetwork !== false
                    },
                    android: {
                        installLocation: policyData.platforms?.android?.installLocation || 'user',
                        requireDeviceAdmin: policyData.platforms?.android?.requireDeviceAdmin || false,
                        wifiOnly: policyData.platforms?.android?.wifiOnly || false
                    },
                    linux: {
                        stores: policyData.platforms?.linux?.stores || ['/etc/ssl/certs', '~/.local/share/ca-certificates'],
                        trustStore: policyData.platforms?.linux?.trustStore || 'system',
                        updateCertificates: policyData.platforms?.linux?.updateCertificates !== false
                    }
                },
                
                // Scheduling
                schedule: {
                    immediate: policyData.schedule?.immediate !== false,
                    maintenance: policyData.schedule?.maintenance || false,
                    maintenanceWindow: policyData.schedule?.maintenanceWindow || null,
                    recurring: policyData.schedule?.recurring || false,
                    recurringInterval: policyData.schedule?.recurringInterval || 'weekly'
                },
                
                // Compliance and monitoring
                compliance: {
                    required: policyData.compliance?.required !== false,
                    gracePeriod: policyData.compliance?.gracePeriod || 7, // days
                    enforcementAction: policyData.compliance?.enforcementAction || 'report',
                    notifyUsers: policyData.compliance?.notifyUsers !== false
                },
                
                createdAt: new Date(),
                updatedAt: new Date()
            };

            this.distributionPolicies.set(policyId, policy);
            await this.saveDistributionPolicy(policy);
            
            this.logger.info(`Distribution policy created: ${policyId}`);
            this.emit('policyCreated', policy);
            
            return policy;

        } catch (error) {
            this.logger.error('Failed to create distribution policy:', error);
            throw error;
        }
    }

    /**
     * Certificate Distribution Jobs
     */
    async createDistributionJob(jobData) {
        try {
            const jobId = this.generateJobId();
            const job = {
                id: jobId,
                name: jobData.name || `Distribution Job ${jobId}`,
                type: jobData.type || 'certificate', // certificate, revocation, update
                status: 'pending',
                
                // Certificates to distribute
                certificates: jobData.certificates || [],
                certificateIds: jobData.certificateIds || [],
                
                // Target devices
                targetDevices: jobData.targetDevices || [],
                targetGroups: jobData.targetGroups || [],
                targetPolicies: jobData.targetPolicies || [],
                
                // Distribution configuration
                distributionMethods: jobData.distributionMethods || ['mdm'],
                priority: jobData.priority || 'normal',
                
                // Scheduling
                scheduledFor: jobData.scheduledFor || new Date(),
                timeoutMs: jobData.timeoutMs || 30 * 60 * 1000, // 30 minutes
                
                // Progress tracking
                progress: {
                    total: 0,
                    completed: 0,
                    failed: 0,
                    inProgress: 0,
                    results: []
                },
                
                // Metadata
                createdBy: jobData.createdBy || 'system',
                createdAt: new Date(),
                startedAt: null,
                completedAt: null,
                metadata: jobData.metadata || {}
            };

            // Calculate total targets
            job.progress.total = await this.calculateJobTargets(job);
            
            this.distributionJobs.set(jobId, job);
            await this.saveDistributionJob(job);
            
            // Schedule job execution
            if (job.scheduledFor <= new Date()) {
                setImmediate(() => this.executeDistributionJob(jobId));
            } else {
                const delay = job.scheduledFor.getTime() - Date.now();
                setTimeout(() => this.executeDistributionJob(jobId), delay);
            }
            
            this.logger.info(`Distribution job created: ${jobId}`);
            this.emit('jobCreated', job);
            
            return job;

        } catch (error) {
            this.logger.error('Failed to create distribution job:', error);
            throw error;
        }
    }

    async executeDistributionJob(jobId) {
        try {
            const job = this.distributionJobs.get(jobId);
            if (!job) {
                throw new Error(`Distribution job not found: ${jobId}`);
            }

            if (job.status !== 'pending') {
                this.logger.warn(`Job ${jobId} is not pending, current status: ${job.status}`);
                return;
            }

            job.status = 'running';
            job.startedAt = new Date();
            
            this.logger.info(`Executing distribution job: ${jobId}`);
            this.emit('jobStarted', job);

            // Get target devices
            const targetDevices = await this.resolveJobTargets(job);
            job.progress.total = targetDevices.length;
            
            // Get certificates to distribute
            const certificates = await this.resolveJobCertificates(job);
            
            // Execute distribution for each device
            const distributionPromises = [];
            for (const device of targetDevices) {
                for (const certificate of certificates) {
                    const distributionPromise = this.distributeCertificateToDevice(
                        certificate,
                        device,
                        job.distributionMethods,
                        job
                    );
                    distributionPromises.push(distributionPromise);
                }
            }

            // Wait for all distributions to complete
            const results = await Promise.allSettled(distributionPromises);
            
            // Process results
            let completed = 0;
            let failed = 0;
            
            results.forEach((result, index) => {
                if (result.status === 'fulfilled') {
                    if (result.value.success) {
                        completed++;
                    } else {
                        failed++;
                    }
                } else {
                    failed++;
                }
                
                job.progress.results.push({
                    deviceId: targetDevices[index % targetDevices.length]?.id,
                    certificateId: certificates[Math.floor(index / targetDevices.length)]?.id,
                    success: result.status === 'fulfilled' && result.value.success,
                    error: result.status === 'rejected' ? result.reason.message : result.value?.error,
                    timestamp: new Date()
                });
            });

            job.progress.completed = completed;
            job.progress.failed = failed;
            job.progress.inProgress = 0;
            job.status = failed === 0 ? 'completed' : 'partial';
            job.completedAt = new Date();
            
            await this.saveDistributionJob(job);
            
            this.metrics.totalDistributions++;
            this.metrics.successfulDistributions += completed;
            this.metrics.failedDistributions += failed;
            
            this.logger.info(`Distribution job completed: ${jobId}, Success: ${completed}, Failed: ${failed}`);
            this.emit('jobCompleted', job);

        } catch (error) {
            const job = this.distributionJobs.get(jobId);
            if (job) {
                job.status = 'failed';
                job.error = error.message;
                job.completedAt = new Date();
                await this.saveDistributionJob(job);
            }
            
            this.logger.error(`Distribution job failed: ${jobId}`, error);
            this.emit('jobFailed', job, error);
        }
    }

    async distributeCertificateToDevice(certificate, device, methods, job = null) {
        try {
            const platformHandler = this.platformHandlers[device.platform];
            if (!platformHandler) {
                throw new Error(`Unsupported platform: ${device.platform}`);
            }

            // Try each distribution method in order
            let lastError = null;
            for (const method of methods) {
                try {
                    const result = await this.distributionMethods[method](certificate, device, platformHandler);
                    
                    if (result.success) {
                        // Update device certificate mapping
                        await this.updateDeviceCertificateMapping(device.id, certificate.id, 'installed');
                        
                        this.metrics.certificatesDeployed++;
                        this.logger.info(`Certificate distributed successfully: ${certificate.id} to ${device.id} via ${method}`);
                        
                        return { success: true, method: method, result: result };
                    }
                } catch (error) {
                    lastError = error;
                    this.logger.warn(`Distribution method ${method} failed for device ${device.id}:`, error);
                    continue;
                }
            }

            // All methods failed
            throw lastError || new Error('All distribution methods failed');

        } catch (error) {
            this.logger.error(`Failed to distribute certificate ${certificate.id} to device ${device.id}:`, error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Platform-Specific Handlers
     */
    createWindowsHandler() {
        return {
            platform: 'windows',
            
            formatCertificate: (certificate, options = {}) => {
                const stores = options.stores || ['My'];
                const location = options.installLocation || 'CurrentUser';
                
                return {
                    format: 'pkcs12',
                    data: certificate.certificate, // Should be PKCS#12 format
                    stores: stores,
                    location: location,
                    exportable: options.exportable || false
                };
            },
            
            generateInstallScript: (certificates, options = {}) => {
                let script = `# Certificate Installation Script for Windows\n`;
                script += `# Generated: ${new Date().toISOString()}\n\n`;
                
                certificates.forEach((cert, index) => {
                    script += `# Install Certificate ${index + 1}\n`;
                    script += `$cert${index} = [Convert]::FromBase64String("${Buffer.from(cert.data).toString('base64')}")\n`;
                    script += `$certObj${index} = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert${index}, "", "Exportable")\n`;
                    
                    cert.stores.forEach(store => {
                        script += `$store${index}_${store} = New-Object System.Security.Cryptography.X509Certificates.X509Store("${store}", "${cert.location}")\n`;
                        script += `$store${index}_${store}.Open("ReadWrite")\n`;
                        script += `$store${index}_${store}.Add($certObj${index})\n`;
                        script += `$store${index}_${store}.Close()\n`;
                    });
                    
                    script += `Write-Host "Certificate ${index + 1} installed successfully"\n\n`;
                });
                
                return script;
            },
            
            generateRemoveScript: (certificates, options = {}) => {
                let script = `# Certificate Removal Script for Windows\n`;
                script += `# Generated: ${new Date().toISOString()}\n\n`;
                
                certificates.forEach((cert, index) => {
                    script += `# Remove Certificate ${index + 1}\n`;
                    cert.stores.forEach(store => {
                        script += `$store${index}_${store} = New-Object System.Security.Cryptography.X509Certificates.X509Store("${store}", "${cert.location}")\n`;
                        script += `$store${index}_${store}.Open("ReadWrite")\n`;
                        script += `$certToRemove = $store${index}_${store}.Certificates | Where-Object { $_.Thumbprint -eq "${cert.thumbprint}" }\n`;
                        script += `if ($certToRemove) { $store${index}_${store}.Remove($certToRemove) }\n`;
                        script += `$store${index}_${store}.Close()\n`;
                    });
                });
                
                return script;
            }
        };
    }

    createMacOSHandler() {
        return {
            platform: 'macos',
            
            formatCertificate: (certificate, options = {}) => {
                const keychain = options.keychain || 'login';
                const trustSettings = options.trustSettings || 'user';
                
                return {
                    format: 'mobileconfig',
                    data: this.generateMacOSProfile(certificate, options),
                    keychain: keychain,
                    trustSettings: trustSettings
                };
            },
            
            generateMacOSProfile: (certificate, options = {}) => {
                const payloadUUID = this.generateUUID();
                const certUUID = this.generateUUID();
                
                const profile = {
                    PayloadType: 'Configuration',
                    PayloadVersion: 1,
                    PayloadIdentifier: `${config.mdm.ios.profilePrefix}.cert.${certUUID}`,
                    PayloadUUID: payloadUUID,
                    PayloadDisplayName: 'OpenDirectory Certificate',
                    PayloadDescription: 'Certificate distribution via OpenDirectory',
                    PayloadOrganization: 'OpenDirectory',
                    PayloadContent: [
                        {
                            PayloadType: 'com.apple.security.pkcs12',
                            PayloadVersion: 1,
                            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.cert.${certUUID}`,
                            PayloadUUID: certUUID,
                            PayloadDisplayName: 'Certificate',
                            PayloadDescription: 'Certificate for device authentication',
                            PayloadContent: certificate.certificate,
                            Password: certificate.password || ''
                        }
                    ],
                    PayloadScope: options.profileScope || 'User'
                };
                
                const plist = require('plist');
                return plist.build(profile);
            },
            
            generateInstallScript: (certificates, options = {}) => {
                let script = `#!/bin/bash\n`;
                script += `# Certificate Installation Script for macOS\n`;
                script += `# Generated: ${new Date().toISOString()}\n\n`;
                
                certificates.forEach((cert, index) => {
                    script += `# Install Certificate ${index + 1}\n`;
                    script += `echo "${cert.data}" | security import - -k "${cert.keychain}"\n`;
                    script += `echo "Certificate ${index + 1} installed in ${cert.keychain} keychain"\n\n`;
                });
                
                return script;
            }
        };
    }

    createIOSHandler() {
        return {
            platform: 'ios',
            
            formatCertificate: (certificate, options = {}) => {
                return {
                    format: 'mobileconfig',
                    data: this.generateiOSProfile(certificate, options),
                    scope: options.profileScope || 'User',
                    removeOnDisenroll: options.removeOnDisenroll !== false
                };
            },
            
            generateiOSProfile: (certificate, options = {}) => {
                // Similar to macOS but with iOS-specific settings
                const profile = this.createMacOSHandler().generateMacOSProfile(certificate, options);
                
                // Parse and modify for iOS
                const plist = require('plist');
                const parsedProfile = plist.parse(profile);
                
                // Add iOS-specific settings
                parsedProfile.PayloadScope = 'User';
                parsedProfile.PayloadRemovalDisallowed = options.preventRemoval || false;
                
                return plist.build(parsedProfile);
            }
        };
    }

    createAndroidHandler() {
        return {
            platform: 'android',
            
            formatCertificate: (certificate, options = {}) => {
                return {
                    format: 'pkcs12',
                    data: certificate.certificate,
                    installLocation: options.installLocation || 'user',
                    requireDeviceAdmin: options.requireDeviceAdmin || false
                };
            },
            
            generateInstallInstructions: (certificates, options = {}) => {
                let instructions = `Certificate Installation Instructions for Android\n\n`;
                
                instructions += `1. Download the certificate file(s)\n`;
                instructions += `2. Go to Settings > Security > Install from storage\n`;
                instructions += `3. Navigate to the downloaded certificate files\n`;
                instructions += `4. Select each certificate file and follow the prompts\n`;
                instructions += `5. Enter the certificate password if prompted\n`;
                instructions += `6. Choose the credential use (VPN and apps, or WiFi)\n\n`;
                
                certificates.forEach((cert, index) => {
                    instructions += `Certificate ${index + 1}: ${cert.filename}\n`;
                });
                
                return instructions;
            }
        };
    }

    createLinuxHandler() {
        return {
            platform: 'linux',
            
            formatCertificate: (certificate, options = {}) => {
                return {
                    format: 'pem',
                    data: certificate.certificate,
                    stores: options.stores || ['/etc/ssl/certs'],
                    trustStore: options.trustStore || 'system'
                };
            },
            
            generateInstallScript: (certificates, options = {}) => {
                let script = `#!/bin/bash\n`;
                script += `# Certificate Installation Script for Linux\n`;
                script += `# Generated: ${new Date().toISOString()}\n\n`;
                
                certificates.forEach((cert, index) => {
                    cert.stores.forEach(store => {
                        const filename = `opendirectory-cert-${index + 1}.crt`;
                        script += `# Install Certificate ${index + 1} to ${store}\n`;
                        script += `sudo cp ${filename} ${store}/\n`;
                        
                        if (options.updateCertificates !== false) {
                            script += `sudo update-ca-certificates\n`;
                        }
                    });
                    script += `echo "Certificate ${index + 1} installed successfully"\n\n`;
                });
                
                return script;
            }
        };
    }

    /**
     * Distribution Methods
     */
    async distributeMDM(certificate, device, platformHandler) {
        try {
            if (!this.mdmService) {
                throw new Error('MDM service not available');
            }

            const formattedCert = platformHandler.formatCertificate(certificate, device.platformOptions || {});
            
            const mdmResult = await this.mdmService.installCertificate(device.id, {
                certificateData: formattedCert.data,
                format: formattedCert.format,
                metadata: {
                    certificateId: certificate.id,
                    purpose: certificate.purpose || 'general',
                    distributionJobId: certificate.distributionJobId
                }
            });

            return {
                success: true,
                method: 'mdm',
                commandId: mdmResult.commandId,
                status: mdmResult.status
            };

        } catch (error) {
            throw new Error(`MDM distribution failed: ${error.message}`);
        }
    }

    async distributeSCEP(certificate, device, platformHandler) {
        try {
            // Generate SCEP enrollment configuration
            const scepConfig = {
                url: `${config.server.host}/scep`,
                challengePassword: this.generateChallengePassword(),
                certificateTemplate: certificate.template,
                subjectTemplate: this.buildSubjectTemplate(device)
            };

            // Create platform-specific SCEP configuration
            const scepProfile = platformHandler.generateSCEPProfile ? 
                platformHandler.generateSCEPProfile(scepConfig) : 
                scepConfig;

            // Send SCEP configuration to device (via MDM or other means)
            if (this.mdmService) {
                const result = await this.mdmService.sendSCEPProfile(device.id, scepProfile);
                return {
                    success: true,
                    method: 'scep',
                    commandId: result.commandId,
                    challengePassword: scepConfig.challengePassword
                };
            }

            throw new Error('SCEP distribution requires MDM service');

        } catch (error) {
            throw new Error(`SCEP distribution failed: ${error.message}`);
        }
    }

    async distributeAPI(certificate, device, platformHandler) {
        try {
            // Use device management API to push certificate
            const deviceAPI = await this.getDeviceAPI(device);
            if (!deviceAPI) {
                throw new Error('Device API not available');
            }

            const formattedCert = platformHandler.formatCertificate(certificate, device.platformOptions || {});
            
            const apiResult = await deviceAPI.installCertificate(device.id, formattedCert);
            
            return {
                success: true,
                method: 'api',
                apiResponse: apiResult
            };

        } catch (error) {
            throw new Error(`API distribution failed: ${error.message}`);
        }
    }

    async distributeManual(certificate, device, platformHandler) {
        try {
            // Create installation package for manual deployment
            const packageData = await this.createInstallationPackage(certificate, device, platformHandler);
            
            // Store package for download
            const packageId = this.generatePackageId();
            await this.storeInstallationPackage(packageId, packageData);
            
            // Notify user/administrator
            await this.notifyManualInstallation(device, certificate, packageId);
            
            return {
                success: true,
                method: 'manual',
                packageId: packageId,
                downloadUrl: `/api/certificates/download/${packageId}`,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
            };

        } catch (error) {
            throw new Error(`Manual distribution failed: ${error.message}`);
        }
    }

    async distributeEmail(certificate, device, platformHandler) {
        try {
            if (!config.notifications.enabled) {
                throw new Error('Email notifications not configured');
            }

            // Create installation package
            const packageData = await this.createInstallationPackage(certificate, device, platformHandler);
            
            // Send email with certificate package
            const emailResult = await this.sendCertificateEmail(device, certificate, packageData);
            
            return {
                success: true,
                method: 'email',
                messageId: emailResult.messageId
            };

        } catch (error) {
            throw new Error(`Email distribution failed: ${error.message}`);
        }
    }

    async distributeDownload(certificate, device, platformHandler) {
        try {
            // Create download package
            const packageData = await this.createInstallationPackage(certificate, device, platformHandler);
            
            const packageId = this.generatePackageId();
            await this.storeInstallationPackage(packageId, packageData);
            
            // Generate secure download link
            const downloadToken = this.generateDownloadToken(device.id, certificate.id, packageId);
            const downloadUrl = `/api/certificates/secure-download/${packageId}?token=${downloadToken}`;
            
            return {
                success: true,
                method: 'download',
                packageId: packageId,
                downloadUrl: downloadUrl,
                downloadToken: downloadToken,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
            };

        } catch (error) {
            throw new Error(`Download distribution failed: ${error.message}`);
        }
    }

    /**
     * Certificate Revocation and Removal
     */
    async revokeCertificateFromDevices(certificateId, reason = 'unspecified') {
        try {
            // Find all devices with this certificate
            const affectedDevices = await this.findDevicesWithCertificate(certificateId);
            
            const revocationJob = await this.createDistributionJob({
                name: `Certificate Revocation - ${certificateId}`,
                type: 'revocation',
                certificateIds: [certificateId],
                targetDevices: affectedDevices.map(d => d.deviceId),
                distributionMethods: ['mdm', 'api', 'manual'],
                metadata: {
                    reason: reason,
                    originalCertificateId: certificateId
                }
            });

            this.logger.info(`Certificate revocation job created: ${revocationJob.id} for certificate: ${certificateId}`);
            return revocationJob;

        } catch (error) {
            this.logger.error(`Failed to revoke certificate ${certificateId}:`, error);
            throw error;
        }
    }

    async removeCertificateFromDevice(certificateId, deviceId, method = 'mdm') {
        try {
            const device = await this.getDeviceInfo(deviceId);
            const certificate = await this.getCertificateInfo(certificateId);
            
            if (!device || !certificate) {
                throw new Error('Device or certificate not found');
            }

            const platformHandler = this.platformHandlers[device.platform];
            
            let result;
            switch (method) {
                case 'mdm':
                    result = await this.removeCertificateViaMDM(certificate, device);
                    break;
                case 'api':
                    result = await this.removeCertificateViaAPI(certificate, device);
                    break;
                case 'manual':
                    result = await this.generateRemovalInstructions(certificate, device, platformHandler);
                    break;
                default:
                    throw new Error(`Unsupported removal method: ${method}`);
            }

            // Update device certificate mapping
            await this.updateDeviceCertificateMapping(deviceId, certificateId, 'removed');
            
            this.metrics.certificatesRevoked++;
            this.logger.info(`Certificate removed from device: ${certificateId} from ${deviceId} via ${method}`);
            
            return result;

        } catch (error) {
            this.logger.error(`Failed to remove certificate ${certificateId} from device ${deviceId}:`, error);
            throw error;
        }
    }

    /**
     * Package Creation and Management
     */
    async createInstallationPackage(certificate, device, platformHandler) {
        try {
            const packageData = {
                platform: device.platform,
                certificates: [certificate],
                instructions: null,
                scripts: {},
                metadata: {
                    deviceId: device.id,
                    certificateId: certificate.id,
                    createdAt: new Date(),
                    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
                }
            };

            const formattedCert = platformHandler.formatCertificate(certificate, device.platformOptions || {});
            
            switch (device.platform) {
                case 'windows':
                    packageData.scripts.install = platformHandler.generateInstallScript([formattedCert]);
                    packageData.scripts.remove = platformHandler.generateRemoveScript([formattedCert]);
                    break;
                    
                case 'macos':
                case 'ios':
                    packageData.profileData = formattedCert.data;
                    packageData.scripts.install = platformHandler.generateInstallScript ? 
                        platformHandler.generateInstallScript([formattedCert]) : null;
                    break;
                    
                case 'android':
                    packageData.certificates = [{ ...formattedCert, filename: `certificate-${certificate.id}.p12` }];
                    packageData.instructions = platformHandler.generateInstallInstructions([formattedCert]);
                    break;
                    
                case 'linux':
                    packageData.certificates = [{ ...formattedCert, filename: `certificate-${certificate.id}.crt` }];
                    packageData.scripts.install = platformHandler.generateInstallScript([formattedCert]);
                    break;
            }

            // Create ZIP package
            const zipBuffer = await this.createZipPackage(packageData);
            packageData.zipData = zipBuffer;
            
            return packageData;

        } catch (error) {
            this.logger.error('Failed to create installation package:', error);
            throw error;
        }
    }

    async createZipPackage(packageData) {
        return new Promise((resolve, reject) => {
            const buffers = [];
            const archive = archiver('zip', { zlib: { level: 9 } });
            
            archive.on('data', (data) => buffers.push(data));
            archive.on('end', () => resolve(Buffer.concat(buffers)));
            archive.on('error', reject);

            // Add certificates
            if (packageData.certificates) {
                packageData.certificates.forEach(cert => {
                    archive.append(cert.data, { name: cert.filename });
                });
            }

            // Add profile data (for Apple platforms)
            if (packageData.profileData) {
                archive.append(packageData.profileData, { name: 'certificate-profile.mobileconfig' });
            }

            // Add scripts
            if (packageData.scripts) {
                Object.entries(packageData.scripts).forEach(([name, script]) => {
                    if (script) {
                        const extension = packageData.platform === 'windows' ? 'ps1' : 'sh';
                        archive.append(script, { name: `${name}.${extension}` });
                    }
                });
            }

            // Add instructions
            if (packageData.instructions) {
                archive.append(packageData.instructions, { name: 'INSTRUCTIONS.txt' });
            }

            // Add README
            const readme = this.generatePackageReadme(packageData);
            archive.append(readme, { name: 'README.txt' });

            archive.finalize();
        });
    }

    generatePackageReadme(packageData) {
        let readme = `Certificate Installation Package\n`;
        readme += `=====================================\n\n`;
        readme += `Platform: ${packageData.platform}\n`;
        readme += `Created: ${packageData.metadata.createdAt}\n`;
        readme += `Expires: ${packageData.metadata.expiresAt}\n\n`;
        
        readme += `Files included:\n`;
        if (packageData.certificates) {
            packageData.certificates.forEach(cert => {
                readme += `- ${cert.filename} (Certificate file)\n`;
            });
        }
        
        if (packageData.scripts) {
            Object.keys(packageData.scripts).forEach(script => {
                const extension = packageData.platform === 'windows' ? 'ps1' : 'sh';
                readme += `- ${script}.${extension} (Installation script)\n`;
            });
        }
        
        if (packageData.instructions) {
            readme += `- INSTRUCTIONS.txt (Manual installation instructions)\n`;
        }
        
        readme += `\nFor support, contact your system administrator.\n`;
        
        return readme;
    }

    /**
     * Compliance and Reporting
     */
    async generateComplianceReport(filters = {}) {
        try {
            const reportId = this.generateReportId();
            const report = {
                id: reportId,
                type: 'compliance',
                generatedAt: new Date(),
                filters: filters,
                summary: {
                    totalDevices: 0,
                    compliantDevices: 0,
                    nonCompliantDevices: 0,
                    certificatesCurrent: 0,
                    certificatesExpiringSoon: 0,
                    certificatesExpired: 0,
                    complianceRate: 0
                },
                details: [],
                recommendations: []
            };

            // Get all devices in scope
            const devices = await this.getDevicesInScope(filters);
            report.summary.totalDevices = devices.length;

            // Check compliance for each device
            for (const device of devices) {
                const deviceCompliance = await this.checkDeviceCompliance(device);
                report.details.push(deviceCompliance);

                if (deviceCompliance.compliant) {
                    report.summary.compliantDevices++;
                } else {
                    report.summary.nonCompliantDevices++;
                }

                report.summary.certificatesCurrent += deviceCompliance.currentCertificates;
                report.summary.certificatesExpiringSoon += deviceCompliance.expiringSoonCertificates;
                report.summary.certificatesExpired += deviceCompliance.expiredCertificates;
            }

            // Calculate compliance rate
            report.summary.complianceRate = report.summary.totalDevices > 0 ? 
                (report.summary.compliantDevices / report.summary.totalDevices * 100) : 0;

            // Generate recommendations
            report.recommendations = this.generateComplianceRecommendations(report);

            // Store report
            this.complianceReports.set(reportId, report);
            await this.saveComplianceReport(report);

            this.logger.info(`Compliance report generated: ${reportId}`);
            return report;

        } catch (error) {
            this.logger.error('Failed to generate compliance report:', error);
            throw error;
        }
    }

    async checkDeviceCompliance(device) {
        try {
            const deviceCerts = await this.getDeviceCertificates(device.id);
            const now = new Date();
            const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

            let compliant = true;
            let currentCertificates = 0;
            let expiringSoonCertificates = 0;
            let expiredCertificates = 0;
            const issues = [];

            for (const cert of deviceCerts) {
                const expiryDate = new Date(cert.notAfter);
                
                if (expiryDate < now) {
                    expiredCertificates++;
                    issues.push(`Certificate ${cert.id} has expired`);
                    compliant = false;
                } else if (expiryDate < thirtyDaysFromNow) {
                    expiringSoonCertificates++;
                    issues.push(`Certificate ${cert.id} expires soon`);
                } else {
                    currentCertificates++;
                }
            }

            // Check against required certificates
            const requiredCerts = await this.getRequiredCertificatesForDevice(device);
            for (const requiredCert of requiredCerts) {
                const hasRequiredCert = deviceCerts.some(cert => cert.templateId === requiredCert.templateId);
                if (!hasRequiredCert) {
                    issues.push(`Missing required certificate: ${requiredCert.name}`);
                    compliant = false;
                }
            }

            return {
                deviceId: device.id,
                deviceName: device.name,
                platform: device.platform,
                compliant: compliant,
                currentCertificates: currentCertificates,
                expiringSoonCertificates: expiringSoonCertificates,
                expiredCertificates: expiredCertificates,
                totalCertificates: deviceCerts.length,
                issues: issues,
                lastChecked: new Date()
            };

        } catch (error) {
            this.logger.error(`Failed to check device compliance for ${device.id}:`, error);
            return {
                deviceId: device.id,
                compliant: false,
                issues: [`Compliance check failed: ${error.message}`],
                lastChecked: new Date()
            };
        }
    }

    /**
     * Utility Methods
     */
    generatePolicyId(name) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(`${name}-${timestamp}`)
            .digest('hex')
            .substring(0, 8);
        return `policy-${hash}`;
    }

    generateJobId() {
        return `job-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generatePackageId() {
        return `pkg-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generateReportId() {
        return `rpt-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generateUUID() {
        return require('uuid').v4();
    }

    generateChallengePassword() {
        return crypto.randomBytes(16).toString('hex');
    }

    generateDownloadToken(deviceId, certificateId, packageId) {
        const payload = { deviceId, certificateId, packageId, exp: Date.now() + 24 * 60 * 60 * 1000 };
        return Buffer.from(JSON.stringify(payload)).toString('base64');
    }

    async calculateJobTargets(job) {
        // Placeholder implementation
        return job.targetDevices.length || 0;
    }

    async resolveJobTargets(job) {
        // Get devices from various sources
        const devices = [];
        
        // Add explicit target devices
        for (const deviceId of job.targetDevices) {
            const device = await this.getDeviceInfo(deviceId);
            if (device) devices.push(device);
        }
        
        // Add devices from groups
        for (const groupId of job.targetGroups) {
            const groupDevices = await this.getDevicesInGroup(groupId);
            devices.push(...groupDevices);
        }
        
        // Add devices from policies
        for (const policyId of job.targetPolicies) {
            const policy = this.distributionPolicies.get(policyId);
            if (policy) {
                const policyDevices = await this.getDevicesForPolicy(policy);
                devices.push(...policyDevices);
            }
        }
        
        // Remove duplicates
        const uniqueDevices = devices.filter((device, index, self) => 
            index === self.findIndex(d => d.id === device.id)
        );
        
        return uniqueDevices;
    }

    async resolveJobCertificates(job) {
        const certificates = [];
        
        // Add explicit certificates
        certificates.push(...job.certificates);
        
        // Add certificates by ID
        for (const certId of job.certificateIds) {
            const cert = await this.getCertificateInfo(certId);
            if (cert) certificates.push(cert);
        }
        
        return certificates;
    }

    buildSubjectTemplate(device) {
        return {
            commonName: device.name || device.id,
            organizationalUnitName: 'Device Certificates',
            organizationName: 'OpenDirectory'
        };
    }

    scheduleComplianceChecks() {
        // Schedule daily compliance checks
        setInterval(async () => {
            try {
                await this.generateComplianceReport();
                this.logger.info('Scheduled compliance check completed');
            } catch (error) {
                this.logger.error('Scheduled compliance check failed:', error);
            }
        }, 24 * 60 * 60 * 1000); // Daily
    }

    generateComplianceRecommendations(report) {
        const recommendations = [];
        
        if (report.summary.complianceRate < 80) {
            recommendations.push('Low compliance rate detected. Review certificate distribution policies.');
        }
        
        if (report.summary.certificatesExpired > 0) {
            recommendations.push('Expired certificates found. Initiate immediate renewal process.');
        }
        
        if (report.summary.certificatesExpiringSoon > 0) {
            recommendations.push('Certificates expiring soon. Schedule renewal before expiration.');
        }
        
        return recommendations;
    }

    /**
     * Integration Methods (Placeholders)
     */
    async getDeviceInfo(deviceId) {
        // Integration with device management system
        return { id: deviceId, name: `Device-${deviceId}`, platform: 'windows' };
    }

    async getCertificateInfo(certificateId) {
        if (this.certificateService) {
            return await this.certificateService.getCertificate(certificateId);
        }
        return { id: certificateId, certificate: 'cert-data' };
    }

    async getDevicesInScope(filters) {
        // Get devices based on filters
        return [];
    }

    async getDevicesInGroup(groupId) {
        // Get devices in a specific group
        return [];
    }

    async getDevicesForPolicy(policy) {
        // Get devices that match policy criteria
        return [];
    }

    async getDeviceCertificates(deviceId) {
        // Get certificates installed on a device
        const mapping = this.deviceCertificates.get(deviceId) || [];
        return mapping.filter(cert => cert.status === 'installed');
    }

    async getRequiredCertificatesForDevice(device) {
        // Get certificates required for a device based on policies
        return [];
    }

    async updateDeviceCertificateMapping(deviceId, certificateId, status) {
        let deviceCerts = this.deviceCertificates.get(deviceId) || [];
        
        // Remove existing mapping for this certificate
        deviceCerts = deviceCerts.filter(cert => cert.certificateId !== certificateId);
        
        // Add new mapping
        deviceCerts.push({
            certificateId: certificateId,
            status: status,
            updatedAt: new Date()
        });
        
        this.deviceCertificates.set(deviceId, deviceCerts);
        
        // Save to storage
        await this.saveDeviceCertificateMapping(deviceId, deviceCerts);
    }

    async findDevicesWithCertificate(certificateId) {
        const devices = [];
        
        for (const [deviceId, certs] of this.deviceCertificates) {
            if (certs.some(cert => cert.certificateId === certificateId && cert.status === 'installed')) {
                devices.push({ deviceId: deviceId });
            }
        }
        
        return devices;
    }

    /**
     * Storage Methods
     */
    async saveDistributionPolicy(policy) {
        const policyPath = path.join(config.storage.certificates, 'distribution', 'policies', `${policy.id}.json`);
        await fs.writeFile(policyPath, JSON.stringify(policy, null, 2));
    }

    async loadDistributionPolicies() {
        try {
            const policiesDir = path.join(config.storage.certificates, 'distribution', 'policies');
            const files = await fs.readdir(policiesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const policyPath = path.join(policiesDir, file);
                    const policy = JSON.parse(await fs.readFile(policyPath, 'utf8'));
                    this.distributionPolicies.set(policy.id, policy);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load distribution policies:', error);
            }
        }
    }

    async saveDistributionJob(job) {
        const jobPath = path.join(config.storage.certificates, 'distribution', 'jobs', `${job.id}.json`);
        await fs.writeFile(jobPath, JSON.stringify(job, null, 2));
    }

    async storeInstallationPackage(packageId, packageData) {
        const packagePath = path.join(config.storage.certificates, 'distribution', 'packages', `${packageId}.zip`);
        await fs.writeFile(packagePath, packageData.zipData);
        
        const metadataPath = path.join(config.storage.certificates, 'distribution', 'packages', `${packageId}.json`);
        await fs.writeFile(metadataPath, JSON.stringify(packageData.metadata, null, 2));
    }

    async saveComplianceReport(report) {
        const reportPath = path.join(config.storage.certificates, 'distribution', 'compliance', `${report.id}.json`);
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
    }

    async saveDeviceCertificateMapping(deviceId, mapping) {
        const mappingPath = path.join(config.storage.certificates, 'distribution', 'device-mapping', `${deviceId}.json`);
        await fs.writeFile(mappingPath, JSON.stringify(mapping, null, 2));
    }

    async loadDeviceCertificateMapping() {
        try {
            const mappingDir = path.join(config.storage.certificates, 'distribution', 'device-mapping');
            const files = await fs.readdir(mappingDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const deviceId = path.basename(file, '.json');
                    const mappingPath = path.join(mappingDir, file);
                    const mapping = JSON.parse(await fs.readFile(mappingPath, 'utf8'));
                    this.deviceCertificates.set(deviceId, mapping);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load device certificate mapping:', error);
            }
        }
    }

    /**
     * Public API Methods
     */
    async getPolicies() {
        return Array.from(this.distributionPolicies.values());
    }

    async getPolicy(policyId) {
        return this.distributionPolicies.get(policyId);
    }

    async getJobs(filters = {}) {
        let jobs = Array.from(this.distributionJobs.values());
        
        if (filters.status) {
            jobs = jobs.filter(job => job.status === filters.status);
        }
        
        if (filters.type) {
            jobs = jobs.filter(job => job.type === filters.type);
        }
        
        return jobs;
    }

    async getJob(jobId) {
        return this.distributionJobs.get(jobId);
    }

    async getComplianceReports(filters = {}) {
        let reports = Array.from(this.complianceReports.values());
        
        if (filters.type) {
            reports = reports.filter(report => report.type === filters.type);
        }
        
        return reports;
    }

    async getMetrics() {
        // Update compliance rate
        const totalDevices = this.deviceCertificates.size;
        if (totalDevices > 0) {
            let compliantDevices = 0;
            for (const [deviceId, certs] of this.deviceCertificates) {
                const hasCurrentCerts = certs.some(cert => cert.status === 'installed');
                if (hasCurrentCerts) compliantDevices++;
            }
            this.metrics.complianceRate = (compliantDevices / totalDevices * 100).toFixed(2);
        }
        
        return {
            ...this.metrics,
            totalPolicies: this.distributionPolicies.size,
            activePolicies: Array.from(this.distributionPolicies.values()).filter(p => p.enabled).length,
            totalJobs: this.distributionJobs.size,
            activeJobs: Array.from(this.distributionJobs.values()).filter(j => j.status === 'running').length,
            totalDevices: this.deviceCertificates.size,
            devicesCertified: this.metrics.devicesCertified || this.deviceCertificates.size
        };
    }
}

module.exports = CertificateDistributionService;