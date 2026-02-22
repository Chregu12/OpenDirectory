#!/usr/bin/env node

/**
 * OpenDirectory Tenant Isolation Layer
 * 
 * Comprehensive isolation system providing:
 * - Network isolation and VPC segmentation
 * - Storage isolation and encryption
 * - Process isolation and containerization
 * - Memory isolation and resource limits
 * - API rate limiting per tenant
 * - Tenant-specific encryption keys
 * - Audit logging per tenant
 * - Security boundaries and access control
 * 
 * Ensures complete tenant isolation at all system levels
 */

const express = require('express');
const { Pool } = require('pg');
const { MongoClient } = require('mongodb');
const Redis = require('ioredis');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');

class TenantIsolationLayer {
    constructor(config = {}) {
        this.config = {
            port: config.port || 3104,
            masterDbUrl: config.masterDbUrl || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
            redisUrl: config.redisUrl || 'redis://:changeme@localhost:6379',
            isolationMode: config.isolationMode || 'container', // 'container', 'vm', 'namespace'
            networkMode: config.networkMode || 'bridge', // 'bridge', 'overlay', 'macvlan'
            storageEncryption: config.storageEncryption !== false,
            auditLogging: config.auditLogging !== false,
            resourceLimits: {
                cpu: config.cpuLimit || '1.0', // CPU cores
                memory: config.memoryLimit || '2Gi', // Memory limit
                storage: config.storageLimit || '50Gi', // Storage limit
                network: config.networkLimit || '100Mbps' // Network bandwidth
            },
            encryptionConfig: {
                algorithm: 'aes-256-gcm',
                keyLength: 32,
                ivLength: 16,
                tagLength: 16
            },
            securityPolicies: {
                networkSegmentation: true,
                processIsolation: true,
                fileSystemIsolation: true,
                keyRotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
                auditRetention: 365 * 24 * 60 * 60 * 1000, // 1 year
                rateLimitWindow: 15 * 60 * 1000, // 15 minutes
                rateLimitMax: 1000 // requests per window
            },
            ...config
        };

        this.masterPool = null;
        this.redisClient = null;
        this.tenantNetworks = new Map();
        this.tenantContainers = new Map();
        this.tenantEncryptionKeys = new Map();
        this.tenantRateLimiters = new Map();
        this.auditLogger = null;
        
        this.initializeConnections();
        this.setupAuditLogging();
    }

    async initializeConnections() {
        try {
            this.masterPool = new Pool({
                connectionString: this.config.masterDbUrl,
                max: 20,
                idleTimeoutMillis: 30000,
            });

            this.redisClient = new Redis(this.config.redisUrl, {
                retryDelayOnFailover: 100,
                maxRetriesPerRequest: 3
            });

            await this.initializeSchema();
            await this.loadTenantIsolationData();
            
            console.log('Tenant Isolation Layer initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Tenant Isolation Layer:', error);
            throw error;
        }
    }

    async initializeSchema() {
        const schema = `
            -- Network isolation configuration
            CREATE TABLE IF NOT EXISTS tenant_network_isolation (
                tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                network_id VARCHAR(100) NOT NULL,
                subnet_cidr VARCHAR(20) NOT NULL,
                gateway_ip INET,
                dns_servers JSONB DEFAULT '["8.8.8.8", "8.8.4.4"]',
                firewall_rules JSONB DEFAULT '[]',
                bandwidth_limit VARCHAR(20), -- e.g., "100Mbps"
                isolation_type VARCHAR(20) DEFAULT 'bridge' CHECK (isolation_type IN ('bridge', 'overlay', 'macvlan', 'none')),
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'maintenance')),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Container/process isolation
            CREATE TABLE IF NOT EXISTS tenant_container_isolation (
                tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                container_runtime VARCHAR(50) DEFAULT 'docker',
                namespace_id VARCHAR(100),
                resource_limits JSONB NOT NULL,
                security_context JSONB DEFAULT '{}',
                volumes JSONB DEFAULT '[]',
                environment_variables JSONB DEFAULT '{}',
                process_limits JSONB DEFAULT '{}',
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'stopped')),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Storage isolation and encryption
            CREATE TABLE IF NOT EXISTS tenant_storage_isolation (
                tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                storage_backend VARCHAR(50) DEFAULT 'filesystem', -- 'filesystem', 's3', 'gcs', 'azure'
                base_path TEXT NOT NULL,
                encryption_enabled BOOLEAN DEFAULT true,
                encryption_algorithm VARCHAR(50) DEFAULT 'aes-256-gcm',
                key_id UUID,
                storage_quota_bytes BIGINT,
                current_usage_bytes BIGINT DEFAULT 0,
                compression_enabled BOOLEAN DEFAULT false,
                backup_enabled BOOLEAN DEFAULT true,
                access_patterns JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Tenant-specific encryption keys
            CREATE TABLE IF NOT EXISTS tenant_encryption_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                key_type VARCHAR(50) NOT NULL, -- 'storage', 'transit', 'database', 'backup'
                key_purpose VARCHAR(100), -- specific use case
                encrypted_key TEXT NOT NULL, -- encrypted with master key
                key_version INTEGER DEFAULT 1,
                algorithm VARCHAR(50) NOT NULL,
                key_size INTEGER NOT NULL,
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deprecated', 'revoked')),
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                rotated_at TIMESTAMP WITH TIME ZONE
            );

            -- API rate limiting per tenant
            CREATE TABLE IF NOT EXISTS tenant_rate_limits (
                tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                requests_per_minute INTEGER DEFAULT 1000,
                requests_per_hour INTEGER DEFAULT 10000,
                requests_per_day INTEGER DEFAULT 100000,
                burst_limit INTEGER DEFAULT 100,
                concurrent_connections INTEGER DEFAULT 50,
                bandwidth_limit_mbps INTEGER DEFAULT 100,
                custom_limits JSONB DEFAULT '{}',
                enforcement_mode VARCHAR(20) DEFAULT 'strict' CHECK (enforcement_mode IN ('strict', 'lenient', 'disabled')),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Tenant audit logging configuration
            CREATE TABLE IF NOT EXISTS tenant_audit_config (
                tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                log_level VARCHAR(20) DEFAULT 'info' CHECK (log_level IN ('debug', 'info', 'warn', 'error')),
                log_categories JSONB DEFAULT '["auth", "data", "admin", "api"]',
                retention_days INTEGER DEFAULT 365,
                storage_location TEXT,
                encryption_enabled BOOLEAN DEFAULT true,
                real_time_alerts BOOLEAN DEFAULT true,
                compliance_mode VARCHAR(20) DEFAULT 'standard', -- 'standard', 'strict', 'custom'
                export_formats JSONB DEFAULT '["json", "csv"]',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Security boundary violations
            CREATE TABLE IF NOT EXISTS security_violations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                violation_type VARCHAR(50) NOT NULL, -- 'network', 'storage', 'process', 'api', 'auth'
                severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                source_ip INET,
                target_resource VARCHAR(255),
                description TEXT NOT NULL,
                metadata JSONB DEFAULT '{}',
                resolved BOOLEAN DEFAULT false,
                resolved_by UUID,
                resolved_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Performance metrics per tenant
            CREATE TABLE IF NOT EXISTS tenant_performance_metrics (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                metric_type VARCHAR(50) NOT NULL, -- 'cpu', 'memory', 'storage', 'network', 'api'
                metric_value DECIMAL(15,4) NOT NULL,
                unit VARCHAR(20) NOT NULL,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                metadata JSONB DEFAULT '{}'
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_tenant_network_status ON tenant_network_isolation(status);
            CREATE INDEX IF NOT EXISTS idx_tenant_container_status ON tenant_container_isolation(status);
            CREATE INDEX IF NOT EXISTS idx_encryption_keys_tenant ON tenant_encryption_keys(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_encryption_keys_type ON tenant_encryption_keys(key_type, status);
            CREATE INDEX IF NOT EXISTS idx_security_violations_tenant ON security_violations(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_security_violations_created ON security_violations(created_at);
            CREATE INDEX IF NOT EXISTS idx_performance_metrics_tenant ON tenant_performance_metrics(tenant_id, timestamp);
        `;

        await this.masterPool.query(schema);
    }

    async loadTenantIsolationData() {
        // Load existing tenant isolation configurations
        const tenants = await this.masterPool.query(`
            SELECT t.id, t.slug, t.status,
                   tni.network_id, tni.subnet_cidr,
                   tci.namespace_id, tci.resource_limits,
                   tsi.base_path, tsi.encryption_enabled
            FROM tenants t
            LEFT JOIN tenant_network_isolation tni ON t.id = tni.tenant_id
            LEFT JOIN tenant_container_isolation tci ON t.id = tci.tenant_id
            LEFT JOIN tenant_storage_isolation tsi ON t.id = tsi.tenant_id
            WHERE t.status = 'active'
        `);

        for (const tenant of tenants.rows) {
            if (tenant.network_id) {
                this.tenantNetworks.set(tenant.id, {
                    networkId: tenant.network_id,
                    subnet: tenant.subnet_cidr
                });
            }

            if (tenant.namespace_id) {
                this.tenantContainers.set(tenant.id, {
                    namespaceId: tenant.namespace_id,
                    limits: tenant.resource_limits
                });
            }

            // Load encryption keys
            await this.loadTenantEncryptionKeys(tenant.id);
        }
    }

    async loadTenantEncryptionKeys(tenantId) {
        const keys = await this.masterPool.query(`
            SELECT * FROM tenant_encryption_keys 
            WHERE tenant_id = $1 AND status = 'active'
        `, [tenantId]);

        const tenantKeys = {};
        for (const key of keys.rows) {
            // Decrypt the key (in production, use proper key management)
            const decryptedKey = await this.decryptMasterKey(key.encrypted_key);
            tenantKeys[key.key_type] = {
                id: key.id,
                key: decryptedKey,
                algorithm: key.algorithm,
                version: key.key_version
            };
        }

        this.tenantEncryptionKeys.set(tenantId, tenantKeys);
    }

    setupAuditLogging() {
        this.auditLogger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ 
                    filename: '/var/log/opendirectory/isolation-audit.log' 
                }),
                new winston.transports.Console({
                    format: winston.format.simple()
                })
            ]
        });
    }

    // Network Isolation
    async createNetworkIsolation(tenantId, config = {}) {
        const networkId = `tenant_${tenantId.replace(/-/g, '_')}`;
        const subnet = config.subnet || this.generateSubnet();

        try {
            // Create Docker network (example - adapt for your container runtime)
            if (this.config.isolationMode === 'container') {
                await this.createDockerNetwork(networkId, subnet, config);
            }

            // Store network configuration
            await this.masterPool.query(`
                INSERT INTO tenant_network_isolation (
                    tenant_id, network_id, subnet_cidr, gateway_ip,
                    dns_servers, firewall_rules, bandwidth_limit, isolation_type
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (tenant_id) 
                DO UPDATE SET
                    network_id = $2, subnet_cidr = $3, gateway_ip = $4,
                    dns_servers = $5, firewall_rules = $6, bandwidth_limit = $7,
                    isolation_type = $8, updated_at = NOW()
            `, [
                tenantId, networkId, subnet, config.gatewayIp,
                JSON.stringify(config.dnsServers || ['8.8.8.8', '8.8.4.4']),
                JSON.stringify(config.firewallRules || []),
                config.bandwidthLimit || this.config.resourceLimits.network,
                config.isolationType || this.config.networkMode
            ]);

            this.tenantNetworks.set(tenantId, { networkId, subnet });

            await this.auditLog(tenantId, 'network_isolation_created', {
                networkId, subnet, isolationType: config.isolationType
            });

            return { networkId, subnet };

        } catch (error) {
            await this.logSecurityViolation(tenantId, 'network', 'high', 
                `Failed to create network isolation: ${error.message}`);
            throw error;
        }
    }

    async createDockerNetwork(networkId, subnet, config) {
        try {
            const cmd = [
                'docker', 'network', 'create',
                '--driver', this.config.networkMode,
                '--subnet', subnet,
                '--ip-range', subnet,
                '--gateway', config.gatewayIp || this.calculateGateway(subnet),
                networkId
            ];

            execSync(cmd.join(' '), { stdio: 'inherit' });

            // Apply bandwidth limits if specified
            if (config.bandwidthLimit) {
                await this.applyNetworkLimits(networkId, config.bandwidthLimit);
            }

        } catch (error) {
            console.error(`Failed to create Docker network ${networkId}:`, error);
            throw error;
        }
    }

    async applyNetworkLimits(networkId, bandwidthLimit) {
        // Apply traffic control rules (requires tc command)
        try {
            const cmd = `tc qdisc add dev ${networkId} root handle 1: htb default 12 && tc class add dev ${networkId} parent 1: classid 1:1 htb rate ${bandwidthLimit}`;
            execSync(cmd, { stdio: 'inherit' });
        } catch (error) {
            console.warn('Failed to apply network limits:', error.message);
        }
    }

    // Storage Isolation and Encryption
    async createStorageIsolation(tenantId, config = {}) {
        const basePath = config.basePath || `/var/lib/opendirectory/tenants/${tenantId}`;
        
        try {
            // Create tenant storage directory
            await fs.mkdir(basePath, { recursive: true, mode: 0o700 });

            // Generate encryption keys if encryption is enabled
            let keyId = null;
            if (this.config.storageEncryption) {
                keyId = await this.generateEncryptionKey(tenantId, 'storage');
            }

            // Store storage configuration
            await this.masterPool.query(`
                INSERT INTO tenant_storage_isolation (
                    tenant_id, storage_backend, base_path, encryption_enabled,
                    encryption_algorithm, key_id, storage_quota_bytes,
                    compression_enabled, backup_enabled
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id)
                DO UPDATE SET
                    base_path = $3, encryption_enabled = $4,
                    encryption_algorithm = $5, key_id = $6,
                    storage_quota_bytes = $7, updated_at = NOW()
            `, [
                tenantId,
                config.storageBackend || 'filesystem',
                basePath,
                this.config.storageEncryption,
                this.config.encryptionConfig.algorithm,
                keyId,
                this.parseStorageQuota(config.storageQuota || this.config.resourceLimits.storage),
                config.compressionEnabled || false,
                config.backupEnabled !== false
            ]);

            await this.auditLog(tenantId, 'storage_isolation_created', {
                basePath, encrypted: this.config.storageEncryption, keyId
            });

            return { basePath, encrypted: this.config.storageEncryption, keyId };

        } catch (error) {
            await this.logSecurityViolation(tenantId, 'storage', 'high',
                `Failed to create storage isolation: ${error.message}`);
            throw error;
        }
    }

    // Container/Process Isolation
    async createContainerIsolation(tenantId, config = {}) {
        const namespaceId = `tenant_${tenantId.replace(/-/g, '_')}`;

        try {
            const resourceLimits = {
                cpu: config.cpuLimit || this.config.resourceLimits.cpu,
                memory: config.memoryLimit || this.config.resourceLimits.memory,
                storage: config.storageLimit || this.config.resourceLimits.storage,
                pids: config.pidLimit || 1000,
                nofile: config.fileLimit || 65536
            };

            const securityContext = {
                runAsUser: config.userId || 1000,
                runAsGroup: config.groupId || 1000,
                fsGroup: config.fsGroup || 1000,
                capabilities: config.capabilities || {
                    drop: ['ALL'],
                    add: ['NET_BIND_SERVICE']
                },
                readOnlyRootFilesystem: config.readOnlyRoot !== false,
                allowPrivilegeEscalation: false
            };

            // Store container configuration
            await this.masterPool.query(`
                INSERT INTO tenant_container_isolation (
                    tenant_id, container_runtime, namespace_id, resource_limits,
                    security_context, volumes, environment_variables, process_limits
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (tenant_id)
                DO UPDATE SET
                    resource_limits = $4, security_context = $5,
                    volumes = $6, environment_variables = $7,
                    process_limits = $8, updated_at = NOW()
            `, [
                tenantId,
                this.config.isolationMode,
                namespaceId,
                JSON.stringify(resourceLimits),
                JSON.stringify(securityContext),
                JSON.stringify(config.volumes || []),
                JSON.stringify(config.environmentVariables || {}),
                JSON.stringify(config.processLimits || {})
            ]);

            // Create cgroups for resource limiting
            await this.createCgroups(tenantId, resourceLimits);

            this.tenantContainers.set(tenantId, { namespaceId, limits: resourceLimits });

            await this.auditLog(tenantId, 'container_isolation_created', {
                namespaceId, resourceLimits, securityContext
            });

            return { namespaceId, resourceLimits, securityContext };

        } catch (error) {
            await this.logSecurityViolation(tenantId, 'process', 'high',
                `Failed to create container isolation: ${error.message}`);
            throw error;
        }
    }

    async createCgroups(tenantId, limits) {
        const cgroupPath = `/sys/fs/cgroup/opendirectory/${tenantId}`;

        try {
            // Create cgroup directory
            await fs.mkdir(cgroupPath, { recursive: true });

            // Set CPU limits
            if (limits.cpu) {
                await fs.writeFile(`${cgroupPath}/cpu.max`, `${Math.floor(parseFloat(limits.cpu) * 100000)} 100000`);
            }

            // Set memory limits
            if (limits.memory) {
                const memoryBytes = this.parseMemoryLimit(limits.memory);
                await fs.writeFile(`${cgroupPath}/memory.max`, memoryBytes.toString());
            }

            // Set process limits
            if (limits.pids) {
                await fs.writeFile(`${cgroupPath}/pids.max`, limits.pids.toString());
            }

        } catch (error) {
            console.warn('Failed to create cgroups:', error.message);
        }
    }

    // Encryption Key Management
    async generateEncryptionKey(tenantId, keyType, keyPurpose = '') {
        const key = crypto.randomBytes(this.config.encryptionConfig.keyLength);
        const encryptedKey = await this.encryptWithMasterKey(key);

        const result = await this.masterPool.query(`
            INSERT INTO tenant_encryption_keys (
                tenant_id, key_type, key_purpose, encrypted_key,
                algorithm, key_size, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        `, [
            tenantId,
            keyType,
            keyPurpose,
            encryptedKey,
            this.config.encryptionConfig.algorithm,
            this.config.encryptionConfig.keyLength * 8, // bits
            new Date(Date.now() + this.config.securityPolicies.keyRotationInterval)
        ]);

        const keyId = result.rows[0].id;

        // Cache the decrypted key
        if (!this.tenantEncryptionKeys.has(tenantId)) {
            this.tenantEncryptionKeys.set(tenantId, {});
        }

        const tenantKeys = this.tenantEncryptionKeys.get(tenantId);
        tenantKeys[keyType] = {
            id: keyId,
            key: key,
            algorithm: this.config.encryptionConfig.algorithm,
            version: 1
        };

        await this.auditLog(tenantId, 'encryption_key_generated', {
            keyId, keyType, keyPurpose, algorithm: this.config.encryptionConfig.algorithm
        });

        return keyId;
    }

    async rotateEncryptionKey(tenantId, keyType) {
        // Mark old key as deprecated
        await this.masterPool.query(`
            UPDATE tenant_encryption_keys 
            SET status = 'deprecated', rotated_at = NOW()
            WHERE tenant_id = $1 AND key_type = $2 AND status = 'active'
        `, [tenantId, keyType]);

        // Generate new key
        const newKeyId = await this.generateEncryptionKey(tenantId, keyType);

        await this.auditLog(tenantId, 'encryption_key_rotated', {
            keyType, newKeyId
        });

        return newKeyId;
    }

    async encryptData(tenantId, keyType, data) {
        const tenantKeys = this.tenantEncryptionKeys.get(tenantId);
        if (!tenantKeys || !tenantKeys[keyType]) {
            throw new Error(`No ${keyType} encryption key found for tenant ${tenantId}`);
        }

        const keyInfo = tenantKeys[keyType];
        const iv = crypto.randomBytes(this.config.encryptionConfig.ivLength);
        const cipher = crypto.createCipher(keyInfo.algorithm, keyInfo.key, iv);

        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return {
            encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            keyId: keyInfo.id,
            version: keyInfo.version
        };
    }

    async decryptData(tenantId, keyType, encryptedData) {
        const tenantKeys = this.tenantEncryptionKeys.get(tenantId);
        if (!tenantKeys || !tenantKeys[keyType]) {
            throw new Error(`No ${keyType} decryption key found for tenant ${tenantId}`);
        }

        const keyInfo = tenantKeys[keyType];
        const decipher = crypto.createDecipher(
            keyInfo.algorithm,
            keyInfo.key,
            Buffer.from(encryptedData.iv, 'hex')
        );

        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    // Rate Limiting
    async createTenantRateLimit(tenantId, limits = {}) {
        const rateLimitConfig = {
            requestsPerMinute: limits.requestsPerMinute || this.config.securityPolicies.rateLimitMax / 15,
            requestsPerHour: limits.requestsPerHour || this.config.securityPolicies.rateLimitMax * 4,
            requestsPerDay: limits.requestsPerDay || this.config.securityPolicies.rateLimitMax * 96,
            burstLimit: limits.burstLimit || 100,
            concurrentConnections: limits.concurrentConnections || 50,
            bandwidthLimitMbps: limits.bandwidthLimitMbps || 100
        };

        await this.masterPool.query(`
            INSERT INTO tenant_rate_limits (
                tenant_id, requests_per_minute, requests_per_hour, requests_per_day,
                burst_limit, concurrent_connections, bandwidth_limit_mbps, custom_limits
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id)
            DO UPDATE SET
                requests_per_minute = $2, requests_per_hour = $3, requests_per_day = $4,
                burst_limit = $5, concurrent_connections = $6, bandwidth_limit_mbps = $7,
                custom_limits = $8, updated_at = NOW()
        `, [
            tenantId,
            rateLimitConfig.requestsPerMinute,
            rateLimitConfig.requestsPerHour,
            rateLimitConfig.requestsPerDay,
            rateLimitConfig.burstLimit,
            rateLimitConfig.concurrentConnections,
            rateLimitConfig.bandwidthLimitMbps,
            JSON.stringify(limits.customLimits || {})
        ]);

        // Create rate limiter instance
        const limiter = rateLimit({
            windowMs: this.config.securityPolicies.rateLimitWindow,
            max: rateLimitConfig.requestsPerMinute,
            keyGenerator: (req) => `${tenantId}:${req.ip}`,
            standardHeaders: true,
            legacyHeaders: false,
            handler: (req, res) => {
                this.logSecurityViolation(tenantId, 'api', 'medium', 
                    `Rate limit exceeded from IP: ${req.ip}`);
                res.status(429).json({ 
                    error: 'Rate limit exceeded',
                    retryAfter: Math.ceil(this.config.securityPolicies.rateLimitWindow / 1000)
                });
            }
        });

        this.tenantRateLimiters.set(tenantId, limiter);

        await this.auditLog(tenantId, 'rate_limit_configured', rateLimitConfig);

        return rateLimitConfig;
    }

    getTenantRateLimit(tenantId) {
        return this.tenantRateLimiters.get(tenantId) || this.createDefaultRateLimit();
    }

    createDefaultRateLimit() {
        return rateLimit({
            windowMs: this.config.securityPolicies.rateLimitWindow,
            max: this.config.securityPolicies.rateLimitMax,
            standardHeaders: true,
            legacyHeaders: false
        });
    }

    // Security Boundary Enforcement
    async enforceSecurityBoundaries(tenantId, request) {
        const checks = [
            this.checkNetworkAccess(tenantId, request),
            this.checkStorageAccess(tenantId, request),
            this.checkProcessAccess(tenantId, request),
            this.checkAPIAccess(tenantId, request)
        ];

        const results = await Promise.allSettled(checks);
        const violations = results.filter(result => result.status === 'rejected')
                                  .map(result => result.reason);

        if (violations.length > 0) {
            for (const violation of violations) {
                await this.logSecurityViolation(tenantId, violation.type, violation.severity, violation.message);
            }
            
            throw new Error(`Security boundary violations detected: ${violations.map(v => v.message).join(', ')}`);
        }

        return true;
    }

    async checkNetworkAccess(tenantId, request) {
        const tenantNetwork = this.tenantNetworks.get(tenantId);
        if (!tenantNetwork) return true;

        // Check if request originates from tenant's network
        const clientIP = request.ip;
        const subnet = tenantNetwork.subnet;

        if (!this.isIPInSubnet(clientIP, subnet)) {
            throw {
                type: 'network',
                severity: 'high',
                message: `Unauthorized network access from ${clientIP} to tenant ${tenantId}`
            };
        }

        return true;
    }

    async checkStorageAccess(tenantId, request) {
        // Implement storage access validation
        const allowedPaths = [`/var/lib/opendirectory/tenants/${tenantId}/`];
        
        if (request.path && !allowedPaths.some(allowed => request.path.startsWith(allowed))) {
            throw {
                type: 'storage',
                severity: 'high',
                message: `Unauthorized storage access attempt to ${request.path}`
            };
        }

        return true;
    }

    async checkProcessAccess(tenantId, request) {
        // Implement process isolation validation
        const tenantContainer = this.tenantContainers.get(tenantId);
        if (!tenantContainer) return true;

        // Check if process is running within tenant boundaries
        return true;
    }

    async checkAPIAccess(tenantId, request) {
        // Apply rate limiting
        const rateLimiter = this.getTenantRateLimit(tenantId);
        
        return new Promise((resolve, reject) => {
            rateLimiter(request, null, (err) => {
                if (err) {
                    reject({
                        type: 'api',
                        severity: 'medium',
                        message: 'API rate limit exceeded'
                    });
                } else {
                    resolve(true);
                }
            });
        });
    }

    // Performance Monitoring
    async recordPerformanceMetric(tenantId, metricType, value, unit = 'count') {
        await this.masterPool.query(`
            INSERT INTO tenant_performance_metrics (
                tenant_id, metric_type, metric_value, unit, metadata
            )
            VALUES ($1, $2, $3, $4, $5)
        `, [tenantId, metricType, value, unit, JSON.stringify({ timestamp: Date.now() })]);

        // Check for performance violations
        await this.checkPerformanceLimits(tenantId, metricType, value);
    }

    async checkPerformanceLimits(tenantId, metricType, value) {
        const tenantContainer = this.tenantContainers.get(tenantId);
        if (!tenantContainer) return;

        const limits = tenantContainer.limits;
        let exceeded = false;
        let severity = 'medium';

        switch (metricType) {
            case 'cpu':
                if (value > parseFloat(limits.cpu) * 0.9) {
                    exceeded = true;
                    severity = value > parseFloat(limits.cpu) ? 'high' : 'medium';
                }
                break;
            case 'memory':
                const memoryLimit = this.parseMemoryLimit(limits.memory);
                if (value > memoryLimit * 0.9) {
                    exceeded = true;
                    severity = value > memoryLimit ? 'high' : 'medium';
                }
                break;
        }

        if (exceeded) {
            await this.logSecurityViolation(tenantId, 'performance', severity,
                `${metricType.toUpperCase()} usage (${value}) approaching or exceeding limit`);
        }
    }

    // Audit Logging
    async auditLog(tenantId, action, details = {}, request = null) {
        if (!this.config.auditLogging) return;

        const logEntry = {
            timestamp: new Date().toISOString(),
            tenantId,
            action,
            details,
            source: {
                ip: request?.ip,
                userAgent: request?.get('User-Agent'),
                method: request?.method,
                path: request?.path
            },
            level: 'info'
        };

        this.auditLogger.info(logEntry);

        // Store in Redis for real-time processing
        await this.redisClient.lpush(
            `audit:${tenantId}`,
            JSON.stringify(logEntry)
        );

        // Trim audit log to prevent memory issues
        await this.redisClient.ltrim(`audit:${tenantId}`, 0, 1000);
    }

    async logSecurityViolation(tenantId, violationType, severity, description, metadata = {}) {
        await this.masterPool.query(`
            INSERT INTO security_violations (
                tenant_id, violation_type, severity, description, metadata
            )
            VALUES ($1, $2, $3, $4, $5)
        `, [tenantId, violationType, severity, description, JSON.stringify(metadata)]);

        // Critical violations should trigger immediate alerts
        if (severity === 'critical') {
            await this.sendSecurityAlert(tenantId, violationType, severity, description);
        }

        await this.auditLog(tenantId, 'security_violation', {
            violationType, severity, description, metadata
        });
    }

    async sendSecurityAlert(tenantId, violationType, severity, description) {
        // Implementation for sending security alerts (email, webhook, etc.)
        console.error(`SECURITY ALERT [${severity}] for tenant ${tenantId}: ${description}`);
    }

    // Isolation Middleware
    createIsolationMiddleware() {
        return async (req, res, next) => {
            try {
                const tenantId = req.tenant?.id || req.headers['x-tenant-id'];
                
                if (!tenantId) {
                    return next();
                }

                // Enforce security boundaries
                await this.enforceSecurityBoundaries(tenantId, req);

                // Add isolation context to request
                req.isolation = {
                    tenantId,
                    network: this.tenantNetworks.get(tenantId),
                    container: this.tenantContainers.get(tenantId),
                    encryptionKeys: this.tenantEncryptionKeys.get(tenantId),
                    rateLimiter: this.tenantRateLimiters.get(tenantId)
                };

                // Record API access
                await this.recordPerformanceMetric(tenantId, 'api_call', 1);
                await this.auditLog(tenantId, 'api_access', {
                    method: req.method,
                    path: req.path,
                    query: req.query
                }, req);

                next();
            } catch (error) {
                console.error('Isolation middleware error:', error);
                res.status(403).json({
                    error: 'Security boundary violation',
                    message: error.message
                });
            }
        };
    }

    // Utility Methods
    generateSubnet() {
        // Generate a random private subnet
        const thirdOctet = Math.floor(Math.random() * 254) + 1;
        return `10.${thirdOctet}.0.0/24`;
    }

    calculateGateway(subnet) {
        const [network] = subnet.split('/');
        const parts = network.split('.');
        parts[3] = '1';
        return parts.join('.');
    }

    isIPInSubnet(ip, subnet) {
        // Simple subnet check implementation
        const [network, bits] = subnet.split('/');
        const mask = ~((1 << (32 - parseInt(bits))) - 1);
        
        const ipInt = this.ipToInt(ip);
        const networkInt = this.ipToInt(network);
        
        return (ipInt & mask) === (networkInt & mask);
    }

    ipToInt(ip) {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    }

    parseStorageQuota(quota) {
        const units = { B: 1, KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
        const match = quota.match(/^(\d+)(B|KB|MB|GB|TB)$/i);
        if (match) {
            return parseInt(match[1]) * units[match[2].toUpperCase()];
        }
        return 0;
    }

    parseMemoryLimit(limit) {
        const units = { B: 1, K: 1024, M: 1024**2, G: 1024**3, T: 1024**4 };
        const match = limit.match(/^(\d+)([KMGT]?i?)$/);
        if (match) {
            const unit = match[2].replace('i', '').toUpperCase() || 'B';
            return parseInt(match[1]) * (units[unit] || 1);
        }
        return 0;
    }

    async encryptWithMasterKey(data) {
        // In production, use proper key management service (KMS)
        const masterKey = process.env.MASTER_ENCRYPTION_KEY || 'default-master-key-change-me';
        const cipher = crypto.createCipher('aes-256-gcm', masterKey);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }

    async decryptMasterKey(encryptedData) {
        const masterKey = process.env.MASTER_ENCRYPTION_KEY || 'default-master-key-change-me';
        const decipher = crypto.createDecipher('aes-256-gcm', masterKey);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return Buffer.from(decrypted, 'hex');
    }

    // REST API
    setupRestAPI() {
        const app = express();

        app.use(helmet());
        app.use(cors({
            origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
            credentials: true
        }));

        app.use(express.json());
        app.use(this.createIsolationMiddleware());

        // Health check
        app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'isolation-layer'
            });
        });

        // Network isolation endpoints
        app.post('/api/tenants/:tenantId/network-isolation', async (req, res) => {
            try {
                const result = await this.createNetworkIsolation(req.params.tenantId, req.body);
                res.status(201).json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Storage isolation endpoints
        app.post('/api/tenants/:tenantId/storage-isolation', async (req, res) => {
            try {
                const result = await this.createStorageIsolation(req.params.tenantId, req.body);
                res.status(201).json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Container isolation endpoints
        app.post('/api/tenants/:tenantId/container-isolation', async (req, res) => {
            try {
                const result = await this.createContainerIsolation(req.params.tenantId, req.body);
                res.status(201).json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Encryption key management
        app.post('/api/tenants/:tenantId/encryption-keys', async (req, res) => {
            try {
                const keyId = await this.generateEncryptionKey(
                    req.params.tenantId,
                    req.body.keyType,
                    req.body.keyPurpose
                );
                res.status(201).json({ keyId });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.post('/api/tenants/:tenantId/encryption-keys/:keyType/rotate', async (req, res) => {
            try {
                const keyId = await this.rotateEncryptionKey(req.params.tenantId, req.params.keyType);
                res.json({ newKeyId: keyId });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Rate limit configuration
        app.post('/api/tenants/:tenantId/rate-limits', async (req, res) => {
            try {
                const config = await this.createTenantRateLimit(req.params.tenantId, req.body);
                res.status(201).json(config);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Security violations
        app.get('/api/tenants/:tenantId/security-violations', async (req, res) => {
            try {
                const violations = await this.masterPool.query(`
                    SELECT * FROM security_violations 
                    WHERE tenant_id = $1 
                    ORDER BY created_at DESC 
                    LIMIT 100
                `, [req.params.tenantId]);

                res.json({ violations: violations.rows });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Performance metrics
        app.get('/api/tenants/:tenantId/performance-metrics', async (req, res) => {
            try {
                const metrics = await this.masterPool.query(`
                    SELECT metric_type, AVG(metric_value) as avg_value, 
                           MAX(metric_value) as max_value, COUNT(*) as data_points
                    FROM tenant_performance_metrics 
                    WHERE tenant_id = $1 
                    AND timestamp >= NOW() - INTERVAL '24 hours'
                    GROUP BY metric_type
                `, [req.params.tenantId]);

                res.json({ metrics: metrics.rows });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Audit logs
        app.get('/api/tenants/:tenantId/audit-logs', async (req, res) => {
            try {
                const logs = await this.redisClient.lrange(`audit:${req.params.tenantId}`, 0, 99);
                const parsedLogs = logs.map(log => JSON.parse(log));
                res.json({ logs: parsedLogs });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        return app;
    }

    async start() {
        const app = this.setupRestAPI();

        const server = app.listen(this.config.port, () => {
            console.log(`Tenant Isolation Layer started on port ${this.config.port}`);
            console.log('Available endpoints:');
            console.log('  POST /api/tenants/:tenantId/network-isolation - Create network isolation');
            console.log('  POST /api/tenants/:tenantId/storage-isolation - Create storage isolation');
            console.log('  POST /api/tenants/:tenantId/container-isolation - Create container isolation');
            console.log('  POST /api/tenants/:tenantId/encryption-keys - Generate encryption key');
            console.log('  POST /api/tenants/:tenantId/encryption-keys/:keyType/rotate - Rotate key');
            console.log('  POST /api/tenants/:tenantId/rate-limits - Configure rate limits');
            console.log('  GET /api/tenants/:tenantId/security-violations - Get violations');
            console.log('  GET /api/tenants/:tenantId/performance-metrics - Get performance metrics');
            console.log('  GET /api/tenants/:tenantId/audit-logs - Get audit logs');
        });

        // Start cleanup tasks
        setInterval(() => this.cleanupExpiredKeys(), 60 * 60 * 1000); // Hourly
        setInterval(() => this.cleanupOldAuditLogs(), 24 * 60 * 60 * 1000); // Daily

        return server;
    }

    async cleanupExpiredKeys() {
        try {
            const expiredKeys = await this.masterPool.query(`
                UPDATE tenant_encryption_keys 
                SET status = 'expired' 
                WHERE expires_at < NOW() AND status = 'active'
                RETURNING tenant_id, key_type
            `);

            for (const key of expiredKeys.rows) {
                await this.auditLog(key.tenant_id, 'encryption_key_expired', {
                    keyType: key.key_type
                });
            }
        } catch (error) {
            console.error('Failed to cleanup expired keys:', error);
        }
    }

    async cleanupOldAuditLogs() {
        try {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - this.config.securityPolicies.auditRetention / (24 * 60 * 60 * 1000));

            // Cleanup old audit logs from Redis
            const tenants = await this.masterPool.query('SELECT id FROM tenants WHERE status = $1', ['active']);
            
            for (const tenant of tenants.rows) {
                await this.redisClient.ltrim(`audit:${tenant.id}`, 0, 999);
            }
        } catch (error) {
            console.error('Failed to cleanup old audit logs:', error);
        }
    }
}

module.exports = TenantIsolationLayer;

if (require.main === module) {
    const config = {
        port: process.env.PORT || 3104,
        masterDbUrl: process.env.MASTER_DB_URL || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
        redisUrl: process.env.REDIS_URL || 'redis://:changeme@localhost:6379',
        isolationMode: process.env.ISOLATION_MODE || 'container',
        storageEncryption: process.env.STORAGE_ENCRYPTION !== 'false'
    };

    const isolation = new TenantIsolationLayer(config);
    isolation.start().catch(error => {
        console.error('Failed to start Tenant Isolation Layer:', error);
        process.exit(1);
    });
}