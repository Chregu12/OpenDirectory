#!/usr/bin/env node

/**
 * OpenDirectory Multi-Tenant Core
 * 
 * Comprehensive multi-tenancy system providing:
 * - Tenant isolation at database level
 * - Tenant-specific schemas/databases
 * - Cross-tenant data isolation
 * - Tenant context injection
 * - Request routing by tenant
 * - Tenant lifecycle management
 * - Resource quotas per tenant
 * - Tenant-specific configurations
 * 
 * Architecture:
 * - Complete data isolation between tenants
 * - High performance at scale (1000+ tenants)
 * - Zero UI changes required
 * - REST APIs for all operations
 * - Backwards compatibility with single-tenant mode
 */

const express = require('express');
const { Pool } = require('pg');
const { MongoClient } = require('mongodb');
const Redis = require('ioredis');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

class MultiTenantCore {
    constructor(config = {}) {
        this.config = {
            port: config.port || 3100,
            jwtSecret: config.jwtSecret || 'mt-core-secret-key',
            masterDbUrl: config.masterDbUrl || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
            mongoUrl: config.mongoUrl || 'mongodb://opendirectory:changeme@localhost:27017',
            redisUrl: config.redisUrl || 'redis://:changeme@localhost:6379',
            maxTenants: config.maxTenants || 10000,
            defaultQuotas: {
                users: 1000,
                devices: 5000,
                policies: 100,
                storage: '10GB',
                apiCallsPerHour: 10000
            },
            ...config
        };

        this.tenantDatabases = new Map();
        this.tenantConfigs = new Map();
        this.tenantMetrics = new Map();
        this.masterPool = null;
        this.mongoClient = null;
        this.redisClient = null;
        
        this.initializeConnections();
    }

    async initializeConnections() {
        try {
            // Master PostgreSQL connection for tenant metadata
            this.masterPool = new Pool({
                connectionString: this.config.masterDbUrl,
                max: 20,
                idleTimeoutMillis: 30000,
                connectionTimeoutMillis: 10000,
            });

            // MongoDB connection for tenant data
            this.mongoClient = new MongoClient(this.config.mongoUrl, {
                maxPoolSize: 50,
                serverSelectionTimeoutMS: 5000
            });
            await this.mongoClient.connect();

            // Redis connection for caching and sessions
            this.redisClient = new Redis(this.config.redisUrl, {
                retryDelayOnFailover: 100,
                maxRetriesPerRequest: 3
            });

            // Initialize master database schema
            await this.initializeMasterSchema();

            console.log('Multi-Tenant Core initialized successfully');
        } catch (error) {
            console.error('Failed to initialize connections:', error);
            throw error;
        }
    }

    async initializeMasterSchema() {
        const schema = `
            -- Tenant registry and metadata
            CREATE TABLE IF NOT EXISTS tenants (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                slug VARCHAR(50) UNIQUE NOT NULL,
                name VARCHAR(200) NOT NULL,
                domain VARCHAR(255),
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
                plan VARCHAR(50) DEFAULT 'basic',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                suspended_at TIMESTAMP WITH TIME ZONE,
                settings JSONB DEFAULT '{}',
                quotas JSONB DEFAULT '{}',
                usage JSONB DEFAULT '{}'
            );

            -- Tenant database connections
            CREATE TABLE IF NOT EXISTS tenant_databases (
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                db_type VARCHAR(20) NOT NULL, -- 'postgresql', 'mongodb'
                connection_string TEXT NOT NULL,
                schema_name VARCHAR(100),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                PRIMARY KEY (tenant_id, db_type)
            );

            -- Tenant configurations
            CREATE TABLE IF NOT EXISTS tenant_configurations (
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                config_key VARCHAR(100) NOT NULL,
                config_value JSONB NOT NULL,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                PRIMARY KEY (tenant_id, config_key)
            );

            -- Tenant API keys for authentication
            CREATE TABLE IF NOT EXISTS tenant_api_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                key_hash VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                permissions JSONB DEFAULT '[]',
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_used_at TIMESTAMP WITH TIME ZONE
            );

            -- Tenant resource usage tracking
            CREATE TABLE IF NOT EXISTS tenant_usage (
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                resource_type VARCHAR(50) NOT NULL,
                current_usage BIGINT DEFAULT 0,
                quota_limit BIGINT,
                last_reset TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                PRIMARY KEY (tenant_id, resource_type)
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
            CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
            CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
            CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_hash ON tenant_api_keys(key_hash);
            CREATE INDEX IF NOT EXISTS idx_tenant_usage_type ON tenant_usage(resource_type);
        `;

        await this.masterPool.query(schema);
    }

    // Tenant Context Middleware
    createTenantMiddleware() {
        return async (req, res, next) => {
            try {
                let tenantId = null;

                // Extract tenant from various sources
                if (req.headers['x-tenant-id']) {
                    tenantId = req.headers['x-tenant-id'];
                } else if (req.headers['x-tenant-slug']) {
                    const tenant = await this.getTenantBySlug(req.headers['x-tenant-slug']);
                    tenantId = tenant?.id;
                } else if (req.headers['authorization']) {
                    // Extract from JWT or API key
                    const token = req.headers['authorization'].replace('Bearer ', '');
                    const tenantInfo = await this.extractTenantFromToken(token);
                    tenantId = tenantInfo?.tenantId;
                } else if (req.hostname && req.hostname !== 'localhost') {
                    // Extract from custom domain
                    const tenant = await this.getTenantByDomain(req.hostname);
                    tenantId = tenant?.id;
                } else if (req.query.tenant) {
                    tenantId = req.query.tenant;
                }

                if (!tenantId) {
                    // Default to single-tenant mode for backwards compatibility
                    req.tenant = {
                        id: 'default',
                        slug: 'default',
                        name: 'Default Tenant',
                        isDefault: true
                    };
                } else {
                    const tenant = await this.getTenantById(tenantId);
                    if (!tenant || tenant.status !== 'active') {
                        return res.status(403).json({
                            error: 'Invalid or inactive tenant',
                            code: 'TENANT_INVALID'
                        });
                    }
                    req.tenant = tenant;
                }

                // Add tenant-specific database connections
                req.tenantDb = await this.getTenantDatabase(req.tenant.id);
                req.tenantMongo = await this.getTenantMongoDB(req.tenant.id);

                // Add tenant configuration
                req.tenantConfig = await this.getTenantConfig(req.tenant.id);

                // Track API usage
                await this.trackApiUsage(req.tenant.id, req.path, req.method);

                next();
            } catch (error) {
                console.error('Tenant middleware error:', error);
                res.status(500).json({
                    error: 'Tenant resolution failed',
                    code: 'TENANT_ERROR'
                });
            }
        };
    }

    // Tenant Database Management
    async getTenantDatabase(tenantId) {
        if (tenantId === 'default') {
            // Return single-tenant connections
            return {
                query: (text, params) => this.masterPool.query(text, params),
                end: () => {}
            };
        }

        if (this.tenantDatabases.has(tenantId)) {
            return this.tenantDatabases.get(tenantId);
        }

        const dbConfig = await this.masterPool.query(
            'SELECT connection_string, schema_name FROM tenant_databases WHERE tenant_id = $1 AND db_type = $2',
            [tenantId, 'postgresql']
        );

        if (dbConfig.rows.length === 0) {
            throw new Error(`No database configuration found for tenant ${tenantId}`);
        }

        const pool = new Pool({
            connectionString: dbConfig.rows[0].connection_string,
            max: 10,
            idleTimeoutMillis: 30000,
        });

        this.tenantDatabases.set(tenantId, pool);
        return pool;
    }

    async getTenantMongoDB(tenantId) {
        if (tenantId === 'default') {
            return this.mongoClient.db('opendirectory_default');
        }

        return this.mongoClient.db(`tenant_${tenantId.replace(/-/g, '_')}`);
    }

    // Tenant Management API
    async createTenant(tenantData) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            // Create tenant record
            const tenantResult = await client.query(`
                INSERT INTO tenants (slug, name, domain, plan, quotas, settings)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            `, [
                tenantData.slug,
                tenantData.name,
                tenantData.domain,
                tenantData.plan || 'basic',
                JSON.stringify(tenantData.quotas || this.config.defaultQuotas),
                JSON.stringify(tenantData.settings || {})
            ]);

            const tenant = tenantResult.rows[0];

            // Create dedicated PostgreSQL schema
            const schemaName = `tenant_${tenant.id.replace(/-/g, '_')}`;
            await client.query(`CREATE SCHEMA "${schemaName}"`);

            // Store database configuration
            await client.query(`
                INSERT INTO tenant_databases (tenant_id, db_type, connection_string, schema_name)
                VALUES ($1, $2, $3, $4)
            `, [
                tenant.id,
                'postgresql',
                `${this.config.masterDbUrl}?currentSchema=${schemaName}`,
                schemaName
            ]);

            // Initialize tenant-specific tables
            await this.initializeTenantTables(client, schemaName);

            // Create MongoDB database
            const mongoDb = this.mongoClient.db(`tenant_${tenant.id.replace(/-/g, '_')}`);
            await mongoDb.createCollection('devices');
            await mongoDb.createCollection('policies');

            // Initialize resource usage tracking
            const resourceTypes = ['users', 'devices', 'policies', 'api_calls', 'storage'];
            for (const resourceType of resourceTypes) {
                await client.query(`
                    INSERT INTO tenant_usage (tenant_id, resource_type, quota_limit)
                    VALUES ($1, $2, $3)
                `, [
                    tenant.id,
                    resourceType,
                    this.getQuotaLimit(tenant.quotas, resourceType)
                ]);
            }

            await client.query('COMMIT');

            // Cache tenant configuration
            await this.cacheTenantConfig(tenant.id, tenant);

            console.log(`Tenant ${tenant.slug} created successfully`);
            return tenant;

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async initializeTenantTables(client, schemaName) {
        const tenantSchema = `
            SET search_path TO "${schemaName}";
            
            -- Users table for this tenant
            CREATE TABLE users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255),
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                status VARCHAR(20) DEFAULT 'active',
                roles JSONB DEFAULT '["user"]',
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Policies table for this tenant
            CREATE TABLE policies (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(200) NOT NULL,
                description TEXT,
                policy_type VARCHAR(50) NOT NULL,
                config JSONB NOT NULL,
                targets JSONB DEFAULT '[]',
                status VARCHAR(20) DEFAULT 'active',
                created_by UUID,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Audit logs for this tenant
            CREATE TABLE audit_logs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID,
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(50),
                resource_id UUID,
                details JSONB DEFAULT '{}',
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Indexes
            CREATE INDEX idx_users_email ON users(email);
            CREATE INDEX idx_users_status ON users(status);
            CREATE INDEX idx_policies_type ON policies(policy_type);
            CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
            CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
        `;

        await client.query(tenantSchema);
    }

    async suspendTenant(tenantId, reason = 'Manual suspension') {
        const client = await this.masterPool.connect();
        
        try {
            await client.query(`
                UPDATE tenants 
                SET status = 'suspended', suspended_at = NOW(), 
                    settings = settings || $2
                WHERE id = $1
            `, [tenantId, JSON.stringify({ suspension_reason: reason })]);

            // Clear tenant cache
            await this.redisClient.del(`tenant:${tenantId}`);
            
            console.log(`Tenant ${tenantId} suspended: ${reason}`);
        } finally {
            client.release();
        }
    }

    async deleteTenant(tenantId) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            // Get tenant info
            const tenant = await client.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
            if (tenant.rows.length === 0) {
                throw new Error('Tenant not found');
            }

            // Drop PostgreSQL schema
            const schemaName = `tenant_${tenantId.replace(/-/g, '_')}`;
            await client.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`);

            // Drop MongoDB database
            await this.mongoClient.db(`tenant_${tenantId.replace(/-/g, '_')}`).dropDatabase();

            // Update tenant status (soft delete)
            await client.query(`
                UPDATE tenants 
                SET status = 'deleted', updated_at = NOW()
                WHERE id = $1
            `, [tenantId]);

            await client.query('COMMIT');

            // Clear cache
            await this.redisClient.del(`tenant:${tenantId}`);
            this.tenantDatabases.delete(tenantId);

            console.log(`Tenant ${tenantId} deleted successfully`);

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    // Tenant Lookup Methods
    async getTenantById(tenantId) {
        const cacheKey = `tenant:${tenantId}`;
        const cached = await this.redisClient.get(cacheKey);
        
        if (cached) {
            return JSON.parse(cached);
        }

        const result = await this.masterPool.query(
            'SELECT * FROM tenants WHERE id = $1 AND status != $2',
            [tenantId, 'deleted']
        );

        if (result.rows.length === 0) {
            return null;
        }

        const tenant = result.rows[0];
        await this.redisClient.setex(cacheKey, 300, JSON.stringify(tenant));
        
        return tenant;
    }

    async getTenantBySlug(slug) {
        const result = await this.masterPool.query(
            'SELECT * FROM tenants WHERE slug = $1 AND status != $2',
            [slug, 'deleted']
        );

        return result.rows.length > 0 ? result.rows[0] : null;
    }

    async getTenantByDomain(domain) {
        const result = await this.masterPool.query(
            'SELECT * FROM tenants WHERE domain = $1 AND status != $2',
            [domain, 'deleted']
        );

        return result.rows.length > 0 ? result.rows[0] : null;
    }

    async getTenantConfig(tenantId) {
        if (tenantId === 'default') {
            return {};
        }

        const cacheKey = `config:${tenantId}`;
        const cached = await this.redisClient.get(cacheKey);
        
        if (cached) {
            return JSON.parse(cached);
        }

        const result = await this.masterPool.query(
            'SELECT config_key, config_value FROM tenant_configurations WHERE tenant_id = $1',
            [tenantId]
        );

        const config = {};
        result.rows.forEach(row => {
            config[row.config_key] = row.config_value;
        });

        await this.redisClient.setex(cacheKey, 600, JSON.stringify(config));
        return config;
    }

    // Resource Quota Management
    async checkResourceQuota(tenantId, resourceType, increment = 1) {
        if (tenantId === 'default') {
            return true; // No limits for single-tenant mode
        }

        const result = await this.masterPool.query(
            'SELECT current_usage, quota_limit FROM tenant_usage WHERE tenant_id = $1 AND resource_type = $2',
            [tenantId, resourceType]
        );

        if (result.rows.length === 0) {
            return true;
        }

        const usage = result.rows[0];
        return (usage.current_usage + increment) <= usage.quota_limit;
    }

    async incrementResourceUsage(tenantId, resourceType, increment = 1) {
        if (tenantId === 'default') {
            return;
        }

        await this.masterPool.query(`
            UPDATE tenant_usage 
            SET current_usage = current_usage + $3, updated_at = NOW()
            WHERE tenant_id = $1 AND resource_type = $2
        `, [tenantId, resourceType, increment]);
    }

    async trackApiUsage(tenantId, endpoint, method) {
        if (tenantId === 'default') {
            return;
        }

        const hour = new Date().toISOString().slice(0, 13);
        const key = `api_usage:${tenantId}:${hour}`;
        
        const current = await this.redisClient.incr(key);
        if (current === 1) {
            await this.redisClient.expire(key, 3600); // Expire after 1 hour
        }

        // Check rate limits
        const tenant = await this.getTenantById(tenantId);
        const hourlyLimit = tenant.quotas?.apiCallsPerHour || this.config.defaultQuotas.apiCallsPerHour;
        
        if (current > hourlyLimit) {
            throw new Error(`API rate limit exceeded for tenant ${tenantId}`);
        }
    }

    // Token and Authentication
    async extractTenantFromToken(token) {
        try {
            // Try JWT first
            const decoded = jwt.verify(token, this.config.jwtSecret);
            if (decoded.tenantId) {
                return { tenantId: decoded.tenantId };
            }
        } catch (error) {
            // Try API key
            const hashedKey = crypto.createHash('sha256').update(token).digest('hex');
            const result = await this.masterPool.query(
                'SELECT tenant_id FROM tenant_api_keys WHERE key_hash = $1',
                [hashedKey]
            );

            if (result.rows.length > 0) {
                // Update last used timestamp
                await this.masterPool.query(
                    'UPDATE tenant_api_keys SET last_used_at = NOW() WHERE key_hash = $1',
                    [hashedKey]
                );
                
                return { tenantId: result.rows[0].tenant_id };
            }
        }

        return null;
    }

    async createApiKey(tenantId, name, permissions = []) {
        const key = crypto.randomBytes(32).toString('hex');
        const hashedKey = crypto.createHash('sha256').update(key).digest('hex');

        await this.masterPool.query(`
            INSERT INTO tenant_api_keys (tenant_id, key_hash, name, permissions)
            VALUES ($1, $2, $3, $4)
        `, [tenantId, hashedKey, name, JSON.stringify(permissions)]);

        return key;
    }

    // Utility Methods
    getQuotaLimit(quotas, resourceType) {
        const limits = {
            users: quotas?.users || this.config.defaultQuotas.users,
            devices: quotas?.devices || this.config.defaultQuotas.devices,
            policies: quotas?.policies || this.config.defaultQuotas.policies,
            api_calls: quotas?.apiCallsPerHour || this.config.defaultQuotas.apiCallsPerHour,
            storage: this.parseStorageQuota(quotas?.storage || this.config.defaultQuotas.storage)
        };

        return limits[resourceType] || 0;
    }

    parseStorageQuota(storageStr) {
        const units = { GB: 1024 * 1024 * 1024, MB: 1024 * 1024, KB: 1024 };
        const match = storageStr.match(/(\d+)(GB|MB|KB)/);
        if (match) {
            return parseInt(match[1]) * units[match[2]];
        }
        return 0;
    }

    async cacheTenantConfig(tenantId, tenant) {
        const cacheKey = `tenant:${tenantId}`;
        await this.redisClient.setex(cacheKey, 300, JSON.stringify(tenant));
    }

    // REST API Setup
    setupRestAPI() {
        const app = express();

        // Security middleware
        app.use(helmet());
        app.use(cors({
            origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
            credentials: true
        }));

        // Rate limiting
        app.use(rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 1000, // Limit each IP to 1000 requests per windowMs
            message: 'Too many requests from this IP'
        }));

        app.use(express.json({ limit: '10mb' }));

        // Health check
        app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'multi-tenant-core'
            });
        });

        // Tenant management endpoints
        app.post('/api/tenants', async (req, res) => {
            try {
                const tenant = await this.createTenant(req.body);
                res.status(201).json(tenant);
            } catch (error) {
                console.error('Create tenant error:', error);
                res.status(500).json({ error: error.message });
            }
        });

        app.get('/api/tenants/:id', async (req, res) => {
            try {
                const tenant = await this.getTenantById(req.params.id);
                if (!tenant) {
                    return res.status(404).json({ error: 'Tenant not found' });
                }
                res.json(tenant);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.put('/api/tenants/:id/suspend', async (req, res) => {
            try {
                await this.suspendTenant(req.params.id, req.body.reason);
                res.json({ message: 'Tenant suspended successfully' });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.delete('/api/tenants/:id', async (req, res) => {
            try {
                await this.deleteTenant(req.params.id);
                res.json({ message: 'Tenant deleted successfully' });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.post('/api/tenants/:id/api-keys', async (req, res) => {
            try {
                const key = await this.createApiKey(
                    req.params.id, 
                    req.body.name, 
                    req.body.permissions
                );
                res.status(201).json({ key });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Tenant context testing endpoint
        app.get('/api/tenant-info', this.createTenantMiddleware(), (req, res) => {
            res.json({
                tenant: req.tenant,
                hasDbConnection: !!req.tenantDb,
                hasMongoConnection: !!req.tenantMongo,
                config: req.tenantConfig
            });
        });

        return app;
    }

    // Start the service
    async start() {
        const app = this.setupRestAPI();

        const server = app.listen(this.config.port, () => {
            console.log(`Multi-Tenant Core started on port ${this.config.port}`);
            console.log('Available endpoints:');
            console.log('  POST /api/tenants - Create tenant');
            console.log('  GET /api/tenants/:id - Get tenant');
            console.log('  PUT /api/tenants/:id/suspend - Suspend tenant');
            console.log('  DELETE /api/tenants/:id - Delete tenant');
            console.log('  POST /api/tenants/:id/api-keys - Create API key');
            console.log('  GET /api/tenant-info - Test tenant context');
            console.log('  GET /health - Health check');
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('Shutting down Multi-Tenant Core...');
            server.close(() => {
                this.masterPool?.end();
                this.mongoClient?.close();
                this.redisClient?.disconnect();
                process.exit(0);
            });
        });

        return server;
    }
}

// Export for use as module
module.exports = MultiTenantCore;

// CLI usage
if (require.main === module) {
    const config = {
        port: process.env.PORT || 3100,
        masterDbUrl: process.env.MASTER_DB_URL || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
        mongoUrl: process.env.MONGO_URL || 'mongodb://opendirectory:changeme@localhost:27017',
        redisUrl: process.env.REDIS_URL || 'redis://:changeme@localhost:6379',
        jwtSecret: process.env.JWT_SECRET || 'mt-core-secret-key'
    };

    const core = new MultiTenantCore(config);
    core.start().catch(error => {
        console.error('Failed to start Multi-Tenant Core:', error);
        process.exit(1);
    });
}