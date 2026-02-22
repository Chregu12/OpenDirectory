#!/usr/bin/env node

/**
 * OpenDirectory Federation Service
 * 
 * Comprehensive federation system providing:
 * - Cross-tenant authentication
 * - Federated identity management
 * - Trust relationships between tenants
 * - Shared resource management
 * - Cross-tenant API access
 * - SAML/OIDC federation
 * - B2B collaboration features
 * - Guest user management
 * 
 * Enables secure inter-tenant communication and resource sharing
 */

const express = require('express');
const { Pool } = require('pg');
const Redis = require('ioredis');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const saml = require('passport-saml');
const { Issuer, Strategy } = require('openid-client');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const xmlbuilder = require('xmlbuilder');
const xmlparser = require('xml2js');

class FederationService {
    constructor(config = {}) {
        this.config = {
            port: config.port || 3102,
            jwtSecret: config.jwtSecret || 'federation-secret-key',
            masterDbUrl: config.masterDbUrl || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
            redisUrl: config.redisUrl || 'redis://:changeme@localhost:6379',
            coreServiceUrl: config.coreServiceUrl || 'http://localhost:3100',
            federationDomain: config.federationDomain || 'federation.opendirectory.io',
            samlConfig: {
                entryPoint: config.samlEntryPoint || 'https://federation.opendirectory.io/saml/sso',
                issuer: config.samlIssuer || 'opendirectory-federation',
                cert: config.samlCert,
                privateKey: config.samlPrivateKey
            },
            oidcConfig: {
                issuer: config.oidcIssuer || 'https://federation.opendirectory.io',
                clientId: config.oidcClientId || 'federation-client',
                clientSecret: config.oidcClientSecret || 'federation-secret'
            },
            ...config
        };

        this.masterPool = null;
        this.redisClient = null;
        this.trustedIssuers = new Map();
        this.federationKeys = new Map();
        this.activeConnections = new Map();
        
        this.initializeConnections();
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
            console.log('Federation Service initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Federation Service:', error);
            throw error;
        }
    }

    async initializeSchema() {
        const schema = `
            -- Trust relationships between tenants
            CREATE TABLE IF NOT EXISTS tenant_trust_relationships (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                source_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                target_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                relationship_type VARCHAR(50) NOT NULL CHECK (relationship_type IN ('bidirectional', 'unidirectional', 'guest_access')),
                trust_level VARCHAR(20) DEFAULT 'basic' CHECK (trust_level IN ('basic', 'elevated', 'admin')),
                status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'suspended', 'revoked')),
                permissions JSONB DEFAULT '[]',
                metadata JSONB DEFAULT '{}',
                created_by UUID,
                approved_by UUID,
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(source_tenant_id, target_tenant_id)
            );

            -- Federated identity providers
            CREATE TABLE IF NOT EXISTS federated_identity_providers (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                provider_type VARCHAR(50) NOT NULL CHECK (provider_type IN ('saml', 'oidc', 'oauth2', 'ldap')),
                provider_name VARCHAR(200) NOT NULL,
                configuration JSONB NOT NULL,
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'error')),
                certificate TEXT,
                metadata_url TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Cross-tenant user mappings
            CREATE TABLE IF NOT EXISTS federated_user_mappings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                local_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                remote_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                local_user_id UUID,
                remote_user_id UUID,
                identity_provider_id UUID REFERENCES federated_identity_providers(id),
                external_user_id VARCHAR(255), -- For external IdPs
                mapping_attributes JSONB DEFAULT '{}',
                access_permissions JSONB DEFAULT '[]',
                last_login TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Shared resources across tenants
            CREATE TABLE IF NOT EXISTS shared_resources (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                owner_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                resource_type VARCHAR(50) NOT NULL, -- 'policy', 'application', 'certificate', etc.
                resource_id UUID NOT NULL,
                resource_name VARCHAR(200) NOT NULL,
                sharing_permissions JSONB NOT NULL, -- Which tenants can access and how
                access_rules JSONB DEFAULT '{}',
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Cross-tenant access tokens
            CREATE TABLE IF NOT EXISTS federation_tokens (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                token_hash VARCHAR(255) UNIQUE NOT NULL,
                source_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                target_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                user_id UUID,
                token_type VARCHAR(20) DEFAULT 'access' CHECK (token_type IN ('access', 'refresh', 'delegation')),
                scopes JSONB DEFAULT '[]',
                permissions JSONB DEFAULT '[]',
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_used_at TIMESTAMP WITH TIME ZONE
            );

            -- SAML assertions cache
            CREATE TABLE IF NOT EXISTS saml_assertions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                assertion_id VARCHAR(255) UNIQUE NOT NULL,
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                user_id UUID,
                issuer VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                attributes JSONB DEFAULT '{}',
                conditions JSONB DEFAULT '{}',
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Guest user sessions
            CREATE TABLE IF NOT EXISTS guest_sessions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                session_token VARCHAR(255) UNIQUE NOT NULL,
                host_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                guest_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                guest_user_id UUID,
                permissions JSONB DEFAULT '[]',
                access_restrictions JSONB DEFAULT '{}',
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Audit log for federation activities
            CREATE TABLE IF NOT EXISTS federation_audit_log (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_type VARCHAR(100) NOT NULL,
                source_tenant_id UUID,
                target_tenant_id UUID,
                user_id UUID,
                resource_type VARCHAR(50),
                resource_id UUID,
                details JSONB DEFAULT '{}',
                ip_address INET,
                user_agent TEXT,
                success BOOLEAN DEFAULT true,
                error_message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_trust_relationships_source ON tenant_trust_relationships(source_tenant_id);
            CREATE INDEX IF NOT EXISTS idx_trust_relationships_target ON tenant_trust_relationships(target_tenant_id);
            CREATE INDEX IF NOT EXISTS idx_federated_providers_tenant ON federated_identity_providers(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_user_mappings_local ON federated_user_mappings(local_tenant_id, local_user_id);
            CREATE INDEX IF NOT EXISTS idx_user_mappings_remote ON federated_user_mappings(remote_tenant_id, remote_user_id);
            CREATE INDEX IF NOT EXISTS idx_shared_resources_owner ON shared_resources(owner_tenant_id);
            CREATE INDEX IF NOT EXISTS idx_federation_tokens_hash ON federation_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_federation_tokens_expires ON federation_tokens(expires_at);
            CREATE INDEX IF NOT EXISTS idx_saml_assertions_id ON saml_assertions(assertion_id);
            CREATE INDEX IF NOT EXISTS idx_guest_sessions_token ON guest_sessions(session_token);
            CREATE INDEX IF NOT EXISTS idx_federation_audit_source ON federation_audit_log(source_tenant_id);
            CREATE INDEX IF NOT EXISTS idx_federation_audit_created ON federation_audit_log(created_at);
        `;

        await this.masterPool.query(schema);
    }

    // Trust Relationship Management
    async createTrustRelationship(sourceTenantId, targetTenantId, options = {}) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            // Verify both tenants exist and are active
            const tenants = await client.query(
                'SELECT id, name FROM tenants WHERE id IN ($1, $2) AND status = $3',
                [sourceTenantId, targetTenantId, 'active']
            );

            if (tenants.rows.length !== 2) {
                throw new Error('One or both tenants are invalid or inactive');
            }

            const relationship = await client.query(`
                INSERT INTO tenant_trust_relationships (
                    source_tenant_id, target_tenant_id, relationship_type, 
                    trust_level, permissions, metadata, created_by, expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
            `, [
                sourceTenantId,
                targetTenantId,
                options.relationshipType || 'unidirectional',
                options.trustLevel || 'basic',
                JSON.stringify(options.permissions || []),
                JSON.stringify(options.metadata || {}),
                options.createdBy,
                options.expiresAt
            ]);

            // Create bidirectional relationship if requested
            if (options.relationshipType === 'bidirectional') {
                await client.query(`
                    INSERT INTO tenant_trust_relationships (
                        source_tenant_id, target_tenant_id, relationship_type, 
                        trust_level, permissions, metadata, created_by, expires_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                `, [
                    targetTenantId,
                    sourceTenantId,
                    'unidirectional',
                    options.trustLevel || 'basic',
                    JSON.stringify(options.permissions || []),
                    JSON.stringify(options.metadata || {}),
                    options.createdBy,
                    options.expiresAt
                ]);
            }

            await client.query('COMMIT');

            // Log audit event
            await this.logFederationEvent('trust_relationship_created', sourceTenantId, targetTenantId, {
                relationshipType: options.relationshipType,
                trustLevel: options.trustLevel
            });

            return relationship.rows[0];

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async approveTrustRelationship(relationshipId, approvedBy) {
        await this.masterPool.query(`
            UPDATE tenant_trust_relationships 
            SET status = 'active', approved_by = $2, updated_at = NOW()
            WHERE id = $1 AND status = 'pending'
        `, [relationshipId, approvedBy]);

        // Clear trust cache
        const relationship = await this.getTrustRelationship(relationshipId);
        await this.redisClient.del(`trust:${relationship.source_tenant_id}:${relationship.target_tenant_id}`);
    }

    async revokeTrustRelationship(relationshipId, reason = '') {
        const relationship = await this.getTrustRelationship(relationshipId);
        
        await this.masterPool.query(`
            UPDATE tenant_trust_relationships 
            SET status = 'revoked', metadata = metadata || $2, updated_at = NOW()
            WHERE id = $1
        `, [relationshipId, JSON.stringify({ revocation_reason: reason })]);

        // Invalidate all related federation tokens
        await this.masterPool.query(`
            DELETE FROM federation_tokens 
            WHERE (source_tenant_id = $1 AND target_tenant_id = $2) 
               OR (source_tenant_id = $2 AND target_tenant_id = $1)
        `, [relationship.source_tenant_id, relationship.target_tenant_id]);

        // Clear caches
        await this.redisClient.del(`trust:${relationship.source_tenant_id}:${relationship.target_tenant_id}`);
    }

    async getTrustRelationship(relationshipId) {
        const result = await this.masterPool.query(
            'SELECT * FROM tenant_trust_relationships WHERE id = $1',
            [relationshipId]
        );
        return result.rows.length > 0 ? result.rows[0] : null;
    }

    async checkTrustRelationship(sourceTenantId, targetTenantId) {
        const cacheKey = `trust:${sourceTenantId}:${targetTenantId}`;
        const cached = await this.redisClient.get(cacheKey);
        
        if (cached) {
            return JSON.parse(cached);
        }

        const result = await this.masterPool.query(`
            SELECT * FROM tenant_trust_relationships 
            WHERE source_tenant_id = $1 AND target_tenant_id = $2 
            AND status = 'active' AND (expires_at IS NULL OR expires_at > NOW())
        `, [sourceTenantId, targetTenantId]);

        const trust = result.rows.length > 0 ? result.rows[0] : null;
        
        if (trust) {
            await this.redisClient.setex(cacheKey, 300, JSON.stringify(trust));
        }

        return trust;
    }

    // Federated Identity Management
    async configureFederatedProvider(tenantId, providerConfig) {
        const provider = await this.masterPool.query(`
            INSERT INTO federated_identity_providers (
                tenant_id, provider_type, provider_name, configuration, certificate
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        `, [
            tenantId,
            providerConfig.type,
            providerConfig.name,
            JSON.stringify(providerConfig.config),
            providerConfig.certificate
        ]);

        // Initialize provider-specific configuration
        await this.initializeProviderConfiguration(provider.rows[0]);

        return provider.rows[0];
    }

    async initializeProviderConfiguration(provider) {
        switch (provider.provider_type) {
            case 'saml':
                await this.configureSAMLProvider(provider);
                break;
            case 'oidc':
                await this.configureOIDCProvider(provider);
                break;
            case 'oauth2':
                await this.configureOAuth2Provider(provider);
                break;
        }
    }

    async configureSAMLProvider(provider) {
        const config = JSON.parse(provider.configuration);
        
        // Generate SAML metadata
        const metadata = this.generateSAMLMetadata(provider.tenant_id, config);
        
        // Store metadata
        await this.masterPool.query(`
            UPDATE federated_identity_providers 
            SET metadata_url = $2, configuration = configuration || $3
            WHERE id = $1
        `, [
            provider.id, 
            `${this.config.federationDomain}/saml/metadata/${provider.tenant_id}`,
            JSON.stringify({ metadata: metadata })
        ]);
    }

    generateSAMLMetadata(tenantId, config) {
        const metadata = xmlbuilder.create('EntityDescriptor', { encoding: 'UTF-8' })
            .att('xmlns', 'urn:oasis:names:tc:SAML:2.0:metadata')
            .att('entityID', `${this.config.federationDomain}/saml/${tenantId}`)
            .ele('SPSSODescriptor')
                .att('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol')
                .att('AuthnRequestsSigned', 'true')
                .ele('SingleLogoutService')
                    .att('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
                    .att('Location', `${this.config.federationDomain}/saml/slo/${tenantId}`)
                .up()
                .ele('AssertionConsumerService')
                    .att('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
                    .att('Location', `${this.config.federationDomain}/saml/acs/${tenantId}`)
                    .att('index', '1')
                    .att('isDefault', 'true')
                .up()
            .up();

        return metadata.end({ pretty: true });
    }

    // Cross-tenant Authentication
    async authenticateCrossTenant(sourceToken, targetTenantId, scopes = []) {
        try {
            // Decode source token
            const decoded = jwt.verify(sourceToken, this.config.jwtSecret);
            const sourceTenantId = decoded.tenantId;

            // Check trust relationship
            const trust = await this.checkTrustRelationship(sourceTenantId, targetTenantId);
            if (!trust) {
                throw new Error('No trust relationship exists between tenants');
            }

            // Verify requested scopes are permitted
            const permittedScopes = trust.permissions || [];
            const unauthorizedScopes = scopes.filter(scope => !permittedScopes.includes(scope));
            
            if (unauthorizedScopes.length > 0) {
                throw new Error(`Unauthorized scopes: ${unauthorizedScopes.join(', ')}`);
            }

            // Create cross-tenant access token
            const federationToken = await this.createFederationToken({
                sourceTenantId,
                targetTenantId,
                userId: decoded.userId,
                scopes,
                trustLevel: trust.trust_level
            });

            await this.logFederationEvent('cross_tenant_auth_success', sourceTenantId, targetTenantId, {
                userId: decoded.userId,
                scopes
            });

            return {
                success: true,
                federationToken,
                expiresAt: federationToken.expires_at,
                scopes,
                trustLevel: trust.trust_level
            };

        } catch (error) {
            await this.logFederationEvent('cross_tenant_auth_failed', null, targetTenantId, {
                error: error.message
            });
            throw error;
        }
    }

    async createFederationToken(options) {
        const tokenId = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(tokenId).digest('hex');
        
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 2); // 2 hour expiration

        const token = await this.masterPool.query(`
            INSERT INTO federation_tokens (
                token_hash, source_tenant_id, target_tenant_id, user_id,
                token_type, scopes, permissions, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
        `, [
            tokenHash,
            options.sourceTenantId,
            options.targetTenantId,
            options.userId,
            options.tokenType || 'access',
            JSON.stringify(options.scopes || []),
            JSON.stringify(options.permissions || []),
            expiresAt
        ]);

        // Create JWT with federation claims
        const jwtToken = jwt.sign({
            federationId: token.rows[0].id,
            tokenId,
            sourceTenantId: options.sourceTenantId,
            targetTenantId: options.targetTenantId,
            userId: options.userId,
            scopes: options.scopes,
            trustLevel: options.trustLevel,
            type: 'federation'
        }, this.config.jwtSecret, {
            expiresIn: '2h',
            issuer: this.config.federationDomain,
            audience: options.targetTenantId
        });

        return {
            ...token.rows[0],
            jwt_token: jwtToken
        };
    }

    async validateFederationToken(token) {
        try {
            const decoded = jwt.verify(token, this.config.jwtSecret);
            
            if (decoded.type !== 'federation') {
                throw new Error('Invalid token type');
            }

            // Check token in database
            const tokenHash = crypto.createHash('sha256').update(decoded.tokenId).digest('hex');
            const dbToken = await this.masterPool.query(`
                SELECT * FROM federation_tokens 
                WHERE token_hash = $1 AND expires_at > NOW()
            `, [tokenHash]);

            if (dbToken.rows.length === 0) {
                throw new Error('Token not found or expired');
            }

            // Update last used timestamp
            await this.masterPool.query(
                'UPDATE federation_tokens SET last_used_at = NOW() WHERE id = $1',
                [dbToken.rows[0].id]
            );

            return {
                valid: true,
                token: dbToken.rows[0],
                claims: decoded
            };

        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    // User Mapping and Guest Access
    async createUserMapping(localTenantId, remoteTenantId, mappingData) {
        const mapping = await this.masterPool.query(`
            INSERT INTO federated_user_mappings (
                local_tenant_id, remote_tenant_id, local_user_id, remote_user_id,
                identity_provider_id, external_user_id, mapping_attributes, access_permissions
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
        `, [
            localTenantId,
            remoteTenantId,
            mappingData.localUserId,
            mappingData.remoteUserId,
            mappingData.identityProviderId,
            mappingData.externalUserId,
            JSON.stringify(mappingData.attributes || {}),
            JSON.stringify(mappingData.permissions || [])
        ]);

        return mapping.rows[0];
    }

    async createGuestSession(hostTenantId, guestTenantId, guestUserId, permissions = []) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 8); // 8 hour guest session

        const session = await this.masterPool.query(`
            INSERT INTO guest_sessions (
                session_token, host_tenant_id, guest_tenant_id, 
                guest_user_id, permissions, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        `, [
            sessionToken,
            hostTenantId,
            guestTenantId,
            guestUserId,
            JSON.stringify(permissions),
            expiresAt
        ]);

        await this.logFederationEvent('guest_session_created', hostTenantId, guestTenantId, {
            guestUserId,
            sessionDuration: '8h'
        });

        return session.rows[0];
    }

    async validateGuestSession(sessionToken) {
        const session = await this.masterPool.query(`
            SELECT * FROM guest_sessions 
            WHERE session_token = $1 AND expires_at > NOW()
        `, [sessionToken]);

        if (session.rows.length === 0) {
            return null;
        }

        // Update last activity
        await this.masterPool.query(
            'UPDATE guest_sessions SET last_activity = NOW() WHERE id = $1',
            [session.rows[0].id]
        );

        return session.rows[0];
    }

    // Resource Sharing
    async shareResource(ownerTenantId, resourceType, resourceId, sharingConfig) {
        const sharedResource = await this.masterPool.query(`
            INSERT INTO shared_resources (
                owner_tenant_id, resource_type, resource_id, resource_name,
                sharing_permissions, access_rules, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        `, [
            ownerTenantId,
            resourceType,
            resourceId,
            sharingConfig.name,
            JSON.stringify(sharingConfig.permissions),
            JSON.stringify(sharingConfig.accessRules || {}),
            JSON.stringify(sharingConfig.metadata || {})
        ]);

        return sharedResource.rows[0];
    }

    async getSharedResources(tenantId, resourceType = null) {
        let query = `
            SELECT sr.*, t.name as owner_tenant_name
            FROM shared_resources sr
            JOIN tenants t ON sr.owner_tenant_id = t.id
            WHERE $1 = ANY(
                SELECT jsonb_array_elements_text(sharing_permissions->'allowed_tenants')
            )
        `;
        let params = [tenantId];

        if (resourceType) {
            query += ' AND sr.resource_type = $2';
            params.push(resourceType);
        }

        const result = await this.masterPool.query(query, params);
        return result.rows;
    }

    // SAML SSO Implementation
    async handleSAMLRequest(tenantId, samlRequest) {
        try {
            // Parse SAML request
            const parsed = await xmlparser.parseStringPromise(samlRequest);
            const authRequest = parsed['samlp:AuthnRequest'];

            // Validate request
            await this.validateSAMLRequest(tenantId, authRequest);

            // Generate SAML response
            const response = await this.generateSAMLResponse(tenantId, authRequest);

            return {
                success: true,
                response: response,
                relayState: authRequest.$.ID
            };

        } catch (error) {
            await this.logFederationEvent('saml_request_failed', tenantId, null, {
                error: error.message
            });
            throw error;
        }
    }

    async generateSAMLResponse(tenantId, authRequest) {
        const assertionId = crypto.randomBytes(16).toString('hex');
        const responseId = crypto.randomBytes(16).toString('hex');
        
        const now = new Date();
        const notBefore = new Date(now.getTime() - 5 * 60 * 1000); // 5 minutes ago
        const notOnOrAfter = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes from now

        const response = xmlbuilder.create('samlp:Response', { encoding: 'UTF-8' })
            .att('xmlns:samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
            .att('xmlns:saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
            .att('ID', responseId)
            .att('Version', '2.0')
            .att('IssueInstant', now.toISOString())
            .att('Destination', authRequest.$.AssertionConsumerServiceURL)
            .att('InResponseTo', authRequest.$.ID)
            .ele('saml:Issuer', `${this.config.federationDomain}/saml/${tenantId}`)
            .up()
            .ele('samlp:Status')
                .ele('samlp:StatusCode')
                    .att('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success')
                .up()
            .up()
            .ele('saml:Assertion')
                .att('ID', assertionId)
                .att('Version', '2.0')
                .att('IssueInstant', now.toISOString())
                .ele('saml:Issuer', `${this.config.federationDomain}/saml/${tenantId}`)
                .up()
                .ele('saml:Conditions')
                    .att('NotBefore', notBefore.toISOString())
                    .att('NotOnOrAfter', notOnOrAfter.toISOString())
                    .ele('saml:AudienceRestriction')
                        .ele('saml:Audience', authRequest.$.Issuer)
                        .up()
                    .up()
                .up()
                .ele('saml:AuthnStatement')
                    .att('AuthnInstant', now.toISOString())
                    .ele('saml:AuthnContext')
                        .ele('saml:AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified')
                        .up()
                    .up()
                .up()
            .up();

        return response.end({ pretty: true });
    }

    // Federation Middleware
    createFederationMiddleware() {
        return async (req, res, next) => {
            try {
                const authHeader = req.headers['authorization'];
                
                if (authHeader && authHeader.startsWith('Bearer ')) {
                    const token = authHeader.substring(7);
                    const validation = await this.validateFederationToken(token);
                    
                    if (validation.valid) {
                        req.federation = {
                            active: true,
                            token: validation.token,
                            claims: validation.claims,
                            sourceTenant: validation.claims.sourceTenantId,
                            targetTenant: validation.claims.targetTenantId,
                            trustLevel: validation.claims.trustLevel,
                            scopes: validation.claims.scopes || []
                        };
                    }
                }

                // Check for guest session
                const guestToken = req.headers['x-guest-session'];
                if (guestToken) {
                    const guestSession = await this.validateGuestSession(guestToken);
                    if (guestSession) {
                        req.guest = {
                            active: true,
                            session: guestSession,
                            hostTenant: guestSession.host_tenant_id,
                            guestTenant: guestSession.guest_tenant_id,
                            permissions: guestSession.permissions || []
                        };
                    }
                }

                next();
            } catch (error) {
                console.error('Federation middleware error:', error);
                next();
            }
        };
    }

    // Audit Logging
    async logFederationEvent(eventType, sourceTenantId, targetTenantId, details = {}, req = null) {
        await this.masterPool.query(`
            INSERT INTO federation_audit_log (
                event_type, source_tenant_id, target_tenant_id, user_id,
                details, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            eventType,
            sourceTenantId,
            targetTenantId,
            details.userId,
            JSON.stringify(details),
            req?.ip || null,
            req?.get('User-Agent') || null
        ]);
    }

    // Utility Methods
    async validateSAMLRequest(tenantId, authRequest) {
        // Implement SAML request validation logic
        if (!authRequest || !authRequest.$ || !authRequest.$.ID) {
            throw new Error('Invalid SAML AuthnRequest');
        }
    }

    async configureOIDCProvider(provider) {
        // Configure OIDC provider
        console.log(`Configuring OIDC provider for tenant ${provider.tenant_id}`);
    }

    async configureOAuth2Provider(provider) {
        // Configure OAuth2 provider
        console.log(`Configuring OAuth2 provider for tenant ${provider.tenant_id}`);
    }

    // REST API
    setupRestAPI() {
        const app = express();

        app.use(helmet());
        app.use(cors({
            origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
            credentials: true
        }));

        app.use(rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 1000
        }));

        app.use(express.json());
        app.use(this.createFederationMiddleware());

        // Health check
        app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'federation-service'
            });
        });

        // Trust relationship endpoints
        app.post('/api/trust-relationships', async (req, res) => {
            try {
                const relationship = await this.createTrustRelationship(
                    req.body.sourceTenantId,
                    req.body.targetTenantId,
                    req.body.options
                );
                res.status(201).json(relationship);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.put('/api/trust-relationships/:id/approve', async (req, res) => {
            try {
                await this.approveTrustRelationship(req.params.id, req.body.approvedBy);
                res.json({ success: true });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.delete('/api/trust-relationships/:id', async (req, res) => {
            try {
                await this.revokeTrustRelationship(req.params.id, req.body.reason);
                res.json({ success: true });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Cross-tenant authentication
        app.post('/api/auth/cross-tenant', async (req, res) => {
            try {
                const result = await this.authenticateCrossTenant(
                    req.body.sourceToken,
                    req.body.targetTenantId,
                    req.body.scopes
                );
                res.json(result);
            } catch (error) {
                res.status(401).json({ error: error.message });
            }
        });

        // User mapping endpoints
        app.post('/api/user-mappings', async (req, res) => {
            try {
                const mapping = await this.createUserMapping(
                    req.body.localTenantId,
                    req.body.remoteTenantId,
                    req.body.mappingData
                );
                res.status(201).json(mapping);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Guest session endpoints
        app.post('/api/guest-sessions', async (req, res) => {
            try {
                const session = await this.createGuestSession(
                    req.body.hostTenantId,
                    req.body.guestTenantId,
                    req.body.guestUserId,
                    req.body.permissions
                );
                res.status(201).json(session);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Resource sharing endpoints
        app.post('/api/shared-resources', async (req, res) => {
            try {
                const resource = await this.shareResource(
                    req.body.ownerTenantId,
                    req.body.resourceType,
                    req.body.resourceId,
                    req.body.sharingConfig
                );
                res.status(201).json(resource);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.get('/api/shared-resources/:tenantId', async (req, res) => {
            try {
                const resources = await this.getSharedResources(
                    req.params.tenantId,
                    req.query.type
                );
                res.json({ resources });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Identity provider configuration
        app.post('/api/identity-providers', async (req, res) => {
            try {
                const provider = await this.configureFederatedProvider(
                    req.body.tenantId,
                    req.body.providerConfig
                );
                res.status(201).json(provider);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // SAML endpoints
        app.get('/saml/metadata/:tenantId', async (req, res) => {
            try {
                const provider = await this.masterPool.query(
                    'SELECT configuration FROM federated_identity_providers WHERE tenant_id = $1 AND provider_type = $2',
                    [req.params.tenantId, 'saml']
                );

                if (provider.rows.length === 0) {
                    return res.status(404).json({ error: 'SAML provider not configured' });
                }

                const config = JSON.parse(provider.rows[0].configuration);
                res.set('Content-Type', 'application/xml');
                res.send(config.metadata);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.post('/saml/acs/:tenantId', async (req, res) => {
            try {
                const result = await this.handleSAMLRequest(req.params.tenantId, req.body.SAMLResponse);
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        return app;
    }

    async start() {
        const app = this.setupRestAPI();

        const server = app.listen(this.config.port, () => {
            console.log(`Federation Service started on port ${this.config.port}`);
            console.log('Available endpoints:');
            console.log('  POST /api/trust-relationships - Create trust relationship');
            console.log('  PUT /api/trust-relationships/:id/approve - Approve trust relationship');
            console.log('  DELETE /api/trust-relationships/:id - Revoke trust relationship');
            console.log('  POST /api/auth/cross-tenant - Cross-tenant authentication');
            console.log('  POST /api/user-mappings - Create user mapping');
            console.log('  POST /api/guest-sessions - Create guest session');
            console.log('  POST /api/shared-resources - Share resource');
            console.log('  GET /api/shared-resources/:tenantId - Get shared resources');
            console.log('  POST /api/identity-providers - Configure identity provider');
            console.log('  GET /saml/metadata/:tenantId - SAML metadata');
            console.log('  POST /saml/acs/:tenantId - SAML assertion consumer');
        });

        // Cleanup expired tokens periodically
        setInterval(async () => {
            await this.cleanupExpiredTokens();
        }, 60 * 60 * 1000); // Every hour

        return server;
    }

    async cleanupExpiredTokens() {
        try {
            await this.masterPool.query('DELETE FROM federation_tokens WHERE expires_at < NOW()');
            await this.masterPool.query('DELETE FROM saml_assertions WHERE expires_at < NOW()');
            await this.masterPool.query('DELETE FROM guest_sessions WHERE expires_at < NOW()');
        } catch (error) {
            console.error('Failed to cleanup expired tokens:', error);
        }
    }
}

module.exports = FederationService;

if (require.main === module) {
    const config = {
        port: process.env.PORT || 3102,
        masterDbUrl: process.env.MASTER_DB_URL || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
        redisUrl: process.env.REDIS_URL || 'redis://:changeme@localhost:6379',
        jwtSecret: process.env.JWT_SECRET || 'federation-secret-key'
    };

    const federation = new FederationService(config);
    federation.start().catch(error => {
        console.error('Failed to start Federation Service:', error);
        process.exit(1);
    });
}