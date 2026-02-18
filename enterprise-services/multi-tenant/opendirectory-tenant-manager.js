#!/usr/bin/env node

/**
 * OpenDirectory Tenant Management Service
 * 
 * Comprehensive tenant management providing:
 * - Tenant provisioning automation
 * - Tenant onboarding workflows
 * - Billing and usage tracking
 * - Resource quota management
 * - Tenant suspension/deletion
 * - White-labeling configuration
 * - Custom domain management
 * - Tenant backup/restore
 * 
 * Integrates with Multi-Tenant Core for complete tenant lifecycle management
 */

const express = require('express');
const { Pool } = require('pg');
const { MongoClient } = require('mongodb');
const Redis = require('ioredis');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const AWS = require('aws-sdk');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

class TenantManager {
    constructor(config = {}) {
        this.config = {
            port: config.port || 3101,
            coreServiceUrl: config.coreServiceUrl || 'http://localhost:3100',
            masterDbUrl: config.masterDbUrl || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
            mongoUrl: config.mongoUrl || 'mongodb://opendirectory:changeme@localhost:27017',
            redisUrl: config.redisUrl || 'redis://:changeme@localhost:6379',
            emailConfig: {
                host: config.emailHost || 'smtp.gmail.com',
                port: 587,
                auth: {
                    user: config.emailUser || process.env.EMAIL_USER,
                    pass: config.emailPass || process.env.EMAIL_PASS
                }
            },
            s3Config: {
                accessKeyId: config.s3AccessKey || process.env.S3_ACCESS_KEY,
                secretAccessKey: config.s3SecretKey || process.env.S3_SECRET_KEY,
                region: config.s3Region || 'us-east-1',
                bucket: config.s3Bucket || 'opendirectory-backups'
            },
            billingPlans: {
                basic: {
                    name: 'Basic Plan',
                    price: 29.99,
                    quotas: {
                        users: 100,
                        devices: 500,
                        policies: 25,
                        storage: '5GB',
                        apiCallsPerHour: 5000
                    }
                },
                professional: {
                    name: 'Professional Plan',
                    price: 99.99,
                    quotas: {
                        users: 1000,
                        devices: 5000,
                        policies: 100,
                        storage: '50GB',
                        apiCallsPerHour: 25000
                    }
                },
                enterprise: {
                    name: 'Enterprise Plan',
                    price: 299.99,
                    quotas: {
                        users: 10000,
                        devices: 50000,
                        policies: 500,
                        storage: '500GB',
                        apiCallsPerHour: 100000
                    }
                }
            },
            ...config
        };

        this.masterPool = null;
        this.mongoClient = null;
        this.redisClient = null;
        this.emailTransporter = null;
        this.s3Client = null;
        this.onboardingTemplates = new Map();
        
        this.initializeConnections();
        this.setupCronJobs();
    }

    async initializeConnections() {
        try {
            // Database connections
            this.masterPool = new Pool({
                connectionString: this.config.masterDbUrl,
                max: 20,
                idleTimeoutMillis: 30000,
            });

            this.mongoClient = new MongoClient(this.config.mongoUrl, {
                maxPoolSize: 50,
                serverSelectionTimeoutMS: 5000
            });
            await this.mongoClient.connect();

            this.redisClient = new Redis(this.config.redisUrl);

            // Email configuration
            this.emailTransporter = nodemailer.createTransporter(this.config.emailConfig);

            // S3 for backups
            this.s3Client = new AWS.S3(this.config.s3Config);

            // Initialize tenant management schema
            await this.initializeSchema();

            console.log('Tenant Manager initialized successfully');
        } catch (error) {
            console.error('Failed to initialize connections:', error);
            throw error;
        }
    }

    async initializeSchema() {
        const schema = `
            -- Tenant onboarding workflows
            CREATE TABLE IF NOT EXISTS tenant_onboarding (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                step VARCHAR(50) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'skipped')),
                data JSONB DEFAULT '{}',
                error_message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Billing and subscription management
            CREATE TABLE IF NOT EXISTS tenant_subscriptions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                plan VARCHAR(50) NOT NULL,
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled', 'trial')),
                billing_cycle VARCHAR(20) DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'yearly')),
                amount DECIMAL(10,2) NOT NULL,
                currency VARCHAR(3) DEFAULT 'USD',
                trial_ends_at TIMESTAMP WITH TIME ZONE,
                current_period_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                current_period_end TIMESTAMP WITH TIME ZONE,
                cancelled_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Billing invoices
            CREATE TABLE IF NOT EXISTS tenant_invoices (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                subscription_id UUID REFERENCES tenant_subscriptions(id),
                invoice_number VARCHAR(50) UNIQUE NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                tax_amount DECIMAL(10,2) DEFAULT 0,
                total_amount DECIMAL(10,2) NOT NULL,
                currency VARCHAR(3) DEFAULT 'USD',
                status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
                due_date DATE,
                paid_at TIMESTAMP WITH TIME ZONE,
                payment_method VARCHAR(50),
                payment_id VARCHAR(255),
                line_items JSONB DEFAULT '[]',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- White-labeling configurations
            CREATE TABLE IF NOT EXISTS tenant_branding (
                tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                company_name VARCHAR(200),
                logo_url TEXT,
                primary_color VARCHAR(7), -- Hex color
                secondary_color VARCHAR(7),
                favicon_url TEXT,
                custom_css TEXT,
                email_templates JSONB DEFAULT '{}',
                support_email VARCHAR(255),
                support_phone VARCHAR(50),
                custom_domain VARCHAR(255),
                ssl_certificate TEXT,
                ssl_private_key TEXT,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Backup configurations and history
            CREATE TABLE IF NOT EXISTS tenant_backups (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                backup_type VARCHAR(20) NOT NULL CHECK (backup_type IN ('full', 'incremental', 'manual')),
                status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
                file_size BIGINT,
                backup_location TEXT,
                checksum VARCHAR(255),
                retention_days INTEGER DEFAULT 30,
                expires_at TIMESTAMP WITH TIME ZONE,
                error_message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                completed_at TIMESTAMP WITH TIME ZONE
            );

            -- Notification preferences
            CREATE TABLE IF NOT EXISTS tenant_notifications (
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                notification_type VARCHAR(50) NOT NULL,
                enabled BOOLEAN DEFAULT true,
                delivery_method VARCHAR(20) DEFAULT 'email' CHECK (delivery_method IN ('email', 'webhook', 'sms')),
                endpoint TEXT, -- email address, webhook URL, or phone number
                settings JSONB DEFAULT '{}',
                PRIMARY KEY (tenant_id, notification_type)
            );

            -- Domain verification
            CREATE TABLE IF NOT EXISTS tenant_domains (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                domain VARCHAR(255) NOT NULL,
                verification_token VARCHAR(100),
                verification_status VARCHAR(20) DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'failed')),
                dns_records JSONB DEFAULT '[]',
                ssl_status VARCHAR(20) DEFAULT 'pending' CHECK (ssl_status IN ('pending', 'issued', 'expired', 'failed')),
                certificate_expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                verified_at TIMESTAMP WITH TIME ZONE
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_tenant_onboarding_tenant ON tenant_onboarding(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_tenant_subscriptions_tenant ON tenant_subscriptions(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_tenant_invoices_tenant ON tenant_invoices(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_tenant_backups_tenant ON tenant_backups(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_tenant_backups_expires ON tenant_backups(expires_at);
            CREATE INDEX IF NOT EXISTS idx_tenant_domains_domain ON tenant_domains(domain);
        `;

        await this.masterPool.query(schema);
    }

    // Tenant Onboarding Workflows
    async startOnboarding(tenantData, onboardingConfig = {}) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            // Create the tenant first via Multi-Tenant Core
            const tenant = await this.createTenantViaCoreService(tenantData);

            // Define onboarding steps
            const onboardingSteps = [
                'tenant_creation',
                'admin_user_setup',
                'initial_configuration',
                'sample_data_import',
                'welcome_email',
                'billing_setup'
            ];

            // Create onboarding workflow
            for (const step of onboardingSteps) {
                await client.query(`
                    INSERT INTO tenant_onboarding (tenant_id, step, status, data)
                    VALUES ($1, $2, $3, $4)
                `, [tenant.id, step, 'pending', JSON.stringify(onboardingConfig[step] || {})]);
            }

            // Start trial subscription
            await this.createTrialSubscription(client, tenant.id, onboardingConfig.plan || 'basic');

            // Setup default notifications
            await this.setupDefaultNotifications(client, tenant.id, onboardingConfig.adminEmail);

            await client.query('COMMIT');

            // Start asynchronous onboarding process
            this.processOnboardingSteps(tenant.id);

            return {
                tenant,
                onboardingId: tenant.id,
                status: 'started',
                nextSteps: onboardingSteps
            };

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async processOnboardingSteps(tenantId) {
        const steps = await this.masterPool.query(`
            SELECT * FROM tenant_onboarding 
            WHERE tenant_id = $1 AND status = 'pending'
            ORDER BY created_at
        `, [tenantId]);

        for (const step of steps.rows) {
            try {
                await this.executeOnboardingStep(tenantId, step);
                await this.updateOnboardingStep(step.id, 'completed');
            } catch (error) {
                console.error(`Onboarding step ${step.step} failed for tenant ${tenantId}:`, error);
                await this.updateOnboardingStep(step.id, 'failed', error.message);
            }
        }
    }

    async executeOnboardingStep(tenantId, step) {
        switch (step.step) {
            case 'tenant_creation':
                // Already completed during tenant creation
                break;

            case 'admin_user_setup':
                await this.createAdminUser(tenantId, step.data);
                break;

            case 'initial_configuration':
                await this.setupInitialConfiguration(tenantId, step.data);
                break;

            case 'sample_data_import':
                await this.importSampleData(tenantId, step.data);
                break;

            case 'welcome_email':
                await this.sendWelcomeEmail(tenantId, step.data);
                break;

            case 'billing_setup':
                await this.setupBillingConfiguration(tenantId, step.data);
                break;

            default:
                throw new Error(`Unknown onboarding step: ${step.step}`);
        }
    }

    async createAdminUser(tenantId, stepData) {
        // Create admin user via tenant-specific database
        const tenantDb = await this.getTenantDatabase(tenantId);
        
        await tenantDb.query(`
            INSERT INTO users (username, email, password_hash, first_name, last_name, roles, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            stepData.username || 'admin',
            stepData.email,
            await this.hashPassword(stepData.password || this.generatePassword()),
            stepData.firstName || 'Administrator',
            stepData.lastName || 'User',
            JSON.stringify(['admin', 'user']),
            'active'
        ]);
    }

    async setupInitialConfiguration(tenantId, stepData) {
        // Configure basic tenant settings
        await this.masterPool.query(`
            INSERT INTO tenant_configurations (tenant_id, config_key, config_value)
            VALUES 
                ($1, 'timezone', $2),
                ($1, 'date_format', $3),
                ($1, 'default_language', $4),
                ($1, 'password_policy', $5)
            ON CONFLICT (tenant_id, config_key) 
            DO UPDATE SET config_value = EXCLUDED.config_value
        `, [
            tenantId,
            JSON.stringify(stepData.timezone || 'UTC'),
            JSON.stringify(stepData.dateFormat || 'YYYY-MM-DD'),
            JSON.stringify(stepData.language || 'en'),
            JSON.stringify({
                minLength: 8,
                requireUppercase: true,
                requireNumbers: true,
                requireSymbols: false,
                maxAge: 90
            })
        ]);
    }

    async importSampleData(tenantId, stepData) {
        if (!stepData.includeSampleData) return;

        const tenantDb = await this.getTenantDatabase(tenantId);
        
        // Create sample policies
        await tenantDb.query(`
            INSERT INTO policies (name, description, policy_type, config, status)
            VALUES 
                ('Default Security Policy', 'Basic security requirements for all devices', 'security', $1, 'active'),
                ('BYOD Policy', 'Bring Your Own Device policy template', 'device', $2, 'active')
        `, [
            JSON.stringify({
                passwordRequired: true,
                encryptionRequired: true,
                autoLockTimeout: 300
            }),
            JSON.stringify({
                allowedAppCategories: ['productivity', 'business'],
                restrictedFeatures: ['camera', 'microphone']
            })
        ]);
    }

    async sendWelcomeEmail(tenantId, stepData) {
        const tenant = await this.getTenantById(tenantId);
        
        const emailContent = {
            to: stepData.email,
            subject: `Welcome to ${tenant.name} - Your OpenDirectory MDM is Ready!`,
            html: this.generateWelcomeEmailTemplate(tenant, stepData)
        };

        await this.emailTransporter.sendMail(emailContent);
    }

    // Billing Management
    async createTrialSubscription(client, tenantId, plan = 'basic') {
        const planConfig = this.config.billingPlans[plan];
        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + 14); // 14-day trial

        const periodEnd = new Date();
        periodEnd.setMonth(periodEnd.getMonth() + 1);

        await client.query(`
            INSERT INTO tenant_subscriptions (
                tenant_id, plan, status, billing_cycle, amount, currency,
                trial_ends_at, current_period_end
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            tenantId,
            plan,
            'trial',
            'monthly',
            planConfig.price,
            'USD',
            trialEnd,
            periodEnd
        ]);
    }

    async generateInvoice(tenantId, subscriptionId) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            const subscription = await client.query(
                'SELECT * FROM tenant_subscriptions WHERE id = $1',
                [subscriptionId]
            );

            if (subscription.rows.length === 0) {
                throw new Error('Subscription not found');
            }

            const sub = subscription.rows[0];
            const invoiceNumber = this.generateInvoiceNumber();

            const invoice = await client.query(`
                INSERT INTO tenant_invoices (
                    tenant_id, subscription_id, invoice_number, amount, total_amount,
                    currency, status, due_date, line_items
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *
            `, [
                tenantId,
                subscriptionId,
                invoiceNumber,
                sub.amount,
                sub.amount,
                sub.currency,
                'draft',
                new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
                JSON.stringify([{
                    description: `${this.config.billingPlans[sub.plan].name} - ${sub.billing_cycle}`,
                    quantity: 1,
                    unit_price: sub.amount,
                    total: sub.amount
                }])
            ]);

            await client.query('COMMIT');
            return invoice.rows[0];

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async processPayment(invoiceId, paymentData) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            // Simulate payment processing (integrate with Stripe, PayPal, etc.)
            const paymentResult = await this.processPaymentProvider(paymentData);

            if (paymentResult.success) {
                await client.query(`
                    UPDATE tenant_invoices 
                    SET status = 'paid', paid_at = NOW(), payment_method = $2, payment_id = $3
                    WHERE id = $1
                `, [invoiceId, paymentData.method, paymentResult.transactionId]);
            }

            await client.query('COMMIT');
            return paymentResult;

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    // White-labeling and Custom Domains
    async updateBranding(tenantId, brandingData) {
        await this.masterPool.query(`
            INSERT INTO tenant_branding (
                tenant_id, company_name, logo_url, primary_color, secondary_color,
                favicon_url, custom_css, support_email, support_phone, custom_domain
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id)
            DO UPDATE SET
                company_name = COALESCE($2, tenant_branding.company_name),
                logo_url = COALESCE($3, tenant_branding.logo_url),
                primary_color = COALESCE($4, tenant_branding.primary_color),
                secondary_color = COALESCE($5, tenant_branding.secondary_color),
                favicon_url = COALESCE($6, tenant_branding.favicon_url),
                custom_css = COALESCE($7, tenant_branding.custom_css),
                support_email = COALESCE($8, tenant_branding.support_email),
                support_phone = COALESCE($9, tenant_branding.support_phone),
                custom_domain = COALESCE($10, tenant_branding.custom_domain),
                updated_at = NOW()
        `, [
            tenantId,
            brandingData.companyName,
            brandingData.logoUrl,
            brandingData.primaryColor,
            brandingData.secondaryColor,
            brandingData.faviconUrl,
            brandingData.customCss,
            brandingData.supportEmail,
            brandingData.supportPhone,
            brandingData.customDomain
        ]);

        // Clear branding cache
        await this.redisClient.del(`branding:${tenantId}`);
    }

    async setupCustomDomain(tenantId, domain) {
        const verificationToken = crypto.randomBytes(32).toString('hex');

        await this.masterPool.query(`
            INSERT INTO tenant_domains (tenant_id, domain, verification_token, dns_records)
            VALUES ($1, $2, $3, $4)
        `, [
            tenantId,
            domain,
            verificationToken,
            JSON.stringify([
                {
                    type: 'TXT',
                    name: `_opendirectory-verify.${domain}`,
                    value: verificationToken
                },
                {
                    type: 'CNAME',
                    name: domain,
                    value: 'mdm.opendirectory.io'
                }
            ])
        ]);

        return {
            verificationToken,
            dnsRecords: [
                {
                    type: 'TXT',
                    name: `_opendirectory-verify.${domain}`,
                    value: verificationToken
                },
                {
                    type: 'CNAME', 
                    name: domain,
                    value: 'mdm.opendirectory.io'
                }
            ]
        };
    }

    // Backup and Restore
    async createBackup(tenantId, backupType = 'manual') {
        const backupId = crypto.randomBytes(16).toString('hex');
        
        const backup = await this.masterPool.query(`
            INSERT INTO tenant_backups (tenant_id, backup_type, status, backup_location)
            VALUES ($1, $2, $3, $4)
            RETURNING *
        `, [tenantId, backupType, 'pending', `s3://${this.config.s3Config.bucket}/backups/${tenantId}/${backupId}.tar.gz`]);

        // Start backup process asynchronously
        this.processBackup(backup.rows[0]);

        return backup.rows[0];
    }

    async processBackup(backup) {
        try {
            await this.masterPool.query(
                'UPDATE tenant_backups SET status = $2 WHERE id = $1',
                [backup.id, 'running']
            );

            // Export tenant data
            const tenantData = await this.exportTenantData(backup.tenant_id);
            
            // Compress and upload to S3
            const backupBuffer = await this.compressTenantData(tenantData);
            const uploadResult = await this.uploadBackupToS3(backup.backup_location, backupBuffer);

            // Calculate expiration date
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + backup.retention_days);

            await this.masterPool.query(`
                UPDATE tenant_backups 
                SET status = 'completed', file_size = $2, checksum = $3, 
                    expires_at = $4, completed_at = NOW()
                WHERE id = $1
            `, [
                backup.id,
                uploadResult.size,
                uploadResult.checksum,
                expiresAt
            ]);

        } catch (error) {
            console.error(`Backup failed for tenant ${backup.tenant_id}:`, error);
            await this.masterPool.query(
                'UPDATE tenant_backups SET status = $2, error_message = $3 WHERE id = $1',
                [backup.id, 'failed', error.message]
            );
        }
    }

    async restoreBackup(tenantId, backupId) {
        const backup = await this.masterPool.query(
            'SELECT * FROM tenant_backups WHERE id = $1 AND tenant_id = $2',
            [backupId, tenantId]
        );

        if (backup.rows.length === 0) {
            throw new Error('Backup not found');
        }

        // Download backup from S3
        const backupData = await this.downloadBackupFromS3(backup.rows[0].backup_location);
        
        // Decompress and restore
        const tenantData = await this.decompressTenantData(backupData);
        await this.importTenantData(tenantId, tenantData);

        return { success: true, restoredAt: new Date().toISOString() };
    }

    // Cron Jobs
    setupCronJobs() {
        // Daily backup job
        cron.schedule('0 2 * * *', () => {
            this.runDailyBackups();
        });

        // Monthly billing job
        cron.schedule('0 0 1 * *', () => {
            this.processMonthlyBilling();
        });

        // Trial expiration check
        cron.schedule('0 */6 * * *', () => {
            this.checkTrialExpirations();
        });

        // Cleanup expired backups
        cron.schedule('0 3 * * 0', () => {
            this.cleanupExpiredBackups();
        });
    }

    async runDailyBackups() {
        const tenants = await this.masterPool.query(`
            SELECT t.id FROM tenants t
            JOIN tenant_subscriptions ts ON t.id = ts.tenant_id
            WHERE t.status = 'active' AND ts.status IN ('active', 'trial')
        `);

        for (const tenant of tenants.rows) {
            try {
                await this.createBackup(tenant.id, 'full');
            } catch (error) {
                console.error(`Failed to create backup for tenant ${tenant.id}:`, error);
            }
        }
    }

    async processMonthlyBilling() {
        const subscriptions = await this.masterPool.query(`
            SELECT * FROM tenant_subscriptions 
            WHERE status = 'active' AND current_period_end <= NOW()
        `);

        for (const subscription of subscriptions.rows) {
            try {
                await this.generateInvoice(subscription.tenant_id, subscription.id);
            } catch (error) {
                console.error(`Failed to generate invoice for subscription ${subscription.id}:`, error);
            }
        }
    }

    // Utility Methods
    async getTenantDatabase(tenantId) {
        // Get tenant-specific database connection
        const dbConfig = await this.masterPool.query(
            'SELECT connection_string FROM tenant_databases WHERE tenant_id = $1 AND db_type = $2',
            [tenantId, 'postgresql']
        );

        if (dbConfig.rows.length === 0) {
            throw new Error(`No database configuration found for tenant ${tenantId}`);
        }

        return new Pool({ connectionString: dbConfig.rows[0].connection_string, max: 5 });
    }

    async getTenantById(tenantId) {
        const result = await this.masterPool.query(
            'SELECT * FROM tenants WHERE id = $1',
            [tenantId]
        );
        return result.rows.length > 0 ? result.rows[0] : null;
    }

    generateInvoiceNumber() {
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2);
        return `INV-${timestamp}-${random}`.toUpperCase();
    }

    generatePassword(length = 12) {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }

    async hashPassword(password) {
        return await require('bcryptjs').hash(password, 12);
    }

    generateWelcomeEmailTemplate(tenant, stepData) {
        return `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h1 style="color: #333;">Welcome to ${tenant.name}!</h1>
                <p>Your OpenDirectory MDM instance has been successfully created and configured.</p>
                
                <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <h3>Getting Started:</h3>
                    <ol>
                        <li>Log in to your admin portal: <a href="https://${tenant.domain || 'your-domain'}.opendirectory.io">Admin Portal</a></li>
                        <li>Complete your profile setup</li>
                        <li>Import your users and devices</li>
                        <li>Configure your first policies</li>
                    </ol>
                </div>
                
                <p><strong>Admin Credentials:</strong><br>
                Username: ${stepData.username || 'admin'}<br>
                Email: ${stepData.email}</p>
                
                <p>If you need help getting started, check out our <a href="https://docs.opendirectory.io">documentation</a> or contact our support team.</p>
                
                <p>Best regards,<br>The OpenDirectory Team</p>
            </div>
        `;
    }

    // Mock methods for external integrations
    async createTenantViaCoreService(tenantData) {
        // In real implementation, this would call the Multi-Tenant Core API
        return {
            id: crypto.randomBytes(16).toString('hex'),
            slug: tenantData.slug,
            name: tenantData.name,
            domain: tenantData.domain,
            status: 'active'
        };
    }

    async processPaymentProvider(paymentData) {
        // Mock payment processing - integrate with actual payment provider
        return {
            success: true,
            transactionId: `tx_${crypto.randomBytes(8).toString('hex')}`
        };
    }

    async exportTenantData(tenantId) {
        // Export all tenant data for backup
        return {
            tenantInfo: await this.getTenantById(tenantId),
            timestamp: new Date().toISOString()
        };
    }

    async compressTenantData(data) {
        // Compress tenant data for storage
        return Buffer.from(JSON.stringify(data), 'utf8');
    }

    async uploadBackupToS3(location, buffer) {
        // Upload backup to S3
        return {
            size: buffer.length,
            checksum: crypto.createHash('sha256').update(buffer).digest('hex')
        };
    }

    async downloadBackupFromS3(location) {
        // Download backup from S3
        return Buffer.from('{}', 'utf8');
    }

    async decompressTenantData(buffer) {
        // Decompress backup data
        return JSON.parse(buffer.toString('utf8'));
    }

    async importTenantData(tenantId, data) {
        // Import tenant data from backup
        console.log(`Restoring tenant ${tenantId} data`);
    }

    // REST API
    setupRestAPI() {
        const app = express();

        app.use(helmet());
        app.use(cors({ origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'] }));
        app.use(rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 500
        }));
        app.use(express.json());

        // Health check
        app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'tenant-manager'
            });
        });

        // Onboarding endpoints
        app.post('/api/onboarding', async (req, res) => {
            try {
                const result = await this.startOnboarding(req.body.tenant, req.body.config);
                res.status(201).json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.get('/api/onboarding/:tenantId', async (req, res) => {
            try {
                const steps = await this.masterPool.query(
                    'SELECT * FROM tenant_onboarding WHERE tenant_id = $1 ORDER BY created_at',
                    [req.params.tenantId]
                );
                res.json({ steps: steps.rows });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Billing endpoints
        app.post('/api/tenants/:tenantId/invoices', async (req, res) => {
            try {
                const invoice = await this.generateInvoice(req.params.tenantId, req.body.subscriptionId);
                res.status(201).json(invoice);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.post('/api/invoices/:invoiceId/payments', async (req, res) => {
            try {
                const result = await this.processPayment(req.params.invoiceId, req.body);
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Branding endpoints
        app.put('/api/tenants/:tenantId/branding', async (req, res) => {
            try {
                await this.updateBranding(req.params.tenantId, req.body);
                res.json({ success: true });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Domain management
        app.post('/api/tenants/:tenantId/domains', async (req, res) => {
            try {
                const result = await this.setupCustomDomain(req.params.tenantId, req.body.domain);
                res.status(201).json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Backup endpoints
        app.post('/api/tenants/:tenantId/backups', async (req, res) => {
            try {
                const backup = await this.createBackup(req.params.tenantId, req.body.type);
                res.status(201).json(backup);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.post('/api/tenants/:tenantId/restore/:backupId', async (req, res) => {
            try {
                const result = await this.restoreBackup(req.params.tenantId, req.params.backupId);
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
            console.log(`Tenant Manager started on port ${this.config.port}`);
            console.log('Available endpoints:');
            console.log('  POST /api/onboarding - Start tenant onboarding');
            console.log('  GET /api/onboarding/:tenantId - Get onboarding status');
            console.log('  POST /api/tenants/:tenantId/invoices - Generate invoice');
            console.log('  POST /api/invoices/:invoiceId/payments - Process payment');
            console.log('  PUT /api/tenants/:tenantId/branding - Update branding');
            console.log('  POST /api/tenants/:tenantId/domains - Setup custom domain');
            console.log('  POST /api/tenants/:tenantId/backups - Create backup');
            console.log('  POST /api/tenants/:tenantId/restore/:backupId - Restore backup');
        });

        return server;
    }

    async setupDefaultNotifications(client, tenantId, email) {
        const notifications = [
            'billing_invoice_created',
            'billing_payment_failed',
            'security_alert',
            'system_maintenance',
            'quota_warning'
        ];

        for (const notificationType of notifications) {
            await client.query(`
                INSERT INTO tenant_notifications (tenant_id, notification_type, endpoint)
                VALUES ($1, $2, $3)
            `, [tenantId, notificationType, email]);
        }
    }

    async updateOnboardingStep(stepId, status, errorMessage = null) {
        await this.masterPool.query(`
            UPDATE tenant_onboarding 
            SET status = $2, error_message = $3, updated_at = NOW()
            WHERE id = $1
        `, [stepId, status, errorMessage]);
    }

    async setupBillingConfiguration(tenantId, stepData) {
        // Setup billing configuration for tenant
        console.log(`Setting up billing for tenant ${tenantId}`);
    }

    async checkTrialExpirations() {
        const expiredTrials = await this.masterPool.query(`
            SELECT * FROM tenant_subscriptions 
            WHERE status = 'trial' AND trial_ends_at <= NOW()
        `);

        for (const subscription of expiredTrials.rows) {
            // Convert trial to paid or suspend
            await this.handleTrialExpiration(subscription);
        }
    }

    async handleTrialExpiration(subscription) {
        // Handle trial expiration logic
        console.log(`Trial expired for tenant ${subscription.tenant_id}`);
    }

    async cleanupExpiredBackups() {
        const expiredBackups = await this.masterPool.query(`
            DELETE FROM tenant_backups 
            WHERE expires_at <= NOW() AND status = 'completed'
            RETURNING backup_location
        `);

        for (const backup of expiredBackups.rows) {
            // Delete backup files from S3
            console.log(`Cleaning up backup: ${backup.backup_location}`);
        }
    }
}

module.exports = TenantManager;

if (require.main === module) {
    const config = {
        port: process.env.PORT || 3101,
        masterDbUrl: process.env.MASTER_DB_URL || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
        mongoUrl: process.env.MONGO_URL || 'mongodb://opendirectory:changeme@localhost:27017',
        redisUrl: process.env.REDIS_URL || 'redis://:changeme@localhost:6379'
    };

    const manager = new TenantManager(config);
    manager.start().catch(error => {
        console.error('Failed to start Tenant Manager:', error);
        process.exit(1);
    });
}