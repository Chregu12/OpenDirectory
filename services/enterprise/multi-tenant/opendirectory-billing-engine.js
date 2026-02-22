#!/usr/bin/env node

/**
 * OpenDirectory Usage & Billing Engine
 * 
 * Comprehensive billing system providing:
 * - Usage metering and tracking
 * - Billing calculation engine
 * - Invoice generation
 * - Payment integration
 * - Usage analytics per tenant
 * - Cost allocation
 * - Subscription management
 * - Usage limits enforcement
 * 
 * Supports multiple billing models and payment providers
 */

const express = require('express');
const { Pool } = require('pg');
const Redis = require('ioredis');
const crypto = require('crypto');
const cron = require('node-cron');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');
const Stripe = require('stripe');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

class BillingEngine {
    constructor(config = {}) {
        this.config = {
            port: config.port || 3103,
            masterDbUrl: config.masterDbUrl || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
            redisUrl: config.redisUrl || 'redis://:changeme@localhost:6379',
            stripeSecretKey: config.stripeSecretKey || process.env.STRIPE_SECRET_KEY,
            paypalConfig: {
                clientId: config.paypalClientId || process.env.PAYPAL_CLIENT_ID,
                clientSecret: config.paypalClientSecret || process.env.PAYPAL_CLIENT_SECRET,
                sandbox: config.paypalSandbox !== false
            },
            emailConfig: {
                host: config.emailHost || 'smtp.gmail.com',
                port: 587,
                auth: {
                    user: config.emailUser || process.env.EMAIL_USER,
                    pass: config.emailPass || process.env.EMAIL_PASS
                }
            },
            billingModels: {
                subscription: {
                    basic: { monthly: 29.99, yearly: 299.99 },
                    professional: { monthly: 99.99, yearly: 999.99 },
                    enterprise: { monthly: 299.99, yearly: 2999.99 }
                },
                usage: {
                    users: 0.50,     // per user per month
                    devices: 0.25,   // per device per month
                    apiCalls: 0.001, // per 1000 API calls
                    storage: 0.10    // per GB per month
                },
                overage: {
                    users: 0.75,     // per user over quota
                    devices: 0.35,   // per device over quota
                    storage: 0.15    // per GB over quota
                }
            },
            currency: 'USD',
            taxRates: {
                default: 0.08,   // 8% default tax rate
                EU: 0.20,        // 20% VAT for EU
                US: {
                    CA: 0.0825,   // California
                    NY: 0.08,     // New York
                    TX: 0.0625    // Texas
                }
            },
            ...config
        };

        this.masterPool = null;
        this.redisClient = null;
        this.stripe = null;
        this.emailTransporter = null;
        this.usageCollectors = new Map();
        
        this.initializeConnections();
        this.setupCronJobs();
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

            // Initialize Stripe
            if (this.config.stripeSecretKey) {
                this.stripe = new Stripe(this.config.stripeSecretKey);
            }

            // Initialize email
            this.emailTransporter = nodemailer.createTransporter(this.config.emailConfig);

            await this.initializeSchema();
            console.log('Billing Engine initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Billing Engine:', error);
            throw error;
        }
    }

    async initializeSchema() {
        const schema = `
            -- Usage metering and tracking
            CREATE TABLE IF NOT EXISTS usage_metrics (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                metric_type VARCHAR(50) NOT NULL, -- 'users', 'devices', 'api_calls', 'storage', etc.
                metric_value DECIMAL(15,4) NOT NULL,
                unit VARCHAR(20) NOT NULL, -- 'count', 'bytes', 'calls', etc.
                recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                period_start TIMESTAMP WITH TIME ZONE NOT NULL,
                period_end TIMESTAMP WITH TIME ZONE NOT NULL,
                metadata JSONB DEFAULT '{}',
                aggregation_level VARCHAR(20) DEFAULT 'hourly' CHECK (aggregation_level IN ('hourly', 'daily', 'monthly'))
            );

            -- Billing calculations and line items
            CREATE TABLE IF NOT EXISTS billing_line_items (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                invoice_id UUID,
                item_type VARCHAR(50) NOT NULL, -- 'subscription', 'usage', 'overage', 'addon', 'credit'
                description TEXT NOT NULL,
                quantity DECIMAL(10,4) NOT NULL DEFAULT 1,
                unit_price DECIMAL(10,4) NOT NULL,
                total_amount DECIMAL(10,2) NOT NULL,
                tax_amount DECIMAL(10,2) DEFAULT 0,
                discount_amount DECIMAL(10,2) DEFAULT 0,
                period_start TIMESTAMP WITH TIME ZONE,
                period_end TIMESTAMP WITH TIME ZONE,
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Enhanced invoice management
            CREATE TABLE IF NOT EXISTS billing_invoices (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                invoice_number VARCHAR(50) UNIQUE NOT NULL,
                status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'pending', 'sent', 'paid', 'overdue', 'cancelled', 'refunded')),
                subtotal DECIMAL(10,2) NOT NULL DEFAULT 0,
                tax_amount DECIMAL(10,2) DEFAULT 0,
                discount_amount DECIMAL(10,2) DEFAULT 0,
                total_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                currency VARCHAR(3) DEFAULT 'USD',
                billing_period_start TIMESTAMP WITH TIME ZONE,
                billing_period_end TIMESTAMP WITH TIME ZONE,
                due_date DATE,
                payment_terms INTEGER DEFAULT 30, -- days
                sent_at TIMESTAMP WITH TIME ZONE,
                paid_at TIMESTAMP WITH TIME ZONE,
                payment_method VARCHAR(50),
                payment_reference VARCHAR(255),
                notes TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Payment processing and tracking
            CREATE TABLE IF NOT EXISTS payment_transactions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                invoice_id UUID REFERENCES billing_invoices(id),
                transaction_id VARCHAR(255) UNIQUE NOT NULL,
                payment_provider VARCHAR(50) NOT NULL, -- 'stripe', 'paypal', 'bank_transfer', etc.
                payment_method VARCHAR(50), -- 'card', 'bank_account', 'paypal', etc.
                amount DECIMAL(10,2) NOT NULL,
                currency VARCHAR(3) DEFAULT 'USD',
                status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled', 'refunded')),
                provider_response JSONB,
                fees DECIMAL(10,2) DEFAULT 0,
                net_amount DECIMAL(10,2),
                processed_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Subscription management
            CREATE TABLE IF NOT EXISTS billing_subscriptions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                plan_id VARCHAR(50) NOT NULL,
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('trial', 'active', 'paused', 'cancelled', 'expired')),
                billing_cycle VARCHAR(20) DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'yearly')),
                base_price DECIMAL(10,2) NOT NULL,
                currency VARCHAR(3) DEFAULT 'USD',
                trial_ends_at TIMESTAMP WITH TIME ZONE,
                current_period_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                current_period_end TIMESTAMP WITH TIME ZONE,
                cancelled_at TIMESTAMP WITH TIME ZONE,
                cancel_at_period_end BOOLEAN DEFAULT false,
                payment_provider VARCHAR(50),
                provider_subscription_id VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Usage quotas and limits
            CREATE TABLE IF NOT EXISTS usage_quotas (
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                quota_type VARCHAR(50) NOT NULL,
                quota_limit DECIMAL(15,4) NOT NULL,
                current_usage DECIMAL(15,4) DEFAULT 0,
                reset_cycle VARCHAR(20) DEFAULT 'monthly' CHECK (reset_cycle IN ('daily', 'weekly', 'monthly', 'yearly')),
                last_reset TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                overage_allowed BOOLEAN DEFAULT true,
                overage_rate DECIMAL(10,4) DEFAULT 0,
                alert_threshold DECIMAL(4,2) DEFAULT 0.80, -- Alert at 80% usage
                PRIMARY KEY (tenant_id, quota_type)
            );

            -- Cost allocation and reporting
            CREATE TABLE IF NOT EXISTS cost_allocations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                allocation_period TIMESTAMP WITH TIME ZONE NOT NULL,
                cost_center VARCHAR(100),
                department VARCHAR(100),
                project VARCHAR(100),
                allocation_method VARCHAR(50) NOT NULL, -- 'usage_based', 'equal_split', 'weighted', 'fixed'
                total_cost DECIMAL(10,2) NOT NULL,
                allocated_costs JSONB NOT NULL, -- breakdown by resource/service
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Payment methods and billing profiles
            CREATE TABLE IF NOT EXISTS tenant_payment_methods (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                method_type VARCHAR(50) NOT NULL, -- 'card', 'bank_account', 'paypal'
                provider VARCHAR(50) NOT NULL,
                provider_payment_method_id VARCHAR(255) NOT NULL,
                is_default BOOLEAN DEFAULT false,
                last_four VARCHAR(4),
                expiry_month INTEGER,
                expiry_year INTEGER,
                brand VARCHAR(50),
                country VARCHAR(2),
                status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'inactive')),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Billing alerts and notifications
            CREATE TABLE IF NOT EXISTS billing_alerts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                alert_type VARCHAR(50) NOT NULL, -- 'quota_exceeded', 'payment_failed', 'trial_expiring'
                severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                title VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                metadata JSONB DEFAULT '{}',
                acknowledged BOOLEAN DEFAULT false,
                acknowledged_by UUID,
                acknowledged_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_usage_metrics_tenant_period ON usage_metrics(tenant_id, period_start, period_end);
            CREATE INDEX IF NOT EXISTS idx_usage_metrics_type_period ON usage_metrics(metric_type, period_start);
            CREATE INDEX IF NOT EXISTS idx_billing_line_items_tenant ON billing_line_items(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_billing_line_items_invoice ON billing_line_items(invoice_id);
            CREATE INDEX IF NOT EXISTS idx_billing_invoices_tenant ON billing_invoices(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_billing_invoices_status ON billing_invoices(status);
            CREATE INDEX IF NOT EXISTS idx_billing_invoices_due_date ON billing_invoices(due_date);
            CREATE INDEX IF NOT EXISTS idx_payment_transactions_tenant ON payment_transactions(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_payment_transactions_invoice ON payment_transactions(invoice_id);
            CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_tenant ON billing_subscriptions(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_usage_quotas_tenant ON usage_quotas(tenant_id);
        `;

        await this.masterPool.query(schema);
    }

    // Usage Metering and Tracking
    async recordUsage(tenantId, metricType, value, unit = 'count', metadata = {}) {
        const now = new Date();
        const hourStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours());
        const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000);

        await this.masterPool.query(`
            INSERT INTO usage_metrics (
                tenant_id, metric_type, metric_value, unit, 
                period_start, period_end, metadata, aggregation_level
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            tenantId, metricType, value, unit,
            hourStart, hourEnd, JSON.stringify(metadata), 'hourly'
        ]);

        // Update real-time quota tracking
        await this.updateQuotaUsage(tenantId, metricType, value);

        // Check for quota violations
        await this.checkQuotaViolations(tenantId, metricType);
    }

    async updateQuotaUsage(tenantId, quotaType, increment) {
        await this.masterPool.query(`
            INSERT INTO usage_quotas (tenant_id, quota_type, current_usage, quota_limit)
            VALUES ($1, $2, $3, 0)
            ON CONFLICT (tenant_id, quota_type)
            DO UPDATE SET 
                current_usage = usage_quotas.current_usage + $3,
                last_reset = CASE 
                    WHEN usage_quotas.reset_cycle = 'daily' AND date_trunc('day', NOW()) > date_trunc('day', usage_quotas.last_reset) 
                    THEN NOW()
                    WHEN usage_quotas.reset_cycle = 'monthly' AND date_trunc('month', NOW()) > date_trunc('month', usage_quotas.last_reset)
                    THEN NOW()
                    ELSE usage_quotas.last_reset
                END,
                current_usage = CASE 
                    WHEN usage_quotas.reset_cycle = 'daily' AND date_trunc('day', NOW()) > date_trunc('day', usage_quotas.last_reset) 
                    THEN $3
                    WHEN usage_quotas.reset_cycle = 'monthly' AND date_trunc('month', NOW()) > date_trunc('month', usage_quotas.last_reset)
                    THEN $3
                    ELSE usage_quotas.current_usage + $3
                END
        `, [tenantId, quotaType, increment]);
    }

    async checkQuotaViolations(tenantId, quotaType) {
        const quota = await this.masterPool.query(`
            SELECT * FROM usage_quotas 
            WHERE tenant_id = $1 AND quota_type = $2
        `, [tenantId, quotaType]);

        if (quota.rows.length === 0) return;

        const quotaData = quota.rows[0];
        const usagePercentage = quotaData.current_usage / quotaData.quota_limit;

        // Alert at threshold (default 80%)
        if (usagePercentage >= quotaData.alert_threshold && usagePercentage < 1.0) {
            await this.createBillingAlert(tenantId, 'quota_warning', {
                quotaType,
                usagePercentage: Math.round(usagePercentage * 100),
                currentUsage: quotaData.current_usage,
                quotaLimit: quotaData.quota_limit
            });
        }

        // Alert when quota exceeded
        if (usagePercentage >= 1.0) {
            await this.createBillingAlert(tenantId, 'quota_exceeded', {
                quotaType,
                currentUsage: quotaData.current_usage,
                quotaLimit: quotaData.quota_limit,
                overage: quotaData.current_usage - quotaData.quota_limit
            });

            // Calculate overage charges if applicable
            if (quotaData.overage_allowed && quotaData.overage_rate > 0) {
                const overageAmount = quotaData.current_usage - quotaData.quota_limit;
                await this.recordOverageCharge(tenantId, quotaType, overageAmount, quotaData.overage_rate);
            }
        }
    }

    async recordOverageCharge(tenantId, quotaType, overageAmount, rate) {
        const totalCharge = overageAmount * rate;
        
        await this.masterPool.query(`
            INSERT INTO billing_line_items (
                tenant_id, item_type, description, quantity, 
                unit_price, total_amount, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            tenantId,
            'overage',
            `${quotaType.toUpperCase()} overage charges`,
            overageAmount,
            rate,
            totalCharge,
            JSON.stringify({ quota_type: quotaType, overage_amount: overageAmount })
        ]);
    }

    // Billing Calculation Engine
    async calculateMonthlyBill(tenantId, billingPeriodStart, billingPeriodEnd) {
        const client = await this.masterPool.connect();
        
        try {
            await client.query('BEGIN');

            // Get subscription charges
            const subscriptionCharges = await this.calculateSubscriptionCharges(
                client, tenantId, billingPeriodStart, billingPeriodEnd
            );

            // Get usage-based charges
            const usageCharges = await this.calculateUsageCharges(
                client, tenantId, billingPeriodStart, billingPeriodEnd
            );

            // Get overage charges
            const overageCharges = await this.calculateOverageCharges(
                client, tenantId, billingPeriodStart, billingPeriodEnd
            );

            // Calculate totals
            const subtotal = subscriptionCharges + usageCharges + overageCharges;
            const taxAmount = await this.calculateTax(tenantId, subtotal);
            const total = subtotal + taxAmount;

            // Create invoice
            const invoiceNumber = await this.generateInvoiceNumber();
            const invoice = await client.query(`
                INSERT INTO billing_invoices (
                    tenant_id, invoice_number, subtotal, tax_amount, total_amount,
                    billing_period_start, billing_period_end, due_date, status
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *
            `, [
                tenantId, invoiceNumber, subtotal, taxAmount, total,
                billingPeriodStart, billingPeriodEnd,
                new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
                'draft'
            ]);

            // Move line items to invoice
            await client.query(`
                UPDATE billing_line_items 
                SET invoice_id = $2
                WHERE tenant_id = $1 AND invoice_id IS NULL 
                AND created_at >= $3 AND created_at <= $4
            `, [tenantId, invoice.rows[0].id, billingPeriodStart, billingPeriodEnd]);

            await client.query('COMMIT');
            return invoice.rows[0];

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async calculateSubscriptionCharges(client, tenantId, periodStart, periodEnd) {
        const subscription = await client.query(`
            SELECT * FROM billing_subscriptions 
            WHERE tenant_id = $1 AND status = 'active'
        `, [tenantId]);

        if (subscription.rows.length === 0) return 0;

        const sub = subscription.rows[0];
        
        // Calculate prorated amount based on billing cycle
        const cycleDays = sub.billing_cycle === 'monthly' ? 30 : 365;
        const periodDays = Math.ceil((periodEnd - periodStart) / (24 * 60 * 60 * 1000));
        const proratedAmount = (sub.base_price * periodDays) / cycleDays;

        // Add subscription line item
        await client.query(`
            INSERT INTO billing_line_items (
                tenant_id, item_type, description, quantity, 
                unit_price, total_amount, period_start, period_end
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            tenantId,
            'subscription',
            `${sub.plan_id} plan - ${sub.billing_cycle}`,
            1,
            proratedAmount,
            proratedAmount,
            periodStart,
            periodEnd
        ]);

        return proratedAmount;
    }

    async calculateUsageCharges(client, tenantId, periodStart, periodEnd) {
        const usageMetrics = await client.query(`
            SELECT metric_type, SUM(metric_value) as total_usage
            FROM usage_metrics 
            WHERE tenant_id = $1 AND period_start >= $2 AND period_end <= $3
            AND metric_type IN ('users', 'devices', 'api_calls', 'storage')
            GROUP BY metric_type
        `, [tenantId, periodStart, periodEnd]);

        let totalUsageCharges = 0;

        for (const metric of usageMetrics.rows) {
            const rate = this.config.billingModels.usage[metric.metric_type] || 0;
            const charge = metric.total_usage * rate;

            await client.query(`
                INSERT INTO billing_line_items (
                    tenant_id, item_type, description, quantity, 
                    unit_price, total_amount, period_start, period_end
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `, [
                tenantId,
                'usage',
                `${metric.metric_type.toUpperCase()} usage`,
                metric.total_usage,
                rate,
                charge,
                periodStart,
                periodEnd
            ]);

            totalUsageCharges += charge;
        }

        return totalUsageCharges;
    }

    async calculateOverageCharges(client, tenantId, periodStart, periodEnd) {
        const overageItems = await client.query(`
            SELECT SUM(total_amount) as total_overage
            FROM billing_line_items 
            WHERE tenant_id = $1 AND item_type = 'overage'
            AND created_at >= $2 AND created_at <= $3
        `, [tenantId, periodStart, periodEnd]);

        return overageItems.rows[0]?.total_overage || 0;
    }

    async calculateTax(tenantId, subtotal) {
        // Get tenant billing address/region for tax calculation
        const tenant = await this.masterPool.query(
            'SELECT settings FROM tenants WHERE id = $1',
            [tenantId]
        );

        if (tenant.rows.length === 0) return 0;

        const settings = tenant.rows[0].settings || {};
        const region = settings.billing_region || 'default';
        
        let taxRate = this.config.taxRates.default;
        if (this.config.taxRates[region]) {
            if (typeof this.config.taxRates[region] === 'number') {
                taxRate = this.config.taxRates[region];
            } else if (settings.billing_state && this.config.taxRates[region][settings.billing_state]) {
                taxRate = this.config.taxRates[region][settings.billing_state];
            }
        }

        return Math.round(subtotal * taxRate * 100) / 100;
    }

    // Invoice Management
    async generateInvoice(tenantId, billingPeriod = 'monthly') {
        const now = new Date();
        let periodStart, periodEnd;

        if (billingPeriod === 'monthly') {
            periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
            periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);
        } else {
            periodStart = new Date(now.getFullYear(), 0, 1);
            periodEnd = new Date(now.getFullYear(), 11, 31, 23, 59, 59);
        }

        return await this.calculateMonthlyBill(tenantId, periodStart, periodEnd);
    }

    async generateInvoicePDF(invoiceId) {
        const invoice = await this.getInvoiceDetails(invoiceId);
        const doc = new PDFDocument({ margin: 50 });

        // Header
        doc.fontSize(20).text('INVOICE', 50, 50);
        doc.fontSize(12).text(`Invoice #: ${invoice.invoice_number}`, 50, 80);
        doc.text(`Date: ${invoice.created_at.toDateString()}`, 50, 95);
        doc.text(`Due Date: ${invoice.due_date}`, 50, 110);

        // Tenant information
        doc.text(`Bill To: ${invoice.tenant_name}`, 50, 140);
        
        // Line items
        let yPosition = 180;
        doc.text('Description', 50, yPosition);
        doc.text('Quantity', 200, yPosition);
        doc.text('Unit Price', 300, yPosition);
        doc.text('Total', 400, yPosition);
        
        yPosition += 20;
        for (const item of invoice.line_items) {
            doc.text(item.description, 50, yPosition);
            doc.text(item.quantity.toString(), 200, yPosition);
            doc.text(`$${item.unit_price.toFixed(2)}`, 300, yPosition);
            doc.text(`$${item.total_amount.toFixed(2)}`, 400, yPosition);
            yPosition += 20;
        }

        // Totals
        yPosition += 20;
        doc.text(`Subtotal: $${invoice.subtotal.toFixed(2)}`, 300, yPosition);
        yPosition += 15;
        doc.text(`Tax: $${invoice.tax_amount.toFixed(2)}`, 300, yPosition);
        yPosition += 15;
        doc.fontSize(14).text(`Total: $${invoice.total_amount.toFixed(2)}`, 300, yPosition);

        doc.end();
        return doc;
    }

    async getInvoiceDetails(invoiceId) {
        const invoice = await this.masterPool.query(`
            SELECT i.*, t.name as tenant_name
            FROM billing_invoices i
            JOIN tenants t ON i.tenant_id = t.id
            WHERE i.id = $1
        `, [invoiceId]);

        if (invoice.rows.length === 0) {
            throw new Error('Invoice not found');
        }

        const lineItems = await this.masterPool.query(
            'SELECT * FROM billing_line_items WHERE invoice_id = $1',
            [invoiceId]
        );

        return {
            ...invoice.rows[0],
            line_items: lineItems.rows
        };
    }

    async sendInvoiceEmail(invoiceId) {
        const invoice = await this.getInvoiceDetails(invoiceId);
        
        // Get tenant contact email
        const tenant = await this.masterPool.query(
            'SELECT settings FROM tenants WHERE id = $1',
            [invoice.tenant_id]
        );

        const settings = tenant.rows[0]?.settings || {};
        const billingEmail = settings.billing_email || settings.contact_email;

        if (!billingEmail) {
            throw new Error('No billing email configured for tenant');
        }

        const pdfBuffer = await this.generateInvoicePDF(invoiceId);

        const emailContent = {
            to: billingEmail,
            subject: `Invoice ${invoice.invoice_number} from OpenDirectory`,
            html: this.generateInvoiceEmailTemplate(invoice),
            attachments: [{
                filename: `invoice-${invoice.invoice_number}.pdf`,
                content: pdfBuffer
            }]
        };

        await this.emailTransporter.sendMail(emailContent);

        // Update invoice status
        await this.masterPool.query(
            'UPDATE billing_invoices SET status = $2, sent_at = NOW() WHERE id = $1',
            [invoiceId, 'sent']
        );
    }

    // Payment Processing
    async processPayment(invoiceId, paymentMethod, provider = 'stripe') {
        const invoice = await this.getInvoiceDetails(invoiceId);
        
        if (invoice.status !== 'sent' && invoice.status !== 'pending') {
            throw new Error('Invoice cannot be paid in current status');
        }

        try {
            let paymentResult;

            if (provider === 'stripe') {
                paymentResult = await this.processStripePayment(invoice, paymentMethod);
            } else if (provider === 'paypal') {
                paymentResult = await this.processPayPalPayment(invoice, paymentMethod);
            } else {
                throw new Error(`Unsupported payment provider: ${provider}`);
            }

            // Record payment transaction
            const transaction = await this.masterPool.query(`
                INSERT INTO payment_transactions (
                    tenant_id, invoice_id, transaction_id, payment_provider,
                    payment_method, amount, currency, status, provider_response,
                    fees, net_amount, processed_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                RETURNING *
            `, [
                invoice.tenant_id,
                invoiceId,
                paymentResult.transactionId,
                provider,
                paymentMethod.type || 'card',
                invoice.total_amount,
                invoice.currency,
                paymentResult.status,
                JSON.stringify(paymentResult.response),
                paymentResult.fees || 0,
                invoice.total_amount - (paymentResult.fees || 0),
                new Date()
            ]);

            // Update invoice if payment successful
            if (paymentResult.status === 'completed') {
                await this.masterPool.query(`
                    UPDATE billing_invoices 
                    SET status = 'paid', paid_at = NOW(), 
                        payment_method = $2, payment_reference = $3
                    WHERE id = $1
                `, [invoiceId, paymentMethod.type, paymentResult.transactionId]);
            }

            return {
                success: paymentResult.status === 'completed',
                transaction: transaction.rows[0],
                paymentResult
            };

        } catch (error) {
            // Record failed transaction
            await this.masterPool.query(`
                INSERT INTO payment_transactions (
                    tenant_id, invoice_id, transaction_id, payment_provider,
                    payment_method, amount, currency, status, provider_response
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            `, [
                invoice.tenant_id,
                invoiceId,
                crypto.randomBytes(16).toString('hex'),
                provider,
                paymentMethod.type || 'card',
                invoice.total_amount,
                invoice.currency,
                'failed',
                JSON.stringify({ error: error.message })
            ]);

            throw error;
        }
    }

    async processStripePayment(invoice, paymentMethod) {
        if (!this.stripe) {
            throw new Error('Stripe not configured');
        }

        const paymentIntent = await this.stripe.paymentIntents.create({
            amount: Math.round(invoice.total_amount * 100), // Stripe uses cents
            currency: invoice.currency.toLowerCase(),
            payment_method: paymentMethod.id,
            confirm: true,
            metadata: {
                tenant_id: invoice.tenant_id,
                invoice_id: invoice.id,
                invoice_number: invoice.invoice_number
            }
        });

        return {
            transactionId: paymentIntent.id,
            status: paymentIntent.status === 'succeeded' ? 'completed' : 'failed',
            response: paymentIntent,
            fees: paymentIntent.charges?.data[0]?.balance_transaction?.fee || 0
        };
    }

    async processPayPalPayment(invoice, paymentMethod) {
        // PayPal integration would go here
        // For demo purposes, we'll simulate success
        return {
            transactionId: `paypal_${crypto.randomBytes(8).toString('hex')}`,
            status: 'completed',
            response: { status: 'COMPLETED' },
            fees: Math.round(invoice.total_amount * 0.029 * 100) / 100 // 2.9% fee
        };
    }

    // Usage Analytics and Reporting
    async getUsageAnalytics(tenantId, period = 'month', metricTypes = null) {
        let periodStart, periodEnd;
        const now = new Date();

        switch (period) {
            case 'day':
                periodStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                periodEnd = new Date(periodStart.getTime() + 24 * 60 * 60 * 1000);
                break;
            case 'week':
                const dayOfWeek = now.getDay();
                periodStart = new Date(now.getTime() - dayOfWeek * 24 * 60 * 60 * 1000);
                periodStart.setHours(0, 0, 0, 0);
                periodEnd = new Date(periodStart.getTime() + 7 * 24 * 60 * 60 * 1000);
                break;
            case 'month':
                periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
                periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);
                break;
            case 'year':
                periodStart = new Date(now.getFullYear(), 0, 1);
                periodEnd = new Date(now.getFullYear(), 11, 31, 23, 59, 59);
                break;
        }

        let query = `
            SELECT 
                metric_type,
                SUM(metric_value) as total_usage,
                AVG(metric_value) as avg_usage,
                MAX(metric_value) as peak_usage,
                COUNT(*) as data_points
            FROM usage_metrics 
            WHERE tenant_id = $1 AND period_start >= $2 AND period_end <= $3
        `;
        let params = [tenantId, periodStart, periodEnd];

        if (metricTypes && metricTypes.length > 0) {
            query += ` AND metric_type = ANY($4)`;
            params.push(metricTypes);
        }

        query += ` GROUP BY metric_type ORDER BY metric_type`;

        const result = await this.masterPool.query(query, params);

        return {
            period: {
                start: periodStart,
                end: periodEnd,
                type: period
            },
            metrics: result.rows
        };
    }

    async generateCostReport(tenantId, period = 'month') {
        const analytics = await this.getUsageAnalytics(tenantId, period);
        
        let totalCost = 0;
        const costBreakdown = {};

        for (const metric of analytics.metrics) {
            const rate = this.config.billingModels.usage[metric.metric_type] || 0;
            const cost = metric.total_usage * rate;
            
            costBreakdown[metric.metric_type] = {
                usage: metric.total_usage,
                rate: rate,
                cost: Math.round(cost * 100) / 100
            };
            
            totalCost += cost;
        }

        // Get subscription cost
        const subscription = await this.masterPool.query(
            'SELECT plan_id, base_price FROM billing_subscriptions WHERE tenant_id = $1 AND status = $2',
            [tenantId, 'active']
        );

        const subscriptionCost = subscription.rows[0]?.base_price || 0;

        return {
            period: analytics.period,
            subscriptionCost: subscriptionCost,
            usageCosts: costBreakdown,
            totalUsageCost: Math.round(totalCost * 100) / 100,
            totalCost: Math.round((totalCost + subscriptionCost) * 100) / 100
        };
    }

    // Alert Management
    async createBillingAlert(tenantId, alertType, metadata = {}) {
        const alertConfig = {
            quota_warning: {
                severity: 'medium',
                title: 'Usage Quota Warning',
                message: `You have used ${metadata.usagePercentage}% of your ${metadata.quotaType} quota.`
            },
            quota_exceeded: {
                severity: 'high',
                title: 'Usage Quota Exceeded',
                message: `Your ${metadata.quotaType} usage has exceeded the quota limit. Overage charges may apply.`
            },
            payment_failed: {
                severity: 'critical',
                title: 'Payment Failed',
                message: `Payment for invoice ${metadata.invoiceNumber} has failed. Please update your payment method.`
            },
            trial_expiring: {
                severity: 'medium',
                title: 'Trial Expiring Soon',
                message: `Your trial will expire in ${metadata.daysRemaining} days. Please add a payment method to continue service.`
            }
        };

        const config = alertConfig[alertType];
        if (!config) {
            throw new Error(`Unknown alert type: ${alertType}`);
        }

        await this.masterPool.query(`
            INSERT INTO billing_alerts (
                tenant_id, alert_type, severity, title, message, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [
            tenantId,
            alertType,
            config.severity,
            config.title,
            config.message,
            JSON.stringify(metadata)
        ]);

        // Send notification if configured
        await this.sendAlertNotification(tenantId, alertType, config, metadata);
    }

    async sendAlertNotification(tenantId, alertType, config, metadata) {
        // Get tenant notification preferences
        const tenant = await this.masterPool.query(
            'SELECT settings FROM tenants WHERE id = $1',
            [tenantId]
        );

        const settings = tenant.rows[0]?.settings || {};
        const notifications = settings.billing_notifications || {};

        if (notifications.email_enabled && notifications.email_address) {
            const emailContent = {
                to: notifications.email_address,
                subject: `OpenDirectory Alert: ${config.title}`,
                html: this.generateAlertEmailTemplate(config, metadata)
            };

            try {
                await this.emailTransporter.sendMail(emailContent);
            } catch (error) {
                console.error('Failed to send alert email:', error);
            }
        }
    }

    // Cron Jobs
    setupCronJobs() {
        // Monthly billing generation
        cron.schedule('0 0 1 * *', () => {
            this.generateMonthlyBills();
        });

        // Daily usage aggregation
        cron.schedule('0 1 * * *', () => {
            this.aggregateDailyUsage();
        });

        // Overdue invoice alerts
        cron.schedule('0 9 * * *', () => {
            this.checkOverdueInvoices();
        });

        // Trial expiration checks
        cron.schedule('0 9 * * *', () => {
            this.checkTrialExpirations();
        });

        // Usage quota resets
        cron.schedule('0 0 * * *', () => {
            this.resetDailyQuotas();
        });

        cron.schedule('0 0 1 * *', () => {
            this.resetMonthlyQuotas();
        });
    }

    async generateMonthlyBills() {
        const tenants = await this.masterPool.query(`
            SELECT DISTINCT t.id FROM tenants t
            JOIN billing_subscriptions bs ON t.id = bs.tenant_id
            WHERE t.status = 'active' AND bs.status = 'active'
        `);

        for (const tenant of tenants.rows) {
            try {
                const invoice = await this.generateInvoice(tenant.id, 'monthly');
                await this.sendInvoiceEmail(invoice.id);
            } catch (error) {
                console.error(`Failed to generate monthly bill for tenant ${tenant.id}:`, error);
            }
        }
    }

    async aggregateDailyUsage() {
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        yesterday.setHours(0, 0, 0, 0);

        const today = new Date(yesterday);
        today.setDate(today.getDate() + 1);

        // Aggregate hourly metrics into daily
        await this.masterPool.query(`
            INSERT INTO usage_metrics (
                tenant_id, metric_type, metric_value, unit, 
                period_start, period_end, aggregation_level
            )
            SELECT 
                tenant_id, 
                metric_type,
                SUM(metric_value) as daily_value,
                unit,
                $1 as period_start,
                $2 as period_end,
                'daily' as aggregation_level
            FROM usage_metrics 
            WHERE aggregation_level = 'hourly' 
            AND period_start >= $1 AND period_end <= $2
            GROUP BY tenant_id, metric_type, unit
        `, [yesterday, today]);
    }

    async checkOverdueInvoices() {
        const overdueInvoices = await this.masterPool.query(`
            SELECT id, tenant_id, invoice_number, total_amount 
            FROM billing_invoices 
            WHERE status = 'sent' AND due_date < CURRENT_DATE
        `);

        for (const invoice of overdueInvoices.rows) {
            await this.createBillingAlert(invoice.tenant_id, 'payment_overdue', {
                invoiceNumber: invoice.invoice_number,
                amount: invoice.total_amount
            });

            // Update invoice status
            await this.masterPool.query(
                'UPDATE billing_invoices SET status = $2 WHERE id = $1',
                [invoice.id, 'overdue']
            );
        }
    }

    async checkTrialExpirations() {
        const expiringTrials = await this.masterPool.query(`
            SELECT bs.tenant_id, bs.trial_ends_at,
                   EXTRACT(DAYS FROM bs.trial_ends_at - NOW()) as days_remaining
            FROM billing_subscriptions bs
            WHERE bs.status = 'trial' 
            AND bs.trial_ends_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'
        `);

        for (const trial of expiringTrials.rows) {
            await this.createBillingAlert(trial.tenant_id, 'trial_expiring', {
                daysRemaining: Math.ceil(trial.days_remaining)
            });
        }
    }

    async resetDailyQuotas() {
        await this.masterPool.query(`
            UPDATE usage_quotas 
            SET current_usage = 0, last_reset = NOW()
            WHERE reset_cycle = 'daily'
        `);
    }

    async resetMonthlyQuotas() {
        await this.masterPool.query(`
            UPDATE usage_quotas 
            SET current_usage = 0, last_reset = NOW()
            WHERE reset_cycle = 'monthly'
        `);
    }

    // Utility Methods
    async generateInvoiceNumber() {
        const year = new Date().getFullYear();
        const sequence = await this.redisClient.incr(`invoice_sequence:${year}`);
        return `${year}-${sequence.toString().padStart(6, '0')}`;
    }

    generateInvoiceEmailTemplate(invoice) {
        return `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Invoice ${invoice.invoice_number}</h2>
                <p>Dear ${invoice.tenant_name},</p>
                <p>Your invoice for the period ${invoice.billing_period_start.toDateString()} to ${invoice.billing_period_end.toDateString()} is now available.</p>
                
                <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <h3>Invoice Summary:</h3>
                    <p><strong>Invoice Number:</strong> ${invoice.invoice_number}</p>
                    <p><strong>Amount Due:</strong> $${invoice.total_amount.toFixed(2)} ${invoice.currency}</p>
                    <p><strong>Due Date:</strong> ${invoice.due_date}</p>
                </div>
                
                <p>The invoice is attached to this email. You can also view and pay your invoice online in your account portal.</p>
                
                <p>Thank you for your business!</p>
                <p>The OpenDirectory Team</p>
            </div>
        `;
    }

    generateAlertEmailTemplate(config, metadata) {
        return `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: ${config.severity === 'critical' ? '#d32f2f' : '#f57c00'};">
                    ${config.title}
                </h2>
                <p>${config.message}</p>
                
                ${metadata.currentUsage ? `
                    <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        <h4>Usage Details:</h4>
                        <p><strong>Current Usage:</strong> ${metadata.currentUsage}</p>
                        <p><strong>Quota Limit:</strong> ${metadata.quotaLimit}</p>
                        ${metadata.overage ? `<p><strong>Overage:</strong> ${metadata.overage}</p>` : ''}
                    </div>
                ` : ''}
                
                <p>Please log in to your account portal to take action or contact our support team if you need assistance.</p>
                
                <p>Best regards,<br>The OpenDirectory Team</p>
            </div>
        `;
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

        // Health check
        app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'billing-engine'
            });
        });

        // Usage tracking endpoints
        app.post('/api/usage', async (req, res) => {
            try {
                await this.recordUsage(
                    req.body.tenantId,
                    req.body.metricType,
                    req.body.value,
                    req.body.unit,
                    req.body.metadata
                );
                res.json({ success: true });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Invoice management
        app.post('/api/tenants/:tenantId/invoices', async (req, res) => {
            try {
                const invoice = await this.generateInvoice(req.params.tenantId, req.body.period);
                res.status(201).json(invoice);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.get('/api/invoices/:invoiceId', async (req, res) => {
            try {
                const invoice = await this.getInvoiceDetails(req.params.invoiceId);
                res.json(invoice);
            } catch (error) {
                res.status(404).json({ error: error.message });
            }
        });

        app.get('/api/invoices/:invoiceId/pdf', async (req, res) => {
            try {
                const pdfStream = await this.generateInvoicePDF(req.params.invoiceId);
                res.setHeader('Content-Type', 'application/pdf');
                res.setHeader('Content-Disposition', `attachment; filename=invoice-${req.params.invoiceId}.pdf`);
                pdfStream.pipe(res);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.post('/api/invoices/:invoiceId/send', async (req, res) => {
            try {
                await this.sendInvoiceEmail(req.params.invoiceId);
                res.json({ success: true });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Payment processing
        app.post('/api/invoices/:invoiceId/pay', async (req, res) => {
            try {
                const result = await this.processPayment(
                    req.params.invoiceId,
                    req.body.paymentMethod,
                    req.body.provider
                );
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Analytics and reporting
        app.get('/api/tenants/:tenantId/analytics', async (req, res) => {
            try {
                const analytics = await this.getUsageAnalytics(
                    req.params.tenantId,
                    req.query.period,
                    req.query.metrics?.split(',')
                );
                res.json(analytics);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.get('/api/tenants/:tenantId/cost-report', async (req, res) => {
            try {
                const report = await this.generateCostReport(req.params.tenantId, req.query.period);
                res.json(report);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Quota management
        app.get('/api/tenants/:tenantId/quotas', async (req, res) => {
            try {
                const quotas = await this.masterPool.query(
                    'SELECT * FROM usage_quotas WHERE tenant_id = $1',
                    [req.params.tenantId]
                );
                res.json({ quotas: quotas.rows });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        app.put('/api/tenants/:tenantId/quotas/:quotaType', async (req, res) => {
            try {
                await this.masterPool.query(`
                    INSERT INTO usage_quotas (tenant_id, quota_type, quota_limit, overage_rate, alert_threshold)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (tenant_id, quota_type)
                    DO UPDATE SET 
                        quota_limit = $3,
                        overage_rate = $4,
                        alert_threshold = $5
                `, [
                    req.params.tenantId,
                    req.params.quotaType,
                    req.body.limit,
                    req.body.overageRate || 0,
                    req.body.alertThreshold || 0.8
                ]);

                res.json({ success: true });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Billing alerts
        app.get('/api/tenants/:tenantId/alerts', async (req, res) => {
            try {
                const alerts = await this.masterPool.query(`
                    SELECT * FROM billing_alerts 
                    WHERE tenant_id = $1 
                    ORDER BY created_at DESC
                    LIMIT 50
                `, [req.params.tenantId]);

                res.json({ alerts: alerts.rows });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        return app;
    }

    async start() {
        const app = this.setupRestAPI();

        const server = app.listen(this.config.port, () => {
            console.log(`Billing Engine started on port ${this.config.port}`);
            console.log('Available endpoints:');
            console.log('  POST /api/usage - Record usage metrics');
            console.log('  POST /api/tenants/:tenantId/invoices - Generate invoice');
            console.log('  GET /api/invoices/:invoiceId - Get invoice details');
            console.log('  GET /api/invoices/:invoiceId/pdf - Download invoice PDF');
            console.log('  POST /api/invoices/:invoiceId/send - Send invoice email');
            console.log('  POST /api/invoices/:invoiceId/pay - Process payment');
            console.log('  GET /api/tenants/:tenantId/analytics - Get usage analytics');
            console.log('  GET /api/tenants/:tenantId/cost-report - Generate cost report');
            console.log('  GET /api/tenants/:tenantId/quotas - Get usage quotas');
            console.log('  PUT /api/tenants/:tenantId/quotas/:quotaType - Update quota');
            console.log('  GET /api/tenants/:tenantId/alerts - Get billing alerts');
        });

        return server;
    }
}

module.exports = BillingEngine;

if (require.main === module) {
    const config = {
        port: process.env.PORT || 3103,
        masterDbUrl: process.env.MASTER_DB_URL || 'postgresql://opendirectory:changeme@localhost:5432/multitenant_master',
        redisUrl: process.env.REDIS_URL || 'redis://:changeme@localhost:6379',
        stripeSecretKey: process.env.STRIPE_SECRET_KEY
    };

    const billing = new BillingEngine(config);
    billing.start().catch(error => {
        console.error('Failed to start Billing Engine:', error);
        process.exit(1);
    });
}