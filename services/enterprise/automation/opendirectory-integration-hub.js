/**
 * OpenDirectory Integration Hub
 * Comprehensive integration platform with REST API gateway, GraphQL, and external service connectors
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');

class IntegrationHub extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            port: config.port || 3000,
            graphqlPort: config.graphqlPort || 3001,
            enableCors: config.enableCors !== false,
            enableRateLimit: config.enableRateLimit !== false,
            rateLimitWindow: config.rateLimitWindow || 900000, // 15 minutes
            rateLimitMax: config.rateLimitMax || 1000,
            webhookTimeout: config.webhookTimeout || 30000,
            storageDir: config.storageDir || '/tmp/integrations',
            enableLogging: config.enableLogging !== false,
            authEnabled: config.authEnabled || false,
            ...config
        };
        
        this.app = express();
        this.graphqlApp = express();
        this.server = null;
        this.graphqlServer = null;
        
        this.apiRoutes = new Map();
        this.webhookEndpoints = new Map();
        this.externalConnectors = new Map();
        this.messageQueues = new Map();
        this.fileWatchers = new Map();
        this.databaseConnections = new Map();
        
        this.requestStats = {
            total: 0,
            successful: 0,
            failed: 0,
            webhooks: 0,
            connectorCalls: 0
        };
        
        this.init();
    }
    
    async init() {
        await this.ensureStorageDir();
        this.setupExpressMiddleware();
        this.setupGraphQL();
        this.setupBuiltinRoutes();
        this.setupExternalConnectors();
        this.setupMessageQueues();
        this.startServers();
        
        this.emit('hub:ready');
        console.log(`Integration Hub initialized on ports ${this.config.port} (REST) and ${this.config.graphqlPort} (GraphQL)`);
    }
    
    async ensureStorageDir() {
        try {
            await fs.mkdir(this.config.storageDir, { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'logs'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'webhooks'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'connectors'), { recursive: true });
        } catch (error) {
            console.error('Failed to create storage directories:', error);
        }
    }
    
    setupExpressMiddleware() {
        // Enable CORS if configured
        if (this.config.enableCors) {
            this.app.use((req, res, next) => {
                res.header('Access-Control-Allow-Origin', '*');
                res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
                res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
                if (req.method === 'OPTIONS') {
                    res.sendStatus(200);
                } else {
                    next();
                }
            });
        }
        
        // Parse JSON and URL-encoded bodies
        this.app.use(express.json({ limit: '50mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));
        
        // Request logging and statistics
        if (this.config.enableLogging) {
            this.app.use((req, res, next) => {
                const startTime = Date.now();
                
                res.on('finish', () => {
                    const duration = Date.now() - startTime;
                    this.logRequest(req, res, duration);
                    this.updateRequestStats(res.statusCode);
                });
                
                next();
            });
        }
        
        // Rate limiting
        if (this.config.enableRateLimit) {
            this.setupRateLimit();
        }
        
        // Authentication middleware
        if (this.config.authEnabled) {
            this.setupAuthentication();
        }
        
        // Error handling
        this.app.use((error, req, res, next) => {
            console.error('Express error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message,
                timestamp: new Date().toISOString()
            });
        });
    }
    
    setupRateLimit() {
        const rateLimitStore = new Map();
        
        this.app.use((req, res, next) => {
            const clientId = req.ip || req.connection.remoteAddress;
            const now = Date.now();
            const windowStart = now - this.config.rateLimitWindow;
            
            if (!rateLimitStore.has(clientId)) {
                rateLimitStore.set(clientId, []);
            }
            
            const clientRequests = rateLimitStore.get(clientId);
            
            // Remove old requests outside the window
            const validRequests = clientRequests.filter(timestamp => timestamp > windowStart);
            
            if (validRequests.length >= this.config.rateLimitMax) {
                res.status(429).json({
                    error: 'Rate limit exceeded',
                    limit: this.config.rateLimitMax,
                    window: this.config.rateLimitWindow,
                    retryAfter: this.config.rateLimitWindow / 1000
                });
                return;
            }
            
            validRequests.push(now);
            rateLimitStore.set(clientId, validRequests);
            
            res.header('X-RateLimit-Limit', this.config.rateLimitMax.toString());
            res.header('X-RateLimit-Remaining', (this.config.rateLimitMax - validRequests.length).toString());
            res.header('X-RateLimit-Reset', new Date(now + this.config.rateLimitWindow).toISOString());
            
            next();
        });
    }
    
    setupAuthentication() {
        this.app.use('/api', (req, res, next) => {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Unauthorized', message: 'Missing or invalid authorization header' });
                return;
            }
            
            const token = authHeader.substring(7);
            
            // In a real implementation, this would validate the JWT token
            // For demo purposes, we'll accept any non-empty token
            if (!token) {
                res.status(401).json({ error: 'Unauthorized', message: 'Invalid token' });
                return;
            }
            
            req.user = { id: 'authenticated_user', token };
            next();
        });
    }
    
    setupGraphQL() {
        const schema = buildSchema(`
            type Query {
                users(filter: UserFilter): [User]
                user(id: String!): User
                groups(filter: GroupFilter): [Group]
                group(id: String!): Group
                devices(filter: DeviceFilter): [Device]
                device(id: String!): Device
                certificates(filter: CertificateFilter): [Certificate]
                certificate(id: String!): Certificate
                integrationStats: IntegrationStats
                connectors: [Connector]
                webhooks: [Webhook]
            }
            
            type Mutation {
                createUser(input: UserInput!): User
                updateUser(id: String!, input: UserInput!): User
                deleteUser(id: String!): Boolean
                createGroup(input: GroupInput!): Group
                updateGroup(id: String!, input: GroupInput!): Group
                deleteGroup(id: String!): Boolean
                enrollDevice(input: DeviceInput!): Device
                updateDevice(id: String!, input: DeviceInput!): Device
                removeDevice(id: String!): Boolean
                issueCertificate(input: CertificateInput!): Certificate
                revokeCertificate(id: String!): Boolean
                createWebhook(input: WebhookInput!): Webhook
                updateWebhook(id: String!, input: WebhookInput!): Webhook
                deleteWebhook(id: String!): Boolean
                triggerSync(connector: String!): SyncResult
            }
            
            type User {
                id: String!
                username: String!
                email: String!
                firstName: String
                lastName: String
                department: String
                manager: String
                groups: [Group]
                devices: [Device]
                certificates: [Certificate]
                status: String!
                lastLogin: String
                createdAt: String!
                updatedAt: String!
            }
            
            type Group {
                id: String!
                name: String!
                description: String
                members: [User]
                memberCount: Int!
                permissions: [String]
                createdAt: String!
                updatedAt: String!
            }
            
            type Device {
                id: String!
                name: String!
                type: String!
                platform: String!
                owner: User
                status: String!
                lastSeen: String
                compliance: DeviceCompliance
                applications: [Application]
                certificates: [Certificate]
                enrolledAt: String!
                updatedAt: String!
            }
            
            type Certificate {
                id: String!
                commonName: String!
                serialNumber: String!
                issuer: String!
                validFrom: String!
                validTo: String!
                status: String!
                keySize: Int!
                usage: [String]
                owner: User
                device: Device
                issuedAt: String!
            }
            
            type DeviceCompliance {
                status: String!
                lastChecked: String!
                violations: [ComplianceViolation]
            }
            
            type ComplianceViolation {
                rule: String!
                severity: String!
                description: String!
                detectedAt: String!
            }
            
            type Application {
                id: String!
                name: String!
                version: String!
                installedAt: String!
            }
            
            type IntegrationStats {
                totalRequests: Int!
                successfulRequests: Int!
                failedRequests: Int!
                webhookDeliveries: Int!
                connectorCalls: Int!
                uptime: Float!
            }
            
            type Connector {
                id: String!
                name: String!
                type: String!
                status: String!
                lastSync: String
                config: String
            }
            
            type Webhook {
                id: String!
                name: String!
                url: String!
                events: [String]!
                status: String!
                deliveries: Int!
                lastDelivery: String
            }
            
            type SyncResult {
                success: Boolean!
                message: String!
                recordsProcessed: Int!
                errors: [String]
            }
            
            input UserFilter {
                status: String
                department: String
                search: String
                limit: Int
                offset: Int
            }
            
            input GroupFilter {
                search: String
                limit: Int
                offset: Int
            }
            
            input DeviceFilter {
                type: String
                platform: String
                status: String
                owner: String
                limit: Int
                offset: Int
            }
            
            input CertificateFilter {
                status: String
                owner: String
                expiring: Boolean
                limit: Int
                offset: Int
            }
            
            input UserInput {
                username: String!
                email: String!
                firstName: String
                lastName: String
                department: String
                manager: String
                password: String
                status: String
            }
            
            input GroupInput {
                name: String!
                description: String
                permissions: [String]
            }
            
            input DeviceInput {
                name: String!
                type: String!
                platform: String!
                owner: String!
                serialNumber: String
            }
            
            input CertificateInput {
                commonName: String!
                owner: String
                device: String
                validityPeriod: String
                keySize: Int
                usage: [String]
            }
            
            input WebhookInput {
                name: String!
                url: String!
                events: [String]!
                secret: String
            }
        `);
        
        const root = {
            // Queries
            users: async (args) => this.handleGraphQLUsers(args),
            user: async (args) => this.handleGraphQLUser(args),
            groups: async (args) => this.handleGraphQLGroups(args),
            group: async (args) => this.handleGraphQLGroup(args),
            devices: async (args) => this.handleGraphQLDevices(args),
            device: async (args) => this.handleGraphQLDevice(args),
            certificates: async (args) => this.handleGraphQLCertificates(args),
            certificate: async (args) => this.handleGraphQLCertificate(args),
            integrationStats: () => this.getIntegrationStats(),
            connectors: () => this.getConnectors(),
            webhooks: () => this.getWebhooks(),
            
            // Mutations
            createUser: async (args) => this.handleGraphQLCreateUser(args),
            updateUser: async (args) => this.handleGraphQLUpdateUser(args),
            deleteUser: async (args) => this.handleGraphQLDeleteUser(args),
            createGroup: async (args) => this.handleGraphQLCreateGroup(args),
            updateGroup: async (args) => this.handleGraphQLUpdateGroup(args),
            deleteGroup: async (args) => this.handleGraphQLDeleteGroup(args),
            enrollDevice: async (args) => this.handleGraphQLEnrollDevice(args),
            updateDevice: async (args) => this.handleGraphQLUpdateDevice(args),
            removeDevice: async (args) => this.handleGraphQLRemoveDevice(args),
            issueCertificate: async (args) => this.handleGraphQLIssueCertificate(args),
            revokeCertificate: async (args) => this.handleGraphQLRevokeCertificate(args),
            createWebhook: async (args) => this.handleGraphQLCreateWebhook(args),
            updateWebhook: async (args) => this.handleGraphQLUpdateWebhook(args),
            deleteWebhook: async (args) => this.handleGraphQLDeleteWebhook(args),
            triggerSync: async (args) => this.handleGraphQLTriggerSync(args)
        };
        
        this.graphqlApp.use('/graphql', graphqlHTTP({
            schema: schema,
            rootValue: root,
            graphiql: true // Enable GraphiQL interface
        }));
    }
    
    setupBuiltinRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: '1.0.0',
                uptime: process.uptime()
            });
        });
        
        // Statistics endpoint
        this.app.get('/stats', (req, res) => {
            res.json(this.getIntegrationStats());
        });
        
        // LDAP API endpoints
        this.setupLdapRoutes();
        
        // Device management endpoints
        this.setupDeviceRoutes();
        
        // Certificate management endpoints
        this.setupCertificateRoutes();
        
        // Webhook management endpoints
        this.setupWebhookRoutes();
        
        // External connector endpoints
        this.setupConnectorRoutes();
    }
    
    setupLdapRoutes() {
        const router = express.Router();
        
        // Users
        router.get('/users', async (req, res) => {
            try {
                const users = await this.getLdapUsers(req.query);
                res.json({ success: true, data: users, total: users.length });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.get('/users/:id', async (req, res) => {
            try {
                const user = await this.getLdapUser(req.params.id);
                if (!user) {
                    res.status(404).json({ success: false, error: 'User not found' });
                    return;
                }
                res.json({ success: true, data: user });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.post('/users', async (req, res) => {
            try {
                const user = await this.createLdapUser(req.body);
                res.status(201).json({ success: true, data: user });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.put('/users/:id', async (req, res) => {
            try {
                const user = await this.updateLdapUser(req.params.id, req.body);
                res.json({ success: true, data: user });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.delete('/users/:id', async (req, res) => {
            try {
                await this.deleteLdapUser(req.params.id);
                res.json({ success: true, message: 'User deleted successfully' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        // Groups
        router.get('/groups', async (req, res) => {
            try {
                const groups = await this.getLdapGroups(req.query);
                res.json({ success: true, data: groups, total: groups.length });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.post('/groups', async (req, res) => {
            try {
                const group = await this.createLdapGroup(req.body);
                res.status(201).json({ success: true, data: group });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.post('/groups/:id/members', async (req, res) => {
            try {
                await this.addGroupMember(req.params.id, req.body.userId);
                res.json({ success: true, message: 'Member added successfully' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.delete('/groups/:id/members/:userId', async (req, res) => {
            try {
                await this.removeGroupMember(req.params.id, req.params.userId);
                res.json({ success: true, message: 'Member removed successfully' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        this.app.use('/api/ldap', router);
    }
    
    setupDeviceRoutes() {
        const router = express.Router();
        
        router.get('/devices', async (req, res) => {
            try {
                const devices = await this.getDevices(req.query);
                res.json({ success: true, data: devices, total: devices.length });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.post('/devices/enroll', async (req, res) => {
            try {
                const device = await this.enrollDevice(req.body);
                res.status(201).json({ success: true, data: device });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.get('/devices/:id', async (req, res) => {
            try {
                const device = await this.getDevice(req.params.id);
                if (!device) {
                    res.status(404).json({ success: false, error: 'Device not found' });
                    return;
                }
                res.json({ success: true, data: device });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.put('/devices/:id', async (req, res) => {
            try {
                const device = await this.updateDevice(req.params.id, req.body);
                res.json({ success: true, data: device });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.delete('/devices/:id', async (req, res) => {
            try {
                await this.removeDevice(req.params.id);
                res.json({ success: true, message: 'Device removed successfully' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.post('/devices/:id/compliance-check', async (req, res) => {
            try {
                const compliance = await this.checkDeviceCompliance(req.params.id);
                res.json({ success: true, data: compliance });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        this.app.use('/api/mdm', router);
    }
    
    setupCertificateRoutes() {
        const router = express.Router();
        
        router.get('/certificates', async (req, res) => {
            try {
                const certificates = await this.getCertificates(req.query);
                res.json({ success: true, data: certificates, total: certificates.length });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.post('/certificates', async (req, res) => {
            try {
                const certificate = await this.issueCertificate(req.body);
                res.status(201).json({ success: true, data: certificate });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.get('/certificates/:id', async (req, res) => {
            try {
                const certificate = await this.getCertificate(req.params.id);
                if (!certificate) {
                    res.status(404).json({ success: false, error: 'Certificate not found' });
                    return;
                }
                res.json({ success: true, data: certificate });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        router.post('/certificates/:id/revoke', async (req, res) => {
            try {
                await this.revokeCertificate(req.params.id, req.body.reason);
                res.json({ success: true, message: 'Certificate revoked successfully' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.post('/certificates/:id/renew', async (req, res) => {
            try {
                const certificate = await this.renewCertificate(req.params.id);
                res.json({ success: true, data: certificate });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        this.app.use('/api/pki', router);
    }
    
    setupWebhookRoutes() {
        const router = express.Router();
        
        router.get('/webhooks', (req, res) => {
            const webhooks = Array.from(this.webhookEndpoints.values());
            res.json({ success: true, data: webhooks, total: webhooks.length });
        });
        
        router.post('/webhooks', async (req, res) => {
            try {
                const webhookId = await this.createWebhook(req.body);
                const webhook = this.webhookEndpoints.get(webhookId);
                res.status(201).json({ success: true, data: webhook });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.put('/webhooks/:id', async (req, res) => {
            try {
                await this.updateWebhook(req.params.id, req.body);
                const webhook = this.webhookEndpoints.get(req.params.id);
                res.json({ success: true, data: webhook });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.delete('/webhooks/:id', async (req, res) => {
            try {
                await this.deleteWebhook(req.params.id);
                res.json({ success: true, message: 'Webhook deleted successfully' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.post('/webhooks/:id/test', async (req, res) => {
            try {
                const result = await this.testWebhook(req.params.id, req.body);
                res.json({ success: true, data: result });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        // Generic webhook receiver
        router.post('/webhook/:id', async (req, res) => {
            try {
                await this.receiveWebhook(req.params.id, req.body, req.headers);
                res.json({ success: true, message: 'Webhook received' });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        this.app.use('/api/webhooks', router);
    }
    
    setupConnectorRoutes() {
        const router = express.Router();
        
        router.get('/connectors', (req, res) => {
            const connectors = Array.from(this.externalConnectors.values()).map(conn => ({
                id: conn.id,
                name: conn.name,
                type: conn.type,
                status: conn.status,
                lastSync: conn.lastSync,
                config: conn.publicConfig || {}
            }));
            res.json({ success: true, data: connectors, total: connectors.length });
        });
        
        router.post('/connectors/:id/sync', async (req, res) => {
            try {
                const result = await this.syncConnector(req.params.id, req.body);
                res.json({ success: true, data: result });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.post('/connectors/:id/test', async (req, res) => {
            try {
                const result = await this.testConnector(req.params.id);
                res.json({ success: true, data: result });
            } catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        
        router.get('/connectors/:id/logs', async (req, res) => {
            try {
                const logs = await this.getConnectorLogs(req.params.id, req.query);
                res.json({ success: true, data: logs });
            } catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        
        this.app.use('/api/connectors', router);
    }
    
    // External Service Connectors
    setupExternalConnectors() {
        // Slack Connector
        this.externalConnectors.set('slack', {
            id: 'slack',
            name: 'Slack Integration',
            type: 'messaging',
            status: 'active',
            config: {
                webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
                channel: process.env.SLACK_CHANNEL || '#general',
                botToken: process.env.SLACK_BOT_TOKEN || ''
            },
            publicConfig: {
                channel: process.env.SLACK_CHANNEL || '#general',
                enabled: !!(process.env.SLACK_WEBHOOK_URL || process.env.SLACK_BOT_TOKEN)
            },
            lastSync: null,
            methods: {
                sendMessage: this.sendSlackMessage.bind(this),
                sendAlert: this.sendSlackAlert.bind(this),
                createChannel: this.createSlackChannel.bind(this),
                inviteUser: this.inviteSlackUser.bind(this)
            }
        });
        
        // Microsoft Teams Connector
        this.externalConnectors.set('teams', {
            id: 'teams',
            name: 'Microsoft Teams Integration',
            type: 'messaging',
            status: 'active',
            config: {
                webhookUrl: process.env.TEAMS_WEBHOOK_URL || '',
                tenantId: process.env.TEAMS_TENANT_ID || '',
                clientId: process.env.TEAMS_CLIENT_ID || '',
                clientSecret: process.env.TEAMS_CLIENT_SECRET || ''
            },
            publicConfig: {
                enabled: !!process.env.TEAMS_WEBHOOK_URL
            },
            lastSync: null,
            methods: {
                sendMessage: this.sendTeamsMessage.bind(this),
                sendCard: this.sendTeamsCard.bind(this),
                createMeeting: this.createTeamsMeeting.bind(this)
            }
        });
        
        // Jira Connector
        this.externalConnectors.set('jira', {
            id: 'jira',
            name: 'Jira Integration',
            type: 'ticketing',
            status: 'active',
            config: {
                baseUrl: process.env.JIRA_BASE_URL || '',
                username: process.env.JIRA_USERNAME || '',
                apiToken: process.env.JIRA_API_TOKEN || '',
                projectKey: process.env.JIRA_PROJECT_KEY || 'IT'
            },
            publicConfig: {
                baseUrl: process.env.JIRA_BASE_URL || '',
                projectKey: process.env.JIRA_PROJECT_KEY || 'IT',
                enabled: !!(process.env.JIRA_BASE_URL && process.env.JIRA_API_TOKEN)
            },
            lastSync: null,
            methods: {
                createTicket: this.createJiraTicket.bind(this),
                updateTicket: this.updateJiraTicket.bind(this),
                searchTickets: this.searchJiraTickets.bind(this),
                addComment: this.addJiraComment.bind(this)
            }
        });
        
        // ServiceNow Connector
        this.externalConnectors.set('servicenow', {
            id: 'servicenow',
            name: 'ServiceNow Integration',
            type: 'itsm',
            status: 'active',
            config: {
                instanceUrl: process.env.SERVICENOW_INSTANCE_URL || '',
                username: process.env.SERVICENOW_USERNAME || '',
                password: process.env.SERVICENOW_PASSWORD || '',
                table: process.env.SERVICENOW_TABLE || 'incident'
            },
            publicConfig: {
                instanceUrl: process.env.SERVICENOW_INSTANCE_URL || '',
                table: process.env.SERVICENOW_TABLE || 'incident',
                enabled: !!(process.env.SERVICENOW_INSTANCE_URL && process.env.SERVICENOW_USERNAME)
            },
            lastSync: null,
            methods: {
                createIncident: this.createServiceNowIncident.bind(this),
                updateIncident: this.updateServiceNowIncident.bind(this),
                searchIncidents: this.searchServiceNowIncidents.bind(this)
            }
        });
        
        // Email Connector
        this.externalConnectors.set('email', {
            id: 'email',
            name: 'Email Integration',
            type: 'messaging',
            status: 'active',
            config: {
                smtpHost: process.env.SMTP_HOST || 'localhost',
                smtpPort: process.env.SMTP_PORT || 587,
                smtpSecure: process.env.SMTP_SECURE === 'true',
                smtpUser: process.env.SMTP_USER || '',
                smtpPassword: process.env.SMTP_PASSWORD || '',
                fromAddress: process.env.FROM_EMAIL || 'noreply@example.com'
            },
            publicConfig: {
                smtpHost: process.env.SMTP_HOST || 'localhost',
                fromAddress: process.env.FROM_EMAIL || 'noreply@example.com',
                enabled: !!(process.env.SMTP_HOST && process.env.FROM_EMAIL)
            },
            lastSync: null,
            methods: {
                sendEmail: this.sendEmail.bind(this),
                sendBulkEmail: this.sendBulkEmail.bind(this),
                sendTemplate: this.sendEmailTemplate.bind(this)
            }
        });
        
        // SMS Gateway Connector
        this.externalConnectors.set('sms', {
            id: 'sms',
            name: 'SMS Gateway',
            type: 'messaging',
            status: 'active',
            config: {
                provider: process.env.SMS_PROVIDER || 'twilio',
                accountSid: process.env.SMS_ACCOUNT_SID || '',
                authToken: process.env.SMS_AUTH_TOKEN || '',
                fromNumber: process.env.SMS_FROM_NUMBER || ''
            },
            publicConfig: {
                provider: process.env.SMS_PROVIDER || 'twilio',
                enabled: !!(process.env.SMS_ACCOUNT_SID && process.env.SMS_AUTH_TOKEN)
            },
            lastSync: null,
            methods: {
                sendSMS: this.sendSMS.bind(this),
                sendBulkSMS: this.sendBulkSMS.bind(this)
            }
        });
        
        console.log(`Configured ${this.externalConnectors.size} external connectors`);
    }
    
    // Slack Integration Methods
    async sendSlackMessage(message, channel, options = {}) {
        const connector = this.externalConnectors.get('slack');
        const fetch = require('node-fetch');
        
        if (!connector.config.webhookUrl && !connector.config.botToken) {
            throw new Error('Slack webhook URL or bot token not configured');
        }
        
        const payload = {
            text: message,
            channel: channel || connector.config.channel,
            username: options.username || 'OpenDirectory',
            icon_emoji: options.emoji || ':robot_face:',
            attachments: options.attachments || []
        };
        
        const response = await fetch(connector.config.webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`Slack API error: ${response.statusText}`);
        }
        
        connector.lastSync = new Date().toISOString();
        this.requestStats.connectorCalls++;
        
        return { success: true, channel, timestamp: new Date().toISOString() };
    }
    
    async sendSlackAlert(alert) {
        const color = alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'good';
        
        return await this.sendSlackMessage(`Alert: ${alert.title}`, null, {
            attachments: [{
                color,
                title: alert.title,
                text: alert.message,
                fields: [
                    { title: 'Severity', value: alert.severity, short: true },
                    { title: 'Source', value: alert.source, short: true },
                    { title: 'Time', value: alert.timestamp, short: true }
                ]
            }]
        });
    }
    
    // Microsoft Teams Integration Methods
    async sendTeamsMessage(message, options = {}) {
        const connector = this.externalConnectors.get('teams');
        const fetch = require('node-fetch');
        
        if (!connector.config.webhookUrl) {
            throw new Error('Teams webhook URL not configured');
        }
        
        const payload = {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            summary: options.summary || 'OpenDirectory Notification',
            text: message,
            themeColor: options.color || '0078D4'
        };
        
        const response = await fetch(connector.config.webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`Teams API error: ${response.statusText}`);
        }
        
        connector.lastSync = new Date().toISOString();
        this.requestStats.connectorCalls++;
        
        return { success: true, timestamp: new Date().toISOString() };
    }
    
    async sendTeamsCard(card) {
        const connector = this.externalConnectors.get('teams');
        const fetch = require('node-fetch');
        
        const response = await fetch(connector.config.webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(card)
        });
        
        if (!response.ok) {
            throw new Error(`Teams API error: ${response.statusText}`);
        }
        
        connector.lastSync = new Date().toISOString();
        this.requestStats.connectorCalls++;
        
        return { success: true, timestamp: new Date().toISOString() };
    }
    
    // Jira Integration Methods
    async createJiraTicket(ticket) {
        const connector = this.externalConnectors.get('jira');
        const fetch = require('node-fetch');
        
        const auth = Buffer.from(`${connector.config.username}:${connector.config.apiToken}`).toString('base64');
        
        const payload = {
            fields: {
                project: { key: connector.config.projectKey },
                summary: ticket.summary,
                description: ticket.description,
                issuetype: { name: ticket.type || 'Task' },
                priority: { name: ticket.priority || 'Medium' }
            }
        };
        
        const response = await fetch(`${connector.config.baseUrl}/rest/api/2/issue`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`Jira API error: ${response.statusText}`);
        }
        
        const result = await response.json();
        connector.lastSync = new Date().toISOString();
        this.requestStats.connectorCalls++;
        
        return {
            success: true,
            ticketId: result.key,
            url: `${connector.config.baseUrl}/browse/${result.key}`
        };
    }
    
    // ServiceNow Integration Methods
    async createServiceNowIncident(incident) {
        const connector = this.externalConnectors.get('servicenow');
        const fetch = require('node-fetch');
        
        const auth = Buffer.from(`${connector.config.username}:${connector.config.password}`).toString('base64');
        
        const payload = {
            short_description: incident.summary,
            description: incident.description,
            urgency: incident.urgency || '3',
            impact: incident.impact || '3',
            category: incident.category || 'Software',
            caller_id: incident.callerId
        };
        
        const response = await fetch(`${connector.config.instanceUrl}/api/now/table/${connector.config.table}`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`ServiceNow API error: ${response.statusText}`);
        }
        
        const result = await response.json();
        connector.lastSync = new Date().toISOString();
        this.requestStats.connectorCalls++;
        
        return {
            success: true,
            incidentId: result.result.number,
            sysId: result.result.sys_id,
            url: `${connector.config.instanceUrl}/nav_to.do?uri=${connector.config.table}.do?sys_id=${result.result.sys_id}`
        };
    }
    
    // Email Integration Methods
    async sendEmail(emailData) {
        const connector = this.externalConnectors.get('email');
        const nodemailer = require('nodemailer');
        
        const transporter = nodemailer.createTransporter({
            host: connector.config.smtpHost,
            port: connector.config.smtpPort,
            secure: connector.config.smtpSecure,
            auth: connector.config.smtpUser ? {
                user: connector.config.smtpUser,
                pass: connector.config.smtpPassword
            } : null
        });
        
        const mailOptions = {
            from: emailData.from || connector.config.fromAddress,
            to: emailData.to,
            cc: emailData.cc,
            bcc: emailData.bcc,
            subject: emailData.subject,
            text: emailData.text,
            html: emailData.html,
            attachments: emailData.attachments
        };
        
        const result = await transporter.sendMail(mailOptions);
        connector.lastSync = new Date().toISOString();
        this.requestStats.connectorCalls++;
        
        return {
            success: true,
            messageId: result.messageId,
            accepted: result.accepted,
            rejected: result.rejected
        };
    }
    
    // SMS Integration Methods
    async sendSMS(phoneNumber, message) {
        const connector = this.externalConnectors.get('sms');
        
        if (connector.config.provider === 'twilio') {
            const twilio = require('twilio');
            const client = twilio(connector.config.accountSid, connector.config.authToken);
            
            const result = await client.messages.create({
                body: message,
                from: connector.config.fromNumber,
                to: phoneNumber
            });
            
            connector.lastSync = new Date().toISOString();
            this.requestStats.connectorCalls++;
            
            return {
                success: true,
                messageId: result.sid,
                status: result.status
            };
        }
        
        throw new Error(`Unsupported SMS provider: ${connector.config.provider}`);
    }
    
    // Message Queue Setup
    setupMessageQueues() {
        // Redis Queue (if available)
        if (process.env.REDIS_URL) {
            this.messageQueues.set('redis', {
                type: 'redis',
                url: process.env.REDIS_URL,
                client: null,
                connected: false
            });
        }
        
        // RabbitMQ Queue (if available)
        if (process.env.RABBITMQ_URL) {
            this.messageQueues.set('rabbitmq', {
                type: 'rabbitmq',
                url: process.env.RABBITMQ_URL,
                connection: null,
                connected: false
            });
        }
        
        // In-memory queue (default)
        this.messageQueues.set('memory', {
            type: 'memory',
            queues: new Map(),
            connected: true
        });
        
        console.log(`Configured ${this.messageQueues.size} message queue(s)`);
    }
    
    // File System Watchers
    setupFileWatcher(watchPath, options = {}) {
        const fs = require('fs');
        const chokidar = require('chokidar');
        
        const watcherId = this.generateId();
        
        const watcher = chokidar.watch(watchPath, {
            ignored: options.ignored || /(^|[\/\\])\../, // ignore dotfiles
            persistent: true,
            ignoreInitial: options.ignoreInitial !== false
        });
        
        watcher
            .on('add', path => this.emit('file:added', { watcherId, path }))
            .on('change', path => this.emit('file:changed', { watcherId, path }))
            .on('unlink', path => this.emit('file:removed', { watcherId, path }))
            .on('addDir', path => this.emit('directory:added', { watcherId, path }))
            .on('unlinkDir', path => this.emit('directory:removed', { watcherId, path }));
        
        this.fileWatchers.set(watcherId, {
            id: watcherId,
            path: watchPath,
            watcher,
            options,
            createdAt: new Date().toISOString()
        });
        
        return watcherId;
    }
    
    // Webhook Management
    async createWebhook(webhookData) {
        const webhookId = webhookData.id || this.generateId();
        
        const webhook = {
            id: webhookId,
            name: webhookData.name,
            url: webhookData.url,
            events: webhookData.events || [],
            secret: webhookData.secret,
            isActive: webhookData.isActive !== false,
            deliveries: 0,
            lastDelivery: null,
            createdAt: new Date().toISOString(),
            metadata: webhookData.metadata || {}
        };
        
        this.webhookEndpoints.set(webhookId, webhook);
        await this.saveWebhook(webhook);
        
        this.emit('webhook:created', { webhookId, webhook });
        
        return webhookId;
    }
    
    async updateWebhook(webhookId, updates) {
        const webhook = this.webhookEndpoints.get(webhookId);
        if (!webhook) {
            throw new Error('Webhook not found');
        }
        
        Object.assign(webhook, updates, {
            updatedAt: new Date().toISOString()
        });
        
        await this.saveWebhook(webhook);
        this.emit('webhook:updated', { webhookId, webhook });
        
        return webhook;
    }
    
    async deleteWebhook(webhookId) {
        const webhook = this.webhookEndpoints.get(webhookId);
        if (!webhook) return false;
        
        this.webhookEndpoints.delete(webhookId);
        
        try {
            const webhookPath = path.join(this.config.storageDir, 'webhooks', `${webhookId}.json`);
            await fs.unlink(webhookPath);
        } catch (error) {
            console.warn('Failed to delete webhook file:', error);
        }
        
        this.emit('webhook:deleted', { webhookId });
        
        return true;
    }
    
    async deliverWebhook(eventType, data) {
        const deliveries = [];
        
        for (const [webhookId, webhook] of this.webhookEndpoints) {
            if (!webhook.isActive || !webhook.events.includes(eventType)) {
                continue;
            }
            
            try {
                const delivery = await this.sendWebhookPayload(webhook, eventType, data);
                deliveries.push({ webhookId, success: true, delivery });
                
                webhook.deliveries++;
                webhook.lastDelivery = new Date().toISOString();
                
                this.requestStats.webhooks++;
                
            } catch (error) {
                deliveries.push({ webhookId, success: false, error: error.message });
                
                this.emit('webhook:delivery_failed', {
                    webhookId,
                    eventType,
                    error: error.message
                });
            }
        }
        
        return deliveries;
    }
    
    async sendWebhookPayload(webhook, eventType, data) {
        const fetch = require('node-fetch');
        
        const payload = {
            event: eventType,
            timestamp: new Date().toISOString(),
            data
        };
        
        const headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'OpenDirectory-Webhook/1.0'
        };
        
        // Add signature if secret is provided
        if (webhook.secret) {
            const crypto = require('crypto');
            const signature = crypto
                .createHmac('sha256', webhook.secret)
                .update(JSON.stringify(payload))
                .digest('hex');
            
            headers['X-Hub-Signature-256'] = `sha256=${signature}`;
        }
        
        const response = await fetch(webhook.url, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
            timeout: this.config.webhookTimeout
        });
        
        if (!response.ok) {
            throw new Error(`Webhook delivery failed: ${response.status} ${response.statusText}`);
        }
        
        return {
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
            timestamp: new Date().toISOString()
        };
    }
    
    async receiveWebhook(webhookId, payload, headers) {
        this.emit('webhook:received', {
            webhookId,
            payload,
            headers,
            timestamp: new Date().toISOString()
        });
        
        return { received: true };
    }
    
    async testWebhook(webhookId, testPayload = {}) {
        const webhook = this.webhookEndpoints.get(webhookId);
        if (!webhook) {
            throw new Error('Webhook not found');
        }
        
        const testData = {
            test: true,
            timestamp: new Date().toISOString(),
            ...testPayload
        };
        
        try {
            const delivery = await this.sendWebhookPayload(webhook, 'test', testData);
            return { success: true, delivery };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
    
    // Database Connection Management
    setupDatabaseConnection(connectionConfig) {
        const connectionId = connectionConfig.id || this.generateId();
        
        const connection = {
            id: connectionId,
            name: connectionConfig.name,
            type: connectionConfig.type, // mysql, postgresql, mongodb, etc.
            config: connectionConfig.config,
            pool: null,
            connected: false,
            lastQuery: null,
            createdAt: new Date().toISOString()
        };
        
        this.databaseConnections.set(connectionId, connection);
        
        return connectionId;
    }
    
    // Utility Methods
    logRequest(req, res, duration) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration,
            userAgent: req.get('User-Agent'),
            ip: req.ip,
            size: res.get('Content-Length') || 0
        };
        
        // In a real implementation, this would write to a log file or logging service
        if (res.statusCode >= 400) {
            console.error('HTTP Error:', logEntry);
        }
    }
    
    updateRequestStats(statusCode) {
        this.requestStats.total++;
        
        if (statusCode >= 200 && statusCode < 400) {
            this.requestStats.successful++;
        } else {
            this.requestStats.failed++;
        }
    }
    
    async saveWebhook(webhook) {
        try {
            const webhookPath = path.join(this.config.storageDir, 'webhooks', `${webhook.id}.json`);
            await fs.writeFile(webhookPath, JSON.stringify(webhook, null, 2));
        } catch (error) {
            console.error('Failed to save webhook:', error);
        }
    }
    
    startServers() {
        // Start REST API server
        this.server = this.app.listen(this.config.port, () => {
            console.log(`REST API server listening on port ${this.config.port}`);
        });
        
        // Start GraphQL server
        this.graphqlServer = this.graphqlApp.listen(this.config.graphqlPort, () => {
            console.log(`GraphQL server listening on port ${this.config.graphqlPort}`);
        });
    }
    
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }
    
    // Mock data methods (to be replaced with actual implementations)
    async getLdapUsers(filters = {}) {
        // Mock user data
        return [
            {
                id: 'user1',
                username: 'john.doe',
                email: 'john.doe@example.com',
                firstName: 'John',
                lastName: 'Doe',
                department: 'IT',
                status: 'active',
                createdAt: '2024-01-01T00:00:00Z'
            }
        ];
    }
    
    async getLdapUser(userId) {
        // Mock single user
        return {
            id: userId,
            username: 'john.doe',
            email: 'john.doe@example.com',
            firstName: 'John',
            lastName: 'Doe',
            department: 'IT',
            status: 'active',
            groups: ['admin', 'users'],
            createdAt: '2024-01-01T00:00:00Z'
        };
    }
    
    async createLdapUser(userData) {
        // Mock user creation
        const user = {
            id: this.generateId(),
            ...userData,
            status: 'active',
            createdAt: new Date().toISOString()
        };
        
        this.emit('ldap:user_created', user);
        
        return user;
    }
    
    async updateLdapUser(userId, updates) {
        // Mock user update
        const user = {
            id: userId,
            ...updates,
            updatedAt: new Date().toISOString()
        };
        
        this.emit('ldap:user_updated', user);
        
        return user;
    }
    
    async deleteLdapUser(userId) {
        // Mock user deletion
        this.emit('ldap:user_deleted', { userId });
        return true;
    }
    
    async getLdapGroups(filters = {}) {
        // Mock group data
        return [
            {
                id: 'group1',
                name: 'Administrators',
                description: 'System administrators',
                memberCount: 5,
                createdAt: '2024-01-01T00:00:00Z'
            }
        ];
    }
    
    async createLdapGroup(groupData) {
        // Mock group creation
        const group = {
            id: this.generateId(),
            ...groupData,
            memberCount: 0,
            createdAt: new Date().toISOString()
        };
        
        this.emit('ldap:group_created', group);
        
        return group;
    }
    
    // Additional GraphQL resolvers and mock methods would continue here...
    // For brevity, I'll include the essential statistics method
    
    getIntegrationStats() {
        return {
            totalRequests: this.requestStats.total,
            successfulRequests: this.requestStats.successful,
            failedRequests: this.requestStats.failed,
            webhookDeliveries: this.requestStats.webhooks,
            connectorCalls: this.requestStats.connectorCalls,
            activeConnectors: Array.from(this.externalConnectors.values()).filter(c => c.status === 'active').length,
            activeWebhooks: Array.from(this.webhookEndpoints.values()).filter(w => w.isActive).length,
            fileWatchers: this.fileWatchers.size,
            messageQueues: this.messageQueues.size,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        };
    }
    
    getConnectors() {
        return Array.from(this.externalConnectors.values()).map(conn => ({
            id: conn.id,
            name: conn.name,
            type: conn.type,
            status: conn.status,
            lastSync: conn.lastSync,
            config: conn.publicConfig || {}
        }));
    }
    
    getWebhooks() {
        return Array.from(this.webhookEndpoints.values()).map(webhook => ({
            id: webhook.id,
            name: webhook.name,
            url: webhook.url,
            events: webhook.events,
            status: webhook.isActive ? 'active' : 'inactive',
            deliveries: webhook.deliveries,
            lastDelivery: webhook.lastDelivery
        }));
    }
    
    // Placeholder GraphQL handlers
    async handleGraphQLUsers(args) { return await this.getLdapUsers(args.filter); }
    async handleGraphQLUser(args) { return await this.getLdapUser(args.id); }
    async handleGraphQLGroups(args) { return await this.getLdapGroups(args.filter); }
    async handleGraphQLGroup(args) { return { id: args.id, name: 'Sample Group', memberCount: 0 }; }
    async handleGraphQLDevices(args) { return []; }
    async handleGraphQLDevice(args) { return null; }
    async handleGraphQLCertificates(args) { return []; }
    async handleGraphQLCertificate(args) { return null; }
    async handleGraphQLCreateUser(args) { return await this.createLdapUser(args.input); }
    async handleGraphQLUpdateUser(args) { return await this.updateLdapUser(args.id, args.input); }
    async handleGraphQLDeleteUser(args) { return await this.deleteLdapUser(args.id); }
    async handleGraphQLCreateGroup(args) { return await this.createLdapGroup(args.input); }
    async handleGraphQLUpdateGroup(args) { return { id: args.id, ...args.input }; }
    async handleGraphQLDeleteGroup(args) { return true; }
    async handleGraphQLEnrollDevice(args) { return { id: this.generateId(), ...args.input }; }
    async handleGraphQLUpdateDevice(args) { return { id: args.id, ...args.input }; }
    async handleGraphQLRemoveDevice(args) { return true; }
    async handleGraphQLIssueCertificate(args) { return { id: this.generateId(), ...args.input }; }
    async handleGraphQLRevokeCertificate(args) { return true; }
    async handleGraphQLCreateWebhook(args) { 
        const id = await this.createWebhook(args.input);
        return this.webhookEndpoints.get(id);
    }
    async handleGraphQLUpdateWebhook(args) {
        await this.updateWebhook(args.id, args.input);
        return this.webhookEndpoints.get(args.id);
    }
    async handleGraphQLDeleteWebhook(args) { return await this.deleteWebhook(args.id); }
    async handleGraphQLTriggerSync(args) {
        return { success: true, message: `Sync triggered for ${args.connector}`, recordsProcessed: 0, errors: [] };
    }
}

module.exports = { IntegrationHub };