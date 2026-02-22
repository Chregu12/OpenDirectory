/**
 * OpenDirectory Event-Driven Automation System
 * Real-time event processing and automated response system
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

class EventAutomationEngine extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxEventHistory: 10000,
            eventRetentionDays: 30,
            maxCorrelationWindow: 300000, // 5 minutes
            maxWorkers: 4,
            enableReplay: true,
            enableDebugging: true,
            storageDir: config.storageDir || '/tmp/events',
            webhookTimeout: 30000,
            ...config
        };
        
        this.eventHistory = [];
        this.eventFilters = new Map();
        this.eventCorrelations = new Map();
        this.automationRules = new Map();
        this.webhookEndpoints = new Map();
        this.eventWorkers = [];
        this.replayQueues = new Map();
        this.debugSessions = new Map();
        this.eventStats = {
            totalProcessed: 0,
            totalFiltered: 0,
            totalCorrelated: 0,
            totalActionsTriggered: 0,
            errors: 0
        };
        
        this.init();
    }
    
    async init() {
        await this.ensureStorageDir();
        await this.loadAutomationRules();
        await this.initializeWorkers();
        this.startEventProcessor();
        this.startCorrelationEngine();
        this.startCleanupTasks();
        
        // Listen to all system events
        this.setupSystemEventListeners();
        
        this.emit('engine:ready');
        console.log('Event Automation Engine initialized successfully');
    }
    
    async ensureStorageDir() {
        try {
            await fs.mkdir(this.config.storageDir, { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'history'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'rules'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'correlations'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'replays'), { recursive: true });
        } catch (error) {
            console.error('Failed to create storage directories:', error);
        }
    }
    
    setupSystemEventListeners() {
        // Listen to various system events
        const systemEvents = [
            'user:login',
            'user:logout',
            'user:created',
            'user:updated',
            'user:deleted',
            'user:password_changed',
            'user:locked',
            'user:unlocked',
            'device:enrolled',
            'device:updated',
            'device:removed',
            'device:compliance_failed',
            'certificate:issued',
            'certificate:expired',
            'certificate:revoked',
            'group:created',
            'group:updated',
            'group:member_added',
            'group:member_removed',
            'security:failed_login',
            'security:suspicious_activity',
            'security:policy_violation',
            'system:backup_completed',
            'system:backup_failed',
            'system:maintenance_start',
            'system:maintenance_end',
            'application:error',
            'application:performance_issue'
        ];
        
        systemEvents.forEach(eventType => {
            this.on(eventType, (data) => {
                this.processSystemEvent(eventType, data);
            });
        });
    }
    
    async processSystemEvent(eventType, data) {
        const event = {
            id: this.generateId(),
            type: eventType,
            timestamp: new Date().toISOString(),
            data,
            source: 'system',
            processed: false,
            correlationId: null,
            metadata: {
                userId: data.userId,
                deviceId: data.deviceId,
                severity: this.determineEventSeverity(eventType, data),
                tags: this.generateEventTags(eventType, data)
            }
        };
        
        // Add to history
        this.addToEventHistory(event);
        
        // Process through filters and automation rules
        await this.processEvent(event);
        
        this.eventStats.totalProcessed++;
        this.emit('event:processed', event);
    }
    
    determineEventSeverity(eventType, data) {
        const severityMap = {
            'security:failed_login': 'medium',
            'security:suspicious_activity': 'high',
            'security:policy_violation': 'high',
            'user:locked': 'medium',
            'device:compliance_failed': 'medium',
            'certificate:expired': 'high',
            'system:backup_failed': 'high',
            'application:error': 'medium'
        };
        
        return severityMap[eventType] || 'low';
    }
    
    generateEventTags(eventType, data) {
        const tags = [eventType.split(':')[0]]; // Add category tag
        
        if (data.userId) tags.push(`user:${data.userId}`);
        if (data.deviceId) tags.push(`device:${data.deviceId}`);
        if (data.application) tags.push(`app:${data.application}`);
        
        return tags;
    }
    
    addToEventHistory(event) {
        this.eventHistory.push(event);
        
        // Maintain history size limit
        if (this.eventHistory.length > this.config.maxEventHistory) {
            const removed = this.eventHistory.shift();
            this.archiveEvent(removed);
        }
    }
    
    async archiveEvent(event) {
        try {
            const date = new Date(event.timestamp);
            const archiveDir = path.join(
                this.config.storageDir,
                'history',
                date.getFullYear().toString(),
                (date.getMonth() + 1).toString().padStart(2, '0')
            );
            
            await fs.mkdir(archiveDir, { recursive: true });
            
            const filePath = path.join(archiveDir, `${date.getDate()}.jsonl`);
            const eventLine = JSON.stringify(event) + '\n';
            
            await fs.appendFile(filePath, eventLine);
        } catch (error) {
            console.error('Failed to archive event:', error);
        }
    }
    
    // Event Processing
    async processEvent(event) {
        // Apply filters
        const shouldProcess = this.applyEventFilters(event);
        if (!shouldProcess) {
            this.eventStats.totalFiltered++;
            return;
        }
        
        // Check for correlations
        await this.checkEventCorrelations(event);
        
        // Apply automation rules
        await this.applyAutomationRules(event);
        
        event.processed = true;
    }
    
    applyEventFilters(event) {
        for (const [filterId, filter] of this.eventFilters) {
            if (!this.matchesFilter(event, filter)) {
                this.emit('event:filtered', { eventId: event.id, filterId });
                return false;
            }
        }
        return true;
    }
    
    matchesFilter(event, filter) {
        // Type filter
        if (filter.types && !filter.types.includes(event.type)) {
            return false;
        }
        
        // Severity filter
        if (filter.severities && !filter.severities.includes(event.metadata.severity)) {
            return false;
        }
        
        // Tag filter
        if (filter.tags) {
            const hasRequiredTags = filter.tags.every(tag => 
                event.metadata.tags.includes(tag)
            );
            if (!hasRequiredTags) return false;
        }
        
        // User filter
        if (filter.users && (!event.metadata.userId || !filter.users.includes(event.metadata.userId))) {
            return false;
        }
        
        // Custom condition filter
        if (filter.condition) {
            try {
                const vm = require('vm');
                const result = vm.runInNewContext(filter.condition, { event });
                if (!result) return false;
            } catch (error) {
                console.error('Filter condition error:', error);
                return false;
            }
        }
        
        return true;
    }
    
    // Event Correlation
    async checkEventCorrelations(event) {
        for (const [correlationId, correlation] of this.eventCorrelations) {
            if (this.matchesCorrelationPattern(event, correlation)) {
                await this.processCorrelation(event, correlation);
            }
        }
    }
    
    matchesCorrelationPattern(event, correlation) {
        const pattern = correlation.pattern;
        
        // Check if event matches any of the correlation event types
        if (!pattern.eventTypes.includes(event.type)) {
            return false;
        }
        
        // Check time window
        const windowStart = Date.now() - correlation.timeWindow;
        const eventTime = Date.parse(event.timestamp);
        
        if (eventTime < windowStart) {
            return false;
        }
        
        // Check grouping criteria
        if (pattern.groupBy) {
            const groupValue = this.getEventValue(event, pattern.groupBy);
            if (!groupValue) return false;
        }
        
        return true;
    }
    
    async processCorrelation(event, correlation) {
        const groupValue = correlation.pattern.groupBy ? 
            this.getEventValue(event, correlation.pattern.groupBy) : 'default';
        
        const correlationKey = `${correlation.id}:${groupValue}`;
        
        if (!this.recentCorrelations) {
            this.recentCorrelations = new Map();
        }
        
        if (!this.recentCorrelations.has(correlationKey)) {
            this.recentCorrelations.set(correlationKey, {
                events: [],
                firstEvent: event.timestamp,
                lastEvent: event.timestamp
            });
        }
        
        const correlationData = this.recentCorrelations.get(correlationKey);
        correlationData.events.push(event);
        correlationData.lastEvent = event.timestamp;
        
        // Check if correlation threshold is met
        if (correlationData.events.length >= correlation.pattern.threshold) {
            const correlatedEvent = this.createCorrelatedEvent(correlation, correlationData);
            await this.processEvent(correlatedEvent);
            
            this.eventStats.totalCorrelated++;
            this.emit('events:correlated', {
                correlationId: correlation.id,
                eventCount: correlationData.events.length,
                correlatedEvent
            });
            
            // Reset correlation data
            this.recentCorrelations.delete(correlationKey);
        }
    }
    
    createCorrelatedEvent(correlation, correlationData) {
        return {
            id: this.generateId(),
            type: correlation.outputEventType,
            timestamp: new Date().toISOString(),
            data: {
                correlationId: correlation.id,
                eventCount: correlationData.events.length,
                timespan: Date.parse(correlationData.lastEvent) - Date.parse(correlationData.firstEvent),
                events: correlationData.events.map(e => ({
                    id: e.id,
                    type: e.type,
                    timestamp: e.timestamp
                }))
            },
            source: 'correlation',
            processed: false,
            correlationId: correlation.id,
            metadata: {
                severity: correlation.severity || 'medium',
                tags: ['correlation', correlation.id]
            }
        };
    }
    
    getEventValue(event, path) {
        return path.split('.').reduce((obj, key) => obj && obj[key], event);
    }
    
    // Automation Rules
    async applyAutomationRules(event) {
        for (const [ruleId, rule] of this.automationRules) {
            if (this.matchesAutomationRule(event, rule)) {
                await this.executeAutomationActions(event, rule);
            }
        }
    }
    
    matchesAutomationRule(event, rule) {
        // Check if rule is active
        if (!rule.isActive) return false;
        
        // Check event type
        if (rule.trigger.eventTypes && !rule.trigger.eventTypes.includes(event.type)) {
            return false;
        }
        
        // Check conditions
        if (rule.trigger.conditions) {
            try {
                const vm = require('vm');
                const result = vm.runInNewContext(rule.trigger.conditions, { event });
                if (!result) return false;
            } catch (error) {
                console.error('Rule condition error:', error);
                return false;
            }
        }
        
        // Check rate limiting
        if (rule.rateLimiting && !this.checkRateLimit(rule.id, rule.rateLimiting)) {
            return false;
        }
        
        return true;
    }
    
    checkRateLimit(ruleId, rateLimiting) {
        if (!this.rateLimitData) {
            this.rateLimitData = new Map();
        }
        
        const now = Date.now();
        const key = `${ruleId}:${rateLimiting.window}`;
        
        if (!this.rateLimitData.has(key)) {
            this.rateLimitData.set(key, { count: 0, windowStart: now });
        }
        
        const data = this.rateLimitData.get(key);
        
        // Reset window if expired
        if (now - data.windowStart > rateLimiting.window) {
            data.count = 0;
            data.windowStart = now;
        }
        
        // Check limit
        if (data.count >= rateLimiting.maxExecutions) {
            return false;
        }
        
        data.count++;
        return true;
    }
    
    async executeAutomationActions(event, rule) {
        for (const action of rule.actions) {
            try {
                await this.executeAction(action, event, rule);
                
                this.emit('action:executed', {
                    ruleId: rule.id,
                    actionType: action.type,
                    eventId: event.id
                });
                
                this.eventStats.totalActionsTriggered++;
            } catch (error) {
                console.error(`Failed to execute action ${action.type}:`, error);
                
                this.emit('action:failed', {
                    ruleId: rule.id,
                    actionType: action.type,
                    eventId: event.id,
                    error: error.message
                });
                
                this.eventStats.errors++;
            }
        }
    }
    
    async executeAction(action, event, rule) {
        switch (action.type) {
            case 'webhook':
                return await this.executeWebhookAction(action, event);
            case 'email':
                return await this.executeEmailAction(action, event);
            case 'sms':
                return await this.executeSmsAction(action, event);
            case 'notification':
                return await this.executeNotificationAction(action, event);
            case 'ldap_operation':
                return await this.executeLdapAction(action, event);
            case 'workflow':
                return await this.executeWorkflowAction(action, event);
            case 'script':
                return await this.executeScriptAction(action, event);
            case 'api_call':
                return await this.executeApiCallAction(action, event);
            case 'database':
                return await this.executeDatabaseAction(action, event);
            case 'file_operation':
                return await this.executeFileAction(action, event);
            default:
                throw new Error(`Unknown action type: ${action.type}`);
        }
    }
    
    async executeWebhookAction(action, event) {
        const { url, method = 'POST', headers = {}, payload } = action.config;
        const fetch = require('node-fetch');
        const AbortController = require('abort-controller');
        
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.config.webhookTimeout);
        
        try {
            const processedPayload = this.replaceVariables(
                JSON.stringify(payload || event), 
                { event, timestamp: new Date().toISOString() }
            );
            
            const response = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'OpenDirectory-EventAutomation/1.0',
                    ...headers
                },
                body: processedPayload,
                signal: controller.signal
            });
            
            clearTimeout(timeout);
            
            return {
                status: response.status,
                statusText: response.statusText,
                success: response.ok
            };
        } catch (error) {
            clearTimeout(timeout);
            throw new Error(`Webhook action failed: ${error.message}`);
        }
    }
    
    async executeEmailAction(action, event) {
        const { to, cc, bcc, subject, body, attachments = [] } = action.config;
        
        const emailData = {
            to: this.replaceVariables(to, { event }),
            cc: cc ? this.replaceVariables(cc, { event }) : null,
            bcc: bcc ? this.replaceVariables(bcc, { event }) : null,
            subject: this.replaceVariables(subject, { event }),
            body: this.replaceVariables(body, { event }),
            attachments
        };
        
        // Emit email event for external email service to handle
        this.emit('email:send', emailData);
        
        return { sent: true, recipients: emailData.to };
    }
    
    async executeSmsAction(action, event) {
        const { to, message } = action.config;
        
        const smsData = {
            to: this.replaceVariables(to, { event }),
            message: this.replaceVariables(message, { event })
        };
        
        // Emit SMS event for external SMS service to handle
        this.emit('sms:send', smsData);
        
        return { sent: true, recipient: smsData.to };
    }
    
    async executeNotificationAction(action, event) {
        const { type, recipients, title, message, priority = 'normal' } = action.config;
        
        const notification = {
            type,
            recipients: this.replaceVariables(JSON.stringify(recipients), { event }),
            title: this.replaceVariables(title, { event }),
            message: this.replaceVariables(message, { event }),
            priority,
            timestamp: new Date().toISOString(),
            eventId: event.id
        };
        
        this.emit('notification:send', notification);
        
        return { sent: true, type, recipients: notification.recipients };
    }
    
    async executeLdapAction(action, event) {
        const { operation, dn, attributes, filter } = action.config;
        
        // Process LDAP operation based on event data
        const processedDn = this.replaceVariables(dn, { event });
        const processedFilter = filter ? this.replaceVariables(filter, { event }) : null;
        
        // Emit LDAP operation for LDAP service to handle
        this.emit('ldap:operation', {
            operation,
            dn: processedDn,
            attributes: this.replaceVariables(JSON.stringify(attributes || {}), { event }),
            filter: processedFilter,
            eventId: event.id
        });
        
        return { operation, dn: processedDn, success: true };
    }
    
    async executeWorkflowAction(action, event) {
        const { workflowId, context = {} } = action.config;
        
        const workflowContext = {
            ...context,
            triggerEvent: event,
            timestamp: new Date().toISOString()
        };
        
        // Process context variables
        const processedContext = JSON.parse(
            this.replaceVariables(JSON.stringify(workflowContext), { event })
        );
        
        this.emit('workflow:trigger', {
            workflowId,
            context: processedContext,
            triggeredBy: 'event_automation',
            eventId: event.id
        });
        
        return { workflowId, triggered: true };
    }
    
    async executeScriptAction(action, event) {
        const { script, language = 'javascript', timeout = 30000 } = action.config;
        
        if (language === 'javascript') {
            const vm = require('vm');
            const sandbox = {
                event,
                console,
                setTimeout,
                setInterval,
                clearTimeout,
                clearInterval,
                result: null,
                emit: (eventType, data) => this.emit(eventType, data)
            };
            
            const processedScript = this.replaceVariables(script, { event });
            
            try {
                vm.runInNewContext(processedScript, sandbox, { timeout });
                return { success: true, result: sandbox.result };
            } catch (error) {
                throw new Error(`Script execution failed: ${error.message}`);
            }
        }
        
        throw new Error(`Unsupported script language: ${language}`);
    }
    
    async executeApiCallAction(action, event) {
        const { url, method = 'GET', headers = {}, data } = action.config;
        const fetch = require('node-fetch');
        
        const processedUrl = this.replaceVariables(url, { event });
        const processedData = data ? this.replaceVariables(JSON.stringify(data), { event }) : null;
        
        try {
            const response = await fetch(processedUrl, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers
                },
                body: processedData
            });
            
            const responseData = await response.json();
            return {
                status: response.status,
                data: responseData,
                success: response.ok
            };
        } catch (error) {
            throw new Error(`API call failed: ${error.message}`);
        }
    }
    
    async executeDatabaseAction(action, event) {
        const { query, parameters = [] } = action.config;
        
        const processedQuery = this.replaceVariables(query, { event });
        const processedParams = parameters.map(param => 
            this.replaceVariables(param.toString(), { event })
        );
        
        this.emit('database:execute', {
            query: processedQuery,
            parameters: processedParams,
            eventId: event.id
        });
        
        return { query: processedQuery, executed: true };
    }
    
    async executeFileAction(action, event) {
        const { operation, path: filePath, content } = action.config;
        
        const processedPath = this.replaceVariables(filePath, { event });
        const processedContent = content ? this.replaceVariables(content, { event }) : null;
        
        try {
            switch (operation) {
                case 'write':
                    await fs.writeFile(processedPath, processedContent);
                    break;
                case 'append':
                    await fs.appendFile(processedPath, processedContent);
                    break;
                case 'delete':
                    await fs.unlink(processedPath);
                    break;
                default:
                    throw new Error(`Unknown file operation: ${operation}`);
            }
            
            return { operation, path: processedPath, success: true };
        } catch (error) {
            throw new Error(`File operation failed: ${error.message}`);
        }
    }
    
    replaceVariables(template, context) {
        if (typeof template !== 'string') return template;
        
        return template.replace(/\{\{(.+?)\}\}/g, (match, path) => {
            const value = this.getValueByPath(context, path.trim());
            return value !== undefined ? value : match;
        });
    }
    
    getValueByPath(obj, path) {
        return path.split('.').reduce((current, key) => current && current[key], obj);
    }
    
    // Event Replay and Debugging
    async startEventReplay(replayId, options = {}) {
        const { startTime, endTime, eventTypes, filters } = options;
        
        const replayQueue = await this.buildReplayQueue(startTime, endTime, eventTypes, filters);
        this.replayQueues.set(replayId, {
            queue: replayQueue,
            currentIndex: 0,
            isPlaying: false,
            speed: options.speed || 1,
            metadata: {
                totalEvents: replayQueue.length,
                startTime: new Date().toISOString()
            }
        });
        
        this.emit('replay:created', { replayId, totalEvents: replayQueue.length });
        return replayId;
    }
    
    async buildReplayQueue(startTime, endTime, eventTypes, filters) {
        // Build queue from archived events
        const events = [];
        
        // Add current history events
        const filteredHistory = this.eventHistory.filter(event => {
            if (startTime && Date.parse(event.timestamp) < Date.parse(startTime)) return false;
            if (endTime && Date.parse(event.timestamp) > Date.parse(endTime)) return false;
            if (eventTypes && !eventTypes.includes(event.type)) return false;
            
            return true;
        });
        
        events.push(...filteredHistory);
        
        // TODO: Load from archived files if needed
        
        return events.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    }
    
    playEventReplay(replayId) {
        const replay = this.replayQueues.get(replayId);
        if (!replay) throw new Error('Replay not found');
        
        replay.isPlaying = true;
        this.processReplayQueue(replayId);
        
        this.emit('replay:started', { replayId });
    }
    
    pauseEventReplay(replayId) {
        const replay = this.replayQueues.get(replayId);
        if (!replay) throw new Error('Replay not found');
        
        replay.isPlaying = false;
        this.emit('replay:paused', { replayId });
    }
    
    async processReplayQueue(replayId) {
        const replay = this.replayQueues.get(replayId);
        if (!replay || !replay.isPlaying) return;
        
        if (replay.currentIndex >= replay.queue.length) {
            replay.isPlaying = false;
            this.emit('replay:completed', { replayId });
            return;
        }
        
        const event = replay.queue[replay.currentIndex];
        replay.currentIndex++;
        
        // Replay the event
        this.emit(`replay:${event.type}`, {
            ...event,
            isReplay: true,
            replayId
        });
        
        this.emit('replay:event', { replayId, event, progress: replay.currentIndex / replay.queue.length });
        
        // Schedule next event based on speed
        setTimeout(() => {
            this.processReplayQueue(replayId);
        }, 1000 / replay.speed);
    }
    
    // Debugging
    startDebugSession(sessionId, options = {}) {
        const debugSession = {
            id: sessionId,
            isActive: true,
            filters: options.filters || {},
            capturedEvents: [],
            maxCapture: options.maxCapture || 1000,
            startTime: new Date().toISOString()
        };
        
        this.debugSessions.set(sessionId, debugSession);
        this.emit('debug:session_started', { sessionId });
        
        return sessionId;
    }
    
    captureDebugEvent(event) {
        for (const [sessionId, session] of this.debugSessions) {
            if (!session.isActive) continue;
            
            if (this.matchesDebugFilters(event, session.filters)) {
                session.capturedEvents.push({
                    ...event,
                    captureTime: new Date().toISOString()
                });
                
                // Maintain capture limit
                if (session.capturedEvents.length > session.maxCapture) {
                    session.capturedEvents.shift();
                }
                
                this.emit('debug:event_captured', { sessionId, eventId: event.id });
            }
        }
    }
    
    matchesDebugFilters(event, filters) {
        if (filters.eventTypes && !filters.eventTypes.includes(event.type)) {
            return false;
        }
        
        if (filters.severity && event.metadata.severity !== filters.severity) {
            return false;
        }
        
        return true;
    }
    
    getDebugSession(sessionId) {
        return this.debugSessions.get(sessionId);
    }
    
    stopDebugSession(sessionId) {
        const session = this.debugSessions.get(sessionId);
        if (session) {
            session.isActive = false;
            session.endTime = new Date().toISOString();
            this.emit('debug:session_stopped', { sessionId });
        }
        
        return session;
    }
    
    // Management APIs
    createEventFilter(filter) {
        const filterId = filter.id || this.generateId();
        
        const eventFilter = {
            id: filterId,
            name: filter.name,
            description: filter.description,
            types: filter.types,
            severities: filter.severities,
            tags: filter.tags,
            users: filter.users,
            condition: filter.condition,
            isActive: filter.isActive !== false,
            metadata: {
                created: new Date().toISOString(),
                createdBy: filter.createdBy
            }
        };
        
        this.eventFilters.set(filterId, eventFilter);
        this.emit('filter:created', { filterId });
        
        return filterId;
    }
    
    createCorrelationRule(correlation) {
        const correlationId = correlation.id || this.generateId();
        
        const correlationRule = {
            id: correlationId,
            name: correlation.name,
            description: correlation.description,
            pattern: {
                eventTypes: correlation.eventTypes,
                threshold: correlation.threshold || 5,
                groupBy: correlation.groupBy
            },
            timeWindow: correlation.timeWindow || 300000,
            outputEventType: correlation.outputEventType,
            severity: correlation.severity || 'medium',
            isActive: correlation.isActive !== false,
            metadata: {
                created: new Date().toISOString(),
                createdBy: correlation.createdBy
            }
        };
        
        this.eventCorrelations.set(correlationId, correlationRule);
        this.emit('correlation:created', { correlationId });
        
        return correlationId;
    }
    
    createAutomationRule(rule) {
        const ruleId = rule.id || this.generateId();
        
        const automationRule = {
            id: ruleId,
            name: rule.name,
            description: rule.description,
            trigger: {
                eventTypes: rule.eventTypes,
                conditions: rule.conditions
            },
            actions: rule.actions,
            rateLimiting: rule.rateLimiting,
            isActive: rule.isActive !== false,
            metadata: {
                created: new Date().toISOString(),
                createdBy: rule.createdBy,
                executions: 0,
                lastExecuted: null
            }
        };
        
        this.automationRules.set(ruleId, automationRule);
        this.emit('rule:created', { ruleId });
        
        return ruleId;
    }
    
    createWebhookEndpoint(endpoint) {
        const webhookId = endpoint.id || this.generateId();
        
        const webhookEndpoint = {
            id: webhookId,
            name: endpoint.name,
            url: endpoint.url,
            secret: endpoint.secret,
            eventTypes: endpoint.eventTypes || [],
            isActive: endpoint.isActive !== false,
            metadata: {
                created: new Date().toISOString(),
                createdBy: endpoint.createdBy,
                deliveries: 0,
                lastDelivery: null
            }
        };
        
        this.webhookEndpoints.set(webhookId, webhookEndpoint);
        this.emit('webhook:created', { webhookId });
        
        return webhookId;
    }
    
    // Worker Management
    async initializeWorkers() {
        if (!isMainThread) return;
        
        for (let i = 0; i < this.config.maxWorkers; i++) {
            const worker = new Worker(__filename, {
                workerData: { isWorker: true, workerId: i }
            });
            
            worker.on('message', (message) => {
                this.handleWorkerMessage(message);
            });
            
            worker.on('error', (error) => {
                console.error(`Worker ${i} error:`, error);
            });
            
            this.eventWorkers.push(worker);
        }
        
        console.log(`Initialized ${this.config.maxWorkers} event processing workers`);
    }
    
    handleWorkerMessage(message) {
        switch (message.type) {
            case 'event_processed':
                this.emit('worker:event_processed', message.data);
                break;
            case 'error':
                console.error('Worker error:', message.error);
                break;
        }
    }
    
    // Utility Methods
    startEventProcessor() {
        // Process events periodically
        setInterval(() => {
            // Capture events for debugging
            this.eventHistory.slice(-10).forEach(event => {
                this.captureDebugEvent(event);
            });
        }, 1000);
        
        console.log('Event processor started');
    }
    
    startCorrelationEngine() {
        // Clean up old correlation data periodically
        setInterval(() => {
            if (this.recentCorrelations) {
                const cutoffTime = Date.now() - this.config.maxCorrelationWindow;
                for (const [key, data] of this.recentCorrelations) {
                    if (Date.parse(data.lastEvent) < cutoffTime) {
                        this.recentCorrelations.delete(key);
                    }
                }
            }
        }, 60000); // Clean every minute
        
        console.log('Correlation engine started');
    }
    
    startCleanupTasks() {
        // Archive old events periodically
        setInterval(async () => {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - this.config.eventRetentionDays);
            
            const toArchive = this.eventHistory.filter(event => 
                Date.parse(event.timestamp) < cutoffDate.getTime()
            );
            
            for (const event of toArchive) {
                await this.archiveEvent(event);
                const index = this.eventHistory.indexOf(event);
                if (index > -1) {
                    this.eventHistory.splice(index, 1);
                }
            }
            
            if (toArchive.length > 0) {
                console.log(`Archived ${toArchive.length} old events`);
            }
        }, 3600000); // Run every hour
        
        console.log('Cleanup tasks started');
    }
    
    async loadAutomationRules() {
        // Load built-in rules and saved rules
        // This would load from configuration files
        console.log('Loaded automation rules');
    }
    
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }
    
    // API Methods
    getEventHistory(options = {}) {
        const { limit = 100, offset = 0, eventTypes, since } = options;
        
        let filtered = this.eventHistory;
        
        if (eventTypes) {
            filtered = filtered.filter(event => eventTypes.includes(event.type));
        }
        
        if (since) {
            filtered = filtered.filter(event => Date.parse(event.timestamp) >= Date.parse(since));
        }
        
        return {
            events: filtered.slice(offset, offset + limit),
            total: filtered.length,
            hasMore: offset + limit < filtered.length
        };
    }
    
    getEngineStats() {
        return {
            ...this.eventStats,
            activeFilters: this.eventFilters.size,
            activeCorrelations: this.eventCorrelations.size,
            activeRules: this.automationRules.size,
            activeWebhooks: this.webhookEndpoints.size,
            debugSessions: this.debugSessions.size,
            replayQueues: this.replayQueues.size,
            historySize: this.eventHistory.length,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        };
    }
}

// Worker thread code
if (!isMainThread && workerData && workerData.isWorker) {
    // Event processing worker
    parentPort.on('message', (message) => {
        try {
            // Process event in worker thread
            // This would contain heavy event processing logic
            
            parentPort.postMessage({
                type: 'event_processed',
                data: { eventId: message.eventId, workerId: workerData.workerId }
            });
        } catch (error) {
            parentPort.postMessage({
                type: 'error',
                error: error.message
            });
        }
    });
}

module.exports = { EventAutomationEngine };