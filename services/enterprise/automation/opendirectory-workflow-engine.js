/**
 * OpenDirectory Workflow Automation Engine
 * Advanced workflow orchestration and automation system
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class WorkflowEngine extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxConcurrentWorkflows: 100,
            maxRetries: 3,
            retryDelay: 5000,
            workflowTimeout: 300000, // 5 minutes
            storageDir: config.storageDir || '/tmp/workflows',
            enableVersioning: true,
            enableAuditTrail: true,
            ...config
        };
        
        this.workflows = new Map();
        this.templates = new Map();
        this.activeExecutions = new Map();
        this.executionQueue = [];
        this.scheduledWorkflows = new Map();
        this.approvalQueue = new Map();
        this.versions = new Map();
        
        this.init();
    }
    
    async init() {
        await this.ensureStorageDir();
        await this.loadWorkflowTemplates();
        this.startExecutionEngine();
        this.startScheduler();
        
        this.emit('engine:ready');
        console.log('Workflow Engine initialized successfully');
    }
    
    async ensureStorageDir() {
        try {
            await fs.mkdir(this.config.storageDir, { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'templates'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'executions'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'versions'), { recursive: true });
        } catch (error) {
            console.error('Failed to create storage directories:', error);
        }
    }
    
    // Workflow Template Management
    async createWorkflowTemplate(template) {
        const templateId = template.id || this.generateId();
        const version = this.config.enableVersioning ? this.getNextVersion(templateId) : '1.0.0';
        
        const workflowTemplate = {
            id: templateId,
            name: template.name,
            description: template.description,
            version,
            category: template.category || 'general',
            steps: template.steps,
            triggers: template.triggers || [],
            conditions: template.conditions || {},
            variables: template.variables || {},
            settings: {
                timeout: template.timeout || this.config.workflowTimeout,
                retries: template.retries || this.config.maxRetries,
                parallel: template.parallel || false,
                requiresApproval: template.requiresApproval || false,
                approvers: template.approvers || []
            },
            metadata: {
                created: new Date().toISOString(),
                createdBy: template.createdBy,
                tags: template.tags || [],
                priority: template.priority || 'medium'
            }
        };
        
        // Validate workflow template
        this.validateWorkflowTemplate(workflowTemplate);
        
        this.templates.set(templateId, workflowTemplate);
        
        if (this.config.enableVersioning) {
            await this.saveTemplateVersion(workflowTemplate);
        }
        
        await this.saveTemplate(workflowTemplate);
        
        this.emit('template:created', { templateId, version });
        return { templateId, version };
    }
    
    validateWorkflowTemplate(template) {
        if (!template.name) throw new Error('Workflow template must have a name');
        if (!template.steps || !Array.isArray(template.steps) || template.steps.length === 0) {
            throw new Error('Workflow template must have at least one step');
        }
        
        // Validate steps
        template.steps.forEach((step, index) => {
            if (!step.id) throw new Error(`Step ${index} must have an id`);
            if (!step.type) throw new Error(`Step ${index} must have a type`);
            if (!step.action) throw new Error(`Step ${index} must have an action`);
        });
        
        // Validate triggers
        if (template.triggers) {
            template.triggers.forEach(trigger => {
                if (!trigger.type) throw new Error('Trigger must have a type');
                if (!trigger.event && !trigger.schedule) {
                    throw new Error('Trigger must have either event or schedule');
                }
            });
        }
    }
    
    // Workflow Execution
    async executeWorkflow(templateId, context = {}, options = {}) {
        const template = this.templates.get(templateId);
        if (!template) {
            throw new Error(`Workflow template ${templateId} not found`);
        }
        
        const executionId = this.generateId();
        const execution = {
            id: executionId,
            templateId,
            template: { ...template },
            context,
            options,
            status: 'pending',
            currentStep: null,
            stepResults: {},
            errors: [],
            retryCount: 0,
            startTime: null,
            endTime: null,
            metadata: {
                triggeredBy: options.triggeredBy || 'manual',
                priority: template.metadata.priority,
                timeout: template.settings.timeout
            }
        };
        
        // Check if approval is required
        if (template.settings.requiresApproval) {
            return await this.submitForApproval(execution);
        }
        
        return await this.startExecution(execution);
    }
    
    async submitForApproval(execution) {
        execution.status = 'pending_approval';
        this.approvalQueue.set(execution.id, execution);
        
        // Notify approvers
        const approvers = execution.template.settings.approvers;
        this.emit('approval:required', {
            executionId: execution.id,
            workflowName: execution.template.name,
            approvers,
            context: execution.context
        });
        
        await this.saveExecution(execution);
        return { executionId: execution.id, status: 'pending_approval' };
    }
    
    async approveWorkflow(executionId, approverId, approved = true, comments = '') {
        const execution = this.approvalQueue.get(executionId);
        if (!execution) {
            throw new Error('Execution not found in approval queue');
        }
        
        if (!approved) {
            execution.status = 'rejected';
            execution.metadata.rejectedBy = approverId;
            execution.metadata.rejectionComments = comments;
            this.approvalQueue.delete(executionId);
            
            this.emit('workflow:rejected', { executionId, approverId, comments });
            await this.saveExecution(execution);
            return { status: 'rejected' };
        }
        
        execution.metadata.approvedBy = approverId;
        execution.metadata.approvalComments = comments;
        this.approvalQueue.delete(executionId);
        
        return await this.startExecution(execution);
    }
    
    async startExecution(execution) {
        if (this.activeExecutions.size >= this.config.maxConcurrentWorkflows) {
            this.executionQueue.push(execution);
            this.emit('execution:queued', { executionId: execution.id });
            return { executionId: execution.id, status: 'queued' };
        }
        
        execution.status = 'running';
        execution.startTime = new Date().toISOString();
        this.activeExecutions.set(execution.id, execution);
        
        this.emit('execution:started', { executionId: execution.id });
        
        // Set execution timeout
        setTimeout(() => {
            this.timeoutExecution(execution.id);
        }, execution.metadata.timeout);
        
        // Start executing steps
        this.executeNextStep(execution.id);
        
        await this.saveExecution(execution);
        return { executionId: execution.id, status: 'running' };
    }
    
    async executeNextStep(executionId) {
        const execution = this.activeExecutions.get(executionId);
        if (!execution) return;
        
        try {
            const nextStep = this.getNextStep(execution);
            if (!nextStep) {
                await this.completeExecution(executionId);
                return;
            }
            
            execution.currentStep = nextStep.id;
            this.emit('step:started', { executionId, stepId: nextStep.id });
            
            const stepResult = await this.executeStep(execution, nextStep);
            execution.stepResults[nextStep.id] = stepResult;
            
            this.emit('step:completed', { executionId, stepId: nextStep.id, result: stepResult });
            
            // Check for conditional branching
            if (nextStep.conditions) {
                const conditionResult = this.evaluateConditions(nextStep.conditions, execution.context, stepResult);
                if (!conditionResult) {
                    execution.currentStep = null;
                    await this.executeNextStep(executionId);
                    return;
                }
            }
            
            // Handle parallel execution
            if (nextStep.parallel && nextStep.parallelSteps) {
                await this.executeParallelSteps(execution, nextStep.parallelSteps);
            }
            
            // Continue to next step
            execution.currentStep = null;
            await this.executeNextStep(executionId);
            
        } catch (error) {
            await this.handleStepError(executionId, error);
        }
    }
    
    async executeStep(execution, step) {
        switch (step.type) {
            case 'http_request':
                return await this.executeHttpRequest(step, execution.context);
            case 'email':
                return await this.executeEmailStep(step, execution.context);
            case 'ldap_operation':
                return await this.executeLdapOperation(step, execution.context);
            case 'script':
                return await this.executeScript(step, execution.context);
            case 'approval':
                return await this.executeApprovalStep(step, execution.context);
            case 'wait':
                return await this.executeWaitStep(step, execution.context);
            case 'condition':
                return await this.executeConditionStep(step, execution.context);
            case 'loop':
                return await this.executeLoopStep(step, execution);
            case 'webhook':
                return await this.executeWebhookStep(step, execution.context);
            case 'notification':
                return await this.executeNotificationStep(step, execution.context);
            default:
                throw new Error(`Unknown step type: ${step.type}`);
        }
    }
    
    async executeHttpRequest(step, context) {
        const { method = 'GET', url, headers = {}, body, timeout = 30000 } = step.action;
        
        // Replace variables in URL and body
        const processedUrl = this.replaceVariables(url, context);
        const processedBody = body ? this.replaceVariables(JSON.stringify(body), context) : null;
        
        const fetch = require('node-fetch');
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        try {
            const response = await fetch(processedUrl, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers
                },
                body: processedBody,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            const responseData = await response.json();
            return {
                status: response.status,
                statusText: response.statusText,
                data: responseData,
                success: response.ok
            };
        } catch (error) {
            clearTimeout(timeoutId);
            throw new Error(`HTTP request failed: ${error.message}`);
        }
    }
    
    async executeLdapOperation(step, context) {
        const { operation, dn, attributes, filter } = step.action;
        
        // Mock LDAP operation for demonstration
        console.log(`Executing LDAP ${operation} on ${dn}`);
        
        return {
            operation,
            dn: this.replaceVariables(dn, context),
            success: true,
            result: `LDAP ${operation} completed successfully`
        };
    }
    
    async executeScript(step, context) {
        const { script, language = 'javascript', timeout = 30000 } = step.action;
        
        if (language === 'javascript') {
            // Create a sandboxed environment
            const vm = require('vm');
            const sandbox = {
                context,
                console,
                setTimeout,
                setInterval,
                clearTimeout,
                clearInterval,
                result: null
            };
            
            const processedScript = this.replaceVariables(script, context);
            
            try {
                vm.runInNewContext(processedScript, sandbox, { timeout });
                return { success: true, result: sandbox.result };
            } catch (error) {
                throw new Error(`Script execution failed: ${error.message}`);
            }
        }
        
        throw new Error(`Unsupported script language: ${language}`);
    }
    
    async executeEmailStep(step, context) {
        const { to, subject, body, attachments = [] } = step.action;
        
        const processedTo = this.replaceVariables(to, context);
        const processedSubject = this.replaceVariables(subject, context);
        const processedBody = this.replaceVariables(body, context);
        
        // Mock email sending
        console.log(`Sending email to ${processedTo}: ${processedSubject}`);
        
        return {
            to: processedTo,
            subject: processedSubject,
            sent: true,
            messageId: this.generateId()
        };
    }
    
    async executeWaitStep(step, context) {
        const { duration } = step.action;
        const waitTime = this.replaceVariables(duration.toString(), context);
        
        await new Promise(resolve => setTimeout(resolve, parseInt(waitTime)));
        
        return { waited: parseInt(waitTime), success: true };
    }
    
    async executeConditionStep(step, context) {
        const { condition } = step.action;
        const result = this.evaluateConditions(condition, context);
        
        return { condition, result, success: true };
    }
    
    async executeLoopStep(step, execution) {
        const { items, itemVariable, steps } = step.action;
        const results = [];
        
        const itemsToProcess = this.replaceVariables(JSON.stringify(items), execution.context);
        const parsedItems = JSON.parse(itemsToProcess);
        
        for (const item of parsedItems) {
            // Create new context with loop item
            const loopContext = {
                ...execution.context,
                [itemVariable]: item
            };
            
            const loopResults = {};
            for (const loopStep of steps) {
                const tempExecution = { ...execution, context: loopContext };
                const stepResult = await this.executeStep(tempExecution, loopStep);
                loopResults[loopStep.id] = stepResult;
            }
            
            results.push({ item, results: loopResults });
        }
        
        return { iterations: results.length, results, success: true };
    }
    
    async executeWebhookStep(step, context) {
        const { url, method = 'POST', payload } = step.action;
        
        const processedUrl = this.replaceVariables(url, context);
        const processedPayload = payload ? this.replaceVariables(JSON.stringify(payload), context) : null;
        
        const fetch = require('node-fetch');
        
        try {
            const response = await fetch(processedUrl, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: processedPayload
            });
            
            return {
                url: processedUrl,
                status: response.status,
                success: response.ok
            };
        } catch (error) {
            throw new Error(`Webhook execution failed: ${error.message}`);
        }
    }
    
    async executeNotificationStep(step, context) {
        const { type, recipients, message, title } = step.action;
        
        const processedMessage = this.replaceVariables(message, context);
        const processedTitle = title ? this.replaceVariables(title, context) : null;
        
        this.emit('notification:send', {
            type,
            recipients: this.replaceVariables(JSON.stringify(recipients), context),
            message: processedMessage,
            title: processedTitle
        });
        
        return { type, recipients, sent: true };
    }
    
    async executeParallelSteps(execution, parallelSteps) {
        const promises = parallelSteps.map(step => this.executeStep(execution, step));
        const results = await Promise.allSettled(promises);
        
        const parallelResults = {};
        results.forEach((result, index) => {
            const step = parallelSteps[index];
            if (result.status === 'fulfilled') {
                parallelResults[step.id] = result.value;
            } else {
                parallelResults[step.id] = { error: result.reason.message, success: false };
            }
        });
        
        return parallelResults;
    }
    
    getNextStep(execution) {
        const steps = execution.template.steps;
        const currentStepIndex = execution.currentStep ? 
            steps.findIndex(s => s.id === execution.currentStep) : -1;
        
        return steps[currentStepIndex + 1] || null;
    }
    
    evaluateConditions(conditions, context, stepResult = null) {
        // Simple condition evaluation - can be extended
        if (typeof conditions === 'string') {
            return this.evaluateExpression(conditions, context, stepResult);
        }
        
        if (conditions.and) {
            return conditions.and.every(cond => this.evaluateConditions(cond, context, stepResult));
        }
        
        if (conditions.or) {
            return conditions.or.some(cond => this.evaluateConditions(cond, context, stepResult));
        }
        
        if (conditions.not) {
            return !this.evaluateConditions(conditions.not, context, stepResult);
        }
        
        return true;
    }
    
    evaluateExpression(expression, context, stepResult) {
        // Replace variables and evaluate
        const processedExpression = this.replaceVariables(expression, { ...context, stepResult });
        
        try {
            const vm = require('vm');
            return vm.runInNewContext(processedExpression, { 
                ...context, 
                stepResult,
                Math,
                Date,
                JSON
            });
        } catch (error) {
            console.error('Failed to evaluate expression:', expression, error);
            return false;
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
    
    async handleStepError(executionId, error) {
        const execution = this.activeExecutions.get(executionId);
        if (!execution) return;
        
        execution.errors.push({
            step: execution.currentStep,
            error: error.message,
            timestamp: new Date().toISOString()
        });
        
        this.emit('step:error', { 
            executionId, 
            stepId: execution.currentStep, 
            error: error.message 
        });
        
        // Check if we should retry
        if (execution.retryCount < execution.template.settings.retries) {
            execution.retryCount++;
            execution.currentStep = null;
            
            setTimeout(() => {
                this.executeNextStep(executionId);
            }, this.config.retryDelay);
            
            this.emit('execution:retry', { 
                executionId, 
                retryCount: execution.retryCount 
            });
            return;
        }
        
        // Mark execution as failed
        execution.status = 'failed';
        execution.endTime = new Date().toISOString();
        this.activeExecutions.delete(executionId);
        
        this.emit('execution:failed', { 
            executionId, 
            error: error.message,
            errors: execution.errors
        });
        
        await this.saveExecution(execution);
        this.processQueue();
    }
    
    async completeExecution(executionId) {
        const execution = this.activeExecutions.get(executionId);
        if (!execution) return;
        
        execution.status = 'completed';
        execution.endTime = new Date().toISOString();
        this.activeExecutions.delete(executionId);
        
        this.emit('execution:completed', { 
            executionId,
            duration: Date.parse(execution.endTime) - Date.parse(execution.startTime),
            results: execution.stepResults
        });
        
        await this.saveExecution(execution);
        this.processQueue();
    }
    
    timeoutExecution(executionId) {
        const execution = this.activeExecutions.get(executionId);
        if (!execution) return;
        
        execution.status = 'timeout';
        execution.endTime = new Date().toISOString();
        this.activeExecutions.delete(executionId);
        
        this.emit('execution:timeout', { executionId });
        
        this.saveExecution(execution);
        this.processQueue();
    }
    
    processQueue() {
        if (this.executionQueue.length === 0) return;
        if (this.activeExecutions.size >= this.config.maxConcurrentWorkflows) return;
        
        const nextExecution = this.executionQueue.shift();
        this.startExecution(nextExecution);
    }
    
    // Scheduled Workflow Management
    scheduleWorkflow(templateId, schedule, context = {}, options = {}) {
        const scheduleId = this.generateId();
        const cron = require('node-cron');
        
        const scheduledWorkflow = {
            id: scheduleId,
            templateId,
            schedule,
            context,
            options,
            isActive: true,
            lastRun: null,
            nextRun: this.getNextRunTime(schedule),
            metadata: {
                created: new Date().toISOString(),
                createdBy: options.createdBy
            }
        };
        
        // Validate schedule
        if (!cron.validate(schedule)) {
            throw new Error(`Invalid cron schedule: ${schedule}`);
        }
        
        const task = cron.schedule(schedule, async () => {
            if (!scheduledWorkflow.isActive) return;
            
            scheduledWorkflow.lastRun = new Date().toISOString();
            scheduledWorkflow.nextRun = this.getNextRunTime(schedule);
            
            try {
                await this.executeWorkflow(templateId, context, {
                    ...options,
                    triggeredBy: 'schedule',
                    scheduleId
                });
                
                this.emit('schedule:executed', { scheduleId, templateId });
            } catch (error) {
                this.emit('schedule:error', { scheduleId, templateId, error: error.message });
            }
        }, {
            scheduled: false
        });
        
        scheduledWorkflow.task = task;
        this.scheduledWorkflows.set(scheduleId, scheduledWorkflow);
        task.start();
        
        this.emit('schedule:created', { scheduleId, templateId, schedule });
        return scheduleId;
    }
    
    getNextRunTime(schedule) {
        const cron = require('node-cron');
        // This would need a proper cron parser to calculate next run time
        // For now, return a placeholder
        return new Date(Date.now() + 3600000).toISOString(); // 1 hour from now
    }
    
    // Event-based Triggers
    registerTrigger(templateId, trigger) {
        const template = this.templates.get(templateId);
        if (!template) {
            throw new Error(`Template ${templateId} not found`);
        }
        
        if (trigger.type === 'event') {
            this.on(trigger.event, async (data) => {
                if (this.matchesTriggerConditions(trigger, data)) {
                    await this.executeWorkflow(templateId, { 
                        ...data, 
                        trigger: trigger.event 
                    }, {
                        triggeredBy: 'event'
                    });
                }
            });
        }
        
        this.emit('trigger:registered', { templateId, trigger });
    }
    
    matchesTriggerConditions(trigger, data) {
        if (!trigger.conditions) return true;
        
        return this.evaluateConditions(trigger.conditions, data);
    }
    
    // API Methods
    async getWorkflowTemplates() {
        return Array.from(this.templates.values());
    }
    
    async getWorkflowTemplate(templateId) {
        return this.templates.get(templateId);
    }
    
    async deleteWorkflowTemplate(templateId) {
        const deleted = this.templates.delete(templateId);
        if (deleted) {
            this.emit('template:deleted', { templateId });
        }
        return deleted;
    }
    
    async getActiveExecutions() {
        return Array.from(this.activeExecutions.values());
    }
    
    async getExecution(executionId) {
        return this.activeExecutions.get(executionId) || await this.loadExecution(executionId);
    }
    
    async cancelExecution(executionId) {
        const execution = this.activeExecutions.get(executionId);
        if (!execution) return false;
        
        execution.status = 'cancelled';
        execution.endTime = new Date().toISOString();
        this.activeExecutions.delete(executionId);
        
        this.emit('execution:cancelled', { executionId });
        await this.saveExecution(execution);
        return true;
    }
    
    async getScheduledWorkflows() {
        return Array.from(this.scheduledWorkflows.values()).map(sw => ({
            id: sw.id,
            templateId: sw.templateId,
            schedule: sw.schedule,
            isActive: sw.isActive,
            lastRun: sw.lastRun,
            nextRun: sw.nextRun,
            metadata: sw.metadata
        }));
    }
    
    async cancelScheduledWorkflow(scheduleId) {
        const scheduledWorkflow = this.scheduledWorkflows.get(scheduleId);
        if (!scheduledWorkflow) return false;
        
        scheduledWorkflow.isActive = false;
        scheduledWorkflow.task.stop();
        this.scheduledWorkflows.delete(scheduleId);
        
        this.emit('schedule:cancelled', { scheduleId });
        return true;
    }
    
    // Storage Methods
    async saveTemplate(template) {
        const filePath = path.join(this.config.storageDir, 'templates', `${template.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(template, null, 2));
    }
    
    async saveTemplateVersion(template) {
        const versionDir = path.join(this.config.storageDir, 'versions', template.id);
        await fs.mkdir(versionDir, { recursive: true });
        
        const filePath = path.join(versionDir, `${template.version}.json`);
        await fs.writeFile(filePath, JSON.stringify(template, null, 2));
        
        // Update versions map
        if (!this.versions.has(template.id)) {
            this.versions.set(template.id, []);
        }
        this.versions.get(template.id).push(template.version);
    }
    
    async saveExecution(execution) {
        const filePath = path.join(this.config.storageDir, 'executions', `${execution.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(execution, null, 2));
    }
    
    async loadExecution(executionId) {
        try {
            const filePath = path.join(this.config.storageDir, 'executions', `${executionId}.json`);
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return null;
        }
    }
    
    async loadWorkflowTemplates() {
        try {
            const templatesDir = path.join(this.config.storageDir, 'templates');
            const files = await fs.readdir(templatesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const filePath = path.join(templatesDir, file);
                    const data = await fs.readFile(filePath, 'utf8');
                    const template = JSON.parse(data);
                    this.templates.set(template.id, template);
                }
            }
            
            console.log(`Loaded ${this.templates.size} workflow templates`);
        } catch (error) {
            console.error('Failed to load workflow templates:', error);
        }
    }
    
    getNextVersion(templateId) {
        const versions = this.versions.get(templateId) || [];
        if (versions.length === 0) return '1.0.0';
        
        // Simple version increment
        const lastVersion = versions[versions.length - 1];
        const parts = lastVersion.split('.').map(Number);
        parts[2]++; // Increment patch version
        return parts.join('.');
    }
    
    startExecutionEngine() {
        // Process queue periodically
        setInterval(() => {
            this.processQueue();
        }, 1000);
        
        console.log('Workflow execution engine started');
    }
    
    startScheduler() {
        console.log('Workflow scheduler started');
    }
    
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }
    
    // Health and Statistics
    getEngineStats() {
        return {
            templates: this.templates.size,
            activeExecutions: this.activeExecutions.size,
            queuedExecutions: this.executionQueue.length,
            scheduledWorkflows: this.scheduledWorkflows.size,
            pendingApprovals: this.approvalQueue.size,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        };
    }
}

// Built-in Workflow Templates
const BUILTIN_TEMPLATES = {
    userProvisioning: {
        name: 'User Provisioning Workflow',
        description: 'Complete user account provisioning with approval',
        category: 'identity',
        requiresApproval: true,
        steps: [
            {
                id: 'validate_request',
                type: 'script',
                action: {
                    script: 'result = context.email && context.firstName && context.lastName;'
                }
            },
            {
                id: 'create_ldap_user',
                type: 'ldap_operation',
                action: {
                    operation: 'add',
                    dn: 'uid={{username}},ou=users,dc=example,dc=com',
                    attributes: {
                        objectClass: ['inetOrgPerson', 'posixAccount'],
                        uid: '{{username}}',
                        cn: '{{firstName}} {{lastName}}',
                        mail: '{{email}}'
                    }
                }
            },
            {
                id: 'send_welcome_email',
                type: 'email',
                action: {
                    to: '{{email}}',
                    subject: 'Welcome to OpenDirectory',
                    body: 'Your account has been created successfully.'
                }
            }
        ]
    },
    
    passwordReset: {
        name: 'Password Reset Workflow',
        description: 'Automated password reset with security checks',
        category: 'security',
        steps: [
            {
                id: 'verify_user',
                type: 'ldap_operation',
                action: {
                    operation: 'search',
                    filter: '(uid={{username}})',
                    attributes: ['mail', 'telephoneNumber']
                }
            },
            {
                id: 'generate_token',
                type: 'script',
                action: {
                    script: 'result = Math.random().toString(36).substring(7);'
                }
            },
            {
                id: 'send_reset_email',
                type: 'email',
                action: {
                    to: '{{stepResult.verify_user.mail}}',
                    subject: 'Password Reset Request',
                    body: 'Your reset token: {{stepResult.generate_token}}'
                }
            }
        ]
    }
};

module.exports = { WorkflowEngine, BUILTIN_TEMPLATES };