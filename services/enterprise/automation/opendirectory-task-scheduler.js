/**
 * OpenDirectory Intelligent Task Scheduler
 * Advanced task scheduling with dependencies, load balancing, and resource awareness
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const cron = require('node-cron');

class IntelligentTaskScheduler extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxConcurrentTasks: 50,
            maxQueueSize: 1000,
            defaultTimeout: 300000, // 5 minutes
            retryDelays: [1000, 5000, 15000, 60000], // Exponential backoff
            loadBalancingEnabled: true,
            resourceMonitoringEnabled: true,
            storageDir: config.storageDir || '/tmp/scheduler',
            healthCheckInterval: 30000,
            ...config
        };
        
        this.tasks = new Map();
        this.scheduledJobs = new Map();
        this.runningTasks = new Map();
        this.taskQueue = [];
        this.dependencyGraph = new Map();
        this.resourcePools = new Map();
        this.executorNodes = new Map();
        this.failedTasks = new Map();
        this.completedTasks = new Map();
        
        this.statistics = {
            totalExecuted: 0,
            totalFailed: 0,
            totalRetried: 0,
            averageExecutionTime: 0,
            queueSize: 0,
            runningTasks: 0
        };
        
        this.init();
    }
    
    async init() {
        await this.ensureStorageDir();
        await this.loadPersistedTasks();
        this.setupResourcePools();
        this.startTaskProcessor();
        this.startResourceMonitor();
        this.startHealthMonitor();
        
        this.emit('scheduler:ready');
        console.log('Intelligent Task Scheduler initialized successfully');
    }
    
    async ensureStorageDir() {
        try {
            await fs.mkdir(this.config.storageDir, { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'tasks'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'schedules'), { recursive: true });
            await fs.mkdir(path.join(this.config.storageDir, 'logs'), { recursive: true });
        } catch (error) {
            console.error('Failed to create storage directories:', error);
        }
    }
    
    setupResourcePools() {
        // Define resource pools for load balancing
        this.resourcePools.set('ldap', {
            name: 'LDAP Operations',
            maxConcurrent: 10,
            currentLoad: 0,
            queue: [],
            healthy: true
        });
        
        this.resourcePools.set('email', {
            name: 'Email Operations',
            maxConcurrent: 20,
            currentLoad: 0,
            queue: [],
            healthy: true
        });
        
        this.resourcePools.set('http', {
            name: 'HTTP Requests',
            maxConcurrent: 30,
            currentLoad: 0,
            queue: [],
            healthy: true
        });
        
        this.resourcePools.set('database', {
            name: 'Database Operations',
            maxConcurrent: 15,
            currentLoad: 0,
            queue: [],
            healthy: true
        });
        
        this.resourcePools.set('file_system', {
            name: 'File System Operations',
            maxConcurrent: 25,
            currentLoad: 0,
            queue: [],
            healthy: true
        });
        
        // Setup executor nodes for distributed execution
        this.executorNodes.set('local', {
            id: 'local',
            name: 'Local Node',
            capacity: this.config.maxConcurrentTasks,
            currentLoad: 0,
            healthy: true,
            lastHeartbeat: new Date().toISOString(),
            capabilities: ['ldap', 'email', 'http', 'database', 'file_system']
        });
    }
    
    // Task Creation and Management
    async createTask(taskDefinition) {
        const taskId = taskDefinition.id || this.generateId();
        
        const task = {
            id: taskId,
            name: taskDefinition.name,
            description: taskDefinition.description || '',
            type: taskDefinition.type,
            action: taskDefinition.action,
            parameters: taskDefinition.parameters || {},
            
            // Scheduling
            schedule: taskDefinition.schedule, // Cron expression or null for one-time
            scheduleType: taskDefinition.scheduleType || 'cron', // cron, interval, delay, at
            startTime: taskDefinition.startTime, // For 'at' type
            interval: taskDefinition.interval, // For 'interval' type
            delay: taskDefinition.delay, // For 'delay' type
            
            // Dependencies
            dependencies: taskDefinition.dependencies || [],
            dependsOn: taskDefinition.dependsOn || [], // Task IDs this task depends on
            
            // Execution configuration
            priority: taskDefinition.priority || 'normal', // low, normal, high, critical
            timeout: taskDefinition.timeout || this.config.defaultTimeout,
            maxRetries: taskDefinition.maxRetries || 3,
            retryStrategy: taskDefinition.retryStrategy || 'exponential',
            resourcePool: taskDefinition.resourcePool || 'default',
            executorNode: taskDefinition.executorNode || 'local',
            
            // Conditions
            conditions: taskDefinition.conditions || [],
            skipConditions: taskDefinition.skipConditions || [],
            
            // State
            status: 'pending',
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            nextRunTime: null,
            lastRunTime: null,
            runCount: 0,
            failureCount: 0,
            
            // Results
            lastResult: null,
            lastError: null,
            executionHistory: [],
            
            // Metadata
            createdBy: taskDefinition.createdBy,
            tags: taskDefinition.tags || [],
            category: taskDefinition.category || 'general'
        };
        
        // Validate task
        this.validateTask(task);
        
        // Calculate next run time
        if (task.schedule || task.scheduleType !== 'cron') {
            task.nextRunTime = this.calculateNextRunTime(task);
        }
        
        this.tasks.set(taskId, task);
        
        // Setup dependencies
        if (task.dependsOn.length > 0) {
            this.setupDependencies(task);
        }
        
        // Schedule if needed
        if (task.schedule) {
            await this.scheduleTask(task);
        } else if (task.scheduleType === 'at' && task.startTime) {
            await this.scheduleOneTimeTask(task);
        } else if (task.scheduleType === 'delay' && task.delay) {
            setTimeout(() => this.queueTask(task), task.delay);
        }
        
        await this.persistTask(task);
        
        this.emit('task:created', { taskId, task });
        
        return taskId;
    }
    
    validateTask(task) {
        if (!task.name) throw new Error('Task must have a name');
        if (!task.type) throw new Error('Task must have a type');
        if (!task.action) throw new Error('Task must have an action');
        
        // Validate schedule if provided
        if (task.schedule && task.scheduleType === 'cron') {
            if (!cron.validate(task.schedule)) {
                throw new Error(`Invalid cron expression: ${task.schedule}`);
            }
        }
        
        // Validate dependencies
        if (task.dependsOn) {
            task.dependsOn.forEach(depId => {
                if (!this.tasks.has(depId)) {
                    console.warn(`Dependency task ${depId} not found`);
                }
            });
        }
        
        // Validate priority
        const validPriorities = ['low', 'normal', 'high', 'critical'];
        if (!validPriorities.includes(task.priority)) {
            throw new Error(`Invalid priority: ${task.priority}`);
        }
    }
    
    calculateNextRunTime(task) {
        const now = new Date();
        
        switch (task.scheduleType) {
            case 'cron':
                if (task.schedule) {
                    // Use cron library to calculate next run
                    try {
                        const job = cron.schedule(task.schedule, () => {}, { scheduled: false });
                        return job.nextDate()?.toISOString() || null;
                    } catch (error) {
                        console.error('Error calculating next cron run time:', error);
                        return null;
                    }
                }
                break;
                
            case 'interval':
                if (task.interval) {
                    return new Date(now.getTime() + task.interval).toISOString();
                }
                break;
                
            case 'at':
                if (task.startTime) {
                    const startTime = new Date(task.startTime);
                    return startTime > now ? startTime.toISOString() : null;
                }
                break;
                
            case 'delay':
                if (task.delay) {
                    return new Date(now.getTime() + task.delay).toISOString();
                }
                break;
        }
        
        return null;
    }
    
    setupDependencies(task) {
        task.dependsOn.forEach(depId => {
            if (!this.dependencyGraph.has(depId)) {
                this.dependencyGraph.set(depId, new Set());
            }
            this.dependencyGraph.get(depId).add(task.id);
        });
    }
    
    async scheduleTask(task) {
        if (!task.schedule) return;
        
        try {
            const job = cron.schedule(task.schedule, async () => {
                await this.queueTask(task);
            }, {
                scheduled: false,
                timezone: 'UTC'
            });
            
            this.scheduledJobs.set(task.id, job);
            job.start();
            
            this.emit('task:scheduled', { taskId: task.id, schedule: task.schedule });
        } catch (error) {
            console.error(`Failed to schedule task ${task.id}:`, error);
            throw error;
        }
    }
    
    async scheduleOneTimeTask(task) {
        const startTime = new Date(task.startTime);
        const delay = startTime.getTime() - Date.now();
        
        if (delay > 0) {
            setTimeout(() => {
                this.queueTask(task);
            }, delay);
        } else {
            // Start time is in the past, execute now
            this.queueTask(task);
        }
    }
    
    // Task Execution
    async queueTask(task, context = {}) {
        // Check if task should be skipped
        if (await this.shouldSkipTask(task, context)) {
            this.emit('task:skipped', { taskId: task.id, reason: 'Skip conditions met' });
            return;
        }
        
        // Check dependencies
        if (task.dependsOn.length > 0) {
            const dependenciesMet = await this.checkDependencies(task);
            if (!dependenciesMet) {
                this.emit('task:waiting', { taskId: task.id, reason: 'Dependencies not met' });
                return;
            }
        }
        
        // Check conditions
        if (task.conditions.length > 0) {
            const conditionsMet = await this.evaluateConditions(task);
            if (!conditionsMet) {
                this.emit('task:skipped', { taskId: task.id, reason: 'Conditions not met' });
                return;
            }
        }
        
        const queuedTask = {
            ...task,
            queuedAt: new Date().toISOString(),
            context,
            priority: this.calculateTaskPriority(task)
        };
        
        // Add to appropriate queue based on resource pool
        if (this.config.loadBalancingEnabled && task.resourcePool !== 'default') {
            const pool = this.resourcePools.get(task.resourcePool);
            if (pool && pool.currentLoad >= pool.maxConcurrent) {
                pool.queue.push(queuedTask);
                this.emit('task:queued_to_pool', { taskId: task.id, pool: task.resourcePool });
                return;
            }
        }
        
        // Add to main queue with priority ordering
        this.insertTaskInPriorityOrder(queuedTask);
        this.statistics.queueSize = this.taskQueue.length;
        
        this.emit('task:queued', { taskId: task.id, queuePosition: this.taskQueue.length });
        
        // Try to process immediately if capacity allows
        this.processTaskQueue();
    }
    
    insertTaskInPriorityOrder(task) {
        const priorities = { 'critical': 4, 'high': 3, 'normal': 2, 'low': 1 };
        const taskPriority = priorities[task.priority] || 2;
        
        let insertIndex = this.taskQueue.length;
        
        for (let i = 0; i < this.taskQueue.length; i++) {
            const queuedPriority = priorities[this.taskQueue[i].priority] || 2;
            if (taskPriority > queuedPriority) {
                insertIndex = i;
                break;
            }
        }
        
        this.taskQueue.splice(insertIndex, 0, task);
    }
    
    calculateTaskPriority(task) {
        let priority = task.priority;
        
        // Increase priority for overdue tasks
        if (task.nextRunTime && new Date(task.nextRunTime) < new Date()) {
            const minutesOverdue = (Date.now() - new Date(task.nextRunTime).getTime()) / 60000;
            if (minutesOverdue > 60 && priority === 'low') priority = 'normal';
            if (minutesOverdue > 30 && priority === 'normal') priority = 'high';
            if (minutesOverdue > 15 && priority === 'high') priority = 'critical';
        }
        
        return priority;
    }
    
    async shouldSkipTask(task, context) {
        if (task.skipConditions.length === 0) return false;
        
        try {
            for (const condition of task.skipConditions) {
                if (await this.evaluateCondition(condition, task, context)) {
                    return true;
                }
            }
        } catch (error) {
            console.error(`Error evaluating skip conditions for task ${task.id}:`, error);
            return false;
        }
        
        return false;
    }
    
    async checkDependencies(task) {
        for (const depId of task.dependsOn) {
            const depTask = this.tasks.get(depId);
            if (!depTask) {
                console.warn(`Dependency task ${depId} not found`);
                continue;
            }
            
            if (depTask.status !== 'completed') {
                return false;
            }
            
            // Check if dependency completed successfully
            if (depTask.lastResult && !depTask.lastResult.success) {
                return false;
            }
        }
        
        return true;
    }
    
    async evaluateConditions(task) {
        if (task.conditions.length === 0) return true;
        
        try {
            for (const condition of task.conditions) {
                if (!await this.evaluateCondition(condition, task)) {
                    return false;
                }
            }
        } catch (error) {
            console.error(`Error evaluating conditions for task ${task.id}:`, error);
            return false;
        }
        
        return true;
    }
    
    async evaluateCondition(condition, task, context = {}) {
        switch (condition.type) {
            case 'expression':
                return this.evaluateExpression(condition.expression, { task, context });
                
            case 'time_window':
                return this.isInTimeWindow(condition.start, condition.end);
                
            case 'resource_availability':
                return this.isResourceAvailable(condition.resource);
                
            case 'system_load':
                return this.isSystemLoadAcceptable(condition.maxLoad);
                
            case 'file_exists':
                return this.fileExists(condition.path);
                
            case 'http_check':
                return await this.httpHealthCheck(condition.url, condition.expectedStatus);
                
            default:
                console.warn(`Unknown condition type: ${condition.type}`);
                return true;
        }
    }
    
    evaluateExpression(expression, context) {
        try {
            const vm = require('vm');
            return vm.runInNewContext(expression, {
                ...context,
                Math,
                Date,
                console
            });
        } catch (error) {
            console.error('Error evaluating expression:', expression, error);
            return false;
        }
    }
    
    isInTimeWindow(startTime, endTime) {
        const now = new Date();
        const start = new Date(`1970-01-01T${startTime}`);
        const end = new Date(`1970-01-01T${endTime}`);
        const currentTime = new Date(`1970-01-01T${now.toTimeString().split(' ')[0]}`);
        
        if (start <= end) {
            return currentTime >= start && currentTime <= end;
        } else {
            // Time window crosses midnight
            return currentTime >= start || currentTime <= end;
        }
    }
    
    isResourceAvailable(resourceName) {
        const pool = this.resourcePools.get(resourceName);
        return pool && pool.healthy && pool.currentLoad < pool.maxConcurrent;
    }
    
    isSystemLoadAcceptable(maxLoad) {
        const currentLoad = this.runningTasks.size / this.config.maxConcurrentTasks;
        return currentLoad <= maxLoad;
    }
    
    async fileExists(filePath) {
        try {
            await fs.access(filePath);
            return true;
        } catch {
            return false;
        }
    }
    
    async httpHealthCheck(url, expectedStatus = 200) {
        try {
            const fetch = require('node-fetch');
            const response = await fetch(url, { timeout: 5000 });
            return response.status === expectedStatus;
        } catch {
            return false;
        }
    }
    
    // Task Processing
    processTaskQueue() {
        // Check if we can run more tasks
        if (this.runningTasks.size >= this.config.maxConcurrentTasks) {
            return;
        }
        
        if (this.taskQueue.length === 0) {
            return;
        }
        
        // Find next executable task
        const taskIndex = this.findNextExecutableTask();
        if (taskIndex === -1) {
            return;
        }
        
        const task = this.taskQueue.splice(taskIndex, 1)[0];
        this.statistics.queueSize = this.taskQueue.length;
        
        this.executeTask(task);
    }
    
    findNextExecutableTask() {
        for (let i = 0; i < this.taskQueue.length; i++) {
            const task = this.taskQueue[i];
            
            // Check resource pool availability
            if (task.resourcePool && task.resourcePool !== 'default') {
                const pool = this.resourcePools.get(task.resourcePool);
                if (!pool || pool.currentLoad >= pool.maxConcurrent || !pool.healthy) {
                    continue;
                }
            }
            
            // Check executor node availability
            const executor = this.executorNodes.get(task.executorNode);
            if (!executor || executor.currentLoad >= executor.capacity || !executor.healthy) {
                continue;
            }
            
            return i;
        }
        
        return -1;
    }
    
    async executeTask(task) {
        const executionId = this.generateId();
        const execution = {
            id: executionId,
            taskId: task.id,
            startTime: new Date().toISOString(),
            endTime: null,
            duration: 0,
            result: null,
            error: null,
            retryCount: 0
        };
        
        this.runningTasks.set(task.id, execution);
        this.statistics.runningTasks = this.runningTasks.size;
        
        // Update resource pool load
        if (task.resourcePool && task.resourcePool !== 'default') {
            const pool = this.resourcePools.get(task.resourcePool);
            if (pool) pool.currentLoad++;
        }
        
        // Update executor node load
        const executor = this.executorNodes.get(task.executorNode);
        if (executor) executor.currentLoad++;
        
        task.status = 'running';
        task.lastRunTime = execution.startTime;
        task.runCount++;
        
        this.emit('task:started', { taskId: task.id, executionId });
        
        try {
            // Set execution timeout
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Task execution timeout')), task.timeout);
            });
            
            const executionPromise = this.performTaskExecution(task, execution);
            
            const result = await Promise.race([executionPromise, timeoutPromise]);
            
            execution.result = result;
            execution.endTime = new Date().toISOString();
            execution.duration = Date.parse(execution.endTime) - Date.parse(execution.startTime);
            
            await this.completeTask(task, execution);
            
        } catch (error) {
            execution.error = error.message;
            execution.endTime = new Date().toISOString();
            execution.duration = Date.parse(execution.endTime) - Date.parse(execution.startTime);
            
            await this.handleTaskFailure(task, execution, error);
        } finally {
            // Update resource pool load
            if (task.resourcePool && task.resourcePool !== 'default') {
                const pool = this.resourcePools.get(task.resourcePool);
                if (pool) pool.currentLoad = Math.max(0, pool.currentLoad - 1);
            }
            
            // Update executor node load
            if (executor) executor.currentLoad = Math.max(0, executor.currentLoad - 1);
            
            this.runningTasks.delete(task.id);
            this.statistics.runningTasks = this.runningTasks.size;
            
            // Process queued tasks for this resource pool
            this.processResourcePoolQueue(task.resourcePool);
            
            // Continue processing main queue
            this.processTaskQueue();
        }
    }
    
    async performTaskExecution(task, execution) {
        switch (task.type) {
            case 'ldap_operation':
                return await this.executeLdapTask(task);
            case 'email':
                return await this.executeEmailTask(task);
            case 'http_request':
                return await this.executeHttpTask(task);
            case 'database_query':
                return await this.executeDatabaseTask(task);
            case 'file_operation':
                return await this.executeFileTask(task);
            case 'script':
                return await this.executeScriptTask(task);
            case 'workflow':
                return await this.executeWorkflowTask(task);
            case 'backup':
                return await this.executeBackupTask(task);
            case 'maintenance':
                return await this.executeMaintenanceTask(task);
            case 'monitoring':
                return await this.executeMonitoringTask(task);
            default:
                throw new Error(`Unknown task type: ${task.type}`);
        }
    }
    
    async executeLdapTask(task) {
        const { operation, dn, attributes, filter } = task.action;
        
        this.emit('ldap:operation', {
            operation,
            dn: this.replaceParameters(dn, task.parameters),
            attributes,
            filter: filter ? this.replaceParameters(filter, task.parameters) : null,
            taskId: task.id
        });
        
        // Simulate LDAP operation
        return {
            success: true,
            operation,
            timestamp: new Date().toISOString(),
            affected: 1
        };
    }
    
    async executeEmailTask(task) {
        const { to, subject, body, attachments } = task.action;
        
        const email = {
            to: this.replaceParameters(to, task.parameters),
            subject: this.replaceParameters(subject, task.parameters),
            body: this.replaceParameters(body, task.parameters),
            attachments: attachments || [],
            taskId: task.id
        };
        
        this.emit('email:send', email);
        
        return {
            success: true,
            messageId: this.generateId(),
            timestamp: new Date().toISOString(),
            recipients: Array.isArray(email.to) ? email.to.length : 1
        };
    }
    
    async executeHttpTask(task) {
        const { url, method = 'GET', headers = {}, body } = task.action;
        const fetch = require('node-fetch');
        
        const processedUrl = this.replaceParameters(url, task.parameters);
        const processedBody = body ? this.replaceParameters(JSON.stringify(body), task.parameters) : null;
        
        const response = await fetch(processedUrl, {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            },
            body: processedBody,
            timeout: 30000
        });
        
        const responseData = await response.text();
        
        return {
            success: response.ok,
            status: response.status,
            statusText: response.statusText,
            data: responseData,
            timestamp: new Date().toISOString()
        };
    }
    
    async executeDatabaseTask(task) {
        const { query, parameters = [] } = task.action;
        
        const processedQuery = this.replaceParameters(query, task.parameters);
        const processedParams = parameters.map(param => 
            this.replaceParameters(param.toString(), task.parameters)
        );
        
        this.emit('database:execute', {
            query: processedQuery,
            parameters: processedParams,
            taskId: task.id
        });
        
        return {
            success: true,
            query: processedQuery,
            rowsAffected: Math.floor(Math.random() * 10), // Mock result
            timestamp: new Date().toISOString()
        };
    }
    
    async executeFileTask(task) {
        const { operation, source, destination, content } = task.action;
        
        const processedSource = source ? this.replaceParameters(source, task.parameters) : null;
        const processedDestination = destination ? this.replaceParameters(destination, task.parameters) : null;
        const processedContent = content ? this.replaceParameters(content, task.parameters) : null;
        
        switch (operation) {
            case 'copy':
                await fs.copyFile(processedSource, processedDestination);
                break;
            case 'move':
                await fs.rename(processedSource, processedDestination);
                break;
            case 'delete':
                await fs.unlink(processedSource);
                break;
            case 'write':
                await fs.writeFile(processedDestination, processedContent);
                break;
            case 'read':
                const fileContent = await fs.readFile(processedSource, 'utf8');
                return {
                    success: true,
                    operation,
                    content: fileContent,
                    timestamp: new Date().toISOString()
                };
            default:
                throw new Error(`Unknown file operation: ${operation}`);
        }
        
        return {
            success: true,
            operation,
            source: processedSource,
            destination: processedDestination,
            timestamp: new Date().toISOString()
        };
    }
    
    async executeScriptTask(task) {
        const { script, language = 'javascript', timeout = 30000 } = task.action;
        
        if (language === 'javascript') {
            const vm = require('vm');
            const sandbox = {
                parameters: task.parameters,
                console,
                setTimeout,
                setInterval,
                clearTimeout,
                clearInterval,
                result: null,
                emit: (event, data) => this.emit(event, { ...data, taskId: task.id })
            };
            
            const processedScript = this.replaceParameters(script, task.parameters);
            
            try {
                vm.runInNewContext(processedScript, sandbox, { timeout });
                return {
                    success: true,
                    result: sandbox.result,
                    timestamp: new Date().toISOString()
                };
            } catch (error) {
                throw new Error(`Script execution failed: ${error.message}`);
            }
        }
        
        throw new Error(`Unsupported script language: ${language}`);
    }
    
    async executeWorkflowTask(task) {
        const { workflowId, context = {} } = task.action;
        
        const workflowContext = {
            ...context,
            parameters: task.parameters,
            taskId: task.id
        };
        
        this.emit('workflow:trigger', {
            workflowId,
            context: workflowContext,
            triggeredBy: 'scheduler',
            taskId: task.id
        });
        
        return {
            success: true,
            workflowId,
            triggered: true,
            timestamp: new Date().toISOString()
        };
    }
    
    async executeBackupTask(task) {
        const { backupType, source, destination, compression } = task.action;
        
        // Simulate backup operation
        const backupId = this.generateId();
        
        this.emit('backup:started', {
            backupId,
            backupType,
            source: this.replaceParameters(source, task.parameters),
            destination: this.replaceParameters(destination, task.parameters),
            taskId: task.id
        });
        
        // Simulate backup time
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const result = {
            success: true,
            backupId,
            backupType,
            size: Math.floor(Math.random() * 1000000), // Mock size
            timestamp: new Date().toISOString()
        };
        
        this.emit('backup:completed', { ...result, taskId: task.id });
        
        return result;
    }
    
    async executeMaintenanceTask(task) {
        const { maintenanceType, target, parameters } = task.action;
        
        this.emit('maintenance:started', {
            maintenanceType,
            target: this.replaceParameters(target, task.parameters),
            parameters,
            taskId: task.id
        });
        
        // Simulate maintenance operation
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        const result = {
            success: true,
            maintenanceType,
            itemsProcessed: Math.floor(Math.random() * 100),
            timestamp: new Date().toISOString()
        };
        
        this.emit('maintenance:completed', { ...result, taskId: task.id });
        
        return result;
    }
    
    async executeMonitoringTask(task) {
        const { monitorType, target, thresholds } = task.action;
        
        // Simulate monitoring check
        const metrics = {
            cpu: Math.random() * 100,
            memory: Math.random() * 100,
            disk: Math.random() * 100,
            responseTime: Math.random() * 1000
        };
        
        const alerts = [];
        
        if (thresholds) {
            Object.entries(thresholds).forEach(([metric, threshold]) => {
                if (metrics[metric] > threshold) {
                    alerts.push({
                        metric,
                        value: metrics[metric],
                        threshold,
                        severity: metrics[metric] > threshold * 1.5 ? 'high' : 'medium'
                    });
                }
            });
        }
        
        const result = {
            success: true,
            monitorType,
            target: this.replaceParameters(target, task.parameters),
            metrics,
            alerts,
            timestamp: new Date().toISOString()
        };
        
        if (alerts.length > 0) {
            this.emit('monitoring:alert', { ...result, taskId: task.id });
        }
        
        this.emit('monitoring:completed', { ...result, taskId: task.id });
        
        return result;
    }
    
    replaceParameters(template, parameters) {
        if (typeof template !== 'string') return template;
        
        return template.replace(/\{\{(.+?)\}\}/g, (match, key) => {
            const value = parameters[key.trim()];
            return value !== undefined ? value : match;
        });
    }
    
    async completeTask(task, execution) {
        task.status = 'completed';
        task.lastResult = execution.result;
        task.lastError = null;
        task.lastModified = new Date().toISOString();
        
        // Calculate next run time for recurring tasks
        if (task.schedule || task.scheduleType === 'interval') {
            task.nextRunTime = this.calculateNextRunTime(task);
        }
        
        // Add to execution history
        task.executionHistory.unshift({
            executionId: execution.id,
            startTime: execution.startTime,
            endTime: execution.endTime,
            duration: execution.duration,
            result: execution.result,
            success: true
        });
        
        // Keep only last 50 executions
        if (task.executionHistory.length > 50) {
            task.executionHistory = task.executionHistory.slice(0, 50);
        }
        
        // Update statistics
        this.statistics.totalExecuted++;
        this.updateAverageExecutionTime(execution.duration);
        
        // Move to completed tasks
        this.completedTasks.set(task.id, task);
        this.failedTasks.delete(task.id);
        
        // Process dependent tasks
        await this.processDependentTasks(task.id);
        
        this.emit('task:completed', {
            taskId: task.id,
            executionId: execution.id,
            duration: execution.duration,
            result: execution.result
        });
        
        await this.persistTask(task);
    }
    
    async handleTaskFailure(task, execution, error) {
        task.failureCount++;
        task.lastError = error.message;
        task.lastResult = null;
        task.lastModified = new Date().toISOString();
        
        // Add to execution history
        task.executionHistory.unshift({
            executionId: execution.id,
            startTime: execution.startTime,
            endTime: execution.endTime,
            duration: execution.duration,
            error: error.message,
            success: false
        });
        
        // Determine if we should retry
        if (task.failureCount <= task.maxRetries) {
            await this.retryTask(task, execution);
        } else {
            task.status = 'failed';
            this.failedTasks.set(task.id, task);
            this.statistics.totalFailed++;
            
            this.emit('task:failed', {
                taskId: task.id,
                executionId: execution.id,
                error: error.message,
                retries: task.failureCount
            });
        }
        
        await this.persistTask(task);
    }
    
    async retryTask(task, execution) {
        const retryDelay = this.calculateRetryDelay(task, task.failureCount);
        
        task.status = 'retry_pending';
        
        this.statistics.totalRetried++;
        
        this.emit('task:retry_scheduled', {
            taskId: task.id,
            retryCount: task.failureCount,
            retryDelay
        });
        
        setTimeout(() => {
            this.queueTask(task);
        }, retryDelay);
    }
    
    calculateRetryDelay(task, retryCount) {
        switch (task.retryStrategy) {
            case 'exponential':
                const baseDelay = this.config.retryDelays[0] || 1000;
                return Math.min(baseDelay * Math.pow(2, retryCount - 1), 300000); // Max 5 minutes
                
            case 'linear':
                return (this.config.retryDelays[0] || 1000) * retryCount;
                
            case 'fixed':
                return this.config.retryDelays[0] || 5000;
                
            case 'custom':
                return this.config.retryDelays[retryCount - 1] || this.config.retryDelays[this.config.retryDelays.length - 1] || 5000;
                
            default:
                return this.config.retryDelays[retryCount - 1] || 5000;
        }
    }
    
    async processDependentTasks(taskId) {
        const dependentTaskIds = this.dependencyGraph.get(taskId);
        if (!dependentTaskIds) return;
        
        for (const depTaskId of dependentTaskIds) {
            const depTask = this.tasks.get(depTaskId);
            if (depTask && depTask.status === 'pending') {
                // Check if all dependencies are now met
                const dependenciesMet = await this.checkDependencies(depTask);
                if (dependenciesMet) {
                    await this.queueTask(depTask);
                }
            }
        }
    }
    
    processResourcePoolQueue(poolName) {
        if (!poolName || poolName === 'default') return;
        
        const pool = this.resourcePools.get(poolName);
        if (!pool || pool.queue.length === 0) return;
        
        while (pool.currentLoad < pool.maxConcurrent && pool.queue.length > 0) {
            const task = pool.queue.shift();
            this.insertTaskInPriorityOrder(task);
            this.processTaskQueue();
        }
    }
    
    // Resource Management
    addExecutorNode(nodeConfig) {
        const nodeId = nodeConfig.id || this.generateId();
        
        const node = {
            id: nodeId,
            name: nodeConfig.name,
            capacity: nodeConfig.capacity || 10,
            currentLoad: 0,
            healthy: true,
            lastHeartbeat: new Date().toISOString(),
            capabilities: nodeConfig.capabilities || [],
            metadata: nodeConfig.metadata || {}
        };
        
        this.executorNodes.set(nodeId, node);
        
        this.emit('executor:added', { nodeId, node });
        
        return nodeId;
    }
    
    removeExecutorNode(nodeId) {
        const node = this.executorNodes.get(nodeId);
        if (!node) return false;
        
        // Move running tasks to other nodes
        // In a real implementation, this would handle task migration
        
        this.executorNodes.delete(nodeId);
        
        this.emit('executor:removed', { nodeId });
        
        return true;
    }
    
    updateResourcePoolCapacity(poolName, newCapacity) {
        const pool = this.resourcePools.get(poolName);
        if (!pool) return false;
        
        pool.maxConcurrent = newCapacity;
        
        // Process queue if we increased capacity
        if (newCapacity > pool.currentLoad) {
            this.processResourcePoolQueue(poolName);
        }
        
        this.emit('resource_pool:updated', { poolName, newCapacity });
        
        return true;
    }
    
    // Monitoring and Statistics
    updateAverageExecutionTime(duration) {
        const totalExecuted = this.statistics.totalExecuted;
        const currentAverage = this.statistics.averageExecutionTime;
        
        this.statistics.averageExecutionTime = 
            ((currentAverage * (totalExecuted - 1)) + duration) / totalExecuted;
    }
    
    startTaskProcessor() {
        setInterval(() => {
            this.processTaskQueue();
        }, 1000);
        
        console.log('Task processor started');
    }
    
    startResourceMonitor() {
        if (!this.config.resourceMonitoringEnabled) return;
        
        setInterval(() => {
            this.monitorSystemResources();
        }, 30000); // Check every 30 seconds
        
        console.log('Resource monitor started');
    }
    
    startHealthMonitor() {
        setInterval(() => {
            this.performHealthChecks();
        }, this.config.healthCheckInterval);
        
        console.log('Health monitor started');
    }
    
    monitorSystemResources() {
        const memUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();
        
        const resourceMetrics = {
            memory: {
                used: memUsage.heapUsed,
                total: memUsage.heapTotal,
                percentage: (memUsage.heapUsed / memUsage.heapTotal) * 100
            },
            cpu: {
                user: cpuUsage.user,
                system: cpuUsage.system
            },
            tasks: {
                running: this.runningTasks.size,
                queued: this.taskQueue.length,
                total: this.tasks.size
            }
        };
        
        this.emit('system:metrics', resourceMetrics);
        
        // Alert on high resource usage
        if (resourceMetrics.memory.percentage > 80) {
            this.emit('system:alert', {
                type: 'high_memory_usage',
                value: resourceMetrics.memory.percentage,
                threshold: 80
            });
        }
        
        if (this.runningTasks.size > this.config.maxConcurrentTasks * 0.9) {
            this.emit('system:alert', {
                type: 'high_task_load',
                value: this.runningTasks.size,
                threshold: this.config.maxConcurrentTasks * 0.9
            });
        }
    }
    
    performHealthChecks() {
        // Check executor node health
        const now = Date.now();
        
        for (const [nodeId, node] of this.executorNodes) {
            const lastHeartbeat = Date.parse(node.lastHeartbeat);
            const timeSinceHeartbeat = now - lastHeartbeat;
            
            if (timeSinceHeartbeat > 120000) { // 2 minutes
                if (node.healthy) {
                    node.healthy = false;
                    this.emit('executor:unhealthy', { nodeId, timeSinceHeartbeat });
                }
            }
        }
        
        // Check resource pool health
        for (const [poolName, pool] of this.resourcePools) {
            if (pool.queue.length > 100) {
                this.emit('resource_pool:overloaded', {
                    poolName,
                    queueLength: pool.queue.length
                });
            }
        }
    }
    
    // Task Management APIs
    async pauseTask(taskId) {
        const task = this.tasks.get(taskId);
        if (!task) throw new Error('Task not found');
        
        task.status = 'paused';
        
        // Remove from scheduled jobs
        const job = this.scheduledJobs.get(taskId);
        if (job) {
            job.stop();
        }
        
        // Remove from queue if present
        const queueIndex = this.taskQueue.findIndex(t => t.id === taskId);
        if (queueIndex !== -1) {
            this.taskQueue.splice(queueIndex, 1);
        }
        
        this.emit('task:paused', { taskId });
        await this.persistTask(task);
        
        return true;
    }
    
    async resumeTask(taskId) {
        const task = this.tasks.get(taskId);
        if (!task) throw new Error('Task not found');
        
        task.status = 'pending';
        
        // Reschedule if needed
        if (task.schedule) {
            await this.scheduleTask(task);
        } else if (task.scheduleType === 'at' && task.startTime) {
            await this.scheduleOneTimeTask(task);
        }
        
        this.emit('task:resumed', { taskId });
        await this.persistTask(task);
        
        return true;
    }
    
    async deleteTask(taskId) {
        const task = this.tasks.get(taskId);
        if (!task) return false;
        
        // Stop scheduled job
        const job = this.scheduledJobs.get(taskId);
        if (job) {
            job.stop();
            this.scheduledJobs.delete(taskId);
        }
        
        // Remove from queue
        const queueIndex = this.taskQueue.findIndex(t => t.id === taskId);
        if (queueIndex !== -1) {
            this.taskQueue.splice(queueIndex, 1);
        }
        
        // Clean up dependencies
        this.dependencyGraph.delete(taskId);
        for (const [depId, dependents] of this.dependencyGraph) {
            dependents.delete(taskId);
        }
        
        // Remove from all collections
        this.tasks.delete(taskId);
        this.completedTasks.delete(taskId);
        this.failedTasks.delete(taskId);
        
        // Delete persisted file
        try {
            const taskPath = path.join(this.config.storageDir, 'tasks', `${taskId}.json`);
            await fs.unlink(taskPath);
        } catch (error) {
            console.warn('Failed to delete task file:', error);
        }
        
        this.emit('task:deleted', { taskId });
        
        return true;
    }
    
    // Persistence
    async persistTask(task) {
        try {
            const taskPath = path.join(this.config.storageDir, 'tasks', `${task.id}.json`);
            await fs.writeFile(taskPath, JSON.stringify(task, null, 2));
        } catch (error) {
            console.error('Failed to persist task:', error);
        }
    }
    
    async loadPersistedTasks() {
        try {
            const tasksDir = path.join(this.config.storageDir, 'tasks');
            const files = await fs.readdir(tasksDir);
            
            let loadedCount = 0;
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    try {
                        const taskPath = path.join(tasksDir, file);
                        const data = await fs.readFile(taskPath, 'utf8');
                        const task = JSON.parse(data);
                        
                        this.tasks.set(task.id, task);
                        
                        // Restore scheduled jobs for active tasks
                        if (task.status !== 'paused' && task.schedule) {
                            await this.scheduleTask(task);
                        }
                        
                        loadedCount++;
                    } catch (error) {
                        console.error(`Failed to load task from ${file}:`, error);
                    }
                }
            }
            
            console.log(`Loaded ${loadedCount} persisted tasks`);
        } catch (error) {
            console.error('Failed to load persisted tasks:', error);
        }
    }
    
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }
    
    // API Methods
    getTasks(filters = {}) {
        let tasks = Array.from(this.tasks.values());
        
        if (filters.status) {
            tasks = tasks.filter(t => t.status === filters.status);
        }
        
        if (filters.type) {
            tasks = tasks.filter(t => t.type === filters.type);
        }
        
        if (filters.category) {
            tasks = tasks.filter(t => t.category === filters.category);
        }
        
        if (filters.tags) {
            tasks = tasks.filter(t => 
                filters.tags.every(tag => t.tags.includes(tag))
            );
        }
        
        return tasks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    }
    
    getTask(taskId) {
        return this.tasks.get(taskId);
    }
    
    getRunningTasks() {
        return Array.from(this.runningTasks.values());
    }
    
    getTaskQueue() {
        return [...this.taskQueue];
    }
    
    getSchedulerStats() {
        return {
            ...this.statistics,
            tasks: this.tasks.size,
            scheduledJobs: this.scheduledJobs.size,
            resourcePools: this.resourcePools.size,
            executorNodes: this.executorNodes.size,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        };
    }
    
    getResourcePools() {
        return Array.from(this.resourcePools.entries()).map(([name, pool]) => ({
            name,
            ...pool,
            queue: pool.queue.length
        }));
    }
    
    getExecutorNodes() {
        return Array.from(this.executorNodes.values());
    }
}

module.exports = { IntelligentTaskScheduler };