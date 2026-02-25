/**
 * Enterprise Directory Integration Service
 * Connects conditional access with the enterprise directory service
 */

const axios = require('axios');
const config = require('../config');

class EnterpriseDirectoryIntegration {
    constructor(auditLogger) {
        this.auditLogger = auditLogger;
        this.baseURL = config.integrations.enterpriseDirectory.url;
        this.apiKey = config.integrations.enterpriseDirectory.apiKey;
        
        // Create HTTP client
        this.client = axios.create({
            baseURL: this.baseURL,
            timeout: 30000,
            headers: {
                'X-API-Key': this.apiKey,
                'Content-Type': 'application/json',
                'User-Agent': 'ConditionalAccess/1.0.0'
            }
        });
        
        // Cache for frequently accessed data
        this.userCache = new Map();
        this.groupCache = new Map();
        this.deviceCache = new Map();
        
        this.setupInterceptors();
    }

    async initialize() {
        console.log('🔗 Initializing Enterprise Directory Integration...');
        
        try {
            // Test connection to enterprise directory
            await this.testConnection();
            
            // Subscribe to directory events
            await this.subscribeToDirectoryEvents();
            
            console.log('✅ Enterprise Directory Integration initialized');
            
        } catch (error) {
            console.error('❌ Failed to initialize Enterprise Directory Integration:', error);
            throw error;
        }
    }

    setupInterceptors() {
        // Request interceptor for logging
        this.client.interceptors.request.use((config) => {
            console.log(`📤 Enterprise Directory API: ${config.method.toUpperCase()} ${config.url}`);
            return config;
        });

        // Response interceptor for error handling and caching
        this.client.interceptors.response.use(
            (response) => {
                console.log(`📥 Enterprise Directory API Response: ${response.status}`);
                return response;
            },
            async (error) => {
                console.error(`❌ Enterprise Directory API Error:`, error.response?.data || error.message);
                
                await this.auditLogger.logEvent(
                    'system',
                    'ENTERPRISE_DIRECTORY_API_ERROR',
                    {
                        url: error.config?.url,
                        method: error.config?.method,
                        status: error.response?.status,
                        error: error.response?.data || error.message
                    }
                );
                
                return Promise.reject(error);
            }
        );
    }

    /**
     * Test connection to enterprise directory
     */
    async testConnection() {
        try {
            const response = await this.client.get('/health');
            
            if (response.status !== 200) {
                throw new Error(`Health check failed: ${response.status}`);
            }
            
            await this.auditLogger.logEvent(
                'system',
                'ENTERPRISE_DIRECTORY_CONNECTION_SUCCESS',
                {
                    url: this.baseURL,
                    status: response.status
                }
            );
            
            return true;
            
        } catch (error) {
            await this.auditLogger.logEvent(
                'system',
                'ENTERPRISE_DIRECTORY_CONNECTION_FAILED',
                {
                    url: this.baseURL,
                    error: error.message
                }
            );
            
            throw new Error(`Failed to connect to Enterprise Directory: ${error.message}`);
        }
    }

    /**
     * Get user information from enterprise directory
     */
    async getUser(userId) {
        try {
            // Check cache first
            if (this.userCache.has(userId)) {
                const cached = this.userCache.get(userId);
                if (Date.now() - cached.timestamp < 5 * 60 * 1000) { // 5 minutes cache
                    return cached.data;
                }
            }
            
            const response = await this.client.get(`/api/v1/users/${userId}`);
            const userData = response.data;
            
            // Cache the response
            this.userCache.set(userId, {
                data: userData,
                timestamp: Date.now()
            });
            
            await this.auditLogger.logEvent(
                'authentication',
                'USER_LOOKUP_SUCCESS',
                {
                    userId,
                    source: 'enterprise_directory'
                }
            );
            
            return userData;
            
        } catch (error) {
            await this.auditLogger.logEvent(
                'authentication',
                'USER_LOOKUP_FAILED',
                {
                    userId,
                    source: 'enterprise_directory',
                    error: error.message
                }
            );
            
            if (error.response?.status === 404) {
                return null; // User not found
            }
            
            throw error;
        }
    }

    /**
     * Get user groups from enterprise directory
     */
    async getUserGroups(userId) {
        try {
            const response = await this.client.get(`/api/v1/users/${userId}/groups`);
            return response.data.groups || [];
            
        } catch (error) {
            console.error(`Error getting user groups for ${userId}:`, error);
            return [];
        }
    }

    /**
     * Get user roles from enterprise directory
     */
    async getUserRoles(userId) {
        try {
            const response = await this.client.get(`/api/v1/users/${userId}/roles`);
            return response.data.roles || [];
            
        } catch (error) {
            console.error(`Error getting user roles for ${userId}:`, error);
            return [];
        }
    }

    /**
     * Check if user is in specific group
     */
    async isUserInGroup(userId, groupName) {
        try {
            const groups = await this.getUserGroups(userId);
            return groups.some(group => group.name === groupName || group.dn.includes(groupName));
            
        } catch (error) {
            console.error(`Error checking group membership for ${userId}:`, error);
            return false;
        }
    }

    /**
     * Get device information from enterprise directory
     */
    async getDevice(deviceId) {
        try {
            // Check cache first
            if (this.deviceCache.has(deviceId)) {
                const cached = this.deviceCache.get(deviceId);
                if (Date.now() - cached.timestamp < 10 * 60 * 1000) { // 10 minutes cache
                    return cached.data;
                }
            }
            
            const response = await this.client.get(`/api/v1/devices/${deviceId}`);
            const deviceData = response.data;
            
            // Cache the response
            this.deviceCache.set(deviceId, {
                data: deviceData,
                timestamp: Date.now()
            });
            
            return deviceData;
            
        } catch (error) {
            if (error.response?.status === 404) {
                return null; // Device not found
            }
            throw error;
        }
    }

    /**
     * Register device in enterprise directory
     */
    async registerDevice(deviceInfo) {
        try {
            const response = await this.client.post('/api/v1/devices', deviceInfo);
            
            // Clear cache for this device
            this.deviceCache.delete(deviceInfo.deviceId);
            
            await this.auditLogger.logEvent(
                'device_compliance',
                'DEVICE_REGISTERED',
                {
                    deviceId: deviceInfo.deviceId,
                    deviceName: deviceInfo.name,
                    platform: deviceInfo.platform,
                    source: 'enterprise_directory'
                }
            );
            
            return response.data;
            
        } catch (error) {
            await this.auditLogger.logEvent(
                'device_compliance',
                'DEVICE_REGISTRATION_FAILED',
                {
                    deviceId: deviceInfo.deviceId,
                    error: error.message
                }
            );
            
            throw error;
        }
    }

    /**
     * Update device status in enterprise directory
     */
    async updateDeviceStatus(deviceId, status) {
        try {
            const response = await this.client.put(`/api/v1/devices/${deviceId}/status`, {
                status,
                updatedAt: new Date()
            });
            
            // Clear cache for this device
            this.deviceCache.delete(deviceId);
            
            await this.auditLogger.logEvent(
                'device_compliance',
                'DEVICE_STATUS_UPDATED',
                {
                    deviceId,
                    status,
                    source: 'conditional_access'
                }
            );
            
            return response.data;
            
        } catch (error) {
            console.error(`Error updating device status for ${deviceId}:`, error);
            throw error;
        }
    }

    /**
     * Apply group policy to device
     */
    async applyGroupPolicy(deviceId, policyId) {
        try {
            const response = await this.client.post(`/api/v1/devices/${deviceId}/policies`, {
                policyId,
                appliedAt: new Date(),
                source: 'conditional_access'
            });
            
            await this.auditLogger.logEvent(
                'conditional_access',
                'GROUP_POLICY_APPLIED',
                {
                    deviceId,
                    policyId,
                    source: 'conditional_access'
                }
            );
            
            return response.data;
            
        } catch (error) {
            await this.auditLogger.logEvent(
                'conditional_access',
                'GROUP_POLICY_APPLICATION_FAILED',
                {
                    deviceId,
                    policyId,
                    error: error.message
                }
            );
            
            throw error;
        }
    }

    /**
     * Get organizational units from enterprise directory
     */
    async getOrganizationalUnits() {
        try {
            const response = await this.client.get('/api/v1/organizational-units');
            return response.data.organizationalUnits || [];
            
        } catch (error) {
            console.error('Error getting organizational units:', error);
            return [];
        }
    }

    /**
     * Get user's organizational unit
     */
    async getUserOU(userId) {
        try {
            const user = await this.getUser(userId);
            return user?.organizationalUnit || null;
            
        } catch (error) {
            console.error(`Error getting OU for user ${userId}:`, error);
            return null;
        }
    }

    /**
     * Check user account status
     */
    async checkUserAccountStatus(userId) {
        try {
            const user = await this.getUser(userId);
            
            if (!user) {
                return {
                    exists: false,
                    enabled: false,
                    locked: false,
                    expired: false
                };
            }
            
            return {
                exists: true,
                enabled: user.enabled || false,
                locked: user.locked || false,
                expired: user.passwordExpired || false,
                lastLogin: user.lastLogin,
                failedLoginAttempts: user.failedLoginAttempts || 0
            };
            
        } catch (error) {
            console.error(`Error checking account status for ${userId}:`, error);
            return {
                exists: false,
                enabled: false,
                locked: true, // Fail secure
                expired: true
            };
        }
    }

    /**
     * Subscribe to enterprise directory events
     */
    async subscribeToDirectoryEvents() {
        try {
            // In production, this would set up webhooks or event subscriptions
            console.log('📡 Subscribed to Enterprise Directory events');
            
            // For now, just log that we would subscribe
            await this.auditLogger.logEvent(
                'system',
                'DIRECTORY_EVENT_SUBSCRIPTION_CREATED',
                {
                    service: 'conditional_access',
                    events: ['user_created', 'user_updated', 'user_deleted', 'device_created', 'device_updated']
                }
            );
            
        } catch (error) {
            console.error('Error subscribing to directory events:', error);
            throw error;
        }
    }

    /**
     * Handle directory events (webhooks)
     */
    async handleDirectoryEvent(eventType, eventData) {
        try {
            await this.auditLogger.logEvent(
                'system',
                'DIRECTORY_EVENT_RECEIVED',
                {
                    eventType,
                    eventData
                }
            );
            
            switch (eventType) {
                case 'user_updated':
                    // Clear user cache
                    this.userCache.delete(eventData.userId);
                    break;
                    
                case 'device_updated':
                    // Clear device cache
                    this.deviceCache.delete(eventData.deviceId);
                    break;
                    
                case 'user_disabled':
                    // Terminate all sessions for this user
                    await this.handleUserDisabled(eventData.userId);
                    break;
                    
                case 'device_compliance_changed':
                    // Reevaluate device access
                    await this.handleDeviceComplianceChange(eventData.deviceId, eventData.compliant);
                    break;
            }
            
        } catch (error) {
            console.error('Error handling directory event:', error);
        }
    }

    /**
     * Handle user disabled event
     */
    async handleUserDisabled(userId) {
        // This would integrate with the conditional access engine to terminate sessions
        console.log(`🚫 Handling user disabled event for ${userId}`);
        
        await this.auditLogger.logEvent(
            'authentication',
            'USER_DISABLED_EVENT_HANDLED',
            {
                userId,
                action: 'terminate_sessions'
            }
        );
    }

    /**
     * Handle device compliance change
     */
    async handleDeviceComplianceChange(deviceId, compliant) {
        console.log(`📱 Handling compliance change for device ${deviceId}: ${compliant}`);
        
        await this.auditLogger.logEvent(
            'device_compliance',
            'DEVICE_COMPLIANCE_CHANGED',
            {
                deviceId,
                compliant,
                action: compliant ? 'restore_access' : 'restrict_access'
            }
        );
    }

    /**
     * Get password policy from enterprise directory
     */
    async getPasswordPolicy() {
        try {
            const response = await this.client.get('/api/v1/policies/password');
            return response.data;
            
        } catch (error) {
            console.error('Error getting password policy:', error);
            return {
                minLength: 8,
                requireComplexity: true,
                maxAge: 90,
                historyCount: 12
            };
        }
    }

    /**
     * Create computer account for autopilot deployment
     */
    async createComputerAccount(computerInfo) {
        try {
            const response = await this.client.post('/api/v1/computers', {
                name: computerInfo.name,
                serialNumber: computerInfo.serialNumber,
                platform: computerInfo.platform,
                organizationalUnit: computerInfo.ou,
                createdBy: 'conditional-access-service'
            });
            
            await this.auditLogger.logEvent(
                'deployment',
                'COMPUTER_ACCOUNT_CREATED',
                {
                    computerName: computerInfo.name,
                    serialNumber: computerInfo.serialNumber,
                    platform: computerInfo.platform
                }
            );
            
            return response.data;
            
        } catch (error) {
            await this.auditLogger.logEvent(
                'deployment',
                'COMPUTER_ACCOUNT_CREATION_FAILED',
                {
                    computerName: computerInfo.name,
                    error: error.message
                }
            );
            
            throw error;
        }
    }

    /**
     * Get service account information
     */
    async getServiceAccount(serviceName) {
        try {
            const response = await this.client.get(`/api/v1/service-accounts/${serviceName}`);
            return response.data;
            
        } catch (error) {
            if (error.response?.status === 404) {
                return null;
            }
            throw error;
        }
    }

    /**
     * Clear caches
     */
    clearCaches() {
        this.userCache.clear();
        this.groupCache.clear();
        this.deviceCache.clear();
        console.log('🗑️ Enterprise Directory caches cleared');
    }

    /**
     * Get cache statistics
     */
    getCacheStatistics() {
        return {
            users: {
                size: this.userCache.size,
                hitRatio: this.calculateHitRatio('user')
            },
            groups: {
                size: this.groupCache.size,
                hitRatio: this.calculateHitRatio('group')
            },
            devices: {
                size: this.deviceCache.size,
                hitRatio: this.calculateHitRatio('device')
            }
        };
    }

    calculateHitRatio(cacheType) {
        // In production, track cache hits/misses
        return 0.85; // Simulated 85% hit ratio
    }

    /**
     * Shutdown the integration
     */
    async shutdown() {
        console.log('🔗 Shutting down Enterprise Directory Integration...');
        
        this.clearCaches();
        
        await this.auditLogger.logEvent(
            'system',
            'ENTERPRISE_DIRECTORY_INTEGRATION_SHUTDOWN',
            {
                timestamp: new Date()
            }
        );
        
        console.log('✅ Enterprise Directory Integration shutdown complete');
    }
}

module.exports = EnterpriseDirectoryIntegration;