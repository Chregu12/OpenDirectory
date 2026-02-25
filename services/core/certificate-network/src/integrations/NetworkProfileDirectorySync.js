/**
 * OpenDirectory Network Profile Directory Sync Service
 * Synchronizes network profile deployments and configurations with the Enterprise Directory
 * for seamless integration with user and computer objects
 */

const EventEmitter = require('events');
const { logger } = require('../utils/logger');

class NetworkProfileDirectorySync extends EventEmitter {
  constructor(config, enterpriseDirectoryIntegration, wifiProfileService, vpnProfileService, emailProfileService) {
    super();
    
    this.config = config;
    this.enterpriseDirectory = enterpriseDirectoryIntegration;
    this.wifiService = wifiProfileService;
    this.vpnService = vpnProfileService;
    this.emailService = emailProfileService;
    
    // Sync state
    this.profileDeployments = new Map(); // Track active deployments
    this.syncInProgress = false;
    this.lastPolicySync = null;
    
    // Sync configuration
    this.policySyncInterval = config.networkProfileSync.policySyncInterval || 900000; // 15 minutes
    this.deploymentStatusInterval = config.networkProfileSync.deploymentStatusInterval || 300000; // 5 minutes
    
    logger.info('📡 Network Profile Directory Sync Service initialized');
  }

  async initialize() {
    try {
      logger.info('🚀 Starting Network Profile Directory Sync...');

      // Wait for Enterprise Directory to be connected
      if (!this.enterpriseDirectory.connected) {
        await new Promise((resolve) => {
          this.enterpriseDirectory.once('connected', resolve);
        });
      }

      // Set up event listeners
      this.setupEventListeners();
      
      // Perform initial policy synchronization
      await this.syncNetworkPolicies();
      
      // Schedule periodic syncs
      this.schedulePeriodicSyncs();
      
      logger.info('✅ Network Profile Directory Sync initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Network Profile Directory Sync:', error);
      throw error;
    }
  }

  setupEventListeners() {
    // Listen for directory events
    this.enterpriseDirectory.on('userAuthenticated', this.handleUserAuthenticated.bind(this));
    this.enterpriseDirectory.on('computerJoined', this.handleComputerJoined.bind(this));
    this.enterpriseDirectory.on('disconnected', this.handleDirectoryDisconnected.bind(this));
    this.enterpriseDirectory.on('connected', this.handleDirectoryReconnected.bind(this));

    // Listen for network service events
    this.wifiService.on('profileDeployed', this.handleProfileDeployed.bind(this));
    this.vpnService.on('profileDeployed', this.handleProfileDeployed.bind(this));
    this.emailService.on('profileDeployed', this.handleProfileDeployed.bind(this));

    this.wifiService.on('profileRemoved', this.handleProfileRemoved.bind(this));
    this.vpnService.on('profileRemoved', this.handleProfileRemoved.bind(this));
    this.emailService.on('profileRemoved', this.handleProfileRemoved.bind(this));

    logger.info('🔗 Network profile sync event listeners configured');
  }

  // Directory Event Handlers
  async handleUserAuthenticated(event) {
    try {
      const { user } = event;
      
      logger.debug(`📱 Processing network profiles for authenticated user: ${user.sAMAccountName}`);

      // Check for network policy-based profile deployments
      await this.processUserNetworkPolicies(user);

    } catch (error) {
      logger.error('User authentication network sync error:', error);
    }
  }

  async handleComputerJoined(event) {
    try {
      const { computer } = event;
      
      logger.debug(`🖥️ Processing network profiles for joined computer: ${computer.sAMAccountName}`);

      // Check for computer-based network policy deployments
      await this.processComputerNetworkPolicies(computer);

    } catch (error) {
      logger.error('Computer join network sync error:', error);
    }
  }

  async handleDirectoryDisconnected() {
    logger.warn('🔴 Enterprise Directory disconnected - pausing network profile sync');
    this.pausePeriodicSyncs();
  }

  async handleDirectoryReconnected() {
    logger.info('🟢 Enterprise Directory reconnected - resuming network profile sync');
    this.schedulePeriodicSyncs();
    
    // Refresh network policies
    await this.syncNetworkPolicies();
  }

  // Profile Event Handlers
  async handleProfileDeployed(event) {
    try {
      const { profileType, profileData, deploymentInfo } = event;
      
      logger.debug(`📡 Network profile deployed: ${profileType} for ${deploymentInfo.targetType}:${deploymentInfo.targetId}`);

      // Track deployment
      const deploymentKey = `${profileType}:${deploymentInfo.targetType}:${deploymentInfo.targetId}:${profileData.profileId}`;
      this.profileDeployments.set(deploymentKey, {
        profileType,
        profileData,
        deploymentInfo,
        deployedAt: new Date(),
        status: 'deployed'
      });

      // Notify Enterprise Directory of deployment
      await this.notifyProfileDeployment(profileType, profileData, deploymentInfo);

      this.emit('profileDeploymentSynced', { action: 'deployed', profileType, deploymentInfo });

    } catch (error) {
      logger.error('Profile deployment sync error:', error);
    }
  }

  async handleProfileRemoved(event) {
    try {
      const { profileType, profileData, deploymentInfo } = event;
      
      logger.debug(`📱 Network profile removed: ${profileType} for ${deploymentInfo.targetType}:${deploymentInfo.targetId}`);

      // Update deployment tracking
      const deploymentKey = `${profileType}:${deploymentInfo.targetType}:${deploymentInfo.targetId}:${profileData.profileId}`;
      const deployment = this.profileDeployments.get(deploymentKey);
      if (deployment) {
        deployment.status = 'removed';
        deployment.removedAt = new Date();
      }

      // Notify Enterprise Directory of removal
      await this.notifyProfileRemoval(profileType, profileData, deploymentInfo);

      this.emit('profileDeploymentSynced', { action: 'removed', profileType, deploymentInfo });

    } catch (error) {
      logger.error('Profile removal sync error:', error);
    }
  }

  // Network Policy Processing
  async syncNetworkPolicies() {
    if (this.syncInProgress) {
      logger.warn('Network policy sync already in progress, skipping');
      return;
    }

    try {
      this.syncInProgress = true;
      logger.info('🔄 Starting network policy synchronization...');

      const startTime = Date.now();
      let processedPolicies = 0;

      // Get all network-related policies from Enterprise Directory
      const policies = await this.getNetworkPoliciesFromDirectory();

      for (const policy of policies) {
        try {
          await this.processNetworkPolicy(policy);
          processedPolicies++;
        } catch (error) {
          logger.error(`Policy processing error for ${policy.name}:`, error);
        }
      }

      const duration = Date.now() - startTime;
      this.lastPolicySync = new Date();

      logger.info(`✅ Network policy sync completed: ${processedPolicies} policies processed, ${duration}ms`);

    } catch (error) {
      logger.error('Network policy sync failed:', error);
    } finally {
      this.syncInProgress = false;
    }
  }

  async getNetworkPoliciesFromDirectory() {
    try {
      const response = await this.enterpriseDirectory.apiClient.get('/api/policies/network');
      
      if (response.data.success) {
        return response.data.policies.filter(policy => 
          policy.enabled && 
          ['wifi', 'vpn', 'email'].includes(policy.category.toLowerCase())
        );
      } else {
        logger.warn('Failed to retrieve network policies from directory');
        return [];
      }

    } catch (error) {
      logger.error('Failed to get network policies:', error);
      return [];
    }
  }

  async processNetworkPolicy(policy) {
    logger.debug(`📋 Processing network policy: ${policy.name} (${policy.category})`);

    switch (policy.category.toLowerCase()) {
      case 'wifi':
        await this.processWiFiPolicy(policy);
        break;
      case 'vpn':
        await this.processVPNPolicy(policy);
        break;
      case 'email':
        await this.processEmailPolicy(policy);
        break;
      default:
        logger.warn(`Unknown network policy category: ${policy.category}`);
    }
  }

  async processWiFiPolicy(policy) {
    try {
      const { settings, targets } = policy;
      
      // Process user and computer targets
      for (const target of targets) {
        if (target.type === 'user') {
          await this.deployWiFiProfileToUser(target.objectGUID, settings);
        } else if (target.type === 'computer') {
          await this.deployWiFiProfileToComputer(target.objectGUID, settings);
        } else if (target.type === 'group') {
          await this.deployWiFiProfileToGroup(target.objectGUID, settings);
        }
      }

    } catch (error) {
      logger.error('WiFi policy processing error:', error);
    }
  }

  async processVPNPolicy(policy) {
    try {
      const { settings, targets } = policy;
      
      // Process user and computer targets
      for (const target of targets) {
        if (target.type === 'user') {
          await this.deployVPNProfileToUser(target.objectGUID, settings);
        } else if (target.type === 'computer') {
          await this.deployVPNProfileToComputer(target.objectGUID, settings);
        } else if (target.type === 'group') {
          await this.deployVPNProfileToGroup(target.objectGUID, settings);
        }
      }

    } catch (error) {
      logger.error('VPN policy processing error:', error);
    }
  }

  async processEmailPolicy(policy) {
    try {
      const { settings, targets } = policy;
      
      // Process user targets (email profiles are typically user-specific)
      for (const target of targets) {
        if (target.type === 'user') {
          await this.deployEmailProfileToUser(target.objectGUID, settings);
        } else if (target.type === 'group') {
          await this.deployEmailProfileToGroup(target.objectGUID, settings);
        }
      }

    } catch (error) {
      logger.error('Email policy processing error:', error);
    }
  }

  // User-specific Policy Processing
  async processUserNetworkPolicies(user) {
    try {
      // Get user's network policies
      const policiesResult = await this.enterpriseDirectory.getUserPolicies(user.objectGUID);
      if (!policiesResult.success) {
        return;
      }

      const networkPolicies = policiesResult.networkPolicies;

      for (const policy of networkPolicies) {
        if (!policy.enabled) continue;

        switch (policy.category.toLowerCase()) {
          case 'wifi':
            await this.deployWiFiProfileToUser(user.objectGUID, policy.settings, user);
            break;
          case 'vpn':
            await this.deployVPNProfileToUser(user.objectGUID, policy.settings, user);
            break;
          case 'email':
            await this.deployEmailProfileToUser(user.objectGUID, policy.settings, user);
            break;
        }
      }

    } catch (error) {
      logger.error('User network policy processing error:', error);
    }
  }

  async processComputerNetworkPolicies(computer) {
    try {
      // Get computer's network policies
      const policiesResult = await this.enterpriseDirectory.getComputerPolicies(computer.objectGUID);
      if (!policiesResult.success) {
        return;
      }

      const networkPolicies = policiesResult.networkPolicies;

      for (const policy of networkPolicies) {
        if (!policy.enabled) continue;

        switch (policy.category.toLowerCase()) {
          case 'wifi':
            await this.deployWiFiProfileToComputer(computer.objectGUID, policy.settings, computer);
            break;
          case 'vpn':
            await this.deployVPNProfileToComputer(computer.objectGUID, policy.settings, computer);
            break;
        }
      }

    } catch (error) {
      logger.error('Computer network policy processing error:', error);
    }
  }

  // Profile Deployment Methods
  async deployWiFiProfileToUser(userGUID, settings, userInfo = null) {
    try {
      if (!userInfo) {
        const userResult = await this.enterpriseDirectory.getUserByIdentifier(userGUID, 'guid');
        if (!userResult.success) {
          logger.warn(`User not found for WiFi deployment: ${userGUID}`);
          return;
        }
        userInfo = userResult.user;
      }

      logger.debug(`📶 Deploying WiFi profile to user: ${userInfo.sAMAccountName}`);

      // Generate WiFi profile with user-specific settings
      const profileConfig = {
        ssid: settings.ssid,
        security: settings.security,
        authentication: settings.authentication,
        userInfo: {
          username: userInfo.sAMAccountName,
          userPrincipalName: userInfo.userPrincipalName,
          mail: userInfo.mail,
          groups: userInfo.groups
        },
        certificateAuth: settings.certificateAuth,
        autoConnect: settings.autoConnect,
        hidden: settings.hidden
      };

      await this.wifiService.deployUserProfile(userGUID, profileConfig);

    } catch (error) {
      logger.error('WiFi user profile deployment error:', error);
    }
  }

  async deployWiFiProfileToComputer(computerGUID, settings, computerInfo = null) {
    try {
      if (!computerInfo) {
        const computerResult = await this.enterpriseDirectory.getComputerByIdentifier(computerGUID, 'guid');
        if (!computerResult.success) {
          logger.warn(`Computer not found for WiFi deployment: ${computerGUID}`);
          return;
        }
        computerInfo = computerResult.computer;
      }

      logger.debug(`📶 Deploying WiFi profile to computer: ${computerInfo.sAMAccountName}`);

      const profileConfig = {
        ssid: settings.ssid,
        security: settings.security,
        authentication: settings.authentication,
        computerInfo: {
          name: computerInfo.sAMAccountName,
          dnsHostName: computerInfo.dNSHostName,
          operatingSystem: computerInfo.operatingSystem
        },
        certificateAuth: settings.certificateAuth,
        autoConnect: settings.autoConnect,
        machineAuth: true
      };

      await this.wifiService.deployComputerProfile(computerGUID, profileConfig);

    } catch (error) {
      logger.error('WiFi computer profile deployment error:', error);
    }
  }

  async deployVPNProfileToUser(userGUID, settings, userInfo = null) {
    try {
      if (!userInfo) {
        const userResult = await this.enterpriseDirectory.getUserByIdentifier(userGUID, 'guid');
        if (!userResult.success) {
          logger.warn(`User not found for VPN deployment: ${userGUID}`);
          return;
        }
        userInfo = userResult.user;
      }

      logger.debug(`🔒 Deploying VPN profile to user: ${userInfo.sAMAccountName}`);

      const profileConfig = {
        serverAddress: settings.serverAddress,
        protocol: settings.protocol,
        authenticationMethod: settings.authenticationMethod,
        userInfo: {
          username: userInfo.sAMAccountName,
          userPrincipalName: userInfo.userPrincipalName,
          mail: userInfo.mail
        },
        certificateAuth: settings.certificateAuth,
        splitTunneling: settings.splitTunneling,
        routes: settings.routes,
        dnsServers: settings.dnsServers
      };

      await this.vpnService.deployUserProfile(userGUID, profileConfig);

    } catch (error) {
      logger.error('VPN user profile deployment error:', error);
    }
  }

  async deployVPNProfileToComputer(computerGUID, settings, computerInfo = null) {
    try {
      if (!computerInfo) {
        const computerResult = await this.enterpriseDirectory.getComputerByIdentifier(computerGUID, 'guid');
        if (!computerResult.success) {
          logger.warn(`Computer not found for VPN deployment: ${computerGUID}`);
          return;
        }
        computerInfo = computerResult.computer;
      }

      logger.debug(`🔒 Deploying VPN profile to computer: ${computerInfo.sAMAccountName}`);

      const profileConfig = {
        serverAddress: settings.serverAddress,
        protocol: settings.protocol,
        authenticationMethod: settings.authenticationMethod,
        computerInfo: {
          name: computerInfo.sAMAccountName,
          dnsHostName: computerInfo.dNSHostName
        },
        certificateAuth: settings.certificateAuth,
        alwaysOn: settings.alwaysOn,
        machineAuth: true
      };

      await this.vpnService.deployComputerProfile(computerGUID, profileConfig);

    } catch (error) {
      logger.error('VPN computer profile deployment error:', error);
    }
  }

  async deployEmailProfileToUser(userGUID, settings, userInfo = null) {
    try {
      if (!userInfo) {
        const userResult = await this.enterpriseDirectory.getUserByIdentifier(userGUID, 'guid');
        if (!userResult.success) {
          logger.warn(`User not found for email deployment: ${userGUID}`);
          return;
        }
        userInfo = userResult.user;
      }

      logger.debug(`📧 Deploying email profile to user: ${userInfo.sAMAccountName}`);

      const profileConfig = {
        emailProvider: settings.emailProvider,
        serverSettings: settings.serverSettings,
        userInfo: {
          displayName: userInfo.displayName,
          emailAddress: userInfo.mail,
          username: userInfo.sAMAccountName,
          userPrincipalName: userInfo.userPrincipalName
        },
        security: settings.security,
        smimeSettings: settings.smimeSettings,
        autoDiscover: settings.autoDiscover
      };

      await this.emailService.deployUserProfile(userGUID, profileConfig);

    } catch (error) {
      logger.error('Email user profile deployment error:', error);
    }
  }

  // Group-based Deployments
  async deployWiFiProfileToGroup(groupGUID, settings) {
    try {
      const groupMembers = await this.getGroupMembers(groupGUID);
      
      for (const member of groupMembers) {
        if (member.type === 'user') {
          await this.deployWiFiProfileToUser(member.objectGUID, settings);
        } else if (member.type === 'computer') {
          await this.deployWiFiProfileToComputer(member.objectGUID, settings);
        }
      }

    } catch (error) {
      logger.error('WiFi group profile deployment error:', error);
    }
  }

  async deployVPNProfileToGroup(groupGUID, settings) {
    try {
      const groupMembers = await this.getGroupMembers(groupGUID);
      
      for (const member of groupMembers) {
        if (member.type === 'user') {
          await this.deployVPNProfileToUser(member.objectGUID, settings);
        } else if (member.type === 'computer') {
          await this.deployVPNProfileToComputer(member.objectGUID, settings);
        }
      }

    } catch (error) {
      logger.error('VPN group profile deployment error:', error);
    }
  }

  async deployEmailProfileToGroup(groupGUID, settings) {
    try {
      const groupMembers = await this.getGroupMembers(groupGUID);
      
      for (const member of groupMembers) {
        if (member.type === 'user') {
          await this.deployEmailProfileToUser(member.objectGUID, settings);
        }
      }

    } catch (error) {
      logger.error('Email group profile deployment error:', error);
    }
  }

  async getGroupMembers(groupGUID) {
    try {
      const response = await this.enterpriseDirectory.apiClient.get(`/api/groups/${groupGUID}/members`);
      
      if (response.data.success) {
        return response.data.members;
      } else {
        logger.warn(`Failed to get group members: ${groupGUID}`);
        return [];
      }

    } catch (error) {
      logger.error('Group member lookup error:', error);
      return [];
    }
  }

  // Directory Notification Methods
  async notifyProfileDeployment(profileType, profileData, deploymentInfo) {
    try {
      await this.enterpriseDirectory.apiClient.post('/api/network-profiles/deployed', {
        profileType,
        profileData: {
          profileId: profileData.profileId,
          name: profileData.name,
          platform: profileData.platform,
          size: profileData.size || 0
        },
        deploymentInfo,
        deployedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Profile deployment notification error:', error);
    }
  }

  async notifyProfileRemoval(profileType, profileData, deploymentInfo) {
    try {
      await this.enterpriseDirectory.apiClient.post('/api/network-profiles/removed', {
        profileType,
        profileData: {
          profileId: profileData.profileId,
          name: profileData.name
        },
        deploymentInfo,
        removedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Profile removal notification error:', error);
    }
  }

  // Scheduling and Management
  schedulePeriodicSyncs() {
    if (this.policySyncTimer) {
      clearInterval(this.policySyncTimer);
    }
    if (this.deploymentStatusTimer) {
      clearInterval(this.deploymentStatusTimer);
    }

    // Schedule policy sync
    this.policySyncTimer = setInterval(async () => {
      try {
        await this.syncNetworkPolicies();
      } catch (error) {
        logger.error('Scheduled policy sync error:', error);
      }
    }, this.policySyncInterval);

    // Schedule deployment status updates
    this.deploymentStatusTimer = setInterval(async () => {
      try {
        await this.updateDeploymentStatuses();
      } catch (error) {
        logger.error('Deployment status update error:', error);
      }
    }, this.deploymentStatusInterval);

    logger.info('📅 Network profile sync timers scheduled');
  }

  pausePeriodicSyncs() {
    if (this.policySyncTimer) {
      clearInterval(this.policySyncTimer);
      this.policySyncTimer = null;
    }
    if (this.deploymentStatusTimer) {
      clearInterval(this.deploymentStatusTimer);
      this.deploymentStatusTimer = null;
    }

    logger.info('⏸️ Network profile sync timers paused');
  }

  async updateDeploymentStatuses() {
    // Check status of active deployments and update Enterprise Directory
    for (const [key, deployment] of this.profileDeployments) {
      if (deployment.status === 'deployed') {
        // Verify deployment is still active
        // Update status as needed
      }
    }
  }

  // Status and Health
  getStatus() {
    return {
      syncInProgress: this.syncInProgress,
      lastPolicySync: this.lastPolicySync,
      activeDeployments: this.profileDeployments.size,
      timersActive: !!(this.policySyncTimer && this.deploymentStatusTimer),
      enterpriseDirectoryConnected: this.enterpriseDirectory.connected,
      serviceStatus: {
        wifiService: this.wifiService ? 'available' : 'unavailable',
        vpnService: this.vpnService ? 'available' : 'unavailable',
        emailService: this.emailService ? 'available' : 'unavailable'
      }
    };
  }

  async stop() {
    logger.info('🛑 Stopping Network Profile Directory Sync...');
    
    this.pausePeriodicSyncs();
    this.syncInProgress = false;
    this.profileDeployments.clear();
    
    logger.info('✅ Network Profile Directory Sync stopped');
  }
}

module.exports = NetworkProfileDirectorySync;