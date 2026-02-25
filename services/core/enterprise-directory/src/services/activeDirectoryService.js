/**
 * OpenDirectory Active Directory Service
 * Complete replacement for Microsoft Active Directory Domain Services
 * Provides domain controller functionality for Windows, macOS, and Linux
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const EventEmitter = require('events');
const { logger, logHelpers } = require('../utils/logger');

// Domain object schemas
const UserSchema = new mongoose.Schema({
  objectGUID: { type: String, unique: true, default: uuidv4 },
  sAMAccountName: { type: String, unique: true, required: true },
  userPrincipalName: { type: String, unique: true, required: true },
  distinguishedName: { type: String, unique: true, required: true },
  commonName: { type: String, required: true },
  givenName: String,
  surname: String,
  displayName: String,
  description: String,
  mail: String,
  telephoneNumber: String,
  mobile: String,
  department: String,
  title: String,
  manager: { type: mongoose.Schema.Types.ObjectId, ref: 'DomainUser' },
  directReports: [{ type: mongoose.Schema.Types.ObjectId, ref: 'DomainUser' }],
  
  // Authentication
  unicodePwd: { type: String, required: true }, // NT password hash
  pwdLastSet: { type: Date, default: Date.now },
  lastLogon: Date,
  lastLogonTimestamp: Date,
  logonCount: { type: Number, default: 0 },
  badPwdCount: { type: Number, default: 0 },
  badPasswordTime: Date,
  lockoutTime: Date,
  
  // Account control
  userAccountControl: { type: Number, default: 512 }, // UF_NORMAL_ACCOUNT
  accountExpires: Date,
  passwordMustChange: Boolean,
  passwordNeverExpires: Boolean,
  passwordCannotChange: Boolean,
  accountLocked: { type: Boolean, default: false },
  accountEnabled: { type: Boolean, default: true },
  
  // Group memberships
  memberOf: [{ type: mongoose.Schema.Types.ObjectId, ref: 'DomainGroup' }],
  primaryGroupID: { type: Number, default: 513 }, // Domain Users
  
  // Kerberos
  servicePrincipalNames: [String],
  supportedEncryptionTypes: { type: Number, default: 31 }, // All encryption types
  
  // Profile
  profilePath: String,
  homeDirectory: String,
  homeDrive: String,
  scriptPath: String,
  
  // Extended attributes
  extensionAttributes: mongoose.Schema.Types.Mixed,
  customAttributes: mongoose.Schema.Types.Mixed,
  
  // Timestamps
  whenCreated: { type: Date, default: Date.now },
  whenChanged: { type: Date, default: Date.now },
  uSNCreated: Number,
  uSNChanged: Number,
  
  // Replication
  objectSid: String,
  securityIdentifier: String,
  
  // Certificate information
  userCertificate: [String],
  userSMIMECertificate: [String]
});

const GroupSchema = new mongoose.Schema({
  objectGUID: { type: String, unique: true, default: uuidv4 },
  sAMAccountName: { type: String, unique: true, required: true },
  distinguishedName: { type: String, unique: true, required: true },
  commonName: { type: String, required: true },
  displayName: String,
  description: String,
  mail: String,
  
  // Group properties
  groupType: { type: Number, required: true }, // Security or distribution group
  groupScope: { type: String, enum: ['DomainLocal', 'Global', 'Universal'], default: 'Global' },
  
  // Membership
  members: [{ type: mongoose.Schema.Types.ObjectId, refPath: 'memberTypes' }],
  memberTypes: [{ type: String, enum: ['DomainUser', 'DomainGroup', 'DomainComputer'] }],
  memberOf: [{ type: mongoose.Schema.Types.ObjectId, ref: 'DomainGroup' }],
  
  // Security
  objectSid: String,
  securityIdentifier: String,
  
  // Extended attributes
  extensionAttributes: mongoose.Schema.Types.Mixed,
  customAttributes: mongoose.Schema.Types.Mixed,
  
  // Timestamps
  whenCreated: { type: Date, default: Date.now },
  whenChanged: { type: Date, default: Date.now },
  uSNCreated: Number,
  uSNChanged: Number
});

const ComputerSchema = new mongoose.Schema({
  objectGUID: { type: String, unique: true, default: uuidv4 },
  sAMAccountName: { type: String, unique: true, required: true }, // Computer name with $
  distinguishedName: { type: String, unique: true, required: true },
  commonName: { type: String, required: true },
  dNSHostName: String,
  description: String,
  location: String,
  
  // Computer properties
  operatingSystem: String,
  operatingSystemVersion: String,
  operatingSystemServicePack: String,
  operatingSystemHotfix: String,
  
  // Network information
  networkAddresses: [String],
  servicePrincipalNames: [String],
  
  // Trust relationship
  userAccountControl: { type: Number, default: 4096 }, // UF_WORKSTATION_TRUST_ACCOUNT
  unicodePwd: String, // Machine account password
  pwdLastSet: { type: Date, default: Date.now },
  lastLogon: Date,
  lastLogonTimestamp: Date,
  
  // Group memberships
  memberOf: [{ type: mongoose.Schema.Types.ObjectId, ref: 'DomainGroup' }],
  primaryGroupID: { type: Number, default: 515 }, // Domain Computers
  
  // Security
  objectSid: String,
  securityIdentifier: String,
  localPolicyFlags: Number,
  
  // Management
  managedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'DomainUser' },
  
  // Extended attributes
  extensionAttributes: mongoose.Schema.Types.Mixed,
  customAttributes: mongoose.Schema.Types.Mixed,
  
  // Timestamps
  whenCreated: { type: Date, default: Date.now },
  whenChanged: { type: Date, default: Date.now },
  uSNCreated: Number,
  uSNChanged: Number
});

const OrganizationalUnitSchema = new mongoose.Schema({
  objectGUID: { type: String, unique: true, default: uuidv4 },
  distinguishedName: { type: String, unique: true, required: true },
  commonName: { type: String, required: true },
  name: { type: String, required: true },
  description: String,
  
  // OU properties
  street: String,
  l: String, // City
  st: String, // State
  postalCode: String,
  c: String, // Country
  co: String, // Country name
  countryCode: Number,
  
  // Management
  managedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'DomainUser' },
  
  // Group Policy links
  groupPolicyLinks: [{
    gPLinkOptions: Number,
    gPOGuid: String,
    gPODisplayName: String,
    enforced: Boolean,
    enabled: Boolean
  }],
  
  // Security
  objectSid: String,
  
  // Extended attributes
  extensionAttributes: mongoose.Schema.Types.Mixed,
  
  // Timestamps
  whenCreated: { type: Date, default: Date.now },
  whenChanged: { type: Date, default: Date.now },
  uSNCreated: Number,
  uSNChanged: Number
});

class ActiveDirectoryService extends EventEmitter {
  constructor(config, mongodb, redis, ldapService, kerberosService) {
    super();
    
    this.config = config;
    this.mongodb = mongodb;
    this.redis = redis;
    this.ldapService = ldapService;
    this.kerberosService = kerberosService;
    
    // Domain configuration
    this.domain = config.activeDirectory.domain;
    this.netbiosName = config.activeDirectory.netbiosName;
    this.baseDN = config.activeDirectory.baseDN;
    
    // Models
    this.DomainUser = null;
    this.DomainGroup = null;
    this.DomainComputer = null;
    this.OrganizationalUnit = null;
    
    // Domain state
    this.domainControllers = new Map();
    this.forestInfo = null;
    this.domainInfo = null;
    this.usnCounter = 0;
    
    // Built-in security identifiers
    this.wellKnownSids = {
      'Domain Admins': 'S-1-5-21-domain-512',
      'Domain Users': 'S-1-5-21-domain-513',
      'Domain Guests': 'S-1-5-21-domain-514',
      'Domain Computers': 'S-1-5-21-domain-515',
      'Enterprise Admins': 'S-1-5-21-root-domain-519',
      'Schema Admins': 'S-1-5-21-root-domain-518'
    };
  }

  async initialize() {
    try {
      logger.info('🏛️ Initializing Active Directory Service...');

      // Initialize models
      this.initializeModels();

      // Setup domain infrastructure
      await this.setupDomain();

      // Initialize built-in accounts and groups
      await this.createBuiltInObjects();

      // Setup replication monitoring
      this.setupReplication();

      // Start domain controller services
      await this.startDomainController();

      logger.info('✅ Active Directory Service initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Active Directory Service:', error);
      throw error;
    }
  }

  initializeModels() {
    // Add middleware for timestamps and USN
    const updateMiddleware = function(next) {
      this.whenChanged = new Date();
      this.uSNChanged = Date.now();
      next();
    };

    UserSchema.pre('save', updateMiddleware);
    UserSchema.pre('findOneAndUpdate', updateMiddleware);
    GroupSchema.pre('save', updateMiddleware);
    GroupSchema.pre('findOneAndUpdate', updateMiddleware);
    ComputerSchema.pre('save', updateMiddleware);
    ComputerSchema.pre('findOneAndUpdate', updateMiddleware);
    OrganizationalUnitSchema.pre('save', updateMiddleware);
    OrganizationalUnitSchema.pre('findOneAndUpdate', updateMiddleware);

    // Create models
    this.DomainUser = mongoose.model('DomainUser', UserSchema);
    this.DomainGroup = mongoose.model('DomainGroup', GroupSchema);
    this.DomainComputer = mongoose.model('DomainComputer', ComputerSchema);
    this.OrganizationalUnit = mongoose.model('OrganizationalUnit', OrganizationalUnitSchema);

    logger.info('📋 Domain models initialized');
  }

  async setupDomain() {
    try {
      // Initialize domain information
      this.domainInfo = {
        domainDN: this.baseDN,
        domainNetBIOSName: this.netbiosName,
        domainSid: await this.generateDomainSid(),
        domainGuid: uuidv4(),
        forestName: this.domain,
        functionalLevel: this.config.activeDirectory.domainFunctionalLevel,
        creationTime: new Date(),
        lockoutDuration: 30 * 60 * 1000, // 30 minutes
        lockoutObservationWindow: 30 * 60 * 1000,
        lockoutThreshold: 5,
        maxPasswordAge: 42 * 24 * 60 * 60 * 1000, // 42 days
        minPasswordAge: 1 * 24 * 60 * 60 * 1000, // 1 day
        minPasswordLength: 8,
        passwordHistoryLength: 12,
        passwordProperties: 1 // DOMAIN_PASSWORD_COMPLEX
      };

      // Initialize forest information
      this.forestInfo = {
        forestName: this.domain,
        forestSid: this.domainInfo.domainSid,
        forestGuid: uuidv4(),
        functionalLevel: this.config.activeDirectory.forestFunctionalLevel,
        schemaMaster: `CN=NTDS Settings,CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`,
        domainNamingMaster: `CN=NTDS Settings,CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`,
        pdcEmulator: `CN=NTDS Settings,CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`,
        ridMaster: `CN=NTDS Settings,CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`,
        infrastructureMaster: `CN=NTDS Settings,CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`
      };

      // Store domain and forest info in Redis
      await this.redis.hSet('ad:domain:info', this.domainInfo);
      await this.redis.hSet('ad:forest:info', this.forestInfo);

      logger.info('🌲 Domain and forest configuration initialized');

    } catch (error) {
      logger.error('❌ Failed to setup domain:', error);
      throw error;
    }
  }

  async createBuiltInObjects() {
    try {
      // Create default organizational units
      await this.createDefaultOUs();

      // Create built-in groups
      await this.createBuiltInGroups();

      // Create Administrator account
      await this.createAdministratorAccount();

      // Create computer accounts container
      await this.ensureComputersContainer();

      logger.info('🏗️ Built-in domain objects created');

    } catch (error) {
      logger.error('❌ Failed to create built-in objects:', error);
      throw error;
    }
  }

  async createDefaultOUs() {
    const defaultOUs = [
      {
        name: 'Users',
        distinguishedName: `CN=Users,${this.baseDN}`,
        description: 'Default container for user objects'
      },
      {
        name: 'Computers',
        distinguishedName: `CN=Computers,${this.baseDN}`,
        description: 'Default container for computer objects'
      },
      {
        name: 'Builtin',
        distinguishedName: `CN=Builtin,${this.baseDN}`,
        description: 'Built-in security principals'
      },
      {
        name: 'Domain Controllers',
        distinguishedName: `OU=Domain Controllers,${this.baseDN}`,
        description: 'Default container for domain controller computer objects'
      }
    ];

    for (const ou of defaultOUs) {
      const existing = await this.OrganizationalUnit.findOne({ distinguishedName: ou.distinguishedName });
      if (!existing) {
        const newOU = new this.OrganizationalUnit({
          commonName: ou.name,
          name: ou.name,
          distinguishedName: ou.distinguishedName,
          description: ou.description,
          objectSid: await this.generateSid(),
          uSNCreated: this.getNextUSN(),
          uSNChanged: this.getNextUSN()
        });

        await newOU.save();
        logHelpers.logAdminAction('System', 'Create OU', ou.distinguishedName);
      }
    }
  }

  async createBuiltInGroups() {
    const builtInGroups = [
      {
        sAMAccountName: 'Domain Admins',
        distinguishedName: `CN=Domain Admins,CN=Users,${this.baseDN}`,
        groupType: -2147483646, // Global security group
        groupScope: 'Global',
        description: 'Designated administrators of the domain'
      },
      {
        sAMAccountName: 'Domain Users',
        distinguishedName: `CN=Domain Users,CN=Users,${this.baseDN}`,
        groupType: -2147483646,
        groupScope: 'Global',
        description: 'All domain users'
      },
      {
        sAMAccountName: 'Domain Guests',
        distinguishedName: `CN=Domain Guests,CN=Users,${this.baseDN}`,
        groupType: -2147483646,
        groupScope: 'Global',
        description: 'All domain guests'
      },
      {
        sAMAccountName: 'Domain Computers',
        distinguishedName: `CN=Domain Computers,CN=Users,${this.baseDN}`,
        groupType: -2147483646,
        groupScope: 'Global',
        description: 'All workstations and servers joined to the domain'
      },
      {
        sAMAccountName: 'Administrators',
        distinguishedName: `CN=Administrators,CN=Builtin,${this.baseDN}`,
        groupType: -2147483643, // Domain local security group
        groupScope: 'DomainLocal',
        description: 'Built-in account for administering the computer/domain'
      },
      {
        sAMAccountName: 'Users',
        distinguishedName: `CN=Users,CN=Builtin,${this.baseDN}`,
        groupType: -2147483643,
        groupScope: 'DomainLocal',
        description: 'Built-in account for normal users'
      }
    ];

    for (const group of builtInGroups) {
      const existing = await this.DomainGroup.findOne({ sAMAccountName: group.sAMAccountName });
      if (!existing) {
        const newGroup = new this.DomainGroup({
          ...group,
          commonName: group.sAMAccountName,
          displayName: group.sAMAccountName,
          objectSid: this.wellKnownSids[group.sAMAccountName] || await this.generateSid(),
          securityIdentifier: this.wellKnownSids[group.sAMAccountName] || await this.generateSid(),
          uSNCreated: this.getNextUSN(),
          uSNChanged: this.getNextUSN()
        });

        await newGroup.save();
        logHelpers.logAdminAction('System', 'Create Group', group.distinguishedName);
      }
    }
  }

  async createAdministratorAccount() {
    const adminUsername = this.config.activeDirectory.adminUsername;
    const adminPassword = this.config.activeDirectory.adminPassword;

    const existing = await this.DomainUser.findOne({ sAMAccountName: adminUsername });
    if (!existing) {
      // Hash the password
      const hashedPassword = await this.hashPassword(adminPassword);

      const administrator = new this.DomainUser({
        sAMAccountName: adminUsername,
        userPrincipalName: `${adminUsername}@${this.domain}`,
        distinguishedName: `CN=${adminUsername},CN=Users,${this.baseDN}`,
        commonName: adminUsername,
        givenName: 'Built-in',
        surname: 'Administrator',
        displayName: 'Administrator',
        description: 'Built-in account for administering the computer/domain',
        unicodePwd: hashedPassword,
        userAccountControl: 512, // Normal account
        accountEnabled: true,
        passwordNeverExpires: true,
        objectSid: 'S-1-5-21-domain-500', // Well-known Administrator SID
        securityIdentifier: 'S-1-5-21-domain-500',
        uSNCreated: this.getNextUSN(),
        uSNChanged: this.getNextUSN()
      });

      await administrator.save();

      // Add to Domain Admins group
      const domainAdminsGroup = await this.DomainGroup.findOne({ sAMAccountName: 'Domain Admins' });
      if (domainAdminsGroup) {
        await this.addUserToGroup(administrator._id, domainAdminsGroup._id);
      }

      logHelpers.logAdminAction('System', 'Create Administrator', administrator.distinguishedName);
    }
  }

  async ensureComputersContainer() {
    // Ensure the Computers container exists for domain-joined computers
    const existing = await this.OrganizationalUnit.findOne({ 
      distinguishedName: `CN=Computers,${this.baseDN}` 
    });

    if (!existing) {
      const computersContainer = new this.OrganizationalUnit({
        commonName: 'Computers',
        name: 'Computers',
        distinguishedName: `CN=Computers,${this.baseDN}`,
        description: 'Default container for computer objects',
        objectSid: await this.generateSid(),
        uSNCreated: this.getNextUSN(),
        uSNChanged: this.getNextUSN()
      });

      await computersContainer.save();
    }
  }

  setupReplication() {
    // Initialize Update Sequence Number (USN) tracking
    this.usnCounter = Date.now();

    // Set up replication monitoring
    setInterval(async () => {
      try {
        await this.processReplicationChanges();
      } catch (error) {
        logger.error('Replication error:', error);
      }
    }, 5000); // Check for changes every 5 seconds

    logger.info('🔄 Replication system initialized');
  }

  async processReplicationChanges() {
    // In a full implementation, this would handle:
    // - Change tracking for objects
    // - Inter-site replication
    // - Conflict resolution
    // - Replication topology management

    // For now, just update USN counter
    this.usnCounter = Date.now();
    await this.redis.set('ad:replication:usn', this.usnCounter);
  }

  async startDomainController() {
    try {
      // Register this server as a domain controller
      const dcInfo = {
        hostName: this.config.server.host,
        ipAddress: '127.0.0.1', // In production, get actual IP
        siteName: 'Default-First-Site-Name',
        isGlobalCatalog: true,
        ntdsSettings: `CN=NTDS Settings,CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`,
        serverReference: `CN=${this.config.server.host},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${this.baseDN}`,
        fsmoRoles: ['PDC', 'RID', 'Infrastructure'], // Forest and domain roles
        lastLogon: new Date(),
        machinePassword: crypto.randomBytes(32).toString('hex')
      };

      this.domainControllers.set(this.config.server.host, dcInfo);
      await this.redis.hSet('ad:domain-controllers', this.config.server.host, JSON.stringify(dcInfo));

      // Start listening for domain events
      this.on('userAuthentication', this.handleUserAuthentication.bind(this));
      this.on('computerJoin', this.handleComputerJoin.bind(this));
      this.on('groupMembershipChange', this.handleGroupMembershipChange.bind(this));

      logger.info('👑 Domain controller services started');

    } catch (error) {
      logger.error('❌ Failed to start domain controller:', error);
      throw error;
    }
  }

  // User management methods
  async createUser(userInfo, adminUser) {
    try {
      const {
        sAMAccountName,
        userPrincipalName,
        password,
        givenName,
        surname,
        displayName,
        description,
        mail,
        department,
        title,
        organizationalUnit = `CN=Users,${this.baseDN}`
      } = userInfo;

      // Validate user doesn't exist
      const existing = await this.DomainUser.findOne({
        $or: [
          { sAMAccountName },
          { userPrincipalName }
        ]
      });

      if (existing) {
        throw new Error(`User already exists: ${sAMAccountName}`);
      }

      // Hash password
      const hashedPassword = await this.hashPassword(password);

      // Generate distinguished name
      const distinguishedName = `CN=${displayName || `${givenName} ${surname}`},${organizationalUnit}`;

      const user = new this.DomainUser({
        sAMAccountName,
        userPrincipalName: userPrincipalName || `${sAMAccountName}@${this.domain}`,
        distinguishedName,
        commonName: displayName || `${givenName} ${surname}`,
        givenName,
        surname,
        displayName: displayName || `${givenName} ${surname}`,
        description,
        mail,
        department,
        title,
        unicodePwd: hashedPassword,
        objectSid: await this.generateSid(),
        securityIdentifier: await this.generateSid(),
        uSNCreated: this.getNextUSN(),
        uSNChanged: this.getNextUSN()
      });

      await user.save();

      // Add to Domain Users group by default
      const domainUsersGroup = await this.DomainGroup.findOne({ sAMAccountName: 'Domain Users' });
      if (domainUsersGroup) {
        await this.addUserToGroup(user._id, domainUsersGroup._id);
      }

      // Create Kerberos principal
      if (this.kerberosService) {
        await this.kerberosService.createPrincipal(userPrincipalName, password);
      }

      logHelpers.logAdminAction(adminUser, 'Create User', distinguishedName);
      this.emit('userCreated', { user, adminUser });

      return user;

    } catch (error) {
      logger.error('❌ Failed to create user:', error);
      throw error;
    }
  }

  async authenticateUser(username, password, clientInfo = {}) {
    try {
      // Find user by various identifiers
      const user = await this.DomainUser.findOne({
        $or: [
          { sAMAccountName: username },
          { userPrincipalName: username },
          { mail: username }
        ]
      }).populate('memberOf');

      if (!user) {
        logHelpers.logAuthFailure(username, 'domain', clientInfo.ip, 'User not found');
        return { success: false, reason: 'Invalid credentials' };
      }

      // Check account status
      if (!user.accountEnabled) {
        logHelpers.logAuthFailure(username, 'domain', clientInfo.ip, 'Account disabled');
        return { success: false, reason: 'Account disabled' };
      }

      if (user.accountLocked) {
        logHelpers.logAuthFailure(username, 'domain', clientInfo.ip, 'Account locked');
        return { success: false, reason: 'Account locked' };
      }

      // Check password expiration
      if (user.accountExpires && user.accountExpires < new Date()) {
        logHelpers.logAuthFailure(username, 'domain', clientInfo.ip, 'Account expired');
        return { success: false, reason: 'Account expired' };
      }

      // Verify password
      const isValidPassword = await this.verifyPassword(password, user.unicodePwd);
      if (!isValidPassword) {
        // Increment bad password count
        user.badPwdCount += 1;
        user.badPasswordTime = new Date();

        // Check for account lockout
        if (user.badPwdCount >= this.domainInfo.lockoutThreshold) {
          user.accountLocked = true;
          user.lockoutTime = new Date();
        }

        await user.save();

        logHelpers.logAuthFailure(username, 'domain', clientInfo.ip, 'Invalid password');
        return { success: false, reason: 'Invalid credentials' };
      }

      // Success - update user info
      user.lastLogon = new Date();
      user.lastLogonTimestamp = new Date();
      user.logonCount += 1;
      user.badPwdCount = 0; // Reset bad password count
      user.badPasswordTime = null;

      await user.save();

      logHelpers.logAuthSuccess(username, 'domain', clientInfo.ip, {
        userPrincipalName: user.userPrincipalName,
        groups: user.memberOf.map(g => g.sAMAccountName)
      });

      this.emit('userAuthentication', { user, clientInfo, success: true });

      return {
        success: true,
        user: {
          objectGUID: user.objectGUID,
          sAMAccountName: user.sAMAccountName,
          userPrincipalName: user.userPrincipalName,
          distinguishedName: user.distinguishedName,
          displayName: user.displayName,
          mail: user.mail,
          groups: user.memberOf.map(g => ({
            sAMAccountName: g.sAMAccountName,
            distinguishedName: g.distinguishedName,
            groupType: g.groupType
          }))
        }
      };

    } catch (error) {
      logger.error('❌ User authentication failed:', error);
      logHelpers.logAuthFailure(username, 'domain', clientInfo.ip, 'Authentication error');
      return { success: false, reason: 'Authentication error' };
    }
  }

  // Group management methods
  async createGroup(groupInfo, adminUser) {
    try {
      const {
        sAMAccountName,
        displayName,
        description,
        groupType = -2147483646, // Global security group
        groupScope = 'Global',
        organizationalUnit = `CN=Users,${this.baseDN}`
      } = groupInfo;

      const existing = await this.DomainGroup.findOne({ sAMAccountName });
      if (existing) {
        throw new Error(`Group already exists: ${sAMAccountName}`);
      }

      const distinguishedName = `CN=${displayName || sAMAccountName},${organizationalUnit}`;

      const group = new this.DomainGroup({
        sAMAccountName,
        distinguishedName,
        commonName: displayName || sAMAccountName,
        displayName: displayName || sAMAccountName,
        description,
        groupType,
        groupScope,
        objectSid: await this.generateSid(),
        securityIdentifier: await this.generateSid(),
        uSNCreated: this.getNextUSN(),
        uSNChanged: this.getNextUSN()
      });

      await group.save();

      logHelpers.logAdminAction(adminUser, 'Create Group', distinguishedName);
      this.emit('groupCreated', { group, adminUser });

      return group;

    } catch (error) {
      logger.error('❌ Failed to create group:', error);
      throw error;
    }
  }

  async addUserToGroup(userId, groupId, adminUser) {
    try {
      const user = await this.DomainUser.findById(userId);
      const group = await this.DomainGroup.findById(groupId);

      if (!user || !group) {
        throw new Error('User or group not found');
      }

      // Add user to group members
      if (!group.members.includes(userId)) {
        group.members.push(userId);
        group.memberTypes.push('DomainUser');
        await group.save();
      }

      // Add group to user's memberOf
      if (!user.memberOf.includes(groupId)) {
        user.memberOf.push(groupId);
        await user.save();
      }

      logHelpers.logAdminAction(adminUser || 'System', 'Add User to Group', 
        `${user.distinguishedName} -> ${group.distinguishedName}`);

      this.emit('groupMembershipChange', { 
        action: 'add',
        user, 
        group, 
        adminUser 
      });

      return { success: true };

    } catch (error) {
      logger.error('❌ Failed to add user to group:', error);
      throw error;
    }
  }

  // Computer management methods
  async joinComputer(computerInfo, adminUser) {
    try {
      const {
        computerName,
        operatingSystem,
        operatingSystemVersion,
        dnsHostName,
        ipAddress,
        organizationalUnit = `CN=Computers,${this.baseDN}`
      } = computerInfo;

      const sAMAccountName = `${computerName}$`; // Computer accounts end with $
      const existing = await this.DomainComputer.findOne({ sAMAccountName });

      if (existing) {
        throw new Error(`Computer already exists: ${computerName}`);
      }

      // Generate machine account password
      const machinePassword = crypto.randomBytes(32).toString('hex');
      const hashedPassword = await this.hashPassword(machinePassword);

      const distinguishedName = `CN=${computerName},${organizationalUnit}`;

      const computer = new this.DomainComputer({
        sAMAccountName,
        distinguishedName,
        commonName: computerName,
        dNSHostName: dnsHostName || `${computerName}.${this.domain}`,
        operatingSystem,
        operatingSystemVersion,
        networkAddresses: ipAddress ? [ipAddress] : [],
        unicodePwd: hashedPassword,
        objectSid: await this.generateSid(),
        securityIdentifier: await this.generateSid(),
        uSNCreated: this.getNextUSN(),
        uSNChanged: this.getNextUSN()
      });

      await computer.save();

      // Add to Domain Computers group
      const domainComputersGroup = await this.DomainGroup.findOne({ sAMAccountName: 'Domain Computers' });
      if (domainComputersGroup) {
        await this.addComputerToGroup(computer._id, domainComputersGroup._id);
      }

      // Create computer principal in Kerberos
      if (this.kerberosService) {
        await this.kerberosService.createComputerPrincipal(
          `${computerName}$@${this.config.kerberos.realm}`,
          machinePassword
        );
      }

      logHelpers.logAdminAction(adminUser, 'Join Computer', distinguishedName);
      this.emit('computerJoin', { computer, adminUser });

      return {
        success: true,
        computer: {
          sAMAccountName: computer.sAMAccountName,
          distinguishedName: computer.distinguishedName,
          dNSHostName: computer.dNSHostName,
          machinePassword // Return for computer to store locally
        }
      };

    } catch (error) {
      logger.error('❌ Failed to join computer:', error);
      throw error;
    }
  }

  async addComputerToGroup(computerId, groupId) {
    try {
      const computer = await this.DomainComputer.findById(computerId);
      const group = await this.DomainGroup.findById(groupId);

      if (!computer || !group) {
        throw new Error('Computer or group not found');
      }

      if (!group.members.includes(computerId)) {
        group.members.push(computerId);
        group.memberTypes.push('DomainComputer');
        await group.save();
      }

      if (!computer.memberOf.includes(groupId)) {
        computer.memberOf.push(groupId);
        await computer.save();
      }

      return { success: true };

    } catch (error) {
      logger.error('❌ Failed to add computer to group:', error);
      throw error;
    }
  }

  // Utility methods
  async hashPassword(password) {
    // In a real AD implementation, this would use NT hash
    // For compatibility, we'll use bcrypt with high rounds
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  async generateDomainSid() {
    // Generate a domain SID in the format S-1-5-21-X-Y-Z
    const randomPart1 = Math.floor(Math.random() * 1000000000);
    const randomPart2 = Math.floor(Math.random() * 1000000000);
    const randomPart3 = Math.floor(Math.random() * 1000000000);
    return `S-1-5-21-${randomPart1}-${randomPart2}-${randomPart3}`;
  }

  async generateSid() {
    // Generate a random SID for objects
    const domainSid = this.domainInfo?.domainSid || await this.generateDomainSid();
    const rid = Math.floor(Math.random() * 1000000) + 1000; // Random RID
    return `${domainSid}-${rid}`;
  }

  getNextUSN() {
    return ++this.usnCounter;
  }

  // Event handlers
  async handleUserAuthentication({ user, clientInfo, success }) {
    // Additional processing for user authentication events
    if (success) {
      // Update last logon info, check for policy compliance, etc.
      await this.redis.setEx(
        `ad:user:last-logon:${user.objectGUID}`,
        3600, // 1 hour TTL
        JSON.stringify({
          timestamp: new Date(),
          clientIP: clientInfo.ip,
          userAgent: clientInfo.userAgent
        })
      );
    }
  }

  async handleComputerJoin({ computer, adminUser }) {
    // Register computer for group policy updates
    await this.redis.setEx(
      `ad:computer:joined:${computer.objectGUID}`,
      86400, // 24 hours TTL
      JSON.stringify({
        timestamp: new Date(),
        adminUser,
        dNSHostName: computer.dNSHostName
      })
    );
  }

  async handleGroupMembershipChange({ action, user, group, adminUser }) {
    // Invalidate group membership cache
    await this.redis.del(`ad:user:groups:${user.objectGUID}`);
    
    // Log significant group changes
    if (['Domain Admins', 'Enterprise Admins', 'Schema Admins'].includes(group.sAMAccountName)) {
      logger.warn(`Privileged group membership change: ${action}`, {
        user: user.sAMAccountName,
        group: group.sAMAccountName,
        adminUser
      });
    }
  }

  // Query methods
  async findUser(criteria) {
    return await this.DomainUser.findOne(criteria).populate('memberOf');
  }

  async findUsers(criteria, options = {}) {
    return await this.DomainUser.find(criteria, null, options).populate('memberOf');
  }

  async findGroup(criteria) {
    return await this.DomainGroup.findOne(criteria).populate('members');
  }

  async findGroups(criteria, options = {}) {
    return await this.DomainGroup.find(criteria, null, options).populate('members');
  }

  async findComputer(criteria) {
    return await this.DomainComputer.findOne(criteria).populate('memberOf');
  }

  async findComputers(criteria, options = {}) {
    return await this.DomainComputer.find(criteria, null, options).populate('memberOf');
  }

  // Health check
  async healthCheck() {
    try {
      // Check if we can query the database
      await this.DomainUser.findOne().limit(1);
      
      // Check domain controller status
      const dcStatus = this.domainControllers.get(this.config.server.host);
      
      return {
        status: 'healthy',
        domainController: !!dcStatus,
        domain: this.domain,
        forestLevel: this.forestInfo?.functionalLevel,
        domainLevel: this.domainInfo?.functionalLevel,
        services: {
          ldap: this.ldapService ? 'connected' : 'disconnected',
          kerberos: this.kerberosService ? 'connected' : 'disconnected'
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  async getStatus() {
    const userCount = await this.DomainUser.countDocuments();
    const groupCount = await this.DomainGroup.countDocuments();
    const computerCount = await this.DomainComputer.countDocuments();

    return {
      status: 'running',
      domain: this.domain,
      netbiosName: this.netbiosName,
      baseDN: this.baseDN,
      functionalLevel: this.domainInfo?.functionalLevel,
      objects: {
        users: userCount,
        groups: groupCount,
        computers: computerCount
      },
      domainControllers: this.domainControllers.size,
      replication: {
        currentUSN: this.usnCounter,
        lastUpdate: new Date()
      }
    };
  }

  async stop() {
    logger.info('🛑 Stopping Active Directory Service...');
    
    // Clean up resources, close connections, etc.
    this.domainControllers.clear();
    
    logger.info('✅ Active Directory Service stopped');
  }
}

module.exports = ActiveDirectoryService;