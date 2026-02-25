const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const ip = require('ip');
const { Netmask } = require('netmask');

class DHCPManager extends EventEmitter {
  constructor() {
    super();
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/network'
    });
    
    this.dhcpServer = null;
    this.scopes = new Map();
    this.leases = new Map();
    this.reservations = new Map();
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS dhcp_scopes (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) NOT NULL,
          network_address VARCHAR(45) NOT NULL,
          subnet_mask VARCHAR(45) NOT NULL,
          start_ip VARCHAR(45) NOT NULL,
          end_ip VARCHAR(45) NOT NULL,
          default_gateway VARCHAR(45),
          dns_servers TEXT[],
          domain_name VARCHAR(255),
          lease_duration INTEGER DEFAULT 86400,
          enabled BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS dhcp_leases (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          scope_id UUID REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
          ip_address VARCHAR(45) UNIQUE NOT NULL,
          mac_address VARCHAR(17) NOT NULL,
          hostname VARCHAR(255),
          lease_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          lease_end TIMESTAMP,
          state VARCHAR(20) DEFAULT 'active',
          client_identifier VARCHAR(255),
          vendor_class VARCHAR(255)
        );

        CREATE TABLE IF NOT EXISTS dhcp_reservations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          scope_id UUID REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
          ip_address VARCHAR(45) UNIQUE NOT NULL,
          mac_address VARCHAR(17) UNIQUE NOT NULL,
          hostname VARCHAR(255),
          description TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS dhcp_options (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          scope_id UUID REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
          option_code INTEGER NOT NULL,
          option_value TEXT NOT NULL,
          option_name VARCHAR(100)
        );

        CREATE TABLE IF NOT EXISTS dhcp_statistics (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          scope_id UUID REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          total_addresses INTEGER,
          used_addresses INTEGER,
          reserved_addresses INTEGER,
          available_addresses INTEGER,
          discovers INTEGER DEFAULT 0,
          offers INTEGER DEFAULT 0,
          requests INTEGER DEFAULT 0,
          acks INTEGER DEFAULT 0,
          naks INTEGER DEFAULT 0,
          declines INTEGER DEFAULT 0,
          releases INTEGER DEFAULT 0
        );

        CREATE INDEX idx_dhcp_leases_mac ON dhcp_leases(mac_address);
        CREATE INDEX idx_dhcp_leases_ip ON dhcp_leases(ip_address);
        CREATE INDEX idx_dhcp_leases_state ON dhcp_leases(state);
        CREATE INDEX idx_dhcp_stats_time ON dhcp_statistics(timestamp);
      `);
      
      this.logger.info('DHCP database initialized');
      await this.loadScopes();
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async startDHCPServer() {
    try {
      const dhcp = require('dhcp');
      
      const serverConfig = {
        range: [], // Will be set per scope
        static: {}, // Reservations
        netmask: '255.255.255.0',
        router: [],
        timeServer: [],
        nameServer: [],
        dns: [],
        hostname: 'opendirectory',
        domainName: process.env.DOMAIN_NAME || 'local',
        broadcast: '',
        server: '0.0.0.0',
        bootFile: ''
      };
      
      this.dhcpServer = dhcp.createServer(serverConfig);
      
      // Handle DHCP events
      this.dhcpServer.on('message', async (msg) => {
        this.logger.info(`DHCP message: ${msg.op} from ${msg.chaddr}`);
        await this.handleDHCPMessage(msg);
      });
      
      this.dhcpServer.on('listening', () => {
        const address = this.dhcpServer.address();
        this.logger.info(`DHCP server listening on ${address}`);
      });
      
      // Bind to DHCP port
      this.dhcpServer.listen(67);
      
      // Start lease cleanup timer
      setInterval(() => this.cleanupExpiredLeases(), 60000);
      
      // Start statistics collector
      setInterval(() => this.collectStatistics(), 300000);
      
    } catch (error) {
      this.logger.error('Failed to start DHCP server:', error);
      
      // Fallback to configuration management only
      this.logger.info('Running in configuration-only mode (no active DHCP server)');
    }
  }

  async handleDHCPMessage(msg) {
    const messageType = this.getMessageType(msg);
    const clientMac = this.formatMacAddress(msg.chaddr);
    
    switch (messageType) {
      case 'DISCOVER':
        await this.handleDiscover(msg, clientMac);
        break;
      
      case 'REQUEST':
        await this.handleRequest(msg, clientMac);
        break;
      
      case 'RELEASE':
        await this.handleRelease(msg, clientMac);
        break;
      
      case 'DECLINE':
        await this.handleDecline(msg, clientMac);
        break;
      
      case 'INFORM':
        await this.handleInform(msg, clientMac);
        break;
    }
  }

  async handleDiscover(msg, clientMac) {
    // Find appropriate scope
    const scope = this.findScopeForClient(msg);
    
    if (!scope) {
      this.logger.warn(`No scope found for client ${clientMac}`);
      return;
    }
    
    // Check for reservation
    const reservation = await this.getReservation(clientMac);
    
    let offeredIp;
    if (reservation) {
      offeredIp = reservation.ip_address;
    } else {
      // Find available IP
      offeredIp = await this.findAvailableIP(scope.id);
    }
    
    if (!offeredIp) {
      this.logger.error(`No available IPs in scope ${scope.name}`);
      return;
    }
    
    // Create offer
    await this.createOffer(clientMac, offeredIp, scope);
    
    // Send DHCP OFFER
    this.sendOffer(msg, offeredIp, scope);
    
    // Update statistics
    await this.incrementStatistic(scope.id, 'discovers');
    await this.incrementStatistic(scope.id, 'offers');
  }

  async handleRequest(msg, clientMac) {
    const requestedIp = this.getRequestedIP(msg);
    const scope = this.findScopeForIP(requestedIp);
    
    if (!scope) {
      this.sendNak(msg);
      return;
    }
    
    // Verify IP is available or already leased to this client
    const canAssign = await this.canAssignIP(requestedIp, clientMac);
    
    if (!canAssign) {
      this.sendNak(msg);
      await this.incrementStatistic(scope.id, 'naks');
      return;
    }
    
    // Create or update lease
    const lease = await this.createLease(clientMac, requestedIp, scope, msg);
    
    // Send ACK
    this.sendAck(msg, requestedIp, scope, lease);
    
    await this.incrementStatistic(scope.id, 'requests');
    await this.incrementStatistic(scope.id, 'acks');
    
    this.emit('lease:created', lease);
  }

  async handleRelease(msg, clientMac) {
    const releasedIp = msg.ciaddr;
    
    await this.releaseLease(clientMac, releasedIp);
    
    const scope = this.findScopeForIP(releasedIp);
    if (scope) {
      await this.incrementStatistic(scope.id, 'releases');
    }
    
    this.emit('lease:released', { mac: clientMac, ip: releasedIp });
  }

  async handleDecline(msg, clientMac) {
    const declinedIp = this.getRequestedIP(msg);
    
    // Mark IP as conflicted
    await this.markIPConflicted(declinedIp);
    
    const scope = this.findScopeForIP(declinedIp);
    if (scope) {
      await this.incrementStatistic(scope.id, 'declines');
    }
    
    this.logger.warn(`Client ${clientMac} declined IP ${declinedIp} (conflict detected)`);
  }

  async loadScopes() {
    try {
      const result = await this.db.query(`
        SELECT s.*, 
               array_agg(DISTINCT r.ip_address) as reserved_ips
        FROM dhcp_scopes s
        LEFT JOIN dhcp_reservations r ON s.id = r.scope_id
        WHERE s.enabled = true
        GROUP BY s.id
      `);
      
      this.scopes.clear();
      
      for (const scope of result.rows) {
        this.scopes.set(scope.id, scope);
        
        // Load options for scope
        const options = await this.db.query(
          'SELECT * FROM dhcp_options WHERE scope_id = $1',
          [scope.id]
        );
        
        scope.options = options.rows;
      }
      
      // Load all active leases
      await this.loadLeases();
      
      // Load all reservations
      await this.loadReservations();
      
      this.logger.info(`Loaded ${this.scopes.size} DHCP scopes`);
    } catch (error) {
      this.logger.error('Load scopes error:', error);
    }
  }

  async loadLeases() {
    const result = await this.db.query(`
      SELECT * FROM dhcp_leases 
      WHERE state = 'active' AND lease_end > CURRENT_TIMESTAMP
    `);
    
    this.leases.clear();
    
    result.rows.forEach(lease => {
      this.leases.set(lease.mac_address, lease);
      this.leases.set(lease.ip_address, lease);
    });
  }

  async loadReservations() {
    const result = await this.db.query('SELECT * FROM dhcp_reservations');
    
    this.reservations.clear();
    
    result.rows.forEach(reservation => {
      this.reservations.set(reservation.mac_address, reservation);
    });
  }

  async createScope(config) {
    try {
      const {
        name,
        networkAddress,
        subnetMask,
        startIP,
        endIP,
        defaultGateway,
        dnsServers,
        domainName,
        leaseDuration = 86400
      } = config;
      
      // Validate IP range
      this.validateIPRange(networkAddress, subnetMask, startIP, endIP);
      
      const result = await this.db.query(`
        INSERT INTO dhcp_scopes (
          name, network_address, subnet_mask, start_ip, end_ip,
          default_gateway, dns_servers, domain_name, lease_duration
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
      `, [
        name,
        networkAddress,
        subnetMask,
        startIP,
        endIP,
        defaultGateway,
        dnsServers || ['8.8.8.8', '8.8.4.4'],
        domainName,
        leaseDuration
      ]);
      
      const scope = result.rows[0];
      
      // Add default options
      await this.addDefaultOptions(scope.id);
      
      // Reload scopes
      await this.loadScopes();
      
      this.emit('scope:created', scope);
      return scope;
    } catch (error) {
      this.logger.error('Create scope error:', error);
      throw error;
    }
  }

  async addDefaultOptions(scopeId) {
    const defaultOptions = [
      { code: 3, name: 'Router', value: 'scope.default_gateway' },
      { code: 6, name: 'DNS Servers', value: 'scope.dns_servers' },
      { code: 15, name: 'Domain Name', value: 'scope.domain_name' },
      { code: 51, name: 'Lease Time', value: 'scope.lease_duration' },
      { code: 58, name: 'Renewal Time', value: 'scope.lease_duration / 2' },
      { code: 59, name: 'Rebinding Time', value: 'scope.lease_duration * 0.875' }
    ];
    
    for (const option of defaultOptions) {
      await this.db.query(`
        INSERT INTO dhcp_options (scope_id, option_code, option_name, option_value)
        VALUES ($1, $2, $3, $4)
      `, [scopeId, option.code, option.name, option.value]);
    }
  }

  async updateScope(scopeId, updates) {
    try {
      const fields = [];
      const values = [];
      let paramCount = 1;
      
      Object.entries(updates).forEach(([key, value]) => {
        if (key !== 'id') {
          fields.push(`${key} = $${paramCount}`);
          values.push(value);
          paramCount++;
        }
      });
      
      values.push(scopeId);
      
      await this.db.query(`
        UPDATE dhcp_scopes
        SET ${fields.join(', ')}
        WHERE id = $${paramCount}
      `, values);
      
      await this.loadScopes();
      
      this.emit('scope:updated', scopeId);
      return true;
    } catch (error) {
      this.logger.error('Update scope error:', error);
      throw error;
    }
  }

  async deleteScope(scopeId) {
    try {
      await this.db.query('DELETE FROM dhcp_scopes WHERE id = $1', [scopeId]);
      await this.loadScopes();
      
      this.emit('scope:deleted', scopeId);
      return true;
    } catch (error) {
      this.logger.error('Delete scope error:', error);
      throw error;
    }
  }

  async createReservation(mac, ipAddress, hostname, description) {
    try {
      // Validate MAC address
      if (!this.isValidMacAddress(mac)) {
        throw new Error('Invalid MAC address');
      }
      
      // Find appropriate scope
      const scope = this.findScopeForIP(ipAddress);
      if (!scope) {
        throw new Error('IP address not in any scope');
      }
      
      const result = await this.db.query(`
        INSERT INTO dhcp_reservations (scope_id, mac_address, ip_address, hostname, description)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [scope.id, mac.toLowerCase(), ipAddress, hostname, description]);
      
      await this.loadReservations();
      
      this.emit('reservation:created', result.rows[0]);
      return result.rows[0];
    } catch (error) {
      this.logger.error('Create reservation error:', error);
      throw error;
    }
  }

  async deleteReservation(reservationId) {
    try {
      await this.db.query('DELETE FROM dhcp_reservations WHERE id = $1', [reservationId]);
      await this.loadReservations();
      
      this.emit('reservation:deleted', reservationId);
      return true;
    } catch (error) {
      this.logger.error('Delete reservation error:', error);
      throw error;
    }
  }

  async createLease(mac, ipAddress, scope, dhcpMessage) {
    const leaseEnd = new Date();
    leaseEnd.setSeconds(leaseEnd.getSeconds() + scope.lease_duration);
    
    const result = await this.db.query(`
      INSERT INTO dhcp_leases (
        scope_id, mac_address, ip_address, hostname,
        lease_end, state, client_identifier, vendor_class
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (ip_address) 
      DO UPDATE SET 
        mac_address = $2,
        hostname = $4,
        lease_start = CURRENT_TIMESTAMP,
        lease_end = $5,
        state = $6
      RETURNING *
    `, [
      scope.id,
      mac.toLowerCase(),
      ipAddress,
      dhcpMessage.hostname || null,
      leaseEnd,
      'active',
      dhcpMessage.clientId || null,
      dhcpMessage.vendorClass || null
    ]);
    
    const lease = result.rows[0];
    this.leases.set(mac, lease);
    this.leases.set(ipAddress, lease);
    
    return lease;
  }

  async releaseLease(mac, ipAddress) {
    await this.db.query(`
      UPDATE dhcp_leases
      SET state = 'released', lease_end = CURRENT_TIMESTAMP
      WHERE mac_address = $1 AND ip_address = $2
    `, [mac.toLowerCase(), ipAddress]);
    
    this.leases.delete(mac);
    this.leases.delete(ipAddress);
  }

  async findAvailableIP(scopeId) {
    const scope = this.scopes.get(scopeId);
    if (!scope) return null;
    
    const startIP = ip.toLong(scope.start_ip);
    const endIP = ip.toLong(scope.end_ip);
    
    // Get all used IPs (leased + reserved)
    const usedIPs = await this.db.query(`
      SELECT ip_address FROM dhcp_leases 
      WHERE scope_id = $1 AND state = 'active'
      UNION
      SELECT ip_address FROM dhcp_reservations
      WHERE scope_id = $1
    `, [scopeId]);
    
    const usedSet = new Set(usedIPs.rows.map(r => r.ip_address));
    
    // Find first available IP
    for (let i = startIP; i <= endIP; i++) {
      const testIP = ip.fromLong(i);
      if (!usedSet.has(testIP)) {
        return testIP;
      }
    }
    
    return null;
  }

  async canAssignIP(ipAddress, mac) {
    // Check if IP is reserved for this MAC
    const reservation = this.reservations.get(mac);
    if (reservation && reservation.ip_address === ipAddress) {
      return true;
    }
    
    // Check if IP is already leased to this MAC
    const lease = this.leases.get(ipAddress);
    if (lease && lease.mac_address === mac.toLowerCase()) {
      return true;
    }
    
    // Check if IP is available
    if (!lease && !reservation) {
      return true;
    }
    
    return false;
  }

  async getActiveLeases() {
    const result = await this.db.query(`
      SELECT l.*, s.name as scope_name
      FROM dhcp_leases l
      JOIN dhcp_scopes s ON l.scope_id = s.id
      WHERE l.state = 'active' AND l.lease_end > CURRENT_TIMESTAMP
      ORDER BY l.lease_start DESC
    `);
    
    return result.rows;
  }

  async getStatistics() {
    const stats = {
      scopes: [],
      totalAddresses: 0,
      usedAddresses: 0,
      availableAddresses: 0,
      reservations: 0,
      activeLeases: 0
    };
    
    for (const [scopeId, scope] of this.scopes) {
      const scopeStats = await this.getScopeStatistics(scopeId);
      stats.scopes.push(scopeStats);
      
      stats.totalAddresses += scopeStats.totalAddresses;
      stats.usedAddresses += scopeStats.usedAddresses;
      stats.availableAddresses += scopeStats.availableAddresses;
      stats.reservations += scopeStats.reservations;
    }
    
    stats.activeLeases = this.leases.size / 2; // Divided by 2 because we store by MAC and IP
    
    return stats;
  }

  async getScopeStatistics(scopeId) {
    const scope = this.scopes.get(scopeId);
    if (!scope) return null;
    
    const startIP = ip.toLong(scope.start_ip);
    const endIP = ip.toLong(scope.end_ip);
    const totalAddresses = endIP - startIP + 1;
    
    const leases = await this.db.query(`
      SELECT COUNT(*) as count FROM dhcp_leases
      WHERE scope_id = $1 AND state = 'active'
    `, [scopeId]);
    
    const reservations = await this.db.query(`
      SELECT COUNT(*) as count FROM dhcp_reservations
      WHERE scope_id = $1
    `, [scopeId]);
    
    const usedAddresses = parseInt(leases.rows[0].count) + parseInt(reservations.rows[0].count);
    
    return {
      scopeId,
      scopeName: scope.name,
      totalAddresses,
      usedAddresses,
      availableAddresses: totalAddresses - usedAddresses,
      reservations: parseInt(reservations.rows[0].count),
      utilizationPercent: Math.round((usedAddresses / totalAddresses) * 100)
    };
  }

  async cleanupExpiredLeases() {
    const result = await this.db.query(`
      UPDATE dhcp_leases
      SET state = 'expired'
      WHERE state = 'active' AND lease_end < CURRENT_TIMESTAMP
      RETURNING mac_address, ip_address
    `);
    
    result.rows.forEach(lease => {
      this.leases.delete(lease.mac_address);
      this.leases.delete(lease.ip_address);
    });
    
    if (result.rowCount > 0) {
      this.logger.info(`Cleaned up ${result.rowCount} expired leases`);
    }
  }

  async collectStatistics() {
    for (const [scopeId, scope] of this.scopes) {
      const stats = await this.getScopeStatistics(scopeId);
      
      await this.db.query(`
        INSERT INTO dhcp_statistics (
          scope_id, total_addresses, used_addresses,
          reserved_addresses, available_addresses
        ) VALUES ($1, $2, $3, $4, $5)
      `, [
        scopeId,
        stats.totalAddresses,
        stats.usedAddresses,
        stats.reservations,
        stats.availableAddresses
      ]);
    }
  }

  async incrementStatistic(scopeId, field) {
    // Update in-memory counter (would be used for real-time stats)
    // In production, this would update the database
  }

  async listScopes() {
    const result = await this.db.query(`
      SELECT s.*,
             COUNT(DISTINCT l.id) as active_leases,
             COUNT(DISTINCT r.id) as reservations
      FROM dhcp_scopes s
      LEFT JOIN dhcp_leases l ON s.id = l.scope_id AND l.state = 'active'
      LEFT JOIN dhcp_reservations r ON s.id = r.scope_id
      GROUP BY s.id
      ORDER BY s.name
    `);
    
    return result.rows;
  }

  async getReservation(mac) {
    return this.reservations.get(mac.toLowerCase());
  }

  validateIPRange(network, mask, startIP, endIP) {
    const netmask = new Netmask(`${network}/${mask}`);
    
    if (!netmask.contains(startIP)) {
      throw new Error('Start IP not in network range');
    }
    
    if (!netmask.contains(endIP)) {
      throw new Error('End IP not in network range');
    }
    
    if (ip.toLong(startIP) > ip.toLong(endIP)) {
      throw new Error('Start IP must be less than end IP');
    }
  }

  isValidMacAddress(mac) {
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    return macRegex.test(mac);
  }

  formatMacAddress(buffer) {
    return Array.from(buffer.slice(0, 6))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':');
  }

  findScopeForClient(msg) {
    // Logic to determine appropriate scope based on client's network
    // In production, this would check relay agent info, subnet, etc.
    return Array.from(this.scopes.values())[0];
  }

  findScopeForIP(ipAddress) {
    for (const scope of this.scopes.values()) {
      const netmask = new Netmask(`${scope.network_address}/${scope.subnet_mask}`);
      if (netmask.contains(ipAddress)) {
        return scope;
      }
    }
    return null;
  }

  getMessageType(msg) {
    // Extract DHCP message type from options
    return 'DISCOVER'; // Simplified
  }

  getRequestedIP(msg) {
    // Extract requested IP from DHCP options
    return msg.options?.requestedIP || msg.ciaddr;
  }

  sendOffer(msg, offeredIp, scope) {
    // Send DHCP OFFER message
    this.logger.info(`Offering IP ${offeredIp} to client`);
  }

  sendAck(msg, assignedIp, scope, lease) {
    // Send DHCP ACK message
    this.logger.info(`Acknowledging IP ${assignedIp} to client`);
  }

  sendNak(msg) {
    // Send DHCP NAK message
    this.logger.info('Sending NAK to client');
  }

  isHealthy() {
    return this.scopes.size > 0;
  }

  async stop() {
    if (this.dhcpServer) {
      this.dhcpServer.close();
      this.logger.info('DHCP server stopped');
    }
  }
}

module.exports = DHCPManager;