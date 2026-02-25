const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const ping = require('ping');
const { exec } = require('child_process');
const util = require('util');
const snmp = require('snmp-native');

const execAsync = util.promisify(exec);

class NetworkDiscovery extends EventEmitter {
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
    
    this.discoveredDevices = new Map();
    this.networkTopology = new Map();
    this.scanningActive = false;
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS network_devices (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          ip_address VARCHAR(45) UNIQUE NOT NULL,
          mac_address VARCHAR(17),
          hostname VARCHAR(255),
          device_type VARCHAR(50),
          vendor VARCHAR(255),
          model VARCHAR(255),
          serial_number VARCHAR(255),
          os_info TEXT,
          services JSONB,
          snmp_community VARCHAR(255),
          location VARCHAR(255),
          contact VARCHAR(255),
          description TEXT,
          status VARCHAR(20) DEFAULT 'unknown',
          last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          first_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          discovery_method VARCHAR(50),
          managed BOOLEAN DEFAULT false,
          monitoring_enabled BOOLEAN DEFAULT true
        );

        CREATE TABLE IF NOT EXISTS network_topology (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          source_device_id UUID REFERENCES network_devices(id) ON DELETE CASCADE,
          target_device_id UUID REFERENCES network_devices(id) ON DELETE CASCADE,
          connection_type VARCHAR(50),
          interface_source VARCHAR(100),
          interface_target VARCHAR(100),
          speed_mbps INTEGER,
          duplex VARCHAR(20),
          vlan INTEGER,
          distance_hops INTEGER DEFAULT 1,
          discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(source_device_id, target_device_id)
        );

        CREATE TABLE IF NOT EXISTS network_subnets (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          network_address VARCHAR(45) NOT NULL,
          subnet_mask VARCHAR(45) NOT NULL,
          gateway VARCHAR(45),
          vlan INTEGER,
          description TEXT,
          location VARCHAR(255),
          scan_enabled BOOLEAN DEFAULT true,
          last_scan TIMESTAMP,
          device_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS device_services (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          device_id UUID REFERENCES network_devices(id) ON DELETE CASCADE,
          port INTEGER NOT NULL,
          protocol VARCHAR(10) DEFAULT 'TCP',
          service_name VARCHAR(100),
          banner TEXT,
          state VARCHAR(20) DEFAULT 'open',
          discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS switch_ports (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          switch_device_id UUID REFERENCES network_devices(id) ON DELETE CASCADE,
          port_number INTEGER NOT NULL,
          port_name VARCHAR(100),
          connected_device_id UUID REFERENCES network_devices(id),
          mac_address VARCHAR(17),
          vlan INTEGER,
          speed_mbps INTEGER,
          duplex VARCHAR(20),
          status VARCHAR(20),
          poe_enabled BOOLEAN DEFAULT false,
          poe_usage_watts DECIMAL,
          last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(switch_device_id, port_number)
        );

        CREATE TABLE IF NOT EXISTS discovery_scans (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          subnet_id UUID REFERENCES network_subnets(id),
          scan_type VARCHAR(50),
          status VARCHAR(20) DEFAULT 'running',
          started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          completed_at TIMESTAMP,
          devices_found INTEGER DEFAULT 0,
          new_devices INTEGER DEFAULT 0,
          errors TEXT[]
        );

        CREATE INDEX idx_devices_ip ON network_devices(ip_address);
        CREATE INDEX idx_devices_mac ON network_devices(mac_address);
        CREATE INDEX idx_devices_type ON network_devices(device_type);
        CREATE INDEX idx_devices_status ON network_devices(status);
        CREATE INDEX idx_topology_source ON network_topology(source_device_id);
        CREATE INDEX idx_services_device ON device_services(device_id);
        CREATE INDEX idx_switch_ports_switch ON switch_ports(switch_device_id);
      `);
      
      this.logger.info('Network discovery database initialized');
      await this.loadDevices();
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async loadDevices() {
    try {
      const result = await this.db.query(`
        SELECT d.*, COUNT(s.id) as service_count
        FROM network_devices d
        LEFT JOIN device_services s ON d.id = s.device_id
        GROUP BY d.id
        ORDER BY d.ip_address
      `);
      
      this.discoveredDevices.clear();
      
      for (const device of result.rows) {
        this.discoveredDevices.set(device.ip_address, device);
      }
      
      this.logger.info(`Loaded ${this.discoveredDevices.size} known network devices`);
    } catch (error) {
      this.logger.error('Load devices error:', error);
    }
  }

  async discoverDevices(subnet = '192.168.1.0/24', methods = ['ping', 'arp', 'snmp']) {
    if (this.scanningActive) {
      throw new Error('Discovery scan already in progress');
    }
    
    this.scanningActive = true;
    const startTime = Date.now();
    
    try {
      // Create scan record
      const scanResult = await this.db.query(`
        INSERT INTO discovery_scans (scan_type, status)
        VALUES ($1, 'running')
        RETURNING *
      `, [`${methods.join(',')}`]);
      
      const scanId = scanResult.rows[0].id;
      
      this.logger.info(`Starting network discovery on ${subnet} using methods: ${methods.join(', ')}`);
      
      const discoveredDevices = [];
      
      // Get IP range from subnet
      const ipRange = this.generateIPRange(subnet);
      
      // Parallel discovery using different methods
      const discoveries = [];
      
      if (methods.includes('ping')) {
        discoveries.push(this.discoverViaPing(ipRange));
      }
      
      if (methods.includes('arp')) {
        discoveries.push(this.discoverViaARP());
      }
      
      if (methods.includes('nmap')) {
        discoveries.push(this.discoverViaNmap(subnet));
      }
      
      if (methods.includes('snmp')) {
        discoveries.push(this.discoverViaSNMP(ipRange));
      }
      
      if (methods.includes('mdns')) {
        discoveries.push(this.discoverViamDNS());
      }
      
      // Wait for all discovery methods
      const results = await Promise.allSettled(discoveries);
      
      // Merge results
      const allDevices = new Map();
      
      results.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          result.value.forEach(device => {
            if (allDevices.has(device.ip_address)) {
              // Merge device info
              Object.assign(allDevices.get(device.ip_address), device);
            } else {
              allDevices.set(device.ip_address, device);
            }
          });
        } else {
          this.logger.warn(`Discovery method failed: ${result.reason}`);
        }
      });
      
      // Process discovered devices
      let newDevices = 0;
      
      for (const device of allDevices.values()) {
        const saved = await this.processDiscoveredDevice(device);
        if (saved.isNew) {
          newDevices++;
        }
        discoveredDevices.push(saved.device);
      }
      
      // Update scan record
      await this.db.query(`
        UPDATE discovery_scans
        SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
            devices_found = $1, new_devices = $2
        WHERE id = $3
      `, [discoveredDevices.length, newDevices, scanId]);
      
      const duration = Date.now() - startTime;
      this.logger.info(`Discovery completed in ${duration}ms. Found ${discoveredDevices.length} devices (${newDevices} new)`);
      
      this.emit('discovery:completed', {
        scanId,
        devicesFound: discoveredDevices.length,
        newDevices,
        duration
      });
      
      return discoveredDevices;
    } catch (error) {
      this.logger.error('Network discovery error:', error);
      throw error;
    } finally {
      this.scanningActive = false;
    }
  }

  async discoverViaPing(ipRange) {
    const devices = [];
    const concurrency = 50;
    
    this.logger.info(`Ping sweep across ${ipRange.length} IPs`);
    
    // Split into batches for concurrent processing
    for (let i = 0; i < ipRange.length; i += concurrency) {
      const batch = ipRange.slice(i, i + concurrency);
      
      const promises = batch.map(async (ip) => {
        try {
          const result = await ping.promise.probe(ip, { timeout: 1 });
          
          if (result.alive) {
            return {
              ip_address: ip,
              status: 'online',
              response_time: result.time,
              discovery_method: 'ping'
            };
          }
        } catch (error) {
          // Ignore ping failures
        }
        return null;
      });
      
      const results = await Promise.allSettled(promises);
      
      results.forEach(result => {
        if (result.status === 'fulfilled' && result.value) {
          devices.push(result.value);
        }
      });
    }
    
    this.logger.info(`Ping discovery found ${devices.length} responding devices`);
    return devices;
  }

  async discoverViaARP() {
    const devices = [];
    
    try {
      // Read ARP table
      const { stdout } = await execAsync('arp -a');
      const lines = stdout.split('\n');
      
      for (const line of lines) {
        const match = line.match(/\(([\d.]+)\) at ([a-fA-F0-9:]{17})/);
        if (match) {
          devices.push({
            ip_address: match[1],
            mac_address: match[2].toLowerCase(),
            status: 'online',
            discovery_method: 'arp'
          });
        }
      }
      
      this.logger.info(`ARP discovery found ${devices.length} devices`);
    } catch (error) {
      this.logger.warn('ARP discovery failed:', error);
    }
    
    return devices;
  }

  async discoverViaNmap(subnet) {
    const devices = [];
    
    try {
      // Use nmap for comprehensive scanning
      const { stdout } = await execAsync(`nmap -sn ${subnet}`);
      const lines = stdout.split('\n');
      
      let currentDevice = null;
      
      for (const line of lines) {
        if (line.includes('Nmap scan report for')) {
          if (currentDevice) {
            devices.push(currentDevice);
          }
          
          const ipMatch = line.match(/([\d.]+)/);
          const hostnameMatch = line.match(/for (.*) \(([\d.]+)\)/);
          
          currentDevice = {
            ip_address: ipMatch ? ipMatch[1] : null,
            hostname: hostnameMatch ? hostnameMatch[1] : null,
            status: 'online',
            discovery_method: 'nmap'
          };
        } else if (line.includes('MAC Address:') && currentDevice) {
          const macMatch = line.match(/([a-fA-F0-9:]{17})/);
          const vendorMatch = line.match(/\((.+)\)$/);
          
          if (macMatch) {
            currentDevice.mac_address = macMatch[1].toLowerCase();
          }
          if (vendorMatch) {
            currentDevice.vendor = vendorMatch[1];
          }
        }
      }
      
      if (currentDevice) {
        devices.push(currentDevice);
      }
      
      this.logger.info(`Nmap discovery found ${devices.length} devices`);
    } catch (error) {
      this.logger.warn('Nmap discovery failed (may not be installed):', error);
    }
    
    return devices;
  }

  async discoverViaSNMP(ipRange) {
    const devices = [];
    const communities = ['public', 'private', 'community'];
    
    for (const ip of ipRange.slice(0, 50)) { // Limit SNMP scans
      for (const community of communities) {
        try {
          const session = new snmp.Session({ host: ip, community });
          
          const oids = [
            '1.3.6.1.2.1.1.1.0', // sysDescr
            '1.3.6.1.2.1.1.5.0', // sysName
            '1.3.6.1.2.1.1.4.0', // sysContact
            '1.3.6.1.2.1.1.6.0', // sysLocation
            '1.3.6.1.2.1.1.2.0'  // sysObjectID
          ];
          
          const result = await new Promise((resolve, reject) => {
            session.getAll({ oids }, (error, varbinds) => {
              session.close();
              if (error) reject(error);
              else resolve(varbinds);
            });
          });
          
          if (result && result.length > 0) {
            devices.push({
              ip_address: ip,
              hostname: result[1]?.value || null,
              description: result[0]?.value || null,
              contact: result[2]?.value || null,
              location: result[3]?.value || null,
              device_type: this.guessDeviceType(result[0]?.value),
              snmp_community: community,
              status: 'online',
              discovery_method: 'snmp'
            });
            
            break; // Found working community
          }
        } catch (error) {
          // Try next community
        }
      }
    }
    
    this.logger.info(`SNMP discovery found ${devices.length} devices`);
    return devices;
  }

  async discoverViamDNS() {
    const devices = [];
    
    try {
      // Use avahi-browse to discover mDNS services
      const { stdout } = await execAsync('avahi-browse -art');
      const lines = stdout.split('\n');
      
      for (const line of lines) {
        if (line.includes('IPv4') && line.includes('address')) {
          const parts = line.split(/\s+/);
          const ip = parts[parts.length - 1];
          const hostname = parts[3] || null;
          
          if (ip && ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
            devices.push({
              ip_address: ip,
              hostname,
              discovery_method: 'mdns',
              status: 'online'
            });
          }
        }
      }
      
      this.logger.info(`mDNS discovery found ${devices.length} devices`);
    } catch (error) {
      this.logger.warn('mDNS discovery failed (avahi may not be available):', error);
    }
    
    return devices;
  }

  async processDiscoveredDevice(deviceInfo) {
    try {
      // Check if device already exists
      const existing = await this.db.query(
        'SELECT * FROM network_devices WHERE ip_address = $1',
        [deviceInfo.ip_address]
      );
      
      let device;
      let isNew = false;
      
      if (existing.rows.length === 0) {
        // New device
        const result = await this.db.query(`
          INSERT INTO network_devices (
            ip_address, mac_address, hostname, device_type, vendor,
            description, status, discovery_method
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *
        `, [
          deviceInfo.ip_address,
          deviceInfo.mac_address,
          deviceInfo.hostname,
          deviceInfo.device_type,
          deviceInfo.vendor,
          deviceInfo.description,
          deviceInfo.status || 'unknown',
          deviceInfo.discovery_method
        ]);
        
        device = result.rows[0];
        isNew = true;
        
        this.emit('device:discovered', device);
      } else {
        // Update existing device
        device = existing.rows[0];
        
        // Update fields that may have changed
        await this.db.query(`
          UPDATE network_devices
          SET hostname = COALESCE($1, hostname),
              mac_address = COALESCE($2, mac_address),
              vendor = COALESCE($3, vendor),
              description = COALESCE($4, description),
              status = $5,
              last_seen = CURRENT_TIMESTAMP
          WHERE id = $6
        `, [
          deviceInfo.hostname,
          deviceInfo.mac_address,
          deviceInfo.vendor,
          deviceInfo.description,
          deviceInfo.status || device.status,
          device.id
        ]);
      }
      
      // Perform additional scans if this is a new or interesting device
      if (isNew || deviceInfo.device_type === 'switch' || deviceInfo.device_type === 'router') {
        await this.deepScanDevice(device);
      }
      
      return { device, isNew };
    } catch (error) {
      this.logger.error('Process device error:', error);
      return { device: deviceInfo, isNew: false };
    }
  }

  async deepScanDevice(device) {
    try {
      // Port scan common services
      await this.scanDeviceServices(device);
      
      // If it's a switch, scan for connected devices
      if (device.device_type === 'switch' && device.snmp_community) {
        await this.scanSwitchPorts(device);
      }
      
      // Try to get more SNMP information
      if (device.snmp_community) {
        await this.getDetailedSNMPInfo(device);
      }
      
    } catch (error) {
      this.logger.error('Deep scan error:', error);
    }
  }

  async scanDeviceServices(device) {
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306];
    
    try {
      const { stdout } = await execAsync(`nmap -p ${commonPorts.join(',')} ${device.ip_address}`);
      const lines = stdout.split('\n');
      
      for (const line of lines) {
        if (line.includes('/tcp') && line.includes('open')) {
          const parts = line.split(/\s+/);
          const portInfo = parts[0].split('/');
          const port = parseInt(portInfo[0]);
          const service = parts[2] || 'unknown';
          
          await this.db.query(`
            INSERT INTO device_services (device_id, port, protocol, service_name, state)
            VALUES ($1, $2, 'TCP', $3, 'open')
            ON CONFLICT (device_id, port, protocol) DO UPDATE
            SET service_name = $3, discovered_at = CURRENT_TIMESTAMP
          `, [device.id, port, service]);
        }
      }
    } catch (error) {
      this.logger.warn(`Service scan failed for ${device.ip_address}:`, error);
    }
  }

  async getNetworkTopology() {
    // Build network topology from discovered devices and connections
    const devices = await this.db.query(`
      SELECT d.*, COUNT(t1.id) + COUNT(t2.id) as connection_count
      FROM network_devices d
      LEFT JOIN network_topology t1 ON d.id = t1.source_device_id
      LEFT JOIN network_topology t2 ON d.id = t2.target_device_id
      GROUP BY d.id
      ORDER BY connection_count DESC, d.device_type
    `);
    
    const connections = await this.db.query(`
      SELECT t.*, 
             s.hostname as source_hostname,
             s.device_type as source_type,
             tar.hostname as target_hostname,
             tar.device_type as target_type
      FROM network_topology t
      JOIN network_devices s ON t.source_device_id = s.id
      JOIN network_devices tar ON t.target_device_id = tar.id
    `);
    
    return {
      devices: devices.rows,
      connections: connections.rows,
      stats: {
        totalDevices: devices.rows.length,
        switches: devices.rows.filter(d => d.device_type === 'switch').length,
        routers: devices.rows.filter(d => d.device_type === 'router').length,
        servers: devices.rows.filter(d => d.device_type === 'server').length,
        workstations: devices.rows.filter(d => d.device_type === 'workstation').length
      }
    };
  }

  generateIPRange(subnet) {
    const [network, cidr] = subnet.split('/');
    const networkParts = network.split('.').map(Number);
    const hostBits = 32 - parseInt(cidr);
    const hostCount = Math.pow(2, hostBits) - 2; // Exclude network and broadcast
    
    const ips = [];
    const baseIP = (networkParts[0] << 24) + (networkParts[1] << 16) + 
                  (networkParts[2] << 8) + networkParts[3];
    
    for (let i = 1; i <= Math.min(hostCount, 254); i++) {
      const ip = baseIP + i;
      ips.push([
        (ip >>> 24) & 255,
        (ip >>> 16) & 255,
        (ip >>> 8) & 255,
        ip & 255
      ].join('.'));
    }
    
    return ips;
  }

  guessDeviceType(sysDescr) {
    if (!sysDescr) return 'unknown';
    
    const desc = sysDescr.toLowerCase();
    
    if (desc.includes('switch') || desc.includes('catalyst')) return 'switch';
    if (desc.includes('router') || desc.includes('cisco')) return 'router';
    if (desc.includes('windows') || desc.includes('linux') || desc.includes('server')) return 'server';
    if (desc.includes('printer') || desc.includes('hp ') || desc.includes('canon')) return 'printer';
    if (desc.includes('access point') || desc.includes('wireless')) return 'access_point';
    if (desc.includes('firewall') || desc.includes('pfsense')) return 'firewall';
    
    return 'unknown';
  }

  async listKnownDevices() {
    const result = await this.db.query(`
      SELECT d.*, 
             COUNT(DISTINCT s.id) as service_count,
             MAX(s.discovered_at) as last_service_scan
      FROM network_devices d
      LEFT JOIN device_services s ON d.id = s.device_id
      GROUP BY d.id
      ORDER BY d.last_seen DESC
    `);
    
    return result.rows;
  }

  async getDeviceInfo(ipAddress) {
    const device = await this.db.query(`
      SELECT d.*, 
             array_agg(
               json_build_object(
                 'port', s.port,
                 'protocol', s.protocol,
                 'service', s.service_name,
                 'state', s.state
               )
             ) FILTER (WHERE s.id IS NOT NULL) as services
      FROM network_devices d
      LEFT JOIN device_services s ON d.id = s.device_id
      WHERE d.ip_address = $1
      GROUP BY d.id
    `, [ipAddress]);
    
    if (device.rows.length === 0) {
      throw new Error('Device not found');
    }
    
    return device.rows[0];
  }
}

module.exports = NetworkDiscovery;