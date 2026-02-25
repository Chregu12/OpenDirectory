const dns2 = require('dns2');
const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class DNSManager extends EventEmitter {
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
    
    this.dnsServer = null;
    this.zones = new Map();
    this.cache = new Map();
    this.forwarders = process.env.DNS_FORWARDERS?.split(',') || ['8.8.8.8', '8.8.4.4'];
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS dns_zones (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) UNIQUE NOT NULL,
          type VARCHAR(50) DEFAULT 'master',
          ttl INTEGER DEFAULT 3600,
          serial BIGINT DEFAULT 1,
          refresh INTEGER DEFAULT 28800,
          retry INTEGER DEFAULT 7200,
          expire INTEGER DEFAULT 604800,
          minimum INTEGER DEFAULT 86400,
          primary_ns VARCHAR(255),
          admin_email VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS dns_records (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          zone_id UUID REFERENCES dns_zones(id) ON DELETE CASCADE,
          name VARCHAR(255) NOT NULL,
          type VARCHAR(10) NOT NULL,
          value TEXT NOT NULL,
          ttl INTEGER DEFAULT 3600,
          priority INTEGER,
          weight INTEGER,
          port INTEGER,
          flags INTEGER,
          tag VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS dns_query_log (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          query_name VARCHAR(255),
          query_type VARCHAR(10),
          client_ip VARCHAR(45),
          response_code INTEGER,
          response_time INTEGER,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_dns_records_zone ON dns_records(zone_id);
        CREATE INDEX idx_dns_records_name ON dns_records(name);
        CREATE INDEX idx_dns_query_log_time ON dns_query_log(timestamp);
      `);
      
      this.logger.info('DNS database initialized');
      await this.loadZones();
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async startDNSServer() {
    try {
      const { Packet } = dns2;
      
      this.dnsServer = dns2.createServer({
        udp: true,
        tcp: true,
        handle: async (request, send, rinfo) => {
          const response = Packet.createResponseFromRequest(request);
          const [question] = request.questions;
          const { name, type } = question;
          
          this.logger.info(`DNS query: ${name} (${type}) from ${rinfo.address}`);
          
          // Log query
          this.logQuery(name, type, rinfo.address);
          
          try {
            // Check our zones first
            const answer = await this.resolveLocal(name, type);
            
            if (answer) {
              response.answers.push(answer);
            } else {
              // Forward to upstream DNS
              const upstreamAnswer = await this.forwardQuery(name, type);
              if (upstreamAnswer) {
                response.answers.push(...upstreamAnswer);
              }
            }
            
            send(response);
          } catch (error) {
            this.logger.error('DNS resolution error:', error);
            response.header.rcode = Packet.RCODE.SERVFAIL;
            send(response);
          }
        }
      });
      
      this.dnsServer.listen({
        udp: {
          port: process.env.DNS_PORT || 53,
          address: '0.0.0.0'
        },
        tcp: {
          port: process.env.DNS_PORT || 53,
          address: '0.0.0.0'
        }
      });
      
      this.logger.info('DNS server started on port 53');
      
      // Also start DNS-over-HTTPS (DoH) server
      this.startDoHServer();
      
    } catch (error) {
      this.logger.error('Failed to start DNS server:', error);
      throw error;
    }
  }

  async startDoHServer() {
    // DNS-over-HTTPS implementation for modern clients
    const express = require('express');
    const dohApp = express();
    
    dohApp.use(express.raw({ type: 'application/dns-message' }));
    
    dohApp.post('/dns-query', async (req, res) => {
      try {
        const { Packet } = dns2;
        const request = Packet.createFromBuffer(req.body);
        const response = Packet.createResponseFromRequest(request);
        
        const [question] = request.questions;
        const answer = await this.resolveLocal(question.name, question.type);
        
        if (answer) {
          response.answers.push(answer);
        }
        
        res.set('Content-Type', 'application/dns-message');
        res.send(response.toBuffer());
      } catch (error) {
        res.status(400).send('Bad Request');
      }
    });
    
    const dohPort = process.env.DOH_PORT || 8053;
    dohApp.listen(dohPort, () => {
      this.logger.info(`DNS-over-HTTPS server started on port ${dohPort}`);
    });
  }

  async loadZones() {
    try {
      const result = await this.db.query('SELECT * FROM dns_zones');
      
      for (const zone of result.rows) {
        const records = await this.db.query(
          'SELECT * FROM dns_records WHERE zone_id = $1',
          [zone.id]
        );
        
        this.zones.set(zone.name, {
          ...zone,
          records: records.rows
        });
      }
      
      this.logger.info(`Loaded ${this.zones.size} DNS zones`);
    } catch (error) {
      this.logger.error('Load zones error:', error);
    }
  }

  async createZone(name, type = 'master', ttl = 3600, initialRecords = []) {
    try {
      const result = await this.db.query(`
        INSERT INTO dns_zones (name, type, ttl, primary_ns, admin_email)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [
        name,
        type,
        ttl,
        `ns1.${name}`,
        `admin@${name}`
      ]);
      
      const zone = result.rows[0];
      
      // Add default SOA and NS records
      await this.addRecord(zone.id, {
        name: '@',
        type: 'SOA',
        value: `${zone.primary_ns} ${zone.admin_email} ${zone.serial} ${zone.refresh} ${zone.retry} ${zone.expire} ${zone.minimum}`
      });
      
      await this.addRecord(zone.id, {
        name: '@',
        type: 'NS',
        value: zone.primary_ns
      });
      
      // Add initial records
      for (const record of initialRecords) {
        await this.addRecord(zone.id, record);
      }
      
      // Reload zones
      await this.loadZones();
      
      this.emit('zone:created', zone);
      return zone;
    } catch (error) {
      this.logger.error('Create zone error:', error);
      throw error;
    }
  }

  async deleteZone(zoneId) {
    try {
      await this.db.query('DELETE FROM dns_zones WHERE id = $1', [zoneId]);
      await this.loadZones();
      this.emit('zone:deleted', zoneId);
      return true;
    } catch (error) {
      this.logger.error('Delete zone error:', error);
      throw error;
    }
  }

  async addRecord(zoneId, record) {
    try {
      // Validate record type
      const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR', 'NS', 'SOA', 'CAA'];
      if (!validTypes.includes(record.type)) {
        throw new Error(`Invalid record type: ${record.type}`);
      }
      
      const result = await this.db.query(`
        INSERT INTO dns_records (zone_id, name, type, value, ttl, priority, weight, port)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      `, [
        zoneId,
        record.name,
        record.type,
        record.value,
        record.ttl || 3600,
        record.priority,
        record.weight,
        record.port
      ]);
      
      // Increment zone serial
      await this.incrementZoneSerial(zoneId);
      
      // Reload zones
      await this.loadZones();
      
      this.emit('record:added', result.rows[0]);
      return result.rows[0];
    } catch (error) {
      this.logger.error('Add record error:', error);
      throw error;
    }
  }

  async updateRecord(recordId, updates) {
    try {
      const fields = [];
      const values = [];
      let paramCount = 1;
      
      Object.entries(updates).forEach(([key, value]) => {
        if (key !== 'id' && key !== 'zone_id') {
          fields.push(`${key} = $${paramCount}`);
          values.push(value);
          paramCount++;
        }
      });
      
      fields.push('updated_at = CURRENT_TIMESTAMP');
      values.push(recordId);
      
      const result = await this.db.query(`
        UPDATE dns_records
        SET ${fields.join(', ')}
        WHERE id = $${paramCount}
        RETURNING zone_id
      `, values);
      
      if (result.rows.length > 0) {
        await this.incrementZoneSerial(result.rows[0].zone_id);
        await this.loadZones();
      }
      
      return true;
    } catch (error) {
      this.logger.error('Update record error:', error);
      throw error;
    }
  }

  async deleteRecord(zoneId, recordId) {
    try {
      await this.db.query(
        'DELETE FROM dns_records WHERE id = $1 AND zone_id = $2',
        [recordId, zoneId]
      );
      
      await this.incrementZoneSerial(zoneId);
      await this.loadZones();
      
      this.emit('record:deleted', recordId);
      return true;
    } catch (error) {
      this.logger.error('Delete record error:', error);
      throw error;
    }
  }

  async incrementZoneSerial(zoneId) {
    // Format: YYYYMMDDNN (date + revision number)
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    
    const result = await this.db.query(
      'SELECT serial FROM dns_zones WHERE id = $1',
      [zoneId]
    );
    
    let newSerial;
    const currentSerial = result.rows[0]?.serial || 0;
    const currentDate = Math.floor(currentSerial / 100);
    
    if (currentDate === parseInt(today)) {
      // Same day, increment revision
      newSerial = currentSerial + 1;
    } else {
      // New day, reset revision
      newSerial = parseInt(today + '01');
    }
    
    await this.db.query(
      'UPDATE dns_zones SET serial = $1 WHERE id = $2',
      [newSerial, zoneId]
    );
  }

  async resolveLocal(name, type) {
    // Remove trailing dot if present
    name = name.replace(/\.$/, '');
    
    // Check cache first
    const cacheKey = `${name}:${type}`;
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (cached.expires > Date.now()) {
        return cached.answer;
      }
      this.cache.delete(cacheKey);
    }
    
    // Find matching zone
    let matchedZone = null;
    let longestMatch = 0;
    
    for (const [zoneName, zone] of this.zones) {
      if (name.endsWith(zoneName) && zoneName.length > longestMatch) {
        matchedZone = zone;
        longestMatch = zoneName.length;
      }
    }
    
    if (!matchedZone) {
      return null;
    }
    
    // Find matching records
    const records = matchedZone.records.filter(r => {
      const recordName = r.name === '@' ? matchedZone.name : 
                        `${r.name}.${matchedZone.name}`;
      return recordName === name && r.type === type;
    });
    
    if (records.length === 0) {
      // Check for CNAME
      const cname = matchedZone.records.find(r => {
        const recordName = r.name === '@' ? matchedZone.name : 
                          `${r.name}.${matchedZone.name}`;
        return recordName === name && r.type === 'CNAME';
      });
      
      if (cname) {
        return this.resolveLocal(cname.value, type);
      }
      
      return null;
    }
    
    const answer = this.formatAnswer(name, type, records[0]);
    
    // Cache the answer
    this.cache.set(cacheKey, {
      answer,
      expires: Date.now() + (records[0].ttl * 1000)
    });
    
    return answer;
  }

  formatAnswer(name, type, record) {
    const answer = {
      name,
      type,
      class: 'IN',
      ttl: record.ttl,
      isAnswer: true
    };
    
    switch (type) {
      case 'A':
      case 'AAAA':
        answer.address = record.value;
        break;
      
      case 'CNAME':
      case 'PTR':
      case 'NS':
        answer.domain = record.value;
        break;
      
      case 'MX':
        answer.exchange = record.value;
        answer.priority = record.priority || 10;
        break;
      
      case 'TXT':
        answer.data = record.value;
        break;
      
      case 'SRV':
        const parts = record.value.split(' ');
        answer.priority = record.priority || 0;
        answer.weight = record.weight || 0;
        answer.port = record.port || parseInt(parts[0]);
        answer.target = parts[1] || parts[0];
        break;
      
      default:
        answer.data = record.value;
    }
    
    return answer;
  }

  async forwardQuery(name, type) {
    // Forward to upstream DNS servers
    const dns = require('dns').promises;
    dns.setServers(this.forwarders);
    
    try {
      let result;
      
      switch (type) {
        case 'A':
          result = await dns.resolve4(name);
          return result.map(address => ({
            name,
            type: 'A',
            class: 'IN',
            ttl: 300,
            address,
            isAnswer: true
          }));
        
        case 'AAAA':
          result = await dns.resolve6(name);
          return result.map(address => ({
            name,
            type: 'AAAA',
            class: 'IN',
            ttl: 300,
            address,
            isAnswer: true
          }));
        
        case 'CNAME':
          result = await dns.resolveCname(name);
          return result.map(domain => ({
            name,
            type: 'CNAME',
            class: 'IN',
            ttl: 300,
            domain,
            isAnswer: true
          }));
        
        case 'MX':
          result = await dns.resolveMx(name);
          return result.map(mx => ({
            name,
            type: 'MX',
            class: 'IN',
            ttl: 300,
            exchange: mx.exchange,
            priority: mx.priority,
            isAnswer: true
          }));
        
        case 'TXT':
          result = await dns.resolveTxt(name);
          return result.map(data => ({
            name,
            type: 'TXT',
            class: 'IN',
            ttl: 300,
            data: data.join(''),
            isAnswer: true
          }));
        
        default:
          return null;
      }
    } catch (error) {
      this.logger.warn(`Failed to forward query for ${name}: ${error.message}`);
      return null;
    }
  }

  async logQuery(name, type, clientIp) {
    try {
      await this.db.query(`
        INSERT INTO dns_query_log (query_name, query_type, client_ip)
        VALUES ($1, $2, $3)
      `, [name, type, clientIp]);
    } catch (error) {
      // Don't fail on logging errors
      this.logger.warn('Query logging error:', error);
    }
  }

  async query(hostname, type = 'A') {
    const answer = await this.resolveLocal(hostname, type);
    
    if (answer) {
      return answer;
    }
    
    const upstreamAnswer = await this.forwardQuery(hostname, type);
    return upstreamAnswer ? upstreamAnswer[0] : null;
  }

  async listZones() {
    const result = await this.db.query(`
      SELECT z.*, COUNT(r.id) as record_count
      FROM dns_zones z
      LEFT JOIN dns_records r ON z.id = r.zone_id
      GROUP BY z.id
      ORDER BY z.name
    `);
    
    return result.rows;
  }

  async getZoneRecords(zoneName) {
    const zone = this.zones.get(zoneName);
    
    if (!zone) {
      throw new Error('Zone not found');
    }
    
    return zone.records;
  }

  async getQueryStats(startDate, endDate) {
    const result = await this.db.query(`
      SELECT 
        DATE(timestamp) as date,
        COUNT(*) as total_queries,
        COUNT(DISTINCT client_ip) as unique_clients,
        query_type,
        AVG(response_time) as avg_response_time
      FROM dns_query_log
      WHERE timestamp >= $1 AND timestamp <= $2
      GROUP BY DATE(timestamp), query_type
      ORDER BY date DESC
    `, [startDate, endDate]);
    
    return result.rows;
  }

  async exportZone(zoneId) {
    const zone = await this.db.query(
      'SELECT * FROM dns_zones WHERE id = $1',
      [zoneId]
    );
    
    if (zone.rows.length === 0) {
      throw new Error('Zone not found');
    }
    
    const records = await this.db.query(
      'SELECT * FROM dns_records WHERE zone_id = $1 ORDER BY type, name',
      [zoneId]
    );
    
    // Generate BIND zone file format
    let zoneFile = `; Zone file for ${zone.rows[0].name}\n`;
    zoneFile += `$TTL ${zone.rows[0].ttl}\n`;
    zoneFile += `$ORIGIN ${zone.rows[0].name}.\n\n`;
    
    records.rows.forEach(record => {
      const name = record.name === '@' ? '@' : record.name;
      zoneFile += `${name}\t${record.ttl}\tIN\t${record.type}\t${record.value}\n`;
    });
    
    return zoneFile;
  }

  async importZone(zoneData, format = 'bind') {
    // Parse and import zone data
    // Implementation depends on format (BIND, JSON, etc.)
    this.logger.info(`Importing zone in ${format} format`);
    // TODO: Implement zone import
  }

  isHealthy() {
    return this.dnsServer && this.zones.size > 0;
  }

  async stop() {
    if (this.dnsServer) {
      this.dnsServer.close();
      this.logger.info('DNS server stopped');
    }
  }
}

module.exports = DNSManager;