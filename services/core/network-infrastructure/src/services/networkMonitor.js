const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const ping = require('ping');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class NetworkMonitor extends EventEmitter {
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
    
    this.monitoringActive = false;
    this.alerts = new Map();
    this.thresholds = {
      ping_timeout: 5000,
      bandwidth_threshold: 80,
      cpu_threshold: 85,
      memory_threshold: 90,
      disk_threshold: 95
    };
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS network_monitoring (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          device_id UUID,
          device_ip VARCHAR(45),
          metric_type VARCHAR(50),
          metric_value DECIMAL,
          status VARCHAR(20),
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          response_time INTEGER,
          error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS bandwidth_monitoring (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          device_id UUID,
          interface_name VARCHAR(100),
          bytes_in BIGINT,
          bytes_out BIGINT,
          packets_in BIGINT,
          packets_out BIGINT,
          errors_in INTEGER,
          errors_out INTEGER,
          utilization_percent DECIMAL,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS network_alerts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          device_id UUID,
          alert_type VARCHAR(50),
          severity VARCHAR(20),
          title VARCHAR(255),
          description TEXT,
          status VARCHAR(20) DEFAULT 'active',
          acknowledged BOOLEAN DEFAULT false,
          acknowledged_by VARCHAR(255),
          acknowledged_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          resolved_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS monitoring_thresholds (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          device_id UUID,
          metric_type VARCHAR(50),
          warning_threshold DECIMAL,
          critical_threshold DECIMAL,
          enabled BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_monitoring_device ON network_monitoring(device_id);
        CREATE INDEX idx_monitoring_time ON network_monitoring(timestamp);
        CREATE INDEX idx_bandwidth_device ON bandwidth_monitoring(device_id);
        CREATE INDEX idx_alerts_device ON network_alerts(device_id);
        CREATE INDEX idx_alerts_status ON network_alerts(status);
      `);
      
      this.logger.info('Network monitoring database initialized');
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async startMonitoring(interval = 60000) {
    if (this.monitoringActive) {
      this.logger.warn('Monitoring already active');
      return;
    }
    
    this.monitoringActive = true;
    this.logger.info('Starting network monitoring');
    
    // Monitor devices
    this.deviceMonitorInterval = setInterval(() => {
      this.monitorAllDevices().catch(error => 
        this.logger.error('Device monitoring error:', error)
      );
    }, interval);
    
    // Monitor bandwidth (less frequent)
    this.bandwidthMonitorInterval = setInterval(() => {
      this.monitorBandwidth().catch(error =>
        this.logger.error('Bandwidth monitoring error:', error)
      );
    }, interval * 5);
    
    // Check alerts
    this.alertCheckInterval = setInterval(() => {
      this.processAlerts().catch(error =>
        this.logger.error('Alert processing error:', error)
      );
    }, 30000);
    
    // Clean old data
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldData().catch(error =>
        this.logger.error('Cleanup error:', error)
      );
    }, 3600000); // Every hour
  }

  async stop() {
    this.monitoringActive = false;
    
    if (this.deviceMonitorInterval) clearInterval(this.deviceMonitorInterval);
    if (this.bandwidthMonitorInterval) clearInterval(this.bandwidthMonitorInterval);
    if (this.alertCheckInterval) clearInterval(this.alertCheckInterval);
    if (this.cleanupInterval) clearInterval(this.cleanupInterval);
    
    this.logger.info('Network monitoring stopped');
  }

  async monitorAllDevices() {
    try {
      // Get all devices that should be monitored
      const devices = await this.db.query(`
        SELECT * FROM network_devices 
        WHERE monitoring_enabled = true 
        AND status != 'offline'
        ORDER BY last_seen DESC
        LIMIT 100
      `);
      
      const monitoringPromises = devices.rows.map(device => 
        this.monitorDevice(device).catch(error => {
          this.logger.warn(`Failed to monitor device ${device.ip_address}: ${error.message}`);
        })
      );
      
      await Promise.allSettled(monitoringPromises);
      
    } catch (error) {
      this.logger.error('Monitor all devices error:', error);
    }
  }

  async monitorDevice(device) {
    const startTime = Date.now();
    
    try {
      // Ping test
      const pingResult = await ping.promise.probe(device.ip_address, {
        timeout: this.thresholds.ping_timeout / 1000
      });
      
      const responseTime = pingResult.alive ? pingResult.time : null;
      const status = pingResult.alive ? 'online' : 'offline';
      
      // Record monitoring data
      await this.db.query(`
        INSERT INTO network_monitoring (
          device_id, device_ip, metric_type, metric_value, status, response_time
        ) VALUES ($1, $2, 'ping', $3, $4, $5)
      `, [device.id, device.ip_address, responseTime, status, responseTime]);
      
      // Update device status if changed
      if (device.status !== status) {
        await this.db.query(`
          UPDATE network_devices 
          SET status = $1, last_seen = CURRENT_TIMESTAMP
          WHERE id = $2
        `, [status, device.id]);
        
        // Create alert for status change
        await this.createAlert(device.id, 'status_change', 
          status === 'offline' ? 'critical' : 'info',
          `Device ${status}`,
          `Device ${device.hostname || device.ip_address} is now ${status}`
        );
      }
      
      // If device is online, get additional metrics
      if (pingResult.alive) {
        await this.getDeviceMetrics(device);
      }
      
    } catch (error) {
      await this.db.query(`
        INSERT INTO network_monitoring (
          device_id, device_ip, metric_type, status, error_message
        ) VALUES ($1, $2, 'ping', 'error', $3)
      `, [device.id, device.ip_address, error.message]);
    }
  }

  async getDeviceMetrics(device) {
    if (!device.snmp_community) {
      return; // Can't get detailed metrics without SNMP
    }
    
    try {
      const snmp = require('snmp-native');
      const session = new snmp.Session({ 
        host: device.ip_address, 
        community: device.snmp_community 
      });
      
      // Get system metrics
      const oids = [
        '1.3.6.1.4.1.2021.10.1.3.1', // CPU load
        '1.3.6.1.4.1.2021.4.5.0',    // Memory total
        '1.3.6.1.4.1.2021.4.6.0',    // Memory available
        '1.3.6.1.2.1.25.2.3.1.6.1',  // Storage used
        '1.3.6.1.2.1.25.2.3.1.5.1'   // Storage total
      ];
      
      const result = await new Promise((resolve, reject) => {
        session.getAll({ oids }, (error, varbinds) => {
          session.close();
          if (error) reject(error);
          else resolve(varbinds);
        });
      });
      
      if (result && result.length > 0) {
        // Process CPU
        const cpuLoad = parseFloat(result[0]?.value || 0);
        await this.recordMetric(device.id, 'cpu_usage', cpuLoad);
        
        // Process Memory
        const memTotal = parseInt(result[1]?.value || 0);
        const memAvailable = parseInt(result[2]?.value || 0);
        const memUsed = memTotal - memAvailable;
        const memPercent = memTotal > 0 ? (memUsed / memTotal) * 100 : 0;
        await this.recordMetric(device.id, 'memory_usage', memPercent);
        
        // Process Storage
        const storageUsed = parseInt(result[3]?.value || 0);
        const storageTotal = parseInt(result[4]?.value || 0);
        const storagePercent = storageTotal > 0 ? (storageUsed / storageTotal) * 100 : 0;
        await this.recordMetric(device.id, 'disk_usage', storagePercent);
        
        // Check thresholds and create alerts
        await this.checkThresholds(device.id, 'cpu_usage', cpuLoad);
        await this.checkThresholds(device.id, 'memory_usage', memPercent);
        await this.checkThresholds(device.id, 'disk_usage', storagePercent);
      }
      
    } catch (error) {
      this.logger.warn(`Could not get SNMP metrics for ${device.ip_address}: ${error.message}`);
    }
  }

  async recordMetric(deviceId, metricType, value) {
    await this.db.query(`
      INSERT INTO network_monitoring (device_id, metric_type, metric_value, status)
      VALUES ($1, $2, $3, 'ok')
    `, [deviceId, metricType, value]);
  }

  async checkThresholds(deviceId, metricType, value) {
    // Get thresholds for this device/metric
    const thresholdResult = await this.db.query(`
      SELECT * FROM monitoring_thresholds
      WHERE device_id = $1 AND metric_type = $2 AND enabled = true
    `, [deviceId, metricType]);
    
    let warningThreshold, criticalThreshold;
    
    if (thresholdResult.rows.length > 0) {
      const threshold = thresholdResult.rows[0];
      warningThreshold = threshold.warning_threshold;
      criticalThreshold = threshold.critical_threshold;
    } else {
      // Use default thresholds
      switch (metricType) {
        case 'cpu_usage':
          warningThreshold = 70;
          criticalThreshold = this.thresholds.cpu_threshold;
          break;
        case 'memory_usage':
          warningThreshold = 80;
          criticalThreshold = this.thresholds.memory_threshold;
          break;
        case 'disk_usage':
          warningThreshold = 85;
          criticalThreshold = this.thresholds.disk_threshold;
          break;
        default:
          return;
      }
    }
    
    // Check thresholds
    if (value >= criticalThreshold) {
      await this.createAlert(deviceId, `${metricType}_critical`, 'critical',
        `${metricType} Critical`,
        `${metricType} is at ${value.toFixed(1)}% (threshold: ${criticalThreshold}%)`
      );
    } else if (value >= warningThreshold) {
      await this.createAlert(deviceId, `${metricType}_warning`, 'warning',
        `${metricType} Warning`,
        `${metricType} is at ${value.toFixed(1)}% (threshold: ${warningThreshold}%)`
      );
    }
  }

  async monitorBandwidth() {
    try {
      // Get network switches and routers for bandwidth monitoring
      const devices = await this.db.query(`
        SELECT * FROM network_devices 
        WHERE device_type IN ('switch', 'router') 
        AND snmp_community IS NOT NULL
        AND monitoring_enabled = true
      `);
      
      for (const device of devices.rows) {
        await this.getBandwidthData(device);
      }
      
    } catch (error) {
      this.logger.error('Bandwidth monitoring error:', error);
    }
  }

  async getBandwidthData(device) {
    try {
      const snmp = require('snmp-native');
      const session = new snmp.Session({ 
        host: device.ip_address, 
        community: device.snmp_community 
      });
      
      // Get interface statistics
      const oids = [
        '1.3.6.1.2.1.2.2.1.2',  // ifDescr - interface names
        '1.3.6.1.2.1.2.2.1.10', // ifInOctets
        '1.3.6.1.2.1.2.2.1.16', // ifOutOctets
        '1.3.6.1.2.1.2.2.1.11', // ifInUcastPkts
        '1.3.6.1.2.1.2.2.1.17', // ifOutUcastPkts
        '1.3.6.1.2.1.2.2.1.14', // ifInErrors
        '1.3.6.1.2.1.2.2.1.20'  // ifOutErrors
      ];
      
      // Walk the interface table
      const result = await new Promise((resolve, reject) => {
        session.getSubtree({ oid: '1.3.6.1.2.1.2.2.1' }, (error, varbinds) => {
          session.close();
          if (error) reject(error);
          else resolve(varbinds);
        });
      });
      
      // Process interface data
      const interfaces = this.parseInterfaceData(result);
      
      for (const iface of interfaces) {
        await this.db.query(`
          INSERT INTO bandwidth_monitoring (
            device_id, interface_name, bytes_in, bytes_out,
            packets_in, packets_out, errors_in, errors_out
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
          device.id, iface.name, iface.bytesIn, iface.bytesOut,
          iface.packetsIn, iface.packetsOut, iface.errorsIn, iface.errorsOut
        ]);
        
        // Calculate utilization (simplified)
        const totalBytes = iface.bytesIn + iface.bytesOut;
        const utilization = this.calculateUtilization(totalBytes, iface.speed);
        
        if (utilization > this.thresholds.bandwidth_threshold) {
          await this.createAlert(device.id, 'bandwidth_high', 'warning',
            'High Bandwidth Usage',
            `Interface ${iface.name} utilization: ${utilization.toFixed(1)}%`
          );
        }
      }
      
    } catch (error) {
      this.logger.warn(`Could not get bandwidth data for ${device.ip_address}: ${error.message}`);
    }
  }

  parseInterfaceData(varbinds) {
    // Parse SNMP interface data
    const interfaces = {};
    
    varbinds.forEach(vb => {
      const oid = vb.oid;
      const parts = oid.split('.');
      const ifIndex = parts[parts.length - 1];
      const metric = parts[parts.length - 2];
      
      if (!interfaces[ifIndex]) {
        interfaces[ifIndex] = {};
      }
      
      switch (metric) {
        case '2': interfaces[ifIndex].name = vb.value; break;
        case '10': interfaces[ifIndex].bytesIn = parseInt(vb.value); break;
        case '16': interfaces[ifIndex].bytesOut = parseInt(vb.value); break;
        case '11': interfaces[ifIndex].packetsIn = parseInt(vb.value); break;
        case '17': interfaces[ifIndex].packetsOut = parseInt(vb.value); break;
        case '14': interfaces[ifIndex].errorsIn = parseInt(vb.value); break;
        case '20': interfaces[ifIndex].errorsOut = parseInt(vb.value); break;
      }
    });
    
    return Object.values(interfaces).filter(iface => iface.name);
  }

  calculateUtilization(bytes, interfaceSpeed) {
    // Simplified utilization calculation
    // In reality, you'd need to compare with previous measurement
    return Math.min((bytes / 1000000) * 0.1, 100);
  }

  async createAlert(deviceId, alertType, severity, title, description) {
    try {
      // Check if similar alert already exists
      const existing = await this.db.query(`
        SELECT * FROM network_alerts
        WHERE device_id = $1 AND alert_type = $2 AND status = 'active'
      `, [deviceId, alertType]);
      
      if (existing.rows.length === 0) {
        const result = await this.db.query(`
          INSERT INTO network_alerts (device_id, alert_type, severity, title, description)
          VALUES ($1, $2, $3, $4, $5)
          RETURNING *
        `, [deviceId, alertType, severity, title, description]);
        
        const alert = result.rows[0];
        
        // Store in memory for quick access
        this.alerts.set(alert.id, alert);
        
        // Emit event for real-time notifications
        this.emit('alert:created', alert);
        
        this.logger.warn(`Alert created: ${title} - ${description}`);
        
        return alert;
      }
    } catch (error) {
      this.logger.error('Create alert error:', error);
    }
  }

  async acknowledgeAlert(alertId, acknowledgedBy) {
    try {
      await this.db.query(`
        UPDATE network_alerts
        SET acknowledged = true, acknowledged_by = $1, acknowledged_at = CURRENT_TIMESTAMP
        WHERE id = $2
      `, [acknowledgedBy, alertId]);
      
      this.emit('alert:acknowledged', { alertId, acknowledgedBy });
      return true;
    } catch (error) {
      this.logger.error('Acknowledge alert error:', error);
      throw error;
    }
  }

  async resolveAlert(alertId, resolvedBy) {
    try {
      await this.db.query(`
        UPDATE network_alerts
        SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `, [alertId]);
      
      this.alerts.delete(alertId);
      this.emit('alert:resolved', { alertId, resolvedBy });
      return true;
    } catch (error) {
      this.logger.error('Resolve alert error:', error);
      throw error;
    }
  }

  async getActiveAlerts() {
    const result = await this.db.query(`
      SELECT a.*, d.hostname, d.ip_address
      FROM network_alerts a
      LEFT JOIN network_devices d ON a.device_id = d.id
      WHERE a.status = 'active'
      ORDER BY a.severity DESC, a.created_at DESC
    `);
    
    return result.rows;
  }

  async getOverallStatus() {
    // Get overall network health
    const deviceStats = await this.db.query(`
      SELECT 
        COUNT(*) as total_devices,
        COUNT(*) FILTER (WHERE status = 'online') as online_devices,
        COUNT(*) FILTER (WHERE status = 'offline') as offline_devices
      FROM network_devices
      WHERE monitoring_enabled = true
    `);
    
    const alertStats = await this.db.query(`
      SELECT 
        COUNT(*) as total_alerts,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_alerts,
        COUNT(*) FILTER (WHERE severity = 'warning') as warning_alerts
      FROM network_alerts
      WHERE status = 'active'
    `);
    
    const recentMetrics = await this.db.query(`
      SELECT 
        metric_type,
        AVG(metric_value) as avg_value,
        MAX(metric_value) as max_value
      FROM network_monitoring
      WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'
      AND metric_type IN ('cpu_usage', 'memory_usage', 'disk_usage')
      GROUP BY metric_type
    `);
    
    const stats = deviceStats.rows[0];
    const alerts = alertStats.rows[0];
    
    // Calculate health score
    const healthScore = this.calculateHealthScore(stats, alerts);
    
    return {
      healthScore,
      status: healthScore > 80 ? 'healthy' : healthScore > 60 ? 'warning' : 'critical',
      devices: {
        total: parseInt(stats.total_devices),
        online: parseInt(stats.online_devices),
        offline: parseInt(stats.offline_devices),
        availability: stats.total_devices > 0 ? 
          Math.round((stats.online_devices / stats.total_devices) * 100) : 100
      },
      alerts: {
        total: parseInt(alerts.total_alerts),
        critical: parseInt(alerts.critical_alerts),
        warning: parseInt(alerts.warning_alerts)
      },
      metrics: recentMetrics.rows.reduce((acc, row) => {
        acc[row.metric_type] = {
          average: parseFloat(row.avg_value).toFixed(1),
          maximum: parseFloat(row.max_value).toFixed(1)
        };
        return acc;
      }, {})
    };
  }

  calculateHealthScore(deviceStats, alertStats) {
    let score = 100;
    
    // Device availability impact
    const availability = deviceStats.total_devices > 0 ? 
      (deviceStats.online_devices / deviceStats.total_devices) * 100 : 100;
    score = score * (availability / 100);
    
    // Alert impact
    const criticalImpact = parseInt(alertStats.critical_alerts) * 20;
    const warningImpact = parseInt(alertStats.warning_alerts) * 10;
    score = Math.max(0, score - criticalImpact - warningImpact);
    
    return Math.round(score);
  }

  async getBandwidthUsage() {
    const result = await this.db.query(`
      SELECT 
        d.hostname,
        d.ip_address,
        b.interface_name,
        b.bytes_in,
        b.bytes_out,
        b.utilization_percent,
        b.timestamp
      FROM bandwidth_monitoring b
      JOIN network_devices d ON b.device_id = d.id
      WHERE b.timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
      ORDER BY b.timestamp DESC
      LIMIT 100
    `);
    
    return result.rows;
  }

  async pingHost(host) {
    try {
      const result = await ping.promise.probe(host, { timeout: 5 });
      
      return {
        host,
        alive: result.alive,
        time: result.time,
        min: result.min,
        max: result.max,
        avg: result.avg,
        packetLoss: result.packetLoss
      };
    } catch (error) {
      return {
        host,
        alive: false,
        error: error.message
      };
    }
  }

  async traceroute(host) {
    try {
      const { stdout } = await execAsync(`traceroute ${host}`);
      const lines = stdout.split('\n').filter(line => line.trim());
      
      const hops = [];
      
      for (const line of lines.slice(1)) { // Skip header
        const match = line.match(/^\s*(\d+)\s+(.+)/);
        if (match) {
          hops.push({
            hop: parseInt(match[1]),
            details: match[2].trim()
          });
        }
      }
      
      return {
        target: host,
        hops,
        completed: true
      };
    } catch (error) {
      return {
        target: host,
        error: error.message,
        completed: false
      };
    }
  }

  async processAlerts() {
    // Auto-resolve alerts that no longer apply
    const activeAlerts = await this.getActiveAlerts();
    
    for (const alert of activeAlerts) {
      const shouldResolve = await this.shouldAutoResolveAlert(alert);
      if (shouldResolve) {
        await this.resolveAlert(alert.id, 'system');
      }
    }
  }

  async shouldAutoResolveAlert(alert) {
    // Check if conditions that triggered the alert still exist
    switch (alert.alert_type) {
      case 'status_change':
        // Check if device is back online
        const device = await this.db.query(`
          SELECT status FROM network_devices WHERE id = $1
        `, [alert.device_id]);
        
        return device.rows[0]?.status === 'online';
      
      case 'cpu_usage_critical':
      case 'memory_usage_critical':
      case 'disk_usage_critical':
        // Check if metric is below threshold
        const recentMetric = await this.db.query(`
          SELECT metric_value FROM network_monitoring
          WHERE device_id = $1 AND metric_type = $2
          ORDER BY timestamp DESC
          LIMIT 1
        `, [alert.device_id, alert.alert_type.replace('_critical', '')]);
        
        if (recentMetric.rows.length > 0) {
          return recentMetric.rows[0].metric_value < 80; // Below warning threshold
        }
        break;
    }
    
    return false;
  }

  async cleanupOldData() {
    try {
      // Clean old monitoring data (keep 30 days)
      const cleanupResult = await this.db.query(`
        DELETE FROM network_monitoring
        WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '30 days'
      `);
      
      // Clean old bandwidth data (keep 7 days)
      const bandwidthCleanup = await this.db.query(`
        DELETE FROM bandwidth_monitoring
        WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '7 days'
      `);
      
      // Clean resolved alerts (keep 90 days)
      const alertCleanup = await this.db.query(`
        DELETE FROM network_alerts
        WHERE status = 'resolved' 
        AND resolved_at < CURRENT_TIMESTAMP - INTERVAL '90 days'
      `);
      
      if (cleanupResult.rowCount > 0 || bandwidthCleanup.rowCount > 0 || alertCleanup.rowCount > 0) {
        this.logger.info(`Cleaned up old data: ${cleanupResult.rowCount} monitoring records, ${bandwidthCleanup.rowCount} bandwidth records, ${alertCleanup.rowCount} alerts`);
      }
    } catch (error) {
      this.logger.error('Cleanup error:', error);
    }
  }
}

module.exports = NetworkMonitor;