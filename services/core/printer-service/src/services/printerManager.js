const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class PrinterManager extends EventEmitter {
  constructor(cupsIntegration) {
    super();
    
    this.cups = cupsIntegration;
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/printers'
    });
    
    this.printers = new Map();
    this.monitoringInterval = null;
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS printers (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) UNIQUE NOT NULL,
          display_name VARCHAR(255),
          address VARCHAR(255) NOT NULL,
          port INTEGER,
          protocol VARCHAR(50),
          driver VARCHAR(255),
          uri VARCHAR(500),
          description TEXT,
          location VARCHAR(255),
          manufacturer VARCHAR(255),
          model VARCHAR(255),
          serial_number VARCHAR(255),
          capabilities JSONB,
          settings JSONB,
          status VARCHAR(50),
          status_message TEXT,
          page_count INTEGER DEFAULT 0,
          total_jobs INTEGER DEFAULT 0,
          error_count INTEGER DEFAULT 0,
          last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS printer_groups (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) UNIQUE NOT NULL,
          description TEXT,
          settings JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS printer_group_members (
          group_id UUID REFERENCES printer_groups(id) ON DELETE CASCADE,
          printer_id UUID REFERENCES printers(id) ON DELETE CASCADE,
          PRIMARY KEY (group_id, printer_id)
        );

        CREATE TABLE IF NOT EXISTS printer_stats (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          printer_id UUID REFERENCES printers(id) ON DELETE CASCADE,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          pages_printed INTEGER,
          ink_levels JSONB,
          toner_levels JSONB,
          paper_levels JSONB,
          uptime_seconds INTEGER,
          error_rate DECIMAL
        );

        CREATE INDEX idx_printer_status ON printers(status);
        CREATE INDEX idx_printer_location ON printers(location);
        CREATE INDEX idx_printer_stats_time ON printer_stats(timestamp);
      `);
      
      this.logger.info('Database initialized');
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async addPrinter(config) {
    try {
      // Auto-detect driver if requested
      if (config.autoDetect) {
        config.driver = await this.autoDetectDriver(config.address, config.protocol);
      }
      
      // Build printer URI
      if (!config.uri) {
        config.uri = this.buildPrinterURI(config);
      }
      
      // Add to CUPS
      const cupsResult = await this.cups.addPrinter({
        name: config.name,
        uri: config.uri,
        driver: config.driver,
        description: config.description,
        location: config.location
      });
      
      // Save to database
      const result = await this.db.query(`
        INSERT INTO printers (
          name, display_name, address, port, protocol, driver, uri,
          description, location, manufacturer, model, capabilities, settings, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING *
      `, [
        config.name,
        config.displayName || config.name,
        config.address,
        config.port,
        config.protocol,
        config.driver,
        config.uri,
        config.description,
        config.location,
        config.manufacturer,
        config.model,
        JSON.stringify(config.capabilities || {}),
        JSON.stringify(config.settings || {}),
        'idle'
      ]);
      
      const printer = result.rows[0];
      this.printers.set(printer.id, printer);
      
      this.emit('printer:added', printer);
      this.logger.info(`Added printer: ${printer.name}`);
      
      return printer;
    } catch (error) {
      this.logger.error('Add printer error:', error);
      throw error;
    }
  }

  async updatePrinter(id, updates) {
    try {
      const printer = await this.getPrinter(id);
      
      // Update CUPS if name or URI changed
      if (updates.name || updates.uri || updates.description || updates.location) {
        await this.cups.updatePrinter(printer.name, {
          description: updates.description,
          location: updates.location,
          uri: updates.uri
        });
      }
      
      // Build update query
      const fields = [];
      const values = [];
      let paramCount = 1;
      
      Object.keys(updates).forEach(key => {
        if (key !== 'id') {
          fields.push(`${key} = $${paramCount}`);
          values.push(updates[key]);
          paramCount++;
        }
      });
      
      fields.push(`updated_at = CURRENT_TIMESTAMP`);
      values.push(id);
      
      const result = await this.db.query(`
        UPDATE printers 
        SET ${fields.join(', ')}
        WHERE id = $${paramCount}
        RETURNING *
      `, values);
      
      const updatedPrinter = result.rows[0];
      this.printers.set(id, updatedPrinter);
      
      this.emit('printer:updated', updatedPrinter);
      return updatedPrinter;
    } catch (error) {
      this.logger.error('Update printer error:', error);
      throw error;
    }
  }

  async removePrinter(id) {
    try {
      const printer = await this.getPrinter(id);
      
      // Remove from CUPS
      await this.cups.removePrinter(printer.name);
      
      // Remove from database
      await this.db.query('DELETE FROM printers WHERE id = $1', [id]);
      
      this.printers.delete(id);
      this.emit('printer:removed', { id, name: printer.name });
      
      this.logger.info(`Removed printer: ${printer.name}`);
      return true;
    } catch (error) {
      this.logger.error('Remove printer error:', error);
      throw error;
    }
  }

  async getPrinter(id) {
    // Try cache first
    if (this.printers.has(id)) {
      return this.printers.get(id);
    }
    
    // Query database
    const result = await this.db.query('SELECT * FROM printers WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      throw new Error(`Printer ${id} not found`);
    }
    
    const printer = result.rows[0];
    this.printers.set(id, printer);
    
    return printer;
  }

  async listPrinters(filters = {}) {
    let query = 'SELECT * FROM printers WHERE 1=1';
    const values = [];
    let paramCount = 1;
    
    if (filters.status) {
      query += ` AND status = $${paramCount}`;
      values.push(filters.status);
      paramCount++;
    }
    
    if (filters.location) {
      query += ` AND location ILIKE $${paramCount}`;
      values.push(`%${filters.location}%`);
      paramCount++;
    }
    
    if (filters.protocol) {
      query += ` AND protocol = $${paramCount}`;
      values.push(filters.protocol);
      paramCount++;
    }
    
    query += ' ORDER BY name';
    
    const result = await this.db.query(query, values);
    return result.rows;
  }

  async createPrinterGroup(name, description, printerIds = []) {
    try {
      const result = await this.db.query(`
        INSERT INTO printer_groups (name, description)
        VALUES ($1, $2)
        RETURNING *
      `, [name, description]);
      
      const group = result.rows[0];
      
      // Add members
      if (printerIds.length > 0) {
        const memberValues = printerIds.map(printerId => 
          `('${group.id}', '${printerId}')`
        ).join(',');
        
        await this.db.query(`
          INSERT INTO printer_group_members (group_id, printer_id)
          VALUES ${memberValues}
        `);
      }
      
      this.logger.info(`Created printer group: ${name}`);
      return group;
    } catch (error) {
      this.logger.error('Create group error:', error);
      throw error;
    }
  }

  async addPrinterToGroup(groupId, printerId) {
    try {
      await this.db.query(`
        INSERT INTO printer_group_members (group_id, printer_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
      `, [groupId, printerId]);
      
      return true;
    } catch (error) {
      this.logger.error('Add to group error:', error);
      throw error;
    }
  }

  async removePrinterFromGroup(groupId, printerId) {
    try {
      await this.db.query(`
        DELETE FROM printer_group_members
        WHERE group_id = $1 AND printer_id = $2
      `, [groupId, printerId]);
      
      return true;
    } catch (error) {
      this.logger.error('Remove from group error:', error);
      throw error;
    }
  }

  async getGroupPrinters(groupId) {
    const result = await this.db.query(`
      SELECT p.* FROM printers p
      JOIN printer_group_members pgm ON p.id = pgm.printer_id
      WHERE pgm.group_id = $1
      ORDER BY p.name
    `, [groupId]);
    
    return result.rows;
  }

  async startMonitoring(interval = 60000) {
    this.logger.info('Starting printer monitoring');
    
    // Initial check
    this.checkAllPrinters();
    
    // Periodic monitoring
    this.monitoringInterval = setInterval(() => {
      this.checkAllPrinters();
    }, interval);
  }

  async stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
      this.logger.info('Stopped printer monitoring');
    }
  }

  async checkAllPrinters() {
    try {
      const printers = await this.listPrinters();
      
      for (const printer of printers) {
        await this.checkPrinterStatus(printer.id);
      }
    } catch (error) {
      this.logger.error('Monitor check error:', error);
    }
  }

  async checkPrinterStatus(printerId) {
    try {
      const printer = await this.getPrinter(printerId);
      
      // Get status from CUPS
      const cupsInfo = await this.cups.getPrinterInfo(printer.name);
      
      // Update database
      const newStatus = this.mapCUPSStatus(cupsInfo.state);
      
      if (newStatus !== printer.status) {
        await this.db.query(`
          UPDATE printers 
          SET status = $1, status_message = $2, last_seen = CURRENT_TIMESTAMP
          WHERE id = $3
        `, [newStatus, cupsInfo.stateReasons, printerId]);
        
        printer.status = newStatus;
        printer.status_message = cupsInfo.stateReasons;
        
        this.emit('printer:status', {
          printerId,
          status: newStatus,
          message: cupsInfo.stateReasons
        });
      }
      
      // Update page count if changed
      if (cupsInfo.pagesPrinted && cupsInfo.pagesPrinted !== printer.page_count) {
        await this.db.query(`
          UPDATE printers SET page_count = $1 WHERE id = $2
        `, [cupsInfo.pagesPrinted, printerId]);
        
        printer.page_count = cupsInfo.pagesPrinted;
      }
      
      // Record stats
      await this.recordPrinterStats(printerId, {
        pages_printed: cupsInfo.pagesPrinted,
        status: newStatus
      });
      
      return printer;
    } catch (error) {
      this.logger.error(`Status check error for ${printerId}:`, error);
      
      // Mark as offline
      await this.db.query(`
        UPDATE printers 
        SET status = 'offline', status_message = $1
        WHERE id = $2
      `, [error.message, printerId]);
      
      this.emit('printer:status', {
        printerId,
        status: 'offline',
        message: error.message
      });
    }
  }

  async recordPrinterStats(printerId, stats) {
    try {
      await this.db.query(`
        INSERT INTO printer_stats (printer_id, pages_printed)
        VALUES ($1, $2)
      `, [printerId, stats.pages_printed]);
    } catch (error) {
      this.logger.warn('Stats recording error:', error);
    }
  }

  async getPrinterStats(printerId, startDate, endDate) {
    const result = await this.db.query(`
      SELECT * FROM printer_stats
      WHERE printer_id = $1 
        AND timestamp >= $2 
        AND timestamp <= $3
      ORDER BY timestamp
    `, [printerId, startDate, endDate]);
    
    return result.rows;
  }

  buildPrinterURI(config) {
    const { protocol, address, port, path } = config;
    
    switch (protocol) {
      case 'ipp':
        return `ipp://${address}:${port || 631}/${path || 'ipp/print'}`;
      
      case 'ipps':
        return `ipps://${address}:${port || 631}/${path || 'ipp/print'}`;
      
      case 'lpd':
        return `lpd://${address}/${path || ''}`;
      
      case 'socket':
      case 'raw':
        return `socket://${address}:${port || 9100}`;
      
      case 'smb':
        return `smb://${address}/${path}`;
      
      case 'usb':
        return 'usb://Unknown/Printer';
      
      default:
        return `socket://${address}:${port || 9100}`;
    }
  }

  async autoDetectDriver(address, protocol) {
    // Try to determine the best driver
    try {
      // For IPP printers, use IPP Everywhere
      if (protocol === 'ipp' || protocol === 'ipps') {
        return 'everywhere';
      }
      
      // Try to detect via SNMP or other means
      // This is simplified - real implementation would probe the printer
      
      return 'everywhere'; // Default to IPP Everywhere
    } catch (error) {
      this.logger.warn('Auto-detect driver failed, using generic');
      return 'raw';
    }
  }

  mapCUPSStatus(cupsState) {
    const stateMap = {
      3: 'idle',
      4: 'printing',
      5: 'stopped',
      6: 'cancelled',
      7: 'aborted',
      8: 'completed'
    };
    
    return stateMap[cupsState] || 'unknown';
  }

  async setDefaultPrinter(printerId) {
    try {
      const printer = await this.getPrinter(printerId);
      await this.cups.setPrinterDefault(printer.name);
      
      // Update all printers to not default
      await this.db.query(`UPDATE printers SET settings = jsonb_set(settings, '{isDefault}', 'false')`);
      
      // Set this printer as default
      await this.db.query(`
        UPDATE printers 
        SET settings = jsonb_set(settings, '{isDefault}', 'true')
        WHERE id = $1
      `, [printerId]);
      
      this.emit('printer:default', printerId);
      return true;
    } catch (error) {
      this.logger.error('Set default printer error:', error);
      throw error;
    }
  }

  async testPrinter(printerId) {
    try {
      const printer = await this.getPrinter(printerId);
      const result = await this.cups.testPrinter(printer.name);
      
      this.emit('printer:test', { printerId, result });
      return result;
    } catch (error) {
      this.logger.error(`Test printer ${printerId} error:`, error);
      throw error;
    }
  }
}

module.exports = PrinterManager;