const { exec, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const axios = require('axios');

class CUPSIntegration {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.cupsHost = process.env.CUPS_HOST || 'localhost';
    this.cupsPort = process.env.CUPS_PORT || 631;
    this.cupsUrl = `http://${this.cupsHost}:${this.cupsPort}`;
  }

  async addPrinter(config) {
    const {
      name,
      uri,
      driver,
      description,
      location,
      shared = true,
      errorPolicy = 'retry-job'
    } = config;
    
    try {
      // Build lpadmin command
      const args = [
        '-p', name,
        '-E', // Enable printer
        '-v', uri
      ];
      
      if (driver) {
        if (driver.startsWith('model:')) {
          args.push('-m', driver.substring(6));
        } else if (driver.endsWith('.ppd')) {
          args.push('-P', driver);
        } else {
          args.push('-m', `everywhere`); // Use IPP Everywhere for auto-config
        }
      } else {
        args.push('-m', 'everywhere');
      }
      
      if (description) {
        args.push('-D', description);
      }
      
      if (location) {
        args.push('-L', location);
      }
      
      if (shared) {
        args.push('-o', 'printer-is-shared=true');
      }
      
      args.push('-o', `printer-error-policy=${errorPolicy}`);
      
      // Execute lpadmin
      await this.execCommand('lpadmin', args);
      
      // Set printer as accepting jobs
      await this.execCommand('cupsenable', [name]);
      await this.execCommand('cupsaccept', [name]);
      
      this.logger.info(`Added printer ${name} to CUPS`);
      
      return {
        success: true,
        printer: await this.getPrinterInfo(name)
      };
    } catch (error) {
      this.logger.error(`Failed to add printer ${name}:`, error);
      throw error;
    }
  }

  async removePrinter(name) {
    try {
      await this.execCommand('lpadmin', ['-x', name]);
      this.logger.info(`Removed printer ${name} from CUPS`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to remove printer ${name}:`, error);
      throw error;
    }
  }

  async updatePrinter(name, updates) {
    const args = ['-p', name];
    
    if (updates.description) {
      args.push('-D', updates.description);
    }
    
    if (updates.location) {
      args.push('-L', updates.location);
    }
    
    if (updates.shared !== undefined) {
      args.push('-o', `printer-is-shared=${updates.shared}`);
    }
    
    if (updates.errorPolicy) {
      args.push('-o', `printer-error-policy=${updates.errorPolicy}`);
    }
    
    if (updates.uri) {
      args.push('-v', updates.uri);
    }
    
    try {
      await this.execCommand('lpadmin', args);
      this.logger.info(`Updated printer ${name}`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to update printer ${name}:`, error);
      throw error;
    }
  }

  async listPrinters() {
    try {
      const output = await this.execCommand('lpstat', ['-p', '-d', '-l']);
      const printers = this.parseLpstatOutput(output);
      
      // Get additional info from CUPS API
      for (const printer of printers) {
        try {
          const details = await this.getPrinterInfo(printer.name);
          Object.assign(printer, details);
        } catch (error) {
          this.logger.warn(`Could not get details for printer ${printer.name}`);
        }
      }
      
      return printers;
    } catch (error) {
      this.logger.error('Failed to list printers:', error);
      throw error;
    }
  }

  async getPrinterInfo(name) {
    try {
      // Get printer attributes via IPP
      const response = await axios.post(
        `${this.cupsUrl}/printers/${name}`,
        this.buildIPPGetAttributesRequest(),
        {
          headers: {
            'Content-Type': 'application/ipp'
          },
          responseType: 'arraybuffer'
        }
      );
      
      const attributes = this.parseIPPResponse(response.data);
      
      // Also get queue info
      const queueInfo = await this.getQueueInfo(name);
      
      return {
        name,
        uri: attributes['device-uri'],
        state: attributes['printer-state'],
        stateReasons: attributes['printer-state-reasons'],
        makeAndModel: attributes['printer-make-and-model'],
        location: attributes['printer-location'],
        description: attributes['printer-info'],
        shared: attributes['printer-is-shared'],
        accepting: attributes['printer-is-accepting-jobs'],
        jobCount: queueInfo.jobCount,
        capabilities: {
          color: attributes['color-supported'],
          duplex: attributes['sides-supported']?.includes('two-sided'),
          staple: attributes['finishings-supported']?.includes('staple'),
          copies: attributes['copies-supported']
        },
        media: attributes['media-supported'],
        resolution: attributes['printer-resolution-supported'],
        pagesPrinted: attributes['printer-page-counter'] || 0,
        attributes
      };
    } catch (error) {
      this.logger.error(`Failed to get printer info for ${name}:`, error);
      
      // Fallback to lpstat
      const output = await this.execCommand('lpstat', ['-p', name, '-l']);
      return this.parsePrinterFromLpstat(output);
    }
  }

  async getQueueInfo(printerName) {
    try {
      const output = await this.execCommand('lpstat', ['-o', printerName]);
      const lines = output.split('\n').filter(l => l.trim());
      
      return {
        jobCount: lines.length,
        jobs: lines.map(line => this.parseJobLine(line))
      };
    } catch (error) {
      return { jobCount: 0, jobs: [] };
    }
  }

  async printFile(printerName, filePath, options = {}) {
    const args = ['-d', printerName];
    
    // Add print options
    if (options.copies) {
      args.push('-n', options.copies.toString());
    }
    
    if (options.sides) {
      args.push('-o', `sides=${options.sides}`);
    }
    
    if (options.media) {
      args.push('-o', `media=${options.media}`);
    }
    
    if (options.fitToPage) {
      args.push('-o', 'fit-to-page');
    }
    
    if (options.landscape) {
      args.push('-o', 'landscape');
    }
    
    if (options.pageRanges) {
      args.push('-o', `page-ranges=${options.pageRanges}`);
    }
    
    if (options.priority) {
      args.push('-q', options.priority.toString());
    }
    
    if (options.title) {
      args.push('-t', options.title);
    }
    
    // Add file path
    args.push(filePath);
    
    try {
      const output = await this.execCommand('lp', args);
      const jobId = this.extractJobId(output);
      
      this.logger.info(`Print job ${jobId} submitted to ${printerName}`);
      
      return {
        success: true,
        jobId,
        printer: printerName
      };
    } catch (error) {
      this.logger.error(`Failed to print to ${printerName}:`, error);
      throw error;
    }
  }

  async printRaw(printerName, data, options = {}) {
    // Save data to temp file
    const tempFile = `/tmp/print_${Date.now()}.prn`;
    await fs.writeFile(tempFile, data);
    
    try {
      const result = await this.printFile(printerName, tempFile, options);
      await fs.unlink(tempFile).catch(() => {});
      return result;
    } catch (error) {
      await fs.unlink(tempFile).catch(() => {});
      throw error;
    }
  }

  async cancelJob(jobId) {
    try {
      await this.execCommand('cancel', [jobId]);
      this.logger.info(`Cancelled job ${jobId}`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to cancel job ${jobId}:`, error);
      throw error;
    }
  }

  async getJobStatus(jobId) {
    try {
      const output = await this.execCommand('lpstat', ['-l', jobId]);
      return this.parseJobStatus(output);
    } catch (error) {
      this.logger.error(`Failed to get job status ${jobId}:`, error);
      throw error;
    }
  }

  async setPrinterDefault(name) {
    try {
      await this.execCommand('lpadmin', ['-d', name]);
      this.logger.info(`Set ${name} as default printer`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to set default printer ${name}:`, error);
      throw error;
    }
  }

  async pausePrinter(name) {
    try {
      await this.execCommand('cupsdisable', [name]);
      this.logger.info(`Paused printer ${name}`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to pause printer ${name}:`, error);
      throw error;
    }
  }

  async resumePrinter(name) {
    try {
      await this.execCommand('cupsenable', [name]);
      this.logger.info(`Resumed printer ${name}`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to resume printer ${name}:`, error);
      throw error;
    }
  }

  async rejectJobs(name) {
    try {
      await this.execCommand('cupsreject', [name]);
      this.logger.info(`Printer ${name} rejecting jobs`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to reject jobs for ${name}:`, error);
      throw error;
    }
  }

  async acceptJobs(name) {
    try {
      await this.execCommand('cupsaccept', [name]);
      this.logger.info(`Printer ${name} accepting jobs`);
      return { success: true };
    } catch (error) {
      this.logger.error(`Failed to accept jobs for ${name}:`, error);
      throw error;
    }
  }

  async getDrivers() {
    try {
      const output = await this.execCommand('lpinfo', ['-m']);
      return this.parseDriverList(output);
    } catch (error) {
      this.logger.error('Failed to get driver list:', error);
      
      // Return common generic drivers as fallback
      return [
        { name: 'everywhere', description: 'IPP Everywhere' },
        { name: 'raw', description: 'Raw Queue' },
        { name: 'postscript', description: 'Generic PostScript' },
        { name: 'pcl', description: 'Generic PCL' }
      ];
    }
  }

  async testPrinter(name) {
    try {
      // Create test page
      const testPage = this.generateTestPage(name);
      const tempFile = `/tmp/test_${Date.now()}.txt`;
      await fs.writeFile(tempFile, testPage);
      
      const result = await this.printFile(name, tempFile, { title: 'Test Page' });
      await fs.unlink(tempFile).catch(() => {});
      
      return result;
    } catch (error) {
      this.logger.error(`Failed to print test page to ${name}:`, error);
      throw error;
    }
  }

  // Helper methods
  execCommand(command, args = []) {
    return new Promise((resolve, reject) => {
      exec(`${command} ${args.join(' ')}`, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`${command} failed: ${stderr || error.message}`));
        } else {
          resolve(stdout);
        }
      });
    });
  }

  parseLpstatOutput(output) {
    const printers = [];
    const lines = output.split('\n');
    let currentPrinter = null;
    
    lines.forEach(line => {
      if (line.startsWith('printer ')) {
        const match = line.match(/printer (\S+)/);
        if (match) {
          currentPrinter = {
            name: match[1],
            enabled: !line.includes('disabled'),
            accepting: true
          };
          printers.push(currentPrinter);
        }
      } else if (currentPrinter && line.includes('Description:')) {
        currentPrinter.description = line.split('Description:')[1].trim();
      } else if (currentPrinter && line.includes('Location:')) {
        currentPrinter.location = line.split('Location:')[1].trim();
      }
    });
    
    return printers;
  }

  parsePrinterFromLpstat(output) {
    const printer = {};
    const lines = output.split('\n');
    
    lines.forEach(line => {
      if (line.includes('Description:')) {
        printer.description = line.split('Description:')[1].trim();
      } else if (line.includes('Location:')) {
        printer.location = line.split('Location:')[1].trim();
      } else if (line.includes('enabled')) {
        printer.enabled = true;
      } else if (line.includes('disabled')) {
        printer.enabled = false;
      }
    });
    
    return printer;
  }

  parseJobLine(line) {
    const match = line.match(/(\S+)-(\d+)\s+(\S+)\s+(\d+)\s+(.*)/);
    if (match) {
      return {
        id: `${match[1]}-${match[2]}`,
        printer: match[1],
        jobNumber: parseInt(match[2]),
        user: match[3],
        size: parseInt(match[4]),
        date: match[5]
      };
    }
    return null;
  }

  parseJobStatus(output) {
    const status = {
      id: null,
      state: 'unknown',
      user: null,
      title: null,
      size: 0,
      pages: 0
    };
    
    const lines = output.split('\n');
    lines.forEach(line => {
      if (line.includes('job-id')) {
        status.id = line.match(/\d+/)?.[0];
      } else if (line.includes('job-state')) {
        status.state = line.split(':')[1]?.trim();
      } else if (line.includes('job-originating-user')) {
        status.user = line.split(':')[1]?.trim();
      }
    });
    
    return status;
  }

  extractJobId(output) {
    const match = output.match(/request id is (\S+)/);
    return match ? match[1] : null;
  }

  parseDriverList(output) {
    const drivers = [];
    const lines = output.split('\n');
    
    lines.forEach(line => {
      const parts = line.split(' ');
      if (parts.length >= 2) {
        drivers.push({
          name: parts[0],
          description: parts.slice(1).join(' ')
        });
      }
    });
    
    return drivers;
  }

  buildIPPGetAttributesRequest() {
    // Build IPP request for get-printer-attributes
    const buffer = Buffer.alloc(1024);
    let offset = 0;
    
    // Version
    buffer.writeInt8(1, offset++);
    buffer.writeInt8(1, offset++);
    
    // Operation
    buffer.writeInt16BE(0x000B, offset);
    offset += 2;
    
    // Request ID
    buffer.writeInt32BE(1, offset);
    offset += 4;
    
    // Operation attributes tag
    buffer.writeInt8(0x01, offset++);
    
    return buffer.slice(0, offset);
  }

  parseIPPResponse(data) {
    const attributes = {};
    
    try {
      let offset = 8;
      
      while (offset < data.length) {
        const tag = data[offset++];
        if (tag === 0x03) break;
        
        const nameLength = data.readInt16BE(offset);
        offset += 2;
        
        if (nameLength > 0) {
          const name = data.slice(offset, offset + nameLength).toString();
          offset += nameLength;
          
          const valueLength = data.readInt16BE(offset);
          offset += 2;
          
          const value = data.slice(offset, offset + valueLength);
          offset += valueLength;
          
          attributes[name] = value.toString();
        }
      }
    } catch (error) {
      this.logger.error('IPP response parse error:', error);
    }
    
    return attributes;
  }

  generateTestPage(printerName) {
    return `
================================================================================
                           PRINTER TEST PAGE
================================================================================

Printer Name: ${printerName}
Date: ${new Date().toISOString()}
System: OpenDirectory Print Management

This is a test page to verify printer connectivity and configuration.

ASCII Test:
ABCDEFGHIJKLMNOPQRSTUVWXYZ
abcdefghijklmnopqrstuvwxyz
0123456789
!@#$%^&*()_+-=[]{}|;:'"<>,.?/

Line Test:
________________________________________________________________________________

Box Test:
+------------------------------------------------------------------------------+
|                                                                              |
|                          PRINTER SUCCESSFULLY CONFIGURED                     |
|                                                                              |
+------------------------------------------------------------------------------+

================================================================================
                              END OF TEST PAGE
================================================================================
`;
  }
}

module.exports = CUPSIntegration;