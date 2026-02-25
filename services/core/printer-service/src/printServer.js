const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const net = require('net');
const ipp = require('ipp');
const crypto = require('crypto');
const winston = require('winston');

const execAsync = promisify(exec);

/**
 * OpenDirectory Print Server
 * Acts as a central print server like Windows Print Server
 * All clients connect to OpenDirectory, not directly to printers
 */
class OpenDirectoryPrintServer {
  constructor() {
    // OpenDirectory server configuration
    this.serverIP = process.env.OPENDIRECTORY_IP || this.getServerIP();
    this.serverHostname = process.env.OPENDIRECTORY_HOSTNAME || 'opendirectory.local';
    this.serverPort = process.env.PRINT_SERVER_PORT || 631; // CUPS/IPP port
    
    // Print server paths
    this.spoolDirectory = '/var/spool/opendirectory/print';
    this.driverStore = '/var/lib/opendirectory/drivers';
    this.configPath = '/etc/opendirectory/print';
    
    // Managed printers and queues
    this.printers = new Map();
    this.queues = new Map();
    this.jobs = new Map();
    this.connectedClients = new Map();
    
    // Statistics
    this.stats = {
      totalJobs: 0,
      completedJobs: 0,
      failedJobs: 0,
      activeClients: 0
    };
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: '/var/log/opendirectory/print-server.log' })
      ]
    });
    
    this.initialize();
  }
  
  async initialize() {
    try {
      // Create necessary directories
      await this.createDirectories();
      
      // Initialize CUPS backend
      await this.initializeCUPS();
      
      // Initialize Samba for Windows clients
      await this.initializeSamba();
      
      // Load existing printer configurations
      await this.loadPrinterConfigurations();
      
      this.logger.info(`OpenDirectory Print Server initialized at ${this.serverIP}`);
    } catch (error) {
      this.logger.error('Failed to initialize print server:', error);
      throw error;
    }
  }
  
  async createDirectories() {
    const dirs = [
      this.spoolDirectory,
      this.driverStore,
      this.configPath,
      `${this.driverStore}/windows`,
      `${this.driverStore}/macos`,
      `${this.driverStore}/linux`,
      `${this.spoolDirectory}/queues`,
      `${this.spoolDirectory}/completed`,
      `${this.spoolDirectory}/failed`
    ];
    
    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
    }
  }
  
  async initializeCUPS() {
    try {
      // Configure CUPS to accept remote connections
      const cupsConfig = `
# OpenDirectory CUPS Configuration
Listen ${this.serverIP}:631
Listen /var/run/cups/cups.sock

# Allow remote access
BrowseAllow all
BrowseAddress @LOCAL

# Authentication
DefaultAuthType Basic

<Location />
  Order allow,deny
  Allow from all
</Location>

<Location /admin>
  Order allow,deny
  Allow from all
</Location>

<Location /printers>
  Order allow,deny
  Allow from all
</Location>
`;
      
      await fs.writeFile('/etc/cups/cupsd.conf', cupsConfig);
      await execAsync('systemctl restart cups');
      
      this.logger.info('CUPS initialized for remote printing');
    } catch (error) {
      this.logger.error('Failed to initialize CUPS:', error);
    }
  }
  
  async initializeSamba() {
    try {
      // Configure Samba for Windows print sharing
      const sambaConfig = `
# OpenDirectory Print Server Configuration
[global]
  workgroup = WORKGROUP
  server string = OpenDirectory Print Server
  security = user
  map to guest = Bad User
  
  # Print server settings
  load printers = yes
  printing = cups
  printcap name = cups
  
  # Spool settings
  path = ${this.spoolDirectory}
  
  # Log settings
  log file = /var/log/samba/opendirectory-print.log
  max log size = 50
  
[print$]
  comment = Printer Drivers
  path = ${this.driverStore}/windows
  browseable = yes
  read only = yes
  guest ok = no
  write list = @admin
  
[printers]
  comment = All Printers
  path = ${this.spoolDirectory}
  browseable = yes
  guest ok = no
  writable = no
  printable = yes
  create mask = 0700
`;
      
      await fs.writeFile('/etc/samba/opendirectory-print.conf', sambaConfig);
      await execAsync('echo "include = /etc/samba/opendirectory-print.conf" >> /etc/samba/smb.conf');
      await execAsync('systemctl restart smbd nmbd');
      
      this.logger.info('Samba initialized for Windows print sharing');
    } catch (error) {
      this.logger.error('Failed to initialize Samba:', error);
    }
  }
  
  /**
   * Add a physical printer to OpenDirectory Print Server
   * This makes the printer available through OpenDirectory, not directly
   */
  async addPrinter(config) {
    try {
      const printer = {
        id: crypto.randomBytes(8).toString('hex'),
        name: config.name,
        shareName: config.shareName || config.name.replace(/\s+/g, '-'),
        displayName: config.displayName || config.name,
        
        // Physical printer details
        deviceIP: config.deviceIP, // The actual printer IP (e.g., 192.168.1.52)
        devicePort: config.devicePort || 9100, // RAW port or IPP port
        protocol: config.protocol || 'ipp', // ipp, lpd, raw, socket
        
        // OpenDirectory server paths (what clients will use)
        serverPath: {
          windows: `\\\\${this.serverIP}\\${config.shareName}`,
          windowsHostname: `\\\\${this.serverHostname}\\${config.shareName}`,
          macos: `smb://${this.serverIP}/${config.shareName}`,
          linux: `ipp://${this.serverIP}:631/printers/${config.shareName}`,
          ipp: `ipp://${this.serverIP}/printers/${config.shareName}`,
          lpd: `lpd://${this.serverIP}/${config.shareName}`
        },
        
        // Printer capabilities
        capabilities: {
          color: config.color || false,
          duplex: config.duplex || false,
          staple: config.staple || false,
          paperSizes: config.paperSizes || ['A4', 'Letter'],
          resolution: config.resolution || ['600x600dpi']
        },
        
        // Driver information
        driver: {
          windows: config.windowsDriver || 'Generic / Text Only',
          macos: config.macosDriver || 'Generic PostScript Printer',
          linux: config.linuxDriver || 'gutenprint',
          ppd: config.ppdFile || null
        },
        
        // Queue settings
        queue: {
          maxJobs: config.maxQueueJobs || 100,
          priority: config.priority || 50,
          costPerPage: config.costPerPage || 0,
          department: config.department || 'General',
          location: config.location || 'Unknown'
        },
        
        // Access control
        access: {
          allowedUsers: config.allowedUsers || ['all'],
          allowedGroups: config.allowedGroups || ['Domain Users'],
          deniedUsers: config.deniedUsers || [],
          deniedGroups: config.deniedGroups || [],
          requireAuth: config.requireAuth !== false
        },
        
        // Status
        status: 'initializing',
        enabled: true,
        acceptingJobs: true,
        shared: true,
        published: true, // Publish in AD/LDAP
        
        statistics: {
          totalJobs: 0,
          totalPages: 0,
          lastJobTime: null,
          connectedClients: 0
        }
      };
      
      // Configure printer in CUPS
      await this.configureCUPSPrinter(printer);
      
      // Configure Samba share for Windows
      await this.configureSambaPrinter(printer);
      
      // Initialize print queue
      this.queues.set(printer.id, {
        printerId: printer.id,
        jobs: [],
        activeJob: null,
        paused: false
      });
      
      // Store printer configuration
      this.printers.set(printer.id, printer);
      await this.savePrinterConfiguration(printer);
      
      // Update printer status
      printer.status = 'ready';
      
      this.logger.info(`Printer added: ${printer.displayName} at ${printer.serverPath.windows}`);
      
      return {
        success: true,
        printerId: printer.id,
        serverPaths: printer.serverPath,
        message: `Printer successfully added to OpenDirectory Print Server`
      };
      
    } catch (error) {
      this.logger.error('Failed to add printer:', error);
      throw error;
    }
  }
  
  async configureCUPSPrinter(printer) {
    try {
      // Build CUPS URI based on protocol
      let deviceUri;
      switch (printer.protocol) {
        case 'ipp':
          deviceUri = `ipp://${printer.deviceIP}/ipp/print`;
          break;
        case 'lpd':
          deviceUri = `lpd://${printer.deviceIP}/PASSTHROUGH`;
          break;
        case 'raw':
        case 'socket':
          deviceUri = `socket://${printer.deviceIP}:${printer.devicePort}`;
          break;
        default:
          deviceUri = `ipp://${printer.deviceIP}`;
      }
      
      // Add printer to CUPS
      const cupsCommand = `lpadmin -p "${printer.shareName}" \
        -E \
        -v "${deviceUri}" \
        -D "${printer.displayName}" \
        -L "${printer.queue.location}" \
        -o printer-is-shared=true \
        -o auth-info-required=none`;
      
      await execAsync(cupsCommand);
      
      // Set printer options
      if (printer.capabilities.color) {
        await execAsync(`lpadmin -p "${printer.shareName}" -o ColorModel=Color`);
      }
      
      if (printer.capabilities.duplex) {
        await execAsync(`lpadmin -p "${printer.shareName}" -o Duplex=DuplexNoTumble`);
      }
      
      // Set as accepting jobs
      await execAsync(`cupsenable "${printer.shareName}"`);
      await execAsync(`cupsaccept "${printer.shareName}"`);
      
      this.logger.info(`CUPS printer configured: ${printer.shareName}`);
    } catch (error) {
      this.logger.error('Failed to configure CUPS printer:', error);
      throw error;
    }
  }
  
  async configureSambaPrinter(printer) {
    try {
      // Create Samba printer share configuration
      const sambaShare = `
[${printer.shareName}]
  comment = ${printer.displayName}
  path = ${this.spoolDirectory}/queues/${printer.shareName}
  printable = yes
  guest ok = no
  browseable = yes
  create mask = 0700
  print command = /usr/bin/lpr -P '${printer.shareName}' -o raw %s
  lpq command = /usr/bin/lpq -P '${printer.shareName}'
  lprm command = /usr/bin/lprm -P '${printer.shareName}' %j
  lppause command = /usr/bin/lp -i '${printer.shareName}'-%j -H hold
  lpresume command = /usr/bin/lp -i '${printer.shareName}'-%j -H resume
  printer name = ${printer.shareName}
  use client driver = yes
  valid users = @"Domain Users" @admin
`;
      
      // Create spool directory for this printer
      await fs.mkdir(`${this.spoolDirectory}/queues/${printer.shareName}`, { recursive: true });
      
      // Append to Samba configuration
      await fs.appendFile('/etc/samba/opendirectory-print.conf', sambaShare);
      
      // Reload Samba
      await execAsync('smbcontrol all reload-config');
      
      this.logger.info(`Samba share configured: ${printer.shareName}`);
    } catch (error) {
      this.logger.error('Failed to configure Samba printer:', error);
      throw error;
    }
  }
  
  /**
   * Handle print job submission through OpenDirectory
   */
  async submitPrintJob(jobData) {
    try {
      const job = {
        id: crypto.randomBytes(8).toString('hex'),
        printerId: jobData.printerId,
        userId: jobData.userId,
        clientIP: jobData.clientIP,
        documentName: jobData.documentName || 'Untitled',
        
        // Job details
        pages: jobData.pages || 1,
        copies: jobData.copies || 1,
        color: jobData.color || false,
        duplex: jobData.duplex || false,
        
        // Spool file
        spoolFile: null,
        size: 0,
        
        // Status
        status: 'spooling',
        progress: 0,
        
        // Timestamps
        submittedAt: new Date(),
        startedAt: null,
        completedAt: null,
        
        // Priority
        priority: jobData.priority || 50
      };
      
      // Get printer
      const printer = this.printers.get(jobData.printerId);
      if (!printer) {
        throw new Error('Printer not found');
      }
      
      // Check permissions
      if (!await this.checkPrintPermission(printer, jobData.userId)) {
        throw new Error('Access denied');
      }
      
      // Check quota
      if (!await this.checkQuota(jobData.userId, job.pages)) {
        throw new Error('Quota exceeded');
      }
      
      // Spool the job
      const spoolPath = `${this.spoolDirectory}/queues/${printer.shareName}/${job.id}.prn`;
      job.spoolFile = spoolPath;
      
      // Save job data
      if (jobData.data) {
        await fs.writeFile(spoolPath, jobData.data);
        const stats = await fs.stat(spoolPath);
        job.size = stats.size;
      }
      
      // Add to queue
      const queue = this.queues.get(printer.id);
      queue.jobs.push(job);
      
      // Store job
      this.jobs.set(job.id, job);
      
      // Process queue
      this.processQueue(printer.id);
      
      // Update statistics
      printer.statistics.totalJobs++;
      this.stats.totalJobs++;
      
      this.logger.info(`Print job submitted: ${job.id} to ${printer.displayName}`);
      
      return {
        success: true,
        jobId: job.id,
        position: queue.jobs.length,
        estimatedTime: this.estimateCompletionTime(printer.id, job)
      };
      
    } catch (error) {
      this.logger.error('Failed to submit print job:', error);
      throw error;
    }
  }
  
  /**
   * Process print queue for a printer
   */
  async processQueue(printerId) {
    const queue = this.queues.get(printerId);
    const printer = this.printers.get(printerId);
    
    if (!queue || !printer || queue.paused || queue.activeJob) {
      return;
    }
    
    const job = queue.jobs.shift();
    if (!job) {
      return;
    }
    
    try {
      queue.activeJob = job;
      job.status = 'printing';
      job.startedAt = new Date();
      
      // Send to physical printer
      await this.sendToPrinter(printer, job);
      
      // Mark as completed
      job.status = 'completed';
      job.completedAt = new Date();
      job.progress = 100;
      
      // Update statistics
      printer.statistics.totalPages += job.pages * job.copies;
      printer.statistics.lastJobTime = job.completedAt;
      this.stats.completedJobs++;
      
      // Move spool file to completed
      const completedPath = `${this.spoolDirectory}/completed/${job.id}.prn`;
      await fs.rename(job.spoolFile, completedPath);
      
      this.logger.info(`Print job completed: ${job.id}`);
      
    } catch (error) {
      job.status = 'failed';
      job.error = error.message;
      this.stats.failedJobs++;
      
      // Move to failed directory
      const failedPath = `${this.spoolDirectory}/failed/${job.id}.prn`;
      await fs.rename(job.spoolFile, failedPath);
      
      this.logger.error(`Print job failed: ${job.id}`, error);
    } finally {
      queue.activeJob = null;
      
      // Process next job
      setImmediate(() => this.processQueue(printerId));
    }
  }
  
  /**
   * Send job to physical printer
   */
  async sendToPrinter(printer, job) {
    return new Promise((resolve, reject) => {
      if (printer.protocol === 'ipp') {
        // Send via IPP
        const printer_ipp = ipp.Printer(`ipp://${printer.deviceIP}/ipp/print`);
        
        const msg = {
          "operation-attributes-tag": {
            "requesting-user-name": job.userId,
            "job-name": job.documentName,
            "document-format": "application/octet-stream"
          },
          data: fs.createReadStream(job.spoolFile)
        };
        
        printer_ipp.execute("Print-Job", msg, (err, res) => {
          if (err) {
            reject(err);
          } else {
            resolve(res);
          }
        });
        
      } else if (printer.protocol === 'raw' || printer.protocol === 'socket') {
        // Send via RAW socket
        const client = new net.Socket();
        
        client.connect(printer.devicePort, printer.deviceIP, () => {
          const stream = fs.createReadStream(job.spoolFile);
          stream.pipe(client);
          
          stream.on('end', () => {
            client.end();
            resolve();
          });
        });
        
        client.on('error', reject);
        
      } else {
        // Use CUPS lpr command
        execAsync(`lpr -P "${printer.shareName}" "${job.spoolFile}"`)
          .then(resolve)
          .catch(reject);
      }
    });
  }
  
  async checkPrintPermission(printer, userId) {
    // Check user/group permissions
    if (printer.access.deniedUsers.includes(userId)) {
      return false;
    }
    
    if (printer.access.allowedUsers.includes('all') || 
        printer.access.allowedUsers.includes(userId)) {
      return true;
    }
    
    // Check group membership (would integrate with LDAP/AD)
    // For now, return true if auth not required
    return !printer.access.requireAuth;
  }
  
  async checkQuota(userId, pages) {
    // Check user quota (would integrate with quota system)
    // For now, always allow
    return true;
  }
  
  estimateCompletionTime(printerId, job) {
    const queue = this.queues.get(printerId);
    let totalPages = job.pages * job.copies;
    
    for (const queuedJob of queue.jobs) {
      totalPages += queuedJob.pages * queuedJob.copies;
    }
    
    // Estimate 10 pages per minute
    return Math.ceil(totalPages / 10);
  }
  
  async savePrinterConfiguration(printer) {
    const configFile = `${this.configPath}/${printer.id}.json`;
    await fs.writeFile(configFile, JSON.stringify(printer, null, 2));
  }
  
  async loadPrinterConfigurations() {
    try {
      const files = await fs.readdir(this.configPath);
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const config = await fs.readFile(`${this.configPath}/${file}`, 'utf-8');
          const printer = JSON.parse(config);
          
          this.printers.set(printer.id, printer);
          this.queues.set(printer.id, {
            printerId: printer.id,
            jobs: [],
            activeJob: null,
            paused: false
          });
        }
      }
      
      this.logger.info(`Loaded ${this.printers.size} printer configurations`);
    } catch (error) {
      this.logger.error('Failed to load printer configurations:', error);
    }
  }
  
  getServerIP() {
    const interfaces = require('os').networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }
  
  /**
   * Get all managed printers
   */
  async getPrinters() {
    return Array.from(this.printers.values()).map(printer => ({
      id: printer.id,
      name: printer.displayName,
      shareName: printer.shareName,
      serverPaths: printer.serverPath,
      status: printer.status,
      location: printer.queue.location,
      capabilities: printer.capabilities,
      statistics: printer.statistics,
      queueLength: this.queues.get(printer.id)?.jobs.length || 0
    }));
  }
  
  /**
   * Get print queue for a printer
   */
  async getQueue(printerId) {
    const queue = this.queues.get(printerId);
    if (!queue) {
      throw new Error('Printer not found');
    }
    
    return {
      printerId,
      jobs: queue.jobs.map(job => ({
        id: job.id,
        documentName: job.documentName,
        userId: job.userId,
        pages: job.pages,
        status: job.status,
        progress: job.progress,
        submittedAt: job.submittedAt
      })),
      activeJob: queue.activeJob,
      paused: queue.paused
    };
  }
  
  /**
   * Pause/Resume printer
   */
  async setPrinterStatus(printerId, enabled) {
    const printer = this.printers.get(printerId);
    const queue = this.queues.get(printerId);
    
    if (!printer || !queue) {
      throw new Error('Printer not found');
    }
    
    printer.enabled = enabled;
    printer.acceptingJobs = enabled;
    queue.paused = !enabled;
    
    if (enabled) {
      await execAsync(`cupsenable "${printer.shareName}"`);
      await execAsync(`cupsaccept "${printer.shareName}"`);
      
      // Resume queue processing
      this.processQueue(printerId);
    } else {
      await execAsync(`cupsdisable "${printer.shareName}"`);
      await execAsync(`cupsreject "${printer.shareName}"`);
    }
    
    await this.savePrinterConfiguration(printer);
    
    return { success: true, enabled };
  }
  
  /**
   * Delete printer
   */
  async deletePrinter(printerId) {
    const printer = this.printers.get(printerId);
    if (!printer) {
      throw new Error('Printer not found');
    }
    
    // Remove from CUPS
    await execAsync(`lpadmin -x "${printer.shareName}"`);
    
    // Remove from configurations
    this.printers.delete(printerId);
    this.queues.delete(printerId);
    
    // Delete configuration file
    const configFile = `${this.configPath}/${printerId}.json`;
    await fs.unlink(configFile);
    
    // Clean up spool directory
    const spoolDir = `${this.spoolDirectory}/queues/${printer.shareName}`;
    await fs.rmdir(spoolDir, { recursive: true });
    
    this.logger.info(`Printer deleted: ${printer.displayName}`);
    
    return { success: true };
  }
}

module.exports = OpenDirectoryPrintServer;