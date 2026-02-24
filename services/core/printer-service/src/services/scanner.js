const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class ScannerService extends EventEmitter {
  constructor() {
    super();
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.scanners = new Map();
    this.activeScans = new Map();
  }

  async listScanners() {
    try {
      // Use SANE to list scanners
      const output = await this.execCommand('scanimage', ['-L']);
      return this.parseScannerList(output);
    } catch (error) {
      this.logger.error('List scanners error:', error);
      
      // Return cached scanners if available
      return Array.from(this.scanners.values());
    }
  }

  async discoverScanners() {
    try {
      // Network scanner discovery
      const scanners = [];
      
      // Try SANE network discovery
      const saneOutput = await this.execCommand('sane-find-scanner', ['-q']);
      const saneScanners = this.parseSaneOutput(saneOutput);
      scanners.push(...saneScanners);
      
      // Try WSD scanner discovery
      const wsdScanners = await this.discoverWSDScanners();
      scanners.push(...wsdScanners);
      
      // Try eSCL/AirScan discovery
      const esclScanners = await this.discoverESCLScanners();
      scanners.push(...esclScanners);
      
      // Update scanner cache
      scanners.forEach(scanner => {
        this.scanners.set(scanner.id, scanner);
      });
      
      return scanners;
    } catch (error) {
      this.logger.error('Discover scanners error:', error);
      return [];
    }
  }

  async scan(options) {
    const scanId = uuidv4();
    const {
      scannerId,
      userId,
      format = 'pdf',
      resolution = 300,
      color = true,
      duplex = false,
      pageSize = 'A4',
      destination,
      ocr = false
    } = options;
    
    try {
      this.activeScans.set(scanId, {
        id: scanId,
        status: 'preparing',
        progress: 0,
        userId,
        startTime: Date.now()
      });
      
      this.updateScanProgress(scanId, 10, 'scanning');
      
      // Perform scan using scanimage
      const scanFile = await this.performScan(scannerId, {
        format: format === 'pdf' ? 'tiff' : format,
        resolution,
        color,
        duplex,
        pageSize
      });
      
      this.updateScanProgress(scanId, 50, 'processing');
      
      // Convert to requested format if needed
      let finalFile = scanFile;
      if (format === 'pdf') {
        finalFile = await this.convertToPDF(scanFile);
      }
      
      this.updateScanProgress(scanId, 70, 'ocr');
      
      // Perform OCR if requested
      if (ocr) {
        finalFile = await this.performOCR(finalFile);
      }
      
      this.updateScanProgress(scanId, 90, 'saving');
      
      // Save to destination
      const savedFile = await this.saveScannedFile(finalFile, destination, userId);
      
      this.updateScanProgress(scanId, 100, 'completed');
      
      const result = {
        id: scanId,
        status: 'completed',
        file: savedFile,
        format,
        pages: 1, // Would be determined from actual scan
        size: (await fs.stat(savedFile)).size,
        timestamp: new Date().toISOString()
      };
      
      this.activeScans.delete(scanId);
      this.emit('scan:completed', result);
      
      return result;
    } catch (error) {
      this.logger.error(`Scan ${scanId} failed:`, error);
      
      this.updateScanProgress(scanId, 0, 'failed', error.message);
      this.activeScans.delete(scanId);
      
      throw error;
    }
  }

  async performScan(scannerId, options) {
    const tempFile = `/tmp/scan_${Date.now()}.${options.format}`;
    
    const args = [
      '--device-name', scannerId,
      '--resolution', options.resolution,
      '--format', options.format
    ];
    
    if (options.color) {
      args.push('--mode', 'Color');
    } else {
      args.push('--mode', 'Gray');
    }
    
    if (options.pageSize) {
      const sizes = {
        'A4': { x: 210, y: 297 },
        'Letter': { x: 216, y: 279 },
        'Legal': { x: 216, y: 356 },
        'A3': { x: 297, y: 420 }
      };
      
      if (sizes[options.pageSize]) {
        args.push('-x', sizes[options.pageSize].x);
        args.push('-y', sizes[options.pageSize].y);
      }
    }
    
    args.push('>', tempFile);
    
    await this.execCommand('scanimage', args);
    
    return tempFile;
  }

  async convertToPDF(inputFile) {
    const outputFile = inputFile.replace(/\.[^.]+$/, '.pdf');
    
    // Use ImageMagick or similar to convert to PDF
    await this.execCommand('convert', [inputFile, outputFile]);
    
    // Clean up temp file
    await fs.unlink(inputFile).catch(() => {});
    
    return outputFile;
  }

  async performOCR(inputFile) {
    const outputFile = inputFile.replace(/\.pdf$/, '_ocr.pdf');
    
    // Use Tesseract OCR
    await this.execCommand('tesseract', [
      inputFile,
      outputFile.replace('.pdf', ''),
      'pdf'
    ]);
    
    // Clean up original file
    await fs.unlink(inputFile).catch(() => {});
    
    return outputFile;
  }

  async saveScannedFile(file, destination, userId) {
    let finalPath;
    
    if (destination) {
      if (destination.type === 'local') {
        finalPath = destination.path;
      } else if (destination.type === 'cloud') {
        // Upload to cloud storage
        finalPath = await this.uploadToCloud(file, destination);
      } else if (destination.type === 'email') {
        // Send via email
        await this.sendViaEmail(file, destination.email, userId);
        finalPath = file;
      }
    } else {
      // Default location
      const scanDir = `/var/scans/${userId}`;
      await fs.mkdir(scanDir, { recursive: true });
      
      const filename = `scan_${Date.now()}${path.extname(file)}`;
      finalPath = path.join(scanDir, filename);
    }
    
    if (finalPath !== file) {
      await fs.copyFile(file, finalPath);
      await fs.unlink(file).catch(() => {});
    }
    
    return finalPath;
  }

  async discoverWSDScanners() {
    // WS-Discovery for scanners
    const scanners = [];
    
    // Implementation would use WS-Discovery protocol
    // Similar to printer discovery but for scanner services
    
    return scanners;
  }

  async discoverESCLScanners() {
    // eSCL/AirScan discovery via mDNS
    const scanners = [];
    
    try {
      const mdns = require('mdns');
      const browser = mdns.createBrowser(mdns.tcp('uscan'));
      
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          browser.stop();
          resolve(scanners);
        }, 5000);
        
        browser.on('serviceUp', (service) => {
          scanners.push({
            id: `escl_${service.name}`,
            name: service.name,
            type: 'escl',
            address: service.addresses[0],
            port: service.port,
            capabilities: {
              color: true,
              duplex: service.txtRecord?.duplex === 'T',
              adf: service.txtRecord?.adf === 'T'
            }
          });
        });
        
        browser.start();
      });
    } catch (error) {
      this.logger.warn('eSCL discovery error:', error);
      return scanners;
    }
  }

  async getScannerCapabilities(scannerId) {
    try {
      const output = await this.execCommand('scanimage', [
        '--device-name', scannerId,
        '--help'
      ]);
      
      return this.parseScannerCapabilities(output);
    } catch (error) {
      this.logger.error('Get capabilities error:', error);
      
      // Return default capabilities
      return {
        resolutions: [75, 150, 300, 600, 1200],
        modes: ['Color', 'Gray', 'Lineart'],
        sources: ['Flatbed', 'ADF'],
        formats: ['jpeg', 'png', 'tiff', 'pdf']
      };
    }
  }

  async calibrateScanner(scannerId) {
    try {
      await this.execCommand('scanimage', [
        '--device-name', scannerId,
        '--calibrate'
      ]);
      
      return { success: true, message: 'Scanner calibrated successfully' };
    } catch (error) {
      this.logger.error('Calibrate error:', error);
      throw error;
    }
  }

  async getScanStatus(scanId) {
    const scan = this.activeScans.get(scanId);
    
    if (!scan) {
      throw new Error('Scan not found');
    }
    
    return scan;
  }

  async cancelScan(scanId) {
    const scan = this.activeScans.get(scanId);
    
    if (!scan) {
      throw new Error('Scan not found');
    }
    
    // Would need to track and kill the actual scan process
    scan.status = 'cancelled';
    this.activeScans.delete(scanId);
    
    this.emit('scan:cancelled', scanId);
    
    return true;
  }

  updateScanProgress(scanId, progress, status, message = null) {
    const scan = this.activeScans.get(scanId);
    
    if (scan) {
      scan.progress = progress;
      scan.status = status;
      
      if (message) {
        scan.message = message;
      }
      
      this.emit('scan:progress', {
        scanId,
        progress,
        status,
        message
      });
    }
  }

  parseScannerList(output) {
    const scanners = [];
    const lines = output.split('\n');
    
    lines.forEach(line => {
      const match = line.match(/device `([^']+)' is a (.+)/);
      if (match) {
        scanners.push({
          id: match[1],
          name: match[2],
          type: this.detectScannerType(match[1]),
          available: true
        });
      }
    });
    
    return scanners;
  }

  parseSaneOutput(output) {
    const scanners = [];
    const lines = output.split('\n');
    
    lines.forEach(line => {
      if (line.includes('found')) {
        const parts = line.split(' ');
        scanners.push({
          id: `sane_${parts[1]}`,
          name: parts.slice(2).join(' '),
          type: 'sane',
          available: true
        });
      }
    });
    
    return scanners;
  }

  parseScannerCapabilities(output) {
    const capabilities = {
      resolutions: [],
      modes: [],
      sources: [],
      formats: []
    };
    
    const lines = output.split('\n');
    
    lines.forEach(line => {
      if (line.includes('--resolution')) {
        const match = line.match(/\d+/g);
        if (match) {
          capabilities.resolutions = match.map(Number);
        }
      } else if (line.includes('--mode')) {
        const match = line.match(/\[(.*?)\]/);
        if (match) {
          capabilities.modes = match[1].split('|');
        }
      } else if (line.includes('--source')) {
        const match = line.match(/\[(.*?)\]/);
        if (match) {
          capabilities.sources = match[1].split('|');
        }
      }
    });
    
    // Default formats based on SANE capabilities
    capabilities.formats = ['jpeg', 'png', 'tiff', 'pdf'];
    
    return capabilities;
  }

  detectScannerType(deviceId) {
    if (deviceId.includes('net')) return 'network';
    if (deviceId.includes('usb')) return 'usb';
    if (deviceId.includes('escl')) return 'escl';
    if (deviceId.includes('wsd')) return 'wsd';
    return 'local';
  }

  async uploadToCloud(file, destination) {
    // Implementation would depend on cloud provider
    // This is a placeholder
    this.logger.info(`Would upload ${file} to ${destination.provider}`);
    return file;
  }

  async sendViaEmail(file, email, userId) {
    // Implementation would use email service
    this.logger.info(`Would email ${file} to ${email} for user ${userId}`);
    return true;
  }

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
}

module.exports = ScannerService;