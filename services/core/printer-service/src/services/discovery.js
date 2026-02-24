const mdns = require('mdns');
const { Client: SNMPClient } = require('snmp-native');
const ssdp = require('node-ssdp').Client;
const net = require('net');
const dgram = require('dgram');
const axios = require('axios');
const winston = require('winston');

class PrinterDiscoveryService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.discoveredPrinters = new Map();
    this.autoDiscoveryInterval = null;
  }

  async discoverPrinters(method = 'all', subnet = null, timeout = 30000) {
    const discoveries = [];
    
    if (method === 'all' || method === 'mdns') {
      discoveries.push(this.discoverMDNS(timeout));
    }
    
    if (method === 'all' || method === 'ssdp') {
      discoveries.push(this.discoverSSDP(timeout));
    }
    
    if (method === 'all' || method === 'snmp') {
      discoveries.push(this.discoverSNMP(subnet || '192.168.1.0/24', timeout));
    }
    
    if (method === 'all' || method === 'ipp') {
      discoveries.push(this.discoverIPP(subnet || '192.168.1.0/24', timeout));
    }
    
    if (method === 'all' || method === 'wsd') {
      discoveries.push(this.discoverWSD(timeout));
    }
    
    const results = await Promise.allSettled(discoveries);
    const printers = [];
    
    results.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        printers.push(...result.value);
      }
    });
    
    // Deduplicate by IP/MAC
    const uniquePrinters = this.deduplicatePrinters(printers);
    
    // Store discovered printers
    uniquePrinters.forEach(printer => {
      this.discoveredPrinters.set(printer.id, printer);
    });
    
    return uniquePrinters;
  }

  async discoverMDNS(timeout) {
    return new Promise((resolve) => {
      const printers = [];
      const browser = mdns.createBrowser(mdns.tcp('ipp'));
      
      const timer = setTimeout(() => {
        browser.stop();
        resolve(printers);
      }, timeout);
      
      browser.on('serviceUp', (service) => {
        const printer = {
          id: `mdns_${service.name}_${service.addresses[0]}`,
          name: service.name,
          model: service.txtRecord?.ty || 'Unknown',
          manufacturer: service.txtRecord?.mfg || 'Unknown',
          address: service.addresses[0],
          port: service.port,
          protocol: 'ipp',
          discoveryMethod: 'mdns',
          capabilities: {
            color: service.txtRecord?.Color === 'T',
            duplex: service.txtRecord?.Duplex === 'T',
            scan: service.txtRecord?.Scan === 'T',
            fax: service.txtRecord?.Fax === 'T'
          },
          supportedFormats: service.txtRecord?.pdl?.split(',') || [],
          uri: `ipp://${service.addresses[0]}:${service.port}/${service.txtRecord?.rp || 'ipp/print'}`,
          raw: service
        };
        
        printers.push(printer);
        this.logger.info(`Discovered printer via mDNS: ${printer.name} at ${printer.address}`);
      });
      
      browser.start();
    });
  }

  async discoverSSDP(timeout) {
    return new Promise((resolve) => {
      const printers = [];
      const client = new ssdp();
      
      const timer = setTimeout(() => {
        resolve(printers);
      }, timeout);
      
      client.on('response', async (headers, statusCode, info) => {
        if (headers.ST && headers.ST.includes('printer')) {
          try {
            // Fetch device description
            const response = await axios.get(headers.LOCATION, { timeout: 5000 });
            const deviceInfo = this.parseUPnPDescription(response.data);
            
            const printer = {
              id: `ssdp_${deviceInfo.serialNumber || info.address}`,
              name: deviceInfo.friendlyName,
              model: deviceInfo.modelName,
              manufacturer: deviceInfo.manufacturer,
              address: info.address,
              port: 9100,
              protocol: 'raw',
              discoveryMethod: 'ssdp',
              capabilities: deviceInfo.capabilities || {},
              uri: headers.LOCATION,
              raw: headers
            };
            
            printers.push(printer);
            this.logger.info(`Discovered printer via SSDP: ${printer.name} at ${printer.address}`);
          } catch (error) {
            this.logger.error('Error fetching SSDP device info:', error);
          }
        }
      });
      
      // Search for printers
      client.search('urn:schemas-upnp-org:device:Printer:1');
      client.search('ssdp:all');
    });
  }

  async discoverSNMP(subnet, timeout) {
    const printers = [];
    const ips = this.generateIPRange(subnet);
    
    const discoveries = ips.map(ip => this.probeSNMP(ip, timeout / ips.length));
    const results = await Promise.allSettled(discoveries);
    
    results.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        printers.push(result.value);
      }
    });
    
    return printers;
  }

  async probeSNMP(ip, timeout) {
    return new Promise((resolve) => {
      const session = new SNMPClient({ host: ip, port: 161, timeout });
      
      // Standard printer MIBs
      const oids = [
        '1.3.6.1.2.1.1.5.0', // sysName
        '1.3.6.1.2.1.1.1.0', // sysDescr
        '1.3.6.1.2.1.25.3.2.1.3.1', // hrDeviceDescr
        '1.3.6.1.2.1.43.5.1.1.16.1', // prtGeneralSerialNumber
        '1.3.6.1.2.1.43.8.2.1.14.1.1' // prtInterpreterDescription
      ];
      
      session.getAll({ oids }, (error, varbinds) => {
        session.close();
        
        if (!error && varbinds && varbinds[0]) {
          const printer = {
            id: `snmp_${ip}`,
            name: varbinds[0]?.value || `Printer-${ip}`,
            model: this.extractModelFromSNMP(varbinds[1]?.value || varbinds[2]?.value),
            manufacturer: this.extractManufacturerFromSNMP(varbinds[1]?.value),
            address: ip,
            port: 9100,
            protocol: 'raw',
            discoveryMethod: 'snmp',
            serialNumber: varbinds[3]?.value,
            capabilities: {},
            raw: varbinds
          };
          
          this.logger.info(`Discovered printer via SNMP: ${printer.name} at ${printer.address}`);
          resolve(printer);
        } else {
          resolve(null);
        }
      });
    });
  }

  async discoverIPP(subnet, timeout) {
    const printers = [];
    const ips = this.generateIPRange(subnet);
    const ports = [631, 9100, 515, 80, 443];
    
    const discoveries = [];
    ips.forEach(ip => {
      ports.forEach(port => {
        discoveries.push(this.probeIPP(ip, port, timeout / (ips.length * ports.length)));
      });
    });
    
    const results = await Promise.allSettled(discoveries);
    
    results.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        printers.push(result.value);
      }
    });
    
    return printers;
  }

  async probeIPP(ip, port, timeout) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      
      socket.setTimeout(timeout);
      socket.on('connect', async () => {
        socket.destroy();
        
        try {
          // Try IPP get-printer-attributes
          const response = await axios.post(
            `http://${ip}:${port}/ipp/print`,
            this.buildIPPRequest(),
            {
              headers: { 'Content-Type': 'application/ipp' },
              timeout: 5000,
              responseType: 'arraybuffer'
            }
          );
          
          const attributes = this.parseIPPResponse(response.data);
          
          const printer = {
            id: `ipp_${ip}_${port}`,
            name: attributes['printer-name'] || `IPP-Printer-${ip}`,
            model: attributes['printer-make-and-model'],
            manufacturer: this.extractManufacturerFromModel(attributes['printer-make-and-model']),
            address: ip,
            port,
            protocol: 'ipp',
            discoveryMethod: 'ipp',
            capabilities: {
              color: attributes['color-supported'],
              duplex: attributes['sides-supported']?.includes('two-sided'),
              copies: attributes['copies-supported']
            },
            supportedFormats: attributes['document-format-supported'],
            uri: `ipp://${ip}:${port}/ipp/print`,
            raw: attributes
          };
          
          this.logger.info(`Discovered printer via IPP: ${printer.name} at ${printer.address}:${printer.port}`);
          resolve(printer);
        } catch (error) {
          resolve(null);
        }
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve(null);
      });
      
      socket.on('error', () => {
        resolve(null);
      });
      
      socket.connect(port, ip);
    });
  }

  async discoverWSD(timeout) {
    return new Promise((resolve) => {
      const printers = [];
      const MULTICAST_ADDR = '239.255.255.250';
      const WSD_PORT = 3702;
      
      const socket = dgram.createSocket('udp4');
      
      const probeMessage = this.buildWSDProbe();
      
      socket.on('message', (msg, rinfo) => {
        try {
          const printer = this.parseWSDResponse(msg.toString(), rinfo.address);
          if (printer) {
            printers.push(printer);
            this.logger.info(`Discovered printer via WS-Discovery: ${printer.name} at ${printer.address}`);
          }
        } catch (error) {
          this.logger.error('Error parsing WSD response:', error);
        }
      });
      
      socket.bind(() => {
        socket.setBroadcast(true);
        socket.setMulticastTTL(128);
        socket.addMembership(MULTICAST_ADDR);
        
        socket.send(probeMessage, WSD_PORT, MULTICAST_ADDR);
        
        setTimeout(() => {
          socket.close();
          resolve(printers);
        }, timeout);
      });
    });
  }

  startAutoDiscovery(interval = 300000) {
    this.logger.info('Starting automatic printer discovery');
    
    // Initial discovery
    this.discoverPrinters('all').catch(err => 
      this.logger.error('Auto-discovery error:', err)
    );
    
    // Periodic discovery
    this.autoDiscoveryInterval = setInterval(() => {
      this.discoverPrinters('all').catch(err => 
        this.logger.error('Auto-discovery error:', err)
      );
    }, interval);
  }

  stopAutoDiscovery() {
    if (this.autoDiscoveryInterval) {
      clearInterval(this.autoDiscoveryInterval);
      this.autoDiscoveryInterval = null;
      this.logger.info('Stopped automatic printer discovery');
    }
  }

  deduplicatePrinters(printers) {
    const unique = new Map();
    
    printers.forEach(printer => {
      const key = `${printer.address}_${printer.port || ''}`;
      if (!unique.has(key) || printer.discoveryMethod === 'mdns') {
        unique.set(key, printer);
      }
    });
    
    return Array.from(unique.values());
  }

  generateIPRange(subnet) {
    const ips = [];
    const [base, mask] = subnet.split('/');
    const baseParts = base.split('.').map(Number);
    
    if (mask === '24') {
      for (let i = 1; i < 255; i++) {
        ips.push(`${baseParts[0]}.${baseParts[1]}.${baseParts[2]}.${i}`);
      }
    }
    
    return ips;
  }

  buildIPPRequest() {
    // Simplified IPP request for get-printer-attributes
    const request = Buffer.alloc(256);
    let offset = 0;
    
    // Version
    request.writeInt8(1, offset++);
    request.writeInt8(1, offset++);
    
    // Operation
    request.writeInt16BE(0x000B, offset); // Get-Printer-Attributes
    offset += 2;
    
    // Request ID
    request.writeInt32BE(1, offset);
    offset += 4;
    
    // Operation attributes tag
    request.writeInt8(0x01, offset++);
    
    return request.slice(0, offset);
  }

  parseIPPResponse(data) {
    // Simplified IPP response parser
    const attributes = {};
    
    try {
      // Parse IPP binary response
      let offset = 8; // Skip header
      
      while (offset < data.length) {
        const tag = data[offset++];
        if (tag === 0x03) break; // End tag
        
        const nameLength = data.readInt16BE(offset);
        offset += 2;
        
        const name = data.slice(offset, offset + nameLength).toString();
        offset += nameLength;
        
        const valueLength = data.readInt16BE(offset);
        offset += 2;
        
        const value = data.slice(offset, offset + valueLength);
        offset += valueLength;
        
        attributes[name] = value.toString();
      }
    } catch (error) {
      this.logger.error('Error parsing IPP response:', error);
    }
    
    return attributes;
  }

  buildWSDProbe() {
    return Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:${this.generateUUID()}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>wsdp:PrintDeviceType</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>`);
  }

  parseWSDResponse(xml, address) {
    // Simplified WSD response parser
    try {
      const name = xml.match(/<wsd:XAddrs>(.*?)<\/wsd:XAddrs>/)?.[1] || `WSD-Printer-${address}`;
      
      return {
        id: `wsd_${address}`,
        name,
        address,
        port: 80,
        protocol: 'wsd',
        discoveryMethod: 'wsd',
        capabilities: {},
        raw: xml
      };
    } catch (error) {
      return null;
    }
  }

  parseUPnPDescription(xml) {
    // Parse UPnP device description XML
    const info = {
      friendlyName: xml.match(/<friendlyName>(.*?)<\/friendlyName>/)?.[1],
      manufacturer: xml.match(/<manufacturer>(.*?)<\/manufacturer>/)?.[1],
      modelName: xml.match(/<modelName>(.*?)<\/modelName>/)?.[1],
      serialNumber: xml.match(/<serialNumber>(.*?)<\/serialNumber>/)?.[1],
      capabilities: {}
    };
    
    return info;
  }

  extractModelFromSNMP(description) {
    // Extract model from SNMP description
    const patterns = [
      /Model:\s*(.+)/i,
      /^([A-Za-z0-9\-]+\s+[A-Za-z0-9\-]+)/,
      /(.+)/
    ];
    
    for (const pattern of patterns) {
      const match = description?.match(pattern);
      if (match) return match[1].trim();
    }
    
    return 'Unknown Model';
  }

  extractManufacturerFromSNMP(description) {
    const manufacturers = ['HP', 'Canon', 'Epson', 'Brother', 'Xerox', 'Lexmark', 'Samsung', 'Ricoh', 'Kyocera'];
    
    for (const mfg of manufacturers) {
      if (description?.toLowerCase().includes(mfg.toLowerCase())) {
        return mfg;
      }
    }
    
    return 'Unknown';
  }

  extractManufacturerFromModel(model) {
    if (!model) return 'Unknown';
    
    const firstWord = model.split(' ')[0];
    return firstWord || 'Unknown';
  }

  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

module.exports = PrinterDiscoveryService;