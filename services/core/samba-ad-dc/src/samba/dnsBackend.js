'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const winston = require('winston');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const SAMBA_TOOL = '/usr/bin/samba-tool';
const DNS_SERVER = process.env.SAMBA_DNS_SERVER || 'localhost';

/**
 * Validate a DNS record type.
 */
function validateRecordType(type) {
  const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'SOA'];
  if (!validTypes.includes(type.toUpperCase())) {
    throw new Error(`Invalid DNS record type: ${type}. Must be one of: ${validTypes.join(', ')}`);
  }
}

/**
 * Validate a DNS zone name.
 */
function validateZoneName(zone) {
  if (!zone || typeof zone !== 'string') {
    throw new Error('Zone name is required');
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(zone)) {
    throw new Error('Invalid zone name format');
  }
}

/**
 * Validate a DNS record name.
 */
function validateRecordName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('Record name is required');
  }
  if (!/^[a-zA-Z0-9._@*-]+$/.test(name)) {
    throw new Error('Invalid record name format');
  }
}

/**
 * List all DNS zones managed by Samba.
 *
 * @returns {Promise<object>} DNS zones
 */
async function getZones() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, [
      'dns', 'zonelist', DNS_SERVER, '--username=administrator'
    ], { timeout: 30000 });

    const zones = [];
    const lines = stdout.split('\n').filter(l => l.trim());
    let currentZone = null;

    for (const line of lines) {
      const nameMatch = line.match(/pszZoneName\s*:\s*(.+)/);
      const typeMatch = line.match(/dwZoneType\s*:\s*(.+)/);
      const flagsMatch = line.match(/fReverse\s*:\s*(.+)/);

      if (nameMatch) {
        if (currentZone) zones.push(currentZone);
        currentZone = { name: nameMatch[1].trim() };
      } else if (currentZone && typeMatch) {
        currentZone.type = typeMatch[1].trim();
      } else if (currentZone && flagsMatch) {
        currentZone.isReverse = flagsMatch[1].trim().toUpperCase() === 'TRUE';
      }
    }
    if (currentZone) zones.push(currentZone);

    return {
      zones,
      total: zones.length,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error listing DNS zones', { error: err.message });
    throw new Error(`Failed to list DNS zones: ${err.message}`);
  }
}

/**
 * Get DNS records for a specific zone.
 *
 * @param {string} zone - DNS zone name
 * @returns {Promise<object>} DNS records
 */
async function getRecords(zone) {
  validateZoneName(zone);

  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, [
      'dns', 'query', DNS_SERVER, zone, '@', 'ALL',
      '--username=administrator'
    ], { timeout: 30000 });

    const records = parseRecordOutput(stdout, zone);

    return {
      zone,
      records,
      total: records.length,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error listing DNS records', { zone, error: err.message });
    throw new Error(`Failed to list DNS records for zone ${zone}: ${err.message}`);
  }
}

/**
 * Parse samba-tool dns query output into structured records.
 */
function parseRecordOutput(output, zone) {
  const records = [];
  const lines = output.split('\n').filter(l => l.trim());
  let currentName = null;

  for (const line of lines) {
    const nameMatch = line.match(/^\s*Name=([^,]+)/);
    if (nameMatch) {
      currentName = nameMatch[1].trim();
      continue;
    }

    if (!currentName) continue;

    // Parse A records
    const aMatch = line.match(/A:\s*([\d.]+)/);
    if (aMatch) {
      records.push({ name: currentName, type: 'A', data: aMatch[1], zone });
      continue;
    }

    // Parse AAAA records
    const aaaaMatch = line.match(/AAAA:\s*([a-fA-F0-9:]+)/);
    if (aaaaMatch) {
      records.push({ name: currentName, type: 'AAAA', data: aaaaMatch[1], zone });
      continue;
    }

    // Parse CNAME records
    const cnameMatch = line.match(/CNAME:\s*(.+)/);
    if (cnameMatch) {
      records.push({ name: currentName, type: 'CNAME', data: cnameMatch[1].trim(), zone });
      continue;
    }

    // Parse NS records
    const nsMatch = line.match(/NS:\s*(.+)/);
    if (nsMatch) {
      records.push({ name: currentName, type: 'NS', data: nsMatch[1].trim(), zone });
      continue;
    }

    // Parse SRV records
    const srvMatch = line.match(/SRV:\s*priority=(\d+),\s*weight=(\d+),\s*port=(\d+),\s*(.+)/);
    if (srvMatch) {
      records.push({
        name: currentName,
        type: 'SRV',
        data: { priority: parseInt(srvMatch[1]), weight: parseInt(srvMatch[2]), port: parseInt(srvMatch[3]), target: srvMatch[4].trim() },
        zone
      });
      continue;
    }

    // Parse MX records
    const mxMatch = line.match(/MX:\s*priority=(\d+),\s*(.+)/);
    if (mxMatch) {
      records.push({
        name: currentName,
        type: 'MX',
        data: { priority: parseInt(mxMatch[1]), exchange: mxMatch[2].trim() },
        zone
      });
      continue;
    }

    // Parse TXT records
    const txtMatch = line.match(/TXT:\s*(.+)/);
    if (txtMatch) {
      records.push({ name: currentName, type: 'TXT', data: txtMatch[1].trim(), zone });
    }
  }

  return records;
}

/**
 * Add a DNS record to a zone.
 *
 * @param {string} zone - DNS zone
 * @param {string} name - Record name
 * @param {string} type - Record type (A, AAAA, CNAME, MX, NS, PTR, SRV, TXT)
 * @param {string} data - Record data
 * @param {number} ttl - TTL in seconds (optional)
 * @returns {Promise<object>} Creation result
 */
async function addRecord(zone, name, type, data, ttl) {
  validateZoneName(zone);
  validateRecordName(name);
  validateRecordType(type);

  if (!data || typeof data !== 'string') {
    throw new Error('Record data is required');
  }

  const args = [
    'dns', 'add', DNS_SERVER, zone, name, type.toUpperCase(), data,
    '--username=administrator'
  ];

  logger.info('Adding DNS record', { zone, name, type, data });

  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, args, { timeout: 30000 });

    return {
      success: true,
      zone,
      name,
      type: type.toUpperCase(),
      data,
      ttl: ttl || null,
      createdAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error adding DNS record', { zone, name, type, error: err.message });
    throw new Error(`Failed to add DNS record: ${err.message}`);
  }
}

/**
 * Delete a DNS record from a zone.
 *
 * @param {string} zone - DNS zone
 * @param {string} name - Record name
 * @param {string} type - Record type
 * @param {string} data - Record data (required to identify exact record)
 * @returns {Promise<object>} Deletion result
 */
async function deleteRecord(zone, name, type, data) {
  validateZoneName(zone);
  validateRecordName(name);
  validateRecordType(type);

  if (!data || typeof data !== 'string') {
    throw new Error('Record data is required to identify the record');
  }

  const args = [
    'dns', 'delete', DNS_SERVER, zone, name, type.toUpperCase(), data,
    '--username=administrator'
  ];

  logger.info('Deleting DNS record', { zone, name, type, data });

  try {
    await execFileAsync(SAMBA_TOOL, args, { timeout: 30000 });

    return {
      success: true,
      zone,
      name,
      type: type.toUpperCase(),
      deletedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error deleting DNS record', { zone, name, type, error: err.message });
    throw new Error(`Failed to delete DNS record: ${err.message}`);
  }
}

/**
 * Get DNS forwarders configuration.
 *
 * @returns {Promise<object>} Forwarders
 */
async function getForwarders() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, [
      'dns', 'query', DNS_SERVER, '.', '@', 'ALL',
      '--username=administrator'
    ], { timeout: 30000 });

    // Parse forwarders from samba configuration
    const fs = require('fs').promises;
    let forwarders = [];

    try {
      const smbConf = await fs.readFile('/etc/samba/smb.conf', 'utf-8');
      const forwarderMatch = smbConf.match(/dns forwarder\s*=\s*(.+)/i);
      if (forwarderMatch) {
        forwarders = forwarderMatch[1].trim().split(/\s+/);
      }
    } catch {
      // smb.conf not readable
    }

    return {
      forwarders,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error getting DNS forwarders', { error: err.message });
    throw new Error(`Failed to get DNS forwarders: ${err.message}`);
  }
}

/**
 * Configure DNS forwarders.
 *
 * @param {string[]} forwarders - Array of DNS forwarder IP addresses
 * @returns {Promise<object>} Configuration result
 */
async function setForwarders(forwarders) {
  if (!Array.isArray(forwarders) || forwarders.length === 0) {
    throw new Error('At least one forwarder IP address is required');
  }

  // Validate IP addresses
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  for (const ip of forwarders) {
    if (!ipRegex.test(ip)) {
      throw new Error(`Invalid IP address: ${ip}`);
    }
  }

  const forwarderStr = forwarders.join(' ');

  logger.info('Setting DNS forwarders', { forwarders });

  try {
    // Update smb.conf with new forwarder setting
    const fs = require('fs').promises;
    let smbConf = await fs.readFile('/etc/samba/smb.conf', 'utf-8');

    if (smbConf.includes('dns forwarder')) {
      smbConf = smbConf.replace(/dns forwarder\s*=\s*.+/i, `dns forwarder = ${forwarderStr}`);
    } else {
      // Add after [global] section
      smbConf = smbConf.replace(/\[global\]/i, `[global]\n\tdns forwarder = ${forwarderStr}`);
    }

    await fs.writeFile('/etc/samba/smb.conf', smbConf, 'utf-8');

    // Reload Samba configuration
    await execFileAsync('/usr/bin/smbcontrol', ['all', 'reload-config'], { timeout: 15000 });

    return {
      success: true,
      forwarders,
      updatedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error setting DNS forwarders', { forwarders, error: err.message });
    throw new Error(`Failed to set DNS forwarders: ${err.message}`);
  }
}

module.exports = {
  getZones,
  getRecords,
  addRecord,
  deleteRecord,
  getForwarders,
  setForwarders
};
