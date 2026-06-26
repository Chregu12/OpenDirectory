'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const STATUS_FILE = '/var/lib/samba/.opendirectory-status';
const PROVISION_SCRIPT = path.resolve(__dirname, '../../scripts/provision-domain.sh');
const SAMBA_TOOL = '/usr/bin/samba-tool';

/**
 * Validates realm format (uppercase FQDN).
 */
function validateRealm(realm) {
  if (!realm || !/^[A-Z][A-Z0-9.-]+\.[A-Z]{2,}$/.test(realm)) {
    throw new Error('Invalid realm format. Must be uppercase FQDN (e.g., OPENDIRECTORY.LOCAL)');
  }
}

/**
 * Validates NetBIOS domain name.
 */
function validateDomain(domain) {
  if (!domain || !/^[A-Z][A-Z0-9]{0,14}$/.test(domain)) {
    throw new Error('Invalid domain name. Must be uppercase NetBIOS name, max 15 characters');
  }
}

/**
 * Validates DNS backend type.
 */
function validateDnsBackend(backend) {
  const valid = ['SAMBA_INTERNAL', 'BIND9_DLZ', 'BIND9_FLATFILE'];
  if (!valid.includes(backend)) {
    throw new Error(`DNS backend must be one of: ${valid.join(', ')}`);
  }
}

/**
 * Validates AD functional level.
 */
function validateFunctionLevel(level) {
  const valid = ['2000', '2003', '2008', '2008_R2', '2012', '2012_R2', '2016'];
  if (!valid.includes(level)) {
    throw new Error(`Function level must be one of: ${valid.join(', ')}`);
  }
}

/**
 * Validates password complexity.
 */
function validatePassword(password) {
  if (!password || password.length < 8) {
    throw new Error('Admin password must be at least 8 characters');
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    throw new Error('Admin password must contain uppercase, lowercase, and numeric characters');
  }
}

/**
 * Provision a new Samba AD DC domain.
 *
 * @param {string} realm          - Kerberos realm (e.g., OPENDIRECTORY.LOCAL)
 * @param {string} domain         - NetBIOS domain name (e.g., OPENDIRECTORY)
 * @param {string} adminPassword  - Administrator password
 * @param {string} dnsBackend     - DNS backend
 * @param {object} opts           - Optional advanced parameters
 * @param {string} opts.dcHostname     - DC hostname (defaults to system hostname)
 * @param {string} opts.dcIp           - DC IP address
 * @param {string} opts.functionLevel  - AD functional level (default: 2008_R2)
 * @param {string} opts.dnsInterface   - Space-separated DNS interfaces (default: "lo eth0")
 * @param {string} opts.dnsForwarders  - Space-separated DNS forwarders (default: "8.8.8.8 8.8.4.4")
 * @param {boolean} opts.enableLdaps   - Enable LDAPS (default: true)
 * @param {boolean} opts.enableRfc2307 - Enable RFC2307 Unix attributes (default: true)
 * @param {string} opts.serverRole     - Server role: dc, rodc, standalone (default: dc)
 * @returns {Promise<object>} Provisioning result
 */
async function provisionDomain(realm, domain, adminPassword, dnsBackend = 'SAMBA_INTERNAL', opts = {}) {
  validateRealm(realm);
  validateDomain(domain);
  validatePassword(adminPassword);
  validateDnsBackend(dnsBackend);

  const functionLevel = opts.functionLevel || '2008_R2';
  validateFunctionLevel(functionLevel);

  const dcHostname    = opts.dcHostname    || '';
  const dcIp          = opts.dcIp          || '';
  const dnsInterface  = opts.dnsInterface  || 'lo eth0';
  const dnsForwarders = opts.dnsForwarders || '8.8.8.8 8.8.4.4';
  const enableLdaps   = opts.enableLdaps   !== false ? 'true' : 'false';
  const enableRfc2307 = opts.enableRfc2307 !== false ? 'true' : 'false';
  const serverRole    = opts.serverRole    || 'dc';

  // Check if already provisioned
  const status = await getDomainStatus();
  if (status.provisioned) {
    throw new Error(`Domain already provisioned: ${status.realm}. De-provision first to re-provision.`);
  }

  logger.info('Starting domain provisioning', { realm, domain, dnsBackend, functionLevel });

  try {
    const { stdout, stderr } = await execFileAsync(PROVISION_SCRIPT, [
      realm,        // $1
      domain,       // $2
      adminPassword,// $3
      dnsBackend,   // $4
      dcHostname,   // $5  (empty → script uses hostname -s)
      dcIp,         // $6  (empty → samba-tool picks automatically)
      functionLevel,// $7
      dnsInterface, // $8
      dnsForwarders,// $9
      enableLdaps,  // $10
      enableRfc2307,// $11
      serverRole    // $12
    ], {
      timeout: 300000,
      env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' }
    });

    logger.info('Domain provisioning completed', { realm, domain });

    return {
      success: true,
      realm,
      domain,
      dnsBackend,
      functionLevel,
      dcHostname: dcHostname || undefined,
      dcIp: dcIp || undefined,
      enableLdaps: enableLdaps === 'true',
      enableRfc2307: enableRfc2307 === 'true',
      serverRole,
      provisionedAt: new Date().toISOString(),
      output: stdout,
      warnings: stderr || null
    };
  } catch (err) {
    logger.error('Domain provisioning failed', { realm, domain, error: err.message });
    throw new Error(`Provisioning failed: ${err.message}`);
  }
}

/**
 * Get current domain provisioning status.
 *
 * @returns {Promise<object>} Domain status
 */
async function getDomainStatus() {
  try {
    const content = await fs.readFile(STATUS_FILE, 'utf-8');
    const status = JSON.parse(content);
    return status;
  } catch (err) {
    if (err.code === 'ENOENT') {
      return {
        provisioned: false,
        realm: null,
        domain: null,
        message: 'Domain not yet provisioned'
      };
    }
    logger.error('Error reading domain status', { error: err.message });
    return {
      provisioned: false,
      error: err.message
    };
  }
}

/**
 * Get forest information including functional levels and domain details.
 *
 * @returns {Promise<object>} Forest info
 */
async function getForestInfo() {
  const status = await getDomainStatus();
  if (!status.provisioned) {
    return { provisioned: false, message: 'Domain not provisioned' };
  }

  try {
    const [domainLevel, forestDns] = await Promise.all([
      execFileAsync(SAMBA_TOOL, ['domain', 'level', 'show'], { timeout: 30000 }),
      execFileAsync(SAMBA_TOOL, ['domain', 'info', '127.0.0.1'], { timeout: 30000 }).catch(() => null)
    ]);

    const levelOutput = domainLevel.stdout;
    const levels = {};

    const domainMatch = levelOutput.match(/Domain function level:\s*(.+)/);
    const forestMatch = levelOutput.match(/Forest function level:\s*(.+)/);
    const dcMatch = levelOutput.match(/Lowest function level of a DC:\s*(.+)/);

    if (domainMatch) levels.domainFunctionLevel = domainMatch[1].trim();
    if (forestMatch) levels.forestFunctionLevel = forestMatch[1].trim();
    if (dcMatch) levels.lowestDCLevel = dcMatch[1].trim();

    const result = {
      provisioned: true,
      realm: status.realm,
      domain: status.domain,
      levels,
      provisionedAt: status.provisionedAt
    };

    if (forestDns) {
      const dcMatch2 = forestDns.stdout.match(/DC name:\s*(.+)/);
      const dcIpMatch = forestDns.stdout.match(/DC netbios name:\s*(.+)/);
      if (dcMatch2) result.dcName = dcMatch2[1].trim();
      if (dcIpMatch) result.dcNetbiosName = dcIpMatch[1].trim();
    }

    return result;
  } catch (err) {
    logger.error('Error getting forest info', { error: err.message });
    throw new Error(`Failed to retrieve forest info: ${err.message}`);
  }
}

/**
 * Get FSMO role holders for the domain.
 *
 * @returns {Promise<object>} FSMO role information
 */
async function getFSMORoles() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, ['fsmo', 'show'], { timeout: 30000 });
    const roles = {};
    const lines = stdout.split('\n').filter(l => l.trim());

    for (const line of lines) {
      const [roleName, holder] = line.split(/\s*owner:\s*/i);
      if (roleName && holder) {
        const key = roleName.trim()
          .replace(/\s+/g, '_')
          .replace(/Master$/i, '')
          .toLowerCase()
          .replace(/_$/, '');
        roles[key] = holder.trim();
      }
    }

    return {
      roles,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error getting FSMO roles', { error: err.message });
    throw new Error(`Failed to retrieve FSMO roles: ${err.message}`);
  }
}

module.exports = {
  provisionDomain,
  getDomainStatus,
  getForestInfo,
  getFSMORoles,
  validateRealm,
  validateDomain,
  validatePassword,
  validateDnsBackend,
  validateFunctionLevel
};
