'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const winston = require('winston');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const SAMBA_TOOL = '/usr/bin/samba-tool';
const KRB5_CONF = '/etc/krb5.conf';
const KEYTAB_DIR = '/var/lib/samba/private';

/**
 * Read and parse the current Kerberos configuration.
 *
 * @returns {Promise<object>} Kerberos configuration
 */
async function getKerberosConfig() {
  try {
    const content = await fs.readFile(KRB5_CONF, 'utf-8');

    const config = {
      raw: content,
      sections: {}
    };

    // Parse sections
    let currentSection = null;
    let currentSubsection = null;

    for (const line of content.split('\n')) {
      const trimmed = line.trim();

      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

      // Section header
      const sectionMatch = trimmed.match(/^\[(.+)\]$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1];
        currentSubsection = null;
        if (!config.sections[currentSection]) {
          config.sections[currentSection] = {};
        }
        continue;
      }

      // Subsection header (e.g., REALM = {)
      const subMatch = trimmed.match(/^(\S+)\s*=\s*\{$/);
      if (subMatch && currentSection) {
        currentSubsection = subMatch[1];
        config.sections[currentSection][currentSubsection] = {};
        continue;
      }

      // End of subsection
      if (trimmed === '}') {
        currentSubsection = null;
        continue;
      }

      // Key-value pair
      const kvMatch = trimmed.match(/^(\S+)\s*=\s*(.+)$/);
      if (kvMatch) {
        const key = kvMatch[1];
        const value = kvMatch[2].trim();
        if (currentSubsection && currentSection) {
          config.sections[currentSection][currentSubsection][key] = value;
        } else if (currentSection) {
          config.sections[currentSection][key] = value;
        }
      }
    }

    return {
      config,
      path: KRB5_CONF,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    if (err.code === 'ENOENT') {
      return {
        config: null,
        path: KRB5_CONF,
        message: 'Kerberos configuration file not found',
        retrievedAt: new Date().toISOString()
      };
    }
    logger.error('Error reading Kerberos config', { error: err.message });
    throw new Error(`Failed to read Kerberos config: ${err.message}`);
  }
}

/**
 * Create a Service Principal Name (SPN) for a service.
 *
 * @param {string} service - Service type (e.g., HTTP, HOST, ldap)
 * @param {string} hostname - Hostname for the SPN
 * @returns {Promise<object>} Creation result
 */
async function createServicePrincipal(service, hostname) {
  if (!service || typeof service !== 'string') {
    throw new Error('Service name is required');
  }
  if (!hostname || typeof hostname !== 'string') {
    throw new Error('Hostname is required');
  }

  // Validate service name (alphanumeric, hyphens)
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(service)) {
    throw new Error('Invalid service name format');
  }

  // Validate hostname
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/.test(hostname)) {
    throw new Error('Invalid hostname format');
  }

  const spn = `${service}/${hostname}`;

  logger.info('Creating service principal', { spn });

  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, [
      'spn', 'add', spn, hostname,
      '--username=administrator'
    ], { timeout: 30000 });

    return {
      success: true,
      spn,
      service,
      hostname,
      createdAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error creating SPN', { spn, error: err.message });
    throw new Error(`Failed to create SPN ${spn}: ${err.message}`);
  }
}

/**
 * Export a keytab for a given principal.
 *
 * @param {string} principal - Kerberos principal
 * @param {string} outputPath - Path to export the keytab file
 * @returns {Promise<object>} Export result
 */
async function exportKeytab(principal, outputPath) {
  if (!principal || typeof principal !== 'string') {
    throw new Error('Principal is required');
  }
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('Output path is required');
  }

  // Validate output path is within allowed directories
  const allowedPrefixes = ['/var/lib/samba', '/tmp', '/app'];
  const isAllowed = allowedPrefixes.some(prefix => outputPath.startsWith(prefix));
  if (!isAllowed) {
    throw new Error('Keytab export path must be within /var/lib/samba, /tmp, or /app');
  }

  logger.info('Exporting keytab', { principal, outputPath });

  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, [
      'domain', 'exportkeytab', outputPath,
      `--principal=${principal}`
    ], { timeout: 30000 });

    // Verify the keytab was created
    await fs.access(outputPath);
    const stats = await fs.stat(outputPath);

    return {
      success: true,
      principal,
      path: outputPath,
      size: stats.size,
      exportedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error exporting keytab', { principal, outputPath, error: err.message });
    throw new Error(`Failed to export keytab for ${principal}: ${err.message}`);
  }
}

/**
 * List Kerberos principals (SPNs) in the domain.
 *
 * @returns {Promise<object>} List of principals
 */
async function listPrincipals() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, [
      'spn', 'list', '--username=administrator'
    ], { timeout: 30000 }).catch(() => ({ stdout: '' }));

    // Alternative: use user list to find SPNs
    const { stdout: userOutput } = await execFileAsync(SAMBA_TOOL, [
      'user', 'list'
    ], { timeout: 30000 });

    const principals = [];
    const users = userOutput.split('\n').filter(l => l.trim());

    for (const user of users) {
      try {
        const { stdout: spnOutput } = await execFileAsync(SAMBA_TOOL, [
          'spn', 'list', user.trim()
        ], { timeout: 10000 });

        const spns = spnOutput.split('\n').filter(l => l.trim() && !l.includes('User'));
        for (const spn of spns) {
          principals.push({
            principal: spn.trim(),
            user: user.trim()
          });
        }
      } catch {
        // User may not have SPNs
      }
    }

    return {
      principals,
      total: principals.length,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error listing principals', { error: err.message });
    throw new Error(`Failed to list principals: ${err.message}`);
  }
}

/**
 * Test Kerberos authentication for a user.
 *
 * @param {string} username - Username to test
 * @param {string} password - Password to test
 * @returns {Promise<object>} Authentication result
 */
async function testAuthentication(username, password) {
  if (!username || typeof username !== 'string') {
    throw new Error('Username is required');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('Password is required');
  }

  // Validate username format (prevent injection)
  if (!/^[a-zA-Z0-9._@-]+$/.test(username)) {
    throw new Error('Invalid username format');
  }

  logger.info('Testing Kerberos authentication', { username });

  try {
    // Use kinit to test authentication
    const { stdout, stderr } = await execFileAsync('/usr/bin/kinit', [
      '--password-file=STDIN', username
    ], {
      timeout: 15000,
      input: password
    });

    // Clean up the ticket
    await execFileAsync('/usr/bin/kdestroy', [], { timeout: 5000 }).catch(() => {});

    return {
      success: true,
      username,
      message: 'Authentication successful',
      testedAt: new Date().toISOString()
    };
  } catch (err) {
    // Check if it's an auth failure vs. system error
    const isAuthFailure = err.message.includes('Preauthentication failed') ||
                          err.message.includes('Client not found') ||
                          err.stderr?.includes('Preauthentication failed');

    return {
      success: false,
      username,
      message: isAuthFailure ? 'Authentication failed: invalid credentials' : `Authentication error: ${err.message}`,
      isAuthFailure,
      testedAt: new Date().toISOString()
    };
  }
}

module.exports = {
  getKerberosConfig,
  createServicePrincipal,
  exportKeytab,
  listPrincipals,
  testAuthentication
};
