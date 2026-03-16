'use strict';

const ldap = require('ldapjs');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const LDAP_URL = process.env.SAMBA_LDAP_URL || 'ldap://localhost:389';
const BASE_DN = process.env.SAMBA_BASE_DN || 'dc=opendirectory,dc=local';
const ADMIN_DN = process.env.SAMBA_ADMIN_DN || `cn=Administrator,cn=Users,${BASE_DN}`;
const ADMIN_PASSWORD = process.env.SAMBA_ADMIN_PASSWORD || '';

let clientPool = null;

/**
 * Create a bound LDAP client connected to Samba AD.
 *
 * @returns {Promise<ldap.Client>} Bound LDAP client
 */
async function getClient() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: LDAP_URL,
      timeout: 10000,
      connectTimeout: 5000,
      reconnect: {
        initialDelay: 1000,
        maxDelay: 10000,
        failAfter: 5
      }
    });

    client.on('error', (err) => {
      logger.error('LDAP client error', { error: err.message });
    });

    client.bind(ADMIN_DN, ADMIN_PASSWORD, (err) => {
      if (err) {
        client.destroy();
        return reject(new Error(`LDAP bind failed: ${err.message}`));
      }
      resolve(client);
    });
  });
}

/**
 * Perform an LDAP search and return results.
 *
 * @param {ldap.Client} client - Bound LDAP client
 * @param {string} baseDn - Search base DN
 * @param {object} options - Search options
 * @returns {Promise<object[]>} Search results
 */
function ldapSearch(client, baseDn, options) {
  return new Promise((resolve, reject) => {
    const entries = [];

    client.search(baseDn, options, (err, res) => {
      if (err) return reject(err);

      res.on('searchEntry', (entry) => {
        const obj = {};
        obj.dn = entry.objectName || entry.dn;
        if (entry.ppiAttributes || entry.attributes) {
          const attrs = entry.ppiAttributes || entry.attributes;
          for (const attr of attrs) {
            const name = attr.type || attr._name;
            const values = attr.values || attr._vals || [];
            obj[name] = values.length === 1 ? values[0] : values;
          }
        }
        entries.push(obj);
      });

      res.on('error', (err) => {
        reject(new Error(`LDAP search error: ${err.message}`));
      });

      res.on('end', (result) => {
        resolve(entries);
      });
    });
  });
}

/**
 * Search for AD users.
 *
 * @param {string} filter - LDAP filter (default: all users)
 * @param {string[]} attributes - Attributes to return
 * @returns {Promise<object>} User search results
 */
async function searchUsers(filter, attributes) {
  const client = await getClient();

  try {
    const defaultFilter = '(&(objectClass=user)(objectCategory=person))';
    const searchFilter = filter || defaultFilter;

    const defaultAttrs = [
      'cn', 'sAMAccountName', 'displayName', 'mail', 'givenName', 'sn',
      'userPrincipalName', 'distinguishedName', 'memberOf', 'userAccountControl',
      'whenCreated', 'whenChanged', 'department', 'title', 'telephoneNumber',
      'description', 'objectGUID', 'objectSid'
    ];

    const results = await ldapSearch(client, `cn=Users,${BASE_DN}`, {
      scope: 'sub',
      filter: searchFilter,
      attributes: attributes || defaultAttrs,
      sizeLimit: 1000
    });

    return {
      users: results,
      total: results.length,
      baseDn: `cn=Users,${BASE_DN}`,
      retrievedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Create an AD user account.
 *
 * @param {object} userData - User data
 * @param {string} userData.username - sAMAccountName
 * @param {string} userData.password - Initial password
 * @param {string} userData.firstName - Given name
 * @param {string} userData.lastName - Surname
 * @param {string} userData.email - Email address
 * @param {string} userData.displayName - Display name
 * @param {string} userData.department - Department
 * @param {string} userData.title - Job title
 * @param {string} userData.ou - Target OU DN (optional, defaults to cn=Users)
 * @returns {Promise<object>} Created user
 */
async function createUser(userData) {
  if (!userData.username) throw new Error('Username (sAMAccountName) is required');
  if (!userData.password) throw new Error('Password is required');

  // Validate username format
  if (!/^[a-zA-Z0-9._-]+$/.test(userData.username)) {
    throw new Error('Invalid username format. Use alphanumeric characters, dots, underscores, and hyphens only.');
  }

  const client = await getClient();

  try {
    const parentDn = userData.ou || `cn=Users,${BASE_DN}`;
    const dn = `cn=${userData.firstName || userData.username} ${userData.lastName || ''},${parentDn}`.replace(/\s+,/, ',');
    const realm = BASE_DN.split(',').map(c => c.replace('dc=', '')).join('.').toUpperCase();

    const entry = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user'],
      cn: `${userData.firstName || userData.username} ${userData.lastName || ''}`.trim(),
      sAMAccountName: userData.username,
      userPrincipalName: `${userData.username}@${realm.toLowerCase()}`,
      displayName: userData.displayName || `${userData.firstName || ''} ${userData.lastName || ''}`.trim() || userData.username,
      userAccountControl: '512', // Normal account, enabled
      unicodePwd: encodePassword(userData.password)
    };

    if (userData.firstName) entry.givenName = userData.firstName;
    if (userData.lastName) entry.sn = userData.lastName;
    if (userData.email) entry.mail = userData.email;
    if (userData.department) entry.department = userData.department;
    if (userData.title) entry.title = userData.title;
    if (userData.description) entry.description = userData.description;
    if (userData.telephoneNumber) entry.telephoneNumber = userData.telephoneNumber;

    await new Promise((resolve, reject) => {
      client.add(dn, entry, (err) => {
        if (err) return reject(new Error(`Failed to create user: ${err.message}`));
        resolve();
      });
    });

    logger.info('AD user created', { username: userData.username, dn });

    return {
      success: true,
      dn,
      username: userData.username,
      displayName: entry.displayName,
      createdAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Encode a password for AD's unicodePwd attribute.
 */
function encodePassword(password) {
  const quotedPassword = `"${password}"`;
  return Buffer.from(quotedPassword, 'utf16le');
}

/**
 * Modify an AD user's attributes.
 *
 * @param {string} dn - User's Distinguished Name
 * @param {object} changes - Attribute changes
 * @returns {Promise<object>} Modification result
 */
async function modifyUser(dn, changes) {
  if (!dn) throw new Error('User DN is required');
  if (!changes || typeof changes !== 'object') throw new Error('Changes object is required');

  const client = await getClient();

  try {
    const modifications = [];

    for (const [key, value] of Object.entries(changes)) {
      if (key === 'dn' || key === 'objectClass' || key === 'objectGUID' || key === 'objectSid') {
        continue; // Skip read-only attributes
      }

      if (key === 'password') {
        modifications.push(new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({
            type: 'unicodePwd',
            values: [encodePassword(value)]
          })
        }));
        continue;
      }

      if (key === 'enabled') {
        modifications.push(new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({
            type: 'userAccountControl',
            values: [value ? '512' : '514']
          })
        }));
        continue;
      }

      modifications.push(new ldap.Change({
        operation: value === null || value === '' ? 'delete' : 'replace',
        modification: new ldap.Attribute({
          type: key,
          values: value === null || value === '' ? [] : [String(value)]
        })
      }));
    }

    if (modifications.length === 0) {
      return { success: true, dn, message: 'No changes to apply' };
    }

    await new Promise((resolve, reject) => {
      client.modify(dn, modifications, (err) => {
        if (err) return reject(new Error(`Failed to modify user: ${err.message}`));
        resolve();
      });
    });

    logger.info('AD user modified', { dn, changedAttributes: Object.keys(changes) });

    return {
      success: true,
      dn,
      modifiedAttributes: Object.keys(changes),
      modifiedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Delete an AD user.
 *
 * @param {string} dn - User's Distinguished Name
 * @returns {Promise<object>} Deletion result
 */
async function deleteUser(dn) {
  if (!dn) throw new Error('User DN is required');

  const client = await getClient();

  try {
    await new Promise((resolve, reject) => {
      client.del(dn, (err) => {
        if (err) return reject(new Error(`Failed to delete user: ${err.message}`));
        resolve();
      });
    });

    logger.info('AD user deleted', { dn });

    return {
      success: true,
      dn,
      deletedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Search for AD groups.
 *
 * @param {string} filter - LDAP filter (default: all groups)
 * @returns {Promise<object>} Group search results
 */
async function searchGroups(filter) {
  const client = await getClient();

  try {
    const defaultFilter = '(objectClass=group)';
    const results = await ldapSearch(client, BASE_DN, {
      scope: 'sub',
      filter: filter || defaultFilter,
      attributes: [
        'cn', 'sAMAccountName', 'distinguishedName', 'description',
        'member', 'memberOf', 'groupType', 'objectGUID', 'whenCreated', 'whenChanged',
        'managedBy'
      ],
      sizeLimit: 1000
    });

    return {
      groups: results,
      total: results.length,
      retrievedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Create an AD group.
 *
 * @param {object} groupData - Group data
 * @param {string} groupData.name - Group name (sAMAccountName)
 * @param {string} groupData.description - Group description
 * @param {string} groupData.groupType - Group type (security|distribution)
 * @param {string} groupData.groupScope - Group scope (global|domainLocal|universal)
 * @param {string} groupData.ou - Target OU DN (optional)
 * @returns {Promise<object>} Created group
 */
async function createGroup(groupData) {
  if (!groupData.name) throw new Error('Group name is required');

  if (!/^[a-zA-Z0-9._\s-]+$/.test(groupData.name)) {
    throw new Error('Invalid group name format');
  }

  const client = await getClient();

  try {
    const parentDn = groupData.ou || `cn=Users,${BASE_DN}`;
    const dn = `cn=${groupData.name},${parentDn}`;

    // Calculate groupType value
    // Security groups have 0x80000000 flag, distribution groups don't
    // Global = 0x02, DomainLocal = 0x04, Universal = 0x08
    let groupTypeValue = -2147483646; // Default: global security group
    const scopeMap = { global: 2, domainLocal: 4, universal: 8 };
    const scope = scopeMap[groupData.groupScope] || 2;

    if (groupData.groupType === 'distribution') {
      groupTypeValue = scope;
    } else {
      groupTypeValue = -2147483648 + scope; // Security flag + scope
    }

    const entry = {
      objectClass: ['top', 'group'],
      cn: groupData.name,
      sAMAccountName: groupData.name,
      groupType: String(groupTypeValue)
    };

    if (groupData.description) entry.description = groupData.description;
    if (groupData.managedBy) entry.managedBy = groupData.managedBy;

    await new Promise((resolve, reject) => {
      client.add(dn, entry, (err) => {
        if (err) return reject(new Error(`Failed to create group: ${err.message}`));
        resolve();
      });
    });

    logger.info('AD group created', { name: groupData.name, dn });

    return {
      success: true,
      dn,
      name: groupData.name,
      groupType: groupData.groupType || 'security',
      groupScope: groupData.groupScope || 'global',
      createdAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Add a member to an AD group.
 *
 * @param {string} groupDn - Group's Distinguished Name
 * @param {string} userDn - User's Distinguished Name to add
 * @returns {Promise<object>} Operation result
 */
async function addGroupMember(groupDn, userDn) {
  if (!groupDn) throw new Error('Group DN is required');
  if (!userDn) throw new Error('User DN is required');

  const client = await getClient();

  try {
    const change = new ldap.Change({
      operation: 'add',
      modification: new ldap.Attribute({
        type: 'member',
        values: [userDn]
      })
    });

    await new Promise((resolve, reject) => {
      client.modify(groupDn, change, (err) => {
        if (err) return reject(new Error(`Failed to add group member: ${err.message}`));
        resolve();
      });
    });

    logger.info('Member added to group', { groupDn, userDn });

    return {
      success: true,
      groupDn,
      userDn,
      operation: 'add',
      modifiedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Remove a member from an AD group.
 *
 * @param {string} groupDn - Group's Distinguished Name
 * @param {string} userDn - User's Distinguished Name to remove
 * @returns {Promise<object>} Operation result
 */
async function removeGroupMember(groupDn, userDn) {
  if (!groupDn) throw new Error('Group DN is required');
  if (!userDn) throw new Error('User DN is required');

  const client = await getClient();

  try {
    const change = new ldap.Change({
      operation: 'delete',
      modification: new ldap.Attribute({
        type: 'member',
        values: [userDn]
      })
    });

    await new Promise((resolve, reject) => {
      client.modify(groupDn, change, (err) => {
        if (err) return reject(new Error(`Failed to remove group member: ${err.message}`));
        resolve();
      });
    });

    logger.info('Member removed from group', { groupDn, userDn });

    return {
      success: true,
      groupDn,
      userDn,
      operation: 'remove',
      modifiedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Search for Organizational Units.
 *
 * @param {string} baseDn - Base DN to search from (optional)
 * @returns {Promise<object>} OU search results
 */
async function searchOUs(baseDn) {
  const client = await getClient();

  try {
    const results = await ldapSearch(client, baseDn || BASE_DN, {
      scope: 'sub',
      filter: '(objectClass=organizationalUnit)',
      attributes: [
        'ou', 'distinguishedName', 'description', 'whenCreated',
        'whenChanged', 'gPLink', 'gPOptions'
      ],
      sizeLimit: 1000
    });

    return {
      ous: results,
      total: results.length,
      baseDn: baseDn || BASE_DN,
      retrievedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Create an Organizational Unit.
 *
 * @param {string} name - OU name
 * @param {string} parentDn - Parent DN (optional, defaults to base DN)
 * @param {string} description - OU description (optional)
 * @returns {Promise<object>} Created OU
 */
async function createOU(name, parentDn, description) {
  if (!name) throw new Error('OU name is required');

  if (!/^[a-zA-Z0-9._\s-]+$/.test(name)) {
    throw new Error('Invalid OU name format');
  }

  const client = await getClient();

  try {
    const dn = `ou=${name},${parentDn || BASE_DN}`;

    const entry = {
      objectClass: ['top', 'organizationalUnit'],
      ou: name
    };

    if (description) entry.description = description;

    await new Promise((resolve, reject) => {
      client.add(dn, entry, (err) => {
        if (err) return reject(new Error(`Failed to create OU: ${err.message}`));
        resolve();
      });
    });

    logger.info('OU created', { name, dn });

    return {
      success: true,
      dn,
      name,
      description: description || null,
      createdAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Search for computer accounts.
 *
 * @param {string} filter - LDAP filter (default: all computers)
 * @returns {Promise<object>} Computer search results
 */
async function searchComputers(filter) {
  const client = await getClient();

  try {
    const defaultFilter = '(objectClass=computer)';
    const results = await ldapSearch(client, BASE_DN, {
      scope: 'sub',
      filter: filter || defaultFilter,
      attributes: [
        'cn', 'sAMAccountName', 'distinguishedName', 'dNSHostName',
        'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp',
        'whenCreated', 'whenChanged', 'userAccountControl', 'description',
        'managedBy', 'memberOf'
      ],
      sizeLimit: 1000
    });

    return {
      computers: results,
      total: results.length,
      retrievedAt: new Date().toISOString()
    };
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Test LDAP connectivity to Samba AD.
 *
 * @returns {Promise<object>} Connectivity test result
 */
async function testConnection() {
  try {
    const client = await getClient();
    const results = await ldapSearch(client, BASE_DN, {
      scope: 'base',
      filter: '(objectClass=*)',
      attributes: ['defaultNamingContext', 'dnsHostName', 'serverName']
    });
    client.unbind(() => {});

    return {
      connected: true,
      baseDn: BASE_DN,
      serverInfo: results[0] || {},
      testedAt: new Date().toISOString()
    };
  } catch (err) {
    return {
      connected: false,
      baseDn: BASE_DN,
      error: err.message,
      testedAt: new Date().toISOString()
    };
  }
}

module.exports = {
  getClient,
  searchUsers,
  createUser,
  modifyUser,
  deleteUser,
  searchGroups,
  createGroup,
  addGroupMember,
  removeGroupMember,
  searchOUs,
  createOU,
  searchComputers,
  testConnection
};
