'use strict';

const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const { promisify } = require('util');
const { v4: uuidv4 } = require('uuid');
const sambaLdap = require('../ldap/sambaLdap');

const execFileAsync = promisify(execFile);
const SAMBA_TOOL = '/usr/bin/samba-tool';

// ==========================================
// Users API
// ==========================================

/**
 * GET /api/samba/users
 * List AD users with optional filtering.
 */
router.get('/users', async (req, res) => {
  try {
    const { search, filter, attributes, page = 1, limit = 50 } = req.query;

    let ldapFilter = null;
    if (search) {
      ldapFilter = `(&(objectClass=user)(objectCategory=person)(|(cn=*${search}*)(sAMAccountName=*${search}*)(mail=*${search}*)(displayName=*${search}*)))`;
    } else if (filter) {
      ldapFilter = filter;
    }

    const attrs = attributes ? attributes.split(',') : undefined;
    const result = await sambaLdap.searchUsers(ldapFilter, attrs);

    // Paginate
    const startIndex = (parseInt(page, 10) - 1) * parseInt(limit, 10);
    const paginatedUsers = result.users.slice(startIndex, startIndex + parseInt(limit, 10));

    res.json({
      users: paginatedUsers,
      total: result.total,
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
      totalPages: Math.ceil(result.total / parseInt(limit, 10))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/users
 * Create an AD user.
 */
router.post('/users', async (req, res) => {
  try {
    const { username, password, firstName, lastName, email, displayName, department, title, ou, description, telephoneNumber } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    const result = await sambaLdap.createUser({
      username,
      password,
      firstName,
      lastName,
      email,
      displayName,
      department,
      title,
      ou,
      description,
      telephoneNumber
    });

    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('already exists') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * PUT /api/samba/users/:dn
 * Modify an AD user's attributes.
 */
router.put('/users/:dn', async (req, res) => {
  try {
    const dn = decodeURIComponent(req.params.dn);
    const changes = req.body;

    if (!changes || Object.keys(changes).length === 0) {
      return res.status(400).json({ error: 'At least one attribute change is required' });
    }

    const result = await sambaLdap.modifyUser(dn, changes);
    res.json(result);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/users/:dn
 * Delete an AD user.
 */
router.delete('/users/:dn', async (req, res) => {
  try {
    const dn = decodeURIComponent(req.params.dn);
    const result = await sambaLdap.deleteUser(dn);
    res.json(result);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// ==========================================
// Groups API
// ==========================================

/**
 * GET /api/samba/groups
 * List AD groups.
 */
router.get('/groups', async (req, res) => {
  try {
    const { search, filter, page = 1, limit = 50 } = req.query;

    let ldapFilter = null;
    if (search) {
      ldapFilter = `(&(objectClass=group)(|(cn=*${search}*)(sAMAccountName=*${search}*)(description=*${search}*)))`;
    } else if (filter) {
      ldapFilter = filter;
    }

    const result = await sambaLdap.searchGroups(ldapFilter);

    const startIndex = (parseInt(page, 10) - 1) * parseInt(limit, 10);
    const paginatedGroups = result.groups.slice(startIndex, startIndex + parseInt(limit, 10));

    res.json({
      groups: paginatedGroups,
      total: result.total,
      page: parseInt(page, 10),
      limit: parseInt(limit, 10)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/groups
 * Create an AD group.
 */
router.post('/groups', async (req, res) => {
  try {
    const { name, description, groupType, groupScope, ou, managedBy } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }

    const result = await sambaLdap.createGroup({
      name,
      description,
      groupType: groupType || 'security',
      groupScope: groupScope || 'global',
      ou,
      managedBy
    });

    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('already exists') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * POST /api/samba/groups/:dn/members
 * Add a member to a group.
 */
router.post('/groups/:dn/members', async (req, res) => {
  try {
    const groupDn = decodeURIComponent(req.params.dn);
    const { userDn } = req.body;

    if (!userDn) {
      return res.status(400).json({ error: 'userDn is required' });
    }

    const result = await sambaLdap.addGroupMember(groupDn, userDn);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/groups/:dn/members
 * Remove a member from a group.
 */
router.delete('/groups/:dn/members', async (req, res) => {
  try {
    const groupDn = decodeURIComponent(req.params.dn);
    const { userDn } = req.body;

    if (!userDn) {
      return res.status(400).json({ error: 'userDn is required' });
    }

    const result = await sambaLdap.removeGroupMember(groupDn, userDn);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// Organizational Units API
// ==========================================

/**
 * GET /api/samba/ous
 * List Organizational Units.
 */
router.get('/ous', async (req, res) => {
  try {
    const { baseDn } = req.query;
    const result = await sambaLdap.searchOUs(baseDn);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/ous
 * Create an Organizational Unit.
 */
router.post('/ous', async (req, res) => {
  try {
    const { name, parentDn, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'OU name is required' });
    }

    const result = await sambaLdap.createOU(name, parentDn, description);
    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('already exists') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/ous/:dn
 * Delete an Organizational Unit.
 */
router.delete('/ous/:dn', async (req, res) => {
  try {
    const dn = decodeURIComponent(req.params.dn);

    const client = await sambaLdap.getClient();
    await new Promise((resolve, reject) => {
      client.del(dn, (err) => {
        if (err) return reject(new Error(`Failed to delete OU: ${err.message}`));
        resolve();
      });
    });
    client.unbind(() => {});

    res.json({ success: true, dn, deletedAt: new Date().toISOString() });
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// ==========================================
// Computer Accounts API
// ==========================================

/**
 * GET /api/samba/computers
 * List computer accounts.
 */
router.get('/computers', async (req, res) => {
  try {
    const { search, filter } = req.query;

    let ldapFilter = null;
    if (search) {
      ldapFilter = `(&(objectClass=computer)(|(cn=*${search}*)(dNSHostName=*${search}*)))`;
    } else if (filter) {
      ldapFilter = filter;
    }

    const result = await sambaLdap.searchComputers(ldapFilter);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/computers/join-token
 * Generate a one-time token for computer domain join.
 */
router.post('/computers/join-token', async (req, res) => {
  try {
    const { computerName, ou } = req.body;

    if (!computerName) {
      return res.status(400).json({ error: 'computerName is required' });
    }

    // Validate computer name (NetBIOS format)
    if (!/^[a-zA-Z0-9-]{1,15}$/.test(computerName)) {
      return res.status(400).json({ error: 'Invalid computer name. Must be 1-15 alphanumeric characters.' });
    }

    // Generate a one-time join password using samba-tool
    const joinPassword = uuidv4().replace(/-/g, '').slice(0, 20) + 'A1!';

    try {
      await execFileAsync(SAMBA_TOOL, [
        'computer', 'create', computerName,
        `--prepare-oldjoin`
      ], { timeout: 30000 });
    } catch (err) {
      // Computer may already exist, try to reset password
      if (!err.message.includes('already exists')) {
        throw err;
      }
    }

    // Set the computer password
    try {
      await execFileAsync(SAMBA_TOOL, [
        'user', 'setpassword', `${computerName}$`,
        `--newpassword=${joinPassword}`
      ], { timeout: 30000 });
    } catch {
      // Password set may fail in some configurations
    }

    const token = {
      computerName,
      joinPassword,
      ou: ou || null,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
      createdAt: new Date().toISOString()
    };

    res.status(201).json(token);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/computers/:dn
 * Remove a computer account.
 */
router.delete('/computers/:dn', async (req, res) => {
  try {
    const dn = decodeURIComponent(req.params.dn);

    const client = await sambaLdap.getClient();
    await new Promise((resolve, reject) => {
      client.del(dn, (err) => {
        if (err) return reject(new Error(`Failed to delete computer: ${err.message}`));
        resolve();
      });
    });
    client.unbind(() => {});

    res.json({ success: true, dn, deletedAt: new Date().toISOString() });
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

module.exports = router;
