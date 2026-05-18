'use strict';
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { execSync, exec } = require('child_process');

const app = express();
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

const PORT = parseInt(process.env.KDC_API_PORT || '3013');
const REALM = process.env.KRB5_REALM || 'OPENDIRECTORY.LOCAL';

function kadminLocal(command) {
  return execSync(`kadmin.local -q "${command.replace(/"/g, '\\"')}" 2>&1`).toString().trim();
}

function parseKadminOutput(output) {
  const lines = output.split('\n').filter(l => l.trim() && !l.startsWith('Authenticating'));
  return lines;
}

// Health check
app.get('/health', (req, res) => {
  try {
    kadminLocal('listprincs');
    res.json({ status: 'ok', realm: REALM });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// List all principals
app.get('/api/kerberos/principals', (req, res) => {
  try {
    const output = kadminLocal('listprincs');
    const principals = output.split('\n')
      .filter(p => p.trim() && !p.includes('Authenticating'))
      .map(p => p.trim());
    res.json({ realm: REALM, principals, count: principals.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get principal details
app.get('/api/kerberos/principals/:name', (req, res) => {
  try {
    const output = kadminLocal(`getprinc ${req.params.name}@${REALM}`);
    const lines = output.split('\n').filter(l => l.trim());
    const details = {};
    for (const line of lines) {
      const [key, ...val] = line.split(':');
      if (key && val.length) details[key.trim()] = val.join(':').trim();
    }
    res.json({ principal: `${req.params.name}@${REALM}`, details });
  } catch (err) {
    res.status(404).json({ error: 'Principal not found' });
  }
});

// Create principal
app.post('/api/kerberos/principals', (req, res) => {
  const { name, password, noexpiry = true } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    if (password) {
      kadminLocal(`addprinc -pw ${password}${noexpiry ? ' -pwexpiry never' : ''} ${name}@${REALM}`);
    } else {
      kadminLocal(`addprinc -randkey ${name}@${REALM}`);
    }
    res.status(201).json({ principal: `${name}@${REALM}`, realm: REALM });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Change principal password
app.put('/api/kerberos/principals/:name/password', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });
  try {
    kadminLocal(`cpw -pw ${password} ${req.params.name}@${REALM}`);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete principal
app.delete('/api/kerberos/principals/:name', (req, res) => {
  try {
    kadminLocal(`delprinc -force ${req.params.name}@${REALM}`);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Generate keytab for a service principal
app.post('/api/kerberos/keytabs/:name', (req, res) => {
  const keytabPath = `/tmp/keytab-${req.params.name.replace(/[^a-zA-Z0-9]/g, '_')}.keytab`;
  try {
    kadminLocal(`ktadd -k ${keytabPath} ${req.params.name}@${REALM}`);
    const keytabData = require('fs').readFileSync(keytabPath);
    require('fs').unlinkSync(keytabPath);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.name}.keytab"`);
    res.send(keytabData);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Sync user from OpenDirectory (create Kerberos principal for LLDAP user)
app.post('/api/kerberos/sync-user', (req, res) => {
  const { username, password } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  try {
    const exists = (() => { try { kadminLocal(`getprinc ${username}@${REALM}`); return true; } catch { return false; } })();
    if (exists) {
      if (password) kadminLocal(`cpw -pw ${password} ${username}@${REALM}`);
      return res.json({ action: 'updated', principal: `${username}@${REALM}` });
    }
    if (password) {
      kadminLocal(`addprinc -pw ${password} -pwexpiry never ${username}@${REALM}`);
    } else {
      kadminLocal(`addprinc -randkey ${username}@${REALM}`);
    }
    res.status(201).json({ action: 'created', principal: `${username}@${REALM}` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`[kerberos-admin-api] REST API on :${PORT}, Realm: ${REALM}`));
