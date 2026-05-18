'use strict';
require('dotenv').config();
const ldap = require('ldapjs');

const LLDAP_URL = process.env.LLDAP_URL || 'ldap://localhost:3890';
const LLDAP_BASE_DN = process.env.LLDAP_BASE_DN || 'dc=opendirectory,dc=local';
const PROXY_PORT = parseInt(process.env.LDAP_PROXY_PORT || '389');
const PROXY_PORT_TLS = parseInt(process.env.LDAP_PROXY_TLS_PORT || '636');

// Parse LLDAP URL
const lldapUrl = new URL(LLDAP_URL.replace('ldap://', 'http://').replace('ldaps://', 'https://'));
const LLDAP_HOST = lldapUrl.hostname;
const LLDAP_PORT = parseInt(lldapUrl.port || '3890');

const server = ldap.createServer();

// Helper: create a connection to LLDAP
function connectToLLDAP() {
  return ldap.createClient({ url: LLDAP_URL, timeout: 5000, connectTimeout: 5000 });
}

// Bind — forward credentials to LLDAP
server.bind(LLDAP_BASE_DN, async (req, res, next) => {
  const dn = req.dn.toString();
  const password = req.credentials;

  const upstream = connectToLLDAP();
  upstream.bind(dn, password, (err) => {
    upstream.unbind();
    if (err) {
      console.log(`[ldap-proxy] bind failed for ${dn}: ${err.message}`);
      return next(new ldap.InvalidCredentialsError());
    }
    console.log(`[ldap-proxy] bind success: ${dn}`);
    res.end();
    return next();
  });
});

// Also handle binds not under our base DN
server.bind('', async (req, res, next) => {
  const dn = req.dn.toString();
  const password = req.credentials;

  if (!dn) {
    // Anonymous bind
    res.end();
    return next();
  }

  const upstream = connectToLLDAP();
  upstream.bind(dn, password, (err) => {
    upstream.unbind();
    if (err) {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });
});

// Search — forward to LLDAP
server.search(LLDAP_BASE_DN, (req, res, next) => {
  const upstream = connectToLLDAP();

  // Use admin credentials for upstream search
  const adminDn = `uid=${process.env.LLDAP_ADMIN_USER || 'admin'},ou=people,${LLDAP_BASE_DN}`;
  const adminPw = process.env.LLDAP_ADMIN_PASSWORD || '';

  upstream.bind(adminDn, adminPw, (bindErr) => {
    if (bindErr) {
      // Try anonymous
      console.warn('[ldap-proxy] admin bind failed, trying anonymous:', bindErr.message);
    }

    const opts = {
      filter: req.filter.toString(),
      scope: req.scope,
      attributes: req.attributes,
      sizeLimit: req.sizeLimit || 100,
      timeLimit: req.timeLimit || 10,
    };

    upstream.search(req.dn.toString(), opts, (searchErr, searchRes) => {
      if (searchErr) {
        upstream.unbind();
        return next(new ldap.OperationsError(searchErr.message));
      }

      searchRes.on('searchEntry', (entry) => {
        res.send(entry);
      });

      searchRes.on('searchReference', (referral) => {
        res.send(referral);
      });

      searchRes.on('end', (result) => {
        upstream.unbind();
        res.end();
        return next();
      });

      searchRes.on('error', (err) => {
        upstream.unbind();
        return next(new ldap.OperationsError(err.message));
      });
    });
  });
});

// Start server
const port = process.env.NODE_ENV === 'production' && process.getuid && process.getuid() === 0 ? PROXY_PORT : Math.max(PROXY_PORT, 1389);
server.listen(port, '0.0.0.0', () => {
  console.log(`[ldap-proxy] LDAP proxy listening on port ${port} → ${LLDAP_URL}`);
  console.log(`[ldap-proxy] Base DN: ${LLDAP_BASE_DN}`);
});

server.on('error', (err) => {
  console.error('[ldap-proxy] Server error:', err.message);
});

process.on('SIGTERM', () => { server.close(); process.exit(0); });
