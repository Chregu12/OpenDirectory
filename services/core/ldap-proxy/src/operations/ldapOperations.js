'use strict';

const { createClient } = require('ldapts');
const crypto = require('crypto');

/**
 * LDAPOperations — full LDAP operation wrapper around ldapts.
 *
 * Provides a clean async interface for all core LDAP operations with proper
 * error mapping, paged search, persistent search simulation, and RFC 3062
 * password-modify extended operation support.
 */
class LDAPOperations {
  /**
   * @param {{ host: string, port: number, bindDn: string, bindPassword: string, useTLS?: boolean }} config
   */
  constructor(config) {
    this.config = {
      host: config.host || 'localhost',
      port: config.port || 389,
      bindDn: config.bindDn || '',
      bindPassword: config.bindPassword || '',
      useTLS: Boolean(config.useTLS),
    };

    // Session store: sessionId -> { client, boundDn, createdAt }
    this._sessions = new Map();

    // Persistent search subscriptions: id -> { client, cancel }
    this._subscriptions = new Map();
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  _buildClientUrl() {
    const scheme = this.config.useTLS ? 'ldaps' : 'ldap';
    return `${scheme}://${this.config.host}:${this.config.port}`;
  }

  _createClient() {
    return createClient({
      url: this._buildClientUrl(),
      timeout: 10000,
      connectTimeout: 5000,
      tlsOptions: this.config.useTLS ? { rejectUnauthorized: false } : undefined,
    });
  }

  _mapError(err) {
    const msg = err.message || String(err);
    const code = err.code || err.lde_message || null;
    const out = new Error(`LDAP Error: ${msg}`);
    out.ldapCode = code;
    out.original = err;
    return out;
  }

  // -------------------------------------------------------------------------
  // Bind / Unbind
  // -------------------------------------------------------------------------

  /**
   * Perform an LDAP bind and store the session.
   * @param {string} dn
   * @param {string} password
   * @returns {{ success: boolean, sessionId: string }}
   */
  async bind(dn, password) {
    const client = this._createClient();
    try {
      await client.bind(dn, password);
    } catch (err) {
      try { await client.unbind(); } catch (_) {}
      throw this._mapError(err);
    }

    const sessionId = crypto.randomUUID();
    this._sessions.set(sessionId, {
      client,
      boundDn: dn,
      createdAt: Date.now(),
    });

    return { success: true, sessionId };
  }

  /**
   * Unbind a session.
   * @param {string} sessionId
   */
  async unbind(sessionId) {
    const session = this._sessions.get(sessionId);
    if (!session) return;
    try {
      await session.client.unbind();
    } catch (_) {
      // Best effort
    }
    this._sessions.delete(sessionId);
  }

  /**
   * Get an authenticated (admin) client, creating and binding one as needed.
   * @returns {object} ldapts client
   */
  async _adminClient() {
    const client = this._createClient();
    try {
      await client.bind(this.config.bindDn, this.config.bindPassword);
    } catch (err) {
      try { await client.unbind(); } catch (_) {}
      throw this._mapError(err);
    }
    return client;
  }

  // -------------------------------------------------------------------------
  // Search
  // -------------------------------------------------------------------------

  /**
   * Search LDAP.
   * @param {string} baseDn
   * @param {{ filter?: string, scope?: string, attributes?: string[], sizeLimit?: number, timeLimit?: number, paged?: boolean }} options
   * @returns {{ entries: Array<{dn: string, attributes: object}>, referrals: string[], controls: object[] }}
   */
  async search(baseDn, options = {}) {
    const client = await this._adminClient();
    try {
      const searchOpts = {
        filter: options.filter || '(objectClass=*)',
        scope: options.scope || 'sub',
        attributes: options.attributes || [],
        sizeLimit: options.sizeLimit || 1000,
        timeLimit: options.timeLimit || 30,
        returnAttributeValues: true,
        explicitBufferAttributes: [],
      };

      if (options.paged) {
        searchOpts.paged = { pageSize: options.sizeLimit || 100 };
      }

      const { searchEntries, searchReferences } = await client.search(baseDn, searchOpts);

      const entries = searchEntries.map((e) => ({
        dn: e.dn,
        attributes: this._normalizeEntry(e),
      }));

      return {
        entries,
        referrals: searchReferences || [],
        controls: [],
      };
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  _normalizeEntry(entry) {
    const attrs = {};
    for (const [key, val] of Object.entries(entry)) {
      if (key === 'dn') continue;
      attrs[key] = Array.isArray(val) ? val : [val];
    }
    return attrs;
  }

  // -------------------------------------------------------------------------
  // Add
  // -------------------------------------------------------------------------

  /**
   * Add an LDAP entry.
   * @param {string} dn
   * @param {object} attributes — { attrName: string | string[] }
   */
  async add(dn, attributes) {
    const client = await this._adminClient();
    try {
      // ldapts expects values as arrays
      const entry = {};
      for (const [k, v] of Object.entries(attributes)) {
        entry[k] = Array.isArray(v) ? v : [String(v)];
      }
      await client.add(dn, entry);
      return { success: true, dn };
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // Modify
  // -------------------------------------------------------------------------

  /**
   * Modify an LDAP entry.
   * @param {string} dn
   * @param {Array<{operation: 'add'|'replace'|'delete', modification: {type: string, values: string[]}}>} changes
   */
  async modify(dn, changes) {
    const client = await this._adminClient();
    try {
      const { Attribute, Change } = require('ldapts');

      const ldapChanges = changes.map((c) => {
        const op = c.operation;
        if (!['add', 'replace', 'delete'].includes(op)) {
          throw new Error(`Invalid modify operation '${op}'. Must be add, replace, or delete`);
        }
        const mod = c.modification;
        const values = Array.isArray(mod.values) ? mod.values : (mod.values !== undefined ? [mod.values] : []);
        return new Change({
          operation: op,
          modification: new Attribute({ type: mod.type, values: values.map(String) }),
        });
      });

      await client.modify(dn, ldapChanges);
      return { success: true, dn };
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // ModifyDN (rename / move)
  // -------------------------------------------------------------------------

  /**
   * Rename or move an LDAP entry.
   * @param {string} dn
   * @param {string} newRDN
   * @param {boolean} deleteOldRDN
   * @param {string|null} newSuperior
   */
  async modifyDN(dn, newRDN, deleteOldRDN = true, newSuperior = null) {
    const client = await this._adminClient();
    try {
      const opts = { deleteOldRdn: deleteOldRDN };
      if (newSuperior) opts.newSuperior = newSuperior;
      await client.modifyDN(dn, newRDN, opts);
      const newDN = newSuperior
        ? `${newRDN},${newSuperior}`
        : `${newRDN},${dn.split(',').slice(1).join(',')}`;
      return { success: true, dn, newDN };
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // Delete
  // -------------------------------------------------------------------------

  /**
   * Delete an LDAP entry.
   * @param {string} dn
   */
  async delete(dn) {
    const client = await this._adminClient();
    try {
      await client.del(dn);
      return { success: true, dn };
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // Compare
  // -------------------------------------------------------------------------

  /**
   * Compare an attribute value in an LDAP entry.
   * @param {string} dn
   * @param {string} attribute
   * @param {string} value
   * @returns {boolean}
   */
  async compare(dn, attribute, value) {
    const client = await this._adminClient();
    try {
      const result = await client.compare(dn, attribute, value);
      return result;
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // Extended operations
  // -------------------------------------------------------------------------

  /**
   * Send an LDAP extended operation.
   * @param {string} oid
   * @param {Buffer|string|null} value
   */
  async extended(oid, value = null) {
    const client = await this._adminClient();
    try {
      // ldapts exposes extendedRequest
      const result = await client.exop(oid, value ? Buffer.from(value) : Buffer.alloc(0));
      return result;
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // Helper: multi-valued attribute management
  // -------------------------------------------------------------------------

  /**
   * Add values to a multi-valued attribute.
   * @param {string} dn
   * @param {string} attribute
   * @param {string[]} values
   */
  async addValues(dn, attribute, values) {
    return this.modify(dn, [{
      operation: 'add',
      modification: { type: attribute, values: Array.isArray(values) ? values : [values] },
    }]);
  }

  /**
   * Remove values from a multi-valued attribute.
   * @param {string} dn
   * @param {string} attribute
   * @param {string[]} values
   */
  async removeValues(dn, attribute, values) {
    return this.modify(dn, [{
      operation: 'delete',
      modification: { type: attribute, values: Array.isArray(values) ? values : [values] },
    }]);
  }

  /**
   * Replace all values of an attribute.
   * @param {string} dn
   * @param {string} attribute
   * @param {string[]} values
   */
  async replaceValue(dn, attribute, values) {
    return this.modify(dn, [{
      operation: 'replace',
      modification: { type: attribute, values: Array.isArray(values) ? values : [values] },
    }]);
  }

  // -------------------------------------------------------------------------
  // Paged search (async generator)
  // -------------------------------------------------------------------------

  /**
   * Async generator that yields pages of search results.
   * @param {string} baseDn
   * @param {object} options
   * @param {number} pageSize
   * @yields {{ entries: Array<{dn: string, attributes: object}>, page: number }}
   */
  async* pagedSearch(baseDn, options = {}, pageSize = 100) {
    const client = await this._adminClient();
    let page = 0;

    try {
      const searchOpts = {
        filter: options.filter || '(objectClass=*)',
        scope: options.scope || 'sub',
        attributes: options.attributes || [],
        timeLimit: options.timeLimit || 30,
        returnAttributeValues: true,
        paged: { pageSize },
      };

      const { searchEntries } = await client.search(baseDn, searchOpts);

      // ldapts returns all entries at once when paged option is set;
      // we chunk them here to provide generator semantics
      for (let i = 0; i < searchEntries.length; i += pageSize) {
        const chunk = searchEntries.slice(i, i + pageSize);
        yield {
          entries: chunk.map((e) => ({ dn: e.dn, attributes: this._normalizeEntry(e) })),
          page: ++page,
        };
      }
    } catch (err) {
      throw this._mapError(err);
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // Persistent search / change notification
  // -------------------------------------------------------------------------

  /**
   * Subscribe to persistent search (change notification).
   * NOTE: Real persistent search requires the LDAP server to support the
   * Persistent Search control (2.16.840.1.113730.3.4.3).  We simulate this
   * with polling when that control is unavailable.
   *
   * @param {string} baseDn
   * @param {string} filter
   * @param {function} callback  — called with (err, entry) for each change
   * @returns {{ id: string, cancel: function }}
   */
  async subscribeToPersistentSearch(baseDn, filter, callback) {
    const id = crypto.randomUUID();
    let cancelled = false;
    let lastCheck = new Date();

    const poll = async () => {
      if (cancelled) return;
      try {
        const client = await this._adminClient();
        try {
          const since = lastCheck.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
          const { searchEntries } = await client.search(baseDn, {
            filter: `(&${filter}(modifyTimestamp>=${since}))`,
            scope: 'sub',
            attributes: ['*', 'modifyTimestamp'],
          });
          lastCheck = new Date();
          for (const entry of searchEntries) {
            if (!cancelled) callback(null, { dn: entry.dn, attributes: this._normalizeEntry(entry) });
          }
        } finally {
          try { await client.unbind(); } catch (_) {}
        }
      } catch (err) {
        if (!cancelled) callback(this._mapError(err), null);
      }

      if (!cancelled) setTimeout(poll, 30000); // poll every 30s
    };

    // Start polling
    const timer = setTimeout(poll, 5000);
    this._subscriptions.set(id, { timer, cancel: () => { cancelled = true; clearTimeout(timer); } });

    return {
      id,
      cancel: () => {
        const sub = this._subscriptions.get(id);
        if (sub) { sub.cancel(); this._subscriptions.delete(id); }
      },
    };
  }

  // -------------------------------------------------------------------------
  // RFC 3062 — Password Modify Extended Operation
  // -------------------------------------------------------------------------

  /**
   * Change a user's password using the LDAP Password Modify extended operation
   * (RFC 3062, OID 1.3.6.1.4.1.4203.1.11.1).
   * Falls back to a direct userPassword replace if the server doesn't support it.
   *
   * @param {string} userDn
   * @param {string} oldPassword
   * @param {string} newPassword
   */
  async changePassword(userDn, oldPassword, newPassword) {
    // First verify old password by binding as the user
    try {
      const testClient = this._createClient();
      await testClient.bind(userDn, oldPassword);
      await testClient.unbind();
    } catch (err) {
      const e = new Error('Current password is incorrect');
      e.code = 'INVALID_CREDENTIALS';
      throw e;
    }

    // Try RFC 3062 Password Modify Extended Operation
    const OID_PASSWORD_MODIFY = '1.3.6.1.4.1.4203.1.11.1';
    const client = await this._adminClient();
    try {
      // Build BER-encoded request value for PasswdModifyRequestValue
      // SEQUENCE { userIdentity [0] OCTET STRING OPTIONAL,
      //            oldPasswd    [1] OCTET STRING OPTIONAL,
      //            newPasswd    [2] OCTET STRING OPTIONAL }
      const userDnBuf = Buffer.from(userDn, 'utf8');
      const oldPwBuf = Buffer.from(oldPassword, 'utf8');
      const newPwBuf = Buffer.from(newPassword, 'utf8');

      function berTLV(tag, valueBuf) {
        const len = valueBuf.length;
        if (len < 128) {
          return Buffer.concat([Buffer.from([tag, len]), valueBuf]);
        }
        // Long form (up to 2-byte length)
        const lenBytes = len < 256 ? 1 : 2;
        const lenBuf = Buffer.alloc(2 + lenBytes);
        lenBuf[0] = tag;
        lenBuf[1] = 0x80 | lenBytes;
        if (lenBytes === 1) lenBuf[2] = len;
        else { lenBuf[2] = len >> 8; lenBuf[3] = len & 0xff; }
        return Buffer.concat([lenBuf, valueBuf]);
      }

      const userIdField = berTLV(0x80, userDnBuf);
      const oldPwField = berTLV(0x81, oldPwBuf);
      const newPwField = berTLV(0x82, newPwBuf);
      const content = Buffer.concat([userIdField, oldPwField, newPwField]);
      const requestValue = berTLV(0x30, content); // SEQUENCE

      await client.exop(OID_PASSWORD_MODIFY, requestValue);
      return { success: true, method: 'rfc3062' };
    } catch (extErr) {
      // Fall back to direct userPassword attribute replace
      console.warn('[LDAPOperations] RFC 3062 password modify failed, falling back to direct replace:', extErr.message);
      try {
        const { Attribute, Change } = require('ldapts');
        await client.modify(userDn, [
          new Change({
            operation: 'replace',
            modification: new Attribute({ type: 'userPassword', values: [newPassword] }),
          }),
        ]);
        return { success: true, method: 'direct' };
      } catch (modErr) {
        throw this._mapError(modErr);
      }
    } finally {
      try { await client.unbind(); } catch (_) {}
    }
  }

  // -------------------------------------------------------------------------
  // StartTLS
  // -------------------------------------------------------------------------

  /**
   * Upgrade an existing plaintext connection to TLS using the StartTLS
   * extended operation (RFC 4511 §4.14).
   */
  async startTLS() {
    const OID_STARTTLS = '1.3.6.1.4.1.1466.20037';
    return this.extended(OID_STARTTLS, null);
  }

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  /**
   * Destroy all active sessions and subscriptions.
   */
  async destroy() {
    for (const sessionId of [...this._sessions.keys()]) {
      await this.unbind(sessionId);
    }
    for (const [id, sub] of this._subscriptions) {
      sub.cancel();
      this._subscriptions.delete(id);
    }
  }
}

module.exports = LDAPOperations;
