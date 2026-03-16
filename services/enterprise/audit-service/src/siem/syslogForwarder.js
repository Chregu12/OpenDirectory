'use strict';

const dgram = require('dgram');
const net = require('net');
const tls = require('tls');
const logger = require('../utils/logger');

const SEVERITY_MAP = {
  critical: 2,  // syslog: Critical
  error: 3,     // syslog: Error
  warning: 4,   // syslog: Warning
  info: 6,      // syslog: Informational
  debug: 7,     // syslog: Debug
};

class SyslogForwarder {
  constructor(config = {}) {
    this.host = config.host || '127.0.0.1';
    this.port = config.port || 514;
    this.protocol = config.protocol || 'udp';  // 'udp', 'tcp', 'tls'
    this.format = config.format || 'CEF';       // 'CEF', 'LEEF', 'RFC5424'
    this.facility = config.facility || 13;       // log audit (13)
    this.appName = config.appName || 'OpenDirectory';
    this.tlsOptions = config.tlsOptions || {};
    this.socket = null;
    this.connected = false;
  }

  async connect() {
    if (this.protocol === 'udp') {
      this.socket = dgram.createSocket('udp4');
      this.connected = true;
      logger.info('Syslog UDP forwarder ready', { host: this.host, port: this.port });
    } else if (this.protocol === 'tcp') {
      return new Promise((resolve, reject) => {
        this.socket = new net.Socket();
        this.socket.connect(this.port, this.host, () => {
          this.connected = true;
          logger.info('Syslog TCP forwarder connected', { host: this.host, port: this.port });
          resolve();
        });
        this.socket.on('error', (err) => {
          this.connected = false;
          logger.error('Syslog TCP connection error', { error: err.message });
          reject(err);
        });
        this.socket.on('close', () => {
          this.connected = false;
          logger.warn('Syslog TCP connection closed');
        });
      });
    } else if (this.protocol === 'tls') {
      return new Promise((resolve, reject) => {
        this.socket = tls.connect(this.port, this.host, this.tlsOptions, () => {
          this.connected = true;
          logger.info('Syslog TLS forwarder connected', { host: this.host, port: this.port });
          resolve();
        });
        this.socket.on('error', (err) => {
          this.connected = false;
          logger.error('Syslog TLS connection error', { error: err.message });
          reject(err);
        });
        this.socket.on('close', () => {
          this.connected = false;
          logger.warn('Syslog TLS connection closed');
        });
      });
    }
  }

  formatCEF(event) {
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    const severity = this._mapCEFSeverity(event.severity);
    const signatureId = event.category || 'unknown';
    const name = (event.action || 'unknown_action').replace(/\|/g, '\\|');

    const extensions = [];
    if (event.actor_id) extensions.push(`suser=${this._escapeValue(event.actor_id)}`);
    if (event.actor_name) extensions.push(`sname=${this._escapeValue(event.actor_name)}`);
    if (event.actor_ip) extensions.push(`src=${event.actor_ip}`);
    if (event.target_id) extensions.push(`duser=${this._escapeValue(event.target_id)}`);
    if (event.target_name) extensions.push(`dname=${this._escapeValue(event.target_name)}`);
    if (event.target_type) extensions.push(`cs1=${this._escapeValue(event.target_type)} cs1Label=TargetType`);
    if (event.result) extensions.push(`outcome=${event.result}`);
    if (event.correlation_id) extensions.push(`externalId=${event.correlation_id}`);
    if (event.timestamp) extensions.push(`rt=${new Date(event.timestamp).getTime()}`);
    if (event.id) extensions.push(`cn1=${event.id} cn1Label=EventID`);

    return `CEF:0|OpenDirectory|AuditService|1.0|${signatureId}|${name}|${severity}|${extensions.join(' ')}`;
  }

  formatRFC5424(event) {
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    const severity = SEVERITY_MAP[event.severity] || 6;
    const pri = this.facility * 8 + severity;
    const timestamp = event.timestamp
      ? new Date(event.timestamp).toISOString()
      : new Date().toISOString();
    const hostname = process.env.HOSTNAME || 'opendirectory';
    const procId = process.pid;
    const msgId = event.category || '-';

    // Build structured data
    const sdParams = [];
    if (event.actor_id) sdParams.push(`actor="${this._escapeSD(event.actor_id)}"`);
    if (event.actor_name) sdParams.push(`actorName="${this._escapeSD(event.actor_name)}"`);
    if (event.target_id) sdParams.push(`target="${this._escapeSD(event.target_id)}"`);
    if (event.result) sdParams.push(`result="${this._escapeSD(event.result)}"`);
    if (event.correlation_id) sdParams.push(`correlationId="${this._escapeSD(event.correlation_id)}"`);

    const structuredData = sdParams.length > 0
      ? `[audit@48577 ${sdParams.join(' ')}]`
      : '-';

    const msg = event.action || '';

    return `<${pri}>1 ${timestamp} ${hostname} ${this.appName} ${procId} ${msgId} ${structuredData} ${msg}`;
  }

  formatLEEF(event) {
    // LEEF:Version|Vendor|Product|Version|EventID|
    const fields = [];
    if (event.actor_id) fields.push(`usrName=${event.actor_id}`);
    if (event.actor_ip) fields.push(`src=${event.actor_ip}`);
    if (event.target_id) fields.push(`dstName=${event.target_id}`);
    if (event.action) fields.push(`action=${event.action}`);
    if (event.severity) fields.push(`sev=${this._mapLEEFSeverity(event.severity)}`);
    if (event.result) fields.push(`outcome=${event.result}`);
    if (event.category) fields.push(`cat=${event.category}`);

    return `LEEF:2.0|OpenDirectory|AuditService|1.0|${event.id || '0'}|${fields.join('\t')}`;
  }

  async forward(event) {
    if (!this.connected && this.protocol !== 'udp') {
      try {
        await this.connect();
      } catch (err) {
        logger.error('Cannot forward event: syslog not connected', { error: err.message });
        return false;
      }
    }

    let message;
    switch (this.format) {
      case 'CEF':
        message = this.formatCEF(event);
        break;
      case 'LEEF':
        message = this.formatLEEF(event);
        break;
      case 'RFC5424':
        message = this.formatRFC5424(event);
        break;
      default:
        message = this.formatCEF(event);
    }

    try {
      await this._send(message);
      logger.debug('Event forwarded to syslog', { format: this.format, eventId: event.id });
      return true;
    } catch (err) {
      logger.error('Failed to forward event to syslog', { error: err.message, eventId: event.id });
      return false;
    }
  }

  async _send(message) {
    const buffer = Buffer.from(message + '\n', 'utf8');

    if (this.protocol === 'udp') {
      return new Promise((resolve, reject) => {
        if (!this.socket) {
          this.socket = dgram.createSocket('udp4');
          this.connected = true;
        }
        this.socket.send(buffer, 0, buffer.length, this.port, this.host, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    } else {
      return new Promise((resolve, reject) => {
        if (!this.socket || this.socket.destroyed) {
          return reject(new Error('Socket not connected'));
        }
        this.socket.write(buffer, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  }

  async close() {
    if (this.socket) {
      if (this.protocol === 'udp') {
        this.socket.close();
      } else {
        this.socket.destroy();
      }
      this.socket = null;
      this.connected = false;
      logger.info('Syslog forwarder closed');
    }
  }

  _mapCEFSeverity(severity) {
    const map = { critical: 10, error: 7, warning: 5, info: 3, debug: 1 };
    return map[severity] || 3;
  }

  _mapLEEFSeverity(severity) {
    const map = { critical: 10, error: 7, warning: 5, info: 3, debug: 1 };
    return map[severity] || 3;
  }

  _escapeValue(val) {
    if (typeof val !== 'string') return String(val);
    return val.replace(/\\/g, '\\\\').replace(/=/g, '\\=');
  }

  _escapeSD(val) {
    if (typeof val !== 'string') return String(val);
    return val.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\]/g, '\\]');
  }
}

module.exports = SyslogForwarder;
