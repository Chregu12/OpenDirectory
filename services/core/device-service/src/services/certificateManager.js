'use strict';

const logger = require('../utils/logger');

class CertificateManager {
  constructor(db, eventBus) {
    this.db = db;
    this.eventBus = eventBus;
  }

  async getCertificates({ page = 1, limit = 50 } = {}) {
    const certs = await this.db.find('certificates', {});
    const total = certs.length;
    const start = (page - 1) * limit;
    return { certificates: certs.slice(start, start + limit), pagination: { page, limit, total } };
  }

  async issueCertificate(data) {
    const id = `cert-${Date.now()}`;
    const cert = await this.db.insert('certificates', {
      ...data,
      id,
      status: 'active',
      issuedAt: new Date().toISOString(),
      expiresAt: data.expiresAt || new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString()
    });
    this.eventBus.emit('certificate:issued', { certificate: cert });
    return cert;
  }

  async renewCertificate(certId) {
    const cert = await this.db.findById('certificates', certId);
    if (!cert) throw Object.assign(new Error('Certificate not found'), { statusCode: 404 });
    const updated = await this.db.update('certificates', certId, {
      renewedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString()
    });
    this.eventBus.emit('certificate:renewed', { certificate: updated });
    return updated;
  }

  async revokeCertificate(certId, reason) {
    const cert = await this.db.findById('certificates', certId);
    if (!cert) throw Object.assign(new Error('Certificate not found'), { statusCode: 404 });
    const updated = await this.db.update('certificates', certId, {
      status: 'revoked',
      revokedAt: new Date().toISOString(),
      revocationReason: reason
    });
    this.eventBus.emit('certificate:revoked', { certificate: updated });
    return updated;
  }

  async checkCertificateRenewal() {
    const soon = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
    const certs = await this.db.find('certificates', { status: 'active' });
    for (const cert of certs) {
      if (cert.expiresAt && cert.expiresAt < soon) {
        logger.warn('Certificate expiring soon', { certId: cert.id, expiresAt: cert.expiresAt });
        this.eventBus.emit('certificate:expiring_soon', { certificate: cert });
      }
    }
  }
}

module.exports = CertificateManager;
