const auditDb = require('../db');

class AuditService {
  async logSuccessfulAuth(userId, req, provider = 'local') {
    return auditDb.logAuditEvent({
      eventType: 'login_success',
      actor: userId,
      message: `User ${userId} logged in via ${provider}`,
      severity: 'info',
      ipAddress: req?.ip,
      metadata: { provider },
    });
  }

  async logFailedAuth(username, req, reason = '') {
    return auditDb.logAuditEvent({
      eventType: 'login_failed',
      actor: username,
      message: `Failed login for ${username}${reason ? ': ' + reason : ''}`,
      severity: 'warning',
      ipAddress: req?.ip,
      metadata: { reason },
    });
  }

  async logSecurityEvent(eventType, userId, req, metadata = {}) {
    return auditDb.logAuditEvent({
      eventType,
      actor: userId,
      message: `Security event: ${eventType} for ${userId}`,
      severity: eventType.includes('fail') || eventType.includes('block') ? 'warning' : 'info',
      ipAddress: req?.ip,
      metadata,
    });
  }

  async logUserEvent(eventType, userId, req, metadata = {}) {
    return auditDb.logAuditEvent({
      eventType,
      actor: userId,
      message: `User event: ${eventType} for user ${userId}`,
      severity: 'info',
      ipAddress: req?.ip,
      metadata,
    });
  }

  async logAdminAction(action, adminId, data, req) {
    return auditDb.logAuditEvent({
      eventType: `admin_${action}`,
      actor: adminId,
      target: data?.targetUserId,
      message: `Admin ${adminId} performed ${action}`,
      severity: 'info',
      ipAddress: req?.ip,
      metadata: data,
    });
  }

  async getLoginHistory(userId, limit = 20) {
    const events = await auditDb.getRecentEvents(limit * 3);
    return events
      .filter(e => e.event_type === 'login_success' || e.event_type === 'login_failed')
      .filter(e => !userId || e.actor === userId)
      .slice(0, limit);
  }

  async getSecurityEvents(limit = 50) {
    const events = await auditDb.getRecentEvents(limit * 2);
    return events
      .filter(e => e.severity === 'warning' || e.severity === 'error' || e.event_type.startsWith('admin_'))
      .slice(0, limit);
  }
}

module.exports = AuditService;
