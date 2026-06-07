'use strict';

const logger = require('../utils/logger');

class EnrollmentService {
  constructor(db, eventBus) {
    this.db = db;
    this.eventBus = eventBus;
  }

  async initiateEnrollment(data) {
    const id = `enr-${Date.now()}`;
    const enrollment = await this.db.insert('enrollments', {
      id,
      ...data,
      status: 'pending',
      initiatedAt: new Date().toISOString()
    });
    this.eventBus.emit('enrollment:initiated', { enrollment });
    return enrollment;
  }

  async completeEnrollment(enrollmentId, deviceData) {
    const enrollment = await this.db.findById('enrollments', enrollmentId);
    if (!enrollment) throw Object.assign(new Error('Enrollment not found'), { statusCode: 404 });
    const updated = await this.db.update('enrollments', enrollmentId, {
      status: 'completed',
      completedAt: new Date().toISOString(),
      deviceId: deviceData.deviceId
    });
    this.eventBus.emit('device:enrolled', { device: deviceData, enrollment: updated });
    return updated;
  }

  async verifyEnrollment(token) {
    const enrollments = await this.db.find('enrollments', { token });
    return enrollments[0] || null;
  }

  async getEnrollmentStatus(enrollmentId) {
    return this.db.findById('enrollments', enrollmentId);
  }

  async approveEnrollment(enrollmentId) {
    const updated = await this.db.update('enrollments', enrollmentId, {
      status: 'approved',
      approvedAt: new Date().toISOString()
    });
    this.eventBus.emit('enrollment:approved', { enrollmentId });
    return updated;
  }

  async rejectEnrollment(enrollmentId, reason) {
    const updated = await this.db.update('enrollments', enrollmentId, {
      status: 'rejected',
      rejectedAt: new Date().toISOString(),
      rejectionReason: reason
    });
    this.eventBus.emit('enrollment:rejected', { enrollmentId, reason });
    return updated;
  }

  async getPendingCount() {
    return this.db.count('enrollments', { status: 'pending' });
  }
}

module.exports = EnrollmentService;
