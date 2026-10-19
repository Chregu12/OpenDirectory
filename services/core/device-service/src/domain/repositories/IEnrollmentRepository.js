'use strict';

/**
 * IEnrollmentRepository — interface / contract for enrollment persistence.
 * Concrete implementations live under infrastructure/repositories/.
 */
class IEnrollmentRepository {
  /**
   * Find an enrollment by its id.
   * @param {string} id
   * @returns {Promise<EnrollmentAggregate|null>}
   */
  async findById(id) {
    throw new Error('IEnrollmentRepository.findById() not implemented');
  }

  /**
   * Return all enrollments, with optional filters.
   * @param {object} [filters]
   * @param {string} [filters.status]
   * @param {string} [filters.deviceId]
   * @returns {Promise<EnrollmentAggregate[]>}
   */
  async findAll(filters = {}) {
    throw new Error('IEnrollmentRepository.findAll() not implemented');
  }

  /**
   * Persist (create or update) an enrollment aggregate.
   * @param {EnrollmentAggregate} enrollment
   * @returns {Promise<void>}
   */
  async save(enrollment) {
    throw new Error('IEnrollmentRepository.save() not implemented');
  }

  /**
   * Remove an enrollment by id.
   * @param {string} id
   * @returns {Promise<void>}
   */
  async delete(id) {
    throw new Error('IEnrollmentRepository.delete() not implemented');
  }
}

module.exports = IEnrollmentRepository;
