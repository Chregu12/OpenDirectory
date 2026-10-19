'use strict';

/**
 * IPolicyRepository — domain interface for policy persistence.
 * Infrastructure implementations (e.g. PostgresPolicyRepository) must extend
 * this class and override every method.
 */
class IPolicyRepository {
  /** @returns {Promise<PolicyAggregate|null>} */
  async findById(id)                       { throw new Error('Not implemented'); }

  /** @returns {Promise<{policies: PolicyAggregate[], total: number}>} */
  async findAll(filters, pagination)       { throw new Error('Not implemented'); }

  /** @returns {Promise<PolicyAggregate>} */
  async save(policyAggregate)              { throw new Error('Not implemented'); }

  /** @returns {Promise<boolean>} */
  async delete(id)                         { throw new Error('Not implemented'); }

  /** @returns {Promise<PolicyAggregate|null>} */
  async activate(id)                       { throw new Error('Not implemented'); }

  /** @returns {Promise<PolicyAggregate|null>} */
  async deactivate(id)                     { throw new Error('Not implemented'); }
}

module.exports = IPolicyRepository;
