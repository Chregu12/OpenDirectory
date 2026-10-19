'use strict';

/**
 * IBlueprintRepository — domain interface for blueprint persistence.
 * Infrastructure implementations (e.g. PostgresBlueprintRepository) must extend
 * this class and override every method.
 */
class IBlueprintRepository {
  /** @returns {Promise<BlueprintAggregate|null>} */
  async findById(id)                        { throw new Error('Not implemented'); }

  /** @returns {Promise<{blueprints: BlueprintAggregate[], total: number}>} */
  async findAll(filters, pagination)        { throw new Error('Not implemented'); }

  /** @returns {Promise<BlueprintAggregate>} */
  async save(blueprintAggregate)            { throw new Error('Not implemented'); }

  /** @returns {Promise<boolean>} */
  async delete(id)                          { throw new Error('Not implemented'); }
}

module.exports = IBlueprintRepository;
