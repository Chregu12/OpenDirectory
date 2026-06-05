'use strict';
class IUserRepository {
  async findById(userId)           { throw new Error('Not implemented'); }
  async findByUsername(username)   { throw new Error('Not implemented'); }
  async findByEmail(email)         { throw new Error('Not implemented'); }
  async save(userAggregate)        { throw new Error('Not implemented'); }
  async delete(userId)             { throw new Error('Not implemented'); }
  async exists(userId)             { throw new Error('Not implemented'); }
  async findAll(filters)           { throw new Error('Not implemented'); }
}
module.exports = IUserRepository;
