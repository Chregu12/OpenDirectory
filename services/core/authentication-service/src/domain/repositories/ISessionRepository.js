'use strict';
class ISessionRepository {
  async findById(sessionId)         { throw new Error('Not implemented'); }
  async findByToken(token)          { throw new Error('Not implemented'); }
  async findActiveByUser(userId)    { throw new Error('Not implemented'); }
  async save(sessionAggregate)      { throw new Error('Not implemented'); }
  async revokeAllForUser(userId)    { throw new Error('Not implemented'); }
}
module.exports = ISessionRepository;
