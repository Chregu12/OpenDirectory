'use strict';

// Interface / contract — JavaScript convention: throw NotImplementedError
class IHardwareReportRepository {
  async save(key, report)                    { throw new Error('Not implemented'); }
  async findByKey(key)                       { throw new Error('Not implemented'); }
  async saveRecommendations(key, recs)       { throw new Error('Not implemented'); }
  async findRecommendations(key)             { throw new Error('Not implemented'); }
}

module.exports = IHardwareReportRepository;
