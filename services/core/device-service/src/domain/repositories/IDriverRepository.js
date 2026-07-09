'use strict';

// Interface / contract — JavaScript convention: throw NotImplementedError
class IDriverRepository {
  async findById(driverId)                       { throw new Error('Not implemented'); }
  async findAll(filters)                          { throw new Error('Not implemented'); }
  async save(driverAggregate)                     { throw new Error('Not implemented'); }
  async delete(driverId)                          { throw new Error('Not implemented'); }
  async exists(driverId)                          { throw new Error('Not implemented'); }
  // Persists the raw driver binary and returns { filePath, destFilename }.
  async saveFile(driverId, filename, fileBuffer)  { throw new Error('Not implemented'); }
}

module.exports = IDriverRepository;
