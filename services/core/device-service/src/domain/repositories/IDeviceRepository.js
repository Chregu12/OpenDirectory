'use strict';

// Interface / contract — JavaScript convention: throw NotImplementedError
class IDeviceRepository {
  async findById(deviceId)         { throw new Error('Not implemented'); }
  async findAll(filters)           { throw new Error('Not implemented'); }
  async findByOrg(orgId, filters)  { throw new Error('Not implemented'); }
  async save(deviceAggregate)      { throw new Error('Not implemented'); }
  async delete(deviceId)           { throw new Error('Not implemented'); }
  async exists(deviceId)           { throw new Error('Not implemented'); }
}

module.exports = IDeviceRepository;
