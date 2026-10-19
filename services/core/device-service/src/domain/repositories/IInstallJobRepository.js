'use strict';

class IInstallJobRepository {
  async findById(jobId)             { throw new Error('Not implemented'); }
  async findByDevice(deviceId)      { throw new Error('Not implemented'); }
  async save(installJobAggregate)   { throw new Error('Not implemented'); }
  async findPendingForDevice(deviceId) { throw new Error('Not implemented'); }
}

module.exports = IInstallJobRepository;
