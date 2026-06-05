'use strict';
const { randomUUID } = require('crypto');
const InstallJobAggregate = require('../domain/aggregates/InstallJobAggregate');

class InstallApplicationService {
  constructor({ deviceRepository, installJobRepository, messageBus, cache, logger }) {
    this._deviceRepo = deviceRepository;
    this._jobRepo = installJobRepository;
    this._bus = messageBus;
    this._cache = cache;
    this._log = logger || console;
  }

  async createInstallJob({ deviceId, appId, appName, packageId, format, version, downloadUrl, checksum }) {
    const device = await this._deviceRepo.findById(deviceId);
    if (!device) throw new Error(`Device not found: ${deviceId}`);

    const job = InstallJobAggregate.create({
      jobId: randomUUID(), deviceId, appId, appName, packageId, format, version,
    });

    await this._jobRepo.save(job);
    await this._publishDomainEvents(job);

    return {
      jobId: job.jobId,
      command: {
        type: 'store_install',
        jobId: job.jobId,
        appId, appName, packageId, format, version, downloadUrl, checksum,
        installType: 'internal',
      },
    };
  }

  async completeJob(jobId, { success, error, version }) {
    const job = await this._jobRepo.findById(jobId);
    if (!job) throw new Error(`Install job not found: ${jobId}`);

    if (success) {
      job.complete(version);
    } else {
      job.fail(error);
    }

    await this._jobRepo.save(job);
    await this._publishDomainEvents(job);
    return job;
  }

  async getJobsForDevice(deviceId) {
    return this._jobRepo.findByDevice(deviceId);
  }

  async _publishDomainEvents(aggregate) {
    if (!this._bus || !this._bus.isConnected()) return;
    const events = aggregate.getAndClearDomainEvents();
    for (const event of events) {
      try {
        this._bus.publish(event.type, { ...event.payload, _source: 'device-service' });
      } catch (e) {
        this._log.warn(`Failed to publish domain event ${event.type}: ${e.message}`);
      }
    }
  }
}

module.exports = InstallApplicationService;
