'use strict';
const { randomUUID } = require('crypto');
const InstallJobAggregate = require('../domain/aggregates/InstallJobAggregate');

// index.js wires the live install-app / install-jobs / install-jobs/:id/result
// routes to the "…Record"/"…Result" methods below (see class-level note
// further down) rather than to createInstallJob/completeJob/getJobsForDevice
// above them. Those two families deliberately have different contracts:
//
//   createInstallJob()      throws "Device not found" for an unknown device;
//                            the live route returns 200 regardless (agents
//                            enroll asynchronously, so a device unknown to
//                            this service's `devices` table at job-creation
//                            time is a normal, expected occurrence, not an
//                            error).
//   createInstallJobRecord() never throws on an unknown device — ported 1:1
//                            from the old index.js global.__od_installJobs
//                            logic so the swap is behavior-preserving. See
//                            src/__tests__/deviceInstallCharacterization.test.js
//                            for the golden-master HTTP coverage that pins
//                            this contract across the refactor.
class InstallApplicationService {
  constructor({ deviceRepository, installJobRepository, messageBus, cache, logger }) {
    this._deviceRepo = deviceRepository;
    this._jobRepo = installJobRepository;
    this._bus = messageBus;
    this._cache = cache;
    this._log = logger || console;

    // Backing store for the live createInstallJobRecord/getJobsForDeviceRecord/
    // recordInstallResult methods — a private replacement for the old
    // `global.__od_installJobs` Map. This (not installJobRepository/Postgres)
    // remains the single source of truth read back by the HTTP layer; see the
    // "DB durability, not DB authority" note above createInstallJobRecord().
    this._liveJobs = new Map();
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

  // ── Live install endpoints — ported 1:1 from index.js, see class note ────
  //
  // DB durability, not DB authority: install_jobs.device_id carries a real
  // FOREIGN KEY REFERENCES devices(id) (see migrations/004_install_jobs.sql).
  // The live install-app route intentionally succeeds for a deviceId that
  // was never enrolled (golden master: "succeeds even for a deviceId that
  // was never enrolled"), so an unconditional Postgres write would either
  // (a) violate that FK and turn a 200 into a 500 in production, or
  // (b) require dropping the FK / relaxing the schema — a real, riskier
  // behavior change we are not making as a side effect of a wiring pass.
  // So writes below go DB-first on a best-effort basis (never awaited by the
  // caller for its success, never allowed to throw outward) purely for
  // durability/audit, while `this._liveJobs` — populated synchronously,
  // exactly like the old global Map — remains what getJobsForDeviceRecord/
  // recordInstallResult actually read. That keeps the observable HTTP
  // contract byte-for-byte identical to the pre-wiring behavior.

  async createInstallJobRecord({ deviceId, appId, appName, packageId, format, version }) {
    const jobId = `install-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = {
      jobId, deviceId, appId, appName, packageId, format, version,
      status: 'queued', queuedAt: new Date().toISOString(),
    };
    this._liveJobs.set(jobId, record);

    if (this._jobRepo) {
      try {
        await this._jobRepo.save(InstallJobAggregate.create({ jobId, deviceId, appId, appName, packageId, format, version }));
      } catch (e) {
        // Expected/benign for unenrolled devices (FK violation) or when
        // Postgres is unavailable — the in-memory record above is authoritative.
        this._log.warn(`install_jobs durability write failed (non-fatal): ${e.message}`);
      }
    }

    return record;
  }

  getJobsForDeviceRecord(deviceId) {
    return [...this._liveJobs.values()].filter(j => j.deviceId === deviceId);
  }

  recordInstallResult(jobId, { status, output, error }) {
    const job = this._liveJobs.get(jobId);
    if (!job) return null;
    Object.assign(job, { status, output, error, completedAt: new Date().toISOString() });

    if (this._jobRepo) {
      // Fire-and-forget, mirroring the fire-and-forget eventBus.publish()
      // call the caller (index.js#reportInstallResult) makes right after this.
      this._jobRepo.findById(jobId)
        .then(agg => {
          if (!agg) return null; // e.g. the create-time write above failed
          if (status === 'success') agg.complete(job.version);
          else agg.fail(error);
          return this._jobRepo.save(agg);
        })
        .catch(e => this._log.warn(`install_jobs result durability write failed (non-fatal): ${e.message}`));
    }

    return job;
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
