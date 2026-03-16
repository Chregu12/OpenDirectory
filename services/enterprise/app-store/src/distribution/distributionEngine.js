'use strict';

const INSTALL_STATUSES = ['queued', 'downloading', 'installing', 'completed', 'failed'];

class DistributionEngine {
  constructor(pool, installTracker, licenseManager, catalogManager, amqpChannel, logger) {
    this.pool = pool;
    this.installTracker = installTracker;
    this.licenseManager = licenseManager;
    this.catalogManager = catalogManager;
    this.amqpChannel = amqpChannel;
    this.logger = logger;
    this.wss = null;
  }

  /**
   * Attach WebSocket server for real-time communication with agents.
   */
  setWss(wss) {
    this.wss = wss;
  }

  /**
   * Request installation of an app on a device.
   */
  async requestInstall(appId, deviceId, targetVersion = null) {
    const app = await this.catalogManager.getApp(appId);
    if (!app) throw new Error('App not found');

    // Check license availability
    const availability = await this.licenseManager.checkAvailability(appId);
    if (!availability.available) {
      throw new Error('No available licenses for this app');
    }

    // Allocate license
    await this.licenseManager.allocateLicense(appId, deviceId);

    // Create install job
    const job = await this.installTracker.createJob({
      appId,
      deviceId,
      action: 'install',
      version: targetVersion,
    });

    // Send install command to agent via WebSocket
    this._sendToDevice(deviceId, {
      type: 'install',
      jobId: job.id,
      appId,
      appName: app.name,
      version: targetVersion,
      platforms: app.platforms,
    });

    // Publish event
    await this._publishEvent('app.install_requested', {
      jobId: job.id,
      appId,
      deviceId,
      appName: app.name,
      version: targetVersion,
    });

    this.logger.info('Install requested', { jobId: job.id, appId, deviceId });
    return job;
  }

  /**
   * Request uninstallation of an app from a device.
   */
  async requestUninstall(appId, deviceId) {
    const app = await this.catalogManager.getApp(appId);
    if (!app) throw new Error('App not found');

    // Create uninstall job
    const job = await this.installTracker.createJob({
      appId,
      deviceId,
      action: 'uninstall',
    });

    // Send uninstall command to agent
    this._sendToDevice(deviceId, {
      type: 'uninstall',
      jobId: job.id,
      appId,
      appName: app.name,
      platforms: app.platforms,
    });

    // Release license
    await this.licenseManager.releaseLicense(appId, deviceId);

    // Publish event
    await this._publishEvent('app.uninstall_requested', {
      jobId: job.id,
      appId,
      deviceId,
      appName: app.name,
    });

    this.logger.info('Uninstall requested', { jobId: job.id, appId, deviceId });
    return job;
  }

  /**
   * Request update of an app on a device to a specific version.
   */
  async requestUpdate(appId, deviceId, targetVersion) {
    const app = await this.catalogManager.getApp(appId);
    if (!app) throw new Error('App not found');

    const job = await this.installTracker.createJob({
      appId,
      deviceId,
      action: 'update',
      version: targetVersion,
    });

    this._sendToDevice(deviceId, {
      type: 'update',
      jobId: job.id,
      appId,
      appName: app.name,
      version: targetVersion,
      platforms: app.platforms,
    });

    await this._publishEvent('app.update_requested', {
      jobId: job.id,
      appId,
      deviceId,
      appName: app.name,
      version: targetVersion,
    });

    this.logger.info('Update requested', { jobId: job.id, appId, deviceId, targetVersion });
    return job;
  }

  /**
   * Bulk install: install an app on all assigned devices.
   */
  async bulkInstall(appId, deviceIds, targetVersion = null) {
    const results = [];
    for (const deviceId of deviceIds) {
      try {
        const job = await this.requestInstall(appId, deviceId, targetVersion);
        results.push({ deviceId, jobId: job.id, status: 'queued' });
      } catch (err) {
        results.push({ deviceId, error: err.message, status: 'failed' });
        this.logger.warn('Bulk install failed for device', { appId, deviceId, error: err.message });
      }
    }
    return results;
  }

  /**
   * Handle incoming messages from device agents via WebSocket.
   */
  async handleAgentMessage(ws, message) {
    const { type, jobId, status, progress, error } = message;

    if (type === 'install_progress' || type === 'update_progress') {
      if (jobId && status) {
        await this.installTracker.updateJobStatus(jobId, {
          status,
          progress: progress || 0,
          error: error || null,
        });

        // Broadcast progress to admin listeners
        this._broadcastProgress(jobId, { status, progress, error });

        // If completed or failed, publish appropriate event
        if (status === 'completed') {
          const job = await this.installTracker.getJob(jobId);
          if (job) {
            const eventType = job.action === 'install' ? 'app.installed' :
                              job.action === 'uninstall' ? 'app.uninstalled' :
                              'app.updated';
            await this._publishEvent(eventType, {
              jobId,
              appId: job.app_id,
              deviceId: job.device_id,
              action: job.action,
            });
          }
        } else if (status === 'failed') {
          const job = await this.installTracker.getJob(jobId);
          if (job) {
            await this._publishEvent('app.failed', {
              jobId,
              appId: job.app_id,
              deviceId: job.device_id,
              action: job.action,
              error: error || 'Unknown error',
            });
            // Release license on failed install
            if (job.action === 'install') {
              await this.licenseManager.releaseLicense(job.app_id, job.device_id);
            }
          }
        }
      }
    } else if (type === 'heartbeat') {
      ws.send(JSON.stringify({ type: 'heartbeat_ack', timestamp: Date.now() }));
    }
  }

  /**
   * Send a message to a specific device via WebSocket.
   */
  _sendToDevice(deviceId, message) {
    if (!this.wss) {
      this.logger.warn('WebSocket server not available, cannot send to device', { deviceId });
      return false;
    }

    let sent = false;
    this.wss.clients.forEach((client) => {
      if (client._deviceId === deviceId && client.readyState === 1) {
        client.send(JSON.stringify(message));
        sent = true;
      }
    });

    if (!sent) {
      this.logger.warn('Device not connected via WebSocket, install will be queued', { deviceId });
    }
    return sent;
  }

  /**
   * Broadcast install progress to all connected admin clients.
   */
  _broadcastProgress(jobId, progressData) {
    if (!this.wss) return;

    const message = JSON.stringify({
      type: 'install_progress_update',
      jobId,
      ...progressData,
      timestamp: Date.now(),
    });

    this.wss.clients.forEach((client) => {
      if (client.readyState === 1 && client._role === 'admin') {
        client.send(message);
      }
    });
  }

  /**
   * Publish event to RabbitMQ.
   */
  async _publishEvent(routingKey, data) {
    if (!this.amqpChannel) return;

    try {
      const message = Buffer.from(JSON.stringify({
        event: routingKey,
        timestamp: new Date().toISOString(),
        data,
      }));
      this.amqpChannel.publish('opendirectory.events', routingKey, message, {
        persistent: true,
        contentType: 'application/json',
      });
    } catch (err) {
      this.logger.error('Failed to publish event', { routingKey, error: err.message });
    }
  }
}

module.exports = { DistributionEngine, INSTALL_STATUSES };
