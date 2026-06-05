'use strict';

/**
 * ComplianceSaga — choreography-based saga über RabbitMQ.
 *
 * Trigger: device.enrolled → evaluate compliance → publish result
 * Trigger: policy.created/updated → re-evaluate affected devices
 *
 * Kein zentraler Orchestrator — jedes Event löst den nächsten Schritt aus.
 */
class ComplianceSaga {
  constructor({ messageBus, policyApplicationService, db, logger }) {
    this._bus = messageBus;
    this._svc = policyApplicationService;
    this._db = db;
    this._log = logger || console;
  }

  start() {
    if (!this._bus) return;

    // When a device enrolls → run compliance check
    this._subscribeOrRetry('compliance.device-check', ['device.enrolled'], async (payload) => {
      this._log.info(`[ComplianceSaga] Device enrolled: ${payload.deviceId} — running compliance check`);
      try {
        await this._svc.evaluateCompliance({
          deviceId: payload.deviceId,
          devicePlatform: payload.platform,
          deviceProperties: payload.properties || {},
        });
      } catch (e) {
        this._log.warn(`[ComplianceSaga] Compliance check failed for ${payload.deviceId}: ${e.message}`);
      }
    });

    // When a policy changes → mark all enrolled devices for re-evaluation
    this._subscribeOrRetry('compliance.policy-change', ['policy.created', 'policy.updated'], async (payload) => {
      this._log.info(`[ComplianceSaga] Policy changed: ${payload.policyId} — publishing re-evaluation trigger`);
      try {
        const devices = await this._db.query(
          "SELECT id, platform FROM devices WHERE status = 'active' LIMIT 1000"
        );
        for (const device of devices.rows) {
          // Publish re-evaluation event for each device (batched, fire-and-forget)
          if (this._bus.isConnected()) {
            this._bus.publish('device.compliance.recheck', {
              deviceId: device.id,
              platform: device.platform,
              reason: `policy_${payload.policyId}_changed`,
              _source: 'policy-service',
            });
          }
        }
      } catch (e) {
        this._log.warn(`[ComplianceSaga] Policy change re-evaluation failed: ${e.message}`);
      }
    });

    this._log.info('[ComplianceSaga] started — listening on device.enrolled, policy.created/updated');
  }

  _subscribeOrRetry(queueName, routingKeys, handler) {
    const trySubscribe = async () => {
      if (!this._bus.isConnected()) {
        setTimeout(trySubscribe, 5000);
        return;
      }
      try {
        await this._bus.subscribe(queueName, routingKeys, async (payload) => {
          await handler(payload);
        });
      } catch (e) {
        this._log.warn(`[ComplianceSaga] subscribe failed for ${queueName}: ${e.message}`);
        setTimeout(trySubscribe, 5000);
      }
    };
    setTimeout(trySubscribe, 3000); // Delay to let bus connect first
  }
}

module.exports = ComplianceSaga;
