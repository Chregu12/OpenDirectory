'use strict';

/**
 * Base class for choreography-based sagas over RabbitMQ.
 *
 * A saga is a sequence of steps where each step publishes a domain event
 * that triggers the next step. No central orchestrator — each service
 * reacts to events it cares about.
 *
 * Compensating transactions are triggered by failure events.
 */
class SagaBase {
  constructor(messageBus, logger) {
    this._bus = messageBus;
    this._log = logger || console;
    this._handlers = new Map(); // routingKey → handler fn
  }

  on(routingKey, handler) {
    this._handlers.set(routingKey, handler);
    return this;
  }

  async start(queueName, routingKeys) {
    if (!this._bus) {
      this._log.warn(`[Saga:${this.constructor.name}] No message bus — saga disabled`);
      return;
    }

    const trySubscribe = async () => {
      if (!this._bus.isConnected()) {
        setTimeout(trySubscribe, 5000);
        return;
      }
      try {
        await this._bus.subscribe(queueName, routingKeys, async (payload, rawMsg) => {
          const routingKey = rawMsg?.fields?.routingKey || payload?._meta?.routingKey;
          const handler = this._handlers.get(routingKey);
          if (handler) {
            try {
              await handler(payload);
            } catch (err) {
              this._log.warn(`[Saga:${this.constructor.name}] handler error for ${routingKey}: ${err.message}`);
              throw err; // causes NACK → dead letter on redelivery
            }
          }
        });
        this._log.info(`[Saga:${this.constructor.name}] started on queue '${queueName}'`);
      } catch (e) {
        this._log.warn(`[Saga:${this.constructor.name}] subscribe error: ${e.message} — retrying in 5s`);
        setTimeout(trySubscribe, 5000);
      }
    };

    setTimeout(trySubscribe, 3000);
  }

  publish(routingKey, payload) {
    if (!this._bus || !this._bus.isConnected()) return false;
    try {
      return this._bus.publish(routingKey, { ...payload, _saga: this.constructor.name });
    } catch (e) {
      this._log.warn(`[Saga:${this.constructor.name}] publish error: ${e.message}`);
      return false;
    }
  }
}

module.exports = SagaBase;
