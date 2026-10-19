# OpenDirectory Message Bus

RabbitMQ is used as the internal event bus for asynchronous, decoupled communication between
OpenDirectory services. All services connect to a single broker at `amqp://rabbitmq:5672`.

---

## Exchanges

| Exchange name           | Type    | Durable | Purpose                                 |
|-------------------------|---------|---------|-----------------------------------------|
| `opendirectory.events`  | `topic` | yes     | All domain events from every service    |
| `opendirectory.commands`| `direct`| yes     | Point-to-point commands to devices      |
| `opendirectory.dlx`     | `topic` | yes     | Dead-letter exchange for failed messages|

---

## Routing Keys and Topology

### Domain events (exchange: `opendirectory.events`)

| Routing key                     | Producer              | Consumers                              |
|---------------------------------|-----------------------|----------------------------------------|
| `system.backup.started`         | backup-service        | monitoring-service                     |
| `system.backup.completed`       | backup-service        | monitoring-service, notification-service|
| `system.backup.failed`          | backup-service        | monitoring-service, notification-service|
| `device.enrolled`               | device-service        | policy-service, monitoring-service     |
| `device.compliance.changed`     | device-service        | policy-service, notification-service   |
| `device.command.result`         | device-service        | monitoring-service                     |
| `auth.login.success`            | authentication-service| monitoring-service, audit-service      |
| `auth.login.failed`             | authentication-service| monitoring-service, audit-service      |
| `auth.token.revoked`            | authentication-service| all services (invalidate caches)       |
| `identity.user.created`         | identity-service      | notification-service                   |
| `identity.user.updated`         | identity-service      | policy-service                         |
| `identity.user.deleted`         | identity-service      | all services (cleanup)                 |
| `policy.applied`                | policy-service        | monitoring-service, audit-service      |
| `policy.violation`              | policy-service        | notification-service, monitoring-service|

### Device command queue (exchange: `opendirectory.commands`)

Device commands use a dedicated queue per device to guarantee ordered delivery.

| Queue pattern          | Routing key              | Producer       | Consumer       |
|------------------------|--------------------------|----------------|----------------|
| `device.cmd.<deviceId>`| `device.<deviceId>`      | policy-service | device-service |

---

## Dead Letter Queue Configuration

Messages that are rejected, expire, or exceed the retry count are routed to the dead-letter
exchange `opendirectory.dlx` with the original routing key preserved.

To configure a queue with dead-lettering, declare it with these arguments:

```js
await channel.assertQueue('my.queue', {
  durable: true,
  arguments: {
    'x-dead-letter-exchange': 'opendirectory.dlx',
    'x-message-ttl': 86400000,  // 24 hours
    'x-max-retries': 3,
  },
});
```

Dead-lettered messages land in `opendirectory.dlx` and should be monitored via the management UI.

---

## How to Add a New Publisher

1. Add `amqplib` to the service's `package.json` if not already present.
2. Copy the `connectBus` / `publishEvent` pattern:

```js
let _amqpChannel = null;

async function connectBus() {
  const amqplib = require('amqplib');
  try {
    const conn = await amqplib.connect(process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672');
    conn.on('error', () => { _amqpChannel = null; });
    conn.on('close', () => { _amqpChannel = null; setTimeout(connectBus, 5000); });
    const ch = await conn.createChannel();
    await ch.assertExchange('opendirectory.events', 'topic', { durable: true });
    _amqpChannel = ch;
    console.log('[my-service] RabbitMQ connected');
  } catch (e) {
    console.warn('[my-service] RabbitMQ unavailable:', e.message);
    setTimeout(connectBus, 10000);
  }
}

function publishEvent(routingKey, payload) {
  if (!_amqpChannel) return;
  try {
    _amqpChannel.publish(
      'opendirectory.events',
      routingKey,
      Buffer.from(JSON.stringify({
        ...payload,
        _timestamp: new Date().toISOString(),
        _source: 'my-service',
      })),
      { persistent: true }
    );
  } catch (_) {}
}
```

3. Call `connectBus()` in your service's startup function.
4. Call `publishEvent('my.routing.key', { ...data })` wherever the event occurs.
5. Add `RABBITMQ_URL` to the service's environment in `docker-compose.prod.yml` and the
   corresponding Helm deployment template.
6. Document the new routing key in the table above.

---

## How to Add a New Subscriber

```js
async function subscribeToEvents() {
  const amqplib = require('amqplib');
  try {
    const conn = await amqplib.connect(process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672');
    const ch = await conn.createChannel();

    // Declare the exchange (idempotent)
    await ch.assertExchange('opendirectory.events', 'topic', { durable: true });

    // Declare a durable queue for this service
    const { queue } = await ch.assertQueue('my-service.events', {
      durable: true,
      arguments: {
        'x-dead-letter-exchange': 'opendirectory.dlx',
      },
    });

    // Bind to the routing keys you care about (wildcards supported)
    await ch.bindQueue(queue, 'opendirectory.events', 'device.#');
    await ch.bindQueue(queue, 'opendirectory.events', 'auth.login.*');

    // Set prefetch to avoid overwhelming the consumer
    ch.prefetch(10);

    ch.consume(queue, async (msg) => {
      if (!msg) return;
      try {
        const payload = JSON.parse(msg.content.toString());
        console.log('[my-service] received event:', msg.fields.routingKey, payload);
        // ... process event ...
        ch.ack(msg);
      } catch (err) {
        console.error('[my-service] event processing error:', err.message);
        // nack without requeue — sends to DLX after max-retries
        ch.nack(msg, false, false);
      }
    });

    console.log('[my-service] subscribed to RabbitMQ events');
  } catch (e) {
    console.warn('[my-service] RabbitMQ subscription failed:', e.message);
    setTimeout(subscribeToEvents, 10000);
  }
}
```

---

## Device Command Queue Pattern

Device commands require strict ordering and guaranteed delivery per device.  
The pattern uses one queue per device and a `direct` exchange:

```
policy-service  --[opendirectory.commands / device.<deviceId>]--> device.cmd.<deviceId> --> device-service
```

**Publishing a command (policy-service side):**

```js
await ch.assertExchange('opendirectory.commands', 'direct', { durable: true });
await ch.assertQueue(`device.cmd.${deviceId}`, {
  durable: true,
  arguments: { 'x-dead-letter-exchange': 'opendirectory.dlx' },
});
await ch.bindQueue(`device.cmd.${deviceId}`, 'opendirectory.commands', `device.${deviceId}`);

ch.publish(
  'opendirectory.commands',
  `device.${deviceId}`,
  Buffer.from(JSON.stringify({ command: 'lock', payload: {}, _timestamp: new Date().toISOString() })),
  { persistent: true }
);
```

**Consuming commands (device-service side):**

```js
ch.consume(`device.cmd.${deviceId}`, async (msg) => {
  const { command, payload } = JSON.parse(msg.content.toString());
  await handleDeviceCommand(deviceId, command, payload);
  ch.ack(msg);
});
```

---

## Monitoring: RabbitMQ Management UI

The RabbitMQ management plugin is enabled on port `15672`.

**Docker Compose (local/prod):**

```
http://localhost:15672
```

Credentials are set via `RABBITMQ_USER` / `RABBITMQ_PASS` environment variables
(default: `opendirectory` / `changeme` — **always override in production**).

**Kubernetes (port-forward):**

```bash
kubectl port-forward svc/rabbitmq 15672:15672 -n opendirectory
# then open http://localhost:15672
```

**Key things to monitor:**

- Queue depths (unacknowledged / ready messages)
- Dead-letter queue (`opendirectory.dlx`) — non-zero depth indicates processing failures
- Memory and disk alarms — RabbitMQ will block publishers when thresholds are exceeded
- Connection count — each service should maintain one persistent connection

**Prometheus metrics** are available via the RabbitMQ Prometheus plugin on port `15692/metrics`
if the `rabbitmq_prometheus` plugin is enabled.
