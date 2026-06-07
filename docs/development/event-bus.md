# Event Bus

OpenDirectory uses a pluggable event bus for all inter-service communication. The implementation lives in `packages/grpc-event-bus/` and is published as the internal package `@opendirectory/grpc-event-bus`.

## Package location

```
packages/grpc-event-bus/
  src/
    index.js             # exports EventBusClient, EventBusServer, loadConfig, createTransport
    EventBusClient.js    # consumer-facing client
    EventBusServer.js    # gRPC relay server (used by the event-bus platform service)
    config.js            # loadConfig() — merges env vars and constructor overrides
    transports/
      RabbitMQTransport.js
      GrpcTransport.js
      MemoryTransport.js
      index.js           # createTransport() factory
```

## Transports

| Transport | When to use |
|---|---|
| `memory` | Tests — in-process, no broker required |
| `rabbitmq` | Development and production — RabbitMQ on `amqp://opendirectory:changeme@rabbitmq:5672/` |
| `grpc` | Inter-service relay through the `event-bus` platform service on `event-bus:50050` |

The transport is selected by the `EVENT_BUS_TRANSPORT` environment variable, or by passing `transport` in the constructor options. Defaults to `rabbitmq`.

## EventBusClient API

### Constructor

```js
const { EventBusClient } = require('@opendirectory/grpc-event-bus');

const client = new EventBusClient({
  source: 'my-service',       // sets _source tag on every published message
  transport: 'rabbitmq',      // 'rabbitmq' | 'grpc' | 'memory'
  // Memory-transport options (tests only):
  shared: true,               // share subscription registry across instances
  sharedKey: 'test',          // key identifying the shared bus instance
});
```

All constructor options are overrides; unset values fall back to environment variables and then to defaults (see `config.js`).

### connect()

```js
await client.connect();
```

Must be called once before `publish` or `subscribe`. Resolves when the initial connection is established. Reconnection runs in the background automatically.

### publish(routingKey, payload)

```js
await client.publish('device.enrolled', { deviceId: 'abc', platform: 'macos' });
```

The payload is augmented with `_source` (service name) and `_ts` (Unix ms timestamp) before delivery.

In services, always use the fire-and-forget pattern to prevent an event bus failure from crashing request handlers:

```js
function publish(routingKey, payload) {
  _bus.publish(routingKey, payload).catch(() => {});
}
```

### subscribe(queueName, patterns, handler)

```js
await client.subscribe(
  'my-service-queue',              // durable queue name
  ['device.*', 'policy.#'],        // AMQP wildcard patterns
  async (payload, { routingKey, ack, nack }) => {
    console.log(`Received ${routingKey}`, payload);
    // ack() / nack() are no-ops on MemoryTransport
  }
);
```

Pattern syntax:
- `*` — matches exactly one routing-key segment (e.g. `device.*` matches `device.enrolled`)
- `#` — matches zero or more segments (e.g. `device.#` matches `device.enrolled` and `device.install.job.created`)

### close()

```js
await client.close();
```

Gracefully closes the connection. Call this in SIGTERM/SIGINT handlers.

### Static helpers

```js
// Create and connect in one call:
const client = await EventBusClient.create({ source: 'my-service' });

// Singleton instance (shared across multiple requires in the same process):
const client = EventBusClient.getInstance({ source: 'my-service' });
```

## Standard service pattern

Every service uses the same 4-line block to initialise the bus. This pattern tolerates the package not yet being installed (falls back to the local source path), which matters during development before `npm install` has run:

```js
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();

const _bus = new EventBusClient({ source: 'my-service' });

async function connectBus() { await _bus.connect(); }

function publish(routingKey, payload) {
  _bus.publish(routingKey, payload).catch(() => {});
}
```

Call `connectBus()` inside the `start()` function (wrapped in a try/catch so a missing broker does not prevent the service from starting):

```js
async function start() {
  // ... db migrations, etc.
  try { await connectBus(); } catch (e) { logger.warn('[bus] startup connect error: ' + e.message); }
  app.listen(PORT, () => logger.info(`my-service running on port ${PORT}`));
}
```

## Event routing registry

All routing keys, publishers, and subscribers are declared in `/config/event-routing.yaml`. This file is the authoritative source of truth for what events exist and who owns them.

The config file also sets the default transport and connection parameters:

```yaml
event_bus:
  transport: rabbitmq
  grpc_address: event-bus:50050
  grpc_server_port: 50050
  rabbitmq_url: amqp://opendirectory:changeme@rabbitmq:5672/
  exchange: opendirectory.events
  prefetch: 10
  reconnect_delay_ms: 2000
```

## Event namespaces

| Namespace | Description |
|---|---|
| `api.*` | API gateway request events |
| `identity.*` | User and group lifecycle (created, deleted, token issued) |
| `security.*` | Elevation, break-glass, MFA, PIM, scan events |
| `device.*` | Device enrollment, compliance, retirement, install jobs |
| `mdm.*` | Apple MDM commands, profiles, and app installs |
| `policy.*` | Policy creation, updates, violations, simulations |
| `compliance.*` | Compliance check results and violation detection |
| `directory.*` | AD object create/modify/delete/move, group membership, GPO |
| `ad.*` | Samba AD DC events: trusts, computer join/unjoin, replication, LAPS, BitLocker |
| `kerberos.*` | Ticket issuance, renewal, delegation, principal lifecycle |
| `certificate.*` | Certificate issuance and revocation |
| `network.*` | DNS, VLAN, DHCP, and profile deployment events |
| `app.*` | App publishing, install requests and results |
| `license.*` | License assignment, revocation, expiry |
| `audit.*` | Audit log writes |
| `monitoring.*` | Alerts (critical, warning) |
| `notification.*` | Outbound notification send/fail |
| `system.*` | Backup start/complete/fail |
| `update.*` | Software update deployment results |
| `printer.*` | Print job and printer status events |
| `remote.*` | Remote control session start/end |
| `config.*` | Configuration service changes |
| `remediation.*` | Auto-remediation start/complete/fail |
| `admin.#` | Wildcard — all administrative events (subscribed by monitoring and audit) |

## Adding new events

1. Add the routing key to `config/event-routing.yaml` under the publishing service's `publishes` list, and under each subscribing service's `subscribes` list.

2. Publish from the source service:
   ```js
   publish('my-namespace.something.happened', { entityId: '...', extra: 'data' });
   ```

3. Subscribe in the consumer service:
   ```js
   await _bus.subscribe('my-service-queue', ['my-namespace.something.*'], async (payload) => {
     // handle event
   });
   ```

4. Add a test using MemoryTransport shared mode (see [testing.md](./testing.md)).

## Testing events

Use `MemoryTransport` with `shared: true` to test publish/subscribe flows without a broker. See the [testing guide](./testing.md#integration-tests--eventbusclient-flows) for complete examples and the `resetShared()` teardown pattern.
