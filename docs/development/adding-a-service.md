# Adding a New Microservice

Follow these steps to add a new service to the OpenDirectory platform.

## 1. Create the directory

Decide which layer the service belongs to:

- `services/core/` — foundational services (directory, auth, devices, policy)
- `services/enterprise/` — intelligence and analytics services
- `services/platform/` — infrastructure and gateway services

```bash
mkdir -p services/<layer>/my-service/src/__tests__
```

## 2. package.json

```json
{
  "name": "my-service",
  "version": "1.0.0",
  "description": "Brief description of what this service does",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest --no-coverage --forceExit"
  },
  "dependencies": {
    "express": "^4.18.0",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "compression": "^1.7.4",
    "winston": "^3.11.0",
    "pg": "^8.11.0",
    "ioredis": "^5.3.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "nodemon": "^3.0.0",
    "supertest": "^6.3.0",
    "nock": "^13.4.0"
  }
}
```

## 3. src/index.js

The standard service template. Copy and replace `my-service` with your service name and choose a port not already in use (see the [port reference in contributing.md](./contributing.md)).

```js
'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const { Pool } = require('pg');
const Redis = require('ioredis');
const winston = require('winston');

// ─── Logger ───────────────────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

// ─── EventBusClient ───────────────────────────────────────────────────────────
// Falls back to local source path when the package is not yet installed.

const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();

const _bus = new EventBusClient({ source: 'my-service' });

async function connectBus() { await _bus.connect(); }

function publish(routingKey, payload) {
  _bus.publish(routingKey, payload).catch(() => {});
}

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
});

async function connectPostgres() {
  const client = await pool.connect();
  client.release();
  logger.info('PostgreSQL connected');
}

// ─── Redis ────────────────────────────────────────────────────────────────────

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  lazyConnect: true,
  maxRetriesPerRequest: 3,
});

async function connectRedis() {
  await redis.connect();
  logger.info('Redis connected');
}

// ─── Express ──────────────────────────────────────────────────────────────────

const app = express();

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '1mb' }));

// Health endpoint (required — used by Kubernetes liveness/readiness probes)
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'my-service', timestamp: new Date().toISOString() });
});

// Metrics endpoint (Prometheus scrape target)
app.get('/metrics', (_req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send('# HELP my_service_up Service is running\n# TYPE my_service_up gauge\nmy_service_up 1\n');
});

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/api/my-service/items', async (_req, res) => {
  try {
    const result = await pool.query('SELECT * FROM items ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    logger.error('Failed to fetch items', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Startup ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '39XX', 10); // replace XX with your port

async function start() {
  try { await connectPostgres(); } catch (e) { logger.warn('Postgres unavailable: ' + e.message); }
  try { await connectRedis(); } catch (e) { logger.warn('Redis unavailable: ' + e.message); }
  try { await connectBus(); } catch (e) { logger.warn('[bus] startup connect error: ' + e.message); }

  // Subscribe to events this service cares about
  try {
    await _bus.subscribe('my-service-queue', ['some.event.*'], async (payload, { routingKey }) => {
      logger.info(`Received ${routingKey}`, payload);
    });
  } catch (e) { logger.warn('[bus] subscribe error: ' + e.message); }

  const server = app.listen(PORT, () => {
    logger.info(`my-service running on port ${PORT}`);
  });

  return server;
}

// ─── Graceful shutdown ────────────────────────────────────────────────────────

async function shutdown(signal) {
  logger.info(`${signal} received – shutting down`);
  await _bus.close().catch(() => {});
  await pool.end().catch(() => {});
  await redis.quit().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

start();

module.exports = app;
```

## 4. Register events in event-routing.yaml

Open `/config/event-routing.yaml` and add your service block:

```yaml
  my-service:
    publishes:
      - myservice.thing.created
      - myservice.thing.deleted
    subscribes:
      - some.event.happened
```

## 5. Add a Helm deployment template

Create `deploy/helm/opendirectory/templates/deployment-my-service.yaml`. Use an existing template as a reference (e.g. `deployment-auth.yaml`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "opendirectory.fullname" . }}-my-service
  namespace: {{ include "opendirectory.namespace" . }}
  labels:
    {{- include "opendirectory.labels" . | nindent 4 }}
    app.kubernetes.io/component: my-service
spec:
  replicas: {{ .Values.myService.replicaCount }}
  selector:
    matchLabels:
      {{- include "opendirectory.selectorLabels" . | nindent 6 }}
      app.kubernetes.io/component: my-service
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        {{- include "opendirectory.labels" . | nindent 8 }}
        app.kubernetes.io/component: my-service
      annotations:
        {{- include "opendirectory.prometheusAnnotations" . | nindent 8 }}
    spec:
      containers:
        - name: my-service
          image: {{ include "opendirectory.image" (dict "root" . "name" .Values.myService.image.name) }}
          imagePullPolicy: {{ .Values.global.image.pullPolicy }}
          ports:
            - name: http
              containerPort: {{ .Values.myService.service.appPort }}
              protocol: TCP
            - name: metrics
              containerPort: 9090
              protocol: TCP
          envFrom:
            - configMapRef:
                name: {{ include "opendirectory.fullname" . }}-config
            - secretRef:
                name: {{ include "opendirectory.fullname" . }}-secret
          env:
            - name: PORT
              value: {{ .Values.myService.service.appPort | quote }}
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            {{- toYaml .Values.myService.resources | nindent 12 }}
```

## 6. Add values to Helm values.yaml

Add a block to `deploy/helm/opendirectory/values.yaml`:

```yaml
myService:
  replicaCount: 1
  image:
    name: my-service
  service:
    appPort: 39XX   # replace with your chosen port
    port: 80
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 256Mi
```

## 7. Add Jest tests

Create `src/__tests__/api.e2e.test.js` at minimum. Add unit tests for any domain objects or application services. See [testing.md](./testing.md) for patterns.

```js
// src/__tests__/api.e2e.test.js
'use strict';

const request = require('supertest');
const app = require('../index');

describe('my-service health', () => {
  it('returns 200 on /health', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});
```

Add a `jest.config.js` to the service root:

```js
'use strict';

module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/src/__tests__/**/*.test.js'],
  testTimeout: 30000,
};
```

## 8. PR checklist

- [ ] `npm install` and `npx jest --no-coverage --forceExit` pass in the new service directory
- [ ] `/health` endpoint returns `200 { status: 'ok' }`
- [ ] Events declared in `config/event-routing.yaml`
- [ ] No raw `amqplib` usage — only `EventBusClient`
- [ ] Helm template and values added
- [ ] Port added to the [port reference in contributing.md](./contributing.md)
