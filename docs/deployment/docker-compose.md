# Docker Compose Deployment

Docker Compose is the recommended deployment method for evaluation, development, and small-to-medium on-premises installations. The full stack runs from a single `docker compose up -d` command.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+ (bundled with Docker Desktop; install separately on Linux with `apt install docker-compose-plugin`)
- 8 GB RAM, 4 CPU cores, 20 GB free disk space

## Quick Start

```bash
git clone https://github.com/Chregu12/OpenDirectory
cd OpenDirectory
cp .env.example .env
# Edit .env — set all required variables (see below)
docker compose up -d
```

## The Compose File

The `docker-compose.yml` at the repository root defines every service. Here is an annotated overview of the key sections.

### Infrastructure Services

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: opendirectory
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_MULTIPLE_DATABASES: identity,auth,policy,audit,integration,printers,network
    volumes:
      - postgres-data:/var/lib/postgresql/data
      # Init script creates multiple databases in a single instance
      - ./infrastructure/postgres/init-databases.sh:/docker-entrypoint-initdb.d/init-databases.sh
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U opendirectory"]
      interval: 10s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"

  mongodb:
    image: mongo:6
    environment:
      MONGO_INITDB_ROOT_USERNAME: opendirectory
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
      MONGO_INITDB_DATABASE: devices
    volumes:
      - mongo-data:/data/db
    ports:
      - "27017:27017"

  rabbitmq:
    image: rabbitmq:3-management-alpine
    environment:
      RABBITMQ_DEFAULT_USER: opendirectory
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD}
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
    ports:
      - "5672:5672"
      - "15672:15672"   # Management UI
```

### LDAP Service

```yaml
  lldap:
    image: nitnelave/lldap:stable
    environment:
      - LLDAP_JWT_SECRET=${LLDAP_JWT_SECRET}
      - LLDAP_LDAP_USER_PASS=${LLDAP_ADMIN_PASSWORD}
    volumes:
      - lldap-data:/data
    ports:
      - "17170:17170"   # REST API
      - "3890:3890"     # LDAP
```

### Application Services (example — authentication-service)

```yaml
  authentication-service:
    build:
      context: ./services/core/authentication-service
    environment:
      PORT: 3001
      NODE_ENV: production
      DB_HOST: postgres
      DB_PASSWORD: ${DB_PASSWORD}
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      JWT_SECRET: ${JWT_SECRET}
      LLDAP_URL: http://lldap:17170
      LLDAP_JWT_SECRET: ${LLDAP_JWT_SECRET}
      LLDAP_ADMIN_PASSWORD: ${LLDAP_ADMIN_PASSWORD}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    ports:
      - "3001:3001"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

All application services follow the same pattern: they depend on `postgres` and `redis` being healthy, expose their port, and implement a `/health` endpoint.

### Volumes

```yaml
volumes:
  postgres-data:        # PostgreSQL data — 10GB+ recommended
  redis-data:           # Redis append-only log
  mongo-data:           # MongoDB directory objects and GPO data
  rabbitmq-data:        # RabbitMQ message queues and exchange config
  lldap-data:           # LLDAP user database
  grafana-data:         # Grafana dashboards and data sources
  prometheus-data:      # Prometheus time-series data
```

All volumes use the Docker default driver (local bind mounts on the host). For production, consider using a named volume driver backed by network storage.

## Required `.env` Variables

The following variables have no default and must be set before starting the stack. All others have working defaults for local development.

```bash
# .env (minimum required values)
DB_PASSWORD=<generate with: openssl rand -base64 32>
MONGO_PASSWORD=<generate with: openssl rand -base64 32>
REDIS_PASSWORD=<generate with: openssl rand -base64 32>
RABBITMQ_PASSWORD=<generate with: openssl rand -base64 32>
LLDAP_JWT_SECRET=<generate with: openssl rand -base64 64>
LLDAP_ADMIN_PASSWORD=<generate with: openssl rand -base64 32>
JWT_SECRET=<generate with: openssl rand -base64 64>
ENCRYPTION_KEY=<generate with: openssl rand -hex 16>
ADMIN_PASSWORD=<your admin UI password>
```

See [Environment Variables](environment-variables.md) for the complete reference.

## Accessing Services After Start

| Service | URL | Credentials |
|---|---|---|
| OpenDirectory UI | http://localhost:3000 | `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env` |
| API Gateway | http://localhost:8080 | Bearer token from `/api/auth/login` |
| RabbitMQ Management | http://localhost:15672 | `opendirectory` / `RABBITMQ_PASSWORD` |
| LLDAP Web UI | http://localhost:17170 | `admin` / `LLDAP_ADMIN_PASSWORD` |
| PostgreSQL | localhost:5432 | `opendirectory` / `DB_PASSWORD` |
| MongoDB | localhost:27017 | `opendirectory` / `MONGO_PASSWORD` |
| Prometheus | http://localhost:9090 | No auth (internal only) |
| Grafana | http://localhost:3001 | `admin` / `GRAFANA_PASSWORD` |

## Scaling Services

To run more replicas of a stateless service, use `docker compose up --scale`:

```bash
# Scale authentication-service to 3 replicas
docker compose up -d --scale authentication-service=3
```

For services that bind a fixed host port this will fail. Remove the `ports` mapping from the service in `docker-compose.yml` before scaling, and add a reverse proxy (nginx or Traefik) in front to load-balance.

The recommended approach for multi-replica deployments is Kubernetes — see [Kubernetes / Helm](kubernetes.md).

## Persisting Data and Backup

All persistent data lives in Docker named volumes. To back up:

```bash
# Dump PostgreSQL
docker exec od-postgres pg_dumpall -U opendirectory > backup-$(date +%Y%m%d).sql

# Dump MongoDB
docker exec od-mongodb mongodump \
  --username opendirectory --password "$MONGO_PASSWORD" \
  --authenticationDatabase admin \
  --out /tmp/mongodump
docker cp od-mongodb:/tmp/mongodump ./mongodump-$(date +%Y%m%d)
```

For full automated backups, use the built-in backup-service endpoints at `POST /api/backup/start` on device-service.

## Production Hardening for Docker Compose

The default compose file is optimised for ease of use. Before exposing OpenDirectory to a production network:

1. **Remove exposed ports** for services that should not be reachable directly (e.g. postgres, redis, rabbitmq). Only the API gateway and frontend need to be public.
2. **Set `NODE_ENV=production`** in all service environment blocks.
3. **Set a restrictive `CORS_ORIGIN`** — change from `*` to your frontend hostname.
4. **Add TLS** — place nginx or Traefik in front of the API gateway and frontend with a valid certificate.
5. **Enable Docker log rotation** by adding `logging` to long-running services:
   ```yaml
   logging:
     driver: "json-file"
     options:
       max-size: "50m"
       max-file: "5"
   ```
6. **Set resource limits** to prevent a misbehaving service from starving others:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '0.5'
         memory: 512M
   ```

## Lite Mode

For environments with limited resources, `docker-compose.lite.yml` starts only the essential services (postgres, redis, authentication-service, enterprise-directory, device-service, and the frontend):

```bash
docker compose -f docker-compose.lite.yml up -d
```

This removes RabbitMQ (the event bus falls back to in-memory transport), MongoDB (directory objects use PostgreSQL JSON columns), and enterprise services such as compliance-engine and audit-service.
