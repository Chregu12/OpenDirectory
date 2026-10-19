# Configuration

All OpenDirectory services are configured through environment variables. In a Docker Compose deployment, these are set in the root `.env` file. In Kubernetes, they are passed via Helm values (which generate ConfigMaps and Secrets).

Copy `.env.example` to `.env` to start from the documented template:

```bash
cp .env.example .env
```

---

## Secrets Generation

Generate all required secrets before starting the stack:

```bash
# Database and infrastructure passwords
DB_PASSWORD=$(openssl rand -base64 32)
MONGO_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
RABBITMQ_PASSWORD=$(openssl rand -base64 32)

# Authentication
LLDAP_JWT_SECRET=$(openssl rand -base64 64)
LLDAP_ADMIN_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 64)

# Encryption key must be exactly 32 hex characters (16 bytes)
ENCRYPTION_KEY=$(openssl rand -hex 16)

# Admin account
ADMIN_PASSWORD=$(openssl rand -base64 24)
```

---

## Environment Variables Reference

### Core — Required for All Services

These variables must be set before any service will start successfully.

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | Set to `production` to enable secure HTTP headers, disable stack traces in error responses, and enforce HTTPS redirects |
| `DB_PASSWORD` | — | **Required.** PostgreSQL password. Shared by all services that use the relational store |
| `DB_HOST` | `postgres` | PostgreSQL hostname. In Docker Compose this is the container name; in Kubernetes it is the service name |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `opendirectory` | PostgreSQL database name |
| `DB_USER` | `opendirectory` | PostgreSQL username |
| `JWT_SECRET` | — | **Required.** Secret for signing JWTs. Minimum 32 characters. Generate with `openssl rand -base64 64` |
| `JWT_EXPIRES_IN` | `24h` | Access token lifetime. Accepts Go-style duration strings (`15m`, `24h`, `7d`) |
| `REFRESH_TOKEN_EXPIRES_IN` | `7d` | Refresh token lifetime |
| `ENCRYPTION_KEY` | — | **Required.** AES-256 key for encrypting secrets at rest (LAPS passwords, BitLocker keys). Must be exactly 32 hex characters |
| `CORS_ORIGIN` | `*` | Allowed CORS origin. Set to your frontend hostname in production (e.g. `https://opendirectory.example.com`) |

### Authentication Service (port 3001)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3001` | HTTP listen port |
| `REDIS_URL` | `redis://redis:6379` | Redis connection string for session storage and distributed locks |
| `REDIS_PASSWORD` | — | Redis password (appended to `REDIS_URL` automatically if set) |
| `LLDAP_URL` | `http://lldap:17170` | LLDAP service URL for LDAP-backed authentication |
| `LLDAP_JWT_SECRET` | — | **Required.** LLDAP JWT signing secret; must match the value LLDAP is started with |
| `LLDAP_ADMIN_PASSWORD` | — | **Required.** LLDAP admin password for directory write operations |
| `MFA_TOTP_ISSUER` | `OpenDirectory` | Issuer name shown in authenticator apps |
| `SESSION_SECRET` | — | Express session secret. Defaults to `JWT_SECRET` if not set separately |

### Enterprise Directory (port 3008)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3008` | HTTP listen port |
| `MONGO_URL` | `mongodb://opendirectory:...@mongodb:27017/opendirectory` | MongoDB connection string for directory objects and GPO storage |
| `MONGO_PASSWORD` | — | **Required.** MongoDB password injected into `MONGO_URL` |
| `DOMAIN_NAME` | `OPENDIRECTORY.LOCAL` | Active Directory realm. Must match the Kerberos realm and Samba domain |
| `DOMAIN_DN` | `DC=opendirectory,DC=local` | Base distinguished name for the directory |
| `LLDAP_URL` | `http://lldap:17170` | LLDAP service URL |
| `LLDAP_ADMIN_PASSWORD` | — | LLDAP admin password for provisioning OUs and groups |

### Device Service (port 3003)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3003` | HTTP listen port |
| `REDIS_URL` | `redis://redis:6379` | Redis for device session cache and rate-limit state |
| `RABBITMQ_URL` | `amqp://opendirectory:changeme@rabbitmq:5672/` | RabbitMQ connection string for the event bus |
| `RABBITMQ_PASSWORD` | — | RabbitMQ password injected into `RABBITMQ_URL` |
| `EVENT_BUS_TRANSPORT` | `rabbitmq` | Event bus transport: `rabbitmq`, `grpc`, or `memory` |
| `HIGH_RISK_COUNTRIES` | `CN,RU,IR,KP` | Comma-separated ISO-3166-1 alpha-2 country codes considered high-risk for geofencing and conditional access |
| `ABUSEIPDB_API_KEY` | — | Optional. AbuseIPDB API key for IP reputation checks in conditional access |

### Policy Service (port 3004)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3004` | HTTP listen port |
| `DEVICE_SERVICE_URL` | `http://device-service:3003` | URL for calling the device service during RSoP evaluation |
| `ENTERPRISE_DIRECTORY_URL` | `http://enterprise-directory:3008` | URL for calling the directory service for OU/group lookups |

### Conditional Access (port 3007)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3007` | HTTP listen port |
| `VPN_DETECTION_SERVICE_URL` | — | Optional REST endpoint returning `{ "isVPN": true/false }` for network-based policy decisions |
| `PROXY_DETECTION_SERVICE_URL` | — | Optional REST endpoint returning `{ "isProxy": true/false }` |
| `MAX_ACTIVE_SESSIONS` | `10000` | Maximum number of active sessions evaluated per policy evaluation tick |

### Samba AD DC (port 3010)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3010` | HTTP listen port |
| `DOMAIN_NAME` | `OPENDIRECTORY.LOCAL` | Samba AD realm |
| `DOMAIN_DN` | `DC=opendirectory,DC=local` | Directory base DN |
| `LAPS_ENCRYPTION_KEY` | — | AES-256-GCM key for encrypting LAPS passwords at rest. Defaults to `ENCRYPTION_KEY` |

### Kerberos KDC (port 3013)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3013` | HTTP listen port |
| `DOMAIN_NAME` | `OPENDIRECTORY.LOCAL` | Kerberos realm (must match Samba domain) |
| `KDC_HOST` | `kerberos-kdc` | Hostname for the KDC; used when generating SPNs |

### LDAP Proxy (port 8389)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8389` | LDAP listen port (REST API is on 3389) |
| `LLDAP_URL` | `http://lldap:17170` | Backend LLDAP URL |
| `DOMAIN_DN` | `DC=opendirectory,DC=local` | Base DN for LDAP operations |

### Notification Service (port 3020)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3020` | HTTP listen port |
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_FROM` | `OpenDirectory <notifications@example.com>` | Sender address shown on outgoing emails |

### OAuth Provider (port 3015)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3015` | HTTP listen port |
| `OAUTH_ISSUER` | `http://localhost:3015` | OAuth 2.0 / OIDC issuer URL. Set to your public hostname in production |
| `ACCESS_TOKEN_TTL` | `3600` | OAuth access token lifetime in seconds |
| `REFRESH_TOKEN_TTL` | `604800` | Refresh token lifetime in seconds (7 days) |

### Quick Actions (port 3950)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3950` | HTTP listen port |
| `AUTH_SERVICE_URL` | `http://authentication-service:3001` | Used when orchestrating user onboarding |
| `DEVICE_SERVICE_URL` | `http://device-service:3003` | Used when orchestrating device enrollment |
| `POLICY_SERVICE_URL` | `http://policy-service:3004` | Used when orchestrating policy deployment |
| `RATE_LIMIT_MAX` | `200` | Requests per window before rate limiting kicks in |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window in milliseconds |

### API Gateway (port 8080)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` (internal) | Internal HTTP port; exposed as 8080 via Docker or Kubernetes service |
| `ADMIN_USERNAME` | `admin` | Basic-auth username for admin endpoints |
| `ADMIN_PASSWORD` | — | **Required.** Basic-auth password for admin endpoints |
| `API_KEY_READ_ONLY` | — | Optional API key for read-only access |
| `API_KEY_FULL` | — | Optional API key for full read-write access |
| `API_KEY_ADMIN` | — | Optional API key for admin operations |
| `NODE_ENV` | `production` | Set automatically in Helm values |

### Monitoring and Observability

| Variable | Default | Description |
|---|---|---|
| `PROMETHEUS_ENABLED` | `true` | Expose Prometheus metrics on `/metrics` |
| `METRICS_PORT` | `9091` | Port for the Prometheus metrics endpoint |
| `LOG_LEVEL` | `info` | Logging level: `debug`, `info`, `warn`, `error` |
| `GRAFANA_PASSWORD` | — | Grafana admin password (used by the monitoring Docker Compose service) |

### Storage (Optional)

| Variable | Default | Description |
|---|---|---|
| `S3_ENDPOINT` | `http://localhost:9000` | S3-compatible endpoint for backup storage (MinIO, AWS S3, GCS) |
| `S3_ACCESS_KEY` | — | S3 access key |
| `S3_SECRET_KEY` | — | S3 secret key |
| `S3_BUCKET` | `opendirectory` | S3 bucket name for backups and app store packages |

### Feature Flags

| Variable | Default | Description |
|---|---|---|
| `FEATURE_MDM_ENABLED` | `true` | Enable or disable MDM features |
| `FEATURE_CONDITIONAL_ACCESS_ENABLED` | `true` | Enable or disable conditional access evaluation |
| `FEATURE_CERTIFICATE_MANAGEMENT_ENABLED` | `true` | Enable or disable the certificate authority features |
| `FEATURE_UPDATE_MANAGEMENT_ENABLED` | `true` | Enable or disable the update management service |
| `FEATURE_PRINT_MANAGEMENT_ENABLED` | `true` | Enable or disable the printer management service |
| `FEATURE_LICENSE_MANAGEMENT_ENABLED` | `true` | Enable or disable software license tracking |

### SSH / Remote Device Management

| Variable | Default | Description |
|---|---|---|
| `SSH_PASSWORD` | — | Password for SSH-based remote device management. Use SSH keys in production instead |

### Frontend

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | API gateway URL that the browser uses for API calls. Must be publicly reachable from the browser |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8080` | WebSocket URL for real-time updates |

---

## Kubernetes / Helm Configuration

When deploying with Helm, environment variables are set through `values.yaml` overrides. Sensitive values should be stored in Kubernetes Secrets and referenced via `valueFrom.secretKeyRef`.

Example `values.prod.yaml`:

```yaml
global:
  domain: opendirectory.example.com

postgresql:
  auth:
    password: "your-db-password"

rabbitmq:
  auth:
    password: "your-rabbitmq-password"

auth:
  env:
    JWT_SECRET: "your-jwt-secret"
    ENCRYPTION_KEY: "your-32-hex-char-key"
    LLDAP_JWT_SECRET: "your-lldap-secret"
    LLDAP_ADMIN_PASSWORD: "your-lldap-admin-password"
    NODE_ENV: production
    CORS_ORIGIN: "https://opendirectory.example.com"

apiGateway:
  env:
    ADMIN_USERNAME: admin
    ADMIN_PASSWORD: "your-admin-password"
    NODE_ENV: production

ingress:
  enabled: true
  hostname: opendirectory.example.com
  tls:
    enabled: true
    secretName: opendirectory-tls
```

For a complete Helm values reference, see [Kubernetes / Helm](../deployment/kubernetes.md).
