# Environment Variables Reference

Complete alphabetical reference of every environment variable used across OpenDirectory services. The **Service** column identifies which service(s) consume the variable. Variables marked **Required** have no default and the service will refuse to start or behave incorrectly without them.

Variables are read from the process environment. In Docker Compose they come from the root `.env` file. In Kubernetes they are set via Helm values (which generate ConfigMaps and Secrets per service).

---

| Variable | Service(s) | Default | Required | Description |
|---|---|---|---|---|
| `ABUSEIPDB_API_KEY` | conditional-access, device-service | — | No | AbuseIPDB API key for IP reputation lookups. Free tier available at abuseipdb.com. When absent, IP reputation checks are skipped |
| `ACCESS_TOKEN_TTL` | oauth-provider | `3600` | No | OAuth 2.0 access token lifetime in seconds |
| `ADMIN_PASSWORD` | api-gateway | — | Yes | Password for Basic Auth on the API gateway admin endpoints |
| `ADMIN_USERNAME` | api-gateway | `admin` | No | Username for Basic Auth on the API gateway admin endpoints |
| `API_BACKEND_URL` | frontend, quick-actions | `http://localhost:8080` | No | Internal URL of the API backend service |
| `API_GATEWAY_URL` | frontend | `http://localhost:3000` | No | Public URL of the API gateway |
| `API_KEY_ADMIN` | api-gateway | — | No | API key granting admin-level access. When absent, API key auth is disabled |
| `API_KEY_FULL` | api-gateway | — | No | API key granting full read-write access |
| `API_KEY_READ_ONLY` | api-gateway | — | No | API key granting read-only access |
| `AUTH_SERVICE_URL` | quick-actions, integration-service | `http://authentication-service:3001` | No | URL of the authentication service for orchestration calls |
| `CORS_ORIGIN` | all services | `*` | No | Allowed CORS origin header value. Set to your frontend hostname in production. Default `*` is insecure for production |
| `CT2001_HOST` | device-service | `192.168.1.51` | No | Hostname for an optional SSH-managed device. Remove if not used |
| `CT2001_PASSWORD` | device-service | — | No | SSH password for the CT2001 device connection |
| `CT2001_PORT` | device-service | `22` | No | SSH port for the CT2001 device |
| `CT2001_USERNAME` | device-service | `root` | No | SSH username for the CT2001 device |
| `DB_HOST` | all services (PostgreSQL) | `postgres` | No | PostgreSQL hostname. In Docker Compose use the container name; in Kubernetes use the service name |
| `DB_NAME` | all services (PostgreSQL) | `opendirectory` | No | PostgreSQL database name |
| `DB_PASSWORD` | all services (PostgreSQL) | — | Yes | PostgreSQL password. Generate with `openssl rand -base64 32` |
| `DB_PORT` | all services (PostgreSQL) | `5432` | No | PostgreSQL port |
| `DB_USER` | all services (PostgreSQL) | `opendirectory` | No | PostgreSQL username |
| `DEVICE_SERVICE_URL` | quick-actions, policy-service, auto-remediation, app-store | `http://device-service:3003` | No | URL of the device service for inter-service calls |
| `DOMAIN_DN` | enterprise-directory, samba-ad-dc, ldap-proxy | `DC=opendirectory,DC=local` | No | LDAP base distinguished name for the directory. Must match `DOMAIN_NAME` |
| `DOMAIN_NAME` | enterprise-directory, samba-ad-dc, kerberos-kdc | `OPENDIRECTORY.LOCAL` | No | Active Directory realm and Kerberos realm. Must match DNS; changing after initial setup requires a domain reprovision |
| `ENCRYPTION_KEY` | authentication-service, samba-ad-dc | — | Yes | AES-256 key for encrypting secrets at rest (LAPS passwords, BitLocker recovery keys). Must be exactly 32 hex characters. Generate with `openssl rand -hex 16` |
| `ENTERPRISE_DIRECTORY_URL` | policy-service, quick-actions | `http://enterprise-directory:3008` | No | URL of the enterprise directory service |
| `EVENT_BUS_TRANSPORT` | all services using event bus | `rabbitmq` | No | Event bus transport backend: `rabbitmq` (production default), `grpc` (direct without broker), `memory` (unit tests) |
| `FEATURE_CERTIFICATE_MANAGEMENT_ENABLED` | certificate-authority, frontend | `true` | No | Enable or disable certificate management features |
| `FEATURE_CONDITIONAL_ACCESS_ENABLED` | conditional-access, frontend | `true` | No | Enable or disable conditional access policy evaluation |
| `FEATURE_LICENSE_MANAGEMENT_ENABLED` | license-management, frontend | `true` | No | Enable or disable software license tracking |
| `FEATURE_MDM_ENABLED` | device-service, apple-mdm, frontend | `true` | No | Enable or disable MDM features |
| `FEATURE_PRINT_MANAGEMENT_ENABLED` | printer-service, frontend | `true` | No | Enable or disable shared printer management |
| `FEATURE_UPDATE_MANAGEMENT_ENABLED` | update-management, frontend | `true` | No | Enable or disable the update management service |
| `GRAFANA_PASSWORD` | monitoring (Grafana container) | — | No | Grafana admin password. Only used by the Grafana container in Docker Compose monitoring stack |
| `HIGH_RISK_COUNTRIES` | conditional-access, device-service | `CN,RU,IR,KP` | No | Comma-separated ISO-3166-1 alpha-2 country codes treated as high-risk for geofencing and conditional access policies |
| `IDENTITY_SERVICE_URL` | quick-actions, authentication-service | `http://identity-service:3002` | No | URL of the identity service |
| `JWT_EXPIRES_IN` | authentication-service, oauth-provider | `24h` | No | Access token lifetime. Accepts duration strings: `15m`, `1h`, `24h`, `7d` |
| `JWT_SECRET` | authentication-service, api-gateway | — | Yes | Secret used to sign and verify JWTs. Minimum 32 characters. Generate with `openssl rand -base64 64` |
| `KDC_HOST` | kerberos-kdc | `kerberos-kdc` | No | Hostname of the Kerberos KDC. Used when generating service principal names (SPNs) |
| `LAPS_ENCRYPTION_KEY` | samba-ad-dc | — | No | AES-256-GCM key specifically for LAPS password encryption. Defaults to `ENCRYPTION_KEY` if not set |
| `LLDAP_ADMIN_PASSWORD` | authentication-service, enterprise-directory | — | Yes | LLDAP admin password for directory write operations (user creation, group management) |
| `LLDAP_JWT_SECRET` | authentication-service, lldap | — | Yes | JWT signing secret shared between LLDAP and the authentication service. Generate with `openssl rand -base64 64` |
| `LLDAP_URL` | authentication-service, enterprise-directory, ldap-proxy | `http://lldap:17170` | No | URL of the LLDAP REST API |
| `LOG_LEVEL` | all services | `info` | No | Logging verbosity: `debug`, `info`, `warn`, `error` |
| `MAX_ACTIVE_SESSIONS` | conditional-access | `10000` | No | Maximum number of active sessions evaluated per conditional access policy tick |
| `METRICS_PORT` | all services | `9091` | No | Port on which Prometheus metrics are exposed at `/metrics` |
| `MFA_TOTP_ISSUER` | authentication-service | `OpenDirectory` | No | Issuer label shown in TOTP authenticator apps (e.g. Google Authenticator, Authy) |
| `MONGO_PASSWORD` | enterprise-directory | — | Yes | MongoDB password. Used to construct the MongoDB connection string |
| `MONGO_URL` | enterprise-directory | `mongodb://opendirectory:...@mongodb:27017/opendirectory` | No | Full MongoDB connection string. If set, overrides `MONGO_PASSWORD` |
| `NEXT_PUBLIC_API_URL` | frontend (browser) | `http://localhost:8080` | No | API gateway URL as seen from the browser. Must be publicly reachable. Set to `https://opendirectory.example.com` in production |
| `NEXT_PUBLIC_WS_URL` | frontend (browser) | `ws://localhost:8080` | No | WebSocket URL for real-time event streaming from the browser |
| `NODE_ENV` | all services | `development` | No | Runtime environment. `production` enables secure HTTP headers, disables stack traces in error responses, and enforces HTTPS cookie flags |
| `OAUTH_ISSUER` | oauth-provider | `http://localhost:3015` | No | OAuth 2.0 / OIDC issuer URL embedded in tokens and discovery documents. Set to your public hostname |
| `POLICY_SERVICE_URL` | quick-actions, device-service | `http://policy-service:3004` | No | URL of the policy service |
| `PORT` | each service | varies | No | HTTP listen port. See the service table in the Architecture doc for per-service defaults |
| `PRINTER1_IP` | printer-service | `192.168.1.200` | No | IP of the first discovered printer for mock discovery. Remove or adjust for real environments |
| `PRINTER2_IP` | printer-service | `192.168.1.201` | No | IP of the second discovered printer |
| `PROMETHEUS_ENABLED` | all services | `true` | No | Expose Prometheus metrics at `/metrics` |
| `PROXY_DETECTION_SERVICE_URL` | conditional-access | — | No | REST endpoint returning `{ "isProxy": true/false }`. Used for proxy-aware conditional access decisions |
| `RABBITMQ_PASSWORD` | all services using event bus | — | Yes | RabbitMQ password. Injected into `RABBITMQ_URL` |
| `RABBITMQ_URL` | all services using event bus | `amqp://opendirectory:changeme@rabbitmq:5672/` | No | Full RabbitMQ AMQP connection URL. Set automatically in Docker Compose from `RABBITMQ_PASSWORD` |
| `RATE_LIMIT_MAX` | quick-actions, api-gateway | `100` | No | Maximum number of requests allowed per window before rate limiting activates |
| `RATE_LIMIT_WINDOW_MS` | quick-actions, api-gateway | `60000` | No | Rate limit window duration in milliseconds |
| `REDIS_PASSWORD` | authentication-service, device-service, api-gateway | — | Yes | Redis password. Appended to `REDIS_URL` |
| `REDIS_URL` | authentication-service, device-service, api-gateway | `redis://redis:6379` | No | Redis connection string. The password is appended automatically when `REDIS_PASSWORD` is set |
| `REFRESH_TOKEN_EXPIRES_IN` | authentication-service | `7d` | No | Refresh token lifetime. Same format as `JWT_EXPIRES_IN` |
| `REFRESH_TOKEN_TTL` | oauth-provider | `604800` | No | OAuth refresh token lifetime in seconds (7 days) |
| `S3_ACCESS_KEY` | backup-service, app-store | — | No | S3 access key for backup and package storage |
| `S3_BUCKET` | backup-service, app-store | `opendirectory` | No | S3 bucket name |
| `S3_ENDPOINT` | backup-service, app-store | `http://localhost:9000` | No | S3-compatible endpoint (MinIO, AWS S3, GCS, etc.) |
| `S3_SECRET_KEY` | backup-service, app-store | — | No | S3 secret key |
| `SECURITY_SCANNER_URL` | auto-remediation | `http://security-scanner:3902` | No | URL of the security scanner service |
| `SESSION_SECRET` | authentication-service | (uses `JWT_SECRET`) | No | Express session signing secret. Defaults to `JWT_SECRET` if not explicitly set |
| `SMTP_FROM` | notification-service | `OpenDirectory <notifications@example.com>` | No | Sender name and address on outgoing emails |
| `SMTP_HOST` | notification-service | `smtp.gmail.com` | No | SMTP server hostname |
| `SMTP_PASSWORD` | notification-service | — | No | SMTP authentication password. Required if `SMTP_USER` is set |
| `SMTP_PORT` | notification-service | `587` | No | SMTP port (587 for STARTTLS, 465 for SSL, 25 for plain) |
| `SMTP_USER` | notification-service | — | No | SMTP username. When absent, unauthenticated SMTP is attempted |
| `SSH_PASSWORD` | device-service | — | No | Password for SSH-based remote device management. Use SSH key auth in production |
| `VPN_DETECTION_SERVICE_URL` | conditional-access | — | No | REST endpoint returning `{ "isVPN": true/false }`. Used for VPN-aware conditional access decisions |

---

## Notes

### Generating Secrets

```bash
# Standard password (all services)
openssl rand -base64 32

# Long JWT / LLDAP secrets
openssl rand -base64 64

# ENCRYPTION_KEY — must be exactly 32 hex chars (16 bytes)
openssl rand -hex 16
```

### Environment Variable Precedence

1. Variables explicitly set in the process environment take highest priority.
2. Docker Compose reads `.env` in the project root and interpolates variables into `docker-compose.yml`.
3. Helm values set via `--set` or `--values` override the chart defaults and are injected as container environment variables via ConfigMaps.
4. Service defaults (hardcoded in `index.js` or `config/`) apply when a variable is absent.

### Variables Not Listed Here

Some services define additional undocumented variables for internal behaviour. Check each service's `index.js` or `config/index.js` for the full set. All services support `PORT`, `NODE_ENV`, `LOG_LEVEL`, and `CORS_ORIGIN`.
