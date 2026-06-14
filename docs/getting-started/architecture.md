# Architecture

OpenDirectory is a microservices monorepo. All services are written in Node.js 18+ with Express 4, share a common event bus package, and follow the same internal structure: Express router, application service layer, domain model, and Jest tests.

## Service Layers

Services are organised into three layers under `services/`:

### Core Services (`services/core/`)

The core layer handles the primary operational concerns: identity, directory, device management, policy, and security infrastructure.

| Service | Port | Responsibility |
|---|---|---|
| authentication-service | 3001 | User authentication, MFA (TOTP), SSO (OIDC / SAML / OAuth 2.0), session management, SSPR |
| enterprise-directory | 3008 | AD-compatible directory, GPO engine, OU management, RSoP, SAML IdP |
| device-service | 3003 | MDM lifecycle, compliance scanning, remote actions, geofencing, backup/DR |
| policy-service | 3004 | Policy templates, blueprints, deployment, dry-run, RSoP evaluation |
| conditional-access | 3007 | Zero-trust scoring, conditional access policy evaluation |
| least-privilege | — | PIM roles, JIT access, approval chains, risk scoring, session recording |
| samba-ad-dc | 3010 | Samba 4 domain controller, forest trusts, LAPS, BitLocker key escrow, DC replication |
| kerberos-kdc | 3013 | MIT Kerberos KDC, constrained delegation (S4U2Self / S4U2Proxy / RBCD), ticket policies |
| ldap-proxy | 8389 | LDAP proxy, schema management REST API, RFC 4515 filter support |
| identity-service | 3002 | User and group identity objects |
| notification-service | 3020 | Email and push notifications |
| certificate-authority | 3010 | PKI — issue, renew, revoke certificates |
| monitoring-service | 3005 | Prometheus metrics aggregation, alerting |
| update-management | 3018 | Windows Update, WinGet, macOS Software Update rings |
| backup-service | 3011 | Scheduled backups, domain-wide and per-device restore |
| remote-control | 3017 | Remote desktop session brokering |
| oauth-provider | 3015 | OAuth 2.0 / OIDC provider |
| apple-mdm | 3006 | Apple MDM protocol, APNS integration |
| configuration-service | 3012 | Centralised configuration storage |
| license-management | 3013 | Software license assignment and tracking |
| network-infrastructure | 3014 | DNS, DHCP, VLAN management |
| printer-service | 3016 | Shared printer management |
| certificate-network | 3011 | Network profile certificate distribution |

### Enterprise Services (`services/enterprise/`)

The enterprise layer provides compliance, security analytics, automation, and extended platform capabilities.

| Service | Responsibility |
|---|---|
| compliance-engine | Baseline evaluation, waiver management, trend analysis |
| audit-service | Event collection, audit log aggregation, append-only trail |
| security-scanner | Vulnerability assessment |
| mobile-management | iOS / Android MDM, Apple Business Manager integration |
| app-store | Enterprise application store, package distribution |
| antivirus-protection | Antivirus management and threat detection |
| auto-remediation | Automated compliance remediation |
| ai-analytics | Threat detection, anomaly detection, predictive analytics |
| graph-explorer | Microsoft Graph-compatible API layer |
| automation | Webhook-based automation rules |
| policy-engine | Extended policy evaluation engine |
| policy-simulator | What-if policy simulation |
| multi-tenant | Multi-tenant scaffolding (not yet integrated) |
| disaster-recovery | Domain-wide DR orchestration |
| device-lifecycle | Device onboarding and retirement lifecycle |
| integrations | Third-party system integrations |
| background-services | Scheduled background jobs |
| real-time | Real-time event streaming |
| security | Security policy and enforcement |
| containers | Container management |
| certificates | Certificate distribution |

### Platform Services (`services/platform/`)

The platform layer provides infrastructure shared by all other services.

| Service | Port | Responsibility |
|---|---|---|
| api-gateway | 8080 | Unified external API, request routing, rate limiting |
| event-bus | 50050 (gRPC) | gRPC event bus server, RabbitMQ bridge |
| quick-actions | 3950 | Orchestration — one-click service principal creation, device enrollment, user onboarding, policy deployment |
| api-backend | — | Internal API utilities |
| integration-service | — | Third-party integration framework |

## System Architecture Diagram

```
Browser / Mobile App / API Clients
              │
    [API Gateway  :8080]
              │
    ┌─────────┴──────────────────────────────────────────────────────────────┐
    │                          Core Services                                 │
    │                                                                        │
    │  authentication-service :3001  │  enterprise-directory :3008          │
    │  device-service         :3003  │  policy-service       :3004          │
    │  conditional-access     :3007  │  least-privilege                     │
    │  samba-ad-dc            :3010  │  kerberos-kdc         :3013          │
    │  ldap-proxy             :8389  │  identity-service     :3002          │
    │  certificate-authority  :3010  │  oauth-provider       :3015          │
    │  apple-mdm              :3006  │  notification-service :3020          │
    │  update-management      :3018  │  monitoring-service   :3005          │
    │  backup-service         :3011  │  remote-control       :3017          │
    └────────────────────────────────────────────────────────────────────────┘
              │
    [gRPC Event Bus :50050  /  RabbitMQ :5672]
    exchange: opendirectory.events
              │
    ┌─────────┴────────────────────────────────────┐
    │              Enterprise Services              │
    │                                               │
    │  compliance-engine  │  audit-service          │
    │  security-scanner   │  mobile-management      │
    │  antivirus          │  auto-remediation        │
    │  app-store          │  ai-analytics            │
    │  graph-explorer     │  policy-simulator        │
    └───────────────────────────────────────────────┘
              │
    ┌─────────┴──────────────────────────┐
    │         Platform Services          │
    │                                    │
    │  quick-actions :3950               │
    │  integration-service               │
    └────────────────────────────────────┘

Data Layer
──────────
  PostgreSQL :5432   — primary operational store (each service owns its schema)
  MongoDB            — directory objects, GPO data (enterprise-directory)
  Redis              — session cache, distributed locks (auth, device, gateway)
  RabbitMQ :5672     — event bus message broker
```

## Data Stores

### PostgreSQL

The primary relational store. Each service that needs persistent storage connects to PostgreSQL and manages its own schema (tables are prefixed by service to avoid conflicts). In a clustered deployment, all services connect to the same PostgreSQL instance unless overridden via individual `POSTGRES_*` environment variables.

### MongoDB

Used by `enterprise-directory` for directory objects and GPO data. The document model is a natural fit for the variable-attribute schema of Active Directory objects.

### Redis

Used for session tokens, distributed locks, and short-lived cache entries. The `authentication-service` and `device-service` use Redis; the API gateway uses it for rate-limiting state.

## Event Bus

All inter-service communication that does not need a synchronous response uses the `@opendirectory/grpc-event-bus` package. The routing configuration lives in `config/event-routing.yaml`.

**Transport options** (set via `EVENT_BUS_TRANSPORT`):

| Transport | Use case |
|---|---|
| `rabbitmq` | Default; production deployments |
| `grpc` | Direct gRPC without a broker |
| `memory` | Unit and integration tests |

The exchange name is `opendirectory.events`. All events use dot-namespaced routing keys (`device.enrolled`, `security.elevation.approved`, etc.). Wildcard subscriptions use AMQP-style patterns (`policy.#`, `monitoring.alert.*`).

Key event namespaces:

| Namespace | Examples |
|---|---|
| `identity.*` | login.success, login.failed, user.created, token.issued |
| `device.*` | enrolled, compliant, non_compliant, retired |
| `policy.*` | created, updated, applied, violated |
| `security.elevation.*` | requested, approved, denied, expired, revoked |
| `security.breakglass.*` | activated, terminated |
| `directory.object.*` | created, modified, deleted, moved |
| `directory.gpo.*` | applied, modified |
| `kerberos.*` | ticket.issued, delegation.granted |
| `ad.trust.*` | created, removed, verified |
| `ad.replication.*` | failed, recovered |
| `ad.laps.*` | password.retrieved, password.rotated |
| `compliance.*` | check.passed, check.failed, violation.detected |
| `certificate.*` | issued, revoked |

## Frontend

The frontend is a Next.js / React 18 TypeScript single-page application. It uses an Apple Business Manager-style three-column layout: sidebar navigation, item list panel, and detail panel.

In production, the frontend is served as a static build behind the API gateway. In development, it runs on its own port (default 3000) and proxies API calls directly to individual services.

Key UI sections:
- Device Fleet — per-OS cards with compliance indicators and click-to-filter
- Enrollment Wizard — 4-step, OS-aware flow (Windows, macOS, Linux, iOS, Android)
- Service Principal Wizard — one-click create returning ClientID and masked ClientSecret
- User Onboarding Wizard — 4-step new-employee flow
- PIM view — Roles, Requests, Active Elevations, Session Replay, Break-Glass
- Audit Log — filterable, paginated, severity colour-coded
- Compliance Snapshot — donut chart, top violations, devices needing attention
- Kerberos Admin — delegation, Protected Users group, ticket policies
- Trust Management — forest trust graph with verify, rotate, and remove
- Replication Dashboard — per-DC health, USN tracking, 30-second auto-refresh

## Kubernetes Layout

In a Kubernetes deployment (via the Helm chart), each service runs as its own `Deployment` and `Service` in the `opendirectory` namespace. The chart includes 38 deployment templates.

```
namespace: opendirectory
  Deployments: api-gateway, authentication-service, enterprise-directory,
               device-service, policy-service, conditional-access, ...
  Services:    ClusterIP for each deployment
  Ingress:     nginx (configurable), routes / to api-gateway
  StatefulSets: postgresql, rabbitmq
  PVCs:         postgresql-data (10Gi), rabbitmq-data (5Gi),
                app-store-data (20Gi), backup-data (50Gi)
```

See [Kubernetes / Helm](../deployment/kubernetes.md) for the full deployment reference.

## Security Architecture

- All services expose a `/health` endpoint (unauthenticated) and require a Bearer JWT on all other routes
- Inter-service communication is currently unauthenticated at the transport layer (service-to-service mTLS is on the roadmap)
- The API gateway handles rate limiting (200 req/min on quick-actions; additional limits are planned)
- TLS is terminated at the ingress; internal cluster communication is plain HTTP in the default configuration
- CORS is set to `*` by default; restrict `CORS_ORIGIN` in production
