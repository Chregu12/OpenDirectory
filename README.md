# OpenDirectory

Self-hosted, open-source enterprise platform combining Active Directory, MDM, and Privileged Identity Management across all major operating systems.

## What is OpenDirectory?

OpenDirectory is an open-source alternative to Microsoft Intune, Azure Active Directory, and Jamf Pro. It gives organisations full control over their directory, device fleet, and identity infrastructure without vendor lock-in or per-seat licensing fees.

The platform runs on-premises or on Kubernetes and manages the full lifecycle of enterprise IT: domain controllers, user and group provisioning, device enrollment and compliance, group policy, privileged access management, certificate authority, and audit logging — all from a single interface and a unified REST/gRPC API.

OpenDirectory is built for teams that need the capabilities of a Microsoft 365 + Intune stack but want to own the data and the deployment. It is not a thin wrapper around existing tools; it ships its own Samba domain controller integration, Kerberos KDC service, LDAP proxy with schema management, GPO engine, and PIM service with session recording.

## Architecture

OpenDirectory is composed of approximately 30 microservices organised into three layers. Services communicate asynchronously through a pluggable gRPC event bus (RabbitMQ by default). Each service exposes a REST API and a `/health` endpoint, and emits Prometheus metrics.

```
Core Services                Enterprise Services          Platform Services
─────────────────────────    ─────────────────────────    ─────────────────────────
authentication-service       compliance-engine            api-gateway
enterprise-directory         audit-service                quick-actions
device-service               security-scanner             event-bus
policy-service               mobile-management            integration-service
conditional-access           app-store                    api-backend
least-privilege              graph-explorer
samba-ad-dc                  automation
kerberos-kdc                 policy-engine
ldap-proxy                   policy-simulator
notification-service         ai-analytics
certificate-authority        antivirus-protection
monitoring-service           auto-remediation
update-management            multi-tenant
backup-service               disaster-recovery
remote-control
oauth-provider
identity-service
```

**Databases:** PostgreSQL (primary operational store), MongoDB (directory objects and GPO data), Redis (session cache, distributed locks).

**Frontend:** Next.js / React 18 single-page application with an Apple Business Manager-style three-column layout.

## Features

### Active Directory and Identity

- Samba AD DC integration — full domain controller, LDAP, Kerberos
- LDAP proxy with schema management and a full LDAP REST gateway (RFC 4515 filter support)
- Kerberos KDC with constrained delegation (S4U2Self, S4U2Proxy, RBCD), ticket policies, and Protected Users group enforcement
- Forest and trust management — external, forest, shortcut, and Kerberos realm trust types
- Multi-DC replication monitoring with USN tracking and force-sync
- Fine-grained password policies and account lockout enforcement
- Organisational Units, Groups, Computer accounts (domain join and unjoin)
- LAPS (Local Administrator Password Solution) — per-device admin passwords, rotation, and audit log
- BitLocker recovery key escrow and retrieval with full audit trail

### Device Management (MDM)

- Unified device management across Windows, macOS, Linux, iOS, and Android
- Zero-touch enrollment per platform: APNS for macOS/iOS, WinRM for Windows, SSSD for Linux, QR code for mobile
- Bulk enrollment for fleet operations
- Remote actions: lock, wipe, restart, remote command execution
- Device compliance scanning and violation tracking
- Software deployment via enterprise app store
- Network profile deployment (Wi-Fi, VPN, email configuration)
- Backup and disaster recovery, per-device and domain-wide
- Geofencing zones with location-aware conditional access

### Group Policy and Configuration

- GPO engine compatible with Windows Group Policy concepts
- Resultant Set of Policy (RSoP) calculation per user or OU
- GPO enforcement with inheritance and Block Inheritance support
- Fine-grained account and password policies
- Configuration profiles for all managed platforms
- Update management: Windows Update, WinGet, macOS Software Update
- Policy baselines and blueprints

### Privileged Identity Management (PIM)

- Role-based just-in-time (JIT) access with configurable maximum duration
- Multi-level approval chains (sequential approvers per tier)
- Risk scoring based on time-of-day, request frequency, role sensitivity, and active elevations
- Break-glass emergency access with dual-control activation
- Session recording: every privileged action logged with risk score
- Session replay: full activity timeline for an elevation window
- Automatic AD group membership sync on elevation grant and revoke
- Event bus integration (`security.elevation.*` events)

### Security and Compliance

- Conditional access policies evaluated on device health, identity, location, and time
- Zero-trust scoring combining device, identity, network, and behavioural signals
- Compliance engine with baseline definitions and waiver management
- Security scanner for vulnerability assessment
- Antivirus protection management
- Auto-remediation for compliance violations
- Certificate authority: issue, renew, revoke
- Audit trail covering every directory change, authentication event, and GPO application

### Authentication and SSO

- Multi-factor authentication (TOTP, recovery codes)
- Single Sign-On via OIDC, SAML, and OAuth 2.0
- Session management: list, revoke, revoke-all
- Password reset workflows (SSPR)
- Service Principal management — create an application identity with ClientID, ClientSecret, and a Kerberos SPN in a single operation

### Developer Platform

- REST API across all services (400+ endpoints)
- gRPC event bus with pluggable transports (RabbitMQ, gRPC, in-memory for tests)
- Event routing registry (`config/event-routing.yaml`) with 50+ routing keys
- API gateway for unified external access
- Microsoft Graph-compatible API layer (graph-explorer service)
- Integration service for third-party systems
- Webhook and automation support

### UI

The frontend uses an Apple Business Manager-style three-column layout: sidebar navigation, item list, and detail panel.

- Device Fleet view: per-OS cards (macOS, Windows, Linux, iOS, Android) with click-to-filter and compliance indicators
- Enrollment Wizard: 4-step, OS-aware flow with platform-specific setup instructions
- Service Principal Wizard: one-click create returning ClientID, masked ClientSecret with reveal, and `.env` download
- User Onboarding Wizard: 4-step new-employee flow with temporary password reveal
- Policy Deploy Wizard: target by OS, OU, Group, Device, or User; dry-run mode; progress bar
- PIM view: Roles, Requests, Active Elevations, Session Replay, Break-Glass
- Audit Log view: filterable, paginated, severity colour-coded
- Compliance Snapshot: donut chart, top violations, devices needing attention
- Trust Management view: forest trust graph with verify, rotate, and remove actions
- Kerberos Admin view: delegation configuration, Protected Users group, ticket policies
- Replication Dashboard: per-DC health, USN tracking, force-sync, 30-second auto-refresh
- LAPS and BitLocker in device detail: password reveal with audit, key recovery modal

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js 18+, Express 4 |
| Event Bus | gRPC + RabbitMQ (pluggable via `@opendirectory/grpc-event-bus`) |
| Databases | PostgreSQL (primary), MongoDB (directory/GPO), Redis (cache/sessions) |
| AD/LDAP | Samba 4, LLDAP, ldapts |
| Kerberos | MIT Kerberos (kadmin API) |
| Frontend | Next.js, React 18, TypeScript |
| Container | Docker, Kubernetes (Helm chart included) |
| Monitoring | Prometheus metrics on every service, `/health` endpoints |
| Testing | Jest (unit + integration), nock (HTTP mocking), React Testing Library |

## Quick Start

### Prerequisites

- Docker and Docker Compose >= 20.10
- Node.js >= 18 (for local development)

### Run with Docker Compose

```bash
git clone https://github.com/Chregu12/OpenDirectory
cd OpenDirectory
docker compose up -d
# UI:          http://localhost:3000
# API Gateway: http://localhost:8080
```

### Run on Kubernetes

```bash
helm install opendirectory ./deploy/helm/opendirectory \
  --set global.domain=opendirectory.local \
  --set postgresql.auth.password=<password> \
  --namespace opendirectory --create-namespace
```

## Services

| Service | Port | Description |
|---|---|---|
| authentication-service | 3001 | User auth, MFA, SSO, session management |
| enterprise-directory | 3000 | AD-compatible directory, GPO, OU management |
| device-service | 3003 | MDM, device lifecycle, compliance, remote actions |
| policy-service | 3004 | Policy engine, RSoP, templates, blueprints |
| conditional-access | 3007 | Conditional access evaluation, zero-trust scoring |
| least-privilege | 3011 | Permission matrix, PIM role management |
| samba-ad-dc | 3010 | Domain controller (Samba), trusts, LAPS, replication |
| kerberos-kdc | 3013 | Kerberos KDC, delegation, ticket policies |
| ldap-proxy | 8389 | LDAP proxy and schema management REST API |
| notification-service | 3006 | Email and push notifications |
| certificate-authority | 3015 | PKI, certificate lifecycle |
| compliance-engine | 3907 | Baseline evaluation, waivers, trend analysis |
| audit-service | 3908 | Event collection, audit log aggregation |
| security-scanner | — | Vulnerability assessment |
| mobile-management | — | iOS/Android MDM, Apple Business Manager integration |
| app-store | — | Enterprise app store |
| api-gateway | 8080 | Unified external API |
| quick-actions | 3950 | Orchestration: one-click SP, enroll, onboard, deploy |
| integration-service | — | Third-party integrations |
| monitoring-service | — | Prometheus metrics aggregation |

## Event Bus

Events are exchanged via `@opendirectory/grpc-event-bus`. The routing table lives in `config/event-routing.yaml`. Key namespaces:

| Namespace | Events |
|---|---|
| `device.*` | enrollment, compliance, commands |
| `policy.*` | create, activate, evaluate |
| `security.elevation.*` | PIM JIT grant and revoke |
| `security.breakglass.*` | emergency access activation |
| `directory.object.*` | AD CRUD events |
| `kerberos.*` | ticket and delegation events |
| `ad.trust.*` | trust create, verify, remove |
| `ad.replication.*` | DC sync and health events |
| `identity.*` | login, token, MFA events |

## Testing

- 780+ tests across all packages and services
- Unit tests: DDD aggregates, value objects, application services
- Integration tests: EventBusClient flows, saga patterns
- E2E API tests: all REST endpoints with supertest and nock
- Frontend component tests: React Testing Library

```bash
# Run all tests
npm test --workspaces

# Run a specific service
cd services/core/authentication-service && npm test
```

## Contributing

Pull requests are welcome. Please open an issue first for significant changes. All services follow the same pattern: Express router, application service layer, domain model, and Jest tests.

## License

MIT
