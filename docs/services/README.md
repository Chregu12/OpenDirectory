# Services Reference

OpenDirectory consists of approximately 30 microservices across three layers. Services communicate asynchronously through a pluggable gRPC event bus (RabbitMQ by default). Each service exposes a REST API and a `/health` endpoint, and emits Prometheus metrics on `/metrics`.

## Core Services

| Service | Port | Database | Description |
|---|---|---|---|
| authentication-service | 3001 | PostgreSQL (auth) | User auth, MFA, SSO, sessions, password management |
| enterprise-directory | 3000 | MongoDB | AD-compatible directory, GPO, OU hierarchy, audit |
| device-service | 3003 | PostgreSQL (devices) | MDM, device lifecycle, compliance, remote actions |
| policy-service | 3004 | PostgreSQL (policies) | Policy engine, RSoP, templates, blueprints |
| conditional-access | 3007 | PostgreSQL | PIM, zero-trust scoring, session recording, break-glass |
| least-privilege | 3011 | PostgreSQL | Permission matrix, PIM role management |
| samba-ad-dc | 3010 | PostgreSQL + Samba | Domain controller, trusts, LAPS, BitLocker, replication |
| kerberos-kdc | 3013 | PostgreSQL | Kerberos, delegation (KCD/RBCD), ticket policies, Protected Users |
| ldap-proxy | 8389 (REST) / 1389 (LDAP) | — | LDAP proxy + schema management REST API |
| notification-service | 3006 | PostgreSQL | Email, push notifications, alert routing |
| certificate-authority | 3015 | PostgreSQL | PKI, certificate lifecycle (issue/renew/revoke) |
| identity-service | 3002 | PostgreSQL | Identity provider federation |
| network-infrastructure | 3008 | PostgreSQL | Network management (DNS, DHCP, VLANs) |
| backup-service | varies | PostgreSQL | Backup scheduling, status, restore |
| update-management | varies | PostgreSQL | OS/app update orchestration |
| remote-control | varies | — | Remote desktop, command execution |
| oauth-provider | varies | PostgreSQL | OAuth 2.0 authorization server |
| apple-mdm | varies | — | Apple MDM/APNs plumbing; ADE unavailable (no ABM/ASM connector) |
| configuration-service | varies | PostgreSQL | Centralised config management |
| monitoring-service | varies | — | Prometheus aggregation, health dashboard |
| license-management | varies | PostgreSQL | Software license tracking |
| printer-service | varies | — | Print server management |

## Enterprise Services

| Service | Description |
|---|---|
| compliance-engine | Baseline evaluation, waivers, trend analysis |
| audit-service | Event collection and audit log aggregation |
| app-store | Enterprise application store |
| security-scanner | Vulnerability assessment |
| antivirus-protection | AV status monitoring |
| auto-remediation | Automated fix workflows |
| mobile-management | iOS/Android MDM (APNS, MDM protocol) |
| policy-simulator | What-if policy simulation |
| device-lifecycle | Device onboarding/decommission workflows |
| graph-explorer | Microsoft Graph-compatible API |
| multi-tenant | Tenant isolation (roadmap) |

## Platform Services

| Service | Port | Description |
|---|---|---|
| api-gateway | 8080 | Unified external API entry point |
| quick-actions | 3950 | Orchestration: one-click SP, enroll, onboard, deploy |
| integration-service | varies | Third-party integrations (ServiceNow, JIRA, etc.) |
| event-bus | 50051 (gRPC) | @opendirectory/grpc-event-bus |

## Architecture Notes

**Inter-service communication:** All domain events are published to the gRPC event bus using RabbitMQ topic exchanges. Routing keys follow the pattern `<domain>.<entity>.<action>` (e.g., `identity.user.created`, `device.compliance.violated`).

**Authentication:** The api-gateway validates JWT tokens before proxying requests to upstream services. Individual services also accept `Authorization: Bearer <token>` directly for service-to-service calls.

**Databases:**
- PostgreSQL — primary operational store for most services
- MongoDB — directory objects and GPO data (enterprise-directory)
- Redis — session cache, distributed locks, WebSocket message queuing

**Health checks:** Every service exposes `GET /health` returning `{ status, service, timestamp, uptime }`. The device-service health check additionally reports WebSocket connection counts and pending enrollment counts.

For the supported SAML launch flow and external OIDC configuration, see the [OAuth provider README](../../services/core/oauth-provider/README.md). For Apple enrollment prerequisites and limits, see the [Apple MDM README](../../services/core/apple-mdm/README.md).

[Own-company license groups](../features/company-license-groups.md) use identity-service canonical group snapshots and policy-service pool links/source-aware allocations. UI and CLI writes retain the original human owner session and current MFA.

Identity 052 evaluates [current group-rule sources](../features/company-group-live-sources.md) for application authority and group-license observations before worker cleanup. Snapshot source revisions differ from physical group ETags; Policy retains its existing lease and hash checks. Identity 053 adds [source-change subscriptions](../features/company-automation-changes.md); private original-app Identity/Policy observations capture actual local capacity and enqueue existing reconciliation jobs atomically with their checkpoints.

[Own-company confidential app accounts](../features/company-apps.md) use the existing OAuth registry (001–014), original Owner/MFA source and current Identity tenant generation (001–054). The gateway delegates only `/api/clients/company` to `OAUTH_PROVIDER_URL`; receiver authorization remains mandatory. Company credentials do not inherit global application roles, and generic registry routes cannot manage owned clients.
