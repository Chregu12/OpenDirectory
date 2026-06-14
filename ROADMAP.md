# OpenDirectory Roadmap — Outstanding Work

This document lists features that are planned or partially implemented but not yet production-ready.
Grouped by priority: Critical (blocks production use) → High → Medium → Low.

---

## Critical — Must Fix Before Production

### 1. Authentication on Quick-Actions Service (Port 3950)

- **Currently:** no authentication middleware on any endpoint
- **Required:** Bearer token validation tied to authentication-service
- **Impact:** anyone on the network can create service principals, enroll devices, and onboard users without credentials

### 2. Inter-Service Authentication

- **Currently:** services call each other with no auth headers
- **Required:** service-to-service JWT or mTLS
- All quick-actions orchestration calls are unauthenticated at the transport layer

### 3. LAPS Password Encryption

- **Currently:** LAPS passwords stored in plain text in PostgreSQL
- **Required:** encryption at rest (AES-256-GCM, key from vault or KMS)
- BitLocker recovery keys have the same issue

### 4. Break-Glass Audit Completeness

- **Currently:** break-glass events are recorded but records are mutable
- **Required:** append-only audit log with WORM storage for break-glass records
- Compliance requirement for any PAM solution

### 5. Session Recording Storage

- **Currently:** PIM session activities stored as JSONB in PostgreSQL alongside other operational data
- **Required:** separate append-only store, retention policy, encryption at rest

---

## High Priority

### 6. Remote Command Execution UI

- **Backend:** `POST /api/remote/execute` and status polling endpoints fully implemented in device-service
- **Missing:** command console UI in DeviceDetailPanel
- **Affected users:** IT admins who need to run ad-hoc commands on managed devices

### 7. LDAP Schema Browser UI

- **Backend:** full schema management API in ldap-proxy (`GET /api/schema/object-classes`, `/attribute-types`, `/validate`)
- **Missing:** UI view for browsing and extending the AD schema
- **Affected:** directory architects adding custom attributes

### 8. Certificate Lifecycle UI

- **Backend:** `/api/certificates/*` (issue, renew, revoke) in certificate-authority service
- **Missing:** certificate management view in the frontend
- **Affected:** PKI administrators

### 9. Geofencing Configuration UI

- **Backend:** `/api/geofencing/zones` CRUD in device-service
- **Missing:** map-based or coordinate-input UI for zone management
- **Affected:** location-aware conditional access policies have no way to be configured from the UI

### 10. Password Policy Enforcer Integration

- **Backend:** `PasswordPolicyEnforcer` class exists in `authentication-service/src/policies/`
- **Missing:** not wired into the register, change-password, or reset-password flows in `index.js`
- **Impact:** password complexity rules are defined but not enforced at runtime

### 11. Threat Detection Dashboard

- **Backend:** `/api/analytics/threats`, `/api/analytics/anomalies`, `/api/analytics/predictions` in device-service
- **Missing:** threat dashboard UI
- **Affected:** security operations team has no visual surface for these signals

### 12. Backup and DR UI

- **Backend:** full `/api/backup/*` and `/api/dr/*` in device-service
- **Frontend:** `AuditView` skeleton and `BackupView` component exist but make no API calls
- **Missing:** real backup schedule display, status indicators, and restore workflow

### 13. Network Profile Deployment UI

- **Backend:** `/api/agent/network/*` (Wi-Fi, VPN, email configuration) in device-service
- **Missing:** profile builder and deployment UI
- **Affected:** administrators who need to push network configurations to managed devices

---

## Medium Priority

### 14. User Offboarding UI

- **Backend:** `POST /api/quick/users/:id/offboard` fully implemented
- **Missing:** "Offboard Employee" action in UserDetailPanel or admin view
- **Workaround:** direct API call

### 15. Bulk Enrollment UI

- **Backend:** `POST /api/quick/devices/bulk-enroll` implemented
- **Missing:** CSV import or multi-device form in the Enrollment Wizard
- **Current wizard:** handles a single device only

### 16. Policy Rollback UI

- **Backend:** `POST /api/quick/policies/deployments/:id/rollback` implemented
- **Missing:** rollback button in the deployment history view
- **Current state:** the wizard shows a `deploymentId` but provides no rollback action

### 17. PIM Multi-Approver Chain UI

- **Backend:** PIMService supports multi-level approval chains
- **Missing:** UI to configure `approvalChain` on roles; currently the UI only shows a single-approver field
- **Affected:** high-security environments that require dual or sequential approval

### 18. Kerberos Keytab Generation UI

- **Backend:** `POST /api/kerberos/keytabs/:name` in kerberos-kdc
- **Missing:** keytab download UI for service account setup
- **Workaround:** direct API call

### 19. Multi-Tenant Support

- `services/enterprise/multi-tenant/` directory exists with initial scaffolding
- Not integrated into authentication or directory services
- Helm chart has no tenant isolation; all services share a single namespace

### 20. Real Samba Integration

- **Currently:** the samba-ad-dc module has placeholder implementations for several operations
- Trust creation, FSMO role transfer, and some replication operations are simulated rather than delegated to `samba-tool`
- **Required:** shell integration with `samba-tool` and `kadmin` for production use

### 21. Apple MDM (APNS) Real Integration

- **Currently:** APNS profile generation is mocked; no real push connection
- **Required:** APNS certificate provisioning, APN push implementation, and full MDM protocol handling
- **Affects:** all macOS and iOS enrollment and management flows

### 22. Windows WinRM Integration

- **Currently:** WinRM configuration is generated but never executed
- **Required:** real WinRM connection to push policy and execute remote actions on Windows machines

### 23. Linux SSSD Real Configuration

- **Currently:** an SSSD config file is generated in memory
- **Required:** a delivery mechanism (SSH, Ansible, or an on-device agent) to apply the configuration to Linux endpoints

---

## Low Priority / Nice to Have

### 24. Graph Explorer UI

- **Backend:** `services/enterprise/graph-explorer` exists with Microsoft Graph-compatible endpoints
- **Missing:** interactive query UI for exploring the graph API

### 25. Automation Rules Builder

- **Backend:** `services/enterprise/automation` exists
- **Missing:** visual rule builder in the frontend (trigger → condition → action)

### 26. Policy Simulator UI

- **Backend:** `services/enterprise/policy-simulator` exists
- **Missing:** "what-if" simulation UI to preview policy impact before deployment

### 27. Mobile Companion App

- No native iOS or Android companion app for device enrollment
- **Currently:** QR code points to a web-based enrollment flow

### 28. SAML IdP Integration

- SAML routes exist in enterprise-directory (`/saml/*`)
- Not tested end-to-end with a real SAML service provider

### 29. Dark Mode

- Frontend uses CSS variables throughout
- No dark mode theme is defined

### 30. Accessibility (a11y)

- Components use inline styles without ARIA attributes
- Screen reader support is not implemented

---

## Technical Debt

### Testing Gaps

- Frontend component tests: 131 tests exist but do not cover `LAPSView`, `BitLockerView`, `TrustManagementView`, `KerberosAdminView`, or `ReplicationView` (all recently added)
- No Playwright or Cypress end-to-end browser tests
- No load or performance tests

### Security Hardening

- Rate limiting exists on quick-actions (200 req/min) but is absent on most other services
- No WAF rules in the Helm chart Ingress
- CORS is set to `*` in several services; should be restricted to known origins
- Most service endpoints check authentication but do not enforce authorisation level (no RBAC on individual routes)

### Observability

- Prometheus metrics are emitted by all services
- No Grafana dashboards are defined in the repository
- No distributed tracing (OpenTelemetry not integrated)
- No alerting rules defined

### Infrastructure

- Helm chart: no `PodDisruptionBudget` for critical services
- No `HorizontalPodAutoscaler` configured for any service
- No Kubernetes `NetworkPolicy` resources defined (all pods can reach all pods)
- Secrets management: environment variables used directly with no Vault or external secrets integration

---

## Completed

Features fully implemented end-to-end (backend + UI + tests):

- Active Directory core (users, groups, OUs, computers) via Samba
- Kerberos principal management and delegation (S4U2Self, S4U2Proxy, RBCD)
- LDAP schema management API with RFC 4515 filter parser
- PIM: JIT access, multi-approver chains, risk scoring, break-glass activation
- PIM: session recording and session replay
- GPO enforcement engine and Resultant Set of Policy (RSoP)
- Directory audit trail (all object changes, group changes, GPO events)
- Forest and trust management API
- Computer domain join and unjoin, LAPS, and BitLocker key escrow
- Multi-DC replication monitoring
- Device management: enrollment, compliance scanning, remote actions
- Service Principal: create, list, delete, rotate (one-click from UI)
- User onboarding and offboarding orchestration
- Policy deployment with dry-run mode and rollback
- Compliance snapshot view
- Audit log view
- Apple Business Manager-style three-column UI
- 780+ automated tests (unit + integration + E2E + component)
- Kubernetes Helm chart (38 deployment templates)
- gRPC event bus with 50+ routing keys
