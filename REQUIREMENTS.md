# OpenDirectory — Autonomous Implementation Requirements

---

## ROLE

You are a senior fullstack engineer, security architect, and DevOps specialist.
Work fully autonomous.
Do not ask questions.
Make reasonable assumptions when needed.
Prefer completion over discussion.
When multiple solutions exist, choose the simplest maintainable one that fits the existing architecture.

---

## GOAL

Implement OpenDirectory as a complete, production-ready platform that:

1. Replaces **Microsoft Entra ID** (cloud identity, SSO, OAuth2/OIDC/SAML)
2. Replaces **Active Directory** (directory service, groups, policies, DNS, DHCP)
3. Replaces **Microsoft Intune** (MDM, device management, compliance, app deployment)
4. Is **as easy to use as Apple Business Manager** (zero-touch enrollment, one-click app deploy, guided setup)
5. Enforces **Least Privilege by default** — everything automated, no manual permission assignment needed
6. Runs fully **self-hosted** — no Microsoft cloud dependency, DSGVO-compliant

Target OS platforms: **Ubuntu 20.04+**, **macOS 12+**, **Windows 11**

---

## EXECUTION RULES

- Never stop to ask questions
- Never wait for user confirmation
- Make assumptions and continue — document them in `ASSUMPTIONS.md`
- Keep existing architecture patterns (Node.js services, Next.js frontend, Docker Compose)
- Do not refactor unrelated code
- Always run `npm run lint` after frontend changes; fix errors automatically
- Commit changes after each completed phase with a descriptive message
- If blocked by missing information: infer from existing codebase, search similar implementations, continue with best-effort implementation
- Never stop execution entirely
- Prefer existing libraries already in the project before adding new dependencies
- If a new dependency is required, add it to the correct `package.json` and document it

---

## PROJECT CONTEXT

### Stack

```
Frontend:
  - Next.js 14 (App Router, TypeScript)
  - Tailwind CSS
  - Heroicons
  - react-hot-toast

Backend Services (Node.js / Express):
  - services/core/authentication-service  → Auth, JWT, MFA, Zero Trust
  - services/core/oauth-provider          → OAuth2/OIDC/SAML Identity Provider
  - services/core/device-service          → Device lifecycle, MDM
  - services/core/policy-service          → GPO-style policy engine
  - services/core/certificate-network     → PKI, SCEP, certificates
  - services/core/conditional-access      → Zero Trust enforcement
  - services/platform/api-gateway         → Routing, auth middleware
  - services/enterprise/mobile-management → iOS/Android MDM (NanoMDM)

Infrastructure:
  - Docker Compose (docker-compose.yml, docker-compose.lite.yml)
  - PostgreSQL, MongoDB, Redis, RabbitMQ
  - LLDAP (lightweight LDAP)
  - Prometheus + Grafana
  - Step-CA (PKI)

Coding Standards:
  - TypeScript for all new frontend files
  - JSDoc only where non-obvious
  - Feature-based component organization under src/components/views/
  - API calls via src/lib/api.ts
  - No inline styles — use Tailwind classes only
```

### Navigation Structure

```
Sidebar (UnifiLayout.tsx):
  Identity & Enrollment
    → Identity Provider  (/identity)
    → Enrollment Hub     (/enrollment)
  Geräte & Apps
    → Devices            (/devices)
    → Printers           (/printers)
    → Applications       (/applications)
  Infrastruktur
    → Network            (/topology)
    → Infrastructure     (/infrastructure)
    → Users              (/users)
    → Monitoring         (/monitoring)
  Governance
    → Policies           (/policies)
    → Security           (/security)
    → Secrets            (/secrets)
  → Settings             (/settings)
```

### File Conventions

```
New view:       frontend/web-app/src/components/views/<Name>View.tsx
Register view:  frontend/web-app/src/app/[view]/page.tsx  (VALID_VIEWS + renderView switch)
Nav entry:      frontend/web-app/src/components/layout/UnifiLayout.tsx  (ALL_NAV_ITEMS)
API service:    services/core/<service-name>/src/index.js
Docker entry:   docker-compose.yml  (add service block)
Env vars:       .env.example  (add with empty defaults and comments)
```

---

## ARCHITECTURE PRINCIPLES

### 1. Identity: Entra ID Replacement

OpenDirectory is the Identity Provider (IdP). No Microsoft cloud needed.

```
User/Device → OpenDirectory IdP
                ↓
          OAuth2 / OIDC / SAML
                ↓
    SaaS Apps / Internal Services / APIs
```

Required standards:
- OAuth 2.0 Authorization Code + PKCE
- OpenID Connect (OIDC) with discovery document
- SAML 2.0 (SP-initiated + IdP-initiated)
- SCIM 2.0 (user provisioning to SaaS apps)
- FIDO2 / WebAuthn / Passkeys
- TOTP (RFC 6238)
- Conditional Access (risk score, device compliance, geolocation)

### 2. Directory: Active Directory Replacement

```
LLDAP (LDAP) → primary user/group store
     ↓
OpenDirectory API → policy assignment, group membership, OU structure
     ↓
Devices ← pull policies on enrollment and heartbeat
```

Required features:
- Users with roles (admin, user, service-account, device)
- Groups with nested membership
- Organizational Units (OUs) / Departments
- GPO-style policies per OU/Group/Device
- Password policies (complexity, rotation, history)
- Service accounts with scoped permissions

### 3. MDM: Intune + Apple Business Manager Replacement

```
New Device (any OS)
     ↓
Zero-Touch Enrollment (per OS)
     ↓
Certificate issued by Step-CA
     ↓
Policies applied automatically
     ↓
Apps deployed automatically
     ↓
Ongoing: heartbeat, compliance check, remediation
```

Per-OS enrollment:
- **Windows**: Autopilot JSON + PowerShell agent via OOBE or manual
- **macOS**: MDM profile (.mobileconfig) + agent via curl or Homebrew
- **Ubuntu**: One-liner curl install + APT package + cloud-init support

### 4. Least Privilege — Fully Automated

```
User created
     ↓
Role assigned (admin / user / read-only)
     ↓
Permissions derived automatically from role + group + OU
     ↓
App integrations inherit permissions (no manual app-level config)
     ↓
Periodic review: unused permissions flagged + auto-revoked after 90 days
```

Rules:
- No user has more permissions than their role requires
- Service accounts get only the scopes they explicitly need
- Admins require MFA always — no exceptions
- Devices not seen for 30 days are flagged; after 60 days auto-quarantined
- All permission changes are audit-logged with reason

### 5. UX: Apple Business Manager Simplicity

Every workflow must follow this pattern:

```
1. One entry point (button or wizard trigger)
2. Maximum 3 steps to completion
3. Sensible defaults pre-filled
4. One-click apply
5. Immediate feedback (toast + status badge)
6. No jargon — plain language labels
```

Wizards required for:
- Adding a user
- Enrolling a device (per OS)
- Connecting a SaaS app
- Creating a policy
- Deploying an application

---

## FEATURES TO IMPLEMENT

Implement in order. Do not skip phases.

---

### PHASE 1 — Core Identity Provider (Entra ID parity)

**Backend** (`services/core/oauth-provider/`):

- [ ] OIDC discovery endpoint (`/.well-known/openid-configuration`)
- [ ] JWKS endpoint with real RSA key pair (generate on first start, persist to disk/DB)
- [ ] Authorization Code flow with PKCE
- [ ] Token endpoint (access_token, id_token, refresh_token)
- [ ] UserInfo endpoint (sub, name, email, groups, preferred_username)
- [ ] Token introspection endpoint
- [ ] Token revocation endpoint
- [ ] Client Credentials flow
- [ ] Device Authorization flow (RFC 8628) — for CLI tools and TVs
- [ ] SAML 2.0 IdP (metadata XML, SSO endpoint, SLO endpoint, signed assertions)
- [ ] SCIM 2.0 endpoint (`/scim/v2/Users`, `/scim/v2/Groups`) for SaaS provisioning
- [ ] OAuth2 client CRUD API (`GET/POST/PUT/DELETE /api/clients`)
- [ ] Enrollment token API (`GET/POST /api/enrollment/tokens`, `POST /api/enrollment/register`)
- [ ] Device JWT issuance on enrollment

**Frontend** (`IdentityProviderView.tsx`):

- [ ] Übersicht tab: live endpoint list, stats, status banner
- [ ] Apps tab: list connected SaaS apps, add wizard (8 pre-built templates), status per app
- [ ] OAuth2/OIDC tab: client list, create client wizard, per-client config snippet generator
- [ ] SAML tab: IdP metadata display + download, SP connection wizard
- [ ] MFA tab: toggle FIDO2 / TOTP / Conditional Access, rule editor
- [ ] Settings tab: token TTL sliders, session policy, signing key rotation

---

### PHASE 2 — Enrollment Hub (Intune + ABM parity)

**Backend** (`services/core/device-service/` + `services/core/oauth-provider/`):

- [ ] `POST /api/enrollment/register` — accepts token + platform + device metadata → issues device cert + JWT
- [ ] `GET /api/enrollment/tokens` — list tokens per platform with TTL and usage
- [ ] `POST /api/enrollment/tokens/:platform/rotate` — invalidate + regenerate
- [ ] `GET /api/enroll/macos/profile.mobileconfig?token=X` — generate signed MDM profile
- [ ] `GET /api/enroll/windows/agent.ps1?token=X` — generate enrollment PowerShell script
- [ ] `GET /api/enroll/linux/install.sh?token=X` — generate enrollment bash script
- [ ] `GET /api/enroll/ios/profile.mobileconfig?token=X` — iOS MDM profile
- [ ] MDM heartbeat endpoint (`POST /api/devices/:id/heartbeat`) — updates last-seen, triggers policy sync
- [ ] Auto-quarantine: cron job flags devices offline >30 days, quarantines >60 days

**Frontend** (`EnrollmentHubView.tsx`):

- [ ] Platform cards (Windows, macOS, Ubuntu, iOS, Android) with enrolled count
- [ ] Per-platform enrollment guide (Zero-Touch instructions, QR code, download buttons)
- [ ] Token management panel (show token, copy, rotate, expiry bar)
- [ ] Recently enrolled devices list (last 10, with platform icon + hostname + enrolled-at)
- [ ] Comparison table vs. Intune + ABM

---

### PHASE 3 — Directory Service (Active Directory parity)

**Backend** (extend `services/core/authentication-service/`):

- [ ] Organizational Units (OUs) CRUD — hierarchical, stored in PostgreSQL
- [ ] Users belong to OU + Groups
- [ ] Groups: flat and nested, with automatic member inheritance
- [ ] Service Accounts: separate type, scoped OAuth2 client per service account
- [ ] Password policy engine: min length, complexity, rotation interval, history depth
- [ ] Account lifecycle: create → active → disabled → deleted (soft delete, 90-day retention)
- [ ] Bulk import: CSV upload → create users with auto-generated passwords + enrollment email

**Frontend** (`UsersView.tsx` / `LLDAPIntegration.tsx`):

- [ ] User list with OU breadcrumb, group badges, status indicator
- [ ] Add user wizard (3 steps: identity → role/group → notification)
- [ ] User detail panel: groups, devices, app assignments, last login, MFA status
- [ ] OU tree sidebar (collapsible, drag-and-drop user assignment)
- [ ] Group management: create, members, nested groups, policy assignments

---

### PHASE 4 — Least Privilege Automation

**Backend** (new `services/core/least-privilege/`):

- [ ] Permission model: Role → Permissions → Scopes (read, write, admin per resource)
- [ ] Auto-assign permissions on user creation based on role template
- [ ] Auto-assign permissions on group membership change
- [ ] Unused permission scanner: queries audit logs, flags permissions unused >90 days
- [ ] Auto-revoke: cron job revokes flagged permissions after 7-day grace period with email notice
- [ ] App permission inheritance: when user is added to group, group's app assignments propagate
- [ ] Privilege escalation detection: alert when user gains admin on >3 apps simultaneously
- [ ] PIM-lite: time-limited elevated access with auto-expiry (max 8 hours, requires MFA)

**Frontend** (new `PermissionsView.tsx`):

- [ ] Permission matrix: Users × Resources, color-coded (none / read / write / admin)
- [ ] Unused permissions list with "Revoke All" button
- [ ] PIM panel: request elevation, approve/deny, active elevations with countdown
- [ ] Risk score per user (0–100): based on permission breadth + login patterns

---

### PHASE 5 — Application Integration (App SSO + Permission Inheritance)

**Backend** (`services/core/oauth-provider/` + new app-connector templates):

- [ ] App catalog: 20 pre-built OIDC/SAML connectors
  - GitHub Enterprise, GitLab, Grafana, Nextcloud, Mattermost, Jira, Confluence
  - AWS SSO, Proxmox, Kubernetes (OIDC), Vault, Portainer, Rancher
  - Custom OIDC, Custom SAML
- [ ] Per-app group mapping: OpenDirectory group → app role (configurable)
- [ ] SCIM push: when user added to group → automatically provisioned in connected app
- [ ] SCIM push: when user disabled → automatically deprovisioned in all apps (within 60 seconds)
- [ ] App permission audit: which users have access to which apps with which role
- [ ] Token binding: device compliance checked at token issuance (non-compliant device → token denied)

**Frontend** (`ApplicationsView.tsx`):

- [ ] App catalog browse + search
- [ ] One-click "Connect App" → wizard: protocol → client credentials → group mapping → test → done
- [ ] Per-app: user list, group assignments, last token issued, SCIM sync status
- [ ] App health: last successful auth, error rate, token issuance count (24h)

---

### PHASE 6 — Policy Engine (GPO + Intune Configuration Profiles parity)

**Backend** (`services/core/policy-service/`):

- [ ] Policy types: Security Baseline, App Deploy, Update Ring, WiFi Profile, VPN Profile, Script
- [ ] Policy assignment: to OU / Group / Device / Platform
- [ ] Policy inheritance: OU → child OU → device (parent wins unless child overrides)
- [ ] Policy simulator: given user + device → calculate effective policy (RSoP equivalent)
- [ ] Platform-specific enforcement:
  - Windows: PowerShell script delivery via agent
  - macOS: `.mobileconfig` profile delivery via MDM
  - Ubuntu: Bash script + `debconf` / `puppet`-style facts via agent
- [ ] Conflict detection: two policies targeting same setting → flag + block deployment
- [ ] Update rings: Stable / Beta / Dev per OS, with deferral windows
- [ ] Security baselines: CIS Level 1 + 2 pre-built for all 3 OS platforms

**Frontend** (`PoliciesView.tsx`):

- [ ] Policy list with type icons, assignment count, compliance %, last applied
- [ ] Policy editor: form-based (no JSON editing required), live preview of what changes
- [ ] Policy simulator panel (side drawer): pick user + device → show effective settings
- [ ] Baseline wizard: pick OS + CIS level → one click → policy created and assigned

---

### PHASE 7 — UX Refinement (Apple Business Manager simplicity)

- [ ] **Onboarding Wizard** (shown on first login):
  1. Set domain name
  2. Create first admin user
  3. Enroll first device (pick OS → show steps → wait for enrollment → done)
  - No "skip" allowed until first device enrolled
- [ ] **Dashboard** (`DashboardView.tsx`):
  - Health ring: % of devices compliant
  - Platform breakdown chart (donut)
  - Recent activity feed (enrollments, logins, policy changes)
  - Quick actions: Enroll Device, Add User, Connect App, Create Policy
- [ ] **Global Search** (top bar): searches users, devices, apps, policies — keyboard shortcut `Cmd+K`
- [ ] **Notification Center**: bell icon → slide-in panel with alerts (compliance drift, quarantine, PIM requests)
- [ ] **All labels in plain language** — no AD/LDAP/OAuth jargon in the UI. Map:
  - "Distinguished Name" → "Full Path"
  - "Service Principal" → "App Identity"
  - "Grant Type" → "Login Method"
  - "Scope" → "Access Level"
  - "Conditional Access Policy" → "Access Rule"
  - "Compliance Policy" → "Device Health Check"

---

## DELIVERABLES

Every phase must produce:

| What | Where |
|------|-------|
| Backend service or endpoint | `services/core/<name>/src/` |
| Frontend view | `frontend/web-app/src/components/views/<Name>View.tsx` |
| View registered | `frontend/web-app/src/app/[view]/page.tsx` |
| Nav entry | `frontend/web-app/src/components/layout/UnifiLayout.tsx` |
| Docker service | `docker-compose.yml` |
| Env vars | `.env.example` |
| Assumptions documented | `ASSUMPTIONS.md` |

---

## DEFINITION OF DONE

A phase is complete when:

- All listed checkboxes are implemented
- Frontend compiles without TypeScript errors (`npm run build`)
- No lint errors (`npm run lint`)
- All new API endpoints respond correctly to `curl` test
- No `TODO` comments remain in new files
- New env vars documented in `.env.example`
- Changes committed with descriptive message
- `ASSUMPTIONS.md` updated with any decisions made

---

## DECISION RULES

When uncertain, apply in order:

1. Prefer convention over innovation — match existing code patterns exactly
2. Prefer readability over optimization — clear variable names, small functions
3. Prefer existing libraries in `package.json` over new ones
4. If a new library is required: pick the most widely adopted, MIT-licensed option
5. For security decisions: always choose the more restrictive default
6. For UX decisions: always choose what requires fewer clicks
7. For data decisions: prefer PostgreSQL for relational data, Redis for sessions/cache

---

## ALLOWED COMMANDS

The agent may execute:

```bash
# Node
npm install
npm run build
npm run lint
npm run dev

# Git
git add
git commit
git push

# Docker
docker-compose up -d
docker-compose build
docker-compose logs

# File operations
# Create, edit, delete any file under /home/user/OpenDirectory/
# Exception: never delete .env (only .env.example)

# Curl (for endpoint testing)
curl -s http://localhost:<port>/health
```

---

## SECURITY REQUIREMENTS (Non-Negotiable)

These rules apply to every line of code written:

### Authentication
- All API endpoints require JWT authentication except: `/health`, `/.well-known/*`, `/oauth/authorize`, `/oauth/token`, `/saml/sso`, `/api/enrollment/register`
- Admin endpoints require `role: admin` claim in JWT
- Rate limiting on all auth endpoints: 10 req/min per IP

### Least Privilege (Automated)
- New users get `role: user` by default — never admin
- Service accounts get only explicitly listed scopes — no wildcard `*` scopes
- Tokens expire: access_token 1h, refresh_token 30d, device_token 1y
- Unused tokens auto-revoked: refresh_token unused for 30 days → revoked

### Input Validation
- All user input sanitized and validated — never passed raw to DB or shell
- SQL: always parameterized queries — no string concatenation
- Shell: never interpolate user input into shell commands — use argument arrays
- File paths: validate and normalize — no path traversal

### Secrets
- Never log secrets, tokens, or passwords
- Never hardcode secrets — always from environment variables
- Rotate signing keys: JWKS endpoint serves current + previous key (30-day overlap)

### Audit
- Every authentication event logged: user, IP, device, result, timestamp
- Every permission change logged: who changed what for whom, reason
- Every device enrollment logged: platform, hostname, serial, IP, token used
- Audit log is append-only — no delete or update endpoints

---

## WORKFLOW

Execute strictly in this order. Do not skip phases. Do not stop between phases.

```
Phase 1: Core Identity Provider
  → Analyze existing oauth-provider service
  → Implement missing endpoints
  → Update IdentityProviderView.tsx
  → Test endpoints
  → Commit

Phase 2: Enrollment Hub
  → Implement enrollment API endpoints
  → Generate per-OS scripts dynamically
  → Update EnrollmentHubView.tsx
  → Test enrollment flow
  → Commit

Phase 3: Directory Service
  → Extend authentication-service with OU/Group APIs
  → Update UsersView / LLDAPIntegration
  → Test user lifecycle
  → Commit

Phase 4: Least Privilege Automation
  → Create least-privilege service
  → Implement auto-assign, scanner, auto-revoke
  → Create PermissionsView.tsx
  → Register in nav
  → Commit

Phase 5: Application Integration
  → Build app catalog with 20 connectors
  → Implement SCIM push
  → Update ApplicationsView.tsx
  → Test connect-app wizard
  → Commit

Phase 6: Policy Engine
  → Extend policy-service
  → Implement per-OS enforcement
  → Update PoliciesView.tsx
  → Test policy simulator
  → Commit

Phase 7: UX Refinement
  → Implement onboarding wizard
  → Update DashboardView
  → Add global search
  → Add notification center
  → Plain-language label pass
  → Final build + lint check
  → Commit
```

---

## AUTONOMOUS EXECUTION MODE

Operate fully autonomous.
Do not ask questions.
Do not request confirmations.
Do not pause execution between phases.
When assumptions are required:
- make the most reasonable engineering decision
- document the assumption in `ASSUMPTIONS.md` with format:

```markdown
## Assumption: <short title>
**Phase:** <phase number>
**Decision:** <what was decided>
**Reason:** <why this was the most reasonable choice>
**Impact:** <what would need to change if assumption is wrong>
```

Continue until all phases are complete and Definition of Done is met.

---

## QUICK REFERENCE — Entra ID / Intune / AD Feature Map

| Microsoft Feature | OpenDirectory Equivalent | Phase |
|---|---|---|
| Azure AD / Entra ID | Identity Provider (OAuth2/OIDC/SAML) | 1 |
| Azure AD App Registrations | OAuth2 Client Management | 1 |
| Enterprise Applications (SSO) | App Catalog + Connectors | 5 |
| SCIM Provisioning | SCIM 2.0 push to apps | 5 |
| Azure AD Groups | LDAP Groups + OU structure | 3 |
| Azure AD PIM | PIM-lite (time-limited elevation) | 4 |
| Conditional Access Policies | Conditional Access (Zero Trust) | 1 |
| Microsoft Authenticator | TOTP + FIDO2/Passkeys | 1 |
| Windows Hello for Business | FIDO2 / WebAuthn | 1 |
| Intune Device Enrollment | Enrollment Hub | 2 |
| Autopilot | Windows Zero-Touch (JSON + agent) | 2 |
| Apple DEP / ABM | macOS MDM Profile (.mobileconfig) | 2 |
| Intune Compliance Policies | Device Health Checks | 6 |
| Group Policy (GPO) | Policy Engine | 6 |
| Intune Configuration Profiles | Policy Engine (per-OS profiles) | 6 |
| Intune App Deploy | Applications + App Store | 5 |
| Windows Update for Business | Update Rings | 6 |
| Microsoft Graph API | OpenDirectory REST API | 1–6 |
| Azure AD Audit Logs | Audit Trail (append-only) | all |
| Self-Service Password Reset | (Phase 3 extension) | 3 |
| AD FS (Federation) | SAML 2.0 IdP | 1 |

---

*Last updated: 2026-05-16*
*Branch: claude/entra-id-ad-replacement-FGARx*
