# OpenDirectory — Assumptions Log

This file is maintained automatically during autonomous execution.
Every engineering decision made without explicit instruction is documented here.

---

## Phase 1-7 Autonomous Implementation (2026-05-16)

### Phase 1 — OAuth Provider (RSA + SCIM + Device Auth)
- RSA-2048 key pair generated at startup using `crypto.generateKeyPairSync`; private key held in memory, never written to disk.
- All tokens (access, ID, device) signed with RS256. Existing `JWT_SECRET` env var no longer used for signing.
- Device Authorization flow (RFC 8628): Approval page at `/oauth/device/verify` renders inline HTML.
- SCIM 2.0 endpoints are purely in-memory; reset on service restart.
- `PUT /api/clients/:id` and `DELETE /api/clients/:id` complete CRUD on the in-memory clients Map.

### Phase 2 — Enrollment Script Generation
- macOS/iOS `.mobileconfig` uses placeholder APNS values — must be replaced for production MDM.
- Agent binary download URLs are placeholders; actual binaries must be served separately.
- Heartbeat updates in-memory `last_seen`; production should write to device DB.

### Phase 3 — Directory Service API
- OUs, groups, password policy, service accounts appended to authentication-service via an IIFE after startup.
- Service account tokens are plain random hex strings; production should use short-lived JWTs.

### Phase 4 — Least Privilege Service
- New Express service on port 3011 with own in-memory stores.
- PIM elevations not automatically cleaned up in this implementation.
- Risk scores use a heuristic (admin=40pts per resource, write=25, read=10, none=0).

### Phase 5 — App Catalog
- 20 app catalog entries with real-world correct configuration templates.
- SCIM push endpoint is a mock; always returns success.

### Phase 6 — Policy Engine (Baselines)
- Simulate and baseline endpoints fall back gracefully when DB unavailable.
- CIS baselines seeded: Ubuntu 22.04 L1, macOS 14 L1, Windows 11 L1+L2.

### Phase 7 — Frontend
- DashboardView: existing functionality preserved, new sections prepended (quick stats, SVG donut, platform bars, activity feed, quick actions). German UI throughout.
- ApplicationsView: added SSO catalog tab with 4-step wizard; mock test always succeeds.
- UnifiLayout: Cmd+K/Ctrl+K global search overlay; notification center slides in from right; KeyIcon used for Permissions nav item.
- OnboardingWizard: shown when `localStorage.od_onboarded` is falsy. Domain validation, password strength meter, OS-specific enrollment command.
- PermissionsView: 3-tab UI (matrix, unused perms, PIM) with German labels and demo data fallback.
- TypeScript check: only `target: ES5` deprecation warning, no type errors.

---

## Assumption: OAuth Provider port 3010
**Phase:** 1
**Decision:** OAuth2/OIDC provider runs on port 3010 (not conflicting with auth-service on 3002)
**Reason:** Ports 3001–3009 are used by existing services; 3010 is free
**Impact:** If port 3010 is taken in deployment, change `OAUTH_PROVIDER_PORT` in `.env`

---

## Assumption: In-memory store for demo clients
**Phase:** 1
**Decision:** OAuth2 clients seeded in-memory at startup; not persisted to PostgreSQL yet
**Reason:** PostgreSQL migration for oauth_clients table not yet implemented; in-memory is functional for development
**Impact:** Clients reset on service restart — Phase 1 extension: persist to `auth` PostgreSQL database

---

## Assumption: HS256 signing for JWT (not RS256)
**Phase:** 1
**Decision:** Tokens signed with HS256 using `JWT_SECRET` env var
**Reason:** RSA key pair generation requires persistent storage not yet configured; HS256 is functional and secure with a strong secret
**Impact:** JWKS endpoint returns empty keys — Phase 1 must be extended to generate RSA key pair and serve public key via JWKS

---

## Assumption: Enrollment tokens pre-seeded, not persisted
**Phase:** 2
**Decision:** Enrollment tokens generated at service startup and held in memory
**Reason:** Consistent with Phase 1 approach; database schema for enrollment_tokens not yet migrated
**Impact:** Tokens reset on restart — add database persistence in Phase 2 backend work

---

## Assumption: macOS MDM uses .mobileconfig format, not Apple MDM protocol
**Phase:** 2
**Decision:** macOS enrollment generates a `.mobileconfig` XML profile (Configuration Profile), not full Apple MDM push via APNS
**Reason:** APNS requires Apple Developer account, APNs certificate provisioned externally — cannot automate during implementation
**Impact:** Full supervised MDM (Activation Lock bypass, remote wipe) requires APNS keys; document in DEPLOYMENT.md

---

## Assumption: Linux target is Ubuntu 20.04+ (Debian-compatible)
**Phase:** 2
**Decision:** Primary Linux target is Ubuntu; Fedora/RHEL/Arch treated as secondary with best-effort scripts
**Reason:** Ubuntu is the most common enterprise Linux in the target audience
**Impact:** Test enrollment scripts on Ubuntu first; extend for RPM-based in Phase 2

---

## Assumption: Plain-language labels are German by default
**Phase:** 7
**Decision:** UI labels use German (primary) with English technical terms where no German equivalent exists
**Reason:** Existing codebase mixes German and English; user's context is Swiss/German
**Impact:** If English-only UI is required, a `i18n` layer would need to be added

---
