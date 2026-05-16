# OpenDirectory — Assumptions Log

This file is maintained automatically during autonomous execution.
Every engineering decision made without explicit instruction is documented here.

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
