# authentication-service

**Port:** 3001  
**Database:** PostgreSQL (auth), Redis (sessions)  
**Language:** Node.js 18+

## Overview

The authentication service is the identity gateway for all OpenDirectory users. It handles local, LDAP, and SSO-based authentication using Passport.js strategies, issues JWT access tokens and refresh tokens, manages server-side sessions backed by Redis, and enforces multi-factor authentication (TOTP). It also implements continuous zero-trust verification: every JWT-authenticated request is re-scored against device trust, location, and anomaly signals before being allowed through.

Password policies (minimum length, complexity, history of last 10 hashes) are enforced at both registration and login time. Account lockout is applied after five consecutive failures, with a 15-minute cooldown. All authentication events (success, failure, lockout) are written to a PostgreSQL audit table and published to the event bus.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3001` | HTTP listen port |
| `JWT_SECRET` | — | Signing key for access tokens |
| `JWT_EXPIRES_IN` | `15m` | Access token TTL |
| `REFRESH_TOKEN_EXPIRES_IN` | `7d` | Refresh token TTL |
| `REDIS_HOST` | `redis` | Redis host for session store |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | — | Redis password |
| `SESSION_SECRET` | — | Express session signing key |
| `SESSION_MAX_AGE` | `86400000` | Session TTL in milliseconds |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_NAME` | `auth` | PostgreSQL database |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | — | PostgreSQL password |
| `LDAP_URL` | — | LDAP server URL (enables LDAP strategy) |
| `LDAP_BIND_DN` | — | Admin DN for LDAP searches |
| `LDAP_BIND_PASSWORD` | — | Admin password |
| `LDAP_SEARCH_BASE` | — | Search base DN |
| `LDAP_SEARCH_FILTER` | `(uid={{username}})` | User search filter |
| `LDAP_SYNC_NEW_USERS` | `false` | Mirror new registrations to LDAP |
| `KDC_API_URL` | `http://kerberos-kdc` | KDC API for principal syncing |
| `SMTP_HOST` | — | SMTP host for password reset emails |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP credentials |
| `SMTP_PASSWORD` | — | SMTP credentials |
| `ZERO_TRUST_MIN_SCORE` | `0.5` | Minimum trust score to allow login |
| `ALLOWED_ORIGINS` | — | Comma-separated CORS origins |

## API Endpoints

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/auth/login` | Authenticate and receive tokens | No |
| POST | `/api/auth/logout` | Invalidate session/tokens | Yes |
| POST | `/api/auth/register` | Register new user account | No |
| POST | `/api/auth/refresh` | Exchange refresh token for new access token | No |
| POST | `/api/auth/validate` | Validate a JWT token | No |
| POST | `/api/auth/mfa/setup` | Generate TOTP secret and QR code | Yes |
| POST | `/api/auth/mfa/verify` | Verify TOTP code and enable MFA | Yes |
| POST | `/api/auth/mfa/disable` | Disable MFA (requires password confirmation) | Yes |
| GET | `/api/auth/mfa/recovery-codes` | List MFA recovery codes | Yes |
| POST | `/api/auth/verify-device` | Zero-trust device verification | Yes |
| POST | `/api/auth/verify-location` | Zero-trust location verification | Yes |
| GET | `/api/auth/trust-score` | Get current trust score for the session | Yes |
| POST | `/api/auth/step-up` | Request step-up authentication | Yes |
| GET | `/api/auth/sessions` | List active sessions for authenticated user | Yes |
| DELETE | `/api/auth/sessions/:sessionId` | Revoke a specific session | Yes |
| POST | `/api/auth/sessions/revoke-all` | Revoke all sessions for the user | Yes |
| GET | `/api/auth/profile` | Get user profile | Yes |
| PUT | `/api/auth/profile` | Update user profile | Yes |
| POST | `/api/auth/change-password` | Change password (requires current password) | Yes |
| POST | `/api/auth/reset-password` | Initiate password reset (sends email) | No |
| POST | `/api/auth/password-reset/confirm` | Confirm reset with token and new password | No |
| GET | `/api/auth/sso/providers` | List configured SSO providers | No |
| GET | `/api/auth/sso/:provider` | Initiate SSO redirect | No |
| GET | `/api/auth/sso/:provider/callback` | SSO callback handler | No |
| GET | `/api/auth/users` | List all users (admin) | Admin |
| GET | `/api/auth/users/:userId` | Get user by ID (admin) | Admin |
| PUT | `/api/auth/users/:userId` | Update user attributes (admin) | Admin |
| DELETE | `/api/auth/users/:userId` | Delete user (admin) | Admin |
| POST | `/api/auth/users/:userId/lock` | Lock user account (admin) | Admin |
| POST | `/api/auth/users/:userId/unlock` | Unlock user account (admin) | Admin |
| GET | `/api/auth/audit/login-history` | Login history for current user | Yes |
| GET | `/api/auth/audit/security-events` | Security event log (admin) | Admin |
| GET | `/health` | Service health check | No |
| GET | `/metrics` | Prometheus metrics | No |

### POST /api/auth/login

**Request body:**

```json
{
  "username": "alice",
  "password": "S3cr3t!",
  "mfaCode": "123456",
  "deviceId": "dev-uuid",
  "provider": "local"
}
```

`provider` accepts `local` (default) or `ldap`. `mfaCode` is only required if MFA is enabled. `deviceId` is used for zero-trust device scoring.

**Response 200:**

```json
{
  "success": true,
  "user": {
    "id": "user-uuid",
    "username": "alice",
    "email": "alice@example.com",
    "roles": ["user"],
    "permissions": ["read-users"]
  },
  "tokens": {
    "accessToken": "<jwt>",
    "refreshToken": "<jwt>",
    "expiresIn": "15m"
  },
  "session": {
    "id": "session-uuid",
    "expiresAt": "2026-06-08T00:00:00.000Z"
  }
}
```

If MFA is enabled but no code was provided, the service responds with `202 { "requiresMFA": true, "tempToken": "..." }`. If zero-trust score is below the threshold, the service returns `401`.

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"S3cr3t!"}'
```

### POST /api/auth/register

```json
{
  "username": "bob",
  "email": "bob@example.com",
  "password": "S3cr3t!",
  "firstName": "Bob",
  "lastName": "Smith"
}
```

Returns `201 { "success": true, "userId": "..." }`. Synchronises the new principal to the Kerberos KDC (`/api/kerberos/sync-user`) and optionally to LDAP if `LDAP_SYNC_NEW_USERS=true`.

### POST /api/auth/mfa/setup

Returns `{ "secret": "BASE32SECRET", "qrCode": "data:image/png;base64,...", "recoveryCodes": [...], "instructions": "..." }`. The QR code encodes an `otpauth://` URI compatible with all TOTP apps. Save the recovery codes — they are shown only once.

### POST /api/auth/reset-password

```json
{ "email": "alice@example.com" }
```

Sends a password-reset email with a one-time token (valid 1 hour). The token must be submitted to `POST /api/auth/password-reset/confirm` along with the new password.

## Events Published

| Routing Key | Trigger |
|---|---|
| `identity.login.success` | Successful authentication |
| `identity.login.failed` | Failed authentication attempt |
| `identity.account.locked` | Account locked after repeated failures |
| `identity.user.created` | New user registered |
| `identity.mfa.enabled` | MFA enabled for a user |

## Events Subscribed

The authentication service does not subscribe to external events. It is an event producer only.

## Health Check

`GET /health` returns:

```json
{
  "status": "healthy",
  "service": "authentication-service",
  "uptime": 3600.5,
  "timestamp": "2026-06-07T12:00:00.000Z"
}
```

Status is always `healthy` as long as the process is running. Database availability is checked indirectly via query failures. Prometheus metrics (login attempts, active sessions, locked accounts) are available at `GET /metrics`.
