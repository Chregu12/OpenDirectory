# Authentication and SSO

Authentication is provided by the `authentication-service` (port **3001**) and the `oauth-provider` service. SSO is handled via OIDC, SAML 2.0, and OAuth 2.0. Service Principal management is orchestrated by `quick-actions` (port **3950**).

---

## 1. Local Authentication

Users authenticate with a username and password. Passwords are hashed using **bcrypt** (cost factor 12 by default) and stored in PostgreSQL. No plaintext password is ever stored or logged.

```bash
# Login
curl -X POST http://authentication-service:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "MyP@ssw0rd!"}'
# Returns: accessToken (JWT), refreshToken, expiresIn, requiresMFA

# Logout
curl -X POST http://authentication-service:3001/api/auth/logout \
  -H "Authorization: Bearer <accessToken>"

# Refresh an expired access token
curl -X POST http://authentication-service:3001/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refreshToken>"}'

# Validate a token (for service-to-service calls)
curl -X POST http://authentication-service:3001/api/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "<accessToken>"}'
```

---

## 2. Multi-Factor Authentication (MFA)

OpenDirectory supports TOTP (Time-based One-Time Password) as the second factor, compatible with Google Authenticator, Authy, Microsoft Authenticator, and any RFC 6238-compliant app.

### Setup MFA

```bash
curl -X POST http://authentication-service:3001/api/auth/mfa/setup \
  -H "Authorization: Bearer <accessToken>"
# Returns: secret, qrCodeUrl (data URI for QR code), otpAuthUri
```

1. The response includes a `qrCodeUrl` — display it to the user as a QR code image.
2. The user scans the QR code with their authenticator app.
3. Verify the first TOTP code to complete setup:

```bash
curl -X POST http://authentication-service:3001/api/auth/mfa/verify \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
# Returns: verified: true, recoveryCodes[]
```

### Recovery codes

Recovery codes are one-time-use backup codes for when the authenticator app is unavailable:

```bash
# Retrieve recovery codes (displayed once after MFA setup)
curl http://authentication-service:3001/api/auth/mfa/recovery-codes \
  -H "Authorization: Bearer <accessToken>"
```

Store recovery codes in a secure location. Each code can only be used once.

### Using a recovery code

```bash
curl -X POST http://authentication-service:3001/api/auth/mfa/verify \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{"recoveryCode": "XXXX-XXXX-XXXX-XXXX"}'
```

### Disable MFA

```bash
curl -X POST http://authentication-service:3001/api/auth/mfa/disable \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{"confirmPassword": "MyP@ssw0rd!"}'
```

---

## 3. Session Management

Sessions are stored in Redis (for fast revocation) and backed by PostgreSQL.

### List active sessions

```bash
curl http://authentication-service:3001/api/auth/sessions \
  -H "Authorization: Bearer <accessToken>"
# Returns per session: sessionId, deviceInfo (OS, browser, model), ipAddress, lastActivity, createdAt
```

### Revoke a specific session

```bash
curl -X DELETE http://authentication-service:3001/api/auth/sessions/<sessionId> \
  -H "Authorization: Bearer <accessToken>"
```

### Revoke all sessions (emergency)

Revokes every session for the authenticated user — use when a device is lost or credentials are suspected compromised:

```bash
curl -X POST http://authentication-service:3001/api/auth/sessions/revoke-all \
  -H "Authorization: Bearer <accessToken>"
```

Administrators can revoke all sessions for any user:

```bash
curl -X POST http://authentication-service:3001/api/auth/users/<userId>/sessions/revoke-all \
  -H "Authorization: Bearer <adminToken>"
```

---

## 4. Single Sign-On (SSO)

### Central OIDC federation and SAML

External OIDC authentication now uses the central `oauth-provider` authorization page and its generic adapter. It validates discovery, RS256 ID tokens, state, nonce and S256 PKCE. Explicit issuer/subject bindings select existing local identities; application assignments and independent local OTP requirements remain enforced. Tokens distinguish federated authentication from local passwords.

SAML supports authenticated **IdP-initiated HTTP-POST** launches to registered applications, with a persistent matching X.509 signing certificate, signed response and assertion, fixed ACS and audience, local application assignment checks and MFA policy. SP-initiated AuthnRequests, inbound SAML SP federation and Single Logout are not implemented. Without configuration SAML returns `503 saml_not_configured`.

See the [configuration, endpoints, examples and limits](../../services/core/oauth-provider/README.md). The previous `/api/auth/sso/*` endpoints return `410 legacy_sso_retired`; their unvalidated callback and JWT-in-URL behavior has been removed. A Settings → SSO → SAML configuration UI is not implemented. Apple device enrollment and Managed Apple Account federation require separate integrations.

### OAuth 2.0 flows

The `oauth-provider` service implements:
- **Authorization Code flow** — for web applications
- **Client Credentials flow** — for service-to-service (used by Service Principals)
- **PKCE** — required for public clients (mobile apps, SPAs)

---

## 5. App accounts and automation

Use **Identity Provider → OAuth2/OIDC → App-Konto erstellen** for a confidential `client_credentials` account. A name is enough to create it with no redirects or default permissions, initially disabled. Store the one-time secret, then activate it separately. Existing application administration permissions and version checks apply.

The [app-account CLI and scripting guide](app-accounts-automation.md) documents creation, activation, access checking, secret rotation, disablement and conditional API requests. It includes Bash/PowerShell usage and an importable Node.js client. Workload identities receive only explicitly supported app permissions; human MFA and tenant/resource ownership remain enforced by each receiver. App registration does not provision a mailbox or grant Microsoft Graph access.

The older quick-actions AD/Kerberos service-principal orchestration is a separate legacy integration. It is not the authoritative OAuth app-account creation flow. Its illustrative permission labels are not equivalent to granted OAuth API rights.

---

## 6. Password Reset

### Self-service password reset (SSPR)

Users can reset their own password via an email token:

```bash
# Request a password reset email
curl -X POST http://authentication-service:3001/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@corp.example.com"}'

# Confirm reset with the token from the email
curl -X POST http://authentication-service:3001/api/auth/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<resetToken>",
    "newPassword": "NewP@ssw0rd!2026"
  }'
```

### Admin-initiated password reset

```bash
curl -X POST http://authentication-service:3001/api/auth/users/<userId>/reset-password \
  -H "Authorization: Bearer <adminToken>" \
  -H "Content-Type: application/json" \
  -d '{"newPassword": "TempP@ss1!", "requireChangeOnLogin": true}'
```

### Change password (authenticated user)

```bash
curl -X POST http://authentication-service:3001/api/auth/change-password \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "OldP@ssw0rd!",
    "newPassword": "NewP@ssw0rd!2026"
  }'
```

Password changes are subject to the domain password policy (minimum length, complexity, minimum age, history). Violations return a `400` with a descriptive error.
