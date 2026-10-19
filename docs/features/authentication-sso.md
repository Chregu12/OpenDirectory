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

### OIDC provider integration

OpenDirectory can delegate authentication to external OIDC identity providers (Google Workspace, Azure AD, Okta, etc.).

```bash
# List configured SSO providers
curl http://authentication-service:3001/api/auth/sso/providers

# Initiate SSO login (redirects to IdP)
curl -L http://authentication-service:3001/api/auth/sso/google

# Handle callback (called by IdP after authentication)
# GET /api/auth/sso/:provider/callback?code=<authCode>&state=<state>
```

### SAML 2.0 SP support

OpenDirectory acts as a SAML 2.0 Service Provider. Configure a SAML IdP in **Settings → SSO → SAML** by providing:
- IdP metadata URL or XML
- Entity ID
- Assertion Consumer Service URL (provided by OpenDirectory)
- Attribute mapping (email, displayName, groups)

### OAuth 2.0 flows

The `oauth-provider` service implements:
- **Authorization Code flow** — for web applications
- **Client Credentials flow** — for service-to-service (used by Service Principals)
- **PKCE** — required for public clients (mobile apps, SPAs)

---

## 5. Service Principals (App Identities)

A **Service Principal** is a non-human identity for an application or service. It allows automated processes to authenticate to OpenDirectory APIs without using a user account.

### What a Service Principal provides

- **ClientID** — unique identifier (UUID)
- **ClientSecret** — a high-entropy secret (60+ characters) for the client credentials flow
- **Kerberos SPN** — a Service Principal Name registered in Samba AD DC so the app can acquire Kerberos tickets
- **Permissions** — a set of assigned API permissions scoped to the principal

### Create a Service Principal

The `quick-actions` service creates a Service Principal in a single orchestrated operation:

```bash
curl -X POST http://quick-actions:3950/api/service-principals \
  -H "Content-Type: application/json" \
  -d '{
    "appName": "backup-agent",
    "description": "Automated backup service",
    "permissions": ["read-users", "read-devices", "audit-logs"],
    "createdBy": "it-admin"
  }'
```

**What happens under the hood:**
1. A user account is created in the authentication-service (representing the SP).
2. An AD computer/service account is created in Samba AD DC.
3. A Kerberos SPN is registered (`backup-agent/opendirectory.corp.example.com`).
4. The requested permissions are assigned via the PIM permissions API.

**Response:**
```json
{
  "clientId": "550e8400-e29b-41d4-a716-446655440000",
  "clientSecret": "eyJhbGciOiJIUzI1NiJ9...",
  "spn": "backup-agent/opendirectory.corp.example.com",
  "permissions": ["read-users", "read-devices", "audit-logs"],
  "createdAt": "2026-06-07T10:00:00Z"
}
```

The ClientSecret is only shown once. Store it immediately (e.g. in a `.env` file or secrets manager). The UI provides a masked view with a reveal button and a `.env` download button.

### Using a Service Principal

```bash
# Client credentials flow — obtain an access token
curl -X POST http://oauth-provider/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<clientId>&client_secret=<clientSecret>&scope=api"

# Use the token in API calls
curl http://authentication-service:3001/api/auth/users \
  -H "Authorization: Bearer <accessToken>"
```

### Available permissions

| Permission | Access granted |
|------------|---------------|
| `read-users` | Read user accounts, attributes, group membership |
| `read-devices` | Read device inventory and compliance status |
| `write-policies` | Create and modify Group Policy objects |
| `admin-access` | Full administrative access (use sparingly) |
| `api-gateway` | Access via the external API gateway |
| `audit-logs` | Read audit log entries |

### Rotate a Service Principal secret

```bash
curl -X POST http://quick-actions:3950/api/service-principals/<clientId>/rotate-secret
# Returns: clientId, newClientSecret, rotatedAt
# The old secret is invalidated immediately.
```

### List and delete Service Principals

```bash
# List all service principals
curl http://quick-actions:3950/api/service-principals

# Get details for a specific principal
curl http://quick-actions:3950/api/service-principals/<clientId>

# Delete a service principal (removes AD account, SPN, and permissions)
curl -X DELETE http://quick-actions:3950/api/service-principals/<clientId>
```

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
